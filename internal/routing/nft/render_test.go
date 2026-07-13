package nft

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestRenderOwnedTableMarksParityAndProtocolIndependentRules(t *testing.T) {
	route := serverRoute(t, "nl", 1)
	plan := contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}, Entries: []contracts.RouteEntry{
		globalEntry("v4", "8.8.8.8", contracts.EntryKindIP, contracts.RouteClassVPN, contracts.OriginManual, 1),
		globalEntry("v6", "2606:4700::/32", contracts.EntryKindCIDR, contracts.RouteClassVPN, contracts.OriginExternalVPN, 0),
	}}
	got, err := Render(plan, Inventory{ActiveServerID: "nl"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"table inet routerd",
		`comment "managed-by-routerd"`,
		"ip daddr { 8.8.8.8 }",
		"ip6 daddr { 2606:4700::/32 }",
		"ct mark & 0xff000000",
		"meta mark set (meta mark & 0x00ffffff) | 0x1000000",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	for _, forbidden := range []string{"tcp ", "udp "} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("protocol-specific rule %q", forbidden)
		}
	}
	_, err = Render(plan, Inventory{ActiveServerID: "nl", OwnedTables: map[string]string{"routerd": "mwan3"}})
	if err == nil {
		t.Fatal("expected ownership collision")
	}
}

func TestRenderOriginPrecedenceWinsBeforeDirectSafetyTie(t *testing.T) {
	route := serverRoute(t, "nl", 1)
	plan := contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}, Entries: []contracts.RouteEntry{
		globalEntry("weaker-direct", "8.8.8.8", contracts.EntryKindIP, contracts.RouteClassDirect, contracts.OriginExternalDirect, 0),
		globalEntry("stronger-vpn", "8.8.8.8", contracts.EntryKindIP, contracts.RouteClassVPN, contracts.OriginManual, 4),
	}}
	got, err := Render(plan, Inventory{ActiveServerID: "nl"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	vpn := strings.Index(text, "ip daddr { 8.8.8.8 } meta mark set")
	direct := strings.Index(text, "ip daddr { 8.8.8.8 } return")
	if vpn < 0 || direct < 0 || vpn >= direct {
		t.Fatalf("manual VPN rule must precede weaker direct rule:\n%s", text)
	}
}

func TestRenderUsesEntrySpecificServerMark(t *testing.T) {
	nl := serverRoute(t, "nl", 1)
	de := serverRoute(t, "de", 2)
	entry := globalEntry("de-only", "9.9.9.9", contracts.EntryKindIP, contracts.RouteClassVPN, contracts.OriginManual, 1)
	entry.ServerID = "de"
	got, err := Render(
		contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{nl, de}, Entries: []contracts.RouteEntry{entry}},
		Inventory{ActiveServerID: "nl"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "ip daddr { 9.9.9.9 } meta mark set (meta mark & 0x00ffffff) | 0x2000000") {
		t.Fatalf("entry-specific server mark missing:\n%s", got)
	}
}

func TestRenderDeviceModesOverrideRestoredMarks(t *testing.T) {
	route := serverRoute(t, "nl", 1)
	directException := globalEntry("direct-exception", "9.9.9.9", contracts.EntryKindIP, contracts.RouteClassDirect, contracts.OriginManual, 2)
	directException.Scope = contracts.Scope{Type: contracts.ScopeDevice, DeviceID: "vpn-device"}
	plan := contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}, Entries: []contracts.RouteEntry{
		directException,
		globalEntry("vpn", "8.8.8.8", contracts.EntryKindIP, contracts.RouteClassVPN, contracts.OriginExternalVPN, 0),
	}}
	inventory := Inventory{
		ActiveServerID: "nl",
		DeviceModes: map[string]contracts.DeviceMode{
			"direct-device": contracts.DeviceModeAlwaysDirect,
			"vpn-device":    contracts.DeviceModeAlwaysVPN,
		},
		DeviceIPv4: map[string][]netip.Addr{
			"direct-device": {netip.MustParseAddr("192.168.1.11")},
			"vpn-device":    {netip.MustParseAddr("192.168.1.10")},
		},
	}
	got, err := Render(plan, inventory)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	restore := strings.Index(text, "ct mark & 0xff000000 != 0 meta mark set")
	alwaysDirect := strings.Index(text, "ip saddr 192.168.1.11 "+directOverrideAction())
	exception := strings.Index(text, "ip saddr 192.168.1.10 ip daddr { 9.9.9.9 } "+directOverrideAction())
	alwaysVPN := strings.Index(text, "ip saddr 192.168.1.10 "+markAction(route.Mark))
	if restore < 0 || alwaysDirect < 0 || exception < 0 || alwaysVPN < 0 {
		t.Fatalf("missing device-mode rule:\n%s", text)
	}
	if alwaysDirect >= restore || exception >= restore || alwaysVPN <= restore {
		t.Fatalf("device overrides are on the wrong side of connmark restore:\n%s", text)
	}
	if strings.Count(text, "ip saddr 192.168.1.10 ip daddr { 9.9.9.9 }") != 1 {
		t.Fatalf("direct exception rendered more than once:\n%s", text)
	}
}

func TestRenderSystemDirectPrecedesConnmarkRestore(t *testing.T) {
	entry := globalEntry("management", "1.1.1.1", contracts.EntryKindIP, contracts.RouteClassDirect, contracts.OriginSystemDirect, 0)
	got, err := Render(contracts.PolicyPlan{Entries: []contracts.RouteEntry{entry}}, Inventory{})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	systemDirect := strings.Index(text, "ip daddr { 1.1.1.1 } "+directOverrideAction())
	restore := strings.Index(text, "ct mark & 0xff000000 != 0 meta mark set")
	if systemDirect < 0 || restore < 0 || systemDirect >= restore {
		t.Fatalf("system-direct rule must precede connmark restore:\n%s", text)
	}
}

func TestRenderRequiresRuntimeAddressForScopedEntry(t *testing.T) {
	entry := globalEntry("device", "1.1.1.1", contracts.EntryKindIP, contracts.RouteClassDirect, contracts.OriginManual, 1)
	entry.Scope = contracts.Scope{Type: contracts.ScopeDevice, DeviceID: "laptop"}
	_, err := Render(contracts.PolicyPlan{Entries: []contracts.RouteEntry{entry}}, Inventory{})
	if err == nil || !strings.Contains(err.Error(), "no runtime address") {
		t.Fatalf("Render() error = %v, want missing runtime address", err)
	}
}

func TestRenderStableAcrossEntryAndDeviceOrder(t *testing.T) {
	route := serverRoute(t, "nl", 1)
	a := globalEntry("a", "1.1.1.0/24", contracts.EntryKindCIDR, contracts.RouteClassDirect, contracts.OriginCuratedDirect, 0)
	b := globalEntry("b", "8.8.8.0/24", contracts.EntryKindCIDR, contracts.RouteClassVPN, contracts.OriginExternalVPN, 0)
	firstInventory := Inventory{
		ActiveServerID: "nl",
		DeviceModes:    map[string]contracts.DeviceMode{"z": contracts.DeviceModeAlwaysDirect, "a": contracts.DeviceModeAlwaysDirect},
		DeviceIPv4: map[string][]netip.Addr{
			"z": {netip.MustParseAddr("192.168.1.20")},
			"a": {netip.MustParseAddr("192.168.1.10")},
		},
	}
	secondInventory := Inventory{
		ActiveServerID: "nl",
		DeviceModes:    map[string]contracts.DeviceMode{"a": contracts.DeviceModeAlwaysDirect, "z": contracts.DeviceModeAlwaysDirect},
		DeviceIPv4: map[string][]netip.Addr{
			"a": {netip.MustParseAddr("192.168.1.10")},
			"z": {netip.MustParseAddr("192.168.1.20")},
		},
	}
	one, err := Render(contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}, Entries: []contracts.RouteEntry{b, a}}, firstInventory)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Render(contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}, Entries: []contracts.RouteEntry{a, b}}, secondInventory)
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Fatal("output is not deterministic")
	}
}

func globalEntry(id, pattern string, kind contracts.EntryKind, route contracts.RouteClass, origin contracts.OriginTier, sequence uint64) contracts.RouteEntry {
	return contracts.RouteEntry{
		ID:       id,
		Pattern:  pattern,
		Kind:     kind,
		Route:    route,
		Scope:    contracts.Scope{Type: contracts.ScopeGlobal},
		Origin:   origin,
		Sequence: sequence,
	}
}

func serverRoute(t *testing.T, id string, slot uint8) contracts.ServerRoute {
	t.Helper()
	route, err := contracts.ServerRouteForSlot(id, slot)
	if err != nil {
		t.Fatal(err)
	}
	return route
}
