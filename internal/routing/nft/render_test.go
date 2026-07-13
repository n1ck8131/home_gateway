package nft

import (
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestRenderOwnedTableMarksParityAndProtocolIndependentRules(t *testing.T) {
	route, _ := contracts.ServerRouteForSlot("nl", 1)
	plan := contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}, Entries: []contracts.RouteEntry{
		{ID: "v4", Pattern: "203.0.113.4", Kind: contracts.EntryKindIP, Route: contracts.RouteClassVPN},
		{ID: "v6", Pattern: "2001:db8::/32", Kind: contracts.EntryKindCIDR, Route: contracts.RouteClassVPN},
	}}
	got, err := Render(plan, Inventory{ActiveServerID: "nl"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"table inet routerd", "set vpn4", "set vpn6", "ct mark & 0xff000000", "meta mark set 0x1000000"} {
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

func TestRenderStableAcrossEntryOrder(t *testing.T) {
	a := contracts.RouteEntry{ID: "a", Pattern: "198.51.100.0/24", Kind: contracts.EntryKindCIDR, Route: contracts.RouteClassDirect}
	b := contracts.RouteEntry{ID: "b", Pattern: "203.0.113.0/24", Kind: contracts.EntryKindCIDR, Route: contracts.RouteClassVPN}
	one, _ := Render(contracts.PolicyPlan{Entries: []contracts.RouteEntry{b, a}}, Inventory{})
	two, _ := Render(contracts.PolicyPlan{Entries: []contracts.RouteEntry{a, b}}, Inventory{})
	if string(one) != string(two) {
		t.Fatal("output is not deterministic")
	}
}
