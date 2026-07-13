package nft

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

const (
	TableName  = "routerd"
	SetTimeout = 3600
)

type Inventory struct {
	ActiveServerID string
	DeviceIPv4     map[string][]netip.Addr
	DeviceIPv6     map[string][]netip.Addr
	OwnedTables    map[string]string
}

func Render(plan contracts.PolicyPlan, inventory Inventory) ([]byte, error) {
	if owner := inventory.OwnedTables[TableName]; owner != "" && owner != "routerd" {
		return nil, fmt.Errorf("nft table %q is owned by %s", TableName, owner)
	}
	marks := make(map[string]uint32, len(plan.ServerRoutes))
	for _, route := range plan.ServerRoutes {
		marks[route.ServerID] = route.Mark
	}
	active := inventory.ActiveServerID
	if active == "" && len(plan.ServerRoutes) == 1 {
		active = plan.ServerRoutes[0].ServerID
	}
	activeMark := marks[active]
	if len(plan.ServerRoutes) != 0 && activeMark == 0 {
		return nil, fmt.Errorf("active server %q is unavailable", active)
	}

	sets := map[string][]string{"direct4": {}, "direct6": {}, "vpn4": {}, "vpn6": {}}
	entries := append([]contracts.RouteEntry(nil), plan.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, entry := range entries {
		if entry.Kind != contracts.EntryKindIP && entry.Kind != contracts.EntryKindCIDR {
			continue
		}
		prefix, family, err := canonicalNetwork(entry.Pattern, entry.Kind)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", entry.ID, err)
		}
		name := string(entry.Route) + family
		sets[name] = append(sets[name], prefix)
	}
	for name := range sets {
		sort.Strings(sets[name])
	}

	var out strings.Builder
	out.WriteString("table inet routerd {\n")
	for _, spec := range []struct{ name, typ string }{{"direct4", "ipv4_addr"}, {"direct6", "ipv6_addr"}, {"vpn4", "ipv4_addr"}, {"vpn6", "ipv6_addr"}} {
		fmt.Fprintf(&out, "  set %s { type %s; flags interval,timeout; timeout %ds;", spec.name, spec.typ, SetTimeout)
		if len(sets[spec.name]) > 0 {
			fmt.Fprintf(&out, " elements = { %s };", strings.Join(sets[spec.name], ", "))
		}
		out.WriteString(" }\n")
	}
	out.WriteString("  chain prerouting {\n    type filter hook prerouting priority mangle; policy accept;\n")
	out.WriteString("    ct mark & 0xff000000 != 0 meta mark set ct mark\n")
	out.WriteString("    meta mark & 0xff000000 != 0 return\n")
	out.WriteString("    ip daddr @direct4 return\n    ip6 daddr @direct6 return\n")
	if activeMark != 0 {
		fmt.Fprintf(&out, "    ip daddr @vpn4 meta mark set %#x ct mark set meta mark\n", activeMark)
		fmt.Fprintf(&out, "    ip6 daddr @vpn6 meta mark set %#x ct mark set meta mark\n", activeMark)
	}
	out.WriteString("  }\n}\n")
	return []byte(out.String()), nil
}

func canonicalNetwork(raw string, kind contracts.EntryKind) (string, string, error) {
	if kind == contracts.EntryKindIP {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return "", "", err
		}
		address = address.Unmap()
		if address.Is4() {
			return address.String(), "4", nil
		}
		return address.String(), "6", nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return "", "", err
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		return prefix.String(), "4", nil
	}
	return prefix.String(), "6", nil
}
