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
	DeviceModes    map[string]contracts.DeviceMode
	DeviceIPv4     map[string][]netip.Addr
	DeviceIPv6     map[string][]netip.Addr
	OwnedTables    map[string]string
}

func Render(plan contracts.PolicyPlan, inventory Inventory) ([]byte, error) {
	if owner := inventory.OwnedTables[TableName]; owner != "" && owner != "routerd" {
		return nil, fmt.Errorf("nft table %q is owned by %s", TableName, owner)
	}
	groups, err := compile(plan)
	if err != nil {
		return nil, err
	}
	devices, err := validateDevices(groups, inventory)
	if err != nil {
		return nil, err
	}
	marks, activeMark, err := resolveMarks(plan, inventory.ActiveServerID, groups, devices)
	if err != nil {
		return nil, err
	}

	var out strings.Builder
	out.WriteString("table inet routerd {\n")
	writeLocalSets(&out)
	for _, group := range groups {
		if group.kind == contracts.EntryKindDomain {
			fmt.Fprintf(&out, "  set %s { type ipv4_addr; flags timeout; timeout %ds; }\n", group.set4, SetTimeout)
			fmt.Fprintf(&out, "  set %s { type ipv6_addr; flags timeout; timeout %ds; }\n", group.set6, SetTimeout)
		}
	}
	out.WriteString("  chain prerouting {\n")
	out.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
	out.WriteString("    fib daddr type local return\n")
	out.WriteString("    ip daddr @rd_local4 return\n")
	out.WriteString("    ip6 daddr @rd_local6 return\n")

	// Protected system-direct rules precede connection-mark restoration so a
	// newly protected management endpoint cannot remain pinned to VPN.
	for _, group := range groups {
		if group.origin != contracts.OriginSystemDirect {
			continue
		}
		if err := writeGroupRules(&out, group, devices, marks, activeMark, true); err != nil {
			return nil, err
		}
	}

	orderedDevices := sortedDevices(devices)
	for _, device := range orderedDevices {
		if device.mode == contracts.DeviceModeAlwaysDirect {
			writeDeviceAction(&out, device, directOverrideAction())
		}
	}
	for _, group := range groups {
		if group.origin == contracts.OriginSystemDirect || group.route != contracts.RouteClassDirect || group.scope.Type != contracts.ScopeDevice {
			continue
		}
		device := devices[group.scope.DeviceID]
		if device.mode == contracts.DeviceModeAlwaysVPN {
			if err := writeGroupRules(&out, group, devices, marks, activeMark, true); err != nil {
				return nil, err
			}
		}
	}
	out.WriteString("    ct mark & 0xff000000 != 0 meta mark set (meta mark & 0x00ffffff) | (ct mark & 0xff000000)\n")
	out.WriteString("    ct mark & 0xff000000 != 0 return\n")

	for _, device := range orderedDevices {
		if device.mode == contracts.DeviceModeAlwaysVPN {
			writeDeviceAction(&out, device, markAction(activeMark))
		}
	}
	for _, group := range groups {
		if group.origin == contracts.OriginSystemDirect {
			continue
		}
		if group.route == contracts.RouteClassDirect && group.scope.Type == contracts.ScopeDevice && devices[group.scope.DeviceID].mode == contracts.DeviceModeAlwaysVPN {
			continue
		}
		if err := writeGroupRules(&out, group, devices, marks, activeMark, false); err != nil {
			return nil, err
		}
	}
	out.WriteString("  }\n}\n")
	return []byte(out.String()), nil
}

type deviceRuntime struct {
	id   string
	mode contracts.DeviceMode
	v4   []netip.Addr
	v6   []netip.Addr
}

func validateDevices(groups []compiledGroup, inventory Inventory) (map[string]deviceRuntime, error) {
	ids := make(map[string]struct{})
	for id := range inventory.DeviceModes {
		ids[id] = struct{}{}
	}
	for id := range inventory.DeviceIPv4 {
		ids[id] = struct{}{}
	}
	for id := range inventory.DeviceIPv6 {
		ids[id] = struct{}{}
	}
	for _, group := range groups {
		if group.scope.Type == contracts.ScopeDevice {
			ids[group.scope.DeviceID] = struct{}{}
		}
	}
	devices := make(map[string]deviceRuntime, len(ids))
	owners := make(map[netip.Addr]string)
	for id := range ids {
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("runtime device ID is required")
		}
		mode := inventory.DeviceModes[id]
		if mode == "" {
			mode = contracts.DeviceModeAuto
		}
		switch mode {
		case contracts.DeviceModeAuto, contracts.DeviceModeAlwaysDirect, contracts.DeviceModeAlwaysVPN:
		default:
			return nil, fmt.Errorf("device %q has invalid runtime mode %q", id, mode)
		}
		device := deviceRuntime{id: id, mode: mode}
		for _, address := range inventory.DeviceIPv4[id] {
			address = address.Unmap()
			if !address.IsValid() || !address.Is4() {
				return nil, fmt.Errorf("device %q has non-IPv4 address in IPv4 inventory", id)
			}
			if owner := owners[address]; owner != "" && owner != id {
				return nil, fmt.Errorf("address %s belongs to devices %q and %q", address, owner, id)
			}
			owners[address] = id
			device.v4 = append(device.v4, address)
		}
		for _, address := range inventory.DeviceIPv6[id] {
			if !address.IsValid() || !address.Is6() || address.Is4In6() {
				return nil, fmt.Errorf("device %q has non-IPv6 address in IPv6 inventory", id)
			}
			if owner := owners[address]; owner != "" && owner != id {
				return nil, fmt.Errorf("address %s belongs to devices %q and %q", address, owner, id)
			}
			owners[address] = id
			device.v6 = append(device.v6, address)
		}
		device.v4 = uniqueAddresses(device.v4)
		device.v6 = uniqueAddresses(device.v6)
		if len(device.v4) == 0 && len(device.v6) == 0 {
			return nil, fmt.Errorf("device %q has no runtime address", id)
		}
		devices[id] = device
	}
	return devices, nil
}

func resolveMarks(plan contracts.PolicyPlan, activeServer string, groups []compiledGroup, devices map[string]deviceRuntime) (map[string]uint32, uint32, error) {
	marks := make(map[string]uint32, len(plan.ServerRoutes))
	seenMarks := make(map[uint32]string)
	for _, route := range plan.ServerRoutes {
		if strings.TrimSpace(route.ServerID) == "" {
			return nil, 0, fmt.Errorf("server ID is required")
		}
		if route.Mark == 0 || route.Mark&^contracts.RouterdMarkMask != 0 {
			return nil, 0, fmt.Errorf("server %q mark %#x is outside routerd mask", route.ServerID, route.Mark)
		}
		slot := route.Mark >> 24
		if route.Table != contracts.RouterdRoutingTableBase+slot {
			return nil, 0, fmt.Errorf("server %q table %d does not match mark slot %d", route.ServerID, route.Table, slot)
		}
		if _, exists := marks[route.ServerID]; exists {
			return nil, 0, fmt.Errorf("duplicate server %q", route.ServerID)
		}
		if owner := seenMarks[route.Mark]; owner != "" {
			return nil, 0, fmt.Errorf("servers %q and %q share mark %#x", owner, route.ServerID, route.Mark)
		}
		marks[route.ServerID] = route.Mark
		seenMarks[route.Mark] = route.ServerID
	}
	if activeServer == "" && len(plan.ServerRoutes) == 1 {
		activeServer = plan.ServerRoutes[0].ServerID
	}
	if activeServer != "" && marks[activeServer] == 0 {
		return nil, 0, fmt.Errorf("active VPN server %q is unavailable", activeServer)
	}
	activeMark := marks[activeServer]
	needsActive := false
	for _, group := range groups {
		needsActive = needsActive || group.route == contracts.RouteClassVPN && group.serverID == ""
		if group.serverID != "" && marks[group.serverID] == 0 {
			return nil, 0, fmt.Errorf("entry group references unavailable server %q", group.serverID)
		}
	}
	for _, device := range devices {
		needsActive = needsActive || device.mode == contracts.DeviceModeAlwaysVPN
	}
	if needsActive && activeMark == 0 {
		return nil, 0, fmt.Errorf("active VPN server %q is unavailable", activeServer)
	}
	return marks, activeMark, nil
}

func writeLocalSets(out *strings.Builder) {
	out.WriteString("  set rd_local4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } }\n")
	out.WriteString("  set rd_local6 { type ipv6_addr; flags interval; elements = { ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32 } }\n")
}

func writeGroupRules(out *strings.Builder, group compiledGroup, devices map[string]deviceRuntime, marks map[string]uint32, activeMark uint32, protected bool) error {
	action := "return"
	if group.route == contracts.RouteClassVPN {
		mark := activeMark
		if group.serverID != "" {
			mark = marks[group.serverID]
		}
		if mark == 0 {
			return fmt.Errorf("VPN rule %q has no usable server mark", group.firstID)
		}
		action = markAction(mark)
	}
	if protected {
		action = directOverrideAction()
	}
	if group.kind == contracts.EntryKindDomain {
		writeFamilyRule(out, group, devices, 4, "@"+group.set4, action)
		writeFamilyRule(out, group, devices, 6, "@"+group.set6, action)
		return nil
	}
	family := 4
	if group.family == 128 {
		family = 6
	}
	writeFamilyRule(out, group, devices, family, "{ "+strings.Join(group.patterns, ", ")+" }", action)
	return nil
}

func writeFamilyRule(out *strings.Builder, group compiledGroup, devices map[string]deviceRuntime, family int, destination, action string) {
	familyName := "ip"
	if family == 6 {
		familyName = "ip6"
	}
	source := ""
	if group.scope.Type == contracts.ScopeDevice {
		device := devices[group.scope.DeviceID]
		addresses := device.v4
		if family == 6 {
			addresses = device.v6
		}
		if len(addresses) == 0 {
			return
		}
		source = familyName + " saddr " + addressSet(addresses) + " "
	}
	fmt.Fprintf(out, "    %s%s daddr %s %s\n", source, familyName, destination, action)
}

func writeDeviceAction(out *strings.Builder, device deviceRuntime, action string) {
	if len(device.v4) != 0 {
		fmt.Fprintf(out, "    ip saddr %s %s\n", addressSet(device.v4), action)
	}
	if len(device.v6) != 0 {
		fmt.Fprintf(out, "    ip6 saddr %s %s\n", addressSet(device.v6), action)
	}
}

func markAction(mark uint32) string {
	return fmt.Sprintf("meta mark set (meta mark & 0x00ffffff) | %#x ct mark set (ct mark & 0x00ffffff) | (meta mark & 0xff000000) return", mark)
}

func directOverrideAction() string {
	return "meta mark set (meta mark & 0x00ffffff) ct mark set (ct mark & 0x00ffffff) return"
}

func sortedDevices(devices map[string]deviceRuntime) []deviceRuntime {
	ids := make([]string, 0, len(devices))
	for id := range devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]deviceRuntime, 0, len(ids))
	for _, id := range ids {
		result = append(result, devices[id])
	}
	return result
}

func uniqueAddresses(values []netip.Addr) []netip.Addr {
	sort.Slice(values, func(i, j int) bool { return values[i].Less(values[j]) })
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func addressSet(addresses []netip.Addr) string {
	values := make([]string, len(addresses))
	for index, address := range addresses {
		values[index] = address.String()
	}
	if len(values) == 1 {
		return values[0]
	}
	return "{ " + strings.Join(values, ", ") + " }"
}
