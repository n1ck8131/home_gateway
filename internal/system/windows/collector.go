package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

type CommandRunner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}

type InterfaceSnapshot struct {
	Name      string
	Index     int
	Flags     net.Flags
	Addresses []string
}

type InterfaceProvider interface {
	Interfaces() ([]InterfaceSnapshot, error)
}

type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	switch {
	case executable == "powershell.exe" && matchesArguments(arguments,
		"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", netAdapterInventoryScript):
		return exec.CommandContext(ctx, "powershell.exe",
			"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", netAdapterInventoryScript).Output()
	case executable == "route.exe" && matchesArguments(arguments, "PRINT", "-4"):
		return exec.CommandContext(ctx, "route.exe", "PRINT", "-4").Output()
	case executable == "route.exe" && matchesArguments(arguments, "PRINT", "-6"):
		return exec.CommandContext(ctx, "route.exe", "PRINT", "-6").Output()
	default:
		return nil, errors.New("unsupported native Windows inventory command")
	}
}

func matchesArguments(actual []string, expected ...string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

type NetInterfaceProvider struct{}

func (NetInterfaceProvider) Interfaces() ([]InterfaceSnapshot, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]InterfaceSnapshot, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return nil, addressErr
		}
		snapshot := InterfaceSnapshot{
			Name:  networkInterface.Name,
			Index: networkInterface.Index,
			Flags: networkInterface.Flags,
		}
		for _, address := range addresses {
			snapshot.Addresses = append(snapshot.Addresses, address.String())
		}
		result = append(result, snapshot)
	}
	return result, nil
}

type NativeCollector struct {
	Runner     CommandRunner
	Interfaces InterfaceProvider
}

const netAdapterInventoryScript = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object Name,InterfaceDescription,ifIndex,Status)`

type netAdapterRecord struct {
	Name        string `json:"Name"`
	Description string `json:"InterfaceDescription"`
	Index       int    `json:"ifIndex"`
	Status      string `json:"Status"`
}

var allowedUnmatchedActiveSystemDescriptions = [...]string{
	"WAN Miniport (IP)",
	"WAN Miniport (IPv6)",
	"WAN Miniport (Network Monitor)",
	"Hyper-V Virtual Switch Extension Adapter",
}

func (collector NativeCollector) Collect(ctx context.Context) (Inventory, error) {
	if runtime.GOOS != "windows" && (collector.Runner == nil || collector.Interfaces == nil) {
		return Inventory{}, errors.New("native Windows inventory is unavailable on this operating system")
	}
	runner := collector.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	interfaces := collector.Interfaces
	if interfaces == nil {
		interfaces = NetInterfaceProvider{}
	}

	netAdapterOutput, err := runner.Output(
		ctx,
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		netAdapterInventoryScript,
	)
	if err != nil {
		return Inventory{}, errors.New("windows adapter description inventory failed")
	}
	netAdapters, err := parseNetAdapterInventory(netAdapterOutput)
	if err != nil {
		return Inventory{}, err
	}

	networkInterfaces, err := interfaces.Interfaces()
	if err != nil {
		return Inventory{}, errors.New("windows adapter inventory failed")
	}
	adapters := make([]Adapter, 0, len(networkInterfaces))
	matchedNetAdapters := make(map[int]struct{}, len(networkInterfaces))
	for _, networkInterface := range networkInterfaces {
		record, found := netAdapters[networkInterface.Index]
		if !found {
			if networkInterface.Flags&net.FlagLoopback == 0 {
				return Inventory{}, errors.New("windows adapter description is unavailable")
			}
			record = netAdapterRecord{Name: networkInterface.Name, Index: networkInterface.Index, Status: "Up"}
		} else if !strings.EqualFold(record.Name, networkInterface.Name) {
			return Inventory{}, errors.New("windows adapter inventory changed during collection")
		}
		if found {
			matchedNetAdapters[networkInterface.Index] = struct{}{}
		}
		kind := DetectAdapterKind(record.Name, record.Description, networkInterface.Flags)
		up := strings.EqualFold(record.Status, "Up") && networkInterface.Flags&net.FlagUp != 0
		if record.Description == "" && up && kind == AdapterOther {
			return Inventory{}, errors.New("active Windows adapter cannot be classified without a description")
		}
		adapter := Adapter{
			Name:        record.Name,
			Description: record.Description,
			Index:       networkInterface.Index,
			Kind:        kind,
			Up:          up,
		}
		for _, value := range networkInterface.Addresses {
			prefix, parseErr := netip.ParsePrefix(value)
			if parseErr == nil {
				adapter.Addresses = append(adapter.Addresses, prefix.String())
			}
		}
		sort.Strings(adapter.Addresses)
		adapters = append(adapters, adapter)
	}
	for index, record := range netAdapters {
		if _, matched := matchedNetAdapters[index]; !matched && strings.EqualFold(record.Status, "Up") {
			if !isAllowedUnmatchedActiveSystemAdapter(record) {
				return Inventory{}, errors.New("active Windows adapter is missing from the interface inventory")
			}
		}
	}

	ipv4Output, err := runner.Output(ctx, "route.exe", "PRINT", "-4")
	if err != nil {
		return Inventory{}, errors.New("windows IPv4 route inventory failed")
	}
	ipv6Output, err := runner.Output(ctx, "route.exe", "PRINT", "-6")
	if err != nil {
		return Inventory{}, errors.New("windows IPv6 route inventory failed")
	}
	routes := ParseRoutePrint(ipv4Output, ipv6Output, adapters)
	markPhysicalDefaultAdapters(adapters, routes)
	sort.Slice(adapters, func(left, right int) bool { return adapters[left].Index < adapters[right].Index })
	return Inventory{
		Adapters:                   adapters,
		Routes:                     routes,
		RouteSnapshotAuthoritative: false,
		DNSPolicyObserved:          false,
	}, nil
}

func isAllowedUnmatchedActiveSystemAdapter(record netAdapterRecord) bool {
	description := strings.TrimSpace(record.Description)
	for _, allowed := range allowedUnmatchedActiveSystemDescriptions {
		if strings.EqualFold(description, allowed) {
			return true
		}
	}
	return false
}

func parseNetAdapterInventory(data []byte) (map[int]netAdapterRecord, error) {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var records []netAdapterRecord
	if err := decoder.Decode(&records); err != nil {
		return nil, errors.New("windows adapter description inventory is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("windows adapter description inventory has trailing data")
	}
	if len(records) == 0 {
		return nil, errors.New("windows adapter description inventory is empty")
	}
	result := make(map[int]netAdapterRecord, len(records))
	for _, record := range records {
		record.Name = strings.TrimSpace(record.Name)
		record.Description = strings.TrimSpace(record.Description)
		record.Status = strings.TrimSpace(record.Status)
		if record.Index <= 0 || record.Name == "" || record.Status == "" {
			return nil, errors.New("windows adapter description inventory has incomplete entries")
		}
		if _, duplicate := result[record.Index]; duplicate {
			return nil, errors.New("windows adapter description inventory has duplicate indices")
		}
		result[record.Index] = record
	}
	return result, nil
}

func DetectAdapterKind(name, description string, flags net.Flags) AdapterKind {
	if flags&net.FlagLoopback != 0 {
		return AdapterLoopback
	}
	normalized := strings.ToLower(name + " " + description)
	for _, marker := range []string{"redshield", "redlink", "wireguard", "amnezia", "amneziawg", "awg"} {
		if strings.Contains(normalized, marker) {
			return AdapterRedShield
		}
	}
	for _, marker := range []string{"cisco", "anyconnect", "secure client", "secure mobility"} {
		if strings.Contains(normalized, marker) {
			return AdapterCisco
		}
	}
	return AdapterOther
}

func ResolveEndpoint(ctx context.Context, host string) ([]string, error) {
	if address, err := netip.ParseAddr(host); err == nil && address.Zone() == "" && !address.Is4In6() {
		return []string{address.String()}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("endpoint address resolution failed")
	}
	seen := make(map[string]struct{}, len(addresses))
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.Zone() != "" {
			continue
		}
		value := address.String()
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, errors.New("endpoint address resolution returned no usable addresses")
	}
	sort.Strings(result)
	return result, nil
}

func markPhysicalDefaultAdapters(adapters []Adapter, routes []Route) {
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || route.Family != FamilyIPv4 || !prefix.Addr().Is4() || prefix.Bits() != 0 {
			continue
		}
		for index := range adapters {
			if !adapters[index].Up || adapters[index].Kind != AdapterOther || !routeUsesAdapter(route, adapters[index]) {
				continue
			}
			adapters[index].Kind = AdapterPhysical
		}
	}
}

func routeUsesAdapter(route Route, adapter Adapter) bool {
	if route.InterfaceIndex != 0 {
		return route.InterfaceIndex == adapter.Index
	}
	interfaceAddress, err := netip.ParseAddr(route.InterfaceAddress)
	if err != nil {
		return false
	}
	for _, value := range adapter.Addresses {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr == nil && prefix.Addr().Unmap() == interfaceAddress.Unmap() {
			return true
		}
	}
	return false
}
