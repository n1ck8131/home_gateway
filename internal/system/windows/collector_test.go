package windows

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

type fakeInterfaceProvider struct {
	interfaces []InterfaceSnapshot
}

func (provider fakeInterfaceProvider) Interfaces() ([]InterfaceSnapshot, error) {
	return provider.interfaces, nil
}

type commandCall struct {
	executable string
	arguments  []string
}

type fakeInventoryRunner struct {
	netAdapters []byte
	ipv4        []byte
	ipv6        []byte
	calls       []commandCall
}

func (runner *fakeInventoryRunner) Output(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	runner.calls = append(runner.calls, commandCall{executable: executable, arguments: append([]string(nil), arguments...)})
	switch executable {
	case "powershell.exe":
		return runner.netAdapters, nil
	case "route.exe":
		if len(arguments) == 2 && arguments[0] == "PRINT" && arguments[1] == "-4" {
			return runner.ipv4, nil
		}
		if len(arguments) == 2 && arguments[0] == "PRINT" && arguments[1] == "-6" {
			return runner.ipv6, nil
		}
	}
	return nil, errors.New("unexpected command")
}

func TestExecRunnerRejectsCommandsOutsideReadOnlyAllowlist(t *testing.T) {
	for _, testCase := range []struct {
		executable string
		arguments  []string
	}{
		{executable: "cmd.exe", arguments: []string{"/c", "route print"}},
		{executable: "route.exe", arguments: []string{"ADD", "203.0.113.1"}},
		{executable: "powershell.exe", arguments: []string{"-Command", "Get-NetAdapter"}},
	} {
		if _, err := (ExecRunner{}).Output(context.Background(), testCase.executable, testCase.arguments...); err == nil {
			t.Fatalf("native runner accepted unsupported command %q %#v", testCase.executable, testCase.arguments)
		}
	}
}

func TestNativeCollectorUsesDescriptionsBeforePhysicalClassification(t *testing.T) {
	runner := &fakeInventoryRunner{
		netAdapters: []byte(`[
{"Name":"Ethernet","InterfaceDescription":"Intel Ethernet Controller","ifIndex":1,"Status":"Up"},
{"Name":"Ethernet 2","InterfaceDescription":"Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64","ifIndex":2,"Status":"Up"},
{"Name":"redlink","InterfaceDescription":"WireGuard Tunnel","ifIndex":3,"Status":"Up"},
{"Name":"6to4 Adapter","InterfaceDescription":"","ifIndex":99,"Status":"Disconnected"}
]`),
		ipv4: []byte(`
0.0.0.0          0.0.0.0          192.168.1.1  192.168.1.10  25
10.50.0.0        255.255.0.0      On-link      172.16.0.2    1
203.0.113.5      255.255.255.255  On-link      10.20.30.2    1
`),
		ipv6: []byte(`
2 1 ::/0 On-link
2 2 2001:db8:50::/48
3 1 fd00::/8 On-link
`),
	}
	interfaces := fakeInterfaceProvider{interfaces: []InterfaceSnapshot{
		{Name: "Ethernet", Index: 1, Flags: net.FlagUp, Addresses: []string{"192.168.1.10/24"}},
		{Name: "Ethernet 2", Index: 2, Flags: net.FlagUp, Addresses: []string{"172.16.0.2/32"}},
		{Name: "redlink", Index: 3, Flags: net.FlagUp, Addresses: []string{"10.20.30.2/32", "fd00::2/128"}},
	}}

	inventory, err := (NativeCollector{Runner: runner, Interfaces: interfaces}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertAdapterKind(t, inventory.Adapters, 1, AdapterPhysical)
	assertAdapterKind(t, inventory.Adapters, 2, AdapterCisco)
	assertAdapterKind(t, inventory.Adapters, 3, AdapterRedShield)
	if inventory.RouteSnapshotAuthoritative || inventory.DNSPolicyObserved {
		t.Fatalf("partial native inventory overstated capabilities: %#v", inventory)
	}

	wantPowerShellArguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", netAdapterInventoryScript}
	if len(runner.calls) != 3 || runner.calls[0].executable != "powershell.exe" || !reflect.DeepEqual(runner.calls[0].arguments, wantPowerShellArguments) {
		t.Fatalf("unexpected read-only command calls: %#v", runner.calls)
	}
	for _, call := range runner.calls {
		joined := strings.ToLower(call.executable + " " + strings.Join(call.arguments, " "))
		for _, forbidden := range []string{"set-net", "remove-net", "disable-net", "enable-net", "start-service", "stop-service"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("collector attempted mutation %q", joined)
			}
		}
	}

	inventory.EndpointAddresses = []string{"203.0.113.5"}
	plan := (Planner{}).Plan(inventory, tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportWireGuard,
			Endpoint:           tunnel.Endpoint{Host: "vpn.example.test", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/24", "fd00::2/64"},
			IPv4FullTunnel:     true,
			IPv6FullTunnel:     true,
		},
		Status: tunnel.Status{State: tunnel.StateUp, Observed: true},
	})
	assertFinding(t, plan, "cisco_routes_identified", SeverityInfo)
	assertFinding(t, plan, "route_inventory_not_authoritative", SeverityBlock)
	assertFinding(t, plan, "dns_policy_unobserved", SeverityBlock)
	assertOperation(t, plan, OperationPreserveCiscoRoute, "10.50.0.0/16")
	assertOperation(t, plan, OperationPreserveCiscoRoute, "::/0")
	assertOperation(t, plan, OperationPreserveCiscoRoute, "2001:db8:50::/48")
	assertFinding(t, plan, "endpoint_direct_exception_missing", SeverityBlock)
	for _, finding := range plan.Findings {
		if finding.Code == "default_route_adapter_unclassified" {
			t.Fatalf("classified Cisco default was treated as unknown: %#v", plan.Findings)
		}
	}
}

func TestNetAdapterInventoryParserFailsClosed(t *testing.T) {
	for name, data := range map[string][]byte{
		"malformed":      []byte(`not-json`),
		"single object":  []byte(`{"Name":"Ethernet","InterfaceDescription":"Intel","ifIndex":1,"Status":"Up"}`),
		"missing name":   []byte(`[{"Name":"","InterfaceDescription":"Intel","ifIndex":1,"Status":"Up"}]`),
		"missing status": []byte(`[{"Name":"Ethernet","InterfaceDescription":"Intel","ifIndex":1,"Status":""}]`),
		"unknown field":  []byte(`[{"Name":"Ethernet","InterfaceDescription":"Intel","ifIndex":1,"Status":"Up","Extra":true}]`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseNetAdapterInventory(data); err == nil {
				t.Fatal("unsafe adapter inventory accepted")
			}
		})
	}
	records, err := parseNetAdapterInventory([]byte(`[{"Name":"Teredo Tunneling Pseudo-Interface","InterfaceDescription":"","ifIndex":5,"Status":"Disconnected"}]`))
	if err != nil {
		t.Fatalf("inactive hidden adapter with empty description was rejected: %v", err)
	}
	if records[5].Description != "" {
		t.Fatalf("description = %q", records[5].Description)
	}
}

func TestNativeCollectorFailsClosedWhenDescriptionCannotBeJoined(t *testing.T) {
	runner := &fakeInventoryRunner{netAdapters: []byte(`[{"Name":"Ethernet","InterfaceDescription":"Intel Ethernet Controller","ifIndex":1,"Status":"Up"}]`)}
	interfaces := fakeInterfaceProvider{interfaces: []InterfaceSnapshot{
		{Name: "Ethernet 2", Index: 2, Flags: net.FlagUp, Addresses: []string{"172.16.0.2/32"}},
	}}
	if _, err := (NativeCollector{Runner: runner, Interfaces: interfaces}).Collect(context.Background()); err == nil {
		t.Fatal("collector accepted an adapter without description enrichment")
	}
}

func TestNativeCollectorRejectsActiveGenericAdapterWithoutDescription(t *testing.T) {
	runner := &fakeInventoryRunner{netAdapters: []byte(`[{"Name":"Ethernet 2","InterfaceDescription":"","ifIndex":2,"Status":"Up"}]`)}
	interfaces := fakeInterfaceProvider{interfaces: []InterfaceSnapshot{
		{Name: "Ethernet 2", Index: 2, Flags: net.FlagUp, Addresses: []string{"172.16.0.2/32"}},
	}}
	if _, err := (NativeCollector{Runner: runner, Interfaces: interfaces}).Collect(context.Background()); err == nil {
		t.Fatal("collector accepted an active generic adapter without description")
	}
}

func TestNativeCollectorRejectsUnmatchedActiveNetAdapterRecord(t *testing.T) {
	for name, description := range map[string]string{
		"Cisco":             "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64",
		"generic":           "Unknown Virtual Adapter",
		"WAN near miss":     "WAN Miniport (IP) Extra",
		"Hyper-V near miss": "Hyper-V Virtual Switch Extension Adapter Extra",
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeInventoryRunner{netAdapters: []byte(`[{"Name":"Unmatched","InterfaceDescription":"` + description + `","ifIndex":9,"Status":"Up"}]`)}
			if _, err := (NativeCollector{Runner: runner, Interfaces: fakeInterfaceProvider{}}).Collect(context.Background()); err == nil {
				t.Fatal("collector accepted an unmatched active Get-NetAdapter record")
			}
		})
	}
}

func TestNativeCollectorAllowsExactUnmatchedActiveWindowsSystemPseudoAdapters(t *testing.T) {
	runner := &fakeInventoryRunner{netAdapters: []byte(`[
{"Name":"Localized WAN 1","InterfaceDescription":"WAN Miniport (IP)","ifIndex":90,"Status":"Up"},
{"Name":"Localized WAN 2","InterfaceDescription":"  wan miniport (ipv6)  ","ifIndex":91,"Status":"Up"},
{"Name":"Localized WAN 3","InterfaceDescription":"WAN Miniport (Network Monitor)","ifIndex":92,"Status":"Up"},
{"Name":"Localized Hyper-V Extension","InterfaceDescription":"Hyper-V Virtual Switch Extension Adapter","ifIndex":93,"Status":"Up"}
]`)}
	if _, err := (NativeCollector{Runner: runner, Interfaces: fakeInterfaceProvider{}}).Collect(context.Background()); err != nil {
		t.Fatalf("known Windows pseudo-adapters were rejected: %v", err)
	}
}

func TestNativeCollectorAllowsInactiveHiddenAdapterAndPlannerBlocksItsStaleDefault(t *testing.T) {
	runner := &fakeInventoryRunner{
		netAdapters: []byte(`[{"Name":"Teredo Tunneling Pseudo-Interface","InterfaceDescription":"","ifIndex":5,"Status":"Disconnected"}]`),
		ipv6:        []byte("5 999 ::/0 On-link\n"),
	}
	interfaces := fakeInterfaceProvider{interfaces: []InterfaceSnapshot{
		{Name: "Teredo Tunneling Pseudo-Interface", Index: 5, Addresses: []string{"2001:0::2/32"}},
	}}
	inventory, err := (NativeCollector{Runner: runner, Interfaces: interfaces}).Collect(context.Background())
	if err != nil {
		t.Fatalf("inactive hidden adapter blocked inventory: %v", err)
	}
	assertAdapterKind(t, inventory.Adapters, 5, AdapterOther)
	if inventory.Adapters[0].Up {
		t.Fatal("disconnected hidden adapter marked active")
	}
	plan := (Planner{}).Plan(inventory, fullTunnelInspection())
	assertFinding(t, plan, "default_route_adapter_unclassified", SeverityBlock)
}

func TestUnknownIPv6DefaultIsNotMarkedPhysicalAndBlocksPlanner(t *testing.T) {
	inventory := safeInventory()
	inventory.Adapters = append(inventory.Adapters, Adapter{
		Name:        "Ethernet 9",
		Description: "Unclassified Virtual Miniport",
		Index:       9,
		Kind:        AdapterOther,
		Up:          true,
		Addresses:   []string{"2001:db8:9::2/64"},
	})
	inventory.Routes = append(inventory.Routes, Route{
		Family:         FamilyIPv6,
		Destination:    "::/0",
		InterfaceIndex: 9,
		Metric:         1,
	})
	for index := range inventory.Adapters {
		if inventory.Adapters[index].Index == 1 {
			inventory.Adapters[index].Kind = AdapterPhysical
		}
	}

	plan := (Planner{}).Plan(inventory, fullTunnelInspection())
	assertFinding(t, plan, "default_route_adapter_unclassified", SeverityBlock)
	if plan.Ready || !plan.ApplyBlocked {
		t.Fatalf("unknown IPv6 default did not block apply: %#v", plan)
	}

	adapters := normalizedAdapters(inventory.Adapters, inventory.Routes)
	assertAdapterKind(t, adapters, 9, AdapterOther)
}

func assertAdapterKind(t *testing.T, adapters []Adapter, index int, want AdapterKind) {
	t.Helper()
	for _, adapter := range adapters {
		if adapter.Index == index {
			if adapter.Kind != want {
				t.Fatalf("adapter %d kind = %q, want %q", index, adapter.Kind, want)
			}
			return
		}
	}
	t.Fatalf("adapter %d missing from %#v", index, adapters)
}
