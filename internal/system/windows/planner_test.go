package windows

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

func TestPlannerReadyWithEndpointExceptionAndCiscoPreservation(t *testing.T) {
	inventory := safeInventory()
	plan := (Planner{}).Plan(inventory, fullTunnelInspection())

	if !plan.Ready || plan.ApplyBlocked {
		t.Fatalf("expected ready plan, got %#v", plan.Findings)
	}
	assertFinding(t, plan, "endpoint_direct_exception_present", SeverityInfo)
	assertFinding(t, plan, "redshield_adapter_binding_matched", SeverityInfo)
	assertFinding(t, plan, "tunnel_status_up", SeverityInfo)
	assertFinding(t, plan, "cisco_routes_identified", SeverityInfo)
	assertOperation(t, plan, OperationPreserveCiscoRoute, "10.50.0.0/16")
	assertOperation(t, plan, OperationEnforceFailClosed, "")

	data, err := json.Marshal(plan.Operations)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, operation := range decoded {
		for _, forbidden := range []string{"command", "executable", "arguments", "shell"} {
			if _, exists := operation[forbidden]; exists {
				t.Fatalf("operation contains executable field %q: %#v", forbidden, operation)
			}
		}
	}
}

func TestPlannerBlocksEndpointCurrentlyRoutedThroughRedlink(t *testing.T) {
	inventory := safeInventory()
	inventory.Routes = append(inventory.Routes, Route{
		Family:         FamilyIPv4,
		Destination:    "203.0.113.5/32",
		InterfaceIndex: 2,
		Metric:         1,
	})
	plan := (Planner{}).Plan(inventory, fullTunnelInspection())

	if plan.Ready || !plan.ApplyBlocked {
		t.Fatalf("endpoint routed through tunnel must block apply: %#v", plan)
	}
	assertFinding(t, plan, "endpoint_direct_exception_missing", SeverityBlock)
	operation := findOperation(t, plan, OperationAddEndpointDirectException, "203.0.113.5/32")
	if operation.InterfaceIndex != 1 || operation.NextHop != "192.168.1.1" {
		t.Fatalf("direct exception does not target physical default: %#v", operation)
	}
}

func TestPlannerBlocksMissingTunnelCiscoRoutesAndFailClosedFamilies(t *testing.T) {
	inventory := safeInventory()
	inventory.Adapters[1].Up = false
	inventory.Routes = removeRoutesForInterface(inventory.Routes, 3)
	inspection := fullTunnelInspection()
	inspection.Metadata.IPv4FullTunnel = false
	inspection.Metadata.IPv6FullTunnel = false

	plan := (Planner{}).Plan(inventory, inspection)
	if plan.Ready || !plan.ApplyBlocked {
		t.Fatalf("unsafe inventory unexpectedly ready: %#v", plan)
	}
	for _, code := range []string{
		"redshield_tunnel_not_active",
		"cisco_routes_unresolved",
		"ipv4_fail_closed_unresolved",
		"ipv6_fail_closed_unresolved",
	} {
		assertFinding(t, plan, code, SeverityBlock)
	}
}

func TestPlannerAllowsNoIPv6WANLeakPathWithoutIPv6FullTunnel(t *testing.T) {
	inventory := safeInventory()
	filtered := inventory.Routes[:0]
	for _, route := range inventory.Routes {
		if route.Family != FamilyIPv6 || route.InterfaceIndex != 1 {
			filtered = append(filtered, route)
		}
	}
	inventory.Routes = filtered
	inspection := fullTunnelInspection()
	inspection.Metadata.IPv6FullTunnel = false

	plan := (Planner{}).Plan(inventory, inspection)
	if !plan.Ready {
		t.Fatalf("plan should be ready without a physical IPv6 default: %#v", plan.Findings)
	}
	assertFinding(t, plan, "ipv6_no_physical_default", SeverityInfo)
}

func TestPlannerBlocksUnsafeTunnelBindingAndStatus(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Inventory, *tunnel.Inspection)
		finding string
	}{
		"address mismatch": {
			mutate: func(_ *Inventory, inspection *tunnel.Inspection) {
				inspection.Metadata.InterfaceAddresses = []string{"10.99.0.2/32"}
			},
			finding: "redshield_adapter_binding_mismatch",
		},
		"partial address mismatch": {
			mutate: func(_ *Inventory, inspection *tunnel.Inspection) {
				inspection.Metadata.InterfaceAddresses = []string{"10.20.30.2/24", "fd99::2/64"}
			},
			finding: "redshield_adapter_binding_mismatch",
		},
		"two active adapters": {
			mutate: func(inventory *Inventory, _ *tunnel.Inspection) {
				inventory.Adapters = append(inventory.Adapters, Adapter{Name: "WireGuard second", Index: 4, Kind: AdapterRedShield, Up: true, Addresses: []string{"10.99.0.2/32"}})
			},
			finding: "redshield_adapter_count_invalid",
		},
		"status unobserved": {
			mutate: func(_ *Inventory, inspection *tunnel.Inspection) {
				inspection.Status = tunnel.Status{State: tunnel.StateUp, Observed: false}
			},
			finding: "tunnel_status_unobserved",
		},
		"status not up": {
			mutate: func(_ *Inventory, inspection *tunnel.Inspection) {
				inspection.Status = tunnel.Status{State: tunnel.StateDown, Observed: true}
			},
			finding: "tunnel_status_not_up",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			inventory := safeInventory()
			inspection := fullTunnelInspection()
			test.mutate(&inventory, &inspection)
			plan := (Planner{}).Plan(inventory, inspection)
			if plan.Ready || !plan.ApplyBlocked {
				t.Fatalf("unsafe tunnel state unexpectedly ready: %#v", plan)
			}
			assertFinding(t, plan, test.finding, SeverityBlock)
		})
	}
}

func TestPlannerBlocksPartialInventoryCapabilities(t *testing.T) {
	inventory := safeInventory()
	inventory.RouteSnapshotAuthoritative = false
	inventory.DNSPolicyObserved = false
	plan := (Planner{}).Plan(inventory, fullTunnelInspection())

	if plan.Ready || !plan.ApplyBlocked {
		t.Fatalf("partial inventory unexpectedly ready: %#v", plan)
	}
	assertFinding(t, plan, "route_inventory_not_authoritative", SeverityBlock)
	assertFinding(t, plan, "dns_policy_unobserved", SeverityBlock)
}

func TestReadOnlyControllerRefusesMutation(t *testing.T) {
	err := (ReadOnlyController{}).Apply(context.Background(), Preflight{})
	if !IsUnsupportedMutation(err, MutationApplyPreflight) {
		t.Fatalf("expected typed unsupported mutation error, got %v", err)
	}
}

func safeInventory() Inventory {
	return Inventory{
		Adapters: []Adapter{
			{Name: "Ethernet", Index: 1, Kind: AdapterPhysical, Up: true, Addresses: []string{"192.168.1.10/24", "2001:db8:1::10/64"}},
			{Name: "redlink", Index: 2, Kind: AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32", "fd00::2/128"}},
			{Name: "Cisco Secure Client", Index: 3, Kind: AdapterCisco, Up: true, Addresses: []string{"172.16.0.2/32"}},
		},
		Routes: []Route{
			{Family: FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 1, Metric: 25},
			{Family: FamilyIPv6, Destination: "::/0", NextHop: "fe80::1", InterfaceIndex: 1, Metric: 25},
			{Family: FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceIndex: 1, Metric: 5},
			{Family: FamilyIPv4, Destination: "10.50.0.0/16", InterfaceIndex: 3, Metric: 1},
		},
		EndpointAddresses:          []string{"203.0.113.5"},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
}

func fullTunnelInspection() tunnel.Inspection {
	return tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportAmneziaWG,
			Endpoint:           tunnel.Endpoint{Host: "vpn.example.test", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/24", "fd00::2/64"},
			IPv4FullTunnel:     true,
			IPv6FullTunnel:     true,
		},
		Status: tunnel.Status{State: tunnel.StateUp, Observed: true},
	}
}

func removeRoutesForInterface(routes []Route, index int) []Route {
	result := make([]Route, 0, len(routes))
	for _, route := range routes {
		if route.InterfaceIndex != index {
			result = append(result, route)
		}
	}
	return result
}

func assertFinding(t *testing.T, plan Preflight, code string, severity FindingSeverity) {
	t.Helper()
	for _, finding := range plan.Findings {
		if finding.Code == code && finding.Severity == severity {
			return
		}
	}
	t.Fatalf("missing finding %s/%s in %#v", code, severity, plan.Findings)
}

func assertOperation(t *testing.T, plan Preflight, kind OperationKind, destination string) {
	t.Helper()
	_ = findOperation(t, plan, kind, destination)
}

func findOperation(t *testing.T, plan Preflight, kind OperationKind, destination string) Operation {
	t.Helper()
	for _, operation := range plan.Operations {
		if operation.Kind == kind && (destination == "" || operation.Destination == destination) {
			return operation
		}
	}
	t.Fatalf("missing operation %s/%s in %#v", kind, destination, plan.Operations)
	return Operation{}
}
