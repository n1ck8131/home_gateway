package windows

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

func TestPlannerSeparatesReadOnlyQualificationFromUnsupportedApply(t *testing.T) {
	plan := (Planner{}).Plan(safeInventory(), fullTunnelInspection(tunnel.Status{State: tunnel.StateUnknown, Observed: false}))

	if plan.Ready || !plan.ApplyBlocked || !plan.ReadOnlyQualified {
		t.Fatalf("P3.3 readiness semantics = %#v", plan)
	}
	if !plan.LocalTunnelStatus.Observed || plan.LocalTunnelStatus.State != LocalTunnelUp || plan.LocalTunnelStatus.InterfaceGUID != testRedShieldGUID {
		t.Fatalf("local tunnel status = %#v", plan.LocalTunnelStatus)
	}
	assertFinding(t, plan, "backend_tunnel_status_unobserved", SeverityInfo)
	assertFinding(t, plan, "tunnel_adapter_binding_matched", SeverityInfo)
	assertFinding(t, plan, "cisco_routes_identified", SeverityInfo)
	assertFinding(t, plan, "windows_apply_unsupported", SeverityInfo)
	ciscoOperation := findOperation(t, plan, OperationPreserveCiscoRoute, "10.50.0.0/16")
	if ciscoOperation.InterfaceGUID != testCiscoGUID {
		t.Fatalf("Cisco operation lacks stable identity: %#v", ciscoOperation)
	}
	assertOperation(t, plan, OperationEnforceFailClosed, "")

	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["ready"] != false || decoded["apply_blocked"] != true || decoded["read_only_qualified"] != true {
		t.Fatalf("JSON implies apply readiness: %s", data)
	}
	for _, operation := range plan.Operations {
		operationData, marshalErr := json.Marshal(operation)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var fields map[string]any
		if err := json.Unmarshal(operationData, &fields); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"command", "executable", "arguments", "shell"} {
			if _, exists := fields[forbidden]; exists {
				t.Fatalf("operation contains executable field %q: %#v", forbidden, fields)
			}
		}
	}
}

func TestPlannerBackendHealthSemantics(t *testing.T) {
	tests := map[string]struct {
		status    tunnel.Status
		qualified bool
		finding   string
		severity  FindingSeverity
	}{
		"unobserved unknown is informational": {
			status:    tunnel.Status{State: tunnel.StateUnknown, Observed: false},
			qualified: true,
			finding:   "backend_tunnel_status_unobserved",
			severity:  SeverityInfo,
		},
		"authoritative up is informational": {
			status:    tunnel.Status{State: tunnel.StateUp, Observed: true},
			qualified: true,
			finding:   "backend_tunnel_status_up",
			severity:  SeverityInfo,
		},
		"authoritative down blocks": {
			status:    tunnel.Status{State: tunnel.StateDown, Observed: true},
			qualified: false,
			finding:   "backend_tunnel_status_not_up",
			severity:  SeverityBlock,
		},
		"authoritative unknown blocks": {
			status:    tunnel.Status{State: tunnel.StateUnknown, Observed: true},
			qualified: false,
			finding:   "backend_tunnel_status_not_up",
			severity:  SeverityBlock,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			plan := (Planner{}).Plan(safeInventory(), fullTunnelInspection(test.status))
			if plan.ReadOnlyQualified != test.qualified || !plan.ApplyBlocked || plan.Ready {
				t.Fatalf("status semantics = %#v", plan)
			}
			assertFinding(t, plan, test.finding, test.severity)
		})
	}
}

func TestPlannerBlocksEndpointCurrentlyRoutedThroughRedShield(t *testing.T) {
	inventory := safeInventory()
	inventory.Routes = append(inventory.Routes, Route{
		Family:          FamilyIPv4,
		Destination:     "203.0.113.5/32",
		InterfaceIndex:  21,
		InterfaceGUID:   testRedShieldGUID,
		RouteMetric:     0,
		InterfaceMetric: 1,
		Metric:          1,
		State:           routeStateAlive,
	})
	plan := (Planner{}).Plan(inventory, fullTunnelInspection(tunnel.Status{State: tunnel.StateUnknown, Observed: false}))

	if plan.ReadOnlyQualified {
		t.Fatalf("endpoint routed through tunnel qualified: %#v", plan)
	}
	assertFinding(t, plan, "endpoint_direct_exception_missing", SeverityBlock)
	operation := findOperation(t, plan, OperationAddEndpointDirectException, "203.0.113.5/32")
	if operation.InterfaceIndex != 12 || operation.InterfaceGUID != testPhysicalGUID || operation.NextHop != "192.168.1.1" {
		t.Fatalf("direct exception does not target stable physical identity: %#v", operation)
	}
}

func TestPlannerDoesNotPromoteUnknownDefaultAdapterToPhysical(t *testing.T) {
	inventory := safeInventory()
	inventory.Adapters[0].Kind = AdapterOther
	inventory.Adapters[0].HardwareInterface = false

	plan := (Planner{}).Plan(inventory, fullTunnelInspection(tunnel.Status{State: tunnel.StateUnknown, Observed: false}))
	if plan.ReadOnlyQualified {
		t.Fatalf("unknown default adapter qualified as physical: %#v", plan)
	}
	assertFinding(t, plan, "default_route_adapter_unclassified", SeverityBlock)
	assertFinding(t, plan, "endpoint_direct_exception_missing", SeverityBlock)
	assertFinding(t, plan, "endpoint_direct_interface_identity_unresolved", SeverityBlock)
}

func TestPlannerBlocksMissingTunnelCiscoRoutesAndFailClosedFamilies(t *testing.T) {
	inventory := safeInventory()
	inventory.Adapters[1].Up = false
	inventory.Routes = removeRoutesForInterface(inventory.Routes, 31)
	inspection := fullTunnelInspection(tunnel.Status{State: tunnel.StateUnknown, Observed: false})
	inspection.Metadata.IPv4FullTunnel = false
	inspection.Metadata.IPv6FullTunnel = false

	plan := (Planner{}).Plan(inventory, inspection)
	if plan.ReadOnlyQualified || plan.LocalTunnelStatus.State != LocalTunnelDown {
		t.Fatalf("unsafe inventory unexpectedly qualified: %#v", plan)
	}
	for _, code := range []string{
		"tunnel_not_active",
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
		if route.Family != FamilyIPv6 || route.InterfaceIndex != 12 {
			filtered = append(filtered, route)
		}
	}
	inventory.Routes = filtered
	inspection := fullTunnelInspection(tunnel.Status{State: tunnel.StateUnknown, Observed: false})
	inspection.Metadata.IPv6FullTunnel = false

	plan := (Planner{}).Plan(inventory, inspection)
	if !plan.ReadOnlyQualified || !plan.ApplyBlocked || plan.Ready {
		t.Fatalf("read-only plan should qualify without physical IPv6 default: %#v", plan)
	}
	assertFinding(t, plan, "ipv6_no_physical_default", SeverityInfo)
}

func TestPlannerBlocksUnsafeLocalTunnelBindingAndIdentity(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Inventory, *tunnel.Inspection)
		finding string
	}{
		"address mismatch": {
			mutate: func(_ *Inventory, inspection *tunnel.Inspection) {
				inspection.Metadata.InterfaceAddresses = []string{"10.99.0.2/32"}
			},
			finding: "tunnel_adapter_binding_mismatch",
		},
		"partial address mismatch": {
			mutate: func(_ *Inventory, inspection *tunnel.Inspection) {
				inspection.Metadata.InterfaceAddresses = []string{"10.20.30.2/24", "fd99::2/64"}
			},
			finding: "tunnel_adapter_binding_mismatch",
		},
		"two active adapters": {
			mutate: func(inventory *Inventory, _ *tunnel.Inspection) {
				inventory.Adapters = append(inventory.Adapters, Adapter{Name: "WireGuard second", Index: 41, InterfaceGUID: "44444444-4444-4444-8444-444444444444", Kind: AdapterRedShield, Up: true, Addresses: []string{"10.99.0.2/32"}})
			},
			finding: "tunnel_adapter_count_invalid",
		},
		"missing stable identity": {
			mutate: func(inventory *Inventory, _ *tunnel.Inspection) {
				inventory.Adapters[1].InterfaceGUID = ""
			},
			finding: "tunnel_interface_identity_unresolved",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			inventory := safeInventory()
			inspection := fullTunnelInspection(tunnel.Status{State: tunnel.StateUnknown, Observed: false})
			test.mutate(&inventory, &inspection)
			plan := (Planner{}).Plan(inventory, inspection)
			if plan.ReadOnlyQualified || plan.LocalTunnelStatus.State == LocalTunnelUp {
				t.Fatalf("unsafe tunnel state qualified: %#v", plan)
			}
			assertFinding(t, plan, test.finding, SeverityBlock)
		})
	}
}

func TestPlannerBlocksUnresolvedEndpointAndCiscoOperationIdentity(t *testing.T) {
	inventory := safeInventory()
	for index := range inventory.Routes {
		if inventory.Routes[index].Destination == "203.0.113.5/32" {
			inventory.Routes[index].InterfaceGUID = ""
		}
	}
	inventory.Adapters[2].InterfaceGUID = ""
	plan := (Planner{}).Plan(inventory, fullTunnelInspection(tunnel.Status{State: tunnel.StateUnknown, Observed: false}))

	if plan.ReadOnlyQualified {
		t.Fatalf("unresolved operation identity qualified: %#v", plan)
	}
	assertFinding(t, plan, "endpoint_route_interface_identity_unresolved", SeverityBlock)
	assertFinding(t, plan, "cisco_interface_identity_unresolved", SeverityBlock)
	for _, operation := range plan.Operations {
		if operation.Kind == OperationPreserveCiscoRoute {
			t.Fatalf("Cisco operation without stable identity emitted: %#v", operation)
		}
	}
}

func TestPlannerBlocksPartialInventoryCapabilities(t *testing.T) {
	inventory := safeInventory()
	inventory.RouteSnapshotAuthoritative = false
	inventory.DNSPolicyObserved = false
	plan := (Planner{}).Plan(inventory, fullTunnelInspection(tunnel.Status{State: tunnel.StateUnknown, Observed: false}))

	if plan.ReadOnlyQualified {
		t.Fatalf("partial inventory unexpectedly qualified: %#v", plan)
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
			{Name: "Ethernet", Index: 12, InterfaceGUID: testPhysicalGUID, Kind: AdapterPhysical, Up: true, Addresses: []string{"192.168.1.10/24", "2001:db8:1::10/64"}},
			{Name: "redlink", Index: 21, InterfaceGUID: testRedShieldGUID, Kind: AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32", "fd00::2/128"}},
			{Name: "Cisco Secure Client", Index: 31, InterfaceGUID: testCiscoGUID, Kind: AdapterCisco, Up: true, Addresses: []string{"172.16.0.2/32"}},
		},
		Routes: []Route{
			{Family: FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 12, InterfaceGUID: testPhysicalGUID, RouteMetric: 5, InterfaceMetric: 25, Metric: 30, State: routeStateAlive},
			{Family: FamilyIPv6, Destination: "::/0", NextHop: "fe80::1", InterfaceIndex: 12, InterfaceGUID: testPhysicalGUID, RouteMetric: 5, InterfaceMetric: 25, Metric: 30, State: routeStateAlive},
			{Family: FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceIndex: 12, InterfaceGUID: testPhysicalGUID, RouteMetric: 2, InterfaceMetric: 25, Metric: 27, State: routeStateAlive},
			{Family: FamilyIPv4, Destination: "10.50.0.0/16", NextHop: "0.0.0.0", InterfaceIndex: 31, InterfaceGUID: testCiscoGUID, RouteMetric: 1, InterfaceMetric: 1, Metric: 2, State: routeStateAlive},
		},
		DNSPolicy:                  DNSPolicy{ServerSets: []DNSServerSet{}, EffectiveNRPTRuleCount: 0},
		EndpointAddresses:          []string{"203.0.113.5"},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
}

func fullTunnelInspection(status tunnel.Status) tunnel.Inspection {
	return tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportAmneziaWG,
			Endpoint:           tunnel.Endpoint{Host: "vpn.example.test", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/24", "fd00::2/64"},
			IPv4FullTunnel:     true,
			IPv6FullTunnel:     true,
		},
		Status: status,
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
