package windows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

type Planner struct{}

func (Planner) Plan(inventory Inventory, inspection tunnel.Inspection) Preflight {
	plan := Preflight{
		LocalTunnelStatus: LocalTunnelStatus{State: LocalTunnelUnknown, Observed: true},
		Findings:          make([]Finding, 0),
		Operations:        make([]Operation, 0),
	}
	metadata := inspection.Metadata
	adapters := normalizedAdapters(inventory.Adapters)

	if !inventory.RouteSnapshotAuthoritative {
		plan.block("route_inventory_not_authoritative", "The current route snapshot is not authoritative enough for apply readiness.")
	}
	if !inventory.DNSPolicyObserved {
		plan.block("dns_policy_unobserved", "The effective Windows DNS policy has not been observed.")
	}
	if !inspection.Status.Observed {
		plan.info("backend_tunnel_status_unobserved", "Provider handshake health is not observed; local Windows tunnel status is evaluated separately.")
	} else if inspection.Status.State != tunnel.StateUp {
		plan.block("backend_tunnel_status_not_up", "The authoritatively observed provider tunnel state is not up.")
	} else {
		plan.info("backend_tunnel_status_up", "The provider tunnel status is authoritatively observed as up.")
	}
	matchedTunnelAdapters := planTunnelBinding(&plan, adapters, metadata)

	unclassifiedIPv6Default := planUnclassifiedDefaultRoutes(&plan, inventory.Routes, adapters)
	physicalDefaults := defaultRoutesByFamily(inventory.Routes, adapters, AdapterPhysical)
	endpointAddresses := endpointAddresses(metadata, inventory.EndpointAddresses)
	if len(endpointAddresses) == 0 {
		plan.block("endpoint_unresolved", "The provider endpoint has no resolved IP address.")
	} else {
		for _, endpoint := range endpointAddresses {
			planEndpointDirect(&plan, endpoint, inventory.Routes, adapters, physicalDefaults)
		}
	}

	planCiscoPreservation(&plan, inventory.Routes, adapters)
	planFailClosed(&plan, metadata, inventory.Routes, matchedTunnelAdapters, physicalDefaults, unclassifiedIPv6Default)

	plan.ReadOnlyQualified = !hasBlockingFinding(plan.Findings)
	plan.ApplyBlocked = true
	plan.Ready = false
	plan.info("windows_apply_unsupported", "P3.3 is read-only; Windows network mutation remains unsupported and blocked.")
	return plan
}

func planTunnelBinding(plan *Preflight, adapters []Adapter, metadata tunnel.Metadata) []Adapter {
	tunnelAdapters := activeAdapters(adapters, AdapterTunnel)
	switch len(tunnelAdapters) {
	case 0:
		plan.LocalTunnelStatus = LocalTunnelStatus{State: LocalTunnelDown, Observed: true}
		plan.block("tunnel_not_active", "No active WireGuard or AmneziaWG tunnel adapter was found.")
		return nil
	case 1:
		plan.info("tunnel_active", "Exactly one active tunnel adapter was found.")
	default:
		plan.block("tunnel_adapter_count_invalid", "More than one active tunnel adapter was found.")
		return nil
	}
	if tunnelAdapters[0].InterfaceGUID == "" {
		plan.block("tunnel_interface_identity_unresolved", "The active tunnel adapter has no stable Windows interface GUID.")
		return nil
	}

	if !adapterMatchesImportedAddresses(tunnelAdapters[0], metadata.InterfaceAddresses) {
		plan.block("tunnel_adapter_binding_mismatch", "The active tunnel adapter does not match the imported tunnel addresses.")
		return nil
	}
	plan.LocalTunnelStatus = LocalTunnelStatus{
		State:         LocalTunnelUp,
		Observed:      true,
		InterfaceGUID: tunnelAdapters[0].InterfaceGUID,
	}
	plan.info("tunnel_adapter_binding_matched", "The active tunnel adapter matches the imported tunnel addresses.")
	return []Adapter{tunnelAdapters[0]}
}

func adapterMatchesImportedAddresses(adapter Adapter, imported []string) bool {
	importedAddresses := normalizedInterfaceAddresses(imported)
	if len(importedAddresses) == 0 {
		return false
	}
	adapterAddresses := normalizedInterfaceAddresses(adapter.Addresses)
	for address := range importedAddresses {
		if _, matched := adapterAddresses[address]; !matched {
			return false
		}
	}
	return true
}

func normalizedInterfaceAddresses(values []string) map[netip.Addr]struct{} {
	result := make(map[netip.Addr]struct{}, len(values))
	for _, value := range values {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Zone() == "" {
			result[prefix.Addr().Unmap()] = struct{}{}
			continue
		}
		if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
			result[address.Unmap()] = struct{}{}
		}
	}
	return result
}

func planEndpointDirect(plan *Preflight, endpoint netip.Addr, routes []Route, adapters []Adapter, physicalDefaults map[AddressFamily]Route) {
	family := addressFamily(endpoint)
	hostPrefix := netip.PrefixFrom(endpoint, endpoint.BitLen()).String()
	effective, routeFound, routeAmbiguous := effectiveRouteRecord(endpoint, routes)
	adapter, adapterFound := adapterForRoute(effective, adapters)
	if routeAmbiguous {
		plan.block("endpoint_route_ambiguous", "More than one equally preferred route can carry the provider endpoint.")
	}
	if routeFound && (effective.InterfaceGUID == "" || !adapterFound) {
		plan.block("endpoint_route_interface_identity_unresolved", "The effective provider-endpoint route has no stable Windows interface identity.")
	}
	if routeFound && adapterFound && !adapter.Up {
		plan.block("endpoint_route_adapter_not_up", "The effective provider-endpoint route belongs to an adapter that is not operationally up.")
	}
	if routeFound && adapterFound && adapter.Up && adapter.Kind == AdapterPhysical {
		prefix, err := netip.ParsePrefix(effective.Destination)
		if err == nil && prefix.Bits() == endpoint.BitLen() {
			if effective.InterfaceGUID == "" {
				return
			}
			plan.info("endpoint_direct_exception_present", "The provider endpoint has a dedicated route through the physical adapter.")
			return
		}
	}

	plan.block("endpoint_direct_exception_missing", "The provider endpoint is not protected by a dedicated physical-adapter route.")
	operation := Operation{Kind: OperationAddEndpointDirectException, Family: family, Destination: hostPrefix}
	physicalDefault, ok := physicalDefaults[family]
	if !ok || physicalDefault.InterfaceGUID == "" {
		plan.block("endpoint_direct_interface_identity_unresolved", "No operational physical default route with a stable Windows interface GUID is available for an endpoint exception.")
		return
	}
	operation.NextHop = physicalDefault.NextHop
	operation.InterfaceIndex = physicalDefault.InterfaceIndex
	operation.InterfaceGUID = physicalDefault.InterfaceGUID
	plan.Operations = append(plan.Operations, operation)
}

func planCiscoPreservation(plan *Preflight, routes []Route, adapters []Adapter) {
	ciscoAdapters := activeAdapters(adapters, AdapterCisco)
	if len(ciscoAdapters) == 0 {
		plan.info("cisco_not_active", "No active Cisco adapter requires route preservation.")
		return
	}
	for _, adapter := range ciscoAdapters {
		if adapter.InterfaceGUID == "" {
			plan.block("cisco_interface_identity_unresolved", "An active Cisco adapter has no stable Windows interface GUID.")
			continue
		}
		preserved := 0
		for _, route := range routes {
			if route.State != routeStateAlive || !routeUsesAdapter(route, adapter) {
				continue
			}
			plan.Operations = append(plan.Operations, Operation{
				Kind:           OperationPreserveCiscoRoute,
				Family:         route.Family,
				Destination:    route.Destination,
				NextHop:        route.NextHop,
				InterfaceIndex: adapter.Index,
				InterfaceGUID:  adapter.InterfaceGUID,
			})
			preserved++
		}
		if preserved == 0 {
			plan.block("cisco_routes_unresolved", "An active Cisco adapter has no attributable routes to preserve.")
		} else {
			plan.info("cisco_routes_identified", "Active Cisco routes were identified for preservation.")
		}
	}
}

func planFailClosed(plan *Preflight, metadata tunnel.Metadata, routes []Route, redShieldAdapters []Adapter, physicalDefaults map[AddressFamily]Route, unclassifiedIPv6Default bool) {
	plan.Operations = append(plan.Operations, Operation{Kind: OperationEnforceFailClosed, Family: FamilyIPv4})
	if !metadata.IPv4FullTunnel {
		plan.block("ipv4_fail_closed_unresolved", "The imported config does not cover the IPv4 default prefix.")
	} else if !adaptersHaveFamily(redShieldAdapters, routes, FamilyIPv4) {
		plan.block("ipv4_fail_closed_unresolved", "The active RedShield adapter has no usable IPv4 path.")
	} else {
		plan.info("ipv4_fail_closed_ready", "IPv4 fail-closed prerequisites are present.")
	}

	_, physicalIPv6 := physicalDefaults[FamilyIPv6]
	if metadata.IPv6FullTunnel || physicalIPv6 {
		plan.Operations = append(plan.Operations, Operation{Kind: OperationEnforceFailClosed, Family: FamilyIPv6})
	}
	if physicalIPv6 && !metadata.IPv6FullTunnel {
		plan.block("ipv6_fail_closed_unresolved", "A physical IPv6 default route exists but the imported config does not cover the IPv6 default prefix.")
	} else if metadata.IPv6FullTunnel && !adaptersHaveFamily(redShieldAdapters, routes, FamilyIPv6) {
		plan.block("ipv6_fail_closed_unresolved", "The active RedShield adapter has no usable IPv6 path.")
	} else if metadata.IPv6FullTunnel {
		plan.info("ipv6_fail_closed_ready", "IPv6 fail-closed prerequisites are present.")
	} else if !unclassifiedIPv6Default {
		plan.info("ipv6_no_physical_default", "No physical IPv6 default route creates a direct leak path in this snapshot.")
	}
}

func planUnclassifiedDefaultRoutes(plan *Preflight, routes []Route, adapters []Adapter) bool {
	unclassifiedFamilies := make(map[AddressFamily]bool)
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || route.State != routeStateAlive || prefix.Bits() != 0 {
			continue
		}
		adapter, found := adapterForRoute(route, adapters)
		if found && adapter.Kind != AdapterOther {
			continue
		}
		if !unclassifiedFamilies[route.Family] {
			plan.block("default_route_adapter_unclassified", "A default route belongs to an adapter whose role cannot be classified safely.")
		}
		unclassifiedFamilies[route.Family] = true
	}
	return unclassifiedFamilies[FamilyIPv6]
}

func normalizedAdapters(input []Adapter) []Adapter {
	adapters := append([]Adapter(nil), input...)
	for index := range adapters {
		if adapters[index].Kind == "" {
			adapters[index].Kind = DetectAdapterKind(adapters[index].Name, adapters[index].Description)
		}
		if adapters[index].Kind == AdapterOther && adapters[index].HardwareInterface {
			adapters[index].Kind = AdapterPhysical
		}
	}
	return adapters
}

func activeAdapters(adapters []Adapter, kind AdapterKind) []Adapter {
	var result []Adapter
	for _, adapter := range adapters {
		if adapter.Up && adapter.Kind == kind {
			result = append(result, adapter)
		}
	}
	return result
}

func defaultRoutesByFamily(routes []Route, adapters []Adapter, kind AdapterKind) map[AddressFamily]Route {
	result := make(map[AddressFamily]Route)
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		adapter, found := adapterForRoute(route, adapters)
		if err != nil || route.State != routeStateAlive || prefix.Bits() != 0 || !found || !adapter.Up || adapter.Kind != kind {
			continue
		}
		current, exists := result[route.Family]
		if !exists || route.Metric < current.Metric {
			result[route.Family] = route
		}
	}
	return result
}

func effectiveRouteRecord(address netip.Addr, routes []Route) (Route, bool, bool) {
	var selected Route
	selectedBits := -1
	var selectedMetric uint64
	ambiguous := false
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || route.State != routeStateAlive || !prefix.Contains(address) {
			continue
		}
		if prefix.Bits() > selectedBits || prefix.Bits() == selectedBits && route.Metric < selectedMetric {
			selected = route
			selectedBits = prefix.Bits()
			selectedMetric = route.Metric
			ambiguous = false
			continue
		}
		if prefix.Bits() == selectedBits && route.Metric == selectedMetric && (route.InterfaceIndex != selected.InterfaceIndex || route.InterfaceGUID != selected.InterfaceGUID || route.NextHop != selected.NextHop) {
			ambiguous = true
		}
	}
	return selected, selectedBits >= 0, ambiguous
}

func adapterForRoute(route Route, adapters []Adapter) (Adapter, bool) {
	for _, adapter := range adapters {
		if routeUsesAdapter(route, adapter) {
			return adapter, true
		}
	}
	return Adapter{}, false
}

func endpointAddresses(metadata tunnel.Metadata, resolved []string) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	if address, err := netip.ParseAddr(metadata.Endpoint.Host); err == nil && address.Zone() == "" {
		seen[address.Unmap()] = struct{}{}
	}
	for _, value := range resolved {
		address, err := netip.ParseAddr(value)
		if err == nil && address.Zone() == "" {
			seen[address.Unmap()] = struct{}{}
		}
	}
	result := make([]netip.Addr, 0, len(seen))
	for address := range seen {
		result = append(result, address)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Compare(result[right]) < 0 })
	return result
}

func adaptersHaveFamily(adapters []Adapter, routes []Route, family AddressFamily) bool {
	for _, adapter := range adapters {
		for _, value := range adapter.Addresses {
			prefix, err := netip.ParsePrefix(value)
			if err == nil && addressFamily(prefix.Addr()) == family {
				return true
			}
		}
		for _, route := range routes {
			if route.Family == family && route.State == routeStateAlive && routeUsesAdapter(route, adapter) {
				return true
			}
		}
	}
	return false
}

func addressFamily(address netip.Addr) AddressFamily {
	if address.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

func hasBlockingFinding(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Severity == SeverityBlock {
			return true
		}
	}
	return false
}

func (plan *Preflight) block(code, message string) {
	plan.Findings = append(plan.Findings, Finding{Code: code, Severity: SeverityBlock, Message: message})
}

func (plan *Preflight) info(code, message string) {
	plan.Findings = append(plan.Findings, Finding{Code: code, Severity: SeverityInfo, Message: message})
}

type MutationOperation string

const MutationApplyPreflight MutationOperation = "apply_preflight"

type UnsupportedMutationError struct {
	operation MutationOperation
}

func (err *UnsupportedMutationError) Error() string {
	return fmt.Sprintf("Windows network mutation is unsupported: %s", err.operation)
}

func (err *UnsupportedMutationError) Operation() MutationOperation {
	return err.operation
}

type ReadOnlyController struct{}

func (ReadOnlyController) Apply(context.Context, Preflight) error {
	return &UnsupportedMutationError{operation: MutationApplyPreflight}
}

func IsUnsupportedMutation(err error, operation MutationOperation) bool {
	var unsupported *UnsupportedMutationError
	return errors.As(err, &unsupported) && unsupported.Operation() == operation
}
