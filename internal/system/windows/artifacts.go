package windows

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

const (
	ArtifactVersion     = 1
	ArtifactOwner       = "home-gateway/windows"
	ReservedRouteMetric = uint32(42751)
	maxArtifactBytes    = 1 << 20
	maxDNSRules         = 32
	maxManagedRoutes    = 256
	maxFirewallRules    = 256
	// Routes are intentionally transient and must be reconciled before policy
	// activation after boot. The fail-closed firewall remains persistent.
	RoutePolicyStore    = "ActiveStore"
	RouteProtocol       = "NetMgmt"
	FirewallPolicyStore = "PersistentStore"
)

const (
	RouteRoleEndpointDirect = "endpoint-direct"
	RouteRoleVPNClass       = "vpn-class"
)

type RoutesArtifact struct {
	Version          int                    `json:"version"`
	Owner            string                 `json:"owner"`
	Revision         string                 `json:"revision"`
	DirectAssertions []DirectRouteAssertion `json:"direct_assertions"`
	Routes           []ManagedRoute         `json:"routes"`
}

// DirectRouteAssertion describes a pre-existing provider/OS-owned endpoint
// host route. It is protected evidence only and is never added or removed.
type DirectRouteAssertion struct {
	Family         AddressFamily `json:"family"`
	Destination    string        `json:"destination"`
	NextHop        string        `json:"next_hop"`
	InterfaceGUID  string        `json:"interface_guid"`
	InterfaceIndex int           `json:"interface_index"`
}

type ManagedRoute struct {
	Role           string        `json:"role"`
	Family         AddressFamily `json:"family"`
	Destination    string        `json:"destination"`
	NextHop        string        `json:"next_hop"`
	InterfaceGUID  string        `json:"interface_guid"`
	InterfaceIndex int           `json:"interface_index"`
	Metric         uint32        `json:"metric"`
	PolicyStore    string        `json:"policy_store"`
	Protocol       string        `json:"protocol"`
	JournalOwned   bool          `json:"journal_owned"`
}

type FirewallArtifact struct {
	Version  int            `json:"version"`
	Owner    string         `json:"owner"`
	Revision string         `json:"revision"`
	Rules    []FirewallRule `json:"rules"`
}

type FirewallRule struct {
	Name           string        `json:"name"`
	Family         AddressFamily `json:"family"`
	RemoteCIDR     string        `json:"remote_cidr"`
	Action         string        `json:"action"`
	Direction      string        `json:"direction"`
	InterfaceGUID  string        `json:"interface_guid"`
	InterfaceIndex int           `json:"interface_index"`
	PolicyStore    string        `json:"policy_store"`
	Group          string        `json:"group"`
	Description    string        `json:"description"`
}

type DNSArtifact struct {
	Version  int        `json:"version"`
	Owner    string     `json:"owner"`
	Revision string     `json:"revision"`
	Rules    []NRPTRule `json:"rules"`
}

type NRPTRule struct {
	LogicalID string `json:"logical_id"`
	// Name is explicitly serialized even before Windows assigns the native
	// NRPT identity. The fixed StrictMode PowerShell program must receive a
	// present empty property on first creation rather than a missing member.
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Namespace   string   `json:"namespace"`
	NameServers []string `json:"name_servers"`
	Comment     string   `json:"comment"`
}

type artifactSet struct {
	routes   RoutesArtifact
	sinks    SinkArtifact
	firewall FirewallArtifact
	dns      DNSArtifact
}

func parseArtifacts(revision string, routesData, sinksData, firewallData, dnsData []byte) (artifactSet, error) {
	var artifacts artifactSet
	if err := decodeStrict(routesData, &artifacts.routes); err != nil {
		return artifactSet{}, fmt.Errorf("invalid routes artifact: %w", err)
	}
	if err := decodeStrict(sinksData, &artifacts.sinks); err != nil {
		return artifactSet{}, fmt.Errorf("invalid sinks artifact: %w", err)
	}
	if err := decodeStrict(firewallData, &artifacts.firewall); err != nil {
		return artifactSet{}, fmt.Errorf("invalid firewall artifact: %w", err)
	}
	if err := decodeStrict(dnsData, &artifacts.dns); err != nil {
		return artifactSet{}, fmt.Errorf("invalid DNS artifact: %w", err)
	}
	if err := artifacts.validate(revision); err != nil {
		return artifactSet{}, err
	}
	return artifacts, nil
}

func decodeStrict(data []byte, target any) error {
	return decodeStrictLimit(data, target, maxArtifactBytes)
}

func decodeStrictLimit(data []byte, target any, limit int) error {
	if len(data) == 0 {
		return errors.New("artifact is empty")
	}
	if len(data) > limit {
		return errors.New("artifact exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content is forbidden")
	}
	return nil
}

func (artifacts artifactSet) validate(revision string) error {
	for _, header := range []struct {
		label    string
		version  int
		owner    string
		revision string
	}{
		{"routes", artifacts.routes.Version, artifacts.routes.Owner, artifacts.routes.Revision},
		{"sinks", artifacts.sinks.Version, artifacts.sinks.Owner, artifacts.sinks.Revision},
		{"firewall", artifacts.firewall.Version, artifacts.firewall.Owner, artifacts.firewall.Revision},
		{"DNS", artifacts.dns.Version, artifacts.dns.Owner, artifacts.dns.Revision},
	} {
		if header.version != ArtifactVersion || header.owner != ArtifactOwner || header.revision != revision {
			return fmt.Errorf("%s artifact header does not match the runtime contract", header.label)
		}
	}

	if len(artifacts.routes.Routes)+len(artifacts.routes.DirectAssertions) > maxManagedRoutes {
		return errors.New("routes artifact exceeds the route limit")
	}
	seenRoutes := make(map[string]struct{}, len(artifacts.routes.Routes))
	endpointCount := 0
	seenAssertions := make(map[string]struct{}, len(artifacts.routes.DirectAssertions))
	for index, assertion := range artifacts.routes.DirectAssertions {
		prefix, err := parseExplicitPrefix(assertion.Family, assertion.Destination)
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
			return fmt.Errorf("direct assertion %d is not a canonical host route", index)
		}
		nextHop, err := netip.ParseAddr(assertion.NextHop)
		if err != nil || nextHop.Zone() != "" || nextHop.Is4In6() || addressFamily(nextHop) != assertion.Family {
			return fmt.Errorf("direct assertion %d has an invalid next hop", index)
		}
		if _, err := canonicalGUID(assertion.InterfaceGUID); err != nil || assertion.InterfaceIndex <= 0 {
			return fmt.Errorf("direct assertion %d has no stable interface identity", index)
		}
		key := directAssertionKey(assertion)
		if _, exists := seenAssertions[key]; exists {
			return fmt.Errorf("direct assertion %d duplicates an exact route", index)
		}
		seenAssertions[key] = struct{}{}
		endpointCount++
	}
	for index := range artifacts.routes.Routes {
		route := &artifacts.routes.Routes[index]
		prefix, err := parseExplicitPrefix(route.Family, route.Destination)
		if err != nil {
			return fmt.Errorf("route %d: %w", index, err)
		}
		nextHop, err := netip.ParseAddr(route.NextHop)
		if err != nil || nextHop.Zone() != "" || nextHop.Is4In6() || addressFamily(nextHop) != route.Family {
			return fmt.Errorf("route %d has an invalid next hop", index)
		}
		if _, err := canonicalGUID(route.InterfaceGUID); err != nil || route.InterfaceIndex <= 0 {
			return fmt.Errorf("route %d has no stable interface identity", index)
		}
		if route.Metric != ReservedRouteMetric || route.PolicyStore != RoutePolicyStore || route.Protocol != RouteProtocol || !route.JournalOwned {
			return fmt.Errorf("route %d lacks reserved project ownership metadata", index)
		}
		switch route.Role {
		case RouteRoleEndpointDirect:
			if prefix.Bits() != prefix.Addr().BitLen() {
				return fmt.Errorf("route %d endpoint exception is not a host route", index)
			}
			endpointCount++
		case RouteRoleVPNClass:
		default:
			return fmt.Errorf("route %d has an unsupported role", index)
		}
		key := routeTupleKey(*route)
		if _, exists := seenRoutes[key]; exists {
			return fmt.Errorf("route %d duplicates an exact route tuple", index)
		}
		seenRoutes[key] = struct{}{}
	}

	if len(artifacts.sinks.Routes) > maxManagedRoutes {
		return errors.New("sinks artifact exceeds the route limit")
	}
	seenSinks := make(map[string]struct{}, len(artifacts.sinks.Routes))
	sinkCoverage := make(map[string]int, len(artifacts.sinks.Routes))
	for index, route := range artifacts.sinks.Routes {
		prefix, err := parseExplicitPrefix(route.Family, route.Destination)
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
			return fmt.Errorf("sink route %d is not a canonical host route", index)
		}
		nextHop, err := netip.ParseAddr(route.NextHop)
		if err != nil || nextHop.Zone() != "" || nextHop.Is4In6() || addressFamily(nextHop) != route.Family || !nextHop.IsUnspecified() {
			return fmt.Errorf("sink route %d has an invalid next hop", index)
		}
		if route.InterfaceIndex != LoopbackInterfaceIndex || route.Metric != ReservedSinkMetric || route.PolicyStore != SinkPolicyStore || route.Protocol != RouteProtocol || !route.JournalOwned {
			return fmt.Errorf("sink route %d lacks reserved project ownership metadata", index)
		}
		key := sinkTupleKey(route)
		if _, exists := seenSinks[key]; exists {
			return fmt.Errorf("sink route %d duplicates an exact route tuple", index)
		}
		seenSinks[key] = struct{}{}
		sinkCoverage[string(route.Family)+"\x00"+route.Destination]++
	}
	vpnCoverage := make(map[string]int)
	for _, route := range artifacts.routes.Routes {
		if route.Role == RouteRoleVPNClass {
			vpnCoverage[string(route.Family)+"\x00"+route.Destination]++
		}
	}
	for key, count := range vpnCoverage {
		if count != 1 || sinkCoverage[key] != 1 {
			return errors.New("VPN-class route lacks exact persistent sink coverage")
		}
	}
	for key, count := range sinkCoverage {
		if count != 1 || vpnCoverage[key] != 1 {
			return errors.New("sink route has no exact VPN-class route coverage")
		}
	}

	if len(artifacts.firewall.Rules) > maxFirewallRules {
		return errors.New("firewall artifact exceeds the rule limit")
	}
	seenFirewall := make(map[string]struct{}, len(artifacts.firewall.Rules))
	firewallCoverage := make(map[string]int, len(artifacts.firewall.Rules))
	seenFirewallBinding := make(map[string]struct{}, len(artifacts.firewall.Rules))
	for index, rule := range artifacts.firewall.Rules {
		if _, err := parseExplicitPrefix(rule.Family, rule.RemoteCIDR); err != nil {
			return fmt.Errorf("firewall rule %d: %w", index, err)
		}
		if _, err := canonicalGUID(rule.InterfaceGUID); err != nil || rule.InterfaceIndex <= 0 || rule.Action != "block" || rule.Direction != "outbound" || rule.PolicyStore != FirewallPolicyStore || rule.Name != FirewallRuleName(revision, rule.Family, rule.RemoteCIDR, rule.InterfaceGUID) || rule.Group != ownershipGroup(revision) || rule.Description != ownershipDescription(revision) {
			return fmt.Errorf("firewall rule %d lacks exact ownership markers", index)
		}
		if _, exists := seenFirewall[rule.Name]; exists {
			return fmt.Errorf("firewall rule %d duplicates a stable name", index)
		}
		seenFirewall[rule.Name] = struct{}{}
		firewallCoverage[string(rule.Family)+"\x00"+rule.RemoteCIDR]++
		binding := string(rule.Family) + "\x00" + rule.RemoteCIDR + "\x00" + rule.InterfaceGUID
		if _, exists := seenFirewallBinding[binding]; exists {
			return fmt.Errorf("firewall rule %d duplicates a fallback-interface binding", index)
		}
		seenFirewallBinding[binding] = struct{}{}
	}
	for index, route := range artifacts.routes.Routes {
		if route.Role == RouteRoleVPNClass && firewallCoverage[string(route.Family)+"\x00"+route.Destination] == 0 {
			return fmt.Errorf("VPN-class route %d lacks fail-closed firewall coverage", index)
		}
	}
	for key := range firewallCoverage {
		matched := slices.ContainsFunc(artifacts.routes.Routes, func(route ManagedRoute) bool {
			return route.Role == RouteRoleVPNClass && string(route.Family)+"\x00"+route.Destination == key
		})
		if !matched {
			return errors.New("firewall rule has no exact VPN-class route coverage")
		}
	}

	if len(artifacts.dns.Rules) > maxDNSRules {
		return errors.New("DNS artifact exceeds the rule limit")
	}
	seenNamespaces := make(map[string]struct{}, len(artifacts.dns.Rules))
	seenDNSNames := make(map[string]struct{}, len(artifacts.dns.Rules))
	for index, rule := range artifacts.dns.Rules {
		if !validDNSNamespace(rule.Namespace) || rule.LogicalID == "" || rule.Name != "" || rule.DisplayName == "" || rule.Comment != ownershipDescription(revision) {
			return fmt.Errorf("DNS rule %d lacks a bounded namespace or exact ownership markers", index)
		}
		if len(rule.NameServers) == 0 || len(rule.NameServers) > 4 {
			return fmt.Errorf("DNS rule %d has an invalid nameserver count", index)
		}
		for _, server := range rule.NameServers {
			address, err := netip.ParseAddr(server)
			if err != nil || address.Zone() != "" || address.Is4In6() {
				return fmt.Errorf("DNS rule %d has an invalid nameserver", index)
			}
		}
		namespace := strings.ToLower(rule.Namespace)
		if _, exists := seenNamespaces[namespace]; exists {
			return fmt.Errorf("DNS rule %d duplicates a namespace", index)
		}
		if _, exists := seenDNSNames[rule.LogicalID]; exists {
			return fmt.Errorf("DNS rule %d duplicates an exact rule identity", index)
		}
		seenNamespaces[namespace] = struct{}{}
		seenDNSNames[rule.LogicalID] = struct{}{}
	}
	if endpointCount == 0 && (hasVPNRoutes(artifacts.routes.Routes) || len(artifacts.firewall.Rules) != 0 || len(artifacts.dns.Rules) != 0) {
		return errors.New("an endpoint-direct host route is required before selective policy")
	}
	return nil
}

func parseExplicitPrefix(family AddressFamily, value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("prefix is malformed or non-canonical")
	}
	if family != FamilyIPv4 && family != FamilyIPv6 || addressFamily(prefix.Addr()) != family {
		return netip.Prefix{}, errors.New("prefix family does not match")
	}
	if prefix.Bits() == 0 {
		return netip.Prefix{}, errors.New("global default routes and rules are forbidden")
	}
	return prefix, nil
}

func validDNSNamespace(namespace string) bool {
	if len(namespace) < 2 || len(namespace) > 253 || !strings.HasPrefix(namespace, ".") || strings.HasSuffix(namespace, ".") {
		return false
	}
	for _, label := range strings.Split(namespace[1:], ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func ownershipGroup(revision string) string       { return ArtifactOwner + "/" + revision }
func ownershipDescription(revision string) string { return ArtifactOwner + ";revision=" + revision }

// FirewallRuleName is revision-qualified and content-addressed so an OS rule
// identity cannot alias a rule from another revision or CIDR.
func FirewallRuleName(revision string, family AddressFamily, remoteCIDR, interfaceGUID string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{revision, string(family), remoteCIDR, interfaceGUID}, "\x00")))
	return "home-gateway-" + revision + "-" + fmt.Sprintf("%x", digest[:12])
}

func routeTupleKey(route ManagedRoute) string {
	return strings.Join([]string{string(route.Family), route.Destination, route.NextHop, route.InterfaceGUID, fmt.Sprint(route.InterfaceIndex), fmt.Sprint(route.Metric), route.PolicyStore, route.Protocol}, "\x00")
}

func sinkTupleKey(route SinkRoute) string {
	return strings.Join([]string{string(route.Family), route.Destination, route.NextHop, fmt.Sprint(route.InterfaceIndex), fmt.Sprint(route.Metric), route.PolicyStore, route.Protocol}, "\x00")
}

func directAssertionKey(assertion DirectRouteAssertion) string {
	return strings.Join([]string{string(assertion.Family), assertion.Destination, assertion.NextHop, assertion.InterfaceGUID, fmt.Sprint(assertion.InterfaceIndex)}, "\x00")
}

func hasVPNRoutes(routes []ManagedRoute) bool {
	return slices.ContainsFunc(routes, func(route ManagedRoute) bool { return route.Role == RouteRoleVPNClass })
}
