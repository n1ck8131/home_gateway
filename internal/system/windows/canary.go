package windows

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
	"github.com/vsevo/home-gateway/internal/tunnel"
)

const (
	maxCanaryTargets          = 8
	maxCanaryFallbackAdapters = maxAdapters
	CanaryDNSNamespace        = ".one.one.one.one"
	CanaryIsolationBlockCode  = "canary_target_isolation"
)

type CanaryTargetSource string

const (
	CanaryTargetSourceExplicit    CanaryTargetSource = "explicit_target"
	CanaryTargetSourceImportedDNS CanaryTargetSource = "imported_dns"
)

type CanaryProtectedClass string

const (
	CanaryProtectedClassProviderEndpoint CanaryProtectedClass = "provider_endpoint"
	CanaryProtectedClassCiscoPrefix      CanaryProtectedClass = "cisco_prefix"
)

type CanaryIsolationBlock struct {
	TargetSource        CanaryTargetSource   `json:"target_source"`
	ProtectedClass      CanaryProtectedClass `json:"protected_class"`
	Family              AddressFamily        `json:"family"`
	AffectedTargetCount int                  `json:"affected_target_count"`
}

type CanaryIsolationError struct {
	Blocks []CanaryIsolationBlock
}

func (*CanaryIsolationError) Error() string {
	return "canary target isolation failed"
}

func (err *CanaryIsolationError) RedactedBlocks() ([]CanaryIsolationBlock, bool) {
	if err == nil || len(err.Blocks) == 0 || len(err.Blocks) > maxCanaryTargets {
		return nil, false
	}
	previousRank := -1
	for _, block := range err.Blocks {
		rank, ok := canaryIsolationBlockRank(block)
		if !ok || block.AffectedTargetCount < 1 || block.AffectedTargetCount > maxManagedRoutes || rank <= previousRank {
			return nil, false
		}
		previousRank = rank
	}
	return append([]CanaryIsolationBlock(nil), err.Blocks...), true
}

func canaryIsolationBlockRank(block CanaryIsolationBlock) (int, bool) {
	var sourceRank, protectedRank, familyRank int
	switch block.TargetSource {
	case CanaryTargetSourceExplicit:
		sourceRank = 0
	case CanaryTargetSourceImportedDNS:
		sourceRank = 1
	default:
		return 0, false
	}
	switch block.ProtectedClass {
	case CanaryProtectedClassProviderEndpoint:
		protectedRank = 0
	case CanaryProtectedClassCiscoPrefix:
		protectedRank = 1
	default:
		return 0, false
	}
	switch block.Family {
	case FamilyIPv4:
		familyRank = 0
	case FamilyIPv6:
		familyRank = 1
	default:
		return 0, false
	}
	return sourceRank*4 + protectedRank*2 + familyRank, true
}

type canaryTarget struct {
	prefix      netip.Prefix
	explicit    bool
	importedDNS bool
}

// CanaryRequest describes a deliberately narrow P3.5 field candidate. Target
// addresses are restricted to exact public host routes so a diagnostic canary
// cannot accidentally turn into a broad production policy.
type CanaryRequest struct {
	Revision        string
	TargetAddresses []string
	DNSNamespace    string
}

type CanaryPlan struct {
	Candidate              apply.Candidate
	QualifiedEndpoints     []string
	TargetPrefixes         []string
	ConfigSHA256           string
	StateRootIdentity      string
	WatchdogTimeoutSeconds int
	RouteCount             int
	SinkCount              int
	FirewallRuleCount      int
	DNSRuleCount           int
}

type artifactIdentity struct {
	Type   string        `json:"type"`
	Family AddressFamily `json:"family,omitempty"`
	Role   string        `json:"role,omitempty"`
	SHA256 string        `json:"sha256"`
}

type targetClassCounts struct {
	QualifiedEndpoints int `json:"qualified_endpoints"`
	Routes             int `json:"routes"`
	Sinks              int `json:"sinks"`
	Firewall           int `json:"firewall"`
	NRPT               int `json:"nrpt"`
}

type canaryCandidateEnvelope struct {
	Schema                      string             `json:"schema"`
	StateRootIdentity           string             `json:"state_root_identity"`
	RevisionID                  string             `json:"revision_id"`
	ConfigSHA256                string             `json:"config_sha256"`
	QualifiedEndpointIdentities []artifactIdentity `json:"qualified_endpoint_identities"`
	RouteIdentities             []artifactIdentity `json:"route_identities"`
	SinkIdentities              []artifactIdentity `json:"sink_identities"`
	FirewallIdentities          []artifactIdentity `json:"firewall_identities"`
	NRPTIdentities              []artifactIdentity `json:"nrpt_identities"`
	TargetClassCounts           targetClassCounts  `json:"target_class_counts"`
	WatchdogTimeoutSeconds      int                `json:"watchdog_timeout_seconds"`
}

func stateRootIdentity(stateRoot string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(stateRoot)))
	return fmt.Sprintf("%x", digest[:])
}

func StateRootIdentity(stateRoot string) string { return stateRootIdentity(stateRoot) }

func exactArtifactIdentity(kind string, family AddressFamily, role string, value any) artifactIdentity {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return artifactIdentity{Type: kind, Family: family, Role: role, SHA256: fmt.Sprintf("%x", digest[:])}
}

func sortArtifactIdentities(values []artifactIdentity) {
	sort.Slice(values, func(i, j int) bool {
		left := strings.Join([]string{values[i].Type, string(values[i].Family), values[i].Role, values[i].SHA256}, "\x00")
		right := strings.Join([]string{values[j].Type, string(values[j].Family), values[j].Role, values[j].SHA256}, "\x00")
		return left < right
	})
}

func (plan CanaryPlan) candidateEnvelope() canaryCandidateEnvelope {
	artifacts, _ := parseArtifacts(plan.Candidate.RevisionID, plan.Candidate.Routes, plan.Candidate.Sinks, plan.Candidate.Firewall, plan.Candidate.DNS)
	envelope := canaryCandidateEnvelope{
		Schema:                 "home-gateway/windows-canary-candidate/v1",
		StateRootIdentity:      plan.StateRootIdentity,
		RevisionID:             plan.Candidate.RevisionID,
		ConfigSHA256:           plan.ConfigSHA256,
		WatchdogTimeoutSeconds: plan.WatchdogTimeoutSeconds,
	}
	for _, endpoint := range plan.QualifiedEndpoints {
		family := AddressFamily("")
		if prefix, err := netip.ParsePrefix(endpoint); err == nil {
			family = addressFamily(prefix.Addr())
		}
		envelope.QualifiedEndpointIdentities = append(envelope.QualifiedEndpointIdentities, exactArtifactIdentity("qualified-endpoint", family, RouteRoleEndpointDirect, endpoint))
	}
	for _, route := range artifacts.routes.Routes {
		envelope.RouteIdentities = append(envelope.RouteIdentities, exactArtifactIdentity("route", route.Family, route.Role, route))
	}
	for _, sink := range artifacts.sinks.Routes {
		envelope.SinkIdentities = append(envelope.SinkIdentities, exactArtifactIdentity("sink", sink.Family, "fail-closed", sink))
	}
	for _, rule := range artifacts.firewall.Rules {
		envelope.FirewallIdentities = append(envelope.FirewallIdentities, exactArtifactIdentity("firewall", rule.Family, rule.Action, rule))
	}
	for _, rule := range artifacts.dns.Rules {
		envelope.NRPTIdentities = append(envelope.NRPTIdentities, exactArtifactIdentity("nrpt", "", "dns", rule))
	}
	for _, identities := range [][]artifactIdentity{envelope.QualifiedEndpointIdentities, envelope.RouteIdentities, envelope.SinkIdentities, envelope.FirewallIdentities, envelope.NRPTIdentities} {
		sortArtifactIdentities(identities)
	}
	envelope.TargetClassCounts = targetClassCounts{
		QualifiedEndpoints: len(envelope.QualifiedEndpointIdentities),
		Routes:             len(envelope.RouteIdentities),
		Sinks:              len(envelope.SinkIdentities),
		Firewall:           len(envelope.FirewallIdentities),
		NRPT:               len(envelope.NRPTIdentities),
	}
	return envelope
}

func (plan CanaryPlan) CandidateSHA256() string {
	data, _ := json.Marshal(plan.candidateEnvelope())
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

// RedactedCandidateEnvelope exposes only stable hashes and class counts for
// operator review. Exact network values remain private to the candidate.
func (plan CanaryPlan) RedactedCandidateEnvelope() any { return plan.candidateEnvelope() }

func (plan CanaryPlan) ConfirmationChallenge(stateRoot string) string {
	plan.StateRootIdentity = stateRootIdentity(stateRoot)
	return "P35-APPLY-" + strings.ToUpper(plan.CandidateSHA256()[:16])
}

// BuildCanaryPlan converts an already-qualified, read-only Windows snapshot
// into strict structured artifacts. It performs no filesystem or network I/O.
func BuildCanaryPlan(inventory Inventory, inspection tunnel.Inspection, request CanaryRequest) (CanaryPlan, error) {
	if !validCanaryRevision(request.Revision) {
		return CanaryPlan{}, errors.New("canary revision is invalid")
	}
	if len(request.TargetAddresses) == 0 || len(request.TargetAddresses) > maxCanaryTargets {
		return CanaryPlan{}, fmt.Errorf("canary requires between 1 and %d public target addresses", maxCanaryTargets)
	}
	if request.DNSNamespace != CanaryDNSNamespace {
		return CanaryPlan{}, errors.New("canary DNS namespace is not the dedicated diagnostic suffix")
	}
	if len(inspection.Metadata.DNS) == 0 {
		return CanaryPlan{}, errors.New("imported config has no DNS servers for the canary")
	}

	preflight := (Planner{}).Plan(inventory, inspection)
	if !preflight.ReadOnlyQualified {
		return CanaryPlan{}, errors.New("read-only Windows preflight is not qualified")
	}
	tunnel, err := canaryTunnelAdapter(inventory.Adapters, preflight.LocalTunnelStatus)
	if err != nil {
		return CanaryPlan{}, err
	}
	assertions, qualified, err := canaryEndpointAssertions(inventory, inspection)
	if err != nil {
		return CanaryPlan{}, err
	}
	targets, err := canaryTargetPrefixes(request.TargetAddresses, inspection.Metadata)
	if err != nil {
		return CanaryPlan{}, err
	}
	targets, dnsServers, err := addCanaryDNSTargets(targets, inspection.Metadata)
	if err != nil {
		return CanaryPlan{}, err
	}
	if err := validateCanaryTargetIsolation(targets, assertions, inventory); err != nil {
		return CanaryPlan{}, err
	}

	if _, err := canaryFallbackDefaults(inventory, tunnel); err != nil {
		return CanaryPlan{}, err
	}
	failClosedAdapters, err := canaryFailClosedAdapters(inventory, tunnel)
	if err != nil {
		return CanaryPlan{}, err
	}
	routes := make([]ManagedRoute, 0, len(targets))
	sinks := make([]SinkRoute, 0, len(targets))
	if len(targets)*len(failClosedAdapters) > maxFirewallRules {
		return CanaryPlan{}, errors.New("canary fail-closed rule set exceeds the bounded limit")
	}
	firewall := make([]FirewallRule, 0, len(targets)*len(failClosedAdapters))
	for _, target := range targets {
		prefix := target.prefix
		family := addressFamily(prefix.Addr())
		nextHop := "0.0.0.0"
		if family == FamilyIPv6 {
			nextHop = "::"
		}
		route := ManagedRoute{
			Role:           RouteRoleVPNClass,
			Family:         family,
			Destination:    prefix.String(),
			NextHop:        nextHop,
			InterfaceGUID:  tunnel.InterfaceGUID,
			InterfaceIndex: tunnel.Index,
			Metric:         ReservedRouteMetric,
			PolicyStore:    RoutePolicyStore,
			Protocol:       RouteProtocol,
			JournalOwned:   true,
		}
		routes = append(routes, route)
		sinks = append(sinks, sinkForVPNRoute(route))
		for _, fallback := range failClosedAdapters {
			firewall = append(firewall, FirewallRule{
				Name:           FirewallRuleName(request.Revision, family, prefix.String(), fallback.InterfaceGUID),
				Family:         family,
				RemoteCIDR:     prefix.String(),
				Action:         "block",
				Direction:      "outbound",
				InterfaceGUID:  fallback.InterfaceGUID,
				InterfaceIndex: fallback.Index,
				PolicyStore:    FirewallPolicyStore,
				Group:          ownershipGroup(request.Revision),
				Description:    ownershipDescription(request.Revision),
			})
		}
	}

	dnsRule := NRPTRule{
		LogicalID:   "p35-canary-dns",
		DisplayName: "Home Gateway P3.5 canary DNS",
		Namespace:   strings.ToLower(request.DNSNamespace),
		NameServers: dnsServers,
		Comment:     ownershipDescription(request.Revision),
	}
	artifacts := artifactSet{
		routes: RoutesArtifact{
			Version:          ArtifactVersion,
			Owner:            ArtifactOwner,
			Revision:         request.Revision,
			DirectAssertions: assertions,
			Routes:           routes,
		},
		sinks: SinkArtifact{
			Version:  ArtifactVersion,
			Owner:    ArtifactOwner,
			Revision: request.Revision,
			Routes:   sinks,
		},
		firewall: FirewallArtifact{
			Version:  ArtifactVersion,
			Owner:    ArtifactOwner,
			Revision: request.Revision,
			Rules:    firewall,
		},
		dns: DNSArtifact{
			Version:  ArtifactVersion,
			Owner:    ArtifactOwner,
			Revision: request.Revision,
			Rules:    []NRPTRule{dnsRule},
		},
	}
	if err := artifacts.validate(request.Revision); err != nil {
		return CanaryPlan{}, fmt.Errorf("validate canary artifacts: %w", err)
	}
	routesData, err := json.Marshal(artifacts.routes)
	if err != nil {
		return CanaryPlan{}, err
	}
	firewallData, err := json.Marshal(artifacts.firewall)
	if err != nil {
		return CanaryPlan{}, err
	}
	sinksData, err := json.Marshal(artifacts.sinks)
	if err != nil {
		return CanaryPlan{}, err
	}
	dnsData, err := json.Marshal(artifacts.dns)
	if err != nil {
		return CanaryPlan{}, err
	}
	targetStrings := make([]string, 0, len(targets))
	for _, target := range targets {
		targetStrings = append(targetStrings, target.prefix.String())
	}
	return CanaryPlan{
		Candidate: apply.Candidate{
			RevisionID: request.Revision,
			Routes:     routesData,
			Sinks:      sinksData,
			Firewall:   firewallData,
			DNS:        dnsData,
		},
		QualifiedEndpoints:     qualified,
		TargetPrefixes:         targetStrings,
		WatchdogTimeoutSeconds: 120,
		RouteCount:             len(routes),
		SinkCount:              len(sinks),
		FirewallRuleCount:      len(firewall),
		DNSRuleCount:           1,
	}, nil
}

func validateCanaryTargetIsolation(targets []canaryTarget, assertions []DirectRouteAssertion, inventory Inventory) error {
	providerProtected := make([]netip.Prefix, 0, len(assertions))
	for _, assertion := range assertions {
		prefix, err := netip.ParsePrefix(assertion.Destination)
		if err != nil {
			return errors.New("canary provider endpoint assertion is invalid")
		}
		providerProtected = append(providerProtected, prefix)
	}
	ciscoProtected := make([]netip.Prefix, 0, len(inventory.Routes))
	adapters := normalizedAdapters(inventory.Adapters)
	for _, route := range inventory.Routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		adapter, found := adapterForRoute(route, adapters)
		if err != nil || prefix.Bits() == 0 || !found || adapter.Kind != AdapterCisco {
			continue
		}
		ciscoProtected = append(ciscoProtected, prefix)
	}
	type bucketKey struct {
		source    CanaryTargetSource
		protected CanaryProtectedClass
		family    AddressFamily
	}
	counts := make(map[bucketKey]int)
	for _, target := range targets {
		family := addressFamily(target.prefix.Addr())
		for _, match := range []struct {
			class   CanaryProtectedClass
			matches bool
		}{
			{class: CanaryProtectedClassProviderEndpoint, matches: overlapsAny(target.prefix, providerProtected)},
			{class: CanaryProtectedClassCiscoPrefix, matches: overlapsAny(target.prefix, ciscoProtected)},
		} {
			if !match.matches {
				continue
			}
			if target.explicit {
				counts[bucketKey{source: CanaryTargetSourceExplicit, protected: match.class, family: family}]++
			}
			if target.importedDNS {
				counts[bucketKey{source: CanaryTargetSourceImportedDNS, protected: match.class, family: family}]++
			}
		}
	}
	blocks := make([]CanaryIsolationBlock, 0, len(counts))
	for _, source := range []CanaryTargetSource{CanaryTargetSourceExplicit, CanaryTargetSourceImportedDNS} {
		for _, protected := range []CanaryProtectedClass{CanaryProtectedClassProviderEndpoint, CanaryProtectedClassCiscoPrefix} {
			for _, family := range []AddressFamily{FamilyIPv4, FamilyIPv6} {
				if count := counts[bucketKey{source: source, protected: protected, family: family}]; count > 0 {
					blocks = append(blocks, CanaryIsolationBlock{TargetSource: source, ProtectedClass: protected, Family: family, AffectedTargetCount: count})
				}
			}
		}
	}
	if len(blocks) > 0 {
		return &CanaryIsolationError{Blocks: blocks}
	}
	return nil
}

// LoadQualifiedEndpoints reads only immutable, manifest-verified Windows
// revision artifacts. Recovery can therefore preserve provider endpoints even
// when DNS resolution or the tunnel itself is unavailable.
func LoadQualifiedEndpoints(root string, revisions []string) ([]string, error) {
	if root == "" || len(revisions) == 0 || len(revisions) > 4 {
		return nil, errors.New("bounded runtime root and revision set are required")
	}
	runtime := Runtime{Root: root}
	var baseline []string
	seenRevisions := make(map[string]struct{}, len(revisions))
	for _, revision := range revisions {
		if !validCanaryRevision(revision) {
			return nil, errors.New("qualified endpoint revision is invalid")
		}
		if _, duplicate := seenRevisions[revision]; duplicate {
			continue
		}
		seenRevisions[revision] = struct{}{}
		artifacts, err := runtime.readRevision(revision)
		if err != nil {
			return nil, fmt.Errorf("read qualified endpoint revision: %w", err)
		}
		current := make([]string, 0, len(artifacts.routes.DirectAssertions)+len(artifacts.routes.Routes))
		for _, assertion := range artifacts.routes.DirectAssertions {
			current = append(current, assertion.Destination)
		}
		for _, route := range artifacts.routes.Routes {
			if route.Role == RouteRoleEndpointDirect {
				current = append(current, route.Destination)
			}
		}
		sort.Slice(current, func(left, right int) bool {
			leftPrefix, _ := netip.ParsePrefix(current[left])
			rightPrefix, _ := netip.ParsePrefix(current[right])
			return leftPrefix.Addr().Compare(rightPrefix.Addr()) < 0
		})
		current = slices.Compact(current)
		if len(current) == 0 {
			return nil, errors.New("revision contains no qualified provider endpoint")
		}
		if baseline == nil {
			baseline = current
			continue
		}
		if !slices.Equal(baseline, current) {
			return nil, errors.New("journal revisions disagree on the qualified provider endpoint set")
		}
	}
	if len(baseline) == 0 {
		return nil, errors.New("no qualified provider endpoint revision was loaded")
	}
	return append([]string(nil), baseline...), nil
}

func validCanaryRevision(revision string) bool {
	if revision == "" || len(revision) > 128 || strings.Contains(revision, "..") {
		return false
	}
	for _, character := range revision {
		if character != '-' && character != '_' && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func canaryTunnelAdapter(adapters []Adapter, status LocalTunnelStatus) (Adapter, error) {
	if !status.Observed || status.State != LocalTunnelUp || status.InterfaceGUID == "" {
		return Adapter{}, errors.New("canary requires one qualified active Tunnel adapter")
	}
	for _, adapter := range normalizedAdapters(adapters) {
		if adapter.InterfaceGUID == status.InterfaceGUID && adapter.Index > 0 && adapter.Up && adapter.Kind == AdapterTunnel {
			return adapter, nil
		}
	}
	return Adapter{}, errors.New("qualified Tunnel adapter is absent from the inventory")
}

func canaryEndpointAssertions(inventory Inventory, inspection tunnel.Inspection) ([]DirectRouteAssertion, []string, error) {
	addresses := endpointAddresses(inspection.Metadata, inventory.EndpointAddresses)
	if len(addresses) == 0 {
		return nil, nil, errors.New("canary has no qualified provider endpoint")
	}
	adapters := normalizedAdapters(inventory.Adapters)
	assertions := make([]DirectRouteAssertion, 0, len(addresses))
	qualified := make([]string, 0, len(addresses))
	for _, address := range addresses {
		route, found, ambiguous := effectiveRouteRecord(address, inventory.Routes)
		adapter, adapterFound := adapterForRoute(route, adapters)
		prefix := netip.PrefixFrom(address, address.BitLen())
		routePrefix, prefixErr := netip.ParsePrefix(route.Destination)
		if !found || ambiguous || !adapterFound || !adapter.Up || adapter.Kind != AdapterPhysical || prefixErr != nil || routePrefix != prefix {
			return nil, nil, errors.New("provider endpoint lacks one exact qualified physical host route")
		}
		assertions = append(assertions, DirectRouteAssertion{
			Family:         addressFamily(address),
			Destination:    prefix.String(),
			NextHop:        route.NextHop,
			InterfaceGUID:  route.InterfaceGUID,
			InterfaceIndex: route.InterfaceIndex,
		})
		qualified = append(qualified, prefix.String())
	}
	sort.Slice(assertions, func(left, right int) bool { return assertions[left].Destination < assertions[right].Destination })
	return assertions, qualified, nil
}

func canaryTargetPrefixes(values []string, metadata tunnel.Metadata) ([]canaryTarget, error) {
	seen := make(map[netip.Prefix]struct{}, len(values))
	targets := make([]canaryTarget, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4In6() {
			return nil, errors.New("canary targets must be canonical IP addresses")
		}
		address = address.Unmap()
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
			return nil, errors.New("canary targets must be public unicast addresses")
		}
		if address.Is4() && !metadata.IPv4FullTunnel || address.Is6() && !metadata.IPv6FullTunnel {
			return nil, errors.New("canary target family is not covered by the imported config")
		}
		prefix := netip.PrefixFrom(address, address.BitLen())
		if _, duplicate := seen[prefix]; duplicate {
			return nil, errors.New("canary target addresses contain a duplicate")
		}
		seen[prefix] = struct{}{}
		targets = append(targets, canaryTarget{prefix: prefix, explicit: true})
	}
	sort.Slice(targets, func(left, right int) bool {
		return targets[left].prefix.Addr().Compare(targets[right].prefix.Addr()) < 0
	})
	return targets, nil
}

func addCanaryDNSTargets(targets []canaryTarget, metadata tunnel.Metadata) ([]canaryTarget, []string, error) {
	seen := make(map[netip.Prefix]int, len(targets)+len(metadata.DNS))
	for index, target := range targets {
		seen[target.prefix] = index
	}
	servers := make([]string, 0, len(metadata.DNS))
	for _, value := range metadata.DNS {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4In6() {
			return nil, nil, errors.New("imported DNS server is invalid")
		}
		address = address.Unmap()
		if !address.IsGlobalUnicast() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() {
			return nil, nil, errors.New("imported DNS server is not a routable unicast address")
		}
		if address.Is4() && !metadata.IPv4FullTunnel || address.Is6() && !metadata.IPv6FullTunnel {
			return nil, nil, errors.New("imported DNS server family is not covered by the config")
		}
		prefix := netip.PrefixFrom(address, address.BitLen())
		if index, duplicate := seen[prefix]; duplicate {
			targets[index].importedDNS = true
		} else {
			seen[prefix] = len(targets)
			targets = append(targets, canaryTarget{prefix: prefix, importedDNS: true})
		}
		servers = append(servers, address.String())
	}
	if len(targets) > maxManagedRoutes {
		return nil, nil, errors.New("canary target set exceeds the bounded route limit")
	}
	sort.Slice(targets, func(left, right int) bool {
		return targets[left].prefix.Addr().Compare(targets[right].prefix.Addr()) < 0
	})
	sort.Strings(servers)
	servers = slices.Compact(servers)
	return targets, servers, nil
}

// canaryFallbackDefaults returns every stable adapter that could become an
// egress path for a canary target when Tunnel is unavailable. Down and
// currently-unreachable defaults are deliberately included: retaining a /0 is
// enough for adapter reactivation to become a leak path inside the pending
// window. Exact firewall rules can be installed against an existing down
// adapter alias, so rejecting or covering it is safer than ignoring it.
func canaryFallbackDefaults(inventory Inventory, tunnel Adapter) (map[AddressFamily][]Adapter, error) {
	adapters := normalizedAdapters(inventory.Adapters)
	result := make(map[AddressFamily][]Adapter)
	seen := make(map[AddressFamily]map[string]struct{})
	for _, route := range inventory.Routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		adapter, found := adapterForRoute(route, adapters)
		if err != nil || prefix.Bits() != 0 {
			continue
		}
		if !found || route.InterfaceGUID == "" || route.InterfaceGUID != adapter.InterfaceGUID || route.InterfaceIndex != adapter.Index || route.Family != addressFamily(prefix.Addr()) {
			return nil, errors.New("canary default route lacks one stable adapter identity")
		}
		if _, err := canonicalGUID(adapter.InterfaceGUID); err != nil || adapter.Index <= 0 {
			return nil, errors.New("canary default route adapter identity is invalid")
		}
		if adapter.InterfaceGUID == tunnel.InterfaceGUID {
			if adapter.Index != tunnel.Index || adapter.Kind != AdapterTunnel {
				return nil, errors.New("qualified Tunnel default route identity drifted")
			}
			continue
		}
		if adapter.Kind == AdapterTunnel || adapter.Kind == AdapterLoopback {
			return nil, errors.New("canary has an unsupported fallback default adapter")
		}
		if seen[route.Family] == nil {
			seen[route.Family] = make(map[string]struct{})
		}
		if _, duplicate := seen[route.Family][adapter.InterfaceGUID]; duplicate {
			continue
		}
		seen[route.Family][adapter.InterfaceGUID] = struct{}{}
		result[route.Family] = append(result[route.Family], adapter)
	}
	total := 0
	for family := range result {
		sort.Slice(result[family], func(left, right int) bool {
			return result[family][left].InterfaceGUID < result[family][right].InterfaceGUID
		})
		total += len(result[family])
	}
	if len(result) == 0 {
		return nil, errors.New("canary has no qualified fallback default path")
	}
	if total > maxCanaryFallbackAdapters {
		return nil, errors.New("canary fallback default adapter set exceeds the bounded limit")
	}
	return result, nil
}

// canaryFailClosedAdapters returns every stable adapter that could acquire a
// route while a candidate is pending. Coverage is intentionally broader than
// the current default-route set: a retained or newly activated more-specific
// route must remain blocked when the Tunnel route disappears.
func canaryFailClosedAdapters(inventory Inventory, tunnel Adapter) ([]Adapter, error) {
	adapters := normalizedAdapters(inventory.Adapters)
	result := make([]Adapter, 0, len(adapters))
	seenGUID := make(map[string]struct{}, len(adapters))
	seenIndex := make(map[int]struct{}, len(adapters))
	for _, adapter := range adapters {
		guid, err := canonicalGUID(adapter.InterfaceGUID)
		if err != nil || adapter.Index <= 0 || adapter.Name == "" {
			return nil, errors.New("canary adapter lacks one stable identity")
		}
		if _, duplicate := seenGUID[guid]; duplicate {
			return nil, errors.New("canary adapter GUID is duplicated")
		}
		if _, duplicate := seenIndex[adapter.Index]; duplicate {
			return nil, errors.New("canary adapter index is duplicated")
		}
		seenGUID[guid] = struct{}{}
		seenIndex[adapter.Index] = struct{}{}
		if guid == tunnel.InterfaceGUID {
			if adapter.Index != tunnel.Index || adapter.Kind != AdapterTunnel {
				return nil, errors.New("qualified Tunnel adapter identity drifted")
			}
			continue
		}
		if adapter.Kind == AdapterTunnel {
			return nil, errors.New("unqualified Tunnel adapter cannot be covered safely")
		}
		if adapter.Kind == AdapterLoopback {
			continue
		}
		result = append(result, adapter)
	}
	if len(result) == 0 || len(result) > maxCanaryFallbackAdapters {
		return nil, errors.New("canary fail-closed adapter set is empty or exceeds the bounded limit")
	}
	sort.Slice(result, func(left, right int) bool { return result[left].InterfaceGUID < result[right].InterfaceGUID })
	return result, nil
}
