package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/vsevo/home-gateway/internal/lists"
	"github.com/vsevo/home-gateway/internal/routing/explain"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

type candidate struct {
	entry       contracts.RouteEntry
	tier        int
	specificity int
	matchRank   int
}

func Plan(state contracts.DesiredState) (contracts.PolicyPlan, error) {
	if err := state.Validate(); err != nil {
		return contracts.PolicyPlan{}, err
	}
	active := make([]contracts.RouteEntry, 0, len(state.Entries))
	for _, entry := range state.Entries {
		if entry.ExpiresAt != nil && !entry.ExpiresAt.After(state.EvaluationTime) {
			continue
		}
		active = append(active, entry)
	}
	normalized, err := lists.NormalizeEntries(active, lists.DefaultLimits())
	if err != nil {
		return contracts.PolicyPlan{}, err
	}
	serverRoutes := append([]contracts.ServerRoute(nil), state.Servers...)
	sort.Slice(serverRoutes, func(i, j int) bool {
		return serverRoutes[i].ServerID < serverRoutes[j].ServerID
	})
	return contracts.PolicyPlan{
		EvaluationTime: state.EvaluationTime.UTC(),
		Entries:        normalized,
		ServerRoutes:   serverRoutes,
	}, nil
}

func Explain(state contracts.DesiredState, query contracts.RouteQuery) (contracts.RouteDecision, error) {
	plan, err := Plan(state)
	if err != nil {
		return contracts.RouteDecision{}, err
	}
	device, err := findDevice(state.Devices, query.DeviceID)
	if err != nil {
		return contracts.RouteDecision{}, err
	}
	target, address, isAddress, err := normalizeTarget(query.Target)
	if err != nil {
		return contracts.RouteDecision{}, err
	}

	decision := contracts.RouteDecision{Target: target, DeviceID: query.DeviceID, Evidence: []contracts.DecisionEvidence{}}
	if isLocalTarget(target, address, isAddress) {
		return virtualDecision(decision, "local/reserved", contracts.RouteClassLocal, "local-reserved"), nil
	}

	candidates := collectCandidates(plan.Entries, target, address, isAddress, device)
	if device.Mode == contracts.DeviceModeAlwaysDirect {
		return virtualDecisionWithCandidates(decision, "device-mode:always-direct", contracts.RouteClassDirect, "device-mode", candidates, isAddress), nil
	}
	if device.Mode == contracts.DeviceModeAlwaysVPN {
		allCandidates := append([]candidate(nil), candidates...)
		allowed := candidates[:0]
		for _, item := range candidates {
			if item.entry.Origin == contracts.OriginSystemDirect ||
				(item.entry.Route == contracts.RouteClassDirect && item.entry.Scope.Type == contracts.ScopeDevice) {
				allowed = append(allowed, item)
			}
		}
		candidates = allowed
		if len(candidates) == 0 {
			result := virtualDecisionWithCandidates(decision, "device-mode:always-vpn", contracts.RouteClassVPN, "device-mode", allCandidates, isAddress)
			result.ServerID = state.ActiveServerID
			return result, nil
		}
		sortCandidates(candidates, isAddress)
		return candidateDecision(decision, candidates[0], allCandidates, state.ActiveServerID, "device-exception", hasRouteConflict(allCandidates), isAddress)
	}
	if len(candidates) == 0 {
		return virtualDecision(decision, "default-direct", contracts.RouteClassDirect, "default"), nil
	}

	sortCandidates(candidates, isAddress)
	winner := candidates[0]
	conflict := hasRouteConflict(candidates)
	resolution := resolutionFor(candidates, conflict, winner.entry.Route, isAddress)
	return candidateDecision(decision, winner, candidates, state.ActiveServerID, resolution, conflict, isAddress)
}

func candidateDecision(base contracts.RouteDecision, winner candidate, candidates []candidate, activeServerID, resolution string, conflict, isAddress bool) (contracts.RouteDecision, error) {
	sortCandidates(candidates, isAddress)
	evidenceCandidates := make([]contracts.DecisionEvidence, 0, len(candidates))
	evidenceCandidates = append(evidenceCandidates, evidenceFor(winner))
	for _, item := range candidates {
		if item.entry.ID != winner.entry.ID {
			evidenceCandidates = append(evidenceCandidates, evidenceFor(item))
		}
	}
	evidence, err := explain.Build(evidenceCandidates, winner.entry.ID, resolution)
	if err != nil {
		return contracts.RouteDecision{}, err
	}
	base.Route = winner.entry.Route
	base.WinnerEntryID = winner.entry.ID
	base.Conflict = conflict
	base.Resolution = resolution
	base.Evidence = evidence
	if base.Route == contracts.RouteClassVPN {
		base.ServerID = winner.entry.ServerID
		if base.ServerID == "" {
			base.ServerID = activeServerID
		}
	}
	return base, nil
}

func findDevice(devices []contracts.Device, deviceID string) (contracts.Device, error) {
	if deviceID == "" {
		return contracts.Device{Mode: contracts.DeviceModeAuto}, nil
	}
	for _, device := range devices {
		if device.ID == deviceID {
			return device, nil
		}
	}
	return contracts.Device{}, fmt.Errorf("unknown device %q", deviceID)
}

func normalizeTarget(raw string) (string, netip.Addr, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", netip.Addr{}, false, errors.New("route target is required")
	}
	if strings.EqualFold(trimmed, "local") {
		return "local", netip.Addr{}, false, nil
	}
	if address, err := netip.ParseAddr(trimmed); err == nil {
		address = address.Unmap()
		return address.String(), address, true, nil
	}
	domain, err := lists.NormalizeDomain(trimmed, contracts.DomainMatchExact)
	if err != nil {
		return "", netip.Addr{}, false, fmt.Errorf("normalize route target: %w", err)
	}
	return domain, netip.Addr{}, false, nil
}

func isLocalTarget(target string, address netip.Addr, isAddress bool) bool {
	if isAddress {
		return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
			address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified()
	}
	return target == "home.arpa" || strings.HasSuffix(target, ".home.arpa") ||
		target == "local" || strings.HasSuffix(target, ".local")
}

func collectCandidates(entries []contracts.RouteEntry, target string, address netip.Addr, isAddress bool, device contracts.Device) []candidate {
	result := make([]candidate, 0)
	for _, entry := range entries {
		if entry.Scope.Type == contracts.ScopeDevice && entry.Scope.DeviceID != device.ID {
			continue
		}
		if entry.Origin == contracts.OriginAutoCisco && !device.ProtectedWork {
			continue
		}
		specificity, matchRank, matches := matchesEntry(entry, target, address, isAddress)
		if !matches {
			continue
		}
		result = append(result, candidate{entry: entry, tier: originRank(entry.Origin), specificity: specificity, matchRank: matchRank})
	}
	return result
}

func matchesEntry(entry contracts.RouteEntry, target string, address netip.Addr, isAddress bool) (int, int, bool) {
	switch entry.Kind {
	case contracts.EntryKindDomain:
		if isAddress {
			return 0, 0, false
		}
		labels := strings.Count(entry.Pattern, ".") + 1
		switch entry.Match {
		case contracts.DomainMatchExact:
			return labels, 3, target == entry.Pattern
		case contracts.DomainMatchSuffix:
			return labels, 2, target == entry.Pattern || strings.HasSuffix(target, "."+entry.Pattern)
		case contracts.DomainMatchWildcard:
			return labels, 1, target != entry.Pattern && strings.HasSuffix(target, "."+entry.Pattern)
		}
	case contracts.EntryKindIP:
		if !isAddress {
			return 0, 0, false
		}
		entryAddress, err := netip.ParseAddr(entry.Pattern)
		if err == nil && entryAddress.Unmap() == address {
			return address.BitLen(), 3, true
		}
	case contracts.EntryKindCIDR:
		if !isAddress {
			return 0, 0, false
		}
		prefix, err := netip.ParsePrefix(entry.Pattern)
		if err == nil && prefix.Contains(address) {
			return prefix.Bits(), 2, true
		}
	}
	return 0, 0, false
}

func sortCandidates(candidates []candidate, isAddress bool) {
	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if left.tier != right.tier {
			return left.tier < right.tier
		}
		if left.specificity != right.specificity {
			return left.specificity > right.specificity
		}
		if left.matchRank != right.matchRank {
			return left.matchRank > right.matchRank
		}
		if left.entry.Sequence != right.entry.Sequence {
			return left.entry.Sequence > right.entry.Sequence
		}
		if isAddress && left.entry.Route != right.entry.Route {
			return left.entry.Route == contracts.RouteClassDirect
		}
		return left.entry.ID < right.entry.ID
	})
}

func originRank(origin contracts.OriginTier) int {
	switch origin {
	case contracts.OriginSystemDirect:
		return 0
	case contracts.OriginAutoCisco:
		return 1
	case contracts.OriginManual:
		return 2
	case contracts.OriginCuratedDirect:
		return 3
	case contracts.OriginExternalDirect:
		return 4
	case contracts.OriginExternalVPN:
		return 5
	default:
		return 99
	}
}

func hasRouteConflict(candidates []candidate) bool {
	direct := false
	vpn := false
	for _, item := range candidates {
		direct = direct || item.entry.Route == contracts.RouteClassDirect
		vpn = vpn || item.entry.Route == contracts.RouteClassVPN
	}
	return direct && vpn
}

func resolutionFor(candidates []candidate, conflict bool, winnerRoute contracts.RouteClass, isAddress bool) string {
	if conflict && isAddress && winnerRoute == contracts.RouteClassDirect && isUnresolvedTie(candidates) {
		return "shared-ip-direct"
	}
	if len(candidates) > 1 {
		return "precedence"
	}
	return "single-match"
}

func isUnresolvedTie(candidates []candidate) bool {
	if len(candidates) < 2 {
		return false
	}
	winner := candidates[0]
	for _, item := range candidates[1:] {
		if item.entry.Route != winner.entry.Route && item.tier == winner.tier &&
			item.specificity == winner.specificity && item.matchRank == winner.matchRank &&
			item.entry.Sequence == winner.entry.Sequence {
			return true
		}
	}
	return false
}

func evidenceFor(item candidate) contracts.DecisionEvidence {
	return contracts.DecisionEvidence{
		EntryID: item.entry.ID,
		Origin:  item.entry.Origin,
		Route:   item.entry.Route,
		Pattern: item.entry.Pattern,
		Reason:  fmt.Sprintf("tier=%d specificity=%d match=%d sequence=%d", item.tier, item.specificity, item.matchRank, item.entry.Sequence),
	}
}

func virtualDecision(base contracts.RouteDecision, entryID string, route contracts.RouteClass, resolution string) contracts.RouteDecision {
	base.Route = route
	base.WinnerEntryID = entryID
	base.Resolution = resolution
	base.Evidence = []contracts.DecisionEvidence{{
		EntryID:    entryID,
		Route:      route,
		Reason:     resolution,
		Winner:     true,
		Resolution: resolution,
	}}
	return base
}

func virtualDecisionWithCandidates(base contracts.RouteDecision, entryID string, route contracts.RouteClass, resolution string, candidates []candidate, isAddress bool) contracts.RouteDecision {
	base = virtualDecision(base, entryID, route, resolution)
	sortCandidates(candidates, isAddress)
	base.Conflict = hasRouteConflict(candidates)
	for _, item := range candidates {
		base.Evidence = append(base.Evidence, evidenceFor(item))
	}
	return base
}
