package nft

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

type compiledGroup struct {
	key         string
	kind        contracts.EntryKind
	match       contracts.DomainMatch
	family      int
	origin      contracts.OriginTier
	tier        int
	specificity int
	matchRank   int
	sequence    uint64
	route       contracts.RouteClass
	scope       contracts.Scope
	serverID    string
	firstID     string
	patterns    []string
	set4        string
	set6        string
}

// DomainBinding is the shared contract between the nftables and dnsmasq
// renderers. A binding names the dynamic destination sets populated for one
// policy-precedence group.
type DomainBinding struct {
	Set4     string
	Set6     string
	Match    contracts.DomainMatch
	Patterns []string
}

func compile(plan contracts.PolicyPlan) ([]compiledGroup, error) {
	groups := make(map[string]*compiledGroup, len(plan.Entries))
	for _, entry := range plan.Entries {
		if err := entry.Validate(); err != nil {
			return nil, err
		}
		group, err := groupForEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", entry.ID, err)
		}
		current := groups[group.key]
		if current == nil {
			copy := group
			copy.patterns = []string{entry.Pattern}
			copy.firstID = entry.ID
			if copy.kind == contracts.EntryKindDomain {
				copy.set4, copy.set6 = dynamicSetNames(copy.key)
			}
			groups[group.key] = &copy
			continue
		}
		current.patterns = append(current.patterns, entry.Pattern)
		if entry.ID < current.firstID {
			current.firstID = entry.ID
		}
	}

	result := make([]compiledGroup, 0, len(groups))
	for _, group := range groups {
		group.patterns = uniqueStrings(group.patterns)
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.tier != right.tier {
			return left.tier < right.tier
		}
		if left.specificity != right.specificity {
			return left.specificity > right.specificity
		}
		if left.matchRank != right.matchRank {
			return left.matchRank > right.matchRank
		}
		if left.sequence != right.sequence {
			return left.sequence > right.sequence
		}
		// Once DNS names have collapsed to a shared destination IP, direct is
		// the safety tie-breaker for otherwise indistinguishable rules.
		if left.route != right.route {
			return left.route == contracts.RouteClassDirect
		}
		if left.firstID != right.firstID {
			return left.firstID < right.firstID
		}
		return left.key < right.key
	})
	return result, nil
}

func DomainBindings(plan contracts.PolicyPlan) ([]DomainBinding, error) {
	groups, err := compile(plan)
	if err != nil {
		return nil, err
	}
	bindings := make([]DomainBinding, 0)
	for _, group := range groups {
		if group.kind != contracts.EntryKindDomain {
			continue
		}
		bindings = append(bindings, DomainBinding{
			Set4:     group.set4,
			Set6:     group.set6,
			Match:    group.match,
			Patterns: append([]string(nil), group.patterns...),
		})
	}
	return bindings, nil
}

func groupForEntry(entry contracts.RouteEntry) (compiledGroup, error) {
	group := compiledGroup{
		kind:     entry.Kind,
		match:    entry.Match,
		origin:   entry.Origin,
		tier:     originRank(entry.Origin),
		sequence: entry.Sequence,
		route:    entry.Route,
		scope:    entry.Scope,
		serverID: entry.ServerID,
	}
	switch entry.Kind {
	case contracts.EntryKindDomain:
		group.specificity = strings.Count(entry.Pattern, ".") + 1
		switch entry.Match {
		case contracts.DomainMatchExact:
			group.matchRank = 3
		case contracts.DomainMatchSuffix:
			group.matchRank = 2
		case contracts.DomainMatchWildcard:
			group.matchRank = 1
		}
	case contracts.EntryKindIP:
		address, err := netip.ParseAddr(entry.Pattern)
		if err != nil {
			return compiledGroup{}, err
		}
		address = address.Unmap()
		group.family = address.BitLen()
		group.specificity = address.BitLen()
		group.matchRank = 3
	case contracts.EntryKindCIDR:
		prefix, err := netip.ParsePrefix(entry.Pattern)
		if err != nil {
			return compiledGroup{}, err
		}
		prefix = prefix.Masked()
		group.family = prefix.Addr().BitLen()
		group.specificity = prefix.Bits()
		group.matchRank = 2
	default:
		return compiledGroup{}, fmt.Errorf("unsupported entry kind %q", entry.Kind)
	}
	group.key = strings.Join([]string{
		string(group.kind),
		string(group.match),
		strconv.Itoa(group.family),
		string(group.origin),
		strconv.Itoa(group.tier),
		strconv.Itoa(group.specificity),
		strconv.Itoa(group.matchRank),
		strconv.FormatUint(group.sequence, 10),
		string(group.route),
		string(group.scope.Type),
		group.scope.DeviceID,
		group.serverID,
	}, "\x00")
	return group, nil
}

func dynamicSetNames(key string) (string, string) {
	digest := sha256.Sum256([]byte(key))
	suffix := fmt.Sprintf("%x", digest[:8])
	return "rd4_" + suffix, "rd6_" + suffix
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
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
