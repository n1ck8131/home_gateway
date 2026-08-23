package dnsmasq

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/vsevo/home-gateway/internal/routing/nft"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

const (
	DefaultChunkSize = 750
	DefaultCacheTTL  = nft.SetTimeout
)

type Options struct {
	ChunkSize         int
	SetTimeoutSeconds int
	CacheTTLSeconds   int
}

func Render(plan contracts.PolicyPlan, options Options) ([]byte, error) {
	if options.ChunkSize == 0 {
		options.ChunkSize = DefaultChunkSize
	}
	if options.SetTimeoutSeconds == 0 {
		options.SetTimeoutSeconds = nft.SetTimeout
	}
	if options.CacheTTLSeconds == 0 {
		options.CacheTTLSeconds = DefaultCacheTTL
	}
	if options.ChunkSize < 1 || options.SetTimeoutSeconds < 1 || options.CacheTTLSeconds < 1 {
		return nil, errors.New("chunk size and timeouts must be positive")
	}
	if options.SetTimeoutSeconds != nft.SetTimeout {
		return nil, fmt.Errorf("dnsmasq nft timeout %d must equal rendered nft set timeout %d", options.SetTimeoutSeconds, nft.SetTimeout)
	}
	if options.CacheTTLSeconds > options.SetTimeoutSeconds {
		return nil, errors.New("dns cache TTL cannot exceed nft set timeout")
	}

	bindings, err := nft.DomainBindings(plan)
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if binding.Match != contracts.DomainMatchSuffix {
			return nil, fmt.Errorf(
				"%s domain %q cannot be represented safely by dnsmasq nftset without widening its match; use suffix or a hostname-aware adapter",
				binding.Match,
				binding.Patterns[0],
			)
		}
	}
	groups := buildSuffixSelectorGroups(bindings)
	var out strings.Builder
	fmt.Fprintf(&out, "# routerd managed; nft-timeout=%ds\ncache-rr=ANY\nmax-cache-ttl=%d\n", options.SetTimeoutSeconds, options.CacheTTLSeconds)
	for _, group := range groups {
		for start := 0; start < len(group.selectors); start += options.ChunkSize {
			end := start + options.ChunkSize
			if end > len(group.selectors) {
				end = len(group.selectors)
			}
			fmt.Fprintf(
				&out,
				"nftset=/%s/%s\n",
				strings.Join(group.selectors[start:end], "/"),
				group.targets,
			)
		}
	}
	return []byte(out.String()), nil
}

type selectorGroup struct {
	targets   string
	selectors []string
}

// buildSuffixSelectorGroups expands every suffix boundary into the effective
// set memberships dnsmasq must apply there. dnsmasq selects only the longest
// matching suffix, so a more-specific selector must retain every broader
// membership explicitly.
func buildSuffixSelectorGroups(bindings []nft.DomainBinding) []selectorGroup {
	boundarySet := make(map[string]struct{})
	for _, binding := range bindings {
		for _, pattern := range binding.Patterns {
			boundarySet[canonicalSuffix(pattern)] = struct{}{}
		}
	}
	boundaries := make([]string, 0, len(boundarySet))
	for boundary := range boundarySet {
		boundaries = append(boundaries, boundary)
	}
	sort.Strings(boundaries)

	selectorsByTargets := make(map[string][]string)
	for _, boundary := range boundaries {
		targets := targetsForSuffix(boundary, bindings)
		if targets != "" {
			selectorsByTargets[targets] = append(selectorsByTargets[targets], boundary)
		}
	}

	targetKeys := make([]string, 0, len(selectorsByTargets))
	for targets := range selectorsByTargets {
		targetKeys = append(targetKeys, targets)
	}
	sort.Strings(targetKeys)
	result := make([]selectorGroup, 0, len(targetKeys))
	for _, targets := range targetKeys {
		selectors := selectorsByTargets[targets]
		sort.Strings(selectors)
		result = append(result, selectorGroup{targets: targets, selectors: selectors})
	}
	return result
}

func targetsForSuffix(domain string, bindings []nft.DomainBinding) string {
	targets := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		matched := false
		for _, pattern := range binding.Patterns {
			pattern = canonicalSuffix(pattern)
			if domain == pattern || strings.HasSuffix(domain, "."+pattern) {
				matched = true
				break
			}
		}
		if matched {
			targets = append(targets, targetSpec(binding.Set4, binding.Set6))
		}
	}
	sort.Strings(targets)
	return strings.Join(targets, ",")
}

func targetSpec(set4, set6 string) string {
	return fmt.Sprintf("4#inet#%s#%s,6#inet#%s#%s", nft.TableName, set4, nft.TableName, set6)
}

func canonicalSuffix(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}
