package dnsmasq

import (
	"errors"
	"fmt"
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
	var out strings.Builder
	fmt.Fprintf(&out, "# routerd managed; nft-timeout=%ds\ncache-rr=ANY\nmax-cache-ttl=%d\n", options.SetTimeoutSeconds, options.CacheTTLSeconds)
	for _, binding := range bindings {
		domains, err := dnsmasqDomains(binding)
		if err != nil {
			return nil, err
		}
		for start := 0; start < len(domains); start += options.ChunkSize {
			end := start + options.ChunkSize
			if end > len(domains) {
				end = len(domains)
			}
			fmt.Fprintf(
				&out,
				"nftset=/%s/4#inet#%s#%s,6#inet#%s#%s\n",
				strings.Join(domains[start:end], "/"),
				nft.TableName,
				binding.Set4,
				nft.TableName,
				binding.Set6,
			)
		}
	}
	return []byte(out.String()), nil
}

func dnsmasqDomains(binding nft.DomainBinding) ([]string, error) {
	domains := make([]string, 0, len(binding.Patterns))
	for _, pattern := range binding.Patterns {
		domain := strings.TrimPrefix(strings.TrimSuffix(pattern, "."), "*.")
		switch binding.Match {
		case contracts.DomainMatchExact:
			return nil, fmt.Errorf("exact domain %q cannot be represented by dnsmasq nftset without matching subdomains", pattern)
		case contracts.DomainMatchSuffix:
			domains = append(domains, domain)
		case contracts.DomainMatchWildcard:
			return nil, fmt.Errorf("wildcard domain %q cannot be represented by dnsmasq nftset without matching the apex", pattern)
		default:
			return nil, fmt.Errorf("unsupported domain match %q", binding.Match)
		}
	}
	return domains, nil
}
