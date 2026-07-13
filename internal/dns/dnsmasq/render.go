package dnsmasq

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

const (
	DefaultChunkSize  = 750
	DefaultSetTimeout = 3600
	DefaultCacheTTL   = 3600
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
		options.SetTimeoutSeconds = DefaultSetTimeout
	}
	if options.CacheTTLSeconds == 0 {
		options.CacheTTLSeconds = DefaultCacheTTL
	}
	if options.ChunkSize < 1 || options.SetTimeoutSeconds < 1 || options.CacheTTLSeconds < 1 {
		return nil, errors.New("chunk size and timeouts must be positive")
	}
	if options.CacheTTLSeconds > options.SetTimeoutSeconds {
		return nil, errors.New("dns cache TTL cannot exceed nft set timeout")
	}
	bySet := map[string][]string{"direct": {}, "vpn": {}}
	for _, entry := range plan.Entries {
		if entry.Kind != contracts.EntryKindDomain {
			continue
		}
		domain := strings.TrimPrefix(strings.TrimSuffix(entry.Pattern, "."), "*.")
		bySet[string(entry.Route)] = append(bySet[string(entry.Route)], domain)
	}
	var out strings.Builder
	fmt.Fprintf(&out, "# routerd managed; nft-timeout=%ds\ncache-rr=ANY\nmax-cache-ttl=%d\n", options.SetTimeoutSeconds, options.CacheTTLSeconds)
	for _, route := range []string{"direct", "vpn"} {
		domains := uniqueSorted(bySet[route])
		for start := 0; start < len(domains); start += options.ChunkSize {
			end := start + options.ChunkSize
			if end > len(domains) {
				end = len(domains)
			}
			joined := "/" + strings.Join(domains[start:end], "/") + "/"
			fmt.Fprintf(&out, "nftset=%s4#inet#routerd#%s4,%s6#inet#routerd#%s6\n", joined, route, joined, route)
		}
	}
	return []byte(out.String()), nil
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value != "" && (len(out) == 0 || out[len(out)-1] != value) {
			out = append(out, value)
		}
	}
	return out
}
