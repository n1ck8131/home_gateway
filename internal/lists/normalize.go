package lists

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/vsevo/home-gateway/pkg/contracts"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type Limits struct {
	MaxEntries      int
	MaxPatternBytes int
}

func DefaultLimits() Limits {
	return Limits{MaxEntries: 100_000, MaxPatternBytes: 2_048}
}

func NormalizeDomain(raw string, match contracts.DomainMatch) (string, error) {
	switch match {
	case contracts.DomainMatchExact, contracts.DomainMatchSuffix, contracts.DomainMatchWildcard:
	default:
		return "", fmt.Errorf("invalid domain match %q", match)
	}

	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("domain is empty")
	}
	if match == contracts.DomainMatchWildcard {
		if !strings.HasPrefix(value, "*.") {
			return "", errors.New("wildcard domain must start with a star label")
		}
		value = strings.TrimPrefix(value, "*.")
	} else if strings.HasPrefix(value, "*.") {
		return "", errors.New("wildcard prefix requires wildcard match")
	}
	if match == contracts.DomainMatchSuffix {
		value = strings.TrimPrefix(value, ".")
	}
	if strings.Contains(value, "*") {
		return "", errors.New("wildcard is only allowed as the leading star label")
	}

	host, err := extractHost(value)
	if err != nil {
		return "", err
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", errors.New("domain is empty")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", errors.New("IP address is not a domain")
	}
	canonical, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("normalize IDNA domain: %w", err)
	}
	canonical = strings.ToLower(canonical)
	if len(canonical) > 253 {
		return "", errors.New("domain exceeds 253 bytes")
	}
	if strings.Contains(canonical, "..") || strings.HasPrefix(canonical, ".") || strings.HasSuffix(canonical, ".") {
		return "", errors.New("domain contains an empty label")
	}
	suffix, _ := publicsuffix.PublicSuffix(canonical)
	if suffix == canonical {
		return "", fmt.Errorf("bare public suffix %q is not allowed", canonical)
	}
	return canonical, nil
}

func NormalizeIP(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse IP: %w", err)
	}
	return addr.Unmap().String(), nil
}

func NormalizeCIDR(raw string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse CIDR: %w", err)
	}
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked().String(), nil
}

func NormalizeEntries(entries []contracts.RouteEntry, limits Limits) ([]contracts.RouteEntry, error) {
	if limits.MaxEntries <= 0 || limits.MaxPatternBytes <= 0 {
		return nil, errors.New("normalization limits must be positive")
	}
	if len(entries) > limits.MaxEntries {
		return nil, fmt.Errorf("entry count %d exceeds limit %d", len(entries), limits.MaxEntries)
	}

	normalized := make([]contracts.RouteEntry, 0, len(entries))
	for _, source := range entries {
		if len(source.Pattern) > limits.MaxPatternBytes {
			return nil, fmt.Errorf("entry %q pattern exceeds %d bytes", source.ID, limits.MaxPatternBytes)
		}
		entry := source
		var err error
		switch entry.Kind {
		case contracts.EntryKindDomain:
			entry.Pattern, err = NormalizeDomain(entry.Pattern, entry.Match)
		case contracts.EntryKindIP:
			entry.Pattern, err = NormalizeIP(entry.Pattern)
		case contracts.EntryKindCIDR:
			entry.Pattern, err = NormalizeCIDR(entry.Pattern)
		default:
			err = fmt.Errorf("invalid entry kind %q", entry.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", entry.ID, err)
		}
		if entry.ExpiresAt != nil {
			expiresAt := entry.ExpiresAt.UTC()
			entry.ExpiresAt = &expiresAt
		}
		if err := entry.Validate(); err != nil {
			return nil, err
		}
		normalized = append(normalized, entry)
	}
	sort.Slice(normalized, func(i, j int) bool {
		return entrySortKey(normalized[i]) < entrySortKey(normalized[j])
	})
	unique := normalized[:0]
	seen := make(map[string]struct{}, len(normalized))
	for _, entry := range normalized {
		key := entrySemanticKey(entry, true)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, entry)
	}
	normalized = unique

	indexes := make(map[string]*subsumptionIndex)
	for _, entry := range normalized {
		key := entrySemanticKey(entry, false)
		index := indexes[key]
		if index == nil {
			index = &subsumptionIndex{domainSuffixes: make(map[string]struct{}), cidrs: make(map[string]struct{})}
			indexes[key] = index
		}
		if entry.Kind == contracts.EntryKindDomain && entry.Match == contracts.DomainMatchSuffix {
			index.domainSuffixes[entry.Pattern] = struct{}{}
		}
		if entry.Kind == contracts.EntryKindCIDR {
			index.cidrs[entry.Pattern] = struct{}{}
		}
	}

	result := make([]contracts.RouteEntry, 0, len(normalized))
	for _, entry := range normalized {
		if !isSubsumed(entry, indexes[entrySemanticKey(entry, false)]) {
			result = append(result, entry)
		}
	}
	return result, nil
}

func extractHost(value string) (string, error) {
	parsedValue := value
	if !strings.Contains(value, "://") {
		parsedValue = "//" + value
	}
	parsed, err := url.Parse(parsedValue)
	if err != nil {
		return "", fmt.Errorf("parse domain input: %w", err)
	}
	if parsed.User != nil {
		return "", errors.New("domain input cannot contain user information")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", errors.New("domain input has no host")
	}
	return host, nil
}

func entrySemanticKey(entry contracts.RouteEntry, includePattern bool) string {
	expiresAt := ""
	if entry.ExpiresAt != nil {
		expiresAt = entry.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	}
	parts := []string{
		string(entry.Route), string(entry.Origin), string(entry.Scope.Type), entry.Scope.DeviceID,
		entry.ServerID, strconv.FormatUint(entry.Sequence, 10), expiresAt,
	}
	if includePattern {
		parts = append(parts, string(entry.Kind), string(entry.Match), entry.Pattern)
	}
	return strings.Join(parts, "\x00")
}

func entrySortKey(entry contracts.RouteEntry) string {
	return entrySemanticKey(entry, true) + "\x00" + entry.ID
}

type subsumptionIndex struct {
	domainSuffixes map[string]struct{}
	cidrs          map[string]struct{}
}

func isSubsumed(entry contracts.RouteEntry, index *subsumptionIndex) bool {
	if index == nil {
		return false
	}
	if entry.Kind == contracts.EntryKindDomain {
		for offset := strings.IndexByte(entry.Pattern, '.'); offset >= 0; {
			parent := entry.Pattern[offset+1:]
			if _, exists := index.domainSuffixes[parent]; exists {
				return true
			}
			next := strings.IndexByte(parent, '.')
			if next < 0 {
				break
			}
			offset += next + 1
		}
		return false
	}
	if entry.Kind == contracts.EntryKindCIDR {
		prefix, err := netip.ParsePrefix(entry.Pattern)
		if err != nil {
			return false
		}
		for bits := prefix.Bits() - 1; bits >= 0; bits-- {
			parent := netip.PrefixFrom(prefix.Addr(), bits).Masked().String()
			if _, exists := index.cidrs[parent]; exists {
				return true
			}
		}
	}
	return false
}
