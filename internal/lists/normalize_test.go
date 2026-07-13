package lists

import (
	"reflect"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		match   contracts.DomainMatch
		want    string
		wantErr bool
	}{
		{name: "URL and IDNA", raw: " HTTPS://BÜCHER.Example:443/path?q=1 ", match: contracts.DomainMatchExact, want: "xn--bcher-kva.example"},
		{name: "suffix", raw: ".Login.Example.COM.", match: contracts.DomainMatchSuffix, want: "login.example.com"},
		{name: "wildcard", raw: "*.Example.COM", match: contracts.DomainMatchWildcard, want: "example.com"},
		{name: "bare suffix", raw: "co.uk", match: contracts.DomainMatchSuffix, wantErr: true},
		{name: "invalid wildcard", raw: "foo.*.example.com", match: contracts.DomainMatchWildcard, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDomain(tt.raw, tt.match)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeDomain() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDomain() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeIPAndCIDR(t *testing.T) {
	if got, err := NormalizeIP("2001:0db8::1"); err != nil || got != "2001:db8::1" {
		t.Fatalf("NormalizeIP() = %q, %v", got, err)
	}
	if got, err := NormalizeCIDR("192.0.2.42/24"); err != nil || got != "192.0.2.0/24" {
		t.Fatalf("NormalizeCIDR() = %q, %v", got, err)
	}
	if got, err := NormalizeCIDR("::ffff:192.0.2.1/64"); err != nil || got != "::/64" {
		t.Fatalf("NormalizeCIDR(mapped /64) = %q, %v", got, err)
	}
}

func TestNormalizeEntriesIsIndependentOfInputOrder(t *testing.T) {
	first := contracts.RouteEntry{ID: "a", Pattern: "EXAMPLE.COM", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchSuffix, Route: contracts.RouteClassVPN, Origin: contracts.OriginExternalVPN, Scope: contracts.Scope{Type: contracts.ScopeGlobal}}
	second := first
	second.ID = "z"

	forward, err := NormalizeEntries([]contracts.RouteEntry{second, first}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := NormalizeEntries([]contracts.RouteEntry{first, second}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forward, reverse) || len(forward) != 1 || forward[0].ID != "a" {
		t.Fatalf("forward = %#v, reverse = %#v", forward, reverse)
	}
}

func TestNormalizeEntriesOrderIncludesAllPolicyFields(t *testing.T) {
	expiresEarly := time.Unix(100, 0).UTC()
	expiresLate := time.Unix(200, 0).UTC()
	first := contracts.RouteEntry{ID: "same", Pattern: "a.example.com", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchExact, Route: contracts.RouteClassVPN, Origin: contracts.OriginManual, ServerID: "nl-1", ExpiresAt: &expiresLate, Scope: contracts.Scope{Type: contracts.ScopeGlobal}}
	second := first
	second.ServerID = "de-1"
	second.ExpiresAt = &expiresEarly

	forward, err := NormalizeEntries([]contracts.RouteEntry{first, second}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := NormalizeEntries([]contracts.RouteEntry{second, first}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("forward = %#v, reverse = %#v", forward, reverse)
	}
}

func TestNormalizeEntriesDeduplicatesAndSubsumes(t *testing.T) {
	entries := []contracts.RouteEntry{
		{ID: "suffix", Pattern: "example.com", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchSuffix, Route: contracts.RouteClassVPN, Origin: contracts.OriginExternalVPN, Scope: contracts.Scope{Type: contracts.ScopeGlobal}},
		{ID: "exact", Pattern: "login.example.com", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchExact, Route: contracts.RouteClassVPN, Origin: contracts.OriginExternalVPN, Scope: contracts.Scope{Type: contracts.ScopeGlobal}},
		{ID: "cidr", Pattern: "192.0.2.0/24", Kind: contracts.EntryKindCIDR, Route: contracts.RouteClassDirect, Origin: contracts.OriginExternalDirect, Scope: contracts.Scope{Type: contracts.ScopeGlobal}},
		{ID: "cidr-sub", Pattern: "192.0.2.128/25", Kind: contracts.EntryKindCIDR, Route: contracts.RouteClassDirect, Origin: contracts.OriginExternalDirect, Scope: contracts.Scope{Type: contracts.ScopeGlobal}},
		{ID: "duplicate", Pattern: "EXAMPLE.COM", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchSuffix, Route: contracts.RouteClassVPN, Origin: contracts.OriginExternalVPN, Scope: contracts.Scope{Type: contracts.ScopeGlobal}},
	}

	got, err := NormalizeEntries(entries, Limits{MaxEntries: 10, MaxPatternBytes: 256})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"cidr", "duplicate"}
	gotIDs := make([]string, 0, len(got))
	for _, entry := range got {
		gotIDs = append(gotIDs, entry.ID)
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("IDs = %v, want %v", gotIDs, wantIDs)
	}
}

func TestNormalizeEntriesPreservesDifferentPolicy(t *testing.T) {
	entries := []contracts.RouteEntry{
		{ID: "direct", Pattern: "example.com", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchSuffix, Route: contracts.RouteClassDirect, Origin: contracts.OriginManual, Sequence: 1, Scope: contracts.Scope{Type: contracts.ScopeGlobal}},
		{ID: "vpn", Pattern: "example.com", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchSuffix, Route: contracts.RouteClassVPN, Origin: contracts.OriginExternalVPN, Scope: contracts.Scope{Type: contracts.ScopeGlobal}},
	}

	got, err := NormalizeEntries(entries, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
}

func TestNormalizeEntriesEnforcesLimitsBeforeReturningPartialPlan(t *testing.T) {
	entry := contracts.RouteEntry{ID: "one", Pattern: "example.com", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchExact, Route: contracts.RouteClassDirect, Origin: contracts.OriginManual, Scope: contracts.Scope{Type: contracts.ScopeGlobal}}
	if got, err := NormalizeEntries([]contracts.RouteEntry{entry}, Limits{MaxEntries: 0, MaxPatternBytes: 256}); err == nil || got != nil {
		t.Fatalf("invalid limits result = %#v, %v", got, err)
	}
	if got, err := NormalizeEntries([]contracts.RouteEntry{entry, entry}, Limits{MaxEntries: 1, MaxPatternBytes: 256}); err == nil || got != nil {
		t.Fatalf("entry limit result = %#v, %v", got, err)
	}
	if got, err := NormalizeEntries([]contracts.RouteEntry{entry}, Limits{MaxEntries: 1, MaxPatternBytes: 3}); err == nil || got != nil {
		t.Fatalf("pattern limit result = %#v, %v", got, err)
	}
}
