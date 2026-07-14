package dnsmasq

import (
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/routing/nft"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestRenderChunkingSuffixSemanticsAndTimeoutAlignment(t *testing.T) {
	plan := contracts.PolicyPlan{Entries: []contracts.RouteEntry{
		domainEntry("a", "a.example", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginExternalVPN),
		domainEntry("b", "b.example", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginExternalVPN),
	}}
	got, err := Render(plan, Options{ChunkSize: 1, SetTimeoutSeconds: nft.SetTimeout, CacheTTLSeconds: nft.SetTimeout})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"nftset=/a.example/",
		"nftset=/b.example/",
		"4#inet#routerd#rd4_",
		"6#inet#routerd#rd6_",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in config:\n%s", want, text)
		}
	}
	if strings.Count(text, "nftset=") != 2 {
		t.Fatalf("unexpected chunk count:\n%s", text)
	}
	if _, err := Render(plan, Options{SetTimeoutSeconds: nft.SetTimeout - 1}); err == nil {
		t.Fatal("expected rendered-set timeout mismatch")
	}
	if _, err := Render(plan, Options{SetTimeoutSeconds: nft.SetTimeout, CacheTTLSeconds: nft.SetTimeout + 1}); err == nil {
		t.Fatal("expected cache timeout mismatch")
	}
}

func TestRenderPreservesExactWildcardAndSuffixSemantics(t *testing.T) {
	tests := []struct {
		name       string
		match      contracts.DomainMatch
		wantTarget []string
		wantShadow []string
	}{
		{
			name:       "exact apex only",
			match:      contracts.DomainMatchExact,
			wantTarget: []string{"login.example"},
			wantShadow: []string{"*.login.example"},
		},
		{
			name:       "wildcard descendants only",
			match:      contracts.DomainMatchWildcard,
			wantTarget: []string{"*.login.example"},
		},
		{
			name:       "suffix apex and descendants",
			match:      contracts.DomainMatchSuffix,
			wantTarget: []string{"login.example"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := contracts.PolicyPlan{Entries: []contracts.RouteEntry{
				domainEntry("domain", "login.example", tt.match, contracts.RouteClassVPN, contracts.OriginManual),
			}}
			bindings, err := nft.DomainBindings(plan)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Render(plan, Options{})
			if err != nil {
				t.Fatal(err)
			}
			text := string(got)
			targets := targetSpec(bindings[0].Set4, bindings[0].Set6)
			for _, selector := range tt.wantTarget {
				if !lineContainsSelectorAndTargets(text, selector, targets) {
					t.Fatalf("selector %q does not target policy sets:\n%s", selector, text)
				}
			}
			shadowTargets := targetSpec(nft.DNSShadowSet4, nft.DNSShadowSet6)
			for _, selector := range tt.wantShadow {
				if !lineContainsSelectorAndTargets(text, selector, shadowTargets) {
					t.Fatalf("selector %q does not target shadow sets:\n%s", selector, text)
				}
			}
			if tt.match == contracts.DomainMatchWildcard && lineContainsSelectorAndTargets(text, "login.example", targets) {
				t.Fatalf("wildcard profile widened to the apex:\n%s", text)
			}
			if tt.match == contracts.DomainMatchExact && lineContainsSelectorAndTargets(text, "*.login.example", targets) {
				t.Fatalf("exact profile widened to descendants:\n%s", text)
			}
		})
	}
}

func TestRenderPreservesOverlappingDomainMemberships(t *testing.T) {
	suffix := domainEntry("suffix", "example", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginExternalVPN)
	exact := domainEntry("exact", "login.example", contracts.DomainMatchExact, contracts.RouteClassDirect, contracts.OriginManual)
	plan := contracts.PolicyPlan{Entries: []contracts.RouteEntry{suffix, exact}}
	bindings, err := nft.DomainBindings(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 {
		t.Fatalf("domain bindings = %d, want 2", len(bindings))
	}
	got, err := Render(plan, Options{})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)

	var suffixTargets, exactTargets string
	for _, binding := range bindings {
		targets := targetSpec(binding.Set4, binding.Set6)
		switch binding.Match {
		case contracts.DomainMatchSuffix:
			suffixTargets = targets
		case contracts.DomainMatchExact:
			exactTargets = targets
		}
	}
	if !lineContainsAll(text, "login.example", suffixTargets, exactTargets) {
		t.Fatalf("overlapping apex does not populate both policy memberships:\n%s", text)
	}
	if !lineContainsSelectorAndTargets(text, "*.login.example", suffixTargets) ||
		lineContainsSelectorAndTargets(text, "*.login.example", exactTargets) {
		t.Fatalf("overlapping descendants do not preserve suffix-only membership:\n%s", text)
	}
}

func TestRenderStable(t *testing.T) {
	a := domainEntry("a", "a.example", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginExternalVPN)
	b := domainEntry("b", "b.example", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginExternalVPN)
	one, err := Render(contracts.PolicyPlan{Entries: []contracts.RouteEntry{b, a}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Render(contracts.PolicyPlan{Entries: []contracts.RouteEntry{a, b}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Fatal("output is not deterministic")
	}
}

func domainEntry(id, pattern string, match contracts.DomainMatch, route contracts.RouteClass, origin contracts.OriginTier) contracts.RouteEntry {
	entry := contracts.RouteEntry{
		ID:      id,
		Pattern: pattern,
		Kind:    contracts.EntryKindDomain,
		Match:   match,
		Route:   route,
		Scope:   contracts.Scope{Type: contracts.ScopeGlobal},
		Origin:  origin,
	}
	if origin == contracts.OriginManual {
		entry.Sequence = 1
	}
	return entry
}

func lineContainsSelectorAndTargets(text, selector, targets string) bool {
	return lineContainsAll(text, "/"+selector+"/", targets)
}

func lineContainsAll(text string, values ...string) bool {
	for _, line := range strings.Split(text, "\n") {
		matched := true
		for _, value := range values {
			matched = matched && strings.Contains(line, value)
		}
		if matched {
			return true
		}
	}
	return false
}
