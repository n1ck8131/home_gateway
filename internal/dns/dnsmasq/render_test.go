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

func TestRenderRejectsExactAndWildcardInsteadOfWideningThem(t *testing.T) {
	for _, match := range []contracts.DomainMatch{contracts.DomainMatchExact, contracts.DomainMatchWildcard} {
		t.Run(string(match), func(t *testing.T) {
			plan := contracts.PolicyPlan{Entries: []contracts.RouteEntry{
				domainEntry(string(match), "login.example", match, contracts.RouteClassVPN, contracts.OriginManual),
			}}
			_, err := Render(plan, Options{})
			if err == nil || !strings.Contains(err.Error(), "cannot be represented safely") {
				t.Fatalf("Render() error = %v, want fail-safe capability error", err)
			}
		})
	}
}

func TestRenderPreservesNestedSuffixMemberships(t *testing.T) {
	broad := domainEntry("broad", "example", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginExternalVPN)
	specific := domainEntry("specific", "login.example", contracts.DomainMatchSuffix, contracts.RouteClassDirect, contracts.OriginManual)
	plan := contracts.PolicyPlan{Entries: []contracts.RouteEntry{broad, specific}}
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

	var broadTargets, specificTargets string
	for _, binding := range bindings {
		targets := targetSpec(binding.Set4, binding.Set6)
		switch binding.Patterns[0] {
		case "example":
			broadTargets = targets
		case "login.example":
			specificTargets = targets
		}
	}
	if !lineContainsSelectorAndTargets(text, "example", broadTargets) {
		t.Fatalf("broad suffix selector is missing:\n%s", text)
	}
	if !lineContainsAll(text, "/login.example/", broadTargets, specificTargets) {
		t.Fatalf("specific suffix selector does not retain broader membership:\n%s", text)
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
