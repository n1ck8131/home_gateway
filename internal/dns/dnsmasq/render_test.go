package dnsmasq

import (
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/routing/nft"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestRenderChunkingMatchSemanticsAndTimeoutAlignment(t *testing.T) {
	plan := contracts.PolicyPlan{Entries: []contracts.RouteEntry{
		domainEntry("a", "a.example", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginExternalVPN),
		domainEntry("b", "b.example", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginExternalVPN),
		domainEntry("c", "wild.example", contracts.DomainMatchWildcard, contracts.RouteClassDirect, contracts.OriginManual),
	}}
	got, err := Render(plan, Options{ChunkSize: 1, SetTimeoutSeconds: nft.SetTimeout, CacheTTLSeconds: nft.SetTimeout})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"nftset=/a.example/",
		"nftset=/b.example/",
		"nftset=/*.wild.example/",
		"4#inet#routerd#rd4_",
		"6#inet#routerd#rd6_",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in config:\n%s", want, text)
		}
	}
	if strings.Count(text, "nftset=") != 3 {
		t.Fatalf("unexpected chunk count:\n%s", text)
	}
	if _, err := Render(plan, Options{SetTimeoutSeconds: nft.SetTimeout - 1}); err == nil {
		t.Fatal("expected rendered-set timeout mismatch")
	}
	if _, err := Render(plan, Options{SetTimeoutSeconds: nft.SetTimeout, CacheTTLSeconds: nft.SetTimeout + 1}); err == nil {
		t.Fatal("expected cache timeout mismatch")
	}
}

func TestRenderRejectsExactDomainInsteadOfWideningIt(t *testing.T) {
	plan := contracts.PolicyPlan{Entries: []contracts.RouteEntry{
		domainEntry("exact", "login.example", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginManual),
	}}
	_, err := Render(plan, Options{})
	if err == nil || !strings.Contains(err.Error(), "cannot be represented") {
		t.Fatalf("Render() error = %v, want exact-domain capability error", err)
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
