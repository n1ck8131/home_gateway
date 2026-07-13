package dnsmasq

import (
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestRenderChunkingParityAndTimeoutAlignment(t *testing.T) {
	plan := contracts.PolicyPlan{Entries: []contracts.RouteEntry{
		{ID: "a", Pattern: "a.example", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchExact, Route: contracts.RouteClassVPN},
		{ID: "b", Pattern: "example", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchSuffix, Route: contracts.RouteClassVPN},
		{ID: "c", Pattern: "*.wild.example", Kind: contracts.EntryKindDomain, Match: contracts.DomainMatchWildcard, Route: contracts.RouteClassDirect},
	}}
	got, err := Render(plan, Options{ChunkSize: 1, SetTimeoutSeconds: 60, CacheTTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if strings.Count(text, "nftset=") != 3 || !strings.Contains(text, "4#inet#routerd#vpn4") || !strings.Contains(text, "6#inet#routerd#vpn6") {
		t.Fatalf("unexpected config:\n%s", text)
	}
	if _, err := Render(plan, Options{SetTimeoutSeconds: 10, CacheTTLSeconds: 11}); err == nil {
		t.Fatal("expected timeout mismatch")
	}
}

func TestRenderStable(t *testing.T) {
	a := contracts.RouteEntry{ID: "a", Pattern: "a.example", Kind: contracts.EntryKindDomain, Route: contracts.RouteClassVPN}
	b := contracts.RouteEntry{ID: "b", Pattern: "b.example", Kind: contracts.EntryKindDomain, Route: contracts.RouteClassVPN}
	one, _ := Render(contracts.PolicyPlan{Entries: []contracts.RouteEntry{b, a}}, Options{})
	two, _ := Render(contracts.PolicyPlan{Entries: []contracts.RouteEntry{a, b}}, Options{})
	if string(one) != string(two) {
		t.Fatal("output is not deterministic")
	}
}
