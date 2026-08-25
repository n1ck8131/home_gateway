package windows

import (
	"strings"
	"testing"
)

func TestSinkArtifactRequiresExactPersistentLoopbackCoverage(t *testing.T) {
	candidate := safeCandidate(t, "r1")
	artifacts := decodeCandidate(t, candidate)
	if len(artifacts.sinks.Routes) != 2 {
		t.Fatalf("sink routes = %d, want 2", len(artifacts.sinks.Routes))
	}
	want := map[string]SinkRoute{
		"198.51.100.53/32": {
			Family:         FamilyIPv4,
			Destination:    "198.51.100.53/32",
			NextHop:        "0.0.0.0",
			InterfaceIndex: LoopbackInterfaceIndex,
			Metric:         ReservedSinkMetric,
			PolicyStore:    SinkPolicyStore,
			Protocol:       RouteProtocol,
			JournalOwned:   true,
		},
		"2001:db8:100::53/128": {
			Family:         FamilyIPv6,
			Destination:    "2001:db8:100::53/128",
			NextHop:        "::",
			InterfaceIndex: LoopbackInterfaceIndex,
			Metric:         ReservedSinkMetric,
			PolicyStore:    SinkPolicyStore,
			Protocol:       RouteProtocol,
			JournalOwned:   true,
		},
	}
	for _, route := range artifacts.sinks.Routes {
		got, ok := want[route.Destination]
		if !ok || got != route {
			t.Fatalf("unexpected sink route: %#v", route)
		}
	}
}

func TestSinkArtifactRejectsUnsafeCoverage(t *testing.T) {
	tests := map[string]func(*artifactSet){
		"omitted DNS sink": func(artifacts *artifactSet) {
			artifacts.sinks.Routes = artifacts.sinks.Routes[:1]
		},
		"extra sink": func(artifacts *artifactSet) {
			artifacts.sinks.Routes = append(artifacts.sinks.Routes, sinkForVPNRoute(ManagedRoute{Family: FamilyIPv4, Destination: "203.0.113.77/32"}))
		},
		"broad IPv6 sink": func(artifacts *artifactSet) {
			artifacts.sinks.Routes[1].Destination = "2001:db8:100::/64"
			artifacts.routes.Routes[3].Destination = "2001:db8:100::53/128"
		},
		"wrong next hop": func(artifacts *artifactSet) {
			artifacts.sinks.Routes[0].NextHop = "192.0.2.1"
		},
		"wrong metric": func(artifacts *artifactSet) {
			artifacts.sinks.Routes[0].Metric = ReservedRouteMetric
		},
		"duplicate destination": func(artifacts *artifactSet) {
			artifacts.sinks.Routes = append(artifacts.sinks.Routes, artifacts.sinks.Routes[0])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			artifacts := decodeCandidate(t, safeCandidate(t, "r1"))
			mutate(&artifacts)
			candidate := encodeCandidate(t, artifacts)
			if _, err := parseArtifacts(candidate.RevisionID, candidate.Routes, candidate.Sinks, candidate.Firewall, candidate.DNS); err == nil {
				t.Fatal("unsafe sink artifact unexpectedly passed")
			}
		})
	}
}

func TestSinkArtifactRequiresOneToOneVPNRouteCoverage(t *testing.T) {
	artifacts := decodeCandidate(t, safeCandidate(t, "r1"))
	artifacts.sinks.Routes[0].Destination = artifacts.routes.Routes[3].Destination
	candidate := encodeCandidate(t, artifacts)
	if _, err := parseArtifacts(candidate.RevisionID, candidate.Routes, candidate.Sinks, candidate.Firewall, candidate.DNS); err == nil || !strings.Contains(err.Error(), "sink") {
		t.Fatalf("duplicate VPN sink coverage result = %v", err)
	}
}
