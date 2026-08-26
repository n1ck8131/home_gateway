package windows

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

func TestBuildCanaryPlanClassifiesIsolationBlocks(t *testing.T) {
	tests := []struct {
		name    string
		request CanaryRequest
		mutate  func(*Inventory, *tunnel.Inspection)
		want    []CanaryIsolationBlock
	}{
		{
			name:    "explicit provider ipv4",
			request: CanaryRequest{Revision: "p35-canary-isolation", TargetAddresses: []string{"203.0.113.5"}, DNSNamespace: CanaryDNSNamespace},
			want: []CanaryIsolationBlock{{
				TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv4, AffectedTargetCount: 1,
			}},
		},
		{
			name:    "imported DNS provider ipv6",
			request: CanaryRequest{Revision: "p35-canary-isolation", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
			mutate: func(_ *Inventory, inspection *tunnel.Inspection) {
				inspection.Metadata.DNS = []string{"2001:db8:ffff::5"}
			},
			want: []CanaryIsolationBlock{{
				TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv6, AffectedTargetCount: 1,
			}},
		},
		{
			name:    "explicit Cisco ipv6",
			request: CanaryRequest{Revision: "p35-canary-isolation", TargetAddresses: []string{"2001:db8:abcd::53"}, DNSNamespace: CanaryDNSNamespace},
			mutate: func(inventory *Inventory, _ *tunnel.Inspection) {
				inventory.Routes = append(inventory.Routes, Route{Family: FamilyIPv6, Destination: "2001:db8:abcd::/48", NextHop: "::", InterfaceIndex: 31, InterfaceGUID: testCiscoGUID, Metric: 1})
			},
			want: []CanaryIsolationBlock{{
				TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv6, AffectedTargetCount: 1,
			}},
		},
		{
			name:    "imported DNS Cisco ipv4",
			request: CanaryRequest{Revision: "p35-canary-isolation", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
			mutate: func(_ *Inventory, inspection *tunnel.Inspection) {
				inspection.Metadata.DNS = []string{"10.50.0.53"}
			},
			want: []CanaryIsolationBlock{{
				TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv4, AffectedTargetCount: 1,
			}},
		},
		{
			name:    "same target from both sources",
			request: CanaryRequest{Revision: "p35-canary-isolation", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
			mutate: func(inventory *Inventory, inspection *tunnel.Inspection) {
				inventory.Routes = append(inventory.Routes, Route{Family: FamilyIPv4, Destination: "198.51.100.0/24", NextHop: "0.0.0.0", InterfaceIndex: 31, InterfaceGUID: testCiscoGUID, Metric: 1})
				inspection.Metadata.DNS = []string{"198.51.100.10"}
			},
			want: []CanaryIsolationBlock{
				{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv4, AffectedTargetCount: 1},
				{TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv4, AffectedTargetCount: 1},
			},
		},
		{
			name:    "multiple Cisco routes count one target",
			request: CanaryRequest{Revision: "p35-canary-isolation", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
			mutate: func(inventory *Inventory, _ *tunnel.Inspection) {
				inventory.Routes = append(inventory.Routes,
					Route{Family: FamilyIPv4, Destination: "198.51.100.0/24", NextHop: "0.0.0.0", InterfaceIndex: 31, InterfaceGUID: testCiscoGUID, Metric: 1},
					Route{Family: FamilyIPv4, Destination: "198.51.100.10/32", NextHop: "0.0.0.0", InterfaceIndex: 31, InterfaceGUID: testCiscoGUID, Metric: 1},
				)
			},
			want: []CanaryIsolationBlock{{
				TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv4, AffectedTargetCount: 1,
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory, inspection := qualifiedCanaryInput()
			if test.mutate != nil {
				test.mutate(&inventory, &inspection)
			}
			_, err := BuildCanaryPlan(inventory, inspection, test.request)
			var blocked *CanaryIsolationError
			if !errors.As(err, &blocked) {
				t.Fatalf("error type = %T, want *CanaryIsolationError", err)
			}
			blocks, ok := blocked.RedactedBlocks()
			if !ok || !slices.Equal(blocks, test.want) {
				t.Fatalf("blocks = %#v, valid = %v", blocks, ok)
			}
			if blocked.Error() != "canary target isolation failed" {
				t.Fatalf("unsafe error text = %q", blocked.Error())
			}
		})
	}
}

func TestCanaryIsolationErrorValidatesRedactedBlocks(t *testing.T) {
	wantOrder := []CanaryIsolationBlock{
		{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv4, AffectedTargetCount: 1},
		{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv6, AffectedTargetCount: 1},
		{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv4, AffectedTargetCount: 1},
		{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv6, AffectedTargetCount: 1},
		{TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv4, AffectedTargetCount: 1},
		{TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv6, AffectedTargetCount: 1},
		{TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv4, AffectedTargetCount: 1},
		{TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv6, AffectedTargetCount: 1},
	}
	if got, ok := (&CanaryIsolationError{Blocks: wantOrder}).RedactedBlocks(); !ok || !slices.Equal(got, wantOrder) {
		t.Fatalf("canonical blocks = %#v, valid = %v", got, ok)
	}

	invalid := []struct {
		name   string
		blocks []CanaryIsolationBlock
	}{
		{name: "empty", blocks: nil},
		{name: "too many buckets", blocks: append(append([]CanaryIsolationBlock(nil), wantOrder...), wantOrder[0])},
		{name: "unknown target source", blocks: []CanaryIsolationBlock{{TargetSource: "unknown", ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv4, AffectedTargetCount: 1}}},
		{name: "unknown protected class", blocks: []CanaryIsolationBlock{{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: "unknown", Family: FamilyIPv4, AffectedTargetCount: 1}}},
		{name: "unknown family", blocks: []CanaryIsolationBlock{{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: "unknown", AffectedTargetCount: 1}}},
		{name: "zero count", blocks: []CanaryIsolationBlock{{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv4, AffectedTargetCount: 0}}},
		{name: "count exceeds limit", blocks: []CanaryIsolationBlock{{TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv4, AffectedTargetCount: maxManagedRoutes + 1}}},
		{name: "non-canonical order", blocks: []CanaryIsolationBlock{wantOrder[1], wantOrder[0]}},
		{name: "duplicate rank", blocks: []CanaryIsolationBlock{wantOrder[0], wantOrder[0]}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if got, ok := (&CanaryIsolationError{Blocks: test.blocks}).RedactedBlocks(); ok || got != nil {
				t.Fatalf("invalid blocks = %#v, valid = %v", got, ok)
			}
		})
	}
}

func TestBuildCanaryPlanProducesBoundedDualStackArtifacts(t *testing.T) {
	inventory, inspection := qualifiedCanaryInput()
	plan, err := BuildCanaryPlan(inventory, inspection, CanaryRequest{
		Revision:        "p35-canary-001",
		TargetAddresses: []string{"198.51.100.10", "2001:db8:100::10"},
		DNSNamespace:    CanaryDNSNamespace,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.QualifiedEndpoints, []string{"203.0.113.5/32", "2001:db8:ffff::5/128"}) {
		t.Fatalf("qualified endpoints = %v", plan.QualifiedEndpoints)
	}
	if plan.RouteCount != 4 || plan.SinkCount != 4 || plan.FirewallRuleCount != 8 || plan.DNSRuleCount != 1 {
		t.Fatalf("unexpected summary: %#v", plan)
	}
	challenge := plan.ConfirmationChallenge(`C:\ProgramData\HomeGateway\p35`)
	if !strings.HasPrefix(challenge, "P35-APPLY-") || len(challenge) != len("P35-APPLY-")+16 {
		t.Fatalf("confirmation challenge = %q", challenge)
	}
	if challenge == plan.ConfirmationChallenge(`C:\ProgramData\HomeGateway\other`) {
		t.Fatal("confirmation challenge is not bound to the state root")
	}
	artifacts, err := parseArtifacts(
		plan.Candidate.RevisionID,
		plan.Candidate.Routes,
		plan.Candidate.Sinks,
		plan.Candidate.Firewall,
		plan.Candidate.DNS,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts.routes.DirectAssertions) != 2 || len(artifacts.routes.Routes) != 4 {
		t.Fatalf("routes artifact = %#v", artifacts.routes)
	}
	if len(artifacts.sinks.Routes) != len(plan.TargetPrefixes) {
		t.Fatalf("sink count = %d, targets = %d", len(artifacts.sinks.Routes), len(plan.TargetPrefixes))
	}
	for _, route := range artifacts.sinks.Routes {
		if route.InterfaceIndex != LoopbackInterfaceIndex || route.Metric != ReservedSinkMetric || route.PolicyStore != SinkPolicyStore {
			t.Fatalf("unsafe sink route: %#v", route)
		}
	}
	for _, route := range artifacts.routes.Routes {
		if route.Role != RouteRoleVPNClass || route.InterfaceGUID != testRedShieldGUID || route.Metric != ReservedRouteMetric || !route.JournalOwned {
			t.Fatalf("unsafe canary route: %#v", route)
		}
		if route.Destination == "0.0.0.0/0" || route.Destination == "::/0" {
			t.Fatalf("global route escaped into canary: %#v", route)
		}
	}
	if got := artifacts.dns.Rules[0]; got.Namespace != CanaryDNSNamespace || !slices.Equal(got.NameServers, []string{"10.20.30.1", "fd00::1"}) {
		t.Fatalf("DNS artifact = %#v", got)
	}
	for _, payload := range [][]byte{plan.Candidate.Routes, plan.Candidate.Sinks, plan.Candidate.Firewall, plan.Candidate.DNS} {
		var decoded any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "PrivateKey") || strings.Contains(string(payload), "config") {
			t.Fatalf("candidate contains provider source material: %s", payload)
		}
	}
}

func TestBuildCanaryPlanCoversRetainedDownCiscoDefaultPath(t *testing.T) {
	inventory, inspection := qualifiedCanaryInput()
	inventory.Adapters[2].Up = false
	inventory.Routes = append(inventory.Routes, Route{
		Family:         FamilyIPv4,
		Destination:    "0.0.0.0/0",
		NextHop:        "0.0.0.0",
		InterfaceIndex: 31,
		InterfaceGUID:  testCiscoGUID,
		State:          2,
	})
	plan, err := BuildCanaryPlan(inventory, inspection, CanaryRequest{
		Revision:        "p35-canary-cisco-default",
		TargetAddresses: []string{"198.51.100.10"},
		DNSNamespace:    CanaryDNSNamespace,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := parseArtifacts(plan.Candidate.RevisionID, plan.Candidate.Routes, plan.Candidate.Sinks, plan.Candidate.Firewall, plan.Candidate.DNS)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RouteCount != 3 || plan.FirewallRuleCount != 6 {
		t.Fatalf("unexpected fallback coverage summary: %#v", plan)
	}
	ciscoRules := 0
	for _, rule := range artifacts.firewall.Rules {
		if rule.InterfaceGUID == testCiscoGUID {
			ciscoRules++
		}
	}
	if ciscoRules != 3 {
		t.Fatalf("Cisco exact-target fail-closed rules = %d, want 3", ciscoRules)
	}
}

func TestBuildCanaryPlanAllowsIPv6WithoutDefaultWhenLoopbackSinkIsQualified(t *testing.T) {
	inventory, inspection := qualifiedCanaryInput()
	inventory.Routes = slices.DeleteFunc(inventory.Routes, func(route Route) bool {
		return route.Family == FamilyIPv6 && route.Destination == "::/0" && route.InterfaceGUID == testPhysicalGUID
	})
	plan, err := BuildCanaryPlan(inventory, inspection, CanaryRequest{
		Revision:        "p35-canary-v6-sink",
		TargetAddresses: []string{"2001:db8:100::10"},
		DNSNamespace:    CanaryDNSNamespace,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := parseArtifacts(plan.Candidate.RevisionID, plan.Candidate.Routes, plan.Candidate.Sinks, plan.Candidate.Firewall, plan.Candidate.DNS)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(artifacts.sinks.Routes, func(route SinkRoute) bool {
		return route.Family == FamilyIPv6 && route.Destination == "2001:db8:100::10/128" && route.NextHop == "::"
	}) {
		t.Fatalf("IPv6 target sink missing: %#v", artifacts.sinks.Routes)
	}
}

func TestBuildCanaryPlanRejectsBroadOrUnqualifiedInputs(t *testing.T) {
	inventory, inspection := qualifiedCanaryInput()
	tests := map[string]struct {
		mutate  func(*Inventory, *tunnel.Inspection)
		request CanaryRequest
	}{
		"private target": {
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"10.0.0.1"}, DNSNamespace: CanaryDNSNamespace},
		},
		"missing target": {
			request: CanaryRequest{Revision: "p35", DNSNamespace: CanaryDNSNamespace},
		},
		"invalid namespace": {
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: "."},
		},
		"broad namespace": {
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: ".com"},
		},
		"loopback DNS": {
			mutate:  func(_ *Inventory, inspection *tunnel.Inspection) { inspection.Metadata.DNS = []string{"127.0.0.1"} },
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
		},
		"unspecified DNS": {
			mutate:  func(_ *Inventory, inspection *tunnel.Inspection) { inspection.Metadata.DNS = []string{"::"} },
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
		},
		"endpoint is not exact direct": {
			mutate: func(inventory *Inventory, _ *tunnel.Inspection) {
				inventory.Routes[2].Destination = "203.0.113.0/24"
			},
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
		},
		"read-only preflight blocked": {
			mutate:  func(inventory *Inventory, _ *tunnel.Inspection) { inventory.RouteSnapshotAuthoritative = false },
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
		},
		"Cisco protected target": {
			mutate: func(inventory *Inventory, _ *tunnel.Inspection) {
				inventory.Routes = append(inventory.Routes, Route{Family: FamilyIPv4, Destination: "198.51.100.0/24", NextHop: "0.0.0.0", InterfaceIndex: 31, InterfaceGUID: testCiscoGUID, State: routeStateAlive})
			},
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: CanaryDNSNamespace},
		},
		"family not covered": {
			mutate:  func(_ *Inventory, inspection *tunnel.Inspection) { inspection.Metadata.IPv6FullTunnel = false },
			request: CanaryRequest{Revision: "p35", TargetAddresses: []string{"2001:db8:100::10"}, DNSNamespace: CanaryDNSNamespace},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotInventory := cloneCanaryValue(t, inventory)
			gotInspection := cloneCanaryValue(t, inspection)
			if test.mutate != nil {
				test.mutate(&gotInventory, &gotInspection)
			}
			if _, err := BuildCanaryPlan(gotInventory, gotInspection, test.request); err == nil {
				t.Fatal("unsafe canary input unexpectedly passed")
			}
		})
	}
}

func TestLoadQualifiedEndpointsUsesManifestVerifiedRevisionData(t *testing.T) {
	inventory, inspection := qualifiedCanaryInput()
	plan, err := BuildCanaryPlan(inventory, inspection, CanaryRequest{
		Revision:        "p35-canary-001",
		TargetAddresses: []string{"198.51.100.10"},
		DNSNamespace:    CanaryDNSNamespace,
	})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "runtime")
	runtime := Runtime{Root: root, Backend: newSafeBackend(), QualifiedEndpoints: plan.QualifiedEndpoints}
	if err := runtime.Stage(t.Context(), plan.Candidate); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(root, "revisions", plan.Candidate.RevisionID, revisionManifestName)
	manifestData, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded revisionManifest
	if err := json.Unmarshal(manifestData, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Files) != 4 {
		t.Fatalf("manifest file count = %d, want 4: %#v", len(decoded.Files), decoded.Files)
	}
	for _, name := range []string{routesArtifactName, sinksArtifactName, firewallArtifactName, dnsArtifactName} {
		if _, ok := decoded.Files[name]; !ok {
			t.Fatalf("manifest missing %s: %#v", name, decoded.Files)
		}
	}
	loaded, err := LoadQualifiedEndpoints(root, []string{plan.Candidate.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(loaded, plan.QualifiedEndpoints) {
		t.Fatalf("loaded endpoints = %v, want %v", loaded, plan.QualifiedEndpoints)
	}
	if err := os.WriteFile(manifest, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadQualifiedEndpoints(root, []string{plan.Candidate.RevisionID}); err == nil {
		t.Fatal("corrupt revision manifest unexpectedly passed")
	}
}

func qualifiedCanaryInput() (Inventory, tunnel.Inspection) {
	inventory := Inventory{
		Adapters: []Adapter{
			{Name: "Ethernet", Index: 12, InterfaceGUID: testPhysicalGUID, HardwareInterface: true, Kind: AdapterPhysical, Up: true},
			{Name: "RedShield", Index: 21, InterfaceGUID: testRedShieldGUID, Kind: AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32", "fd00::2/128"}},
			{Name: "Cisco", Index: 31, InterfaceGUID: testCiscoGUID, Kind: AdapterCisco, Up: true},
		},
		Routes: []Route{
			{Family: FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 12, InterfaceGUID: testPhysicalGUID, Metric: 25},
			{Family: FamilyIPv6, Destination: "::/0", NextHop: "2001:db8:1::1", InterfaceIndex: 12, InterfaceGUID: testPhysicalGUID, Metric: 25},
			{Family: FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceIndex: 12, InterfaceGUID: testPhysicalGUID, Metric: 1},
			{Family: FamilyIPv6, Destination: "2001:db8:ffff::5/128", NextHop: "2001:db8:1::1", InterfaceIndex: 12, InterfaceGUID: testPhysicalGUID, Metric: 1},
			{Family: FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "0.0.0.0", InterfaceIndex: 21, InterfaceGUID: testRedShieldGUID, Metric: 50},
			{Family: FamilyIPv6, Destination: "::/0", NextHop: "::", InterfaceIndex: 21, InterfaceGUID: testRedShieldGUID, Metric: 50},
			{Family: FamilyIPv4, Destination: "10.50.0.0/16", NextHop: "0.0.0.0", InterfaceIndex: 31, InterfaceGUID: testCiscoGUID, Metric: 1},
		},
		EndpointAddresses:          []string{"203.0.113.5", "2001:db8:ffff::5"},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
	inspection := tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportAmneziaWG,
			Endpoint:           tunnel.Endpoint{Host: "vpn.example.test", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/32", "fd00::2/128"},
			DNS:                []string{"10.20.30.1", "fd00::1"},
			IPv4FullTunnel:     true,
			IPv6FullTunnel:     true,
		},
		Status: tunnel.Status{State: tunnel.StateUnknown, Observed: false},
	}
	return inventory, inspection
}

func cloneCanaryValue[T any](t *testing.T, value T) T {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone T
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
