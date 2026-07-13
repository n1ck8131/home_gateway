package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestExplainPrecedenceAndSpecificity(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	tests := []struct {
		name    string
		device  contracts.Device
		entries []contracts.RouteEntry
		target  string
		wantID  string
		want    contracts.RouteClass
	}{
		{
			name:   "protected tier before more-specific manual",
			device: contracts.Device{ID: "home", Mode: contracts.DeviceModeAuto},
			entries: []contracts.RouteEntry{
				domainEntry("system", "example.com", contracts.DomainMatchSuffix, contracts.RouteClassDirect, contracts.OriginSystemDirect, 0),
				domainEntry("manual", "login.example.com", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginManual, 1),
			},
			target: "login.example.com", wantID: "system", want: contracts.RouteClassDirect,
		},
		{
			name:   "specificity inside manual tier",
			device: contracts.Device{ID: "home", Mode: contracts.DeviceModeAuto},
			entries: []contracts.RouteEntry{
				domainEntry("parent", "example.com", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginManual, 1),
				domainEntry("login", "login.example.com", contracts.DomainMatchExact, contracts.RouteClassDirect, contracts.OriginManual, 1),
			},
			target: "login.example.com", wantID: "login", want: contracts.RouteClassDirect,
		},
		{
			name:   "latest equal manual operation",
			device: contracts.Device{ID: "home", Mode: contracts.DeviceModeAuto},
			entries: []contracts.RouteEntry{
				domainEntry("old", "example.com", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginManual, 1),
				domainEntry("new", "example.com", contracts.DomainMatchExact, contracts.RouteClassDirect, contracts.OriginManual, 2),
			},
			target: "example.com", wantID: "new", want: contracts.RouteClassDirect,
		},
		{
			name:   "expired manual is ignored",
			device: contracts.Device{ID: "home", Mode: contracts.DeviceModeAuto},
			entries: []contracts.RouteEntry{
				domainEntry("external", "example.com", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginExternalVPN, 0),
				withExpiry(domainEntry("manual", "example.com", contracts.DomainMatchExact, contracts.RouteClassDirect, contracts.OriginManual, 1), now),
			},
			target: "example.com", wantID: "external", want: contracts.RouteClassVPN,
		},
		{
			name:   "auto-cisco is device scoped",
			device: contracts.Device{ID: "work-pc", Mode: contracts.DeviceModeAuto, ProtectedWork: true},
			entries: []contracts.RouteEntry{
				deviceDomainEntry("cisco", "work.example", contracts.RouteClassDirect, contracts.OriginAutoCisco, "work-pc"),
				domainEntry("vpn", "work.example", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginManual, 1),
			},
			target: "work.example", wantID: "cisco", want: contracts.RouteClassDirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := contracts.DesiredState{EvaluationTime: now, Devices: []contracts.Device{tt.device}, Entries: tt.entries}
			got, err := Explain(state, contracts.RouteQuery{Target: tt.target, DeviceID: tt.device.ID})
			if err != nil {
				t.Fatal(err)
			}
			if got.WinnerEntryID != tt.wantID || got.Route != tt.want {
				t.Fatalf("decision = %q/%q, want %q/%q", got.WinnerEntryID, got.Route, tt.wantID, tt.want)
			}
			if len(got.Evidence) < 1 || !got.Evidence[0].Winner {
				t.Fatalf("evidence = %#v", got.Evidence)
			}
		})
	}
}

func TestExplainEveryOriginPrecedencePair(t *testing.T) {
	origins := []struct {
		origin contracts.OriginTier
		route  contracts.RouteClass
	}{
		{contracts.OriginSystemDirect, contracts.RouteClassDirect},
		{contracts.OriginAutoCisco, contracts.RouteClassDirect},
		{contracts.OriginManual, contracts.RouteClassVPN},
		{contracts.OriginCuratedDirect, contracts.RouteClassDirect},
		{contracts.OriginExternalDirect, contracts.RouteClassDirect},
		{contracts.OriginExternalVPN, contracts.RouteClassVPN},
	}
	device := contracts.Device{ID: "work-pc", Mode: contracts.DeviceModeAuto, ProtectedWork: true}
	for index := 0; index < len(origins)-1; index++ {
		stronger := origins[index]
		weaker := origins[index+1]
		strongerEntry := domainEntry("stronger", "example.com", contracts.DomainMatchSuffix, stronger.route, stronger.origin, 1)
		if stronger.origin == contracts.OriginAutoCisco {
			strongerEntry.Scope = contracts.Scope{Type: contracts.ScopeDevice, DeviceID: device.ID}
		}
		weakerEntry := domainEntry("weaker", "login.example.com", contracts.DomainMatchExact, weaker.route, weaker.origin, 1)
		if weaker.origin == contracts.OriginAutoCisco {
			weakerEntry.Scope = contracts.Scope{Type: contracts.ScopeDevice, DeviceID: device.ID}
		}
		state := contracts.DesiredState{
			EvaluationTime: time.Unix(100, 0).UTC(), Devices: []contracts.Device{device},
			Entries: []contracts.RouteEntry{weakerEntry, strongerEntry},
		}
		got, err := Explain(state, contracts.RouteQuery{Target: "login.example.com", DeviceID: device.ID})
		if err != nil {
			t.Fatalf("pair %s/%s: %v", stronger.origin, weaker.origin, err)
		}
		if got.WinnerEntryID != "stronger" {
			t.Fatalf("pair %s/%s winner = %q", stronger.origin, weaker.origin, got.WinnerEntryID)
		}
	}
}

func TestExplainDomainMatchRankAndCIDRSpecificity(t *testing.T) {
	t.Run("exact beats suffix and wildcard at equal pattern", func(t *testing.T) {
		state := contracts.DesiredState{
			EvaluationTime: time.Unix(100, 0).UTC(),
			Entries: []contracts.RouteEntry{
				domainEntry("wildcard", "*.example.com", contracts.DomainMatchWildcard, contracts.RouteClassVPN, contracts.OriginManual, 1),
				domainEntry("suffix", "example.com", contracts.DomainMatchSuffix, contracts.RouteClassVPN, contracts.OriginManual, 1),
				domainEntry("exact", "example.com", contracts.DomainMatchExact, contracts.RouteClassDirect, contracts.OriginManual, 1),
			},
		}
		got, err := Explain(state, contracts.RouteQuery{Target: "example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if got.WinnerEntryID != "exact" {
			t.Fatalf("winner = %q", got.WinnerEntryID)
		}
	})

	t.Run("longest CIDR wins", func(t *testing.T) {
		state := contracts.DesiredState{
			EvaluationTime: time.Unix(100, 0).UTC(),
			Entries: []contracts.RouteEntry{
				cidrEntry("wide", "8.8.0.0/16", contracts.RouteClassVPN, contracts.OriginManual),
				cidrEntry("narrow", "8.8.8.0/24", contracts.RouteClassDirect, contracts.OriginManual),
			},
		}
		got, err := Explain(state, contracts.RouteQuery{Target: "8.8.8.8"})
		if err != nil {
			t.Fatal(err)
		}
		if got.WinnerEntryID != "narrow" {
			t.Fatalf("winner = %q", got.WinnerEntryID)
		}
	})
}

func TestExplainDeviceModesIncludeMatchedEvidence(t *testing.T) {
	for _, tt := range []struct {
		mode contracts.DeviceMode
		want contracts.RouteClass
	}{
		{contracts.DeviceModeAlwaysDirect, contracts.RouteClassDirect},
		{contracts.DeviceModeAlwaysVPN, contracts.RouteClassVPN},
	} {
		device := contracts.Device{ID: string(tt.mode), Mode: tt.mode}
		state := contracts.DesiredState{
			EvaluationTime: time.Unix(100, 0).UTC(), Devices: []contracts.Device{device},
			Entries: []contracts.RouteEntry{domainEntry("matched", "example.com", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginExternalVPN, 0)},
		}
		got, err := Explain(state, contracts.RouteQuery{Target: "example.com", DeviceID: device.ID})
		if err != nil {
			t.Fatal(err)
		}
		if got.Route != tt.want || len(got.Evidence) != 2 || got.Evidence[1].EntryID != "matched" {
			t.Fatalf("mode %s decision = %#v", tt.mode, got)
		}
	}
}

func TestExplainSharedIPConflictPrefersDirect(t *testing.T) {
	state := contracts.DesiredState{
		EvaluationTime: time.Unix(100, 0).UTC(),
		Devices:        []contracts.Device{{ID: "home", Mode: contracts.DeviceModeAuto}},
		Entries: []contracts.RouteEntry{
			ipEntry("direct", "203.0.113.10", contracts.RouteClassDirect, contracts.OriginManual),
			ipEntry("vpn", "203.0.113.10", contracts.RouteClassVPN, contracts.OriginManual),
		},
	}

	got, err := Explain(state, contracts.RouteQuery{Target: "203.0.113.10", DeviceID: "home"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Route != contracts.RouteClassDirect || !got.Conflict || got.Resolution != "shared-ip-direct" {
		t.Fatalf("decision = %#v", got)
	}
}

func TestExplainSharedIPManualVPNStillWinsByPrecedence(t *testing.T) {
	manual := ipEntry("manual-vpn", "8.8.8.8", contracts.RouteClassVPN, contracts.OriginManual)
	manual.Sequence = 1
	state := contracts.DesiredState{
		EvaluationTime: time.Unix(100, 0).UTC(),
		Entries: []contracts.RouteEntry{
			manual,
			ipEntry("external-direct", "8.8.8.8", contracts.RouteClassDirect, contracts.OriginExternalDirect),
		},
	}

	got, err := Explain(state, contracts.RouteQuery{Target: "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Route != contracts.RouteClassVPN || !got.Conflict || got.Resolution != "precedence" {
		t.Fatalf("decision = %#v", got)
	}
}

func TestExplainAutoCiscoDoesNotLeakToAnotherDevice(t *testing.T) {
	work := contracts.Device{ID: "work-pc", Mode: contracts.DeviceModeAuto, ProtectedWork: true}
	home := contracts.Device{ID: "home", Mode: contracts.DeviceModeAuto}
	state := contracts.DesiredState{
		EvaluationTime: time.Unix(100, 0).UTC(),
		Devices:        []contracts.Device{work, home},
		Entries: []contracts.RouteEntry{
			deviceDomainEntry("cisco", "work.example", contracts.RouteClassDirect, contracts.OriginAutoCisco, work.ID),
			domainEntry("vpn", "work.example", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginExternalVPN, 0),
		},
	}

	got, err := Explain(state, contracts.RouteQuery{Target: "work.example", DeviceID: home.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.WinnerEntryID != "vpn" || got.Route != contracts.RouteClassVPN {
		t.Fatalf("decision = %#v", got)
	}
}

func TestExplainLocalTargetCannotRouteVPN(t *testing.T) {
	state := contracts.DesiredState{
		EvaluationTime: time.Unix(100, 0).UTC(),
		Entries:        []contracts.RouteEntry{domainEntry("vpn", "router.home.arpa", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginManual, 1)},
	}

	got, err := Explain(state, contracts.RouteQuery{Target: "router.home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Route != contracts.RouteClassLocal || got.WinnerEntryID != "local/reserved" {
		t.Fatalf("decision = %#v", got)
	}
}

func TestExplainUsesEntryServerBeforeActiveServer(t *testing.T) {
	entry := domainEntry("vpn", "example.com", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginManual, 1)
	entry.ServerID = "de-1"
	state := contracts.DesiredState{
		EvaluationTime: time.Unix(100, 0).UTC(), MarkMask: contracts.RouterdMarkMask, ActiveServerID: "nl-1",
		Servers: []contracts.ServerRoute{
			{ServerID: "nl-1", Mark: 0x01000000, Table: 10001},
			{ServerID: "de-1", Mark: 0x02000000, Table: 10002},
		},
		Entries: []contracts.RouteEntry{entry},
	}

	got, err := Explain(state, contracts.RouteQuery{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerID != "de-1" {
		t.Fatalf("server = %q", got.ServerID)
	}
}

func TestPlanIsStableAndSelectsServerRoutes(t *testing.T) {
	state := contracts.DesiredState{
		EvaluationTime: time.Unix(100, 0).UTC(),
		MarkMask:       contracts.RouterdMarkMask,
		ActiveServerID: "nl-1",
		Servers: []contracts.ServerRoute{
			{ServerID: "de-1", Mark: 0x02000000, Table: 10002},
			{ServerID: "nl-1", Mark: 0x01000000, Table: 10001},
		},
		Entries: []contracts.RouteEntry{
			domainEntry("z", "z.example", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginManual, 1),
			domainEntry("a", "a.example", contracts.DomainMatchExact, contracts.RouteClassDirect, contracts.OriginManual, 1),
		},
	}

	first, err := Plan(state)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(state)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("plans differ:\n%#v\n%#v", first, second)
	}
	if got := first.ServerRoutes[0].ServerID; got != "de-1" {
		t.Fatalf("first server = %q", got)
	}
}

func TestPlanMatchesGolden(t *testing.T) {
	state := contracts.DesiredState{
		EvaluationTime: time.Unix(100, 0).UTC(),
		MarkMask:       contracts.RouterdMarkMask,
		ActiveServerID: "nl-1",
		Servers: []contracts.ServerRoute{
			{ServerID: "nl-1", Mark: 0x01000000, Table: 10001},
			{ServerID: "de-1", Mark: 0x02000000, Table: 10002},
		},
		Entries: []contracts.RouteEntry{
			domainEntry("vpn", "BÜCHER.Example", contracts.DomainMatchExact, contracts.RouteClassVPN, contracts.OriginManual, 1),
			domainEntry("direct", "login.example.com", contracts.DomainMatchSuffix, contracts.RouteClassDirect, contracts.OriginCuratedDirect, 0),
		},
	}
	plan, err := Plan(state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("testdata/precedence.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func domainEntry(id, pattern string, match contracts.DomainMatch, route contracts.RouteClass, origin contracts.OriginTier, sequence uint64) contracts.RouteEntry {
	return contracts.RouteEntry{ID: id, Pattern: pattern, Kind: contracts.EntryKindDomain, Match: match, Route: route, Origin: origin, Sequence: sequence, Scope: contracts.Scope{Type: contracts.ScopeGlobal}}
}

func deviceDomainEntry(id, pattern string, route contracts.RouteClass, origin contracts.OriginTier, deviceID string) contracts.RouteEntry {
	entry := domainEntry(id, pattern, contracts.DomainMatchExact, route, origin, 0)
	entry.Scope = contracts.Scope{Type: contracts.ScopeDevice, DeviceID: deviceID}
	return entry
}

func ipEntry(id, pattern string, route contracts.RouteClass, origin contracts.OriginTier) contracts.RouteEntry {
	return contracts.RouteEntry{ID: id, Pattern: pattern, Kind: contracts.EntryKindIP, Route: route, Origin: origin, Scope: contracts.Scope{Type: contracts.ScopeGlobal}}
}

func cidrEntry(id, pattern string, route contracts.RouteClass, origin contracts.OriginTier) contracts.RouteEntry {
	return contracts.RouteEntry{ID: id, Pattern: pattern, Kind: contracts.EntryKindCIDR, Route: route, Origin: origin, Scope: contracts.Scope{Type: contracts.ScopeGlobal}}
}

func withExpiry(entry contracts.RouteEntry, expiresAt time.Time) contracts.RouteEntry {
	entry.ExpiresAt = &expiresAt
	return entry
}
