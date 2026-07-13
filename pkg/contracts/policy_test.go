package contracts

import (
	"testing"
	"time"
)

func TestDesiredStateRejectsProtectedAlwaysVPNDevice(t *testing.T) {
	state := DesiredState{
		EvaluationTime: time.Unix(1, 0).UTC(),
		Devices:        []Device{{ID: "work-pc", Mode: DeviceModeAlwaysVPN, ProtectedWork: true}},
	}

	if err := state.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func TestDesiredStateAcceptsMultipleDeviceIdentities(t *testing.T) {
	state := DesiredState{
		EvaluationTime: time.Unix(1, 0).UTC(),
		Devices: []Device{{
			ID:            "work-pc",
			Mode:          DeviceModeAuto,
			ProtectedWork: true,
			Identities: []DeviceIdentity{
				{Kind: IdentityMAC, Value: "00:11:22:33:44:55"},
				{Kind: IdentityClientID, Value: "work-pc-client"},
			},
		}},
	}

	if err := state.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDesiredStateRejectsInvalidServerMarks(t *testing.T) {
	state := DesiredState{
		EvaluationTime: time.Unix(1, 0).UTC(),
		MarkMask:       RouterdMarkMask,
		Servers: []ServerRoute{
			{ServerID: "nl-1", Mark: 0x01000000, Table: 10001},
			{ServerID: "de-1", Mark: 0x01000000, Table: 10002},
		},
	}

	if err := state.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func TestServerRouteForSlotUsesReservedAllocation(t *testing.T) {
	route, err := ServerRouteForSlot("nl-1", 2)
	if err != nil {
		t.Fatalf("ServerRouteForSlot() error = %v", err)
	}
	if route.Mark != 0x02000000 || route.Table != 10002 {
		t.Fatalf("ServerRouteForSlot() = %#v", route)
	}
	if _, err := ServerRouteForSlot("nl-1", 0); err == nil {
		t.Fatal("ServerRouteForSlot(slot=0) error = nil")
	}
}

func TestRouteEntryRejectsUnknownEnum(t *testing.T) {
	entry := RouteEntry{
		ID:      "bad",
		Pattern: "example.com",
		Kind:    EntryKind("unknown"),
		Route:   RouteClassDirect,
		Origin:  OriginManual,
		Scope:   Scope{Type: ScopeGlobal},
	}

	if err := entry.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func TestDesiredStateRejectsAutoCiscoForUnprotectedDevice(t *testing.T) {
	state := DesiredState{
		EvaluationTime: time.Unix(1, 0).UTC(),
		Devices:        []Device{{ID: "guest", Mode: DeviceModeAuto}},
		Entries: []RouteEntry{{
			ID: "cisco", Pattern: "work.example", Kind: EntryKindDomain, Match: DomainMatchExact,
			Route: RouteClassDirect, Origin: OriginAutoCisco,
			Scope: Scope{Type: ScopeDevice, DeviceID: "guest"},
		}},
	}

	if err := state.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func TestDesiredStateRejectsUnknownSelectedServer(t *testing.T) {
	state := DesiredState{
		EvaluationTime: time.Unix(1, 0).UTC(),
		Entries: []RouteEntry{{
			ID: "vpn", Pattern: "example.com", Kind: EntryKindDomain, Match: DomainMatchExact,
			Route: RouteClassVPN, Origin: OriginManual, Scope: Scope{Type: ScopeGlobal}, ServerID: "missing",
		}},
	}

	if err := state.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}

func TestDesiredStateRejectsEquivalentIdentityFormatsAcrossDevices(t *testing.T) {
	state := DesiredState{
		EvaluationTime: time.Unix(1, 0).UTC(),
		Devices: []Device{
			{ID: "one", Mode: DeviceModeAuto, Identities: []DeviceIdentity{{Kind: IdentityMAC, Value: "00:11:22:33:44:55"}}},
			{ID: "two", Mode: DeviceModeAuto, Identities: []DeviceIdentity{{Kind: IdentityMAC, Value: "00-11-22-33-44-55"}}},
		},
	}

	if err := state.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
}
