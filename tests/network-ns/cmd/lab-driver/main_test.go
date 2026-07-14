//go:build linux

package main

import (
	"net/netip"
	"testing"

	revisionapply "github.com/vsevo/home-gateway/internal/revisions/apply"
)

func TestWatchdogRollbackComplete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		journal revisionapply.Journal
		want    bool
	}{
		{
			name: "restored watchdog rollback",
			journal: revisionapply.Journal{
				State:          revisionapply.StateRolledBack,
				RollbackResult: watchdogRollbackRestored,
			},
			want: true,
		},
		{
			name: "bare reason is incomplete",
			journal: revisionapply.Journal{
				State:          revisionapply.StateRolledBack,
				RollbackResult: "watchdog expiry",
			},
		},
		{
			name: "failed restore is incomplete",
			journal: revisionapply.Journal{
				State:          revisionapply.StateDegraded,
				RollbackResult: "watchdog expiry: failed",
			},
		},
		{
			name: "pending journal is incomplete",
			journal: revisionapply.Journal{
				State:          revisionapply.StatePending,
				RollbackResult: watchdogRollbackRestored,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := watchdogRollbackComplete(tt.journal); got != tt.want {
				t.Fatalf("watchdogRollbackComplete() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyRequestRendersTwoIndependentServerSlots(t *testing.T) {
	t.Parallel()

	request, err := applyRequest("dual", "suffix", requestOptions{
		dualServer:     true,
		activeSlot:     2,
		slot1Available: true,
		slot2Available: false,
	})
	if err != nil {
		t.Fatalf("applyRequest() error = %v", err)
	}
	if request.Inventory.NFT.ActiveServerID != vpnServer2ID {
		t.Fatalf("active server = %q", request.Inventory.NFT.ActiveServerID)
	}
	if len(request.Plan.ServerRoutes) != 2 || len(request.Inventory.IPRule.Servers) != 2 {
		t.Fatalf("server route counts = %d/%d", len(request.Plan.ServerRoutes), len(request.Inventory.IPRule.Servers))
	}
	if request.Inventory.IPRule.Servers[0].Interface != "vpn0" || !request.Inventory.IPRule.Servers[0].Available {
		t.Fatalf("slot 1 inventory = %#v", request.Inventory.IPRule.Servers[0])
	}
	if request.Inventory.IPRule.Servers[1].Interface != "vpn1" || request.Inventory.IPRule.Servers[1].Available {
		t.Fatalf("slot 2 inventory = %#v", request.Inventory.IPRule.Servers[1])
	}
	if request.Plan.Entries[0].ServerID != "" {
		t.Fatalf("active-server domain unexpectedly pinned to %q", request.Plan.Entries[0].ServerID)
	}
	wantIPv6 := netip.MustParseAddr("2001:470:10::3")
	if got := request.Inventory.NFT.DeviceIPv6[workDeviceID][0]; got != wantIPv6 {
		t.Fatalf("work IPv6 = %s, want %s", got, wantIPv6)
	}
}

func TestApplyRequestSharedProfilePreservesDirectOverlap(t *testing.T) {
	t.Parallel()

	request, err := applyRequest("shared", "shared", requestOptions{activeSlot: 1, slot1Available: true})
	if err != nil {
		t.Fatalf("applyRequest() error = %v", err)
	}
	if len(request.Plan.Entries) != 4 {
		t.Fatalf("entry count = %d, want 4", len(request.Plan.Entries))
	}
	direct := request.Plan.Entries[3]
	if direct.ID != "manual-direct-shared" || direct.Pattern != "target.vpn.suite.test" {
		t.Fatalf("shared direct entry = %#v", direct)
	}
}

func TestApplyRequestRejectsSecondSlotWithoutDualServer(t *testing.T) {
	t.Parallel()

	if _, err := applyRequest("invalid", "suffix", requestOptions{activeSlot: 2}); err == nil {
		t.Fatal("applyRequest() error = nil")
	}
}
