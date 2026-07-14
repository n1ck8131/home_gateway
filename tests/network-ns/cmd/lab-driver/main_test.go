//go:build linux

package main

import (
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
