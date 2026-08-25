package windows

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
)

func TestNewCanaryTransactionBuildsBoundedDurableRuntime(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	tx, err := NewCanaryTransaction(CanaryRuntimeConfig{
		Root:               root,
		Backend:            newSafeBackend(),
		QualifiedEndpoints: testQualifiedEndpoints(),
		Watchdog:           apply.TimerWatchdog{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.ConfirmTimeout != DefaultCanaryConfirmTimeout || tx.RecoveryTimeout != DefaultCanaryRecoveryTimeout {
		t.Fatalf("timeouts = %s/%s", tx.ConfirmTimeout, tx.RecoveryTimeout)
	}
	journal, ok := tx.Journal.(apply.FileJournal)
	if !ok || journal.Path != filepath.Join(root, "journal.json") {
		t.Fatalf("journal = %#v", tx.Journal)
	}
	locker, ok := tx.Locker.(apply.FileLocker)
	if !ok || locker.Path != filepath.Join(root, "operation.lock") {
		t.Fatalf("locker = %#v", tx.Locker)
	}
}

func TestNewCanaryTransactionRejectsUnsafeConfiguration(t *testing.T) {
	validRoot := filepath.Join(t.TempDir(), "state")
	tests := map[string]CanaryRuntimeConfig{
		"relative root":      {Root: "state", Backend: newSafeBackend(), QualifiedEndpoints: testQualifiedEndpoints()},
		"missing backend":    {Root: validRoot, QualifiedEndpoints: testQualifiedEndpoints()},
		"missing endpoints":  {Root: validRoot, Backend: newSafeBackend()},
		"negative timeout":   {Root: validRoot, Backend: newSafeBackend(), QualifiedEndpoints: testQualifiedEndpoints(), ConfirmTimeout: -time.Second},
		"excessive timeout":  {Root: validRoot, Backend: newSafeBackend(), QualifiedEndpoints: testQualifiedEndpoints(), ConfirmTimeout: 11 * time.Minute},
		"recovery too long":  {Root: validRoot, Backend: newSafeBackend(), QualifiedEndpoints: testQualifiedEndpoints(), ConfirmTimeout: time.Minute, RecoveryTimeout: 2 * time.Minute},
		"untrusted endpoint": {Root: validRoot, Backend: newSafeBackend(), QualifiedEndpoints: []string{"0.0.0.0/0"}},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCanaryTransaction(config); err == nil {
				t.Fatal("unsafe canary runtime unexpectedly passed")
			}
		})
	}
}

func TestRecoveryOnlyCanaryTransactionAllowsMissingEndpointsAndBlocksForwardUse(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	tx, err := NewCanaryTransaction(CanaryRuntimeConfig{
		Root:         root,
		Backend:      newSafeBackend(),
		RecoveryOnly: true,
		Watchdog:     apply.TimerWatchdog{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !tx.RecoveryOnly {
		t.Fatal("recovery transaction lost its forward-use guard")
	}
	if err := tx.Apply(t.Context(), apply.Candidate{RevisionID: "candidate"}); err == nil {
		t.Fatal("recovery-only transaction unexpectedly applied a candidate")
	}
	if err := tx.Confirm(); err == nil {
		t.Fatal("recovery-only transaction unexpectedly confirmed a candidate")
	}
}
