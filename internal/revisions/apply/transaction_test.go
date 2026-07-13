package apply

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type memoryJournal struct {
	value    Journal
	failSave bool
}

func (store *memoryJournal) Load() (Journal, error) { return store.value, nil }
func (store *memoryJournal) Save(value Journal) error {
	if store.failSave {
		return errors.New("save failed")
	}
	store.value = value
	return nil
}

type fakeClock struct{ now time.Time }

func (clock fakeClock) Now() time.Time { return clock.now }

type fakeRuntime struct {
	fail         string
	calls        []string
	restoreFails bool
}

func (runtime *fakeRuntime) call(name string) error {
	runtime.calls = append(runtime.calls, name)
	if runtime.fail == name {
		return errors.New(name + " failed")
	}
	return nil
}
func (runtime *fakeRuntime) Stage(context.Context, Candidate) error { return runtime.call("stage") }
func (runtime *fakeRuntime) Validate(context.Context, Candidate) error {
	return runtime.call("validate")
}
func (runtime *fakeRuntime) Snapshot(context.Context, string) error { return runtime.call("snapshot") }
func (runtime *fakeRuntime) Activate(context.Context, Candidate) error {
	return runtime.call("activate")
}
func (runtime *fakeRuntime) Reload(context.Context) error    { return runtime.call("reload") }
func (runtime *fakeRuntime) PostCheck(context.Context) error { return runtime.call("post-check") }
func (runtime *fakeRuntime) Restore(context.Context, string) error {
	runtime.calls = append(runtime.calls, "restore")
	if runtime.restoreFails {
		return errors.New("restore failed")
	}
	return nil
}

func newTransaction(runtime *fakeRuntime, store *memoryJournal, now time.Time) *Transaction {
	return &Transaction{Runtime: runtime, Journal: store, Clock: fakeClock{now}, ConfirmTimeout: time.Minute}
}

func TestApplyCompensatesEveryMutationBoundary(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	for _, boundary := range []string{"stage", "validate", "snapshot", "activate", "reload", "post-check"} {
		t.Run(boundary, func(t *testing.T) {
			runtime := &fakeRuntime{fail: boundary}
			store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg", LastKnownGoodRevision: "lkg"}}
			err := newTransaction(runtime, store, now).Apply(context.Background(), Candidate{RevisionID: "next"})
			if err == nil {
				t.Fatal("expected failure")
			}
			restored := strings.Contains(strings.Join(runtime.calls, ","), "restore")
			if restored != (boundary == "activate" || boundary == "reload" || boundary == "post-check") {
				t.Fatalf("calls=%v", runtime.calls)
			}
		})
	}
}

func TestCommitRollbackExpiryCrashAndDegradedRecovery(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	t.Run("confirm", func(t *testing.T) {
		runtime := &fakeRuntime{}
		store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg"}}
		tx := newTransaction(runtime, store, now)
		if err := tx.Apply(context.Background(), Candidate{RevisionID: "next"}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Confirm(); err != nil {
			t.Fatal(err)
		}
		if store.value.State != StateCommitted || store.value.ActiveRevision != "next" {
			t.Fatalf("journal=%+v", store.value)
		}
	})
	t.Run("explicit rollback", func(t *testing.T) {
		runtime := &fakeRuntime{}
		store := &memoryJournal{value: Journal{State: StatePending, LastKnownGoodRevision: "lkg", PendingRevision: "next"}}
		if err := newTransaction(runtime, store, now).Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		if store.value.State != StateRolledBack {
			t.Fatalf("journal=%+v", store.value)
		}
	})
	t.Run("watchdog", func(t *testing.T) {
		runtime := &fakeRuntime{}
		store := &memoryJournal{value: Journal{State: StatePending, LastKnownGoodRevision: "lkg", PendingRevision: "next", PendingDeadline: now.Add(-time.Second)}}
		if err := newTransaction(runtime, store, now).Expire(context.Background()); err != nil {
			t.Fatal(err)
		}
		if store.value.State != StateRolledBack {
			t.Fatalf("journal=%+v", store.value)
		}
	})
	t.Run("crash recovery", func(t *testing.T) {
		runtime := &fakeRuntime{}
		store := &memoryJournal{value: Journal{State: StatePending, LastKnownGoodRevision: "lkg", PendingRevision: "next"}}
		if err := newTransaction(runtime, store, now).Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		if store.value.State != StateRolledBack {
			t.Fatalf("journal=%+v", store.value)
		}
	})
	t.Run("degraded keeps LKG", func(t *testing.T) {
		runtime := &fakeRuntime{restoreFails: true}
		store := &memoryJournal{value: Journal{State: StatePending, LastKnownGoodRevision: "lkg", PendingRevision: "next"}}
		err := newTransaction(runtime, store, now).Recover(context.Background())
		if err == nil {
			t.Fatal("expected failure")
		}
		if store.value.State != StateDegraded || store.value.LastKnownGoodRevision != "lkg" {
			t.Fatalf("journal=%+v", store.value)
		}
	})
}

func TestRejectsTraversalAndConcurrentPendingApply(t *testing.T) {
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StatePending}}
	tx := newTransaction(runtime, store, time.Now())
	if err := tx.Apply(context.Background(), Candidate{RevisionID: "../escape"}); err == nil {
		t.Fatal("expected invalid ID")
	}
	if err := tx.Apply(context.Background(), Candidate{RevisionID: "safe"}); err == nil {
		t.Fatal("expected pending rejection")
	}
}
