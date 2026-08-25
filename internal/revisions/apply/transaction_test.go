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

type fakeLocker struct {
	fail     bool
	locked   bool
	unlocked bool
}

func (locker *fakeLocker) Lock(context.Context) (func() error, error) {
	if locker.fail {
		return nil, errors.New("lock failed")
	}
	if locker.locked && !locker.unlocked {
		return nil, errors.New("lock already held")
	}
	locker.locked = true
	locker.unlocked = false
	return func() error {
		locker.unlocked = true
		return nil
	}, nil
}

type fakeWatchdog struct {
	calls    *[]string
	action   func()
	fail     bool
	canceled bool
}

type fakePersistentWatchdog struct {
	state *fakePersistentWatchdogState
}

type fakePersistentWatchdogState struct {
	recovery   bool
	reconcile  bool
	arms       int
	commits    int
	disarms    int
	failCommit bool
}

func (watchdog *fakePersistentWatchdog) Arm(_ time.Time, action func()) (func(), error) {
	if action == nil || watchdog.state == nil {
		return nil, errors.New("watchdog action is required")
	}
	watchdog.state.arms++
	watchdog.state.recovery = true
	return func() {}, nil
}

func (watchdog *fakePersistentWatchdog) Commit() error {
	if watchdog.state == nil {
		return errors.New("watchdog state is required")
	}
	watchdog.state.commits++
	if watchdog.state.failCommit {
		return errors.New("injected persistent commit failure")
	}
	watchdog.state.reconcile = true
	watchdog.state.recovery = false
	return nil
}

func (watchdog *fakePersistentWatchdog) Disarm() error {
	if watchdog.state == nil {
		return errors.New("watchdog state is required")
	}
	watchdog.state.recovery = false
	watchdog.state.reconcile = false
	watchdog.state.disarms++
	return nil
}

type armAwareJournal struct {
	value      Journal
	watchdog   *fakeWatchdog
	sawArmedAt bool
}

func (store *armAwareJournal) Load() (Journal, error) { return store.value, nil }
func (store *armAwareJournal) Save(value Journal) error {
	if value.State == StatePending {
		store.sawArmedAt = store.watchdog.action != nil
	}
	store.value = value
	return nil
}

type mutableFakeClock struct{ now time.Time }

func (clock *mutableFakeClock) Now() time.Time { return clock.now }

type advancingCommitRuntime struct {
	*fakeRuntime
	clock *mutableFakeClock
}

func (runtime *advancingCommitRuntime) Commit(context.Context, string) error {
	runtime.calls = append(runtime.calls, "commit")
	runtime.clock.now = runtime.clock.now.Add(2 * time.Minute)
	return nil
}

func (watchdog *fakeWatchdog) Arm(_ time.Time, action func()) (func(), error) {
	if watchdog.fail {
		return nil, errors.New("watchdog failed")
	}
	if watchdog.calls != nil {
		*watchdog.calls = append(*watchdog.calls, "watchdog")
	}
	watchdog.action = action
	return func() {
		watchdog.canceled = true
	}, nil
}

type fakeRuntime struct {
	fail               string
	validateCandidate  func(Candidate) error
	calls              []string
	preflightRevisions []string
	reconcileRevision  string
	restoreFails       bool
	restoreErr         error
	restoreContextErr  error
	restoreHasDeadline bool
}

func (runtime *fakeRuntime) call(name string) error {
	runtime.calls = append(runtime.calls, name)
	if runtime.fail == name {
		return errors.New(name + " failed")
	}
	return nil
}
func (runtime *fakeRuntime) Stage(context.Context, Candidate) error { return runtime.call("stage") }
func (runtime *fakeRuntime) Preflight(_ context.Context, revisions []string) error {
	runtime.preflightRevisions = append([]string(nil), revisions...)
	return runtime.call("preflight")
}
func (runtime *fakeRuntime) Validate(_ context.Context, candidate Candidate) error {
	if err := runtime.call("validate"); err != nil {
		return err
	}
	if runtime.validateCandidate != nil {
		return runtime.validateCandidate(candidate)
	}
	return nil
}
func (runtime *fakeRuntime) Snapshot(context.Context, string) error { return runtime.call("snapshot") }
func (runtime *fakeRuntime) Activate(context.Context, Candidate) error {
	return runtime.call("activate")
}
func (runtime *fakeRuntime) Reload(context.Context) error    { return runtime.call("reload") }
func (runtime *fakeRuntime) PostCheck(context.Context) error { return runtime.call("post-check") }
func (runtime *fakeRuntime) Reconcile(_ context.Context, revision string) error {
	runtime.reconcileRevision = revision
	return runtime.call("reconcile")
}
func (runtime *fakeRuntime) Restore(ctx context.Context, _ string) error {
	runtime.calls = append(runtime.calls, "restore")
	runtime.restoreContextErr = ctx.Err()
	_, runtime.restoreHasDeadline = ctx.Deadline()
	if runtime.restoreErr != nil {
		return runtime.restoreErr
	}
	if runtime.restoreFails {
		return errors.New("restore failed")
	}
	return nil
}
func (runtime *fakeRuntime) EmergencyDisable(context.Context) error {
	return runtime.call("emergency-disable")
}
func (runtime *fakeRuntime) FullRestore(context.Context) error {
	return runtime.call("full-restore")
}

type failNthSaveJournal struct {
	value    Journal
	saves    int
	failSave int
}

func (store *failNthSaveJournal) Load() (Journal, error) { return store.value, nil }
func (store *failNthSaveJournal) Save(value Journal) error {
	store.saves++
	if store.saves == store.failSave {
		return errors.New("injected journal save failure")
	}
	store.value = value
	return nil
}

func TestRecoverReconcilesPersistedActiveRevisionAfterBoot(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	for _, test := range []struct {
		name    string
		journal Journal
	}{
		{
			name: "committed",
			journal: Journal{
				State:                 StateCommitted,
				ActiveRevision:        "active-revision",
				LastKnownGoodRevision: "active-revision",
			},
		},
		{
			name: "rolled back",
			journal: Journal{
				State:                 StateRolledBack,
				ActiveRevision:        "active-revision",
				LastKnownGoodRevision: "active-revision",
				RollbackResult:        "explicit rollback: restored",
			},
		},
		{
			name: "degraded",
			journal: Journal{
				State:                 StateDegraded,
				ActiveRevision:        "active-revision",
				LastKnownGoodRevision: "active-revision",
				RollbackResult:        "boot/crash recovery: failed",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &fakeRuntime{}
			store := &memoryJournal{value: test.journal}

			if err := newTransaction(runtime, store, now).Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if runtime.reconcileRevision != "active-revision" {
				t.Fatalf("reconciled revision = %q", runtime.reconcileRevision)
			}
			if strings.Join(runtime.preflightRevisions, ",") != "active-revision" {
				t.Fatalf("preflight revisions = %v", runtime.preflightRevisions)
			}
			if strings.Join(runtime.calls, ",") != "preflight,reconcile" {
				t.Fatalf("runtime calls = %v", runtime.calls)
			}
		})
	}
}

func TestRecoverLeavesIdleRuntimeUntouched(t *testing.T) {
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StateIdle}}

	if err := newTransaction(runtime, store, time.Unix(100, 0).UTC()).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(runtime.calls, ",") != "preflight" || len(runtime.preflightRevisions) != 0 {
		t.Fatalf("runtime calls = %v", runtime.calls)
	}
}

func TestRecoverRejectsOwnershipCollisionBeforeMutation(t *testing.T) {
	runtime := &fakeRuntime{fail: "preflight"}
	store := &memoryJournal{value: Journal{
		State:                 StatePending,
		ActiveRevision:        "lkg",
		LastKnownGoodRevision: "lkg",
		PendingRevision:       "candidate",
	}}

	err := newTransaction(runtime, store, time.Unix(100, 0).UTC()).Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("Recover() error = %v", err)
	}
	if strings.Join(runtime.preflightRevisions, ",") != "candidate,lkg" || strings.Join(runtime.calls, ",") != "preflight" {
		t.Fatalf("runtime calls = %v, preflight revisions = %v", runtime.calls, runtime.preflightRevisions)
	}
}

func newTransaction(runtime *fakeRuntime, store *memoryJournal, now time.Time) *Transaction {
	return &Transaction{
		Runtime:         runtime,
		Journal:         store,
		Clock:           fakeClock{now},
		ConfirmTimeout:  time.Minute,
		RecoveryTimeout: time.Second,
		Locker:          &fakeLocker{},
		Watchdog:        &fakeWatchdog{calls: &runtime.calls},
	}
}

func newPersistentTransaction(runtime *fakeRuntime, store JournalStore, now time.Time, state *fakePersistentWatchdogState) *Transaction {
	return &Transaction{
		Runtime:         runtime,
		Journal:         store,
		Clock:           fakeClock{now},
		ConfirmTimeout:  time.Minute,
		RecoveryTimeout: time.Second,
		Locker:          &fakeLocker{},
		Watchdog:        &fakePersistentWatchdog{state: state},
	}
}

func TestApplyCompensatesEveryMutationBoundary(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	for _, boundary := range []string{"preflight", "stage", "validate", "snapshot", "activate", "reload", "post-check"} {
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
		if !tx.Watchdog.(*fakeWatchdog).canceled {
			t.Fatal("confirmed transaction did not cancel watchdog")
		}
	})
	t.Run("candidate-bound confirm", func(t *testing.T) {
		candidate := Candidate{RevisionID: "next", Routes: []byte("candidate-a")}
		runtime := &fakeRuntime{}
		runtime.validateCandidate = func(got Candidate) error {
			if string(got.Routes) != string(candidate.Routes) {
				return errors.New("candidate bytes differ")
			}
			return nil
		}
		store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg"}}
		tx := newTransaction(runtime, store, now)
		if err := tx.Apply(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
		if err := tx.ConfirmCandidate(context.Background(), Candidate{RevisionID: "other", Routes: candidate.Routes}); err == nil {
			t.Fatal("different revision unexpectedly confirmed")
		}
		if err := tx.ConfirmCandidate(context.Background(), Candidate{RevisionID: candidate.RevisionID, Routes: []byte("candidate-b")}); err == nil {
			t.Fatal("different candidate bytes unexpectedly confirmed")
		}
		if store.value.State != StatePending || store.value.PendingRevision != candidate.RevisionID {
			t.Fatalf("mismatched confirmation changed journal: %+v", store.value)
		}
		if err := tx.ConfirmCandidate(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
		if store.value.State != StateCommitted || store.value.ActiveRevision != candidate.RevisionID {
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

func TestApplyArmsWatchdogBeforeActivationAndCancelsItAfterSuccessfulRecovery(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{fail: "activate"}
	store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg"}}
	tx := newTransaction(runtime, store, now)
	err := tx.Apply(context.Background(), Candidate{RevisionID: "next"})
	if err == nil {
		t.Fatal("expected activation failure")
	}
	wantCalls := []string{"preflight", "stage", "validate", "snapshot", "watchdog", "activate", "restore"}
	if strings.Join(runtime.calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls = %v, want %v", runtime.calls, wantCalls)
	}
	if !tx.Watchdog.(*fakeWatchdog).canceled {
		t.Fatal("failed transaction did not cancel watchdog")
	}
}

func TestApplyPublishesPendingJournalOnlyAfterWatchdogIsArmed(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	watchdog := &fakeWatchdog{}
	store := &armAwareJournal{
		value:    Journal{State: StateCommitted, ActiveRevision: "lkg", LastKnownGoodRevision: "lkg"},
		watchdog: watchdog,
	}
	tx := &Transaction{
		Runtime:         runtime,
		Journal:         store,
		Clock:           fakeClock{now},
		ConfirmTimeout:  time.Minute,
		RecoveryTimeout: time.Second,
		Locker:          &fakeLocker{},
		Watchdog:        watchdog,
	}
	if err := tx.Apply(context.Background(), Candidate{RevisionID: "next"}); err != nil {
		t.Fatal(err)
	}
	if !store.sawArmedAt || store.value.State != StatePending {
		t.Fatalf("pending journal was published without durable watchdog boundary: %+v", store.value)
	}
}

func TestPersistentWatchdogCanBeCommittedByFreshConfirmProcess(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg", LastKnownGoodRevision: "lkg"}}
	watchdogState := &fakePersistentWatchdogState{reconcile: true}
	candidate := Candidate{RevisionID: "next", Routes: []byte("candidate")}
	applyTx := newTransaction(runtime, store, now)
	applyTx.Watchdog = &fakePersistentWatchdog{state: watchdogState}
	if err := applyTx.Apply(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if !watchdogState.recovery {
		t.Fatal("persistent watchdog was not registered")
	}
	confirmTx := newTransaction(runtime, store, now)
	confirmTx.Watchdog = &fakePersistentWatchdog{state: watchdogState}
	if err := confirmTx.ConfirmCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if watchdogState.recovery || !watchdogState.reconcile || watchdogState.commits != 1 || watchdogState.disarms != 0 || store.value.State != StateCommitted {
		t.Fatalf("fresh-process commit failed: watchdog=%+v journal=%+v", watchdogState, store.value)
	}
}

func TestPersistentWatchdogCommitFailureIsRecoveredByFreshProcess(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{
		State:                 StatePending,
		ActiveRevision:        "lkg",
		LastKnownGoodRevision: "lkg",
		PendingRevision:       "next",
		PendingDeadline:       now.Add(time.Minute),
	}}
	watchdogState := &fakePersistentWatchdogState{recovery: true, failCommit: true}
	err := newPersistentTransaction(runtime, store, now, watchdogState).Confirm()
	if err == nil || !strings.Contains(err.Error(), "commit persistent watchdog") {
		t.Fatalf("commit failure = %v", err)
	}
	if store.value.State != StateCommitted || store.value.ActiveRevision != "next" || !watchdogState.recovery || watchdogState.reconcile {
		t.Fatalf("crash boundary lost recovery coverage: journal=%+v watchdog=%+v", store.value, watchdogState)
	}
	watchdogState.failCommit = false
	if err := newPersistentTransaction(runtime, store, now, watchdogState).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if watchdogState.recovery || !watchdogState.reconcile || watchdogState.commits != 2 || runtime.reconcileRevision != "next" {
		t.Fatalf("fresh-process repair failed: watchdog=%+v reconcile=%q", watchdogState, runtime.reconcileRevision)
	}
}

func TestPersistentWatchdogPendingJournalFailureRestoresCommittedCoverage(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "active", LastKnownGoodRevision: "active"}, failSave: true}
	watchdogState := &fakePersistentWatchdogState{reconcile: true}
	err := newPersistentTransaction(runtime, store, now, watchdogState).Apply(context.Background(), Candidate{RevisionID: "next"})
	if err == nil || !strings.Contains(err.Error(), "save failed") {
		t.Fatalf("pending journal failure = %v", err)
	}
	if store.value.State != StateCommitted || store.value.ActiveRevision != "active" || watchdogState.recovery || !watchdogState.reconcile || watchdogState.arms != 1 || watchdogState.commits != 1 || watchdogState.disarms != 0 {
		t.Fatalf("committed coverage after journal failure: journal=%+v watchdog=%+v", store.value, watchdogState)
	}
}

func TestPersistentWatchdogRollbackKeepsReconcileOnlyWithLKG(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	for _, test := range []struct {
		name          string
		lkg           string
		wantReconcile bool
		wantCommits   int
		wantDisarms   int
	}{
		{name: "with LKG", lkg: "lkg", wantReconcile: true, wantCommits: 1},
		{name: "without LKG", wantDisarms: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &fakeRuntime{}
			store := &memoryJournal{value: Journal{State: StatePending, ActiveRevision: test.lkg, LastKnownGoodRevision: test.lkg, PendingRevision: "next"}}
			watchdogState := &fakePersistentWatchdogState{recovery: true, reconcile: test.lkg != ""}
			if err := newPersistentTransaction(runtime, store, now, watchdogState).Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if store.value.State != StateRolledBack || store.value.ActiveRevision != test.lkg || watchdogState.recovery || watchdogState.reconcile != test.wantReconcile || watchdogState.commits != test.wantCommits || watchdogState.disarms != test.wantDisarms {
				t.Fatalf("rollback state: journal=%+v watchdog=%+v", store.value, watchdogState)
			}
		})
	}
}

func TestPersistentWatchdogRollbackRetryRepairsSettledJournal(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{
		State:                 StatePending,
		ActiveRevision:        "lkg",
		LastKnownGoodRevision: "lkg",
		PendingRevision:       "next",
		PendingDeadline:       now.Add(time.Minute),
	}}
	watchdogState := &fakePersistentWatchdogState{recovery: true, failCommit: true}

	err := newPersistentTransaction(runtime, store, now, watchdogState).Rollback(context.Background())
	if err == nil || !strings.Contains(err.Error(), "commit persistent watchdog") {
		t.Fatalf("first rollback error = %v", err)
	}
	if store.value.State != StateRolledBack || strings.Join(runtime.calls, ",") != "preflight,restore" || !watchdogState.recovery {
		t.Fatalf("first rollback boundary: journal=%+v calls=%v watchdog=%+v", store.value, runtime.calls, watchdogState)
	}

	watchdogState.failCommit = false
	if err := newPersistentTransaction(runtime, store, now, watchdogState).Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(runtime.calls, ",") != "preflight,restore" {
		t.Fatalf("retry repeated network restore: calls=%v", runtime.calls)
	}
	if watchdogState.recovery || !watchdogState.reconcile || watchdogState.commits != 2 {
		t.Fatalf("watchdog repair failed: %+v", watchdogState)
	}
}

func TestPersistentWatchdogRepeatedBootReconcileIsIdempotent(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "active", LastKnownGoodRevision: "active"}}
	watchdogState := &fakePersistentWatchdogState{reconcile: true}
	for boot := 0; boot < 2; boot++ {
		if err := newPersistentTransaction(runtime, store, now, watchdogState).Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if watchdogState.recovery || !watchdogState.reconcile || watchdogState.commits != 2 || watchdogState.disarms != 0 {
		t.Fatalf("repeated boot watchdog state = %+v", watchdogState)
	}
	if strings.Join(runtime.calls, ",") != "preflight,reconcile,preflight,reconcile" {
		t.Fatalf("repeated boot runtime calls = %v", runtime.calls)
	}
}

func TestPersistentWatchdogFullRestoreDisarmsBothTasks(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "active", LastKnownGoodRevision: "active"}}
	watchdogState := &fakePersistentWatchdogState{reconcile: true}
	if err := newPersistentTransaction(runtime, store, now, watchdogState).FullRestore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.value.State != StateRestored || store.value.ActiveRevision != "" || watchdogState.recovery || watchdogState.reconcile || watchdogState.disarms != 1 {
		t.Fatalf("full restore state: journal=%+v watchdog=%+v", store.value, watchdogState)
	}
}

func TestConfirmCandidateRollsBackWhenDeadlineExpiresDuringCommit(t *testing.T) {
	clock := &mutableFakeClock{now: time.Unix(100, 0).UTC()}
	baseRuntime := &fakeRuntime{}
	runtime := &advancingCommitRuntime{fakeRuntime: baseRuntime, clock: clock}
	store := &memoryJournal{value: Journal{
		State:                 StatePending,
		ActiveRevision:        "lkg",
		LastKnownGoodRevision: "lkg",
		PendingRevision:       "next",
		PendingDeadline:       clock.now.Add(time.Minute),
	}}
	watchdogState := &fakePersistentWatchdogState{recovery: true, reconcile: true}
	tx := &Transaction{
		Runtime:         runtime,
		Journal:         store,
		Clock:           clock,
		RecoveryTimeout: time.Second,
		Locker:          &fakeLocker{},
		Watchdog:        &fakePersistentWatchdog{state: watchdogState},
	}
	err := tx.ConfirmCandidate(context.Background(), Candidate{RevisionID: "next"})
	if err == nil || !strings.Contains(err.Error(), "expired during commit") {
		t.Fatalf("confirmation result = %v", err)
	}
	if store.value.State != StateRolledBack || store.value.ActiveRevision != "lkg" || watchdogState.recovery || !watchdogState.reconcile || watchdogState.commits != 1 || watchdogState.disarms != 0 {
		t.Fatalf("deadline-race recovery failed: journal=%+v watchdog=%+v", store.value, watchdogState)
	}
	if strings.Join(baseRuntime.calls, ",") != "validate,commit,restore" {
		t.Fatalf("runtime calls = %v", baseRuntime.calls)
	}
}

func TestApplyRecoveryIgnoresCanceledCallerAndKeepsWatchdogArmedOnRestoreFailure(t *testing.T) {
	t.Run("canceled caller", func(t *testing.T) {
		now := time.Unix(100, 0).UTC()
		runtime := &fakeRuntime{fail: "activate"}
		store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg"}}
		tx := newTransaction(runtime, store, now)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := tx.Apply(ctx, Candidate{RevisionID: "next"}); err == nil {
			t.Fatal("expected activation failure")
		}
		if runtime.restoreContextErr != nil || !runtime.restoreHasDeadline {
			t.Fatalf("restore context: err=%v deadline=%v", runtime.restoreContextErr, runtime.restoreHasDeadline)
		}
		if !tx.Watchdog.(*fakeWatchdog).canceled {
			t.Fatal("successful recovery did not cancel watchdog")
		}
	})

	t.Run("restore failure", func(t *testing.T) {
		now := time.Unix(100, 0).UTC()
		runtime := &fakeRuntime{fail: "activate", restoreFails: true}
		store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg"}}
		tx := newTransaction(runtime, store, now)

		if err := tx.Apply(context.Background(), Candidate{RevisionID: "next"}); err == nil || !strings.Contains(err.Error(), "rollback failed") {
			t.Fatalf("Apply() error = %v", err)
		}
		if tx.Watchdog.(*fakeWatchdog).canceled {
			t.Fatal("failed recovery canceled watchdog")
		}
		if store.value.State != StateDegraded {
			t.Fatalf("journal = %+v", store.value)
		}
	})

	t.Run("semantic restore mismatch", func(t *testing.T) {
		now := time.Unix(100, 0).UTC()
		runtime := &fakeRuntime{
			fail:       "post-check",
			restoreErr: errors.New("restore post-check: nft semantics drifted"),
		}
		store := &memoryJournal{value: Journal{
			State:                 StateCommitted,
			ActiveRevision:        "lkg",
			LastKnownGoodRevision: "lkg",
		}}
		tx := newTransaction(runtime, store, now)

		if err := tx.Apply(context.Background(), Candidate{RevisionID: "next"}); err == nil || !strings.Contains(err.Error(), "rollback failed") {
			t.Fatalf("Apply() error = %v", err)
		}
		if tx.Watchdog.(*fakeWatchdog).canceled {
			t.Fatal("semantic restore mismatch canceled watchdog")
		}
		if store.value.State != StateDegraded || store.value.LastKnownGoodRevision != "lkg" {
			t.Fatalf("journal = %+v", store.value)
		}
	})
}

func TestExplicitRollbackUsesBoundedRecoveryContextAfterCallerCancellation(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg", LastKnownGoodRevision: "lkg"}}
	tx := newTransaction(runtime, store, now)
	if err := tx.Apply(context.Background(), Candidate{RevisionID: "next"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if runtime.restoreContextErr != nil || !runtime.restoreHasDeadline {
		t.Fatalf("restore context: err=%v deadline=%v", runtime.restoreContextErr, runtime.restoreHasDeadline)
	}
	if !tx.Watchdog.(*fakeWatchdog).canceled {
		t.Fatal("successful explicit rollback did not cancel watchdog")
	}
	if store.value.State != StateRolledBack || store.value.ActiveRevision != "lkg" {
		t.Fatalf("journal = %+v", store.value)
	}
}

func TestApplyWatchdogArmFailureRestoresJournalWithoutActivation(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StateCommitted, ActiveRevision: "lkg", LastKnownGoodRevision: "lkg"}}
	tx := newTransaction(runtime, store, now)
	tx.Watchdog = &fakeWatchdog{fail: true}

	err := tx.Apply(context.Background(), Candidate{RevisionID: "next"})
	if err == nil || !strings.Contains(err.Error(), "arm watchdog") {
		t.Fatalf("Apply() error = %v", err)
	}
	if store.value.State != StateCommitted || store.value.ActiveRevision != "lkg" || store.value.PendingRevision != "" {
		t.Fatalf("journal = %+v", store.value)
	}
	if strings.Contains(strings.Join(runtime.calls, ","), "activate") {
		t.Fatalf("runtime calls = %v", runtime.calls)
	}
}

func TestTransactionRequiresAndReleasesOperationLock(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	runtime := &fakeRuntime{}
	store := &memoryJournal{value: Journal{State: StateCommitted}}
	tx := newTransaction(runtime, store, now)
	locker := tx.Locker.(*fakeLocker)
	locker.fail = true
	if err := tx.Apply(context.Background(), Candidate{RevisionID: "next"}); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("runtime called without lock: %v", runtime.calls)
	}

	locker.fail = false
	if err := tx.Apply(context.Background(), Candidate{RevisionID: "next"}); err != nil {
		t.Fatal(err)
	}
	if !locker.unlocked {
		t.Fatal("operation lock was not released")
	}
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

func TestRecoveryOperationIntentSurvivesCompletionSaveFailure(t *testing.T) {
	runtime := &fakeRuntime{}
	store := &failNthSaveJournal{
		value:    Journal{State: StateCommitted, ActiveRevision: "active", LastKnownGoodRevision: "active"},
		failSave: 2,
	}
	tx := &Transaction{Runtime: runtime, Journal: store, Clock: fakeClock{time.Now()}, RecoveryTimeout: time.Second, Locker: &fakeLocker{}, Watchdog: &fakeWatchdog{calls: &runtime.calls}}
	if err := tx.EmergencyDisable(context.Background()); err == nil {
		t.Fatal("completion journal save failure was ignored")
	}
	if store.value.State != StateDisabling {
		t.Fatalf("durable intent was lost: %#v", store.value)
	}
	store.failSave = 0
	if err := tx.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.value.State != StateDisabled {
		t.Fatalf("recovered journal = %#v", store.value)
	}
}

func TestApplyBlockedInUnsafeJournalStates(t *testing.T) {
	tests := []Journal{
		{State: StateDegraded, ActiveRevision: "active", LastKnownGoodRevision: "active", RollbackResult: "failed"},
		{State: StateDisabling, ActiveRevision: "active", LastKnownGoodRevision: "active", RollbackResult: "intent"},
		{State: StateDisabled, ActiveRevision: "active", LastKnownGoodRevision: "active", RollbackResult: "completed"},
		{State: StateRestoring, ActiveRevision: "active", LastKnownGoodRevision: "active", RollbackResult: "intent"},
	}
	for _, journal := range tests {
		runtime := &fakeRuntime{}
		tx := newTransaction(runtime, &memoryJournal{value: journal}, time.Now())
		if err := tx.Apply(context.Background(), Candidate{RevisionID: "next"}); err == nil {
			t.Fatalf("apply allowed from %q", journal.State)
		}
		if len(runtime.calls) != 0 {
			t.Fatalf("runtime called from %q: %v", journal.State, runtime.calls)
		}
	}
}
