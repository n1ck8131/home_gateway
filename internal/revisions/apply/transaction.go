package apply

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Candidate struct {
	RevisionID string
	NFT        []byte
	// Firewall carries a platform-specific structured firewall artifact.
	// Linux continues to use NFT; runtimes must not interpret one as the other.
	Firewall []byte
	DNS      []byte
	Routes   []byte
}

type Runtime interface {
	Preflight(context.Context, []string) error
	Stage(context.Context, Candidate) error
	Validate(context.Context, Candidate) error
	Snapshot(context.Context, string) error
	Activate(context.Context, Candidate) error
	Reload(context.Context) error
	PostCheck(context.Context) error
	Reconcile(context.Context, string) error
	Restore(context.Context, string) error
}

type RecoveryPreflighter interface {
	PreflightRecovery(context.Context, Journal) error
}

type RecoveryOperator interface {
	EmergencyDisable(context.Context) error
	FullRestore(context.Context) error
}

type CommitRuntime interface {
	Commit(context.Context, string) error
}

type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type Transaction struct {
	Runtime         Runtime
	Journal         JournalStore
	Clock           Clock
	ConfirmTimeout  time.Duration
	RecoveryTimeout time.Duration
	Locker          Locker
	Watchdog        Watchdog
	mu              sync.Mutex
	watchdogMu      sync.Mutex
	watchdogCancel  func()
}

func (tx *Transaction) Apply(ctx context.Context, candidate Candidate) (resultErr error) {
	release, err := tx.acquire(ctx)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, release())
	}()
	if !validRevisionID(candidate.RevisionID) {
		return errors.New("invalid revision ID")
	}
	if tx.Runtime == nil || tx.Journal == nil {
		return errors.New("runtime and journal are required")
	}
	clock := tx.Clock
	if clock == nil {
		clock = systemClock{}
	}
	timeout := tx.ConfirmTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	current, err := tx.Journal.Load()
	if err != nil {
		return err
	}
	if current.State == StatePending || current.State == StateDegraded || current.State == StateDisabling || current.State == StateDisabled || current.State == StateRestoring {
		return fmt.Errorf("apply is blocked while journal state is %q", current.State)
	}
	if err := tx.Runtime.Preflight(ctx, ownedRevisions(current)); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	if err := tx.Runtime.Stage(ctx, candidate); err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	if err := tx.Runtime.Validate(ctx, candidate); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	if err := tx.Runtime.Snapshot(ctx, current.ActiveRevision); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	pending := current
	pending.State = StatePending
	pending.LastKnownGoodRevision = current.ActiveRevision
	pending.PendingRevision = candidate.RevisionID
	pending.PendingDeadline = clock.Now().Add(timeout)
	pending.RollbackResult = ""
	if err := tx.Journal.Save(pending); err != nil {
		return err
	}
	if err := tx.armWatchdog(pending.PendingDeadline); err != nil {
		restoreJournalErr := tx.Journal.Save(current)
		if restoreJournalErr != nil {
			return errors.Join(fmt.Errorf("arm watchdog: %w", err), fmt.Errorf("restore journal: %w", restoreJournalErr))
		}
		return fmt.Errorf("arm watchdog: %w", err)
	}
	if err := tx.Runtime.Activate(ctx, candidate); err != nil {
		return tx.rollbackAfterFailure(pending, "activate", err)
	}
	if err := tx.Runtime.Reload(ctx); err != nil {
		return tx.rollbackAfterFailure(pending, "reload", err)
	}
	if err := tx.Runtime.PostCheck(ctx); err != nil {
		return tx.rollbackAfterFailure(pending, "post-check", err)
	}
	return nil
}

func (tx *Transaction) Confirm() (resultErr error) {
	release, err := tx.acquire(context.Background())
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, release())
	}()
	if tx.Journal == nil {
		return errors.New("journal is required")
	}
	journal, err := tx.Journal.Load()
	if err != nil {
		return err
	}
	if journal.State != StatePending {
		return errors.New("no revision is pending confirmation")
	}
	clock := tx.Clock
	if clock == nil {
		clock = systemClock{}
	}
	if !clock.Now().Before(journal.PendingDeadline) {
		return errors.New("confirmation deadline has expired")
	}
	if runtime, ok := tx.Runtime.(CommitRuntime); ok {
		if err := runtime.Commit(context.Background(), journal.PendingRevision); err != nil {
			return fmt.Errorf("commit runtime revision pointer: %w", err)
		}
	}
	journal.State = StateCommitted
	journal.ActiveRevision = journal.PendingRevision
	journal.LastKnownGoodRevision = journal.PendingRevision
	journal.PendingRevision = ""
	journal.PendingDeadline = time.Time{}
	if err := tx.Journal.Save(journal); err != nil {
		return err
	}
	tx.cancelWatchdog()
	return nil
}

func (tx *Transaction) Rollback(_ context.Context) (resultErr error) {
	recoveryCtx, cancel := tx.recoveryContext()
	defer cancel()
	release, err := tx.acquire(recoveryCtx)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, release())
	}()
	if tx.Runtime == nil || tx.Journal == nil {
		return errors.New("runtime and journal are required")
	}
	journal, err := tx.Journal.Load()
	if err != nil {
		return err
	}
	if journal.State != StatePending {
		return errors.New("no revision is pending confirmation")
	}
	if err := tx.preflightRecovery(recoveryCtx, journal); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	err = tx.restore(recoveryCtx, journal, "explicit rollback")
	if err == nil {
		tx.cancelWatchdog()
	}
	return err
}

func (tx *Transaction) Recover(ctx context.Context) (resultErr error) {
	acquireCtx, acquireCancel := tx.recoveryContext()
	defer acquireCancel()
	release, err := tx.acquire(acquireCtx)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, release())
	}()
	if tx.Runtime == nil || tx.Journal == nil {
		return errors.New("runtime and journal are required")
	}
	journal, err := tx.Journal.Load()
	if err != nil {
		return err
	}
	if journal.State == StatePending {
		recoveryCtx, cancel := tx.recoveryContext()
		defer cancel()
		if err := tx.preflightRecovery(recoveryCtx, journal); err != nil {
			return fmt.Errorf("preflight: %w", err)
		}
		err = tx.restore(recoveryCtx, journal, "boot/crash recovery")
		if err == nil {
			tx.cancelWatchdog()
		}
		return err
	}
	if journal.State == StateDegraded && journal.FailedRevision != "" {
		recoveryCtx, cancel := tx.recoveryContext()
		defer cancel()
		if err := tx.preflightRecovery(recoveryCtx, journal); err != nil {
			return fmt.Errorf("preflight: %w", err)
		}
		return tx.restore(recoveryCtx, journal, "degraded rollback retry")
	}
	if journal.State == StateDisabling || journal.State == StateRestoring {
		recoveryCtx, cancel := tx.recoveryContext()
		defer cancel()
		return tx.resumeRecoveryOperation(recoveryCtx, journal)
	}
	if journal.State == StateDisabled || journal.State == StateRestored {
		return nil
	}
	if err := tx.Runtime.Preflight(ctx, ownedRevisions(journal)); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	if journal.ActiveRevision == "" {
		return nil
	}
	if err := tx.Runtime.Reconcile(ctx, journal.ActiveRevision); err != nil {
		return fmt.Errorf("reconcile active revision %q: %w", journal.ActiveRevision, err)
	}
	return nil
}

func (tx *Transaction) Expire(_ context.Context) (resultErr error) {
	recoveryCtx, cancel := tx.recoveryContext()
	defer cancel()
	release, err := tx.acquire(recoveryCtx)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, release())
	}()
	if tx.Runtime == nil || tx.Journal == nil {
		return errors.New("runtime and journal are required")
	}
	journal, err := tx.Journal.Load()
	if err != nil {
		return err
	}
	if journal.State != StatePending {
		return nil
	}
	clock := tx.Clock
	if clock == nil {
		clock = systemClock{}
	}
	if clock.Now().Before(journal.PendingDeadline) {
		return nil
	}
	if err := tx.preflightRecovery(recoveryCtx, journal); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	err = tx.restore(recoveryCtx, journal, "watchdog expiry")
	if err == nil {
		tx.cancelWatchdog()
	}
	return err
}

func (tx *Transaction) EmergencyDisable(ctx context.Context) (resultErr error) {
	return tx.runRecoveryOperation(ctx, StateDisabling, StateDisabled, "emergency disable", func(operator RecoveryOperator, operationCtx context.Context) error {
		return operator.EmergencyDisable(operationCtx)
	})
}

func (tx *Transaction) FullRestore(ctx context.Context) (resultErr error) {
	return tx.runRecoveryOperation(ctx, StateRestoring, StateRestored, "full restore", func(operator RecoveryOperator, operationCtx context.Context) error {
		return operator.FullRestore(operationCtx)
	})
}

func (tx *Transaction) runRecoveryOperation(ctx context.Context, intent, complete State, label string, action func(RecoveryOperator, context.Context) error) (resultErr error) {
	release, err := tx.acquire(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, release()) }()
	operator, ok := tx.Runtime.(RecoveryOperator)
	if !ok || tx.Journal == nil {
		return errors.New("runtime recovery operator and journal are required")
	}
	journal, err := tx.Journal.Load()
	if err != nil {
		return err
	}
	if intent == StateDisabling {
		if journal.State == StateDisabled {
			return nil
		}
		if journal.State != StateCommitted && journal.State != StateRolledBack {
			return fmt.Errorf("emergency disable is not allowed from journal state %q", journal.State)
		}
		if journal.ActiveRevision == "" {
			return errors.New("emergency disable requires an active revision")
		}
	} else {
		if journal.State == StateRestored {
			return nil
		}
		if journal.State != StateCommitted && journal.State != StateRolledBack && journal.State != StateDisabled {
			return fmt.Errorf("full restore is not allowed from journal state %q", journal.State)
		}
	}
	if err := tx.preflightRecovery(ctx, journal); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	journal.State = intent
	journal.FailedRevision = ""
	journal.RollbackResult = label + ": intent"
	if err := tx.Journal.Save(journal); err != nil {
		return err
	}
	if err := action(operator, ctx); err != nil {
		journal.RollbackResult = label + ": retry required"
		_ = tx.Journal.Save(journal)
		return fmt.Errorf("%s: %w", label, err)
	}
	journal.State = complete
	journal.RollbackResult = label + ": completed"
	if complete == StateRestored {
		journal.ActiveRevision = ""
		journal.LastKnownGoodRevision = ""
	}
	return tx.Journal.Save(journal)
}

func (tx *Transaction) resumeRecoveryOperation(ctx context.Context, journal Journal) error {
	operator, ok := tx.Runtime.(RecoveryOperator)
	if !ok {
		return errors.New("runtime recovery operator is required")
	}
	if err := tx.preflightRecovery(ctx, journal); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	var err error
	complete := StateDisabled
	label := "emergency disable"
	if journal.State == StateDisabling {
		err = operator.EmergencyDisable(ctx)
	} else {
		complete = StateRestored
		label = "full restore"
		err = operator.FullRestore(ctx)
	}
	if err != nil {
		journal.RollbackResult = label + ": retry required"
		_ = tx.Journal.Save(journal)
		return fmt.Errorf("resume %s: %w", label, err)
	}
	journal.State = complete
	journal.RollbackResult = label + ": completed"
	if complete == StateRestored {
		journal.ActiveRevision = ""
		journal.LastKnownGoodRevision = ""
	}
	return tx.Journal.Save(journal)
}

func (tx *Transaction) preflightRecovery(ctx context.Context, journal Journal) error {
	if runtime, ok := tx.Runtime.(RecoveryPreflighter); ok {
		return runtime.PreflightRecovery(ctx, journal)
	}
	return tx.Runtime.Preflight(ctx, ownedRevisions(journal))
}

func ownedRevisions(journal Journal) []string {
	values := []string{journal.ActiveRevision}
	if journal.State == StatePending {
		values = []string{journal.PendingRevision, journal.ActiveRevision, journal.LastKnownGoodRevision}
	} else if journal.State == StateDegraded && journal.FailedRevision != "" {
		values = []string{journal.FailedRevision, journal.ActiveRevision, journal.LastKnownGoodRevision}
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, revision := range values {
		if revision == "" {
			continue
		}
		if _, exists := seen[revision]; exists {
			continue
		}
		seen[revision] = struct{}{}
		result = append(result, revision)
	}
	return result
}

func (tx *Transaction) acquire(ctx context.Context) (func() error, error) {
	tx.mu.Lock()
	if tx.Locker == nil {
		tx.mu.Unlock()
		return nil, errors.New("operation locker is required")
	}
	unlock, err := tx.Locker.Lock(ctx)
	if err != nil {
		tx.mu.Unlock()
		return nil, err
	}
	return func() error {
		err := unlock()
		tx.mu.Unlock()
		return err
	}, nil
}

func (tx *Transaction) armWatchdog(deadline time.Time) error {
	watchdog := tx.Watchdog
	if watchdog == nil {
		watchdog = TimerWatchdog{}
	}
	cancel, err := watchdog.Arm(deadline, func() {
		_ = tx.Expire(context.Background())
	})
	if err != nil {
		return err
	}
	tx.watchdogMu.Lock()
	previous := tx.watchdogCancel
	tx.watchdogCancel = cancel
	tx.watchdogMu.Unlock()
	if previous != nil {
		previous()
	}
	return nil
}

func (tx *Transaction) cancelWatchdog() {
	tx.watchdogMu.Lock()
	cancel := tx.watchdogCancel
	tx.watchdogCancel = nil
	tx.watchdogMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (tx *Transaction) rollbackAfterFailure(journal Journal, boundary string, cause error) error {
	ctx, cancel := tx.recoveryContext()
	defer cancel()
	err := tx.restore(ctx, journal, boundary)
	if err != nil {
		return errors.Join(fmt.Errorf("%s: %w", boundary, cause), err)
	}
	tx.cancelWatchdog()
	return fmt.Errorf("%s: %w", boundary, cause)
}

func (tx *Transaction) recoveryContext() (context.Context, context.CancelFunc) {
	timeout := tx.RecoveryTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (tx *Transaction) restore(ctx context.Context, journal Journal, reason string) error {
	failedRevision := journal.PendingRevision
	if failedRevision == "" {
		failedRevision = journal.FailedRevision
	}
	err := tx.Runtime.Restore(ctx, journal.LastKnownGoodRevision)
	journal.PendingRevision = ""
	journal.PendingDeadline = time.Time{}
	journal.ActiveRevision = journal.LastKnownGoodRevision
	if err != nil {
		journal.State = StateDegraded
		journal.FailedRevision = failedRevision
		journal.RollbackResult = reason + ": failed"
		_ = tx.Journal.Save(journal)
		return fmt.Errorf("rollback failed; last-known-good snapshot retained: %w", err)
	}
	journal.State = StateRolledBack
	journal.FailedRevision = ""
	journal.RollbackResult = reason + ": restored"
	if saveErr := tx.Journal.Save(journal); saveErr != nil {
		return saveErr
	}
	return nil
}
