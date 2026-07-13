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
	DNS        []byte
	Routes     []byte
}

type Runtime interface {
	Stage(context.Context, Candidate) error
	Validate(context.Context, Candidate) error
	Snapshot(context.Context, string) error
	Activate(context.Context, Candidate) error
	Reload(context.Context) error
	PostCheck(context.Context) error
	Restore(context.Context, string) error
}

type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type Transaction struct {
	Runtime        Runtime
	Journal        JournalStore
	Clock          Clock
	ConfirmTimeout time.Duration
	mu             sync.Mutex
}

func (tx *Transaction) Apply(ctx context.Context, candidate Candidate) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
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
	if current.State == StatePending {
		return errors.New("another revision is pending confirmation")
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
	if err := tx.Runtime.Activate(ctx, candidate); err != nil {
		return tx.rollbackAfterFailure(ctx, pending, "activate", err)
	}
	if err := tx.Runtime.Reload(ctx); err != nil {
		return tx.rollbackAfterFailure(ctx, pending, "reload", err)
	}
	if err := tx.Runtime.PostCheck(ctx); err != nil {
		return tx.rollbackAfterFailure(ctx, pending, "post-check", err)
	}
	return nil
}

func (tx *Transaction) Confirm() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
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
	journal.State = StateCommitted
	journal.ActiveRevision = journal.PendingRevision
	journal.LastKnownGoodRevision = journal.PendingRevision
	journal.PendingRevision = ""
	journal.PendingDeadline = time.Time{}
	return tx.Journal.Save(journal)
}

func (tx *Transaction) Rollback(ctx context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	journal, err := tx.Journal.Load()
	if err != nil {
		return err
	}
	if journal.State != StatePending {
		return errors.New("no revision is pending confirmation")
	}
	return tx.restore(ctx, journal, "explicit rollback")
}

func (tx *Transaction) Recover(ctx context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	journal, err := tx.Journal.Load()
	if err != nil {
		return err
	}
	if journal.State != StatePending {
		return nil
	}
	return tx.restore(ctx, journal, "boot/crash recovery")
}

func (tx *Transaction) Expire(ctx context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
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
	return tx.restore(ctx, journal, "watchdog expiry")
}

func (tx *Transaction) rollbackAfterFailure(ctx context.Context, journal Journal, boundary string, cause error) error {
	err := tx.restore(ctx, journal, boundary)
	if err != nil {
		return errors.Join(fmt.Errorf("%s: %w", boundary, cause), err)
	}
	return fmt.Errorf("%s: %w", boundary, cause)
}

func (tx *Transaction) restore(ctx context.Context, journal Journal, reason string) error {
	err := tx.Runtime.Restore(ctx, journal.LastKnownGoodRevision)
	journal.PendingRevision = ""
	journal.PendingDeadline = time.Time{}
	journal.ActiveRevision = journal.LastKnownGoodRevision
	if err != nil {
		journal.State = StateDegraded
		journal.RollbackResult = reason + ": failed"
		_ = tx.Journal.Save(journal)
		return fmt.Errorf("rollback failed; last-known-good snapshot retained: %w", err)
	}
	journal.State = StateRolledBack
	journal.RollbackResult = reason + ": restored"
	if saveErr := tx.Journal.Save(journal); saveErr != nil {
		return saveErr
	}
	return nil
}
