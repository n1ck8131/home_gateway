package apply

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type State string

const (
	StateIdle       State = "idle"
	StatePending    State = "pending-confirmation"
	StateCommitted  State = "committed"
	StateRolledBack State = "rolled-back"
	StateDegraded   State = "degraded"
)

type Journal struct {
	State                 State     `json:"state"`
	ActiveRevision        string    `json:"active_revision,omitempty"`
	LastKnownGoodRevision string    `json:"last_known_good_revision,omitempty"`
	PendingRevision       string    `json:"pending_revision,omitempty"`
	PendingDeadline       time.Time `json:"pending_deadline,omitempty"`
	RollbackResult        string    `json:"rollback_result,omitempty"`
}

type JournalStore interface {
	Load() (Journal, error)
	Save(Journal) error
}

type FileJournal struct{ Path string }

func (store FileJournal) Load() (Journal, error) {
	if err := store.validatePath(); err != nil {
		return Journal{}, err
	}
	data, err := readRegularFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Journal{State: StateIdle}, nil
	}
	if err != nil {
		return Journal{}, fmt.Errorf("read journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal Journal
	if err := decoder.Decode(&journal); err != nil {
		return Journal{}, fmt.Errorf("decode journal: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Journal{}, errors.New("decode journal: trailing JSON data")
		}
		return Journal{}, fmt.Errorf("decode journal trailing data: %w", err)
	}
	if err := validateJournal(journal); err != nil {
		return Journal{}, fmt.Errorf("validate journal: %w", err)
	}
	return journal, nil
}

func (store FileJournal) Save(journal Journal) error {
	if err := store.validatePath(); err != nil {
		return err
	}
	if err := validateJournal(journal); err != nil {
		return fmt.Errorf("validate journal: %w", err)
	}
	directory := filepath.Dir(store.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create journal directory: %w", err)
	}
	if err := requireDirectory(directory); err != nil {
		return fmt.Errorf("journal directory must be a real directory: %w", err)
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	if err := replaceRegularFile(store.Path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("replace journal: %w", err)
	}
	return nil
}

func (store FileJournal) validatePath() error {
	if store.Path == "" || !filepath.IsAbs(store.Path) || filepath.Clean(store.Path) != store.Path || filepath.Base(store.Path) != "journal.json" {
		return errors.New("journal path must be absolute, clean, and end in journal.json")
	}
	return nil
}

func validateJournal(journal Journal) error {
	for label, revision := range map[string]string{
		"active":          journal.ActiveRevision,
		"last-known-good": journal.LastKnownGoodRevision,
		"pending":         journal.PendingRevision,
	} {
		if revision != "" && !validRevisionID(revision) {
			return fmt.Errorf("%s revision is invalid", label)
		}
	}
	if journal.State != StatePending && (journal.PendingRevision != "" || !journal.PendingDeadline.IsZero()) {
		return errors.New("only a pending journal may contain pending revision data")
	}
	switch journal.State {
	case StateIdle:
		if journal.ActiveRevision != "" || journal.LastKnownGoodRevision != "" || journal.RollbackResult != "" {
			return errors.New("idle journal must not contain revision or rollback data")
		}
	case StatePending:
		if journal.PendingRevision == "" || journal.PendingDeadline.IsZero() {
			return errors.New("pending journal requires revision and deadline")
		}
		if journal.ActiveRevision != journal.LastKnownGoodRevision {
			return errors.New("pending journal active and last-known-good revisions must match")
		}
		if journal.RollbackResult != "" {
			return errors.New("pending journal must not contain a rollback result")
		}
	case StateCommitted:
		if journal.ActiveRevision == "" || journal.ActiveRevision != journal.LastKnownGoodRevision {
			return errors.New("committed journal requires one active last-known-good revision")
		}
		if journal.RollbackResult != "" {
			return errors.New("committed journal must not contain a rollback result")
		}
	case StateRolledBack, StateDegraded:
		if journal.ActiveRevision != journal.LastKnownGoodRevision {
			return errors.New("recovery journal active and last-known-good revisions must match")
		}
		if journal.RollbackResult == "" {
			return errors.New("recovery journal requires a rollback result")
		}
	default:
		return fmt.Errorf("unknown journal state %q", journal.State)
	}
	return nil
}

func validRevisionID(id string) bool {
	if id == "" || len(id) > 128 || strings.Contains(id, "..") {
		return false
	}
	for _, r := range id {
		if !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
