package apply

import (
	"encoding/json"
	"errors"
	"fmt"
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
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Journal{State: StateIdle}, nil
	}
	if err != nil {
		return Journal{}, fmt.Errorf("read journal: %w", err)
	}
	var journal Journal
	if err := json.Unmarshal(data, &journal); err != nil {
		return Journal{}, fmt.Errorf("decode journal: %w", err)
	}
	return journal, nil
}

func (store FileJournal) Save(journal Journal) error {
	if store.Path == "" || filepath.Base(store.Path) != "journal.json" {
		return errors.New("journal path must end in journal.json")
	}
	directory := filepath.Dir(store.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create journal directory: %w", err)
	}
	if info, err := os.Lstat(directory); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("journal directory must exist and not be a symlink")
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	temporary := store.Path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write journal: %w", err)
	}
	if err := os.Rename(temporary, store.Path); err != nil {
		return fmt.Errorf("replace journal: %w", err)
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
