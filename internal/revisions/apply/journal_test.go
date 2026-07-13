package apply

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFileJournalIsDurablePrivateAndSecretFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "journal.json")
	store := FileJournal{Path: path}
	want := Journal{State: StatePending, ActiveRevision: "old", LastKnownGoodRevision: "old", PendingRevision: "new", PendingDeadline: time.Unix(100, 0).UTC()}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.PendingRevision != want.PendingRevision || got.State != want.State {
		t.Fatalf("got=%+v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows exposes synthetic POSIX mode bits (typically 0666); they do not
	// describe the file ACL. Keep the 0600 regression guarantee on platforms
	// where os.FileMode permissions are enforceable.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("permissions=%o", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if string(data) == "" {
		t.Fatal("empty journal")
	}
}

func TestFileJournalRejectsInvalidPathAndState(t *testing.T) {
	if _, err := (FileJournal{Path: filepath.Join("state", "journal.json")}).Load(); err == nil {
		t.Fatal("expected relative journal path rejection")
	}
	absolute := filepath.Join(t.TempDir(), "state", "journal.json")
	store := FileJournal{Path: absolute}
	if err := store.Save(Journal{State: StatePending, PendingRevision: "next"}); err == nil {
		t.Fatal("expected pending journal without deadline to fail")
	}
	if err := store.Save(Journal{State: State("unknown")}); err == nil {
		t.Fatal("expected unknown journal state to fail")
	}
}

func TestFileJournalRejectsUnknownTrailingAndInconsistentData(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "journal.json")
	store := FileJournal{Path: path}
	for name, data := range map[string]string{
		"unknown field":       `{"state":"idle","unexpected":true}`,
		"trailing JSON":       `{"state":"idle"} {"state":"idle"}`,
		"invalid state":       `{"state":"broken"}`,
		"pending no deadline": `{"state":"pending-confirmation","pending_revision":"next"}`,
		"idle has pending":    `{"state":"idle","pending_revision":"next"}`,
		"invalid revision":    `{"state":"committed","active_revision":"../escape"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "journal") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}
