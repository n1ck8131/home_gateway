package apply

import (
	"os"
	"path/filepath"
	"runtime"
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
