//go:build windows

package apply

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xwindows "golang.org/x/sys/windows"
)

func TestFileJournalLoadRecoversWindowsReplacementBackup(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "journal.json")
	backup := destination + replaceFileBackupSuffix
	data := []byte("{\"state\":\"pending-confirmation\",\"pending_revision\":\"r1\",\"pending_deadline\":\"2030-01-01T00:00:00Z\"}\n")
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		t.Fatal(err)
	}

	journal, err := (FileJournal{Path: destination}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if journal.State != StatePending || journal.PendingRevision != "r1" {
		t.Fatalf("recovered journal = %#v", journal)
	}
	if _, err := os.Lstat(destination); err != nil {
		t.Fatalf("recovered destination: %v", err)
	}
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement backup remains after recovery: %v", err)
	}
}

func TestFileJournalLoadFailsClosedForInvalidWindowsReplacementBackup(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(string) error
		want      string
	}{
		{name: "nonregular", configure: func(path string) error { return os.Mkdir(path, 0o700) }, want: "not a regular file"},
		{name: "corrupt", configure: func(path string) error { return os.WriteFile(path, []byte("not-json\n"), 0o600) }, want: "decode journal"},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "journal.json")
			if err := test.configure(destination + replaceFileBackupSuffix); err != nil {
				t.Fatal(err)
			}
			journal, err := (FileJournal{Path: destination}).Load()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() = %#v, %v; want %q", journal, err, test.want)
			}
			if journal.State == StateIdle {
				t.Fatal("invalid backup was treated as idle")
			}
		})
	}
}

func TestAtomicReplaceFileWindowsMaintainsOldOrNewInvariant(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "journal.next")
	destination := filepath.Join(directory, "journal.json")
	oldData := []byte("old\n")
	newData := []byte("new\n")
	if err := os.WriteFile(source, newData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, oldData, 0o600); err != nil {
		t.Fatal(err)
	}

	destinationPointer, err := xwindows.UTF16PtrFromString(destination)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := xwindows.CreateFile(destinationPointer, xwindows.GENERIC_READ, xwindows.FILE_SHARE_READ|xwindows.FILE_SHARE_WRITE, nil, xwindows.OPEN_EXISTING, xwindows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	replaceErr := atomicReplaceFile(source, destination)
	if closeErr := xwindows.CloseHandle(handle); closeErr != nil {
		t.Fatal(closeErr)
	}

	got, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatalf("destination disappeared during replacement: %v", readErr)
	}
	switch {
	case replaceErr == nil:
		if !bytes.Equal(got, newData) {
			t.Fatalf("successful replacement published neither old nor new data: %q", got)
		}
	case !bytes.Equal(got, oldData):
		t.Fatalf("failed replacement damaged prior destination: %q, err=%v", got, replaceErr)
	default:
		if sourceData, err := os.ReadFile(source); err != nil || !bytes.Equal(sourceData, newData) {
			t.Fatalf("failed replacement damaged source: %q, err=%v", sourceData, err)
		}
		if err := atomicReplaceFile(source, destination); err != nil {
			t.Fatalf("replacement after releasing destination handle: %v", err)
		}
		got, readErr = os.ReadFile(destination)
		if readErr != nil || !bytes.Equal(got, newData) {
			t.Fatalf("successful retry destination = %q, err=%v", got, readErr)
		}
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source remains after successful replacement: %v", err)
	}
}

func TestManagedWindowsReaderDoesNotBlockAtomicJournalReplacement(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "journal.next")
	destination := filepath.Join(directory, "journal.json")
	oldData := []byte("old\n")
	newData := []byte("new\n")
	if err := os.WriteFile(source, newData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, oldData, 0o600); err != nil {
		t.Fatal(err)
	}

	reader, err := openRegularFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := atomicReplaceFile(source, destination); err != nil {
		t.Fatalf("managed reader blocked atomic replacement: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, newData) {
		t.Fatalf("replacement destination = %q, err=%v", got, err)
	}
	if _, err := reader.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	handleData := make([]byte, len(oldData))
	if _, err := reader.Read(handleData); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(handleData, oldData) {
		t.Fatalf("open handle did not retain a coherent prior view: %q", handleData)
	}
}
