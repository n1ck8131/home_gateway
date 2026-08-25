package apply

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceRegularFileFailureKeepsPriorDestination(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "journal.json")
	oldData := []byte("old durable journal\n")
	newData := []byte("new durable journal\n")
	if err := os.WriteFile(destination, oldData, 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("injected atomic replacement failure")
	called := false
	err := replaceRegularFileUsing(destination, newData, 0o600, func(source, target string) error {
		called = true
		if target != destination {
			t.Fatalf("replacement target = %q", target)
		}
		if got, readErr := os.ReadFile(target); readErr != nil || !bytes.Equal(got, oldData) {
			t.Fatalf("prior destination before replacement = %q, err=%v", got, readErr)
		}
		if got, readErr := os.ReadFile(source); readErr != nil || !bytes.Equal(got, newData) {
			t.Fatalf("synced temporary before replacement = %q, err=%v", got, readErr)
		}
		return wantErr
	})
	if !called || !errors.Is(err, wantErr) {
		t.Fatalf("replacement failure = %v, called=%v", err, called)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, oldData) {
		t.Fatalf("destination after failed replacement = %q", got)
	}
	temporary := filepath.Join(directory, ".journal.json.routerd.tmp")
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary file remains after failed replacement: %v", err)
	}
}
