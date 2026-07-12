package versioncmd

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRunVersionJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run("routerd", []string{"version", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var got map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["program"] != "routerd" {
		t.Fatalf("program = %q", got["program"])
	}
	for _, key := range []string{"version", "commit", "build_date", "go_version", "goos", "goarch"} {
		if got[key] == "" {
			t.Fatalf("%s is empty", key)
		}
	}
}

func TestRunRejectsUnknownArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run("routerd", []string{"serve"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("code = %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "usage: routerd version --json\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
