package serveragentcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/vsevo/home-gateway/internal/buildinfo"
	"github.com/vsevo/home-gateway/internal/versioncmd"
)

func TestRunPreservesVersionCommand(t *testing.T) {
	t.Parallel()

	args := []string{"version", "--json"}
	var wantStdout, wantStderr bytes.Buffer
	wantCode := versioncmd.Run("server-agent", args, &wantStdout, &wantStderr)
	var stdout, stderr bytes.Buffer
	code := Run("server-agent", args, &stdout, &stderr)

	if code != wantCode || stdout.String() != wantStdout.String() || stderr.String() != wantStderr.String() {
		t.Fatalf(
			"Run(version) = (%d, %q, %q), want (%d, %q, %q)",
			code,
			stdout.String(),
			stderr.String(),
			wantCode,
			wantStdout.String(),
			wantStderr.String(),
		)
	}
}

func TestRunHealthReportsOnlyProcessLiveness(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run("server-agent", []string{"health", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run(health) code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	var got healthResponse
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := healthResponse{
		SchemaVersion: healthSchemaVersion,
		Component:     "server-agent",
		Status:        "ok",
		Scope:         "process",
		Version:       buildinfo.Version,
		Commit:        buildinfo.Commit,
	}
	if got != want {
		t.Fatalf("health response = %#v, want %#v", got, want)
	}
}

func TestRunRejectsUnsupportedOperations(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		nil,
		{"version"},
		{"version", "--text"},
		{"health"},
		{"health", "--text"},
		{"status", "--json"},
		{"configure", "secret"},
	} {
		args := args
		t.Run(testName(args), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := Run("server-agent", args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("Run(%q) code = %d, want 2", args, code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q", stdout.String())
			}
			want := "usage: server-agent version --json\n       server-agent health --json\n"
			if stderr.String() != want {
				t.Fatalf("stderr = %q, want %q", stderr.String(), want)
			}
		})
	}
}

func TestRunFailsClosedWhenHealthEncodingFails(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	code := Run("server-agent", []string{"health", "--json"}, failingWriter{}, &stderr)
	if code != 1 {
		t.Fatalf("Run(health) code = %d, want 1", code)
	}
	if stderr.String() != "encode health: write failed\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func testName(args []string) string {
	if len(args) == 0 {
		return "empty"
	}
	return args[0] + "-" + args[len(args)-1]
}
