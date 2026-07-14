package linux

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerPreservesArgumentBoundariesAndExitStatus(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		if !reflect.DeepEqual(os.Args[3:], []string{"a b", ";echo unsafe"}) {
			os.Exit(41)
		}
		os.Exit(17)
	}
	installTestProgram(t, "nft")
	runner := ExecRunner{}
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	result, err := runner.Run(context.Background(), "nft", "-test.run=^TestExecRunnerPreservesArgumentBoundariesAndExitStatus$", "--", "a b", ";echo unsafe")
	if err == nil || result.ExitCode != 17 {
		t.Fatalf("Run() result=%+v err=%v", result, err)
	}
}

func TestExecRunnerHonorsCancellation(t *testing.T) {
	if os.Getenv("GO_WANT_CANCEL_PROCESS") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	installTestProgram(t, "nft")
	t.Setenv("GO_WANT_CANCEL_PROCESS", "1")
	_, err := (ExecRunner{}).Run(ctx, "nft", "-test.run=^TestExecRunnerHonorsCancellation$")
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("Run() err=%v ctx=%v", err, ctx.Err())
	}
}

func TestExecRunnerProgramAllowlist(t *testing.T) {
	tests := []struct {
		program string
		want    bool
	}{
		{program: "fw4", want: true},
		{program: "nft", want: true},
		{program: "dnsmasq", want: true},
		{program: "ip", want: true},
		{program: "/etc/init.d/dnsmasq", want: true},
		{program: "sh", want: false},
		{program: "/bin/sh", want: false},
		{program: "nft-custom", want: false},
	}
	for _, test := range tests {
		if got := allowedProgram(test.program); got != test.want {
			t.Errorf("allowedProgram(%q) = %v, want %v", test.program, got, test.want)
		}
	}

	_, err := (ExecRunner{}).Run(context.Background(), "sh", "-c", "exit 0")
	if err == nil || !strings.Contains(err.Error(), "not in the dataplane executable allowlist") {
		t.Fatalf("Run() error = %v, want allowlist rejection", err)
	}
}

func installTestProgram(t *testing.T, program string) {
	t.Helper()
	directory := t.TempDir()
	name := program
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	destination := filepath.Join(directory, name)
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
}
