package linux

import (
	"context"
	"errors"
	"os"
	"reflect"
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
	runner := ExecRunner{}
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	result, err := runner.Run(context.Background(), os.Args[0], "-test.run=^TestExecRunnerPreservesArgumentBoundariesAndExitStatus$", "--", "a b", ";echo unsafe")
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
	t.Setenv("GO_WANT_CANCEL_PROCESS", "1")
	_, err := (ExecRunner{}).Run(ctx, os.Args[0], "-test.run=^TestExecRunnerHonorsCancellation$")
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("Run() err=%v ctx=%v", err, ctx.Err())
	}
}
