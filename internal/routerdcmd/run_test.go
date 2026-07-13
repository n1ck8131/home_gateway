package routerdcmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/versioncmd"
)

func TestRunPreservesVersionCommandOutput(t *testing.T) {
	t.Parallel()

	args := []string{"version", "--json"}
	var wantStdout, wantStderr bytes.Buffer
	wantCode := versioncmd.Run("routerd", args, &wantStdout, &wantStderr)
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "routerd", args, &stdout, &stderr, func() (Service, error) {
		panic("version command must not construct the production service")
	})

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

func TestRunRecoversThenWaitsForCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	service := &fakeService{recover: func(context.Context) error {
		cancel()
		return nil
	}}
	var stdout, stderr bytes.Buffer

	code := Run(ctx, "routerd", []string{"run"}, &stdout, &stderr, func() (Service, error) {
		return service, nil
	})
	if code != 0 {
		t.Fatalf("Run(run) code = %d, stderr = %q", code, stderr.String())
	}
	if service.recoverCalls != 1 {
		t.Fatalf("Recover() calls = %d, want 1", service.recoverCalls)
	}
}

func TestRunFailsClosedWhenRecoveryFails(t *testing.T) {
	t.Parallel()

	want := errors.New("recovery failed")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "routerd", []string{"run"}, &stdout, &stderr, func() (Service, error) {
		return &fakeService{recover: func(context.Context) error { return want }}, nil
	})

	if code != 1 {
		t.Fatalf("Run(run) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), want.Error()) {
		t.Fatalf("stderr = %q, want recovery error", stderr.String())
	}
}

func TestRunRejectsInvalidUsageWithoutConstructingService(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), "routerd", []string{"apply"}, &stdout, &stderr, func() (Service, error) {
		panic("invalid command must not construct the production service")
	})

	if code != 2 {
		t.Fatalf("Run(invalid) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "routerd run") {
		t.Fatalf("stderr = %q, want run usage", stderr.String())
	}
}

type fakeService struct {
	recover      func(context.Context) error
	recoverCalls int
}

func (service *fakeService) Recover(ctx context.Context) error {
	service.recoverCalls++
	return service.recover(ctx)
}
