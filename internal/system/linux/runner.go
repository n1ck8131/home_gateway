package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type Runner interface {
	Run(context.Context, string, ...string) (Result, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, program string, args ...string) (Result, error) {
	if program == "" {
		return Result{}, errors.New("program is required")
	}
	command := exec.CommandContext(ctx, program, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, fmt.Errorf("%s exited with status %d: %w", program, result.ExitCode, err)
	}
	return result, fmt.Errorf("run %s: %w", program, err)
}
