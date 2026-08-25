//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type canaryWatchdogRunner struct {
	calls []nativeMutationCommand
}

func (runner *canaryWatchdogRunner) Run(_ context.Context, command nativeMutationCommand) ([]byte, error) {
	copyCommand := command
	copyCommand.Arguments = append([]string(nil), command.Arguments...)
	copyCommand.Environment = append([]string(nil), command.Environment...)
	copyCommand.Input = append([]byte(nil), command.Input...)
	runner.calls = append(runner.calls, copyCommand)
	return []byte(`{"version":1,"ok":true}`), nil
}

func TestDurableCanaryWatchdogUsesFixedStructuredScheduledTaskCommand(t *testing.T) {
	runner := &canaryWatchdogRunner{}
	root := `C:\ProgramData\HomeGateway\P35`
	executable := root + `\bin\hgctl.exe`
	watchdog, err := newDurableCanaryWatchdog(
		root,
		executable,
		nativeInventoryPaths{WindowsDirectory: `C:\Windows`, SystemDirectory: `C:\Windows\System32`},
		runner,
		func(gotRoot, gotExecutable string) error {
			if gotRoot != root || gotExecutable != executable {
				t.Fatalf("runtime identity = %q / %q", gotRoot, gotExecutable)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cancel, err := watchdog.Arm(time.Now().Add(5*time.Minute), func() {})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := watchdog.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := watchdog.Disarm(); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("watchdog calls = %d", len(runner.calls))
	}
	for index, operation := range []string{"arm", "commit", "disarm"} {
		var request canaryWatchdogRequest
		if err := json.Unmarshal(runner.calls[index].Input, &request); err != nil {
			t.Fatal(err)
		}
		if request.Operation != operation || request.Root != root || request.Executable != executable {
			t.Fatalf("request %d = %#v", index, request)
		}
		for _, value := range append(append([]string(nil), runner.calls[index].Arguments...), runner.calls[index].Environment...) {
			if strings.Contains(value, root) || strings.Contains(value, executable) {
				t.Fatalf("runtime path escaped structured stdin: %q", value)
			}
		}
	}
	for _, required := range []string{
		canaryRecoveryTaskName,
		canaryReconcileTaskName,
		"-AtStartup",
		"-Daily -DaysInterval 1",
		"[DateTime]::Today.AddMinutes(7)",
		"-RepetitionInterval ([TimeSpan]::FromMinutes(1))",
		"-RepetitionDuration ([TimeSpan]::FromDays(3650))",
		"New-OwnedTaskSettings 3",
		"New-OwnedTaskSettings 30",
		"-RestartInterval ([TimeSpan]::FromMinutes(1))",
		"-StartWhenAvailable",
		"-MultipleInstances IgnoreNew",
		"P35-RECOVER",
		"Repetition.Duration -cne 'P3650D'",
		"RestartCount -ne $restartCount",
		"ExecutionTimeLimit -cne 'PT5M'",
		"RunOnlyIfIdle",
		"RunOnlyIfNetworkAvailable",
		"$triggers.Count -ne 2",
		"DaysInterval -ne 1",
		"TimeOfDay -ne [TimeSpan]::FromMinutes(7)",
		"bootTriggers[0].Delay",
		"timeTriggers[0].RandomDelay",
		"timeTriggers[0].EndBoundary",
		"$timeTriggers.Count -ne 1",
		"Test-TaskEnabled",
		"Test-RecoveryDeadline",
		"StartBoundary",
		"-Force -ErrorAction Stop",
		"scheduled recovery watchdog operational post-check failed",
		"scheduled reconcile watchdog operational post-check failed",
		"Ensure-ReconcileTask",
		"Remove-RecoveryTask",
		"Remove-AllOwnedTasks",
	} {
		if !strings.Contains(canaryWatchdogScript, required) {
			t.Fatalf("durable watchdog script lacks retry contract %q", required)
		}
	}
	commitStart := strings.Index(canaryWatchdogScript, "'commit' {")
	if commitStart < 0 {
		t.Fatal("commit operation is missing")
	}
	commitScript := canaryWatchdogScript[commitStart:]
	ensureReconcile := strings.Index(commitScript, "Ensure-ReconcileTask")
	removeRecovery := strings.Index(commitScript, "Remove-RecoveryTask")
	if ensureReconcile < 0 || removeRecovery < 0 || ensureReconcile >= removeRecovery {
		t.Fatal("commit does not create/verify reconcile before removing recovery")
	}
}
