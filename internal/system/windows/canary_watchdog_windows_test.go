//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type canaryWatchdogRunner struct {
	calls  []nativeMutationCommand
	output []byte
}

func (runner *canaryWatchdogRunner) Run(_ context.Context, command nativeMutationCommand) ([]byte, error) {
	copyCommand := command
	copyCommand.Arguments = append([]string(nil), command.Arguments...)
	copyCommand.Environment = append([]string(nil), command.Environment...)
	copyCommand.Input = append([]byte(nil), command.Input...)
	runner.calls = append(runner.calls, copyCommand)
	if runner.output != nil {
		return append([]byte(nil), runner.output...), nil
	}
	return []byte(`{"version":1,"ok":true}`), nil
}

func TestObserveWatchdogTasksUsesBoundedExactStructuredReceipt(t *testing.T) {
	want := validObservedWatchdogTasks()
	data, err := json.Marshal(canaryWatchdogResponse{Version: 1, OK: boolPointer(true), Tasks: want})
	if err != nil {
		t.Fatal(err)
	}
	runner := &canaryWatchdogRunner{output: data}
	command, err := buildCanaryWatchdogCommand(nativeInventoryPaths{WindowsDirectory: `C:\Windows`, SystemDirectory: `C:\Windows\System32`})
	if err != nil {
		t.Fatal(err)
	}
	got, err := observeWatchdogTasks(t.Context(), `C:\ProgramData\HomeGateway\P35`, `C:\ProgramData\HomeGateway\P35\bin\hgctl.exe`, command, runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("observed tasks = %#v", got)
	}
	var request canaryWatchdogRequest
	if err := json.Unmarshal(runner.calls[0].Input, &request); err != nil {
		t.Fatal(err)
	}
	if request.Operation != "observe" {
		t.Fatalf("operation = %q", request.Operation)
	}

	for name, output := range map[string][]byte{
		"unbounded": bytes.Repeat([]byte("x"), maxStderrBytes+1),
		"malformed": []byte(`{"version":1,"ok":true,"tasks":`),
		"extra":     append(data[:len(data)-1], []byte(`,"extra":true}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			badRunner := &canaryWatchdogRunner{output: output}
			if _, err := observeWatchdogTasks(t.Context(), `C:\ProgramData\HomeGateway\P35`, `C:\ProgramData\HomeGateway\P35\bin\hgctl.exe`, command, badRunner); err == nil {
				t.Fatal("invalid watchdog observer receipt passed")
			}
		})
	}
}

func TestObserveWatchdogTasksExecutesEmbeddedPowerShellAgainstSyntheticScheduledTasks(t *testing.T) {
	paths, err := resolveNativeInventoryPaths()
	if err != nil {
		t.Fatal(err)
	}
	command, err := buildCanaryWatchdogCommand(paths)
	if err != nil {
		t.Fatal(err)
	}
	manifest := writeSyntheticScheduledTasksModule(t)
	for index, value := range command.Environment {
		if strings.HasPrefix(value, "HG_TASKSCHEDULER_MANIFEST=") {
			command.Environment[index] = "HG_TASKSCHEDULER_MANIFEST=" + manifest
		}
	}
	root, err := ProductionCanaryStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "bin", "hgctl.exe")
	absentStateSHA256 := "1663065c4175b4939a929dc139ad41ba3ff4dc865d2e7a7a95e409c98fc4a74c"
	observations := make(map[string][]WatchdogTaskIdentity)
	for _, scenario := range []string{"committed", "absent", "armed"} {
		t.Run(scenario, func(t *testing.T) {
			spec := command
			spec.Environment = append(append([]string(nil), command.Environment...), "HG_SYNTHETIC_TASK_SCENARIO="+scenario)
			got, observeErr := observeWatchdogTasks(t.Context(), root, executable, spec, nativeExecMutationRunner{})
			if observeErr != nil {
				t.Fatal(observeErr)
			}
			if len(got) != 2 {
				t.Fatalf("observed task identities = %d", len(got))
			}
			if got[0].IdentitySHA256 != "2d58ac8b637df61862670dffe7100d6c425aac2347d7d2d3843dd3ce0130f571" ||
				got[1].IdentitySHA256 != "f5e1d15dbb7b3e43d6e74e84763ae4487a35a673e608806acf5990ecbbd46fc9" {
				t.Fatalf("observed task identities = %#v", got)
			}
			wantRecoveryAbsent := scenario != "armed"
			wantReconcileAbsent := scenario == "absent"
			if (got[0].ObservedStateSHA256 == absentStateSHA256) != wantRecoveryAbsent ||
				(got[1].ObservedStateSHA256 == absentStateSHA256) != wantReconcileAbsent {
				t.Fatalf("observed task presence for %s = %#v", scenario, got)
			}
			observations[scenario] = got
		})
	}
	for _, scenario := range []string{"ambiguous", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			spec := command
			spec.Environment = append(append([]string(nil), command.Environment...), "HG_SYNTHETIC_TASK_SCENARIO="+scenario)
			if _, observeErr := observeWatchdogTasks(t.Context(), root, executable, spec, nativeExecMutationRunner{}); observeErr == nil {
				t.Fatal("invalid synthetic Scheduled Task shape passed embedded observer")
			}
		})
	}

	backend := newSafeBackend()
	runtime, journal := prepareFullRestorePlan(t, backend)
	backend.watchdogTasks = observations["committed"]
	committedPlan, err := runtime.PlanFullRestore(t.Context(), journal)
	if err != nil {
		t.Fatal(err)
	}
	backend.watchdogTasks = observations["armed"]
	armedPlan, err := runtime.PlanFullRestore(t.Context(), journal)
	if err != nil {
		t.Fatal(err)
	}
	if committedPlan.IdentitySHA256() == armedPlan.IdentitySHA256() {
		t.Fatal("watchdog presence drift reused the full restore plan hash")
	}
}

func writeSyntheticScheduledTasksModule(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "ScheduledTasks")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(directory, "ScheduledTasks.psd1")
	manifestBody := `@{
RootModule = 'ScheduledTasks.psm1'
ModuleVersion = '1.0.0'
GUID = 'd2d3451e-7f1f-4b13-ac98-31971bb87f69'
FunctionsToExport = @('Get-ScheduledTask')
CmdletsToExport = @()
VariablesToExport = @()
AliasesToExport = @()
}`
	moduleBody := `Set-StrictMode -Version Latest

function New-SyntheticTrigger([string]$ClassName, [bool]$Recovery) {
    $start = if ($ClassName -ceq 'MSFT_TaskTimeTrigger') {
        if ($Recovery) { [DateTimeOffset]::Now.AddMinutes(5).ToString('o') } else { [DateTime]::Today.AddMinutes(7).ToString('o') }
    } else { '' }
    $daysInterval = if ($ClassName -ceq 'MSFT_TaskTimeTrigger' -and -not $Recovery) { 1 } else { 0 }
    $interval = if ($ClassName -ceq 'MSFT_TaskTimeTrigger' -and $Recovery) { 'PT1M' } else { '' }
    $duration = if ($ClassName -ceq 'MSFT_TaskTimeTrigger' -and $Recovery) { 'P3650D' } else { '' }
    return [pscustomobject]@{
        CimClass = [pscustomobject]@{ CimClassName = $ClassName }
        Enabled = $true
        StartBoundary = $start
        EndBoundary = ''
        Delay = ''
        RandomDelay = ''
        DaysInterval = $daysInterval
        Repetition = [pscustomobject]@{
            Interval = $interval
            Duration = $duration
        }
    }
}

function New-SyntheticTask([string]$Name, [bool]$Malformed) {
    $recovery = $Name -ceq 'HomeGateway-P35-Recovery'
    $root = [IO.Path]::Combine($env:ProgramData, 'HomeGateway', 'P35')
    $description = if ($recovery) { 'Home Gateway P3.5 durable commit-confirm recovery' } else { 'Home Gateway P3.5 committed startup reconciliation' }
    if ($Malformed) { $description = 'foreign task' }
    $restartCount = if ($recovery) { 3 } else { 30 }
    return [pscustomobject]@{
        TaskName = $Name
        TaskPath = '\'
        Description = $description
        State = 'Ready'
        Actions = @([pscustomobject]@{
            Execute = [IO.Path]::Combine($root, 'bin', 'hgctl.exe')
            Arguments = 'windows canary recover --state-root "' + $root + '" --confirm-recovery P35-RECOVER --json'
            WorkingDirectory = $root
        })
        Principal = [pscustomobject]@{ UserId = 'SYSTEM'; LogonType = 'ServiceAccount'; RunLevel = 'Highest' }
        Settings = [pscustomobject]@{
            Enabled = $true
            StartWhenAvailable = $true
            RestartCount = $restartCount
            RestartInterval = 'PT1M'
            ExecutionTimeLimit = 'PT5M'
            DisallowStartIfOnBatteries = $false
            StopIfGoingOnBatteries = $false
            RunOnlyIfIdle = $false
            RunOnlyIfNetworkAvailable = $false
            MultipleInstances = 'IgnoreNew'
        }
        Triggers = @(
            New-SyntheticTrigger 'MSFT_TaskBootTrigger' $recovery
            New-SyntheticTrigger 'MSFT_TaskTimeTrigger' $recovery
        )
    }
}

function Get-ScheduledTask {
    [CmdletBinding()]
    param()
    switch ($env:HG_SYNTHETIC_TASK_SCENARIO) {
        'committed' { return @(New-SyntheticTask 'HomeGateway-P35-Reconcile' $false) }
        'absent' { return @() }
        'armed' { return @((New-SyntheticTask 'HomeGateway-P35-Recovery' $false), (New-SyntheticTask 'HomeGateway-P35-Reconcile' $false)) }
        'ambiguous' { return @((New-SyntheticTask 'HomeGateway-P35-Recovery' $false), (New-SyntheticTask 'HomeGateway-P35-Recovery' $false), (New-SyntheticTask 'HomeGateway-P35-Reconcile' $false)) }
        'malformed' { return @((New-SyntheticTask 'HomeGateway-P35-Recovery' $true), (New-SyntheticTask 'HomeGateway-P35-Reconcile' $false)) }
        default { throw 'unknown synthetic scenario' }
    }
}
Export-ModuleMember -Function Get-ScheduledTask
`
	if err := os.WriteFile(manifest, []byte(manifestBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ScheduledTasks.psm1"), []byte(moduleBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func boolPointer(value bool) *bool { return &value }

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

func TestDurableCanaryWatchdogDisarmVerifiesOwnedTasksBeforeRemoval(t *testing.T) {
	disarmStart := strings.Index(canaryWatchdogScript, "function Remove-AllOwnedTasks")
	if disarmStart < 0 {
		t.Fatal("disarm removal function is missing")
	}
	disarmScript := canaryWatchdogScript[disarmStart:]
	assertRecovery := strings.Index(disarmScript, "Assert-OwnedRecoveryTask $recovery[0]")
	assertReconcile := strings.Index(disarmScript, "Assert-OwnedReconcileTask $reconcile[0]")
	unregisterRecovery := strings.Index(disarmScript, "Unregister-ScheduledTask -InputObject $recovery[0]")
	unregisterReconcile := strings.Index(disarmScript, "Unregister-ScheduledTask -InputObject $reconcile[0]")
	if assertRecovery < 0 || assertReconcile < 0 || unregisterRecovery < 0 || unregisterReconcile < 0 {
		t.Fatal("disarm removal contract is incomplete")
	}
	if assertRecovery >= unregisterRecovery || assertReconcile >= unregisterReconcile {
		t.Fatal("disarm removes a scheduled task before verifying project ownership")
	}
}
