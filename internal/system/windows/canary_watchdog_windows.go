//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
	xwindows "golang.org/x/sys/windows"
)

const (
	canaryWatchdogVersion   = 1
	canaryRecoveryTaskName  = "HomeGateway-P35-Recovery"
	canaryReconcileTaskName = "HomeGateway-P35-Reconcile"
	canaryWatchdogTimeout   = 30 * time.Second
)

type canaryWatchdogRequest struct {
	Version    int    `json:"version"`
	Operation  string `json:"operation"`
	Root       string `json:"root"`
	Executable string `json:"executable"`
	Deadline   string `json:"deadline,omitempty"`
}

type canaryWatchdogResponse struct {
	Version int                    `json:"version"`
	OK      *bool                  `json:"ok"`
	Tasks   []WatchdogTaskIdentity `json:"tasks,omitempty"`
}

type durableCanaryWatchdog struct {
	root       string
	executable string
	command    nativeMutationCommand
	runner     nativeMutationRunner
	timer      apply.TimerWatchdog
	mu         sync.Mutex
}

var _ apply.PersistentWatchdog = (*durableCanaryWatchdog)(nil)

func newDefaultCanaryWatchdog(root string) (apply.Watchdog, error) {
	if err := ValidateProductionCanaryStateRoot(root); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, errors.New("resolve installed P3.5 executable")
	}
	paths, err := resolveNativeInventoryPaths()
	if err != nil {
		return nil, errors.New("resolve trusted Task Scheduler paths")
	}
	return newDurableCanaryWatchdog(root, executable, paths, nativeExecMutationRunner{}, validateInstalledCanaryRuntime)
}

func DisarmProductionCanaryWatchdog(root string) error {
	watchdog, err := newDefaultCanaryWatchdog(root)
	if err != nil {
		return err
	}
	persistent, ok := watchdog.(apply.PersistentWatchdog)
	if !ok {
		return errors.New("production canary watchdog is not persistent")
	}
	return persistent.Disarm()
}

func newDurableCanaryWatchdog(root, executable string, paths nativeInventoryPaths, runner nativeMutationRunner, validate func(string, string) error) (*durableCanaryWatchdog, error) {
	if runner == nil || validate == nil {
		return nil, errors.New("durable canary watchdog runner and validator are required")
	}
	if err := validate(root, executable); err != nil {
		return nil, err
	}
	command, err := buildCanaryWatchdogCommand(paths)
	if err != nil {
		return nil, err
	}
	return &durableCanaryWatchdog{root: root, executable: executable, command: command, runner: runner}, nil
}

func validateInstalledCanaryRuntime(root, executable string) error {
	if err := ValidateProductionCanaryStateRoot(root); err != nil {
		return err
	}
	if err := validateProtectedNativeRoot(root); err != nil {
		return err
	}
	want := canaryInstalledExecutable(root)
	if filepath.Clean(executable) != executable || !strings.EqualFold(executable, want) {
		return errors.New("live P3.5 requires the protected installed hgctl executable")
	}
	for _, path := range []string{filepath.Dir(executable), executable} {
		pointer, err := xwindows.UTF16PtrFromString(path)
		if err != nil {
			return errors.New("installed P3.5 executable path is invalid")
		}
		attributes, err := xwindows.GetFileAttributes(pointer)
		if err != nil || attributes&xwindows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("installed P3.5 executable path is missing or contains a reparse point")
		}
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("installed P3.5 executable is not a regular file")
	}
	return nil
}

func buildCanaryWatchdogCommand(paths nativeInventoryPaths) (nativeMutationCommand, error) {
	base, err := buildInventoryCommand(paths)
	if err != nil {
		return nativeMutationCommand{}, errors.New("trusted Task Scheduler paths are invalid")
	}
	modulesRoot := filepath.Join(base.Directory, "WindowsPowerShell", "v1.0", "Modules")
	environment := append([]string(nil), base.Environment...)
	environment = append(environment, "HG_TASKSCHEDULER_MANIFEST="+filepath.Join(modulesRoot, "ScheduledTasks", "ScheduledTasks.psd1"))
	return nativeMutationCommand{
		Executable: base.Executable,
		Arguments: []string{
			"-NoLogo",
			"-NoProfile",
			"-NonInteractive",
			"-OutputFormat", "Text",
			"-Command", canaryWatchdogScript,
		},
		Environment: environment,
		Directory:   base.Directory,
	}, nil
}

func (watchdog *durableCanaryWatchdog) Arm(deadline time.Time, action func()) (func(), error) {
	if deadline.IsZero() || action == nil {
		return nil, errors.New("durable canary watchdog deadline and action are required")
	}
	cancelTimer, err := watchdog.timer.Arm(deadline, action)
	if err != nil {
		return nil, err
	}
	watchdog.mu.Lock()
	defer watchdog.mu.Unlock()
	if err := watchdog.invoke(canaryWatchdogRequest{
		Version:    canaryWatchdogVersion,
		Operation:  "arm",
		Root:       watchdog.root,
		Executable: watchdog.executable,
		Deadline:   deadline.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		cancelTimer()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(cancelTimer) }, nil
}

func (watchdog *durableCanaryWatchdog) Disarm() error {
	watchdog.mu.Lock()
	defer watchdog.mu.Unlock()
	return watchdog.invoke(canaryWatchdogRequest{
		Version:    canaryWatchdogVersion,
		Operation:  "disarm",
		Root:       watchdog.root,
		Executable: watchdog.executable,
	})
}

func (watchdog *durableCanaryWatchdog) Commit() error {
	watchdog.mu.Lock()
	defer watchdog.mu.Unlock()
	return watchdog.invoke(canaryWatchdogRequest{
		Version:    canaryWatchdogVersion,
		Operation:  "commit",
		Root:       watchdog.root,
		Executable: watchdog.executable,
	})
}

func (watchdog *durableCanaryWatchdog) invoke(request canaryWatchdogRequest) error {
	data, err := json.Marshal(request)
	if err != nil || len(data) > maxArtifactBytes {
		return errors.New("durable canary watchdog request is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), canaryWatchdogTimeout)
	defer cancel()
	spec := watchdog.command
	spec.Arguments = append([]string(nil), watchdog.command.Arguments...)
	spec.Environment = append([]string(nil), watchdog.command.Environment...)
	spec.Input = data
	output, err := watchdog.runner.Run(ctx, spec)
	if err != nil || len(output) == 0 || len(output) > maxStderrBytes {
		return errors.New("durable canary watchdog command failed")
	}
	var response canaryWatchdogResponse
	if err := decodeStrictLimit(output, &response, maxStderrBytes); err != nil || response.Version != canaryWatchdogVersion || response.OK == nil || !*response.OK {
		return errors.New("durable canary watchdog response is invalid")
	}
	return nil
}

func observeWatchdogTasks(ctx context.Context, root, executable string, command nativeMutationCommand, runner nativeMutationRunner) ([]WatchdogTaskIdentity, error) {
	data, err := json.Marshal(canaryWatchdogRequest{Version: canaryWatchdogVersion, Operation: "observe", Root: root, Executable: executable})
	if err != nil || len(data) > maxArtifactBytes || runner == nil {
		return nil, errors.New("watchdog task observation request is invalid")
	}
	boundedContext, cancel := context.WithTimeout(ctx, canaryWatchdogTimeout)
	defer cancel()
	spec := command
	spec.Arguments = append([]string(nil), command.Arguments...)
	spec.Environment = append([]string(nil), command.Environment...)
	spec.Input = data
	output, err := runner.Run(boundedContext, spec)
	if err != nil || len(output) == 0 || len(output) > maxStderrBytes {
		return nil, errors.New("watchdog task observation command failed")
	}
	var response canaryWatchdogResponse
	if err := decodeStrictLimit(output, &response, maxStderrBytes); err != nil || response.Version != canaryWatchdogVersion || response.OK == nil || !*response.OK || len(response.Tasks) != 2 {
		return nil, errors.New("watchdog task observation response is invalid")
	}
	return append([]WatchdogTaskIdentity(nil), response.Tasks...), nil
}

const canaryWatchdogScript = `$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Import-Module -Name $env:HG_UTILITY_MANIFEST -Force -ErrorAction Stop
Import-Module -Name $env:HG_TASKSCHEDULER_MANIFEST -Force -ErrorAction Stop

$inputText = [Console]::In.ReadToEnd()
if ([Text.Encoding]::UTF8.GetByteCount($inputText) -gt 1048576) { throw 'structured input limit exceeded' }
$request = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $inputText -ErrorAction Stop
if ([int]$request.version -ne 1) { throw 'unsupported request version' }
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$expectedRoot = [IO.Path]::Combine($programData, 'HomeGateway', 'P35')
$expectedExecutable = [IO.Path]::Combine($expectedRoot, 'bin', 'hgctl.exe')
if (-not [string]::Equals([string]$request.root, $expectedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'unexpected watchdog root' }
if (-not [string]::Equals([string]$request.executable, $expectedExecutable, [StringComparison]::OrdinalIgnoreCase)) { throw 'unexpected watchdog executable' }

$recoveryTaskName = 'HomeGateway-P35-Recovery'
$reconcileTaskName = 'HomeGateway-P35-Reconcile'
$recoveryMarker = 'Home Gateway P3.5 durable commit-confirm recovery'
$reconcileMarker = 'Home Gateway P3.5 committed startup reconciliation'
$arguments = 'windows canary recover --state-root "' + $expectedRoot + '" --confirm-recovery P35-RECOVER --json'

function Get-ExactTask([string]$taskName) {
    return @(ScheduledTasks\Get-ScheduledTask -ErrorAction Stop | Where-Object {
        [string]::Equals([string]$_.TaskName, $taskName, [StringComparison]::OrdinalIgnoreCase) -and [string]$_.TaskPath -ceq '\'
    })
}

function Assert-CommonOwnedTask([object]$task, [string]$marker, [int]$restartCount) {
    $actions = @($task.Actions)
	$settings = $task.Settings
    if ([string]$task.Description -cne $marker -or $actions.Count -ne 1 -or
        -not [string]::Equals([string]$actions[0].Execute, [string]$request.executable, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$actions[0].Arguments -cne $arguments -or
        -not [string]::Equals([string]$actions[0].WorkingDirectory, [string]$request.root, [StringComparison]::OrdinalIgnoreCase) -or
		-not (@('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18') -contains [string]$task.Principal.UserId) -or
		[string]$task.Principal.LogonType -cne 'ServiceAccount' -or [string]$task.Principal.RunLevel -cne 'Highest' -or
		-not [bool]$settings.StartWhenAvailable -or [int]$settings.RestartCount -ne $restartCount -or
		[string]$settings.RestartInterval -cne 'PT1M' -or [string]$settings.ExecutionTimeLimit -cne 'PT5M' -or
		[bool]$settings.DisallowStartIfOnBatteries -or [bool]$settings.StopIfGoingOnBatteries -or
		[bool]$settings.RunOnlyIfIdle -or [bool]$settings.RunOnlyIfNetworkAvailable -or
		[string]$settings.MultipleInstances -cne 'IgnoreNew') {
        throw 'scheduled watchdog ownership collision'
    }
}

function Test-TaskEnabled([object]$task) {
	if (-not [bool]$task.Settings.Enabled -or [string]$task.State -ceq 'Disabled') { return $false }
	foreach ($trigger in @($task.Triggers)) {
		if (-not [bool]$trigger.Enabled) { return $false }
	}
	return $true
}

function Get-RecoveryTimeTrigger([object]$task) {
	$timeTriggers = @($task.Triggers | Where-Object { [string]$_.CimClass.CimClassName -ceq 'MSFT_TaskTimeTrigger' })
	if ($timeTriggers.Count -ne 1) { return $null }
	return $timeTriggers[0]
}

function Test-RecoveryDeadline([object]$task, [DateTimeOffset]$expectedDeadline) {
	$timeTrigger = Get-RecoveryTimeTrigger $task
	if ($null -eq $timeTrigger -or [string]::IsNullOrWhiteSpace([string]$timeTrigger.StartBoundary)) { return $false }
	$actual = [DateTimeOffset]::Parse(
		[string]$timeTrigger.StartBoundary,
		[Globalization.CultureInfo]::InvariantCulture,
		[Globalization.DateTimeStyles]::AssumeLocal
	)
	return [Math]::Abs(($actual.ToUniversalTime() - $expectedDeadline.ToUniversalTime()).TotalSeconds) -le 1
}

function Assert-OwnedRecoveryTask([object]$task) {
	Assert-CommonOwnedTask $task $recoveryMarker 3
	$triggers = @($task.Triggers)
	$bootTriggers = @($triggers | Where-Object { [string]$_.CimClass.CimClassName -ceq 'MSFT_TaskBootTrigger' })
	$timeTriggers = @($triggers | Where-Object { [string]$_.CimClass.CimClassName -ceq 'MSFT_TaskTimeTrigger' })
	if ($triggers.Count -ne 2 -or $bootTriggers.Count -ne 1 -or $timeTriggers.Count -ne 1 -or
		-not [string]::IsNullOrWhiteSpace([string]$bootTriggers[0].Delay) -or
		-not [string]::IsNullOrWhiteSpace([string]$bootTriggers[0].EndBoundary) -or
		-not [string]::IsNullOrWhiteSpace([string]$timeTriggers[0].RandomDelay) -or
		-not [string]::IsNullOrWhiteSpace([string]$timeTriggers[0].EndBoundary) -or
		[string]$timeTriggers[0].Repetition.Interval -cne 'PT1M' -or [string]$timeTriggers[0].Repetition.Duration -cne 'P3650D') {
		throw 'scheduled recovery watchdog ownership collision'
	}
}

function Assert-OwnedReconcileTask([object]$task) {
	Assert-CommonOwnedTask $task $reconcileMarker 30
	$triggers = @($task.Triggers)
	$bootTriggers = @($triggers | Where-Object { [string]$_.CimClass.CimClassName -ceq 'MSFT_TaskBootTrigger' })
	$timeTriggers = @($triggers | Where-Object { [string]$_.CimClass.CimClassName -ceq 'MSFT_TaskTimeTrigger' })
	if ($triggers.Count -ne 2 -or $bootTriggers.Count -ne 1 -or $timeTriggers.Count -ne 1 -or
		-not [string]::IsNullOrWhiteSpace([string]$bootTriggers[0].Delay) -or
		-not [string]::IsNullOrWhiteSpace([string]$bootTriggers[0].EndBoundary) -or
		[int]$timeTriggers[0].DaysInterval -ne 1 -or
		-not [string]::IsNullOrWhiteSpace([string]$timeTriggers[0].RandomDelay) -or
		-not [string]::IsNullOrWhiteSpace([string]$timeTriggers[0].EndBoundary) -or
		-not [string]::IsNullOrWhiteSpace([string]$timeTriggers[0].Repetition.Interval) -or
		-not [string]::IsNullOrWhiteSpace([string]$timeTriggers[0].Repetition.Duration) -or
		[DateTimeOffset]::Parse([string]$timeTriggers[0].StartBoundary, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal).TimeOfDay -ne [TimeSpan]::FromMinutes(7)) {
		throw 'scheduled reconcile watchdog ownership collision'
	}
}

function New-OwnedTaskSettings([int]$restartCount) {
	return ScheduledTasks\New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5)) -RestartCount $restartCount -RestartInterval ([TimeSpan]::FromMinutes(1)) -MultipleInstances IgnoreNew
}

function Ensure-RecoveryTask([DateTimeOffset]$deadline) {
	$existing = @(Get-ExactTask $recoveryTaskName)
	if ($existing.Count -gt 1) { throw 'scheduled recovery watchdog identity is ambiguous' }
	if ($existing.Count -eq 1) {
		Assert-OwnedRecoveryTask $existing[0]
		if ((Test-TaskEnabled $existing[0]) -and (Test-RecoveryDeadline $existing[0] $deadline)) { return }
	}
    $action = ScheduledTasks\New-ScheduledTaskAction -Execute ([string]$request.executable) -Argument $arguments -WorkingDirectory ([string]$request.root)
    $triggers = @(
		ScheduledTasks\New-ScheduledTaskTrigger -Once -At $deadline.LocalDateTime -RepetitionInterval ([TimeSpan]::FromMinutes(1)) -RepetitionDuration ([TimeSpan]::FromDays(3650))
        ScheduledTasks\New-ScheduledTaskTrigger -AtStartup
    )
    $principal = ScheduledTasks\New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
	$definition = ScheduledTasks\New-ScheduledTask -Action $action -Trigger $triggers -Principal $principal -Settings (New-OwnedTaskSettings 3) -Description $recoveryMarker
	$null = ScheduledTasks\Register-ScheduledTask -TaskName $recoveryTaskName -InputObject $definition -Force -ErrorAction Stop
	$created = @(Get-ExactTask $recoveryTaskName)
	if ($created.Count -ne 1) { throw 'scheduled recovery watchdog registration post-check failed' }
	Assert-OwnedRecoveryTask $created[0]
	if (-not (Test-TaskEnabled $created[0]) -or -not (Test-RecoveryDeadline $created[0] $deadline)) { throw 'scheduled recovery watchdog operational post-check failed' }
}

function Ensure-ReconcileTask {
	$existing = @(Get-ExactTask $reconcileTaskName)
	if ($existing.Count -gt 1) { throw 'scheduled reconcile watchdog identity is ambiguous' }
	if ($existing.Count -eq 1) {
		Assert-OwnedReconcileTask $existing[0]
		if (Test-TaskEnabled $existing[0]) { return }
	}
	$action = ScheduledTasks\New-ScheduledTaskAction -Execute ([string]$request.executable) -Argument $arguments -WorkingDirectory ([string]$request.root)
	$triggers = @(
		ScheduledTasks\New-ScheduledTaskTrigger -AtStartup
		ScheduledTasks\New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At ([DateTime]::Today.AddMinutes(7))
	)
	$principal = ScheduledTasks\New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
	$definition = ScheduledTasks\New-ScheduledTask -Action $action -Trigger $triggers -Principal $principal -Settings (New-OwnedTaskSettings 30) -Description $reconcileMarker
	$null = ScheduledTasks\Register-ScheduledTask -TaskName $reconcileTaskName -InputObject $definition -Force -ErrorAction Stop
	$created = @(Get-ExactTask $reconcileTaskName)
	if ($created.Count -ne 1) { throw 'scheduled reconcile watchdog registration post-check failed' }
	Assert-OwnedReconcileTask $created[0]
	if (-not (Test-TaskEnabled $created[0])) { throw 'scheduled reconcile watchdog operational post-check failed' }
}

function Remove-RecoveryTask {
	$existing = @(Get-ExactTask $recoveryTaskName)
	if ($existing.Count -gt 1) { throw 'scheduled recovery watchdog identity is ambiguous' }
	if ($existing.Count -eq 1) {
		Assert-OwnedRecoveryTask $existing[0]
		ScheduledTasks\Unregister-ScheduledTask -InputObject $existing[0] -Confirm:$false -ErrorAction Stop
	}
	if (@(Get-ExactTask $recoveryTaskName).Count -ne 0) { throw 'scheduled recovery watchdog removal post-check failed' }
}

function Remove-AllOwnedTasks {
	$recovery = @(Get-ExactTask $recoveryTaskName)
	$reconcile = @(Get-ExactTask $reconcileTaskName)
	if ($recovery.Count -gt 1 -or $reconcile.Count -gt 1) { throw 'scheduled watchdog identity is ambiguous' }
	if ($recovery.Count -eq 1) { Assert-OwnedRecoveryTask $recovery[0] }
	if ($reconcile.Count -eq 1) { Assert-OwnedReconcileTask $reconcile[0] }
	if ($recovery.Count -eq 1) { ScheduledTasks\Unregister-ScheduledTask -InputObject $recovery[0] -Confirm:$false -ErrorAction Stop }
	if ($reconcile.Count -eq 1) { ScheduledTasks\Unregister-ScheduledTask -InputObject $reconcile[0] -Confirm:$false -ErrorAction Stop }
	if (@(Get-ExactTask $recoveryTaskName).Count -ne 0 -or @(Get-ExactTask $reconcileTaskName).Count -ne 0) { throw 'scheduled watchdog removal post-check failed' }
}

function Get-TextSHA256([string]$value) {
	$sha = [Security.Cryptography.SHA256]::Create()
	try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Get-TaskProperty([object]$value, [string]$name) {
	if ($null -eq $value) { return $null }
	$property = $value.PSObject.Properties[$name]
	if ($null -eq $property) { return $null }
	return $property.Value
}

function Get-ObservedTaskStateSHA256([object]$task) {
	$triggers = @()
	foreach ($trigger in @($task.Triggers)) {
		$repetition = Get-TaskProperty $trigger 'Repetition'
		$triggers += [pscustomobject][ordered]@{
			class = [string]$trigger.CimClass.CimClassName
			enabled = [bool]$trigger.Enabled
			start_boundary = [string](Get-TaskProperty $trigger 'StartBoundary')
			end_boundary = [string](Get-TaskProperty $trigger 'EndBoundary')
			delay = [string](Get-TaskProperty $trigger 'Delay')
			random_delay = [string](Get-TaskProperty $trigger 'RandomDelay')
			days_interval = [int](Get-TaskProperty $trigger 'DaysInterval')
			repetition_interval = [string](Get-TaskProperty $repetition 'Interval')
			repetition_duration = [string](Get-TaskProperty $repetition 'Duration')
		}
	}
	$state = [pscustomobject][ordered]@{
		description = [string]$task.Description
		state = [string]$task.State
		enabled = Test-TaskEnabled $task
		principal_user = [string]$task.Principal.UserId
		principal_logon_type = [string]$task.Principal.LogonType
		principal_run_level = [string]$task.Principal.RunLevel
		settings_enabled = [bool]$task.Settings.Enabled
		settings_restart_count = [int]$task.Settings.RestartCount
		settings_restart_interval = [string]$task.Settings.RestartInterval
		settings_execution_time_limit = [string]$task.Settings.ExecutionTimeLimit
		triggers = $triggers
	}
	return Get-TextSHA256 (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $state -Compress -Depth 5)
}

function New-ObservedTask([object]$task, [string]$identitySHA256) {
	return [pscustomobject][ordered]@{
		type = 'scheduled-task'
		role = 'remove'
		identity_sha256 = $identitySHA256
		observed_state_sha256 = Get-ObservedTaskStateSHA256 $task
	}
}

$observedTasks = $null
switch ([string]$request.operation) {
	'arm' {
		$deadline = [DateTimeOffset]::Parse([string]$request.deadline, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
		if ($deadline -le [DateTimeOffset]::UtcNow.AddSeconds(-5) -or $deadline -gt [DateTimeOffset]::UtcNow.AddMinutes(11)) { throw 'watchdog deadline is outside the bounded window' }
		Ensure-RecoveryTask $deadline
	}
	'commit' {
		Ensure-ReconcileTask
		Remove-RecoveryTask
	}
	'disarm' {
		Remove-AllOwnedTasks
	}
	'observe' {
		$recovery = @(Get-ExactTask $recoveryTaskName)
		$reconcile = @(Get-ExactTask $reconcileTaskName)
		if ($recovery.Count -ne 1 -or $reconcile.Count -ne 1) { throw 'scheduled watchdog observation is incomplete or ambiguous' }
		Assert-OwnedRecoveryTask $recovery[0]
		Assert-OwnedReconcileTask $reconcile[0]
		$observedTasks = @(
			New-ObservedTask $recovery[0] '2d58ac8b637df61862670dffe7100d6c425aac2347d7d2d3843dd3ce0130f571'
			New-ObservedTask $reconcile[0] 'f5e1d15dbb7b3e43d6e74e84763ae4487a35a673e608806acf5990ecbbd46fc9'
		)
	}
	default { throw 'unsupported watchdog operation' }
}

if ($null -eq $observedTasks) {
	Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject ([pscustomobject][ordered]@{ version = 1; ok = $true }) -Compress
} else {
	Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject ([pscustomobject][ordered]@{ version = 1; ok = $true; tasks = $observedTasks }) -Compress
}`
