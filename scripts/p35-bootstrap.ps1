[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Install', 'RestoreConfigAclPlan', 'RestoreConfigAcl')]
    [string]$Action = 'Install',
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [Parameter(Mandatory = $true)][string]$ExpectedConfigSHA256,
    [Parameter(Mandatory = $true)][string]$ExpectedDriverSHA256,
    [Parameter(Mandatory = $true)][string]$ExpectedPayloadSHA256,
    [string]$ExpectedLauncherSHA256,
    [string]$ExpectedHgctlSHA256,
    [string]$Confirmation,
    [string]$ACLPlanSHA256,
    [string]$NetworkRestorePlanSHA256,
    [string]$DriverPath,
    [string]$PayloadPath,
    [string]$LauncherPath,
    [string]$HgctlPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not [string]::IsNullOrEmpty($PSCommandPath)) { throw 'P3.5 bootstrap driver must execute only as an independently pinned in-memory ScriptBlock' }

function Assert-SHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label must be one lowercase SHA-256 value" }
}

function Get-TextSHA256([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function New-RestoreConfigAclPlan(
    [string]$ConfigPath,
    [string]$CurrentAclSDDL,
    [string]$BaselineAclSDDL,
    [string]$ConfigSHA256,
    [string]$DriverSHA256,
    [string]$PayloadSHA256,
    [string]$NetworkRestorePlanSHA256
) {
    $identity = [pscustomobject][ordered]@{
        schema = 'home-gateway/windows-restore-config-acl/v1'
        protected_config_path_identity = Get-TextSHA256 -Value $ConfigPath.ToLowerInvariant()
        current_acl_sha256 = Get-TextSHA256 -Value $CurrentAclSDDL
        baseline_acl_sha256 = Get-TextSHA256 -Value $BaselineAclSDDL
        config_sha256 = $ConfigSHA256
        bootstrap_driver_sha256 = $DriverSHA256
        bootstrap_payload_sha256 = $PayloadSHA256
        network_restore_plan_sha256 = $NetworkRestorePlanSHA256
        operation = 'restore-config-acl'
    }
    $planHash = Get-TextSHA256 -Value (ConvertTo-Json -Compress -InputObject $identity)
    $challengeHash = Get-TextSHA256 -Value ($ConfigPath.ToLowerInvariant() + [char]0 + $planHash)
    return [pscustomobject][ordered]@{
        mode = 'restore-config-acl-plan'
        live_mutation_performed = $false
        identity = $identity
        acl_plan_sha256 = $planHash
        confirmation_challenge = 'P35-RESTORE-CONFIG-ACL-' + $challengeHash.Substring(0, 16).ToUpperInvariant()
    }
}

function Read-ExactUTF8JSON([string]$Path, [string]$Label) {
    $stream = Open-RegularExclusive -Path $Path -Label $Label
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 65536) { throw "$Label length differs" }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true)
        try { return ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Resolve-LocalCleanPath([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\', [StringComparison]::Ordinal) -or $Path.StartsWith('\\?\', [StringComparison]::Ordinal) -or $Path.StartsWith('\\.\', [StringComparison]::Ordinal)) { throw "$Label must be a local absolute path" }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals($Path.TrimEnd('\'), $full.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw "$Label must be clean" }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw "$Label must be on a fixed local volume" }
    $current = $full
    while (-not [string]::IsNullOrEmpty($current)) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Label contains a reparse point" }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or [string]::Equals($parent, $current, [StringComparison]::OrdinalIgnoreCase)) { break }
        $current = $parent
    }
    return $full
}

function Open-RegularExclusive([string]$Path, [string]$Label) {
    $null = Resolve-LocalCleanPath -Path $Path -Label $Label
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "$Label must be a regular non-reparse file" }
    return [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
}

function Get-StreamSHA256([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Assert-FileSHA256([string]$Path, [string]$Expected, [string]$Label) {
    $stream = Open-RegularExclusive -Path $Path -Label $Label
    try { $actual = Get-StreamSHA256 -Stream $stream } finally { $stream.Dispose() }
    if ($actual -cne $Expected) { throw "$Label SHA-256 differs from the approved value" }
}

function New-PinnedPayloadLoader([string]$Path, [string]$Expected, [string]$RequestBase64) {
    Assert-SHA256 -Value $Expected -Label 'payload hash'
    try { $requestBytes = [Convert]::FromBase64String($RequestBase64) } catch { throw 'bootstrap request must be valid Base64' }
    if ($requestBytes.Length -le 0 -or $requestBytes.Length -gt 65536) { throw 'P3.5 bootstrap request exceeds its limit' }
    $requestBase64Literal = [Convert]::ToBase64String($requestBytes)
    $pathBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Path))
    $loader = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
if (-not [string]::IsNullOrEmpty(`$PSCommandPath)) { throw 'P3.5 bootstrap loader must execute only as an EncodedCommand payload' }
function Get-StreamSHA256([IO.Stream]`$Stream) {
    `$sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString(`$sha.ComputeHash(`$Stream))).Replace('-', '').ToLowerInvariant() } finally { `$sha.Dispose() }
}
`$payloadPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$pathBase64'))
`$expectedPayloadSHA256 = '$Expected'
if (`$expectedPayloadSHA256 -cnotmatch '^[0-9a-f]{64}$') { throw 'bootstrap payload hash must be one lowercase SHA-256 value' }
`$stream = [IO.File]::Open(`$payloadPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
try {
    if (`$stream.Length -le 0 -or `$stream.Length -gt 1048576) { throw 'bootstrap payload length differs' }
    `$actual = Get-StreamSHA256 -Stream `$stream
    if (`$actual -cne `$expectedPayloadSHA256) { throw 'bootstrap payload SHA-256 differs from the approved value' }
    `$stream.Position = 0
    `$bytes = [byte[]]::new([int]`$stream.Length)
    `$offset = 0
    while (`$offset -lt `$bytes.Length) {
        `$read = `$stream.Read(`$bytes, `$offset, `$bytes.Length - `$offset)
        if (`$read -eq 0) { throw 'bootstrap payload is truncated' }
        `$offset += `$read
    }
} finally {
    `$stream.Dispose()
}
`$encoding = [Text.UTF8Encoding]::new(`$false, `$true)
`$payloadText = `$encoding.GetString(`$bytes)
`$previousRequest = `$env:HG_P35_BOOTSTRAP_REQUEST_B64
try {
    `$env:HG_P35_BOOTSTRAP_REQUEST_B64 = '$requestBase64Literal'
    [ScriptBlock]::Create(`$payloadText).Invoke()
} finally {
    `$env:HG_P35_BOOTSTRAP_REQUEST_B64 = `$previousRequest
}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loader))
    if ($encoded.Length -ge 32767) { throw 'P3.5 bootstrap loader exceeds CreateProcess command length budget' }
    return $encoded
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'P3.5 bootstrap driver must run from a non-elevated session' }
if ($null -eq $identity.User -or -not $identity.User.IsValidTargetType([Security.Principal.SecurityIdentifier])) { throw 'P3.5 bootstrap caller identity is unavailable' }

if ($Action -ceq 'Install' -and $Confirmation -cne 'P35-BOOTSTRAP-FILESYSTEM-V1') { throw 'P3.5 bootstrap driver confirmation differs' }
foreach ($entry in @(
    @{ Value = $ExpectedConfigSHA256; Label = 'config hash' },
    @{ Value = $ExpectedDriverSHA256; Label = 'driver hash' },
    @{ Value = $ExpectedPayloadSHA256; Label = 'payload hash' }
)) { Assert-SHA256 -Value $entry.Value -Label $entry.Label }
if ($Action -ceq 'Install') {
    Assert-SHA256 -Value $ExpectedLauncherSHA256 -Label 'launcher hash'
    Assert-SHA256 -Value $ExpectedHgctlSHA256 -Label 'hgctl hash'
}

if ([string]::IsNullOrWhiteSpace($DriverPath)) { throw 'P3.5 bootstrap driver path is required for an in-memory pinned invocation' }
if ([string]::IsNullOrWhiteSpace($PayloadPath)) { $PayloadPath = Join-Path $PSScriptRoot 'p35-bootstrap-elevated.ps1' }
$resolvedConfig = Resolve-LocalCleanPath -Path $ConfigPath -Label 'Tunnel config source'
$resolvedDriver = Resolve-LocalCleanPath -Path $DriverPath -Label 'bootstrap driver'
$resolvedPayload = Resolve-LocalCleanPath -Path $PayloadPath -Label 'bootstrap payload'

Assert-FileSHA256 -Path $resolvedConfig -Expected $ExpectedConfigSHA256 -Label 'Tunnel config source'
Assert-FileSHA256 -Path $resolvedDriver -Expected $ExpectedDriverSHA256 -Label 'bootstrap driver'
Assert-FileSHA256 -Path $resolvedPayload -Expected $ExpectedPayloadSHA256 -Label 'bootstrap payload'

if ($Action -ceq 'RestoreConfigAclPlan') {
    if (-not [string]::IsNullOrWhiteSpace($Confirmation) -or -not [string]::IsNullOrWhiteSpace($ACLPlanSHA256)) { throw 'RestoreConfigAclPlan does not accept mutation approval' }
}
if ($Action -in @('RestoreConfigAclPlan','RestoreConfigAcl')) {
    Assert-SHA256 -Value $NetworkRestorePlanSHA256 -Label 'network restore plan hash'
}
if ($Action -ceq 'RestoreConfigAcl') {
    Assert-SHA256 -Value $ACLPlanSHA256 -Label 'ACL plan hash'
    if ($Confirmation -cnotmatch '^P35-RESTORE-CONFIG-ACL-[0-9A-F]{16}$') { throw 'P3.5 ACL restore challenge differs' }
}

if ($Action -ceq 'Install') {
    if ([string]::IsNullOrWhiteSpace($LauncherPath)) { $LauncherPath = Join-Path $PSScriptRoot 'p35-canary.ps1' }
    if ([string]::IsNullOrWhiteSpace($HgctlPath)) { $HgctlPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\hgctl_windows_amd64.exe' }
    $resolvedLauncher = Resolve-LocalCleanPath -Path $LauncherPath -Label 'canary launcher'
    $resolvedHgctl = Resolve-LocalCleanPath -Path $HgctlPath -Label 'hgctl artifact'
    Assert-FileSHA256 -Path $resolvedLauncher -Expected $ExpectedLauncherSHA256 -Label 'canary launcher'
    Assert-FileSHA256 -Path $resolvedHgctl -Expected $ExpectedHgctlSHA256 -Label 'hgctl artifact'
    $request = [pscustomobject][ordered]@{
        version = 1
        action = 'install'
        confirmation = $Confirmation
        caller_sid = $identity.User.Value
        config_path = $resolvedConfig
        config_sha256 = $ExpectedConfigSHA256
        launcher_path = $resolvedLauncher
        launcher_sha256 = $ExpectedLauncherSHA256
        hgctl_path = $resolvedHgctl
        hgctl_sha256 = $ExpectedHgctlSHA256
    }
} else {
    $request = [pscustomobject][ordered]@{
        version = 1
        action = if ($Action -ceq 'RestoreConfigAclPlan') { 'restore-config-acl-plan' } else { 'restore-config-acl' }
        confirmation = $Confirmation
        caller_sid = $identity.User.Value
        config_path = $resolvedConfig
        config_sha256 = $ExpectedConfigSHA256
        acl_plan_sha256 = $ACLPlanSHA256
        network_restore_plan_sha256 = $NetworkRestorePlanSHA256
        driver_path = $resolvedDriver
        driver_sha256 = $ExpectedDriverSHA256
        payload_path = $resolvedPayload
        payload_sha256 = $ExpectedPayloadSHA256
    }
}
$requestBytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -InputObject $request))
if ($requestBytes.Length -gt 65536) { throw 'P3.5 bootstrap request exceeds its limit' }
$requestBase64 = [Convert]::ToBase64String($requestBytes)
$payloadCommandBase64 = New-PinnedPayloadLoader -Path $resolvedPayload -Expected $ExpectedPayloadSHA256 -RequestBase64 $requestBase64

$windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$trustedPowerShell = [IO.Path]::Combine($windows, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
$null = Resolve-LocalCleanPath -Path $trustedPowerShell -Label 'trusted Windows PowerShell'
Assert-FileSHA256 -Path $resolvedPayload -Expected $ExpectedPayloadSHA256 -Label 'bootstrap payload'
Assert-FileSHA256 -Path $resolvedDriver -Expected $ExpectedDriverSHA256 -Label 'bootstrap driver'
if ($Action -cne 'RestoreConfigAclPlan' -and -not $PSCmdlet.ShouldProcess('protected P3.5 filesystem state and the selected config ACL', "$Action via pinned elevated EncodedCommand")) { return }

$arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $payloadCommandBase64)
$commandLength = $trustedPowerShell.Length + 1 + (($arguments | ForEach-Object { [string]$_ }) -join ' ').Length
if ($commandLength -ge 32767) { throw 'P3.5 bootstrap command exceeds CreateProcess command length budget' }
$process = Start-Process -FilePath $trustedPowerShell -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
if ($null -eq $process -or $process.ExitCode -ne 0) { throw "P3.5 elevated bootstrap failed with exit code $($process.ExitCode)" }
Write-Output (ConvertTo-Json -Compress -InputObject ([pscustomobject][ordered]@{
    version = 1
    ok = $true
    action = $Action
    elevated_exit_code = $process.ExitCode
}))
