[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Plan', 'Apply', 'Confirm', 'Rollback', 'Recover', 'EmergencyDisable', 'FullRestorePlan', 'FullRestore', 'Status')]
    [string]$Action = 'Plan',
    [string]$ConfigPath,
    [string]$StateRoot,
    [string]$Revision = 'p35-canary-001',
    [string[]]$Target,
    [string]$DnsNamespace = '.one.one.one.one',
    [string]$Challenge,
    [string]$CandidateSHA256,
    [string]$RecoveryPlanSHA256,
    [string]$QuickCheckRecordPath,
    [string]$QuickCheckRecordSHA256,
    [int]$QuickCheckElapsedSeconds,
    [switch]$ConfirmLiveMutation,
    [switch]$ConfirmRecovery,
    [string]$HgctlPath,
    [string]$ExpectedHgctlSHA256,
    [string]$ExpectedLauncherSHA256,
    [string]$ExpectedConfigSHA256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:OwnerMarker = 'home-gateway/p35/windows/v1'
$script:ParentMarkerName = '.p35-parent-owner.v1'
$script:RootMarkerName = '.p35-root-owner.v1'
$script:BinMarkerName = '.p35-bin-owner.v1'
$script:SecretsMarkerName = '.p35-secrets-owner.v1'

function Test-NativeWindows {
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Test-ElevatedWindows {
    if (-not (Test-NativeWindows)) { return $false }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-ElevatedWindows {
    if (-not (Test-ElevatedWindows)) {
        throw 'P3.5 live operations require an elevated Administrator session'
    }
}

function Get-ProductionStateRoot {
    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($programData)) { throw 'trusted ProgramData known folder is unavailable' }
    return [IO.Path]::Combine($programData, 'HomeGateway', 'P35')
}

function Resolve-CleanAbsolutePath {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { throw "$Label must be an absolute path" }
    $full = [IO.Path]::GetFullPath($Path)
    $inputClean = $Path.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $fullClean = $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if (-not [string]::Equals($inputClean, $fullClean, [StringComparison]::OrdinalIgnoreCase)) { throw "$Label must be clean" }
    return $fullClean
}

function Assert-ProductionStateRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not [string]::Equals($Path, (Get-ProductionStateRoot), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'P3.5 state root must be the dedicated ProgramData path'
    }
}

function Assert-LocalNonReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    if ($Path.StartsWith('\\', [StringComparison]::Ordinal) -or $Path.StartsWith('\\?\', [StringComparison]::Ordinal) -or $Path.StartsWith('\\.\', [StringComparison]::Ordinal)) { throw "$Label must use a local drive path" }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw "$Label must be on a fixed local volume" }
    $current = $Path
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Label contains a reparse point" }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or [string]::Equals($parent, $current, [StringComparison]::OrdinalIgnoreCase)) { break }
        $current = $parent
    }
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    Assert-LocalNonReparsePath -Path $Path -Label $Label
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "$Label must be a regular non-reparse file" }
}

function Assert-RestrictedConfigSource {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularFile -Path $Path -Label 'tunnel config'
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { throw 'tunnel config ACL inherits access and is not approved for live use' }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $allowed) { throw 'tunnel config has an unauthorized owner' }
    $currentUserCanRead = $false
    foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        $sid = $rule.IdentityReference.Value
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $sid -notin $allowed) {
            throw 'tunnel config ACL grants an unauthorized principal'
        }
        if ($sid -ceq $currentSid -and (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0)) {
            $currentUserCanRead = $true
        }
    }
    if (-not $currentUserCanRead) { throw 'tunnel config ACL does not grant the current owner explicit read access' }
}

function Assert-InstalledConfigFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularFile -Path $Path -Label 'installed tunnel config'
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $allowed) { throw 'installed tunnel config has an unauthorized owner' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'installed tunnel config ACL count differs' }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $sid -notin $allowed -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $seen.ContainsKey($sid)) {
            throw 'installed tunnel config ACL is not the exact SYSTEM/Administrators contract'
        }
        $seen[$sid] = $true
    }
    foreach ($sid in $allowed) { if (-not $seen.ContainsKey($sid)) { throw 'installed tunnel config lacks a required administrative ACE' } }
}

function New-ProtectedDirectorySecurity {
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($administrators)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sidText), $full, $inheritance,
            [Security.AccessControl.PropagationFlags]::None, $allow
        )
        $security.AddAccessRule($rule)
    }
	return $security
}

function Assert-ProtectedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$MarkerName)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'P3.5 protected path must be a real directory' }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw 'P3.5 protected directory inherits access rules' }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'P3.5 protected directory has an unauthorized owner' }
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'P3.5 protected directory ACL count differs' }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $sid -notin $allowed -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $seen.ContainsKey($sid)) {
            throw 'P3.5 protected directory ACL is not the exact SYSTEM/Administrators contract'
        }
        $seen[$sid] = $true
    }
    foreach ($sid in $allowed) { if (-not $seen.ContainsKey($sid)) { throw 'P3.5 protected directory lacks a required administrative ACE' } }
    $marker = Join-Path $Path $MarkerName
    $markerItem = Get-Item -LiteralPath $marker -Force -ErrorAction Stop
    if ($markerItem.PSIsContainer -or ($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'P3.5 ownership marker is invalid' }
    $reader = [IO.StreamReader]::new([IO.File]::Open($marker, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
    try { if ($reader.ReadToEnd() -ne $script:OwnerMarker) { throw 'P3.5 ownership marker differs' } } finally { $reader.Dispose() }
}

function New-ProtectedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$MarkerName)
	$security = New-ProtectedDirectorySecurity
	$null = [IO.Directory]::CreateDirectory($Path, $security)
    [IO.File]::WriteAllText((Join-Path $Path $MarkerName), $script:OwnerMarker, [Text.UTF8Encoding]::new($false))
    Assert-ProtectedDirectory -Path $Path -MarkerName $MarkerName
}

function Initialize-ProtectedStateRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-ElevatedWindows
    Assert-ProductionStateRoot -Path $Path
    $parent = Split-Path -Parent $Path
    if (Test-Path -LiteralPath $parent) { Assert-ProtectedDirectory -Path $parent -MarkerName $script:ParentMarkerName } else { New-ProtectedDirectory -Path $parent -MarkerName $script:ParentMarkerName }
    if (Test-Path -LiteralPath $Path) { Assert-ProtectedDirectory -Path $Path -MarkerName $script:RootMarkerName } else { New-ProtectedDirectory -Path $Path -MarkerName $script:RootMarkerName }
}

function Assert-ProtectedStateRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-ProductionStateRoot -Path $Path
    Assert-ProtectedDirectory -Path (Split-Path -Parent $Path) -MarkerName $script:ParentMarkerName
    Assert-ProtectedDirectory -Path $Path -MarkerName $script:RootMarkerName
}

function Get-StreamSHA256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Get-LockedFileSHA256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try { return Get-StreamSHA256 -Stream $stream } finally { $stream.Dispose() }
}

function Assert-ExpectedSHA256 {
    param([Parameter(Mandatory = $true)][string]$Expected)
    if ($Expected -cnotmatch '^[0-9a-f]{64}$') { throw 'expected digest must be one lowercase SHA-256 value' }
}

function Read-ExactSHA256Pin {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    Assert-RegularFile -Path $Path -Label $Label
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        if ($stream.Length -ne 64) { throw "$Label length differs" }
        $bytes = [byte[]]::new(64)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw "$Label is truncated" }
            $offset += $read
        }
        $value = [Text.Encoding]::ASCII.GetString($bytes)
    } finally { $stream.Dispose() }
    Assert-ExpectedSHA256 -Expected $value
    return $value
}

function Resolve-HgctlSource {
    param([string]$ExplicitPath, [Parameter(Mandatory = $true)][string]$Expected)
    Assert-ExpectedSHA256 -Expected $Expected
    if ([string]::IsNullOrWhiteSpace($ExplicitPath)) { $ExplicitPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\hgctl_windows_amd64.exe' }
    $resolved = Resolve-CleanAbsolutePath -Path $ExplicitPath -Label 'hgctl source path'
    Assert-RegularFile -Path $resolved -Label 'hgctl source'
    if ((Get-LockedFileSHA256 -Path $resolved) -cne $Expected) { throw 'hgctl source hash differs from the approved artifact' }
    return $resolved
}

function Install-ProtectedFile {
    param([Parameter(Mandatory = $true)][string]$Source, [Parameter(Mandatory = $true)][string]$Destination, [string]$ExpectedSHA256)
    Assert-RegularFile -Path $Source -Label 'protected source'
    $sourceStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $actual = Get-StreamSHA256 -Stream $sourceStream
        if (-not [string]::IsNullOrEmpty($ExpectedSHA256) -and $actual -cne $ExpectedSHA256) { throw 'protected source hash differs from the approved value' }
        if (Test-Path -LiteralPath $Destination) {
            Assert-RegularFile -Path $Destination -Label 'protected destination'
            if ((Get-LockedFileSHA256 -Path $Destination) -cne $actual) { throw 'existing protected destination differs' }
            return $actual
        }
        $temporary = $Destination + '.next'
        if (Test-Path -LiteralPath $temporary) { throw 'protected staging path already exists' }
        $sourceStream.Position = 0
        $destinationStream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $sourceStream.CopyTo($destinationStream); $destinationStream.Flush($true) } finally { $destinationStream.Dispose() }
        [IO.File]::Move($temporary, $Destination)
        return $actual
    } finally { $sourceStream.Dispose() }
}

function Install-TrustedHgctl {
    param([Parameter(Mandatory = $true)][string]$Source, [Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Expected)
    $bin = Join-Path $Root 'bin'
    if (-not (Test-Path -LiteralPath $bin)) { $null = New-Item -ItemType Directory -Path $bin -ErrorAction Stop }
    $binItem = Get-Item -LiteralPath $bin -Force -ErrorAction Stop
    if (-not $binItem.PSIsContainer -or ($binItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'protected binary directory is invalid' }
    $destination = Join-Path $bin 'hgctl.exe'
    $actual = Install-ProtectedFile -Source $Source -Destination $destination -ExpectedSHA256 $Expected
    [IO.File]::WriteAllText((Join-Path $bin 'hgctl.sha256'), $actual, [Text.Encoding]::ASCII)
    return $destination
}

function Resolve-InstalledHgctl {
    param([Parameter(Mandatory = $true)][string]$Root)
    Assert-ProtectedStateRoot -Path $Root
    Assert-ProtectedDirectory -Path (Join-Path $Root 'bin') -MarkerName $script:BinMarkerName
    $path = Join-Path $Root 'bin\hgctl.exe'
    $approved = Join-Path $Root 'bin\hgctl.sha256'
    Assert-RegularFile -Path $path -Label 'installed hgctl'
    Assert-RegularFile -Path $approved -Label 'installed hgctl hash'
    $reader = [IO.StreamReader]::new([IO.File]::Open($approved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
    try { $expected = $reader.ReadToEnd() } finally { $reader.Dispose() }
    Assert-ExpectedSHA256 -Expected $expected
    if ((Get-LockedFileSHA256 -Path $path) -cne $expected) { throw 'installed hgctl hash differs from its protected pin' }
    return $path
}

function Resolve-InstalledConfig {
    param([Parameter(Mandatory = $true)][string]$Root)
    Assert-ProtectedStateRoot -Path $Root
    Assert-ProtectedDirectory -Path (Join-Path $Root 'secrets') -MarkerName $script:SecretsMarkerName
    $path = Join-Path $Root 'secrets\tunnel.conf'
    Assert-InstalledConfigFile -Path $path
    $pin = Read-ExactSHA256Pin -Path (Join-Path $Root 'secrets\tunnel.sha256') -Label 'installed tunnel config pin'
    if ((Get-LockedFileSHA256 -Path $path) -cne $pin) { throw 'installed tunnel config differs from its protected pin' }
    return [pscustomobject]@{ Path = $path; SHA256 = $pin }
}

function Assert-ProtectedLauncher {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Expected)
    Assert-ExpectedSHA256 -Expected $Expected
    Assert-ProtectedStateRoot -Path $Root
    Assert-ProtectedDirectory -Path (Join-Path $Root 'bin') -MarkerName $script:BinMarkerName
    $expectedPath = Join-Path $Root 'bin\p35-canary.ps1'
    $actualPath = Resolve-CleanAbsolutePath -Path $PSCommandPath -Label 'P3.5 launcher path'
    if (-not [string]::Equals($actualPath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'P3.5 live actions must run only from the protected staged launcher'
    }
    $pin = Join-Path $Root 'bin\p35-canary.sha256'
    Assert-RegularFile -Path $actualPath -Label 'installed P3.5 launcher'
    Assert-RegularFile -Path $pin -Label 'installed P3.5 launcher hash'
    $reader = [IO.StreamReader]::new([IO.File]::Open($pin, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
    try { $approved = $reader.ReadToEnd() } finally { $reader.Dispose() }
    Assert-ExpectedSHA256 -Expected $approved
    if ($approved -cne $Expected -or (Get-LockedFileSHA256 -Path $actualPath) -cne $Expected) {
        throw 'protected P3.5 launcher hash differs from the approved value'
    }
}

function Invoke-CheckedHgctl {
    param([Parameter(Mandatory = $true)][string]$Executable, [Parameter(Mandatory = $true)][string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "hgctl failed with exit code $LASTEXITCODE" }
}

function Invoke-HgctlPlan {
    param([Parameter(Mandatory = $true)][string]$Executable, [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments)
    & $Executable @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 3) { exit 3 }
    if ($exitCode -ne 0) { throw "hgctl failed with exit code $exitCode" }
}

if ([string]::IsNullOrWhiteSpace($StateRoot)) { $StateRoot = Get-ProductionStateRoot }
$resolvedStateRoot = Resolve-CleanAbsolutePath -Path $StateRoot -Label 'state root'

if ($Action -eq 'Plan') {
    Assert-ProductionStateRoot -Path $resolvedStateRoot
    if (Test-ElevatedWindows) { throw 'run P3.5 Plan from a non-elevated session' }
    if ([string]::IsNullOrWhiteSpace($ConfigPath) -or @($Target).Count -eq 0 -or [string]::IsNullOrWhiteSpace($ExpectedConfigSHA256)) { throw 'Plan requires ConfigPath, ExpectedConfigSHA256 and Target' }
    $installedConfig = Resolve-InstalledConfig -Root $resolvedStateRoot
    $requestedConfig = Resolve-CleanAbsolutePath -Path $ConfigPath -Label 'tunnel config path'
    if (-not [string]::Equals($requestedConfig, $installedConfig.Path, [StringComparison]::OrdinalIgnoreCase)) { throw 'P3.5 Plan accepts only the protected installed tunnel config' }
    Assert-ExpectedSHA256 -Expected $ExpectedConfigSHA256
    if ($ExpectedConfigSHA256 -cne $installedConfig.SHA256) { throw 'requested tunnel config SHA-256 differs from the protected pin' }
    $resolvedHgctl = Resolve-HgctlSource -ExplicitPath $HgctlPath -Expected $ExpectedHgctlSHA256
    $arguments = @('windows', 'canary', 'plan', '--config', $installedConfig.Path, '--config-sha256', $installedConfig.SHA256, '--state-root', $resolvedStateRoot, '--revision', $Revision)
    foreach ($address in @($Target)) { $arguments += @('--target', $address) }
    $arguments += @('--dns-namespace', $DnsNamespace, '--json')
    Invoke-HgctlPlan -Executable $resolvedHgctl -Arguments $arguments
    return
}

if ($Action -eq 'Status') {
    Assert-ElevatedWindows
    Assert-ProductionStateRoot -Path $resolvedStateRoot
    Assert-ProtectedLauncher -Root $resolvedStateRoot -Expected $ExpectedLauncherSHA256
    Invoke-CheckedHgctl -Executable (Resolve-InstalledHgctl -Root $resolvedStateRoot) -Arguments @('windows', 'canary', 'status', '--state-root', $resolvedStateRoot, '--json')
    return
}

if ($Action -eq 'FullRestorePlan') {
    Assert-ElevatedWindows
    Assert-ProductionStateRoot -Path $resolvedStateRoot
    Assert-ProtectedLauncher -Root $resolvedStateRoot -Expected $ExpectedLauncherSHA256
    Invoke-HgctlPlan -Executable (Resolve-InstalledHgctl -Root $resolvedStateRoot) -Arguments @(
        'windows', 'canary', 'full-restore-plan', '--state-root', $resolvedStateRoot, '--json'
    )
    return
}

if ($Action -in @('Apply', 'Confirm')) {
    if (@($Target).Count -eq 0 -or -not $ConfirmLiveMutation -or [string]::IsNullOrWhiteSpace($Challenge) -or $CandidateSHA256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Apply and Confirm require Target, ConfirmLiveMutation, exact CandidateSHA256 and the exact candidate challenge' }
    if (-not $PSCmdlet.ShouldProcess('current Windows network state', "P3.5 $Action with durable automatic rollback boundary")) { return }
    Assert-ElevatedWindows
    Assert-ProductionStateRoot -Path $resolvedStateRoot
    Assert-ProtectedLauncher -Root $resolvedStateRoot -Expected $ExpectedLauncherSHA256
    Assert-ProtectedStateRoot -Path $resolvedStateRoot
    $resolvedHgctl = Resolve-InstalledHgctl -Root $resolvedStateRoot
    $installedConfig = Resolve-InstalledConfig -Root $resolvedStateRoot
    if ($Action -eq 'Confirm') {
        if ($QuickCheckElapsedSeconds -lt 1 -or $QuickCheckElapsedSeconds -gt 90 -or [string]::IsNullOrWhiteSpace($QuickCheckRecordPath) -or $QuickCheckRecordSHA256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Confirm requires a successful bounded PendingQuickCheck record with at least 30 seconds watchdog safety margin' }
        $quickCheckPath = Resolve-CleanAbsolutePath -Path $QuickCheckRecordPath -Label 'PendingQuickCheck record path'
        Assert-RegularFile -Path $quickCheckPath -Label 'PendingQuickCheck record'
        if ((Get-LockedFileSHA256 -Path $quickCheckPath) -cne $QuickCheckRecordSHA256) { throw 'PendingQuickCheck record hash differs' }
    }
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        $requestedConfig = Resolve-CleanAbsolutePath -Path $ConfigPath -Label 'tunnel config path'
        if (-not [string]::Equals($requestedConfig, $installedConfig.Path, [StringComparison]::OrdinalIgnoreCase)) { throw 'live P3.5 accepts only the protected installed tunnel config' }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedConfigSHA256) -and $ExpectedConfigSHA256 -cne $installedConfig.SHA256) { throw 'requested tunnel config SHA-256 differs from the protected pin' }
    $arguments = @('windows', 'canary', $Action.ToLowerInvariant(), '--config', $installedConfig.Path, '--config-sha256', $installedConfig.SHA256, '--state-root', $resolvedStateRoot, '--revision', $Revision)
    foreach ($address in @($Target)) { $arguments += @('--target', $address) }
    $arguments += @('--dns-namespace', $DnsNamespace, '--candidate-sha256', $CandidateSHA256, '--confirm-live', $Challenge, '--json')
    Invoke-CheckedHgctl -Executable $resolvedHgctl -Arguments $arguments
    return
}

if (-not $ConfirmRecovery) { throw 'Recovery actions require ConfirmRecovery' }
if ($Action -eq 'FullRestore' -and ($RecoveryPlanSHA256 -cnotmatch '^[0-9a-f]{64}$' -or $Challenge -cnotmatch '^P35-FULL-RESTORE-[0-9A-F]{16}$')) { throw 'FullRestore requires an exact RecoveryPlanSHA256 and P35-FULL-RESTORE recovery-plan-derived challenge' }
if (-not $PSCmdlet.ShouldProcess('project-owned Windows network state', "P3.5 $Action recovery action")) { return }
Assert-ElevatedWindows
Assert-ProductionStateRoot -Path $resolvedStateRoot
Assert-ProtectedLauncher -Root $resolvedStateRoot -Expected $ExpectedLauncherSHA256
$resolvedHgctl = Resolve-InstalledHgctl -Root $resolvedStateRoot
$recoveryTokens = @{ Rollback = 'P35-ROLLBACK'; Recover = 'P35-RECOVER'; EmergencyDisable = 'P35-EMERGENCY-DISABLE'; FullRestore = $Challenge }
$recoveryCommands = @{ Rollback = 'rollback'; Recover = 'recover'; EmergencyDisable = 'emergency-disable'; FullRestore = 'full-restore' }
    $recoveryArguments = @(
    'windows', 'canary', $recoveryCommands[$Action], '--state-root', $resolvedStateRoot,
    '--confirm-recovery', $recoveryTokens[$Action], '--json'
)
if ($Action -eq 'FullRestore') { $recoveryArguments = $recoveryArguments[0..4] + @('--recovery-plan-sha256', $RecoveryPlanSHA256) + $recoveryArguments[5..($recoveryArguments.Count - 1)] }
Invoke-CheckedHgctl -Executable $resolvedHgctl -Arguments $recoveryArguments
if ($Action -eq 'FullRestore') {
    [Console]::Out.WriteLine('NETWORK_RESTORE=COMPLETE')
    [Console]::Out.WriteLine('ACL_RESTORE=PENDING')
}
