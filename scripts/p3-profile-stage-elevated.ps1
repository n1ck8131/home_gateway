Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:MarkerName = '.p3-profile-stage-owner.v1'
$script:MarkerText = 'home-gateway/p3/profile-stage/v1'
$script:ExportName = 'profile-export.conf'

function Test-StageManifest([string[]]$Names, [string]$Action) {
    $markerName = '.p3-profile-stage-owner.v1'
    $exportName = 'profile-export.conf'
    $allowed = if ($Action -ceq 'Verify') { @($markerName, $exportName) } else { @($markerName) }
    $unexpected = @($Names | Where-Object { $_ -notin $allowed })
    if ($unexpected.Count -ne 0) { throw 'profile staging contains foreign content' }
    foreach ($required in $allowed) { if ($required -notin $Names) { throw 'profile staging manifest is incomplete' } }
    return $true
}

function Assert-CleanPath([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\', [StringComparison]::Ordinal)) { throw "$Label must be a local absolute path" }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals($full, $Path, [StringComparison]::OrdinalIgnoreCase)) { throw "$Label must be clean" }
    $current = $full
    while (-not [string]::IsNullOrEmpty($current)) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Label contains a reparse point" }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
    return $full
}

function Get-StreamSHA256([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Invoke-PinnedProfileInspection(
    [string]$HgctlPath,
    [string]$ExpectedHgctlSHA256,
    [string]$ProfilePath,
    [scriptblock]$Runner,
    [scriptblock]$OnVerified
) {
    $profileItem = Get-Item -LiteralPath $ProfilePath -Force -ErrorAction Stop
    $hgctlItem = Get-Item -LiteralPath $HgctlPath -Force -ErrorAction Stop
    foreach ($item in @($profileItem,$hgctlItem)) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'profile inspection input must be a regular non-reparse file' }
    }
    $source = [IO.File]::Open($ProfilePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $hgctlStream = [IO.File]::Open($HgctlPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $profileSHA256 = Get-StreamSHA256 $source
        if ((Get-StreamSHA256 $hgctlStream) -cne $ExpectedHgctlSHA256) { throw 'hgctl hash differs' }
        $arguments = @('tunnel','inspect','--config',$ProfilePath,'--config-sha256',$profileSHA256,'--json')
        if ($null -eq $Runner) {
            $Runner = { param($Executable,$Arguments,$LockedProfilePath) $null = & $Executable @Arguments; return $LASTEXITCODE }
        }
        $exitCode = & $Runner $HgctlPath $arguments $ProfilePath
        if ([int]$exitCode -ne 0) { throw 'profile inspection failed' }
        $source.Position = 0
        if ($null -ne $OnVerified) { & $OnVerified $source $profileSHA256 }
        return [pscustomobject]@{ profile_sha256 = $profileSHA256 }
    } finally {
        $hgctlStream.Dispose()
        $source.Dispose()
    }
}

function New-StageSecurity([Security.Principal.SecurityIdentifier]$CurrentSID) {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security.SetOwner($admin)
    foreach ($sid in @([Security.Principal.SecurityIdentifier]::new('S-1-5-18'), $admin, $CurrentSID)) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    return $security
}

function Assert-Stage([string]$Path, [Security.Principal.SecurityIdentifier]$CurrentSID) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'profile staging directory is invalid' }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { throw 'profile staging ACL inherits' }
    $allowed = @('S-1-5-18','S-1-5-32-544',$CurrentSID.Value)
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 3) { throw 'profile staging ACL count differs' }
    foreach ($rule in $rules) { if ($rule.IsInherited -or $rule.IdentityReference.Value -notin $allowed -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'profile staging ACL differs' } }
    $marker = Join-Path $Path $script:MarkerName
    $reader = [IO.StreamReader]::new([IO.File]::Open($marker,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
    try { if ($reader.ReadToEnd() -cne $script:MarkerText) { throw 'profile staging marker differs' } } finally { $reader.Dispose() }
}

function Install-ExactFile([IO.Stream]$Source, [string]$Destination, [string]$Expected) {
    $temporary = $Destination + '.next'
    if ([IO.File]::Exists($temporary)) { throw 'profile installation atomic leftover exists' }
    $Source.Position = 0
    $target = [IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $Source.CopyTo($target); $target.Flush($true) } finally { $target.Dispose() }
    if ([IO.File]::Exists($Destination)) { [IO.File]::Replace($temporary,$Destination,$null,$true) } else { [IO.File]::Move($temporary,$Destination) }
    $check = [IO.File]::Open($Destination,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try { if ((Get-StreamSHA256 $check) -cne $Expected) { throw 'installed profile hash differs' } } finally { $check.Dispose() }
}

$requestText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$env:HG_P3_PROFILE_STAGE_REQUEST_B64))
$env:HG_P3_PROFILE_STAGE_REQUEST_B64 = $null
$request = ConvertFrom-Json -InputObject $requestText -ErrorAction Stop
if ([int]$request.version -ne 1 -or [string]$request.action -notin @('prepare','verify','cleanup')) { throw 'profile staging request differs' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'profile staging payload requires elevation' }
$currentSID = $identity.User
$stateRoot = Assert-CleanPath ([string]$request.state_root) 'state root'
$expectedRoot = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData),'HomeGateway','P35')
if (-not [string]::Equals($stateRoot,$expectedRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'profile staging state root differs' }
$stage = Join-Path $stateRoot 'profile-stage'
$export = Join-Path $stage $script:ExportName

if ([string]$request.action -ceq 'prepare') {
    if ([IO.Directory]::Exists($stage)) {
        Assert-Stage $stage $currentSID
        $names = @(Get-ChildItem -LiteralPath $stage -Force | Select-Object -ExpandProperty Name)
        $null = Test-StageManifest $names Prepare
    } else {
        $null = [IO.Directory]::CreateDirectory($stage,(New-StageSecurity $currentSID))
        [IO.File]::WriteAllText((Join-Path $stage $script:MarkerName),$script:MarkerText,[Text.UTF8Encoding]::new($false))
        Assert-Stage $stage $currentSID
    }
    if ([IO.File]::Exists($export) -or [IO.Directory]::Exists($export)) { throw 'profile export target must be absent' }
    [Console]::Out.WriteLine('{"schema":"home-gateway/p3-profile-stage/v1","action":"prepare","ready_for_export":true,"live_mutation_performed":false}')
    return
}

Assert-Stage $stage $currentSID
if ([string]$request.action -ceq 'cleanup') {
    $names = @(Get-ChildItem -LiteralPath $stage -Force | Select-Object -ExpandProperty Name)
    foreach ($name in $names) { if ($name -notin @($script:MarkerName,$script:ExportName)) { throw 'profile staging contains foreign content' } }
    [IO.File]::Delete((Join-Path $stage $script:MarkerName))
    if (@(Get-ChildItem -LiteralPath $stage -Force).Count -eq 0) { [IO.Directory]::Delete($stage,$false) }
    [Console]::Out.WriteLine('{"schema":"home-gateway/p3-profile-stage/v1","action":"cleanup","metadata_removed":true,"profile_preserved":true}')
    return
}

$names = @(Get-ChildItem -LiteralPath $stage -Force | Select-Object -ExpandProperty Name)
$null = Test-StageManifest $names Verify
if (-not [string]::Equals([IO.Path]::GetFullPath([string]$request.export_path),$export,[StringComparison]::OrdinalIgnoreCase)) { throw 'profile export path differs' }
$exportItem = Get-Item -LiteralPath $export -Force -ErrorAction Stop
if ($exportItem.PSIsContainer -or ($exportItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'profile export must be a regular non-reparse file' }
$hgctl = Assert-CleanPath ([string]$request.hgctl_path) 'hgctl'
$inspection = Invoke-PinnedProfileInspection -HgctlPath $hgctl -ExpectedHgctlSHA256 ([string]$request.hgctl_sha256) -ProfilePath $export -OnVerified {
    param($source,$profileSHA256)
    $secrets = Join-Path $stateRoot 'secrets'
    $destination = Join-Path $secrets 'tunnel.conf'
    Install-ExactFile $source $destination $profileSHA256
    $pin = Join-Path $secrets 'tunnel.sha256'
    $pinNext = $pin + '.next'
    [IO.File]::WriteAllText($pinNext,$profileSHA256,[Text.Encoding]::ASCII)
    if ([IO.File]::Exists($pin)) { [IO.File]::Replace($pinNext,$pin,$null,$true) } else { [IO.File]::Move($pinNext,$pin) }
}
$profileSHA256 = [string]$inspection.profile_sha256
[Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject ([pscustomobject][ordered]@{schema='home-gateway/p3-profile-stage/v1';action='verify';profile_sha256=$profileSHA256;profile_count=1;installed=$true;live_mutation_performed=$false})))
