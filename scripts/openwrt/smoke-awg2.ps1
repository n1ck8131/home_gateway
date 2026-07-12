[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Smoke')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')]
    [string]$RouterHost,

    [Parameter(Mandatory, ParameterSetName = 'Smoke')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$PackageDirectory,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$KnownHostsFile,

    [ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')]
    [string]$SshUser = 'root',

    [Parameter(ParameterSetName = 'Smoke')]
    [switch]$ConfirmInstall,

    [Parameter(Mandatory, ParameterSetName = 'Recover')]
    [switch]$Recover,

    [Parameter(Mandatory, ParameterSetName = 'Recover')]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RecoveryToken
)

$ErrorActionPreference = 'Stop'
$remoteDirectory = '/tmp/home-gateway-p0'
$kernelAbi = 'kernel-6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1'

if ($WhatIfPreference) {
    "WHATIF local validation: $PackageDirectory"
    "WHATIF read-only preflight: $SshUser@$RouterHost"
    if ($Recover) {
        "WHATIF mutation: ownership-checked recovery of $remoteDirectory"
    } else {
        "WHATIF mutation: temporary AWG2 install, UAPI smoke and rollback"
    }
    return
}

$knownHosts = (Resolve-Path -LiteralPath $KnownHostsFile).Path
$sshCommand = (Get-Command -Name ssh -ErrorAction Stop).Source
$connectionOptions = @(
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$knownHosts",
    '-o', 'ConnectTimeout=10'
)
$target = "$SshUser@$RouterHost"
$remoteScript = Join-Path $PSScriptRoot 'smoke-awg2-remote.sh'

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter()][int[]]$AllowedExitCodes = @(0)
    )
    $output = @(& $FilePath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -notin $AllowedExitCodes) {
        throw "$FilePath failed with exit code $exitCode"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join [Environment]::NewLine) }
}

function Invoke-Ssh {
    param(
        [Parameter(Mandatory)][string[]]$RemoteArguments,
        [Parameter()][int[]]$AllowedExitCodes = @(0)
    )
    Invoke-CheckedNative -FilePath $sshCommand -Arguments ($connectionOptions + @($target) + $RemoteArguments) -AllowedExitCodes $AllowedExitCodes
}

function Invoke-RemoteScript {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter()][int[]]$AllowedExitCodes = @(0)
    )
    $priorEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $output = @(Get-Content -LiteralPath $remoteScript -Raw -Encoding UTF8 | & $sshCommand @connectionOptions $target sh -s -- @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        [Console]::OutputEncoding = $priorEncoding
    }
    if ($exitCode -notin $AllowedExitCodes) {
        throw "remote smoke script failed with exit code $exitCode"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join [Environment]::NewLine) }
}

function Write-RecoveryCommand {
    param([Parameter(Mandatory)][string]$Nonce)
    $quotedKnownHosts = '"' + $knownHosts.Replace('"', '`"') + '"'
    Write-Error -ErrorAction Continue "Router cleanup could not be confirmed. Run: & `"$PSCommandPath`" -RouterHost $RouterHost -KnownHostsFile $quotedKnownHosts -SshUser $SshUser -Recover -RecoveryToken $Nonce -Confirm:`$false"
}

if ($Recover) {
    if (-not $PSCmdlet.ShouldProcess($target, "ownership-checked cleanup of $remoteDirectory")) { return }
    Invoke-RemoteScript -Arguments @('recover', $RecoveryToken) | Out-Null
    'AWG2_RECOVERY_PASS'
    return
}

$scpCommand = (Get-Command -Name scp -ErrorAction Stop).Source
$packageRoot = (Resolve-Path -LiteralPath $PackageDirectory).Path
$kmodPackages = @(Get-ChildItem -LiteralPath $packageRoot -File -Filter 'kmod-amneziawg-*.apk')
$toolsPackages = @(Get-ChildItem -LiteralPath $packageRoot -File -Filter 'amneziawg-tools-*.apk')
if ($kmodPackages.Count -ne 1 -or $toolsPackages.Count -ne 1) {
    throw 'PackageDirectory must contain exactly one kmod-amneziawg APK and one amneziawg-tools APK'
}
$sumPath = Join-Path $packageRoot 'SHA256SUMS'
$metadataPath = Join-Path $packageRoot 'build-metadata.txt'
if (-not (Test-Path -LiteralPath $sumPath -PathType Leaf)) { throw 'SHA256SUMS is missing' }
if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { throw 'build-metadata.txt is missing' }
$packages = @($kmodPackages[0], $toolsPackages[0])
foreach ($package in $packages) {
    if ($package.Name -notmatch '^[A-Za-z0-9._+-]+$') { throw "Unsafe package filename: $($package.Name)" }
}
$sumEntries = @{}
foreach ($line in Get-Content -LiteralPath $sumPath -Encoding UTF8) {
    if ($line -notmatch '^([0-9a-fA-F]{64})  ([A-Za-z0-9._+-]+)$') { throw 'Invalid SHA256SUMS format' }
    $sumEntries[$Matches[2]] = $Matches[1].ToLowerInvariant()
}
if ($sumEntries.Count -ne 2) { throw 'SHA256SUMS must contain only the two expected APKs' }
foreach ($package in $packages) {
    if (-not $sumEntries.ContainsKey($package.Name)) { throw "SHA256SUMS is missing $($package.Name)" }
    $actual = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $sumEntries[$package.Name]) { throw "Local SHA256 mismatch for $($package.Name)" }
}
$metadata = @(Get-Content -LiteralPath $metadataPath -Encoding UTF8)
foreach ($required in @(
    'kernel_version=6.12.94',
    'kernel_vermagic=5a6c1f71be683ae9980b15d3ce73e24d',
    'package_architecture=aarch64_cortex-a53'
)) {
    if ($required -notin $metadata) { throw "Package metadata mismatch: $required" }
}

$board = (Invoke-Ssh -RemoteArguments @('ubus', 'call', 'system', 'board')).Output | ConvertFrom-Json
if ($board.board_name -ne 'glinet,gl-mt6000') { throw "Unexpected board_name: $($board.board_name)" }
$architecture = (Invoke-Ssh -RemoteArguments @('apk', '--print-arch')).Output.Trim()
if ($architecture -ne 'aarch64_cortex-a53') { throw "Unexpected package architecture: $architecture" }
$kernel = (Invoke-Ssh -RemoteArguments @('uname', '-r')).Output.Trim()
if ($kernel -ne '6.12.94') { throw "Unexpected kernel: $kernel" }
$release = (Invoke-Ssh -RemoteArguments @('cat', '/etc/openwrt_release')).Output
if ($release -notmatch "(?m)^DISTRIB_RELEASE='25\.12\.5'$") { throw 'Unexpected OpenWrt version' }
$installedKernel = (Invoke-Ssh -RemoteArguments @("apk list -I 'kernel*'")).Output
if ($installedKernel -notmatch "(?m)^$([regex]::Escape($kernelAbi))(\s|$)") { throw 'Installed kernel ABI/vermagic mismatch' }
foreach ($packageName in @('kmod-amneziawg', 'amneziawg-tools')) {
    $present = Invoke-Ssh -RemoteArguments @('apk', 'info', '-e', $packageName) -AllowedExitCodes @(0, 1)
    if ($present.ExitCode -eq 0) { throw "$packageName is already installed" }
}
$modules = (Invoke-Ssh -RemoteArguments @('lsmod')).Output
if ($modules -match '(?m)^amneziawg\s') { throw 'amneziawg module is already loaded' }
$interface = Invoke-Ssh -RemoteArguments @('ip', 'link', 'show', 'awg-p0') -AllowedExitCodes @(0, 1)
if ($interface.ExitCode -eq 0) { throw 'awg-p0 already exists' }
$temporaryState = Invoke-Ssh -RemoteArguments @('test', '-e', $remoteDirectory) -AllowedExitCodes @(0, 1)
if ($temporaryState.ExitCode -eq 0) { throw "$remoteDirectory already exists" }

if (-not $ConfirmInstall) {
    'AWG2_PREFLIGHT_PASS (no mutation; use -ConfirmInstall to request the temporary smoke)'
    return
}
if (-not $PSCmdlet.ShouldProcess($target, 'temporarily install and roll back AWG2 smoke packages')) { return }

$nonce = [guid]::NewGuid().ToString('N')
"AWG2_RECOVERY_TOKEN=$nonce"
$remotePrepared = $false
$smokePassed = $false
$cleanupConfirmed = $false
$failure = $null
try {
    $remotePrepared = $true
    Invoke-RemoteScript -Arguments @('prepare', $nonce) | Out-Null
    $copyArguments = $connectionOptions + @(
        '--',
        $kmodPackages[0].FullName,
        $toolsPackages[0].FullName,
        $sumPath,
        "${target}:$remoteDirectory/"
    )
    Invoke-CheckedNative -FilePath $scpCommand -Arguments $copyArguments | Out-Null
    Invoke-RemoteScript -Arguments @('smoke', $nonce, $kmodPackages[0].Name, $toolsPackages[0].Name, $kernelAbi) | Out-Null
    $smokePassed = $true
    $cleanupConfirmed = $true
} catch {
    $failure = $_
} finally {
    if ($remotePrepared -and -not $cleanupConfirmed) {
        try {
            Invoke-RemoteScript -Arguments @('cleanup', $nonce) | Out-Null
            $cleanupConfirmed = $true
        } catch {
            Write-RecoveryCommand -Nonce $nonce
        }
    }
}
if ($failure) { throw $failure }
if (-not $smokePassed -or -not $cleanupConfirmed) { throw 'AWG2 smoke cleanup was not confirmed' }
'AWG2_HARDWARE_SMOKE_PASS'
