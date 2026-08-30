[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Prepare', 'Verify', 'Cleanup')][string]$Action,
    [string]$StateRoot,
    [string]$ExportPath,
    [string]$HgctlPath,
    [Parameter(Mandatory = $true)][string]$ExpectedDriverSHA256,
    [Parameter(Mandatory = $true)][string]$ExpectedPayloadSHA256,
    [string]$ExpectedHgctlSHA256,
    [string]$PayloadPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Assert-SHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label must be one lowercase SHA-256 value" }
}

function Resolve-LocalRegularFile([string]$Path, [string]$Label) {
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
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer) { throw "$Label must be a regular file" }
    return $full
}

function Get-ExclusiveSHA256([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
}

if ([string]::IsNullOrWhiteSpace($StateRoot)) {
    $StateRoot = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData), 'HomeGateway', 'P35')
}
$StateRoot = [IO.Path]::GetFullPath($StateRoot)
if ([string]::IsNullOrWhiteSpace($PayloadPath)) { $PayloadPath = Join-Path $PSScriptRoot 'p3-profile-stage-elevated.ps1' }
$driver = Resolve-LocalRegularFile -Path $PSCommandPath -Label 'profile stage driver'
$payload = Resolve-LocalRegularFile -Path ([IO.Path]::GetFullPath($PayloadPath)) -Label 'profile stage payload'
Assert-SHA256 $ExpectedDriverSHA256 'driver hash'
Assert-SHA256 $ExpectedPayloadSHA256 'payload hash'
if ((Get-ExclusiveSHA256 $driver) -cne $ExpectedDriverSHA256) { throw 'profile stage driver hash differs' }
if ((Get-ExclusiveSHA256 $payload) -cne $ExpectedPayloadSHA256) { throw 'profile stage payload hash differs' }

if ($Action -ceq 'Verify') {
    if ([string]::IsNullOrWhiteSpace($ExportPath) -or [string]::IsNullOrWhiteSpace($HgctlPath)) { throw 'Verify requires ExportPath and HgctlPath' }
    Assert-SHA256 $ExpectedHgctlSHA256 'hgctl hash'
    $ExportPath = [IO.Path]::GetFullPath($ExportPath)
    $HgctlPath = Resolve-LocalRegularFile -Path ([IO.Path]::GetFullPath($HgctlPath)) -Label 'hgctl'
    if ((Get-ExclusiveSHA256 $HgctlPath) -cne $ExpectedHgctlSHA256) { throw 'hgctl hash differs' }
}

if (-not $PSCmdlet.ShouldProcess('marker-owned protected P3 profile staging metadata', $Action)) { return }
$request = [pscustomobject][ordered]@{
    version = 1; action = $Action.ToLowerInvariant(); state_root = $StateRoot; export_path = $ExportPath
    hgctl_path = $HgctlPath; hgctl_sha256 = $ExpectedHgctlSHA256
}
$requestBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -InputObject $request)))
$payloadPathBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
$loader = @"
`$ErrorActionPreference='Stop'
`$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$payloadPathBase64'))
`$stream=[IO.File]::Open(`$path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
try{`$sha=[Security.Cryptography.SHA256]::Create();try{`$actual=([BitConverter]::ToString(`$sha.ComputeHash(`$stream))).Replace('-','').ToLowerInvariant()}finally{`$sha.Dispose()};if(`$actual -cne '$ExpectedPayloadSHA256'){throw 'profile stage payload hash differs'};`$stream.Position=0;`$reader=[IO.StreamReader]::new(`$stream,[Text.UTF8Encoding]::new(`$false,`$true),`$true);try{`$text=`$reader.ReadToEnd()}finally{`$reader.Dispose()}}finally{`$stream.Dispose()}
`$env:HG_P3_PROFILE_STAGE_REQUEST_B64='$requestBase64'
[ScriptBlock]::Create(`$text).Invoke()
"@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loader))
if ($encoded.Length -ge 32767) { throw 'profile stage loader exceeds CreateProcess limit' }
$windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$powershell = [IO.Path]::Combine($windows, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
$process = Start-Process -FilePath $powershell -Verb RunAs -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -WindowStyle Hidden -Wait -PassThru
if ($null -eq $process -or $process.ExitCode -ne 0) { throw "profile stage payload failed with exit code $($process.ExitCode)" }
