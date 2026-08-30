[CmdletBinding()]
param(
    [string]$PinsPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.p3-vps-run\gate65-pins.json'),
    [string]$PythonPath = 'python.exe',
    [string]$PayloadPath = (Join-Path $PSScriptRoot 'p3-amnezia-peer-guard.py'),
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Read-BoundedPins([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt 65536) { throw 'runtime pins must be one bounded regular file' }
    $stream = [IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try {
        $reader = [IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$true)
        try { return ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-TextSHA256([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Test-CurrentEgress([string[]]$Endpoints,[string]$ExpectedCIDRSHA256,[scriptblock]$Runner) {
    if ($ExpectedCIDRSHA256 -cnotmatch '^[0-9a-f]{64}$' -or @($Endpoints).Count -ne 3) { throw 'current egress pins differ' }
    if ($null -eq $Runner) { $Runner = { param($endpoint) Invoke-RestMethod -Uri ([Uri]$endpoint) -Method Get -TimeoutSec 10 -MaximumRedirection 0 -ErrorAction Stop } }
    $hashes = foreach ($endpoint in @($Endpoints)) {
        $uri = [Uri][string]$endpoint
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https') { throw 'egress endpoint must use HTTPS' }
        $value = ([string](& $Runner $endpoint)).Trim()
        $parsed = [Net.IPAddress]$null
        if (-not [Net.IPAddress]::TryParse($value,[ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'egress observation is not one IPv4 value' }
        Get-TextSHA256 ($parsed.ToString() + '/32')
    }
    if (@($hashes | Select-Object -Unique).Count -ne 1) { throw 'current egress consensus differs' }
    if ([string]$hashes[0] -cne $ExpectedCIDRSHA256) { throw 'current egress /32 differs from its pin' }
    return [string]$hashes[0]
}

function Invoke-BoundedNativeProcess([string]$Executable,[string[]]$Arguments,[int]$TimeoutSeconds,[int]$MaxOutputBytes) {
    $stdoutPath = [IO.Path]::GetTempFileName()
    $stderrPath = [IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $timedOut = $false
        $oversized = $false
        while (-not $process.HasExited) {
            if (([IO.FileInfo]$stdoutPath).Length + ([IO.FileInfo]$stderrPath).Length -gt $MaxOutputBytes) { $oversized=$true;$process.Kill();break }
            if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $timedOut=$true;$process.Kill();break }
            Start-Sleep -Milliseconds 50
            $process.Refresh()
        }
        $process.WaitForExit()
        if (([IO.FileInfo]$stdoutPath).Length + ([IO.FileInfo]$stderrPath).Length -gt $MaxOutputBytes) { $oversized=$true }
        return [pscustomobject]@{
            ExitCode=$process.ExitCode;TimedOut=$timedOut;Oversized=$oversized
            StdOut=if($oversized){''}else{[IO.File]::ReadAllText($stdoutPath,[Text.UTF8Encoding]::new($false,$true))}
            StdErr=if($oversized){''}else{[IO.File]::ReadAllText($stderrPath,[Text.UTF8Encoding]::new($false,$true))}
        }
    } finally { [IO.File]::Delete($stdoutPath);[IO.File]::Delete($stderrPath) }
}

function Invoke-BoundedPeerGuard([string]$Executable,[string[]]$Arguments,[string]$ExpectedPayloadSHA256,[string]$ExpectedProtocolSHA256,[int]$TimeoutSeconds,[int]$MaxOutputBytes,[scriptblock]$Runner) {
    if ($ExpectedPayloadSHA256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedProtocolSHA256 -cnotmatch '^[0-9a-f]{64}$' -or $TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 30 -or $MaxOutputBytes -lt 256 -or $MaxOutputBytes -gt 65536) { throw 'peer guard execution bounds differ' }
    if ($null -eq $Runner) { $Runner = { param($Executable,$Arguments) Invoke-BoundedNativeProcess -Executable $Executable -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds -MaxOutputBytes $MaxOutputBytes } }
    $result = & $Runner $Executable $Arguments
    if ([bool]$result.TimedOut) { throw 'peer guard transport timed out' }
    $bytes = [Text.Encoding]::UTF8.GetByteCount([string]$result.StdOut) + [Text.Encoding]::UTF8.GetByteCount([string]$result.StdErr)
    if ([bool]$result.Oversized -or $bytes -gt $MaxOutputBytes) { throw 'peer guard output exceeds its bound' }
    if ([int]$result.ExitCode -ne 0) { throw 'peer guard transport failed' }
    $receipt = ConvertFrom-Json -InputObject ([string]$result.StdOut) -ErrorAction Stop
    if (@(Compare-Object -ReferenceObject @('payload_sha256','protocol_sha256','ready_for_ui') -DifferenceObject @($receipt.PSObject.Properties.Name)).Count -ne 0) { throw 'peer guard attestation schema differs' }
    if ([string]$receipt.payload_sha256 -cne $ExpectedPayloadSHA256) { throw 'remote peer guard payload identity differs' }
    if ([string]$receipt.protocol_sha256 -cne $ExpectedProtocolSHA256) { throw 'remote peer guard protocol identity differs' }
    if (-not [bool]$receipt.ready_for_ui) { throw 'remote peer guard is not ready for UI' }
    return $receipt
}

$pins = Read-BoundedPins $PinsPath
if ([string]$pins.schema -cne 'home-gateway/p3-peer-guard-pins/v1') { throw 'runtime pin schema differs' }
$payload = [IO.Path]::GetFullPath($PayloadPath)
$payloadItem = Get-Item -LiteralPath $payload -Force -ErrorAction Stop
if ($payloadItem.PSIsContainer -or ($payloadItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $payloadItem.Length -le 0 -or $payloadItem.Length -gt 131072) { throw 'peer guard payload differs' }
if ([string]$pins.local_payload_sha256 -cnotmatch '^[0-9a-f]{64}$' -or (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$pins.local_payload_sha256) { throw 'local peer guard payload hash differs' }
& $PythonPath $payload --self-test
if ($LASTEXITCODE -ne 0) { throw 'peer guard payload self-test failed' }
& $PythonPath $payload --pins ([IO.Path]::GetFullPath($PinsPath)) --validate-only
if ($LASTEXITCODE -ne 0) { throw 'peer guard payload validation failed' }
if ($ValidateOnly) { return }

foreach ($name in @('ssh_host','ssh_user','known_hosts_path','known_hosts_sha256','current_egress_cidr_sha256','remote_payload_sha256','remote_protocol_sha256')) {
    if ([string]::IsNullOrWhiteSpace([string]$pins.$name)) { throw 'live runtime pins are incomplete' }
}
if ([string]$pins.expected_source_prefix_length -ne '32') { throw 'current egress source pin must describe exactly one /32' }
if ([string]::IsNullOrWhiteSpace($env:SSH_AUTH_SOCK)) { throw 'memory-only ssh-agent is unavailable' }
$knownHosts = [IO.Path]::GetFullPath([string]$pins.known_hosts_path)
$knownHostsItem = Get-Item -LiteralPath $knownHosts -Force -ErrorAction Stop
if ($knownHostsItem.PSIsContainer -or ($knownHostsItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'known-hosts pin file differs' }
$knownHostsHash = (Get-FileHash -LiteralPath $knownHosts -Algorithm SHA256).Hash.ToLowerInvariant()
if ($knownHostsHash -cne [string]$pins.known_hosts_sha256) { throw 'known-hosts hash differs' }
$null = Test-CurrentEgress -Endpoints @($pins.egress_https_endpoints) -ExpectedCIDRSHA256 ([string]$pins.current_egress_cidr_sha256)
$windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$ssh = [IO.Path]::Combine($windows,'System32','OpenSSH','ssh.exe')
$arguments = @('-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o',"UserKnownHostsFile=$knownHosts",'-o','ConnectTimeout=10',
    "$([string]$pins.ssh_user)@$([string]$pins.ssh_host)","sudo /usr/local/libexec/home-gateway-p3-peer-guard --automatic --json --expected-payload-sha256 $([string]$pins.remote_payload_sha256) --expected-protocol-sha256 $([string]$pins.remote_protocol_sha256)")
$null = Invoke-BoundedPeerGuard -Executable $ssh -Arguments $arguments -ExpectedPayloadSHA256 ([string]$pins.remote_payload_sha256) `
    -ExpectedProtocolSHA256 ([string]$pins.remote_protocol_sha256) -TimeoutSeconds 25 -MaxOutputBytes 16384
[Console]::Out.WriteLine('READY_FOR_UI=YES')
