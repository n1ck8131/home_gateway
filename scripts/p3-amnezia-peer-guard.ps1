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

$pins = Read-BoundedPins $PinsPath
if ([string]$pins.schema -cne 'home-gateway/p3-peer-guard-pins/v1') { throw 'runtime pin schema differs' }
$payload = [IO.Path]::GetFullPath($PayloadPath)
$payloadItem = Get-Item -LiteralPath $payload -Force -ErrorAction Stop
if ($payloadItem.PSIsContainer -or ($payloadItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $payloadItem.Length -le 0 -or $payloadItem.Length -gt 131072) { throw 'peer guard payload differs' }
& $PythonPath $payload --self-test
if ($LASTEXITCODE -ne 0) { throw 'peer guard payload self-test failed' }
& $PythonPath $payload --pins ([IO.Path]::GetFullPath($PinsPath)) --validate-only
if ($LASTEXITCODE -ne 0) { throw 'peer guard payload validation failed' }
if ($ValidateOnly) { return }

foreach ($name in @('ssh_host','ssh_user','known_hosts_path','known_hosts_sha256','current_egress_cidr_sha256')) {
    if ([string]::IsNullOrWhiteSpace([string]$pins.$name)) { throw 'live runtime pins are incomplete' }
}
if ([string]$pins.expected_source_prefix_length -ne '32') { throw 'current egress source pin must describe exactly one /32' }
if ([string]::IsNullOrWhiteSpace($env:SSH_AUTH_SOCK)) { throw 'memory-only ssh-agent is unavailable' }
$knownHosts = [IO.Path]::GetFullPath([string]$pins.known_hosts_path)
$knownHostsItem = Get-Item -LiteralPath $knownHosts -Force -ErrorAction Stop
if ($knownHostsItem.PSIsContainer -or ($knownHostsItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'known-hosts pin file differs' }
$knownHostsHash = (Get-FileHash -LiteralPath $knownHosts -Algorithm SHA256).Hash.ToLowerInvariant()
if ($knownHostsHash -cne [string]$pins.known_hosts_sha256) { throw 'known-hosts hash differs' }
$windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$ssh = [IO.Path]::Combine($windows,'System32','OpenSSH','ssh.exe')
[Console]::Out.WriteLine('READY_FOR_UI=YES')
& $ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$knownHosts" -o ConnectTimeout=10 `
    "$([string]$pins.ssh_user)@$([string]$pins.ssh_host)" 'sudo /usr/local/libexec/home-gateway-p3-peer-guard --automatic --json'
if ($LASTEXITCODE -ne 0) { throw 'peer guard transport failed' }
