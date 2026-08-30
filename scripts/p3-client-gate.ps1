[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Preflight', 'PostConnect', 'PostRollback')][string]$Action,
    [string]$ObservationPath,
    [string]$RuntimePinsPath,
    [string]$ClientPath,
    [string]$ProfilePath,
    [Parameter(Mandatory = $true)][string]$ExpectedGuestPeerFingerprintSHA256,
    [Parameter(Mandatory = $true)][string]$ExpectedEgressIdentitySHA256,
    [string]$ExpectedProfileSHA256,
    [string]$ExpectedClientSHA256,
    [string]$ExpectedClientVersion = '5.0.1.5',
    [int]$FreshnessSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-TextSHA256([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Assert-SHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label must be one lowercase SHA-256 value" }
}

function ConvertTo-SanitizedClientRecord(
    [string]$Action,
    [object]$Observation,
    [string]$ExpectedGuestPeerFingerprintSHA256,
    [string]$ExpectedEgressIdentitySHA256
) {
    $redshieldHash = Get-TextSHA256 ([string]$Observation.redshield_identity)
    $ciscoHash = Get-TextSHA256 ([string]$Observation.cisco_identity)
    $selfhostedHash = if ([string]::IsNullOrWhiteSpace([string]$Observation.selfhosted_identity)) { '' } else { Get-TextSHA256 ([string]$Observation.selfhosted_identity) }
    $routeHash = if ([string]::IsNullOrWhiteSpace([string]$Observation.route_interface_identity)) { '' } else { Get-TextSHA256 ([string]$Observation.route_interface_identity) }
    $peerHash = [string]$Observation.peer_fingerprint_sha256
    $egressHashes = @($Observation.egress_values | ForEach-Object { Get-TextSHA256 ([string]$_) })
    $egressMatches = @($egressHashes | Where-Object { $_ -ceq $ExpectedEgressIdentitySHA256 }).Count
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-client-gate/v1'
        action = $Action.ToLowerInvariant()
        profile_sha256 = [string]$Observation.profile_sha256
        client_sha256 = [string]$Observation.client_sha256
        client_version_match = ([string]$Observation.client_version -ceq '5.0.1.5')
        signature_valid = [bool]$Observation.signature_valid
        redshield_adapter_class_sha256 = $redshieldHash
        cisco_adapter_class_sha256 = $ciscoHash
        selfhosted_adapter_count = if ($selfhostedHash) { 1 } else { 0 }
        selfhosted_adapter_class_sha256 = $selfhostedHash
        route_matches_selfhosted = ($selfhostedHash -ne '' -and $routeHash -ceq $selfhostedHash)
        peer_fingerprint_match = ($peerHash -ne '' -and $peerHash -ceq $ExpectedGuestPeerFingerprintSHA256)
        handshake_fresh = [bool]$Observation.handshake_fresh
        traffic_delta_observed = [bool]$Observation.traffic_delta
        egress_observation_count = $egressHashes.Count
        egress_match_count = $egressMatches
        egress_consensus = ($egressHashes.Count -eq 3 -and @($egressHashes | Select-Object -Unique).Count -eq 1)
        redshield_equals_pre = [bool]$Observation.redshield_equals_pre
        cisco_equals_pre = [bool]$Observation.cisco_equals_pre
        live_mutation_performed = $false
    }
}

function Read-BoundedObservation([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or [IO.Path]::GetFullPath($Path) -cne $Path) { throw 'observation path must be clean and absolute' }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt 65536) { throw 'observation must be one bounded regular file' }
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try {
        $reader = [IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$true)
        try { return ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-LiveClientObservation([string]$Action, [string]$PinsPath, [string]$ClientPath, [string]$ProfilePath) {
    if ([string]::IsNullOrWhiteSpace($PinsPath) -or [string]::IsNullOrWhiteSpace($ClientPath) -or [string]::IsNullOrWhiteSpace($ProfilePath)) { throw 'live observation requires RuntimePinsPath, ClientPath and ProfilePath' }
    $pins = Read-BoundedObservation ([IO.Path]::GetFullPath($PinsPath))
    if (@($pins.egress_https_endpoints).Count -ne 3 -or [string]::IsNullOrWhiteSpace([string]$pins.ssh_host) -or [string]::IsNullOrWhiteSpace([string]$pins.ssh_user) -or [string]::IsNullOrWhiteSpace([string]$pins.known_hosts_path)) { throw 'runtime observation pins are incomplete' }
    if ([string]::IsNullOrWhiteSpace($env:SSH_AUTH_SOCK)) { throw 'memory-only SSH agent is unavailable' }
    $clientItem = Get-Item -LiteralPath ([IO.Path]::GetFullPath($ClientPath)) -Force -ErrorAction Stop
    $profileItem = Get-Item -LiteralPath ([IO.Path]::GetFullPath($ProfilePath)) -Force -ErrorAction Stop
    foreach ($item in @($clientItem,$profileItem)) { if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'client/profile input is not one regular file' } }
    $signature = Get-AuthenticodeSignature -LiteralPath $clientItem.FullName
    $clientVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($clientItem.FullName).FileVersion
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $redshield = @($adapters | Where-Object { $_.InterfaceDescription -match 'RedShield' })
    $cisco = @($adapters | Where-Object { $_.InterfaceDescription -match 'Cisco' })
    $selfhosted = @($adapters | Where-Object { $_.InterfaceDescription -match 'Amnezia|Wintun|WireGuard' -and $_.InterfaceDescription -notmatch 'RedShield' })
    $egressValues = @()
    $routeIdentity = ''
    $server = [pscustomobject]@{ selected_peer_fingerprint_sha256=''; handshake_fresh=$false; traffic_delta=$false }
    if ($Action -ceq 'PostConnect') {
        foreach ($endpoint in @($pins.egress_https_endpoints)) {
            try { $uri = [Uri][string]$endpoint } catch { throw 'egress endpoint URI is invalid' }
            if (-not $uri.IsAbsoluteUri -or -not $uri.Scheme.Equals('https',[StringComparison]::OrdinalIgnoreCase)) { throw 'egress endpoint must use HTTPS' }
            $value = [string](Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -MaximumRedirection 0 -ErrorAction Stop)
            $parsed = [Net.IPAddress]$null
            if (-not [Net.IPAddress]::TryParse($value.Trim(),[ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'egress observation is not one IPv4 value' }
            $egressValues += $parsed.ToString()
        }
        $routeTarget = @([Net.Dns]::GetHostAddresses(([Uri][string]$pins.egress_https_endpoints[0]).Host) | Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork })
        if ($routeTarget.Count -eq 0) { throw 'egress route target resolution failed' }
        $route = Find-NetRoute -RemoteIPAddress $routeTarget[0].ToString() -ErrorAction Stop | Select-Object -ExpandProperty Route
        $routeAdapter = @($adapters | Where-Object { $_.ifIndex -eq $route.ifIndex })
        if ($routeAdapter.Count -eq 1) { $routeIdentity = [string]$routeAdapter[0].InterfaceGuid }
        $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        $ssh = [IO.Path]::Combine($windows,'System32','OpenSSH','ssh.exe')
        $serverText = & $ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$([string]$pins.known_hosts_path)" -o ConnectTimeout=10 "$([string]$pins.ssh_user)@$([string]$pins.ssh_host)" 'sudo /usr/local/libexec/home-gateway-p3-peer-observe --json'
        if ($LASTEXITCODE -ne 0) { throw 'server peer observation transport failed' }
        $server = ConvertFrom-Json -InputObject ($serverText -join '') -ErrorAction Stop
    }
    return [pscustomobject]@{
        profile_sha256 = (Get-FileHash -LiteralPath $profileItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        client_sha256 = (Get-FileHash -LiteralPath $clientItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        client_version = $clientVersion
        signature_valid = ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid)
        redshield_identity = (@($redshield.InterfaceGuid) -join '|')
        cisco_identity = (@($cisco.InterfaceGuid) -join '|')
        selfhosted_identity = if ($selfhosted.Count -eq 1) { [string]$selfhosted[0].InterfaceGuid } else { '' }
        route_interface_identity = $routeIdentity
        peer_fingerprint_sha256 = [string]$server.selected_peer_fingerprint_sha256
        handshake_fresh = [bool]$server.handshake_fresh
        traffic_delta = [bool]$server.traffic_delta
        egress_values = $egressValues
        redshield_equals_pre = [bool]$pins.redshield_equals_pre
        cisco_equals_pre = [bool]$pins.cisco_equals_pre
    }
}

# The live collector contract is intentionally read-only. The runtime wrapper
# may obtain its sanitized observation using pinned inbox commands only:
# Get-AuthenticodeSignature/Get-FileHash, Get-NetAdapter/Get-NetRoute, three
# bounded Invoke-RestMethod HTTPS observations, and ssh.exe with BatchMode,
# IdentitiesOnly and StrictHostKeyChecking against a runtime known-hosts pin.
# It must use the existing memory-only SSH_AUTH_SOCK and a key-only server
# observer that returns only fingerprint-hash/freshness/delta booleans.
if ($FreshnessSeconds -lt 30 -or $FreshnessSeconds -gt 300) { throw 'freshness bound must be between 30 and 300 seconds' }
foreach ($entry in @(
    @{Value=$ExpectedGuestPeerFingerprintSHA256;Label='Guest peer fingerprint hash'},
    @{Value=$ExpectedEgressIdentitySHA256;Label='egress identity hash'}
)) { Assert-SHA256 $entry.Value $entry.Label }
if (-not [string]::IsNullOrWhiteSpace($ExpectedProfileSHA256)) { Assert-SHA256 $ExpectedProfileSHA256 'profile hash' }
if (-not [string]::IsNullOrWhiteSpace($ExpectedClientSHA256)) { Assert-SHA256 $ExpectedClientSHA256 'client hash' }

$observation = if ([string]::IsNullOrWhiteSpace($ObservationPath)) {
    Get-LiveClientObservation -Action $Action -PinsPath $RuntimePinsPath -ClientPath $ClientPath -ProfilePath $ProfilePath
} else {
    Read-BoundedObservation ([IO.Path]::GetFullPath($ObservationPath))
}
$record = ConvertTo-SanitizedClientRecord -Action $Action -Observation $observation `
    -ExpectedGuestPeerFingerprintSHA256 $ExpectedGuestPeerFingerprintSHA256 -ExpectedEgressIdentitySHA256 $ExpectedEgressIdentitySHA256
if ($ExpectedClientVersion -cne '5.0.1.5' -or -not $record.client_version_match -or -not $record.signature_valid) { throw 'AmneziaVPN binary version or Authenticode signature differs' }
if ($ExpectedProfileSHA256 -and $record.profile_sha256 -cne $ExpectedProfileSHA256) { throw 'profile hash differs' }
if ($ExpectedClientSHA256 -and $record.client_sha256 -cne $ExpectedClientSHA256) { throw 'client binary hash differs' }
switch ($Action) {
    'Preflight' {
        if ($record.selfhosted_adapter_count -ne 0) { throw 'self-hosted adapter exists before activation' }
    }
    'PostConnect' {
        if ($record.selfhosted_adapter_count -ne 1 -or -not $record.route_matches_selfhosted -or -not $record.peer_fingerprint_match -or -not $record.handshake_fresh -or -not $record.traffic_delta_observed -or -not $record.egress_consensus -or $record.egress_match_count -ne 3) { throw 'post-connect observation gate failed' }
    }
    'PostRollback' {
        if ($record.selfhosted_adapter_count -ne 0 -or -not $record.redshield_equals_pre -or -not $record.cisco_equals_pre) { throw 'post-rollback preservation gate failed' }
    }
}
[Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject $record))
