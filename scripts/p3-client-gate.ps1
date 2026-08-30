[CmdletBinding()]
param(
    [ValidateSet('', 'Preflight', 'PostConnect', 'PostRollback')][string]$Action = '',
    [string]$ObservationPath,
    [switch]$TestOnlyFixture,
    [string]$TestFixtureRoot,
    [string]$RuntimeRoot,
    [string]$PreReceiptPath,
    [string]$ClientPath,
    [string]$ProfilePath,
    [string]$ExpectedManifestSHA256,
    [string]$ExpectedGuestPeerFingerprintSHA256,
    [string]$ExpectedEgressIdentitySHA256,
    [string]$ExpectedProfileSHA256,
    [string]$ExpectedClientSHA256,
    [string]$ExpectedKnownHostsSHA256,
    [string]$ExpectedBeforeCounterSHA256,
    [string]$ExpectedAfterCounterSHA256,
    [string[]]$EgressEndpoints,
    [string]$PreviousNonceSHA256 = ('0' * 64),
    [string]$ExpectedClientVersion = '5.0.1.5'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:P3ClientObservationProperties = @(
    'cisco_class_count', 'cisco_class_sha256', 'client_sha256', 'client_version_match',
    'egress_identity_sha256', 'egress_observation_count', 'live_mutation_performed', 'observed_at_utc',
    'profile_absent', 'profile_sha256', 'redshield_class_count', 'redshield_class_sha256',
    'route_matches_selfhosted', 'schema', 'selfhosted_adapter_count', 'selfhosted_class_sha256',
    'signature_valid'
)
$script:P3ClientReceiptProperties = @(
    'after_counter_sha256', 'before_counter_sha256', 'handshake_fresh', 'nonce_sha256',
    'observation_duration_seconds', 'payload_sha256', 'protocol_sha256', 'schema',
    'selected_guest_match', 'traffic_delta'
)
$script:P3ClientPreProperties = @(
    'cisco_class_count', 'cisco_class_sha256', 'observed_at_utc', 'redshield_class_count',
    'redshield_class_sha256', 'schema'
)

function Get-P3ClientTextSHA256([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Assert-P3ClientSHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label hash differs" }
}

function Assert-P3ClientExactProperties([object]$Value, [string[]]$Expected, [string]$Label) {
    if ($Value -is [Array]) {
        if ($Value.Count -ne 1) { throw "$Label schema differs" }
        $Value = $Value[0]
    }
    if ($null -eq $Value) { throw "$Label schema differs" }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject ($Expected | Sort-Object) -DifferenceObject $actual).Count -ne 0) {
        throw "$Label schema differs"
    }
}

function Get-P3ClientUtc([string]$Value, [string]$Label) {
    try {
        return [DateTime]::Parse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
    } catch { throw "$Label timestamp differs" }
}

function Read-P3ClientFixture([string]$Path, [string]$FixtureRoot) {
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($FixtureRoot)) {
        throw 'test-only fixture mode requires ObservationPath and fixture root'
    }
    $fullRoot = [IO.Path]::GetFullPath($FixtureRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $prefix = $fullRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'observation is outside fixture root' }
    $rootItem = Get-Item -LiteralPath $fullRoot -Force -ErrorAction Stop
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt 65536) { throw 'fixture must be one bounded regular file' }
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true)
        try { $value = ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    Assert-P3ClientExactProperties -Value $value -Expected $script:P3ClientObservationProperties -Label 'client observation'
    if ([string]$value.schema -cne 'home-gateway/p3-client-local-observation/v2' -or [bool]$value.live_mutation_performed) {
        throw 'client observation schema differs'
    }
    return $value
}

function Read-P3ClientObservation(
    [string]$Action,
    [string]$ObservationPath,
    [switch]$TestOnlyFixture,
    [string]$TestFixtureRoot
) {
    if (-not [string]::IsNullOrWhiteSpace($ObservationPath) -and -not $TestOnlyFixture) { throw 'ObservationPath is test-only' }
    if ($TestOnlyFixture -and [string]::IsNullOrWhiteSpace($ObservationPath)) { throw 'test-only fixture mode requires ObservationPath' }
    if (-not $TestOnlyFixture) { throw 'production observation requires the current-state collector' }
    return Read-P3ClientFixture -Path $ObservationPath -FixtureRoot $TestFixtureRoot
}

function Invoke-P3ClientChildProcess(
    [string]$Executable,
    [string[]]$Arguments,
    [string]$InputJson,
    [int]$TimeoutSeconds,
    [int]$MaximumBytes
) {
    $inputPath = [IO.Path]::GetTempFileName()
    $outputPath = [IO.Path]::GetTempFileName()
    $errorPath = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($inputPath, $InputJson, [Text.UTF8Encoding]::new($false))
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden `
            -RedirectStandardInput $inputPath -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath -PassThru
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $timedOut = $false
        $oversized = $false
        while (-not $process.HasExited) {
            if (([IO.FileInfo]$outputPath).Length + ([IO.FileInfo]$errorPath).Length -gt $MaximumBytes) {
                $oversized = $true
                $process.Kill()
                break
            }
            if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                $timedOut = $true
                $process.Kill()
                break
            }
            Start-Sleep -Milliseconds 50
            $process.Refresh()
        }
        $process.WaitForExit()
        if (([IO.FileInfo]$outputPath).Length + ([IO.FileInfo]$errorPath).Length -gt $MaximumBytes) { $oversized = $true }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode; TimedOut = $timedOut; Oversized = $oversized
            StdOut = if ($oversized) { '' } else { [IO.File]::ReadAllText($outputPath, [Text.UTF8Encoding]::new($false, $true)) }
            StdErr = if ($oversized) { '' } else { [IO.File]::ReadAllText($errorPath, [Text.UTF8Encoding]::new($false, $true)) }
        }
    } finally {
        foreach ($path in @($inputPath, $outputPath, $errorPath)) {
            if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
        }
    }
}

$script:P3ClientChildRunner = {
    param($Executable, $Arguments, $InputJson, $TimeoutSeconds, $MaximumBytes)
    Invoke-P3ClientChildProcess @PSBoundParameters
}

function Invoke-P3ClientPeerObservation([object]$Context, [string]$Nonce, [scriptblock]$Runner) {
    foreach ($entry in @(
        @{ Value = $Context.ExpectedManifestSHA256; Label = 'manifest' },
        @{ Value = $Context.PayloadSHA256; Label = 'payload' },
        @{ Value = $Context.ProtocolSHA256; Label = 'protocol' },
        @{ Value = $Context.SelectedGuestFingerprintSHA256; Label = 'selected Guest' },
        @{ Value = $Context.PreviousNonceSHA256; Label = 'previous nonce' },
        @{ Value = $Context.ExpectedBeforeCounterSHA256; Label = 'before counter' },
        @{ Value = $Context.ExpectedAfterCounterSHA256; Label = 'after counter' }
    )) { Assert-P3ClientSHA256 -Value ([string]$entry.Value) -Label ([string]$entry.Label) }
    if ($Nonce -cnotmatch '^[0-9a-f]{64}$') { throw 'nonce differs' }
    $nonceSHA256 = Get-P3ClientTextSHA256 $Nonce
    if ($nonceSHA256 -ceq [string]$Context.PreviousNonceSHA256) { throw 'replayed nonce differs' }
    $launcher = [IO.Path]::GetFullPath([string]$Context.LauncherPath)
    if ([IO.Path]::GetFileName($launcher) -cne 'p3-amnezia-peer-guard.ps1') { throw 'fixed guard launcher differs' }
    $request = [ordered]@{
        nonce = $Nonce
        selected_guest_fingerprint_sha256 = [string]$Context.SelectedGuestFingerprintSHA256
        previous_nonce_sha256 = [string]$Context.PreviousNonceSHA256
        expected_before_counter_sha256 = [string]$Context.ExpectedBeforeCounterSHA256
        expected_after_counter_sha256 = [string]$Context.ExpectedAfterCounterSHA256
    }
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $launcher, '-Action', 'ClientObserve',
        '-RuntimeRoot', [string]$Context.RuntimeRoot, '-ExpectedManifestSHA256', [string]$Context.ExpectedManifestSHA256
    )
    if ($null -eq $Runner) { $Runner = $script:P3ClientChildRunner }
    $configuredExecutable = if ($Context.PSObject.Properties.Name -contains 'PowerShellPath') { [string]$Context.PowerShellPath } else { '' }
    $executable = if ([string]::IsNullOrWhiteSpace($configuredExecutable)) { (Get-Process -Id $PID).Path } else { $configuredExecutable }
    $result = & $Runner $executable $arguments ($request | ConvertTo-Json -Compress) 40 65536
    if ([bool]$result.TimedOut) { throw 'client observation duration timed out' }
    $size = [Text.Encoding]::UTF8.GetByteCount([string]$result.StdOut) + [Text.Encoding]::UTF8.GetByteCount([string]$result.StdErr)
    if ([bool]$result.Oversized -or $size -gt 65536) { throw 'client observation output exceeds bound' }
    if ([int]$result.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace([string]$result.StdErr)) { throw 'client observation transport differs' }
    try { $receipt = ConvertFrom-Json -InputObject ([string]$result.StdOut) -ErrorAction Stop }
    catch { throw 'client observation schema differs' }
    Assert-P3ClientExactProperties -Value $receipt -Expected $script:P3ClientReceiptProperties -Label 'client receipt'
    if ([string]$receipt.schema -cne 'home-gateway/p3-peer-client-observe/v2') { throw 'client receipt schema differs' }
    if ([string]$receipt.payload_sha256 -cne [string]$Context.PayloadSHA256) { throw 'client receipt payload differs' }
    if ([string]$receipt.protocol_sha256 -cne [string]$Context.ProtocolSHA256) { throw 'client receipt protocol differs' }
    if ([string]$receipt.nonce_sha256 -cne $nonceSHA256) { throw 'client receipt nonce differs' }
    if (-not [bool]$receipt.selected_guest_match) { throw 'client receipt selected Guest differs' }
    if (-not [bool]$receipt.handshake_fresh) { throw 'client receipt handshake differs' }
    if ([string]$receipt.before_counter_sha256 -cne [string]$Context.ExpectedBeforeCounterSHA256) { throw 'client receipt before counter differs' }
    if ([string]$receipt.after_counter_sha256 -cne [string]$Context.ExpectedAfterCounterSHA256) { throw 'client receipt after counter differs' }
    if (-not [bool]$receipt.traffic_delta) { throw 'client receipt traffic differs' }
    if ([int]$receipt.observation_duration_seconds -lt 1 -or [int]$receipt.observation_duration_seconds -gt 180) { throw 'client receipt duration differs' }
    return $receipt
}

function New-P3ClientPreReceipt([object]$Observation, [DateTime]$NowUtc) {
    foreach ($name in @('redshield_class_sha256', 'cisco_class_sha256')) {
        Assert-P3ClientSHA256 -Value ([string]$Observation.$name) -Label $name
    }
    if ([int]$Observation.redshield_class_count -lt 0 -or [int]$Observation.cisco_class_count -lt 0) { throw 'adapter class count differs' }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-client-pre-receipt/v2'
        redshield_class_sha256 = [string]$Observation.redshield_class_sha256
        redshield_class_count = [int]$Observation.redshield_class_count
        cisco_class_sha256 = [string]$Observation.cisco_class_sha256
        cisco_class_count = [int]$Observation.cisco_class_count
        observed_at_utc = $NowUtc.ToUniversalTime().ToString('o')
    }
}

function Test-P3ClientPreservation([object]$PreReceipt, [object]$Observation, [DateTime]$NowUtc) {
    Assert-P3ClientExactProperties -Value $PreReceipt -Expected $script:P3ClientPreProperties -Label 'PRE receipt'
    if ([string]$PreReceipt.schema -cne 'home-gateway/p3-client-pre-receipt/v2') { throw 'PRE receipt schema differs' }
    $observed = Get-P3ClientUtc -Value ([string]$PreReceipt.observed_at_utc) -Label 'PRE receipt'
    if ($observed -gt $NowUtc.ToUniversalTime().AddMinutes(1)) { throw 'PRE receipt timestamp differs' }
    $redshieldEqual = ([string]$PreReceipt.redshield_class_sha256 -ceq [string]$Observation.redshield_class_sha256 -and
        [int]$PreReceipt.redshield_class_count -eq [int]$Observation.redshield_class_count)
    $ciscoEqual = ([string]$PreReceipt.cisco_class_sha256 -ceq [string]$Observation.cisco_class_sha256 -and
        [int]$PreReceipt.cisco_class_count -eq [int]$Observation.cisco_class_count)
    if (-not $redshieldEqual) { throw 'RedShield preservation differs from PRE receipt' }
    if (-not $ciscoEqual) { throw 'Cisco preservation differs from PRE receipt' }
    return [pscustomobject]@{ redshield_equals_pre = $true; cisco_equals_pre = $true }
}

function ConvertTo-P3ClientRecord([string]$Action, [object]$Observation, [object]$ClientReceipt) {
    $record = [ordered]@{
        schema = 'home-gateway/p3-client-gate/v2'; action = $Action.ToLowerInvariant()
        profile_sha256 = [string]$Observation.profile_sha256; profile_absent = [bool]$Observation.profile_absent
        client_sha256 = [string]$Observation.client_sha256; client_version_match = [bool]$Observation.client_version_match
        signature_valid = [bool]$Observation.signature_valid
        redshield_class_sha256 = [string]$Observation.redshield_class_sha256; redshield_class_count = [int]$Observation.redshield_class_count
        cisco_class_sha256 = [string]$Observation.cisco_class_sha256; cisco_class_count = [int]$Observation.cisco_class_count
        selfhosted_adapter_count = [int]$Observation.selfhosted_adapter_count; selfhosted_class_sha256 = [string]$Observation.selfhosted_class_sha256
        route_matches_selfhosted = [bool]$Observation.route_matches_selfhosted
        egress_identity_sha256 = [string]$Observation.egress_identity_sha256; egress_observation_count = [int]$Observation.egress_observation_count
        live_mutation_performed = $false
    }
    if ($null -ne $ClientReceipt) {
        foreach ($name in $script:P3ClientReceiptProperties) { $record["peer_$name"] = $ClientReceipt.$name }
    }
    return [pscustomobject]$record
}

function Get-P3ClientClass([object[]]$Items) {
    $values = @($Items | ForEach-Object { [string]$_.InterfaceDescription } | Sort-Object -Unique)
    return [pscustomobject]@{ Count = $values.Count; SHA256 = Get-P3ClientTextSHA256 ($values -join "`n") }
}

function Test-P3ClientEgressAuthorities([string[]]$Endpoints, [string[]]$ExpectedAuthoritySHA256) {
    if (@($Endpoints).Count -ne 3 -or @($ExpectedAuthoritySHA256).Count -ne 3) { throw 'three HTTPS egress authorities are required' }
    $actual = @()
    foreach ($endpoint in $Endpoints) {
        try { $uri = [Uri]$endpoint } catch { throw 'egress endpoint must use HTTPS' }
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https' -or -not [string]::IsNullOrEmpty($uri.Query) -or -not [string]::IsNullOrEmpty($uri.Fragment)) {
            throw 'egress endpoint must use HTTPS'
        }
        $actual += Get-P3ClientTextSHA256 $uri.Authority.ToLowerInvariant()
    }
    if (@($actual | Select-Object -Unique).Count -ne 3 -or
        @(Compare-Object -ReferenceObject ($ExpectedAuthoritySHA256 | Sort-Object) -DifferenceObject ($actual | Sort-Object)).Count -ne 0) {
        throw 'egress authority hashes differ'
    }
}

function Get-P3LiveClientObservation([string]$Action, [string]$ClientPath, [string]$ProfilePath, [string]$ExpectedClientVersion, [string[]]$EgressEndpoints) {
    $clientItem = Get-Item -LiteralPath ([IO.Path]::GetFullPath($ClientPath)) -Force -ErrorAction Stop
    if ($clientItem.PSIsContainer -or ($clientItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'client binary differs' }
    $profileItem = if ($Action -ceq 'PostRollback') { $null } else { Get-Item -LiteralPath ([IO.Path]::GetFullPath($ProfilePath)) -Force -ErrorAction Stop }
    if ($null -ne $profileItem -and ($profileItem.PSIsContainer -or ($profileItem.Attributes -band [IO.FileAttributes]::ReparsePoint))) { throw 'profile differs' }
    if ($Action -ceq 'PostRollback' -and (Test-Path -LiteralPath ([IO.Path]::GetFullPath($ProfilePath)))) { throw 'profile still present after rollback' }
    $clientSHA256 = (Get-FileHash -LiteralPath $clientItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $profileSHA256 = if ($null -eq $profileItem) { '' } else { (Get-FileHash -LiteralPath $profileItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    $signature = Get-AuthenticodeSignature -LiteralPath $clientItem.FullName
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($clientItem.FullName).FileVersion
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $redshield = Get-P3ClientClass @($adapters | Where-Object { $_.InterfaceDescription -match 'RedShield' })
    $cisco = Get-P3ClientClass @($adapters | Where-Object { $_.InterfaceDescription -match 'Cisco' })
    $selfhosted = @($adapters | Where-Object { $_.InterfaceDescription -match 'Amnezia|Wintun|WireGuard' -and $_.InterfaceDescription -notmatch 'RedShield' })
    $selfhostedClass = Get-P3ClientClass $selfhosted
    $routeMatches = $false
    $egressSHA256 = Get-P3ClientTextSHA256 ''
    $egressCount = 0
    if ($Action -ceq 'PostConnect') {
        if (@($EgressEndpoints).Count -ne 3) { throw 'three HTTPS egress endpoints are required' }
        $values = @()
        foreach ($endpoint in $EgressEndpoints) {
            $uri = [Uri]$endpoint
            if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https') { throw 'egress endpoint must use HTTPS' }
            $value = [string](Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -MaximumRedirection 0 -ErrorAction Stop)
            $address = [Net.IPAddress]$null
            if (-not [Net.IPAddress]::TryParse($value.Trim(), [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'egress observation differs' }
            $values += $address.ToString()
        }
        $egressCount = $values.Count
        if (@($values | Select-Object -Unique).Count -ne 1) { throw 'egress consensus differs' }
        $egressSHA256 = Get-P3ClientTextSHA256 $values[0]
        $target = @([Net.Dns]::GetHostAddresses(([Uri]$EgressEndpoints[0]).Host) | Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork })
        if ($target.Count -eq 0) { throw 'route target differs' }
        $route = Find-NetRoute -RemoteIPAddress $target[0].ToString() -ErrorAction Stop | Select-Object -ExpandProperty Route
        $routeMatches = (@($selfhosted | Where-Object { $_.ifIndex -eq $route.ifIndex }).Count -eq 1)
    }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-client-local-observation/v2'
        profile_sha256 = $profileSHA256; profile_absent = ($null -eq $profileItem); client_sha256 = $clientSHA256
        client_version_match = ($version -ceq $ExpectedClientVersion); signature_valid = ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid)
        redshield_class_sha256 = $redshield.SHA256; redshield_class_count = $redshield.Count
        cisco_class_sha256 = $cisco.SHA256; cisco_class_count = $cisco.Count
        selfhosted_adapter_count = $selfhosted.Count; selfhosted_class_sha256 = $selfhostedClass.SHA256
        route_matches_selfhosted = $routeMatches; egress_identity_sha256 = $egressSHA256; egress_observation_count = $egressCount
        observed_at_utc = [DateTime]::UtcNow.ToString('o'); live_mutation_performed = $false
    }
}

function Get-P3ClientRuntimeContext([string]$Root, [string]$ManifestSHA256) {
    . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
    $null = Invoke-P3RuntimeValidate -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestSHA256
    $manifest = Open-P3BoundedStableJson -Path (Join-Path $Root 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
    $trust = Open-P3BoundedStableJson -Path (Join-Path $Root 'trust.json') -MaximumBytes 65536 -ExpectedProperties $script:P3TrustProperties
    return [pscustomobject]@{ Manifest = $manifest; Trust = $trust }
}

function Get-P3ClientPreReceipt([string]$Root, [string]$ManifestSHA256, [string]$Path) {
    $null = Get-P3ClientRuntimeContext -Root $Root -ManifestSHA256 $ManifestSHA256
    $expectedPath = [IO.Path]::GetFullPath((Join-Path $Root 'pre-receipt.json'))
    if ([IO.Path]::GetFullPath($Path) -cne $expectedPath) { throw 'PRE receipt path differs' }
    return Open-P3BoundedStableJson -Path $expectedPath -MaximumBytes 65536 -ExpectedProperties $script:P3ClientPreProperties
}

function Set-P3ClientPreReceipt([string]$Root, [string]$ManifestSHA256, [string]$Path, [object]$Receipt) {
    $null = Get-P3ClientRuntimeContext -Root $Root -ManifestSHA256 $ManifestSHA256
    $expectedPath = [IO.Path]::GetFullPath((Join-Path $Root 'pre-receipt.json'))
    if ([IO.Path]::GetFullPath($Path) -cne $expectedPath) { throw 'PRE receipt path differs' }
    Write-P3RuntimeJson -RuntimeRoot $Root -Name 'pre-receipt.json' -Value $Receipt
}

if (-not [string]::IsNullOrEmpty($Action)) {
    foreach ($entry in @(
        @{ Value = $ExpectedManifestSHA256; Label = 'manifest' }, @{ Value = $ExpectedGuestPeerFingerprintSHA256; Label = 'Guest fingerprint' },
        @{ Value = $ExpectedEgressIdentitySHA256; Label = 'egress identity' }, @{ Value = $ExpectedProfileSHA256; Label = 'profile' },
        @{ Value = $ExpectedClientSHA256; Label = 'client' }, @{ Value = $ExpectedKnownHostsSHA256; Label = 'known-hosts' }
    )) { Assert-P3ClientSHA256 -Value $entry.Value -Label $entry.Label }
    if (-not [string]::IsNullOrWhiteSpace($ObservationPath) -and -not $TestOnlyFixture) { throw 'ObservationPath is test-only' }
    if ($TestOnlyFixture -and [string]::IsNullOrWhiteSpace($ObservationPath)) { throw 'test-only fixture mode requires ObservationPath' }
    $runtime = Get-P3ClientRuntimeContext -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256
    if ([string]$runtime.Manifest.known_hosts_sha256 -cne $ExpectedKnownHostsSHA256) { throw 'known-hosts hash differs' }
    if ($Action -ceq 'PostConnect') { Test-P3ClientEgressAuthorities -Endpoints $EgressEndpoints -ExpectedAuthoritySHA256 @($runtime.Trust.egress_authority_sha256) }
    $observation = if ($TestOnlyFixture) {
        Read-P3ClientObservation -Action $Action -ObservationPath $ObservationPath -TestOnlyFixture -TestFixtureRoot $TestFixtureRoot
    } else {
        Get-P3LiveClientObservation -Action $Action -ClientPath $ClientPath -ProfilePath $ProfilePath -ExpectedClientVersion $ExpectedClientVersion -EgressEndpoints $EgressEndpoints
    }
    if ([string]$observation.client_sha256 -cne $ExpectedClientSHA256 -or -not [bool]$observation.client_version_match -or -not [bool]$observation.signature_valid) { throw 'client binary identity differs' }
    if ($Action -cne 'PostRollback' -and [string]$observation.profile_sha256 -cne $ExpectedProfileSHA256) { throw 'profile hash differs' }
    $peerReceipt = $null
    if ($Action -ceq 'Preflight') {
        if ([int]$observation.selfhosted_adapter_count -ne 0) { throw 'self-hosted adapter exists before activation' }
        Set-P3ClientPreReceipt -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256 -Path $PreReceiptPath -Receipt (New-P3ClientPreReceipt -Observation $observation -NowUtc ([DateTime]::UtcNow))
    } else {
        $pre = Get-P3ClientPreReceipt -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256 -Path $PreReceiptPath
        $null = Test-P3ClientPreservation -PreReceipt $pre -Observation $observation -NowUtc ([DateTime]::UtcNow)
    }
    if ($Action -ceq 'PostConnect') {
        $nonceBytes = [byte[]]::new(32)
        $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($nonceBytes) } finally { $generator.Dispose() }
        $nonce = ([BitConverter]::ToString($nonceBytes)).Replace('-', '').ToLowerInvariant()
        $context = [pscustomobject]@{
            LauncherPath = Join-Path $PSScriptRoot 'p3-amnezia-peer-guard.ps1'; RuntimeRoot = $RuntimeRoot
            ExpectedManifestSHA256 = $ExpectedManifestSHA256; PayloadSHA256 = $runtime.Manifest.local_payload_sha256
            ProtocolSHA256 = $runtime.Manifest.protocol_sha256; SelectedGuestFingerprintSHA256 = $ExpectedGuestPeerFingerprintSHA256
            PreviousNonceSHA256 = $PreviousNonceSHA256; ExpectedBeforeCounterSHA256 = $ExpectedBeforeCounterSHA256
            ExpectedAfterCounterSHA256 = $ExpectedAfterCounterSHA256
        }
        $peerReceipt = Invoke-P3ClientPeerObservation -Context $context -Nonce $nonce -Runner $null
        if ([int]$observation.selfhosted_adapter_count -ne 1 -or -not [bool]$observation.route_matches_selfhosted -or
            [int]$observation.egress_observation_count -ne 3 -or [string]$observation.egress_identity_sha256 -cne $ExpectedEgressIdentitySHA256) {
            throw 'post-connect observation gate failed'
        }
    }
    if ($Action -ceq 'PostRollback' -and (-not [bool]$observation.profile_absent -or [int]$observation.selfhosted_adapter_count -ne 0)) {
        throw 'post-rollback observation gate failed'
    }
    [Console]::Out.WriteLine((ConvertTo-P3ClientRecord -Action $Action -Observation $observation -ClientReceipt $peerReceipt | ConvertTo-Json -Compress))
}
