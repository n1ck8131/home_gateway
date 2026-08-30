[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('PreApply','PendingQuickCheck','CommittedMatrix','TunnelDown','ProcessRecovery','AdapterLoss','RebootRecovery','RollbackVerify')][string]$Action,
    [Parameter(Mandatory = $true)][string]$ObservationPath,
    [string]$CandidateSHA256,
    [string]$StateRootIdentity,
    [string]$PendingDeadlineUtc,
    [ValidateRange(5,90)][int]$MaxDurationSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function ConvertTo-FieldMatrixRecord([string]$Action, [object]$Observation, [int]$MaxDurationSeconds, [string]$CandidateSHA256 = '', [string]$StateRootIdentity = '', [string]$PendingDeadlineUtc = '', [string]$CreatedUtc = '') {
    if ($MaxDurationSeconds -lt 5 -or $MaxDurationSeconds -gt 90) { throw 'matrix timeout lacks the required two-minute watchdog safety margin' }
    if ([int]$Observation.elapsed_seconds -lt 0 -or [int]$Observation.elapsed_seconds -gt $MaxDurationSeconds) { throw 'matrix observation exceeded its timeout' }
    function Get-IdentityHash([string]$Value) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    }
    $targetHashes = @($Observation.target_identities | ForEach-Object { Get-IdentityHash ([string]$_) } | Sort-Object -Unique)
    $transportPassCount = @([bool]$Observation.tcp_ok,[bool]$Observation.udp_ok,[bool]$Observation.quic_ok | Where-Object { $_ }).Count
    $record = [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-windows-field-matrix/v1'
        action = $Action.ToLowerInvariant()
        candidate_sha256 = $CandidateSHA256
        state_root_identity = $StateRootIdentity
        pending_deadline_utc = $PendingDeadlineUtc
        created_utc = $CreatedUtc
        target_identity_sha256 = $targetHashes
        target_count = $targetHashes.Count
        direct_egress_identity_sha256 = Get-IdentityHash ([string]$Observation.direct_egress_identity)
        selfhosted_egress_identity_sha256 = Get-IdentityHash ([string]$Observation.selfhosted_egress_identity)
        cisco_egress_identity_sha256 = Get-IdentityHash ([string]$Observation.cisco_egress_identity)
        dns_ok = [bool]$Observation.dns_ok
        ipv4_ok = [bool]$Observation.ipv4_ok
        ipv6_ok = [bool]$Observation.ipv6_ok
        mtu_ok = [bool]$Observation.mtu_ok
        transport_pass_count = $transportPassCount
        tunnel_down_blocked = [bool]$Observation.tunnel_down_blocked
        process_recovered = [bool]$Observation.process_recovered
        adapter_loss_blocked = [bool]$Observation.adapter_loss_blocked
        reboot_recovered = [bool]$Observation.reboot_recovered
        emergency_disable_required = [bool]$Observation.emergency_disable_required
        emergency_disabled = [bool]$Observation.emergency_disabled
        redshield_equals_pre = [bool]$Observation.redshield_equals_pre
        cisco_equals_pre = [bool]$Observation.cisco_equals_pre
        selfhosted_absent = [bool]$Observation.selfhosted_absent
        elapsed_seconds = [int]$Observation.elapsed_seconds
        live_mutation_performed = $false
    }
    $core = $record.target_count -gt 0 -and $record.dns_ok -and $record.ipv4_ok -and $record.ipv6_ok -and $record.mtu_ok -and $record.transport_pass_count -eq 3
    $passed = switch ($Action) {
        'PreApply' { $record.direct_egress_identity_sha256 -ne '' -and $record.cisco_egress_identity_sha256 -ne '' -and $record.selfhosted_absent }
        'PendingQuickCheck' { $core -and $record.candidate_sha256 -cmatch '^[0-9a-f]{64}$' -and $record.state_root_identity -cmatch '^[0-9a-f]{64}$' -and -not [string]::IsNullOrWhiteSpace($record.pending_deadline_utc) -and -not [string]::IsNullOrWhiteSpace($record.created_utc) }
        'CommittedMatrix' { $core -and $record.selfhosted_egress_identity_sha256 -ne '' }
        'TunnelDown' { $record.tunnel_down_blocked -and $record.redshield_equals_pre -and $record.cisco_equals_pre }
        'ProcessRecovery' { $record.process_recovered }
        'AdapterLoss' { $record.adapter_loss_blocked -and $record.redshield_equals_pre -and $record.cisco_equals_pre }
        'RebootRecovery' { $record.reboot_recovered }
        'RollbackVerify' { $record.selfhosted_absent -and $record.redshield_equals_pre -and $record.cisco_equals_pre -and (-not $record.emergency_disable_required -or $record.emergency_disabled) }
        default { $false }
    }
    if (-not $passed) { throw "$Action field matrix failed" }
    return $record
}

$full = [IO.Path]::GetFullPath($ObservationPath)
if (-not [IO.Path]::IsPathRooted($ObservationPath) -or -not [string]::Equals($full,$ObservationPath,[StringComparison]::OrdinalIgnoreCase)) { throw 'observation path must be clean and absolute' }
$item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt 131072) { throw 'observation must be one bounded regular file' }
$stream = [IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
try {
    $reader = [IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$true)
    try { $observation = ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop } finally { $reader.Dispose() }
} finally { $stream.Dispose() }
$created = [DateTimeOffset]::UtcNow
if ($Action -ceq 'PendingQuickCheck') {
    if ($CandidateSHA256 -cnotmatch '^[0-9a-f]{64}$' -or $StateRootIdentity -cnotmatch '^[0-9a-f]{64}$') { throw 'PendingQuickCheck requires exact candidate and state-root identities' }
    $deadline = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($PendingDeadlineUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$deadline) -or $deadline -le $created.AddSeconds(30) -or $deadline -gt $created.AddSeconds(120)) { throw 'PendingQuickCheck deadline is outside the watchdog window' }
    $PendingDeadlineUtc = $deadline.ToUniversalTime().ToString('O')
}
$record = ConvertTo-FieldMatrixRecord -Action $Action -Observation $observation -MaxDurationSeconds $MaxDurationSeconds `
    -CandidateSHA256 $CandidateSHA256 -StateRootIdentity $StateRootIdentity -PendingDeadlineUtc $PendingDeadlineUtc -CreatedUtc $created.ToString('O')
[Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject $record))
