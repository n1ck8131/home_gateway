[CmdletBinding()]
param(
    [ValidateSet('', 'PreparePlan', 'Prepare', 'Validate', 'RecordCloudFirewall', 'RecordEgress', 'ObserveLocalBaseline', 'CleanupPlan', 'Cleanup')]
    [string]$Action = '',
    [string]$RuntimeRoot,
    [string]$ExpectedManifestSHA256,
    [string]$ExpectedPlanSHA256,
    [string]$Confirmation,
    [string]$ProtectedProfilePath,
    [string[]]$EgressEndpoint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:P3RuntimeMarkerName = '.home-gateway-p3-runtime-owner.v1'
$script:P3RuntimeMarkerText = 'home-gateway/p3-prelive-runtime-owner/v1'
$script:P3RuntimeFiles = @(
    '.home-gateway-p3-runtime-owner.v1',
    'trust.json',
    'manifest.json',
    'cloud-firewall-receipt.json',
    'egress-receipt.json',
    'local-baseline-receipt.json',
    'agent-receipt.json',
    'remote-install-receipt.json',
    'pre-receipt.json'
)
$script:P3TrustProperties = @(
    'accepted_cloud_firewall_sha256', 'accepted_prerequisite_cloud_firewall_sha256',
    'accepted_prerequisite_ssh_trust', 'accepted_server_baseline', 'egress_authority_sha256',
    'git_scp_path', 'git_ssh_add_path', 'git_ssh_agent_path', 'git_ssh_path', 'known_hosts_path',
    'local_payload_path', 'management_source_cidr_sha256', 'private_key_path', 'protocol_sha256',
    'public_key_fingerprint_sha256', 'public_key_path', 'remote_payload_sha256', 'rollback_paths', 'schema', 'ssh_host', 'ssh_user',
    'prerequisite_receipt_path', 'expected_prerequisite_receipt_sha256'
)
$script:P3ServerBaselineProperties = @(
    'atomic_leftover_count', 'candidate_leftover_count', 'container_count', 'container_identity_sha256',
    'container_restart_count', 'container_running', 'firewall_identity_sha256', 'host_policy_loaded',
    'host_policy_sha256', 'image_identity_sha256', 'ipv6_non_mutation', 'listener_identity_sha256',
    'ipv6_policy_sha256', 'metadata_sha256', 'persistent_config_sha256',
    'live_peer_set_sha256', 'metadata_peer_set_sha256', 'payload_sha256', 'peer_fingerprint_sha256',
    'persistent_peer_set_sha256', 'protocol_sha256', 'public_listener_class_count',
    'runtime_identity_sha256', 'temporary_leftover_count', 'temporary_state_sha256',
    'udp_publication_count', 'udp_publication_sha256'
)
$script:P3RollbackPathProperties = @('metadata_path', 'persistent_config_path', 'syncconf_path', 'temporary_path')
$script:P3ManifestProperties = @(
    'accepted_cloud_firewall_sha256', 'accepted_prerequisite_cloud_firewall_sha256',
    'accepted_prerequisite_receipt_sha256', 'accepted_prerequisite_ssh_trust_sha256', 'accepted_server_baseline_sha256',
    'git_scp_sha256', 'git_ssh_add_sha256', 'git_ssh_agent_sha256', 'git_ssh_sha256',
    'known_hosts_sha256', 'local_payload_sha256', 'management_source_cidr_sha256',
    'protocol_sha256', 'public_key_fingerprint_sha256', 'remote_payload_sha256', 'schema', 'trust_sha256'
)
$script:P3PrerequisiteReceiptProperties = @(
    'schema', 'prerequisite_manifest_sha256', 'server_baseline', 'server_baseline_sha256',
    'cloud_firewall_identity_sha256', 'firewall_resource_sha256', 'droplet_resource_sha256',
    'inbound_union_sha256', 'outbound_union_sha256', 'management_source_cidr_sha256',
    'egress_authority_sha256', 'egress_observation_sha256', 'ssh_trust', 'ssh_trust_sha256', 'payload_sha256',
    'protocol_sha256', 'nonce_sha256', 'observed_at_utc', 'owner_observed', 'server_confirmed',
    'live_mutation_performed', 'raw_identity_exposed'
)
$script:P3PrerequisiteSshTrustProperties = @(
    'schema','ssh_host','ssh_user','known_hosts_path','known_hosts_sha256','host_key_fingerprint_sha256',
    'git_ssh_agent_path','git_ssh_agent_sha256','git_ssh_add_path','git_ssh_add_sha256',
    'git_ssh_path','git_ssh_sha256','git_scp_path','git_scp_sha256','public_key_path','public_key_sha256',
    'public_key_fingerprint_sha256','private_key_path','observer_payload_path','observer_payload_sha256',
    'observer_protocol_sha256','expected_ipv6_policy_sha256','egress','connect_timeout_seconds',
    'command_timeout_seconds','maximum_output_bytes','no_write_scope'
)
$script:P3PrerequisiteManifestProperties = @(
    'schema', 'manifest_sha256', 'payload_sha256', 'protocol_sha256', 'ssh_trust', 'ssh_trust_sha256',
    'management_source_cidr_sha256', 'egress_authority_sha256', 'firewall_resource_sha256',
    'droplet_resource_sha256', 'inbound_union_sha256', 'outbound_union_sha256'
)
$script:P3PrerequisiteAgentManifestProperties = @(
    'git_scp_path','git_scp_sha256','git_ssh_add_path','git_ssh_add_sha256','git_ssh_agent_path','git_ssh_agent_sha256',
    'git_ssh_path','git_ssh_sha256','manifest_sha256','private_key_path','public_key_fingerprint_sha256','public_key_path'
)
$script:P3PrerequisiteConsumptionProperties = @('prerequisite_receipt_sha256','runtime_manifest_sha256','schema')
$script:P3CloudFirewallReceiptProperties = @(
    'cloud_firewall_identity_sha256', 'droplet_association_count', 'inbound_rule_count',
    'live_mutation_performed', 'management_source_cidr_sha256', 'observed_at_utc',
    'owner_observed', 'schema', 'server_confirmed'
)
$script:P3LocalBaselineReceiptProperties = @(
    'adapter_class_set_sha256', 'cisco_class_count', 'live_mutation_performed', 'observed_at_utc',
    'protected_profile_absent', 'redshield_class_count', 'schema', 'selfhosted_adapter_count'
)
$script:P3EgressReceiptProperties = @(
    'live_mutation_performed', 'management_source_cidr_sha256', 'observations', 'observed_at_utc', 'schema'
)
$script:P3EgressObservationProperties = @('authority_sha256', 'observed_at_utc', 'source_cidr_sha256')
$script:P3CombinedAgentReceiptProperties = @(
    'agent_executable_path', 'agent_executable_sha256', 'agent_pid', 'agent_pid_match',
    'expected_fingerprint_sha256', 'expected_key_match', 'loaded_key_count', 'manifest_sha256',
    'schema', 'socket', 'started_at_utc', 'toolchain_match'
)
$script:P3InstallReceiptProperties = @(
    'group_match', 'installed_by_gate', 'mode_match', 'owner_match', 'payload_sha256',
    'preinstall_state', 'schema', 'target_state', 'temporary_leftover_count'
)

if (-not ('HomeGateway.P3.NativeFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HomeGateway.P3 {
    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    public static class NativeFileIdentity {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);
    }
}
'@
}

function Assert-P3SHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label must be one lowercase SHA-256 value" }
}

function Get-P3SHA256Bytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-P3SHA256Text([string]$Text) {
    return Get-P3SHA256Bytes -Bytes ([Text.Encoding]::UTF8.GetBytes($Text))
}

function Resolve-P3FixedCleanPath([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path) -or
        $Path.StartsWith('\\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('\\?\', [StringComparison]::Ordinal) -or
        $Path.StartsWith('\\.\', [StringComparison]::Ordinal)) {
        throw "$Label must be a local absolute path"
    }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals($Path.TrimEnd('\'), $full.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be clean"
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw "$Label must be on a fixed local volume" }
    $cursor = $full
    while (-not [string]::IsNullOrEmpty($cursor)) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Label contains a reparse point" }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or [string]::Equals($parent, $cursor, [StringComparison]::OrdinalIgnoreCase)) { break }
        $cursor = $parent
    }
    return $full
}

function Get-P3StreamIdentity([IO.FileStream]$Stream) {
    $info = [HomeGateway.P3.ByHandleFileInformation]::new()
    if (-not [HomeGateway.P3.NativeFileIdentity]::GetFileInformationByHandle($Stream.SafeFileHandle, [ref]$info)) {
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    return ('{0:x8}:{1:x8}{2:x8}' -f $info.VolumeSerialNumber, $info.FileIndexHigh, $info.FileIndexLow)
}

function Assert-P3RegularFile([string]$Path, [string]$Label) {
    $resolved = Resolve-P3FixedCleanPath -Path $Path -Label $Label
    if (-not [IO.File]::Exists($resolved)) { throw "$Label is missing" }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file"
    }
    $streams = @(Get-Item -LiteralPath $resolved -Stream * -ErrorAction Stop)
    $named = @($streams | Where-Object { $_.Stream -notin @(':$DATA', '::$DATA') })
    if ($named.Count -ne 0) { throw "$Label contains an alternate data stream" }
    return $resolved
}

function Read-P3BoundedStableBytes([string]$Path, [int]$MaximumBytes, [string]$Label) {
    $resolved = Assert-P3RegularFile -Path $Path -Label $Label
    $stream = [IO.File]::Open($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) { throw "$Label size differs" }
        $before = Get-P3StreamIdentity -Stream $stream
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw "$Label is truncated" }
            $offset += $read
        }
        $after = Get-P3StreamIdentity -Stream $stream
        if ($before -cne $after) { throw "$Label identity changed during read" }
        return $bytes
    }
    finally { $stream.Dispose() }
}

function Assert-P3ExactProperties([object]$Value, [string[]]$ExpectedProperties, [string]$Label) {
    if ($null -eq $Value -or $Value -is [Array]) { throw "$Label schema differs" }
    $actual = if ($Value -is [Collections.IDictionary]) { @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object) } else { @($Value.PSObject.Properties.Name | Sort-Object) }
    $expected = @($ExpectedProperties | Sort-Object)
    if (@(Compare-Object -ReferenceObject $expected -DifferenceObject $actual).Count -ne 0) {
        throw "$Label schema differs"
    }
}

function Open-P3BoundedStableJson([string]$Path, [int]$MaximumBytes, [string[]]$ExpectedProperties) {
    $bytes = Read-P3BoundedStableBytes -Path $Path -MaximumBytes $MaximumBytes -Label 'JSON file'
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    try { $text = $encoding.GetString($bytes) } catch { throw 'JSON file UTF-8 differs' }
    try { $value = ConvertFrom-Json -InputObject $text -ErrorAction Stop } catch { throw 'JSON file is malformed' }
    Assert-P3ExactProperties -Value $value -ExpectedProperties $ExpectedProperties -Label 'JSON file'
    return $value
}

function ConvertTo-P3CanonicalValue([object]$Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)) {
            $ordered[$key] = ConvertTo-P3CanonicalValue -Value $Value[$key]
        }
        return $ordered
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)) {
            $ordered[$property] = ConvertTo-P3CanonicalValue -Value $Value.$property
        }
        return $ordered
    }
    if ($Value -is [Array]) {
        $items = @()
        foreach ($item in $Value) { $items += ,(ConvertTo-P3CanonicalValue -Value $item) }
        return ,$items
    }
    return $Value
}

function ConvertTo-P3CanonicalJson([object]$Value) {
    $canonical = ConvertTo-P3CanonicalValue -Value $Value
    $text = ConvertTo-Json -InputObject $canonical -Depth 32 -Compress
    return [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function Get-P3ExactFileSHA256([string]$Path, [string]$Label) {
    return Get-P3SHA256Bytes -Bytes (Read-P3BoundedStableBytes -Path $Path -MaximumBytes 16777216 -Label $Label)
}

function Test-P3AcceptedPrerequisiteSshTrust([object]$Accepted, [object]$Trust) {
    Assert-P3ExactProperties $Accepted $script:P3PrerequisiteSshTrustProperties 'accepted prerequisite SSH trust'
    if ([string]$Accepted.schema -cne 'home-gateway/p3-prelive-prerequisite-ssh-trust/v1' -or
        [string]$Accepted.ssh_host -cne [string]$Trust.ssh_host -or [string]$Accepted.ssh_user -cne [string]$Trust.ssh_user -or
        -not [bool]$Accepted.no_write_scope -or [int]$Accepted.connect_timeout_seconds -ne 10 -or
        [int]$Accepted.command_timeout_seconds -ne 30 -or [int]$Accepted.maximum_output_bytes -ne 65536 -or
        [string]$Accepted.known_hosts_path -cne [string]$Trust.known_hosts_path -or
        [string]$Accepted.public_key_path -cne [string]$Trust.public_key_path -or
        [string]$Accepted.private_key_path -cne [string]$Trust.private_key_path -or
        [string]$Accepted.git_ssh_agent_path -cne [string]$Trust.git_ssh_agent_path -or
        [string]$Accepted.git_ssh_add_path -cne [string]$Trust.git_ssh_add_path -or
        [string]$Accepted.git_ssh_path -cne [string]$Trust.git_ssh_path -or
        [string]$Accepted.git_scp_path -cne [string]$Trust.git_scp_path -or
        [string]$Accepted.observer_payload_path -cne [string]$Trust.local_payload_path -or
        [string]$Accepted.observer_payload_sha256 -cne [string]$Trust.remote_payload_sha256 -or
        [string]$Accepted.observer_protocol_sha256 -cne [string]$Trust.protocol_sha256 -or
        [string]$Accepted.expected_ipv6_policy_sha256 -cne [string]$Trust.accepted_server_baseline.ipv6_policy_sha256 -or
        [string]$Accepted.public_key_fingerprint_sha256 -cne [string]$Trust.public_key_fingerprint_sha256) {
        throw 'accepted prerequisite SSH trust differs'
    }
    foreach ($pair in @(
            @('known_hosts_path','known_hosts_sha256','known-hosts'),@('git_ssh_agent_path','git_ssh_agent_sha256','Git ssh-agent'),
            @('git_ssh_add_path','git_ssh_add_sha256','Git ssh-add'),@('git_ssh_path','git_ssh_sha256','Git ssh'),
            @('git_scp_path','git_scp_sha256','Git scp'),@('public_key_path','public_key_sha256','public key'),
            @('observer_payload_path','observer_payload_sha256','observer payload'))) {
        $path = [string]$Accepted.PSObject.Properties[[string]$pair[0]].Value
        $expected = [string]$Accepted.PSObject.Properties[[string]$pair[1]].Value
        if ((Get-P3ExactFileSHA256 $path ([string]$pair[2])) -cne $expected) { throw 'accepted prerequisite external file differs' }
    }
    $authorities = @($Accepted.egress | ForEach-Object { [string]$_.authority_sha256 })
    if ($authorities.Count -ne 3 -or @(Compare-Object -ReferenceObject @($Trust.egress_authority_sha256 | Sort-Object) `
            -DifferenceObject @($authorities | Sort-Object)).Count -ne 0) { throw 'accepted prerequisite HTTPS authority differs' }
    return $Accepted
}

function Assert-P3ProtectedPrerequisiteReceiptState(
    [object]$Trust,
    [string]$ExpectedReceiptSHA256,
    [switch]$AllowConsumed
) {
    Assert-P3SHA256 $ExpectedReceiptSHA256 'expected prerequisite receipt'
    $receiptPath = Resolve-P3FixedCleanPath ([string]$Trust.prerequisite_receipt_path) 'prerequisite receipt'
    if ([IO.Path]::GetFileName($receiptPath) -cne 'prerequisite-receipt.json') { throw 'protected prerequisite receipt path differs' }
    $root = Split-Path -Parent $receiptPath
    $item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'protected prerequisite root differs' }
    $currentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $root -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $currentSID.Value) {
        throw 'protected prerequisite ACL differs'
    }
    $markerPath = Join-Path $root '.home-gateway-p3-prerequisite-owner.v1'
    $marker = [Text.Encoding]::UTF8.GetString((Read-P3BoundedStableBytes $markerPath 256 'prerequisite owner marker'))
    if ($marker -cne 'home-gateway/p3-prelive-prerequisite-owner/v1') { throw 'prerequisite owner marker differs' }
    $consumedPath = Join-Path $root 'prerequisite-receipt.consumed.json'
    if ([IO.File]::Exists($consumedPath) -and -not $AllowConsumed) { throw 'prerequisite receipt is already consumed' }
    $expectedNames = @('.home-gateway-p3-prerequisite-owner.v1','manifest.json','agent-manifest.json',
        'observation-batch.json','cloud-observation.json','prerequisite-receipt.json')
    if ($AllowConsumed) { $expectedNames += 'prerequisite-receipt.consumed.json' }
    $children = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    foreach ($child in $children) {
        if ($child.Name -notin $expectedNames -or $child.PSIsContainer -or
            ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'foreign prerequisite content is present' }
    }
    foreach ($name in $expectedNames) {
        if (-not [IO.File]::Exists((Join-Path $root $name))) { throw 'required prerequisite file is missing' }
    }
    if ((Get-P3ExactFileSHA256 $receiptPath 'prerequisite receipt') -cne $ExpectedReceiptSHA256) {
        throw 'prerequisite receipt hash differs'
    }
    $receipt = Open-P3BoundedStableJson $receiptPath 131072 $script:P3PrerequisiteReceiptProperties
    $manifest = Open-P3BoundedStableJson (Join-Path $root 'manifest.json') 65536 $script:P3PrerequisiteManifestProperties
    if ([string]$manifest.schema -cne 'home-gateway/p3-prelive-prerequisite-manifest/v1' -or
        [string]$manifest.manifest_sha256 -cne [string]$receipt.prerequisite_manifest_sha256 -or
        [string]$manifest.payload_sha256 -cne [string]$receipt.payload_sha256 -or
        [string]$manifest.protocol_sha256 -cne [string]$receipt.protocol_sha256 -or
        [string]$manifest.ssh_trust_sha256 -cne [string]$receipt.ssh_trust_sha256 -or
        (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $manifest.ssh_trust)) -cne [string]$manifest.ssh_trust_sha256) {
        throw 'protected prerequisite manifest differs'
    }
    foreach ($name in @('management_source_cidr_sha256','firewall_resource_sha256','droplet_resource_sha256',
            'inbound_union_sha256','outbound_union_sha256')) {
        if ([string]$manifest.$name -cne [string]$receipt.$name) { throw 'protected prerequisite manifest differs' }
    }
    if (@(Compare-Object @($manifest.egress_authority_sha256) @($receipt.egress_authority_sha256)).Count -ne 0 -or
        (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $manifest.ssh_trust)) -cne
        (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $Trust.accepted_prerequisite_ssh_trust))) {
        throw 'protected prerequisite manifest differs'
    }
    $agent = Open-P3BoundedStableJson (Join-Path $root 'agent-manifest.json') 65536 $script:P3PrerequisiteAgentManifestProperties
    if ([string]$agent.manifest_sha256 -cne [string]$manifest.manifest_sha256) { throw 'protected prerequisite agent manifest differs' }
    foreach ($pair in @(
            @('git_ssh_agent_path','git_ssh_agent_sha256'),@('git_ssh_add_path','git_ssh_add_sha256'),
            @('git_ssh_path','git_ssh_sha256'),@('git_scp_path','git_scp_sha256'))) {
        if ([string]$agent.($pair[0]) -cne [string]$manifest.ssh_trust.($pair[0]) -or
            [string]$agent.($pair[1]) -cne [string]$manifest.ssh_trust.($pair[1])) {
            throw 'protected prerequisite agent manifest differs'
        }
    }
    if ([string]$agent.public_key_path -cne [string]$manifest.ssh_trust.public_key_path -or
        [string]$agent.private_key_path -cne [string]$manifest.ssh_trust.private_key_path -or
        [string]$agent.public_key_fingerprint_sha256 -cne [string]$manifest.ssh_trust.public_key_fingerprint_sha256) {
        throw 'protected prerequisite agent manifest differs'
    }
    return [pscustomobject]@{ root=$root;receipt=$receipt;manifest=$manifest;consumed_path=$consumedPath }
}

function New-P3ManifestPlan([object]$Trust, [string]$RuntimeRoot) {
    $null = Resolve-P3FixedCleanPath -Path $RuntimeRoot -Label 'runtime root'
    Assert-P3ExactProperties -Value $Trust -ExpectedProperties $script:P3TrustProperties -Label 'trust input'
    if ([string]$Trust.schema -cne 'home-gateway/p3-prelive-trust-input/v1') { throw 'trust input schema differs' }
    if ([string]$Trust.ssh_user -cne 'homegateway') { throw 'trust SSH user differs' }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse([string]$Trust.ssh_host, [ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'trust SSH host must be one IPv4 address'
    }
    foreach ($name in @('public_key_fingerprint_sha256', 'management_source_cidr_sha256', 'remote_payload_sha256', 'protocol_sha256',
            'accepted_cloud_firewall_sha256', 'accepted_prerequisite_cloud_firewall_sha256', 'expected_prerequisite_receipt_sha256')) {
        Assert-P3SHA256 -Value ([string]$Trust.$name) -Label $name
    }
    $baseline = $Trust.accepted_server_baseline
    $baselineSHA256 = Get-P3ServerBaselineSHA256 -Baseline $baseline
    Assert-P3ExactProperties -Value $Trust.rollback_paths -ExpectedProperties $script:P3RollbackPathProperties -Label 'rollback paths'
    $rollbackRoots = @{
        persistent_config_path = '/opt/amnezia/awg/'
        metadata_path = '/opt/amnezia/awg/'
        temporary_path = '/run/home-gateway-p3-peer-guard/'
        syncconf_path = '/run/home-gateway-p3-peer-guard/'
    }
    foreach ($name in $script:P3RollbackPathProperties) {
        $value = [string]$Trust.rollback_paths.$name
        if ([string]::IsNullOrWhiteSpace($value) -or -not $value.StartsWith($rollbackRoots[$name], [StringComparison]::Ordinal) -or
            $value.Contains('..') -or $value.Contains('\') -or $value.EndsWith('/', [StringComparison]::Ordinal)) { throw 'rollback paths differ' }
    }
    $egress = @($Trust.egress_authority_sha256)
    if ($egress.Count -ne 3 -or @($egress | Select-Object -Unique).Count -ne 3) { throw 'three distinct egress authorities are required' }
    foreach ($hash in $egress) { Assert-P3SHA256 -Value ([string]$hash) -Label 'egress authority' }
    $null = Test-P3AcceptedPrerequisiteSshTrust $Trust.accepted_prerequisite_ssh_trust $Trust
    foreach ($pathName in @('known_hosts_path', 'public_key_path', 'private_key_path', 'git_ssh_agent_path', 'git_ssh_add_path', 'git_ssh_path',
            'git_scp_path', 'local_payload_path', 'prerequisite_receipt_path')) {
        $null = Resolve-P3FixedCleanPath -Path ([string]$Trust.$pathName) -Label $pathName
    }
    $trustBytes = ConvertTo-P3CanonicalJson -Value $Trust
    $localPayloadSHA256 = Get-P3ExactFileSHA256 -Path ([string]$Trust.local_payload_path) -Label 'local payload'
    if ([string]$Trust.remote_payload_sha256 -cne $localPayloadSHA256 -or [string]$baseline.payload_sha256 -cne $localPayloadSHA256 -or
        [string]$baseline.protocol_sha256 -cne [string]$Trust.protocol_sha256) { throw 'accepted server payload or protocol differs' }
    $knownHostsSHA256 = Get-P3ExactFileSHA256 -Path ([string]$Trust.known_hosts_path) -Label 'known-hosts'
    $gitSCPHash = Get-P3ExactFileSHA256 -Path ([string]$Trust.git_scp_path) -Label 'Git scp'
    $gitAddHash = Get-P3ExactFileSHA256 -Path ([string]$Trust.git_ssh_add_path) -Label 'Git ssh-add'
    $gitAgentHash = Get-P3ExactFileSHA256 -Path ([string]$Trust.git_ssh_agent_path) -Label 'Git ssh-agent'
    $gitSshHash = Get-P3ExactFileSHA256 -Path ([string]$Trust.git_ssh_path) -Label 'Git ssh'
    $acceptedPrerequisiteSshTrustSHA256 = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $Trust.accepted_prerequisite_ssh_trust)
    $prerequisitePath = [string]$Trust.prerequisite_receipt_path
    $prerequisiteSHA256 = Get-P3ExactFileSHA256 -Path $prerequisitePath -Label 'prerequisite receipt'
    if ($prerequisiteSHA256 -cne [string]$Trust.expected_prerequisite_receipt_sha256) { throw 'prerequisite receipt hash differs' }
    $prerequisite = Open-P3BoundedStableJson -Path $prerequisitePath -MaximumBytes 131072 -ExpectedProperties $script:P3PrerequisiteReceiptProperties
    $null = Test-P3AcceptedPrerequisiteReceipt -Receipt $prerequisite -Trust $Trust `
        -ExpectedSshTrustSHA256 $acceptedPrerequisiteSshTrustSHA256 -NowUtc ([DateTime]::UtcNow)
    $null = Assert-P3ProtectedPrerequisiteReceiptState $Trust $prerequisiteSHA256
    $manifest = [pscustomobject][ordered]@{
        accepted_cloud_firewall_sha256 = [string]$Trust.accepted_cloud_firewall_sha256
        accepted_prerequisite_cloud_firewall_sha256 = [string]$Trust.accepted_prerequisite_cloud_firewall_sha256
        accepted_prerequisite_receipt_sha256 = $prerequisiteSHA256
        accepted_prerequisite_ssh_trust_sha256 = $acceptedPrerequisiteSshTrustSHA256
        accepted_server_baseline_sha256 = $baselineSHA256
        git_scp_sha256 = $gitSCPHash
        git_ssh_add_sha256 = $gitAddHash
        git_ssh_agent_sha256 = $gitAgentHash
        git_ssh_sha256 = $gitSshHash
        known_hosts_sha256 = $knownHostsSHA256
        local_payload_sha256 = $localPayloadSHA256
        management_source_cidr_sha256 = [string]$Trust.management_source_cidr_sha256
        protocol_sha256 = [string]$Trust.protocol_sha256
        public_key_fingerprint_sha256 = [string]$Trust.public_key_fingerprint_sha256
        remote_payload_sha256 = [string]$Trust.remote_payload_sha256
        schema = 'home-gateway/p3-prelive-trust-manifest/v1'
        trust_sha256 = Get-P3SHA256Bytes -Bytes $trustBytes
    }
    Assert-P3ExactProperties -Value $manifest -ExpectedProperties $script:P3ManifestProperties -Label 'manifest'
    $manifestBytes = ConvertTo-P3CanonicalJson -Value $manifest
    $manifestSHA256 = Get-P3SHA256Bytes -Bytes $manifestBytes
    $challengeSeed = Get-P3SHA256Text -Text ($manifestSHA256 + [char]0 + $RuntimeRoot.ToLowerInvariant())
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-runtime-plan/v1'
        manifest = $manifest
        manifest_sha256 = $manifestSHA256
        confirmation_challenge = 'P3-PRELIVE-RUNTIME-' + $challengeSeed.Substring(0, 16).ToUpperInvariant()
    }
}

function New-P3RuntimeAcl {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($current)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($system, $administrators, $current)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Assert-P3ProtectedRuntimeRoot([string]$Path, [Security.Principal.SecurityIdentifier]$CurrentSID) {
    $resolved = Resolve-P3FixedCleanPath -Path $Path -Label 'runtime root'
    if (-not [IO.Directory]::Exists($resolved)) { throw 'protected runtime root is missing' }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'protected runtime root differs' }
    $acl = Get-Acl -LiteralPath $resolved -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { throw 'runtime ACL inherits access' }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if ($null -eq $owner -or $owner.Value -cne $CurrentSID.Value) { throw 'runtime ACL owner differs' }
    $expectedSids = @('S-1-5-18', 'S-1-5-32-544', $CurrentSID.Value)
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 3) { throw 'runtime ACL differs' }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IdentityReference.Value -notin $expectedSids -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'runtime ACL differs' }
    }
    $marker = Join-Path $resolved $script:P3RuntimeMarkerName
    $bytes = Read-P3BoundedStableBytes -Path $marker -MaximumBytes 128 -Label 'runtime owner marker'
    if ([Text.Encoding]::UTF8.GetString($bytes) -cne $script:P3RuntimeMarkerText) { throw 'runtime owner marker differs' }
    return $item
}

function Install-P3ExactRuntimeFile([byte[]]$Bytes, [string]$Destination, [string]$ExpectedSHA256) {
    Assert-P3SHA256 -Value $ExpectedSHA256 -Label 'runtime file hash'
    if ((Get-P3SHA256Bytes -Bytes $Bytes) -cne $ExpectedSHA256) { throw 'runtime file bytes differ from expected hash' }
    if ([IO.File]::Exists($Destination) -or [IO.Directory]::Exists($Destination)) { throw 'runtime file already exists' }
    $temporary = $Destination + '.next-' + [guid]::NewGuid().ToString('N')
    try {
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ((Get-P3ExactFileSHA256 -Path $temporary -Label 'staged runtime file') -cne $ExpectedSHA256) { throw 'staged runtime file hash differs' }
        [IO.File]::Move($temporary, $Destination)
        return [pscustomobject]@{ sha256 = $ExpectedSHA256; length = $Bytes.Length }
    }
    finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}

function Invoke-P3RuntimePrepare([object]$Trust, [string]$RuntimeRoot, [string]$ExpectedManifestSHA256, [string]$Confirmation) {
    Assert-P3SHA256 -Value $ExpectedManifestSHA256 -Label 'expected manifest'
    $plan = New-P3ManifestPlan -Trust $Trust -RuntimeRoot $RuntimeRoot
    if ($plan.manifest_sha256 -cne $ExpectedManifestSHA256 -or $Confirmation -cne $plan.confirmation_challenge -or
        $Confirmation -cnotmatch '^P3-PRELIVE-RUNTIME-[0-9A-F]{16}$') { throw 'runtime approval differs' }
    $prerequisite = Assert-P3ProtectedPrerequisiteReceiptState $Trust ([string]$Trust.expected_prerequisite_receipt_sha256)
    $consumption = [pscustomobject][ordered]@{
        prerequisite_receipt_sha256=[string]$Trust.expected_prerequisite_receipt_sha256
        runtime_manifest_sha256=$plan.manifest_sha256
        schema='home-gateway/p3-prelive-prerequisite-consumption/v1'
    }
    $consumptionBytes = ConvertTo-P3CanonicalJson $consumption
    $consumptionSHA256 = Get-P3SHA256Bytes $consumptionBytes
    try {
        $null = Install-P3ExactRuntimeFile $consumptionBytes $prerequisite.consumed_path $consumptionSHA256
    }
    catch { throw 'prerequisite receipt is already consumed' }
    $consumed = $true
    $resolved = Resolve-P3FixedCleanPath -Path $RuntimeRoot -Label 'runtime root'
    try {
        $reopenedConsumption = Open-P3BoundedStableJson $prerequisite.consumed_path 4096 $script:P3PrerequisiteConsumptionProperties
        if ((Get-P3ExactFileSHA256 $prerequisite.consumed_path 'prerequisite consumption') -cne $consumptionSHA256 -or
            (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $reopenedConsumption)) -cne $consumptionSHA256) {
            throw 'prerequisite consumption differs'
        }
        $null = Assert-P3ProtectedPrerequisiteReceiptState $Trust ([string]$Trust.expected_prerequisite_receipt_sha256) -AllowConsumed
        if ([IO.File]::Exists($resolved) -or [IO.Directory]::Exists($resolved)) { throw 'runtime root already exists' }
        $parent = Split-Path -Parent $resolved
        if (-not [IO.Directory]::Exists($parent)) { throw 'runtime parent is missing' }
        $item = [IO.Directory]::CreateDirectory($resolved)
        Set-Acl -LiteralPath $resolved -AclObject (New-P3RuntimeAcl) -ErrorAction Stop
        $markerBytes = [Text.UTF8Encoding]::new($false).GetBytes($script:P3RuntimeMarkerText)
        $null = Install-P3ExactRuntimeFile -Bytes $markerBytes -Destination (Join-Path $resolved $script:P3RuntimeMarkerName) -ExpectedSHA256 (Get-P3SHA256Bytes -Bytes $markerBytes)
        $trustBytes = ConvertTo-P3CanonicalJson -Value $Trust
        $null = Install-P3ExactRuntimeFile -Bytes $trustBytes -Destination (Join-Path $resolved 'trust.json') -ExpectedSHA256 $plan.manifest.trust_sha256
        $manifestBytes = ConvertTo-P3CanonicalJson -Value $plan.manifest
        $null = Install-P3ExactRuntimeFile -Bytes $manifestBytes -Destination (Join-Path $resolved 'manifest.json') -ExpectedSHA256 $plan.manifest_sha256
        $null = Invoke-P3RuntimeValidate -RuntimeRoot $resolved -ExpectedManifestSHA256 $plan.manifest_sha256
    }
    catch {
        if ([IO.Directory]::Exists($resolved)) { [IO.Directory]::Delete($resolved, $true) }
        if ($consumed -and [IO.File]::Exists($prerequisite.consumed_path) -and
            (Get-P3ExactFileSHA256 $prerequisite.consumed_path 'prerequisite consumption') -ceq $consumptionSHA256) {
            [IO.File]::Delete($prerequisite.consumed_path)
        }
        throw
    }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-runtime-receipt/v1'
        manifest_sha256 = $plan.manifest_sha256
        protected_root = $true
        live_mutation_performed = $false
    }
}

function Invoke-P3RuntimeValidate([string]$RuntimeRoot, [string]$ExpectedManifestSHA256) {
    Assert-P3SHA256 -Value $ExpectedManifestSHA256 -Label 'expected manifest'
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $null = Assert-P3ProtectedRuntimeRoot -Path $RuntimeRoot -CurrentSID $sid
    $children = @(Get-ChildItem -LiteralPath $RuntimeRoot -Force)
    foreach ($child in $children) {
        if ($child.Name -notin $script:P3RuntimeFiles) { throw 'foreign runtime content is present' }
        if ($child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'foreign runtime content is present' }
    }
    foreach ($required in @($script:P3RuntimeMarkerName, 'trust.json', 'manifest.json')) {
        if (-not [IO.File]::Exists((Join-Path $RuntimeRoot $required))) { throw 'required runtime file is missing' }
    }
    $manifestPath = Join-Path $RuntimeRoot 'manifest.json'
    $manifest = Open-P3BoundedStableJson -Path $manifestPath -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
    if ((Get-P3ExactFileSHA256 -Path $manifestPath -Label 'manifest') -cne $ExpectedManifestSHA256) { throw 'manifest hash differs' }
    $trustPath = Join-Path $RuntimeRoot 'trust.json'
    if ((Get-P3ExactFileSHA256 -Path $trustPath -Label 'trust') -cne [string]$manifest.trust_sha256) { throw 'trust hash differs' }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-runtime-receipt/v1'
        manifest_sha256 = $ExpectedManifestSHA256
        protected_root = $true
        live_mutation_performed = $false
    }
}

function Get-P3CloudFirewallIdentitySHA256([object]$Observation) {
    $properties = @('droplet_association_count', 'extra_inbound_rule_count', 'management_source_cidr_sha256', 'observed_at_utc', 'schema', 'tcp_22_management_source_count', 'udp_38556_all_ipv4_count', 'udp_ipv6_count')
    Assert-P3ExactProperties -Value $Observation -ExpectedProperties $properties -Label 'Cloud Firewall observation'
    Assert-P3SHA256 -Value ([string]$Observation.management_source_cidr_sha256) -Label 'management source CIDR'
    if ([string]$Observation.schema -cne 'home-gateway/p3-prelive-cloud-firewall-observation/v1') { throw 'Cloud Firewall schema differs' }
    $identity = [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-cloud-firewall-identity/v1'
        droplet_association_count = [int]$Observation.droplet_association_count
        tcp_22_management_source_count = [int]$Observation.tcp_22_management_source_count
        management_source_cidr_sha256 = [string]$Observation.management_source_cidr_sha256
        udp_38556_all_ipv4_count = [int]$Observation.udp_38556_all_ipv4_count
        udp_ipv6_count = [int]$Observation.udp_ipv6_count
        extra_inbound_rule_count = [int]$Observation.extra_inbound_rule_count
    }
    return Get-P3SHA256Bytes -Bytes (ConvertTo-P3CanonicalJson -Value $identity)
}

function New-P3CloudFirewallReceipt(
    [object]$Observation,
    [string]$ExpectedIdentitySHA256,
    [string]$ExpectedManagementSourceCIDRSHA256,
    [DateTime]$NowUtc
) {
    Assert-P3SHA256 -Value $ExpectedIdentitySHA256 -Label 'Cloud Firewall identity'
    Assert-P3SHA256 -Value $ExpectedManagementSourceCIDRSHA256 -Label 'expected management source CIDR'
    $actualIdentity = Get-P3CloudFirewallIdentitySHA256 -Observation $Observation
    if ($actualIdentity -cne $ExpectedIdentitySHA256) { throw 'Cloud Firewall identity differs' }
    if ([string]$Observation.management_source_cidr_sha256 -cne $ExpectedManagementSourceCIDRSHA256) { throw 'Cloud Firewall management source differs' }
    if ([int]$Observation.droplet_association_count -ne 1) { throw 'Cloud Firewall Droplet association differs' }
    if ([int]$Observation.tcp_22_management_source_count -ne 1) { throw 'Cloud Firewall management SSH union differs' }
    if ([int]$Observation.udp_38556_all_ipv4_count -ne 1 -or [int]$Observation.udp_ipv6_count -ne 0) { throw 'Cloud Firewall UDP union differs' }
    if ([int]$Observation.extra_inbound_rule_count -ne 0) { throw 'Cloud Firewall contains an extra inbound rule' }
    $observed = [DateTime]::Parse([string]$Observation.observed_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $age = ($NowUtc.ToUniversalTime() - $observed).TotalSeconds
    if ($age -lt 0 -or $age -gt 900) { throw 'Cloud Firewall observation is stale' }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-cloud-firewall-receipt/v1'
        cloud_firewall_identity_sha256 = $actualIdentity
        management_source_cidr_sha256 = [string]$Observation.management_source_cidr_sha256
        droplet_association_count = 1
        inbound_rule_count = 2
        observed_at_utc = $observed.ToString('o')
        owner_observed = $true
        server_confirmed = $false
        live_mutation_performed = $false
    }
}

function New-P3EgressReceipt(
    [string[]]$ExpectedAuthoritySHA256,
    [string]$ExpectedManagementSourceCIDRSHA256,
    [DateTime]$NowUtc,
    [scriptblock]$HttpsRunner
) {
    Assert-P3SHA256 -Value $ExpectedManagementSourceCIDRSHA256 -Label 'expected egress source'
    $expected = @($ExpectedAuthoritySHA256)
    if ($expected.Count -ne 3 -or @($expected | Select-Object -Unique).Count -ne 3) { throw 'three distinct egress authorities are required' }
    foreach ($hash in $expected) { Assert-P3SHA256 -Value $hash -Label 'egress authority' }
    $observations = @()
    foreach ($authority in $expected) {
        $item = & $HttpsRunner $authority
        Assert-P3ExactProperties -Value $item -ExpectedProperties $script:P3EgressObservationProperties -Label 'egress observation'
        if ([string]$item.authority_sha256 -cne $authority) { throw 'egress authority differs' }
        Assert-P3SHA256 -Value ([string]$item.source_cidr_sha256) -Label 'egress source'
        if ([string]$item.source_cidr_sha256 -cne $ExpectedManagementSourceCIDRSHA256) { throw 'egress source differs' }
        try { $observed = [DateTime]::Parse([string]$item.observed_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
        catch { throw 'egress observation timestamp differs' }
        $age = ($NowUtc.ToUniversalTime() - $observed).TotalSeconds
        if ($age -lt -1 -or $age -gt 120) { throw 'egress observation is stale' }
        $observations += [pscustomobject][ordered]@{ authority_sha256 = $authority; source_cidr_sha256 = [string]$item.source_cidr_sha256; observed_at_utc = $observed.ToString('o') }
    }
    $receipt = [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-egress-receipt/v1'
        management_source_cidr_sha256 = $ExpectedManagementSourceCIDRSHA256
        observations = @($observations)
        observed_at_utc = $NowUtc.ToUniversalTime().ToString('o')
        live_mutation_performed = $false
    }
    return Test-P3ExactEgressReceipt -Receipt $receipt -ExpectedAuthoritySHA256 $expected `
        -ExpectedManagementSourceCIDRSHA256 $ExpectedManagementSourceCIDRSHA256 -NowUtc $NowUtc
}

function Test-P3ExactJsonInteger([object]$Value) {
    return $Value -is [sbyte] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]
}

function Get-P3ServerBaselineSHA256([object]$Baseline) {
    Assert-P3ExactProperties -Value $Baseline -ExpectedProperties $script:P3ServerBaselineProperties -Label 'accepted server baseline'
    foreach ($name in @(
        'container_identity_sha256', 'firewall_identity_sha256', 'host_policy_sha256', 'image_identity_sha256',
        'ipv6_policy_sha256', 'listener_identity_sha256', 'live_peer_set_sha256', 'metadata_peer_set_sha256',
        'metadata_sha256', 'payload_sha256', 'persistent_config_sha256', 'persistent_peer_set_sha256',
        'protocol_sha256', 'runtime_identity_sha256', 'temporary_state_sha256', 'udp_publication_sha256'
    )) { Assert-P3SHA256 -Value ([string]$Baseline.$name) -Label "accepted server $name" }
    foreach ($name in @('container_count', 'container_restart_count', 'public_listener_class_count', 'temporary_leftover_count', 'candidate_leftover_count', 'atomic_leftover_count', 'udp_publication_count')) {
        if (-not (Test-P3ExactJsonInteger $Baseline.$name)) { throw "accepted server $name type differs" }
    }
    foreach ($name in @('container_running', 'host_policy_loaded', 'ipv6_non_mutation')) {
        if ($Baseline.$name -isnot [bool]) { throw "accepted server $name type differs" }
    }
    if ([int64]$Baseline.container_count -ne 1 -or -not $Baseline.container_running -or
        [int64]$Baseline.container_restart_count -lt 0 -or [int64]$Baseline.udp_publication_count -ne 1 -or
        [int64]$Baseline.public_listener_class_count -lt 1 -or -not $Baseline.host_policy_loaded -or
        -not $Baseline.ipv6_non_mutation -or [int64]$Baseline.candidate_leftover_count -ne 0 -or
        [int64]$Baseline.temporary_leftover_count -ne 0 -or [int64]$Baseline.atomic_leftover_count -ne 0) {
        throw 'accepted server baseline facts differ'
    }
    $peers = @($Baseline.peer_fingerprint_sha256)
    if ($Baseline.peer_fingerprint_sha256 -isnot [Array] -or $peers.Count -gt 1024 -or @($peers | Select-Object -Unique).Count -ne $peers.Count) {
        throw 'accepted server peer count differs'
    }
    foreach ($peer in $peers) { Assert-P3SHA256 -Value ([string]$peer) -Label 'accepted server peer fingerprint' }
    $sortedPeers = @($peers | Sort-Object -CaseSensitive)
    $peerSetHash = Get-P3SHA256Bytes -Bytes (ConvertTo-P3CanonicalJson -Value $sortedPeers)
    if ([string]$Baseline.persistent_peer_set_sha256 -cne $peerSetHash -or
        [string]$Baseline.live_peer_set_sha256 -cne $peerSetHash -or
        [string]$Baseline.metadata_peer_set_sha256 -cne $peerSetHash) { throw 'accepted server peer set differs' }
    $canonical = [ordered]@{}
    foreach ($name in $script:P3ServerBaselineProperties) {
        if ($name -ceq 'peer_fingerprint_sha256') { $canonical[$name] = [object[]]$sortedPeers }
        else { $canonical[$name] = $Baseline.$name }
    }
    return Get-P3SHA256Bytes -Bytes (ConvertTo-P3CanonicalJson -Value $canonical)
}

function Test-P3AcceptedPrerequisiteReceipt(
    [object]$Receipt,
    [object]$Trust,
    [string]$ExpectedSshTrustSHA256,
    [DateTime]$NowUtc
) {
    Assert-P3ExactProperties -Value $Receipt -ExpectedProperties $script:P3PrerequisiteReceiptProperties -Label 'prerequisite receipt'
    foreach ($name in @('prerequisite_manifest_sha256', 'server_baseline_sha256', 'cloud_firewall_identity_sha256',
            'firewall_resource_sha256', 'droplet_resource_sha256', 'inbound_union_sha256', 'outbound_union_sha256',
            'management_source_cidr_sha256', 'egress_observation_sha256', 'ssh_trust_sha256', 'payload_sha256', 'protocol_sha256')) {
        Assert-P3SHA256 ([string]$Receipt.$name) $name
    }
    if ([string]$Receipt.schema -cne 'home-gateway/p3-prelive-prerequisite-receipt/v1' -or
        -not [bool]$Receipt.owner_observed -or -not [bool]$Receipt.server_confirmed -or
        [bool]$Receipt.live_mutation_performed -or [bool]$Receipt.raw_identity_exposed) { throw 'prerequisite receipt provenance differs' }
    $observed = Get-P3EgressUtc $Receipt.observed_at_utc 'prerequisite receipt'
    $now = $NowUtc.ToUniversalTime()
    if ($observed -gt $now.AddSeconds(5) -or $observed -lt $now.AddMinutes(-10)) { throw 'prerequisite receipt freshness differs' }
    $baselineSHA256 = Get-P3ServerBaselineSHA256 $Receipt.server_baseline
    Assert-P3SHA256 ([string]$Receipt.nonce_sha256) 'prerequisite receipt nonce'
    if ($baselineSHA256 -cne [string]$Receipt.server_baseline_sha256 -or
        $baselineSHA256 -cne (Get-P3ServerBaselineSHA256 $Trust.accepted_server_baseline) -or
        [string]$Receipt.payload_sha256 -cne [string]$Trust.remote_payload_sha256 -or
        [string]$Receipt.protocol_sha256 -cne [string]$Trust.protocol_sha256 -or
        [string]$Receipt.management_source_cidr_sha256 -cne [string]$Trust.management_source_cidr_sha256 -or
        [string]$Receipt.cloud_firewall_identity_sha256 -cne [string]$Trust.accepted_prerequisite_cloud_firewall_sha256 -or
        [string]$Receipt.ssh_trust_sha256 -cne $ExpectedSshTrustSHA256 -or
        (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $Receipt.ssh_trust)) -cne $ExpectedSshTrustSHA256 -or
        (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $Trust.accepted_prerequisite_ssh_trust)) -cne $ExpectedSshTrustSHA256) {
        throw 'prerequisite receipt binding differs'
    }
    $expectedAuthorities = @($Trust.egress_authority_sha256)
    $actualAuthorities = @($Receipt.egress_authority_sha256)
    if ($actualAuthorities.Count -ne 3 -or @(Compare-Object -ReferenceObject $expectedAuthorities -DifferenceObject $actualAuthorities).Count -ne 0) {
        throw 'prerequisite receipt authority differs'
    }
    return $Receipt
}

function Get-P3EgressUtc([object]$Value, [string]$Label) {
    if ($Value -is [DateTime]) {
        $date = [DateTime]$Value
        if ($date.Kind -eq [DateTimeKind]::Unspecified) { $date = [DateTime]::SpecifyKind($date, [DateTimeKind]::Utc) }
        return $date.ToUniversalTime()
    }
    try {
        return [DateTime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    } catch { throw "$Label timestamp differs" }
}

function Test-P3ExactEgressReceipt(
    [object]$Receipt,
    [string[]]$ExpectedAuthoritySHA256,
    [string]$ExpectedManagementSourceCIDRSHA256,
    [DateTime]$NowUtc
) {
    Assert-P3ExactProperties -Value $Receipt -ExpectedProperties $script:P3EgressReceiptProperties -Label 'egress receipt'
    Assert-P3SHA256 -Value $ExpectedManagementSourceCIDRSHA256 -Label 'expected egress source'
    $expected = @($ExpectedAuthoritySHA256)
    if ($expected.Count -ne 3 -or @($expected | Select-Object -Unique).Count -ne 3) { throw 'egress authority set differs' }
    foreach ($authority in $expected) { Assert-P3SHA256 -Value $authority -Label 'egress authority' }
    if ([string]$Receipt.schema -cne 'home-gateway/p3-prelive-egress-receipt/v1' -or
        [string]$Receipt.management_source_cidr_sha256 -cne $ExpectedManagementSourceCIDRSHA256 -or
        [bool]$Receipt.live_mutation_performed) { throw 'egress receipt differs' }
    $clock = $NowUtc.ToUniversalTime()
    $receiptAge = ($clock - (Get-P3EgressUtc -Value $Receipt.observed_at_utc -Label 'egress receipt')).TotalSeconds
    if ($receiptAge -lt -1 -or $receiptAge -gt 120) { throw 'egress receipt is stale' }
    $observations = @($Receipt.observations)
    if ($observations.Count -ne 3) { throw 'egress observation count differs' }
    $observedAuthorities = @()
    foreach ($observation in $observations) {
        Assert-P3ExactProperties -Value $observation -ExpectedProperties $script:P3EgressObservationProperties -Label 'egress observation'
        $authority = [string]$observation.authority_sha256
        $source = [string]$observation.source_cidr_sha256
        Assert-P3SHA256 -Value $authority -Label 'egress observation authority'
        Assert-P3SHA256 -Value $source -Label 'egress observation source'
        if ($authority -notin $expected -or $source -cne $ExpectedManagementSourceCIDRSHA256) { throw 'egress observation identity differs' }
        $age = ($clock - (Get-P3EgressUtc -Value $observation.observed_at_utc -Label 'egress observation')).TotalSeconds
        if ($age -lt -1 -or $age -gt 120) { throw 'egress observation is stale' }
        $observedAuthorities += $authority
    }
    if (@($observedAuthorities | Select-Object -Unique).Count -ne 3) { throw 'egress observation authority set differs' }
    return $Receipt
}

function Get-P3AdapterClass([string]$InterfaceDescription) {
    if ([string]::IsNullOrWhiteSpace($InterfaceDescription)) { throw 'adapter description is empty' }
    $redshield = $InterfaceDescription -match '(?i)redshield'
    $cisco = $InterfaceDescription -match '(?i)cisco|anyconnect|secure\s+client'
    $selfhosted = $InterfaceDescription -match '(?i)amnezia|wintun|wireguard'
    if (($redshield -and $cisco) -or ($cisco -and $selfhosted)) { throw 'adapter classification is ambiguous' }
    if ($redshield) { return 'redshield' }
    if ($cisco) { return 'cisco' }
    if ($selfhosted) { return 'selfhosted' }
    return 'other'
}

function New-P3LocalBaselineReceipt([string]$ProtectedProfilePath, [DateTime]$NowUtc, [scriptblock]$AdapterRunner) {
    $profile = Resolve-P3FixedCleanPath -Path $ProtectedProfilePath -Label 'protected profile'
    $adapters = @(& $AdapterRunner)
    $classes = @($adapters | ForEach-Object {
        $description = if ($_.PSObject.Properties.Name -contains 'InterfaceDescription') { [string]$_.InterfaceDescription } else { [string]$_.Class }
        Get-P3AdapterClass -InterfaceDescription $description
    })
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-local-baseline-receipt/v1'
        protected_profile_absent = -not ([IO.File]::Exists($profile) -or [IO.Directory]::Exists($profile))
        selfhosted_adapter_count = @($classes | Where-Object { $_ -ceq 'selfhosted' }).Count
        redshield_class_count = @($classes | Where-Object { $_ -ceq 'redshield' }).Count
        cisco_class_count = @($classes | Where-Object { $_ -ceq 'cisco' }).Count
        adapter_class_set_sha256 = Get-P3SHA256Text -Text (($classes | Sort-Object -CaseSensitive) -join "`n")
        observed_at_utc = $NowUtc.ToUniversalTime().ToString('o')
        live_mutation_performed = $false
    }
}

function New-P3RuntimeCleanupPlan([string]$RuntimeRoot, [string]$ExpectedManifestSHA256) {
    $null = Invoke-P3RuntimeValidate -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256
    $identity = [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-runtime-cleanup-plan/v1'
        manifest_sha256 = $ExpectedManifestSHA256
        runtime_root_sha256 = Get-P3SHA256Text -Text ((Resolve-P3FixedCleanPath -Path $RuntimeRoot -Label 'runtime root').ToLowerInvariant())
        scope = 'marker-owned-child-only'
    }
    $planHash = Get-P3SHA256Bytes -Bytes (ConvertTo-P3CanonicalJson -Value $identity)
    return [pscustomobject][ordered]@{
        schema = $identity.schema
        manifest_sha256 = $identity.manifest_sha256
        runtime_root_sha256 = $identity.runtime_root_sha256
        scope = $identity.scope
        cleanup_plan_sha256 = $planHash
        confirmation_challenge = 'P3-PRELIVE-CLEANUP-' + $planHash.Substring(0, 16).ToUpperInvariant()
    }
}

function Invoke-P3RuntimeCleanup([string]$RuntimeRoot, [object]$CleanupPlan, [string]$ExpectedPlanSHA256, [string]$Confirmation) {
    Assert-P3SHA256 -Value $ExpectedPlanSHA256 -Label 'cleanup plan'
    $current = New-P3RuntimeCleanupPlan -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 ([string]$CleanupPlan.manifest_sha256)
    if ($current.cleanup_plan_sha256 -cne $ExpectedPlanSHA256 -or $CleanupPlan.cleanup_plan_sha256 -cne $ExpectedPlanSHA256 -or
        $Confirmation -cne $current.confirmation_challenge -or $Confirmation -cnotmatch '^P3-PRELIVE-CLEANUP-[0-9A-F]{16}$') {
        throw 'runtime cleanup approval differs'
    }
    $resolved = Resolve-P3FixedCleanPath -Path $RuntimeRoot -Label 'runtime root'
    [IO.Directory]::Delete($resolved, $true)
    return [pscustomobject]@{ schema = 'home-gateway/p3-prelive-runtime-cleanup-receipt/v1'; removed = $true; live_mutation_performed = $false }
}

function Write-P3RuntimeJson([string]$RuntimeRoot, [string]$Name, [object]$Value) {
    $path = Join-Path $RuntimeRoot $Name
    if ([IO.File]::Exists($path)) { throw 'runtime receipt already exists' }
    $bytes = ConvertTo-P3CanonicalJson -Value $Value
    $null = Install-P3ExactRuntimeFile -Bytes $bytes -Destination $path -ExpectedSHA256 (Get-P3SHA256Bytes -Bytes $bytes)
}

if (-not [string]::IsNullOrEmpty($Action)) {
    $inputText = [Console]::In.ReadToEnd()
    switch ($Action) {
        'PreparePlan' {
            $trust = ConvertFrom-Json -InputObject $inputText -ErrorAction Stop
            New-P3ManifestPlan -Trust $trust -RuntimeRoot $RuntimeRoot | ConvertTo-Json -Depth 32 -Compress
        }
        'Prepare' {
            $trust = ConvertFrom-Json -InputObject $inputText -ErrorAction Stop
            Invoke-P3RuntimePrepare -Trust $trust -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256 -Confirmation $Confirmation | ConvertTo-Json -Compress
        }
        'Validate' {
            Invoke-P3RuntimeValidate -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256 | ConvertTo-Json -Compress
        }
        'RecordCloudFirewall' {
            $runtime = Invoke-P3RuntimeValidate -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256
            $manifest = Open-P3BoundedStableJson -Path (Join-Path $RuntimeRoot 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
            $observation = ConvertFrom-Json -InputObject $inputText -ErrorAction Stop
            $receipt = New-P3CloudFirewallReceipt -Observation $observation -ExpectedIdentitySHA256 $manifest.accepted_cloud_firewall_sha256 `
                -ExpectedManagementSourceCIDRSHA256 $manifest.management_source_cidr_sha256 -NowUtc ([DateTime]::UtcNow)
            Write-P3RuntimeJson -RuntimeRoot $RuntimeRoot -Name 'cloud-firewall-receipt.json' -Value $receipt
            $receipt | ConvertTo-Json -Compress
        }
        'RecordEgress' {
            $null = Invoke-P3RuntimeValidate -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256
            $manifest = Open-P3BoundedStableJson -Path (Join-Path $RuntimeRoot 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
            $trust = Open-P3BoundedStableJson -Path (Join-Path $RuntimeRoot 'trust.json') -MaximumBytes 65536 -ExpectedProperties $script:P3TrustProperties
            if (@($EgressEndpoint).Count -ne 3) { throw 'three egress endpoints are required' }
            $endpointByHash = @{}
            foreach ($endpoint in $EgressEndpoint) {
                $uri = [Uri]$endpoint
                if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https') { throw 'egress endpoint must use HTTPS' }
                $endpointByHash[(Get-P3SHA256Text $uri.Authority.ToLowerInvariant())] = $uri
            }
            $receipt = New-P3EgressReceipt -ExpectedAuthoritySHA256 @($trust.egress_authority_sha256) `
                -ExpectedManagementSourceCIDRSHA256 $manifest.management_source_cidr_sha256 -NowUtc ([DateTime]::UtcNow) -HttpsRunner {
                    param($authoritySHA256)
                    if (-not $endpointByHash.ContainsKey($authoritySHA256)) { throw 'egress endpoint authority differs' }
                    $value = [string](Invoke-RestMethod -Uri $endpointByHash[$authoritySHA256] -Method Get -TimeoutSec 10 -MaximumRedirection 0 -ErrorAction Stop)
                    $address = [Net.IPAddress]$null
                    if (-not [Net.IPAddress]::TryParse($value.Trim(), [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'egress source differs' }
                    [pscustomobject]@{ authority_sha256=$authoritySHA256;source_cidr_sha256=(Get-P3SHA256Text ($address.ToString() + '/32'));observed_at_utc=[DateTime]::UtcNow.ToString('o') }
                }
            Write-P3RuntimeJson -RuntimeRoot $RuntimeRoot -Name 'egress-receipt.json' -Value $receipt
            $receipt | ConvertTo-Json -Depth 8 -Compress
        }
        'ObserveLocalBaseline' {
            $null = Invoke-P3RuntimeValidate -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256
            $receipt = New-P3LocalBaselineReceipt -ProtectedProfilePath $ProtectedProfilePath -NowUtc ([DateTime]::UtcNow) -AdapterRunner { Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ InterfaceDescription = [string]$_.InterfaceDescription } } }
            Write-P3RuntimeJson -RuntimeRoot $RuntimeRoot -Name 'local-baseline-receipt.json' -Value $receipt
            $receipt | ConvertTo-Json -Compress
        }
        'CleanupPlan' {
            New-P3RuntimeCleanupPlan -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256 | ConvertTo-Json -Compress
        }
        'Cleanup' {
            $plan = ConvertFrom-Json -InputObject $inputText -ErrorAction Stop
            Invoke-P3RuntimeCleanup -RuntimeRoot $RuntimeRoot -CleanupPlan $plan -ExpectedPlanSHA256 $ExpectedPlanSHA256 -Confirmation $Confirmation | ConvertTo-Json -Compress
        }
    }
}
