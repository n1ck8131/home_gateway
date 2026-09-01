[CmdletBinding()]
param(
    [ValidateSet('', 'Plan', 'AgentPlan', 'AgentStart', 'AgentValidate', 'Observe', 'AgentStop', 'RecordCloudFirewall', 'Assemble', 'Validate')]
    [string]$Action = '',
    [string]$PrerequisiteRoot,
    [string]$ExpectedReceiptSHA256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:P3PrerequisiteManifestProperties = @(
    'schema', 'manifest_sha256', 'payload_sha256', 'protocol_sha256', 'ssh_trust', 'ssh_trust_sha256',
    'management_source_cidr_sha256', 'egress_authority_sha256', 'firewall_resource_sha256',
    'droplet_resource_sha256', 'inbound_union_sha256', 'outbound_union_sha256'
)
$script:P3CloudFirewallV2Properties = @(
    'schema', 'firewall_resource_sha256', 'droplet_resource_sha256', 'associations',
    'management_source_cidr_sha256', 'inbound_rules', 'outbound_rules',
    'observed_at_utc', 'owner_observed', 'server_confirmed',
    'live_mutation_performed'
)
$script:P3PrerequisiteEgressProperties = @('schema', 'authority_sha256', 'source_cidr_sha256', 'observed_at_utc')
$script:P3PrerequisiteObservationBatchProperties = @(
    'schema','server_baseline','server_baseline_sha256','egress','nonce_sha256','observed_at_utc',
    'live_mutation_performed','raw_identity_exposed'
)
$script:P3PrerequisiteReceiptProperties = @(
    'schema', 'prerequisite_manifest_sha256', 'server_baseline', 'server_baseline_sha256',
    'cloud_firewall_identity_sha256', 'firewall_resource_sha256', 'droplet_resource_sha256',
    'inbound_union_sha256', 'outbound_union_sha256', 'management_source_cidr_sha256',
    'egress_authority_sha256', 'egress_observation_sha256', 'ssh_trust', 'ssh_trust_sha256', 'payload_sha256',
    'protocol_sha256', 'nonce_sha256', 'observed_at_utc', 'owner_observed', 'server_confirmed',
    'live_mutation_performed', 'raw_identity_exposed'
)

$script:P3PrerequisiteSelectedAction = $Action
. (Join-Path $PSScriptRoot 'p3-ssh-agent.ps1')
$Action = $script:P3PrerequisiteSelectedAction

function Import-P3PrerequisiteRuntime {
    if ($null -eq (Get-Command Get-P3ServerBaselineSHA256 -ErrorAction SilentlyContinue)) {
        $savedAction = $Action
        try { . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1') }
        finally { $Action = $savedAction }
    }
}

function Test-P3PrerequisiteManifest([object]$Manifest) {
    Import-P3PrerequisiteRuntime
    Assert-P3ExactProperties -Value $Manifest -ExpectedProperties $script:P3PrerequisiteManifestProperties -Label 'prerequisite manifest'
    if ([string]$Manifest.schema -cne 'home-gateway/p3-prelive-prerequisite-manifest/v1') { throw 'prerequisite manifest schema differs' }
    foreach ($name in @('manifest_sha256', 'payload_sha256', 'protocol_sha256', 'ssh_trust_sha256',
            'management_source_cidr_sha256', 'firewall_resource_sha256', 'droplet_resource_sha256',
            'inbound_union_sha256', 'outbound_union_sha256')) {
        Assert-P3SHA256 -Value ([string]$Manifest.$name) -Label $name
    }
    $authorities = @($Manifest.egress_authority_sha256)
    if ($authorities.Count -ne 3 -or @($authorities | Select-Object -Unique).Count -ne 3) { throw 'three distinct egress authorities are required' }
    foreach ($authority in $authorities) { Assert-P3SHA256 -Value ([string]$authority) -Label 'egress authority' }
    if ((Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $Manifest.ssh_trust)) -cne [string]$Manifest.ssh_trust_sha256) {
        throw 'prerequisite SSH trust canonical identity differs'
    }
    return $Manifest
}

function Get-P3PrerequisiteUtc([object]$Value, [string]$Label) {
    if ($Value -is [DateTime]) {
        $instant = [DateTime]$Value
        if ($instant.Kind -ne [DateTimeKind]::Utc) { throw "$Label timestamp differs" }
        return $instant.ToUniversalTime()
    }
    $text = [string]$Value
    if ($text -cnotmatch 'Z$') { throw "$Label timestamp differs" }
    try { $instant = [DateTime]::Parse($text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { throw "$Label timestamp differs" }
    if ($instant.Kind -ne [DateTimeKind]::Utc) { throw "$Label timestamp differs" }
    return $instant.ToUniversalTime()
}

function Assert-P3PrerequisiteFresh([object]$Value, [DateTime]$NowUtc, [string]$Label) {
    $observed = Get-P3PrerequisiteUtc -Value $Value -Label $Label
    $now = $NowUtc.ToUniversalTime()
    if ($observed -gt $now.AddSeconds(5) -or $observed -lt $now.AddMinutes(-10)) { throw "$Label freshness differs" }
    return $observed
}

function Get-P3PrerequisiteCloudUnion([object]$CloudObservation) {
    Import-P3PrerequisiteRuntime
    Assert-P3ExactProperties $CloudObservation $script:P3CloudFirewallV2Properties 'Cloud Firewall observation'
    if ([string]$CloudObservation.schema -cne 'home-gateway/p3-prelive-cloud-firewall-observation/v2' -or
        -not [bool]$CloudObservation.owner_observed -or [bool]$CloudObservation.server_confirmed -or
        [bool]$CloudObservation.live_mutation_performed) { throw 'Cloud Firewall observation provenance differs' }
    foreach ($name in @('firewall_resource_sha256','droplet_resource_sha256','management_source_cidr_sha256')) {
        Assert-P3SHA256 ([string]$CloudObservation.$name) $name
    }
    $associations = @($CloudObservation.associations)
    if ($CloudObservation.associations -isnot [Array] -or $associations.Count -ne 1) { throw 'Cloud Firewall association differs' }
    Assert-P3ExactProperties $associations[0] @('firewall_resource_sha256','droplet_resource_sha256') 'Cloud Firewall association'
    if ([string]$associations[0].firewall_resource_sha256 -cne [string]$CloudObservation.firewall_resource_sha256 -or
        [string]$associations[0].droplet_resource_sha256 -cne [string]$CloudObservation.droplet_resource_sha256) {
        throw 'Cloud Firewall association differs'
    }
    $inbound = @($CloudObservation.inbound_rules)
    if ($CloudObservation.inbound_rules -isnot [Array] -or $inbound.Count -ne 2) { throw 'Cloud Firewall inbound union differs' }
    foreach ($rule in $inbound) {
        Assert-P3ExactProperties $rule @('protocol','port','source_class','source_sha256') 'Cloud Firewall inbound rule'
        Assert-P3SHA256 ([string]$rule.source_sha256) 'Cloud Firewall inbound source'
        if (-not (Test-P3ExactJsonInteger $rule.port)) { throw 'Cloud Firewall inbound rule differs' }
    }
    $expectedInbound = @(
        [pscustomobject][ordered]@{protocol='tcp';port=22;source_class='management_ipv4';source_sha256=[string]$CloudObservation.management_source_cidr_sha256},
        [pscustomobject][ordered]@{protocol='udp';port=38556;source_class='all_ipv4';source_sha256=(Get-P3SHA256Text 'all_ipv4')}
    )
    $orderedInbound = @($inbound | Sort-Object -Property protocol,port,source_class,source_sha256)
    $orderedExpectedInbound = @($expectedInbound | Sort-Object -Property protocol,port,source_class,source_sha256)
    if ((Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $orderedInbound)) -cne
        (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $orderedExpectedInbound))) { throw 'Cloud Firewall inbound union differs' }
    $outbound = @($CloudObservation.outbound_rules)
    if ($CloudObservation.outbound_rules -isnot [Array] -or $outbound.Count -ne 6) { throw 'Cloud Firewall outbound union differs' }
    foreach ($rule in $outbound) {
        Assert-P3ExactProperties $rule @('protocol','destination_class') 'Cloud Firewall outbound rule'
    }
    $expectedOutbound = @(
        foreach ($protocol in @('icmp','tcp','udp')) {
            foreach ($destination in @('all_ipv4','all_ipv6')) {
                [pscustomobject][ordered]@{protocol=$protocol;destination_class=$destination}
            }
        }
    )
    $orderedOutbound = @($outbound | Sort-Object -Property protocol,destination_class)
    $orderedExpectedOutbound = @($expectedOutbound | Sort-Object -Property protocol,destination_class)
    if ((Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $orderedOutbound)) -cne
        (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $orderedExpectedOutbound))) { throw 'Cloud Firewall outbound union differs' }
    return [pscustomobject][ordered]@{
        inbound_union_sha256=Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $orderedInbound)
        outbound_union_sha256=Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $orderedOutbound)
    }
}

function New-P3PrerequisiteReceipt(
    [object]$Manifest,
    [object]$ServerBaseline,
    [object]$CloudObservation,
    [object[]]$EgressObservations,
    [string]$NonceSHA256,
    [DateTime]$NowUtc
) {
    Import-P3PrerequisiteRuntime
    $null = Test-P3PrerequisiteManifest $Manifest
    $baselineSHA256 = Get-P3ServerBaselineSHA256 -Baseline $ServerBaseline
    Assert-P3SHA256 $NonceSHA256 'prerequisite receipt nonce'
    $cloudUnion = Get-P3PrerequisiteCloudUnion $CloudObservation
    $cloudObserved = Assert-P3PrerequisiteFresh $CloudObservation.observed_at_utc $NowUtc 'Cloud Firewall observation'
    foreach ($name in @('firewall_resource_sha256', 'droplet_resource_sha256', 'management_source_cidr_sha256')) {
        if ([string]$CloudObservation.$name -cne [string]$Manifest.$name) { throw "Cloud Firewall $name differs" }
    }
    foreach ($name in @('inbound_union_sha256','outbound_union_sha256')) {
        if ([string]$cloudUnion.$name -cne [string]$Manifest.$name) { throw "Cloud Firewall $name differs" }
    }
    $egress = @($EgressObservations)
    if ($egress.Count -ne 3) { throw 'three egress observations are required' }
    $seen = @{}
    foreach ($observation in $egress) {
        Assert-P3ExactProperties -Value $observation -ExpectedProperties $script:P3PrerequisiteEgressProperties -Label 'egress observation'
        if ([string]$observation.schema -cne 'home-gateway/p3-prelive-egress-observation/v1') { throw 'egress observation schema differs' }
        Assert-P3SHA256 ([string]$observation.authority_sha256) 'egress authority'
        Assert-P3SHA256 ([string]$observation.source_cidr_sha256) 'egress management source'
        $null = Assert-P3PrerequisiteFresh $observation.observed_at_utc $NowUtc 'egress observation'
        if ([string]$observation.source_cidr_sha256 -cne [string]$Manifest.management_source_cidr_sha256 -or
            [string]$observation.source_cidr_sha256 -ceq [string]$Manifest.droplet_resource_sha256) { throw 'egress management source differs' }
        if ($seen.ContainsKey([string]$observation.authority_sha256)) { throw 'egress authority differs' }
        $seen[[string]$observation.authority_sha256] = $true
    }
    if (@(Compare-Object -ReferenceObject @($Manifest.egress_authority_sha256 | Sort-Object) -DifferenceObject @($seen.Keys | Sort-Object)).Count -ne 0) {
        throw 'egress authority differs'
    }
    $orderedEgress = @($egress | Sort-Object -Property authority_sha256)
    $observedAt = @($cloudObserved; $orderedEgress | ForEach-Object { Get-P3PrerequisiteUtc $_.observed_at_utc 'egress observation' } |
        Sort-Object -Descending | Select-Object -First 1) | Sort-Object -Descending | Select-Object -First 1
    $receipt = [pscustomobject][ordered]@{
        schema='home-gateway/p3-prelive-prerequisite-receipt/v1'
        prerequisite_manifest_sha256=[string]$Manifest.manifest_sha256
        server_baseline=$ServerBaseline;server_baseline_sha256=$baselineSHA256
        cloud_firewall_identity_sha256=Get-P3AgentCanonicalSHA256 $CloudObservation
        firewall_resource_sha256=[string]$CloudObservation.firewall_resource_sha256
        droplet_resource_sha256=[string]$CloudObservation.droplet_resource_sha256
        inbound_union_sha256=[string]$cloudUnion.inbound_union_sha256
        outbound_union_sha256=[string]$cloudUnion.outbound_union_sha256
        management_source_cidr_sha256=[string]$CloudObservation.management_source_cidr_sha256
        egress_authority_sha256=@($Manifest.egress_authority_sha256)
        egress_observation_sha256=Get-P3AgentCanonicalSHA256 $orderedEgress
        ssh_trust=$Manifest.ssh_trust
        ssh_trust_sha256=[string]$Manifest.ssh_trust_sha256
        payload_sha256=[string]$Manifest.payload_sha256;protocol_sha256=[string]$Manifest.protocol_sha256
        nonce_sha256=$NonceSHA256
        observed_at_utc=([DateTime]$observedAt).ToUniversalTime().ToString('o')
        owner_observed=$true;server_confirmed=$true;live_mutation_performed=$false;raw_identity_exposed=$false
    }
    return Test-P3PrerequisiteReceipt -Receipt $receipt -Manifest $Manifest -NowUtc $NowUtc
}

function Test-P3PrerequisiteReceipt([object]$Receipt, [object]$Manifest, [DateTime]$NowUtc) {
    Import-P3PrerequisiteRuntime
    $null = Test-P3PrerequisiteManifest $Manifest
    Assert-P3ExactProperties -Value $Receipt -ExpectedProperties $script:P3PrerequisiteReceiptProperties -Label 'prerequisite receipt'
    if ([string]$Receipt.schema -cne 'home-gateway/p3-prelive-prerequisite-receipt/v1' -or
        [string]$Receipt.prerequisite_manifest_sha256 -cne [string]$Manifest.manifest_sha256 -or
        -not [bool]$Receipt.owner_observed -or -not [bool]$Receipt.server_confirmed -or
        [bool]$Receipt.live_mutation_performed -or [bool]$Receipt.raw_identity_exposed) { throw 'prerequisite receipt provenance differs' }
    $null = Assert-P3PrerequisiteFresh $Receipt.observed_at_utc $NowUtc 'prerequisite receipt'
    if ((Get-P3ServerBaselineSHA256 $Receipt.server_baseline) -cne [string]$Receipt.server_baseline_sha256) { throw 'prerequisite server baseline differs' }
    foreach ($name in @('firewall_resource_sha256', 'droplet_resource_sha256', 'inbound_union_sha256',
            'outbound_union_sha256', 'management_source_cidr_sha256', 'ssh_trust_sha256', 'payload_sha256', 'protocol_sha256')) {
        Assert-P3SHA256 ([string]$Receipt.$name) $name
        if ([string]$Receipt.$name -cne [string]$Manifest.$name) { throw "prerequisite receipt $name differs" }
    }
    foreach ($name in @('server_baseline_sha256', 'cloud_firewall_identity_sha256', 'egress_observation_sha256')) {
        Assert-P3SHA256 ([string]$Receipt.$name) $name
    }
    Assert-P3SHA256 ([string]$Receipt.nonce_sha256) 'prerequisite receipt nonce'
    if ([string]$Receipt.server_baseline.payload_sha256 -cne [string]$Receipt.payload_sha256 -or
        [string]$Receipt.server_baseline.protocol_sha256 -cne [string]$Receipt.protocol_sha256 -or
        @(Compare-Object -ReferenceObject @($Manifest.egress_authority_sha256) -DifferenceObject @($Receipt.egress_authority_sha256)).Count -ne 0) {
        throw 'prerequisite receipt payload or authority differs'
    }
    if ((Get-P3AgentCanonicalSHA256 $Receipt.ssh_trust) -cne (Get-P3AgentCanonicalSHA256 $Manifest.ssh_trust) -or
        (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $Manifest.ssh_trust)) -cne [string]$Receipt.ssh_trust_sha256) {
        throw 'prerequisite receipt SSH trust differs'
    }
    return $Receipt
}

function Invoke-P3PrerequisiteOwnedObservation(
    [scriptblock]$StartRunner,
    [scriptblock]$ValidateRunner,
    [scriptblock]$ObserveRunner,
    [scriptblock]$StopRunner
) {
    $started = $null
    $validated = $null
    $bodyResult = $null
    $bodyFailure = $null
    try {
        $started = & $StartRunner
        $validated = & $ValidateRunner $started
        $bodyResult = & $ObserveRunner $validated
    } catch { $bodyFailure = $_ }
    finally {
        if ($null -ne $started) {
            try { $null = & $StopRunner $(if ($null -ne $validated) { $validated } else { $started }) }
            catch { throw 'prerequisite agent stop failure' }
        }
    }
    if ($null -ne $bodyFailure) { throw $bodyFailure }
    return $bodyResult
}

function Test-P3PrerequisiteSshTrust([object]$Trust, [object]$Manifest) {
    Import-P3PrerequisiteRuntime
    $properties = @(
        'schema','ssh_host','ssh_user','known_hosts_path','known_hosts_sha256','host_key_fingerprint_sha256',
        'git_ssh_agent_path','git_ssh_agent_sha256','git_ssh_add_path','git_ssh_add_sha256',
        'git_ssh_path','git_ssh_sha256','git_scp_path','git_scp_sha256','public_key_path','public_key_sha256',
        'public_key_fingerprint_sha256','private_key_path','observer_payload_path','observer_payload_sha256',
        'observer_protocol_sha256','expected_ipv6_policy_sha256','egress','connect_timeout_seconds',
        'command_timeout_seconds','maximum_output_bytes','no_write_scope'
    )
    Assert-P3ExactProperties $Trust $properties 'prerequisite SSH trust'
    $sshHostAddress = $null
    $sshHostIsExactIpv4 = [Net.IPAddress]::TryParse([string]$Trust.ssh_host,[ref]$sshHostAddress) -and
        $sshHostAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $sshHostAddress.ToString() -ceq [string]$Trust.ssh_host
    if ([string]$Trust.schema -cne 'home-gateway/p3-prelive-prerequisite-ssh-trust/v1' -or
        [string]$Trust.ssh_user -cne 'homegateway' -or -not $sshHostIsExactIpv4 -or
        -not [bool]$Trust.no_write_scope -or
        -not (Test-P3ExactJsonInteger $Trust.connect_timeout_seconds) -or [int]$Trust.connect_timeout_seconds -ne 10 -or
        -not (Test-P3ExactJsonInteger $Trust.command_timeout_seconds) -or [int]$Trust.command_timeout_seconds -ne 30 -or
        -not (Test-P3ExactJsonInteger $Trust.maximum_output_bytes) -or [int]$Trust.maximum_output_bytes -ne 65536) {
        throw 'prerequisite SSH trust differs'
    }
    foreach ($name in @('known_hosts_sha256','host_key_fingerprint_sha256','git_ssh_agent_sha256',
            'git_ssh_add_sha256','git_ssh_sha256','git_scp_sha256','public_key_sha256','public_key_fingerprint_sha256',
            'observer_payload_sha256','observer_protocol_sha256','expected_ipv6_policy_sha256')) {
        Assert-P3SHA256 ([string]$Trust.$name) $name
    }
    foreach ($name in @('known_hosts_path','git_ssh_agent_path','git_ssh_add_path','git_ssh_path','git_scp_path',
            'public_key_path','private_key_path','observer_payload_path')) {
        $null = Resolve-P3FixedCleanPath ([string]$Trust.$name) $name
    }
    if ([string]$Trust.observer_payload_sha256 -cne [string]$Manifest.payload_sha256 -or
        [string]$Trust.observer_protocol_sha256 -cne [string]$Manifest.protocol_sha256) {
        throw 'prerequisite observer trust differs'
    }
    $egress = @($Trust.egress)
    if ($egress.Count -ne 3) { throw 'three distinct egress authorities are required' }
    $seen = @{}
    foreach ($entry in $egress) {
        Assert-P3ExactProperties $entry @('endpoint','authority_sha256') 'prerequisite HTTPS authority'
        Assert-P3SHA256 ([string]$entry.authority_sha256) 'egress authority'
        try { $uri = [Uri]([string]$entry.endpoint) } catch { throw 'prerequisite HTTPS authority differs' }
        if ($uri.Scheme -cne 'https' -or -not $uri.IsAbsoluteUri -or -not [string]::IsNullOrEmpty($uri.UserInfo) -or
            -not [string]::IsNullOrEmpty($uri.Query) -or -not [string]::IsNullOrEmpty($uri.Fragment) -or
            [string]$entry.authority_sha256 -cne (Get-P3SHA256Text ($uri.Authority.ToLowerInvariant())) -or
            $seen.ContainsKey([string]$entry.authority_sha256)) { throw 'prerequisite HTTPS authority differs' }
        $seen[[string]$entry.authority_sha256] = $true
    }
    if (@(Compare-Object -ReferenceObject @($Manifest.egress_authority_sha256 | Sort-Object) `
            -DifferenceObject @($seen.Keys | Sort-Object)).Count -ne 0) { throw 'egress authority differs' }
    if ((Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $Trust)) -cne [string]$Manifest.ssh_trust_sha256) {
        throw 'prerequisite SSH trust canonical identity differs'
    }
    return $Trust
}

function Assert-P3PrerequisiteKnownHostPin([object]$Trust) {
    Import-P3PrerequisiteRuntime
    $bytes = Read-P3BoundedStableBytes ([string]$Trust.known_hosts_path) 8192 'known-hosts'
    try { $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes) }
    catch { throw 'prerequisite known-hosts pin differs' }
    $match = [regex]::Match($text,'\A(?<host>[0-9]{1,3}(?:\.[0-9]{1,3}){3}) ssh-ed25519 (?<key>[A-Za-z0-9+/]+={0,2})(?:\r?\n)?\z')
    if (-not $match.Success -or $match.Groups['host'].Value -cne [string]$Trust.ssh_host) {
        throw 'prerequisite known-hosts pin differs'
    }
    try { $blob = [Convert]::FromBase64String($match.Groups['key'].Value) }
    catch { throw 'prerequisite known-hosts pin differs' }
    if ($blob.Length -ne 51 -or $blob[0] -ne 0 -or $blob[1] -ne 0 -or $blob[2] -ne 0 -or $blob[3] -ne 11 -or
        [Text.Encoding]::ASCII.GetString($blob,4,11) -cne 'ssh-ed25519' -or
        $blob[15] -ne 0 -or $blob[16] -ne 0 -or $blob[17] -ne 0 -or $blob[18] -ne 32) {
        throw 'prerequisite known-hosts pin differs'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $fingerprint = 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash($blob)).TrimEnd('=') }
    finally { $sha.Dispose() }
    if ((Get-P3SHA256Text $fingerprint) -cne [string]$Trust.host_key_fingerprint_sha256) {
        throw 'prerequisite known-hosts pin differs'
    }
}

function New-P3PrerequisitePlan([object]$Manifest, [string]$Nonce, [string]$PrerequisiteRoot) {
    Import-P3PrerequisiteRuntime
    $null = Test-P3PrerequisiteManifest $Manifest
    Assert-P3SHA256 $Nonce 'observer nonce'
    $canonicalRoot = Resolve-P3FixedCleanPath $PrerequisiteRoot 'prerequisite root'
    $identity = [pscustomobject][ordered]@{
        schema='home-gateway/p3-prelive-prerequisite-plan/v2'
        prerequisite_manifest_sha256=[string]$Manifest.manifest_sha256
        prerequisite_root_sha256=Get-P3SHA256Text $canonicalRoot.ToUpperInvariant()
        nonce_sha256=Get-P3SHA256Text $Nonce
        payload_sha256=[string]$Manifest.payload_sha256;protocol_sha256=[string]$Manifest.protocol_sha256
        ssh_trust_sha256=[string]$Manifest.ssh_trust_sha256
        management_source_cidr_sha256=[string]$Manifest.management_source_cidr_sha256
        egress_authority_sha256=@($Manifest.egress_authority_sha256)
        firewall_resource_sha256=[string]$Manifest.firewall_resource_sha256
        droplet_resource_sha256=[string]$Manifest.droplet_resource_sha256
        inbound_union_sha256=[string]$Manifest.inbound_union_sha256;outbound_union_sha256=[string]$Manifest.outbound_union_sha256
        connect_timeout_seconds=10;command_timeout_seconds=30;maximum_output_bytes=65536
        no_write_scope=$true
        live_mutation_performed=$false
    }
    $planSHA256 = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $identity)
    $result = [ordered]@{}
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result.plan_sha256 = $planSHA256
    $result.confirmation_challenge = 'P3-PRELIVE-PREREQUISITE-' + $planSHA256.Substring(0, 16).ToUpperInvariant()
    return [pscustomobject]$result
}

function New-P3PrerequisiteObserverInvocation(
    [object]$Trust,
    [object]$AgentReceipt,
    [string]$Nonce,
    [byte[]]$Payload
) {
    Import-P3PrerequisiteRuntime
    Assert-P3ExactProperties $Trust @(
        'git_ssh_path','known_hosts_path','ssh_host','ssh_user','connect_timeout_seconds',
        'command_timeout_seconds','maximum_output_bytes','observer_payload_sha256',
        'observer_protocol_sha256','expected_ipv6_policy_sha256'
    ) 'prerequisite observer trust'
    Assert-P3ExactProperties $AgentReceipt @('ssh_auth_sock') 'prerequisite observer agent receipt'
    Assert-P3SHA256 $Nonce 'observer nonce'
    Assert-P3SHA256 ([string]$Trust.observer_payload_sha256) 'observer payload'
    Assert-P3SHA256 ([string]$Trust.observer_protocol_sha256) 'observer protocol'
    Assert-P3SHA256 ([string]$Trust.expected_ipv6_policy_sha256) 'observer IPv6 policy'
    if ([string]$Trust.ssh_user -cne 'homegateway' -or [string]::IsNullOrWhiteSpace([string]$Trust.ssh_host) -or
        [string]::IsNullOrWhiteSpace([string]$Trust.git_ssh_path) -or
        [string]::IsNullOrWhiteSpace([string]$Trust.known_hosts_path) -or
        [string]::IsNullOrWhiteSpace([string]$AgentReceipt.ssh_auth_sock) -or
        -not (Test-P3ExactJsonInteger $Trust.connect_timeout_seconds) -or [int]$Trust.connect_timeout_seconds -ne 10 -or
        -not (Test-P3ExactJsonInteger $Trust.command_timeout_seconds) -or [int]$Trust.command_timeout_seconds -lt 1 -or [int]$Trust.command_timeout_seconds -gt 60 -or
        -not (Test-P3ExactJsonInteger $Trust.maximum_output_bytes) -or [int]$Trust.maximum_output_bytes -lt 1024 -or [int]$Trust.maximum_output_bytes -gt 65536 -or
        $null -eq $Payload -or $Payload.Length -lt 1 -or $Payload.Length -gt 524288 -or
        (Get-P3SHA256Bytes $Payload) -cne [string]$Trust.observer_payload_sha256) {
        throw 'prerequisite observer invocation differs'
    }
    $header = [pscustomobject][ordered]@{
        expected_ipv6_policy_sha256=[string]$Trust.expected_ipv6_policy_sha256
        length=$Payload.Length;nonce=$Nonce;payload_sha256=[string]$Trust.observer_payload_sha256
        protocol_sha256=[string]$Trust.observer_protocol_sha256
        schema='home-gateway/p3-prelive-observer-frame/v1'
    }
    $headerBytes = ConvertTo-P3CanonicalJson $header
    $stdin = [byte[]]::new($headerBytes.Length + 1 + $Payload.Length)
    [Array]::Copy($headerBytes, 0, $stdin, 0, $headerBytes.Length)
    $stdin[$headerBytes.Length] = 10
    [Array]::Copy($Payload, 0, $stdin, $headerBytes.Length + 1, $Payload.Length)
    $loader = @'
import hashlib,json,re,sys
maximum=526337
raw=sys.stdin.buffer.read(maximum+1)
if not raw or len(raw)>maximum or raw.count(b'\n')<1: raise ValueError('observer frame length differs')
header_raw,payload=raw.split(b'\n',1)
header=json.loads(header_raw.decode('utf-8','strict'))
expected={'expected_ipv6_policy_sha256','length','nonce','payload_sha256','protocol_sha256','schema'}
if not isinstance(header,dict) or set(header)!=expected: raise ValueError('observer frame header differs')
if header['schema']!='home-gateway/p3-prelive-observer-frame/v1': raise ValueError('observer frame schema differs')
if not isinstance(header['length'],int) or isinstance(header['length'],bool) or header['length']<1 or header['length']>524288 or len(payload)!=header['length']: raise ValueError('observer frame length differs')
for name in ('nonce','payload_sha256','protocol_sha256','expected_ipv6_policy_sha256'):
    if not isinstance(header[name],str) or re.fullmatch('[0-9a-f]{64}',header[name]) is None: raise ValueError('observer frame identity differs')
if hashlib.sha256(payload).hexdigest()!=header['payload_sha256']: raise ValueError('observer frame hash differs')
scope={'__name__':'p3_transient_observer','__file__':'<memory>'}
exec(compile(payload,'<p3-observer>','exec'),scope)
for name in ('collect_server_snapshot','server_baseline_sha256','_sha'):
    if name not in scope: raise ValueError('observer payload contract differs')
scope['own_payload_sha256']=lambda: header['payload_sha256']
baseline=scope['collect_server_snapshot']({'expected_ipv6_policy_sha256':header['expected_ipv6_policy_sha256']})
if baseline.get('payload_sha256')!=header['payload_sha256'] or baseline.get('protocol_sha256')!=header['protocol_sha256'] or baseline.get('ipv6_non_mutation') is not True: raise ValueError('observer baseline identity differs')
receipt={'schema':'home-gateway/p3-prelive-server-observation/v1','server_baseline':baseline,'server_baseline_sha256':scope['server_baseline_sha256'](baseline),'payload_sha256':header['payload_sha256'],'protocol_sha256':header['protocol_sha256'],'nonce_sha256':scope['_sha'](header['nonce'].encode()),'live_mutation_performed':False,'raw_identity_exposed':False}
sys.stdout.write(json.dumps(receipt,sort_keys=True,separators=(',',':')))
'@.Trim()
    $loaderEncoded = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($loader))
    $remoteCommand = 'sudo -n /usr/bin/python3 -c "import base64;exec(base64.b64decode(''' + $loaderEncoded + '''))"'
    $arguments = @(
        '-F','NUL','-o','GlobalKnownHostsFile=NUL',
        '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o',("IdentityAgent=" + [string]$AgentReceipt.ssh_auth_sock),
        '-o',("UserKnownHostsFile=" + [string]$Trust.known_hosts_path),'-o','StrictHostKeyChecking=yes',
        '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','ClearAllForwardings=yes',
        '-o','RequestTTY=no','-o',("ConnectTimeout=" + [string]$Trust.connect_timeout_seconds),'-T',
        ([string]$Trust.ssh_user + '@' + [string]$Trust.ssh_host),
        $remoteCommand
    )
    return [pscustomobject][ordered]@{
        executable=[string]$Trust.git_ssh_path;arguments=$arguments;stdin=$stdin
        timeout_seconds=[int]$Trust.command_timeout_seconds;maximum_output_bytes=[int]$Trust.maximum_output_bytes
    }
}

function Test-P3PrerequisiteAgentTrust([object]$Trust, [object]$AgentManifest, [object]$Manifest) {
    Import-P3PrerequisiteAgent
    $null = Test-P3PrerequisiteSshTrust $Trust $Manifest
    $expected = @('git_scp_path','git_scp_sha256','git_ssh_add_path','git_ssh_add_sha256','git_ssh_agent_path','git_ssh_agent_sha256',
        'git_ssh_path','git_ssh_sha256','manifest_sha256','private_key_path','public_key_fingerprint_sha256','public_key_path')
    Assert-P3ExactProperties $AgentManifest $expected 'prerequisite agent manifest'
    if ([string]$AgentManifest.manifest_sha256 -cne [string]$Manifest.manifest_sha256) {
        throw 'prerequisite agent manifest differs'
    }
    foreach ($name in @('git_scp_path','git_scp_sha256','git_ssh_add_path','git_ssh_add_sha256',
            'git_ssh_agent_path','git_ssh_agent_sha256','git_ssh_path','git_ssh_sha256',
            'private_key_path','public_key_fingerprint_sha256','public_key_path')) {
        if ([string]$AgentManifest.$name -cne [string]$Trust.$name) {
            throw 'prerequisite agent SSH trust differs'
        }
    }
    $boundAgent = [pscustomobject][ordered]@{
        git_scp_path=[string]$Trust.git_scp_path;git_scp_sha256=[string]$Trust.git_scp_sha256
        git_ssh_add_path=[string]$Trust.git_ssh_add_path;git_ssh_add_sha256=[string]$Trust.git_ssh_add_sha256
        git_ssh_agent_path=[string]$Trust.git_ssh_agent_path;git_ssh_agent_sha256=[string]$Trust.git_ssh_agent_sha256
        git_ssh_path=[string]$Trust.git_ssh_path;git_ssh_sha256=[string]$Trust.git_ssh_sha256
        manifest_sha256=[string]$Manifest.manifest_sha256;private_key_path=[string]$Trust.private_key_path
        public_key_fingerprint_sha256=[string]$Trust.public_key_fingerprint_sha256
        public_key_path=[string]$Trust.public_key_path
    }
    if ((Get-P3AgentCanonicalSHA256 $boundAgent) -cne (Get-P3AgentCanonicalSHA256 $AgentManifest)) {
        throw 'prerequisite agent canonical trust differs'
    }
    return $AgentManifest
}

function Assert-P3PrerequisiteExternalFiles([object]$Trust) {
    Import-P3PrerequisiteRuntime
    foreach ($pair in @(
            @('known_hosts_path','known_hosts_sha256','known-hosts'),
            @('git_ssh_agent_path','git_ssh_agent_sha256','Git ssh-agent'),
            @('git_ssh_add_path','git_ssh_add_sha256','Git ssh-add'),
            @('git_ssh_path','git_ssh_sha256','Git ssh'),
            @('git_scp_path','git_scp_sha256','Git scp'),
            @('public_key_path','public_key_sha256','public key'),
            @('observer_payload_path','observer_payload_sha256','observer payload'))) {
        $path = [string]$Trust.PSObject.Properties[[string]$pair[0]].Value
        $expected = [string]$Trust.PSObject.Properties[[string]$pair[1]].Value
        if ((Get-P3ExactFileSHA256 $path ([string]$pair[2])) -cne $expected) {
            throw 'prerequisite external file identity differs'
        }
    }
    Assert-P3PrerequisiteKnownHostPin $Trust
}

function Invoke-P3PrerequisiteSshObservation(
    [object]$Manifest,
    [object]$Trust,
    [object]$AgentReceipt,
    [string]$Nonce,
    [scriptblock]$Runner
) {
    Import-P3PrerequisiteRuntime
    $null = Test-P3PrerequisiteSshTrust $Trust $Manifest
    foreach ($pair in @(
            @('known_hosts_path','known_hosts_sha256','known-hosts'),
            @('git_ssh_path','git_ssh_sha256','Git ssh'),
            @('observer_payload_path','observer_payload_sha256','observer payload'))) {
        $path = [string]$Trust.PSObject.Properties[[string]$pair[0]].Value
        $expected = [string]$Trust.PSObject.Properties[[string]$pair[1]].Value
        $actual = Get-P3ExactFileSHA256 $path ([string]$pair[2])
        if ($actual -cne $expected) { throw 'prerequisite SSH boundary identity differs' }
    }
    Assert-P3PrerequisiteKnownHostPin $Trust
    $payload = Read-P3BoundedStableBytes ([string]$Trust.observer_payload_path) 524288 'observer payload'
    $invocation = New-P3PrerequisiteObserverInvocation -Trust ([pscustomobject]@{
        git_ssh_path=[string]$Trust.git_ssh_path;known_hosts_path=[string]$Trust.known_hosts_path
        ssh_host=[string]$Trust.ssh_host;ssh_user=[string]$Trust.ssh_user
        connect_timeout_seconds=[int]$Trust.connect_timeout_seconds
        command_timeout_seconds=[int]$Trust.command_timeout_seconds
        maximum_output_bytes=[int]$Trust.maximum_output_bytes
        observer_payload_sha256=[string]$Trust.observer_payload_sha256
        observer_protocol_sha256=[string]$Trust.observer_protocol_sha256
        expected_ipv6_policy_sha256=[string]$Trust.expected_ipv6_policy_sha256
    }) -AgentReceipt ([pscustomobject]@{ssh_auth_sock=[string]$AgentReceipt.socket}) -Nonce $Nonce -Payload $payload
    $result = & $Runner $invocation.executable @($invocation.arguments) ([byte[]]$invocation.stdin) `
        ([int]$invocation.timeout_seconds) ([int]$invocation.maximum_output_bytes)
    Assert-P3ExactProperties $result @('ExitCode','TimedOut','Oversized','StdOut','StdErr') 'prerequisite SSH result'
    $stdout = [string]$result.StdOut
    $stderr = [string]$result.StdErr
    $stdoutLength = [Text.UTF8Encoding]::new($false).GetByteCount($stdout)
    $stderrLength = [Text.UTF8Encoding]::new($false).GetByteCount($stderr)
    if ([bool]$result.TimedOut -or [bool]$result.Oversized -or [int]$result.ExitCode -ne 0 -or
        $stderrLength -ne 0 -or $stdoutLength -lt 2 -or $stdoutLength -gt [int]$Trust.maximum_output_bytes) {
        throw 'prerequisite SSH observation failed'
    }
    try { $receipt = ConvertFrom-Json -InputObject $stdout -ErrorAction Stop }
    catch { throw 'prerequisite SSH observation JSON differs' }
    if ($receipt -is [Array]) { throw 'prerequisite SSH observation JSON differs' }
    return $receipt
}

function ConvertTo-P3PrerequisiteNativeArgument([string]$Value) {
    if ($null -eq $Value) { $Value = '' }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = [Text.StringBuilder]::new();$null=$builder.Append('"');$slashes=0
    foreach($character in $Value.ToCharArray()) {
        if($character -eq '\'){$slashes++;continue}
        if($character -eq '"'){$null=$builder.Append(('\' * (($slashes*2)+1)));$null=$builder.Append('"');$slashes=0;continue}
        if($slashes -gt 0){$null=$builder.Append(('\' * $slashes));$slashes=0}
        $null=$builder.Append($character)
    }
    if($slashes -gt 0){$null=$builder.Append(('\' * ($slashes*2)))}
    $null=$builder.Append('"');return $builder.ToString()
}

function Read-P3PrerequisiteBoundedUtf8Stdin([int]$MaximumBytes = 131072) {
    $stream=[Console]::OpenStandardInput();$memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(4096)
    try {
        while(($read=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
            if($memory.Length + $read -gt $MaximumBytes){throw 'prerequisite stdin exceeds bound'}
            $memory.Write($buffer,0,$read)
        }
        if($memory.Length -lt 2){throw 'prerequisite stdin differs'}
        try{return [Text.UTF8Encoding]::new($false,$true).GetString($memory.ToArray())}
        catch{throw 'prerequisite stdin UTF-8 differs'}
    } finally {$memory.Dispose()}
}

function Invoke-P3PrerequisiteNativeProcess(
    [string]$Executable,
    [string[]]$Arguments,
    [byte[]]$InputBytes,
    [int]$TimeoutSeconds,
    [int]$MaximumBytes
) {
    if ($null -eq $InputBytes -or $InputBytes.Length -lt 1 -or $InputBytes.Length -gt 526337 -or
        $TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 60 -or $MaximumBytes -lt 1024 -or $MaximumBytes -gt 65536) {
        throw 'prerequisite child boundary differs'
    }
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Executable;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $quotedArguments=@($Arguments|ForEach-Object{ConvertTo-P3PrerequisiteNativeArgument ([string]$_)})
    $start.Arguments=$quotedArguments -join ' '
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    $stdout=[IO.MemoryStream]::new();$stderr=[IO.MemoryStream]::new();$watch=[Diagnostics.Stopwatch]::StartNew()
    $timedOut=$false;$oversized=$false;$writeClosed=$false
    try {
        if(-not $process.Start()){throw 'prerequisite child start differs'}
        $writeTask=$process.StandardInput.BaseStream.WriteAsync($InputBytes,0,$InputBytes.Length)
        $outBuffer=[byte[]]::new(4096);$errBuffer=[byte[]]::new(4096)
        $outTask=$process.StandardOutput.BaseStream.ReadAsync($outBuffer,0,$outBuffer.Length)
        $errTask=$process.StandardError.BaseStream.ReadAsync($errBuffer,0,$errBuffer.Length)
        $outDone=$false;$errDone=$false
        while(-not $outDone -or -not $errDone -or -not $process.HasExited){
            if(-not $writeClosed -and $writeTask.IsCompleted){
                try{$null=$writeTask.GetAwaiter().GetResult()}catch{}
                $process.StandardInput.Close();$writeClosed=$true
            }
            foreach($channel in @('out','err')){
                $task=if($channel -ceq 'out'){$outTask}else{$errTask}
                if($null -ne $task -and $task.IsCompleted){
                    $count=$task.GetAwaiter().GetResult();$target=if($channel -ceq 'out'){$stdout}else{$stderr};$source=if($channel -ceq 'out'){$outBuffer}else{$errBuffer}
                    if($count -eq 0){if($channel -ceq 'out'){$outDone=$true;$outTask=$null}else{$errDone=$true;$errTask=$null}}
                    else{
                        $remaining=$MaximumBytes-[int]($stdout.Length+$stderr.Length)
                        if($count -gt $remaining){$oversized=$true;if($remaining -gt 0){$target.Write($source,0,$remaining)}}else{$target.Write($source,0,$count)}
                        if(-not $oversized){if($channel -ceq 'out'){$outTask=$process.StandardOutput.BaseStream.ReadAsync($outBuffer,0,$outBuffer.Length)}else{$errTask=$process.StandardError.BaseStream.ReadAsync($errBuffer,0,$errBuffer.Length)}}
                    }
                }
            }
            if(($oversized -or $watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) -and -not $process.HasExited){
                if(-not $oversized){$timedOut=$true};$process.Kill()
            }
            if($oversized -and $process.HasExited){$outDone=$true;$errDone=$true}
            if(-not $outDone -or -not $errDone -or -not $process.HasExited){Start-Sleep -Milliseconds 5;$process.Refresh()}
        }
        if(-not $writeClosed){try{$null=$writeTask.GetAwaiter().GetResult()}catch{};$process.StandardInput.Close();$writeClosed=$true}
        $process.WaitForExit()
        $encoding=[Text.UTF8Encoding]::new($false,$true)
        return [pscustomobject][ordered]@{ExitCode=[int]$process.ExitCode;TimedOut=$timedOut;Oversized=$oversized
            StdOut=$(if($oversized){''}else{$encoding.GetString($stdout.ToArray())});StdErr=$(if($oversized){''}else{$encoding.GetString($stderr.ToArray())})}
    } finally {
        if(-not $writeClosed -and $null -ne $process.StandardInput){try{$process.StandardInput.Close()}catch{}}
        if(-not $process.HasExited){$process.Kill();$process.WaitForExit()}
        $stdout.Dispose();$stderr.Dispose();$process.Dispose()
    }
}

function Read-P3PrerequisiteBoundedHttpBody(
    [IO.Stream]$Stream,
    [Threading.CancellationToken]$CancellationToken,
    [int]$MaximumBytes = 65536,
    [scriptblock]$ReadRunner = $null
) {
    if ($null -eq $Stream -or $MaximumBytes -ne 65536) { throw 'prerequisite HTTPS body boundary differs' }
    if ($null -eq $ReadRunner) {
        $ReadRunner = { param($Body,$Buffer,$Offset,$Count,$Token) $Body.ReadAsync($Buffer,$Offset,$Count,$Token) }
    }
    $memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(4096)
    try {
        while ($true) {
            if ($CancellationToken.IsCancellationRequested) { throw 'prerequisite HTTPS body timed out' }
            $remaining=$MaximumBytes-[int]$memory.Length
            $requested=[Math]::Min($buffer.Length,$remaining+1)
            $task=& $ReadRunner $Stream $buffer 0 $requested $CancellationToken
            if ($null -eq $task -or $task -isnot [Threading.Tasks.Task]) { throw 'prerequisite HTTPS body read differs' }
            while (-not $task.IsCompleted) {
                if ($CancellationToken.IsCancellationRequested) { throw 'prerequisite HTTPS body timed out' }
                Start-Sleep -Milliseconds 5
            }
            try { $read=[int]$task.GetAwaiter().GetResult() }
            catch {
                if ($CancellationToken.IsCancellationRequested) { throw 'prerequisite HTTPS body timed out' }
                throw 'prerequisite HTTPS body read differs'
            }
            if ($read -lt 0 -or $read -gt $requested) { throw 'prerequisite HTTPS body read differs' }
            if ($read -eq 0) { break }
            if ($memory.Length+$read -gt $MaximumBytes) { throw 'prerequisite HTTPS response exceeds its bound' }
            $memory.Write($buffer,0,$read)
        }
        try { return [Text.UTF8Encoding]::new($false,$true).GetString($memory.ToArray()) }
        catch { throw 'prerequisite HTTPS response UTF-8 differs' }
    } finally { $memory.Dispose();$Stream.Dispose() }
}

function Invoke-P3PrerequisiteNativeHttps([object]$Entry, [scriptblock]$ClockRunner) {
    Import-P3PrerequisiteRuntime
    Assert-P3ExactProperties $Entry @('endpoint','authority_sha256') 'prerequisite HTTPS authority'
    $uri = [Uri]([string]$Entry.endpoint)
    if ($uri.Scheme -cne 'https' -or -not $uri.IsAbsoluteUri -or
        [string]$Entry.authority_sha256 -cne (Get-P3SHA256Text ($uri.Authority.ToLowerInvariant()))) {
        throw 'prerequisite HTTPS authority differs'
    }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $cancellation=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(10))
    try {
        try { $response = $client.GetAsync($uri,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancellation.Token).GetAwaiter().GetResult() }
        catch { if($cancellation.IsCancellationRequested){throw 'prerequisite HTTPS request timed out'};throw }
        try {
            if ([int]$response.StatusCode -ne 200) { throw 'prerequisite HTTPS status differs' }
            if ($null -ne $response.Content.Headers.ContentLength -and [long]$response.Content.Headers.ContentLength -gt 65536) {
                throw 'prerequisite HTTPS response exceeds its bound'
            }
            $streamTask=$response.Content.ReadAsStreamAsync()
            while(-not $streamTask.IsCompleted){
                if($cancellation.IsCancellationRequested){$response.Dispose();throw 'prerequisite HTTPS body timed out'}
                Start-Sleep -Milliseconds 5
            }
            try{$stream=$streamTask.GetAwaiter().GetResult()}catch{if($cancellation.IsCancellationRequested){throw 'prerequisite HTTPS body timed out'};throw}
            $text=(Read-P3PrerequisiteBoundedHttpBody $stream $cancellation.Token 65536).Trim()
            $address = $null
            if (-not [Net.IPAddress]::TryParse($text,[ref]$address) -or
                $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
                throw 'prerequisite HTTPS response differs'
            }
            return [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-egress-observation/v1'
                authority_sha256=[string]$Entry.authority_sha256
                source_cidr_sha256=Get-P3SHA256Text ($address.ToString() + '/32')
                observed_at_utc=([DateTime](& $ClockRunner)).ToUniversalTime().ToString('o')
            }
        } finally { $response.Dispose() }
    } finally { $cancellation.Dispose();$client.Dispose(); $handler.Dispose() }
}

function Invoke-P3PrerequisiteProductionObservation(
    [string]$PrerequisiteRoot,
    [object]$InputObject,
    [object]$Boundaries
) {
    Import-P3PrerequisiteRuntime
    Import-P3PrerequisiteAgent
    $required = @('AddRunner','AgentRunner','ClockRunner','DeleteRunner','HttpsRunner','ListRunner','ProcessRunner',
        'ReceiptRemoveRunner','ReobserveRunner','SocketExistsRunner','SshRunner','StopRunner','WaitRunner')
    Assert-P3ExactProperties $Boundaries $required 'prerequisite production boundaries'
    Assert-P3ExactProperties $InputObject @('manifest','ssh_trust','agent_manifest','nonce','expected_plan_sha256','confirmation_challenge') 'prerequisite production input'
    $manifest = Test-P3PrerequisiteManifest $InputObject.manifest
    $trust = Test-P3PrerequisiteSshTrust $InputObject.ssh_trust $manifest
    $agentManifest = Test-P3PrerequisiteAgentTrust $trust $InputObject.agent_manifest $manifest
    Assert-P3SHA256 ([string]$InputObject.nonce) 'observer nonce'
    $plan = New-P3PrerequisitePlan $manifest ([string]$InputObject.nonce) $PrerequisiteRoot
    if ([string]$InputObject.expected_plan_sha256 -cne [string]$plan.plan_sha256 -or
        [string]$InputObject.confirmation_challenge -cne [string]$plan.confirmation_challenge) {
        throw 'prerequisite observation approval differs'
    }
    Assert-P3PrerequisiteExternalFiles $trust
    $null = Initialize-P3PrerequisiteRoot $PrerequisiteRoot $manifest $agentManifest
    $storedManifest = Get-P3PrerequisiteStoredAgentManifest $PrerequisiteRoot $manifest $agentManifest
    $started = Start-P3Agent $storedManifest $Boundaries.AgentRunner $Boundaries.ProcessRunner $Boundaries.AddRunner $Boundaries.StopRunner
    $protectedCombined = $null
    $observationBatch = $null
    try {
        $combined = Test-P3AgentState $storedManifest $started $Boundaries.ListRunner $Boundaries.ProcessRunner
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json (ConvertTo-P3AgentCanonicalValue $combined) -Depth 16 -Compress))
        $receiptPath = Join-Path $PrerequisiteRoot 'agent-receipt.json'
        $null = Install-P3ExactRuntimeFile $bytes $receiptPath (Get-P3SHA256Bytes $bytes)
        $reopened = Open-P3BoundedStableJson $receiptPath 65536 $script:P3CombinedAgentReceiptProperties
        if ((Get-P3AgentCanonicalSHA256 $reopened) -cne (Get-P3AgentCanonicalSHA256 $combined)) {
            throw 'protected prerequisite agent receipt differs'
        }
        $protectedCombined = $reopened
        $sshObservationCommand = Get-Command Invoke-P3PrerequisiteSshObservation
        $bodyBoundaries = [pscustomobject]@{
            ClockRunner=$Boundaries.ClockRunner
            ObserverRunner={param($m,$t,$a,$n) & $sshObservationCommand $m $t $a $n $Boundaries.SshRunner}.GetNewClosure()
            HttpsRunner={param($entry) & $Boundaries.HttpsRunner $entry $Boundaries.ClockRunner}.GetNewClosure()
        }
        $bodyInput = [pscustomobject][ordered]@{
            manifest=$manifest;ssh_trust=$trust;nonce=[string]$InputObject.nonce
            expected_plan_sha256=[string]$InputObject.expected_plan_sha256
            confirmation_challenge=[string]$InputObject.confirmation_challenge
        }
        $observationBatch = Invoke-P3PrerequisiteObserve $bodyInput $bodyBoundaries $protectedCombined $PrerequisiteRoot
    }
    finally {
        $protectedReceiptFailure = $null
        $storedCombined = $null
        if ($null -ne $protectedCombined) {
            try {
                $receiptPath = Join-Path $PrerequisiteRoot 'agent-receipt.json'
                $storedCombined = Open-P3BoundedStableJson $receiptPath 65536 $script:P3CombinedAgentReceiptProperties
                if ((Get-P3AgentCanonicalSHA256 $storedCombined) -cne (Get-P3AgentCanonicalSHA256 $protectedCombined)) {
                    throw 'protected prerequisite agent receipt differs'
                }
            } catch { $protectedReceiptFailure = $_ }
        }
        if ($null -eq $protectedCombined -or $null -ne $protectedReceiptFailure) {
            Stop-P3OwnedAgentEmergency -Manifest $storedManifest -AgentReceipt $started `
                -DeleteRunner $Boundaries.DeleteRunner -StopRunner $Boundaries.StopRunner `
                -ProcessRunner $Boundaries.ProcessRunner -WaitRunner $Boundaries.WaitRunner `
                -ReobserveRunner $Boundaries.ReobserveRunner -SocketExistsRunner $Boundaries.SocketExistsRunner | Out-Null
            if ($null -ne $protectedReceiptFailure) { throw $protectedReceiptFailure }
        } else {
            $storedReceipt = ConvertTo-P3AgentReceiptFromCombined $storedCombined
            Stop-P3Agent -Manifest $storedManifest -AgentReceipt $storedReceipt `
                -DeleteRunner $Boundaries.DeleteRunner -StopRunner $Boundaries.StopRunner `
                -ListRunner $Boundaries.ListRunner -ProcessRunner $Boundaries.ProcessRunner `
                -WaitRunner $Boundaries.WaitRunner -ReobserveRunner $Boundaries.ReobserveRunner `
                -SocketExistsRunner $Boundaries.SocketExistsRunner | Out-Null
            & $Boundaries.ReceiptRemoveRunner $receiptPath
            if ([IO.File]::Exists($receiptPath)) { throw 'protected prerequisite agent cleanup differs' }
        }
    }
    return Write-P3ProtectedPrerequisiteObservationBatch -Root $PrerequisiteRoot -Manifest $manifest `
        -ObservationBatch $observationBatch -NonceSHA256 (Get-P3SHA256Text ([string]$InputObject.nonce))
}

function Invoke-P3PrerequisiteObserve([object]$InputObject, [object]$Boundaries, [object]$AgentReceipt, [string]$PrerequisiteRoot) {
    Import-P3PrerequisiteRuntime
    Assert-P3ExactProperties $Boundaries @('ClockRunner', 'HttpsRunner', 'ObserverRunner') 'prerequisite observe boundaries'
    Assert-P3ExactProperties $InputObject @('manifest', 'ssh_trust', 'nonce', 'expected_plan_sha256', 'confirmation_challenge') 'prerequisite observe input'
    $manifest = Test-P3PrerequisiteManifest $InputObject.manifest
    $trust = Test-P3PrerequisiteSshTrust $InputObject.ssh_trust $manifest
    Assert-P3SHA256 ([string]$InputObject.nonce) 'observer nonce'
    Assert-P3SHA256 ([string]$InputObject.expected_plan_sha256) 'prerequisite approval plan'
    $approvedPlan = New-P3PrerequisitePlan $manifest ([string]$InputObject.nonce) $PrerequisiteRoot
    if ([string]$InputObject.expected_plan_sha256 -cne [string]$approvedPlan.plan_sha256 -or
        [string]$InputObject.confirmation_challenge -cne [string]$approvedPlan.confirmation_challenge) {
        throw 'prerequisite observation approval differs'
    }
    $now = ([DateTime](& $Boundaries.ClockRunner)).ToUniversalTime()
    $server = & $Boundaries.ObserverRunner $manifest $trust $AgentReceipt ([string]$InputObject.nonce)
    $serverProperties = @('schema', 'server_baseline', 'server_baseline_sha256', 'payload_sha256', 'protocol_sha256',
        'nonce_sha256', 'live_mutation_performed', 'raw_identity_exposed')
    Assert-P3ExactProperties $server $serverProperties 'server observation'
    if ([string]$server.schema -cne 'home-gateway/p3-prelive-server-observation/v1' -or
        [string]$server.payload_sha256 -cne [string]$manifest.payload_sha256 -or
        [string]$server.protocol_sha256 -cne [string]$manifest.protocol_sha256 -or
        [string]$server.nonce_sha256 -cne (Get-P3SHA256Text ([string]$InputObject.nonce)) -or
        [string]$server.server_baseline_sha256 -cne (Get-P3ServerBaselineSHA256 $server.server_baseline) -or
        [bool]$server.live_mutation_performed -or [bool]$server.raw_identity_exposed) { throw 'server observation differs' }
    $egress = @()
    foreach ($entry in @($trust.egress | Sort-Object -Property authority_sha256)) {
        $authority = [string]$entry.authority_sha256
        $item = & $Boundaries.HttpsRunner $entry
        Assert-P3ExactProperties $item $script:P3PrerequisiteEgressProperties 'egress observation'
        if ([string]$item.schema -cne 'home-gateway/p3-prelive-egress-observation/v1' -or
            [string]$item.authority_sha256 -cne [string]$authority -or
            [string]$item.source_cidr_sha256 -cne [string]$manifest.management_source_cidr_sha256 -or
            [string]$item.source_cidr_sha256 -ceq [string]$manifest.droplet_resource_sha256) { throw 'egress management source differs' }
        $null = Assert-P3PrerequisiteFresh $item.observed_at_utc $now 'egress observation'
        $egress += $item
    }
    return [pscustomobject][ordered]@{
        schema='home-gateway/p3-prelive-observation-batch/v1';server_baseline=$server.server_baseline
        server_baseline_sha256=[string]$server.server_baseline_sha256;egress=@($egress)
        nonce_sha256=Get-P3SHA256Text ([string]$InputObject.nonce)
        observed_at_utc=$now.ToString('o');live_mutation_performed=$false;raw_identity_exposed=$false
    }
}

function Import-P3PrerequisiteAgent {
    if ($null -eq (Get-Command New-P3AgentPlan -ErrorAction SilentlyContinue)) {
        $savedAction = $Action
        try { . (Join-Path $PSScriptRoot 'p3-ssh-agent.ps1') }
        finally { $Action = $savedAction }
    }
}

function Assert-P3PrerequisiteRoot([string]$Root, [object]$PrerequisiteManifest) {
    Import-P3PrerequisiteRuntime
    $resolved = Resolve-P3FixedCleanPath $Root 'prerequisite root'
    if (-not [IO.Directory]::Exists($resolved)) { throw 'protected prerequisite root is missing' }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'protected prerequisite root differs' }
    $currentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $resolved -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $currentSID.Value) {
        throw 'protected prerequisite ACL differs'
    }
    $expectedSids = @('S-1-5-18','S-1-5-32-544',$currentSID.Value)
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 3 -or @($rules | Where-Object { $_.IdentityReference.Value -notin $expectedSids -or
                $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl }).Count -ne 0) {
        throw 'protected prerequisite ACL differs'
    }
    $markerPath = Join-Path $resolved '.home-gateway-p3-prerequisite-owner.v1'
    $marker = [Text.Encoding]::UTF8.GetString((Read-P3BoundedStableBytes $markerPath 256 'prerequisite marker'))
    if ($marker -cne 'home-gateway/p3-prelive-prerequisite-owner/v1') { throw 'prerequisite marker differs' }
    $stored = Open-P3BoundedStableJson (Join-Path $resolved 'manifest.json') 65536 $script:P3PrerequisiteManifestProperties
    if ((Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $stored)) -cne (Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $PrerequisiteManifest))) {
        throw 'protected prerequisite manifest differs'
    }
    return $resolved
}

function Initialize-P3PrerequisiteRoot([string]$Root, [object]$PrerequisiteManifest, [object]$AgentManifest) {
    Import-P3PrerequisiteRuntime
    Import-P3PrerequisiteAgent
    $null = Test-P3PrerequisiteManifest $PrerequisiteManifest
    $resolved = Resolve-P3FixedCleanPath $Root 'prerequisite root'
    if ([IO.Directory]::Exists($resolved)) { return Assert-P3PrerequisiteRoot $resolved $PrerequisiteManifest }
    $null = [IO.Directory]::CreateDirectory($resolved)
    Set-Acl -LiteralPath $resolved -AclObject (New-P3RuntimeAcl) -ErrorAction Stop
    $markerBytes = [Text.UTF8Encoding]::new($false).GetBytes('home-gateway/p3-prelive-prerequisite-owner/v1')
    Install-P3ExactRuntimeFile $markerBytes (Join-Path $resolved '.home-gateway-p3-prerequisite-owner.v1') (Get-P3SHA256Bytes $markerBytes)
    $manifestBytes = ConvertTo-P3CanonicalJson $PrerequisiteManifest
    Install-P3ExactRuntimeFile $manifestBytes (Join-Path $resolved 'manifest.json') (Get-P3SHA256Bytes $manifestBytes)
    $agentBytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json (ConvertTo-P3AgentCanonicalValue $AgentManifest) -Depth 16 -Compress))
    Install-P3ExactRuntimeFile $agentBytes (Join-Path $resolved 'agent-manifest.json') (Get-P3SHA256Bytes $agentBytes)
    return Assert-P3PrerequisiteRoot $resolved $PrerequisiteManifest
}

function Get-P3PrerequisiteStoredAgentManifest([string]$Root, [object]$PrerequisiteManifest, [object]$Candidate) {
    Import-P3PrerequisiteAgent
    $resolved = Assert-P3PrerequisiteRoot $Root $PrerequisiteManifest
    $expected = @('git_scp_path','git_scp_sha256','git_ssh_add_path','git_ssh_add_sha256','git_ssh_agent_path','git_ssh_agent_sha256',
        'git_ssh_path','git_ssh_sha256','manifest_sha256','private_key_path','public_key_fingerprint_sha256','public_key_path')
    $stored = Open-P3BoundedStableJson (Join-Path $resolved 'agent-manifest.json') 65536 $expected
    if ((Get-P3AgentCanonicalSHA256 $stored) -cne (Get-P3AgentCanonicalSHA256 $Candidate) -or
        [string]$stored.manifest_sha256 -cne [string]$PrerequisiteManifest.manifest_sha256) { throw 'protected prerequisite agent manifest differs' }
    return $stored
}

function Assert-P3PrerequisiteFileSet([string]$Root, [string[]]$ExpectedNames) {
    $children = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop)
    foreach ($child in $children) {
        if ($child.Name -notin $ExpectedNames -or $child.PSIsContainer -or
            ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'foreign prerequisite content is present'
        }
    }
    foreach ($name in $ExpectedNames) {
        if (-not [IO.File]::Exists((Join-Path $Root $name))) { throw 'required prerequisite file is missing' }
    }
}

function Write-P3ProtectedPrerequisiteObservationBatch(
    [string]$Root,
    [object]$Manifest,
    [object]$ObservationBatch,
    [string]$NonceSHA256
) {
    Import-P3PrerequisiteRuntime
    Assert-P3SHA256 $NonceSHA256 'protected observation nonce'
    $resolved = Assert-P3PrerequisiteRoot $Root $Manifest
    $baseFiles = @('.home-gateway-p3-prerequisite-owner.v1','manifest.json','agent-manifest.json')
    Assert-P3PrerequisiteFileSet $resolved $baseFiles
    Assert-P3ExactProperties $ObservationBatch $script:P3PrerequisiteObservationBatchProperties 'prerequisite observation batch'
    if ([string]$ObservationBatch.schema -cne 'home-gateway/p3-prelive-observation-batch/v1' -or
        [string]$ObservationBatch.nonce_sha256 -cne $NonceSHA256 -or
        [bool]$ObservationBatch.live_mutation_performed -or [bool]$ObservationBatch.raw_identity_exposed -or
        (Get-P3ServerBaselineSHA256 $ObservationBatch.server_baseline) -cne [string]$ObservationBatch.server_baseline_sha256) {
        throw 'prerequisite observation batch differs'
    }
    if (@($ObservationBatch.egress).Count -ne 3) { throw 'prerequisite observation egress differs' }
    $bytes = ConvertTo-P3CanonicalJson $ObservationBatch
    $hash = Get-P3SHA256Bytes $bytes
    $path = Join-Path $resolved 'observation-batch.json'
    $null = Install-P3ExactRuntimeFile $bytes $path $hash
    $reopened = Open-P3BoundedStableJson $path 262144 $script:P3PrerequisiteObservationBatchProperties
    if ((Get-P3AgentCanonicalSHA256 $reopened) -cne (Get-P3AgentCanonicalSHA256 $ObservationBatch) -or
        (Get-P3ExactFileSHA256 $path 'prerequisite observation batch') -cne $hash) {
        throw 'protected prerequisite observation batch differs'
    }
    Assert-P3PrerequisiteFileSet $resolved @($baseFiles + 'observation-batch.json')
    return $reopened
}

function Write-P3ProtectedPrerequisiteCloudObservation(
    [string]$Root,
    [object]$Manifest,
    [object]$CloudObservation,
    [DateTime]$NowUtc
) {
    Import-P3PrerequisiteRuntime
    $resolved = Assert-P3PrerequisiteRoot $Root $Manifest
    $baseFiles = @('.home-gateway-p3-prerequisite-owner.v1','manifest.json','agent-manifest.json')
    $allowedBefore = @($baseFiles)
    if ([IO.File]::Exists((Join-Path $resolved 'observation-batch.json'))) { $allowedBefore += 'observation-batch.json' }
    Assert-P3PrerequisiteFileSet $resolved $allowedBefore
    $union = Get-P3PrerequisiteCloudUnion $CloudObservation
    $null = Assert-P3PrerequisiteFresh $CloudObservation.observed_at_utc $NowUtc 'Cloud Firewall observation'
    foreach ($name in @('firewall_resource_sha256','droplet_resource_sha256','management_source_cidr_sha256')) {
        if ([string]$CloudObservation.$name -cne [string]$Manifest.$name) { throw "Cloud Firewall $name differs" }
    }
    foreach ($name in @('inbound_union_sha256','outbound_union_sha256')) {
        if ([string]$union.$name -cne [string]$Manifest.$name) { throw "Cloud Firewall $name differs" }
    }
    $bytes = ConvertTo-P3CanonicalJson $CloudObservation
    $hash = Get-P3SHA256Bytes $bytes
    $path = Join-Path $resolved 'cloud-observation.json'
    $null = Install-P3ExactRuntimeFile $bytes $path $hash
    $reopened = Open-P3BoundedStableJson $path 131072 $script:P3CloudFirewallV2Properties
    if ((Get-P3AgentCanonicalSHA256 $reopened) -cne (Get-P3AgentCanonicalSHA256 $CloudObservation) -or
        (Get-P3ExactFileSHA256 $path 'prerequisite Cloud observation') -cne $hash) {
        throw 'protected prerequisite Cloud observation differs'
    }
    Assert-P3PrerequisiteFileSet $resolved @($allowedBefore + 'cloud-observation.json')
    return $reopened
}

function Get-P3ProtectedPrerequisiteInputs([string]$Root, [object]$Manifest) {
    Import-P3PrerequisiteRuntime
    $resolved = Assert-P3PrerequisiteRoot $Root $Manifest
    $expected = @('.home-gateway-p3-prerequisite-owner.v1','manifest.json','agent-manifest.json',
        'observation-batch.json','cloud-observation.json')
    Assert-P3PrerequisiteFileSet $resolved $expected
    $batch = Open-P3BoundedStableJson (Join-Path $resolved 'observation-batch.json') 262144 $script:P3PrerequisiteObservationBatchProperties
    $cloud = Open-P3BoundedStableJson (Join-Path $resolved 'cloud-observation.json') 131072 $script:P3CloudFirewallV2Properties
    if ((Get-P3ServerBaselineSHA256 $batch.server_baseline) -cne [string]$batch.server_baseline_sha256) {
        throw 'protected prerequisite observation batch differs'
    }
    $null = Get-P3PrerequisiteCloudUnion $cloud
    return [pscustomobject]@{batch=$batch;cloud=$cloud}
}

function Write-P3ProtectedPrerequisiteReceipt(
    [string]$Root,
    [object]$Manifest,
    [object]$Receipt,
    [string]$ExpectedReceiptSHA256,
    [DateTime]$NowUtc
) {
    Import-P3PrerequisiteRuntime
    Assert-P3SHA256 $ExpectedReceiptSHA256 'expected prerequisite receipt'
    $resolved = Assert-P3PrerequisiteRoot $Root $Manifest
    $baseFiles = @('.home-gateway-p3-prerequisite-owner.v1','manifest.json','agent-manifest.json','observation-batch.json','cloud-observation.json')
    Assert-P3PrerequisiteFileSet $resolved $baseFiles
    $validated = Test-P3PrerequisiteReceipt $Receipt $Manifest $NowUtc
    $bytes = ConvertTo-P3CanonicalJson $validated
    if ((Get-P3SHA256Bytes $bytes) -cne $ExpectedReceiptSHA256) { throw 'expected prerequisite receipt hash differs' }
    $path = Join-Path $resolved 'prerequisite-receipt.json'
    $null = Install-P3ExactRuntimeFile $bytes $path $ExpectedReceiptSHA256
    $reopened = Open-P3BoundedStableJson $path 131072 $script:P3PrerequisiteReceiptProperties
    if ((Get-P3AgentCanonicalSHA256 $reopened) -cne (Get-P3AgentCanonicalSHA256 $validated) -or
        (Get-P3ExactFileSHA256 $path 'prerequisite receipt') -cne $ExpectedReceiptSHA256) {
        throw 'protected prerequisite receipt differs'
    }
    $null = Test-P3PrerequisiteReceipt $reopened $Manifest $NowUtc
    Assert-P3PrerequisiteFileSet $resolved @($baseFiles + 'prerequisite-receipt.json')
    return $reopened
}

function Get-P3ProtectedPrerequisiteReceipt(
    [string]$Root,
    [object]$Manifest,
    [string]$ExpectedReceiptSHA256,
    [DateTime]$NowUtc
) {
    Import-P3PrerequisiteRuntime
    Assert-P3SHA256 $ExpectedReceiptSHA256 'expected prerequisite receipt'
    $resolved = Assert-P3PrerequisiteRoot $Root $Manifest
    $baseFiles = @('.home-gateway-p3-prerequisite-owner.v1','manifest.json','agent-manifest.json',
        'observation-batch.json','cloud-observation.json','prerequisite-receipt.json')
    Assert-P3PrerequisiteFileSet $resolved $baseFiles
    $path = Join-Path $resolved 'prerequisite-receipt.json'
    if ((Get-P3ExactFileSHA256 $path 'prerequisite receipt') -cne $ExpectedReceiptSHA256) {
        throw 'protected prerequisite receipt hash differs'
    }
    $receipt = Open-P3BoundedStableJson $path 131072 $script:P3PrerequisiteReceiptProperties
    $null = Test-P3PrerequisiteReceipt $receipt $Manifest $NowUtc
    Assert-P3PrerequisiteFileSet $resolved $baseFiles
    return $receipt
}

function Invoke-P3PrerequisiteAgentAction(
    [string]$SelectedAction, [string]$PrerequisiteRoot, [object]$PrerequisiteManifest,
    [object]$InputObject, [object]$Boundaries
) {
    Import-P3PrerequisiteRuntime
    Import-P3PrerequisiteAgent
    $null = Test-P3PrerequisiteManifest $PrerequisiteManifest
    if ($SelectedAction -ceq 'AgentPlan') { return New-P3AgentPlan $InputObject }
    $agentManifest = $InputObject.agent_manifest
    if ($SelectedAction -ceq 'AgentStart') {
        $null = Initialize-P3PrerequisiteRoot $PrerequisiteRoot $PrerequisiteManifest $agentManifest
    }
    $storedManifest = Get-P3PrerequisiteStoredAgentManifest $PrerequisiteRoot $PrerequisiteManifest $agentManifest
    switch ($SelectedAction) {
        'AgentStart' {
            $expectedPlan = New-P3AgentPlan $storedManifest
            if ((Get-P3AgentCanonicalSHA256 $expectedPlan) -cne (Get-P3AgentCanonicalSHA256 $InputObject.plan)) { throw 'prerequisite agent plan differs' }
            return Start-P3Agent $storedManifest $Boundaries.AgentRunner $Boundaries.ProcessRunner $Boundaries.AddRunner $Boundaries.StopRunner
        }
        'AgentValidate' {
            $combined = Test-P3AgentState $storedManifest $InputObject.receipt $Boundaries.ListRunner $Boundaries.ProcessRunner
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json (ConvertTo-P3AgentCanonicalValue $combined) -Depth 16 -Compress))
            $null = Install-P3ExactRuntimeFile $bytes (Join-Path $PrerequisiteRoot 'agent-receipt.json') (Get-P3SHA256Bytes $bytes)
            $reopened = Open-P3BoundedStableJson (Join-Path $PrerequisiteRoot 'agent-receipt.json') 65536 $script:P3CombinedAgentReceiptProperties
            if ((Get-P3AgentCanonicalSHA256 $reopened) -cne (Get-P3AgentCanonicalSHA256 $combined)) { throw 'protected prerequisite agent receipt differs' }
            return $reopened
        }
        'AgentStop' {
            $receiptPath = Join-Path $PrerequisiteRoot 'agent-receipt.json'
            $storedCombined = Open-P3BoundedStableJson $receiptPath 65536 $script:P3CombinedAgentReceiptProperties
            if ((Get-P3AgentCanonicalSHA256 $storedCombined) -cne (Get-P3AgentCanonicalSHA256 $InputObject.combined_receipt)) {
                throw 'protected prerequisite agent receipt differs'
            }
            $storedReceipt = ConvertTo-P3AgentReceiptFromCombined $storedCombined
            if ((Get-P3AgentCanonicalSHA256 $storedReceipt) -cne (Get-P3AgentCanonicalSHA256 $InputObject.receipt)) {
                throw 'protected prerequisite agent receipt differs'
            }
            $stop = Stop-P3Agent -Manifest $storedManifest -AgentReceipt $storedReceipt `
                -DeleteRunner $Boundaries.DeleteRunner -StopRunner $Boundaries.StopRunner `
                -ListRunner $Boundaries.ListRunner -ProcessRunner $Boundaries.ProcessRunner `
                -WaitRunner $Boundaries.WaitRunner -ReobserveRunner $Boundaries.ReobserveRunner `
                -SocketExistsRunner $Boundaries.SocketExistsRunner
            & $Boundaries.ReceiptRemoveRunner $receiptPath
            if ([IO.File]::Exists($receiptPath)) { throw 'protected prerequisite agent cleanup differs' }
            return $stop
        }
        default { throw 'prerequisite agent action differs' }
    }
}

function Invoke-P3PrerequisiteAction([string]$SelectedAction, [object]$InputObject, [object]$Boundaries) {
    switch ($SelectedAction) {
        'Plan' {
            Import-P3PrerequisiteRuntime
            Assert-P3ExactProperties $InputObject @('manifest','nonce') 'prerequisite plan input'
            Assert-P3ExactProperties $Boundaries @('PrerequisiteRoot') 'prerequisite plan boundaries'
            return New-P3PrerequisitePlan $InputObject.manifest ([string]$InputObject.nonce) ([string]$Boundaries.PrerequisiteRoot)
        }
        'Observe' {
            Import-P3PrerequisiteRuntime
            Assert-P3ExactProperties $InputObject @('manifest', 'ssh_trust', 'nonce', 'expected_plan_sha256', 'confirmation_challenge') 'prerequisite observe input'
            $null = Test-P3PrerequisiteSshTrust $InputObject.ssh_trust $InputObject.manifest
            if ($null -eq $Boundaries -or $Boundaries.PSObject.Properties.Name -notcontains 'PrerequisiteRoot') { throw 'prerequisite Observe root differs' }
            $approvedPlan = New-P3PrerequisitePlan $InputObject.manifest ([string]$InputObject.nonce) ([string]$Boundaries.PrerequisiteRoot)
            if ([string]$InputObject.expected_plan_sha256 -cne [string]$approvedPlan.plan_sha256 -or
                [string]$InputObject.confirmation_challenge -cne [string]$approvedPlan.confirmation_challenge) {
                throw 'prerequisite observation approval differs'
            }
            $bodyBoundaries = [pscustomobject]@{
                ClockRunner=$Boundaries.ClockRunner;HttpsRunner=$Boundaries.HttpsRunner;ObserverRunner=$Boundaries.ObserverRunner
            }
            $observeCommand = Get-Command Invoke-P3PrerequisiteObserve
            return Invoke-P3PrerequisiteOwnedObservation -StartRunner $Boundaries.StartRunner `
                -ValidateRunner $Boundaries.ValidateRunner -ObserveRunner { param($receipt) & $observeCommand $InputObject $bodyBoundaries $receipt ([string]$Boundaries.PrerequisiteRoot) }.GetNewClosure() `
                -StopRunner $Boundaries.StopRunner
        }
        'RecordCloudFirewall' {
            Import-P3PrerequisiteRuntime
            Assert-P3ExactProperties $InputObject @('manifest','cloud_firewall') 'prerequisite Cloud input'
            Assert-P3ExactProperties $Boundaries @('ClockRunner','PrerequisiteRoot') 'prerequisite Cloud boundaries'
            return Write-P3ProtectedPrerequisiteCloudObservation $Boundaries.PrerequisiteRoot $InputObject.manifest `
                $InputObject.cloud_firewall ([DateTime](& $Boundaries.ClockRunner))
        }
        'Assemble' {
            Import-P3PrerequisiteRuntime
            Assert-P3ExactProperties $InputObject @('manifest','expected_receipt_sha256') 'prerequisite assemble input'
            Assert-P3ExactProperties $Boundaries @('ClockRunner','PrerequisiteRoot') 'prerequisite assemble boundaries'
            $now = [DateTime](& $Boundaries.ClockRunner)
            $protected = Get-P3ProtectedPrerequisiteInputs $Boundaries.PrerequisiteRoot $InputObject.manifest
            $receipt = New-P3PrerequisiteReceipt -Manifest $InputObject.manifest -ServerBaseline $protected.batch.server_baseline `
                -CloudObservation $protected.cloud -EgressObservations @($protected.batch.egress) `
                -NonceSHA256 ([string]$protected.batch.nonce_sha256) -NowUtc $now
            return Write-P3ProtectedPrerequisiteReceipt $Boundaries.PrerequisiteRoot $InputObject.manifest $receipt `
                ([string]$InputObject.expected_receipt_sha256) $now
        }
        'Validate' {
            Import-P3PrerequisiteRuntime
            Assert-P3ExactProperties $InputObject @('manifest','expected_receipt_sha256') 'prerequisite validate input'
            Assert-P3ExactProperties $Boundaries @('ClockRunner','PrerequisiteRoot') 'prerequisite validate boundaries'
            return Get-P3ProtectedPrerequisiteReceipt $Boundaries.PrerequisiteRoot $InputObject.manifest `
                ([string]$InputObject.expected_receipt_sha256) ([DateTime](& $Boundaries.ClockRunner))
        }
        { $_ -in @('AgentPlan', 'AgentStart', 'AgentValidate', 'AgentStop') } {
            if ($null -eq $Boundaries -or $Boundaries.PSObject.Properties.Name -notcontains 'PrerequisiteRoot' -or
                $Boundaries.PSObject.Properties.Name -notcontains 'PrerequisiteManifest') { throw 'prerequisite protected agent boundary differs' }
            return Invoke-P3PrerequisiteAgentAction -SelectedAction $SelectedAction `
                -PrerequisiteRoot ([string]$Boundaries.PrerequisiteRoot) `
                -PrerequisiteManifest $Boundaries.PrerequisiteManifest -InputObject $InputObject -Boundaries $Boundaries
        }
        default { throw 'prerequisite action differs' }
    }
}

if (-not [string]::IsNullOrEmpty($Action)) {
    $inputText = Read-P3PrerequisiteBoundedUtf8Stdin 131072
    Import-P3PrerequisiteRuntime
    $inputObject = ConvertFrom-Json -InputObject $inputText -ErrorAction Stop
    switch ($Action) {
        'Plan' {
            Assert-P3ExactProperties $inputObject @('manifest','nonce') 'prerequisite plan input'
            New-P3PrerequisitePlan $inputObject.manifest ([string]$inputObject.nonce) $PrerequisiteRoot | ConvertTo-Json -Depth 20 -Compress
        }
        'Observe' {
            $candidateAgentManifest = $inputObject.agent_manifest
            $productionBoundaries = [pscustomobject]@{
                AgentRunner={param($Executable)Start-P3WindowsAgentProcess -ExecutablePath $Executable}
                AddRunner={param($KeyPath)Invoke-P3InteractiveAgentAdd -ExecutablePath $candidateAgentManifest.git_ssh_add_path -KeyPath $KeyPath}.GetNewClosure()
                StopRunner={param($ProcessId)Stop-Process -Id $ProcessId -ErrorAction Stop}
                ListRunner={param($Executable)& $Executable -l -E sha256}
                ProcessRunner={param($ProcessId)Get-Process -Id $ProcessId -ErrorAction Stop|Select-Object Id,Path,StartTime}
                DeleteRunner={& $candidateAgentManifest.git_ssh_add_path -D}.GetNewClosure()
                WaitRunner={param($ProcessId)Wait-P3BoundedAgentExit -ProcessId $ProcessId `
                    -ObserveRunner {param($OwnedProcessId)@(Get-Process -Id $OwnedProcessId -ErrorAction SilentlyContinue)} `
                    -SleepRunner {param($Milliseconds)Start-Sleep -Milliseconds $Milliseconds} -ClockRunner {[DateTime]::UtcNow}}
                ReobserveRunner={param($ProcessId)@(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)}
                SocketExistsRunner={param($Path)[IO.File]::Exists($Path)}
                ReceiptRemoveRunner={param($Path)[IO.File]::Delete($Path)}
                SshRunner={param($Executable,$Arguments,$InputBytes,$TimeoutSeconds,$MaximumBytes)
                    Invoke-P3PrerequisiteNativeProcess $Executable $Arguments $InputBytes $TimeoutSeconds $MaximumBytes}
                HttpsRunner={param($Entry,$ClockRunner)Invoke-P3PrerequisiteNativeHttps $Entry $ClockRunner}
                ClockRunner={[DateTime]::UtcNow}
            }
            Invoke-P3PrerequisiteProductionObservation -PrerequisiteRoot $PrerequisiteRoot `
                -InputObject $inputObject -Boundaries $productionBoundaries | ConvertTo-Json -Depth 30 -Compress
        }
        { $_ -in @('AgentPlan', 'AgentStart', 'AgentValidate', 'AgentStop') } {
            Assert-P3ExactProperties $inputObject @('action_input','prerequisite_manifest') 'prerequisite agent action input'
            $actionInput = $inputObject.action_input
            $candidateAgentManifest = if ($Action -ceq 'AgentPlan') { $actionInput } else { $actionInput.agent_manifest }
            $agentBoundaries = [pscustomobject]@{
                PrerequisiteRoot=$PrerequisiteRoot;PrerequisiteManifest=$inputObject.prerequisite_manifest
                AgentRunner={param($Executable)Start-P3WindowsAgentProcess -ExecutablePath $Executable};AddRunner={param($KeyPath)Invoke-P3InteractiveAgentAdd -ExecutablePath $candidateAgentManifest.git_ssh_add_path -KeyPath $KeyPath}
                StopRunner={param($ProcessId)Stop-Process -Id $ProcessId -ErrorAction Stop}
                ListRunner={param($Executable)& $Executable -l -E sha256}
                ProcessRunner={param($ProcessId)Get-Process -Id $ProcessId -ErrorAction Stop|Select-Object Id,Path,StartTime}
                DeleteRunner={& $candidateAgentManifest.git_ssh_add_path -D}
                WaitRunner={param($ProcessId)Wait-P3BoundedAgentExit -ProcessId $ProcessId `
                    -ObserveRunner {param($OwnedProcessId)@(Get-Process -Id $OwnedProcessId -ErrorAction SilentlyContinue)} `
                    -SleepRunner {param($Milliseconds)Start-Sleep -Milliseconds $Milliseconds} -ClockRunner {[DateTime]::UtcNow}}
                ReobserveRunner={param($ProcessId)@(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)}
                SocketExistsRunner={param($Path)[IO.File]::Exists($Path)}
                ReceiptRemoveRunner={param($Path)[IO.File]::Delete($Path)}
            }
            Invoke-P3PrerequisiteAction $Action $actionInput $agentBoundaries | ConvertTo-Json -Depth 20 -Compress
        }
        'RecordCloudFirewall' {
            Invoke-P3PrerequisiteAction RecordCloudFirewall $inputObject ([pscustomobject]@{
                ClockRunner={[DateTime]::UtcNow};PrerequisiteRoot=$PrerequisiteRoot
            }) | ConvertTo-Json -Depth 30 -Compress
        }
        'Assemble' {
            if ([string]$inputObject.expected_receipt_sha256 -cne $ExpectedReceiptSHA256) { throw 'expected prerequisite receipt differs' }
            Invoke-P3PrerequisiteAction Assemble $inputObject ([pscustomobject]@{
                ClockRunner={[DateTime]::UtcNow};PrerequisiteRoot=$PrerequisiteRoot
            }) | ConvertTo-Json -Depth 30 -Compress
        }
        'Validate' {
            if ([string]$inputObject.expected_receipt_sha256 -cne $ExpectedReceiptSHA256) { throw 'expected prerequisite receipt differs' }
            Invoke-P3PrerequisiteAction Validate $inputObject ([pscustomobject]@{
                ClockRunner={[DateTime]::UtcNow};PrerequisiteRoot=$PrerequisiteRoot
            }) | ConvertTo-Json -Depth 30 -Compress
        }
        default { throw 'prerequisite action requires the approved injected execution boundary' }
    }
}
