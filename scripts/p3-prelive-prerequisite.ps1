[CmdletBinding()]
param(
    [ValidateSet('', 'Plan', 'AgentPlan', 'AgentStart', 'AgentValidate', 'Observe', 'AgentStop', 'Assemble', 'Validate')]
    [string]$Action = '',
    [string]$PrerequisiteRoot,
    [string]$ExpectedReceiptSHA256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:P3PrerequisiteManifestProperties = @(
    'schema', 'manifest_sha256', 'payload_sha256', 'protocol_sha256', 'ssh_trust_sha256',
    'management_source_cidr_sha256', 'egress_authority_sha256', 'firewall_resource_sha256',
    'droplet_resource_sha256', 'inbound_union_sha256', 'outbound_union_sha256'
)
$script:P3CloudFirewallV2Properties = @(
    'schema', 'firewall_resource_sha256', 'droplet_resource_sha256', 'droplet_association_count',
    'management_source_cidr_sha256', 'tcp_22_management_source_count', 'udp_38556_all_ipv4_count',
    'udp_ipv6_count', 'extra_inbound_rule_count', 'inbound_union_sha256', 'outbound_union_sha256',
    'outbound_icmp_all_count', 'outbound_tcp_all_count', 'outbound_udp_all_count',
    'extra_outbound_rule_count', 'observed_at_utc', 'owner_observed', 'server_confirmed',
    'live_mutation_performed'
)
$script:P3PrerequisiteEgressProperties = @('schema', 'authority_sha256', 'source_cidr_sha256', 'observed_at_utc')
$script:P3PrerequisiteReceiptProperties = @(
    'schema', 'prerequisite_manifest_sha256', 'server_baseline', 'server_baseline_sha256',
    'cloud_firewall_identity_sha256', 'firewall_resource_sha256', 'droplet_resource_sha256',
    'inbound_union_sha256', 'outbound_union_sha256', 'management_source_cidr_sha256',
    'egress_authority_sha256', 'egress_observation_sha256', 'ssh_trust_sha256', 'payload_sha256',
    'protocol_sha256', 'observed_at_utc', 'owner_observed', 'server_confirmed',
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
    return $Manifest
}

function Get-P3PrerequisiteUtc([object]$Value, [string]$Label) {
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

function New-P3PrerequisiteReceipt(
    [object]$Manifest,
    [object]$ServerBaseline,
    [object]$CloudObservation,
    [object[]]$EgressObservations,
    [DateTime]$NowUtc
) {
    Import-P3PrerequisiteRuntime
    $null = Test-P3PrerequisiteManifest $Manifest
    $baselineSHA256 = Get-P3ServerBaselineSHA256 -Baseline $ServerBaseline
    Assert-P3ExactProperties -Value $CloudObservation -ExpectedProperties $script:P3CloudFirewallV2Properties -Label 'Cloud Firewall observation'
    if ([string]$CloudObservation.schema -cne 'home-gateway/p3-prelive-cloud-firewall-observation/v2' -or
        -not [bool]$CloudObservation.owner_observed -or [bool]$CloudObservation.server_confirmed -or
        [bool]$CloudObservation.live_mutation_performed) { throw 'Cloud Firewall observation provenance differs' }
    foreach ($name in @('firewall_resource_sha256', 'droplet_resource_sha256', 'management_source_cidr_sha256',
            'inbound_union_sha256', 'outbound_union_sha256')) { Assert-P3SHA256 ([string]$CloudObservation.$name) $name }
    foreach ($name in @('droplet_association_count', 'tcp_22_management_source_count', 'udp_38556_all_ipv4_count')) {
        if (-not (Test-P3ExactJsonInteger $CloudObservation.$name) -or [int]$CloudObservation.$name -ne 1) { throw 'Cloud Firewall inbound rule differs' }
    }
    foreach ($name in @('udp_ipv6_count', 'extra_inbound_rule_count', 'extra_outbound_rule_count')) {
        if (-not (Test-P3ExactJsonInteger $CloudObservation.$name) -or [int]$CloudObservation.$name -ne 0) { throw 'Cloud Firewall extra rule differs' }
    }
    foreach ($name in @('outbound_icmp_all_count', 'outbound_tcp_all_count', 'outbound_udp_all_count')) {
        if (-not (Test-P3ExactJsonInteger $CloudObservation.$name) -or [int]$CloudObservation.$name -ne 2) { throw 'Cloud Firewall outbound union differs' }
    }
    $cloudObserved = Assert-P3PrerequisiteFresh $CloudObservation.observed_at_utc $NowUtc 'Cloud Firewall observation'
    foreach ($name in @('firewall_resource_sha256', 'droplet_resource_sha256', 'management_source_cidr_sha256',
            'inbound_union_sha256', 'outbound_union_sha256')) {
        if ([string]$CloudObservation.$name -cne [string]$Manifest.$name) { throw "Cloud Firewall $name differs" }
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
        cloud_firewall_identity_sha256=Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $CloudObservation)
        firewall_resource_sha256=[string]$CloudObservation.firewall_resource_sha256
        droplet_resource_sha256=[string]$CloudObservation.droplet_resource_sha256
        inbound_union_sha256=[string]$CloudObservation.inbound_union_sha256
        outbound_union_sha256=[string]$CloudObservation.outbound_union_sha256
        management_source_cidr_sha256=[string]$CloudObservation.management_source_cidr_sha256
        egress_authority_sha256=@($Manifest.egress_authority_sha256)
        egress_observation_sha256=Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $orderedEgress)
        ssh_trust_sha256=[string]$Manifest.ssh_trust_sha256
        payload_sha256=[string]$Manifest.payload_sha256;protocol_sha256=[string]$Manifest.protocol_sha256
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
    if ([string]$Receipt.server_baseline.payload_sha256 -cne [string]$Receipt.payload_sha256 -or
        [string]$Receipt.server_baseline.protocol_sha256 -cne [string]$Receipt.protocol_sha256 -or
        @(Compare-Object -ReferenceObject @($Manifest.egress_authority_sha256) -DifferenceObject @($Receipt.egress_authority_sha256)).Count -ne 0) {
        throw 'prerequisite receipt payload or authority differs'
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

function New-P3PrerequisitePlan([object]$Manifest) {
    Import-P3PrerequisiteRuntime
    $null = Test-P3PrerequisiteManifest $Manifest
    $identity = [pscustomobject][ordered]@{
        schema='home-gateway/p3-prelive-prerequisite-plan/v1'
        prerequisite_manifest_sha256=[string]$Manifest.manifest_sha256
        payload_sha256=[string]$Manifest.payload_sha256;protocol_sha256=[string]$Manifest.protocol_sha256
        ssh_trust_sha256=[string]$Manifest.ssh_trust_sha256
        management_source_cidr_sha256=[string]$Manifest.management_source_cidr_sha256
        egress_authority_sha256=@($Manifest.egress_authority_sha256)
        firewall_resource_sha256=[string]$Manifest.firewall_resource_sha256
        droplet_resource_sha256=[string]$Manifest.droplet_resource_sha256
        inbound_union_sha256=[string]$Manifest.inbound_union_sha256;outbound_union_sha256=[string]$Manifest.outbound_union_sha256
        live_mutation_performed=$false
    }
    $planSHA256 = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $identity)
    $result = [ordered]@{}
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result.plan_sha256 = $planSHA256
    $result.confirmation_challenge = 'P3-PRELIVE-PREREQUISITE-' + $planSHA256.Substring(0, 16).ToUpperInvariant()
    return [pscustomobject]$result
}

function Invoke-P3PrerequisiteObserve([object]$InputObject, [object]$Boundaries) {
    Import-P3PrerequisiteRuntime
    Assert-P3ExactProperties $Boundaries @('ClockRunner', 'HttpsRunner', 'ObserverRunner') 'prerequisite observe boundaries'
    Assert-P3ExactProperties $InputObject @('manifest', 'nonce') 'prerequisite observe input'
    $manifest = Test-P3PrerequisiteManifest $InputObject.manifest
    Assert-P3SHA256 ([string]$InputObject.nonce) 'observer nonce'
    $now = ([DateTime](& $Boundaries.ClockRunner)).ToUniversalTime()
    $server = & $Boundaries.ObserverRunner $manifest ([string]$InputObject.nonce)
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
    foreach ($authority in @($manifest.egress_authority_sha256)) {
        $item = & $Boundaries.HttpsRunner $authority
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
            return Start-P3Agent $storedManifest $Boundaries.AgentRunner $Boundaries.AddRunner $Boundaries.StopRunner
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
        'Plan' { return New-P3PrerequisitePlan $InputObject }
        'Observe' {
            $bodyBoundaries = [pscustomobject]@{
                ClockRunner=$Boundaries.ClockRunner;HttpsRunner=$Boundaries.HttpsRunner;ObserverRunner=$Boundaries.ObserverRunner
            }
            $observeCommand = Get-Command Invoke-P3PrerequisiteObserve
            return Invoke-P3PrerequisiteOwnedObservation -StartRunner $Boundaries.StartRunner `
                -ValidateRunner $Boundaries.ValidateRunner -ObserveRunner { param($receipt) & $observeCommand $InputObject $bodyBoundaries }.GetNewClosure() `
                -StopRunner $Boundaries.StopRunner
        }
        'Assemble' {
            return New-P3PrerequisiteReceipt -Manifest $InputObject.manifest -ServerBaseline $InputObject.server_baseline `
                -CloudObservation $InputObject.cloud_firewall -EgressObservations @($InputObject.egress) -NowUtc ([DateTime](& $Boundaries.ClockRunner))
        }
        'Validate' { return Test-P3PrerequisiteReceipt $InputObject.receipt $InputObject.manifest ([DateTime](& $Boundaries.ClockRunner)) }
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
    $inputObject = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd()) -ErrorAction Stop
    switch ($Action) {
        'Plan' { New-P3PrerequisitePlan $inputObject | ConvertTo-Json -Depth 20 -Compress }
        { $_ -in @('AgentPlan', 'AgentStart', 'AgentValidate', 'AgentStop') } {
            Assert-P3ExactProperties $inputObject @('action_input','prerequisite_manifest') 'prerequisite agent action input'
            $actionInput = $inputObject.action_input
            $candidateAgentManifest = if ($Action -ceq 'AgentPlan') { $actionInput } else { $actionInput.agent_manifest }
            $agentBoundaries = [pscustomobject]@{
                PrerequisiteRoot=$PrerequisiteRoot;PrerequisiteManifest=$inputObject.prerequisite_manifest
                AgentRunner={param($Executable)& $Executable -s};AddRunner={param($KeyPath)& $candidateAgentManifest.git_ssh_add_path $KeyPath}
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
        'Assemble' {
            New-P3PrerequisiteReceipt -Manifest $inputObject.manifest -ServerBaseline $inputObject.server_baseline `
                -CloudObservation $inputObject.cloud_firewall -EgressObservations @($inputObject.egress) -NowUtc ([DateTime]::UtcNow) |
                ConvertTo-Json -Depth 20 -Compress
        }
        'Validate' {
            Test-P3PrerequisiteReceipt -Receipt $inputObject.receipt -Manifest $inputObject.manifest -NowUtc ([DateTime]::UtcNow) |
                ConvertTo-Json -Depth 20 -Compress
        }
        default { throw 'prerequisite action requires the approved injected execution boundary' }
    }
}
