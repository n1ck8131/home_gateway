[CmdletBinding()]
param(
    [ValidateSet('', 'ValidateOnly', 'Reconcile', 'GuardAdmin', 'GuardGuest', 'ClientObserve', 'EmergencyRollbackPlan', 'EmergencyRollback',
        'ManagementReceiptPlan', 'ManagementReceiptRecord', 'ManagementReceiptConsume',
        'GuestProfilePlan', 'GuestProfileInspect', 'GuestProfileConsume')]
    [string]$Action = '',
    [string]$RuntimeRoot,
    [string]$ExpectedManifestSHA256,
    [string]$ExpectedPlanSHA256,
    [string]$Confirmation,
    [string]$EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:P3HelperPath = '/usr/local/libexec/home-gateway-p3-peer-guard'
$script:P3ReconcileProperties = @(
    'atomic_leftover_count', 'candidate_leftover_count', 'container_count', 'container_identity_sha256',
    'container_restart_count_sha256', 'container_running', 'host_policy_loaded', 'host_policy_sha256',
    'image_identity_sha256', 'install_receipt_sha256', 'ipv6_non_mutation', 'listener_identity_sha256',
    'manifest_sha256', 'nonce_sha256', 'payload_sha256', 'peer_count', 'peer_set_sha256',
    'protocol_sha256', 'public_listener_class_count', 'schema', 'server_baseline_sha256',
    'temporary_leftover_count', 'udp_publication_count', 'udp_publication_sha256'
)
$script:P3ClientProperties = @(
    'after_counter_sha256', 'before_counter_sha256', 'handshake_fresh', 'nonce_sha256',
    'observation_duration_seconds', 'payload_sha256', 'protocol_sha256', 'schema',
    'selected_guest_match', 'traffic_delta'
)
$script:P3ReadyEventProperties = @(
    'event', 'nonce_sha256', 'operation', 'payload_sha256', 'pre_peer_count',
    'pre_peer_set_sha256', 'protocol_sha256', 'reconcile_sha256', 'schema'
)
$script:P3CandidateEventProperties = @(
    'candidate_count', 'candidate_fingerprint_sha256', 'container_restart_delta',
    'emergency_rollback_ready', 'event', 'firewall_equal', 'listeners_equal', 'nonce_sha256',
    'official_ui_rollback_ready', 'operation', 'payload_sha256', 'persistent_live_metadata_equal',
    'post_peer_set_sha256', 'pre_peer_set_sha256', 'protocol_sha256', 'schema',
    'semantic_transition_count'
)
$script:P3StoppedEventProperties = @(
    'event', 'nonce_sha256', 'operation', 'payload_sha256', 'protocol_sha256', 'reason', 'schema'
)
$script:P3LocalGuardProperties = @(
    'candidate_fingerprint_sha256', 'candidate_received', 'live_mutation_performed', 'nonce_sha256',
    'operation', 'post_peer_set_sha256', 'pre_peer_set_sha256', 'ready_emitted', 'schema'
)
$script:P3RollbackObservationProperties = @(
    'candidate_fingerprint_sha256', 'candidate_receipt_sha256', 'live_peer_set_sha256',
    'metadata_sha256', 'peer_fingerprint_sha256', 'peer_set_sha256', 'persistent_config_sha256',
    'prepared_syncconf_sha256', 'runtime_identity_sha256', 'schema', 'temporary_state_sha256'
)
$script:P3EmergencyReceiptProperties = @(
    'candidate_fingerprint_sha256', 'candidate_receipt_sha256', 'install_receipt_sha256',
    'manifest_sha256', 'one_syncconf', 'payload_sha256', 'protocol_sha256', 'restored',
    'rollback_plan_sha256', 'schema', 'temporary_leftover_count'
)
$script:P3GuardEgressReceiptProperties = @(
    'live_mutation_performed', 'management_source_cidr_sha256', 'observations', 'observed_at_utc', 'schema'
)
$script:P3ManagementOperationReceiptProperties = @(
    'schema', 'manifest_sha256', 'candidate_receipt_sha256', 'client_binary_sha256', 'client_version_sha256',
    'source_mapping_sha256', 'ui_action_class_sha256', 'selected_entry_sha256', 'candidate_nonce_sha256',
    'pre_peer_set_sha256', 'post_peer_set_sha256', 'candidate_fingerprint_sha256', 'runtime_identity_sha256',
    'observed_at_utc', 'owner_observed', 'server_role_confirmed', 'classification', 'raw_identity_exposed', 'consumed'
)
$script:P3GuestProfileReceiptProperties = @(
    'schema', 'manifest_sha256', 'candidate_receipt_sha256', 'profile_sha256', 'profile_file_identity_sha256',
    'profile_acl_identity_sha256', 'candidate_nonce_sha256', 'pre_peer_set_sha256', 'post_peer_set_sha256',
    'derived_public_fingerprint_sha256', 'runtime_identity_sha256', 'observed_at_utc', 'raw_key_exposed', 'consumed'
)
$script:P3GuardEgressObservationProperties = @('authority_sha256', 'observed_at_utc', 'source_cidr_sha256')

function Get-P3GuardTextSHA256([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-P3GuardSHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label hash differs" }
}

function Assert-P3GuardExactProperties([object]$Value, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Value -or $Value -is [Array]) { throw "$Label schema differs" }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject ($Expected | Sort-Object) -DifferenceObject $actual).Count -ne 0) { throw "$Label schema differs" }
}

function ConvertTo-P3GuardCanonicalValue([object]$Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)) {
            $ordered[$key] = ConvertTo-P3GuardCanonicalValue $Value[$key]
        }
        return $ordered
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)) {
            $ordered[$property] = ConvertTo-P3GuardCanonicalValue $Value.$property
        }
        return $ordered
    }
    if ($Value -is [Array]) {
        $array = @()
        foreach ($item in $Value) { $array += ,(ConvertTo-P3GuardCanonicalValue $item) }
        return $array
    }
    return $Value
}

function Get-P3GuardCanonicalSHA256([object]$Value) {
    $json = ConvertTo-Json -InputObject (ConvertTo-P3GuardCanonicalValue $Value) -Depth 32 -Compress
    return Get-P3GuardTextSHA256 $json
}

function Get-P3GuardUtc([object]$Value, [string]$Label) {
    if ($Value -is [DateTime]) {
        $date = [DateTime]$Value
        if ($date.Kind -eq [DateTimeKind]::Unspecified) { $date = [DateTime]::SpecifyKind($date, [DateTimeKind]::Utc) }
        return $date.ToUniversalTime()
    }
    try { return [DateTime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
    catch { throw "$Label timestamp differs" }
}

function Assert-P3GuardReceiptFresh([object]$Value, [DateTime]$NowUtc, [string]$Label) {
    $observed = Get-P3GuardUtc -Value $Value -Label $Label
    $now = $NowUtc.ToUniversalTime()
    if ($observed -gt $now.AddSeconds(5) -or $observed -lt $now.AddMinutes(-10)) { throw "$Label is stale" }
    return $observed
}

function New-P3ManagementOperationContextReceipt(
    [string]$ManifestSHA256, [string]$CandidateReceiptSHA256, [string]$ClientBinarySHA256,
    [string]$ClientVersionSHA256, [string]$SourceMappingSHA256, [string]$UiActionClassSHA256,
    [string]$SelectedEntrySHA256, [string]$CandidateNonceSHA256, [string]$PrePeerSetSHA256,
    [string]$PostPeerSetSHA256, [string]$CandidateFingerprintSHA256, [string]$RuntimeIdentitySHA256,
    [DateTime]$NowUtc
) {
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -ne 'NowUtc') { Assert-P3GuardSHA256 ([string]$entry.Value) $entry.Key }
    }
    return [pscustomobject][ordered]@{
        schema='home-gateway/p3-management-operation-context-receipt/v1';manifest_sha256=$ManifestSHA256
        candidate_receipt_sha256=$CandidateReceiptSHA256;client_binary_sha256=$ClientBinarySHA256
        client_version_sha256=$ClientVersionSHA256;source_mapping_sha256=$SourceMappingSHA256
        ui_action_class_sha256=$UiActionClassSHA256;selected_entry_sha256=$SelectedEntrySHA256
        candidate_nonce_sha256=$CandidateNonceSHA256;pre_peer_set_sha256=$PrePeerSetSHA256
        post_peer_set_sha256=$PostPeerSetSHA256;candidate_fingerprint_sha256=$CandidateFingerprintSHA256
        runtime_identity_sha256=$RuntimeIdentitySHA256;observed_at_utc=$NowUtc.ToUniversalTime().ToString('o')
        owner_observed=$true;server_role_confirmed=$false;classification='source_pinned_management_operation'
        raw_identity_exposed=$false;consumed=$false
    }
}

function Test-P3ManagementOperationContextReceipt(
    [object]$Receipt, [string]$ExpectedManifestSHA256, [string]$ExpectedCandidateReceiptSHA256,
    [string]$ExpectedUiActionClassSHA256, [DateTime]$NowUtc
) {
    Assert-P3GuardExactProperties $Receipt $script:P3ManagementOperationReceiptProperties 'management operation context receipt'
    foreach ($name in $script:P3ManagementOperationReceiptProperties | Where-Object { $_ -match '_sha256$' }) {
        Assert-P3GuardSHA256 ([string]$Receipt.$name) $name
    }
    $null = Assert-P3GuardReceiptFresh $Receipt.observed_at_utc $NowUtc 'management operation context receipt'
    if ([string]$Receipt.schema -cne 'home-gateway/p3-management-operation-context-receipt/v1' -or
        [string]$Receipt.manifest_sha256 -cne $ExpectedManifestSHA256 -or
        [string]$Receipt.candidate_receipt_sha256 -cne $ExpectedCandidateReceiptSHA256 -or
        [string]$Receipt.ui_action_class_sha256 -cne $ExpectedUiActionClassSHA256 -or
        -not [bool]$Receipt.owner_observed -or [bool]$Receipt.server_role_confirmed -or
        [string]$Receipt.classification -cne 'source_pinned_management_operation' -or
        [bool]$Receipt.raw_identity_exposed -or [bool]$Receipt.consumed) { throw 'management operation context receipt differs' }
    return $Receipt
}

function New-P3GuestProfileIdentityReceipt(
    [string]$ManifestSHA256, [string]$CandidateReceiptSHA256, [string]$ProfileSHA256,
    [string]$ProfileFileIdentitySHA256, [string]$ProfileAclIdentitySHA256, [string]$CandidateNonceSHA256,
    [string]$PrePeerSetSHA256, [string]$PostPeerSetSHA256, [string]$DerivedPublicFingerprintSHA256,
    [string]$CandidateFingerprintSHA256, [string]$RuntimeIdentitySHA256, [DateTime]$NowUtc
) {
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -ne 'NowUtc') { Assert-P3GuardSHA256 ([string]$entry.Value) $entry.Key }
    }
    if ($DerivedPublicFingerprintSHA256 -cne $CandidateFingerprintSHA256) { throw 'Guest derived public fingerprint differs' }
    return [pscustomobject][ordered]@{
        schema='home-gateway/p3-guest-profile-identity-receipt/v1';manifest_sha256=$ManifestSHA256
        candidate_receipt_sha256=$CandidateReceiptSHA256;profile_sha256=$ProfileSHA256
        profile_file_identity_sha256=$ProfileFileIdentitySHA256;profile_acl_identity_sha256=$ProfileAclIdentitySHA256
        candidate_nonce_sha256=$CandidateNonceSHA256;pre_peer_set_sha256=$PrePeerSetSHA256
        post_peer_set_sha256=$PostPeerSetSHA256;derived_public_fingerprint_sha256=$DerivedPublicFingerprintSHA256
        runtime_identity_sha256=$RuntimeIdentitySHA256;observed_at_utc=$NowUtc.ToUniversalTime().ToString('o')
        raw_key_exposed=$false;consumed=$false
    }
}

function Test-P3GuestProfileIdentityReceipt(
    [object]$Receipt, [string]$ExpectedManifestSHA256, [string]$ExpectedCandidateReceiptSHA256,
    [string]$ExpectedCandidateFingerprintSHA256, [string]$ExpectedProfileAclIdentitySHA256 = '', [DateTime]$NowUtc
) {
    Assert-P3GuardExactProperties $Receipt $script:P3GuestProfileReceiptProperties 'Guest profile identity receipt'
    foreach ($name in $script:P3GuestProfileReceiptProperties | Where-Object { $_ -match '_sha256$' }) {
        Assert-P3GuardSHA256 ([string]$Receipt.$name) $name
    }
    $null = Assert-P3GuardReceiptFresh $Receipt.observed_at_utc $NowUtc 'Guest profile identity receipt'
    if ([string]$Receipt.schema -cne 'home-gateway/p3-guest-profile-identity-receipt/v1' -or
        [string]$Receipt.manifest_sha256 -cne $ExpectedManifestSHA256 -or
        [string]$Receipt.candidate_receipt_sha256 -cne $ExpectedCandidateReceiptSHA256 -or
        [string]$Receipt.derived_public_fingerprint_sha256 -cne $ExpectedCandidateFingerprintSHA256 -or
        (-not [string]::IsNullOrEmpty($ExpectedProfileAclIdentitySHA256) -and
            [string]$Receipt.profile_acl_identity_sha256 -cne $ExpectedProfileAclIdentitySHA256) -or
        [bool]$Receipt.raw_key_exposed -or [bool]$Receipt.consumed) { throw 'Guest profile identity receipt differs' }
    return $Receipt
}

function Import-P3GuardRuntime {
    if ($null -eq (Get-Command Resolve-P3FixedCleanPath -ErrorAction SilentlyContinue)) {
        $savedAction = $Action
        try { . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1') }
        finally { $Action = $savedAction }
    }
}

function Get-P3EvidenceFileFacts([string]$Path, [int]$MaximumBytes, [string]$Label) {
    Import-P3GuardRuntime
    $resolved = Assert-P3RegularFile $Path $Label
    $stream = [IO.File]::Open($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) { throw "$Label size differs" }
        $identity = Get-P3StreamIdentity $stream
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $contentSHA256 = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        $acl = Get-Acl -LiteralPath $resolved -ErrorAction Stop
        $aclText = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
        return [pscustomobject]@{
            path=$resolved;content_sha256=$contentSHA256
            file_identity_sha256=Get-P3GuardTextSHA256 $identity
            acl_identity_sha256=Get-P3GuardTextSHA256 $aclText
        }
    } finally { $stream.Dispose() }
}

function New-P3ProtectedEvidencePlan([string]$Kind, [string]$Root, [object]$InputObject) {
    Import-P3GuardRuntime
    if ($Kind -notin @('management','guest')) { throw 'protected evidence kind differs' }
    $resolvedRoot = Resolve-P3FixedCleanPath $Root 'protected evidence root'
    Assert-P3GuardExactProperties $InputObject @(
        'candidate_fingerprint_sha256','candidate_nonce_sha256','candidate_receipt','manifest_sha256',
        'post_peer_set_sha256','pre_peer_set_sha256','runtime_identity_sha256','subject'
    ) 'protected evidence plan input'
    Assert-P3GuardExactProperties $InputObject.candidate_receipt $script:P3LocalGuardProperties 'candidate receipt'
    $expectedOperation = if($Kind -ceq 'management'){'admin'}else{'guest'}
    if([string]$InputObject.candidate_receipt.schema -cne 'home-gateway/p3-local-guard-receipt/v2' -or
        [string]$InputObject.candidate_receipt.operation -cne $expectedOperation -or
        -not [bool]$InputObject.candidate_receipt.ready_emitted -or -not [bool]$InputObject.candidate_receipt.candidate_received -or
        [bool]$InputObject.candidate_receipt.live_mutation_performed){throw 'protected evidence candidate differs'}
    $candidateReceiptSHA256 = Get-P3GuardCanonicalSHA256 $InputObject.candidate_receipt
    foreach ($name in @('candidate_fingerprint_sha256','candidate_nonce_sha256','manifest_sha256','post_peer_set_sha256',
            'pre_peer_set_sha256','runtime_identity_sha256')) { Assert-P3GuardSHA256 ([string]$InputObject.$name) $name }
    if ([string]$InputObject.candidate_receipt.candidate_fingerprint_sha256 -cne [string]$InputObject.candidate_fingerprint_sha256 -or
        [string]$InputObject.candidate_receipt.nonce_sha256 -cne [string]$InputObject.candidate_nonce_sha256 -or
        [string]$InputObject.candidate_receipt.pre_peer_set_sha256 -cne [string]$InputObject.pre_peer_set_sha256 -or
        [string]$InputObject.candidate_receipt.post_peer_set_sha256 -cne [string]$InputObject.post_peer_set_sha256) {
        throw 'protected evidence candidate differs'
    }
    $identity = [ordered]@{
        schema='home-gateway/p3-protected-evidence-plan/v1';kind=$Kind;evidence_root=$resolvedRoot
        manifest_sha256=[string]$InputObject.manifest_sha256;candidate_receipt_sha256=$candidateReceiptSHA256
        candidate_nonce_sha256=[string]$InputObject.candidate_nonce_sha256;pre_peer_set_sha256=[string]$InputObject.pre_peer_set_sha256
        post_peer_set_sha256=[string]$InputObject.post_peer_set_sha256;candidate_fingerprint_sha256=[string]$InputObject.candidate_fingerprint_sha256
        runtime_identity_sha256=[string]$InputObject.runtime_identity_sha256
    }
    if ($Kind -ceq 'management') {
        Assert-P3GuardExactProperties $InputObject.subject @(
            'client_binary_path','client_version_sha256','selected_entry_sha256','source_mapping_sha256','ui_action_class_sha256'
        ) 'management evidence subject'
        $client = Get-P3EvidenceFileFacts ([string]$InputObject.subject.client_binary_path) 67108864 'management client binary'
        foreach ($name in @('client_version_sha256','selected_entry_sha256','source_mapping_sha256','ui_action_class_sha256')) {
            Assert-P3GuardSHA256 ([string]$InputObject.subject.$name) $name
        }
        $identity.client_binary_path=$client.path;$identity.client_binary_sha256=$client.content_sha256
        $identity.client_binary_file_identity_sha256=$client.file_identity_sha256;$identity.client_binary_acl_identity_sha256=$client.acl_identity_sha256
        foreach ($name in @('client_version_sha256','selected_entry_sha256','source_mapping_sha256','ui_action_class_sha256')) {
            $identity[$name]=[string]$InputObject.subject.$name
        }
    } else {
        Assert-P3GuardExactProperties $InputObject.subject @('hgctl_path','profile_path') 'Guest evidence subject'
        $hgctl = Get-P3EvidenceFileFacts ([string]$InputObject.subject.hgctl_path) 67108864 'pinned hgctl'
        $profile = Get-P3EvidenceFileFacts ([string]$InputObject.subject.profile_path) 1048576 'protected Guest profile'
        $identity.hgctl_path=$hgctl.path;$identity.hgctl_sha256=$hgctl.content_sha256
        $identity.hgctl_file_identity_sha256=$hgctl.file_identity_sha256;$identity.hgctl_acl_identity_sha256=$hgctl.acl_identity_sha256
        $identity.profile_path=$profile.path;$identity.profile_sha256=$profile.content_sha256
        $identity.profile_file_identity_sha256=$profile.file_identity_sha256;$identity.profile_acl_identity_sha256=$profile.acl_identity_sha256
    }
    $planSHA256 = Get-P3GuardCanonicalSHA256 ([pscustomobject]$identity)
    $plan = [ordered]@{};foreach($pair in $identity.GetEnumerator()){$plan[$pair.Key]=$pair.Value}
    $plan.plan_sha256=$planSHA256;$plan.confirmation_challenge='P3-EVIDENCE-' + $planSHA256.Substring(0,16).ToUpperInvariant()
    return [pscustomobject]$plan
}

function Assert-P3ProtectedEvidenceRoot([string]$Root, [object]$Plan, [string[]]$ExpectedFiles) {
    Import-P3GuardRuntime
    $resolved = Resolve-P3FixedCleanPath $Root 'protected evidence root'
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'protected evidence root differs' }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $resolved -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value) { throw 'protected evidence ACL differs' }
    $marker = [Text.Encoding]::UTF8.GetString((Read-P3BoundedStableBytes (Join-Path $resolved '.home-gateway-p3-evidence-owner.v1') 128 'evidence marker'))
    if ($marker -cne 'home-gateway/p3-protected-evidence-owner/v1') { throw 'protected evidence marker differs' }
    $storedPlan = Open-P3BoundedStableJson (Join-Path $resolved 'plan.json') 65536 @($Plan.PSObject.Properties.Name)
    if ((Get-P3GuardCanonicalSHA256 $storedPlan) -cne (Get-P3GuardCanonicalSHA256 $Plan)) { throw 'protected evidence plan differs' }
    $candidatePath=Join-Path $resolved 'candidate-receipt.json'
    $storedCandidate=Open-P3BoundedStableJson $candidatePath 65536 $script:P3LocalGuardProperties
    if((Get-P3ExactFileSHA256 $candidatePath 'protected candidate receipt') -cne [string]$Plan.candidate_receipt_sha256 -or
        [string]$storedCandidate.candidate_fingerprint_sha256 -cne [string]$Plan.candidate_fingerprint_sha256 -or
        [string]$storedCandidate.nonce_sha256 -cne [string]$Plan.candidate_nonce_sha256 -or
        [string]$storedCandidate.pre_peer_set_sha256 -cne [string]$Plan.pre_peer_set_sha256 -or
        [string]$storedCandidate.post_peer_set_sha256 -cne [string]$Plan.post_peer_set_sha256){throw 'protected evidence candidate differs'}
    $children=@(Get-ChildItem -LiteralPath $resolved -Force)
    foreach($child in $children){if($child.Name -notin $ExpectedFiles -or $child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'foreign protected evidence content is present'}}
    foreach($name in $ExpectedFiles){if(-not [IO.File]::Exists((Join-Path $resolved $name))){throw 'required protected evidence file is missing'}}
    return $resolved
}

function Initialize-P3ProtectedEvidenceRoot([string]$Root, [object]$Plan, [object]$CandidateReceipt) {
    Import-P3GuardRuntime
    $resolved = Resolve-P3FixedCleanPath $Root 'protected evidence root'
    if ([IO.File]::Exists($resolved) -or [IO.Directory]::Exists($resolved)) { throw 'protected evidence root already exists' }
    $null=[IO.Directory]::CreateDirectory($resolved)
    try {
        Set-Acl -LiteralPath $resolved -AclObject (New-P3RuntimeAcl) -ErrorAction Stop
        $marker=[Text.UTF8Encoding]::new($false).GetBytes('home-gateway/p3-protected-evidence-owner/v1')
        $null=Install-P3ExactRuntimeFile $marker (Join-Path $resolved '.home-gateway-p3-evidence-owner.v1') (Get-P3SHA256Bytes $marker)
        $planBytes=ConvertTo-P3CanonicalJson $Plan;$null=Install-P3ExactRuntimeFile $planBytes (Join-Path $resolved 'plan.json') (Get-P3SHA256Bytes $planBytes)
        $candidateBytes=ConvertTo-P3CanonicalJson $CandidateReceipt
        if((Get-P3SHA256Bytes $candidateBytes) -cne [string]$Plan.candidate_receipt_sha256){throw 'protected evidence candidate differs'}
        $null=Install-P3ExactRuntimeFile $candidateBytes (Join-Path $resolved 'candidate-receipt.json') ([string]$Plan.candidate_receipt_sha256)
        return Assert-P3ProtectedEvidenceRoot $resolved $Plan @('.home-gateway-p3-evidence-owner.v1','plan.json','candidate-receipt.json')
    } catch { if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)};throw }
}

function Invoke-P3ProtectedEvidenceAction(
    [string]$SelectedAction,[string]$Root,[object]$InputObject,[string]$ExpectedPlanSHA256,[string]$Confirmation,[object]$Boundaries
) {
    $savedEvidenceAction = $Action
    $savedEvidenceExpectedPlan = $ExpectedPlanSHA256
    $savedEvidenceConfirmation = $Confirmation
    . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
    $Action = $savedEvidenceAction
    $ExpectedPlanSHA256 = $savedEvidenceExpectedPlan
    $Confirmation = $savedEvidenceConfirmation
    $kind = if($SelectedAction.StartsWith('Management',[StringComparison]::Ordinal)){'management'}else{'guest'}
    if($SelectedAction -in @('ManagementReceiptPlan','GuestProfilePlan')){return New-P3ProtectedEvidencePlan $kind $Root $InputObject}
    Assert-P3GuardExactProperties $InputObject @('candidate_receipt','plan') 'protected evidence action input'
    $plan=$InputObject.plan;$identity=[ordered]@{};foreach($property in $plan.PSObject.Properties){if($property.Name -notin @('plan_sha256','confirmation_challenge')){$identity[$property.Name]=$property.Value}}
    if((Get-P3GuardCanonicalSHA256 ([pscustomobject]$identity)) -cne [string]$plan.plan_sha256){throw 'protected evidence plan identity differs'}
    if([string]$plan.plan_sha256 -cne $ExpectedPlanSHA256){throw 'protected evidence expected plan differs'}
    if([string]$plan.confirmation_challenge -cne $Confirmation -or $Confirmation -cnotmatch '^P3-EVIDENCE-[0-9A-F]{16}$'){throw 'protected evidence confirmation differs'}
    if([string]$plan.kind -cne $kind -or [string]$plan.evidence_root -cne (Resolve-P3FixedCleanPath $Root 'protected evidence root')){throw 'protected evidence approval differs'}
    if($SelectedAction.EndsWith('Consume',[StringComparison]::Ordinal)){
        $expected=@('.home-gateway-p3-evidence-owner.v1','plan.json','candidate-receipt.json','receipt.json')
        $resolved=Assert-P3ProtectedEvidenceRoot $Root $plan $expected
        $receiptPath=Join-Path $resolved 'receipt.json';$receiptSHA256=Get-P3ExactFileSHA256 $receiptPath 'protected evidence receipt'
        $receiptProperties=if($kind -ceq 'management'){$script:P3ManagementOperationReceiptProperties}else{$script:P3GuestProfileReceiptProperties}
        $storedReceipt=Open-P3BoundedStableJson $receiptPath 65536 $receiptProperties
        $now=([DateTime](& $Boundaries.ClockRunner)).ToUniversalTime()
        if($kind -ceq 'management'){
            $current=Get-P3EvidenceFileFacts ([string]$plan.client_binary_path) 67108864 'management client binary'
            if($current.content_sha256 -cne [string]$plan.client_binary_sha256 -or $current.file_identity_sha256 -cne [string]$plan.client_binary_file_identity_sha256 -or
                $current.acl_identity_sha256 -cne [string]$plan.client_binary_acl_identity_sha256){throw 'management client binary differs'}
            $null=Test-P3ManagementOperationContextReceipt $storedReceipt $plan.manifest_sha256 $plan.candidate_receipt_sha256 $plan.ui_action_class_sha256 $now
        }else{
            $profile=Get-P3EvidenceFileFacts ([string]$plan.profile_path) 1048576 'protected Guest profile';$hgctl=Get-P3EvidenceFileFacts ([string]$plan.hgctl_path) 67108864 'pinned hgctl'
            if($profile.content_sha256 -cne [string]$plan.profile_sha256 -or $profile.file_identity_sha256 -cne [string]$plan.profile_file_identity_sha256 -or
                $profile.acl_identity_sha256 -cne [string]$plan.profile_acl_identity_sha256 -or $hgctl.content_sha256 -cne [string]$plan.hgctl_sha256 -or
                $hgctl.file_identity_sha256 -cne [string]$plan.hgctl_file_identity_sha256 -or $hgctl.acl_identity_sha256 -cne [string]$plan.hgctl_acl_identity_sha256){throw 'Guest inspection input differs'}
            $null=Test-P3GuestProfileIdentityReceipt $storedReceipt $plan.manifest_sha256 $plan.candidate_receipt_sha256 $plan.candidate_fingerprint_sha256 $plan.profile_acl_identity_sha256 $now
        }
        $marker=[pscustomobject][ordered]@{receipt_sha256=$receiptSHA256;schema='home-gateway/p3-protected-evidence-consumption/v1'}
        $bytes=ConvertTo-P3CanonicalJson $marker;$null=Install-P3ExactRuntimeFile $bytes (Join-Path $resolved 'consumed.json') (Get-P3SHA256Bytes $bytes)
        $null=Assert-P3ProtectedEvidenceRoot $Root $plan @($expected+'consumed.json')
        return $marker
    }
    $resolved=Initialize-P3ProtectedEvidenceRoot $Root $plan $InputObject.candidate_receipt
    try {
        $now=([DateTime](& $Boundaries.ClockRunner)).ToUniversalTime()
        if($kind -ceq 'management'){
            $current=Get-P3EvidenceFileFacts ([string]$plan.client_binary_path) 67108864 'management client binary'
            if($current.content_sha256 -cne [string]$plan.client_binary_sha256 -or $current.file_identity_sha256 -cne [string]$plan.client_binary_file_identity_sha256 -or $current.acl_identity_sha256 -cne [string]$plan.client_binary_acl_identity_sha256){throw 'management client binary differs'}
            $receipt=New-P3ManagementOperationContextReceipt -ManifestSHA256 $plan.manifest_sha256 -CandidateReceiptSHA256 $plan.candidate_receipt_sha256 `
                -ClientBinarySHA256 $plan.client_binary_sha256 -ClientVersionSHA256 $plan.client_version_sha256 -SourceMappingSHA256 $plan.source_mapping_sha256 `
                -UiActionClassSHA256 $plan.ui_action_class_sha256 -SelectedEntrySHA256 $plan.selected_entry_sha256 -CandidateNonceSHA256 $plan.candidate_nonce_sha256 `
                -PrePeerSetSHA256 $plan.pre_peer_set_sha256 -PostPeerSetSHA256 $plan.post_peer_set_sha256 -CandidateFingerprintSHA256 $plan.candidate_fingerprint_sha256 `
                -RuntimeIdentitySHA256 $plan.runtime_identity_sha256 -NowUtc $now
        }else{
            $profile=Get-P3EvidenceFileFacts ([string]$plan.profile_path) 1048576 'protected Guest profile';$hgctl=Get-P3EvidenceFileFacts ([string]$plan.hgctl_path) 67108864 'pinned hgctl'
            if($profile.content_sha256 -cne [string]$plan.profile_sha256 -or $profile.file_identity_sha256 -cne [string]$plan.profile_file_identity_sha256 -or $profile.acl_identity_sha256 -cne [string]$plan.profile_acl_identity_sha256 -or
                $hgctl.content_sha256 -cne [string]$plan.hgctl_sha256 -or $hgctl.file_identity_sha256 -cne [string]$plan.hgctl_file_identity_sha256 -or
                $hgctl.acl_identity_sha256 -cne [string]$plan.hgctl_acl_identity_sha256){throw 'Guest inspection input differs'}
            $result=& $Boundaries.ProfileInspectorRunner $plan.hgctl_path @('tunnel','inspect','--config',$plan.profile_path,'--config-sha256',$plan.profile_sha256,'--json') 30 65536
            $null=Test-P3ProcessResult $result 65536 'Guest profile inspector'
            $profileAfter=Get-P3EvidenceFileFacts ([string]$plan.profile_path) 1048576 'protected Guest profile';$hgctlAfter=Get-P3EvidenceFileFacts ([string]$plan.hgctl_path) 67108864 'pinned hgctl'
            if($profileAfter.content_sha256 -cne $profile.content_sha256 -or $profileAfter.file_identity_sha256 -cne $profile.file_identity_sha256 -or
                $profileAfter.acl_identity_sha256 -cne $profile.acl_identity_sha256 -or $hgctlAfter.content_sha256 -cne $hgctl.content_sha256 -or
                $hgctlAfter.file_identity_sha256 -cne $hgctl.file_identity_sha256){throw 'Guest inspection input changed'}
            try{$inspection=ConvertFrom-Json ([string]$result.StdOut) -ErrorAction Stop}catch{throw 'Guest profile inspection receipt differs'}
            Assert-P3GuardExactProperties $inspection @('capabilities','interface_public_fingerprint_sha256','metadata','status') 'Guest profile inspection receipt'
            Assert-P3GuardSHA256 ([string]$inspection.interface_public_fingerprint_sha256) 'Guest derived public fingerprint'
            $receipt=New-P3GuestProfileIdentityReceipt -ManifestSHA256 $plan.manifest_sha256 -CandidateReceiptSHA256 $plan.candidate_receipt_sha256 `
                -ProfileSHA256 $plan.profile_sha256 -ProfileFileIdentitySHA256 $plan.profile_file_identity_sha256 -ProfileAclIdentitySHA256 $plan.profile_acl_identity_sha256 `
                -CandidateNonceSHA256 $plan.candidate_nonce_sha256 -PrePeerSetSHA256 $plan.pre_peer_set_sha256 -PostPeerSetSHA256 $plan.post_peer_set_sha256 `
                -DerivedPublicFingerprintSHA256 $inspection.interface_public_fingerprint_sha256 -CandidateFingerprintSHA256 $plan.candidate_fingerprint_sha256 `
                -RuntimeIdentitySHA256 $plan.runtime_identity_sha256 -NowUtc $now
            $result.StdOut='';$inspection=$null
        }
        $bytes=ConvertTo-P3CanonicalJson $receipt;$hash=Get-P3SHA256Bytes $bytes;$null=Install-P3ExactRuntimeFile $bytes (Join-Path $resolved 'receipt.json') $hash
        $reopened=Open-P3BoundedStableJson (Join-Path $resolved 'receipt.json') 65536 @($receipt.PSObject.Properties.Name)
        if($reopened.observed_at_utc -is [DateTime]){$reopened.observed_at_utc=([DateTime]$reopened.observed_at_utc).ToUniversalTime().ToString('o')}
        if((Get-P3GuardCanonicalSHA256 $reopened) -cne (Get-P3GuardCanonicalSHA256 $receipt)){throw 'protected evidence receipt differs'}
        $null=Assert-P3ProtectedEvidenceRoot $Root $plan @('.home-gateway-p3-evidence-owner.v1','plan.json','candidate-receipt.json','receipt.json')
        return $reopened
    }catch{if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)};throw}
}

function Test-P3GuardExactEgressReceipt([object]$Receipt, [object[]]$ExpectedEgress, [string]$ExpectedSource, [DateTime]$NowUtc) {
    $savedAction = $Action
    try {
        . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
        return Test-P3ExactEgressReceipt -Receipt $Receipt -ExpectedAuthoritySHA256 @($ExpectedEgress.authority_sha256) `
            -ExpectedManagementSourceCIDRSHA256 $ExpectedSource -NowUtc $NowUtc
    } finally { $Action = $savedAction }
}

function Test-P3PreliveInputs([object]$Context, [DateTime]$NowUtc) {
    $clock = $NowUtc.ToUniversalTime()
    foreach ($name in @(
        'ManifestSHA256', 'PayloadSHA256', 'ProtocolSHA256', 'InstallReceiptSHA256',
        'ExpectedServerBaselineSHA256', 'ExpectedCloudFirewallSHA256', 'ExpectedContainerIdentitySHA256',
        'ExpectedImageIdentitySHA256', 'ExpectedUdpPublicationSHA256', 'ExpectedListenerIdentitySHA256',
        'ExpectedHostPolicySHA256', 'ExpectedPeerSetSHA256'
    )) { Assert-P3GuardSHA256 -Value ([string]$Context.$name) -Label $name }
    if ([int]$Context.ExpectedPeerCount -lt 0 -or [int]$Context.ExpectedPeerCount -gt 1024) { throw 'expected peer count differs' }
    if ([string]$Context.Trust.ssh_user -cne 'homegateway') { throw 'SSH user differs' }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse([string]$Context.Trust.ssh_host, [ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'SSH host differs' }
    Assert-P3GuardSHA256 -Value ([string]$Context.Trust.management_source_cidr_sha256) -Label 'management source'
    $egress = @($Context.Trust.egress)
    if ($egress.Count -ne 3 -or @($egress.authority_sha256 | Select-Object -Unique).Count -ne 3) { throw 'egress authority set differs' }
    foreach ($item in $egress) {
        Assert-P3GuardSHA256 -Value ([string]$item.authority_sha256) -Label 'egress authority'
        if ([string]$item.source_cidr_sha256 -cne [string]$Context.Trust.management_source_cidr_sha256) { throw 'egress source consensus differs' }
    }
    if ([string]$Context.Agent.schema -cne 'home-gateway/p3-ssh-agent-combined-receipt/v2' -or
        [int]$Context.Agent.loaded_key_count -ne 1 -or -not [bool]$Context.Agent.expected_key_match -or
        -not [bool]$Context.Agent.toolchain_match -or [int]$Context.Agent.agent_pid -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$Context.Agent.socket) -or
        [string]$Context.Agent.manifest_sha256 -cne [string]$Context.ManifestSHA256) { throw 'agent validation differs' }
    if ([string]$Context.Install.schema -cne 'home-gateway/p3-remote-helper-install-receipt/v1' -or
        [string]$Context.Install.target_state -cne 'exact' -or [string]$Context.Install.payload_sha256 -cne [string]$Context.PayloadSHA256 -or
        -not [bool]$Context.Install.owner_match -or -not [bool]$Context.Install.group_match -or -not [bool]$Context.Install.mode_match -or
        [int]$Context.Install.temporary_leftover_count -ne 0) { throw 'install receipt differs' }
    if ([string]$Context.CloudFirewall.schema -cne 'home-gateway/p3-prelive-cloud-firewall-receipt/v1' -or
        [string]$Context.CloudFirewall.cloud_firewall_identity_sha256 -cne [string]$Context.ExpectedCloudFirewallSHA256 -or
        [int]$Context.CloudFirewall.droplet_association_count -ne 1 -or [int]$Context.CloudFirewall.inbound_rule_count -ne 2 -or
        -not [bool]$Context.CloudFirewall.owner_observed -or [bool]$Context.CloudFirewall.server_confirmed -or
        [bool]$Context.CloudFirewall.live_mutation_performed) { throw 'Cloud Firewall receipt differs' }
    $cloudObserved = Get-P3GuardUtc $Context.CloudFirewall.observed_at_utc 'Cloud Firewall'
    $cloudAge = ($clock - $cloudObserved).TotalSeconds
    if ($cloudAge -lt 0 -or $cloudAge -gt 900) { throw 'Cloud Firewall receipt is stale' }
    if ([string]$Context.LocalBaseline.schema -cne 'home-gateway/p3-prelive-local-baseline-receipt/v1' -or
        -not [bool]$Context.LocalBaseline.protected_profile_absent -or [int]$Context.LocalBaseline.selfhosted_adapter_count -ne 0 -or
        [bool]$Context.LocalBaseline.live_mutation_performed) { throw 'local baseline receipt differs' }
    $localAge = ($clock - (Get-P3GuardUtc $Context.LocalBaseline.observed_at_utc 'local baseline')).TotalSeconds
    if ($localAge -lt 0 -or $localAge -gt 300) { throw 'local baseline receipt is stale' }
    if ($Context.PSObject.Properties.Name -notcontains 'EgressReceipt') { throw 'egress receipt schema differs' }
    $null = Test-P3GuardExactEgressReceipt -Receipt $Context.EgressReceipt -ExpectedEgress $egress `
        -ExpectedSource ([string]$Context.Trust.management_source_cidr_sha256) -NowUtc $clock
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-prelive-input-validation/v1'
        manifest_sha256 = [string]$Context.ManifestSHA256
        prelive_inputs_valid = $true
        cloud_firewall_owner_observed = $true
        local_profile_absent = $true
        selfhosted_adapter_count = 0
        loaded_key_count = 1
        live_mutation_performed = $false
    }
}

function Assert-P3GuardExternalFiles([object]$Context) {
    if ($Context.PSObject.Properties.Name -notcontains 'ExternalFilesBound' -or -not [bool]$Context.ExternalFilesBound) { return }
    foreach ($entry in @(
        @('known_hosts_path', 'known_hosts_sha256', 'known-hosts'),
        @('git_ssh_path', 'git_ssh_sha256', 'Git ssh'),
        @('git_scp_path', 'git_scp_sha256', 'Git scp'),
        @('local_payload_path', 'local_payload_sha256', 'local payload')
    )) {
        $actual = Get-P3ExactFileSHA256 -Path ([string]$Context.Trust.($entry[0])) -Label $entry[2]
        if ($actual -cne [string]$Context.Trust.($entry[1])) { throw "$($entry[2]) final hash differs" }
    }
}

function New-P3RemoteRequest(
    [object]$Context,
    [string]$Mode,
    [string]$Operation,
    [string]$Nonce,
    [string]$SelectedGuestFingerprintSHA256 = '',
    [string]$PreviousNonceSHA256 = '',
    [object]$RollbackPlan = $null
) {
    if ($Mode -notin @('attest', 'reconcile', 'guard', 'client-observe', 'emergency-rollback')) { throw 'remote request mode differs' }
    if ($Nonce -cnotmatch '^[0-9A-Fa-f]{64}$') { throw 'remote request nonce differs' }
    $nonceValue = $Nonce.ToLowerInvariant()
    $request = [ordered]@{
        schema = 'home-gateway/p3-peer-guard-request/v2'
        mode = $Mode
        payload_sha256 = [string]$Context.PayloadSHA256
        protocol_sha256 = [string]$Context.ProtocolSHA256
        manifest_sha256 = [string]$Context.ManifestSHA256
        install_receipt_sha256 = [string]$Context.InstallReceiptSHA256
        nonce = $nonceValue
    }
    if ($Mode -in @('reconcile', 'guard')) {
        if ([string]$Context.Rollback.persistent_config_path -cne '/opt/amnezia/awg/awg0.conf' -or
            [string]$Context.Rollback.metadata_path -cne '/opt/amnezia/awg/clientsTable' -or
            [string]$Context.Rollback.temporary_path -cne '/tmp/p3-candidate-{nonce32}.tmp' -or
            [string]$Context.Rollback.syncconf_path -cne '/opt/amnezia/awg/awg0.conf') { throw 'rollback paths differ' }
        $request.expected_container_identity_sha256 = [string]$Context.ExpectedContainerIdentitySHA256
        $request.expected_image_identity_sha256 = [string]$Context.ExpectedImageIdentitySHA256
        $request.expected_udp_publication_sha256 = [string]$Context.ExpectedUdpPublicationSHA256
        $request.expected_listener_identity_sha256 = [string]$Context.ExpectedListenerIdentitySHA256
        $request.expected_host_policy_sha256 = [string]$Context.ExpectedHostPolicySHA256
        $request.expected_peer_count = [int]$Context.ExpectedPeerCount
        $request.expected_peer_set_sha256 = [string]$Context.ExpectedPeerSetSHA256
        $request.expected_server_baseline_sha256 = [string]$Context.ExpectedServerBaselineSHA256
        $request.expected_firewall_identity_sha256 = [string]$Context.ExpectedCloudFirewallSHA256
        $request.expected_ipv6_policy_sha256 = [string]$Context.ExpectedIPv6PolicySHA256
        $request.persistent_config_path = [string]$Context.Rollback.persistent_config_path
        $request.metadata_path = [string]$Context.Rollback.metadata_path
        $request.temporary_path = '/tmp/p3-candidate-' + $nonceValue.Substring(0, 32) + '.tmp'
    }
    if ($Mode -ceq 'guard') {
        if ($Operation -notin @('admin', 'guest')) { throw 'remote guard operation differs' }
        $request.operation = $Operation
        $request.candidate_class = $Operation
        $request.maximum_guard_seconds = 180
    }
    if ($Mode -ceq 'client-observe') {
        foreach ($pair in @(
            @($SelectedGuestFingerprintSHA256, 'selected Guest'), @($PreviousNonceSHA256, 'previous nonce')
        )) { Assert-P3GuardSHA256 -Value ([string]$pair[0]) -Label $pair[1] }
        $request.previous_nonce_sha256 = $PreviousNonceSHA256
        $request.selected_guest_fingerprint_sha256 = $SelectedGuestFingerprintSHA256
        $request.maximum_handshake_age_seconds = 180
    }
    if ($Mode -ceq 'emergency-rollback') {
        if ($null -eq $RollbackPlan) { throw 'emergency rollback plan is required' }
        foreach ($property in $RollbackPlan.PSObject.Properties) {
            if ($property.Name -eq 'plan_sha256') { $request.rollback_plan_sha256 = $property.Value }
            elseif ($property.Name -notin @('schema', 'confirmation_challenge')) { $request[$property.Name] = $property.Value }
        }
        $request.confirmation = [string]$RollbackPlan.confirmation_challenge
    }
    return [pscustomobject]$request
}

function New-P3GuardSshArguments([object]$Context, [string]$Mode, [string]$Operation) {
    $remote = @('sudo', '-n', $script:P3HelperPath, $Mode)
    if ($Mode -ceq 'guard') { $remote += $Operation }
    return @(
        '-F', 'NUL', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no', '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$($Context.Trust.known_hosts_path)", '-o', 'GlobalKnownHostsFile=NUL',
        '-o', "IdentityAgent=$($Context.Agent.socket)", '-o', 'ConnectTimeout=10',
        "$($Context.Trust.ssh_user)@$($Context.Trust.ssh_host)"
    ) + $remote
}

function Test-P3ProcessResult([object]$Result, [int]$MaximumBytes, [string]$Label) {
    if ([bool]$Result.TimedOut) { throw "$Label timed out" }
    $stdoutBytes = [Text.Encoding]::UTF8.GetByteCount([string]$Result.StdOut)
    $stderrBytes = [Text.Encoding]::UTF8.GetByteCount([string]$Result.StdErr)
    if ([bool]$Result.Oversized -or ($stdoutBytes + $stderrBytes) -gt $MaximumBytes) { throw "$Label output exceeds its bound" }
    if ($stderrBytes -ne 0) { throw "$Label emitted stderr" }
    if ([int]$Result.ExitCode -ne 0) { throw "$Label transport failed" }
}

function Assert-P3ReconcileReceipt([object]$Context, [object]$Request, [object]$Receipt) {
    Assert-P3GuardExactProperties -Value $Receipt -Expected $script:P3ReconcileProperties -Label 'reconcile receipt'
    if ([string]$Receipt.schema -cne 'home-gateway/p3-peer-reconcile-receipt/v2' -or
        [string]$Receipt.payload_sha256 -cne [string]$Context.PayloadSHA256 -or
        [string]$Receipt.protocol_sha256 -cne [string]$Context.ProtocolSHA256 -or
        [string]$Receipt.manifest_sha256 -cne [string]$Context.ManifestSHA256 -or
        [string]$Receipt.install_receipt_sha256 -cne [string]$Context.InstallReceiptSHA256 -or
        [string]$Receipt.nonce_sha256 -cne (Get-P3GuardTextSHA256 ([string]$Request.nonce))) { throw 'reconcile receipt binding differs' }
    if ([int]$Receipt.container_count -ne 1 -or -not [bool]$Receipt.container_running -or
        [string]$Receipt.container_identity_sha256 -cne [string]$Context.ExpectedContainerIdentitySHA256 -or
        [string]$Receipt.image_identity_sha256 -cne [string]$Context.ExpectedImageIdentitySHA256 -or
        [int]$Receipt.udp_publication_count -ne 1 -or [string]$Receipt.udp_publication_sha256 -cne [string]$Context.ExpectedUdpPublicationSHA256 -or
        [string]$Receipt.listener_identity_sha256 -cne [string]$Context.ExpectedListenerIdentitySHA256 -or
        -not [bool]$Receipt.host_policy_loaded -or [string]$Receipt.host_policy_sha256 -cne [string]$Context.ExpectedHostPolicySHA256 -or
        -not [bool]$Receipt.ipv6_non_mutation -or [int]$Receipt.peer_count -ne [int]$Context.ExpectedPeerCount -or
        [string]$Receipt.peer_set_sha256 -cne [string]$Context.ExpectedPeerSetSHA256 -or
        [int]$Receipt.candidate_leftover_count -ne 0 -or [int]$Receipt.temporary_leftover_count -ne 0 -or [int]$Receipt.atomic_leftover_count -ne 0 -or
        [string]$Receipt.server_baseline_sha256 -cne [string]$Context.ExpectedServerBaselineSHA256) { throw 'reconcile receipt fact differs' }
    return $Receipt
}

function Assert-P3ClientReceipt([object]$Context, [object]$Request, [object]$Receipt) {
    Assert-P3GuardExactProperties -Value $Receipt -Expected $script:P3ClientProperties -Label 'client observation receipt'
    if ([string]$Receipt.schema -cne 'home-gateway/p3-peer-client-observe/v2') { throw 'client observation schema differs' }
    if ([string]$Receipt.payload_sha256 -cne [string]$Context.PayloadSHA256 -or [string]$Receipt.protocol_sha256 -cne [string]$Context.ProtocolSHA256) { throw 'client observation payload or protocol differs' }
    if ([string]$Receipt.nonce_sha256 -cne (Get-P3GuardTextSHA256 ([string]$Request.nonce))) { throw 'client observation nonce differs' }
    if (-not [bool]$Receipt.selected_guest_match) { throw 'client observation selected Guest differs' }
    if (-not [bool]$Receipt.handshake_fresh) { throw 'client observation handshake differs' }
    Assert-P3GuardSHA256 -Value ([string]$Receipt.before_counter_sha256) -Label 'before counter'
    Assert-P3GuardSHA256 -Value ([string]$Receipt.after_counter_sha256) -Label 'after counter'
    if ([string]$Receipt.before_counter_sha256 -ceq [string]$Receipt.after_counter_sha256) { throw 'client observation counter hash differs' }
    if (-not [bool]$Receipt.traffic_delta -or [int]$Receipt.observation_duration_seconds -ne 10) { throw 'client observation traffic delta differs' }
    return $Receipt
}

function Assert-P3EmergencyReceipt([object]$Context, [object]$Request, [object]$Receipt) {
    Assert-P3GuardExactProperties -Value $Receipt -Expected $script:P3EmergencyReceiptProperties -Label 'emergency rollback receipt'
    if ([string]$Receipt.schema -cne 'home-gateway/p3-peer-emergency-rollback/v2' -or
        [string]$Receipt.payload_sha256 -cne [string]$Context.PayloadSHA256 -or
        [string]$Receipt.protocol_sha256 -cne [string]$Context.ProtocolSHA256 -or
        [string]$Receipt.manifest_sha256 -cne [string]$Context.ManifestSHA256 -or
        [string]$Receipt.install_receipt_sha256 -cne [string]$Context.InstallReceiptSHA256 -or
        [string]$Receipt.candidate_receipt_sha256 -cne [string]$Request.candidate_receipt_sha256 -or
        [string]$Receipt.rollback_plan_sha256 -cne [string]$Request.rollback_plan_sha256 -or
        [string]$Receipt.candidate_fingerprint_sha256 -cne [string]$Request.candidate_fingerprint_sha256 -or
        -not [bool]$Receipt.one_syncconf -or -not [bool]$Receipt.restored -or
        [int]$Receipt.temporary_leftover_count -ne 0) { throw 'emergency rollback receipt binding differs' }
    return $Receipt
}

function Invoke-P3BoundedJsonSsh([object]$Context, [object]$Request, [int]$TimeoutSeconds, [int]$MaximumBytes, [scriptblock]$Runner) {
    $null = Test-P3PreliveInputs -Context $Context -NowUtc ([DateTime]::UtcNow)
    Assert-P3GuardExternalFiles -Context $Context
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 190 -or $MaximumBytes -lt 256 -or $MaximumBytes -gt 65536) { throw 'bounded SSH limits differ' }
    if ($null -eq $Runner) { $Runner = $script:P3NativeJsonRunner }
    $operation = if ($Request.PSObject.Properties.Name -contains 'operation') { [string]$Request.operation } else { '' }
    $arguments = New-P3GuardSshArguments -Context $Context -Mode ([string]$Request.mode) -Operation $operation
    $json = ConvertTo-Json -InputObject $Request -Depth 32 -Compress
    $result = & $Runner ([string]$Context.Trust.git_ssh_path) $arguments $json $TimeoutSeconds $MaximumBytes
    Test-P3ProcessResult -Result $result -MaximumBytes $MaximumBytes -Label 'bounded SSH'
    try { $receipt = ConvertFrom-Json -InputObject ([string]$result.StdOut) -ErrorAction Stop } catch { throw 'bounded SSH receipt is malformed' }
    if ([string]$Request.mode -ceq 'reconcile') { return Assert-P3ReconcileReceipt -Context $Context -Request $Request -Receipt $receipt }
    if ([string]$Request.mode -ceq 'client-observe') { return Assert-P3ClientReceipt -Context $Context -Request $Request -Receipt $receipt }
    if ([string]$Request.mode -ceq 'emergency-rollback') { return Assert-P3EmergencyReceipt -Context $Context -Request $Request -Receipt $receipt }
    return $receipt
}

function Assert-P3ReadyEvent([object]$Context, [object]$Request, [object]$Event) {
    Assert-P3GuardExactProperties -Value $Event -Expected $script:P3ReadyEventProperties -Label 'ready event'
    if ([string]$Event.event -cne 'ready_for_ui' -or [string]$Event.schema -cne 'home-gateway/p3-peer-guard-event/v2' -or
        [string]$Event.operation -cne [string]$Request.operation -or [string]$Event.payload_sha256 -cne [string]$Context.PayloadSHA256 -or
        [string]$Event.protocol_sha256 -cne [string]$Context.ProtocolSHA256 -or [string]$Event.nonce_sha256 -cne (Get-P3GuardTextSHA256 ([string]$Request.nonce)) -or
        [int]$Event.pre_peer_count -ne [int]$Context.ExpectedPeerCount -or [string]$Event.pre_peer_set_sha256 -cne [string]$Context.ExpectedPeerSetSHA256) { throw 'ready event binding differs' }
    Assert-P3GuardSHA256 -Value ([string]$Event.reconcile_sha256) -Label 'ready reconcile'
}

function Assert-P3CandidateEvent([object]$Context, [object]$Request, [object]$Event) {
    Assert-P3GuardExactProperties -Value $Event -Expected $script:P3CandidateEventProperties -Label 'candidate event'
    if ([string]$Event.event -cne 'candidate' -or [string]$Event.schema -cne 'home-gateway/p3-peer-guard-event/v2' -or
        [string]$Event.operation -cne [string]$Request.operation -or [string]$Event.payload_sha256 -cne [string]$Context.PayloadSHA256 -or
        [string]$Event.protocol_sha256 -cne [string]$Context.ProtocolSHA256 -or [string]$Event.nonce_sha256 -cne (Get-P3GuardTextSHA256 ([string]$Request.nonce)) -or
        [int]$Event.candidate_count -ne 1 -or [string]$Event.pre_peer_set_sha256 -cne [string]$Context.ExpectedPeerSetSHA256 -or
        -not [bool]$Event.persistent_live_metadata_equal -or [int]$Event.semantic_transition_count -ne 1 -or
        [int]$Event.container_restart_delta -ne 0 -or -not [bool]$Event.firewall_equal -or -not [bool]$Event.listeners_equal -or
        -not [bool]$Event.official_ui_rollback_ready -or -not [bool]$Event.emergency_rollback_ready) { throw 'candidate event binding differs' }
    Assert-P3GuardSHA256 -Value ([string]$Event.candidate_fingerprint_sha256) -Label 'candidate fingerprint'
    Assert-P3GuardSHA256 -Value ([string]$Event.post_peer_set_sha256) -Label 'candidate post set'
}

function Invoke-P3GuardStream([object]$Context, [string]$Operation, [string]$Nonce, [scriptblock]$Runner) {
    $null = Test-P3PreliveInputs -Context $Context -NowUtc ([DateTime]::UtcNow)
    Assert-P3GuardExternalFiles -Context $Context
    $request = New-P3RemoteRequest -Context $Context -Mode 'guard' -Operation $Operation -Nonce $Nonce
    $arguments = New-P3GuardSshArguments -Context $Context -Mode 'guard' -Operation $Operation
    $inputJson = ConvertTo-Json -InputObject $request -Depth 32 -Compress
    $state = @{ Phase = 'initial'; Ready = $false; Candidate = $null; Stopped = $false; Bytes = 0 }
    $onEvent = {
        param([string]$Line, [bool]$ChildAlive)
        $state.Bytes += [Text.Encoding]::UTF8.GetByteCount($Line) + 1
        if ($state.Bytes -gt 65536) { throw 'guard stream output exceeds its bound' }
        try { $event = ConvertFrom-Json -InputObject $Line -ErrorAction Stop } catch { throw 'guard stream event is malformed' }
        if ([string]$event.event -ceq 'ready_for_ui') {
            if ($state.Phase -cne 'initial' -or -not $ChildAlive) { throw 'guard ready event order differs' }
            Assert-P3ReadyEvent -Context $Context -Request $request -Event $event
            $state.Phase = 'ready'; $state.Ready = $true
            [Console]::Out.WriteLine('READY_FOR_UI=YES')
            return
        }
        if ([string]$event.event -ceq 'candidate') {
            if ($state.Phase -cne 'ready' -or -not $ChildAlive) { throw 'guard candidate event order differs' }
            Assert-P3CandidateEvent -Context $Context -Request $request -Event $event
            $state.Phase = 'candidate'; $state.Candidate = $event
            return
        }
        if ([string]$event.event -ceq 'stopped') {
            Assert-P3GuardExactProperties -Value $event -Expected $script:P3StoppedEventProperties -Label 'stopped event'
            if ($state.Phase -cne 'ready') { throw 'guard stopped event order differs' }
            $state.Stopped = $true; $state.Phase = 'stopped'
            return
        }
        throw 'guard stream event type differs'
    }
    if ($null -eq $Runner) { $Runner = $script:P3NativeStreamRunner }
    $terminal = & $Runner ([string]$Context.Trust.git_ssh_path) $arguments $inputJson $onEvent 190 65536
    if ([bool]$terminal.TimedOut) { throw 'guard stream timed out' }
    if ([bool]$terminal.Oversized) { throw 'guard stream output exceeds its bound' }
    if ([bool]$terminal.PartialLine) { throw 'guard stream ended with a partial line' }
    if ([Text.Encoding]::UTF8.GetByteCount([string]$terminal.StdErr) -ne 0) { throw 'guard stream emitted stderr' }
    if ([int]$terminal.ExitCode -ne 0) { throw 'guard stream transport failed' }
    if ($state.Stopped) { throw 'guard stream stopped without an accepted candidate' }
    if (-not $state.Ready -or $null -eq $state.Candidate -or $state.Phase -cne 'candidate') { throw 'guard stream ended before one candidate' }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-local-guard-receipt/v2'
        operation = $Operation
        ready_emitted = $true
        candidate_received = $true
        candidate_fingerprint_sha256 = [string]$state.Candidate.candidate_fingerprint_sha256
        pre_peer_set_sha256 = [string]$state.Candidate.pre_peer_set_sha256
        post_peer_set_sha256 = [string]$state.Candidate.post_peer_set_sha256
        nonce_sha256 = Get-P3GuardTextSHA256 ([string]$request.nonce)
        live_mutation_performed = $false
    }
}

function New-P3EmergencyRollbackPlan([object]$Context, [object]$CandidateReceipt, [object]$CurrentReceipt, [string]$Nonce) {
    $null = Test-P3PreliveInputs -Context $Context -NowUtc ([DateTime]::UtcNow)
    Assert-P3GuardSHA256 -Value $Nonce -Label 'emergency rollback nonce'
    $nonceValue = $Nonce.ToLowerInvariant()
    if ([string]$Context.Rollback.persistent_config_path -cne '/opt/amnezia/awg/awg0.conf' -or
        [string]$Context.Rollback.metadata_path -cne '/opt/amnezia/awg/clientsTable' -or
        [string]$Context.Rollback.temporary_path -cne '/tmp/p3-candidate-{nonce32}.tmp' -or
        [string]$Context.Rollback.syncconf_path -cne '/opt/amnezia/awg/awg0.conf') { throw 'rollback paths differ' }
    Assert-P3GuardExactProperties -Value $CandidateReceipt -Expected $script:P3LocalGuardProperties -Label 'candidate receipt'
    Assert-P3GuardExactProperties -Value $CurrentReceipt -Expected $script:P3RollbackObservationProperties -Label 'rollback observation'
    foreach ($name in @('candidate_fingerprint_sha256', 'post_peer_set_sha256', 'pre_peer_set_sha256')) { Assert-P3GuardSHA256 -Value ([string]$CandidateReceipt.$name) -Label $name }
    $candidateReceiptSHA256 = Get-P3GuardCanonicalSHA256 $CandidateReceipt
    if ([string]$CurrentReceipt.schema -cne 'home-gateway/p3-peer-rollback-observation/v2' -or
        [string]$CurrentReceipt.candidate_receipt_sha256 -cne $candidateReceiptSHA256 -or
        [string]$CurrentReceipt.candidate_fingerprint_sha256 -cne [string]$CandidateReceipt.candidate_fingerprint_sha256 -or
        [string]$CurrentReceipt.peer_set_sha256 -cne [string]$CandidateReceipt.post_peer_set_sha256 -or
        [string]$CurrentReceipt.live_peer_set_sha256 -cne [string]$CandidateReceipt.post_peer_set_sha256) { throw 'emergency rollback current candidate differs' }
    $prePeers = @($Context.ExpectedPeerFingerprints | Sort-Object)
    $postPeers = @($CurrentReceipt.peer_fingerprint_sha256 | Sort-Object)
    if ($postPeers.Count -ne ($prePeers.Count + 1) -or @($postPeers | Where-Object { $_ -notin ($prePeers + @([string]$CandidateReceipt.candidate_fingerprint_sha256)) }).Count -ne 0) { throw 'emergency rollback peer delta differs' }
    $identity = [pscustomobject][ordered]@{
        nonce = $nonceValue
        manifest_sha256 = [string]$Context.ManifestSHA256
        payload_sha256 = [string]$Context.PayloadSHA256
        protocol_sha256 = [string]$Context.ProtocolSHA256
        install_receipt_sha256 = [string]$Context.InstallReceiptSHA256
        candidate_receipt_sha256 = $candidateReceiptSHA256
        candidate_fingerprint_sha256 = [string]$CandidateReceipt.candidate_fingerprint_sha256
        pre_peer_fingerprint_sha256 = $prePeers
        post_peer_fingerprint_sha256 = $postPeers
        baseline_peer_set_sha256 = [string]$CandidateReceipt.pre_peer_set_sha256
        persistent_config_path = [string]$Context.Rollback.persistent_config_path
        metadata_path = [string]$Context.Rollback.metadata_path
        temporary_path = '/tmp/p3-candidate-' + $nonceValue.Substring(0, 32) + '.tmp'
        syncconf_path = '/opt/amnezia/awg/awg0.conf'
        prepared_syncconf_sha256 = [string]$CurrentReceipt.prepared_syncconf_sha256
        pre_persistent_config_sha256 = [string]$CurrentReceipt.persistent_config_sha256
        pre_live_peer_set_sha256 = [string]$CurrentReceipt.live_peer_set_sha256
        pre_metadata_sha256 = [string]$CurrentReceipt.metadata_sha256
        pre_temporary_state_sha256 = [string]$CurrentReceipt.temporary_state_sha256
        pre_runtime_identity_sha256 = [string]$CurrentReceipt.runtime_identity_sha256
        baseline_persistent_config_sha256 = [string]$Context.BaselinePersistentConfigSHA256
        baseline_metadata_sha256 = [string]$Context.BaselineMetadataSHA256
        baseline_temporary_state_sha256 = [string]$Context.BaselineTemporaryStateSHA256
        baseline_runtime_identity_sha256 = [string]$Context.BaselineRuntimeIdentitySHA256
        baseline_ipv6_policy_sha256 = [string]$Context.ExpectedIPv6PolicySHA256
    }
    $hash = Get-P3GuardCanonicalSHA256 $identity
    $result = [ordered]@{ schema = 'home-gateway/p3-emergency-rollback-plan/v2' }
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result.plan_sha256 = $hash
    $result.confirmation_challenge = 'P3-EMERGENCY-ROLLBACK-' + $hash.Substring(0, 16).ToUpperInvariant()
    return [pscustomobject]$result
}

function Invoke-P3EmergencyRollback([object]$Context, [object]$Plan, [string]$ExpectedPlanSHA256, [string]$Confirmation, [scriptblock]$Runner) {
    $identity = [ordered]@{}
    foreach ($property in $Plan.PSObject.Properties) {
        if ($property.Name -notin @('schema', 'plan_sha256', 'confirmation_challenge')) { $identity[$property.Name] = $property.Value }
    }
    $computed = Get-P3GuardCanonicalSHA256 ([pscustomobject]$identity)
    if ([string]$Plan.schema -cne 'home-gateway/p3-emergency-rollback-plan/v2' -or $computed -cne [string]$Plan.plan_sha256 -or
        [string]$Plan.plan_sha256 -cne $ExpectedPlanSHA256 -or $Confirmation -cne [string]$Plan.confirmation_challenge -or
        $Confirmation -cnotmatch '^P3-EMERGENCY-ROLLBACK-[0-9A-F]{16}$') { throw 'emergency rollback approval differs' }
    Assert-P3GuardSHA256 -Value ([string]$Plan.nonce) -Label 'emergency rollback nonce'
    if ([string]$Plan.temporary_path -cne ('/tmp/p3-candidate-' + ([string]$Plan.nonce).Substring(0, 32) + '.tmp')) {
        throw 'emergency rollback approval differs'
    }
    $request = New-P3RemoteRequest -Context $Context -Mode 'emergency-rollback' -Operation '' -Nonce ([string]$Plan.nonce) -RollbackPlan $Plan
    return Invoke-P3BoundedJsonSsh -Context $Context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner $Runner
}

function Invoke-P3OwnedAgentLifecycle([scriptblock]$StartRunner, [scriptblock]$BodyRunner, [scriptblock]$StopRunner) {
    if ($null -eq $StartRunner -or $null -eq $BodyRunner -or $null -eq $StopRunner) { throw 'owned agent lifecycle runner differs' }
    $state = & $StartRunner
    if ($null -eq $state) { throw 'owned agent lifecycle start differs' }
    try {
        return & $BodyRunner $state
    } finally {
        & $StopRunner $state
    }
}

function ConvertTo-P3GuardNativeArgument([string]$Value) {
    if($null -eq $Value){$Value=''}
    if($Value.Length -gt 0 -and $Value -notmatch '[\s"]'){return $Value}
    $builder=[Text.StringBuilder]::new();$null=$builder.Append('"');$slashes=0
    foreach($character in $Value.ToCharArray()){
        if($character -eq '\'){$slashes++;continue}
        if($character -eq '"'){$null=$builder.Append(('\'*(($slashes*2)+1)));$null=$builder.Append('"');$slashes=0;continue}
        if($slashes -gt 0){$null=$builder.Append(('\'*$slashes));$slashes=0};$null=$builder.Append($character)
    }
    if($slashes -gt 0){$null=$builder.Append(('\'*($slashes*2)))};$null=$builder.Append('"');return $builder.ToString()
}

function Read-P3GuardBoundedUtf8Stdin([int]$MaximumBytes=131072){
    $stream=[Console]::OpenStandardInput();$memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(4096)
    try{
        while(($read=$stream.Read($buffer,0,$buffer.Length)) -gt 0){if($memory.Length+$read -gt $MaximumBytes){throw 'guard stdin exceeds bound'};$memory.Write($buffer,0,$read)}
        if($memory.Length -lt 2){throw 'guard stdin differs'}
        try{return [Text.UTF8Encoding]::new($false,$true).GetString($memory.ToArray())}catch{throw 'guard stdin UTF-8 differs'}
    }finally{$memory.Dispose()}
}

function Invoke-P3NativeJsonProcess([string]$Executable, [string[]]$Arguments, [string]$InputJson, [int]$TimeoutSeconds, [int]$MaximumBytes) {
    $inputBytes=[Text.UTF8Encoding]::new($false).GetBytes($InputJson)
    if($inputBytes.Length -lt 2 -or $inputBytes.Length -gt 131072 -or $TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 60 -or $MaximumBytes -lt 1024 -or $MaximumBytes -gt 65536){throw 'guard child boundary differs'}
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Executable;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $quotedArguments=@($Arguments|ForEach-Object{ConvertTo-P3GuardNativeArgument ([string]$_)})
    $start.Arguments=$quotedArguments -join ' '
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$stdout=[IO.MemoryStream]::new();$stderr=[IO.MemoryStream]::new()
    $watch=[Diagnostics.Stopwatch]::StartNew();$timedOut=$false;$oversized=$false;$writeClosed=$false
    try {
        if(-not $process.Start()){throw 'guard child start differs'}
        $writeTask=$process.StandardInput.BaseStream.WriteAsync($inputBytes,0,$inputBytes.Length)
        $outBuffer=[byte[]]::new(4096);$errBuffer=[byte[]]::new(4096);$outTask=$process.StandardOutput.BaseStream.ReadAsync($outBuffer,0,$outBuffer.Length);$errTask=$process.StandardError.BaseStream.ReadAsync($errBuffer,0,$errBuffer.Length)
        $outDone=$false;$errDone=$false
        while(-not $outDone -or -not $errDone -or -not $process.HasExited){
            if(-not $writeClosed -and $writeTask.IsCompleted){try{$null=$writeTask.GetAwaiter().GetResult()}catch{};$process.StandardInput.Close();$writeClosed=$true}
            foreach($channel in @('out','err')){
                $task=if($channel -ceq 'out'){$outTask}else{$errTask}
                if($null -ne $task -and $task.IsCompleted){
                    $count=$task.GetAwaiter().GetResult();$target=if($channel -ceq 'out'){$stdout}else{$stderr};$source=if($channel -ceq 'out'){$outBuffer}else{$errBuffer}
                    if($count -eq 0){if($channel -ceq 'out'){$outDone=$true;$outTask=$null}else{$errDone=$true;$errTask=$null}}
                    else{$remaining=$MaximumBytes-[int]($stdout.Length+$stderr.Length);if($count -gt $remaining){$oversized=$true;if($remaining -gt 0){$target.Write($source,0,$remaining)}}else{$target.Write($source,0,$count)}
                        if(-not $oversized){if($channel -ceq 'out'){$outTask=$process.StandardOutput.BaseStream.ReadAsync($outBuffer,0,$outBuffer.Length)}else{$errTask=$process.StandardError.BaseStream.ReadAsync($errBuffer,0,$errBuffer.Length)}}}
                }
            }
            if(($oversized -or $watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) -and -not $process.HasExited){if(-not $oversized){$timedOut=$true};$process.Kill()}
            if($oversized -and $process.HasExited){$outDone=$true;$errDone=$true}
            if(-not $outDone -or -not $errDone -or -not $process.HasExited){Start-Sleep -Milliseconds 5;$process.Refresh()}
        }
        if(-not $writeClosed){try{$null=$writeTask.GetAwaiter().GetResult()}catch{};$process.StandardInput.Close();$writeClosed=$true};$process.WaitForExit();$encoding=[Text.UTF8Encoding]::new($false,$true)
        return [pscustomobject]@{ExitCode=$process.ExitCode;TimedOut=$timedOut;Oversized=$oversized;StdOut=$(if($oversized){''}else{$encoding.GetString($stdout.ToArray())});StdErr=$(if($oversized){''}else{$encoding.GetString($stderr.ToArray())})}
    }finally{
        if(-not $writeClosed){try{$process.StandardInput.Close()}catch{}};if(-not $process.HasExited){$process.Kill();$process.WaitForExit()};$stdout.Dispose();$stderr.Dispose();$process.Dispose()
    }
}

function Invoke-P3NativeGuardStreamProcess(
    [string]$Executable, [string[]]$Arguments, [string]$InputJson, [scriptblock]$OnEvent,
    [int]$TimeoutSeconds, [int]$MaximumBytes,
    [scriptblock]$ProcessRunner = $null, [scriptblock]$KillRunner = $null, [scriptblock]$WaitRunner = $null
) {
    $inputPath = [IO.Path]::GetTempFileName(); $outputPath = [IO.Path]::GetTempFileName(); $errorPath = [IO.Path]::GetTempFileName()
    $process = $null; $waited = $false
    if ($null -eq $ProcessRunner) {
        $ProcessRunner = { param($Executable, $Arguments, $InputPath, $OutputPath, $ErrorPath) Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -RedirectStandardInput $InputPath -RedirectStandardOutput $OutputPath -RedirectStandardError $ErrorPath -PassThru }
    }
    if ($null -eq $KillRunner) { $KillRunner = { param($Process) $Process.Kill() } }
    if ($null -eq $WaitRunner) { $WaitRunner = { param($Process) $Process.WaitForExit() } }
    try {
        [IO.File]::WriteAllText($inputPath, $InputJson, [Text.UTF8Encoding]::new($false))
        $process = & $ProcessRunner $Executable $Arguments $inputPath $outputPath $errorPath
        if ($null -eq $process) { throw 'guard stream child start differs' }
        $watch = [Diagnostics.Stopwatch]::StartNew(); $processed = 0; $timedOut = $false; $oversized = $false
        while (-not $process.HasExited) {
            $length = ([IO.FileInfo]$outputPath).Length + ([IO.FileInfo]$errorPath).Length
            if ($length -gt $MaximumBytes) { $oversized = $true; & $KillRunner $process; break }
            if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $timedOut = $true; & $KillRunner $process; break }
            $text = [IO.File]::ReadAllText($outputPath, [Text.UTF8Encoding]::new($false, $true))
            $lines = @($text -split "`r?`n")
            $completeCount = if ($text.EndsWith("`n")) { $lines.Count - 1 } else { [Math]::Max(0, $lines.Count - 1) }
            while ($processed -lt $completeCount) { if (-not [string]::IsNullOrEmpty($lines[$processed])) { & $OnEvent $lines[$processed] (-not $process.HasExited) }; $processed++ }
            Start-Sleep -Milliseconds 50; $process.Refresh()
        }
        & $WaitRunner $process; $waited = $true
        $text = if ($oversized) { '' } else { [IO.File]::ReadAllText($outputPath, [Text.UTF8Encoding]::new($false, $true)) }
        $lines = @($text -split "`r?`n"); $endsNewline = $text.EndsWith("`n")
        $completeCount = if ($endsNewline) { $lines.Count - 1 } else { [Math]::Max(0, $lines.Count - 1) }
        while ($processed -lt $completeCount) { if (-not [string]::IsNullOrEmpty($lines[$processed])) { & $OnEvent $lines[$processed] $false }; $processed++ }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode; TimedOut = $timedOut; Oversized = $oversized
            StdErr = if ($oversized) { '' } else { [IO.File]::ReadAllText($errorPath, [Text.UTF8Encoding]::new($false, $true)) }
            PartialLine = (-not $endsNewline -and $text.Length -gt 0)
        }
    } catch {
        if ($null -ne $process -and -not [bool]$process.HasExited) { & $KillRunner $process }
        if ($null -ne $process -and -not $waited) { & $WaitRunner $process; $waited = $true }
        throw
    } finally {
        if ($null -ne $process -and -not [bool]$process.HasExited) { & $KillRunner $process }
        if ($null -ne $process -and -not $waited) { & $WaitRunner $process }
        foreach ($path in @($inputPath, $outputPath, $errorPath)) { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
    }
}

$script:P3NativeJsonRunner = { param($Executable, $Arguments, $InputJson, $TimeoutSeconds, $MaximumBytes) Invoke-P3NativeJsonProcess @PSBoundParameters }
$script:P3NativeStreamRunner = { param($Executable, $Arguments, $InputJson, $OnEvent, $TimeoutSeconds, $MaximumBytes) Invoke-P3NativeGuardStreamProcess @PSBoundParameters }

function Get-P3PreliveContext([string]$RuntimeRoot, [string]$ExpectedManifestSHA256) {
    $requestedRoot = $RuntimeRoot
    $requestedManifestSHA256 = $ExpectedManifestSHA256
    . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
    $null = Invoke-P3RuntimeValidate -RuntimeRoot $requestedRoot -ExpectedManifestSHA256 $requestedManifestSHA256
    $trust = Open-P3BoundedStableJson -Path (Join-Path $requestedRoot 'trust.json') -MaximumBytes 65536 -ExpectedProperties $script:P3TrustProperties
    $manifest = Open-P3BoundedStableJson -Path (Join-Path $requestedRoot 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
    $cloud = Open-P3BoundedStableJson -Path (Join-Path $requestedRoot 'cloud-firewall-receipt.json') -MaximumBytes 65536 -ExpectedProperties $script:P3CloudFirewallReceiptProperties
    $local = Open-P3BoundedStableJson -Path (Join-Path $requestedRoot 'local-baseline-receipt.json') -MaximumBytes 65536 -ExpectedProperties $script:P3LocalBaselineReceiptProperties
    $egressReceipt = Open-P3BoundedStableJson -Path (Join-Path $requestedRoot 'egress-receipt.json') -MaximumBytes 65536 -ExpectedProperties $script:P3EgressReceiptProperties
    $agent = Open-P3BoundedStableJson -Path (Join-Path $requestedRoot 'agent-receipt.json') -MaximumBytes 65536 -ExpectedProperties $script:P3CombinedAgentReceiptProperties
    $install = Open-P3BoundedStableJson -Path (Join-Path $requestedRoot 'remote-install-receipt.json') -MaximumBytes 65536 -ExpectedProperties $script:P3InstallReceiptProperties
    if ($trust.PSObject.Properties.Name -notcontains 'accepted_server_baseline') { throw 'protected trust lacks accepted server baseline details' }
    $baseline = $trust.accepted_server_baseline
    $egress = @()
    foreach ($observation in @($egressReceipt.observations)) {
        Assert-P3ExactProperties -Value $observation -ExpectedProperties $script:P3EgressObservationProperties -Label 'egress observation'
        $egress += [pscustomobject]@{ authority_sha256 = [string]$observation.authority_sha256; source_cidr_sha256 = [string]$observation.source_cidr_sha256 }
    }
    $peerFingerprints = @($baseline.peer_fingerprint_sha256)
    $peerSetSHA256 = [string]$baseline.persistent_peer_set_sha256
    if ([string]$baseline.live_peer_set_sha256 -cne $peerSetSHA256 -or [string]$baseline.metadata_peer_set_sha256 -cne $peerSetSHA256) { throw 'accepted peer set convergence differs' }
    $external = @(
        @($trust.known_hosts_path, $manifest.known_hosts_sha256, 'known-hosts'),
        @($trust.git_ssh_path, $manifest.git_ssh_sha256, 'Git ssh'),
        @($trust.git_scp_path, $manifest.git_scp_sha256, 'Git scp'),
        @($trust.local_payload_path, $manifest.local_payload_sha256, 'local payload')
    )
    foreach ($entry in $external) { if ((Get-P3ExactFileSHA256 -Path $entry[0] -Label $entry[2]) -cne $entry[1]) { throw "$($entry[2]) context hash differs" } }
    return [pscustomobject]@{
        ManifestSHA256 = $requestedManifestSHA256; PayloadSHA256 = $manifest.local_payload_sha256; ProtocolSHA256 = $manifest.protocol_sha256
        InstallReceiptSHA256 = Get-P3GuardCanonicalSHA256 $install; ExpectedServerBaselineSHA256 = $manifest.accepted_server_baseline_sha256
        ExpectedCloudFirewallSHA256 = $manifest.accepted_cloud_firewall_sha256; ExpectedContainerIdentitySHA256 = $baseline.container_identity_sha256
        ExpectedImageIdentitySHA256 = $baseline.image_identity_sha256; ExpectedUdpPublicationSHA256 = $baseline.udp_publication_sha256
        ExpectedListenerIdentitySHA256 = $baseline.listener_identity_sha256; ExpectedHostPolicySHA256 = $baseline.host_policy_sha256
        ExpectedIPv6PolicySHA256 = $baseline.ipv6_policy_sha256
        ExpectedPeerCount = $peerFingerprints.Count; ExpectedPeerSetSHA256 = $peerSetSHA256; ExpectedPeerFingerprints = $peerFingerprints
        BaselinePersistentConfigSHA256 = $baseline.persistent_config_sha256; BaselineMetadataSHA256 = $baseline.metadata_sha256
        BaselineTemporaryStateSHA256 = $baseline.temporary_state_sha256; BaselineRuntimeIdentitySHA256 = $baseline.runtime_identity_sha256
        Trust = [pscustomobject]@{
            ssh_user = $trust.ssh_user; ssh_host = $trust.ssh_host
            known_hosts_path = $trust.known_hosts_path; known_hosts_sha256 = $manifest.known_hosts_sha256
            git_ssh_path = $trust.git_ssh_path; git_ssh_sha256 = $manifest.git_ssh_sha256
            git_scp_path = $trust.git_scp_path; git_scp_sha256 = $manifest.git_scp_sha256
            local_payload_path = $trust.local_payload_path; local_payload_sha256 = $manifest.local_payload_sha256
            management_source_cidr_sha256 = $trust.management_source_cidr_sha256; egress = $egress
        }
        Agent = $agent; Install = $install; CloudFirewall = $cloud; LocalBaseline = $local
        EgressReceipt = $egressReceipt; Rollback = $trust.rollback_paths; ExternalFilesBound = $true
    }
}

function Invoke-P3ApprovedGuardBody(
    [string]$SelectedAction,
    [object]$Context,
    [object]$InputObject,
    [string]$ExpectedBodyPlanSHA256,
    [string]$BodyConfirmation,
    [object]$Boundaries
) {
    switch ($SelectedAction) {
        'ValidateOnly' { return Test-P3PreliveInputs -Context $Context -NowUtc (& $Boundaries.ClockRunner) }
        'Reconcile' {
            $nonce = ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
            $request = New-P3RemoteRequest -Context $Context -Mode 'reconcile' -Operation '' -Nonce $nonce
            return Invoke-P3BoundedJsonSsh -Context $Context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner $Boundaries.JsonRunner
        }
        'GuardAdmin' {
            return Invoke-P3GuardStream -Context $Context -Operation 'admin' `
                -Nonce (([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))) -Runner $Boundaries.StreamRunner
        }
        'GuardGuest' {
            return Invoke-P3GuardStream -Context $Context -Operation 'guest' `
                -Nonce (([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))) -Runner $Boundaries.StreamRunner
        }
        'ClientObserve' {
            $request = New-P3RemoteRequest -Context $Context -Mode 'client-observe' -Operation '' -Nonce ([string]$InputObject.nonce) `
                -SelectedGuestFingerprintSHA256 ([string]$InputObject.selected_guest_fingerprint_sha256) `
                -PreviousNonceSHA256 ([string]$InputObject.previous_nonce_sha256)
            return Invoke-P3BoundedJsonSsh -Context $Context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner $Boundaries.JsonRunner
        }
        'EmergencyRollbackPlan' {
            return New-P3EmergencyRollbackPlan -Context $Context -CandidateReceipt $InputObject.candidate `
                -CurrentReceipt $InputObject.current -Nonce ([string]$InputObject.nonce)
        }
        'EmergencyRollback' {
            return Invoke-P3EmergencyRollback -Context $Context -Plan $InputObject -ExpectedPlanSHA256 $ExpectedBodyPlanSHA256 `
                -Confirmation $BodyConfirmation -Runner $Boundaries.JsonRunner
        }
        default { throw 'owned guard action differs' }
    }
}

function Invoke-P3OwnedGuardAction(
    [string]$SelectedAction,
    [string]$RuntimeRoot,
    [string]$ExpectedManifestSHA256,
    [object]$InputObject,
    [string]$ExpectedBodyPlanSHA256,
    [string]$BodyConfirmation,
    [object]$Boundaries
) {
    if ($SelectedAction -notin @('ValidateOnly', 'Reconcile', 'GuardAdmin', 'GuardGuest', 'ClientObserve', 'EmergencyRollbackPlan', 'EmergencyRollback')) {
        throw 'owned guard action differs'
    }
    $requiredBoundaries = @(
        'AddRunner', 'AgentRunner', 'ClockRunner', 'DeleteRunner', 'JsonRunner', 'ListRunner', 'ProcessRunner',
        'ReceiptRemoveRunner', 'ReobserveRunner', 'SocketExistsRunner', 'StopRunner', 'StreamRunner', 'WaitRunner'
    )
    Assert-P3GuardExactProperties -Value $Boundaries -Expected $requiredBoundaries -Label 'owned guard boundaries'
    $ownedRoot = $RuntimeRoot
    $ownedManifestSHA256 = $ExpectedManifestSHA256
    $savedAction = $Action
    . (Join-Path $PSScriptRoot 'p3-ssh-agent.ps1')
    $Action = $savedAction
    $agentManifest = Get-P3ProtectedAgentManifest -Root $ownedRoot -ManifestSHA256 $ownedManifestSHA256
    $agentReceipt = Start-P3Agent -Manifest $agentManifest -AgentRunner $Boundaries.AgentRunner `
        -AddRunner $Boundaries.AddRunner -StopRunner $Boundaries.StopRunner
    $combined = $null
    $protectedCombined = $null
    try {
        $combined = Test-P3AgentState -Manifest $agentManifest -AgentReceipt $agentReceipt `
            -ListRunner $Boundaries.ListRunner -ProcessRunner $Boundaries.ProcessRunner
        Write-P3ProtectedAgentReceipt -Root $ownedRoot -ManifestSHA256 $ownedManifestSHA256 -Receipt $combined
        $reopenedCombined = Get-P3ProtectedAgentReceipt -Root $ownedRoot -ManifestSHA256 $ownedManifestSHA256
        if ((Get-P3AgentCanonicalSHA256 $reopenedCombined) -cne (Get-P3AgentCanonicalSHA256 $combined)) {
            throw 'protected agent receipt differs'
        }
        $protectedCombined = $reopenedCombined
        $context = Get-P3PreliveContext -RuntimeRoot $ownedRoot -ExpectedManifestSHA256 $ownedManifestSHA256
        return Invoke-P3ApprovedGuardBody -SelectedAction $SelectedAction -Context $context -InputObject $InputObject `
            -ExpectedBodyPlanSHA256 $ExpectedBodyPlanSHA256 -BodyConfirmation $BodyConfirmation -Boundaries $Boundaries
    }
    finally {
        if ($null -eq $protectedCombined) {
            Stop-P3OwnedAgentEmergency -Manifest $agentManifest -AgentReceipt $agentReceipt -DeleteRunner $Boundaries.DeleteRunner `
                -StopRunner $Boundaries.StopRunner -ProcessRunner $Boundaries.ProcessRunner `
                -WaitRunner $Boundaries.WaitRunner -ReobserveRunner $Boundaries.ReobserveRunner `
                -SocketExistsRunner $Boundaries.SocketExistsRunner | Out-Null
        } else {
            $storedCombined = Get-P3ProtectedAgentReceipt -Root $ownedRoot -ManifestSHA256 $ownedManifestSHA256
            if ((Get-P3AgentCanonicalSHA256 $storedCombined) -cne (Get-P3AgentCanonicalSHA256 $protectedCombined)) {
                throw 'protected agent receipt differs'
            }
            $storedReceipt = ConvertTo-P3AgentReceiptFromCombined -CombinedReceipt $storedCombined
            Stop-P3Agent -Manifest $agentManifest -AgentReceipt $storedReceipt -DeleteRunner $Boundaries.DeleteRunner `
                -StopRunner $Boundaries.StopRunner -ListRunner $Boundaries.ListRunner -ProcessRunner $Boundaries.ProcessRunner `
                -WaitRunner $Boundaries.WaitRunner -ReobserveRunner $Boundaries.ReobserveRunner `
                -SocketExistsRunner $Boundaries.SocketExistsRunner | Out-Null
            Remove-P3ProtectedAgentState -Root $ownedRoot -ManifestSHA256 $ownedManifestSHA256 -Receipt $storedCombined `
                -ReceiptRemoveRunner $Boundaries.ReceiptRemoveRunner
        }
    }
}

if (-not [string]::IsNullOrEmpty($Action)) {
    $selectedAction = $Action
    $evidenceActions=@('ManagementReceiptPlan','ManagementReceiptRecord','ManagementReceiptConsume','GuestProfilePlan','GuestProfileInspect','GuestProfileConsume')
    $inputObject = if ($selectedAction -in (@('ClientObserve', 'EmergencyRollbackPlan', 'EmergencyRollback') + $evidenceActions)) {
        ConvertFrom-Json (Read-P3GuardBoundedUtf8Stdin 131072) -ErrorAction Stop
    } else { $null }
    $boundaries = [pscustomobject]@{
        AgentRunner = { param($Executable) & $Executable -s }
        AddRunner = { param($KeyPath) & $agentManifest.git_ssh_add_path $KeyPath }
        ListRunner = { param($Executable) & $Executable -l -E sha256 }
        ProcessRunner = { param($ProcessId) Get-Process -Id $ProcessId -ErrorAction Stop | Select-Object Id, Path, StartTime }
        DeleteRunner = { & $agentManifest.git_ssh_add_path -D }
        StopRunner = { param($ProcessId) Stop-Process -Id $ProcessId -ErrorAction Stop }
        WaitRunner = {
            param($ProcessId)
            Wait-P3BoundedAgentExit -ProcessId $ProcessId `
                -ObserveRunner { param($OwnedProcessId) @(Get-Process -Id $OwnedProcessId -ErrorAction SilentlyContinue) } `
                -SleepRunner { param($Milliseconds) Start-Sleep -Milliseconds $Milliseconds } `
                -ClockRunner { [DateTime]::UtcNow } | Out-Null
        }
        ReobserveRunner = { param($ProcessId) @(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) }
        SocketExistsRunner = { param($Path) [IO.File]::Exists($Path) }
        ReceiptRemoveRunner = { param($Path) [IO.File]::Delete($Path) }
        JsonRunner = $script:P3NativeJsonRunner
        StreamRunner = $script:P3NativeStreamRunner
        ClockRunner = { [DateTime]::UtcNow }
    }
    if($selectedAction -in $evidenceActions){
        $boundaries | Add-Member -NotePropertyName ProfileInspectorRunner -NotePropertyValue {
            param($Executable,$Arguments,$TimeoutSeconds,$MaximumBytes)
            & $script:P3NativeJsonRunner $Executable $Arguments '{}' $TimeoutSeconds $MaximumBytes
        }
        $result=Invoke-P3ProtectedEvidenceAction -SelectedAction $selectedAction -Root $EvidenceRoot -InputObject $inputObject `
            -ExpectedPlanSHA256 $ExpectedPlanSHA256 -Confirmation $Confirmation -Boundaries $boundaries
    }else{
        $result = Invoke-P3OwnedGuardAction -SelectedAction $selectedAction -RuntimeRoot $RuntimeRoot `
            -ExpectedManifestSHA256 $ExpectedManifestSHA256 -InputObject $inputObject -ExpectedBodyPlanSHA256 $ExpectedPlanSHA256 `
            -BodyConfirmation $Confirmation -Boundaries $boundaries
    }
    if ($selectedAction -ceq 'Reconcile') { [Console]::Out.WriteLine('PRELIVE_READY=YES') }
    else { $result | ConvertTo-Json -Depth 32 -Compress }
}
