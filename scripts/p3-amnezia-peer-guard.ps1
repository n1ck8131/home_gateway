[CmdletBinding()]
param(
    [ValidateSet('', 'ValidateOnly', 'Reconcile', 'GuardAdmin', 'GuardGuest', 'ClientObserve', 'EmergencyRollbackPlan', 'EmergencyRollback')]
    [string]$Action = '',
    [string]$RuntimeRoot,
    [string]$ExpectedManifestSHA256,
    [string]$ExpectedPlanSHA256,
    [string]$Confirmation
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

function Get-P3GuardUtc([string]$Value, [string]$Label) {
    try { return [DateTime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
    catch { throw "$Label timestamp differs" }
}

function Test-P3PreliveInputs([object]$Context, [DateTime]$NowUtc) {
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
    if ([int]$Context.Agent.loaded_key_count -ne 1 -or -not [bool]$Context.Agent.expected_key_match -or
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
    $cloudAge = ($NowUtc.ToUniversalTime() - (Get-P3GuardUtc ([string]$Context.CloudFirewall.observed_at_utc) 'Cloud Firewall')).TotalSeconds
    if ($cloudAge -lt 0 -or $cloudAge -gt 900) { throw 'Cloud Firewall receipt is stale' }
    if ([string]$Context.LocalBaseline.schema -cne 'home-gateway/p3-prelive-local-baseline-receipt/v1' -or
        -not [bool]$Context.LocalBaseline.protected_profile_absent -or [int]$Context.LocalBaseline.selfhosted_adapter_count -ne 0 -or
        [bool]$Context.LocalBaseline.live_mutation_performed) { throw 'local baseline receipt differs' }
    $localAge = ($NowUtc.ToUniversalTime() - (Get-P3GuardUtc ([string]$Context.LocalBaseline.observed_at_utc) 'local baseline')).TotalSeconds
    if ($localAge -lt 0 -or $localAge -gt 300) { throw 'local baseline receipt is stale' }
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

function New-P3RemoteRequest(
    [object]$Context,
    [string]$Mode,
    [string]$Operation,
    [string]$Nonce,
    [string]$SelectedGuestFingerprintSHA256 = '',
    [string]$PreviousNonceSHA256 = '',
    [string]$ExpectedBeforeCounterSHA256 = '',
    [string]$ExpectedAfterCounterSHA256 = '',
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
        $request.expected_container_identity_sha256 = [string]$Context.ExpectedContainerIdentitySHA256
        $request.expected_image_identity_sha256 = [string]$Context.ExpectedImageIdentitySHA256
        $request.expected_udp_publication_sha256 = [string]$Context.ExpectedUdpPublicationSHA256
        $request.expected_listener_identity_sha256 = [string]$Context.ExpectedListenerIdentitySHA256
        $request.expected_host_policy_sha256 = [string]$Context.ExpectedHostPolicySHA256
        $request.expected_peer_count = [int]$Context.ExpectedPeerCount
        $request.expected_peer_set_sha256 = [string]$Context.ExpectedPeerSetSHA256
        $request.expected_server_baseline_sha256 = [string]$Context.ExpectedServerBaselineSHA256
    }
    if ($Mode -ceq 'guard') {
        if ($Operation -notin @('admin', 'guest')) { throw 'remote guard operation differs' }
        $request.operation = $Operation
        $request.candidate_class = $Operation
        $request.maximum_guard_seconds = 180
    }
    if ($Mode -ceq 'client-observe') {
        foreach ($pair in @(
            @($SelectedGuestFingerprintSHA256, 'selected Guest'), @($PreviousNonceSHA256, 'previous nonce'),
            @($ExpectedBeforeCounterSHA256, 'before counter'), @($ExpectedAfterCounterSHA256, 'after counter')
        )) { Assert-P3GuardSHA256 -Value ([string]$pair[0]) -Label $pair[1] }
        $request.previous_nonce_sha256 = $PreviousNonceSHA256
        $request.selected_guest_fingerprint_sha256 = $SelectedGuestFingerprintSHA256
        $request.maximum_handshake_age_seconds = 180
        $request.expected_before_counter_sha256 = $ExpectedBeforeCounterSHA256
        $request.expected_after_counter_sha256 = $ExpectedAfterCounterSHA256
    }
    if ($Mode -ceq 'emergency-rollback') {
        if ($null -eq $RollbackPlan) { throw 'emergency rollback plan is required' }
        $request.candidate_receipt_sha256 = [string]$RollbackPlan.candidate_receipt_sha256
        $request.rollback_plan_sha256 = [string]$RollbackPlan.plan_sha256
        $request.confirmation = [string]$RollbackPlan.confirmation_challenge
        $request.candidate_fingerprint_sha256 = [string]$RollbackPlan.candidate_fingerprint_sha256
        $request.persistent_config_path = [string]$Context.Rollback.persistent_config_path
        $request.metadata_path = [string]$Context.Rollback.metadata_path
        $request.temporary_path = [string]$Context.Rollback.temporary_path
        $request.syncconf_path = [string]$Context.Rollback.syncconf_path
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
    if ([string]$Receipt.before_counter_sha256 -cne [string]$Request.expected_before_counter_sha256 -or [string]$Receipt.after_counter_sha256 -cne [string]$Request.expected_after_counter_sha256) { throw 'client observation counter hash differs' }
    if (-not [bool]$Receipt.traffic_delta -or [int]$Receipt.observation_duration_seconds -ne 10) { throw 'client observation traffic delta differs' }
    return $Receipt
}

function Invoke-P3BoundedJsonSsh([object]$Context, [object]$Request, [int]$TimeoutSeconds, [int]$MaximumBytes, [scriptblock]$Runner) {
    $null = Test-P3PreliveInputs -Context $Context -NowUtc ([DateTime]::UtcNow)
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

function New-P3EmergencyRollbackPlan([object]$Context, [object]$CandidateReceipt, [object]$CurrentReceipt) {
    $null = Test-P3PreliveInputs -Context $Context -NowUtc ([DateTime]::UtcNow)
    foreach ($name in @('candidate_fingerprint_sha256', 'post_peer_set_sha256', 'pre_peer_set_sha256')) { Assert-P3GuardSHA256 -Value ([string]$CandidateReceipt.$name) -Label $name }
    if (-not [bool]$CurrentReceipt.exact_plus_one -or [string]$CurrentReceipt.candidate_fingerprint_sha256 -cne [string]$CandidateReceipt.candidate_fingerprint_sha256 -or
        [string]$CurrentReceipt.post_peer_set_sha256 -cne [string]$CandidateReceipt.post_peer_set_sha256) { throw 'emergency rollback current candidate differs' }
    $identity = [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-emergency-rollback-plan/v2'
        manifest_sha256 = [string]$Context.ManifestSHA256
        payload_sha256 = [string]$Context.PayloadSHA256
        protocol_sha256 = [string]$Context.ProtocolSHA256
        install_receipt_sha256 = [string]$Context.InstallReceiptSHA256
        candidate_receipt_sha256 = Get-P3GuardCanonicalSHA256 $CandidateReceipt
        candidate_fingerprint_sha256 = [string]$CandidateReceipt.candidate_fingerprint_sha256
        pre_peer_set_sha256 = [string]$CandidateReceipt.pre_peer_set_sha256
        post_peer_set_sha256 = [string]$CandidateReceipt.post_peer_set_sha256
        rollback_scope = 'one-exact-candidate'
        expected_syncconf_count = 1
    }
    $hash = Get-P3GuardCanonicalSHA256 $identity
    $result = [ordered]@{}
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result.plan_sha256 = $hash
    $result.confirmation_challenge = 'P3-EMERGENCY-ROLLBACK-' + $hash.Substring(0, 16).ToUpperInvariant()
    return [pscustomobject]$result
}

function Invoke-P3EmergencyRollback([object]$Context, [object]$Plan, [string]$ExpectedPlanSHA256, [string]$Confirmation, [scriptblock]$Runner) {
    if ([string]$Plan.plan_sha256 -cne $ExpectedPlanSHA256 -or $Confirmation -cne [string]$Plan.confirmation_challenge -or
        $Confirmation -cnotmatch '^P3-EMERGENCY-ROLLBACK-[0-9A-F]{16}$') { throw 'emergency rollback approval differs' }
    $nonce = ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')).ToLowerInvariant()
    $request = New-P3RemoteRequest -Context $Context -Mode 'emergency-rollback' -Operation '' -Nonce $nonce -RollbackPlan $Plan
    return Invoke-P3BoundedJsonSsh -Context $Context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner $Runner
}

function Invoke-P3NativeJsonProcess([string]$Executable, [string[]]$Arguments, [string]$InputJson, [int]$TimeoutSeconds, [int]$MaximumBytes) {
    $inputPath = [IO.Path]::GetTempFileName(); $outputPath = [IO.Path]::GetTempFileName(); $errorPath = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($inputPath, $InputJson, [Text.UTF8Encoding]::new($false))
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -RedirectStandardInput $inputPath -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath -PassThru
        $watch = [Diagnostics.Stopwatch]::StartNew(); $timedOut = $false; $oversized = $false
        while (-not $process.HasExited) {
            if (([IO.FileInfo]$outputPath).Length + ([IO.FileInfo]$errorPath).Length -gt $MaximumBytes) { $oversized = $true; $process.Kill(); break }
            if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $timedOut = $true; $process.Kill(); break }
            Start-Sleep -Milliseconds 50; $process.Refresh()
        }
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode; TimedOut = $timedOut; Oversized = $oversized
            StdOut = if ($oversized) { '' } else { [IO.File]::ReadAllText($outputPath, [Text.UTF8Encoding]::new($false, $true)) }
            StdErr = if ($oversized) { '' } else { [IO.File]::ReadAllText($errorPath, [Text.UTF8Encoding]::new($false, $true)) }
        }
    } finally { foreach ($path in @($inputPath, $outputPath, $errorPath)) { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } } }
}

function Invoke-P3NativeGuardStreamProcess(
    [string]$Executable, [string[]]$Arguments, [string]$InputJson, [scriptblock]$OnEvent,
    [int]$TimeoutSeconds, [int]$MaximumBytes
) {
    $inputPath = [IO.Path]::GetTempFileName(); $outputPath = [IO.Path]::GetTempFileName(); $errorPath = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($inputPath, $InputJson, [Text.UTF8Encoding]::new($false))
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -RedirectStandardInput $inputPath -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath -PassThru
        $watch = [Diagnostics.Stopwatch]::StartNew(); $processed = 0; $timedOut = $false; $oversized = $false
        while (-not $process.HasExited) {
            $length = ([IO.FileInfo]$outputPath).Length + ([IO.FileInfo]$errorPath).Length
            if ($length -gt $MaximumBytes) { $oversized = $true; $process.Kill(); break }
            if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $timedOut = $true; $process.Kill(); break }
            $text = [IO.File]::ReadAllText($outputPath, [Text.UTF8Encoding]::new($false, $true))
            $lines = @($text -split "`r?`n", -1)
            $completeCount = if ($text.EndsWith("`n")) { $lines.Count - 1 } else { [Math]::Max(0, $lines.Count - 1) }
            while ($processed -lt $completeCount) { if (-not [string]::IsNullOrEmpty($lines[$processed])) { & $OnEvent $lines[$processed] (-not $process.HasExited) }; $processed++ }
            Start-Sleep -Milliseconds 50; $process.Refresh()
        }
        $process.WaitForExit()
        $text = if ($oversized) { '' } else { [IO.File]::ReadAllText($outputPath, [Text.UTF8Encoding]::new($false, $true)) }
        $lines = @($text -split "`r?`n", -1); $endsNewline = $text.EndsWith("`n")
        $completeCount = if ($endsNewline) { $lines.Count - 1 } else { [Math]::Max(0, $lines.Count - 1) }
        while ($processed -lt $completeCount) { if (-not [string]::IsNullOrEmpty($lines[$processed])) { & $OnEvent $lines[$processed] $false }; $processed++ }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode; TimedOut = $timedOut; Oversized = $oversized
            StdErr = if ($oversized) { '' } else { [IO.File]::ReadAllText($errorPath, [Text.UTF8Encoding]::new($false, $true)) }
            PartialLine = (-not $endsNewline -and $text.Length -gt 0)
        }
    } finally { foreach ($path in @($inputPath, $outputPath, $errorPath)) { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } } }
}

$script:P3NativeJsonRunner = { param($Executable, $Arguments, $InputJson, $TimeoutSeconds, $MaximumBytes) Invoke-P3NativeJsonProcess @PSBoundParameters }
$script:P3NativeStreamRunner = { param($Executable, $Arguments, $InputJson, $OnEvent, $TimeoutSeconds, $MaximumBytes) Invoke-P3NativeGuardStreamProcess @PSBoundParameters }

function Get-P3PreliveContext([string]$RuntimeRoot, [string]$ExpectedManifestSHA256) {
    . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
    $null = Invoke-P3RuntimeValidate -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256
    $trust = Open-P3BoundedStableJson -Path (Join-Path $RuntimeRoot 'trust.json') -MaximumBytes 65536 -ExpectedProperties $script:P3TrustProperties
    $manifest = Open-P3BoundedStableJson -Path (Join-Path $RuntimeRoot 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
    $cloud = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $RuntimeRoot 'cloud-firewall-receipt.json'), [Text.UTF8Encoding]::new($false, $true)))
    $local = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $RuntimeRoot 'local-baseline-receipt.json'), [Text.UTF8Encoding]::new($false, $true)))
    $agent = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $RuntimeRoot 'agent-receipt.json'), [Text.UTF8Encoding]::new($false, $true)))
    $install = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $RuntimeRoot 'remote-install-receipt.json'), [Text.UTF8Encoding]::new($false, $true)))
    if ($trust.PSObject.Properties.Name -notcontains 'accepted_server_baseline') { throw 'protected trust lacks accepted server baseline details' }
    $baseline = $trust.accepted_server_baseline
    $egress = @(); foreach ($authority in @($trust.egress_authority_sha256)) { $egress += [pscustomobject]@{ authority_sha256 = $authority; source_cidr_sha256 = $trust.management_source_cidr_sha256 } }
    return [pscustomobject]@{
        ManifestSHA256 = $ExpectedManifestSHA256; PayloadSHA256 = $manifest.local_payload_sha256; ProtocolSHA256 = $manifest.protocol_sha256
        InstallReceiptSHA256 = Get-P3GuardCanonicalSHA256 $install; ExpectedServerBaselineSHA256 = $manifest.accepted_server_baseline_sha256
        ExpectedCloudFirewallSHA256 = $manifest.accepted_cloud_firewall_sha256; ExpectedContainerIdentitySHA256 = $baseline.container_identity_sha256
        ExpectedImageIdentitySHA256 = $baseline.image_identity_sha256; ExpectedUdpPublicationSHA256 = $baseline.udp_publication_sha256
        ExpectedListenerIdentitySHA256 = $baseline.listener_identity_sha256; ExpectedHostPolicySHA256 = $baseline.host_policy_sha256
        ExpectedPeerCount = $baseline.peer_count; ExpectedPeerSetSHA256 = $baseline.peer_set_sha256
        Trust = [pscustomobject]@{ ssh_user = $trust.ssh_user; ssh_host = $trust.ssh_host; known_hosts_path = $trust.known_hosts_path; git_ssh_path = $trust.git_ssh_path; management_source_cidr_sha256 = $trust.management_source_cidr_sha256; egress = $egress }
        Agent = $agent; Install = $install; CloudFirewall = $cloud; LocalBaseline = $local; Rollback = $trust.rollback_paths
    }
}

if (-not [string]::IsNullOrEmpty($Action)) {
    $context = Get-P3PreliveContext -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256
    switch ($Action) {
        'ValidateOnly' { Test-P3PreliveInputs -Context $context -NowUtc ([DateTime]::UtcNow) | ConvertTo-Json -Compress }
        'Reconcile' {
            $nonce = ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
            $request = New-P3RemoteRequest -Context $context -Mode 'reconcile' -Operation '' -Nonce $nonce
            $null = Invoke-P3BoundedJsonSsh -Context $context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner $null
            [Console]::Out.WriteLine('PRELIVE_READY=YES')
        }
        'GuardAdmin' { Invoke-P3GuardStream -Context $context -Operation 'admin' -Nonce (([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))) -Runner $null | ConvertTo-Json -Compress }
        'GuardGuest' { Invoke-P3GuardStream -Context $context -Operation 'guest' -Nonce (([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))) -Runner $null | ConvertTo-Json -Compress }
        'ClientObserve' {
            $input = ConvertFrom-Json ([Console]::In.ReadToEnd())
            $request = New-P3RemoteRequest -Context $context -Mode 'client-observe' -Operation '' -Nonce ([string]$input.nonce) `
                -SelectedGuestFingerprintSHA256 ([string]$input.selected_guest_fingerprint_sha256) -PreviousNonceSHA256 ([string]$input.previous_nonce_sha256) `
                -ExpectedBeforeCounterSHA256 ([string]$input.expected_before_counter_sha256) -ExpectedAfterCounterSHA256 ([string]$input.expected_after_counter_sha256)
            Invoke-P3BoundedJsonSsh -Context $context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner $null | ConvertTo-Json -Compress
        }
        'EmergencyRollbackPlan' {
            $input = ConvertFrom-Json ([Console]::In.ReadToEnd())
            New-P3EmergencyRollbackPlan -Context $context -CandidateReceipt $input.candidate -CurrentReceipt $input.current | ConvertTo-Json -Compress
        }
        'EmergencyRollback' {
            $plan = ConvertFrom-Json ([Console]::In.ReadToEnd())
            Invoke-P3EmergencyRollback -Context $context -Plan $plan -ExpectedPlanSHA256 $ExpectedPlanSHA256 -Confirmation $Confirmation -Runner $null | ConvertTo-Json -Compress
        }
    }
}
