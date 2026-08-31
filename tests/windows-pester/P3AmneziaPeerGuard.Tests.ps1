$ErrorActionPreference = 'Stop'

Describe 'P3 local pre-live reconciliation and streaming guard' {
    BeforeAll {
        $script:Launcher = Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1'
        . $script:Launcher

        function New-TestContext([DateTime]$NowUtc = [DateTime]::UtcNow) {
            $now = $NowUtc.ToUniversalTime()
            return [pscustomobject]@{
                ManifestSHA256 = ('1' * 64)
                PayloadSHA256 = ('2' * 64)
                ProtocolSHA256 = ('3' * 64)
                InstallReceiptSHA256 = ('4' * 64)
                ExpectedServerBaselineSHA256 = ('5' * 64)
                ExpectedCloudFirewallSHA256 = ('6' * 64)
                ExpectedContainerIdentitySHA256 = ('7' * 64)
                ExpectedImageIdentitySHA256 = ('8' * 64)
                ExpectedUdpPublicationSHA256 = ('9' * 64)
                ExpectedListenerIdentitySHA256 = ('a' * 64)
                ExpectedHostPolicySHA256 = ('b' * 64)
                ExpectedIPv6PolicySHA256 = ('0' * 64)
                ExpectedPeerCount = 1
                ExpectedPeerSetSHA256 = Get-P3GuardCanonicalSHA256 @(('1' * 64))
                ExpectedPeerFingerprints = @(('1' * 64))
                BaselinePersistentConfigSHA256 = ('2' * 64)
                BaselineMetadataSHA256 = ('3' * 64)
                BaselineTemporaryStateSHA256 = ('4' * 64)
                BaselineRuntimeIdentitySHA256 = ('5' * 64)
                Rollback = [pscustomobject]@{
                    persistent_config_path = '/opt/amnezia/awg/awg0.conf'; metadata_path = '/opt/amnezia/awg/clientsTable'
                    temporary_path = '/tmp/p3-candidate-{nonce32}.tmp'; syncconf_path = '/opt/amnezia/awg/awg0.conf'
                }
                Trust = [pscustomobject]@{
                    ssh_user = 'homegateway'; ssh_host = '192.0.2.10'; known_hosts_path = 'C:\synthetic\known_hosts'
                    git_ssh_path = 'C:\synthetic\Git\usr\bin\ssh.exe'; management_source_cidr_sha256 = ('d' * 64)
                    egress = @(
                        [pscustomobject]@{ authority_sha256 = ('e' * 64); source_cidr_sha256 = ('d' * 64) },
                        [pscustomobject]@{ authority_sha256 = ('f' * 64); source_cidr_sha256 = ('d' * 64) },
                        [pscustomobject]@{ authority_sha256 = ('0' * 64); source_cidr_sha256 = ('d' * 64) }
                    )
                }
                EgressReceipt = [pscustomobject]@{
                    schema = 'home-gateway/p3-prelive-egress-receipt/v1'
                    management_source_cidr_sha256 = ('d' * 64)
                    observations = @(
                        [pscustomobject]@{ authority_sha256 = ('e' * 64); source_cidr_sha256 = ('d' * 64); observed_at_utc = $now.AddSeconds(-12).ToString('o') },
                        [pscustomobject]@{ authority_sha256 = ('f' * 64); source_cidr_sha256 = ('d' * 64); observed_at_utc = $now.AddSeconds(-11).ToString('o') },
                        [pscustomobject]@{ authority_sha256 = ('0' * 64); source_cidr_sha256 = ('d' * 64); observed_at_utc = $now.AddSeconds(-10).ToString('o') }
                    )
                    observed_at_utc = $now.AddSeconds(-10).ToString('o')
                    live_mutation_performed = $false
                }
                Agent = [pscustomobject]@{
                    schema = 'home-gateway/p3-ssh-agent-combined-receipt/v2'
                    agent_pid = 4242; socket = '/tmp/ssh-synthetic/agent.4242'; loaded_key_count = 1
                    expected_key_match = $true; toolchain_match = $true; manifest_sha256 = ('1' * 64)
                }
                Install = [pscustomobject]@{
                    schema = 'home-gateway/p3-remote-helper-install-receipt/v1'; target_state = 'exact'
                    payload_sha256 = ('2' * 64); owner_match = $true; group_match = $true; mode_match = $true
                    installed_by_gate = $true; preinstall_state = 'absent'; temporary_leftover_count = 0
                }
                CloudFirewall = [pscustomobject]@{
                    schema = 'home-gateway/p3-prelive-cloud-firewall-receipt/v1'; cloud_firewall_identity_sha256 = ('6' * 64)
                    management_source_cidr_sha256 = ('d' * 64); droplet_association_count = 1; inbound_rule_count = 2
                    observed_at_utc = $now.AddSeconds(-30).ToString('o'); owner_observed = $true
                    server_confirmed = $false; live_mutation_performed = $false
                }
                LocalBaseline = [pscustomobject]@{
                    schema = 'home-gateway/p3-prelive-local-baseline-receipt/v1'; protected_profile_absent = $true
                    selfhosted_adapter_count = 0; redshield_class_count = 1; cisco_class_count = 0
                    adapter_class_set_sha256 = ('f' * 64); observed_at_utc = $now.AddSeconds(-20).ToString('o')
                    live_mutation_performed = $false
                }
            }
        }

        function New-ReconcileReceipt([object]$Context, [string]$NonceSHA256) {
            return [ordered]@{
                schema = 'home-gateway/p3-peer-reconcile-receipt/v2'; payload_sha256 = $Context.PayloadSHA256
                protocol_sha256 = $Context.ProtocolSHA256; manifest_sha256 = $Context.ManifestSHA256
                install_receipt_sha256 = $Context.InstallReceiptSHA256; nonce_sha256 = $NonceSHA256
                container_count = 1; container_running = $true; container_identity_sha256 = $Context.ExpectedContainerIdentitySHA256
                image_identity_sha256 = $Context.ExpectedImageIdentitySHA256; container_restart_count_sha256 = ('b' * 64)
                udp_publication_count = 1; udp_publication_sha256 = $Context.ExpectedUdpPublicationSHA256
                public_listener_class_count = 2; listener_identity_sha256 = $Context.ExpectedListenerIdentitySHA256
                host_policy_loaded = $true; host_policy_sha256 = $Context.ExpectedHostPolicySHA256; ipv6_non_mutation = $true
                peer_count = $Context.ExpectedPeerCount; peer_set_sha256 = $Context.ExpectedPeerSetSHA256
                candidate_leftover_count = 0; temporary_leftover_count = 0; atomic_leftover_count = 0
                server_baseline_sha256 = $Context.ExpectedServerBaselineSHA256
            }
        }

        function New-ReadyEvent([object]$Context, [string]$Operation, [string]$NonceSHA256) {
            return [ordered]@{
                event = 'ready_for_ui'; schema = 'home-gateway/p3-peer-guard-event/v2'; operation = $Operation
                payload_sha256 = $Context.PayloadSHA256; protocol_sha256 = $Context.ProtocolSHA256
                nonce_sha256 = $NonceSHA256; pre_peer_count = 1; pre_peer_set_sha256 = $Context.ExpectedPeerSetSHA256
                reconcile_sha256 = ('1' * 64)
            } | ConvertTo-Json -Compress
        }

        function New-CandidateEvent([object]$Context, [string]$Operation, [string]$NonceSHA256) {
            return [ordered]@{
                event = 'candidate'; schema = 'home-gateway/p3-peer-guard-event/v2'; operation = $Operation
                payload_sha256 = $Context.PayloadSHA256; protocol_sha256 = $Context.ProtocolSHA256
                nonce_sha256 = $NonceSHA256; candidate_count = 1; candidate_fingerprint_sha256 = ('e' * 64)
                pre_peer_set_sha256 = $Context.ExpectedPeerSetSHA256; post_peer_set_sha256 = ('f' * 64)
                persistent_live_metadata_equal = $true; semantic_transition_count = 1; container_restart_delta = 0
                firewall_equal = $true; listeners_equal = $true; official_ui_rollback_ready = $true
                emergency_rollback_ready = $true
            } | ConvertTo-Json -Compress
        }
    }

    BeforeEach {
        $script:Context = New-TestContext
    }

    It 'accepts only a fresh complete three-source pre-live context' {
        $receipt = Test-P3PreliveInputs -Context $script:Context -NowUtc ([DateTime]::UtcNow)
        $receipt.prelive_inputs_valid | Should -BeTrue
        $receipt.live_mutation_performed | Should -BeFalse

        $cases = @(
            @{ Name = 'Cloud Firewall'; Change = { $script:Context.CloudFirewall.observed_at_utc = '2000-01-01T00:00:00Z' } },
            @{ Name = 'local baseline'; Change = { $script:Context.LocalBaseline.selfhosted_adapter_count = 1 } },
            @{ Name = 'agent'; Change = { $script:Context.Agent.loaded_key_count = 2 } },
            @{ Name = 'install'; Change = { $script:Context.Install.target_state = 'conflict' } },
            @{ Name = 'egress'; Change = { $script:Context.Trust.egress[0].source_cidr_sha256 = ('0' * 64) } }
        )
        foreach ($case in $cases) {
            $script:Context = New-TestContext
            & $case.Change
            { Test-P3PreliveInputs -Context $script:Context -NowUtc ([DateTime]::UtcNow) } | Should -Throw "*$($case.Name)*"
        }
    }

    It 'rejects stale future malformed or source-mutated egress evidence against one clock' {
        $clock = [DateTime]::Parse('2026-08-31T12:00:00Z').ToUniversalTime()
        $cases = @(
            { param($context, $now) $context.EgressReceipt.observed_at_utc = $now.AddSeconds(-121).ToString('o') },
            { param($context, $now) $context.EgressReceipt.observed_at_utc = $now.AddSeconds(2).ToString('o') },
            { param($context, $now) $context.EgressReceipt.observations[1].observed_at_utc = $now.AddSeconds(-121).ToString('o') },
            { param($context, $now) $context.EgressReceipt.observations[1].observed_at_utc = $now.AddSeconds(2).ToString('o') },
            { param($context, $now) $context.EgressReceipt.management_source_cidr_sha256 = ('a' * 64) },
            { param($context, $now) $context.EgressReceipt.observations[1].source_cidr_sha256 = ('a' * 64) },
            { param($context, $now) $context.EgressReceipt.observations[1].authority_sha256 = ('a' * 64) },
            { param($context, $now) $context.EgressReceipt | Add-Member -NotePropertyName extra -NotePropertyValue $true }
        )

        foreach ($change in $cases) {
            $context = New-TestContext -NowUtc $clock
            & $change $context $clock
            { Test-P3PreliveInputs -Context $context -NowUtc $clock } | Should -Throw '*egress*'
        }
    }

    It 'requires exact egress evidence before invoking a top-level remote runner' {
        $script:Context.EgressReceipt.observations[0].source_cidr_sha256 = ('a' * 64)
        $calls = 0
        $request = New-P3RemoteRequest -Context $script:Context -Mode 'reconcile' -Operation '' -Nonce ('a' * 64)
        { Invoke-P3BoundedJsonSsh -Context $script:Context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner { $calls++ } } |
            Should -Throw '*egress*'
        $calls | Should -Be 0
    }

    It 'binds management classification to the exact full-access operation context rather than a display name' {
        $now = [DateTime]::Parse('2026-08-31T12:00:00Z').ToUniversalTime()
        $receipt = New-P3ManagementOperationContextReceipt -ManifestSHA256 ('1' * 64) -CandidateReceiptSHA256 ('2' * 64) `
            -ClientBinarySHA256 ('3' * 64) -ClientVersionSHA256 ('4' * 64) -SourceMappingSHA256 ('5' * 64) `
            -UiActionClassSHA256 ('6' * 64) -SelectedEntrySHA256 ('7' * 64) -CandidateNonceSHA256 ('8' * 64) `
            -PrePeerSetSHA256 ('9' * 64) -PostPeerSetSHA256 ('a' * 64) -CandidateFingerprintSHA256 ('b' * 64) `
            -RuntimeIdentitySHA256 ('c' * 64) -NowUtc $now
        $receipt.classification | Should -BeExactly 'source_pinned_management_operation'
        $receipt.owner_observed | Should -BeTrue
        $receipt.server_role_confirmed | Should -BeFalse
        Test-P3ManagementOperationContextReceipt -Receipt $receipt -ExpectedManifestSHA256 ('1' * 64) `
            -ExpectedCandidateReceiptSHA256 ('2' * 64) -ExpectedUiActionClassSHA256 ('6' * 64) -NowUtc $now.AddMinutes(1) |
            Should -BeExactly $receipt
        $receipt.ui_action_class_sha256 = ('0' * 64)
        { Test-P3ManagementOperationContextReceipt -Receipt $receipt -ExpectedManifestSHA256 ('1' * 64) `
                -ExpectedCandidateReceiptSHA256 ('2' * 64) -ExpectedUiActionClassSHA256 ('6' * 64) -NowUtc $now.AddMinutes(1) } |
            Should -Throw '*operation context*'
    }

    It 'accepts Guest identity only from the protected profile derived X25519 public fingerprint' {
        $now = [DateTime]::Parse('2026-08-31T12:00:00Z').ToUniversalTime()
        $receipt = New-P3GuestProfileIdentityReceipt -ManifestSHA256 ('1' * 64) -CandidateReceiptSHA256 ('2' * 64) `
            -ProfileSHA256 ('3' * 64) -ProfileFileIdentitySHA256 ('4' * 64) -ProfileAclIdentitySHA256 ('5' * 64) `
            -CandidateNonceSHA256 ('6' * 64) -PrePeerSetSHA256 ('7' * 64) -PostPeerSetSHA256 ('8' * 64) `
            -DerivedPublicFingerprintSHA256 ('9' * 64) -CandidateFingerprintSHA256 ('9' * 64) `
            -RuntimeIdentitySHA256 ('a' * 64) -NowUtc $now
        $receipt.raw_key_exposed | Should -BeFalse
        Test-P3GuestProfileIdentityReceipt -Receipt $receipt -ExpectedManifestSHA256 ('1' * 64) `
            -ExpectedCandidateReceiptSHA256 ('2' * 64) -ExpectedCandidateFingerprintSHA256 ('9' * 64) -NowUtc $now.AddMinutes(1) |
            Should -BeExactly $receipt
        $receipt.profile_acl_identity_sha256 = ('0' * 64)
        { Test-P3GuestProfileIdentityReceipt -Receipt $receipt -ExpectedManifestSHA256 ('1' * 64) `
                -ExpectedCandidateReceiptSHA256 ('2' * 64) -ExpectedCandidateFingerprintSHA256 ('9' * 64) `
                -ExpectedProfileAclIdentitySHA256 ('5' * 64) -NowUtc $now.AddMinutes(1) } | Should -Throw '*profile identity*'
    }

    It 'records and consumes one protected management receipt after exact approval' {
        $client = Join-Path $TestDrive 'management-client.exe';[IO.File]::WriteAllText($client,'synthetic-client')
        $candidate = [pscustomobject][ordered]@{
            schema='home-gateway/p3-local-guard-receipt/v2';operation='admin';ready_emitted=$true;candidate_received=$true
            candidate_fingerprint_sha256=('b'*64);pre_peer_set_sha256=('9'*64);post_peer_set_sha256=('a'*64)
            nonce_sha256=('8'*64);live_mutation_performed=$false
        }
        $input=[pscustomobject]@{
            manifest_sha256=('1'*64);candidate_receipt=$candidate;candidate_nonce_sha256=('8'*64)
            pre_peer_set_sha256=('9'*64);post_peer_set_sha256=('a'*64);candidate_fingerprint_sha256=('b'*64)
            runtime_identity_sha256=('c'*64);subject=[pscustomobject]@{
                client_binary_path=$client;client_version_sha256=('4'*64);source_mapping_sha256=('5'*64)
                ui_action_class_sha256=('6'*64);selected_entry_sha256=('7'*64)
            }
        }
        $root=Join-Path $TestDrive 'management-evidence';$plan=Invoke-P3ProtectedEvidenceAction ManagementReceiptPlan $root $input '' '' $null
        $planIdentity=[ordered]@{};foreach($property in $plan.PSObject.Properties){if($property.Name -notin @('plan_sha256','confirmation_challenge')){$planIdentity[$property.Name]=$property.Value}}
        (Get-P3GuardCanonicalSHA256 ([pscustomobject]$planIdentity))|Should -BeExactly $plan.plan_sha256
        $receipt=Invoke-P3ProtectedEvidenceAction -SelectedAction ManagementReceiptRecord -Root $root -InputObject ([pscustomobject]@{plan=$plan;candidate_receipt=$candidate}) `
            -ExpectedPlanSHA256 $plan.plan_sha256 -Confirmation $plan.confirmation_challenge -Boundaries ([pscustomobject]@{ClockRunner={[DateTime]::UtcNow}})
        $receipt.owner_observed|Should -BeTrue;$receipt.server_role_confirmed|Should -BeFalse
        $consumed=Invoke-P3ProtectedEvidenceAction -SelectedAction ManagementReceiptConsume -Root $root -InputObject ([pscustomobject]@{plan=$plan;candidate_receipt=$candidate}) `
            -ExpectedPlanSHA256 $plan.plan_sha256 -Confirmation $plan.confirmation_challenge -Boundaries ([pscustomobject]@{ClockRunner={[DateTime]::UtcNow}})
        $consumed.receipt_sha256|Should -Match '^[0-9a-f]{64}$'
        {Invoke-P3ProtectedEvidenceAction -SelectedAction ManagementReceiptConsume -Root $root -InputObject ([pscustomobject]@{plan=$plan;candidate_receipt=$candidate}) `
                -ExpectedPlanSHA256 $plan.plan_sha256 -Confirmation $plan.confirmation_challenge -Boundaries ([pscustomobject]@{ClockRunner={[DateTime]::UtcNow}})}|Should -Throw
    }

    It 'runs the pinned Guest inspector and persists only its candidate-matched fingerprint' {
        $hgctl=Join-Path $TestDrive 'hgctl.exe';$profile=Join-Path $TestDrive 'guest.conf'
        [IO.File]::WriteAllText($hgctl,'synthetic-hgctl');[IO.File]::WriteAllText($profile,'synthetic-private-profile')
        $candidate=[pscustomobject][ordered]@{
            schema='home-gateway/p3-local-guard-receipt/v2';operation='guest';ready_emitted=$true;candidate_received=$true
            candidate_fingerprint_sha256=('b'*64);pre_peer_set_sha256=('9'*64);post_peer_set_sha256=('a'*64)
            nonce_sha256=('8'*64);live_mutation_performed=$false
        }
        $input=[pscustomobject]@{manifest_sha256=('1'*64);candidate_receipt=$candidate;candidate_nonce_sha256=('8'*64)
            pre_peer_set_sha256=('9'*64);post_peer_set_sha256=('a'*64);candidate_fingerprint_sha256=('b'*64)
            runtime_identity_sha256=('c'*64);subject=[pscustomobject]@{hgctl_path=$hgctl;profile_path=$profile}}
        $root=Join-Path $TestDrive 'guest-evidence';$plan=Invoke-P3ProtectedEvidenceAction GuestProfilePlan $root $input '' '' $null
        $inspectorCalls=[Collections.Generic.List[string]]::new()
        $boundaries=[pscustomobject]@{ClockRunner={[DateTime]::UtcNow};ProfileInspectorRunner={
            param($exe,$arguments,$timeout,$maximum)$inspectorCalls.Add('inspect');$exe|Should -BeExactly $hgctl
            $arguments|Should -Be @('tunnel','inspect','--config',$profile,'--json')
            [pscustomobject]@{ExitCode=0;TimedOut=$false;Oversized=$false;StdErr='';StdOut=([ordered]@{
                metadata=@{};status=@{};capabilities=@{};interface_public_fingerprint_sha256=('b'*64)}|ConvertTo-Json -Compress)}
        }.GetNewClosure()}
        $receipt=Invoke-P3ProtectedEvidenceAction -SelectedAction GuestProfileInspect -Root $root -InputObject ([pscustomobject]@{plan=$plan;candidate_receipt=$candidate}) `
            -ExpectedPlanSHA256 $plan.plan_sha256 -Confirmation $plan.confirmation_challenge -Boundaries $boundaries
        $inspectorCalls.Count|Should -Be 1;$receipt.derived_public_fingerprint_sha256|Should -BeExactly ('b'*64)
        $receipt.raw_key_exposed|Should -BeFalse
        (Get-Content (Join-Path $root 'receipt.json') -Raw)|Should -Not -Match 'synthetic-private-profile'
    }

    It 'rejects protected evidence approval or Guest fingerprint mismatch without a durable receipt' {
        $hgctl=Join-Path $TestDrive 'blocked-hgctl.exe';$profile=Join-Path $TestDrive 'blocked-guest.conf'
        [IO.File]::WriteAllText($hgctl,'synthetic-hgctl');[IO.File]::WriteAllText($profile,'synthetic-profile')
        $candidate=[pscustomobject][ordered]@{schema='home-gateway/p3-local-guard-receipt/v2';operation='guest';ready_emitted=$true;candidate_received=$true
            candidate_fingerprint_sha256=('b'*64);pre_peer_set_sha256=('9'*64);post_peer_set_sha256=('a'*64);nonce_sha256=('8'*64);live_mutation_performed=$false}
        $input=[pscustomobject]@{manifest_sha256=('1'*64);candidate_receipt=$candidate;candidate_nonce_sha256=('8'*64);pre_peer_set_sha256=('9'*64)
            post_peer_set_sha256=('a'*64);candidate_fingerprint_sha256=('b'*64);runtime_identity_sha256=('c'*64);subject=[pscustomobject]@{hgctl_path=$hgctl;profile_path=$profile}}
        $root=Join-Path $TestDrive 'blocked-evidence';$plan=Invoke-P3ProtectedEvidenceAction GuestProfilePlan $root $input '' '' $null;$script:InspectorCalls=0
        $boundaries=[pscustomobject]@{ClockRunner={[DateTime]::UtcNow};ProfileInspectorRunner={param($exe,$arguments,$timeout,$maximum)$script:InspectorCalls++
            [pscustomobject]@{ExitCode=0;TimedOut=$false;Oversized=$false;StdErr='';StdOut=([ordered]@{metadata=@{};status=@{};capabilities=@{};interface_public_fingerprint_sha256=('0'*64)}|ConvertTo-Json -Compress)}}}
        {Invoke-P3ProtectedEvidenceAction -SelectedAction GuestProfileInspect -Root $root -InputObject ([pscustomobject]@{plan=$plan;candidate_receipt=$candidate}) -ExpectedPlanSHA256 ('0'*64) -Confirmation $plan.confirmation_challenge -Boundaries $boundaries}|Should -Throw '*plan*'
        $script:InspectorCalls|Should -Be 0;Test-Path $root|Should -BeFalse
        {Invoke-P3ProtectedEvidenceAction -SelectedAction GuestProfileInspect -Root $root -InputObject ([pscustomobject]@{plan=$plan;candidate_receipt=$candidate}) -ExpectedPlanSHA256 $plan.plan_sha256 -Confirmation $plan.confirmation_challenge -Boundaries $boundaries}|Should -Throw '*fingerprint*'
        Test-Path $root|Should -BeFalse
    }

    It 'builds only fixed strict protocol v2 requests' {
        $nonce = 'A' * 64
        $request = New-P3RemoteRequest -Context $script:Context -Mode 'guard' -Operation 'guest' -Nonce $nonce
        $request.schema | Should -BeExactly 'home-gateway/p3-peer-guard-request/v2'
        $request.mode | Should -BeExactly 'guard'
        $request.operation | Should -BeExactly 'guest'
        $request.nonce | Should -BeExactly ('a' * 64)
        $request.PSObject.Properties.Name | Should -Not -Contain 'ssh_host'
        { New-P3RemoteRequest -Context $script:Context -Mode 'arbitrary' -Operation '' -Nonce $nonce } | Should -Throw '*mode*'
    }

    It 'accepts one exact bounded reconcile receipt and rejects transport ambiguity' {
        $request = New-P3RemoteRequest -Context $script:Context -Mode 'reconcile' -Operation '' -Nonce ('a' * 64)
        $nonceHash = Get-P3GuardTextSHA256 $request.nonce
        $receipt = Invoke-P3BoundedJsonSsh -Context $script:Context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner {
            [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Oversized = $false; StdOut = (New-ReconcileReceipt $script:Context $nonceHash | ConvertTo-Json -Compress); StdErr = '' }
        }
        $receipt.server_baseline_sha256 | Should -BeExactly $script:Context.ExpectedServerBaselineSHA256
        foreach ($bad in @(
            [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Oversized = $false; StdOut = (New-ReconcileReceipt $script:Context $nonceHash | ConvertTo-Json -Compress); StdErr = 'warning' },
            [pscustomobject]@{ ExitCode = 1; TimedOut = $false; Oversized = $false; StdOut = ''; StdErr = '' },
            [pscustomobject]@{ ExitCode = 0; TimedOut = $true; Oversized = $false; StdOut = ''; StdErr = '' }
        )) {
            { Invoke-P3BoundedJsonSsh -Context $script:Context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner { $bad }.GetNewClosure() } | Should -Throw
        }
    }

    It 'emits READY only after validated ready event while the child is alive then accepts one candidate' {
        $script:Captured = @()
        $result = Invoke-P3GuardStream -Context $script:Context -Operation 'guest' -Nonce ('a' * 64) -Runner {
            param($Executable, $Arguments, $InputJson, $OnEvent, $TimeoutSeconds, $MaximumBytes)
            $request = $InputJson | ConvertFrom-Json
            $nonceHash = Get-P3GuardTextSHA256 $request.nonce
            & $OnEvent (New-ReadyEvent $script:Context 'guest' $nonceHash) $true
            & $OnEvent (New-CandidateEvent $script:Context 'guest' $nonceHash) $true
            [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Oversized = $false; StdErr = ''; PartialLine = $false }
        }
        $result.ready_emitted | Should -BeTrue
        $result.candidate_received | Should -BeTrue
        $result.candidate_fingerprint_sha256 | Should -BeExactly ('e' * 64)
    }

    It 'never invokes a stream runner when a pre-live receipt is stale' {
        $script:Context.CloudFirewall.observed_at_utc = '2000-01-01T00:00:00Z'
        $calls = 0
        { Invoke-P3GuardStream -Context $script:Context -Operation 'admin' -Nonce ('a' * 64) -Runner { $calls++ } } |
            Should -Throw '*Cloud Firewall*'
        $calls | Should -Be 0
    }

    It 'fails closed on malformed order duplicate stopped partial stderr timeout and overflow' {
        $factory = {
            param([string[]]$Events, [object]$Terminal)
            return {
                param($Executable, $Arguments, $InputJson, $OnEvent, $TimeoutSeconds, $MaximumBytes)
                foreach ($event in $Events) { & $OnEvent $event $true }
                return $Terminal
            }.GetNewClosure()
        }
        $request = New-P3RemoteRequest -Context $script:Context -Mode 'guard' -Operation 'admin' -Nonce ('a' * 64)
        $nonceHash = Get-P3GuardTextSHA256 $request.nonce
        $ready = New-ReadyEvent $script:Context 'admin' $nonceHash
        $candidate = New-CandidateEvent $script:Context 'admin' $nonceHash
        $terminal = [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Oversized = $false; StdErr = ''; PartialLine = $false }
        $cases = @(
            @{ Events = @($candidate); Terminal = $terminal },
            @{ Events = @($ready, $ready); Terminal = $terminal },
            @{ Events = @('not-json'); Terminal = $terminal },
            @{ Events = @($ready, '{"event":"stopped","schema":"home-gateway/p3-peer-guard-event/v2","operation":"admin","payload_sha256":"' + ('2' * 64) + '","protocol_sha256":"' + ('3' * 64) + '","nonce_sha256":"' + $nonceHash + '","reason":"TIMEOUT"}'); Terminal = $terminal },
            @{ Events = @($ready, $candidate); Terminal = [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Oversized = $false; StdErr = ''; PartialLine = $true } },
            @{ Events = @($ready, $candidate); Terminal = [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Oversized = $false; StdErr = 'warning'; PartialLine = $false } },
            @{ Events = @($ready, $candidate); Terminal = [pscustomobject]@{ ExitCode = 1; TimedOut = $true; Oversized = $false; StdErr = ''; PartialLine = $false } },
            @{ Events = @($ready, $candidate); Terminal = [pscustomobject]@{ ExitCode = 1; TimedOut = $false; Oversized = $true; StdErr = ''; PartialLine = $false } }
        )
        foreach ($case in $cases) {
            { Invoke-P3GuardStream -Context $script:Context -Operation 'admin' -Nonce ('a' * 64) -Runner (& $factory $case.Events $case.Terminal) } |
                Should -Throw
        }
    }

    It 'routes ClientObserve through the same helper and validates exact nonce-bound receipt' {
        $request = New-P3RemoteRequest -Context $script:Context -Mode 'client-observe' -Operation '' -Nonce ('a' * 64) `
            -SelectedGuestFingerprintSHA256 ('e' * 64) -PreviousNonceSHA256 ('f' * 64)
        $nonceHash = Get-P3GuardTextSHA256 $request.nonce
        $context = $script:Context
        $receipt = Invoke-P3BoundedJsonSsh -Context $script:Context -Request $request -TimeoutSeconds 30 -MaximumBytes 65536 -Runner {
            [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Oversized = $false; StdErr = ''; StdOut = ([ordered]@{
                schema = 'home-gateway/p3-peer-client-observe/v2'; payload_sha256 = $context.PayloadSHA256
                protocol_sha256 = $context.ProtocolSHA256; nonce_sha256 = $nonceHash; selected_guest_match = $true
                handshake_fresh = $true; before_counter_sha256 = ('1' * 64); after_counter_sha256 = ('2' * 64)
                traffic_delta = $true; observation_duration_seconds = 10
            } | ConvertTo-Json -Compress) }
        }.GetNewClosure()
        $receipt.traffic_delta | Should -BeTrue
    }

    It 'keeps emergency rollback plan read-only and apply challenge-bound' {
        $candidate = [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-local-guard-receipt/v2'; operation = 'guest'; ready_emitted = $true; candidate_received = $true
            candidate_fingerprint_sha256 = ('e' * 64); pre_peer_set_sha256 = $script:Context.ExpectedPeerSetSHA256
            post_peer_set_sha256 = Get-P3GuardCanonicalSHA256 @(('1' * 64), ('e' * 64))
            nonce_sha256 = ('a' * 64); live_mutation_performed = $false
        }
        $candidateHash = Get-P3GuardCanonicalSHA256 $candidate
        $current = [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-peer-rollback-observation/v2'; candidate_receipt_sha256 = $candidateHash
            candidate_fingerprint_sha256 = ('e' * 64); peer_fingerprint_sha256 = @(('1' * 64), ('e' * 64)); peer_set_sha256 = $candidate.post_peer_set_sha256
            persistent_config_sha256 = ('6' * 64); live_peer_set_sha256 = $candidate.post_peer_set_sha256; metadata_sha256 = ('7' * 64)
            temporary_state_sha256 = ('8' * 64); runtime_identity_sha256 = ('9' * 64); prepared_syncconf_sha256 = ('a' * 64)
        }
        $nonce = 'd' * 64
        $plan = New-P3EmergencyRollbackPlan -Context $script:Context -CandidateReceipt $candidate -CurrentReceipt $current -Nonce $nonce
        $plan.plan_sha256 | Should -Match '^[0-9a-f]{64}$'
        $plan.confirmation_challenge | Should -Match '^P3-EMERGENCY-ROLLBACK-[0-9A-F]{16}$'
        $plan.nonce | Should -BeExactly $nonce
        $plan.temporary_path | Should -BeExactly ('/tmp/p3-candidate-' + ('d' * 32) + '.tmp')
        $plan.syncconf_path | Should -BeExactly '/opt/amnezia/awg/awg0.conf'
        $request = New-P3RemoteRequest -Context $script:Context -Mode 'emergency-rollback' -Operation '' -Nonce $nonce -RollbackPlan $plan
        $request.rollback_plan_sha256 | Should -BeExactly $plan.plan_sha256
        $request.PSObject.Properties.Name | Should -Not -Contain 'plan_sha256'
        $calls = 0
        { Invoke-P3EmergencyRollback -Context $script:Context -Plan $plan -ExpectedPlanSHA256 ('0' * 64) `
            -Confirmation $plan.confirmation_challenge -Runner { $calls++ } } | Should -Throw '*approval*'
        $calls | Should -Be 0
    }

    It 'contains no legacy automatic observer or Windows OpenSSH production path' {
        $text = Get-Content -LiteralPath $script:Launcher -Raw
        $text | Should -Not -Match 'home-gateway-p3-peer-observe|--automatic|System32.{1,4}OpenSSH'
        $text | Should -Match "ClientObserve"
    }

    It 'owns AgentStop in finally and treats cleanup failure as terminal' {
        $script:Stops = 0
        { Invoke-P3OwnedAgentLifecycle -StartRunner { [pscustomobject]@{ agent_pid = 4242 } } -BodyRunner { throw 'synthetic body failure' } -StopRunner {
            param($state) $script:Stops++; $state.agent_pid | Should -Be 4242
        } } | Should -Throw '*body failure*'
        $script:Stops | Should -Be 1
        { Invoke-P3OwnedAgentLifecycle -StartRunner { [pscustomobject]@{ agent_pid = 4242 } } -BodyRunner { 'done' } -StopRunner {
            throw 'synthetic cleanup failure'
        } } | Should -Throw '*cleanup failure*'
    }

    It 'kills and waits the exact stream child when OnEvent throws before temp cleanup' {
        $script:Kills = 0; $script:Waits = 0
        $script:FakeProcess = [pscustomobject]@{ HasExited = $false; ExitCode = 1 }
        $script:FakeProcess | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
        { Invoke-P3NativeGuardStreamProcess -Executable 'synthetic.exe' -Arguments @() -InputJson '{}' `
            -OnEvent { throw 'synthetic OnEvent failure' } -TimeoutSeconds 2 -MaximumBytes 65536 `
            -ProcessRunner {
                param($Executable, $Arguments, $InputPath, $OutputPath, $ErrorPath)
                [IO.File]::WriteAllText($OutputPath, "synthetic-event`n", [Text.UTF8Encoding]::new($false))
                $script:FakeProcess
            } -KillRunner { param($Process) $script:Kills++; $Process.HasExited = $true } `
            -WaitRunner { param($Process) $script:Waits++ } } | Should -Throw '*OnEvent failure*'
        $script:Kills | Should -Be 1
        $script:Waits | Should -Be 1
    }
}
