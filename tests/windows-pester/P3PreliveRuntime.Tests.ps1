$ErrorActionPreference = 'Stop'

Describe 'P3 protected pre-live runtime' {
    BeforeAll {
        $script:Runtime = Join-Path $PSScriptRoot '..\..\scripts\p3-prelive-runtime.ps1'
        $script:Prerequisite = Join-Path $PSScriptRoot '..\..\scripts\p3-prelive-prerequisite.ps1'
        $script:Root = Join-Path $TestDrive 'protected-v1'
        . $script:Runtime
        . $script:Prerequisite

        function Get-TestTextSHA256([string]$Text) {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
        }

        function New-TrustFixture {
            param([string]$Root)
            $files = @{}
            foreach ($name in @('known_hosts', 'operator.pub', 'ssh-agent.exe', 'ssh-add.exe', 'ssh.exe', 'scp.exe', 'guard.py')) {
                $path = Join-Path $Root $name
                [IO.File]::WriteAllText($path, "synthetic-$name", [Text.UTF8Encoding]::new($false))
                $files[$name] = $path
            }
            $payloadHash = (Get-FileHash -LiteralPath $files.'guard.py' -Algorithm SHA256).Hash.ToLowerInvariant()
            $peerSetHash = Get-TestTextSHA256 ((ConvertTo-Json -Compress -InputObject @(('8' * 64))))
            $endpoints = @('https://one.example/ip','https://two.example/ip','https://three.example/ip')
            $authorityHashes = @($endpoints | ForEach-Object { Get-TestTextSHA256 (([Uri]$_).Authority.ToLowerInvariant()) })
            $cloudObservation = [pscustomobject][ordered]@{
                schema = 'home-gateway/p3-prelive-cloud-firewall-observation/v1'
                droplet_association_count = 1; tcp_22_management_source_count = 1
                management_source_cidr_sha256 = ('2' * 64); udp_38556_all_ipv4_count = 1
                udp_ipv6_count = 0; extra_inbound_rule_count = 0; observed_at_utc = [DateTime]::UtcNow.ToString('o')
            }
            $trust = [ordered]@{
                schema = 'home-gateway/p3-prelive-trust-input/v1'
                ssh_host = '192.0.2.10'
                ssh_user = 'homegateway'
                known_hosts_path = $files.known_hosts
                public_key_path = $files.'operator.pub'
                private_key_path = (Join-Path $Root 'operator')
                public_key_fingerprint_sha256 = Get-TestTextSHA256 'SHA256:synthetic-key'
                management_source_cidr_sha256 = ('2' * 64)
                git_ssh_agent_path = $files.'ssh-agent.exe'
                git_ssh_add_path = $files.'ssh-add.exe'
                git_ssh_path = $files.'ssh.exe'
                git_scp_path = $files.'scp.exe'
                local_payload_path = $files.'guard.py'
                remote_payload_sha256 = $payloadHash
                protocol_sha256 = ('4' * 64)
                accepted_server_baseline = [ordered]@{
                    container_count = 1; container_running = $true; container_identity_sha256 = ('3' * 64)
                    image_identity_sha256 = ('4' * 64); container_restart_count = 0
                    udp_publication_count = 1; udp_publication_sha256 = ('5' * 64)
                    public_listener_class_count = 2; listener_identity_sha256 = ('6' * 64)
                    host_policy_loaded = $true; host_policy_sha256 = ('7' * 64); ipv6_non_mutation = $true
                    ipv6_policy_sha256 = ('b' * 64); persistent_config_sha256 = ('c' * 64)
                    metadata_sha256 = ('d' * 64); temporary_state_sha256 = ('e' * 64)
                    runtime_identity_sha256 = ('f' * 64)
                    peer_fingerprint_sha256 = @(('8' * 64)); persistent_peer_set_sha256 = $peerSetHash
                    live_peer_set_sha256 = $peerSetHash; metadata_peer_set_sha256 = $peerSetHash
                    candidate_leftover_count = 0; temporary_leftover_count = 0; atomic_leftover_count = 0
                    firewall_identity_sha256 = ('a' * 64); payload_sha256 = $payloadHash; protocol_sha256 = ('4' * 64)
                }
                accepted_cloud_firewall_sha256 = Get-P3CloudFirewallIdentitySHA256 $cloudObservation
                rollback_paths = [ordered]@{
                    persistent_config_path = '/opt/amnezia/awg/awg0.conf'
                    metadata_path = '/opt/amnezia/awg/clientsTable'
                    temporary_path = '/tmp/p3-candidate-{nonce32}.tmp'
                    syncconf_path = '/opt/amnezia/awg/awg0.conf'
                }
                egress_authority_sha256 = $authorityHashes
            }
            $now = [DateTime]::UtcNow
            $allIpv4 = Get-TestTextSHA256 'all_ipv4'
            $cloudV2 = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-cloud-firewall-observation/v2';firewall_resource_sha256=('1' * 64)
                droplet_resource_sha256=('6' * 64)
                associations=@([pscustomobject][ordered]@{firewall_resource_sha256=('1'*64);droplet_resource_sha256=('6'*64)})
                management_source_cidr_sha256=[string]$trust.management_source_cidr_sha256
                inbound_rules=@(
                    [pscustomobject][ordered]@{protocol='tcp';port=22;source_class='management_ipv4';source_sha256=[string]$trust.management_source_cidr_sha256},
                    [pscustomobject][ordered]@{protocol='udp';port=38556;source_class='all_ipv4';source_sha256=$allIpv4}
                )
                outbound_rules=@(foreach($protocol in @('icmp','tcp','udp')){foreach($destination in @('all_ipv4','all_ipv6')){
                    [pscustomobject][ordered]@{protocol=$protocol;destination_class=$destination}
                }})
                observed_at_utc=$now.ToString('o');owner_observed=$true;server_confirmed=$false;live_mutation_performed=$false
            }
            $cloudUnion = Get-P3PrerequisiteCloudUnion $cloudV2
            $preSshTrust = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-prerequisite-ssh-trust/v1';ssh_host=[string]$trust.ssh_host;ssh_user=[string]$trust.ssh_user
                known_hosts_path=$files.known_hosts;known_hosts_sha256=(Get-FileHash $files.known_hosts).Hash.ToLowerInvariant()
                host_key_fingerprint_sha256=('1'*64)
                git_ssh_agent_path=$files.'ssh-agent.exe';git_ssh_agent_sha256=(Get-FileHash $files.'ssh-agent.exe').Hash.ToLowerInvariant()
                git_ssh_add_path=$files.'ssh-add.exe';git_ssh_add_sha256=(Get-FileHash $files.'ssh-add.exe').Hash.ToLowerInvariant()
                git_ssh_path=$files.'ssh.exe';git_ssh_sha256=(Get-FileHash $files.'ssh.exe').Hash.ToLowerInvariant()
                git_scp_path=$files.'scp.exe';git_scp_sha256=(Get-FileHash $files.'scp.exe').Hash.ToLowerInvariant()
                public_key_path=$files.'operator.pub';public_key_sha256=(Get-FileHash $files.'operator.pub').Hash.ToLowerInvariant()
                public_key_fingerprint_sha256=[string]$trust.public_key_fingerprint_sha256;private_key_path=[string]$trust.private_key_path
                observer_payload_path=$files.'guard.py';observer_payload_sha256=$payloadHash
                observer_protocol_sha256=[string]$trust.protocol_sha256;expected_ipv6_policy_sha256=[string]$trust.accepted_server_baseline.ipv6_policy_sha256
                egress=@(for($i=0;$i -lt 3;$i++){[pscustomobject][ordered]@{endpoint=$endpoints[$i];authority_sha256=$authorityHashes[$i]}})
                connect_timeout_seconds=10;command_timeout_seconds=30;maximum_output_bytes=65536;no_write_scope=$true
            }
            $sshTrustSHA256 = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $preSshTrust)
            $preManifest = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-prerequisite-manifest/v1';manifest_sha256=('a' * 64)
                payload_sha256=$payloadHash;protocol_sha256=[string]$trust.protocol_sha256;ssh_trust=$preSshTrust;ssh_trust_sha256=$sshTrustSHA256
                management_source_cidr_sha256=[string]$trust.management_source_cidr_sha256
                egress_authority_sha256=@($trust.egress_authority_sha256);firewall_resource_sha256=('1' * 64)
                droplet_resource_sha256=('6' * 64);inbound_union_sha256=$cloudUnion.inbound_union_sha256;outbound_union_sha256=$cloudUnion.outbound_union_sha256
            }
            $egressV2 = foreach ($authority in $trust.egress_authority_sha256) {
                [pscustomobject][ordered]@{schema='home-gateway/p3-prelive-egress-observation/v1';authority_sha256=$authority
                    source_cidr_sha256=[string]$trust.management_source_cidr_sha256;observed_at_utc=$now.ToString('o')}
            }
            $receipt = New-P3PrerequisiteReceipt -Manifest $preManifest -ServerBaseline ([pscustomobject]$trust.accepted_server_baseline) `
                -CloudObservation $cloudV2 -EgressObservations @($egressV2) -NonceSHA256 (Get-TestTextSHA256 ('c'*64)) -NowUtc $now
            $prerequisiteRoot = Join-Path $Root 'prerequisite-protected'
            $agentManifest = [pscustomobject]@{
                manifest_sha256=[string]$preManifest.manifest_sha256
                git_ssh_agent_path=$preSshTrust.git_ssh_agent_path;git_ssh_agent_sha256=$preSshTrust.git_ssh_agent_sha256
                git_ssh_add_path=$preSshTrust.git_ssh_add_path;git_ssh_add_sha256=$preSshTrust.git_ssh_add_sha256
                git_ssh_path=$preSshTrust.git_ssh_path;git_ssh_sha256=$preSshTrust.git_ssh_sha256
                git_scp_path=$preSshTrust.git_scp_path;git_scp_sha256=$preSshTrust.git_scp_sha256
                public_key_path=$preSshTrust.public_key_path;private_key_path=$preSshTrust.private_key_path
                public_key_fingerprint_sha256=$preSshTrust.public_key_fingerprint_sha256
            }
            $null = Initialize-P3PrerequisiteRoot $prerequisiteRoot $preManifest $agentManifest
            $observationBatch = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-observation-batch/v1';server_baseline=[pscustomobject]$trust.accepted_server_baseline
                server_baseline_sha256=Get-P3ServerBaselineSHA256 ([pscustomobject]$trust.accepted_server_baseline)
                egress=@($egressV2);nonce_sha256=Get-TestTextSHA256 ('c'*64);observed_at_utc=$now.ToString('o')
                live_mutation_performed=$false;raw_identity_exposed=$false
            }
            $null = Write-P3ProtectedPrerequisiteObservationBatch $prerequisiteRoot $preManifest $observationBatch $observationBatch.nonce_sha256
            $null = Write-P3ProtectedPrerequisiteCloudObservation $prerequisiteRoot $preManifest $cloudV2 $now
            $receiptPath = Join-Path $prerequisiteRoot 'prerequisite-receipt.json'
            $expectedReceiptSHA256 = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $receipt)
            $null = Write-P3ProtectedPrerequisiteReceipt $prerequisiteRoot $preManifest $receipt $expectedReceiptSHA256 $now
            $trust.prerequisite_receipt_path = $receiptPath
            $trust.expected_prerequisite_receipt_sha256 = $expectedReceiptSHA256
            $trust.accepted_prerequisite_cloud_firewall_sha256 = [string]$receipt.cloud_firewall_identity_sha256
            $trust.accepted_prerequisite_ssh_trust = $preSshTrust
            return $trust
        }

        function Initialize-OwnedBatchRuntime([string]$Root, [object]$Trust) {
            $now = [DateTime]::UtcNow
            $fingerprint = 'SHA256:synthetic-key'
            $Trust.public_key_fingerprint_sha256 = Get-TestTextSHA256 $fingerprint
            $plan = New-P3ManifestPlan -Trust ([pscustomobject]$Trust) -RuntimeRoot $Root
            $null = Invoke-P3RuntimePrepare -Trust ([pscustomobject]$Trust) -RuntimeRoot $Root `
                -ExpectedManifestSHA256 $plan.manifest_sha256 -Confirmation $plan.confirmation_challenge
            $cloudObservation = [pscustomobject][ordered]@{
                schema = 'home-gateway/p3-prelive-cloud-firewall-observation/v1'; droplet_association_count = 1
                tcp_22_management_source_count = 1; management_source_cidr_sha256 = ('2' * 64)
                udp_38556_all_ipv4_count = 1; udp_ipv6_count = 0; extra_inbound_rule_count = 0
                observed_at_utc = $now.ToString('o')
            }
            Write-P3RuntimeJson -RuntimeRoot $Root -Name 'cloud-firewall-receipt.json' -Value `
                (New-P3CloudFirewallReceipt -Observation $cloudObservation -ExpectedIdentitySHA256 $Trust.accepted_cloud_firewall_sha256 `
                    -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc $now)
            $egress = New-P3EgressReceipt -ExpectedAuthoritySHA256 @($Trust.egress_authority_sha256) `
                -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc $now -HttpsRunner {
                    param($authority) [pscustomobject]@{ authority_sha256=$authority;source_cidr_sha256=('2'*64);observed_at_utc=$now.ToString('o') }
                }
            Write-P3RuntimeJson -RuntimeRoot $Root -Name 'egress-receipt.json' -Value $egress
            $local = New-P3LocalBaselineReceipt -ProtectedProfilePath (Join-Path (Split-Path -Parent $Root) 'missing-profile.conf') `
                -NowUtc $now -AdapterRunner { @([pscustomobject]@{ InterfaceDescription='RedShield Virtual Adapter' }) }
            Write-P3RuntimeJson -RuntimeRoot $Root -Name 'local-baseline-receipt.json' -Value $local
            $manifest = Open-P3BoundedStableJson -Path (Join-Path $Root 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
            Write-P3RuntimeJson -RuntimeRoot $Root -Name 'remote-install-receipt.json' -Value ([pscustomobject][ordered]@{
                schema='home-gateway/p3-remote-helper-install-receipt/v1';target_state='exact';payload_sha256=$manifest.local_payload_sha256
                owner_match=$true;group_match=$true;mode_match=$true;installed_by_gate=$true;preinstall_state='absent';temporary_leftover_count=0
            })
            return [pscustomobject]@{ Root=$Root;ManifestSHA256=$plan.manifest_sha256;Fingerprint=$fingerprint;AgentPath=$Trust.git_ssh_agent_path;NowUtc=$now }
        }

        function New-OwnedBatchBoundaries([object]$Fixture, [scriptblock]$JsonRunner, [scriptblock]$StopRunner) {
            $list = { "256 $($Fixture.Fingerprint) p3 (ED25519)" }.GetNewClosure()
            $process = { param($ProcessId) [pscustomobject]@{ Id=$ProcessId;Path=$Fixture.AgentPath;StartTime=[DateTime]::UtcNow } }.GetNewClosure()
            return [pscustomobject]@{
                AgentRunner = { "SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;`nSSH_AGENT_PID=4242; export SSH_AGENT_PID;" }
                AddRunner = { param($KeyPath) }; ListRunner = $list; ProcessRunner = $process
                DeleteRunner = { }; StopRunner = $StopRunner
                WaitRunner = { param($ProcessId) $script:OwnedWaits++ }
                ReobserveRunner = { param($ProcessId) $script:OwnedReobservedPid = $ProcessId; @() }
                SocketExistsRunner = { param($Path) $false }
                ReceiptRemoveRunner = { param($Path) [IO.File]::Delete($Path) }
                JsonRunner = $JsonRunner; StreamRunner = { throw 'stream runner is not expected' }
                ClockRunner = { $Fixture.NowUtc.AddSeconds(30) }.GetNewClosure()
            }
        }

        function New-OwnedRemoteBoundaries(
            [object]$Fixture,
            [scriptblock]$SshRunner,
            [scriptblock]$ScpRunner,
            [scriptblock]$StopRunner
        ) {
            $list = { "256 $($Fixture.Fingerprint) p3 (ED25519)" }.GetNewClosure()
            $process = { param($ProcessId) [pscustomobject]@{Id=$ProcessId;Path=$Fixture.AgentPath;StartTime=[DateTime]::UtcNow} }.GetNewClosure()
            $script:OwnedClockNow = $Fixture.NowUtc.AddSeconds(30)
            $clock = { $script:OwnedClockCalls++; $script:OwnedClockNow }
            return [pscustomobject]@{
                AgentRunner={ $script:OwnedAgentStarts++; "SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;`nSSH_AGENT_PID=4242; export SSH_AGENT_PID;" }
                AddRunner={param($KeyPath)};ListRunner=$list;ProcessRunner=$process;DeleteRunner={}
                StopRunner=$StopRunner;WaitRunner={param($ProcessId)$script:OwnedWaits++}
                ReobserveRunner={param($ProcessId)$script:OwnedReobservedPid=$ProcessId;@()};SocketExistsRunner={param($Path)$false}
                ReceiptRemoveRunner={param($Path)[IO.File]::Delete($Path)};ClockRunner=$clock
                SshRunner=$SshRunner;ScpRunner=$ScpRunner
            }
        }

        function Set-ProtectedEgressReceipt([string]$Root, [scriptblock]$Change) {
            $path = Join-Path $Root 'egress-receipt.json'
            $receipt = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            & $Change $receipt
            [IO.File]::WriteAllBytes($path, (ConvertTo-P3CanonicalJson -Value $receipt))
        }
    }

    BeforeEach {
        $script:Root = Join-Path $TestDrive ('protected-' + [guid]::NewGuid().ToString('N'))
        $script:Fixture = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:Fixture
        $script:Trust = New-TrustFixture -Root $script:Fixture
    }

    It 'rejects an extra static trust property without creating the root' {
        $script:Trust.unexpected = $true
        { New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root } |
            Should -Throw '*trust input schema differs*'
        Test-Path -LiteralPath $script:Root | Should -BeFalse
    }

    It 'creates a candidate-bound plan without creating runtime state' {
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $plan.schema | Should -BeExactly 'home-gateway/p3-prelive-runtime-plan/v1'
        $plan.manifest_sha256 | Should -Match '^[0-9a-f]{64}$'
        $plan.manifest.accepted_server_baseline_sha256 | Should -Match '^[0-9a-f]{64}$'
        $plan.confirmation_challenge | Should -Match '^P3-PRELIVE-RUNTIME-[0-9A-F]{16}$'
        $plan.manifest.PSObject.Properties.Name | Should -Be @(
            'accepted_cloud_firewall_sha256', 'accepted_prerequisite_cloud_firewall_sha256',
            'accepted_prerequisite_receipt_sha256', 'accepted_prerequisite_ssh_trust_sha256', 'accepted_server_baseline_sha256',
            'git_scp_sha256', 'git_ssh_add_sha256', 'git_ssh_agent_sha256', 'git_ssh_sha256',
            'known_hosts_sha256', 'local_payload_sha256', 'management_source_cidr_sha256',
            'protocol_sha256', 'public_key_fingerprint_sha256', 'remote_payload_sha256', 'schema', 'trust_sha256'
        )
        Test-Path -LiteralPath $script:Root | Should -BeFalse
    }

    It 'prepares validates and cleans only the marker-owned runtime child' {
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $receipt = Invoke-P3RuntimePrepare -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root `
            -ExpectedManifestSHA256 $plan.manifest_sha256 -Confirmation $plan.confirmation_challenge
        $receipt.schema | Should -BeExactly 'home-gateway/p3-prelive-runtime-receipt/v1'
        (Invoke-P3RuntimeValidate -RuntimeRoot $script:Root -ExpectedManifestSHA256 $plan.manifest_sha256).manifest_sha256 |
            Should -BeExactly $plan.manifest_sha256
        $cleanup = New-P3RuntimeCleanupPlan -RuntimeRoot $script:Root -ExpectedManifestSHA256 $plan.manifest_sha256
        Invoke-P3RuntimeCleanup -RuntimeRoot $script:Root -CleanupPlan $cleanup `
            -ExpectedPlanSHA256 $cleanup.cleanup_plan_sha256 -Confirmation $cleanup.confirmation_challenge
        Test-Path -LiteralPath $script:Root | Should -BeFalse
        Test-Path -LiteralPath $script:Trust.known_hosts_path | Should -BeTrue
    }

    It 'keeps prerequisite validation read-only and consumes it once only in Prepare' {
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $null = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $consumedPath = Join-Path (Split-Path -Parent $script:Trust.prerequisite_receipt_path) 'prerequisite-receipt.consumed.json'
        Test-Path -LiteralPath $consumedPath | Should -BeFalse
        $null = Invoke-P3RuntimePrepare -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root `
            -ExpectedManifestSHA256 $plan.manifest_sha256 -Confirmation $plan.confirmation_challenge
        Test-Path -LiteralPath $consumedPath | Should -BeTrue
        $cleanup = New-P3RuntimeCleanupPlan -RuntimeRoot $script:Root -ExpectedManifestSHA256 $plan.manifest_sha256
        Invoke-P3RuntimeCleanup -RuntimeRoot $script:Root -CleanupPlan $cleanup `
            -ExpectedPlanSHA256 $cleanup.cleanup_plan_sha256 -Confirmation $cleanup.confirmation_challenge
        { New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root } |
            Should -Throw '*already consumed*'
    }

    It 'fails closed on a crash marker bound to the prerequisite receipt' {
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $consumedPath = Join-Path (Split-Path -Parent $script:Trust.prerequisite_receipt_path) 'prerequisite-receipt.consumed.json'
        [IO.File]::WriteAllText($consumedPath, '{"schema":"foreign"}', [Text.UTF8Encoding]::new($false))
        { Invoke-P3RuntimePrepare -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root `
                -ExpectedManifestSHA256 $plan.manifest_sha256 -Confirmation $plan.confirmation_challenge } |
            Should -Throw '*already consumed*'
        Test-Path -LiteralPath $script:Root | Should -BeFalse
    }

    It 'accepts only the canonical container rollback path contract' {
        $script:Trust.rollback_paths.temporary_path = '/run/home-gateway-p3-peer-guard/candidate.tmp'
        { New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root } |
            Should -Throw '*rollback paths differ*'
        Test-Path -LiteralPath $script:Root | Should -BeFalse
    }

    It 'rejects a changed manifest and foreign runtime content' {
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $null = Invoke-P3RuntimePrepare -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root `
            -ExpectedManifestSHA256 $plan.manifest_sha256 -Confirmation $plan.confirmation_challenge
        { Invoke-P3RuntimeValidate -RuntimeRoot $script:Root -ExpectedManifestSHA256 ('a' * 64) } |
            Should -Throw '*manifest*'
        [IO.File]::WriteAllText((Join-Path $script:Root 'foreign.txt'), 'foreign')
        { Invoke-P3RuntimeValidate -RuntimeRoot $script:Root -ExpectedManifestSHA256 $plan.manifest_sha256 } |
            Should -Throw '*foreign*'
    }

    It 'rejects malformed oversized and non-local inputs before state creation' {
        { Resolve-P3FixedCleanPath -Path '\\server\share\protected-v1' -Label 'runtime root' } |
            Should -Throw '*local absolute*'
        { Open-P3BoundedStableJson -Path (Join-Path $script:Fixture 'missing.json') -MaximumBytes 10 -ExpectedProperties @('schema') } |
            Should -Throw '*missing*'
        $large = Join-Path $script:Fixture 'large.json'
        [IO.File]::WriteAllText($large, ('x' * 100))
        { Open-P3BoundedStableJson -Path $large -MaximumBytes 10 -ExpectedProperties @('schema') } |
            Should -Throw '*size*'
    }

    It 'records only an exact fresh owner-observed Cloud Firewall union' {
        $observation = [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-prelive-cloud-firewall-observation/v1'
            droplet_association_count = 1
            tcp_22_management_source_count = 1
            management_source_cidr_sha256 = ('2' * 64)
            udp_38556_all_ipv4_count = 1
            udp_ipv6_count = 0
            extra_inbound_rule_count = 0
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        $identity = Get-P3CloudFirewallIdentitySHA256 $observation
        $receipt = New-P3CloudFirewallReceipt -Observation $observation -ExpectedIdentitySHA256 $identity `
            -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc ([DateTime]::UtcNow)
        $receipt.cloud_firewall_identity_sha256 | Should -BeExactly $identity
        $receipt.owner_observed | Should -BeTrue
        $receipt.live_mutation_performed | Should -BeFalse
        $invalidInbound = [pscustomobject]@{
            schema = 'home-gateway/p3-prelive-cloud-firewall-observation/v1'; droplet_association_count = 1
            tcp_22_management_source_count = 1; management_source_cidr_sha256 = ('2' * 64)
            udp_38556_all_ipv4_count = 1; udp_ipv6_count = 0; extra_inbound_rule_count = 1
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        { New-P3CloudFirewallReceipt -Observation $invalidInbound -ExpectedIdentitySHA256 (Get-P3CloudFirewallIdentitySHA256 $invalidInbound) `
            -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc ([DateTime]::UtcNow) } | Should -Throw '*inbound*'
        $observation.management_source_cidr_sha256 = ('f' * 64)
        { New-P3CloudFirewallReceipt -Observation $observation -ExpectedIdentitySHA256 (Get-P3CloudFirewallIdentitySHA256 $observation) `
            -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc ([DateTime]::UtcNow) } | Should -Throw '*management*'
    }

    It 'builds a sanitized local baseline from an injected read-only observer' {
        $profile = Join-Path $script:Fixture 'absent.conf'
        $receipt = New-P3LocalBaselineReceipt -ProtectedProfilePath $profile -NowUtc ([DateTime]::UtcNow) -AdapterRunner {
            @(
                [pscustomobject]@{ InterfaceDescription = 'RedShield WireGuard Tunnel' },
                [pscustomobject]@{ InterfaceDescription = 'Intel Ethernet Controller' }
            )
        }
        $receipt.protected_profile_absent | Should -BeTrue
        $receipt.selfhosted_adapter_count | Should -Be 0
        $receipt.redshield_class_count | Should -Be 1
        $receipt.PSObject.Properties.Name | Should -Not -Contain 'adapter_name'
        $receipt.live_mutation_performed | Should -BeFalse
    }

    It 'classifies realistic adapter descriptions and rejects ambiguous identities' {
        (Get-P3AdapterClass 'RedShield Virtual Adapter') | Should -BeExactly 'redshield'
        (Get-P3AdapterClass 'Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter') | Should -BeExactly 'cisco'
        (Get-P3AdapterClass 'AmneziaWG Tunnel') | Should -BeExactly 'selfhosted'
        (Get-P3AdapterClass 'Wintun Userspace Tunnel') | Should -BeExactly 'selfhosted'
        (Get-P3AdapterClass 'WireGuard Tunnel') | Should -BeExactly 'selfhosted'
        (Get-P3AdapterClass 'Intel Ethernet Controller') | Should -BeExactly 'other'
        { Get-P3AdapterClass 'Cisco RedShield WireGuard Adapter' } | Should -Throw '*ambiguous*'
        $profile = Join-Path $script:Fixture 'missing.conf'
        $receipt = New-P3LocalBaselineReceipt -ProtectedProfilePath $profile -NowUtc ([DateTime]::UtcNow) -AdapterRunner {
            @([pscustomobject]@{ InterfaceDescription = 'Cisco Secure Client' }, [pscustomobject]@{ InterfaceDescription = 'Cisco Secure Client' })
        }
        $receipt.cisco_class_count | Should -Be 2
    }

    It 'builds one fresh exact three-authority egress receipt from an injected HTTPS boundary' {
        $authorities = @(('7' * 64), ('8' * 64), ('9' * 64))
        $script:EgressCalls = 0
        $receipt = New-P3EgressReceipt -ExpectedAuthoritySHA256 $authorities -ExpectedManagementSourceCIDRSHA256 ('2' * 64) `
            -NowUtc ([DateTime]::UtcNow) -HttpsRunner {
                param($authoritySHA256)
                $script:EgressCalls++
                [pscustomobject]@{ authority_sha256 = $authoritySHA256; source_cidr_sha256 = ('2' * 64); observed_at_utc = [DateTime]::UtcNow.ToString('o') }
            }
        $script:EgressCalls | Should -Be 3
        @($receipt.observations).Count | Should -Be 3
        $receipt.management_source_cidr_sha256 | Should -BeExactly ('2' * 64)
        { New-P3EgressReceipt -ExpectedAuthoritySHA256 $authorities -ExpectedManagementSourceCIDRSHA256 ('2' * 64) `
            -NowUtc ([DateTime]::UtcNow) -HttpsRunner { param($authoritySHA256) [pscustomobject]@{ authority_sha256=$authoritySHA256;source_cidr_sha256=('f'*64);observed_at_utc=[DateTime]::UtcNow.ToString('o') } } } |
            Should -Throw '*source*'
    }

    It 'canonicalizes the exact 27-field baseline identically to Python' {
        $fixturePath = Join-Path $PSScriptRoot '..\fixtures\p3\server-baseline-v2.json'
        $baseline = Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json
        @($baseline.PSObject.Properties).Count | Should -Be 27
        $baseline.PSObject.Properties.Name | Should -Not -Contain 'prepared_syncconf_sha256'
        Get-P3ServerBaselineSHA256 -Baseline $baseline | Should -BeExactly `
            '68943c7693ed9a442b206749572dc44e2e44a595af080e254836f29ff73ebb1f'
    }

    It 'requires and binds the independently accepted prerequisite receipt' {
        $fixtureRoot = Join-Path $TestDrive 'prerequisite-bound-runtime'
        [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
        $trust = New-TrustFixture $fixtureRoot
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$trust) -RuntimeRoot (Join-Path $fixtureRoot 'runtime')
        $plan.manifest.accepted_prerequisite_receipt_sha256 | Should -BeExactly $trust.expected_prerequisite_receipt_sha256
        $trust.expected_prerequisite_receipt_sha256 = ('0' * 64)
        { New-P3ManifestPlan -Trust ([pscustomobject]$trust) -RuntimeRoot (Join-Path $fixtureRoot 'foreign') } |
            Should -Throw '*prerequisite receipt*'
    }

    It 'uses one exact shared validator for persisted egress evidence' {
        $clock = [DateTime]::Parse('2026-08-31T12:00:00Z').ToUniversalTime()
        $authorities = @(('7' * 64), ('8' * 64), ('9' * 64))
        $receipt = [pscustomobject][ordered]@{
            schema='home-gateway/p3-prelive-egress-receipt/v1';management_source_cidr_sha256=('2'*64)
            observations=@(
                [pscustomobject]@{authority_sha256=$authorities[0];source_cidr_sha256=('2'*64);observed_at_utc=$clock.AddSeconds(-3).ToString('o')},
                [pscustomobject]@{authority_sha256=$authorities[1];source_cidr_sha256=('2'*64);observed_at_utc=$clock.AddSeconds(-2).ToString('o')},
                [pscustomobject]@{authority_sha256=$authorities[2];source_cidr_sha256=('2'*64);observed_at_utc=$clock.AddSeconds(-1).ToString('o')}
            );observed_at_utc=$clock.AddSeconds(-1).ToString('o');live_mutation_performed=$false
        }
        (Test-P3ExactEgressReceipt -Receipt $receipt -ExpectedAuthoritySHA256 $authorities `
            -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc $clock).observations.Count | Should -Be 3
        $receipt.observations[1].source_cidr_sha256 = ('a' * 64)
        { Test-P3ExactEgressReceipt -Receipt $receipt -ExpectedAuthoritySHA256 $authorities `
            -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc $clock } | Should -Throw '*egress*'
    }

    It 'rejects a runtime ACL whose owner differs even when allow rules match' {
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $null = Invoke-P3RuntimePrepare -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root `
            -ExpectedManifestSHA256 $plan.manifest_sha256 -Confirmation $plan.confirmation_challenge
        Mock Get-Acl { $acl = New-P3RuntimeAcl; $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18')); $acl }
        { Assert-P3ProtectedRuntimeRoot -Path $script:Root -CurrentSID ([Security.Principal.WindowsIdentity]::GetCurrent().User) } |
            Should -Throw '*owner*'
    }

    It 'rejects alternate streams' {
        $file = Join-Path $script:Fixture 'stable.json'
        [IO.File]::WriteAllText($file, '{"schema":"synthetic"}', [Text.UTF8Encoding]::new($false))
        Mock Get-Item { [pscustomobject]@{ Attributes = [IO.FileAttributes]::Normal; PSIsContainer = $false } }
        Mock Get-Item -ParameterFilter { $null -ne $Stream } {
            @(
                [pscustomobject]@{ Stream = ':$DATA' },
                [pscustomobject]@{ Stream = 'synthetic' }
            )
        }
        { Assert-P3RegularFile -Path $file -Label 'synthetic file' } | Should -Throw '*alternate data stream*'
    }

    It 'rejects handle identity drift during a bounded read' {
        $file = Join-Path $script:Fixture 'stable.json'
        [IO.File]::WriteAllText($file, '{"schema":"synthetic"}', [Text.UTF8Encoding]::new($false))
        Mock Get-Item { [pscustomobject]@{ Attributes = [IO.FileAttributes]::Normal; PSIsContainer = $false } }
        Mock Get-Item -ParameterFilter { $null -ne $Stream } { @([pscustomobject]@{ Stream = ':$DATA' }) }
        $script:IdentityCall = 0
        Mock Get-P3StreamIdentity { $script:IdentityCall++; if ($script:IdentityCall -eq 1) { 'one' } else { 'two' } }
        { Read-P3BoundedStableBytes -Path $file -MaximumBytes 65536 -Label 'stable file' } | Should -Throw '*identity changed*'
    }

    It 'rejects a reparse ancestor before opening the leaf' {
        $file = Join-Path $script:Fixture 'stable.json'
        [IO.File]::WriteAllText($file, '{"schema":"synthetic"}', [Text.UTF8Encoding]::new($false))
        $parent = Split-Path -Parent $file
        Mock Get-Item {
            param($LiteralPath)
            if ([IO.Path]::GetFullPath($LiteralPath) -ceq [IO.Path]::GetFullPath($parent)) {
                return [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint; PSIsContainer = $true }
            }
            [pscustomobject]@{ Attributes = [IO.FileAttributes]::Normal; PSIsContainer = $false }
        }
        { Resolve-P3FixedCleanPath -Path $file -Label 'reparse test' } | Should -Throw '*reparse*'
    }

    It 'rejects inherited ACLs even when the expected explicit rules exist' {
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $null = Invoke-P3RuntimePrepare -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root `
            -ExpectedManifestSHA256 $plan.manifest_sha256 -Confirmation $plan.confirmation_challenge
        Mock Get-Acl { $acl = New-P3RuntimeAcl; $acl.SetAccessRuleProtection($false, $true); $acl }
        { Assert-P3ProtectedRuntimeRoot -Path $script:Root -CurrentSID ([Security.Principal.WindowsIdentity]::GetCurrent().User) } |
            Should -Throw '*inherits*'
    }

    It 'assembles one validated context from actual Task 1 through 3 outputs in TestDrive' {
        $fingerprint = 'SHA256:synthetic-key'
        $script:Trust.public_key_fingerprint_sha256 = Get-TestTextSHA256 $fingerprint
        $plan = New-P3ManifestPlan -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root
        $null = Invoke-P3RuntimePrepare -Trust ([pscustomobject]$script:Trust) -RuntimeRoot $script:Root `
            -ExpectedManifestSHA256 $plan.manifest_sha256 -Confirmation $plan.confirmation_challenge
        $cloudObservation = [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-prelive-cloud-firewall-observation/v1'; droplet_association_count = 1
            tcp_22_management_source_count = 1; management_source_cidr_sha256 = ('2' * 64)
            udp_38556_all_ipv4_count = 1; udp_ipv6_count = 0; extra_inbound_rule_count = 0
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        Write-P3RuntimeJson -RuntimeRoot $script:Root -Name 'cloud-firewall-receipt.json' -Value `
            (New-P3CloudFirewallReceipt -Observation $cloudObservation -ExpectedIdentitySHA256 $script:Trust.accepted_cloud_firewall_sha256 `
                -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc ([DateTime]::UtcNow))
        $egress = New-P3EgressReceipt -ExpectedAuthoritySHA256 @($script:Trust.egress_authority_sha256) `
            -ExpectedManagementSourceCIDRSHA256 ('2' * 64) -NowUtc ([DateTime]::UtcNow) -HttpsRunner {
                param($authority) [pscustomobject]@{ authority_sha256=$authority;source_cidr_sha256=('2'*64);observed_at_utc=[DateTime]::UtcNow.ToString('o') }
            }
        Write-P3RuntimeJson -RuntimeRoot $script:Root -Name 'egress-receipt.json' -Value $egress
        Write-P3RuntimeJson -RuntimeRoot $script:Root -Name 'local-baseline-receipt.json' -Value `
            (New-P3LocalBaselineReceipt -ProtectedProfilePath (Join-Path $script:Fixture 'missing-profile.conf') `
                -NowUtc ([DateTime]::UtcNow) -AdapterRunner { @([pscustomobject]@{ InterfaceDescription='RedShield Virtual Adapter' }) })

        $context = & {
            param($Root, $ManifestHash, $Trust, $Fingerprint)
            . (Join-Path $PSScriptRoot '..\..\scripts\p3-ssh-agent.ps1')
            . (Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1')
            . (Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1')
            $manifest = Open-P3BoundedStableJson -Path (Join-Path $Root 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
            $agentManifest = [pscustomobject]@{
                manifest_sha256=$ManifestHash; git_ssh_agent_path=$Trust.git_ssh_agent_path; git_ssh_add_path=$Trust.git_ssh_add_path
                git_ssh_path=$Trust.git_ssh_path; git_scp_path=$Trust.git_scp_path; git_ssh_agent_sha256=$manifest.git_ssh_agent_sha256
                git_ssh_add_sha256=$manifest.git_ssh_add_sha256; git_ssh_sha256=$manifest.git_ssh_sha256; git_scp_sha256=$manifest.git_scp_sha256
                public_key_path=$Trust.public_key_path; private_key_path=$Trust.private_key_path; public_key_fingerprint_sha256=$Trust.public_key_fingerprint_sha256
            }
            $start = Start-P3Agent -Manifest $agentManifest `
                -AgentRunner { "SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;`nSSH_AGENT_PID=4242; export SSH_AGENT_PID;" } `
                -AddRunner { param($KeyPath) } -StopRunner { param($ProcessId) }
            $combined = Test-P3AgentState -Manifest $agentManifest -AgentReceipt $start `
                -ListRunner { "256 $Fingerprint p3 (ED25519)" } `
                -ProcessRunner { [pscustomobject]@{ Id=4242;Path=$agentManifest.git_ssh_agent_path;StartTime=[DateTime]::UtcNow } }
            Write-P3ProtectedAgentReceipt -Root $Root -ManifestSHA256 $ManifestHash -Receipt $combined
            $remoteContext = [pscustomobject]@{
                manifest_sha256=$ManifestHash; Agent=$combined
                Trust=[pscustomobject]@{
                    ssh_user=$Trust.ssh_user;ssh_host=$Trust.ssh_host;known_hosts_path=$Trust.known_hosts_path;known_hosts_sha256=$manifest.known_hosts_sha256
                    git_ssh_path=$Trust.git_ssh_path;git_ssh_sha256=$manifest.git_ssh_sha256;git_scp_path=$Trust.git_scp_path;git_scp_sha256=$manifest.git_scp_sha256
                    local_payload_path=$Trust.local_payload_path;local_payload_sha256=$manifest.local_payload_sha256;remote_payload_sha256=$manifest.remote_payload_sha256
                    management_source_cidr_sha256=$Trust.management_source_cidr_sha256
                    egress=@($Trust.egress_authority_sha256 | ForEach-Object { [pscustomobject]@{authority_sha256=$_;source_cidr_sha256=$Trust.management_source_cidr_sha256} })
                }
            }
            $absent = [ordered]@{state='absent';regular=$false;owner_match=$false;group_match=$false;mode_match=$false;payload_sha256=('0'*64);temporary_leftover_count=0}
            $installPlan = Invoke-P3RemoteInstallPlan -Context $remoteContext -SshRunner { $absent | ConvertTo-Json -Compress }
            $install = Invoke-P3RemoteInstall -Context $remoteContext -Plan $installPlan -ScpRunner { [pscustomobject]@{exit_code=0} } -SshRunner {
                param($Executable,$Arguments,$Mode)
                if ($Mode -ceq 'classify') { return ($absent | ConvertTo-Json -Compress) }
                if ($Mode -ceq 'cleanup') { return ([ordered]@{state='exact';regular=$true;owner_match=$true;group_match=$true;mode_match=$true;payload_sha256=$manifest.local_payload_sha256;temporary_leftover_count=0} | ConvertTo-Json -Compress) }
                [ordered]@{schema='home-gateway/p3-remote-helper-install-receipt/v1';target_state='exact';payload_sha256=$manifest.local_payload_sha256;owner_match=$true;group_match=$true;mode_match=$true;installed_by_gate=$true;preinstall_state='absent';temporary_leftover_count=0} | ConvertTo-Json -Compress
            }
            Write-P3ProtectedInstallReceipt -Root $Root -ManifestSHA256 $ManifestHash -Receipt $install
            if ($ManifestHash -cnotmatch '^[0-9a-f]{64}$') { throw 'integration manifest binding drifted' }
            return Get-P3PreliveContext -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestHash
        } $script:Root $plan.manifest_sha256 ([pscustomobject]$script:Trust) $fingerprint
        $context.ManifestSHA256 | Should -BeExactly $plan.manifest_sha256
        $context.Agent.schema | Should -BeExactly 'home-gateway/p3-ssh-agent-combined-receipt/v2'
        $context.Install.schema | Should -BeExactly 'home-gateway/p3-remote-helper-install-receipt/v1'
        $context.ExpectedPeerCount | Should -Be 1
        $env:SSH_AUTH_SOCK = $null; $env:SSH_AGENT_PID = $null
    }

    It 'runs the actual owned action switch and reobserves exact terminal cleanup' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1')
        $fixture = Initialize-OwnedBatchRuntime -Root $script:Root -Trust $script:Trust
        $script:OwnedWaits = 0; $script:OwnedReobservedPid = 0
        $boundaries = New-OwnedBatchBoundaries -Fixture $fixture -JsonRunner { throw 'JSON runner is not expected' } -StopRunner { param($ProcessId) }

        $result = Invoke-P3OwnedGuardAction -SelectedAction 'ValidateOnly' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -InputObject $null -ExpectedBodyPlanSHA256 '' `
            -BodyConfirmation '' -Boundaries $boundaries

        $result.prelive_inputs_valid | Should -BeTrue
        $script:OwnedWaits | Should -Be 1
        $script:OwnedReobservedPid | Should -Be 4242
        Test-Path -LiteralPath (Join-Path $fixture.Root 'agent-receipt.json') | Should -BeFalse
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'stops and cleans the owned action after body failure and cancellation' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1')
        foreach ($failure in @(
            { throw 'synthetic body failure' },
            { throw [OperationCanceledException]::new('synthetic cancellation') }
        )) {
            $root = Join-Path $TestDrive ('owned-' + [guid]::NewGuid().ToString('N'))
            $fixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $fixtureRoot
            $trust = New-TrustFixture -Root $fixtureRoot
            $fixture = Initialize-OwnedBatchRuntime -Root $root -Trust $trust
            $script:OwnedWaits = 0; $script:OwnedReobservedPid = 0
            $boundaries = New-OwnedBatchBoundaries -Fixture $fixture -JsonRunner $failure -StopRunner { param($ProcessId) }
            $caught = $null
            try {
                $null = Invoke-P3OwnedGuardAction -SelectedAction 'Reconcile' -RuntimeRoot $fixture.Root `
                    -ExpectedManifestSHA256 $fixture.ManifestSHA256 -InputObject $null -ExpectedBodyPlanSHA256 '' `
                    -BodyConfirmation '' -Boundaries $boundaries
            } catch { $caught = $_ }
            $caught | Should -Not -BeNullOrEmpty
            $caught.Exception.Message | Should -Match 'synthetic body failure|synthetic cancellation'
            $script:OwnedWaits | Should -Be 1
            $script:OwnedReobservedPid | Should -Be 4242
            Test-Path -LiteralPath (Join-Path $fixture.Root 'agent-receipt.json') | Should -BeFalse
            $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
            $env:SSH_AGENT_PID | Should -BeNullOrEmpty
        }
    }

    It 'makes an owned action stop failure terminal' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1')
        $fixture = Initialize-OwnedBatchRuntime -Root $script:Root -Trust $script:Trust
        $boundaries = New-OwnedBatchBoundaries -Fixture $fixture -JsonRunner { throw 'JSON runner is not expected' } `
            -StopRunner { throw 'synthetic stop failure' }
        { Invoke-P3OwnedGuardAction -SelectedAction 'ValidateOnly' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -InputObject $null -ExpectedBodyPlanSHA256 '' `
            -BodyConfirmation '' -Boundaries $boundaries } | Should -Throw '*stop failure*'
    }

    It 'tears down the newly owned agent when initial key or process validation fails' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1')
        foreach ($failureKind in @('list', 'process')) {
            $root = Join-Path $TestDrive ("initial-$failureKind-" + [guid]::NewGuid().ToString('N'))
            $fixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $fixtureRoot
            $trust = New-TrustFixture -Root $fixtureRoot
            $fixture = Initialize-OwnedBatchRuntime -Root $root -Trust $trust
            $script:OwnedStops = 0; $script:OwnedWaits = 0; $script:OwnedReobservedPid = 0
            $boundaries = New-OwnedBatchBoundaries -Fixture $fixture -JsonRunner { throw 'body must not run' } `
                -StopRunner { param($ProcessId) $script:OwnedStops++ }
            if ($failureKind -ceq 'list') { $boundaries.ListRunner = { throw 'synthetic initial list failure' } }
            else { $boundaries.ProcessRunner = { throw 'synthetic initial process failure' } }

            { Invoke-P3OwnedGuardAction -SelectedAction 'ValidateOnly' -RuntimeRoot $fixture.Root `
                -ExpectedManifestSHA256 $fixture.ManifestSHA256 -InputObject $null -ExpectedBodyPlanSHA256 '' `
                -BodyConfirmation '' -Boundaries $boundaries } | Should -Throw '*synthetic initial*'

            $script:OwnedStops | Should -Be 1
            $script:OwnedWaits | Should -Be 1
            $script:OwnedReobservedPid | Should -Be 4242
            $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
            $env:SSH_AGENT_PID | Should -BeNullOrEmpty
        }
    }

    It 'emergency cleans guard and remote agents when protected receipt persistence fails' {
        foreach ($owner in @('guard', 'remote')) {
            $root = Join-Path $TestDrive ("persist-$owner-" + [guid]::NewGuid().ToString('N'))
            $fixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $fixtureRoot
            $trust = New-TrustFixture -Root $fixtureRoot
            $fixture = Initialize-OwnedBatchRuntime -Root $root -Trust $trust
            [IO.File]::WriteAllText((Join-Path $fixture.Root 'agent-receipt.json'), '{}', [Text.UTF8Encoding]::new($false))
            $script:OwnedAgentStarts=0;$script:OwnedClockCalls=0;$script:OwnedStops=0;$script:OwnedDeletes=0
            $script:OwnedWaits=0;$script:OwnedReobservedPid=0;$script:OwnedBodyCalls=0
            $caught = $null
            if ($owner -ceq 'guard') {
                . (Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1')
                $boundaries = New-OwnedBatchBoundaries -Fixture $fixture `
                    -JsonRunner { $script:OwnedBodyCalls++; throw 'body must not run' } `
                    -StopRunner { param($ProcessId) $script:OwnedStops++ }
                $boundaries.DeleteRunner = { $script:OwnedDeletes++ }
                try {
                    $null = Invoke-P3OwnedGuardAction -SelectedAction 'Reconcile' -RuntimeRoot $fixture.Root `
                        -ExpectedManifestSHA256 $fixture.ManifestSHA256 -InputObject $null -ExpectedBodyPlanSHA256 '' `
                        -BodyConfirmation '' -Boundaries $boundaries
                } catch { $caught = $_ }
            } else {
                . (Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1')
                $boundaries = New-OwnedRemoteBoundaries -Fixture $fixture `
                    -SshRunner { $script:OwnedBodyCalls++; throw 'body must not run' } -ScpRunner { throw 'SCP must not run' } `
                    -StopRunner { param($ProcessId) $script:OwnedStops++ }
                $boundaries.DeleteRunner = { $script:OwnedDeletes++ }
                try {
                    $null = Invoke-P3RemoteActionSwitch -SelectedAction 'RemoteInstallPlan' -RuntimeRoot $fixture.Root `
                        -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 '' -Confirmation '' `
                        -InputObject $null -Boundaries $boundaries
                } catch { $caught = $_ }
            }
            $env:SSH_AUTH_SOCK=$null;$env:SSH_AGENT_PID=$null
            $caught | Should -Not -BeNullOrEmpty
            $script:OwnedBodyCalls | Should -Be 0
            $script:OwnedDeletes | Should -Be 1
            $script:OwnedStops | Should -Be 1
            $script:OwnedWaits | Should -Be 1
            $script:OwnedReobservedPid | Should -Be 4242
        }
    }

    It 'never stops a reused PID after validated guard or remote process identity drifts' {
        foreach ($owner in @('guard', 'remote')) {
            foreach ($drift in @('path', 'start')) {
                $root = Join-Path $TestDrive ("validated-$owner-$drift-" + [guid]::NewGuid().ToString('N'))
                $fixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
                $null = New-Item -ItemType Directory -Path $fixtureRoot
                $trust = New-TrustFixture -Root $fixtureRoot
                $fixture = Initialize-OwnedBatchRuntime -Root $root -Trust $trust
                $processState = [pscustomobject]@{ Calls=0;Fixture=$fixture;Trust=$trust;Drift=$drift }
                $script:OwnedAgentStarts = 0; $script:OwnedClockCalls = 0; $script:OwnedStops = 0; $script:OwnedDeletes = 0
                $processRunner = {
                    param($ProcessId)
                    $processState.Calls++
                    $path = if ($processState.Calls -eq 1 -or $processState.Drift -ceq 'start') { $processState.Fixture.AgentPath } else { $processState.Trust.git_ssh_path }
                    $start = if ($processState.Calls -eq 1 -or $processState.Drift -ceq 'path') { [DateTime]::UtcNow } else { [DateTime]::UtcNow.AddMinutes(-5) }
                    [pscustomobject]@{ Id=$ProcessId;Path=$path;StartTime=$start }
                }.GetNewClosure()
                $caught = $null
                if ($owner -ceq 'guard') {
                    . (Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1')
                    $boundaries = New-OwnedBatchBoundaries -Fixture $fixture -JsonRunner { throw 'body runner must not run' } `
                        -StopRunner { param($ProcessId) $script:OwnedStops++ }
                    $boundaries.ProcessRunner = $processRunner
                    $boundaries.DeleteRunner = { $script:OwnedDeletes++ }
                    try {
                        $null = Invoke-P3OwnedGuardAction -SelectedAction 'ValidateOnly' -RuntimeRoot $fixture.Root `
                            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -InputObject $null -ExpectedBodyPlanSHA256 '' `
                            -BodyConfirmation '' -Boundaries $boundaries
                    } catch { $caught = $_ }
                } else {
                    . (Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1')
                    $ssh = { param($Executable,$Arguments,$Mode,$Request) `
                        ([ordered]@{state='absent';regular=$false;owner_match=$false;group_match=$false;mode_match=$false;payload_sha256=('0'*64);temporary_leftover_count=0}|ConvertTo-Json -Compress) }
                    $boundaries = New-OwnedRemoteBoundaries -Fixture $fixture -SshRunner $ssh `
                        -ScpRunner { throw 'SCP must not run' } -StopRunner { param($ProcessId) $script:OwnedStops++ }
                    $boundaries.ProcessRunner = $processRunner
                    $boundaries.DeleteRunner = { $script:OwnedDeletes++ }
                    try {
                        $null = Invoke-P3RemoteActionSwitch -SelectedAction 'RemoteInstallPlan' -RuntimeRoot $fixture.Root `
                            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 '' -Confirmation '' `
                            -InputObject $null -Boundaries $boundaries
                    } catch { $caught = $_ }
                }
                $env:SSH_AUTH_SOCK = $null; $env:SSH_AGENT_PID = $null
                $caught | Should -Not -BeNullOrEmpty
                $caught.Exception.Message | Should -Match 'agent process'
                $processState.Calls | Should -Be 2
                $script:OwnedDeletes | Should -Be 0
                $script:OwnedStops | Should -Be 0
                Test-Path -LiteralPath (Join-Path $fixture.Root 'agent-receipt.json') | Should -BeTrue
            }
        }
    }

    It 'does not stop a mismatched PID during initial-validation emergency teardown' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1')
        $fixture = Initialize-OwnedBatchRuntime -Root $script:Root -Trust $script:Trust
        $processState = [pscustomobject]@{ Calls=0;Fixture=$fixture;Trust=$script:Trust }
        $script:OwnedStops = 0; $script:OwnedDeletes = 0; $script:OwnedWaits = 0
        $boundaries = New-OwnedBatchBoundaries -Fixture $fixture -JsonRunner { throw 'body must not run' } `
            -StopRunner { param($ProcessId) $script:OwnedStops++ }
        $boundaries.ListRunner = { throw 'synthetic initial list failure' }
        $boundaries.DeleteRunner = { $script:OwnedDeletes++ }
        $boundaries.ProcessRunner = {
            param($ProcessId)
            $processState.Calls++
            $path = if ($processState.Calls -eq 1) { $processState.Fixture.AgentPath } else { $processState.Trust.git_ssh_path }
            [pscustomobject]@{ Id=$ProcessId;Path=$path;StartTime=[DateTime]::UtcNow }
        }.GetNewClosure()

        { Invoke-P3OwnedGuardAction -SelectedAction 'ValidateOnly' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -InputObject $null -ExpectedBodyPlanSHA256 '' `
            -BodyConfirmation '' -Boundaries $boundaries } | Should -Throw '*emergency cleanup failed*'

        $processState.Calls | Should -Be 2
        $script:OwnedDeletes | Should -Be 0
        $script:OwnedStops | Should -Be 0
        $script:OwnedWaits | Should -Be 0
    }

    It 'rejects a self-consistent foreign AgentStart action before any runner' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-ssh-agent.ps1')
        $fixture = Initialize-OwnedBatchRuntime -Root $script:Root -Trust $script:Trust
        $protected = Get-P3ProtectedAgentManifest -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256
        $foreign = $protected | Select-Object *
        $foreign.manifest_sha256 = ('f' * 64)
        $foreign.public_key_fingerprint_sha256 = ('e' * 64)
        $foreignPlan = New-P3AgentPlan -Manifest $foreign
        $script:MutationRunnerCalls = 0
        $boundaries = [pscustomobject]@{
            AgentRunner={ $script:MutationRunnerCalls++ };AddRunner={ $script:MutationRunnerCalls++ };StopRunner={ $script:MutationRunnerCalls++ }
            ListRunner={ $script:MutationRunnerCalls++ };ProcessRunner={ $script:MutationRunnerCalls++ };DeleteRunner={ $script:MutationRunnerCalls++ }
            WaitRunner={ $script:MutationRunnerCalls++ };ReobserveRunner={ $script:MutationRunnerCalls++ };SocketExistsRunner={ $script:MutationRunnerCalls++ }
            ReceiptRemoveRunner={ $script:MutationRunnerCalls++ }
        }
        { Invoke-P3AgentAction -SelectedAction 'AgentStart' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 $foreignPlan.plan_sha256 `
            -Confirmation $foreignPlan.confirmation_challenge -InputObject $foreign -Boundaries $boundaries } |
            Should -Throw '*protected*'
        $script:MutationRunnerCalls | Should -Be 0

        $foreignReceipt = [pscustomobject]@{
            schema='home-gateway/p3-ssh-agent-receipt/v1';manifest_sha256=('f' * 64);agent_pid=4242
            socket='/tmp/ssh-synthetic/agent.4242';agent_executable_path=$protected.git_ssh_agent_path
            agent_executable_sha256=$protected.git_ssh_agent_sha256;expected_fingerprint_sha256=$protected.public_key_fingerprint_sha256
            started_at_utc=[DateTime]::UtcNow.ToString('o')
        }
        { Invoke-P3AgentAction -SelectedAction 'AgentValidate' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 '' -Confirmation '' `
            -InputObject ([pscustomobject]@{manifest=$protected;receipt=$foreignReceipt}) -Boundaries $boundaries } |
            Should -Throw '*receipt*protected*'
        $script:MutationRunnerCalls | Should -Be 0
    }

    It 'rejects an alternate AgentStop receipt before every mutation runner' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-ssh-agent.ps1')
        $fixture = Initialize-OwnedBatchRuntime -Root $script:Root -Trust $script:Trust
        $manifest = Get-P3ProtectedAgentManifest -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256
        $stored = [pscustomobject][ordered]@{
            schema='home-gateway/p3-ssh-agent-combined-receipt/v2';manifest_sha256=$fixture.ManifestSHA256;agent_pid=4242
            socket='/tmp/ssh-synthetic/agent.4242';agent_executable_path=$manifest.git_ssh_agent_path
            agent_executable_sha256=$manifest.git_ssh_agent_sha256;expected_fingerprint_sha256=$manifest.public_key_fingerprint_sha256
            started_at_utc='2026-08-31T12:00:00.1234500Z';loaded_key_count=1;expected_key_match=$true;agent_pid_match=$true;toolchain_match=$true
        }
        Write-P3ProtectedAgentReceipt -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256 -Receipt $stored
        $alternate = $stored | ConvertTo-Json -Depth 16 | ConvertFrom-Json
        $alternate.agent_pid = 4343; $alternate.socket = '/tmp/ssh-synthetic/agent.4343'
        $raw = [pscustomobject][ordered]@{
            schema='home-gateway/p3-ssh-agent-receipt/v1';manifest_sha256=$fixture.ManifestSHA256;agent_pid=4343
            socket=$alternate.socket;agent_executable_path=$alternate.agent_executable_path
            agent_executable_sha256=$alternate.agent_executable_sha256;expected_fingerprint_sha256=$alternate.expected_fingerprint_sha256
            started_at_utc=$alternate.started_at_utc
        }
        $env:SSH_AUTH_SOCK = $raw.socket; $env:SSH_AGENT_PID = [string]$raw.agent_pid
        $script:MutationRunnerCalls = 0
        $boundaries = [pscustomobject]@{
            AgentRunner={throw 'must not run'};AddRunner={throw 'must not run'}
            ListRunner={ '256 SHA256:synthetic-key p3 (ED25519)' }
            ProcessRunner={ [pscustomobject]@{Id=4343;Path=$manifest.git_ssh_agent_path;StartTime=[DateTime]$raw.started_at_utc} }.GetNewClosure()
            DeleteRunner={ $script:MutationRunnerCalls++ };StopRunner={ $script:MutationRunnerCalls++ }
            WaitRunner={ $script:MutationRunnerCalls++ };ReobserveRunner={ $script:MutationRunnerCalls++; @() }
            SocketExistsRunner={ $script:MutationRunnerCalls++; $false };ReceiptRemoveRunner={ $script:MutationRunnerCalls++ }
        }
        { Invoke-P3AgentAction -SelectedAction 'AgentStop' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 '' -Confirmation '' `
            -InputObject ([pscustomobject]@{manifest=$manifest;receipt=$raw;combined_receipt=$alternate}) -Boundaries $boundaries } |
            Should -Throw '*protected*receipt*'
        $script:MutationRunnerCalls | Should -Be 0
        $env:SSH_AUTH_SOCK = $null; $env:SSH_AGENT_PID = $null
    }

    It 'rejects a self-consistent foreign RemoteInstall action before SSH or SCP' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-ssh-agent.ps1')
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1')
        $fixture = Initialize-OwnedBatchRuntime -Root $script:Root -Trust $script:Trust
        $agentManifest = Get-P3ProtectedAgentManifest -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256
        $combined = [pscustomobject][ordered]@{
            schema='home-gateway/p3-ssh-agent-combined-receipt/v2';manifest_sha256=$fixture.ManifestSHA256;agent_pid=4242
            socket='/tmp/ssh-synthetic/agent.4242';agent_executable_path=$agentManifest.git_ssh_agent_path
            agent_executable_sha256=$agentManifest.git_ssh_agent_sha256;expected_fingerprint_sha256=$agentManifest.public_key_fingerprint_sha256
            started_at_utc=[DateTime]::UtcNow.ToString('o');loaded_key_count=1;expected_key_match=$true;agent_pid_match=$true;toolchain_match=$true
        }
        Write-P3RuntimeJson -RuntimeRoot $fixture.Root -Name 'agent-receipt.json' -Value $combined
        $protected = Get-P3ProtectedRemoteContext -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256
        $foreign = $protected | ConvertTo-Json -Depth 16 | ConvertFrom-Json
        $foreign.manifest_sha256 = ('f' * 64)
        $foreign.Agent.manifest_sha256 = ('f' * 64)
        $script:MutationRunnerCalls = 0
        $boundaries = [pscustomobject]@{
            SshRunner={ $script:MutationRunnerCalls++; throw 'must not run' }
            ScpRunner={ $script:MutationRunnerCalls++; throw 'must not run' }
            ClockRunner={ $fixture.NowUtc.AddSeconds(30) }.GetNewClosure()
            ReceiptRemoveRunner={ $script:MutationRunnerCalls++ }
        }
        { Invoke-P3RemoteAction -SelectedAction 'RemoteInstall' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 ('0' * 64) -Confirmation '' `
            -InputObject ([pscustomobject]@{ context=$foreign; plan=$null }) -Boundaries $boundaries } |
            Should -Throw '*protected*'
        $script:MutationRunnerCalls | Should -Be 0

        $badReceipt = [pscustomobject][ordered]@{
            schema='home-gateway/p3-remote-helper-install-receipt/v1';target_state='exact';payload_sha256=('f' * 64)
            owner_match=$true;group_match=$true;mode_match=$true;installed_by_gate=$true;preinstall_state='absent';temporary_leftover_count=0
        }
        { Write-P3ProtectedInstallReceipt -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256 -Receipt $badReceipt } |
            Should -Throw '*payload*'
    }

    It 'rejects a forged RemoteRemove receipt before every SSH mutation runner' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-ssh-agent.ps1')
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1')
        $fixture = Initialize-OwnedBatchRuntime -Root $script:Root -Trust $script:Trust
        $manifest = Get-P3ProtectedAgentManifest -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256
        $combined = [pscustomobject][ordered]@{
            schema='home-gateway/p3-ssh-agent-combined-receipt/v2';manifest_sha256=$fixture.ManifestSHA256;agent_pid=4242
            socket='/tmp/ssh-synthetic/agent.4242';agent_executable_path=$manifest.git_ssh_agent_path
            agent_executable_sha256=$manifest.git_ssh_agent_sha256;expected_fingerprint_sha256=$manifest.public_key_fingerprint_sha256
            started_at_utc='2026-08-31T12:00:00.1234500Z';loaded_key_count=1;expected_key_match=$true;agent_pid_match=$true;toolchain_match=$true
        }
        Write-P3ProtectedAgentReceipt -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256 -Receipt $combined
        $installPath = Join-Path $fixture.Root 'remote-install-receipt.json'
        [IO.File]::Delete($installPath)
        $stored = [pscustomobject][ordered]@{
            schema='home-gateway/p3-remote-helper-install-receipt/v1';target_state='exact'
            payload_sha256=(Get-P3ProtectedRemoteContext -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256).Trust.local_payload_sha256
            owner_match=$true;group_match=$true;mode_match=$true;installed_by_gate=$false;preinstall_state='exact';temporary_leftover_count=0
        }
        Write-P3RuntimeJson -RuntimeRoot $fixture.Root -Name 'remote-install-receipt.json' -Value $stored
        $context = Get-P3ProtectedRemoteContext -Root $fixture.Root -ManifestSHA256 $fixture.ManifestSHA256
        $forged = $stored | Select-Object *
        $forged.installed_by_gate = $true; $forged.preinstall_state = 'absent'
        $exactState = [ordered]@{state='exact';regular=$true;owner_match=$true;group_match=$true;mode_match=$true;payload_sha256=$forged.payload_sha256;temporary_leftover_count=0}
        $plan = Invoke-P3RemoteRemovePlan -Context $context -InstallReceipt $forged -SshRunner { $exactState | ConvertTo-Json -Compress }
        $script:MutationRunnerCalls = 0
        $boundaries = [pscustomobject]@{
            ScpRunner={ $script:MutationRunnerCalls++; throw 'must not run' }
            SshRunner={
                param($Executable,$Arguments,$Mode)
                $script:MutationRunnerCalls++
                if($Mode -ceq 'classify'){return ($exactState|ConvertTo-Json -Compress)}
                return '{"schema":"home-gateway/p3-remote-helper-remove-receipt/v1","removed":true,"target_state":"absent","temporary_leftover_count":0}'
            }.GetNewClosure()
            ClockRunner={ $fixture.NowUtc.AddSeconds(30) }.GetNewClosure()
            ReceiptRemoveRunner={ $script:MutationRunnerCalls++ }
        }
        { Invoke-P3RemoteAction -SelectedAction 'RemoteRemove' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 $plan.remove_plan_sha256 `
            -Confirmation $plan.confirmation_challenge -InputObject ([pscustomobject]@{context=$context;install_receipt=$forged;remove_plan=$plan}) `
            -Boundaries $boundaries } | Should -Throw '*protected*receipt*'
        $script:MutationRunnerCalls | Should -Be 0
    }

    It 'runs all protected remote actions in one owned agent session per action' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1')
        $fixture = Initialize-OwnedBatchRuntime -Root $script:Root -Trust $script:Trust
        [IO.File]::Delete((Join-Path $fixture.Root 'remote-install-receipt.json'))
        $script:OwnedAgentStarts=0;$script:OwnedStops=0;$script:OwnedWaits=0;$script:OwnedClockCalls=0;$script:RemoteInstalled=$false
        $payloadHash = (Open-P3BoundedStableJson -Path (Join-Path $fixture.Root 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties).local_payload_sha256
        $ssh = {
            param($Executable,$Arguments,$Mode,$Request)
            if($Mode -ceq 'classify'){
                $state=if($script:RemoteInstalled){'exact'}else{'absent'}
                return ([ordered]@{state=$state;regular=$script:RemoteInstalled;owner_match=$script:RemoteInstalled;group_match=$script:RemoteInstalled;mode_match=$script:RemoteInstalled;payload_sha256=if($script:RemoteInstalled){$payloadHash}else{'0'*64};temporary_leftover_count=0}|ConvertTo-Json -Compress)
            }
            if($Mode -ceq 'install'){$script:RemoteInstalled=$true;return ([ordered]@{schema='home-gateway/p3-remote-helper-install-receipt/v1';target_state='exact';payload_sha256=$payloadHash;owner_match=$true;group_match=$true;mode_match=$true;installed_by_gate=$true;preinstall_state='absent';temporary_leftover_count=0}|ConvertTo-Json -Compress)}
            if($Mode -ceq 'cleanup'){return ([ordered]@{state='exact';regular=$true;owner_match=$true;group_match=$true;mode_match=$true;payload_sha256=$payloadHash;temporary_leftover_count=0}|ConvertTo-Json -Compress)}
            if($Mode -ceq 'remove'){$script:RemoteInstalled=$false;return '{"schema":"home-gateway/p3-remote-helper-remove-receipt/v1","removed":true,"target_state":"absent","temporary_leftover_count":0}'}
            throw 'unexpected remote mode'
        }.GetNewClosure()
        $boundaries = New-OwnedRemoteBoundaries -Fixture $fixture -SshRunner $ssh `
            -ScpRunner { [pscustomobject]@{exit_code=0} } -StopRunner {param($ProcessId)$script:OwnedStops++}

        $installPlan = Invoke-P3RemoteActionSwitch -SelectedAction 'RemoteInstallPlan' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 '' -Confirmation '' -InputObject $null -Boundaries $boundaries
        $installReceipt = Invoke-P3RemoteActionSwitch -SelectedAction 'RemoteInstall' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 $installPlan.plan_sha256 `
            -Confirmation $installPlan.confirmation_challenge -InputObject ([pscustomobject]@{plan=$installPlan}) -Boundaries $boundaries
        $removePlan = Invoke-P3RemoteActionSwitch -SelectedAction 'RemoteRemovePlan' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 '' -Confirmation '' `
            -InputObject ([pscustomobject]@{install_receipt=$installReceipt}) -Boundaries $boundaries
        $removed = Invoke-P3RemoteActionSwitch -SelectedAction 'RemoteRemove' -RuntimeRoot $fixture.Root `
            -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 $removePlan.remove_plan_sha256 `
            -Confirmation $removePlan.confirmation_challenge -InputObject ([pscustomobject]@{install_receipt=$installReceipt;remove_plan=$removePlan}) -Boundaries $boundaries

        $removed.removed | Should -BeTrue
        $script:OwnedAgentStarts | Should -Be 4
        $script:OwnedStops | Should -Be 4
        $script:OwnedWaits | Should -Be 4
        $script:OwnedClockCalls | Should -Be 4
        Test-Path -LiteralPath (Join-Path $fixture.Root 'agent-receipt.json') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $fixture.Root 'remote-install-receipt.json') | Should -BeFalse
    }

    It 'rejects stale future schema and source-mutated remote egress before SSH or SCP' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1')
        $cases = @(
            @{Change={param($r)$r.observed_at_utc=[DateTime]::Parse('2000-01-01T00:00:00Z').ToString('o')};Expected='*egress*'},
            @{Change={param($r)$r.observations[0].observed_at_utc=[DateTime]::Parse('2099-01-01T00:00:00Z').ToString('o')};Expected='*egress*'},
            @{Change={param($r)$r|Add-Member -NotePropertyName extra -NotePropertyValue $true};Expected='*schema*'},
            @{Change={param($r)$r.observations[1].source_cidr_sha256=('a'*64)};Expected='*egress*'}
        )
        foreach($case in $cases){
            $root=Join-Path $TestDrive ('egress-'+[guid]::NewGuid().ToString('N'));$fixtureRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null=New-Item -ItemType Directory -Path $fixtureRoot;$trust=New-TrustFixture -Root $fixtureRoot
            $fixture=Initialize-OwnedBatchRuntime -Root $root -Trust $trust;Set-ProtectedEgressReceipt -Root $fixture.Root -Change $case.Change
            $script:OwnedClockCalls=0;$script:OwnedAgentStarts=0;$script:OwnedStops=0;$script:OwnedWaits=0;$script:MutationRunnerCalls=0
            $boundaries=New-OwnedRemoteBoundaries -Fixture $fixture -SshRunner {$script:MutationRunnerCalls++;throw 'SSH must not run'} `
                -ScpRunner {$script:MutationRunnerCalls++;throw 'SCP must not run'} -StopRunner {param($ProcessId)$script:OwnedStops++}
            {Invoke-P3RemoteActionSwitch -SelectedAction 'RemoteInstallPlan' -RuntimeRoot $fixture.Root `
                -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 '' -Confirmation '' -InputObject $null -Boundaries $boundaries}|
                Should -Throw $case.Expected
            $script:MutationRunnerCalls|Should -Be 0;$script:OwnedClockCalls|Should -Be 1;$script:OwnedStops|Should -Be 1;$script:OwnedWaits|Should -Be 1
        }
    }

    It 'cleans the owned remote agent on validation body cancellation and cleanup failure' {
        . (Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1')
        foreach($kind in @('validation','body','cancellation','cleanup')){
            $root=Join-Path $TestDrive ("remote-$kind-"+[guid]::NewGuid().ToString('N'));$fixtureRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null=New-Item -ItemType Directory -Path $fixtureRoot;$trust=New-TrustFixture -Root $fixtureRoot;$fixture=Initialize-OwnedBatchRuntime -Root $root -Trust $trust
            $script:OwnedClockCalls=0;$script:OwnedAgentStarts=0;$script:OwnedStops=0;$script:OwnedWaits=0;$script:MutationRunnerCalls=0
            $ssh=if($kind -ceq 'cancellation'){{throw [OperationCanceledException]::new('synthetic remote cancellation')}}else{{throw 'synthetic remote body failure'}}
            $stop=if($kind -ceq 'cleanup'){{param($ProcessId)$script:OwnedStops++;throw 'synthetic remote stop failure'}}else{{param($ProcessId)$script:OwnedStops++}}
            $boundaries=New-OwnedRemoteBoundaries -Fixture $fixture -SshRunner $ssh -ScpRunner {throw 'SCP must not run'} -StopRunner $stop
            if($kind -ceq 'validation'){$boundaries.ListRunner={throw 'synthetic remote validation failure'}}
            $expectedFailure=if($kind -ceq 'cleanup'){'*stop failure*'}else{'*synthetic remote*'}
            {Invoke-P3RemoteActionSwitch -SelectedAction 'RemoteInstallPlan' -RuntimeRoot $fixture.Root `
                -ExpectedManifestSHA256 $fixture.ManifestSHA256 -ExpectedPlanSHA256 '' -Confirmation '' -InputObject $null -Boundaries $boundaries}|
                Should -Throw $expectedFailure
            $script:OwnedStops|Should -Be 1;$script:OwnedWaits|Should -Be 1
            if($kind -ceq 'cleanup'){Test-Path -LiteralPath (Join-Path $fixture.Root 'agent-receipt.json')|Should -BeTrue}
            else{Test-Path -LiteralPath (Join-Path $fixture.Root 'agent-receipt.json')|Should -BeFalse}
            $env:SSH_AUTH_SOCK|Should -BeNullOrEmpty;$env:SSH_AGENT_PID|Should -BeNullOrEmpty
        }
    }
}
