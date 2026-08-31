$ErrorActionPreference = 'Stop'

Describe 'P3 protected pre-live runtime' {
    BeforeAll {
        $script:Runtime = Join-Path $PSScriptRoot '..\..\scripts\p3-prelive-runtime.ps1'
        $script:Root = Join-Path $TestDrive 'protected-v1'
        . $script:Runtime

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
            $cloudObservation = [pscustomobject][ordered]@{
                schema = 'home-gateway/p3-prelive-cloud-firewall-observation/v1'
                droplet_association_count = 1; tcp_22_management_source_count = 1
                management_source_cidr_sha256 = ('2' * 64); udp_38556_all_ipv4_count = 1
                udp_ipv6_count = 0; extra_inbound_rule_count = 0; observed_at_utc = [DateTime]::UtcNow.ToString('o')
            }
            return [ordered]@{
                schema = 'home-gateway/p3-prelive-trust-input/v1'
                ssh_host = '192.0.2.10'
                ssh_user = 'homegateway'
                known_hosts_path = $files.known_hosts
                public_key_path = $files.'operator.pub'
                private_key_path = (Join-Path $Root 'operator')
                public_key_fingerprint_sha256 = ('1' * 64)
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
                    runtime_identity_sha256 = ('f' * 64); prepared_syncconf_sha256 = ('0' * 64)
                    peer_fingerprint_sha256 = @(('8' * 64)); persistent_peer_set_sha256 = $peerSetHash
                    live_peer_set_sha256 = $peerSetHash; metadata_peer_set_sha256 = $peerSetHash
                    candidate_leftover_count = 0; temporary_leftover_count = 0; atomic_leftover_count = 0
                    firewall_identity_sha256 = ('a' * 64); payload_sha256 = $payloadHash; protocol_sha256 = ('4' * 64)
                }
                accepted_cloud_firewall_sha256 = Get-P3CloudFirewallIdentitySHA256 $cloudObservation
                rollback_paths = [ordered]@{
                    persistent_config_path = '/opt/amnezia/awg/wg0.conf'
                    metadata_path = '/opt/amnezia/awg/peers.json'
                    temporary_path = '/run/home-gateway-p3-peer-guard/candidate.tmp'
                    syncconf_path = '/run/home-gateway-p3-peer-guard/awg.conf'
                }
                egress_authority_sha256 = @(('7' * 64), ('8' * 64), ('9' * 64))
            }
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
            'accepted_cloud_firewall_sha256', 'accepted_server_baseline_sha256',
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
}
