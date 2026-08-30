$ErrorActionPreference = 'Stop'

Describe 'P3 protected pre-live runtime' {
    BeforeAll {
        $script:Runtime = Join-Path $PSScriptRoot '..\..\scripts\p3-prelive-runtime.ps1'
        $script:Root = Join-Path $TestDrive 'protected-v1'
        . $script:Runtime

        function New-TrustFixture {
            param([string]$Root)
            $files = @{}
            foreach ($name in @('known_hosts', 'operator.pub', 'ssh-agent.exe', 'ssh-add.exe', 'ssh.exe', 'scp.exe', 'guard.py')) {
                $path = Join-Path $Root $name
                [IO.File]::WriteAllText($path, "synthetic-$name", [Text.UTF8Encoding]::new($false))
                $files[$name] = $path
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
                remote_payload_sha256 = ('3' * 64)
                protocol_sha256 = ('4' * 64)
                accepted_server_baseline_sha256 = ('5' * 64)
                accepted_cloud_firewall_sha256 = ('6' * 64)
                egress_authority_sha256 = @(('7' * 64), ('8' * 64), ('9' * 64))
            }
        }
    }

    BeforeEach {
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
        $receipt = New-P3CloudFirewallReceipt -Observation ([pscustomobject][ordered]@{
            schema = 'home-gateway/p3-prelive-cloud-firewall-observation/v1'
            droplet_association_count = 1
            tcp_22_management_source_count = 1
            management_source_cidr_sha256 = ('2' * 64)
            udp_38556_all_ipv4_count = 1
            udp_ipv6_count = 0
            extra_inbound_rule_count = 0
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
        }) -ExpectedIdentitySHA256 ('6' * 64) -NowUtc ([DateTime]::UtcNow)
        $receipt.owner_observed | Should -BeTrue
        $receipt.live_mutation_performed | Should -BeFalse
        { New-P3CloudFirewallReceipt -Observation ([pscustomobject]@{
            schema = 'home-gateway/p3-prelive-cloud-firewall-observation/v1'; droplet_association_count = 1
            tcp_22_management_source_count = 1; management_source_cidr_sha256 = ('2' * 64)
            udp_38556_all_ipv4_count = 1; udp_ipv6_count = 0; extra_inbound_rule_count = 1
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
        }) -ExpectedIdentitySHA256 ('6' * 64) -NowUtc ([DateTime]::UtcNow) } | Should -Throw '*inbound*'
    }

    It 'builds a sanitized local baseline from an injected read-only observer' {
        $profile = Join-Path $script:Fixture 'absent.conf'
        $receipt = New-P3LocalBaselineReceipt -ProtectedProfilePath $profile -NowUtc ([DateTime]::UtcNow) -AdapterRunner {
            @(
                [pscustomobject]@{ Class = 'redshield' },
                [pscustomobject]@{ Class = 'other' }
            )
        }
        $receipt.protected_profile_absent | Should -BeTrue
        $receipt.selfhosted_adapter_count | Should -Be 0
        $receipt.redshield_class_count | Should -Be 1
        $receipt.PSObject.Properties.Name | Should -Not -Contain 'adapter_name'
        $receipt.live_mutation_performed | Should -BeFalse
    }
}
