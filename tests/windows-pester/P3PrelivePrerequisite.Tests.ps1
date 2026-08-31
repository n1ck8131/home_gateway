$ErrorActionPreference = 'Stop'

Describe 'P3 pre-live prerequisite boundary' {
    BeforeAll {
        $script:Driver = Join-Path $PSScriptRoot '..\..\scripts\p3-prelive-prerequisite.ps1'
        $script:Runtime = Join-Path $PSScriptRoot '..\..\scripts\p3-prelive-runtime.ps1'
        . $script:Runtime
        . $script:Driver

        function New-PrerequisiteFixture {
            $now = [DateTime]::Parse('2026-08-31T12:00:00Z').ToUniversalTime()
            $baseline = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\fixtures\p3\server-baseline-v2.json') -Raw | ConvertFrom-Json
            $authorities = @(('7' * 64), ('8' * 64), ('9' * 64))
            $cloud = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-cloud-firewall-observation/v2'
                firewall_resource_sha256=('1' * 64);droplet_resource_sha256=('2' * 64)
                droplet_association_count=1;management_source_cidr_sha256=('3' * 64)
                tcp_22_management_source_count=1;udp_38556_all_ipv4_count=1;udp_ipv6_count=0
                extra_inbound_rule_count=0;inbound_union_sha256=('4' * 64)
                outbound_union_sha256=('5' * 64);outbound_icmp_all_count=2
                outbound_tcp_all_count=2;outbound_udp_all_count=2;extra_outbound_rule_count=0
                observed_at_utc=$now.ToString('o');owner_observed=$true;server_confirmed=$false
                live_mutation_performed=$false
            }
            $egress = foreach ($index in 0..2) {
                [pscustomobject][ordered]@{
                    schema='home-gateway/p3-prelive-egress-observation/v1'
                    authority_sha256=$authorities[$index];source_cidr_sha256=('3' * 64)
                    observed_at_utc=$now.AddSeconds($index).ToString('o')
                }
            }
            $manifest = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-prerequisite-manifest/v1'
                manifest_sha256=('a' * 64);payload_sha256=[string]$baseline.payload_sha256
                protocol_sha256=[string]$baseline.protocol_sha256;ssh_trust_sha256=('b' * 64)
                management_source_cidr_sha256=('3' * 64);egress_authority_sha256=$authorities
                firewall_resource_sha256=('1' * 64);droplet_resource_sha256=('2' * 64)
                inbound_union_sha256=('4' * 64);outbound_union_sha256=('5' * 64)
            }
            return [pscustomobject]@{ Now=$now;Baseline=$baseline;Cloud=$cloud;Egress=@($egress);Manifest=$manifest }
        }

        function New-PrerequisiteAgentFixture([string]$Root, [object]$PrerequisiteManifest) {
            [IO.Directory]::CreateDirectory($Root) | Out-Null
            $files = @{}
            foreach ($name in @('ssh-agent.exe','ssh-add.exe','ssh.exe','scp.exe','operator.pub')) {
                $path = Join-Path $Root $name
                [IO.File]::WriteAllText($path, "synthetic-$name", [Text.UTF8Encoding]::new($false))
                $files[$name] = $path
            }
            $fingerprint = 'SHA256:prerequisite-synthetic'
            $agentManifest = [pscustomobject]@{
                manifest_sha256=[string]$PrerequisiteManifest.manifest_sha256
                git_ssh_agent_path=$files.'ssh-agent.exe';git_ssh_agent_sha256=(Get-FileHash $files.'ssh-agent.exe').Hash.ToLowerInvariant()
                git_ssh_add_path=$files.'ssh-add.exe';git_ssh_add_sha256=(Get-FileHash $files.'ssh-add.exe').Hash.ToLowerInvariant()
                git_ssh_path=$files.'ssh.exe';git_ssh_sha256=(Get-FileHash $files.'ssh.exe').Hash.ToLowerInvariant()
                git_scp_path=$files.'scp.exe';git_scp_sha256=(Get-FileHash $files.'scp.exe').Hash.ToLowerInvariant()
                public_key_path=$files.'operator.pub';private_key_path=(Join-Path $Root 'operator')
                public_key_fingerprint_sha256=Get-P3SHA256Text $fingerprint
            }
            return [pscustomobject]@{ Manifest=$agentManifest;Fingerprint=$fingerprint;Root=(Join-Path $Root 'protected') }
        }
    }

    It 'assembles and validates one exact fresh prerequisite receipt' {
        $f = New-PrerequisiteFixture
        $receipt = New-P3PrerequisiteReceipt -Manifest $f.Manifest -ServerBaseline $f.Baseline `
            -CloudObservation $f.Cloud -EgressObservations $f.Egress -NowUtc $f.Now.AddSeconds(5)
        $receipt.schema | Should -BeExactly 'home-gateway/p3-prelive-prerequisite-receipt/v1'
        $receipt.server_baseline_sha256 | Should -BeExactly (Get-P3ServerBaselineSHA256 $f.Baseline)
        $receipt.management_source_cidr_sha256 | Should -BeExactly ('3' * 64)
        $receipt.egress_authority_sha256 | Should -BeExactly $f.Manifest.egress_authority_sha256
        Test-P3PrerequisiteReceipt -Receipt $receipt -Manifest $f.Manifest -NowUtc $f.Now.AddMinutes(1) |
            Should -BeExactly $receipt
    }

    It 'rejects a Droplet-derived or mismatched management source' {
        $f = New-PrerequisiteFixture
        $f.Egress[1].source_cidr_sha256 = $f.Cloud.droplet_resource_sha256
        { New-P3PrerequisiteReceipt -Manifest $f.Manifest -ServerBaseline $f.Baseline `
                -CloudObservation $f.Cloud -EgressObservations $f.Egress -NowUtc $f.Now.AddSeconds(5) } |
            Should -Throw '*management source*'
    }

    It 'always tears down the prerequisite agent and makes stop failure terminal' {
        $calls = [Collections.Generic.List[string]]::new()
        { Invoke-P3PrerequisiteOwnedObservation `
                -StartRunner { $calls.Add('start'); [pscustomobject]@{ token='owned' } } `
                -ValidateRunner { param($r) $calls.Add('validate'); $r } `
                -ObserveRunner { param($r) $calls.Add('observe'); throw 'synthetic body failure' } `
                -StopRunner { param($r) $calls.Add('stop') } } | Should -Throw '*synthetic body failure*'
        $calls | Should -BeExactly @('start','validate','observe','stop')

        { Invoke-P3PrerequisiteOwnedObservation -StartRunner { [pscustomobject]@{ token='owned' } } `
                -ValidateRunner { param($r) $r } -ObserveRunner { param($r) 'ok' } `
                -StopRunner { param($r) throw 'synthetic stop failure' } } | Should -Throw '*stop failure*'
    }

    It 'routes Plan and Observe through the fixed injected action switch' {
        $f = New-PrerequisiteFixture
        $plan = Invoke-P3PrerequisiteAction -SelectedAction Plan -InputObject $f.Manifest -Boundaries ([pscustomobject]@{})
        $plan.confirmation_challenge | Should -Match '^P3-PRELIVE-PREREQUISITE-[0-9A-F]{16}$'
        $baselineSHA256 = Get-P3ServerBaselineSHA256 $f.Baseline
        $nonceSHA256 = Get-P3SHA256Text ('c' * 64)
        $calls = [Collections.Generic.List[string]]::new()
        $observed = Invoke-P3PrerequisiteAction -SelectedAction Observe -InputObject ([pscustomobject]@{
            manifest=$f.Manifest;nonce=('c' * 64)
        }) -Boundaries ([pscustomobject]@{
            StartRunner={ $calls.Add('start'); [pscustomobject]@{owned=$true} }.GetNewClosure()
            ValidateRunner={ param($receipt) $calls.Add('validate'); $receipt }.GetNewClosure()
            StopRunner={ param($receipt) $calls.Add('stop') }.GetNewClosure()
            ObserverRunner={ param($manifest,$nonce) $calls.Add('observer'); [pscustomobject]@{
                schema='home-gateway/p3-prelive-server-observation/v1';server_baseline=$f.Baseline
                server_baseline_sha256=$baselineSHA256;payload_sha256=$f.Manifest.payload_sha256
                protocol_sha256=$f.Manifest.protocol_sha256;nonce_sha256=$nonceSHA256
                live_mutation_performed=$false;raw_identity_exposed=$false
            } }.GetNewClosure()
            HttpsRunner={ param($authority) $calls.Add('https'); [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-egress-observation/v1';authority_sha256=$authority
                source_cidr_sha256=$f.Manifest.management_source_cidr_sha256;observed_at_utc=$f.Now.ToString('o')
            } }.GetNewClosure()
            ClockRunner={ $f.Now.AddSeconds(5) }.GetNewClosure()
        })
        @($calls | Where-Object { $_ -eq 'observer' }).Count | Should -Be 1
        @($calls | Where-Object { $_ -eq 'https' }).Count | Should -Be 3
        $calls[0] | Should -BeExactly 'start'
        $calls[-1] | Should -BeExactly 'stop'
        $observed.egress.Count | Should -Be 3
        $observed.server_baseline_sha256 | Should -BeExactly (Get-P3ServerBaselineSHA256 $f.Baseline)
    }

    It 'owns prerequisite AgentPlan Start Validate Stop under its protected root' {
        $f = New-PrerequisiteFixture
        $agent = New-PrerequisiteAgentFixture (Join-Path $TestDrive 'agent-action') $f.Manifest
        $script:Stopped = 0
        $boundaries = [pscustomobject]@{
            PrerequisiteRoot=$agent.Root;PrerequisiteManifest=$f.Manifest
            AgentRunner={ "SSH_AUTH_SOCK=/tmp/ssh-prerequisite/agent.4343; export SSH_AUTH_SOCK;`nSSH_AGENT_PID=4343; export SSH_AGENT_PID;" }
            AddRunner={ param($path) };StopRunner={ param($ProcessId) $script:Stopped++ }
            ListRunner={ "256 $($agent.Fingerprint) p3 (ED25519)" }.GetNewClosure()
            ProcessRunner={ param($ProcessId) [pscustomobject]@{Id=$ProcessId;Path=$agent.Manifest.git_ssh_agent_path;StartTime=[DateTime]::UtcNow} }.GetNewClosure()
            DeleteRunner={};WaitRunner={param($ProcessId)};ReobserveRunner={param($ProcessId) @()}
            SocketExistsRunner={param($path) $false};ReceiptRemoveRunner={param($path) [IO.File]::Delete($path)}
        }
        $plan = Invoke-P3PrerequisiteAction AgentPlan $agent.Manifest $boundaries
        $receipt = Invoke-P3PrerequisiteAction AgentStart ([pscustomobject]@{agent_manifest=$agent.Manifest;plan=$plan}) $boundaries
        $combined = Invoke-P3PrerequisiteAction AgentValidate ([pscustomobject]@{agent_manifest=$agent.Manifest;receipt=$receipt}) $boundaries
        (Test-Path (Join-Path $agent.Root 'agent-receipt.json')) | Should -BeTrue
        $stop = Invoke-P3PrerequisiteAction AgentStop `
            ([pscustomobject]@{agent_manifest=$agent.Manifest;receipt=$receipt;combined_receipt=$combined}) $boundaries
        $stop.stopped | Should -BeTrue
        (Test-Path (Join-Path $agent.Root 'agent-receipt.json')) | Should -BeFalse
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'tears down failed Observe actions and blocks on stop failure' {
        $f = New-PrerequisiteFixture
        $calls = [Collections.Generic.List[string]]::new()
        $observeInput = [pscustomobject]@{manifest=$f.Manifest;nonce=('c' * 64)}
        $boundaries = [pscustomobject]@{
            StartRunner={ $calls.Add('start'); [pscustomobject]@{owned=$true} }.GetNewClosure()
            ValidateRunner={param($receipt) $calls.Add('validate');$receipt}.GetNewClosure()
            StopRunner={param($receipt) $calls.Add('stop')}.GetNewClosure()
            ObserverRunner={param($manifest,$nonce) throw 'synthetic observe failure'}
            HttpsRunner={param($authority) throw 'not reached'};ClockRunner={$f.Now}.GetNewClosure()
        }
        { Invoke-P3PrerequisiteAction Observe $observeInput $boundaries } | Should -Throw '*synthetic observe failure*'
        $calls | Should -BeExactly @('start','validate','stop')

        $boundaries.ObserverRunner = {param($manifest,$nonce) throw 'body is not material'}
        $boundaries.StopRunner = {param($receipt) throw 'synthetic stop failure'}
        { Invoke-P3PrerequisiteAction Observe $observeInput $boundaries } | Should -Throw '*stop failure*'
    }
}
