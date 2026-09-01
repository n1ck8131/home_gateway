$ErrorActionPreference = 'Stop'

Describe 'P3 pre-live prerequisite boundary' {
    BeforeAll {
        $script:Driver = Join-Path $PSScriptRoot '..\..\scripts\p3-prelive-prerequisite.ps1'
        $script:Runtime = Join-Path $PSScriptRoot '..\..\scripts\p3-prelive-runtime.ps1'
        . $script:Runtime
        . $script:Driver

        function New-P3PrerequisiteTestAgentLaunch([string[]]$Output) {
            return [pscustomobject][ordered]@{
                schema = 'home-gateway/p3-windows-agent-launch/v1'
                output = $Output
                started_at_utc = [DateTime]::UtcNow.ToString('o')
                windows_process_id = 26484
            }
        }

        function New-PrerequisiteFixture {
            $now = [DateTime]::Parse('2026-08-31T12:00:00Z').ToUniversalTime()
            $baseline = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\fixtures\p3\server-baseline-v2.json') -Raw | ConvertFrom-Json
            $endpoints = @('https://one.example/ip','https://two.example/ip','https://three.example/ip')
            $authorities = @($endpoints | ForEach-Object { Get-P3SHA256Text (([Uri]$_).Authority.ToLowerInvariant()) })
            $allIpv4 = Get-P3SHA256Text 'all_ipv4'
            $cloud = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-cloud-firewall-observation/v2'
                firewall_resource_sha256=('1' * 64);droplet_resource_sha256=('2' * 64)
                associations=@([pscustomobject][ordered]@{firewall_resource_sha256=('1'*64);droplet_resource_sha256=('2'*64)})
                management_source_cidr_sha256=('3' * 64)
                inbound_rules=@(
                    [pscustomobject][ordered]@{protocol='tcp';port=22;source_class='management_ipv4';source_sha256=('3'*64)},
                    [pscustomobject][ordered]@{protocol='udp';port=38556;source_class='all_ipv4';source_sha256=$allIpv4}
                )
                outbound_rules=@(
                    foreach($protocol in @('icmp','tcp','udp')){foreach($destination in @('all_ipv4','all_ipv6')){
                        [pscustomobject][ordered]@{protocol=$protocol;destination_class=$destination}
                    }}
                )
                observed_at_utc=$now.ToString('o');owner_observed=$true;server_confirmed=$false
                live_mutation_performed=$false
            }
            $cloudUnion = Get-P3PrerequisiteCloudUnion $cloud
            $egress = foreach ($index in 0..2) {
                [pscustomobject][ordered]@{
                    schema='home-gateway/p3-prelive-egress-observation/v1'
                    authority_sha256=$authorities[$index];source_cidr_sha256=('3' * 64)
                    observed_at_utc=$now.AddSeconds($index).ToString('o')
                }
            }
            $trust = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-prerequisite-ssh-trust/v1'
                ssh_host='192.0.2.10';ssh_user='homegateway';known_hosts_path='C:\synthetic\known_hosts'
                known_hosts_sha256=('1' * 64);host_key_fingerprint_sha256=('2' * 64)
                git_ssh_agent_path='C:\synthetic\ssh-agent.exe';git_ssh_agent_sha256=('3' * 64)
                git_ssh_add_path='C:\synthetic\ssh-add.exe';git_ssh_add_sha256=('4' * 64)
                git_ssh_path='C:\synthetic\ssh.exe';git_ssh_sha256=('5' * 64)
                git_scp_path='C:\synthetic\scp.exe';git_scp_sha256=('6' * 64)
                public_key_path='C:\synthetic\operator.pub';public_key_sha256=('0' * 64);public_key_fingerprint_sha256=('7' * 64)
                private_key_path='C:\synthetic\operator'
                observer_payload_path='C:\synthetic\p3-amnezia-peer-guard.py'
                observer_payload_sha256=[string]$baseline.payload_sha256
                observer_protocol_sha256=[string]$baseline.protocol_sha256
                expected_ipv6_policy_sha256=[string]$baseline.ipv6_policy_sha256
                egress=@(for($i=0;$i -lt 3;$i++){[pscustomobject][ordered]@{endpoint=$endpoints[$i];authority_sha256=$authorities[$i]}})
                connect_timeout_seconds=10;command_timeout_seconds=30;maximum_output_bytes=65536
                no_write_scope=$true
            }
            $manifest = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-prerequisite-manifest/v1'
                manifest_sha256=('a' * 64);payload_sha256=[string]$baseline.payload_sha256
                protocol_sha256=[string]$baseline.protocol_sha256
                ssh_trust=$trust
                ssh_trust_sha256=Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $trust)
                management_source_cidr_sha256=('3' * 64);egress_authority_sha256=$authorities
                firewall_resource_sha256=('1' * 64);droplet_resource_sha256=('2' * 64)
                inbound_union_sha256=$cloudUnion.inbound_union_sha256;outbound_union_sha256=$cloudUnion.outbound_union_sha256
            }
            return [pscustomobject]@{ Now=$now;Baseline=$baseline;Cloud=$cloud;Egress=@($egress);Manifest=$manifest;SshTrust=$trust }
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

        function New-ProductionPrerequisiteFixture([string]$Root) {
            $f = New-PrerequisiteFixture
            $agent = New-PrerequisiteAgentFixture (Join-Path $Root 'agent') $f.Manifest
            $knownHosts = Join-Path $Root 'known_hosts'
            $observerPayload = Join-Path $Root 'observer.py'
            [IO.Directory]::CreateDirectory($Root) | Out-Null
            $hostKey = 'AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f' # gitleaks:allow synthetic public test key, not a credential
            [IO.File]::WriteAllText($knownHosts, "192.0.2.10 ssh-ed25519 $hostKey`n", [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($observerPayload, 'synthetic observer payload', [Text.UTF8Encoding]::new($false))
            $f.Baseline.payload_sha256 = (Get-FileHash $observerPayload).Hash.ToLowerInvariant()
            $endpoints = @('https://one.example/ip','https://two.example/ip','https://three.example/ip')
            $authorities = @($endpoints | ForEach-Object { Get-P3SHA256Text (([Uri]$_).Authority.ToLowerInvariant()) })
            $trust = [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-prerequisite-ssh-trust/v1'
                ssh_host='192.0.2.10';ssh_user='homegateway';known_hosts_path=$knownHosts
                known_hosts_sha256=(Get-FileHash $knownHosts).Hash.ToLowerInvariant();host_key_fingerprint_sha256='cfb2081423dfac1fcc8f8593d1ef587c68090f88aee7dd69a3e662fb04043559' # gitleaks:allow synthetic public fingerprint, not a credential
                git_ssh_agent_path=$agent.Manifest.git_ssh_agent_path;git_ssh_agent_sha256=$agent.Manifest.git_ssh_agent_sha256
                git_ssh_add_path=$agent.Manifest.git_ssh_add_path;git_ssh_add_sha256=$agent.Manifest.git_ssh_add_sha256
                git_ssh_path=$agent.Manifest.git_ssh_path;git_ssh_sha256=$agent.Manifest.git_ssh_sha256
                git_scp_path=$agent.Manifest.git_scp_path;git_scp_sha256=$agent.Manifest.git_scp_sha256
                public_key_path=$agent.Manifest.public_key_path;public_key_sha256=(Get-FileHash $agent.Manifest.public_key_path).Hash.ToLowerInvariant()
                public_key_fingerprint_sha256=$agent.Manifest.public_key_fingerprint_sha256
                private_key_path=$agent.Manifest.private_key_path;observer_payload_path=$observerPayload
                observer_payload_sha256=$f.Baseline.payload_sha256;observer_protocol_sha256=$f.Manifest.protocol_sha256
                expected_ipv6_policy_sha256=$f.Baseline.ipv6_policy_sha256
                egress=@(for($i=0;$i -lt 3;$i++){[pscustomobject][ordered]@{endpoint=$endpoints[$i];authority_sha256=$authorities[$i]}})
                connect_timeout_seconds=10;command_timeout_seconds=30;maximum_output_bytes=65536;no_write_scope=$true
            }
            $f.Manifest.payload_sha256=$trust.observer_payload_sha256
            $f.Manifest.egress_authority_sha256=$authorities
            $f.Manifest.ssh_trust=$trust
            $f.Manifest.ssh_trust_sha256=Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $trust)
            return [pscustomobject]@{Fixture=$f;Agent=$agent;Trust=$trust}
        }
    }

    It 'assembles and validates one exact fresh prerequisite receipt' {
        $f = New-PrerequisiteFixture
        $receipt = New-P3PrerequisiteReceipt -Manifest $f.Manifest -ServerBaseline $f.Baseline `
            -CloudObservation $f.Cloud -EgressObservations $f.Egress -NonceSHA256 (Get-P3SHA256Text ('c' * 64)) -NowUtc $f.Now.AddSeconds(5)
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
                -CloudObservation $f.Cloud -EgressObservations $f.Egress -NonceSHA256 (Get-P3SHA256Text ('c' * 64)) -NowUtc $f.Now.AddSeconds(5) } |
            Should -Throw '*management source*'
    }

    It 'recomputes semantic Cloud unions and rejects an added caller rule' {
        $f = New-PrerequisiteFixture
        $f.Cloud.inbound_rules += [pscustomobject][ordered]@{
            protocol='tcp';port=443;source_class='all_ipv4';source_sha256=(Get-P3SHA256Text 'all_ipv4')
        }
        { New-P3PrerequisiteReceipt -Manifest $f.Manifest -ServerBaseline $f.Baseline `
                -CloudObservation $f.Cloud -EgressObservations $f.Egress -NonceSHA256 (Get-P3SHA256Text ('c' * 64)) -NowUtc $f.Now.AddSeconds(5) } |
            Should -Throw '*Cloud Firewall inbound*'
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
        $root=Join-Path $TestDrive 'action-switch-root'
        $plan = Invoke-P3PrerequisiteAction -SelectedAction Plan -InputObject ([pscustomobject]@{manifest=$f.Manifest;nonce=('c' * 64)}) -Boundaries ([pscustomobject]@{PrerequisiteRoot=$root})
        $plan.confirmation_challenge | Should -Match '^P3-PRELIVE-PREREQUISITE-[0-9A-F]{16}$'
        $baselineSHA256 = Get-P3ServerBaselineSHA256 $f.Baseline
        $nonceSHA256 = Get-P3SHA256Text ('c' * 64)
        $calls = [Collections.Generic.List[string]]::new()
        $observed = Invoke-P3PrerequisiteAction -SelectedAction Observe -InputObject ([pscustomobject]@{
            manifest=$f.Manifest;ssh_trust=$f.SshTrust;nonce=('c' * 64);expected_plan_sha256=$plan.plan_sha256
            confirmation_challenge=$plan.confirmation_challenge
        }) -Boundaries ([pscustomobject]@{
            PrerequisiteRoot=$root
            StartRunner={ $calls.Add('start'); [pscustomobject]@{owned=$true} }.GetNewClosure()
            ValidateRunner={ param($receipt) $calls.Add('validate'); $receipt }.GetNewClosure()
            StopRunner={ param($receipt) $calls.Add('stop') }.GetNewClosure()
            ObserverRunner={ param($manifest,$trust,$agentReceipt,$nonce) $calls.Add('observer'); [pscustomobject]@{
                schema='home-gateway/p3-prelive-server-observation/v1';server_baseline=$f.Baseline
                server_baseline_sha256=$baselineSHA256;payload_sha256=$f.Manifest.payload_sha256
                protocol_sha256=$f.Manifest.protocol_sha256;nonce_sha256=$nonceSHA256
                live_mutation_performed=$false;raw_identity_exposed=$false
            } }.GetNewClosure()
            HttpsRunner={ param($entry) $calls.Add('https'); [pscustomobject][ordered]@{
                schema='home-gateway/p3-prelive-egress-observation/v1';authority_sha256=$entry.authority_sha256
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

    It 'binds approval to one canonical prerequisite root and rejects replay before mutation' {
        $p=New-ProductionPrerequisiteFixture (Join-Path $TestDrive 'root-bound-fixture');$f=$p.Fixture
        $approvedRoot=$p.Agent.Root
        $foreignRoot=Join-Path $TestDrive 'foreign-root'
        $plan=New-P3PrerequisitePlan $f.Manifest ('c'*64) $approvedRoot
        $plan.schema|Should -BeExactly 'home-gateway/p3-prelive-prerequisite-plan/v2'
        $plan.prerequisite_root_sha256|Should -BeExactly (Get-P3SHA256Text ([IO.Path]::GetFullPath($approvedRoot).ToUpperInvariant()))
        $other=New-P3PrerequisitePlan $f.Manifest ('c'*64) $foreignRoot
        $other.plan_sha256|Should -Not -BeExactly $plan.plan_sha256
        $calls=[Collections.Generic.List[string]]::new()
        $boundaries=[pscustomobject]@{
            AgentRunner={$calls.Add('start')}.GetNewClosure();AddRunner={$calls.Add('add')}.GetNewClosure()
            ListRunner={$calls.Add('list')}.GetNewClosure();ProcessRunner={$calls.Add('process')}.GetNewClosure()
            DeleteRunner={$calls.Add('delete')}.GetNewClosure();StopRunner={$calls.Add('stop')}.GetNewClosure()
            WaitRunner={$calls.Add('wait')}.GetNewClosure();ReobserveRunner={$calls.Add('reobserve')}.GetNewClosure()
            SocketExistsRunner={$calls.Add('socket')}.GetNewClosure();ReceiptRemoveRunner={$calls.Add('receipt')}.GetNewClosure()
            SshRunner={$calls.Add('ssh')}.GetNewClosure();HttpsRunner={$calls.Add('https')}.GetNewClosure();ClockRunner={$f.Now}.GetNewClosure()
        }
        {Invoke-P3PrerequisiteProductionObservation -PrerequisiteRoot $foreignRoot -InputObject ([pscustomobject]@{
                manifest=$f.Manifest;ssh_trust=$p.Trust;agent_manifest=$p.Agent.Manifest;nonce=('c'*64)
                expected_plan_sha256=$plan.plan_sha256;confirmation_challenge=$plan.confirmation_challenge
            }) -Boundaries $boundaries}|Should -Throw '*approval*'
        $calls.Count|Should -Be 0
        Test-Path $foreignRoot|Should -BeFalse
    }

    It 'cancels a slow HTTPS body and caps a fast oversized body without lingering streams' {
        $slow=[IO.MemoryStream]::new([byte[]](1,2,3));$cts=[Threading.CancellationTokenSource]::new(40)
        $script:slowTask=$null
        {Read-P3PrerequisiteBoundedHttpBody -Stream $slow -CancellationToken $cts.Token -MaximumBytes 65536 -ReadRunner {
                param($stream,$buffer,$offset,$count,$token)
                $script:slowTask=[Threading.Tasks.Task]::Delay(30000,$token)
                return $script:slowTask
            }}|Should -Throw '*timed out*'
        $script:slowTask.IsCompleted|Should -BeTrue
        $slow.CanRead|Should -BeFalse
        $cts.Dispose()
        $large=[IO.MemoryStream]::new([byte[]]::new(65537));$open=[Threading.CancellationTokenSource]::new()
        {Read-P3PrerequisiteBoundedHttpBody -Stream $large -CancellationToken $open.Token -MaximumBytes 65536}|Should -Throw '*exceeds*'
        $large.CanRead|Should -BeFalse
        $open.Dispose()
    }

    It 'owns prerequisite AgentPlan Start Validate Stop under its protected root' {
        $f = New-PrerequisiteFixture
        $agent = New-PrerequisiteAgentFixture (Join-Path $TestDrive 'agent-action') $f.Manifest
        $script:Stopped = 0
        $processPids = [Collections.Generic.List[int]]::new(); $stoppedPids = [Collections.Generic.List[int]]::new(); $waitPids = [Collections.Generic.List[int]]::new(); $reobservePids = [Collections.Generic.List[int]]::new()
        $boundaries = [pscustomobject]@{
            PrerequisiteRoot=$agent.Root;PrerequisiteManifest=$f.Manifest
            AgentRunner={ New-P3PrerequisiteTestAgentLaunch -Output @('SSH_AUTH_SOCK=/tmp/ssh-prerequisite/agent.77; export SSH_AUTH_SOCK;', 'SSH_AGENT_PID=77; export SSH_AGENT_PID;') }
            AddRunner={ param($path) };StopRunner={ param($ProcessId) $stoppedPids.Add($ProcessId); $script:Stopped++ }.GetNewClosure()
            ListRunner={ "256 $($agent.Fingerprint) p3 (ED25519)" }.GetNewClosure()
            ProcessRunner={ param($ProcessId) $processPids.Add($ProcessId); [pscustomobject]@{Id=$ProcessId;Path=$agent.Manifest.git_ssh_agent_path;StartTime=[DateTime]::UtcNow} }.GetNewClosure()
            DeleteRunner={};WaitRunner={param($ProcessId)$waitPids.Add($ProcessId)}.GetNewClosure();ReobserveRunner={param($ProcessId)$reobservePids.Add($ProcessId); @()}.GetNewClosure()
            SocketExistsRunner={param($path) $false};ReceiptRemoveRunner={param($path) [IO.File]::Delete($path)}
        }
        $plan = Invoke-P3PrerequisiteAction AgentPlan $agent.Manifest $boundaries
        $receipt = Invoke-P3PrerequisiteAction AgentStart ([pscustomobject]@{agent_manifest=$agent.Manifest;plan=$plan}) $boundaries
        $combined = Invoke-P3PrerequisiteAction AgentValidate ([pscustomobject]@{agent_manifest=$agent.Manifest;receipt=$receipt}) $boundaries
        (Test-Path (Join-Path $agent.Root 'agent-receipt.json')) | Should -BeTrue
        $stop = Invoke-P3PrerequisiteAction AgentStop `
            ([pscustomobject]@{agent_manifest=$agent.Manifest;receipt=$receipt;combined_receipt=$combined}) $boundaries
        $stop.stopped | Should -BeTrue
        $receipt.agent_pid | Should -Be 77
        $receipt.windows_process_id | Should -Be 26484
        @($processPids) | Should -Be @(26484, 26484, 26484)
        @($stoppedPids) | Should -Be @(26484)
        @($waitPids) | Should -Be @(26484)
        @($reobservePids) | Should -Be @(26484)
        (Test-Path (Join-Path $agent.Root 'agent-receipt.json')) | Should -BeFalse
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'tears down failed Observe actions and blocks on stop failure' {
        $f = New-PrerequisiteFixture
        $root=Join-Path $TestDrive 'failed-observe-root'
        $calls = [Collections.Generic.List[string]]::new()
        $plan = New-P3PrerequisitePlan $f.Manifest ('c' * 64) $root
        $observeInput = [pscustomobject]@{
            manifest=$f.Manifest;ssh_trust=$f.SshTrust;nonce=('c' * 64);expected_plan_sha256=$plan.plan_sha256
            confirmation_challenge=$plan.confirmation_challenge
        }
        $boundaries = [pscustomobject]@{
            PrerequisiteRoot=$root
            StartRunner={ $calls.Add('start'); [pscustomobject]@{owned=$true} }.GetNewClosure()
            ValidateRunner={param($receipt) $calls.Add('validate');$receipt}.GetNewClosure()
            StopRunner={param($receipt) $calls.Add('stop')}.GetNewClosure()
            ObserverRunner={param($manifest,$trust,$agentReceipt,$nonce) throw 'synthetic observe failure'}
            HttpsRunner={param($entry) throw 'not reached'};ClockRunner={$f.Now}.GetNewClosure()
        }
        { Invoke-P3PrerequisiteAction Observe $observeInput $boundaries } | Should -Throw '*synthetic observe failure*'
        $calls | Should -BeExactly @('start','validate','stop')

        $boundaries.ObserverRunner = {param($manifest,$trust,$agentReceipt,$nonce) throw 'body is not material'}
        $boundaries.StopRunner = {param($receipt) throw 'synthetic stop failure'}
        { Invoke-P3PrerequisiteAction Observe $observeInput $boundaries } | Should -Throw '*stop failure*'
    }

    It 'rejects an Observe approval mismatch before any owned or network boundary' {
        $f = New-PrerequisiteFixture
        $root=Join-Path $TestDrive 'approval-mismatch-root'
        $plan = New-P3PrerequisitePlan $f.Manifest ('c' * 64) $root
        $calls = [Collections.Generic.List[string]]::new()
        $observeApprovalInput = [pscustomobject]@{
            manifest=$f.Manifest;ssh_trust=$f.SshTrust;nonce=('c' * 64);expected_plan_sha256=('0' * 64)
            confirmation_challenge=$plan.confirmation_challenge
        }
        $boundaries = [pscustomobject]@{
            PrerequisiteRoot=$root
            StartRunner={ $calls.Add('start') }.GetNewClosure()
            ValidateRunner={ $calls.Add('validate') }.GetNewClosure()
            StopRunner={ $calls.Add('stop') }.GetNewClosure()
            ObserverRunner={ $calls.Add('ssh') }.GetNewClosure()
            HttpsRunner={ $calls.Add('https') }.GetNewClosure()
            ClockRunner={ $f.Now }.GetNewClosure()
        }
        { Invoke-P3PrerequisiteAction Observe $observeApprovalInput $boundaries } | Should -Throw '*approval*'
        $calls.Count | Should -Be 0
    }

    It 'builds the exact no-write SSH invocation and attested stdin frame' {
        $f = New-PrerequisiteFixture
        $trust = [pscustomobject]@{
            git_ssh_path='C:\synthetic\ssh.exe';known_hosts_path='C:\synthetic\known_hosts'
            ssh_host='192.0.2.10';ssh_user='homegateway';connect_timeout_seconds=10
            command_timeout_seconds=30;maximum_output_bytes=65536
            observer_payload_sha256=(Get-P3SHA256Text 'synthetic-observer')
            observer_protocol_sha256=$f.Manifest.protocol_sha256
            expected_ipv6_policy_sha256=('d' * 64)
        }
        $agent = [pscustomobject]@{ ssh_auth_sock='C:\synthetic\agent.sock' }
        $invocation = New-P3PrerequisiteObserverInvocation -Trust $trust -AgentReceipt $agent -Nonce ('c' * 64) `
            -Payload ([Text.UTF8Encoding]::new($false).GetBytes('synthetic-observer'))
        $invocation.arguments | Should -Contain 'BatchMode=yes'
        $invocation.arguments | Should -Contain 'IdentitiesOnly=yes'
        $invocation.arguments | Should -Contain 'StrictHostKeyChecking=yes'
        $invocation.arguments | Should -Contain '-F'
        $invocation.arguments | Should -Contain 'NUL'
        $invocation.arguments | Should -Contain 'GlobalKnownHostsFile=NUL'
        $invocation.arguments | Should -Contain 'PasswordAuthentication=no'
        $invocation.arguments | Should -Contain 'KbdInteractiveAuthentication=no'
        $invocation.arguments | Should -Contain 'ClearAllForwardings=yes'
        $invocation.arguments | Should -Contain '-T'
        $invocation.arguments[-2] | Should -BeExactly 'homegateway@192.0.2.10'
        $invocation.arguments[-1] | Should -Match '^sudo -n /usr/bin/python3 -c '
        $invocation.stdin.Length | Should -BeGreaterThan 18
        $invocation.timeout_seconds | Should -Be 30
        $invocation.maximum_output_bytes | Should -Be 65536
    }

    It 'rejects a self-consistent foreign known-host pin before the SSH runner' {
        $p = New-ProductionPrerequisiteFixture (Join-Path $TestDrive 'foreign-known-host')
        $knownHosts = [string]$p.Trust.known_hosts_path
        $hostKey = 'AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f' # gitleaks:allow synthetic public test key, not a credential
        [IO.File]::WriteAllText($knownHosts,"192.0.2.11 ssh-ed25519 $hostKey`n",[Text.UTF8Encoding]::new($false))
        $p.Trust.known_hosts_sha256 = (Get-FileHash $knownHosts).Hash.ToLowerInvariant()
        $p.Fixture.Manifest.ssh_trust = $p.Trust
        $p.Fixture.Manifest.ssh_trust_sha256 = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $p.Trust)
        $script:SshCalls = 0
        { Invoke-P3PrerequisiteSshObservation -Manifest $p.Fixture.Manifest -Trust $p.Trust `
                -AgentReceipt ([pscustomobject]@{socket='C:\synthetic\agent.sock'}) -Nonce ('c'*64) `
                -Runner {$script:SshCalls++;[pscustomobject]@{ExitCode=1;TimedOut=$false;Oversized=$false;StdOut='';StdErr='blocked'}} } |
            Should -Throw '*known-host*'
        $script:SshCalls | Should -Be 0
    }

    It 'caps a fast noisy child without temp files and preserves exact observer argv' {
        $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $savedTemp=$env:TEMP;$savedTmp=$env:TMP;$missing=Join-Path $TestDrive 'missing-temp'
        try {
            $env:TEMP=$missing;$env:TMP=$missing
            $noisy=Invoke-P3PrerequisiteNativeProcess $powershell @('-NoLogo','-NoProfile','-NonInteractive','-Command',"[Console]::Out.Write('x' * 131072)") ([Text.Encoding]::UTF8.GetBytes('{}')) 10 1024
        } finally { $env:TEMP=$savedTemp;$env:TMP=$savedTmp }
        $noisy.Oversized|Should -BeTrue;$noisy.TimedOut|Should -BeFalse;$noisy.StdOut|Should -BeExactly ''

        $capture=Join-Path $TestDrive 'capture-argv.ps1'
        [IO.File]::WriteAllText($capture,'[Console]::Out.Write(($args | ConvertTo-Json -Compress))',[Text.UTF8Encoding]::new($false))
        $f=New-PrerequisiteFixture
        $trust=[pscustomobject]@{git_ssh_path='C:\synthetic\ssh.exe';known_hosts_path='C:\synthetic\known_hosts';ssh_host='192.0.2.10';ssh_user='homegateway'
            connect_timeout_seconds=10;command_timeout_seconds=30;maximum_output_bytes=65536;observer_payload_sha256=(Get-P3SHA256Text 'payload')
            observer_protocol_sha256=$f.Manifest.protocol_sha256;expected_ipv6_policy_sha256=('d'*64)}
        $invocation=New-P3PrerequisiteObserverInvocation $trust ([pscustomobject]@{ssh_auth_sock='C:\synthetic\agent.sock'}) ('c'*64) ([Text.Encoding]::UTF8.GetBytes('payload'))
        $captured=Invoke-P3PrerequisiteNativeProcess $powershell (@('-NoLogo','-NoProfile','-NonInteractive','-File',$capture)+@($invocation.arguments)) ([Text.Encoding]::UTF8.GetBytes('{}')) 10 65536
        $captured.ExitCode|Should -Be 0;$captured.Oversized|Should -BeFalse;$captured.StdErr|Should -BeExactly ''
        $actual=@($captured.StdOut|ConvertFrom-Json|ForEach-Object { $_ })
        $actual[-1]|Should -BeExactly $invocation.arguments[-1]
        $actual[-1]|Should -Match '^sudo -n /usr/bin/python3 -c '
        $actual|Should -Contain 'GlobalKnownHostsFile=NUL'
    }

    It 'rejects oversized CLI stdin before creating a prerequisite root' {
        $root=Join-Path $TestDrive 'oversized-cli-root';$pwsh=(Get-Process -Id $PID).Path
        $oversized='{"padding":"' + ('x'*140000) + '"}'
        $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$pwsh;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
        $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $start.Arguments='-NoLogo -NoProfile -NonInteractive -File "'+$script:Driver+'" -Action Plan -PrerequisiteRoot "'+$root+'"'
        $child=[Diagnostics.Process]::new();$child.StartInfo=$start;$null=$child.Start()
        $child.StandardInput.Write($oversized);$child.StandardInput.Close()
        $output=$child.StandardOutput.ReadToEnd()+$child.StandardError.ReadToEnd();$child.WaitForExit()
        $child.ExitCode|Should -Not -Be 0
        ($output|Out-String)|Should -Match 'stdin exceeds'
        Test-Path $root|Should -BeFalse
        $child.Dispose()
    }

    It 'executes the production owned Observe switch and always removes its exact agent' {
        $p = New-ProductionPrerequisiteFixture (Join-Path $TestDrive 'production-observe')
        $f = $p.Fixture
        $plan = New-P3PrerequisitePlan $f.Manifest ('c' * 64) $p.Agent.Root
        $calls = [Collections.Generic.List[string]]::new()
        $baselineSHA256 = Get-P3ServerBaselineSHA256 $f.Baseline
        $serverReceipt = [pscustomobject]@{
            schema='home-gateway/p3-prelive-server-observation/v1';server_baseline=$f.Baseline
            server_baseline_sha256=$baselineSHA256;payload_sha256=$f.Manifest.payload_sha256
            protocol_sha256=$f.Manifest.protocol_sha256;nonce_sha256=Get-P3SHA256Text ('c' * 64)
            live_mutation_performed=$false;raw_identity_exposed=$false
        }
        $boundaries = [pscustomobject]@{
            AgentRunner={param($exe)$calls.Add('start');[pscustomobject]@{schema='home-gateway/p3-windows-agent-launch/v1';output=@('SSH_AUTH_SOCK=C:\synthetic\agent.sock; export SSH_AUTH_SOCK;', 'SSH_AGENT_PID=77; export SSH_AGENT_PID;');started_at_utc=[DateTime]::UtcNow.ToString('o');windows_process_id=26484}}.GetNewClosure()
            AddRunner={param($path)$calls.Add('add')}.GetNewClosure()
            ListRunner={param($exe)"256 $($p.Agent.Fingerprint) p3 (ED25519)"}.GetNewClosure()
            ProcessRunner={param($pid)[pscustomobject]@{Id=$pid;Path=$p.Agent.Manifest.git_ssh_agent_path;StartTime=[DateTime]::UtcNow}}.GetNewClosure()
            DeleteRunner={$calls.Add('delete')}.GetNewClosure();StopRunner={param($pid)$calls.Add('stop')}.GetNewClosure()
            WaitRunner={param($pid)$calls.Add('wait')}.GetNewClosure();ReobserveRunner={param($pid)$calls.Add('reobserve');@()}.GetNewClosure()
            SocketExistsRunner={param($path)$false};ReceiptRemoveRunner={param($path)$calls.Add('receipt-remove');[IO.File]::Delete($path)}.GetNewClosure()
            SshRunner={param($exe,$args,$stdin,$timeout,$maximum)$calls.Add('ssh');[pscustomobject]@{ExitCode=0;TimedOut=$false;Oversized=$false;StdOut=($serverReceipt|ConvertTo-Json -Depth 30 -Compress);StdErr=''}}.GetNewClosure()
            HttpsRunner={param($entry,$clock)$calls.Add('https');[pscustomobject][ordered]@{schema='home-gateway/p3-prelive-egress-observation/v1';authority_sha256=$entry.authority_sha256;source_cidr_sha256=$f.Manifest.management_source_cidr_sha256;observed_at_utc=$f.Now.ToString('o')}}.GetNewClosure()
            ClockRunner={$f.Now.AddSeconds(5)}.GetNewClosure()
        }
        $result = Invoke-P3PrerequisiteProductionObservation -PrerequisiteRoot $p.Agent.Root `
            -InputObject ([pscustomobject]@{manifest=$f.Manifest;ssh_trust=$p.Trust;agent_manifest=$p.Agent.Manifest;nonce=('c'*64);expected_plan_sha256=$plan.plan_sha256;confirmation_challenge=$plan.confirmation_challenge}) `
            -Boundaries $boundaries
        $result.server_baseline_sha256 | Should -BeExactly $baselineSHA256
        $calls | Should -Contain 'ssh'
        @($calls | Where-Object {$_ -eq 'https'}).Count | Should -Be 3
        $calls[-1] | Should -BeExactly 'receipt-remove'
        (Test-Path (Join-Path $p.Agent.Root 'observation-batch.json')) | Should -BeTrue
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'emergency tears down the exact owned agent when its protected receipt changes before cleanup' {
        $p = New-ProductionPrerequisiteFixture (Join-Path $TestDrive 'tampered-agent-receipt')
        $f = $p.Fixture
        $plan = New-P3PrerequisitePlan $f.Manifest ('c' * 64) $p.Agent.Root
        $calls = [Collections.Generic.List[string]]::new()
        $boundaries = [pscustomobject]@{
            AgentRunner={param($exe)$calls.Add('start');[pscustomobject]@{schema='home-gateway/p3-windows-agent-launch/v1';output=@('SSH_AUTH_SOCK=C:\synthetic\agent.sock; export SSH_AUTH_SOCK;', 'SSH_AGENT_PID=77; export SSH_AGENT_PID;');started_at_utc=[DateTime]::UtcNow.ToString('o');windows_process_id=26484}}.GetNewClosure()
            AddRunner={param($path)$calls.Add('add')}.GetNewClosure()
            ListRunner={param($exe)"256 $($p.Agent.Fingerprint) p3 (ED25519)"}.GetNewClosure()
            ProcessRunner={param($ProcessId)[pscustomobject]@{Id=$ProcessId;Path=$p.Agent.Manifest.git_ssh_agent_path;StartTime=[DateTime]::UtcNow}}.GetNewClosure()
            DeleteRunner={$calls.Add('delete')}.GetNewClosure();StopRunner={param($ProcessId)$calls.Add('stop')}.GetNewClosure()
            WaitRunner={param($ProcessId)$calls.Add('wait')}.GetNewClosure();ReobserveRunner={param($ProcessId)$calls.Add('reobserve');@()}.GetNewClosure()
            SocketExistsRunner={param($path)$false};ReceiptRemoveRunner={param($path)$calls.Add('receipt-remove');[IO.File]::Delete($path)}.GetNewClosure()
            SshRunner={
                param($exe,$args,$stdin,$timeout,$maximum)
                $calls.Add('ssh')
                $receiptPath = Join-Path $p.Agent.Root 'agent-receipt.json'
                $stored = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
                $stored.socket = 'C:\synthetic\foreign.sock'
                [IO.File]::WriteAllText($receiptPath,($stored | ConvertTo-Json -Depth 16 -Compress),[Text.UTF8Encoding]::new($false))
                throw 'synthetic body failure'
            }.GetNewClosure()
            HttpsRunner={param($entry,$clock)throw 'not reached'}
            ClockRunner={$f.Now.AddSeconds(5)}.GetNewClosure()
        }
        { Invoke-P3PrerequisiteProductionObservation -PrerequisiteRoot $p.Agent.Root `
                -InputObject ([pscustomobject]@{manifest=$f.Manifest;ssh_trust=$p.Trust;agent_manifest=$p.Agent.Manifest;nonce=('c'*64);expected_plan_sha256=$plan.plan_sha256;confirmation_challenge=$plan.confirmation_challenge}) `
                -Boundaries $boundaries } | Should -Throw '*protected prerequisite agent receipt differs*'
        $calls | Should -Contain 'ssh'
        $calls | Should -Contain 'delete'
        $calls | Should -Contain 'stop'
        $calls | Should -Contain 'wait'
        $calls | Should -Contain 'reobserve'
        $calls | Should -Not -Contain 'receipt-remove'
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'persists, reopens, validates, and consumes the protected nonce-bound receipt once' {
        $p = New-ProductionPrerequisiteFixture (Join-Path $TestDrive 'protected-receipt')
        $f = $p.Fixture
        $null = Initialize-P3PrerequisiteRoot $p.Agent.Root $f.Manifest $p.Agent.Manifest
        $batch = [pscustomobject][ordered]@{
            schema='home-gateway/p3-prelive-observation-batch/v1';server_baseline=$f.Baseline
            server_baseline_sha256=Get-P3ServerBaselineSHA256 $f.Baseline;egress=$f.Egress
            nonce_sha256=Get-P3SHA256Text ('c' * 64);observed_at_utc=$f.Now.AddSeconds(5).ToString('o')
            live_mutation_performed=$false;raw_identity_exposed=$false
        }
        $null = Write-P3ProtectedPrerequisiteObservationBatch $p.Agent.Root $f.Manifest $batch $batch.nonce_sha256
        $null = Invoke-P3PrerequisiteAction RecordCloudFirewall ([pscustomobject]@{
            manifest=$f.Manifest;cloud_firewall=$f.Cloud
        }) ([pscustomobject]@{ClockRunner={$f.Now.AddSeconds(5)}.GetNewClosure();PrerequisiteRoot=$p.Agent.Root})
        $candidate = New-P3PrerequisiteReceipt -Manifest $f.Manifest -ServerBaseline $f.Baseline `
            -CloudObservation $f.Cloud -EgressObservations $f.Egress -NonceSHA256 (Get-P3SHA256Text ('c' * 64)) -NowUtc $f.Now.AddSeconds(5)
        $expected = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $candidate)
        $assembled = Invoke-P3PrerequisiteAction Assemble ([pscustomobject]@{
            manifest=$f.Manifest;expected_receipt_sha256=$expected
        }) ([pscustomobject]@{ClockRunner={$f.Now.AddSeconds(5)}.GetNewClosure();PrerequisiteRoot=$p.Agent.Root})
        $assembled.nonce_sha256 | Should -BeExactly (Get-P3SHA256Text ('c' * 64))
        (Test-Path (Join-Path $p.Agent.Root 'prerequisite-receipt.json')) | Should -BeTrue
        $validateBoundaries = [pscustomobject]@{ClockRunner={$f.Now.AddMinutes(1)}.GetNewClosure();PrerequisiteRoot=$p.Agent.Root}
        $validated = Invoke-P3PrerequisiteAction Validate ([pscustomobject]@{
            manifest=$f.Manifest;expected_receipt_sha256=$expected
        }) $validateBoundaries
        (Get-P3AgentCanonicalSHA256 $validated) | Should -BeExactly (Get-P3AgentCanonicalSHA256 $assembled)
        (Get-P3AgentCanonicalSHA256 (Invoke-P3PrerequisiteAction Validate ([pscustomobject]@{
            manifest=$f.Manifest;expected_receipt_sha256=$expected
        }) $validateBoundaries)) | Should -BeExactly (Get-P3AgentCanonicalSHA256 $assembled)
    }

    It 'rejects Assemble when no protected Observe batch and Cloud input exist' {
        $p = New-ProductionPrerequisiteFixture (Join-Path $TestDrive 'synthetic-bypass')
        $null = Initialize-P3PrerequisiteRoot $p.Agent.Root $p.Fixture.Manifest $p.Agent.Manifest
        { Invoke-P3PrerequisiteAction Assemble ([pscustomobject]@{
                manifest=$p.Fixture.Manifest;expected_receipt_sha256=('1' * 64)
            }) ([pscustomobject]@{ClockRunner={[DateTime]::Parse('2026-08-31T12:00:00Z').ToUniversalTime()};PrerequisiteRoot=$p.Agent.Root}) } |
            Should -Throw '*required prerequisite file*'
    }
}
