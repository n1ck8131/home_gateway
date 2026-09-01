$ErrorActionPreference = 'Stop'

Describe 'P3 exact remote helper lifecycle' {
    BeforeAll {
        $script:Remote = Join-Path $PSScriptRoot '..\..\scripts\p3-remote-helper.ps1'
        . $script:Remote

        function Write-SyntheticFile([string]$Path, [string]$Text) {
            [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
            return $Path
        }
    }

    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $root
        $ssh = Write-SyntheticFile (Join-Path $root 'ssh.exe') 'synthetic-ssh'
        $scp = Write-SyntheticFile (Join-Path $root 'scp.exe') 'synthetic-scp'
        $known = Write-SyntheticFile (Join-Path $root 'known_hosts') 'synthetic-known-host'
        $payload = Write-SyntheticFile (Join-Path $root 'guard.py') 'synthetic-payload-v2'
        $payloadHash = Get-P3RemoteFileSHA256 $payload
        $sourceHash = ('2' * 64)
        $script:Context = [pscustomobject]@{
            manifest_sha256 = ('1' * 64)
            Trust = [pscustomobject]@{
                ssh_user = 'homegateway'
                ssh_host = '192.0.2.10'
                known_hosts_path = $known
                known_hosts_sha256 = Get-P3RemoteFileSHA256 $known
                git_ssh_path = $ssh
                git_ssh_sha256 = Get-P3RemoteFileSHA256 $ssh
                git_scp_path = $scp
                git_scp_sha256 = Get-P3RemoteFileSHA256 $scp
                local_payload_path = $payload
                local_payload_sha256 = $payloadHash
                remote_payload_sha256 = $payloadHash
                management_source_cidr_sha256 = $sourceHash
                egress = @(
                    [pscustomobject]@{ authority_sha256 = ('a' * 64); source_cidr_sha256 = $sourceHash },
                    [pscustomobject]@{ authority_sha256 = ('b' * 64); source_cidr_sha256 = $sourceHash },
                    [pscustomobject]@{ authority_sha256 = ('c' * 64); source_cidr_sha256 = $sourceHash }
                )
            }
            Agent = [pscustomobject]@{
                schema = 'home-gateway/p3-ssh-agent-combined-receipt/v3'
                socket = '/tmp/ssh-synthetic/agent.4242'
                agent_pid = 77
                windows_process_id = 26484
                loaded_key_count = 1
                expected_key_match = $true
                agent_pid_match = $true
                windows_process_id_match = $true
                toolchain_match = $true
                manifest_sha256 = ('1' * 64)
            }
        }
        $script:ExactState = [ordered]@{
            state = 'exact'; regular = $true; owner_match = $true; group_match = $true
            mode_match = $true; payload_sha256 = $payloadHash; temporary_leftover_count = 0
        }
        $script:AbsentState = [ordered]@{
            state = 'absent'; regular = $false; owner_match = $false; group_match = $false
            mode_match = $false; payload_sha256 = ('0' * 64); temporary_leftover_count = 0
        }
    }

    It 'builds one strict pinned SSH argument contract' {
        $arguments = New-P3GitSshArguments -Trust $script:Context.Trust -Agent $script:Context.Agent -RemoteCommand @('sudo', '-n', '/usr/bin/stat')
        $arguments | Should -Contain 'BatchMode=yes'
        $arguments | Should -Contain 'StrictHostKeyChecking=yes'
        $arguments | Should -Contain "IdentityAgent=$($script:Context.Agent.socket)"
        $arguments | Should -Contain 'homegateway@192.0.2.10'
        $arguments[-3..-1] | Should -Be @('sudo', '-n', '/usr/bin/stat')
    }

    It 'builds a fixed JSON-emitting lifecycle adapter and a dedicated SCP contract' {
        $command = New-P3RemoteAdapterCommand -Mode classify -ExpectedPayloadSHA256 $script:Context.Trust.local_payload_sha256 -Token ''
        $command | Should -Contain '/usr/bin/python3'
        $command | Should -Contain 'classify'
        ($command -join ' ') | Should -Not -Match '/usr/bin/stat|sha256sum|&&'
        $scp = New-P3GitScpArguments -Trust $script:Context.Trust -Agent $script:Context.Agent
        $scp | Should -Contain 'BatchMode=yes'
        $scp | Should -Not -Contain 'homegateway@192.0.2.10'
        ($scp -join ' ') | Should -Not -Match 'sudo|classify|install|remove'
    }

    It 'executes the exact adapter protocol for absent install remove and failed-upload cleanup in TestDrive' {
        $program = Get-P3RemoteAdapterProgram
        $encodedProgram = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))
        $bootstrap = "import base64;exec(compile(base64.b64decode('$encodedProgram'),'<p3-test>','exec'))"
        $target = Join-Path $TestDrive 'adapter\home-gateway-p3-peer-guard'
        $uploadRoot = Join-Path $TestDrive 'adapter\uploads'
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target), $uploadRoot
        $token = '1' * 32
        $payload = [Text.Encoding]::UTF8.GetBytes('adapter-payload')
        $payloadHash = Get-P3RemoteSHA256Bytes $payload
        $absent = (& python -c $bootstrap classify $payloadHash $token $target $uploadRoot) | ConvertFrom-Json
        $LASTEXITCODE | Should -Be 0
        $absent.state | Should -BeExactly 'absent'

        $upload = Join-Path $uploadRoot ('.home-gateway-p3-' + $token + '.upload')
        [IO.File]::WriteAllBytes($upload, $payload)
        $installed = (& python -c $bootstrap install $payloadHash $token $target $uploadRoot) | ConvertFrom-Json
        $LASTEXITCODE | Should -Be 0
        $installed.schema | Should -BeExactly 'home-gateway/p3-remote-helper-install-receipt/v1'
        (Get-P3RemoteFileSHA256 $target) | Should -BeExactly $payloadHash
        Test-Path -LiteralPath $upload | Should -BeFalse

        $removed = (& python -c $bootstrap remove $payloadHash $token $target $uploadRoot) | ConvertFrom-Json
        $LASTEXITCODE | Should -Be 0
        $removed.schema | Should -BeExactly 'home-gateway/p3-remote-helper-remove-receipt/v1'
        Test-Path -LiteralPath $target | Should -BeFalse

        [IO.File]::WriteAllText($upload, 'wrong')
        $savedPreference = $ErrorActionPreference
        try { $ErrorActionPreference = 'Continue'; $null = & python -c $bootstrap install $payloadHash $token $target $uploadRoot 2>&1 }
        finally { $ErrorActionPreference = $savedPreference }
        $LASTEXITCODE | Should -Not -Be 0
        Test-Path -LiteralPath $upload | Should -BeFalse
        @(Get-ChildItem -LiteralPath (Split-Path -Parent $target) -Filter '*.next-*').Count | Should -Be 0

        [IO.File]::WriteAllText($upload, 'partial-upload')
        $next = $target + '.next-' + $token
        [IO.File]::WriteAllText($next, 'partial-next')
        $cleaned = (& python -c $bootstrap cleanup $payloadHash $token $target $uploadRoot) | ConvertFrom-Json
        $LASTEXITCODE | Should -Be 0
        $cleaned.state | Should -BeExactly 'absent'
        $cleaned.temporary_leftover_count | Should -Be 0
        Test-Path -LiteralPath $upload | Should -BeFalse
        Test-Path -LiteralPath $next | Should -BeFalse
    }

    It 'revalidates absent state at apply and stops on a target race before upload' {
        $plan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $script:AbsentState | ConvertTo-Json -Compress }
        $script:ScpCalls = 0
        { Invoke-P3RemoteInstall -Context $script:Context -Plan $plan -ScpRunner { $script:ScpCalls++ } -SshRunner {
            param($Executable, $Arguments, $Mode)
            if ($Mode -ceq 'classify') { return ($script:ExactState | ConvertTo-Json -Compress) }
            throw 'install must not run'
        } } | Should -Throw '*race*'
        $script:ScpCalls | Should -Be 0
    }

    It 'classifies absent and exact state through a read-only plan runner' {
        $script:SshCalls = 0
        $absent = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner {
            param($Executable, $Arguments, $Mode) $script:SshCalls++; $script:AbsentState | ConvertTo-Json -Compress
        }
        $exact = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner {
            param($Executable, $Arguments, $Mode) $script:SshCalls++; $script:ExactState | ConvertTo-Json -Compress
        }
        $absent.state | Should -BeExactly 'absent'
        $exact.state | Should -BeExactly 'exact'
        $absent.confirmation_challenge | Should -Match '^P3-REMOTE-INSTALL-[0-9A-F]{16}$'
        $script:SshCalls | Should -Be 2
    }

    It 'never overwrites a conflicting remote path' {
        $conflictState = [ordered]@{} + $script:ExactState
        $conflictState.owner_match = $false
        $plan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $conflictState | ConvertTo-Json -Compress }
        $plan.state | Should -BeExactly 'conflict'
        $script:ScpCalls = 0
        { Invoke-P3RemoteInstall -Context $script:Context -Plan $plan -ScpRunner { $script:ScpCalls++ } -SshRunner { throw 'must not run' } } |
            Should -Throw '*conflict*'
        $script:ScpCalls | Should -Be 0
    }

    It 'keeps a pre-existing exact helper as an idempotent no-op' {
        $plan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $script:ExactState | ConvertTo-Json -Compress }
        $script:NoopCalls = 0
        $receipt = Invoke-P3RemoteInstall -Context $script:Context -Plan $plan -ScpRunner { $script:NoopCalls++ } -SshRunner { $script:NoopCalls++; $script:ExactState | ConvertTo-Json -Compress }
        $receipt.installed_by_gate | Should -BeFalse
        $receipt.preinstall_state | Should -BeExactly 'exact'
        $script:NoopCalls | Should -Be 1
    }

    It 'installs an absent helper through one upload and one atomic install request' {
        $plan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $script:AbsentState | ConvertTo-Json -Compress }
        $script:ScpCalls = 0
        $script:InstallCalls = 0
        $receipt = Invoke-P3RemoteInstall -Context $script:Context -Plan $plan `
            -ScpRunner { param($Executable, $Arguments, $Source, $Target) $script:ScpCalls++; [pscustomobject]@{ exit_code = 0 } } `
            -SshRunner {
                param($Executable, $Arguments, $Mode, $Request)
                $script:InstallCalls++
                if ($Mode -ceq 'classify') { return ($script:AbsentState | ConvertTo-Json -Compress) }
                if ($Mode -ceq 'cleanup') { return ($script:ExactState | ConvertTo-Json -Compress) }
                [ordered]@{
                    schema = 'home-gateway/p3-remote-helper-install-receipt/v1'; target_state = 'exact'
                    payload_sha256 = $script:Context.Trust.local_payload_sha256; owner_match = $true
                    group_match = $true; mode_match = $true; installed_by_gate = $true
                    preinstall_state = 'absent'; temporary_leftover_count = 0
                } | ConvertTo-Json -Compress
            }
        $receipt.installed_by_gate | Should -BeTrue
        $receipt.temporary_leftover_count | Should -Be 0
        $script:ScpCalls | Should -Be 1
        $script:InstallCalls | Should -Be 3
    }

    It 'cleans and reclassifies a partial upload after every failed SCP attempt' {
        $plan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $script:AbsentState | ConvertTo-Json -Compress }
        $partial = Join-Path $TestDrive 'partial-upload'

        {
            Invoke-P3RemoteInstall -Context $script:Context -Plan $plan `
                -ScpRunner {
                    [IO.File]::WriteAllText($partial, 'partial')
                    [pscustomobject]@{ exit_code = 17 }
                } `
                -SshRunner {
                    param($Executable, $Arguments, $Mode)
                    if ($Mode -ceq 'classify') { return ($script:AbsentState | ConvertTo-Json -Compress) }
                    if ($Mode -ceq 'cleanup') {
                        [IO.File]::Delete($partial)
                        return ($script:AbsentState | ConvertTo-Json -Compress)
                    }
                    throw 'unexpected remote mode'
                }
        } | Should -Throw '*upload*'

        Test-Path -LiteralPath $partial | Should -BeFalse
    }

    It 'makes partial-upload cleanup failure terminal' {
        $plan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $script:AbsentState | ConvertTo-Json -Compress }
        $dirty = [ordered]@{} + $script:AbsentState
        $dirty.temporary_leftover_count = 1

        {
            Invoke-P3RemoteInstall -Context $script:Context -Plan $plan `
                -ScpRunner { [pscustomobject]@{ exit_code = 17 } } `
                -SshRunner {
                    param($Executable, $Arguments, $Mode)
                    if ($Mode -ceq 'classify') { return ($script:AbsentState | ConvertTo-Json -Compress) }
                    if ($Mode -ceq 'cleanup') { return ($dirty | ConvertTo-Json -Compress) }
                    throw 'unexpected remote mode'
                }
        } | Should -Throw '*cleanup*'
    }

    It 'rejects changed context failed upload identity and cleanup leftovers' {
        $plan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $script:AbsentState | ConvertTo-Json -Compress }
        $script:Context.Trust.egress[0].source_cidr_sha256 = ('f' * 64)
        { Invoke-P3RemoteInstall -Context $script:Context -Plan $plan -ScpRunner { } -SshRunner { } } | Should -Throw '*egress*'

        $script:Context.Trust.egress[0].source_cidr_sha256 = $script:Context.Trust.management_source_cidr_sha256
        { Invoke-P3RemoteInstall -Context $script:Context -Plan $plan -ScpRunner { [pscustomobject]@{ exit_code = 1 } } -SshRunner { $script:AbsentState | ConvertTo-Json -Compress } } |
            Should -Throw '*upload*'
        { Invoke-P3RemoteInstall -Context $script:Context -Plan $plan -ScpRunner { [pscustomobject]@{ exit_code = 0 } } -SshRunner {
            param($Executable, $Arguments, $Mode)
            if ($Mode -ceq 'classify') { return ($script:AbsentState | ConvertTo-Json -Compress) }
            [ordered]@{
                schema = 'home-gateway/p3-remote-helper-install-receipt/v1'; target_state = 'exact'
                payload_sha256 = $script:Context.Trust.local_payload_sha256; owner_match = $true
                group_match = $true; mode_match = $true; installed_by_gate = $true
                preinstall_state = 'absent'; temporary_leftover_count = 1
            } | ConvertTo-Json -Compress
        } } | Should -Throw '*cleanup*'
    }

    It 'removes only the exact helper installed by this gate' {
        $installPlan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $script:AbsentState | ConvertTo-Json -Compress }
        $installReceipt = Invoke-P3RemoteInstall -Context $script:Context -Plan $installPlan `
            -ScpRunner { [pscustomobject]@{ exit_code = 0 } } -SshRunner {
                param($Executable, $Arguments, $Mode)
                if ($Mode -ceq 'classify') { return ($script:AbsentState | ConvertTo-Json -Compress) }
                if ($Mode -ceq 'cleanup') { return ($script:ExactState | ConvertTo-Json -Compress) }
                [ordered]@{
                    schema = 'home-gateway/p3-remote-helper-install-receipt/v1'; target_state = 'exact'
                    payload_sha256 = $script:Context.Trust.local_payload_sha256; owner_match = $true
                    group_match = $true; mode_match = $true; installed_by_gate = $true
                    preinstall_state = 'absent'; temporary_leftover_count = 0
                } | ConvertTo-Json -Compress
            }
        $removePlan = Invoke-P3RemoteRemovePlan -Context $script:Context -InstallReceipt $installReceipt -SshRunner { $script:ExactState | ConvertTo-Json -Compress }
        $script:RemoveCalls = 0
        $removed = Invoke-P3RemoteRemove -Context $script:Context -InstallReceipt $installReceipt -RemovePlan $removePlan -SshRunner {
            param($Executable, $Arguments, $Mode)
            $script:RemoveCalls++
            if ($Mode -ceq 'classify') { return ($script:ExactState | ConvertTo-Json -Compress) }
            '{"schema":"home-gateway/p3-remote-helper-remove-receipt/v1","removed":true,"target_state":"absent","temporary_leftover_count":0}'
        }
        $removed.removed | Should -BeTrue
        $script:RemoveCalls | Should -Be 2

        $preexisting = $installReceipt | Select-Object *
        $preexisting.installed_by_gate = $false
        $preexisting.preinstall_state = 'exact'
        { Invoke-P3RemoteRemovePlan -Context $script:Context -InstallReceipt $preexisting -SshRunner { throw 'must not run' } } |
            Should -Throw '*not installed by this gate*'
    }

    It 'rejects trust or agent drift before any external runner' {
        $calls = 0
        $script:Context.Agent.loaded_key_count = 2
        { Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $calls++ } } | Should -Throw '*agent*'
        $calls | Should -Be 0
        $script:Context.Agent.loaded_key_count = 1
        [IO.File]::AppendAllText($script:Context.Trust.known_hosts_path, 'changed')
        { Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner { $calls++ } } | Should -Throw '*known-hosts*'
        $calls | Should -Be 0
    }
}
