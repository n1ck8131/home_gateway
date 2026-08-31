$ErrorActionPreference = 'Stop'

Describe 'P3 dedicated Git OpenSSH agent lifecycle' {
    BeforeAll {
        $script:AgentScript = Join-Path $PSScriptRoot '..\..\scripts\p3-ssh-agent.ps1'
        . $script:AgentScript

        function Get-TestSHA256([string]$Text) {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
        }
    }

    BeforeEach {
        $env:SSH_AUTH_SOCK = $null
        $env:SSH_AGENT_PID = $null
        $script:GitRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:GitBin = Join-Path $script:GitRoot 'usr\bin'
        $null = New-Item -ItemType Directory -Path $script:GitBin
        $script:Paths = [ordered]@{}
        foreach ($name in @('ssh-agent.exe', 'ssh-add.exe', 'ssh.exe', 'scp.exe')) {
            $path = Join-Path $script:GitBin $name
            [IO.File]::WriteAllText($path, "synthetic-$name", [Text.UTF8Encoding]::new($false))
            $script:Paths[$name] = $path
        }
        $script:Fingerprint = 'SHA256:synthetic-key'
        $script:Manifest = [pscustomobject]@{
            git_ssh_agent_path = $script:Paths.'ssh-agent.exe'
            git_ssh_add_path = $script:Paths.'ssh-add.exe'
            git_ssh_path = $script:Paths.'ssh.exe'
            git_scp_path = $script:Paths.'scp.exe'
            git_ssh_agent_sha256 = Get-P3AgentFileSHA256 $script:Paths.'ssh-agent.exe'
            git_ssh_add_sha256 = Get-P3AgentFileSHA256 $script:Paths.'ssh-add.exe'
            git_ssh_sha256 = Get-P3AgentFileSHA256 $script:Paths.'ssh.exe'
            git_scp_sha256 = Get-P3AgentFileSHA256 $script:Paths.'scp.exe'
            public_key_path = Join-Path $TestDrive 'operator.pub'
            private_key_path = Join-Path $TestDrive 'operator'
            public_key_fingerprint_sha256 = Get-TestSHA256 $script:Fingerprint
            manifest_sha256 = ('a' * 64)
        }
        [IO.File]::WriteAllText($script:Manifest.public_key_path, 'ssh-ed25519 AAAA synthetic')
        $script:AgentReceipt = [pscustomobject]@{
            schema = 'home-gateway/p3-ssh-agent-receipt/v1'
            manifest_sha256 = ('a' * 64)
            agent_pid = 4242
            socket = '/tmp/ssh-synthetic/agent.4242'
            agent_executable_path = $script:Paths.'ssh-agent.exe'
            agent_executable_sha256 = $script:Manifest.git_ssh_agent_sha256
            expected_fingerprint_sha256 = $script:Manifest.public_key_fingerprint_sha256
            started_at_utc = [DateTime]::UtcNow.AddSeconds(-2).ToString('o')
        }
    }

    AfterEach {
        $env:SSH_AUTH_SOCK = $null
        $env:SSH_AGENT_PID = $null
    }

    It 'plans one exact Git toolchain and public key without starting an agent' {
        $calls = 0
        $plan = New-P3AgentPlan -Manifest $script:Manifest
        $plan.schema | Should -BeExactly 'home-gateway/p3-ssh-agent-plan/v1'
        $plan.plan_sha256 | Should -Match '^[0-9a-f]{64}$'
        $plan.confirmation_challenge | Should -Match '^P3-SSH-AGENT-[0-9A-F]{16}$'
        $plan.toolchain_root_sha256 | Should -Match '^[0-9a-f]{64}$'
        $calls | Should -Be 0
    }

    It 'rejects mixed or changed Git toolchain files' {
        $other = Join-Path $TestDrive 'other\ssh.exe'
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $other)
        [IO.File]::WriteAllText($other, 'synthetic-ssh.exe')
        $script:Manifest.git_ssh_path = $other
        { Resolve-P3GitOpenSshToolchain -Manifest $script:Manifest } | Should -Throw '*one Git OpenSSH root*'

        $script:Manifest.git_ssh_path = $script:Paths.'ssh.exe'
        [IO.File]::AppendAllText($script:Manifest.git_ssh_path, 'changed')
        { Resolve-P3GitOpenSshToolchain -Manifest $script:Manifest } | Should -Throw '*hash*'
    }

    It 'accepts exactly one expected key and the receipt-bound process' {
        $receipt = Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 4242; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) } }
        $receipt.schema | Should -BeExactly 'home-gateway/p3-ssh-agent-combined-receipt/v2'
        $receipt.agent_pid | Should -Be 4242
        $receipt.socket | Should -BeExactly '/tmp/ssh-synthetic/agent.4242'
        $receipt.loaded_key_count | Should -Be 1
        $receipt.expected_key_match | Should -BeTrue
    }

    It 'keeps persisted UTC receipt identity exact across the PS7 JSON timestamp type' {
        $receipt = [pscustomobject]@{
            schema = 'home-gateway/p3-ssh-agent-combined-receipt/v2'; manifest_sha256 = ('a' * 64)
            agent_pid = 4242; socket = '/tmp/ssh-synthetic/agent.4242'
            agent_executable_path = $script:Paths.'ssh-agent.exe'; agent_executable_sha256 = $script:Manifest.git_ssh_agent_sha256
            expected_fingerprint_sha256 = $script:Manifest.public_key_fingerprint_sha256
            started_at_utc = '2026-08-31T12:34:56.1234500Z'
            loaded_key_count = 1; expected_key_match = $true; agent_pid_match = $true; toolchain_match = $true
        }
        $persisted = $receipt | ConvertTo-Json -Depth 16 -Compress | ConvertFrom-Json

        (Get-P3AgentCanonicalSHA256 $persisted) | Should -BeExactly (Get-P3AgentCanonicalSHA256 $receipt)
        $persisted.socket = '/tmp/ssh-synthetic/agent.changed'
        (Get-P3AgentCanonicalSHA256 $persisted) | Should -Not -BeExactly (Get-P3AgentCanonicalSHA256 $receipt)
    }

    It 'rejects zero two or wrong agent keys and PID reuse' {
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt -ListRunner { '' } `
            -ProcessRunner { [pscustomobject]@{ Id = 4242; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*exactly one*'
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { "256 SHA256:synthetic-key p3 (ED25519)`n256 SHA256:second p3 (ED25519)" } `
            -ProcessRunner { [pscustomobject]@{ Id = 4242; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*exactly one*'
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:wrong p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 4242; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*fingerprint*'
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 4242; Path = $script:Paths.'ssh.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*process*'
    }

    It 'refuses a pre-existing agent environment before invoking a runner' {
        $env:SSH_AUTH_SOCK = '/tmp/preexisting'
        $calls = 0
        { Start-P3Agent -Manifest $script:Manifest -AgentRunner { $calls++ } -AddRunner { $calls++ } -StopRunner { $calls++ } } |
            Should -Throw '*pre-existing*'
        $calls | Should -Be 0
    }

    It 'destroys only the newly created agent when ssh-add fails' {
        $script:StoppedPids = @()
        { Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { "SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;`nSSH_AGENT_PID=4242; export SSH_AGENT_PID;" } `
            -AddRunner { throw 'synthetic add failure' } `
            -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } } | Should -Throw '*ssh-add*'
        $script:StoppedPids | Should -Be @(4242)
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'stops a uniquely parsed newly created PID when the full agent output is malformed' {
        $script:StoppedPids = @()
        { Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { "unexpected`nSSH_AGENT_PID=4242; export SSH_AGENT_PID;" } `
            -AddRunner { throw 'must not add' } `
            -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } } | Should -Throw '*malformed*'
        $script:StoppedPids | Should -Be @(4242)
    }

    It 'treats cleanup failure as terminal and never swallows it' {
        { Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { "SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;`nSSH_AGENT_PID=4242; export SSH_AGENT_PID;" } `
            -AddRunner { throw 'synthetic add failure' } `
            -StopRunner { throw 'synthetic stop failure' } } | Should -Throw '*cleanup failed*'
    }

    It 'starts validates and stops only the receipt-bound agent' {
        $script:StoppedPids = @()
        $script:Deleted = 0
        $receipt = Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { "SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;`nSSH_AGENT_PID=4242; export SSH_AGENT_PID;" } `
            -AddRunner { param($Path) if ($Path -cne $script:Manifest.private_key_path) { throw 'wrong key path' } } `
            -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId }
        $validated = Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $receipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 4242; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } }
        $stop = Stop-P3Agent -Manifest $script:Manifest -AgentReceipt $receipt `
            -DeleteRunner { $script:Deleted++ } -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 4242; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } `
            -WaitRunner { param($ProcessId) } -ReobserveRunner { param($ProcessId) @() } -SocketExistsRunner { param($Path) $false }
        $validated.expected_key_match | Should -BeTrue
        $stop.stopped | Should -BeTrue
        $script:Deleted | Should -Be 1
        $script:StoppedPids | Should -Be @(4242)
    }

    It 'rejects a changed receipt before deleting keys or stopping a process' {
        $script:AgentReceipt.socket = '/tmp/changed'
        $calls = 0
        { Stop-P3Agent -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -DeleteRunner { $calls++ } -StopRunner { $calls++ } `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 4242; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*environment*'
        $calls | Should -Be 0
    }

    It 'bounds agent exit polling for absent delayed and timed out processes' {
        $base = [DateTime]::Parse('2026-08-31T12:00:00Z')

        $script:WaitObserveCalls = 0; $script:WaitSleepCalls = 0
        Wait-P3BoundedAgentExit -ProcessId 4242 -ObserveRunner { param($ProcessId) $script:WaitObserveCalls++; @() } `
            -SleepRunner { param($Milliseconds) $script:WaitSleepCalls++ } -ClockRunner { $base } | Out-Null
        $script:WaitObserveCalls | Should -Be 1
        $script:WaitSleepCalls | Should -Be 0

        $script:WaitObserveCalls = 0; $script:WaitSleepCalls = 0; $script:WaitNow = $base
        Wait-P3BoundedAgentExit -ProcessId 4242 -ObserveRunner {
            param($ProcessId)
            $script:WaitObserveCalls++
            if ($script:WaitObserveCalls -lt 3) { @([pscustomobject]@{ Id = $ProcessId }) } else { @() }
        } -SleepRunner { param($Milliseconds) $script:WaitSleepCalls++; $script:WaitNow = $script:WaitNow.AddMilliseconds($Milliseconds) } `
            -ClockRunner { $script:WaitNow } | Out-Null
        $script:WaitObserveCalls | Should -Be 3
        $script:WaitSleepCalls | Should -Be 2

        $script:WaitNow = $base; $script:WaitSleepCalls = 0
        { Wait-P3BoundedAgentExit -ProcessId 4242 -ObserveRunner { param($ProcessId) @([pscustomobject]@{ Id = $ProcessId }) } `
            -SleepRunner { param($Milliseconds) $script:WaitSleepCalls++; $script:WaitNow = $script:WaitNow.AddSeconds(11) } `
            -ClockRunner { $script:WaitNow } } | Should -Throw '*timed out*'
        $script:WaitSleepCalls | Should -Be 1
    }

    It 'normalizes native local and unspecified process start times for validation and cleanup' {
        $receiptUtc = [DateTime]::SpecifyKind([DateTime]::Parse('2026-08-31T12:00:00'), [DateTimeKind]::Utc)
        [TimeZoneInfo]::Local.GetUtcOffset($receiptUtc).TotalMinutes | Should -Not -Be 0
        $localStart = $receiptUtc.ToLocalTime()
        $unspecifiedStart = [DateTime]::SpecifyKind($localStart, [DateTimeKind]::Unspecified)
        $script:AgentReceipt.started_at_utc = $receiptUtc.ToString('o')
        $processState = [pscustomobject]@{ Calls=0;Local=$localStart;Unspecified=$unspecifiedStart;Path=$script:Paths.'ssh-agent.exe' }
        $processRunner = {
            param($ProcessId)
            $processState.Calls++
            $start = if ($processState.Calls -eq 1) { $processState.Local } else { $processState.Unspecified }
            [pscustomobject]@{ Id=$ProcessId;Path=$processState.Path;StartTime=$start }
        }.GetNewClosure()

        $validated = Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } -ProcessRunner $processRunner
        $env:SSH_AUTH_SOCK = $script:AgentReceipt.socket; $env:SSH_AGENT_PID = [string]$script:AgentReceipt.agent_pid
        $stop = Stop-P3Agent -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -DeleteRunner { } -StopRunner { param($ProcessId) } -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner $processRunner -WaitRunner { param($ProcessId) } -ReobserveRunner { param($ProcessId) @() } `
            -SocketExistsRunner { param($Path) $false }

        $validated.expected_key_match | Should -BeTrue
        $stop.stopped | Should -BeTrue
        $processState.Calls | Should -Be 2
    }

    It 'rejects non-UTC receipt timestamps and true process start drift' {
        $receiptUtc = [DateTime]::SpecifyKind([DateTime]::Parse('2026-08-31T12:00:00'), [DateTimeKind]::Utc)
        $localStart = $receiptUtc.ToLocalTime()
        $script:AgentReceipt.started_at_utc = '2026-08-31T14:00:00.0000000+02:00'
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id=4242;Path=$script:Paths.'ssh-agent.exe';StartTime=$localStart } } } |
            Should -Throw '*UTC*'

        $script:AgentReceipt.started_at_utc = $receiptUtc.ToString('o')
        $drifted = [DateTime]::SpecifyKind($localStart.AddSeconds(11), [DateTimeKind]::Unspecified)
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id=4242;Path=$script:Paths.'ssh-agent.exe';StartTime=$drifted } } } |
            Should -Throw '*creation window*'
    }
}
