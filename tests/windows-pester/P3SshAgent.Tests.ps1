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
}
