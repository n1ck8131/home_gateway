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

        function New-TestAgentLaunch([string[]]$Output, [int]$WindowsProcessId = 26484, [DateTime]$StartedAtUtc = ([DateTime]::UtcNow.AddSeconds(-2))) {
            return [pscustomobject][ordered]@{
                schema = 'home-gateway/p3-windows-agent-launch/v1'
                output = $Output
                started_at_utc = $StartedAtUtc.ToUniversalTime().ToString('o')
                windows_process_id = $WindowsProcessId
            }
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
            schema = 'home-gateway/p3-ssh-agent-receipt/v2'
            manifest_sha256 = ('a' * 64)
            agent_pid = 77
            windows_process_id = 26484
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

    It 'accepts exact LF and CRLF foreground records with at most one terminal newline' {
        $socket = 'SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.77; export SSH_AUTH_SOCK;'
        $foregroundPid = 'echo Agent pid 77;'
        foreach ($output in @("$socket`n$foregroundPid", "$socket`r`n$foregroundPid`r`n")) {
            $parsed = ConvertFrom-P3AgentOutput -Output $output
            $parsed.socket | Should -BeExactly '/tmp/ssh-synthetic/agent.77'
            $parsed.agent_pid | Should -Be 77
        }
    }

    It 'rejects assignment ambiguous duplicate missing malformed unknown blank lone-CR and overflow foreground records' {
        $socket = 'SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.77; export SSH_AUTH_SOCK;'
        $foregroundPid = 'echo Agent pid 77;'
        $cases = @(
            @($socket, 'SSH_AGENT_PID=77; export SSH_AGENT_PID;'),
            @($socket, $foregroundPid, 'SSH_AGENT_PID=77; export SSH_AGENT_PID;'),
            @($socket, $foregroundPid, $foregroundPid),
            @($socket),
            @($socket, 'echo Agent pid 0;'),
            @($socket, 'echo Agent pid 77'),
            @('unknown', $socket, $foregroundPid),
            @($socket, $foregroundPid, 'unknown'),
            @($socket, ' SSH_AGENT_PID=77; export SSH_AGENT_PID;'),
            @($socket, 'echo Agent pid 2147483648;')
        )

        foreach ($records in $cases) {
            { ConvertFrom-P3AgentOutput -Output ($records -join "`n") } | Should -Throw '*malformed*'
        }
        { ConvertFrom-P3AgentOutput -Output "$socket`n`n$foregroundPid" } | Should -Throw '*malformed*'
        { ConvertFrom-P3AgentOutput -Output "$socket`r$foregroundPid" } | Should -Throw '*malformed*'
    }

    It 'accepts exactly one expected key and the receipt-bound process' {
        $receipt = Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) } }
        $receipt.schema | Should -BeExactly 'home-gateway/p3-ssh-agent-combined-receipt/v3'
        $receipt.agent_pid | Should -Be 77
        $receipt.windows_process_id | Should -Be 26484
        $receipt.socket | Should -BeExactly '/tmp/ssh-synthetic/agent.4242'
        $receipt.loaded_key_count | Should -Be 1
        $receipt.expected_key_match | Should -BeTrue
    }

    It 'keeps persisted UTC receipt identity exact across the PS7 JSON timestamp type' {
        $receipt = [pscustomobject]@{
            schema = 'home-gateway/p3-ssh-agent-combined-receipt/v3'; manifest_sha256 = ('a' * 64)
            agent_pid = 77; windows_process_id = 26484; socket = '/tmp/ssh-synthetic/agent.4242'
            agent_executable_path = $script:Paths.'ssh-agent.exe'; agent_executable_sha256 = $script:Manifest.git_ssh_agent_sha256
            expected_fingerprint_sha256 = $script:Manifest.public_key_fingerprint_sha256
            started_at_utc = '2026-08-31T12:34:56.1234500Z'
            loaded_key_count = 1; expected_key_match = $true; agent_pid_match = $true; windows_process_id_match = $true; toolchain_match = $true
        }
        $persisted = $receipt | ConvertTo-Json -Depth 16 -Compress | ConvertFrom-Json

        (Get-P3AgentCanonicalSHA256 $persisted) | Should -BeExactly (Get-P3AgentCanonicalSHA256 $receipt)
        $persisted.socket = '/tmp/ssh-synthetic/agent.changed'
        (Get-P3AgentCanonicalSHA256 $persisted) | Should -Not -BeExactly (Get-P3AgentCanonicalSHA256 $receipt)
    }

    It 'rejects zero two or wrong agent keys and PID reuse' {
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt -ListRunner { '' } `
            -ProcessRunner { [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*exactly one*'
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { "256 SHA256:synthetic-key p3 (ED25519)`n256 SHA256:second p3 (ED25519)" } `
            -ProcessRunner { [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*exactly one*'
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:wrong p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*fingerprint*'
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh.exe'; StartTime = [DateTime]::UtcNow } } } |
            Should -Throw '*process*'
    }

    It 'refuses a pre-existing agent environment before invoking a runner' {
        $env:SSH_AUTH_SOCK = '/tmp/preexisting'
        $calls = 0
        { Start-P3Agent -Manifest $script:Manifest -AgentRunner { $calls++ } -ProcessRunner { $calls++ } -AddRunner { $calls++ } -StopRunner { $calls++ } } |
            Should -Throw '*pre-existing*'
        $calls | Should -Be 0
    }

    It 'preserves native ssh-agent output records when starting the dedicated agent' {
        $receipt = Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner {
                New-TestAgentLaunch -Output @(
                    'SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;'
                    'echo Agent pid 4242;'
                )
            } `
            -ProcessRunner { param($ProcessId) [pscustomobject]@{ Id = $ProcessId; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) } } `
            -AddRunner { } `
            -StopRunner { throw 'must not stop a successfully started agent' }

        $receipt.agent_pid | Should -Be 4242
        $receipt.windows_process_id | Should -Be 26484
        $receipt.socket | Should -BeExactly '/tmp/ssh-synthetic/agent.4242'
    }

    It 'keeps emitted MSYS PID for the environment but uses Windows PID for lifecycle' {
        $script:ObservedPids = @()
        $script:StoppedPids = @()
        $script:Launch = [pscustomobject]@{
            schema = 'home-gateway/p3-windows-agent-launch/v1'
            output = @(
                'SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.77; export SSH_AUTH_SOCK;'
                'echo Agent pid 77;'
            )
            started_at_utc = [DateTime]::UtcNow.AddSeconds(-1).ToString('o')
            windows_process_id = 26484
        }
        $receipt = Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { $script:Launch } -ProcessRunner {
                param($ProcessId) $script:ObservedPids += $ProcessId
                [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-1) }
            } -AddRunner { } -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId }
        $env:SSH_AGENT_PID | Should -BeExactly '77'
        $receipt.agent_pid | Should -Be 77
        $receipt.windows_process_id | Should -Be 26484
        $script:ObservedPids | Should -Be @(26484)
    }

    It 'cleans up the Windows PID when structured launch output is malformed' {
        $script:StoppedPids = @()
        { Start-P3Agent -Manifest $script:Manifest -AgentRunner {
            [pscustomobject]@{ schema = 'home-gateway/p3-windows-agent-launch/v1'; output = @('unexpected', 'echo Agent pid 77;'); started_at_utc = [DateTime]::UtcNow.ToString('o'); windows_process_id = 26484 }
        } -ProcessRunner { param($ProcessId) [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } -AddRunner { throw 'must not add' } -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } } | Should -Throw '*malformed*'
        $script:StoppedPids | Should -Be @(26484)
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'rejects an extra foreground agent record end to end before adding a key' {
        $script:Added = 0
        $script:StoppedPids = @()
        { Start-P3Agent -Manifest $script:Manifest -AgentRunner {
            New-TestAgentLaunch -Output @(
                'SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.77; export SSH_AUTH_SOCK;'
                'echo Agent pid 77;'
                'unexpected third record'
            )
        } -ProcessRunner { param($ProcessId) [pscustomobject]@{ Id = $ProcessId; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } `
            -AddRunner { $script:Added++ } -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } } | Should -Throw '*malformed*'
        $script:Added | Should -Be 0
        $script:StoppedPids | Should -Be @(26484)
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'fails closed without stopping an unvalidated Windows process observation' {
        $cases = @(@{ Processes = @() }, @{ Processes = @([pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow }, [pscustomobject]@{ Id = 26485; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow }) }, @{ Processes = @([pscustomobject]@{ Id = 77; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow }) }, @{ Processes = @([pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh.exe'; StartTime = [DateTime]::UtcNow }) }, @{ Processes = @([pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-11) }) })
        foreach ($case in $cases) {
            $script:Added = 0; $script:StoppedPids = @()
            { Start-P3Agent -Manifest $script:Manifest -AgentRunner { [pscustomobject]@{ schema = 'home-gateway/p3-windows-agent-launch/v1'; output = @('SSH_AUTH_SOCK=/tmp/a; export SSH_AUTH_SOCK;', 'echo Agent pid 77;'); started_at_utc = [DateTime]::UtcNow.ToString('o'); windows_process_id = 26484 } } -ProcessRunner { param($ProcessId) $case.Processes } -AddRunner { $script:Added++ } -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } } | Should -Throw
            $script:Added | Should -Be 0; $script:StoppedPids | Should -BeNullOrEmpty
        }
    }

    It 'configures the visible non-redirecting ssh-add boundary' {
        $script:CapturedAddStartInfo = $null
        Invoke-P3InteractiveAgentAdd -ExecutablePath $script:Paths.'ssh-add.exe' -KeyPath $script:Manifest.private_key_path -ProcessRunner { param($ProcessStartInfo) $script:CapturedAddStartInfo = $ProcessStartInfo; [pscustomobject]@{ exit_code = 0 } }
        $script:CapturedAddStartInfo.UseShellExecute | Should -BeTrue; $script:CapturedAddStartInfo.CreateNoWindow | Should -BeFalse
        $script:CapturedAddStartInfo.RedirectStandardInput | Should -BeFalse; $script:CapturedAddStartInfo.RedirectStandardOutput | Should -BeFalse; $script:CapturedAddStartInfo.RedirectStandardError | Should -BeFalse
        $script:CapturedAddStartInfo.WindowStyle | Should -Be ([System.Diagnostics.ProcessWindowStyle]::Normal)
        $script:CapturedAddStartInfo.FileName | Should -BeExactly $script:Paths.'ssh-add.exe'
        $script:CapturedAddStartInfo.Arguments | Should -BeExactly ('"' + $script:Manifest.private_key_path + '"')
    }

    It 'rejects quoted agent executable ssh-add executable and key paths before a process boundary' {
        $processBoundaryCalls = 0
        $quotedAgentPath = $script:Paths.'ssh-agent.exe'.Replace('ssh-agent.exe', 'ssh"agent.exe')
        $quotedAddPath = $script:Paths.'ssh-add.exe'.Replace('ssh-add.exe', 'ssh"add.exe')
        $quotedKeyPath = $script:Manifest.private_key_path + '"'

        { Start-P3WindowsAgentProcess -ExecutablePath $quotedAgentPath -ProcessRunner { $processBoundaryCalls++ } } | Should -Throw '*launch input*'
        { Invoke-P3InteractiveAgentAdd -ExecutablePath $quotedAddPath -KeyPath $script:Manifest.private_key_path -ProcessRunner { $processBoundaryCalls++ } } | Should -Throw '*executable path*'
        { Invoke-P3InteractiveAgentAdd -ExecutablePath $script:Paths.'ssh-add.exe' -KeyPath $quotedKeyPath -ProcessRunner { $processBoundaryCalls++ } } | Should -Throw '*key path*'
        $processBoundaryCalls | Should -Be 0
    }

    It 'rejects a nonzero visible ssh-add exit code' {
        { Invoke-P3InteractiveAgentAdd -ExecutablePath $script:Paths.'ssh-add.exe' -KeyPath $script:Manifest.private_key_path -ProcessRunner { param($ProcessStartInfo) [pscustomobject]@{ exit_code = 1 } } } | Should -Throw
    }

    It 'builds an owned foreground agent launch boundary with bounded collection' {
        $script:CapturedAgentLaunch = $null
        $script:ExpectedAgentLaunch = [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-windows-agent-launch/v1'
            output = @('SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.77; export SSH_AUTH_SOCK;', 'echo Agent pid 77;')
            started_at_utc = '2026-09-01T12:00:00.0000000Z'
            windows_process_id = 26484
        }
        $actual = Start-P3WindowsAgentProcess -ExecutablePath $script:Paths.'ssh-agent.exe' -ProcessRunner {
            param($ProcessStartInfo, $TimeoutSeconds, $MaximumOutputRecords, $MaximumOutputBytes)
            $script:CapturedAgentLaunch = [pscustomobject]@{ Info = $ProcessStartInfo; TimeoutSeconds = $TimeoutSeconds; MaximumOutputRecords = $MaximumOutputRecords; MaximumOutputBytes = $MaximumOutputBytes }
            $script:ExpectedAgentLaunch
        }

        $actual | Should -Be $script:ExpectedAgentLaunch
        $script:CapturedAgentLaunch.Info.FileName | Should -BeExactly $script:Paths.'ssh-agent.exe'
        $script:CapturedAgentLaunch.Info.Arguments | Should -BeExactly '-D -s'
        $script:CapturedAgentLaunch.Info.UseShellExecute | Should -BeFalse
        $script:CapturedAgentLaunch.Info.CreateNoWindow | Should -BeTrue
        $script:CapturedAgentLaunch.Info.RedirectStandardOutput | Should -BeTrue
        $script:CapturedAgentLaunch.Info.RedirectStandardInput | Should -BeFalse
        $script:CapturedAgentLaunch.Info.RedirectStandardError | Should -BeFalse
        $script:CapturedAgentLaunch.TimeoutSeconds | Should -Be 10
        $script:CapturedAgentLaunch.MaximumOutputRecords | Should -Be 16
        $script:CapturedAgentLaunch.MaximumOutputBytes | Should -Be 65536
    }

    It 'fails terminally when owned native launch cleanup cannot kill the exact process' {
        $process = [pscustomobject]@{ HasExited = $false; KillCalls = 0; WaitCalls = 0 }
        $process | Add-Member -MemberType ScriptMethod -Name Kill -Value { $this.KillCalls++; throw 'synthetic kill failure' }
        $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($Milliseconds) $this.WaitCalls++; $true }

        { Complete-P3OwnedWindowsAgentCleanup -Process $process -Started $true } | Should -Throw '*cleanup*'
        $process.KillCalls | Should -Be 1
        $process.WaitCalls | Should -Be 0
    }

    It 'fails terminally when owned native launch cleanup does not observe process exit' {
        $process = [pscustomobject]@{ HasExited = $false; KillCalls = 0; WaitCalls = 0 }
        $process | Add-Member -MemberType ScriptMethod -Name Kill -Value { $this.KillCalls++ }
        $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($Milliseconds) $this.WaitCalls++; $false }

        { Complete-P3OwnedWindowsAgentCleanup -Process $process -Started $true } | Should -Throw '*cleanup*'
        $process.KillCalls | Should -Be 1
        $process.WaitCalls | Should -Be 1
    }

    It 'derives native launch receipt time from the normalized Windows process start time' {
        $expectedUtc = [DateTime]::SpecifyKind([DateTime]::Parse('2026-09-01T12:00:00'), [DateTimeKind]::Utc)
        $process = [pscustomobject]@{ StartTime = [DateTime]::SpecifyKind($expectedUtc.ToLocalTime(), [DateTimeKind]::Unspecified) }

        (Get-P3WindowsAgentStartedAtUtc -Process $process).ToString('o') | Should -BeExactly $expectedUtc.ToString('o')
    }

    It 'destroys only the newly created agent when ssh-add fails' {
        $script:StoppedPids = @()
        { Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { New-TestAgentLaunch -Output @('SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;', 'echo Agent pid 4242;') } `
            -ProcessRunner { param($ProcessId) [pscustomobject]@{ Id = $ProcessId; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) } } `
            -AddRunner { throw 'synthetic add failure' } `
            -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } } | Should -Throw '*ssh-add*'
        $script:StoppedPids | Should -Be @(26484)
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'stops a uniquely parsed newly created PID when the full agent output is malformed' {
        $script:StoppedPids = @()
        { Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { New-TestAgentLaunch -Output @('unexpected', 'echo Agent pid 4242;') } `
            -ProcessRunner { param($ProcessId) [pscustomobject]@{ Id = $ProcessId; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) } } `
            -AddRunner { throw 'must not add' } `
            -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } } | Should -Throw '*malformed*'
        $script:StoppedPids | Should -Be @(26484)
    }

    It 'stops a uniquely parsed PID from malformed native ssh-agent output records' {
        $script:StoppedPids = @()
        { Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner {
                New-TestAgentLaunch -Output @(
                    'unexpected'
                    'echo Agent pid 4242;'
                )
            } `
            -ProcessRunner { param($ProcessId) [pscustomobject]@{ Id = $ProcessId; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) } } `
            -AddRunner { throw 'must not add' } `
            -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } } | Should -Throw '*malformed*'
        $script:StoppedPids | Should -Be @(26484)
    }

    It 'treats cleanup failure as terminal and never swallows it' {
        { Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { New-TestAgentLaunch -Output @('SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;', 'echo Agent pid 4242;') } `
            -ProcessRunner { param($ProcessId) [pscustomobject]@{ Id = $ProcessId; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) } } `
            -AddRunner { throw 'synthetic add failure' } `
            -StopRunner { throw 'synthetic stop failure' } } | Should -Throw '*cleanup failed*'
    }

    It 'fails closed without PID stop or wait when emergency reobservation throws after earlier validation' {
        $null = Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) } }
        $env:SSH_AUTH_SOCK = $script:AgentReceipt.socket
        $env:SSH_AGENT_PID = [string]$script:AgentReceipt.agent_pid
        $stopCalls = 0
        $waitCalls = 0

        { Stop-P3OwnedAgentEmergency -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -DeleteRunner { throw 'must not delete after missing identity observation' } `
            -StopRunner { $stopCalls++ } `
            -ProcessRunner { throw 'synthetic process reobservation failure' } `
            -WaitRunner { $waitCalls++ } `
            -ReobserveRunner { @() } `
            -SocketExistsRunner { $false } } | Should -Throw '*process identity failure*'

        $stopCalls | Should -Be 0
        $waitCalls | Should -Be 0
    }

    It 'starts validates and stops only the receipt-bound agent' {
        $script:StoppedPids = @()
        $script:LifecyclePids = @()
        $script:Deleted = 0
        $processRunner = {
            param($ProcessId)
            $script:LifecyclePids += $ProcessId
            [pscustomobject]@{ Id = $ProcessId; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow.AddSeconds(-2) }
        }
        $receipt = Start-P3Agent -Manifest $script:Manifest `
            -AgentRunner { New-TestAgentLaunch -Output @('SSH_AUTH_SOCK=/tmp/ssh-synthetic/agent.4242; export SSH_AUTH_SOCK;', 'echo Agent pid 4242;') } `
            -ProcessRunner $processRunner `
            -AddRunner { param($Path) if ($Path -cne $script:Manifest.private_key_path) { throw 'wrong key path' } } `
            -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId }
        $validated = Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $receipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner $processRunner
        $stop = Stop-P3Agent -Manifest $script:Manifest -AgentReceipt $receipt `
            -DeleteRunner { $script:Deleted++ } -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner $processRunner `
            -WaitRunner { param($ProcessId) $script:LifecyclePids += $ProcessId } -ReobserveRunner { param($ProcessId) $script:LifecyclePids += $ProcessId; @() } -SocketExistsRunner { param($Path) $false }
        $validated.expected_key_match | Should -BeTrue
        $stop.stopped | Should -BeTrue
        $script:Deleted | Should -Be 1
        $script:StoppedPids | Should -Be @(26484)
        $script:LifecyclePids | Should -Be @(26484, 26484, 26484, 26484, 26484)
    }

    It 'emergency-cleans the owned agent when normal state validation fails' {
        $script:Deleted = 0
        $script:StoppedPids = @()
        $script:WaitedPids = @()
        $script:ReobservedPids = @()
        $script:ProcessCalls = 0
        $env:SSH_AUTH_SOCK = $script:AgentReceipt.socket
        $env:SSH_AGENT_PID = [string]$script:AgentReceipt.agent_pid
        $processRunner = {
            param($ProcessId)
            $script:ProcessCalls++
            [pscustomobject]@{
                Id = $ProcessId
                Path = $script:Paths.'ssh-agent.exe'
                StartTime = [DateTime]::UtcNow.AddSeconds(-2)
            }
        }

        { Stop-P3Agent -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -DeleteRunner { $script:Deleted++ } `
            -StopRunner { param($ProcessId) $script:StoppedPids += $ProcessId } `
            -ListRunner { throw 'synthetic state validation failure' } `
            -ProcessRunner $processRunner `
            -WaitRunner { param($ProcessId) $script:WaitedPids += $ProcessId } `
            -ReobserveRunner { param($ProcessId) $script:ReobservedPids += $ProcessId; @() } `
            -SocketExistsRunner { $false } } | Should -Throw '*synthetic state validation failure*'

        $script:Deleted | Should -Be 1
        $script:StoppedPids | Should -Be @(26484)
        $script:WaitedPids | Should -Be @(26484)
        $script:ReobservedPids | Should -Be @(26484)
        $script:ProcessCalls | Should -Be 2
        $env:SSH_AUTH_SOCK | Should -BeNullOrEmpty
        $env:SSH_AGENT_PID | Should -BeNullOrEmpty
    }

    It 'rejects a changed receipt before deleting keys or stopping a process' {
        $script:AgentReceipt.socket = '/tmp/changed'
        $calls = 0
        { Stop-P3Agent -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -DeleteRunner { $calls++ } -StopRunner { $calls++ } `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id = 26484; Path = $script:Paths.'ssh-agent.exe'; StartTime = [DateTime]::UtcNow } } } |
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
            -ProcessRunner { [pscustomobject]@{ Id=26484;Path=$script:Paths.'ssh-agent.exe';StartTime=$localStart } } } |
            Should -Throw '*UTC*'

        $script:AgentReceipt.started_at_utc = $receiptUtc.ToString('o')
        $drifted = [DateTime]::SpecifyKind($localStart.AddSeconds(11), [DateTimeKind]::Unspecified)
        { Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:AgentReceipt `
            -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
            -ProcessRunner { [pscustomobject]@{ Id=26484;Path=$script:Paths.'ssh-agent.exe';StartTime=$drifted } } } |
            Should -Throw '*creation window*'
    }
}
