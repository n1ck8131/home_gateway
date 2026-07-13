BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:WrapperPath = Join-Path $script:Root 'scripts/openwrt/smoke-awg2.ps1'
    $script:RemotePath = Join-Path $script:Root 'scripts/openwrt/smoke-awg2-remote.sh'
    $script:Wrapper = Get-Content -LiteralPath $script:WrapperPath -Raw
    $script:Remote = Get-Content -LiteralPath $script:RemotePath -Raw
    $currentPowerShell = (Get-Process -Id $PID -ErrorAction SilentlyContinue).Path
    if ($currentPowerShell -and (Test-Path -LiteralPath $currentPowerShell -PathType Leaf)) {
        $script:Pwsh = $currentPowerShell
    } else {
        $pwshCommand = Get-Command -Name pwsh -CommandType Application -ErrorAction SilentlyContinue
        if ($pwshCommand) {
            $script:Pwsh = $pwshCommand.Source
        } else {
            $script:Pwsh = (Get-Command -Name powershell.exe -CommandType Application -ErrorAction Stop).Source
        }
    }

$script:NewIsolatedSmokeFixture = {
    param([Parameter(Mandatory)][string]$Root)

    $repo = Join-Path $Root 'repo'
    $scriptDirectory = Join-Path $repo 'scripts/openwrt'
    $manifestDirectory = Join-Path $repo 'manifest'
    $packages = Join-Path $Root 'packages'
    New-Item -ItemType Directory -Force $scriptDirectory, $manifestDirectory, $packages | Out-Null
    $wrapper = Join-Path $scriptDirectory 'smoke-awg2.ps1'
    Copy-Item -LiteralPath $script:WrapperPath -Destination $wrapper
    Copy-Item -LiteralPath $script:RemotePath -Destination (Join-Path $scriptDirectory 'smoke-awg2-remote.sh')

    $kmodName = 'kmod-amneziawg-6.12.94.1.0.20260611-r1.apk'
    $toolsName = 'amneziawg-tools-1.0.20260618.2-r1.apk'
    $kmod = Join-Path $packages $kmodName
    $tools = Join-Path $packages $toolsName
    Set-Content -LiteralPath $kmod -Value 'kmod fixture' -NoNewline
    Set-Content -LiteralPath $tools -Value 'tools fixture' -NoNewline
    $kmodHash = (Get-FileHash -LiteralPath $kmod -Algorithm SHA256).Hash.ToLowerInvariant()
    $toolsHash = (Get-FileHash -LiteralPath $tools -Algorithm SHA256).Hash.ToLowerInvariant()
    @(
        "$kmodHash  $kmodName"
        "$toolsHash  $toolsName"
    ) | Set-Content -LiteralPath (Join-Path $packages 'SHA256SUMS') -Encoding ASCII
    @(
        'kernel_version=6.12.94'
        'kernel_vermagic=5a6c1f71be683ae9980b15d3ce73e24d'
        'package_architecture=aarch64_cortex-a53'
    ) | Set-Content -LiteralPath (Join-Path $packages 'build-metadata.txt') -Encoding ASCII
    @"
{
  "amneziawg": {
    "verified_openwrt_packages": {
      "kmod": { "filename": "$kmodName", "sha256": "$kmodHash" },
      "tools": { "filename": "$toolsName", "sha256": "$toolsHash" }
    }
  }
}
"@ | Set-Content -LiteralPath (Join-Path $manifestDirectory 'versions.lock.yaml') -Encoding UTF8

    return [pscustomobject]@{
        Wrapper = $wrapper
        Packages = $packages
        Kmod = $kmod
        Tools = $tools
    }
}

$script:NewFakeAwgTransport = {
    param([Parameter(Mandatory)][string]$Directory)

    New-Item -ItemType Directory -Force $Directory | Out-Null
    $isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    $pwshForCmd = $script:Pwsh.Replace('%', '%%')
    $pwshForShell = $script:Pwsh.Replace('\', '\\').Replace('"', '\"').Replace('$', '\$').Replace('`', '\`')
    @'
begin {
}
process {
}
end {
    $line = 'SSH' + [char]31 + ($args -join [char]31)
    Add-Content -LiteralPath $env:AWG_FAKE_LOG -Value $line
    $command = $args -join ' '
    if ($command -match 'ubus call system board') { '{"board_name":"glinet,gl-mt6000"}'; exit 0 }
    if ($command -match 'apk --print-arch') { 'aarch64_cortex-a53'; exit 0 }
    if ($command -match 'uname -r') { '6.12.94'; exit 0 }
    if ($command -match '/etc/openwrt_release') { "DISTRIB_RELEASE='25.12.5'"; exit 0 }
    if ($command -match 'apk list -I') { 'kernel-6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1 installed'; exit 0 }
    if ($command -match 'apk info -e') { exit 1 }
    if ($command -match 'lsmod') { 'Module Size Used by'; exit 0 }
    if ($command -match 'ip link show awg-p0') { exit 1 }
    if ($command -match 'test -e /tmp/home-gateway-p0') { exit 1 }
    if ($args -contains 'sh' -and $args -contains '-s' -and $args -contains '--') {
        $separatorIndex = [array]::IndexOf($args, '--')
        $mode = $args[$separatorIndex + 1]
        if ($mode -eq 'smoke' -and $env:AWG_FAKE_SMOKE_EXIT) { exit [int]$env:AWG_FAKE_SMOKE_EXIT }
        if ($mode -eq 'cleanup' -and $env:AWG_FAKE_CLEANUP_EXIT) { exit [int]$env:AWG_FAKE_CLEANUP_EXIT }
        exit 0
    }
    exit 99
}
'@ | Set-Content -LiteralPath (Join-Path $Directory 'ssh.ps1') -Encoding UTF8
    if ($isWindowsHost) {
        @"
@echo off
"$pwshForCmd" -NoProfile -ExecutionPolicy Bypass -File "%~dp0ssh.ps1" %*
exit /b %ERRORLEVEL%
"@ | Set-Content -LiteralPath (Join-Path $Directory 'ssh.cmd') -Encoding ASCII
    } else {
        @"
#!/bin/sh
exec "$pwshForShell" -NoProfile -ExecutionPolicy Bypass -File "`$(dirname "`$0")/ssh.ps1" "`$@"
"@ | Set-Content -LiteralPath (Join-Path $Directory 'ssh') -Encoding UTF8
        chmod +x (Join-Path $Directory 'ssh')
    }
    @'
Add-Content -LiteralPath $env:AWG_FAKE_LOG -Value ('SCP' + [char]31 + ($args -join [char]31))
if ($env:AWG_FAKE_SCP_EXIT) { exit [int]$env:AWG_FAKE_SCP_EXIT }
exit 0
'@ | Set-Content -LiteralPath (Join-Path $Directory 'scp.ps1') -Encoding UTF8
    if ($isWindowsHost) {
        @"
@echo off
"$pwshForCmd" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scp.ps1" %*
exit /b %ERRORLEVEL%
"@ | Set-Content -LiteralPath (Join-Path $Directory 'scp.cmd') -Encoding ASCII
    } else {
        @"
#!/bin/sh
exec "$pwshForShell" -NoProfile -ExecutionPolicy Bypass -File "`$(dirname "`$0")/scp.ps1" "`$@"
"@ | Set-Content -LiteralPath (Join-Path $Directory 'scp') -Encoding UTF8
        chmod +x (Join-Path $Directory 'scp')
    }
}

$script:ConvertToPowerShellSingleQuotedLiteral = {
    param([Parameter(Mandatory)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

$script:NewConfirmInstallCommand = {
    param(
        [Parameter(Mandatory)][string]$Wrapper,
        [Parameter(Mandatory)][string]$Packages,
        [Parameter(Mandatory)][string]$KnownHosts
    )
    $quotedWrapper = & $script:ConvertToPowerShellSingleQuotedLiteral -Value $Wrapper
    $quotedPackages = & $script:ConvertToPowerShellSingleQuotedLiteral -Value $Packages
    $quotedKnownHosts = & $script:ConvertToPowerShellSingleQuotedLiteral -Value $KnownHosts
    return "& $quotedWrapper -RouterHost 'router.test' -PackageDirectory $quotedPackages -KnownHostsFile $quotedKnownHosts -ConfirmInstall -Confirm:`$false"
}

$script:InvokeChildPowerShell = {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Stdout,
        [Parameter(Mandatory)][string]$Stderr
    )
    $priorErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $script:Pwsh @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorErrorActionPreference
    }
    $text = $output -join [Environment]::NewLine
    Set-Content -LiteralPath $Stdout -Value $text -Encoding UTF8
    Set-Content -LiteralPath $Stderr -Value $text -Encoding UTF8
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $text }
}

}

Describe 'rollback-safe AWG2 hardware smoke' {
    BeforeEach {
        $script:KnownHosts = Join-Path $TestDrive 'known_hosts'
        New-Item -ItemType File -Force $script:KnownHosts | Out-Null
        $script:Fixture = & $script:NewIsolatedSmokeFixture -Root $TestDrive
        $script:Packages = $script:Fixture.Packages
        $script:TestWrapperPath = $script:Fixture.Wrapper
    }

    It 'requires safe connection and recovery parameters' {
        $stdout = Join-Path $TestDrive 'invalid-host.stdout'
        $stderr = Join-Path $TestDrive 'invalid-host.stderr'
        $process = & $script:InvokeChildPowerShell -Arguments @(
            '-NoProfile', '-File', $script:WrapperPath, '-RouterHost', 'router;reboot',
            '-KnownHostsFile', $script:KnownHosts, '-Recover', '-RecoveryToken', ('a' * 32)
        ) -Stdout $stdout -Stderr $stderr
        $process.ExitCode | Should -Not -Be 0
        $stdout = Join-Path $TestDrive 'invalid-token.stdout'
        $stderr = Join-Path $TestDrive 'invalid-token.stderr'
        $process = & $script:InvokeChildPowerShell -Arguments @(
            '-NoProfile', '-File', $script:WrapperPath, '-RouterHost', 'router',
            '-KnownHostsFile', $script:KnownHosts, '-Recover', '-RecoveryToken', 'short'
        ) -Stdout $stdout -Stderr $stderr
        $process.ExitCode | Should -Not -Be 0
    }

    It 'does not resolve or invoke SSH in WhatIf mode' {
        $emptyPath = Join-Path $TestDrive 'empty-path'
        New-Item -ItemType Directory $emptyPath | Out-Null
        $priorPath = $env:PATH
        try {
            $env:PATH = $emptyPath
            $output = & $script:Pwsh -NoProfile -File $script:TestWrapperPath -RouterHost 192.0.2.1 -PackageDirectory $script:Packages -KnownHostsFile $script:KnownHosts -WhatIf 2>&1
            $LASTEXITCODE | Should -Be 0
            ($output -join [Environment]::NewLine) | Should -Match 'WHATIF read-only preflight'
        } finally {
            $env:PATH = $priorPath
        }
    }

    It 'runs only a strict read-only preflight without ConfirmInstall' {
        $fakeBin = Join-Path $TestDrive 'fake-bin'
        $log = Join-Path $TestDrive 'transport.log'
        New-Item -ItemType Directory $fakeBin | Out-Null
        & $script:NewFakeAwgTransport -Directory $fakeBin
        $stdout = Join-Path $TestDrive 'preflight.stdout'
        $stderr = Join-Path $TestDrive 'preflight.stderr'
        $priorPath = $env:PATH
        $priorLog = $env:AWG_FAKE_LOG
        try {
            $env:PATH = "$fakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:AWG_FAKE_LOG = $log
            $process = & $script:InvokeChildPowerShell -Arguments @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:TestWrapperPath,
                '-RouterHost', 'router.test', '-PackageDirectory', $script:Packages,
                '-KnownHostsFile', $script:KnownHosts
            ) -Stdout $stdout -Stderr $stderr
        } finally {
            $env:PATH = $priorPath
            $env:AWG_FAKE_LOG = $priorLog
        }
        $process.ExitCode | Should -Be 0 -Because $process.Output
        $process.Output | Should -Match 'AWG2_PREFLIGHT_PASS'
        $calls = @(Get-Content -LiteralPath $log)
        $calls.Count | Should -BeGreaterThan 0
        foreach ($call in $calls) {
            $call | Should -Match '^SSH'
            $call | Should -Match 'BatchMode=yes'
            $call | Should -Match 'StrictHostKeyChecking=yes'
            $call | Should -Match ([regex]::Escape("UserKnownHostsFile=$((Resolve-Path $script:KnownHosts).Path)"))
            $call | Should -Match 'ConnectTimeout=10'
        }
        $calls | Should -Not -Match '^SCP'
        $calls | Should -Not -Match 'sh.*-s.*--'
    }

    It 'completes ConfirmInstall through prepare, copy and remote smoke' {
        $fakeBin = Join-Path $TestDrive 'fake-success'
        $log = Join-Path $TestDrive 'success.log'
        $stdout = Join-Path $TestDrive 'success.stdout'
        $stderr = Join-Path $TestDrive 'success.stderr'
        & $script:NewFakeAwgTransport -Directory $fakeBin
        $priorPath = $env:PATH
        $priorLog = $env:AWG_FAKE_LOG
        try {
            $env:PATH = "$fakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:AWG_FAKE_LOG = $log
            $command = & $script:NewConfirmInstallCommand -Wrapper $script:TestWrapperPath -Packages $script:Packages -KnownHosts $script:KnownHosts
            $process = & $script:InvokeChildPowerShell -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $command) -Stdout $stdout -Stderr $stderr
        } finally {
            $env:PATH = $priorPath
            $env:AWG_FAKE_LOG = $priorLog
        }
        $process.ExitCode | Should -Be 0 -Because $process.Output
        $process.Output | Should -Match 'AWG2_HARDWARE_SMOKE_PASS'
        $calls = Get-Content -LiteralPath $log -Raw
        $calls | Should -Match 'sh.*-s.*--.*prepare'
        $calls | Should -Match '(?m)^SCP'
        $calls | Should -Match 'sh.*-s.*--.*smoke'
        $calls | Should -Not -Match 'sh.*-s.*--.*cleanup'
    }

    It 'runs cleanup after scp failure' {
        $fakeBin = Join-Path $TestDrive 'fake-scp-failure'
        $log = Join-Path $TestDrive 'scp-failure.log'
        $stdout = Join-Path $TestDrive 'scp-failure.stdout'
        $stderr = Join-Path $TestDrive 'scp-failure.stderr'
        & $script:NewFakeAwgTransport -Directory $fakeBin
        $priorPath = $env:PATH
        $priorLog = $env:AWG_FAKE_LOG
        $priorScpExit = $env:AWG_FAKE_SCP_EXIT
        try {
            $env:PATH = "$fakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:AWG_FAKE_LOG = $log
            $env:AWG_FAKE_SCP_EXIT = '17'
            $command = & $script:NewConfirmInstallCommand -Wrapper $script:TestWrapperPath -Packages $script:Packages -KnownHosts $script:KnownHosts
            $process = & $script:InvokeChildPowerShell -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $command) -Stdout $stdout -Stderr $stderr
        } finally {
            $env:PATH = $priorPath
            $env:AWG_FAKE_LOG = $priorLog
            $env:AWG_FAKE_SCP_EXIT = $priorScpExit
        }
        $process.ExitCode | Should -Not -Be 0
        $calls = Get-Content -LiteralPath $log -Raw
        $calls | Should -Match '(?m)^SCP'
        $calls | Should -Match 'sh.*-s.*--.*cleanup'
        $calls | Should -Not -Match 'sh.*-s.*--.*smoke'
    }

    It 'runs cleanup after remote smoke failure' {
        $fakeBin = Join-Path $TestDrive 'fake-smoke-failure'
        $log = Join-Path $TestDrive 'smoke-failure.log'
        $stdout = Join-Path $TestDrive 'smoke-failure.stdout'
        $stderr = Join-Path $TestDrive 'smoke-failure.stderr'
        & $script:NewFakeAwgTransport -Directory $fakeBin
        $priorPath = $env:PATH
        $priorLog = $env:AWG_FAKE_LOG
        $priorSmokeExit = $env:AWG_FAKE_SMOKE_EXIT
        try {
            $env:PATH = "$fakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:AWG_FAKE_LOG = $log
            $env:AWG_FAKE_SMOKE_EXIT = '23'
            $command = & $script:NewConfirmInstallCommand -Wrapper $script:TestWrapperPath -Packages $script:Packages -KnownHosts $script:KnownHosts
            $process = & $script:InvokeChildPowerShell -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $command) -Stdout $stdout -Stderr $stderr
        } finally {
            $env:PATH = $priorPath
            $env:AWG_FAKE_LOG = $priorLog
            $env:AWG_FAKE_SMOKE_EXIT = $priorSmokeExit
        }
        $process.ExitCode | Should -Not -Be 0
        $calls = Get-Content -LiteralPath $log -Raw
        $calls | Should -Match 'sh.*-s.*--.*smoke'
        $calls | Should -Match 'sh.*-s.*--.*cleanup'
    }

    It 'emits a single-quoted recovery command for metacharacter paths' {
        $fakeBin = Join-Path $TestDrive 'fake-cleanup-failure'
        $log = Join-Path $TestDrive 'cleanup-failure.log'
        $stdout = Join-Path $TestDrive 'cleanup-failure.stdout'
        $stderr = Join-Path $TestDrive 'cleanup-failure.stderr'
        $weirdKnownHosts = Join-Path $TestDrive 'known`$()''hosts'
        New-Item -ItemType File -Force $weirdKnownHosts | Out-Null
        & $script:NewFakeAwgTransport -Directory $fakeBin
        $priorPath = $env:PATH
        $priorLog = $env:AWG_FAKE_LOG
        $priorScpExit = $env:AWG_FAKE_SCP_EXIT
        $priorCleanupExit = $env:AWG_FAKE_CLEANUP_EXIT
        try {
            $env:PATH = "$fakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:AWG_FAKE_LOG = $log
            $env:AWG_FAKE_SCP_EXIT = '17'
            $env:AWG_FAKE_CLEANUP_EXIT = '44'
            $command = & $script:NewConfirmInstallCommand -Wrapper $script:TestWrapperPath -Packages $script:Packages -KnownHosts $weirdKnownHosts
            $process = & $script:InvokeChildPowerShell -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $command) -Stdout $stdout -Stderr $stderr
        } finally {
            $env:PATH = $priorPath
            $env:AWG_FAKE_LOG = $priorLog
            $env:AWG_FAKE_SCP_EXIT = $priorScpExit
            $env:AWG_FAKE_CLEANUP_EXIT = $priorCleanupExit
        }
        $process.ExitCode | Should -Not -Be 0
        $resolved = (Resolve-Path -LiteralPath $weirdKnownHosts).Path
        $escapedLeaf = (Split-Path -Leaf $resolved).Replace("'", "''")
        $unescapedLeaf = Split-Path -Leaf $resolved
        $errorText = $process.Output
        $errorText.Contains($escapedLeaf) | Should -BeTrue
        $errorText.Contains($unescapedLeaf) | Should -BeFalse
    }

    It 'rejects a package that differs from the trusted lock before SSH' {
        Add-Content -LiteralPath $script:Fixture.Kmod -Value 'tampered'
        $fakeBin = Join-Path $TestDrive 'fake-trust-failure'
        $log = Join-Path $TestDrive 'trust-failure.log'
        $stdout = Join-Path $TestDrive 'trust-failure.stdout'
        $stderr = Join-Path $TestDrive 'trust-failure.stderr'
        & $script:NewFakeAwgTransport -Directory $fakeBin
        $priorPath = $env:PATH
        $priorLog = $env:AWG_FAKE_LOG
        try {
            $env:PATH = "$fakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:AWG_FAKE_LOG = $log
            $process = & $script:InvokeChildPowerShell -Arguments @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:TestWrapperPath,
                '-RouterHost', 'router.test', '-PackageDirectory', $script:Packages,
                '-KnownHostsFile', $script:KnownHosts
            ) -Stdout $stdout -Stderr $stderr
        } finally {
            $env:PATH = $priorPath
            $env:AWG_FAKE_LOG = $priorLog
        }
        $process.ExitCode | Should -Not -Be 0
        Test-Path -LiteralPath $log | Should -BeFalse
        $process.Output | Should -Match 'Trusted SHA256 mismatch'
    }

    It 'hardens every transport call and gates mutation' {
        $script:Wrapper | Should -Match "BatchMode=yes"
        $script:Wrapper | Should -Match "StrictHostKeyChecking=yes"
        $script:Wrapper | Should -Match 'UserKnownHostsFile=\$knownHosts'
        $script:Wrapper | Should -Match "ConnectTimeout=10"
        $script:Wrapper | Should -Match 'if \(-not \$ConfirmInstall\)'
        $script:Wrapper | Should -Match '\$PSCmdlet\.ShouldProcess'
        $script:Wrapper | Should -Match 'finally'
        $script:Wrapper | Should -Not -Match 'Invoke-Expression|cmd /c|StrictHostKeyChecking=no'
    }

    It 'uses the exact AWG parser vector and protects the in-memory key' {
        foreach ($value in @("'<r 2>'", "'<r 3>'", "'<rd 4>'", "'<rc 4>'", "'<b 0x0102>'")) {
            $script:Remote | Should -Match ([regex]::Escape($value))
        }
        $script:Remote | Should -Match 'awg genkey \| awg set awg-p0 private-key /dev/stdin'
        $script:Remote | Should -Not -Match '(?i)private[-_ ]?key\s*='
    }

    It 'limits cleanup to nonce-owned temporary state' {
        $script:Remote | Should -Match 'stored_nonce.*=.*nonce'
        $script:Remote | Should -Match 'created_interface'
        $script:Remote | Should -Match 'created_module'
        $script:Remote | Should -Match 'created_kmod'
        $script:Remote | Should -Match 'created_tools'
        $script:Remote | Should -Match 'test "\$work" = /tmp/home-gateway-p0'
        $script:Wrapper | Should -Match '-Recover -RecoveryToken \$quotedNonce'
    }

    It 'contains no persistent network or secret mutation' {
        "$script:Wrapper`n$script:Remote" | Should -Not -Match '(?i)firmware|sysupgrade|\buci\b|/etc/config/network|\bwan\b|firewall|\bdns\b|password'
    }
}
