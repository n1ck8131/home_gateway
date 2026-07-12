BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:WrapperPath = Join-Path $script:Root 'scripts/openwrt/smoke-awg2.ps1'
    $script:RemotePath = Join-Path $script:Root 'scripts/openwrt/smoke-awg2-remote.sh'
    $script:Wrapper = Get-Content -LiteralPath $script:WrapperPath -Raw
    $script:Remote = Get-Content -LiteralPath $script:RemotePath -Raw
    $script:Pwsh = (Get-Process -Id $PID).Path
}

Describe 'rollback-safe AWG2 hardware smoke' {
    BeforeEach {
        $script:KnownHosts = Join-Path $TestDrive 'known_hosts'
        $script:Packages = Join-Path $TestDrive 'packages'
        New-Item -ItemType File -Force $script:KnownHosts | Out-Null
        New-Item -ItemType Directory -Force $script:Packages | Out-Null
    }

    It 'requires safe connection and recovery parameters' {
        $stderr = Join-Path $TestDrive 'invalid-host.stderr'
        $process = Start-Process -FilePath $script:Pwsh -ArgumentList @(
            '-NoProfile', '-File', $script:WrapperPath, '-RouterHost', 'router;reboot',
            '-KnownHostsFile', $script:KnownHosts, '-Recover', '-RecoveryToken', ('a' * 32)
        ) -RedirectStandardError $stderr -Wait -PassThru
        $process.ExitCode | Should -Not -Be 0
        $stderr = Join-Path $TestDrive 'invalid-token.stderr'
        $process = Start-Process -FilePath $script:Pwsh -ArgumentList @(
            '-NoProfile', '-File', $script:WrapperPath, '-RouterHost', 'router',
            '-KnownHostsFile', $script:KnownHosts, '-Recover', '-RecoveryToken', 'short'
        ) -RedirectStandardError $stderr -Wait -PassThru
        $process.ExitCode | Should -Not -Be 0
    }

    It 'does not resolve or invoke SSH in WhatIf mode' {
        $emptyPath = Join-Path $TestDrive 'empty-path'
        New-Item -ItemType Directory $emptyPath | Out-Null
        $priorPath = $env:PATH
        try {
            $env:PATH = $emptyPath
            $output = & $script:Pwsh -NoProfile -File $script:WrapperPath -RouterHost 192.0.2.1 -PackageDirectory $script:Packages -KnownHostsFile $script:KnownHosts -WhatIf 2>&1
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
        @'
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
exit 99
'@ | Set-Content -LiteralPath (Join-Path $fakeBin 'ssh.ps1') -Encoding UTF8
        @'
Add-Content -LiteralPath $env:AWG_FAKE_LOG -Value ('SCP' + [char]31 + ($args -join [char]31))
exit 0
'@ | Set-Content -LiteralPath (Join-Path $fakeBin 'scp.ps1') -Encoding UTF8
        $kmod = Join-Path $script:Packages 'kmod-amneziawg-fixture.apk'
        $tools = Join-Path $script:Packages 'amneziawg-tools-fixture.apk'
        Set-Content -LiteralPath $kmod -Value 'kmod fixture' -NoNewline
        Set-Content -LiteralPath $tools -Value 'tools fixture' -NoNewline
        @(
            "$((Get-FileHash $kmod -Algorithm SHA256).Hash.ToLowerInvariant())  $(Split-Path $kmod -Leaf)"
            "$((Get-FileHash $tools -Algorithm SHA256).Hash.ToLowerInvariant())  $(Split-Path $tools -Leaf)"
        ) | Set-Content -LiteralPath (Join-Path $script:Packages 'SHA256SUMS') -Encoding ASCII
        @(
            'kernel_version=6.12.94'
            'kernel_vermagic=5a6c1f71be683ae9980b15d3ce73e24d'
            'package_architecture=aarch64_cortex-a53'
        ) | Set-Content -LiteralPath (Join-Path $script:Packages 'build-metadata.txt') -Encoding ASCII
        $stdout = Join-Path $TestDrive 'preflight.stdout'
        $stderr = Join-Path $TestDrive 'preflight.stderr'
        $priorPath = $env:PATH
        $priorLog = $env:AWG_FAKE_LOG
        try {
            $env:PATH = "$fakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:AWG_FAKE_LOG = $log
            $process = Start-Process -FilePath $script:Pwsh -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:WrapperPath,
                '-RouterHost', 'router.test', '-PackageDirectory', $script:Packages,
                '-KnownHostsFile', $script:KnownHosts
            ) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
        } finally {
            $env:PATH = $priorPath
            $env:AWG_FAKE_LOG = $priorLog
        }
        $process.ExitCode | Should -Be 0 -Because (Get-Content -LiteralPath $stderr -Raw)
        Get-Content -LiteralPath $stdout -Raw | Should -Match 'AWG2_PREFLIGHT_PASS'
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
        $script:Wrapper | Should -Match '-Recover -RecoveryToken \$Nonce'
    }

    It 'contains no persistent network or secret mutation' {
        "$script:Wrapper`n$script:Remote" | Should -Not -Match '(?i)firmware|sysupgrade|\buci\b|/etc/config/network|\bwan\b|firewall|\bdns\b|password'
    }
}
