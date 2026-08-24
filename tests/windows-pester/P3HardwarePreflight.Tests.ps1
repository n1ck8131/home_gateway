BeforeAll {
$script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:Preflight = Join-Path $script:Root 'scripts/openwrt/preflight-p3.ps1'
$script:Example = Join-Path $script:Root 'deploy/openwrt/p3-acceptance.example.json'
$script:PwshCommand = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $script:PwshCommand) { $script:PwshCommand = Get-Command powershell -ErrorAction Stop }
$script:Pwsh = $script:PwshCommand.Source

function New-P3Inventory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [bool]$Sanitized = $false,
        [bool]$RecoveryReady = $true,
        [bool]$TunnelExpectedUp = $false,
        [string]$ManagementIPv4 = '192.168.10.1',
        [switch]$UnknownField
    )
    $inventory = [ordered]@{
        schema_version = 1
        sanitized_example = $Sanitized
        router = [ordered]@{
            host = 'router.test'
            ssh_user = 'root'
            board_name = 'glinet,gl-mt6000'
            openwrt_release = '25.12.5'
            openwrt_revision = 'r33051-f5dae5ece4'
            package_arch = 'aarch64_cortex-a53'
            kernel_version = '6.12.94'
            kernel_abi = 'kernel-6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1'
            management_ipv4 = $ManagementIPv4
            wan_device = 'wan'
        }
        vps = [ordered]@{
            endpoint_ipv4 = '8.8.8.8'
            endpoint_port = 51820
            expected_country = 'NL'
        }
        tunnel = [ordered]@{
            interface = 'awg0'
            expected_up = $TunnelExpectedUp
            max_handshake_age_seconds = 180
        }
        recovery = [ordered]@{
            wired_management_verified = $RecoveryReady
            factory_image_verified = $RecoveryReady
            vps_console_verified = $RecoveryReady
        }
    }
    if ($UnknownField) { $inventory.router.unreviewed = 'reject-me' }
    [IO.File]::WriteAllText($Path, ($inventory | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
}

function New-FakeP3SSH {
    param([Parameter(Mandatory)][string]$Directory)
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $utf8 = [Text.UTF8Encoding]::new($false)
    $shim = @'
Add-Content -LiteralPath $env:P3_FAKE_LOG -Value ($args -join [char]31)
$command = $args -join ' '
if ($command -match 'ubus call system board') { '{"board_name":"glinet,gl-mt6000"}'; exit 0 }
if ($command -match 'apk --print-arch') { 'aarch64_cortex-a53'; exit 0 }
if ($command -match 'uname -r') { '6.12.94'; exit 0 }
if ($command -match 'cat /etc/openwrt_release') { "DISTRIB_RELEASE='25.12.5'`nDISTRIB_REVISION='r33051-f5dae5ece4'"; exit 0 }
if ($command -match 'apk info -e kernel-6.12.94') { exit 0 }
if ($command -match 'test -e /tmp/home-gateway-p0') { exit 1 }
if ($command -match 'ip -4 route show table main default') { 'default via 192.168.10.254 dev wan'; exit 0 }
if ($command -match 'ip -4 route get 8.8.8.8') {
    if ($env:P3_FAKE_ENDPOINT_TUNNEL) { '8.8.8.8 dev awg0'; exit 0 }
    '8.8.8.8 via 192.168.10.254 dev wan'; exit 0
}
if ($command -match 'ip -4 route get 192.168.10.1') { '192.168.10.1 dev br-lan'; exit 0 }
if ($command -match 'ip link show dev awg0') {
    if ($env:P3_FAKE_TUNNEL_UP) { '42: awg0: <POINTOPOINT,UP,LOWER_UP>'; exit 0 }
    [Console]::Error.WriteLine('Device awg0 does not exist')
    exit 1
}
if ($command -match 'date \+%s') { if ($env:P3_FAKE_NOW) { $env:P3_FAKE_NOW } else { '200' }; exit 0 }
if ($command -match 'awg show awg0 latest-handshakes') { if ($env:P3_FAKE_HANDSHAKES) { $env:P3_FAKE_HANDSHAKES } else { 'PUBLICKEY 190' }; exit 0 }
if ($command -match 'awg show awg0 endpoints') { if ($env:P3_FAKE_ENDPOINTS) { $env:P3_FAKE_ENDPOINTS } else { 'PUBLICKEY 8.8.8.8:51820' }; exit 0 }
exit 99
'@
    [IO.File]::WriteAllText((Join-Path $Directory 'ssh.ps1'), $shim, $utf8)
    $windows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    if ($windows) {
        $cmd = "@echo off`r`n`"$script:Pwsh`" -NoProfile -File `"%~dp0ssh.ps1`" %*`r`nexit /b %ERRORLEVEL%`r`n"
        [IO.File]::WriteAllText((Join-Path $Directory 'ssh.cmd'), $cmd, [Text.Encoding]::ASCII)
    } else {
        $escapedPwsh = $script:Pwsh.Replace('\', '\\').Replace('"', '\"').Replace('$', '\$').Replace('`', '\`')
        $shell = "#!/bin/sh`nexec `"$escapedPwsh`" -NoProfile -File `"`$(dirname `"`$0`")/ssh.ps1`" `"`$@`"`n"
        $path = Join-Path $Directory 'ssh'
        [IO.File]::WriteAllText($path, $shell, $utf8)
        chmod +x $path
    }
}

function Invoke-P3PreflightChild {
    param(
        [Parameter(Mandatory)][string]$Inventory,
        [Parameter(Mandatory)][string]$KnownHosts,
        [Parameter(Mandatory)][string]$Evidence,
        [switch]$WhatIf
    )
    $arguments = @(
        '-NoProfile', '-File', $script:Preflight,
        '-InventoryFile', $Inventory,
        '-KnownHostsFile', $KnownHosts,
        '-EvidenceDirectory', $Evidence
    )
    if ($WhatIf) { $arguments += '-WhatIf' }
    $priorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $script:Pwsh @arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join [Environment]::NewLine) }
}
}

Describe 'P3 physical read-only preflight' {
    BeforeEach {
        $caseID = [guid]::NewGuid().ToString('N')
        $script:Inventory = Join-Path $TestDrive "p3-acceptance-$caseID.local.json"
        $script:KnownHosts = Join-Path $TestDrive "known_hosts-$caseID"
        [IO.File]::WriteAllText($script:KnownHosts, 'router.test ssh-ed25519 fixture-public-host-key', [Text.Encoding]::ASCII)
        $script:Evidence = Join-Path $TestDrive "evidence-$caseID"
        $script:FakeBin = Join-Path $TestDrive "fake-bin-$caseID"
        $script:Log = Join-Path $TestDrive "ssh-$caseID.log"
    }

    It 'ships a sanitized non-executable example' {
        $example = Get-Content -LiteralPath $script:Example -Raw | ConvertFrom-Json
        $example.schema_version | Should -Be 1
        $example.sanitized_example | Should -BeTrue
        $example.recovery.wired_management_verified | Should -BeFalse
        $example.recovery.factory_image_verified | Should -BeFalse
        $example.recovery.vps_console_verified | Should -BeFalse
    }

    It 'does not resolve SSH or create evidence in WhatIf mode' {
        $emptyPath = Join-Path $TestDrive 'empty-path'
        New-Item -ItemType Directory -Path $emptyPath | Out-Null
        $priorPath = $env:PATH
        try {
            $env:PATH = $emptyPath
            $output = & $script:Pwsh -NoProfile -File $script:Preflight -InventoryFile $script:Example -KnownHostsFile $script:KnownHosts -EvidenceDirectory $script:Evidence -WhatIf 2>&1
            $LASTEXITCODE | Should -Be 0
        } finally {
            $env:PATH = $priorPath
        }
        ($output -join [Environment]::NewLine) | Should -Match 'WHATIF P3 read-only preflight'
        Test-Path -LiteralPath $script:Evidence | Should -BeFalse
    }

    It 'rejects a reparse point in an evidence ancestor before SSH' {
        New-P3Inventory -Path $script:Inventory
        $targetDirectory = Join-Path $TestDrive 'evidence-target'
        $linkedDirectory = Join-Path $TestDrive 'evidence-link'
        New-Item -ItemType Directory -Path $targetDirectory | Out-Null
        try {
            $itemType = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'Junction' } else { 'SymbolicLink' }
            New-Item -ItemType $itemType -Path $linkedDirectory -Target $targetDirectory -ErrorAction Stop | Out-Null
        } catch {
            (Get-Content -LiteralPath $script:Preflight -Raw) | Should -Match 'Assert-NoReparseAncestors'
            return
        }
        $emptyPath = Join-Path $TestDrive 'reparse-no-transport'
        New-Item -ItemType Directory -Path $emptyPath | Out-Null
        $priorPath = $env:PATH
        try {
            $env:PATH = $emptyPath
            $result = Invoke-P3PreflightChild -Inventory $script:Inventory -KnownHosts $script:KnownHosts -Evidence (Join-Path $linkedDirectory 'new-evidence')
        } finally {
            $env:PATH = $priorPath
        }
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'symlink or reparse-point path'
        Test-Path -LiteralPath (Join-Path $targetDirectory 'new-evidence') | Should -BeFalse
    }

    It 'rejects sanitized, unknown, unrecoverable and non-LAN inventory before SSH' {
        foreach ($case in @('sanitized', 'unknown', 'recovery', 'management')) {
            switch ($case) {
                sanitized { Copy-Item -LiteralPath $script:Example -Destination $script:Inventory }
                unknown { New-P3Inventory -Path $script:Inventory -UnknownField }
                recovery { New-P3Inventory -Path $script:Inventory -RecoveryReady:$false }
                management { New-P3Inventory -Path $script:Inventory -ManagementIPv4 '8.8.8.8' }
            }
            $result = Invoke-P3PreflightChild -Inventory $script:Inventory -KnownHosts $script:KnownHosts -Evidence $script:Evidence
            $result.ExitCode | Should -Not -Be 0
            Test-Path -LiteralPath $script:Log | Should -BeFalse
            Remove-Item -LiteralPath $script:Inventory -Force
        }
    }

    It 'uses strict read-only argv calls and writes redacted evidence' {
        New-P3Inventory -Path $script:Inventory
        New-FakeP3SSH -Directory $script:FakeBin
        $priorPath = $env:PATH
        $priorLog = $env:P3_FAKE_LOG
        try {
            $env:PATH = "$script:FakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:P3_FAKE_LOG = $script:Log
            $result = Invoke-P3PreflightChild -Inventory $script:Inventory -KnownHosts $script:KnownHosts -Evidence $script:Evidence
        } finally {
            $env:PATH = $priorPath
            $env:P3_FAKE_LOG = $priorLog
        }
        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'P3_READ_ONLY_PREFLIGHT_PASS'
        $calls = Get-Content -LiteralPath $script:Log -Raw
        $calls | Should -Match 'BatchMode=yes'
        $calls | Should -Match 'StrictHostKeyChecking=yes'
        $calls | Should -Match ([regex]::Escape("UserKnownHostsFile=$((Resolve-Path $script:KnownHosts).Path)"))
        $calls | Should -Match ([regex]::Escape("GlobalKnownHostsFile=$((Resolve-Path $script:KnownHosts).Path)"))
        $calls | Should -Match 'ConnectionAttempts=1'
        $calls | Should -Match 'ServerAliveInterval=5'
        $calls | Should -Match 'ServerAliveCountMax=2'
        $calls | Should -Not -Match '(?i)\bapk add\b|\bapk del\b|\buci\b|\breboot\b|route replace|\bscp\b|sh -s'
        $reportPath = Join-Path $script:Evidence 'p3-read-only-preflight.json'
        $report = Get-Content -LiteralPath $reportPath -Raw
        $report | Should -Not -Match 'router\.test|8\.8\.8\.8|fixture-public-host-key|PUBLICKEY'
        $report | Should -Not -Match ([regex]::Escape((Resolve-Path $script:KnownHosts).Path))
        $parsedReport = $report | ConvertFrom-Json
        $parsedReport.status | Should -Be 'preflight-passed'
        $parsedReport.tool.name | Should -Be 'preflight-p3'
        $parsedReport.tool.version | Should -Be 1
        $parsedReport.tool.script_sha256 | Should -Be (Get-FileHash -LiteralPath $script:Preflight -Algorithm SHA256).Hash.ToLowerInvariant()
        $parsedReport.commitments.inventory_sha256 | Should -Be (Get-FileHash -LiteralPath $script:Inventory -Algorithm SHA256).Hash.ToLowerInvariant()
        $parsedReport.commitments.known_hosts_sha256 | Should -Be (Get-FileHash -LiteralPath $script:KnownHosts -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    It 'validates a fresh single-peer handshake without recording peer material' {
        New-P3Inventory -Path $script:Inventory -TunnelExpectedUp:$true
        New-FakeP3SSH -Directory $script:FakeBin
        $priorPath = $env:PATH
        $priorLog = $env:P3_FAKE_LOG
        $priorTunnel = $env:P3_FAKE_TUNNEL_UP
        try {
            $env:PATH = "$script:FakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:P3_FAKE_LOG = $script:Log
            $env:P3_FAKE_TUNNEL_UP = '1'
            $result = Invoke-P3PreflightChild -Inventory $script:Inventory -KnownHosts $script:KnownHosts -Evidence $script:Evidence
        } finally {
            $env:PATH = $priorPath
            $env:P3_FAKE_LOG = $priorLog
            $env:P3_FAKE_TUNNEL_UP = $priorTunnel
        }
        $result.ExitCode | Should -Be 0 -Because $result.Output
        $report = Get-Content -LiteralPath (Join-Path $script:Evidence 'p3-read-only-preflight.json') -Raw | ConvertFrom-Json
        $report.checks.handshake_fresh | Should -BeTrue
    }

    It 'rejects stale, future, multi-peer, malformed and unapproved handshakes' {
        foreach ($case in @(
            @{ Name = 'stale'; Now = '500'; Handshakes = 'PUBLICKEY 190'; Endpoints = 'PUBLICKEY 8.8.8.8:51820' },
            @{ Name = 'future'; Now = '100'; Handshakes = 'PUBLICKEY 190'; Endpoints = 'PUBLICKEY 8.8.8.8:51820' },
            @{ Name = 'multiple'; Now = '200'; Handshakes = "KEY1 190`nKEY2 190"; Endpoints = 'KEY1 8.8.8.8:51820' },
            @{ Name = 'epoch'; Now = 'not-an-epoch'; Handshakes = 'PUBLICKEY 190'; Endpoints = 'PUBLICKEY 8.8.8.8:51820' },
            @{ Name = 'endpoint'; Now = '200'; Handshakes = 'PUBLICKEY 190'; Endpoints = 'PUBLICKEY 1.1.1.1:51820' }
        )) {
            $inventory = Join-Path $TestDrive "handshake-$($case.Name).json"
            $evidence = Join-Path $TestDrive "handshake-$($case.Name)-evidence"
            $fakeBin = Join-Path $TestDrive "handshake-$($case.Name)-bin"
            $log = Join-Path $TestDrive "handshake-$($case.Name).log"
            New-P3Inventory -Path $inventory -TunnelExpectedUp:$true
            New-FakeP3SSH -Directory $fakeBin
            $priorPath = $env:PATH
            $priorLog = $env:P3_FAKE_LOG
            $priorTunnel = $env:P3_FAKE_TUNNEL_UP
            $priorNow = $env:P3_FAKE_NOW
            $priorHandshakes = $env:P3_FAKE_HANDSHAKES
            $priorEndpoints = $env:P3_FAKE_ENDPOINTS
            try {
                $env:PATH = "$fakeBin$([IO.Path]::PathSeparator)$priorPath"
                $env:P3_FAKE_LOG = $log
                $env:P3_FAKE_TUNNEL_UP = '1'
                $env:P3_FAKE_NOW = $case.Now
                $env:P3_FAKE_HANDSHAKES = $case.Handshakes
                $env:P3_FAKE_ENDPOINTS = $case.Endpoints
                $result = Invoke-P3PreflightChild -Inventory $inventory -KnownHosts $script:KnownHosts -Evidence $evidence
            } finally {
                $env:PATH = $priorPath
                $env:P3_FAKE_LOG = $priorLog
                $env:P3_FAKE_TUNNEL_UP = $priorTunnel
                $env:P3_FAKE_NOW = $priorNow
                $env:P3_FAKE_HANDSHAKES = $priorHandshakes
                $env:P3_FAKE_ENDPOINTS = $priorEndpoints
            }
            $result.ExitCode | Should -Not -Be 0 -Because $case.Name
            Test-Path -LiteralPath (Join-Path $evidence 'p3-read-only-preflight.json') | Should -BeFalse
        }
    }

    It 'rejects an unexpected pre-existing tunnel interface' {
        New-P3Inventory -Path $script:Inventory
        New-FakeP3SSH -Directory $script:FakeBin
        $priorPath = $env:PATH
        $priorLog = $env:P3_FAKE_LOG
        $priorTunnel = $env:P3_FAKE_TUNNEL_UP
        try {
            $env:PATH = "$script:FakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:P3_FAKE_LOG = $script:Log
            $env:P3_FAKE_TUNNEL_UP = '1'
            $result = Invoke-P3PreflightChild -Inventory $script:Inventory -KnownHosts $script:KnownHosts -Evidence $script:Evidence
        } finally {
            $env:PATH = $priorPath
            $env:P3_FAKE_LOG = $priorLog
            $env:P3_FAKE_TUNNEL_UP = $priorTunnel
        }
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'unexpected AWG tunnel interface'
        Test-Path -LiteralPath (Join-Path $script:Evidence 'p3-read-only-preflight.json') | Should -BeFalse
    }

    It 'fails when the approved VPS endpoint would use the tunnel' {
        New-P3Inventory -Path $script:Inventory
        New-FakeP3SSH -Directory $script:FakeBin
        $priorPath = $env:PATH
        $priorLog = $env:P3_FAKE_LOG
        $priorFault = $env:P3_FAKE_ENDPOINT_TUNNEL
        try {
            $env:PATH = "$script:FakeBin$([IO.Path]::PathSeparator)$priorPath"
            $env:P3_FAKE_LOG = $script:Log
            $env:P3_FAKE_ENDPOINT_TUNNEL = '1'
            $result = Invoke-P3PreflightChild -Inventory $script:Inventory -KnownHosts $script:KnownHosts -Evidence $script:Evidence
        } finally {
            $env:PATH = $priorPath
            $env:P3_FAKE_LOG = $priorLog
            $env:P3_FAKE_ENDPOINT_TUNNEL = $priorFault
        }
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'endpoint route does not remain on WAN'
        Test-Path -LiteralPath (Join-Path $script:Evidence 'p3-read-only-preflight.json') | Should -BeFalse
    }
}
