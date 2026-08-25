BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Bootstrap = Join-Path $script:Root 'scripts/p35-bootstrap-elevated.ps1'
    $script:Driver = Join-Path $script:Root 'scripts/p35-bootstrap.ps1'
}

Describe 'scripts/p35-bootstrap-elevated.ps1' {
    It 'parses and is pinned to trusted Windows PowerShell EncodedCommand execution' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Bootstrap, [ref]$tokens, [ref]$parseErrors)

        $parseErrors | Should -BeNullOrEmpty
        $text = $ast.Extent.Text
        $text | Should -Match '\$PSCommandPath'
        $text | Should -Match 'pinned EncodedCommand payload'
        $text | Should -Match "PSEdition -cne 'Desktop'"
        $text | Should -Match 'PSVersion\.Major -ne 5'
        $text | Should -Match "System32', 'WindowsPowerShell', 'v1\.0"
        $text | Should -Match 'WindowsBuiltInRole\]::Administrator'
        $text | Should -Match 'P35-BOOTSTRAP-FILESYSTEM-V1'
    }

    It 'accepts only the exact bounded hash-pinned request schema' {
        $text = Get-Content -LiteralPath $script:Bootstrap -Raw

        $text | Should -Match "expectedProperties = @\('version', 'action', 'confirmation', 'caller_sid', 'config_path', 'config_sha256'\)"
        $text | Should -Match "expectedProperties \+= @\('launcher_path', 'launcher_sha256', 'hgctl_path', 'hgctl_sha256'\)"
        $text | Should -Match 'Compare-Object'
        $text | Should -Match '65536'
        $text | Should -Match "\^\[0-9a-f\]\{64\}\$"
        $text | Should -Match 'Get-StreamSHA256'
        $text | Should -Match 'FileShare\]::None'
    }

    It 'creates only protected ProgramData artifacts and preserves the source ACL for rollback' {
        $text = Get-Content -LiteralPath $script:Bootstrap -Raw

        $text | Should -Match 'CommonApplicationData'
        $text | Should -Match 'DirectorySecurity\]::new\(\)'
        $text | Should -Match 'CreateDirectory\(\$staging, \(New-ProtectedDirectorySecurity\)\)'
        $text | Should -Match 'SetAccessRuleProtection\(\$true, \$false\)'
        $text | Should -Match 'S-1-5-18'
        $text | Should -Match 'S-1-5-32-544'
        $text | Should -Match 'FileMode\]::CreateNew'
        $text | Should -Match 'Flush\(\$true\)'
        $text | Should -Match 'config-source-before\.v1\.json'
        $text | Should -Match 'config_path'
        $text | Should -Match 'config_sha256'
        $text | Should -Match 'volume_serial'
        $text | Should -Match 'file_index'
        $text | Should -Match 'GetSecurityDescriptorSddlForm'
        $text | Should -Match 'SetSecurityDescriptorSddlForm'
        $text | Should -Match 'Restore-ConfigSourceACL'
        $text | Should -Match 'CreateFileW'
        $text | Should -Match 'OpenConfigSecurityFile'
        $text | Should -Match 'OpenReparsePoint'
        $text | Should -Match '\$stream\.SetAccessControl\(\$security\)'
        $text | Should -Match '\$stream\.GetAccessControl\(\)'
        $text | Should -Not -Match '\[IO\.FileInfo\].*\.SetAccessControl'
        $text | Should -Match 'Ensure-OwnedProtectedDirectory'
        $text | Should -Match 'p35-next-'
        $text | Should -Match 'ReadAndExecute'
        $text | Should -Match 'FullControl'
    }

    It 'copies the approved config from one exclusive handle without disclosure or network mutation' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Bootstrap, [ref]$tokens, [ref]$parseErrors)
        $commands = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true))
        $names = @($commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $text = $ast.Extent.Text

        $parseErrors | Should -BeNullOrEmpty
        @($names | Where-Object { $_ -match '(?i)(NetRoute|NetFirewall|DnsClient|NetAdapter|VpnConnection|ScheduledTask|New-Service|Set-Service|netsh|route\.exe|sc\.exe)' }) | Should -BeNullOrEmpty
        @($names | Where-Object { $_ -in @('Start-Process', 'Invoke-Expression', 'Get-Content', 'Set-Content', 'Add-Content', 'Out-File', 'Invoke-WebRequest', 'Invoke-RestMethod') }) | Should -BeNullOrEmpty
        $text | Should -Match 'Install-PinnedConfig\s+-Source\s+\$configSource'
        $text | Should -Match "secrets, 'redshield\.conf'"
        $text | Should -Match "secrets, 'redshield\.sha256'"
        $text | Should -Match 'FileShare\]::None'
        $text | Should -Not -Match 'ReadAllText|ReadAllBytes'
    }

    It 'round-trips an ACL through the same held file handle in Windows PowerShell 5.1' {
        $probe = Join-Path $TestDrive 'handle-acl-probe.conf'
        [IO.File]::WriteAllText($probe, '[redacted-test-placeholder]', [Text.UTF8Encoding]::new($false))
        $text = [IO.File]::ReadAllText($script:Bootstrap)
        $match = [regex]::Match($text, "Add-Type -TypeDefinition @'\r?\n(?<csharp>.*?)\r?\n'@", [Text.RegularExpressions.RegexOptions]::Singleline)
        $match.Success | Should -BeTrue
        $typeBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($match.Groups['csharp'].Value))
        $pathBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probe))
        $probeScript = @"
`$typeText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$typeBase64'))
`$probePath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$pathBase64'))
Add-Type -TypeDefinition `$typeText
`$handle = [HomeGateway.P35.NativeFileIdentity]::OpenConfigSecurityFile(`$probePath)
`$stream = `$null
try {
    if (`$handle.IsInvalid) { throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    `$stream = [IO.FileStream]::new(`$handle, [IO.FileAccess]::Read, 4096, `$false)
    `$handle = `$null
    `$before = `$stream.GetAccessControl()
    `$stream.SetAccessControl(`$before)
    if (`$null -eq `$stream.GetAccessControl()) { throw 'handle ACL post-check failed' }
    [Console]::Out.WriteLine('handle_acl_round_trip_ok')
} finally {
    if (`$null -ne `$stream) { `$stream.Dispose() }
    if (`$null -ne `$handle) { `$handle.Dispose() }
}
"@
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeScript))
        $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        $windowsPowerShell = Join-Path $windows 'System32\WindowsPowerShell\v1.0\powershell.exe'

        $output = & $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1

        $LASTEXITCODE | Should -Be 0
        ($output | Out-String) | Should -Match 'handle_acl_round_trip_ok'
    }

    It 'has a non-elevated hash-pinned EncodedCommand driver with a no-mutation WhatIf path' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Driver, [ref]$tokens, [ref]$parseErrors)
        $text = $ast.Extent.Text

        $parseErrors | Should -BeNullOrEmpty
        $text | Should -Match 'ExpectedPayloadSHA256'
        $text | Should -Match 'ExpectedDriverSHA256'
        $text | Should -Match 'Read-PinnedPayload'
        $text | Should -Match "System32', 'WindowsPowerShell', 'v1\.0', 'powershell\.exe'"
        $text | Should -Match 'Start-Process.*-Verb RunAs'
        $text | Should -Match "'-EncodedCommand'"
        $text | Should -Match '-WindowStyle Hidden'
        $text | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
        $text | Should -Match 'HG_P35_BOOTSTRAP_REQUEST_B64 = \$previousRequest'
        $text | Should -Not -Match 'Invoke-Expression|Get-Content|ReadAllText|ReadAllBytes'

        $config = Join-Path $TestDrive 'provider.conf'
        $payload = Join-Path $TestDrive 'payload.ps1'
        $launcher = Join-Path $TestDrive 'launcher.ps1'
        $hgctl = Join-Path $TestDrive 'hgctl.exe'
        [IO.File]::WriteAllText($config, '[redacted-test-placeholder]', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($payload, "'payload'", [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($launcher, "'launcher'", [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($hgctl, 'binary-placeholder', [Text.UTF8Encoding]::new($false))
        $before = $env:HG_P35_BOOTSTRAP_REQUEST_B64
        $driverStream = [IO.File]::Open($script:Driver, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $driverSHA256 = ([BitConverter]::ToString($sha.ComputeHash($driverStream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
            $driverStream.Position = 0
            $driverReader = [IO.StreamReader]::new($driverStream, [Text.UTF8Encoding]::new($false, $true), $true)
            try { $driverText = $driverReader.ReadToEnd() } finally { $driverReader.Dispose() }
        } finally { $driverStream.Dispose() }
        $driverBlock = [ScriptBlock]::Create($driverText)

        & $driverBlock -Action Install -ConfigPath $config -DriverPath $script:Driver `
            -ExpectedConfigSHA256 (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() `
            -ExpectedDriverSHA256 $driverSHA256 `
            -ExpectedPayloadSHA256 (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() `
            -ExpectedLauncherSHA256 (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash.ToLowerInvariant() `
            -ExpectedHgctlSHA256 (Get-FileHash -LiteralPath $hgctl -Algorithm SHA256).Hash.ToLowerInvariant() `
            -Confirmation 'P35-BOOTSTRAP-FILESYSTEM-V1' -PayloadPath $payload -LauncherPath $launcher -HgctlPath $hgctl -WhatIf

        & $driverBlock -Action RestoreConfigAcl -ConfigPath $config -DriverPath $script:Driver `
            -ExpectedConfigSHA256 (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() `
            -ExpectedDriverSHA256 $driverSHA256 `
            -ExpectedPayloadSHA256 (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() `
            -Confirmation 'P35-RESTORE-CONFIG-ACL-V1' -PayloadPath $payload -WhatIf

        $env:HG_P35_BOOTSTRAP_REQUEST_B64 | Should -Be $before

        {
            & $driverBlock -Action Install -ConfigPath $config -DriverPath $script:Driver `
                -ExpectedConfigSHA256 (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() `
                -ExpectedDriverSHA256 $driverSHA256 `
                -ExpectedPayloadSHA256 ('0' * 64) `
                -ExpectedLauncherSHA256 (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash.ToLowerInvariant() `
                -ExpectedHgctlSHA256 (Get-FileHash -LiteralPath $hgctl -Algorithm SHA256).Hash.ToLowerInvariant() `
                -Confirmation 'P35-BOOTSTRAP-FILESYSTEM-V1' -PayloadPath $payload -LauncherPath $launcher -HgctlPath $hgctl -WhatIf
        } | Should -Throw '*payload SHA-256 differs*'
        {
            & $driverBlock -Action Install -ConfigPath '\\server\share\provider.conf' -DriverPath $script:Driver `
                -ExpectedConfigSHA256 ('0' * 64) -ExpectedDriverSHA256 ('0' * 64) -ExpectedPayloadSHA256 ('0' * 64) `
                -ExpectedLauncherSHA256 ('0' * 64) -ExpectedHgctlSHA256 ('0' * 64) `
                -Confirmation 'P35-BOOTSTRAP-FILESYSTEM-V1' -PayloadPath $payload -LauncherPath $launcher -HgctlPath $hgctl -WhatIf
        } | Should -Throw '*local absolute path*'
    }

    It 'rejects direct driver execution before evaluating any requested path' {
        $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        $windowsPowerShell = Join-Path $windows 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $output = & $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:Driver `
            -Action Install -ConfigPath 'C:\does-not-exist.conf' -ExpectedConfigSHA256 ('0' * 64) `
            -ExpectedDriverSHA256 ('0' * 64) -ExpectedPayloadSHA256 ('0' * 64) `
            -Confirmation 'P35-BOOTSTRAP-FILESYSTEM-V1' 2>&1

        $LASTEXITCODE | Should -Not -Be 0
        ($output | Out-String) | Should -Match 'independently pinned in-memory ScriptBlock'
    }

    It 'rejects direct File execution before evaluating its request' {
        $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        $windowsPowerShell = Join-Path $windows 'System32\WindowsPowerShell\v1.0\powershell.exe'

        $output = & $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:Bootstrap 2>&1

        $LASTEXITCODE | Should -Not -Be 0
        ($output | Out-String) | Should -Match 'pinned EncodedCommand payload'
    }
}
