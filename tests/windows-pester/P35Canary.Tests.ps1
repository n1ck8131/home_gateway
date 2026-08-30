$script:IsNativeWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Canary = Join-Path $script:Root 'scripts/p35-canary.ps1'
    $script:Tokens = $null
    $script:ParseErrors = $null
    $script:Ast = [Management.Automation.Language.Parser]::ParseFile(
        $script:Canary,
        [ref]$script:Tokens,
        [ref]$script:ParseErrors
    )
}

Describe 'scripts/p35-canary.ps1' {
    It 'parses under Windows PowerShell-compatible syntax and gates every mutation' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Canary, [ref]$tokens, [ref]$parseErrors)

        $parseErrors | Should -BeNullOrEmpty
        $text = $ast.Extent.Text
        $text | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
        $text | Should -Match 'ConfirmLiveMutation'
        $text | Should -Match 'ConfirmRecovery'
        $text | Should -Match 'P35-ROLLBACK'
        $text | Should -Match 'P35-RECOVER'
        $text | Should -Match 'P35-EMERGENCY-DISABLE'
        $text | Should -Match 'P35-FULL-RESTORE'
    }

    It 'never reads or prints RedShield config contents' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Canary, [ref]$tokens, [ref]$parseErrors)
        $commands = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true))

        $parseErrors | Should -BeNullOrEmpty
        @($commands | Where-Object { $_.GetCommandName() -in @('Get-Content', 'Write-Host', 'Write-Output') }) | Should -BeNullOrEmpty
    }

    It 'forwards blocked Plan JSON and exit 3 in both PowerShell runtimes' -Skip:(-not $script:IsNativeWindows) {
        $engines = @(
            (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
            (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop).Source
        )
        $definition = @($script:Ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Invoke-HgctlPlan'
        }, $true))
        $definition.Count | Should -Be 1
        $expected = '{"mode":"plan","ready_for_live_gate":false}'
        $stub = Join-Path $TestDrive 'fake-hgctl.cmd'
        $stubText = "@echo off`r`necho $expected`r`nexit /b 3`r`n"
        [IO.File]::WriteAllText($stub, $stubText, [Text.Encoding]::ASCII)
        $stubLiteral = $stub.Replace("'", "''")
        $driver = Join-Path $TestDrive 'invoke-hgctl-plan.ps1'
        $driverText = $definition[0].Extent.Text + "`r`n" +
            "Invoke-HgctlPlan -Executable '$stubLiteral' -Arguments @()`r`n"
        [IO.File]::WriteAllText($driver, $driverText, [Text.UTF8Encoding]::new($false))
        foreach ($engine in $engines) {
            $stderrPath = Join-Path $TestDrive ((Split-Path $engine -Leaf) + '.stderr')
            $output = @(& $engine -NoLogo -NoProfile -NonInteractive -File $driver 2>$stderrPath)
            $exitCode = $LASTEXITCODE
            $exitCode | Should -Be 3
            ($output -join [Environment]::NewLine) | Should -Be $expected
            [IO.File]::ReadAllText($stderrPath) | Should -BeNullOrEmpty
        }
    }

    It 'uses Plan-only forwarding while preserving checked live actions' {
        $commands = @($script:Ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true))
        $planInvocations = @($commands | Where-Object { $_.GetCommandName() -ceq 'Invoke-HgctlPlan' })
        $planInvocations.Count | Should -Be 1
        $checkedInvocations = @($commands | Where-Object { $_.GetCommandName() -ceq 'Invoke-CheckedHgctl' })
        $checkedInvocations.Count |
            Should -BeGreaterThan 1
        $text = $script:Ast.Extent.Text
        $text | Should -Match 'if \(\$Action -eq ''Plan''\)[\s\S]*Invoke-HgctlPlan -Executable \$resolvedHgctl -Arguments \$arguments[\s\S]*return'
        @($checkedInvocations | Where-Object { $_.Extent.StartOffset -gt $planInvocations[0].Extent.StartOffset }).Count |
            Should -BeGreaterThan 1
    }

    It 'uses the provider-neutral protected ProgramData config for Plan Apply and Confirm' {
        $text = Get-Content -LiteralPath $script:Canary -Raw

		$text | Should -Match 'CommonApplicationData'
		$text | Should -Match 'S-1-5-18'
		$text | Should -Match 'S-1-5-32-544'
		$text | Should -Match 'SetAccessRuleProtection\(\$true, \$false\)'
		$text | Should -Match 'ExpectedHgctlSHA256'
		$text | Should -Match 'ExpectedLauncherSHA256'
		$text | Should -Match 'FileShare\]::Read'
		$text | Should -Match 'Assert-RestrictedConfigSource'
		$text | Should -Match 'Assert-InstalledConfigFile'
		$text | Should -Match 'ExpectedConfigSHA256'
		$text | Should -Match 'secrets\\tunnel\.conf'
		$text | Should -Match 'secrets\\tunnel\.sha256'
		$text | Should -Not -Match 'secrets\\redshield\.conf'
		$text | Should -Not -Match 'secrets\\redshield\.sha256'
		$text | Should -Match '--config-sha256'
		$text | Should -Match 'live P3\.5 accepts only the protected installed tunnel config'
		$text | Should -Match 'if \(\$Action -eq ''Plan''\)[\s\S]*Resolve-InstalledConfig'
		$text | Should -Match 'if \(\$Action -in @\(''Apply'', ''Confirm''\)\)[\s\S]*Resolve-InstalledConfig'
		$text | Should -Match 'AreAccessRulesProtected'
		$text | Should -Match 'grants an unauthorized principal'
		$text | Should -Match 'bin\\p35-canary\.ps1'
		$text | Should -Match 'live actions must run only from the protected staged launcher'
		$text | Should -Not -Match 'Install-ProtectedConfig'
		$text | Should -Not -Match '\$identity\.User\.Value.*FullControl'
    }

    It 'resolves one exact regular provider-neutral config and rejects stale hash or reparse state' -Skip:(-not $script:IsNativeWindows) {
        $required = @(
            'Assert-LocalNonReparsePath',
            'Assert-RegularFile',
            'Get-StreamSHA256',
            'Get-LockedFileSHA256',
            'Assert-ExpectedSHA256',
            'Read-ExactSHA256Pin',
            'Resolve-InstalledConfig'
        )
        $definitions = foreach ($name in $required) {
            $definition = @($script:Ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
            }, $true))
            $definition.Count | Should -Be 1
            $definition[0].Extent.Text
        }
        . ([ScriptBlock]::Create(($definitions -join "`r`n")))
        function Assert-ProtectedStateRoot { param([string]$Path) }
        function Assert-ProtectedDirectory { param([string]$Path, [string]$MarkerName) }
        function Assert-InstalledConfigFile {
            param([string]$Path)
            Assert-RegularFile -Path $Path -Label 'installed tunnel config'
        }
        $script:SecretsMarkerName = '.p35-secrets-owner.v1'

        $root = Join-Path $TestDrive 'installed'
        $secrets = Join-Path $root 'secrets'
        New-Item -ItemType Directory -Path $secrets | Out-Null
        $config = Join-Path $secrets 'tunnel.conf'
        $pin = Join-Path $secrets 'tunnel.sha256'
        [IO.File]::WriteAllText($config, '[synthetic-provider-profile]', [Text.UTF8Encoding]::new($false))
        $expected = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText($pin, $expected, [Text.Encoding]::ASCII)

        $resolved = Resolve-InstalledConfig -Root $root
        $resolved.Path | Should -Be $config
        $resolved.SHA256 | Should -BeExactly $expected

        [IO.File]::WriteAllText($pin, ('0' * 64), [Text.Encoding]::ASCII)
        { Resolve-InstalledConfig -Root $root } | Should -Throw '*protected pin*'
        [IO.File]::WriteAllText($pin, $expected, [Text.Encoding]::ASCII)

        Remove-Item -LiteralPath $config
        New-Item -ItemType Directory -Path $config | Out-Null
        { Resolve-InstalledConfig -Root $root } | Should -Throw '*regular non-reparse file*'

        $junctionRoot = Join-Path $TestDrive 'junction-root'
        $realSecrets = Join-Path $TestDrive 'real-secrets'
        New-Item -ItemType Directory -Path $junctionRoot, $realSecrets | Out-Null
        [IO.File]::WriteAllText((Join-Path $realSecrets 'tunnel.conf'), '[synthetic-provider-profile]', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $realSecrets 'tunnel.sha256'), $expected, [Text.Encoding]::ASCII)
        New-Item -ItemType Junction -Path (Join-Path $junctionRoot 'secrets') -Target $realSecrets | Out-Null
        { Resolve-InstalledConfig -Root $junctionRoot } | Should -Throw '*reparse point*'
    }

    It 'performs no filesystem or native mutation under Apply or Confirm WhatIf' {
        foreach ($action in @('Apply', 'Confirm')) {
            $config = Join-Path $TestDrive ($action + '-provider.conf')
            Set-Content -LiteralPath $config -Value '[redacted-test-placeholder]'
            $state = Join-Path $TestDrive ($action + '-state')

            & $script:Canary -Action $action `
                -ConfigPath $config `
                -StateRoot $state `
                -Target '1.1.1.1' `
                -DnsNamespace '.one.one.one.one' `
                -Challenge 'P35-APPLY-0011223344556677' `
                -ConfirmLiveMutation `
                -HgctlPath (Join-Path $TestDrive 'missing-hgctl.exe') `
                -WhatIf

            $state | Should -Not -Exist
        }
    }
}
