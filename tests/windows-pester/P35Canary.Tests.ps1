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

    It 'uses protected ProgramData state, pinned executable bytes, and a restricted config source' {
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
		$text | Should -Match 'redshield\.sha256'
		$text | Should -Match '--config-sha256'
		$text | Should -Match 'live P3\.5 accepts only the protected installed RedShield config'
		$text | Should -Match 'AreAccessRulesProtected'
		$text | Should -Match 'grants an unauthorized principal'
		$text | Should -Match 'bin\\p35-canary\.ps1'
		$text | Should -Match 'live actions must run only from the protected staged launcher'
		$text | Should -Not -Match 'Install-ProtectedConfig'
		$text | Should -Not -Match '\$identity\.User\.Value.*FullControl'
    }

    It 'performs no filesystem or native mutation under Apply WhatIf' {
        $config = Join-Path $TestDrive 'provider.conf'
        Set-Content -LiteralPath $config -Value '[redacted-test-placeholder]'
        $state = Join-Path $TestDrive 'state'

        & $script:Canary -Action Apply `
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
