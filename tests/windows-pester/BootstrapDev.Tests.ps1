BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Bootstrap = Join-Path $script:Root 'scripts/bootstrap-dev.ps1'
    . $script:Bootstrap
}

Describe 'scripts/bootstrap-dev.ps1' {
    BeforeEach {
        $script:FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path (Join-Path $script:FixtureRoot 'manifest') | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:Root 'manifest/versions.lock.yaml') -Destination (Join-Path $script:FixtureRoot 'manifest/versions.lock.yaml')
    }

    It 'performs WhatIf without files or network calls' {
        Mock Invoke-WebRequest { throw 'network must not be called' }

        Invoke-Bootstrap -Root $script:FixtureRoot -WhatIf | Out-Null

        Join-Path $script:FixtureRoot '.tools' | Should -Not -Exist
        Join-Path $script:FixtureRoot '.cache' | Should -Not -Exist
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'fails closed for a corrupt cached artifact' {
        $lock = Get-Content -LiteralPath (Join-Path $script:FixtureRoot 'manifest/versions.lock.yaml') -Raw | ConvertFrom-Json
        $windowsPlatform = Test-WindowsPlatform
        $platform = if ($windowsPlatform) { 'windows_amd64' } else { 'linux_amd64' }
        $artifact = $lock.artifacts.PSObject.Properties["go_$platform"].Value
        $filename = Get-ArtifactFilename -Artifact $artifact
        $downloads = Join-Path $script:FixtureRoot '.cache/downloads'
        New-Item -ItemType Directory -Force -Path $downloads | Out-Null
        Set-Content -LiteralPath (Join-Path $downloads $filename) -Value 'corrupt'
        Mock Invoke-WebRequest { throw 'network must not be called for cached content' }

        { Invoke-Bootstrap -Root $script:FixtureRoot } | Should -Throw '*Cached SHA256 mismatch*'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'resumes an existing partial with bounded curl' {
        $partial = Join-Path $script:FixtureRoot 'artifact.partial'
        Set-Content -LiteralPath $partial -Value 'partial'
        Mock Get-Command { [pscustomobject]@{ Source = 'curl.exe' } } -ParameterFilter { $Name -in @('curl.exe', 'curl') }
        Mock Invoke-CurlDownload { }
        Mock Invoke-WebRequest { throw 'Invoke-WebRequest must not restart a partial' }

        Invoke-ArtifactDownload -Uri 'https://example.invalid/artifact.zip' -Partial $partial

        Should -Invoke Invoke-CurlDownload -Times 1 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'uses the application Path when Source is empty' {
        $partial = Join-Path $script:FixtureRoot 'artifact.partial'
        $curlName = if (Test-WindowsPlatform) { 'curl.exe' } else { 'curl' }
        $curlPath = if (Test-WindowsPlatform) { 'C:\Windows\System32\curl.exe' } else { '/usr/bin/curl' }
        Mock Get-Command { [pscustomobject]@{ Path = $curlPath; Source = ''; Definition = '' } } -ParameterFilter { $Name -eq $curlName }
        Mock Invoke-CurlDownload { }

        Invoke-ArtifactDownload -Uri 'https://example.invalid/artifact.zip' -Partial $partial

        Should -Invoke Invoke-CurlDownload -ParameterFilter { $CurlPath -eq $curlPath } -Times 1 -Exactly
    }

    It 'performs zero downloads and replacements on a second valid invocation' {
        $script:Installed = $false
        Mock Test-InstalledComponent { return $script:Installed }
        Mock Get-VerifiedArtifact { return 'fixture.archive' }
        Mock Install-ToolComponent { }
        Mock Assert-BootstrapVersions { $script:Installed = $true }

        Invoke-Bootstrap -Root $script:FixtureRoot | Out-Null
        Invoke-Bootstrap -Root $script:FixtureRoot | Out-Null

        $expected = if (Test-WindowsPlatform) { 4 } else { 5 }
        Should -Invoke Get-VerifiedArtifact -Times $expected -Exactly
        Should -Invoke Install-ToolComponent -Times $expected -Exactly
    }

    It 'installs the locked Go archive even when a matching system Go exists' {
        Mock Test-InstalledComponent { return $false }
        Mock Get-Command { [pscustomobject]@{ Source = 'C:\system\go.exe' } } -ParameterFilter { $Name -eq 'go' }
        Mock Get-VerifiedArtifact { return 'fixture.archive' }
        Mock Install-ToolComponent { }
        Mock Assert-BootstrapVersions { }

        Invoke-Bootstrap -Root $script:FixtureRoot | Out-Null

        Should -Invoke Get-Command -ParameterFilter { $Name -eq 'go' } -Times 0 -Exactly
        Should -Invoke Get-VerifiedArtifact -ParameterFilter { $Name -like 'go*' } -Times 1 -Exactly
        Should -Invoke Install-ToolComponent -ParameterFilter { $Component -eq 'go' } -Times 1 -Exactly
    }

    It 'uses each tool native version argument' {
        Get-ToolVersionArguments -Component shellcheck | Should -Be '--version'
        Get-ToolVersionArguments -Component actionlint | Should -Be '-version'
        Get-ToolVersionArguments -Component gitleaks | Should -Be 'version'
    }

    It 'does not bind the read-only IsWindows automatic variable' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:Bootstrap,
            [ref]$tokens,
            [ref]$parseErrors
        )
        $conflicts = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.VariablePath.UserPath -ieq 'IsWindows'
        }, $true))

        $parseErrors | Should -BeNullOrEmpty
        $conflicts | Should -BeNullOrEmpty
    }

    It 'selects mutually exclusive Windows and Linux artifacts' {
        $windows = @(Get-PlatformArtifactNames -Platform windows_amd64 | ForEach-Object ArtifactKey)
        $linux = @(Get-PlatformArtifactNames -Platform linux_amd64 | ForEach-Object ArtifactKey)

        ($windows -join ',') | Should -Not -Match 'linux_amd64'
        ($linux -join ',') | Should -Not -Match 'windows_amd64'
        $windows | Should -Contain 'go_windows_amd64'
        $linux | Should -Contain 'go_linux_amd64'
        $windows | Should -Not -Contain 'shellcheck_linux_amd64'
        $linux | Should -Contain 'shellcheck_linux_amd64'
    }
}
