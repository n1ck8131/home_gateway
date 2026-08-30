BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Driver = Join-Path $script:Root 'scripts/p3-profile-stage.ps1'
    $script:Payload = Join-Path $script:Root 'scripts/p3-profile-stage-elevated.ps1'
}

Describe 'protected P3 profile staging' {
    It 'parses under Windows PowerShell-compatible syntax and exposes only bounded actions' {
        foreach ($path in @($script:Driver, $script:Payload)) {
            $tokens = $null
            $errors = $null
            [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
            $errors | Should -BeNullOrEmpty
        }
        $driver = Get-Content -LiteralPath $script:Driver -Raw
        $payload = Get-Content -LiteralPath $script:Payload -Raw
        $driver | Should -Match "ValidateSet\('Prepare', 'Verify', 'Cleanup'\)"
        $driver | Should -Match 'ExpectedDriverSHA256'
        $driver | Should -Match 'ExpectedPayloadSHA256'
        $payload | Should -Match 'S-1-5-18'
        $payload | Should -Match 'S-1-5-32-544'
        $payload | Should -Match 'FileShare\]::None'
        $payload | Should -Match 'secrets.+tunnel\.conf'
        $payload | Should -Match 'secrets.+tunnel\.sha256'
        $payload | Should -Not -Match 'Remove-Item[^\r\n]+tunnel\.conf|Remove-Item[^\r\n]+profile-export\.conf'
        $payload | Should -Not -Match 'AmneziaVPN|rasdial|wg-quick|Set-Net|New-Net|Remove-Net|Disable-Net|Enable-Net'
    }

    It 'validates marker-owned staging state and fails closed for foreign content' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Payload, [ref]$tokens, [ref]$errors)
        $definition = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-StageManifest'
        }, $true))
        $definition.Count | Should -Be 1
        . ([ScriptBlock]::Create($definition[0].Extent.Text))

        (Test-StageManifest -Names @('.p3-profile-stage-owner.v1') -Action Prepare) | Should -BeTrue
        (Test-StageManifest -Names @('.p3-profile-stage-owner.v1', 'profile-export.conf') -Action Verify) | Should -BeTrue
        { Test-StageManifest -Names @('.p3-profile-stage-owner.v1', 'foreign.tmp') -Action Prepare } | Should -Throw '*foreign*'
        { Test-StageManifest -Names @('.p3-profile-stage-owner.v1', 'profile-export.conf', 'other.conf') -Action Verify } | Should -Throw '*foreign*'
    }

    It 'keeps exact profile and executable bytes locked while an actual child reopens them for inspection' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Payload, [ref]$tokens, [ref]$errors)
        $definitions = foreach ($name in @('Get-StreamSHA256','Invoke-PinnedProfileInspection')) {
            $definition = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
            }, $true))
            $definition.Count | Should -Be 1
            $definition[0].Extent.Text
        }
        . ([ScriptBlock]::Create(($definitions -join "`r`n")))
        $profile = Join-Path $TestDrive 'profile-export.conf'
        [IO.File]::WriteAllText($profile,'[synthetic-profile]',[Text.UTF8Encoding]::new($false))
        $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        $child = Join-Path $windows 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $childHash = (Get-FileHash -LiteralPath $child -Algorithm SHA256).Hash.ToLowerInvariant()
        $exclusiveWriteBlocked = $false
        $runner = {
            param($Executable,$Arguments,$ProfilePath)
            try {
                $probe = [IO.File]::Open($ProfilePath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
                $probe.Dispose()
            } catch { $script:exclusiveWriteBlocked = $true }
            $encodedPath = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ProfilePath))
            $probeScript = "`$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encodedPath'));`$s=[IO.File]::Open(`$p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{if(`$s.Length -le 0){exit 9}}finally{`$s.Dispose()}"
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeScript))
            & $Executable -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded
            return $LASTEXITCODE
        }

        $result = Invoke-PinnedProfileInspection -HgctlPath $child -ExpectedHgctlSHA256 $childHash -ProfilePath $profile -Runner $runner

        $result.profile_sha256 | Should -Be (Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:exclusiveWriteBlocked | Should -BeTrue
    }
}
