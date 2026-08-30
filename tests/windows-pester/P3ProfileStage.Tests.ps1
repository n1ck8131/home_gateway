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
}
