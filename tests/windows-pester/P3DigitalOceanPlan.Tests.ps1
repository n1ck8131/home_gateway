$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Describe 'P3 DigitalOcean plan-only guard' {
    It 'ships a non-billable manifest and plan script' {
        $manifest = Join-Path $root 'deploy/digitalocean/p3-droplet.v1.json'
        $script = Join-Path $root 'scripts/p3-digitalocean-plan.ps1'
        Test-Path -LiteralPath $manifest | Should -BeTrue
        Test-Path -LiteralPath $script | Should -BeTrue
        $raw = Get-Content -LiteralPath $script -Raw -Encoding UTF8
        $raw | Should -Match 'billable_action_performed'
        $raw | Should -Not -Match '(?i)doctl|Invoke-WebRequest|Invoke-RestMethod|Start-Process|https?://'
    }

    It 'emits a stable redacted non-billable checklist for one synthetic public key' {
        $keyPath = Join-Path $TestDrive 'operator.pub'
        $key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA synthetic'
        [IO.File]::WriteAllText($keyPath, $key, [Text.UTF8Encoding]::new($false))
        $output = & (Join-Path $root 'scripts/p3-digitalocean-plan.ps1') -PublicKeyPath $keyPath -WhatIf
        $LASTEXITCODE | Should -Be 0
        $json = $output | ConvertFrom-Json
        $json.billable_action_performed | Should -BeFalse
        $json.provider | Should -Be 'digitalocean'
        $json.primary_region | Should -Be 'ams3'
        $json.fallback_region | Should -Be 'fra1'
        $json.image | Should -Be 'ubuntu-24-04-x64'
        $json.public_key_path | Should -Be '[REDACTED]'
        $json.public_key_sha256 | Should -Be ((Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash.ToLowerInvariant())
    }

    It 'rejects relative, non-public, private, and malformed key inputs before any provider action' {
        $private = Join-Path $TestDrive 'private.pub'
        [IO.File]::WriteAllText($private, '-----BEGIN OPENSSH PRIVATE KEY-----', [Text.UTF8Encoding]::new($false))
        $scriptPath = Join-Path $root 'scripts/p3-digitalocean-plan.ps1'
        foreach ($input in @('relative.pub', (Join-Path $TestDrive 'not-public.txt'), $private)) {
            { & $scriptPath -PublicKeyPath $input -WhatIf } | Should -Throw
        }
    }
}
