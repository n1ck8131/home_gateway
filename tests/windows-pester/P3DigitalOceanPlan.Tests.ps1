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
}
