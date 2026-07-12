BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

Describe 'configuration baseline' {
    It 'contains all safe defaults' {
        $text = Get-Content (Join-Path $script:Root 'configs/defaults.yaml') -Raw
        $expected = @(
            'schema_version: 1'
            'default_route: direct'
            'vpn_failure_policy: fail_closed_for_vpn_entries'
            'external_source_mode: staged_auto_for_trusted'
            'source_refresh: 6h'
            'source_jitter: 30m'
            'server_mode: manual_sticky'
            'health_failures_to_down: 3'
            'health_successes_to_up: 2'
            'failover_hold_down: 120s'
            'failback_stable_period: 10m'
            'one_time_profile_ttl: 10m'
            'dns_query_logging: false'
            'panel_wan_access: false'
            'panel_guest_access: false'
            'mobile_peer_to_peer: false'
            'ipv6_policy: route_or_block_no_leak'
            'backup_retention: 7d/4w/6m'
        ) -join "`n"
        (($text -replace "`r`n", "`n").Trim()) | Should -BeExactly $expected
    }

    It 'models both work PC identities' {
        $text = Get-Content (Join-Path $script:Root 'configs/inventory.example.yaml') -Raw
        $text | Should -Match 'kind: ethernet'
        $text | Should -Match 'kind: flint-wifi'
        $text | Should -Match 'allow_repeater: false'
        $text | Should -Match '(?s)id: work-pc.*kind: ethernet.*kind: flint-wifi'
    }

    It 'keeps router access local and built-in sources empty' {
        $router = Get-Content (Join-Path $script:Root 'configs/routerd.example.yaml') -Raw
        $router | Should -Match '(?m)^  wan: false$'
        $router | Should -Match '(?m)^  guest: false$'
        $router | Should -Match '(?m)^  mobile_peers: false$'
        $sources = Get-Content (Join-Path $script:Root 'configs/builtin-sources.yaml') -Raw
        $sources | Should -Match '(?m)^qualification_phase: P6$'
        $sources | Should -Match '(?m)^sources: \[\]$'
    }

    It 'contains no secret values' {
        $files = Get-ChildItem (Join-Path $script:Root 'configs') -File
        foreach ($file in $files) {
            $text = Get-Content $file.FullName -Raw
            $text | Should -Not -Match '(?im)^\s*(password|private_key|preshared_key|token):\s*\S+'
        }
    }

    It 'has a valid JSON-subset OpenAPI document' {
        $raw = Get-Content (Join-Path $script:Root 'api/openapi.yaml') -Raw
        $api = $raw | ConvertFrom-Json
        $api.openapi | Should -Be '3.0.3'
        $api.servers[0].url | Should -Be 'https://router.home.arpa:8443'
        @($api.paths.PSObject.Properties).Count | Should -Be 0
    }
}
