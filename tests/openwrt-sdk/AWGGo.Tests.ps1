BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:BuildPath = Join-Path $script:Root 'scripts/openwrt/build-amneziawg-go.sh'
    $script:Build = Get-Content -LiteralPath $script:BuildPath -Raw
}

Describe 'pinned amneziawg-go contingency build' {
    It 'exists and reads the locked v0.2.19 source' {
        $script:BuildPath | Should -Exist
        $script:Build | Should -Match '\.artifacts\.awg_go_source\.(url|sha256)'
        $script:Build | Should -Match 'v0\.2\.19'
        $script:Build | Should -Not -Match '(?i)latest'
    }

    It 'uses the exact hermetic Go build environment' {
        $script:Build | Should -Match 'GOWORK=off'
        $script:Build | Should -Match 'GOTOOLCHAIN=local'
        $script:Build | Should -Match 'GOFLAGS=-mod=readonly'
        $script:Build | Should -Match 'GOSUMDB=sum\.golang\.org'
        $script:Build | Should -Match "GOOS=linux GOARCH=arm64"
        $script:Build | Should -Match 'CGO_ENABLED=0'
        $script:Build | Should -Match "go1\.26\.5"
        $script:Build | Should -Match 'mod verify'
        $script:Build | Should -Match 'test \./\.\.\.'
        $script:Build | Should -Match '-buildvcs=false'
    }

    It 're-extracts source by locked SHA and owns clean output' {
        $script:Build | Should -Match '\.cache/awg-go-source/\$locked_sha'
        $script:Build | Should -Match 'rm -rf "\$source_root"'
        $script:Build | Should -Match 'rm -rf "\$output_dir"'
        $script:Build | Should -Match 'artifacts/openwrt/aarch64_cortex-a53'
        $script:Build | Should -Match 'amneziawg-go\.buildinfo'
        $script:Build | Should -Match 'amneziawg-go\.sha256'
    }
}
