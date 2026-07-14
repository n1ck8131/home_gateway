BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Ci = Get-Content -LiteralPath (Join-Path $script:Root '.github/workflows/ci.yml') -Raw
    $script:OpenWrt = Get-Content -LiteralPath (Join-Path $script:Root '.github/workflows/openwrt-sdk.yml') -Raw
    $script:Qemu = Get-Content -LiteralPath (Join-Path $script:Root '.github/workflows/openwrt-qemu.yml') -Raw
    $script:Workflows = @($script:Ci, $script:OpenWrt, $script:Qemu)
}

Describe 'pinned GitHub workflows' {
    It 'uses read-only repository permissions' {
        foreach ($workflow in $script:Workflows) {
            $workflow | Should -Match '(?ms)^permissions:\s+contents: read\s*$'
        }
    }

    It 'pins every action to an immutable commit' {
        foreach ($workflow in $script:Workflows) {
            $workflow | Should -Match 'actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0'
            $workflow | Should -Match 'actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16'
            $workflow | Should -Not -Match '(?m)uses:\s*[^\s]+@v\d+\s*$'
            $workflow | Should -Not -Match '(?i)latest'
        }
        $script:OpenWrt | Should -Match 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
        $script:Ci | Should -Match 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
        $script:Qemu | Should -Match 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
    }

    It 'hardens every checkout' {
        foreach ($workflow in $script:Workflows) {
            $checkoutCount = ([regex]::Matches($workflow, 'actions/checkout@')).Count
            ([regex]::Matches($workflow, 'fetch-depth:\s*0')).Count | Should -Be $checkoutCount
            ([regex]::Matches($workflow, 'persist-credentials:\s*false')).Count | Should -Be $checkoutCount
        }
    }

    It 'runs the Windows and Linux verification gates' {
        $script:Ci | Should -Match '\.\\scripts\\bootstrap-dev\.ps1'
        $script:Ci | Should -Match '\.\\scripts\\dev\.ps1 -Command verify'
        $script:Ci | Should -Match './scripts/bootstrap-dev\.ps1 -IncludePowerShell'
        $script:Ci | Should -Match 'make PWSH=\./\.tools/pwsh/pwsh verify'
        $script:Ci | Should -Match 'cc --version && ld --version'
        $script:Ci | Should -Match 'GOMAXPROCS=2 go test -p=1 -timeout=15m -race \./\.\.\.'
        $script:Ci | Should -Match 'sudo tests/network-ns/check-prereqs\.sh'
        $script:Ci | Should -Match 'tests/network-ns/run\.sh'
        $script:Qemu | Should -Match 'tests/openwrt-qemu/run\.sh'
    }

    It 'builds and compares two clean OpenWrt and userspace trees' {
        $script:OpenWrt | Should -Match 'tests/openwrt-sdk/assert-awg2-helper\.sh'
        $script:OpenWrt | Should -Match 'rm -rf \.cache/openwrt-sdk'
        $script:OpenWrt | Should -Match 'artifacts/openwrt-run1'
        $script:OpenWrt | Should -Match 'artifacts/openwrt-run2'
        $script:OpenWrt | Should -Match 'diff -ru --no-dereference artifacts/openwrt-run1 artifacts/openwrt-run2'
        $script:OpenWrt | Should -Match 'artifacts/awg-go-run1'
        $script:OpenWrt | Should -Match 'artifacts/awg-go-run2'
        $script:OpenWrt | Should -Match 'diff -ru --no-dereference artifacts/awg-go-run1 artifacts/awg-go-run2'
        $script:OpenWrt | Should -Match '\.tools/bin/shellcheck'
    }

    It 'uploads only verified outputs and fails closed for missing files' {
        $script:OpenWrt | Should -Match '(?m)^\s+artifacts/openwrt-run2\s*$'
        $script:OpenWrt | Should -Match '(?m)^\s+artifacts/awg-go-run2\s*$'
        $script:OpenWrt | Should -Not -Match '(?m)^\s+artifacts/openwrt\s*$'
        $script:OpenWrt | Should -Match 'if-no-files-found:\s*error'
        $script:OpenWrt | Should -Match 'retention-days:\s*7'
    }
}
