BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Dev = Join-Path $script:Root 'scripts/dev.ps1'
}

Describe 'scripts/dev.ps1' {
    It 'exists' {
        $script:Dev | Should -Exist
    }

    It 'rejects an unknown command' {
        { & $script:Dev -Command invalid } | Should -Throw
    }

    It 'builds all four target artifacts' {
        Remove-Item -LiteralPath (Join-Path $script:Root 'build') -Recurse -Force -ErrorAction SilentlyContinue
        & $script:Dev -Command build
        $LASTEXITCODE | Should -Be 0
        @(
            'build/routerd_linux_arm64',
            'build/server-agent_linux_amd64',
            'build/cisco-discovery_windows_amd64.exe',
            'build/hgctl_windows_amd64.exe'
        ) | ForEach-Object {
            Join-Path $script:Root $_ | Should -Exist
        }
        Join-Path $script:Root 'build/SHA256SUMS' | Should -Exist
    }

    It 'fails when a native verification tool fails' {
        $env:PESTER_TEST_ACTIVE = '1'
        $env:HOME_GATEWAY_TEST_FAIL_NATIVE = 'go-vet'
        try {
            { & $script:Dev -Command lint } | Should -Throw '*failed with exit code*'
        } finally {
            Remove-Item Env:HOME_GATEWAY_TEST_FAIL_NATIVE -ErrorAction SilentlyContinue
            Remove-Item Env:PESTER_TEST_ACTIVE -ErrorAction SilentlyContinue
        }
    }

    It 'restores cross-build environment variables' {
        $before = @($env:GOOS, $env:GOARCH, $env:CGO_ENABLED)
        & $script:Dev -Command build
        @($env:GOOS, $env:GOARCH, $env:CGO_ENABLED) | Should -BeExactly $before
    }

    It 'builds the exact target tuples and Windows program contracts' {
        $go = Join-Path $script:Root ".tools/go/bin/go$(if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' })"
        $targets = @(
            @{ Path = 'build/routerd_linux_arm64'; GOOS = 'linux'; GOARCH = 'arm64' },
            @{ Path = 'build/server-agent_linux_amd64'; GOOS = 'linux'; GOARCH = 'amd64' },
            @{ Path = 'build/cisco-discovery_windows_amd64.exe'; GOOS = 'windows'; GOARCH = 'amd64' },
            @{ Path = 'build/hgctl_windows_amd64.exe'; GOOS = 'windows'; GOARCH = 'amd64' }
        )
        foreach ($target in $targets) {
            $metadata = & $go version -m (Join-Path $script:Root $target.Path) 2>&1
            $LASTEXITCODE | Should -Be 0
            $text = $metadata -join "`n"
            $text | Should -Match "GOOS=$($target.GOOS)"
            $text | Should -Match "GOARCH=$($target.GOARCH)"
            $text | Should -Match 'CGO_ENABLED=0'
        }
        if ($env:OS -eq 'Windows_NT') {
            $ciscoOutput = & (Join-Path $script:Root 'build/cisco-discovery_windows_amd64.exe') version --json
            $ciscoExitCode = $LASTEXITCODE
            $ciscoExitCode | Should -Be 0
            ($ciscoOutput | ConvertFrom-Json).program | Should -Be 'cisco-discovery'
            $hgctlOutput = & (Join-Path $script:Root 'build/hgctl_windows_amd64.exe') version --json
            $hgctlExitCode = $LASTEXITCODE
            $hgctlExitCode | Should -Be 0
            ($hgctlOutput | ConvertFrom-Json).program | Should -Be 'hgctl'
        }
    }
}
