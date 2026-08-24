BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Kernel = Get-Content -LiteralPath (Join-Path $script:Root 'packaging/openwrt-awg2/kmod-amneziawg/Makefile') -Raw
    $script:Tools = Get-Content -LiteralPath (Join-Path $script:Root 'packaging/openwrt-awg2/amneziawg-tools/Makefile') -Raw
    $script:Helper = Get-Content -LiteralPath (Join-Path $script:Root 'packaging/openwrt-awg2/amneziawg-tools/files/amneziawg.sh') -Raw
    $script:Build = Get-Content -LiteralPath (Join-Path $script:Root 'scripts/openwrt/build-packages.sh') -Raw
    $script:ApkValidator = Get-Content -LiteralPath (Join-Path $script:Root 'scripts/openwrt/apk-validation.jq') -Raw
    $script:ApkFixture = Get-Content -LiteralPath (Join-Path $script:Root 'tests/openwrt-sdk/assert-apk-dependencies.sh') -Raw

    $shellCommand = Get-Command sh -ErrorAction SilentlyContinue
    $script:Shell = if ($shellCommand) { $shellCommand.Source } else { $null }
    if (-not $script:Shell) {
        $gitCommand = Get-Command git -ErrorAction SilentlyContinue
        if ($gitCommand) {
            $gitRoot = Split-Path -Parent (Split-Path -Parent $gitCommand.Source)
            $gitShell = Join-Path $gitRoot 'bin/sh.exe'
            if (Test-Path -LiteralPath $gitShell) {
                $script:Shell = $gitShell
            }
        }
    }

    function New-FetchSdkFixture {
        param(
            [Parameter(Mandatory)]
            [string]$Path,
            [switch]$ChecksumMismatch
        )

        $scriptDirectory = Join-Path $Path 'scripts/openwrt'
        $archiveDirectory = Join-Path $Path '.cache/downloads'
        $binDirectory = Join-Path $Path 'bin'
        New-Item -ItemType Directory -Force -Path $scriptDirectory, $archiveDirectory, $binDirectory, (Join-Path $Path 'manifest') | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:Root 'scripts/openwrt/fetch-sdk.sh') -Destination $scriptDirectory

        $archive = Join-Path $archiveDirectory 'fixture-sdk.tar.zst'
        [IO.File]::WriteAllBytes($archive, [Text.Encoding]::UTF8.GetBytes("fixture archive`n"))
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $actualHash = ([BitConverter]::ToString($sha256.ComputeHash([IO.File]::ReadAllBytes($archive)))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
        $expectedHash = if ($ChecksumMismatch) { '0' * 64 } else { $actualHash }

        [IO.File]::WriteAllText((Join-Path $Path 'manifest/versions.lock.yaml'), '{}', (New-Object Text.UTF8Encoding($false)))
        $jq = @'
#!/bin/sh
case "$2" in
    .artifacts.openwrt_sdk.url) printf '%s\n' "$FIXTURE_URL" ;;
    .artifacts.openwrt_sdk.sha256) printf '%s\n' "$FIXTURE_HASH" ;;
    *) exit 1 ;;
esac
'@
        [IO.File]::WriteAllText((Join-Path $binDirectory 'jq'), $jq.Replace("`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
        $runner = @'
#!/bin/sh
set -eu
chmod +x "$PWD/bin/jq" "$PWD/scripts/openwrt/fetch-sdk.sh"
PATH="$PWD/bin:$PATH" exec "$PWD/scripts/openwrt/fetch-sdk.sh"
'@
        [IO.File]::WriteAllText((Join-Path $Path 'run-fetch.sh'), $runner.Replace("`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))

        if (-not $ChecksumMismatch) {
            $sdk = Join-Path $Path ".cache/openwrt-sdk/$expectedHash/sdk"
            New-Item -ItemType Directory -Force -Path (Join-Path $sdk 'include') | Out-Null
            [IO.File]::WriteAllText((Join-Path $sdk 'include/toplevel.mk'), '', (New-Object Text.UTF8Encoding($false)))
            [IO.File]::WriteAllText((Join-Path $Path ".cache/openwrt-sdk/$expectedHash/.complete"), "$expectedHash`n", (New-Object Text.UTF8Encoding($false)))
        }

        [pscustomobject]@{
            Path = $Path
            URL = 'https://example.invalid/fixture-sdk.tar.zst'
            Hash = $expectedHash
        }
    }

    function Invoke-FetchSdkFixture {
        param(
            [Parameter(Mandatory)]
            [pscustomobject]$Fixture
        )

        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = $script:Shell
        $startInfo.Arguments = 'run-fetch.sh'
        $startInfo.WorkingDirectory = $Fixture.Path
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.EnvironmentVariables['FIXTURE_URL'] = $Fixture.URL
        $startInfo.EnvironmentVariables['FIXTURE_HASH'] = $Fixture.Hash
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    }
}

Describe 'pinned AWG2 OpenWrt packages' {
    It 'pins official kernel and tools source versions and hashes' {
        $script:Kernel | Should -Match 'PKG_VERSION:=1\.0\.20260611'
        $script:Kernel | Should -Match 'PKG_HASH:=e062ecc9f1d89eeafa9f56a29473372a1d796ee061eaa8c7b61eeb51c38b80d6'
        $script:Tools | Should -Match '(?m)^PKG_SOURCE_VERSION:=1\.0\.20260618-2$'
        $script:Tools | Should -Match '(?m)^PKG_SOURCE:=v\$\(PKG_SOURCE_VERSION\)\.tar\.gz$'
        $script:Tools | Should -Match '(?m)^PKG_SOURCE_URL:=https://github\.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/$'
        $script:Tools | Should -Match '(?m)^PKG_BUILD_DIR:=\$\(BUILD_DIR\)/\$\(PKG_NAME\)-\$\(PKG_SOURCE_VERSION\)$'
        $script:Tools | Should -Match 'PKG_HASH:=cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10'
        "$script:Kernel`n$script:Tools`n$script:Build" | Should -Not -Match '(?i)latest'
    }

    It 'emits an APK-compatible tools package version' {
        $packageVersion = [regex]::Match($script:Tools, '(?m)^PKG_VERSION:=(?<Value>[^\r\n]+)$')

        $packageVersion.Success | Should -BeTrue
        $packageVersion.Groups['Value'].Value | Should -Be '1.0.20260618.2'
        $script:Tools | Should -Match '(?m)^PKG_RELEASE:=2$'
    }

    It 'declares the required package contracts' {
        $script:Kernel | Should -Match 'PKG_EXTMOD_SUBDIRS:=src'
        $script:Tools | Should -Match 'SUBMENU:=VPN'
        $script:Tools | Should -Match '\+!BUSYBOX_CONFIG_IP:ip'
        $script:Tools | Should -Match '\+kmod-amneziawg'
    }

    It 'declares and renders the complete AWG2 schema' {
        foreach ($key in @('s3', 's4')) {
            $script:Helper | Should -Match "proto_config_add_int `"awg_$key`""
            $script:Helper | Should -Match "config_get awg_$key"
            $script:Helper | Should -Match "${($key.ToUpperInvariant())} = \$\{awg_$key\}"
        }
        foreach ($key in @('h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5')) {
            $script:Helper | Should -Match "proto_config_add_string `"awg_$key`""
            $script:Helper | Should -Match "config_get awg_$key"
        }
        $script:Helper | Should -Match 'config_get_bool route_allowed_ips .* 0'
        $script:Helper | Should -Match 'renew_handler=1'
        $script:Helper | Should -Match 'peer_detect=1'
        $script:Helper | Should -Match 'proto_config_add_string "addresses"'
        $script:Helper | Should -Match 'proto_config_add_string "private_key_file"'
        $script:Helper | Should -Match 'config_get private_key_file'
        $script:Helper | Should -Match '/etc/routerd/secrets'
        $script:Helper | Should -Match "stat -c '%u:%a'"
        $script:Helper | Should -Match '0:600'
        $script:Helper | Should -Match 'mktemp -d /tmp/amneziawg\.XXXXXX'
        $script:Helper | Should -Match "trap 'proto_amneziawg_cleanup_runtime_config' EXIT HUP INT TERM"
        $script:Helper | Should -Not -Match '/etc/routerd/secrets/runtime'
        $script:Helper | Should -Match 'proto_amneziawg_renew'
    }

    It 'owns reproducible SDK selection, tuple and APK validation' {
        $script:Build | Should -Match 'CONFIG_PACKAGE_kmod-amneziawg=m'
        $script:Build | Should -Match 'CONFIG_PACKAGE_amneziawg-tools=m'
        $script:Build | Should -Match 'SOURCE_DATE_EPOCH'
        $script:Build | Should -Match 'OUTPUT_DIR'
        $script:Build | Should -Match 'r33051-f5dae5ece4'
        $script:Build | Should -Match '6\.12\.94'
        $script:Build | Should -Match '5a6c1f71be683ae9980b15d3ce73e24d'
        $script:Build | Should -Match 'aarch64_cortex-a53'
        $script:Build | Should -Match 'adbdump --format json'
        $script:Build | Should -Not -Match 'val\.LINUX_(VERSION|VERMAGIC)'
        $script:Build | Should -Match 'apk-validation\.jq'
        $script:ApkValidator | Should -Match 'expected exactly one kernel dependency string'
        $script:ApkValidator | Should -Match 'capture\("\^kernel=\(\?<kernel>'
        $script:ApkValidator | Should -Match '\(\?<kernel>'
        $script:ApkValidator | Should -Match '\(\?<vermagic>\[0-9a-f\]\{32\}\)'
        $script:Build | Should -Match 'require_single_payload_file'
        $script:Build | Should -Match "--arg mode 'payload'"
        $script:ApkValidator | Should -Match 'missing APK payload file at'
        $script:ApkValidator | Should -Match 'duplicate APK payload file at'
    }

    It 'uses APK v3 dependency strings' {
        $script:ApkValidator | Should -Match 'malformed \\\(\$context\) dependencies: expected a dependency array'
        $script:ApkValidator | Should -Match 'malformed \\\(\$context\) dependencies: expected dependency strings'
        $script:ApkValidator | Should -Match 'require_dependency_strings\("package"\)'
        $script:ApkValidator | Should -Match 'require_dependency_strings\("kmod"\)'
        $script:ApkValidator | Should -Match 'all\(\$depends\[\]; type == "string"\)'
        $script:ApkValidator | Should -Not -Match 'select\(\.name =='
    }

    It 'rejects malformed, multiple and versioned dependency strings' {
        $script:ApkValidator | Should -Match 'dependency named \\\(\$name\) must be an exact unversioned string'
        $script:ApkValidator | Should -Match 'conflicting dependency named \\\(\$name\) is not allowed'
        $script:ApkValidator | Should -Match 'expected exactly one unversioned dependency named'
        $script:ApkValidator | Should -Match 'expected exactly one kernel dependency string'
        $script:ApkValidator | Should -Match 'kernel dependency string has an unexpected format'
        $script:ApkFixture | Should -Match "assert_rejected 'duplicate package dependency'"
        $script:ApkFixture | Should -Match "assert_rejected 'conflicting package dependency'"
        $script:ApkFixture | Should -Match "assert_rejected 'duplicate kernel dependency'"
        $script:ApkFixture | Should -Match "assert_rejected 'conflicting kernel dependency'"
    }

    It 'validates APK v3 payloads with optional root and parent fields' {
        $script:ApkValidator | Should -Match 'present path names must be strings'
        $script:ApkValidator | Should -Match 'present path files must be arrays'
        $script:ApkValidator | Should -Match '\(\$path\.files\? // \[\]\)\[\]'
        $script:ApkValidator | Should -Match '\(\$path\.name\? // ""\) == ""'
        $script:ApkFixture | Should -Match 'payload_fixture='
        $script:ApkFixture | Should -Match "assert_payload_rejected 'duplicate payload file'"
        $script:ApkFixture | Should -Match "assert_payload_rejected 'missing payload file'"
        $script:ApkFixture | Should -Match "assert_payload_rejected 'non-array payload files'"
    }

    It 'returns exactly one SDK path and sends checksum diagnostics to stderr' {
        if (-not $script:Shell) {
            Set-ItResult -Skipped -Because 'no POSIX shell is available'
            return
        }
        $fixture = New-FetchSdkFixture -Path (Join-Path $TestDrive 'fetch-success')
        $result = Invoke-FetchSdkFixture -Fixture $fixture

        $result.ExitCode | Should -Be 0
        $result.Stdout | Should -Match '\A[^\r\n]+[/\\]sdk\r?\n\z'
        $result.Stderr | Should -Match ': OK'
    }

    It 'fails closed without emitting an SDK path on checksum mismatch' {
        if (-not $script:Shell) {
            Set-ItResult -Skipped -Because 'no POSIX shell is available'
            return
        }
        $fixture = New-FetchSdkFixture -Path (Join-Path $TestDrive 'fetch-mismatch') -ChecksumMismatch
        $result = Invoke-FetchSdkFixture -Fixture $fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Stdout | Should -BeNullOrEmpty
        $result.Stderr | Should -Match 'FAILED'
    }
}
