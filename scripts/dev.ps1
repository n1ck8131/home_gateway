param(
    [Parameter(Mandatory)]
    [ValidateSet('bootstrap', 'format', 'format-check', 'test', 'lint', 'build', 'pester', 'verify')]
    [string]$Command
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$windowsPlatform = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$suffix = if ($windowsPlatform) { '.exe' } else { '' }

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$Arguments = @()
    )
    $failureName = $env:HOME_GATEWAY_TEST_FAIL_NATIVE
    if ($failureName -and $env:PESTER_TEST_ACTIVE -ne '1') {
        throw 'HOME_GATEWAY_TEST_FAIL_NATIVE is restricted to Pester'
    }
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $invocationName = if ($leaf -eq 'go' -and $Arguments.Count -ne 0) {
        "go-$($Arguments[0])"
    } else {
        $leaf
    }
    if ($failureName -and $failureName -eq $invocationName) {
        if ($windowsPlatform) {
            & $env:ComSpec /d /c 'exit 17'
        } else {
            & /bin/sh -c 'exit 17'
        }
    } else {
        & $FilePath @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Get-PinnedGo {
    $go = Join-Path $root ".tools/go/bin/go$suffix"
    $env:GOTOOLCHAIN = 'local'
    if (-not (Test-Path -LiteralPath $go)) {
        throw 'Pinned Go toolchain is missing; run bootstrap'
    }
    return $go
}

function Get-PinnedGofmt {
    $gofmt = Join-Path $root ".tools/go/bin/gofmt$suffix"
    if (-not (Test-Path -LiteralPath $gofmt)) {
        throw 'Pinned gofmt is missing; run bootstrap'
    }
    return $gofmt
}

function Invoke-BootstrapCommand {
    & (Join-Path $root 'scripts/bootstrap-dev.ps1')
    $go = Get-PinnedGo
    Invoke-CheckedNative -FilePath $go -Arguments @('mod', 'download')
    Invoke-CheckedNative -FilePath $go -Arguments @('tool', 'staticcheck', '-version')
    Invoke-CheckedNative -FilePath $go -Arguments @('tool', 'gosec', '-version')
    Invoke-CheckedNative -FilePath $go -Arguments @('tool', 'govulncheck', '-version')
}

function Invoke-Format {
    $gofmt = Get-PinnedGofmt
    $files = @(Get-ChildItem -LiteralPath (Join-Path $root 'cmd'), (Join-Path $root 'internal') -Recurse -Filter '*.go' -File | Select-Object -ExpandProperty FullName)
    if ($files.Count -ne 0) {
        Invoke-CheckedNative -FilePath $gofmt -Arguments (@('-w') + $files)
    }
}

function Invoke-FormatCheck {
    $gofmt = Get-PinnedGofmt
    $files = @(Get-ChildItem -LiteralPath (Join-Path $root 'cmd'), (Join-Path $root 'internal') -Recurse -Filter '*.go' -File | Select-Object -ExpandProperty FullName)
    if ($files.Count -eq 0) {
        return
    }
    $unformatted = @(Invoke-CheckedNative -FilePath $gofmt -Arguments (@('-l') + $files))
    if ($unformatted.Count -ne 0) {
        throw "gofmt required: $($unformatted -join ', ')"
    }
}

function Invoke-GoTests {
    $go = Get-PinnedGo
    Invoke-CheckedNative -FilePath $go -Arguments @('test', './...')
}

function Invoke-PesterTests {
    $pesterPath = Join-Path $root '.tools/modules/Pester/6.0.0/Pester.psd1'
    Import-Module $pesterPath -Force
    $result = Invoke-Pester -Path (Join-Path $root 'tests/windows-pester') -Output Detailed -PassThru
    if ($result.Result -ne 'Passed' -or $result.TotalCount -eq 0) {
        throw "Pester failed or discovered no tests: $($result.Result)"
    }
}

function Invoke-Lint {
    $go = Get-PinnedGo
    Invoke-CheckedNative -FilePath $go -Arguments @('vet', './...')
    Invoke-CheckedNative -FilePath $go -Arguments @('tool', 'staticcheck', './...')
    Invoke-CheckedNative -FilePath $go -Arguments @('tool', 'gosec', './cmd/...', './internal/...')
    Invoke-CheckedNative -FilePath $go -Arguments @('tool', 'govulncheck', './...')
    $gitleaks = Join-Path $root ".tools/bin/gitleaks$suffix"
    $actionlint = Join-Path $root ".tools/bin/actionlint$suffix"
    Invoke-CheckedNative -FilePath $gitleaks -Arguments @('git', '--no-banner', '--redact', '.')
    Invoke-CheckedNative -FilePath $actionlint
    if (-not $windowsPlatform) {
        $shellcheck = Join-Path $root '.tools/bin/shellcheck'
        $shellFiles = @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.sh' -File | Select-Object -ExpandProperty FullName)
        if ($shellFiles.Count -ne 0) {
            Invoke-CheckedNative -FilePath $shellcheck -Arguments $shellFiles
        }
    }
}

function Invoke-GoBuildTarget {
    param(
        [Parameter(Mandatory)][string]$Go,
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string]$Ldflags
    )
    $names = @('GOOS', 'GOARCH', 'CGO_ENABLED')
    $prior = @{}
    foreach ($name in $names) {
        $item = Get-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        $prior[$name] = [pscustomobject]@{
            Exists = $null -ne $item
            Value = if ($item) { $item.Value } else { $null }
        }
    }
    try {
        $env:GOOS = $Target.GOOS
        $env:GOARCH = $Target.GOARCH
        $env:CGO_ENABLED = '0'
        $output = Join-Path $OutputRoot $Target.Output
        Invoke-CheckedNative -FilePath $Go -Arguments @(
            'build',
            '-trimpath',
            '-buildvcs=false',
            '-ldflags', $Ldflags,
            '-o', $output,
            $Target.Package
        )
    } finally {
        foreach ($name in $names) {
            if ($prior[$name].Exists) {
                Set-Item -LiteralPath "Env:$name" -Value $prior[$name].Value
            } else {
                Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
            }
        }
    }
}

function Write-BuildChecksums {
    param([Parameter(Mandatory)][string]$Directory)
    $lines = @(Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -ne 'SHA256SUMS' } | ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    } | Sort-Object)
    [System.IO.File]::WriteAllLines((Join-Path $Directory 'SHA256SUMS'), $lines, [System.Text.Encoding]::ASCII)
    return $lines
}

function Invoke-Build {
    $go = Get-PinnedGo
    $commitOutput = git rev-parse HEAD
    $commitExitCode = $LASTEXITCODE
    if ($commitExitCode -ne 0) { throw 'git rev-parse HEAD failed' }
    $commit = ($commitOutput -join [Environment]::NewLine).Trim()
    $epoch = 1782737960
    $buildDate = [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $ldflags = @(
        '-s',
        '-w',
        '-X', 'github.com/vsevo/home-gateway/internal/buildinfo.Version=0.0.0-p0',
        '-X', "github.com/vsevo/home-gateway/internal/buildinfo.Commit=$commit",
        '-X', "github.com/vsevo/home-gateway/internal/buildinfo.BuildDate=$buildDate"
    ) -join ' '
    $targets = @(
        [pscustomobject]@{ Output = 'routerd_linux_arm64'; GOOS = 'linux'; GOARCH = 'arm64'; Package = './cmd/routerd' },
        [pscustomobject]@{ Output = 'server-agent_linux_amd64'; GOOS = 'linux'; GOARCH = 'amd64'; Package = './cmd/server-agent' },
        [pscustomobject]@{ Output = 'cisco-discovery_windows_amd64.exe'; GOOS = 'windows'; GOARCH = 'amd64'; Package = './cmd/cisco-discovery' },
        [pscustomobject]@{ Output = 'hgctl_windows_amd64.exe'; GOOS = 'windows'; GOARCH = 'amd64'; Package = './cmd/hgctl' }
    )
    $temporaryRoot = Join-Path $root 'tmp'
    $runId = [guid]::NewGuid().ToString('N')
    $runOne = Join-Path $temporaryRoot "build-run-1-$runId"
    $runTwo = Join-Path $temporaryRoot "build-run-2-$runId"
    New-Item -ItemType Directory -Force -Path $runOne, $runTwo | Out-Null
    foreach ($target in $targets) {
        Invoke-GoBuildTarget -Go $go -Target $target -OutputRoot $runOne -Ldflags $ldflags
        Invoke-GoBuildTarget -Go $go -Target $target -OutputRoot $runTwo -Ldflags $ldflags
    }
    $hashesOne = @(Write-BuildChecksums -Directory $runOne)
    $hashesTwo = @(Write-BuildChecksums -Directory $runTwo)
    if (($hashesOne -join "`n") -ne ($hashesTwo -join "`n")) {
        throw "Reproducible build mismatch; retained $runOne and $runTwo"
    }
    $build = Join-Path $root 'build'
    Remove-Item -LiteralPath $build -Recurse -Force -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $runOne -Destination $build
    if (Test-Path -LiteralPath $runTwo) {
        Remove-Item -LiteralPath $runTwo -Recurse -Force
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        $remainingTemporaryItems = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -ErrorAction SilentlyContinue)
        if ($remainingTemporaryItems.Count -eq 0) {
            Remove-Item -LiteralPath $temporaryRoot -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-Verify {
    Invoke-BootstrapCommand
    Invoke-FormatCheck
    Invoke-GoTests
    Invoke-PesterTests
    Invoke-Lint
    Invoke-Build
    & (Join-Path $root 'scripts/check-governance.ps1')
    & (Join-Path $root 'tests/bootstrap/Governance.Smoke.ps1')
    & (Join-Path $root 'tests/bootstrap/GovernanceChecker.Smoke.ps1')
    & (Join-Path $root 'tests/bootstrap/ToolchainLock.Smoke.ps1')
}

switch ($Command) {
    'bootstrap' { Invoke-BootstrapCommand }
    'format' { Invoke-Format }
    'format-check' { Invoke-FormatCheck }
    'test' { Invoke-GoTests }
    'lint' { Invoke-Lint }
    'build' { Invoke-Build }
    'pester' { Invoke-PesterTests }
    'verify' { Invoke-Verify }
}
