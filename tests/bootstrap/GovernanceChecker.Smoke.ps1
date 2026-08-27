$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$checker = Join-Path $root 'scripts/check-governance.ps1'
if (-not (Test-Path -LiteralPath $checker)) {
    throw 'scripts/check-governance.ps1 missing'
}

try {
    $powerShellExecutable = (Get-Process -Id $PID -ErrorAction Stop).Path
} catch {
    throw "Unable to resolve the current PowerShell executable: $($_.Exception.Message)"
}
if ([string]::IsNullOrWhiteSpace($powerShellExecutable) -or -not (Test-Path -LiteralPath $powerShellExecutable -PathType Leaf)) {
    throw "Current PowerShell executable is not a file: $powerShellExecutable"
}

$adrPaths = @(
    'docs/adr/ADR-0001-supported-platform.md',
    'docs/adr/ADR-0002-vpn-transports.md',
    'docs/adr/ADR-0003-routing-ownership-and-marks.md',
    'docs/adr/ADR-0004-dns-and-precedence.md',
    'docs/adr/ADR-0005-transaction-model.md',
    'docs/adr/ADR-0006-state-secrets-backup.md',
    'docs/adr/ADR-0007-mobile-peer-lifecycle.md',
    'docs/adr/ADR-0008-cisco-discovery.md',
    'docs/adr/ADR-0009-supply-chain-signing.md',
    'docs/adr/ADR-0010-dnsmasq-domain-match-capability.md',
    'docs/adr/ADR-0011-pc-first-platform-tunnel-boundary.md'
)
$encoding = New-Object System.Text.UTF8Encoding($false)
$sectionSign = [char]0x00A7
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("home-gateway-governance-$([guid]::NewGuid().ToString('N'))")
$validRoot = Join-Path $tempRoot 'valid'

function Set-FixtureFile {
    param(
        [Parameter(Mandatory)][string]$FixtureRoot,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Content
    )
    $path = Join-Path $FixtureRoot $RelativePath
    $directory = Split-Path -Parent $path
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    [System.IO.File]::WriteAllText($path, $Content, $encoding)
}

function New-DefectCase {
    param([Parameter(Mandatory)][string]$Name)
    $caseRoot = Join-Path $tempRoot $Name
    Copy-Item -LiteralPath $validRoot -Destination $caseRoot -Recurse
    return $caseRoot
}

function Assert-CheckerFailure {
    param(
        [Parameter(Mandatory)][string]$FixtureRoot,
        [Parameter(Mandatory)][string[]]$ExpectedDiagnostics
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $checker -Root $FixtureRoot 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -eq 0) {
        throw "Expected governance checker failure for $FixtureRoot"
    }
    $text = $output -join "`n"
    foreach ($diagnostic in $ExpectedDiagnostics) {
        if ($text -notmatch [regex]::Escape($diagnostic)) {
            throw "Missing diagnostic '$diagnostic' for $FixtureRoot. Output: $text"
        }
    }
}

try {
    New-Item -ItemType Directory -Force -Path $validRoot | Out-Null
    foreach ($name in @('SPEC.md', 'PLAN.md', 'STATUS.md', 'docs/SECURITY.md', 'docs/COMPATIBILITY.md')) {
        Set-FixtureFile -FixtureRoot $validRoot -RelativePath $name -Content "valid`n"
    }
    $decisionLines = @('# Architecture Decisions', '')
    foreach ($relativePath in $adrPaths) {
        $filename = Split-Path -Leaf $relativePath
        $decisionLines += "- [$filename]($relativePath)"
        Set-FixtureFile -FixtureRoot $validRoot -RelativePath $relativePath -Content "# $filename`n`nStatus: Accepted`n`n## Context`n`nComplete.`n"
    }
    Set-FixtureFile -FixtureRoot $validRoot -RelativePath 'DECISIONS.md' -Content (($decisionLines -join "`n") + "`n")
    $matrix = (1..8 | ForEach-Object { "## ${sectionSign}30.$_ Evidence`n`n| Requirement | Owner phase | Evidence type |`n|---|---|---|`n| Fixture | P$_ | automated |" }) -join "`n`n"
    Set-FixtureFile -FixtureRoot $validRoot -RelativePath 'docs/ACCEPTANCE_MATRIX.md' -Content ($matrix + "`n")
    $p3Lock = @{ amnezia_self_hosted_p3 = @{ client = @{ tag = '5.0.1.5'; commit = '7d4f3e0f5090b74903609179653d1f669d2ad08a'; size = 91991200; sha256 = '2e898bbd1d639f5066416961a2a458dba7c3455c0e8f49c7f130e9281d700377' }; amneziawg_go = @{ tag = 'v3.1.20260814'; commit = '1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1' }; amneziawg_tools = @{ tag = 'v3.1.20260812'; commit = 'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843' }; amneziawg_linux_kernel_module = @{ tag = 'v3.1.20260812'; commit = '46803204e7ec3b068199cd671143bec661d3fe21' }; server_image_pin_state = 'observed-after-install' } } | ConvertTo-Json -Depth 8
    Set-FixtureFile -FixtureRoot $validRoot -RelativePath 'manifest/versions.lock.yaml' -Content $p3Lock

    $validOutput = @(& $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $checker -Root $validRoot 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($validOutput -join "`n") -notmatch 'GOVERNANCE_CHECK_PASS') {
        throw "Valid fixture rejected: $($validOutput -join "`n")"
    }

    $missingAdr = New-DefectCase -Name 'missing-adr'
    Remove-Item -LiteralPath (Join-Path $missingAdr $adrPaths[0]) -Force
    Assert-CheckerFailure -FixtureRoot $missingAdr -ExpectedDiagnostics @(
        "missing required path: $($adrPaths[0])"
    )

    $placeholder = New-DefectCase -Name 'placeholder'
    Add-Content -LiteralPath (Join-Path $placeholder $adrPaths[1]) -Value "`nTODO"
    Assert-CheckerFailure -FixtureRoot $placeholder -ExpectedDiagnostics @(
        "accepted ADR contains placeholder: $($adrPaths[1])"
    )

    $brokenLink = New-DefectCase -Name 'broken-link'
    $brokenDecisions = (Get-Content -LiteralPath (Join-Path $brokenLink 'DECISIONS.md') -Raw).Replace(
        (Split-Path -Leaf $adrPaths[2]),
        'broken-adr-link.md'
    )
    Set-FixtureFile -FixtureRoot $brokenLink -RelativePath 'DECISIONS.md' -Content $brokenDecisions
    Assert-CheckerFailure -FixtureRoot $brokenLink -ExpectedDiagnostics @(
        "DECISIONS.md missing link: $(Split-Path -Leaf $adrPaths[2])"
    )

    $missingRow = New-DefectCase -Name 'missing-section'
    $matrixPath = Join-Path $missingRow 'docs/ACCEPTANCE_MATRIX.md'
    $missingMatrix = (Get-Content -LiteralPath $matrixPath -Raw -Encoding UTF8).Replace("## ${sectionSign}30.4 Evidence", '### Removed section 30.4')
    Set-FixtureFile -FixtureRoot $missingRow -RelativePath 'docs/ACCEPTANCE_MATRIX.md' -Content $missingMatrix
    Assert-CheckerFailure -FixtureRoot $missingRow -ExpectedDiagnostics @(
        "ACCEPTANCE_MATRIX.md missing heading: ${sectionSign}30.4"
    )

    $aggregate = New-DefectCase -Name 'aggregate'
    Remove-Item -LiteralPath (Join-Path $aggregate $adrPaths[3]) -Force
    Add-Content -LiteralPath (Join-Path $aggregate $adrPaths[4]) -Value "`nPLACEHOLDER"
    Assert-CheckerFailure -FixtureRoot $aggregate -ExpectedDiagnostics @(
        "missing required path: $($adrPaths[3])",
        "accepted ADR contains placeholder: $($adrPaths[4])"
    )

    $repositoryOutput = @(& $powerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $checker -Root $root 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($repositoryOutput -join "`n") -notmatch 'GOVERNANCE_CHECK_PASS') {
        throw "Real repository governance rejected: $($repositoryOutput -join "`n")"
    }

    $lock = Get-Content -LiteralPath (Join-Path $root 'manifest/versions.lock.yaml') -Raw -Encoding UTF8
    foreach ($requiredPin in @(
        '"amnezia_self_hosted_p3"',
        '"tag": "5.0.1.5"',
        '"server_image_pin_state": "observed-after-install"',
        'v3.1.20260814',
        'v3.1.20260812'
    )) {
        if ($lock -notmatch [regex]::Escape($requiredPin)) {
            throw "Self-hosted P3 lock missing: $requiredPin"
        }
    }
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

'GOVERNANCE_CHECKER_SMOKE_PASS'
