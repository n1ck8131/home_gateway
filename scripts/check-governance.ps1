param(
    [Parameter()][string]$Root
)

$ErrorActionPreference = 'Stop'

if (-not $Root) {
    $Root = Split-Path -Parent $PSScriptRoot
}
$Root = [System.IO.Path]::GetFullPath($Root)

$adrPaths = @(
    'docs/adr/ADR-0001-supported-platform.md',
    'docs/adr/ADR-0002-vpn-transports.md',
    'docs/adr/ADR-0003-routing-ownership-and-marks.md',
    'docs/adr/ADR-0004-dns-and-precedence.md',
    'docs/adr/ADR-0005-transaction-model.md',
    'docs/adr/ADR-0006-state-secrets-backup.md',
    'docs/adr/ADR-0007-mobile-peer-lifecycle.md',
    'docs/adr/ADR-0008-cisco-discovery.md',
    'docs/adr/ADR-0009-supply-chain-signing.md'
)
$required = @(
    'SPEC.md',
    'PLAN.md',
    'STATUS.md',
    'DECISIONS.md',
    'docs/SECURITY.md',
    'docs/COMPATIBILITY.md',
    'docs/ACCEPTANCE_MATRIX.md'
) + $adrPaths

$errors = New-Object 'System.Collections.Generic.List[string]'
foreach ($relativePath in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root $relativePath))) {
        $errors.Add("missing required path: $relativePath")
    }
}

foreach ($relativePath in $adrPaths) {
    $path = Join-Path $Root $relativePath
    if (-not (Test-Path -LiteralPath $path)) {
        continue
    }
    $raw = Get-Content -LiteralPath $path -Raw
    $accepted = $raw -match '(?mi)^Status:\s*Accepted\s*$'
    $hasPlaceholder = $raw -match '(?i)\b(TODO|TBD|PLACEHOLDER|FIXME|XXX)\b'
    if ($accepted -and $hasPlaceholder) {
        $errors.Add("accepted ADR contains placeholder: $relativePath")
    }
}

$decisionsPath = Join-Path $Root 'DECISIONS.md'
if (Test-Path -LiteralPath $decisionsPath) {
    $decisions = Get-Content -LiteralPath $decisionsPath -Raw
    foreach ($relativePath in $adrPaths) {
        $filename = Split-Path -Leaf $relativePath
        if ($decisions -notmatch [regex]::Escape($filename)) {
            $errors.Add("DECISIONS.md missing link: $filename")
        }
    }
}

$matrixPath = Join-Path $Root 'docs/ACCEPTANCE_MATRIX.md'
if (Test-Path -LiteralPath $matrixPath) {
    $matrix = Get-Content -LiteralPath $matrixPath -Raw
    foreach ($section in 1..8) {
        $heading = "§30.$section"
        $pattern = '(?m)^##\s+' + [regex]::Escape($heading) + '(\s|$)'
        if ($matrix -notmatch $pattern) {
            $errors.Add("ACCEPTANCE_MATRIX.md missing heading: $heading")
        }
    }
}

if ($errors.Count -ne 0) {
    foreach ($message in $errors) {
        [Console]::Error.WriteLine($message)
    }
    exit 1
}

'GOVERNANCE_CHECK_PASS'
