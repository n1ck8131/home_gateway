$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$required = @(
    'SPEC.md',
    'PLAN.md',
    'README.md',
    'STATUS.md',
    'DECISIONS.md',
    '.editorconfig',
    '.gitattributes',
    '.gitignore',
    'docs/SECURITY.md',
    'docs/COMPATIBILITY.md',
    'docs/ACCEPTANCE_MATRIX.md',
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
$missing = @($required | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $root $_))
})
if ($missing.Count -ne 0) {
    throw "Missing governance files: $($missing -join ', ')"
}
if ((Get-Content -LiteralPath (Join-Path $root 'STATUS.md') -Raw) -notmatch 'Current phase: P0') {
    throw 'STATUS.md must identify P0'
}
'GOVERNANCE_SMOKE_PASS'
