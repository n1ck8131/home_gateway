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
    '.gitignore'
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
