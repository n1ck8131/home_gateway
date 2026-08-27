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
    'docs/adr/ADR-0009-supply-chain-signing.md',
    'docs/adr/ADR-0010-dnsmasq-domain-match-capability.md',
    'docs/adr/ADR-0011-pc-first-platform-tunnel-boundary.md'
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

$versionsPath = Join-Path $Root 'manifest/versions.lock.yaml'
if (-not (Test-Path -LiteralPath $versionsPath)) {
    $errors.Add('missing required path: manifest/versions.lock.yaml')
} else {
    try {
        $versions = Get-Content -LiteralPath $versionsPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $p3 = $versions.amnezia_self_hosted_p3
        if ($null -eq $p3 -or $p3.client.tag -ne '5.0.1.5' -or $p3.client.commit -ne '7d4f3e0f5090b74903609179653d1f669d2ad08a' -or $p3.client.windows_x64_url -ne 'https://github.com/amnezia-vpn/amnezia-client/releases/download/5.0.1.5/AmneziaVPN_5.0.1.5_windows_x64.exe' -or $p3.client.size -ne 91991200 -or $p3.client.sha256 -ne '2e898bbd1d639f5066416961a2a458dba7c3455c0e8f49c7f130e9281d700377' -or $p3.server_image_pin_state -ne 'observed-after-install' -or $p3.amneziawg_go.tag -ne 'v3.1.20260814' -or $p3.amneziawg_go.commit -ne '1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1' -or $p3.amneziawg_tools.tag -ne 'v3.1.20260812' -or $p3.amneziawg_tools.commit -ne 'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843' -or $p3.amneziawg_linux_kernel_module.tag -ne 'v3.1.20260812' -or $p3.amneziawg_linux_kernel_module.commit -ne '46803204e7ec3b068199cd671143bec661d3fe21') {
            $errors.Add('invalid self-hosted P3 Amnezia lock')
        }
    } catch {
        $errors.Add('invalid manifest/versions.lock.yaml')
    }
}

foreach ($relativePath in $adrPaths) {
    $path = Join-Path $Root $relativePath
    if (-not (Test-Path -LiteralPath $path)) {
        continue
    }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    $accepted = $raw -match '(?mi)^Status:\s*Accepted\s*$'
    $hasPlaceholder = $raw -match '(?i)\b(TODO|TBD|PLACEHOLDER|FIXME|XXX)\b'
    if ($accepted -and $hasPlaceholder) {
        $errors.Add("accepted ADR contains placeholder: $relativePath")
    }
}

$decisionsPath = Join-Path $Root 'DECISIONS.md'
if (Test-Path -LiteralPath $decisionsPath) {
    $decisions = Get-Content -LiteralPath $decisionsPath -Raw -Encoding UTF8
    foreach ($relativePath in $adrPaths) {
        $filename = Split-Path -Leaf $relativePath
        if ($decisions -notmatch [regex]::Escape($filename)) {
            $errors.Add("DECISIONS.md missing link: $filename")
        }
    }
}

$matrixPath = Join-Path $Root 'docs/ACCEPTANCE_MATRIX.md'
if (Test-Path -LiteralPath $matrixPath) {
    $matrix = Get-Content -LiteralPath $matrixPath -Raw -Encoding UTF8
    foreach ($section in 1..8) {
        $heading = "$([char]0x00A7)30.$section"
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
