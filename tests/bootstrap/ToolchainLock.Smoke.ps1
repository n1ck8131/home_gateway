$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$lockPath = Join-Path $root 'manifest/versions.lock.yaml'
if (-not (Test-Path -LiteralPath $lockPath)) {
    throw 'versions lock missing'
}
$raw = Get-Content -LiteralPath $lockPath -Raw
$lock = $raw | ConvertFrom-Json
if ($lock.schema_version -ne 1) {
    throw 'unexpected lock schema'
}
$latestCount = ([regex]::Matches($raw, '(?i)latest')).Count
if ($lock.amnezia_self_hosted_p3.server_image_pin_state -ne 'observed-after-install' -or $lock.amnezia_self_hosted_p3.server_image_note -notmatch 'amneziavpn/amneziawg-go:latest' -or $latestCount -ne 1) {
    throw 'versions lock contains an unapproved mutable image reference'
}
$requiredArtifacts = @(
    'go_windows_amd64', 'go_linux_amd64',
    'powershell_windows_amd64', 'powershell_linux_amd64', 'pester',
    'gitleaks_windows_amd64', 'gitleaks_linux_amd64',
    'shellcheck_linux_amd64',
    'actionlint_windows_amd64', 'actionlint_linux_amd64',
    'openwrt_sdk', 'openwrt_factory', 'openwrt_sysupgrade',
    'openwrt_qemu', 'openwrt_qemu_dnsmasq_full', 'openwrt_qemu_ip_full',
    'openwrt_qemu_libnetfilter_conntrack3', 'openwrt_qemu_libnettle8',
    'openwrt_qemu_libbpf1', 'openwrt_qemu_libelf1',
    'openwrt_qemu_libgmp10', 'openwrt_qemu_libnfnetlink0',
    'openwrt_qemu_kmod_nf_conntrack_netlink',
    'awg_kernel_source', 'awg_tools_source', 'awg_go_source',
    'awg_openwrt_adapter_source'
)
$actualArtifacts = @($lock.artifacts.PSObject.Properties.Name | Sort-Object)
if (($actualArtifacts -join ',') -ne (($requiredArtifacts | Sort-Object) -join ',')) {
    throw 'artifact key set mismatch'
}
$requiredActions = @('checkout', 'setup_go', 'upload_artifact')
if ((@($lock.actions.PSObject.Properties.Name | Sort-Object) -join ',') -ne (($requiredActions | Sort-Object) -join ',')) {
    throw 'action key set mismatch'
}
foreach ($action in $lock.actions.PSObject.Properties.Value) {
    if ($action -notmatch '^[^@]+@[0-9a-f]{40}$') {
        throw "mutable or invalid action pin: $action"
    }
}
$requiredModules = @('gosec', 'govulncheck', 'staticcheck')
if ((@($lock.go_modules.PSObject.Properties.Name | Sort-Object) -join ',') -ne (($requiredModules | Sort-Object) -join ',')) {
    throw 'Go tool key set mismatch'
}
$expectedChecksums = @()
foreach ($property in $lock.artifacts.PSObject.Properties) {
    $artifact = $property.Value
    if ($artifact.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "invalid sha256 for $($artifact.url)"
    }
    if ($artifact.url -notmatch '^https://') {
        throw "non-HTTPS artifact $($artifact.url)"
    }
    $filename = if ($artifact.filename) {
        $artifact.filename
    } else {
        ([Uri]$artifact.url).Segments[-1]
    }
    $expectedChecksums += "$($artifact.sha256)  $filename"
}
$client = $lock.amnezia_self_hosted_p3.client
if ($client.sha256 -notmatch '^[0-9a-f]{64}$' -or $client.windows_x64_url -notmatch '^https://') {
    throw 'invalid self-hosted P3 client artifact'
}
$clientFilename = ([Uri]$client.windows_x64_url).Segments[-1]
$expectedChecksums += "$($client.sha256)  $clientFilename"
$checksumPath = Join-Path $root 'manifest/checksums.lock'
if (-not (Test-Path -LiteralPath $checksumPath)) {
    throw 'checksums lock missing'
}
$actualChecksums = @(Get-Content -LiteralPath $checksumPath | Where-Object { $_ } | Sort-Object)
if (($actualChecksums -join "`n") -ne (($expectedChecksums | Sort-Object) -join "`n")) {
    throw 'checksums lock differs from versions lock'
}
'TOOLCHAIN_LOCK_SMOKE_PASS'
