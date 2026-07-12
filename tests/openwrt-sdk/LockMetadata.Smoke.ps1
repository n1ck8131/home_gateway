$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$lock = Get-Content (Join-Path $root 'manifest/versions.lock.yaml') -Raw | ConvertFrom-Json

if ($lock.openwrt.version -ne '25.12.5') { throw 'wrong OpenWrt version' }
if ($lock.openwrt.target -ne 'mediatek/filogic') { throw 'wrong target' }
if ($lock.openwrt.profile -ne 'glinet_gl-mt6000') { throw 'wrong profile' }
if ($lock.openwrt.package_arch -ne 'aarch64_cortex-a53') { throw 'wrong package arch' }
if ($lock.openwrt.kernel_vermagic -ne '5a6c1f71be683ae9980b15d3ce73e24d') { throw 'wrong vermagic' }
if (-not (Test-Path (Join-Path $root 'scripts/openwrt/fetch-sdk.sh'))) { throw 'fetch script missing' }

'OPENWRT_LOCK_METADATA_PASS'
