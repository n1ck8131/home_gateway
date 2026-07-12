BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Kernel = Get-Content -LiteralPath (Join-Path $script:Root 'packaging/openwrt-awg2/kmod-amneziawg/Makefile') -Raw
    $script:Tools = Get-Content -LiteralPath (Join-Path $script:Root 'packaging/openwrt-awg2/amneziawg-tools/Makefile') -Raw
    $script:Helper = Get-Content -LiteralPath (Join-Path $script:Root 'packaging/openwrt-awg2/amneziawg-tools/files/amneziawg.sh') -Raw
    $script:Build = Get-Content -LiteralPath (Join-Path $script:Root 'scripts/openwrt/build-packages.sh') -Raw
}

Describe 'pinned AWG2 OpenWrt packages' {
    It 'pins official kernel and tools source versions and hashes' {
        $script:Kernel | Should -Match 'PKG_VERSION:=1\.0\.20260611'
        $script:Kernel | Should -Match 'PKG_HASH:=e062ecc9f1d89eeafa9f56a29473372a1d796ee061eaa8c7b61eeb51c38b80d6'
        $script:Tools | Should -Match 'PKG_VERSION:=1\.0\.20260618-2'
        $script:Tools | Should -Match 'PKG_HASH:=cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10'
        "$script:Kernel`n$script:Tools`n$script:Build" | Should -Not -Match '(?i)latest'
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
        $script:Build | Should -Match 'adbdump'
    }
}
