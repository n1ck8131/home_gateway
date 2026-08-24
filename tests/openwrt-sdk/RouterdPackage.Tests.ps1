BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Package = Get-Content -LiteralPath (Join-Path $script:Root 'packaging/openwrt-apk/routerd/Makefile') -Raw
    $script:Init = Get-Content -LiteralPath (Join-Path $script:Root 'packaging/openwrt-apk/routerd/files/routerd.init') -Raw
    $script:Build = Get-Content -LiteralPath (Join-Path $script:Root 'scripts/openwrt/build-packages.sh') -Raw
    $script:Lifecycle = Get-Content -LiteralPath (Join-Path $script:Root 'tests/openwrt-sdk/assert-routerd-lifecycle.sh') -Raw
    $script:Workflow = Get-Content -LiteralPath (Join-Path $script:Root '.github/workflows/openwrt-sdk.yml') -Raw
    $script:Lock = Get-Content -LiteralPath (Join-Path $script:Root 'manifest/versions.lock.yaml') -Raw | ConvertFrom-Json
}

Describe 'routerd OpenWrt APK contract' {
    It 'locks the exact package identity without trusting pending evidence' {
        $script:Lock.schema_version | Should -Be 1
        $script:Lock.routerd.version | Should -Be '0.3.4'
        $script:Lock.routerd.release | Should -Be 2
        $script:Lock.routerd.go_version | Should -Be '1.26.6'
        $script:Lock.routerd.package_arch | Should -Be 'aarch64_cortex-a53'
        $script:Lock.routerd.artifact.filename | Should -Be 'routerd_0.3.4_aarch64_cortex-a53.apk'
        $script:Lock.routerd.artifact.sha256 | Should -Be 'b44a00d78849b697b29d2645fe3095bbf8de921777f62d7542d596191d108ee4'
        $script:Lock.routerd.lifecycle_r1.filename | Should -Be 'routerd-0.3.4-r1.apk'
        $script:Lock.routerd.lifecycle_r1.sha256 | Should -Be '4b06ec4b46968aa92a1911effd3da1c0e6cccd473c82b9e1b028ccd7f94b2c01'

        $script:Package | Should -Match '(?m)^PKG_NAME:=routerd$'
        $script:Package | Should -Match '(?m)^PKG_VERSION:=0\.3\.4$'
        $script:Package | Should -Match '(?m)^ROUTERD_PACKAGE_RELEASE\?=2$'
        $script:Package | Should -Match 'ifeq \(\$\(ROUTERD_PACKAGE_RELEASE\),1\)'
        $script:Package | Should -Match 'else ifeq \(\$\(ROUTERD_PACKAGE_RELEASE\),2\)'
        $script:Package | Should -Match 'ROUTERD_PACKAGE_RELEASE must be 1 or 2'
        $script:Package | Should -Match '(?m)^PKG_RELEASE:=\$\(ROUTERD_PACKAGE_RELEASE\)$'
        $script:Build | Should -Match "jq -er '\.routerd\.artifact\.sha256'"
        $script:Build | Should -Match "jq -er '\.routerd\.lifecycle_r1\.sha256'"
        $script:Build | Should -Match 'routerd_apk_sha256" != "\$locked_routerd_artifact_sha256'
        $script:Build | Should -Match 'routerd_lifecycle_r1_sha256" != "\$locked_routerd_lifecycle_r1_sha256'
        $script:Build | Should -Match 'routerd r2 APK SHA256 differs from manifest lock'
        $script:Build | Should -Match 'routerd r1 lifecycle APK SHA256 differs from manifest lock'
        $script:Lifecycle | Should -Not -Match 'PENDING_BUILD_EVIDENCE'
        ($script:Lock | ConvertTo-Json -Depth 8) | Should -Not -Match 'PENDING_BUILD_EVIDENCE'
    }

    It 'installs only the service binary and procd init entry' {
        $script:Package | Should -Match '\$\(INSTALL_BIN\) ./files/routerd \$\(1\)/usr/bin/routerd'
        $script:Package | Should -Match '\$\(INSTALL_BIN\) ./files/routerd\.init \$\(1\)/etc/init\.d/routerd'
        $script:Package | Should -Not -Match 'Package/routerd/conffiles'
        $script:Package | Should -Not -Match '/etc/config'
        $script:Package | Should -Not -Match '/etc/routerd'
        $script:Build | Should -Match "routerd_payload_files"
        $script:Build | Should -Match "etc/init\.d/routerd"
        $script:Build | Should -Match "usr/bin/routerd"
        $script:Build | Should -Not -Match "etc/config/routerd"
        $script:Package | Should -Not -Match "etc/routerd/dataplane"
    }

    It 'uses a fixed late procd service definition with no network mutation' {
        $script:Init | Should -Match '(?m)^#!/bin/sh /etc/rc\.common$'
        $script:Init | Should -Match '(?m)^USE_PROCD=1$'
        $script:Init | Should -Match '(?m)^START=95$'
        $script:Init | Should -Match '(?m)^STOP=05$'
        $script:Init | Should -Match '(?m)^PROG=/usr/bin/routerd$'
        $script:Init | Should -Match 'procd_set_param command "\$PROG" run'
        $script:Init | Should -Match 'procd_set_param respawn 3600 5 5'
        $script:Init | Should -Match 'procd_set_param term_timeout 15'
        $script:Init | Should -Not -Match '(?i)\b(eval|uci|ubus|ifup|ifdown|nft|iptables|dnsmasq|firewall)\b'
        $script:Init | Should -Not -Match '\$\{?[1-9@*]'
        $script:Init | Should -Not -Match '`'
    }

    It 'cross-builds a deterministic static arm64 binary from pinned Go' {
        $script:Build | Should -Match '\.routerd\.go_version'
        $script:Build | Should -Match 'env GOVERSION'
        $script:Build | Should -Match 'GOTOOLCHAIN=local'
        $script:Build | Should -Match 'realpath -e -- "\$artifacts_root"'
        $script:Build | Should -Match 'realpath -ms -- "\$requested_output_dir"'
        $script:Build | Should -Match 'realpath -m -- "\$requested_output_dir"'
        $script:Build | Should -Match 'OUTPUT_DIR must not contain symlinks or redirected path components'
        $script:Build | Should -Match 'OUTPUT_DIR must resolve to a child of repository artifacts'
        $script:Build | Should -Match 'repository cache directory must not be a symlink'
        $script:Build | Should -Match 'mktemp -d "\$cache_root/routerd-package\.XXXXXX"'
        $script:Build | Should -Match 'resolved_cleanup_path="\$\(realpath -e -- "\$cleanup_path"\)"'
        $script:Build | Should -Match 'refusing redirected package cleanup path'
        $script:Build | Should -Match 'CGO_ENABLED=0 GOOS=linux GOARCH=arm64'
        $script:Build | Should -Match '-trimpath'
        $script:Build | Should -Match '-buildvcs=false'
        $script:Build | Should -Match '-buildid='
        $script:Build | Should -Match 'internal/buildinfo\.Version=\$routerd_version'
        $script:Build | Should -Match 'internal/buildinfo\.Commit=sha256:\$routerd_source_digest'
        $script:Build | Should -Match 'internal/buildinfo\.BuildDate=\$routerd_build_date'
        $script:Build | Should -Match 'list -deps -json ./cmd/routerd'
        $script:Build | Should -Match 'readelf -lW'
        $script:Build | Should -Match 'readelf -dW'
        $script:Build | Should -Match '(?m)^: > "\$sdk/\.config"$'
        $script:Build | Should -Match "'# CONFIG_ALL is not set'"
        $script:Build | Should -Match "'# CONFIG_ALL_KMODS is not set'"
        $script:Build | Should -Match "'# CONFIG_ALL_NONSHARED is not set'"
        $script:Build | Should -Not -Match '(?m)^touch "\$sdk/\.config"$'
        $script:Build | Should -Not -Match 'git rev-parse'
    }

    It 'builds r1 only for lifecycle evidence and publishes exact r2 metadata' {
        $script:Build | Should -Match 'ROUTERD_PACKAGE_RELEASE=1'
        $script:Build | Should -Match 'routerd-0\.3\.4-r1\.apk'
        $script:Build | Should -Match 'ROUTERD_PACKAGE_RELEASE=2'
        $script:Build | Should -Match 'routerd-0\.3\.4-r2\.apk'
        $script:Build | Should -Match "require_apk_info_field version '0\.3\.4-r2'"
        $script:Build | Should -Match 'require_apk_info_field arch "\$architecture"'
        $script:Build | Should -Match 'require_no_dependencies'
        $script:Build | Should -Match 'require_routerd_maintainer_scripts'
        $script:Build | Should -Match '\.scripts\["post-install"\]'
        $script:Build | Should -Match 'default_postinst'
        $script:Build | Should -Match 'default_prerm'
        $script:Build | Should -Match 'assert-routerd-lifecycle\.sh'
        $script:Build | Should -Match 'routerd_0\.3\.4_aarch64_cortex-a53\.apk'
        $script:Build | Should -Match 'lifecycle_output="\$output_dir/lifecycle"'
        $script:Build | Should -Match 'routerd_lifecycle_r1_name'
        $script:Build | Should -Match '\(cd "\$lifecycle_output" && sha256sum'
    }

    It 'confines offline lifecycle operations to one guarded temporary root' {
        $script:Lifecycle | Should -Match 'mktemp -d'
        $script:Lifecycle | Should -Match 'routerd-apk-lifecycle\.XXXXXX'
        $script:Lifecycle | Should -Match '--root "\$lifecycle_root"'
        $script:Lifecycle | Should -Match 'if \[ "\$\(id -u\)" -ne 0 \]'
        $script:Lifecycle | Should -Match 'set -- --usermode "\$@"'
        $script:Lifecycle | Should -Match '--no-network'
        $script:Lifecycle | Should -Match '--no-scripts'
        $script:Lifecycle | Should -Match '--repositories-file'
        $script:Lifecycle | Should -Match 'printf ''%s\\n'' ''config routerd "lifecycle"'''
        $script:Lifecycle | Should -Match 'lifecycle-state\.json'
        $script:Lifecycle | Should -Match 'printf ''%s\\n'' ''\{"revision":"state-fixture"\}'''
        $script:Lifecycle | Should -Match 'apk_run add'
        $script:Lifecycle | Should -Match 'apk_run add --upgrade'
        $script:Lifecycle | Should -Match 'apk_run del routerd'
        $script:Lifecycle | Should -Match 'refusing unsafe lifecycle cleanup path'
        $script:Lifecycle | Should -Match 'refusing redirected lifecycle cleanup path'
        $script:Lifecycle | Should -Not -Match 'rm -rf /etc'
    }

    It 'runs focused assertions in the pinned two-clean-tree workflow' {
        $script:Workflow | Should -Match 'RouterdPackage\.Tests\.ps1'
        $script:Workflow | Should -Match 'assert-routerd-lifecycle\.sh'
        $script:Workflow | Should -Match 'artifacts/openwrt-run1'
        $script:Workflow | Should -Match 'artifacts/openwrt-run2'
        $script:Workflow | Should -Match 'diff -ru --no-dereference artifacts/openwrt-run1 artifacts/openwrt-run2'
        $script:Workflow | Should -Match 'shellcheck -e SC2034 packaging/openwrt-apk/routerd/files/routerd\.init'
        $script:Workflow | Should -Match '(?m)^\s+artifacts/openwrt-run2\s*$'
        $script:Workflow | Should -Match 'if-no-files-found:\s*error'
        $script:Workflow | Should -Not -Match '(?m)uses:\s*[^\s]+@v\d+\s*$'
    }
}
