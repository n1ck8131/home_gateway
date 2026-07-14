#!/bin/sh
set -eu

phase="${1:-}"
case "$phase" in
    phase1|phase2) ;;
    *) printf 'usage: %s phase1|phase2\n' "$0" >&2; exit 2 ;;
esac

root=/root/routerd-p2
driver="$root/lab-driver"
evidence="$root/evidence"
journal=/etc/routerd/dataplane/journal.json
revision_root=/etc/routerd/dataplane/revisions
firewall_include=/usr/share/nftables.d/ruleset-post/50-routerd.nft
dns_include=/tmp/dnsmasq.d/routerd.conf
mkdir -p "$evidence"

fail() {
    printf 'QEMU_GUEST_FAIL: %s\n' "$*" >&2
    exit 1
}

ensure_real_directory() {
    path="$1"
    mode="$2"
    if [ -L "$path" ]; then
        fail "$path must not be a symlink"
    fi
    if [ -e "$path" ]; then
        [ -d "$path" ] || fail "$path is not a directory"
    else
        mkdir -p "$path" || fail "could not create $path"
    fi
    chmod "$mode" "$path" || fail "could not set mode $mode on $path"
    if [ ! -d "$path" ] || [ -L "$path" ]; then
        fail "$path is not a real directory"
    fi
}

journal_value() {
    jsonfilter -i "$journal" -e "@$1"
}

assert_journal() {
    expected_state="$1"
    expected_active="$2"
    [ "$(journal_value .state)" = "$expected_state" ] || fail "journal state is not $expected_state"
    [ "$(journal_value .active_revision)" = "$expected_active" ] || fail "active revision is not $expected_active"
}

record_runtime() {
    label="$1"
    nft list table inet routerd >"$evidence/$label.nft"
    ip -4 rule show >"$evidence/$label.ipv4-rules"
    ip -4 route show table all >"$evidence/$label.ipv4-routes"
    ip -6 rule show >"$evidence/$label.ipv6-rules"
    ip -6 route show table all >"$evidence/$label.ipv6-routes"
    fw4 print >"$evidence/$label.fw4" 2>&1
    cp "$journal" "$evidence/$label.journal.json"
}

expect_apply_failure() {
    fault="$1"
    revision="$2"
    before="$(sha256sum "$journal" | awk '{print $1}')"
    if "$driver" apply --runtime openwrt --revision "$revision" --available=false --fault "$fault" \
        >"$evidence/$revision.stdout" 2>"$evidence/$revision.stderr"; then
        fail "$fault apply unexpectedly succeeded"
    fi
    after="$(sha256sum "$journal" | awk '{print $1}')"
    [ "$before" = "$after" ] || fail "$fault changed the committed journal"
    assert_journal committed qemu-baseline
}

assert_identity() {
    # This file is provided by the pinned OpenWrt image.
    # shellcheck disable=SC1091
    . /etc/openwrt_release
    [ "$DISTRIB_RELEASE" = 25.12.5 ] || fail "unexpected OpenWrt release $DISTRIB_RELEASE"
    [ "$DISTRIB_REVISION" = r33051-f5dae5ece4 ] || fail "unexpected OpenWrt revision $DISTRIB_REVISION"
    [ "$DISTRIB_ARCH" = x86_64 ] || fail "unexpected OpenWrt architecture $DISTRIB_ARCH"
    [ "$(uname -r)" = 6.12.94 ] || fail "unexpected kernel $(uname -r)"
    for command in apk dnsmasq fw4 ip jsonfilter nft sha256sum; do
        command -v "$command" >/dev/null 2>&1 || fail "$command is missing"
    done
}

package_is_installed_exact() {
    apk info | grep -Fqx "$1"
}

assert_full_packages() {
    for package in \
        dnsmasq-full ip-full kmod-nf-conntrack-netlink libbpf1 libelf1 libgmp10 \
        libnetfilter-conntrack3 libnfnetlink0 libnettle8; do
        package_is_installed_exact "$package" || fail "$package is not installed"
    done
    if package_is_installed_exact dnsmasq; then
        fail "plain dnsmasq is installed alongside dnsmasq-full"
    fi
    dnsmasq --version | grep -qw nftset || fail "dnsmasq lacks nftset support"
}

active_route_artifact() {
    revision=$(journal_value .active_revision)
    case "$revision" in
        ''|*[!A-Za-z0-9_-]*) fail "active revision cannot select a route artifact" ;;
    esac
    artifact="$revision_root/$revision/routes.json"
    [ -s "$artifact" ] || fail "active route artifact is missing"
    printf '%s\n' "$artifact"
}

route_tables_from_artifact() {
    awk '
        /^[[:space:]]*"route",[[:space:]]*$/ { route_command = 1; next }
        route_command && /^[[:space:]]*"table",[[:space:]]*$/ {
            if (getline > 0) {
                gsub(/[",[:space:]]/, "")
                if ($0 ~ /^[0-9]+$/) print
            }
            route_command = 0
        }
    ' "$1" | sort -u
}

assert_runtime() {
    [ -s "$firewall_include" ] || fail "firewall include is missing"
    [ -s "$dns_include" ] || fail "DNS include is missing"
    nft list table inet routerd | grep -q 'managed-by-routerd' || fail "routerd nft ownership marker is missing"
    fw4_output="$evidence/assert-runtime.fw4"
    fw4 print >"$fw4_output" 2>&1 || fail "fw4 could not render the active ruleset"
    grep -Fq "$firewall_include" "$fw4_output" || fail "fw4 does not consume the routerd include"
    artifact=$(active_route_artifact)
    tables=$(route_tables_from_artifact "$artifact")
    [ "$tables" = 10001 ] || fail "active route artifact does not own canonical table 10001: $tables"
    ip -4 route show table "$tables" | grep -q '^blackhole default' || fail "IPv4 fail-closed route is missing"
    ip -6 route show table "$tables" | grep -q '^blackhole default' || fail "IPv6 fail-closed route is missing"
    dnsmasq --test --conf-file="$dns_include" >/dev/null 2>&1 || fail "active DNS include is invalid"
}

assert_identity
ensure_real_directory /usr/share/nftables.d 0755
ensure_real_directory /usr/share/nftables.d/ruleset-post 0755
ensure_real_directory /tmp/dnsmasq.d 0755

if [ "$phase" = phase1 ]; then
    package_is_installed_exact dnsmasq || fail "pinned base image lacks plain dnsmasq"
    sha256sum /etc/config/firewall /etc/config/dhcp >"$root/base-config.sha256"
    if ! (CDPATH='' cd "$root" && sha256sum -c qemu-apks.sha256) \
        >"$evidence/apk-checksums.txt" 2>&1; then
        cat "$evidence/apk-checksums.txt" >&2
        fail "uploaded package checksum verification failed"
    fi
    empty_repositories="$root/empty-repositories"
    : >"$empty_repositories"
    chmod 600 "$empty_repositories"
    if ! apk add --no-network --allow-untrusted --repositories-file "$empty_repositories" \
        "$root/dnsmasq-full-2.93-r1.apk" "$root/ip-full-6.18.0-r2.apk" \
        "$root/libnetfilter-conntrack3-1.1.0-r1.apk" "$root/libnettle8-3.10.2-r1.apk" \
        "$root/libbpf1-1.6.2-r1.apk" "$root/libelf1-0.192-r1.apk" \
        "$root/libgmp10-6.3.0-r2.apk" "$root/libnfnetlink0-1.0.2-r1.apk" \
        "$root/kmod-nf-conntrack-netlink-6.12.94-r1.apk" \
        >"$evidence/apk-install.stdout" 2>"$evidence/apk-install.stderr"; then
        cat "$evidence/apk-install.stderr" >&2
        fail "offline package install failed"
    fi
    assert_full_packages
    /etc/init.d/dnsmasq restart
    apk info -vv >"$evidence/packages.txt"
    cat /etc/openwrt_release >"$evidence/openwrt-release.txt"
    uname -a >"$evidence/uname.txt"

    "$driver" apply --runtime openwrt --revision qemu-baseline --available=false
    "$driver" confirm --runtime openwrt
    assert_journal committed qemu-baseline
    assert_runtime
    record_runtime baseline

    expect_apply_failure nft-validate qemu-invalid-nft
    expect_apply_failure dns-validate qemu-invalid-dns

    if "$driver" apply --runtime openwrt --revision qemu-postcheck --available=false --fault postcheck \
        >"$evidence/qemu-postcheck.stdout" 2>"$evidence/qemu-postcheck.stderr"; then
        fail "post-check fault unexpectedly succeeded"
    fi
    assert_journal rolled-back qemu-baseline
    [ "$(journal_value .rollback_result)" = 'post-check: restored' ] || fail "post-check rollback result is wrong"
    assert_runtime

    "$driver" apply --runtime openwrt --revision qemu-timeout --available=false \
        --confirm-timeout 3s --expect-timeout
    assert_journal rolled-back qemu-baseline
    [ "$(journal_value .rollback_result)" = 'watchdog expiry: restored' ] || fail "watchdog rollback result is wrong"
    assert_runtime

    "$driver" apply --runtime openwrt --revision qemu-crash --available=false --confirm-timeout 30s
    [ "$(journal_value .state)" = pending-confirmation ] || fail "crash fixture is not pending"
    "$driver" recover --runtime openwrt
    assert_journal rolled-back qemu-baseline
    [ "$(journal_value .rollback_result)" = 'boot/crash recovery: restored' ] || fail "crash recovery result is wrong"
    assert_runtime

    "$driver" apply --runtime openwrt --revision qemu-lkg --available=false
    "$driver" confirm --runtime openwrt
    assert_journal committed qemu-lkg
    assert_runtime
    sha256sum -c "$root/base-config.sha256" >/dev/null || fail "UCI config changed before reboot"
    record_runtime pre-reboot
    sync
    printf 'QEMU_GUEST_PHASE1_PASS\n'
    exit 0
fi

assert_full_packages
[ ! -e "$dns_include" ] || fail "volatile DNS include survived reboot unexpectedly"
"$driver" recover --runtime openwrt
assert_journal committed qemu-lkg
assert_runtime
sha256sum -c "$root/base-config.sha256" >/dev/null || fail "UCI config changed after reboot"
record_runtime post-reboot
printf 'QEMU_GUEST_P2_PASS\n'
