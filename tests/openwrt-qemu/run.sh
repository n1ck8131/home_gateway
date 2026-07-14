#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
root="$(CDPATH='' cd -- "$script_dir/../.." && pwd -P)"

timeout_seconds="${OPENWRT_QEMU_TIMEOUT_SECONDS:-1800}"
case "$timeout_seconds" in
    ''|*[!0-9]*) printf 'OPENWRT_QEMU_TIMEOUT_SECONDS must be an integer\n' >&2; exit 2 ;;
esac
if [ "$timeout_seconds" -lt 60 ] || [ "$timeout_seconds" -gt 2400 ]; then
    printf 'OPENWRT_QEMU_TIMEOUT_SECONDS must be between 60 and 2400\n' >&2
    exit 2
fi
if [ "${ROUTERD_QEMU_INNER:-0}" != 1 ]; then
    exec timeout --signal=TERM --kill-after=30s "${timeout_seconds}s" \
        env ROUTERD_QEMU_INNER=1 "$0" "$@"
fi

"$script_dir/check-prereqs.sh"

fail() {
    printf 'OPENWRT_QEMU_FAIL: %s\n' "$*" >&2
    exit 1
}

port="${OPENWRT_QEMU_SSH_PORT:-22222}"
case "$port" in
    ''|*[!0-9]*) fail 'OPENWRT_QEMU_SSH_PORT must be an integer' ;;
esac
if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
    fail 'OPENWRT_QEMU_SSH_PORT must be between 1024 and 65535'
fi

tmp_parent="${TMPDIR:-/tmp}"
tmp_parent="$(CDPATH='' cd -- "$tmp_parent" && pwd -P)"

if [ -n "${OPENWRT_QEMU_EVIDENCE_DIR:-}" ]; then
    output_dir="$OPENWRT_QEMU_EVIDENCE_DIR"
    case "$output_dir" in /*) ;; *) fail 'OPENWRT_QEMU_EVIDENCE_DIR must be absolute' ;; esac
    if [ -L "$output_dir" ]; then
        fail 'OPENWRT_QEMU_EVIDENCE_DIR must not be a symlink'
    fi
    mkdir -p "$output_dir"
    [ -d "$output_dir" ] || fail 'OPENWRT_QEMU_EVIDENCE_DIR must be a directory'
    if [ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        fail 'OPENWRT_QEMU_EVIDENCE_DIR must be empty'
    fi
else
    output_dir="$(mktemp -d "$tmp_parent/routerd-qemu-evidence.XXXXXX")"
fi

work_root="$(mktemp -d "$tmp_parent/routerd-qemu.XXXXXX")"
evidence="$work_root/evidence"
mkdir -p "$evidence"

qemu_pid=""
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$qemu_pid" ] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill -TERM "$qemu_pid" 2>/dev/null || true
        count=0
        while kill -0 "$qemu_pid" 2>/dev/null && [ "$count" -lt 20 ]; do
            sleep 1
            count=$((count + 1))
        done
        if kill -0 "$qemu_pid" 2>/dev/null; then
            kill -KILL "$qemu_pid" 2>/dev/null || true
        fi
        wait "$qemu_pid" 2>/dev/null || true
    fi
    printf '%s\n' "$status" >"$evidence/exit-status.txt"
    size_kib="$(du -sk "$evidence" | awk '{print $1}')"
    if [ "$size_kib" -gt 51200 ]; then
        printf 'evidence exceeds 50 MiB: %s KiB\n' "$size_kib" >"$evidence/size-error.txt"
        status=1
    fi
    rsync -a "$evidence/" "$output_dir/" || status=1
    case "$work_root" in
        "$tmp_parent"/routerd-qemu.*) rm -rf -- "$work_root" ;;
        *) printf 'refusing unsafe QEMU cleanup path: %s\n' "$work_root" >&2; status=1 ;;
    esac
    if [ "$status" -ne 0 ]; then
        printf 'QEMU evidence: %s\n' "$output_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

lock="$root/manifest/versions.lock.yaml"
checksums="$root/manifest/checksums.lock"
cache="$root/.cache/downloads"
mkdir -p "$cache"

fetch_artifact() {
    key="$1"
    kind="${2:-input}"
    url="$(jq -er ".artifacts.$key.url" "$lock")"
    expected="$(jq -er ".artifacts.$key.sha256" "$lock")"
    case "$url" in
        https://downloads.openwrt.org/*) ;;
        *) fail "$key URL is not an approved OpenWrt HTTPS URL" ;;
    esac
    filename="$(basename "$url")"
    grep -Fqx "$expected  $filename" "$checksums" || fail "$key is missing from checksums.lock"
    destination="$cache/$filename"
    if [ ! -f "$destination" ]; then
        partial="$work_root/$filename.partial"
        curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$partial"
        printf '%s  %s\n' "$expected" "$partial" | sha256sum --check - >&2
        mv "$partial" "$destination"
    fi
    printf '%s  %s\n' "$expected" "$destination" | sha256sum --check - >&2
    printf '%s  %s\n' "$expected" "$filename" >>"$evidence/locked-inputs.sha256"
    if [ "$kind" = apk ]; then
        printf '%s  %s\n' "$expected" "$filename" >>"$work_root/qemu-apks.sha256"
    fi
    printf '%s\n' "$destination"
}

: >"$evidence/locked-inputs.sha256"
: >"$work_root/qemu-apks.sha256"
image_archive="$(fetch_artifact openwrt_qemu)"
dnsmasq_apk="$(fetch_artifact openwrt_qemu_dnsmasq_full apk)"
ip_apk="$(fetch_artifact openwrt_qemu_ip_full apk)"
libnetfilter_conntrack_apk="$(fetch_artifact openwrt_qemu_libnetfilter_conntrack3 apk)"
libnettle_apk="$(fetch_artifact openwrt_qemu_libnettle8 apk)"
libbpf_apk="$(fetch_artifact openwrt_qemu_libbpf1 apk)"
libelf_apk="$(fetch_artifact openwrt_qemu_libelf1 apk)"
libgmp_apk="$(fetch_artifact openwrt_qemu_libgmp10 apk)"
libnfnetlink_apk="$(fetch_artifact openwrt_qemu_libnfnetlink0 apk)"
kmod_conntrack_netlink_apk="$(fetch_artifact openwrt_qemu_kmod_nf_conntrack_netlink apk)"

jq '{openwrt_qemu, artifacts: {
        openwrt_qemu: .artifacts.openwrt_qemu,
        openwrt_qemu_dnsmasq_full: .artifacts.openwrt_qemu_dnsmasq_full,
        openwrt_qemu_ip_full: .artifacts.openwrt_qemu_ip_full,
        openwrt_qemu_libnetfilter_conntrack3: .artifacts.openwrt_qemu_libnetfilter_conntrack3,
        openwrt_qemu_libnettle8: .artifacts.openwrt_qemu_libnettle8,
        openwrt_qemu_libbpf1: .artifacts.openwrt_qemu_libbpf1,
        openwrt_qemu_libelf1: .artifacts.openwrt_qemu_libelf1,
        openwrt_qemu_libgmp10: .artifacts.openwrt_qemu_libgmp10,
        openwrt_qemu_libnfnetlink0: .artifacts.openwrt_qemu_libnfnetlink0,
        openwrt_qemu_kmod_nf_conntrack_netlink: .artifacts.openwrt_qemu_kmod_nf_conntrack_netlink
    }}' \
    "$lock" >"$evidence/locked-inputs.json"
qemu-system-x86_64 --version >"$evidence/qemu-version.txt"
"${GO_BIN:-go}" version >"$evidence/go-version.txt"

raw_image="$work_root/openwrt.raw"
overlay="$work_root/openwrt.qcow2"
gzip -dc "$image_archive" >"$raw_image"
qemu-img info "$raw_image" >"$evidence/base-image-info.txt"
qemu-img create -q -f qcow2 -F raw -b "$raw_image" "$overlay"

driver="$work_root/lab-driver"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO_BIN:-go}" build -trimpath \
    -o "$driver" ./tests/network-ns/cmd/lab-driver

qemu_log="$evidence/qemu-console.log"
qemu-system-x86_64 \
    -machine pc -accel tcg -cpu max -smp 1 -m 512 -nographic \
    -drive "file=$overlay,format=qcow2,if=virtio" \
    -device virtio-net-pci,netdev=lan \
    -netdev "user,id=lan,net=192.168.1.0/24,host=192.168.1.2,hostfwd=tcp:127.0.0.1:$port-192.168.1.1:22" \
    -device virtio-net-pci,netdev=wan \
    -netdev user,id=wan,net=192.168.2.0/24 \
    >"$qemu_log" 2>&1 &
qemu_pid=$!
known_hosts="$work_root/known_hosts"
: >"$known_hosts"
chmod 600 "$known_hosts"

guest_ssh() {
    ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$known_hosts" \
        root@127.0.0.1 "$@"
}

wait_for_guest() {
    attempts=0
    while [ "$attempts" -lt 90 ]; do
        kill -0 "$qemu_pid" 2>/dev/null || fail 'QEMU exited before SSH became ready'
        if guest_ssh true >/dev/null 2>&1; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 2
    done
    fail 'OpenWrt SSH did not become ready within 180 seconds'
}

wait_for_guest
guest_ssh 'mkdir -p /root/routerd-p2 && chmod 700 /root/routerd-p2'
scp -O -P "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$known_hosts" \
    "$driver" "$script_dir/guest-smoke.sh" "$work_root/qemu-apks.sha256" \
    "$dnsmasq_apk" "$ip_apk" "$libnetfilter_conntrack_apk" "$libnettle_apk" \
    "$libbpf_apk" "$libelf_apk" "$libgmp_apk" "$libnfnetlink_apk" \
    "$kmod_conntrack_netlink_apk" \
    root@127.0.0.1:/root/routerd-p2/ >"$evidence/scp-upload.log" 2>&1
guest_ssh 'chmod 700 /root/routerd-p2/lab-driver /root/routerd-p2/guest-smoke.sh'

if ! guest_ssh '/root/routerd-p2/guest-smoke.sh phase1' >"$evidence/phase1.log" 2>&1; then
    cat "$evidence/phase1.log" >&2
    fail 'guest phase1 failed'
fi
cat "$evidence/phase1.log"

guest_ssh 'sync; reboot' >/dev/null 2>&1 || true
went_down=false
attempts=0
while [ "$attempts" -lt 30 ]; do
    if ! guest_ssh true >/dev/null 2>&1; then
        went_down=true
        break
    fi
    attempts=$((attempts + 1))
    sleep 1
done
[ "$went_down" = true ] || fail 'guest did not leave SSH during reboot'
wait_for_guest

if ! guest_ssh '/root/routerd-p2/guest-smoke.sh phase2' >"$evidence/phase2.log" 2>&1; then
    cat "$evidence/phase2.log" >&2
    fail 'guest phase2 failed'
fi
cat "$evidence/phase2.log"

mkdir -p "$evidence/guest"
scp -O -r -P "$port" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$known_hosts" \
    root@127.0.0.1:/root/routerd-p2/evidence/. "$evidence/guest/" \
    >"$evidence/scp-download.log" 2>&1

printf 'OPENWRT_QEMU_P2_PASS\n'
printf 'EVIDENCE_DIR=%s\n' "$output_dir"
