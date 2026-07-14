#!/bin/sh
# shellcheck disable=SC2154

fail() {
    echo "NETWORK_NS_FAIL: $*" >&2
    exit 1
}

note() {
    echo "NETWORK_NS: $*"
}

register_pid() {
    LAB_PIDS="${LAB_PIDS:-} $1"
}

stop_pid_bounded() {
    pid=$1
    if ! kill -0 "$pid" >/dev/null 2>&1; then
        wait "$pid" >/dev/null 2>&1 || true
        return
    fi
    kill -TERM "$pid" >/dev/null 2>&1 || true
    attempts=0
    while kill -0 "$pid" >/dev/null 2>&1 && [ "$attempts" -lt 30 ]; do
        sleep 0.1
        attempts=$((attempts + 1))
    done
    if kill -0 "$pid" >/dev/null 2>&1; then
        kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
    wait "$pid" >/dev/null 2>&1 || true
}

cleanup_lab() {
    trap - EXIT INT TERM HUP
    for pid in ${LAB_PIDS:-}; do
        stop_pid_bounded "$pid"
    done
    if [ -n "${LAB_ROOT:-}" ] && [ -f "${LAB_ROOT}/run/dnsmasq.pid" ]; then
        dns_pid=$(sed -n '1p' "${LAB_ROOT}/run/dnsmasq.pid" 2>/dev/null || true)
        case "$dns_pid" in
            ''|*[!0-9]*) ;;
            *) stop_pid_bounded "$dns_pid" ;;
        esac
    fi
    for namespace in ${LAB_NAMESPACES:-}; do
        ip netns del "$namespace" >/dev/null 2>&1 || true
    done
    for link in ${LAB_HOST_LINKS:-}; do
        ip link del "$link" >/dev/null 2>&1 || true
    done
}

assert_file_size_cap() {
    size_kib=$(du -sk "$EVIDENCE_DIR" | awk '{print $1}')
    case "$size_kib" in
        ''|*[!0-9]*) fail "cannot determine evidence size" ;;
    esac
    if [ "$size_kib" -gt 51200 ]; then
        fail "evidence exceeds 50 MiB: ${size_kib} KiB"
    fi
    printf '%s\n' "$size_kib" >"$EVIDENCE_DIR/size-kib.txt"
}
