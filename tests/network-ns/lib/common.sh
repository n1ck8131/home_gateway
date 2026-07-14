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
    for text_evidence in "$EVIDENCE_DIR"/*.log "$EVIDENCE_DIR"/*.txt "$EVIDENCE_DIR"/*.conf "$EVIDENCE_DIR"/*.json "$EVIDENCE_DIR"/*.tsv; do
        [ -f "$text_evidence" ] || continue
        sed -i \
            -e "s|$LAB_ROOT|<LAB_ROOT>|g" \
            -e "s|$NS_CLIENT|<NS_CLIENT>|g" \
            -e "s|$NS_ROUTER|<NS_ROUTER>|g" \
            -e "s|$NS_WAN|<NS_WAN>|g" \
            -e "s|$NS_VPN|<NS_VPN>|g" \
            -e "s|$NS_INTERNET2|<NS_INTERNET2>|g" \
            -e "s|$NS_INTERNET|<NS_INTERNET>|g" \
            "$text_evidence"
    done
    assert_file_size_cap
    handoff_external_evidence
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

handoff_external_evidence() {
    [ "${EVIDENCE_IS_EXTERNAL:-0}" = 1 ] || return 0
    [ "$(id -u)" -eq 0 ] || return 0
    if [ -z "${SUDO_UID:-}" ] && [ -z "${SUDO_GID:-}" ]; then
        return 0
    fi
    case "${SUDO_UID:-}" in
        ''|*[!0-9]*) fail "SUDO_UID must be numeric for evidence handoff" ;;
    esac
    case "${SUDO_GID:-}" in
        ''|*[!0-9]*) fail "SUDO_GID must be numeric for evidence handoff" ;;
    esac
    chown -R "$SUDO_UID:$SUDO_GID" "$EVIDENCE_DIR"
}
