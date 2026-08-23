#!/bin/sh
# shellcheck disable=SC2154

router_driver() {
    ip netns exec "$NS_ROUTER" "$LAB_DRIVER" "$@" --lab-root "$LAB_ROOT"
}

client_probe() {
    network=$1
    target=$2
    source=$3
    expected=$4
    probe_timeout=${5:-2s}
    ip netns exec "$NS_CLIENT" "$LAB_DRIVER" probe \
        --network "$network" \
        --target "$target" \
        --source "$source" \
        --expect "$expected" \
        --timeout "$probe_timeout"
}

client_probe_eventually() {
    eventually_network=$1
    eventually_target=$2
    eventually_source=$3
    eventually_expected=$4
    eventually_timeout=${5:-2s}
    eventually_attempt=1
    eventually_error="$LAB_ROOT/run/probe-error.log"

    while ! client_probe "$eventually_network" "$eventually_target" "$eventually_source" \
        "$eventually_expected" "$eventually_timeout" >"$eventually_error" 2>&1; do
        if [ "$eventually_attempt" -ge 5 ]; then
            cat "$eventually_error" >&2
            fail "expected $eventually_network connectivity did not stabilize from $eventually_source to $eventually_target"
        fi
        eventually_attempt=$((eventually_attempt + 1))
        sleep 0.2
    done

    if [ "$eventually_attempt" -gt 1 ]; then
        printf '%s\t%s\t%s\t%s\n' \
            "$eventually_network" "$eventually_source" "$eventually_target" "$eventually_attempt" \
            >>"$EVIDENCE_DIR/probe-retries.tsv"
    fi
    rm -f "$eventually_error"
}

expect_probe_failure() {
    network=$1
    target=$2
    source=$3
    if client_probe "$network" "$target" "$source" unused 400ms >/dev/null 2>&1; then
        fail "unexpected $network connectivity from $source to $target"
    fi
}

wait_for_dns() {
    attempts=0
    while [ "$attempts" -lt 30 ]; do
        if ip netns exec "$NS_CLIENT" dig +time=1 +tries=1 +short "@$ROUTER_LAN4" "$VPN_DOMAIN" A 2>/dev/null | grep -Fx "$VPN4" >/dev/null; then
            return
        fi
        attempts=$((attempts + 1))
        sleep 0.1
    done
    fail "dnsmasq did not become ready"
}

populate_vpn_sets() {
    wait_for_dns
    ip netns exec "$NS_CLIENT" dig +time=1 +tries=1 +short "@$ROUTER_LAN4" "$VPN_DOMAIN" AAAA | grep -Fx "$VPN6" >/dev/null || fail "AAAA fixture missing"
}

forward_counter_packets() {
    comment=$1
    ip netns exec "$NS_ROUTER" nft -j list chain inet lab_nat forward |
        jq -er --arg comment "$comment" '
            [.nftables[] | .rule? | select(.comment == $comment) | .expr[] | .counter?.packets // empty]
            | if length == 1 then .[0] else error("expected one forwarding counter") end
        '
}

assert_up_matrix() {
    vpn_token=${1:-vpn-1}
    client_probe_eventually tcp "$VPN4:$TCP_PORT" "$CLIENT4" "$vpn_token"
    client_probe_eventually udp "$VPN4:$UDP_PORT" "$CLIENT4" "$vpn_token"
    client_probe_eventually udp-quic "$VPN4:$QUIC_PORT" "$CLIENT4" "$vpn_token"
    client_probe_eventually tcp "[$VPN6]:$TCP_PORT" "$CLIENT6" "$vpn_token"
    client_probe_eventually udp "[$VPN6]:$UDP_PORT" "$CLIENT6" "$vpn_token"
    client_probe_eventually udp-quic "[$VPN6]:$QUIC_PORT" "$CLIENT6" "$vpn_token"

    client_probe_eventually tcp "$DIRECT4:$TCP_PORT" "$CLIENT4" wan
    client_probe_eventually tcp "[$DIRECT6]:$TCP_PORT" "$CLIENT6" wan
    client_probe_eventually tcp "$VPN4:$TCP_PORT" "$WORK4" wan
    client_probe_eventually tcp "[$VPN6]:$TCP_PORT" "$WORK6" wan
}

assert_slot_down_no_leak() {
    slot=$1
    table=$((10000 + slot))
    before_wan=$(forward_counter_packets lab-wan-egress)
    before_vpn1=$(forward_counter_packets lab-vpn-egress)
    before_vpn2=$(forward_counter_packets lab-vpn2-egress)
    expect_probe_failure tcp "$VPN4:$TCP_PORT" "$CLIENT4"
    expect_probe_failure udp "$VPN4:$UDP_PORT" "$CLIENT4"
    expect_probe_failure udp-quic "$VPN4:$QUIC_PORT" "$CLIENT4"
    expect_probe_failure tcp "[$VPN6]:$TCP_PORT" "$CLIENT6"
    expect_probe_failure udp "[$VPN6]:$UDP_PORT" "$CLIENT6"
    expect_probe_failure udp-quic "[$VPN6]:$QUIC_PORT" "$CLIENT6"
    after_wan=$(forward_counter_packets lab-wan-egress)
    after_vpn1=$(forward_counter_packets lab-vpn-egress)
    after_vpn2=$(forward_counter_packets lab-vpn2-egress)
    [ "$before_wan" -eq "$after_wan" ] || fail "VPN-class traffic leaked to WAN: $before_wan -> $after_wan"
    [ "$before_vpn1" -eq "$after_vpn1" ] || fail "VPN-class traffic leaked to slot 1: $before_vpn1 -> $after_vpn1"
    [ "$before_vpn2" -eq "$after_vpn2" ] || fail "VPN-class traffic leaked to slot 2: $before_vpn2 -> $after_vpn2"
    ip -n "$NS_ROUTER" -4 route show table "$table" |
        awk '$1 == "blackhole" && $2 == "default" { found = 1 } END { exit !found }' ||
        fail "IPv4 VPN table $table is not fail-closed"
    ip -n "$NS_ROUTER" -6 route show table "$table" |
        awk '$1 == "blackhole" && $2 == "default" { found = 1 } END { exit !found }' ||
        fail "IPv6 VPN table $table is not fail-closed"
}

assert_journal_active() {
    expected=$1
    actual=$(jq -er '.active_revision' "$LAB_ROOT/state/journal.json")
    [ "$actual" = "$expected" ] || fail "active revision is $actual, expected $expected"
}

expect_apply_failure() {
    revision=$1
    profile=$2
    fault=$3
    output=$4
    if router_driver apply --revision "$revision" --profile "$profile" --fault "$fault" \
        --dual-server --active-slot 1 --slot1-available=true --slot2-available=true >"$output" 2>&1; then
        fail "apply $revision unexpectedly succeeded"
    fi
}

assert_interface_absent() {
    if ip -n "$NS_ROUTER" link show dev "$1" >/dev/null 2>&1; then
        fail "$1 unexpectedly exists"
    fi
}

assert_interface_present() {
    ip -n "$NS_ROUTER" link show dev "$1" >/dev/null 2>&1 || fail "$1 is missing"
}
