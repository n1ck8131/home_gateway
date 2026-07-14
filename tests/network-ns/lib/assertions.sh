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

wan_tx_packets() {
    ip -n "$NS_ROUTER" -j -s link show dev wan0 | jq -er '.[0].stats64.tx.packets // .[0].stats.tx.packets'
}

assert_up_matrix() {
    client_probe tcp "$VPN4:$TCP_PORT" "$CLIENT4" vpn
    client_probe udp "$VPN4:$UDP_PORT" "$CLIENT4" vpn
    client_probe udp-quic "$VPN4:$QUIC_PORT" "$CLIENT4" vpn
    client_probe tcp "[$VPN6]:$TCP_PORT" "$CLIENT6" vpn
    client_probe udp "[$VPN6]:$UDP_PORT" "$CLIENT6" vpn
    client_probe udp-quic "[$VPN6]:$QUIC_PORT" "$CLIENT6" vpn

    client_probe tcp "$DIRECT4:$TCP_PORT" "$CLIENT4" wan
    client_probe tcp "[$DIRECT6]:$TCP_PORT" "$CLIENT6" wan
    client_probe tcp "$VPN4:$TCP_PORT" "$WORK4" wan
    client_probe tcp "[$VPN6]:$TCP_PORT" "$WORK6" wan
}

assert_down_no_leak() {
    before=$(wan_tx_packets)
    expect_probe_failure tcp "$VPN4:$TCP_PORT" "$CLIENT4"
    expect_probe_failure udp "$VPN4:$UDP_PORT" "$CLIENT4"
    expect_probe_failure udp-quic "$VPN4:$QUIC_PORT" "$CLIENT4"
    expect_probe_failure tcp "[$VPN6]:$TCP_PORT" "$CLIENT6"
    expect_probe_failure udp "[$VPN6]:$UDP_PORT" "$CLIENT6"
    expect_probe_failure udp-quic "[$VPN6]:$QUIC_PORT" "$CLIENT6"
    after=$(wan_tx_packets)
    if [ "$before" -ne "$after" ]; then
        fail "VPN-class traffic leaked to WAN: tx packets $before -> $after"
    fi
    ip -n "$NS_ROUTER" -4 route show table 10001 | grep -Fx 'blackhole default' >/dev/null || fail "IPv4 VPN table is not fail-closed"
    ip -n "$NS_ROUTER" -6 route show table 10001 | grep -F 'blackhole default' >/dev/null || fail "IPv6 VPN table is not fail-closed"
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
    if router_driver apply --revision "$revision" --profile "$profile" --fault "$fault" --available=true >"$output" 2>&1; then
        fail "apply $revision unexpectedly succeeded"
    fi
}
