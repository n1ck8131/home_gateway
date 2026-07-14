#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)

NETWORK_NS_TIMEOUT_SECONDS=${NETWORK_NS_TIMEOUT_SECONDS:-900}
case "$NETWORK_NS_TIMEOUT_SECONDS" in
    ''|*[!0-9]*) echo "NETWORK_NS_TIMEOUT_SECONDS must be an integer" >&2; exit 64 ;;
esac
if [ "$NETWORK_NS_TIMEOUT_SECONDS" -lt 60 ] || [ "$NETWORK_NS_TIMEOUT_SECONDS" -gt 900 ]; then
    echo "NETWORK_NS_TIMEOUT_SECONDS must be between 60 and 900" >&2
    exit 64
fi

if [ "${NETWORK_NS_UNDER_DEADLINE:-0}" != 1 ]; then
    if ! command -v timeout >/dev/null 2>&1; then
        echo "missing command: timeout" >&2
        exit 1
    fi
    NETWORK_NS_UNDER_DEADLINE=1
    export NETWORK_NS_UNDER_DEADLINE
    exec timeout --signal=TERM --kill-after=10s "${NETWORK_NS_TIMEOUT_SECONDS}s" "$0" "$@"
fi

sh "$SCRIPT_DIR/check-prereqs.sh"

# The runtime fixture is intentionally not a *.sh ShellCheck input.
# shellcheck disable=SC1091
. "$SCRIPT_DIR/fixtures/endpoints.env"
# shellcheck source=tests/network-ns/lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=tests/network-ns/lib/topology.sh
. "$SCRIPT_DIR/lib/topology.sh"
# shellcheck source=tests/network-ns/lib/assertions.sh
. "$SCRIPT_DIR/lib/assertions.sh"

token=$(tr -d '-' </proc/sys/kernel/random/uuid | cut -c1-6)
case "$token" in
    ''|*[!0-9a-f]*) fail "cannot allocate a safe namespace token" ;;
esac

NS_CLIENT="n${token}c"
NS_ROUTER="n${token}r"
NS_WAN="n${token}w"
NS_VPN="n${token}v"
NS_INTERNET="n${token}i"
NS_INTERNET2="n${token}j"
LINK_PREFIX="h${token}"
LAB_NAMESPACES=
LAB_HOST_LINKS=
LAB_PIDS=

LAB_ROOT=$(mktemp -d "/tmp/routerd-netns-${token}-XXXXXX")
EVIDENCE_DIR="$LAB_ROOT/evidence"
EVIDENCE_IS_EXTERNAL=0
LAB_DRIVER="$LAB_ROOT/bin/lab-driver"
mkdir -p "$LAB_ROOT/bin" "$LAB_ROOT/etc/routerd.d" "$LAB_ROOT/run"
chmod 700 "$LAB_ROOT" "$LAB_ROOT/bin" "$LAB_ROOT/etc" "$LAB_ROOT/etc/routerd.d" "$LAB_ROOT/run"
if [ -n "${NETWORK_NS_EVIDENCE_DIR:-}" ]; then
    case "$NETWORK_NS_EVIDENCE_DIR" in
        /*/) fail "NETWORK_NS_EVIDENCE_DIR must not have a trailing slash" ;;
        /*) ;;
        *) fail "NETWORK_NS_EVIDENCE_DIR must be an absolute path" ;;
    esac
    [ "$NETWORK_NS_EVIDENCE_DIR" != / ] || fail "NETWORK_NS_EVIDENCE_DIR cannot be root"
    [ ! -e "$NETWORK_NS_EVIDENCE_DIR" ] || fail "NETWORK_NS_EVIDENCE_DIR already exists"
    mkdir -m 700 "$NETWORK_NS_EVIDENCE_DIR"
    EVIDENCE_DIR=$NETWORK_NS_EVIDENCE_DIR
    EVIDENCE_IS_EXTERNAL=1
else
    mkdir -m 700 "$EVIDENCE_DIR"
fi
trap cleanup_lab EXIT INT TERM HUP

{
    printf '%s\n' 'port=53' 'interface=lan0' 'bind-interfaces' 'no-resolv' 'no-hosts' 'user=root' 'group=root'
    printf 'conf-dir=%s\n' "$LAB_ROOT/etc/routerd.d"
    printf 'log-facility=%s\n' "$EVIDENCE_DIR/dnsmasq.log"
    printf 'host-record=%s,%s,%s\n' "$VPN_DOMAIN" "$VPN4" "$VPN6"
    printf 'host-record=%s,%s,%s\n' "$VPN_APEX" "$VPN4" "$VPN6"
    printf 'host-record=%s,%s,%s\n' "$VPN_EXACT_CHILD" "$VPN4" "$VPN6"
    printf 'host-record=%s,%s,%s\n' "$DIRECT_DOMAIN" "$DIRECT4" "$DIRECT6"
    printf 'cname=%s,%s\n' "$VPN_ALIAS" "$VPN_DOMAIN"
    printf 'local=/%s/\n' 'suite.test'
} >"$LAB_ROOT/etc/dnsmasq-base.conf"
chmod 600 "$LAB_ROOT/etc/dnsmasq-base.conf"

GO_BIN=${GO_BIN:-go}
if ! command -v "$GO_BIN" >/dev/null 2>&1; then
    fail "GO_BIN is unavailable: $GO_BIN"
fi
note "building bounded lab driver"
(
    cd "$REPO_ROOT"
    GOMAXPROCS=1 GOMEMLIMIT=512MiB "$GO_BIN" build -p=1 -trimpath -o "$LAB_DRIVER" ./tests/network-ns/cmd/lab-driver
)

note "creating isolated topology"
create_topology

ip netns exec "$NS_WAN" "$LAB_DRIVER" serve \
    --token wan \
    --address "$DIRECT4" --address "$DIRECT6" \
    --address "$VPN4" --address "$VPN6" \
    --tcp-port "$TCP_PORT" --udp-port "$UDP_PORT" --quic-port "$QUIC_PORT" \
    >"$EVIDENCE_DIR/wan-server.log" 2>&1 &
WAN_SERVER_PID=$!
register_pid "$WAN_SERVER_PID"

ip netns exec "$NS_INTERNET" "$LAB_DRIVER" serve \
    --token vpn-1 \
    --address "$VPN4" --address "$VPN6" \
    --tcp-port "$TCP_PORT" --udp-port "$UDP_PORT" --quic-port "$QUIC_PORT" \
    >"$EVIDENCE_DIR/vpn-server.log" 2>&1 &
VPN_SERVER_PID=$!
register_pid "$VPN_SERVER_PID"

ip netns exec "$NS_INTERNET2" "$LAB_DRIVER" serve \
    --token vpn-2 \
    --address "$VPN4" --address "$VPN6" \
    --tcp-port "$TCP_PORT" --udp-port "$UDP_PORT" --quic-port "$QUIC_PORT" \
    >"$EVIDENCE_DIR/vpn2-server.log" 2>&1 &
VPN2_SERVER_PID=$!
register_pid "$VPN2_SERVER_PID"

for ready_file in "$EVIDENCE_DIR/wan-server.log" "$EVIDENCE_DIR/vpn-server.log" "$EVIDENCE_DIR/vpn2-server.log"; do
    attempts=0
    while ! grep -q '^SERVE_READY ' "$ready_file" 2>/dev/null; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 50 ] || fail "traffic server did not become ready: $ready_file"
        sleep 0.1
    done
done

timeout --signal=TERM --kill-after=2s 600s ip netns exec "$NS_ROUTER" \
    tcpdump -U -n -i wan0 -c 200 -s 96 -w "$EVIDENCE_DIR/wan0.pcap" \
    >"$EVIDENCE_DIR/wan0-tcpdump.log" 2>&1 &
CAPTURE_WAN_PID=$!
register_pid "$CAPTURE_WAN_PID"
timeout --signal=TERM --kill-after=2s 600s ip netns exec "$NS_ROUTER" \
    tcpdump -U -n -i any -c 400 -s 96 -w "$EVIDENCE_DIR/router-any.pcap" \
    >"$EVIDENCE_DIR/router-any-tcpdump.log" 2>&1 &
CAPTURE_ANY_PID=$!
register_pid "$CAPTURE_ANY_PID"

note "applying and confirming baseline through the production controller"
router_driver apply --revision baseline --profile suffix --fault none \
    --dual-server --active-slot 1 --slot1-available=true --slot2-available=true
router_driver confirm
assert_journal_active baseline
populate_vpn_sets
assert_up_matrix vpn-1

DNS_INCLUDE="$LAB_ROOT/etc/routerd.d/routerd.conf"
FIREWALL_INCLUDE="$LAB_ROOT/etc/50-routerd.nft"
VPN_SETS="$EVIDENCE_DIR/vpn-sets.txt"
awk -F'#' '/\/vpn\.suite\.test\// { sub(/,6$/, "", $4); print $4, $7 }' "$DNS_INCLUDE" >"$VPN_SETS"
[ -s "$VPN_SETS" ] || fail "VPN dnsmasq nftset binding is missing"

while read -r set4 set6; do
    ip netns exec "$NS_ROUTER" nft get element inet routerd "$set4" "{ $VPN4 }" >/dev/null || fail "A answer did not populate $set4"
    ip netns exec "$NS_ROUTER" nft get element inet routerd "$set6" "{ $VPN6 }" >/dev/null || fail "AAAA answer did not populate $set6"
    ip netns exec "$NS_ROUTER" nft delete element inet routerd "$set4" "{ $VPN4 }"
    ip netns exec "$NS_ROUTER" nft delete element inet routerd "$set6" "{ $VPN6 }"
done <"$VPN_SETS"

ip netns exec "$NS_CLIENT" dig +time=1 +tries=1 +short "@$ROUTER_LAN4" "$VPN_ALIAS" CNAME | grep -Fx "${VPN_DOMAIN}." >/dev/null || fail "CNAME fixture missing"
ip netns exec "$NS_CLIENT" dig +time=1 +tries=1 +short "@$ROUTER_LAN4" "$VPN_ALIAS" A | grep -Fx "$VPN4" >/dev/null || fail "CNAME A answer missing"
ip netns exec "$NS_CLIENT" dig +time=1 +tries=1 +short "@$ROUTER_LAN4" "$VPN_ALIAS" AAAA | grep -Fx "$VPN6" >/dev/null || fail "CNAME AAAA answer missing"
while read -r set4 set6; do
    ip netns exec "$NS_ROUTER" nft get element inet routerd "$set4" "{ $VPN4 }" >/dev/null || fail "CNAME did not populate $set4"
    ip netns exec "$NS_ROUTER" nft get element inet routerd "$set6" "{ $VPN6 }" >/dev/null || fail "CNAME did not populate $set6"
done <"$VPN_SETS"

read -r EXPIRY_SET4 EXPIRY_SET6 <"$VPN_SETS"
ip netns exec "$NS_ROUTER" nft delete element inet routerd "$EXPIRY_SET4" "{ $VPN4 }"
ip netns exec "$NS_ROUTER" nft delete element inet routerd "$EXPIRY_SET6" "{ $VPN6 }"
ip netns exec "$NS_ROUTER" nft add element inet routerd "$EXPIRY_SET4" "{ $VPN4 timeout 1s }"
ip netns exec "$NS_ROUTER" nft add element inet routerd "$EXPIRY_SET6" "{ $VPN6 timeout 1s }"
sleep 2
if ip netns exec "$NS_ROUTER" nft get element inet routerd "$EXPIRY_SET4" "{ $VPN4 }" >/dev/null 2>&1; then
    fail "IPv4 nftset element did not expire"
fi
if ip netns exec "$NS_ROUTER" nft get element inet routerd "$EXPIRY_SET6" "{ $VPN6 }" >/dev/null 2>&1; then
    fail "IPv6 nftset element did not expire"
fi
grep -F 'timeout 3600s' "$FIREWALL_INCLUDE" >/dev/null || fail "production nft set timeout is not explicit"
grep -F 'max-cache-ttl=3600' "$DNS_INCLUDE" >/dev/null || fail "dnsmasq cache TTL is not aligned"
populate_vpn_sets

vpn_policy_sets() {
    mark=$1
    set4=$(awk -v mark="$mark" '$1 == "ip" && $2 == "daddr" && $3 ~ /^@/ && index($0, "| " mark " ") { sub(/^@/, "", $3); print $3 }' "$FIREWALL_INCLUDE" | sort -u)
    set6=$(awk -v mark="$mark" '$1 == "ip6" && $2 == "daddr" && $3 ~ /^@/ && index($0, "| " mark " ") { sub(/^@/, "", $3); print $3 }' "$FIREWALL_INCLUDE" | sort -u)
    case "$set4:$set6" in
        *[!A-Za-z0-9_:]*) fail "VPN policy set selection is ambiguous" ;;
        :) fail "VPN policy sets are missing" ;;
    esac
    printf '%s %s\n' "$set4" "$set6"
}

direct_domain_sets() {
    set4=$(awk '$1 == "ip" && $2 == "daddr" && $3 ~ /^@/ && /ct mark set \(ct mark & 0x00ffffff\) return$/ { sub(/^@/, "", $3); print $3 }' "$FIREWALL_INCLUDE" | sort -u)
    set6=$(awk '$1 == "ip6" && $2 == "daddr" && $3 ~ /^@/ && /ct mark set \(ct mark & 0x00ffffff\) return$/ { sub(/^@/, "", $3); print $3 }' "$FIREWALL_INCLUDE" | sort -u)
    case "$set4:$set6" in
        *[!A-Za-z0-9_:]*) fail "direct domain set selection is ambiguous" ;;
        :) fail "direct domain sets are missing" ;;
    esac
    printf '%s %s\n' "$set4" "$set6"
}

flush_set_pair() {
    ip netns exec "$NS_ROUTER" nft flush set inet routerd "$1"
    ip netns exec "$NS_ROUTER" nft flush set inet routerd "$2"
}

query_domain_pair() {
    name=$1
    ip netns exec "$NS_CLIENT" dig +time=1 +tries=1 +short "@$ROUTER_LAN4" "$name" A | grep -Fx "$VPN4" >/dev/null || fail "$name A fixture missing"
    ip netns exec "$NS_CLIENT" dig +time=1 +tries=1 +short "@$ROUTER_LAN4" "$name" AAAA | grep -Fx "$VPN6" >/dev/null || fail "$name AAAA fixture missing"
}

assert_set_pair_present() {
    ip netns exec "$NS_ROUTER" nft get element inet routerd "$1" "{ $VPN4 }" >/dev/null || fail "$VPN4 did not populate $1"
    ip netns exec "$NS_ROUTER" nft get element inet routerd "$2" "{ $VPN6 }" >/dev/null || fail "$VPN6 did not populate $2"
}

assert_set_pair_absent() {
    if ip netns exec "$NS_ROUTER" nft get element inet routerd "$1" "{ $VPN4 }" >/dev/null 2>&1; then
        fail "$VPN4 unexpectedly populated $1"
    fi
    if ip netns exec "$NS_ROUTER" nft get element inet routerd "$2" "{ $VPN6 }" >/dev/null 2>&1; then
        fail "$VPN6 unexpectedly populated $2"
    fi
}

assert_dns_profile() {
    revision=$1
    profile=$2
    apex=$3
    apex_expected=$4
    descendant=$5
    descendant_expected=$6
    router_driver apply --revision "$revision" --profile "$profile" --fault none \
        --dual-server --active-slot 1 --slot1-available=true --slot2-available=true
    read -r profile_set4 profile_set6 <<EOF
$(vpn_policy_sets 0x1000000)
EOF
    flush_set_pair "$profile_set4" "$profile_set6"
    query_domain_pair "$apex"
    if [ "$apex_expected" = present ]; then
        assert_set_pair_present "$profile_set4" "$profile_set6"
    else
        assert_set_pair_absent "$profile_set4" "$profile_set6"
    fi
    flush_set_pair "$profile_set4" "$profile_set6"
    query_domain_pair "$descendant"
    if [ "$descendant_expected" = present ]; then
        assert_set_pair_present "$profile_set4" "$profile_set6"
    else
        assert_set_pair_absent "$profile_set4" "$profile_set6"
    fi
    router_driver rollback
    assert_journal_active baseline
}

note "asserting exact, wildcard, suffix, and overlap semantics through real dnsmasq"
assert_dns_profile dns-suffix suffix "$VPN_APEX" present "$VPN_DOMAIN" present
assert_dns_profile dns-exact exact "$VPN_DOMAIN" present "$VPN_EXACT_CHILD" absent
assert_dns_profile dns-wildcard wildcard "$VPN_APEX" absent "$VPN_DOMAIN" present

router_driver apply --revision dns-shared --profile shared --fault none \
    --dual-server --active-slot 1 --slot1-available=true --slot2-available=true
read -r shared_vpn4 shared_vpn6 <<EOF
$(vpn_policy_sets 0x1000000)
EOF
read -r shared_direct4 shared_direct6 <<EOF
$(direct_domain_sets)
EOF
flush_set_pair "$shared_vpn4" "$shared_vpn6"
flush_set_pair "$shared_direct4" "$shared_direct6"
query_domain_pair "$VPN_DOMAIN"
assert_set_pair_present "$shared_vpn4" "$shared_vpn6"
assert_set_pair_present "$shared_direct4" "$shared_direct6"
client_probe tcp "$VPN4:$TCP_PORT" "$CLIENT4" wan
client_probe tcp "[$VPN6]:$TCP_PORT" "$CLIENT6" wan
router_driver rollback
assert_journal_active baseline

note "asserting validation and post-check compensation boundaries"
expect_apply_failure invalid-nft suffix nft-validate "$EVIDENCE_DIR/invalid-nft.log"
expect_apply_failure invalid-dns suffix dns-validate "$EVIDENCE_DIR/invalid-dns.log"
assert_journal_active baseline
expect_apply_failure invalid-postcheck suffix postcheck "$EVIDENCE_DIR/invalid-postcheck.log"
assert_journal_active baseline
populate_vpn_sets
client_probe tcp "$VPN4:$TCP_PORT" "$CLIENT4" vpn-1

note "proving active-server switch preserves the established IPv6 connection mark"
STICKY_READY="$LAB_ROOT/run/sticky.ready"
STICKY_CONTINUE="$LAB_ROOT/run/sticky.continue"
STICKY_LOG="$EVIDENCE_DIR/sticky-flow.log"
rm -f "$STICKY_READY" "$STICKY_CONTINUE"
ip netns exec "$NS_CLIENT" "$LAB_DRIVER" sticky-probe \
    --target "[$VPN6]:$TCP_PORT" --source "$CLIENT6" --expect vpn-1 \
    --ready-file "$STICKY_READY" --continue-file "$STICKY_CONTINUE" --timeout 30s \
    >"$STICKY_LOG" 2>&1 &
STICKY_PID=$!
register_pid "$STICKY_PID"
attempts=0
while [ ! -f "$STICKY_READY" ]; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 100 ] || fail "sticky probe did not establish through slot 1"
    sleep 0.05
done
router_driver apply --revision active-slot-2 --profile suffix --fault none \
    --dual-server --active-slot 2 --slot1-available=true --slot2-available=true
populate_vpn_sets
client_probe tcp "[$VPN6]:$TCP_PORT" "$CLIENT6" vpn-2
printf '%s\n' continue >"$STICKY_CONTINUE"
if ! wait "$STICKY_PID"; then
    fail "established slot-1 flow did not survive the active-server switch"
fi
grep -Fx 'STICKY_PROBE_PASS vpn-1' "$STICKY_LOG" >/dev/null || fail "sticky flow evidence is missing"
router_driver rollback
assert_journal_active baseline
populate_vpn_sets

note "running twenty bounded tunnel-down fault cycles"
FAULT_SUMMARY="$EVIDENCE_DIR/fault-summary.tsv"
printf '%s\t%s\t%s\t%s\t%s\n' iteration slot interface recovery result >"$FAULT_SUMMARY"
i=1
while [ "$i" -le 20 ]; do
    revision=$(printf 'fault-%02d' "$i")
    if [ $((i % 2)) -eq 1 ]; then
        slot=1
        interface=vpn0
    else
        slot=2
        interface=vpn1
    fi
    remove_vpn_link "$slot"
    assert_interface_absent "$interface"
    if [ "$slot" -eq 1 ]; then
        router_driver apply --revision "$revision" --profile suffix --fault none \
            --dual-server --active-slot 1 --slot1-available=false --slot2-available=true
    else
        router_driver apply --revision "$revision" --profile suffix --fault none \
            --dual-server --active-slot 2 --slot1-available=true --slot2-available=false
    fi
    state=$(jq -er '.state' "$LAB_ROOT/state/journal.json")
    [ "$state" = pending-confirmation ] || fail "$revision is not pending"
    populate_vpn_sets
    assert_slot_down_no_leak "$slot"
    restore_vpn_link "$slot"
    assert_interface_present "$interface"

    if [ $((i % 2)) -eq 0 ]; then
        recovery=boot-recover
        router_driver recover
    else
        recovery=explicit-rollback
        router_driver rollback
    fi
    assert_journal_active baseline
    populate_vpn_sets
    if [ $((i % 2)) -eq 0 ]; then
        client_probe tcp "[$VPN6]:$TCP_PORT" "$CLIENT6" vpn-1
    else
        client_probe tcp "$VPN4:$TCP_PORT" "$CLIENT4" vpn-1
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$i" "$slot" "$interface" "$recovery" pass >>"$FAULT_SUMMARY"
    i=$((i + 1))
done

note "simulating cold-boot loss of volatile dataplane state"
ip netns exec "$NS_ROUTER" nft delete table inet routerd
ip -n "$NS_ROUTER" -4 rule del priority 10001
ip -n "$NS_ROUTER" -6 rule del priority 10001
ip -n "$NS_ROUTER" -4 route flush table 10001
ip -n "$NS_ROUTER" -6 route flush table 10001
ip -n "$NS_ROUTER" -4 rule del priority 10002
ip -n "$NS_ROUTER" -6 rule del priority 10002
ip -n "$NS_ROUTER" -4 route flush table 10002
ip -n "$NS_ROUTER" -6 route flush table 10002
dns_pid=$(sed -n '1p' "$LAB_ROOT/run/dnsmasq.pid")
stop_pid_bounded "$dns_pid"
rm -f "$LAB_ROOT/run/dnsmasq.pid" "$FIREWALL_INCLUDE" "$DNS_INCLUDE"
router_driver recover
assert_journal_active baseline
populate_vpn_sets
assert_up_matrix vpn-1

stop_pid_bounded "$CAPTURE_WAN_PID"
stop_pid_bounded "$CAPTURE_ANY_PID"
ip netns exec "$NS_ROUTER" nft -a list table inet routerd >"$EVIDENCE_DIR/nft-routerd.txt"
ip netns exec "$NS_ROUTER" nft -a list table inet lab_nat >"$EVIDENCE_DIR/nft-counters.txt"
ip -n "$NS_ROUTER" -4 rule show >"$EVIDENCE_DIR/ip-rule-v4.txt"
ip -n "$NS_ROUTER" -6 rule show >"$EVIDENCE_DIR/ip-rule-v6.txt"
ip -n "$NS_ROUTER" -4 route show table main >"$EVIDENCE_DIR/route-main-v4.txt"
ip -n "$NS_ROUTER" -6 route show table main >"$EVIDENCE_DIR/route-main-v6.txt"
ip -n "$NS_ROUTER" -4 route show table 10001 >"$EVIDENCE_DIR/route-slot1-v4.txt"
ip -n "$NS_ROUTER" -6 route show table 10001 >"$EVIDENCE_DIR/route-slot1-v6.txt"
ip -n "$NS_ROUTER" -4 route show table 10002 >"$EVIDENCE_DIR/route-slot2-v4.txt"
ip -n "$NS_ROUTER" -6 route show table 10002 >"$EVIDENCE_DIR/route-slot2-v6.txt"
jq . "$LAB_ROOT/state/journal.json" >"$EVIDENCE_DIR/journal.json"
sed -n '1,200p' "$DNS_INCLUDE" >"$EVIDENCE_DIR/dnsmasq-active.conf"

namespaces_to_check=$LAB_NAMESPACES
cleanup_lab
for namespace in $namespaces_to_check; do
    if ip netns list | awk '{print $1}' | grep -Fx "$namespace" >/dev/null; then
        echo "namespace cleanup failed: $namespace" >&2
        exit 1
    fi
done

echo "NETWORK_NS_P2_PASS"
echo "EVIDENCE_DIR=$EVIDENCE_DIR"
