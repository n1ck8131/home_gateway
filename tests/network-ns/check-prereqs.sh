#!/bin/sh
set -eu

for command in ip nft dnsmasq jq curl; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing command: $command" >&2
        exit 1
    fi
done

if [ "$(id -u)" -ne 0 ]; then
    echo "root is required for network namespace smoke" >&2
    exit 2
fi

namespace="hg-p0-$$"
cleanup() {
    ip netns del "$namespace" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ip netns add "$namespace"
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" nft -c -f /dev/stdin <<'EOF'
table inet home_gateway_p0 {
    chain input {
        type filter hook input priority filter;
        policy accept;
    }
}
EOF
ip netns exec "$namespace" dnsmasq --version >/dev/null

ip netns del "$namespace"
trap - EXIT INT TERM
if ip netns list | awk '{print $1}' | grep -Fx "$namespace" >/dev/null; then
    echo "namespace cleanup failed: $namespace" >&2
    exit 3
fi

echo "NETWORK_LAB_PREREQUISITES_PASS"
