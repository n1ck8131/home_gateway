#!/bin/sh
# shellcheck disable=SC2154

create_veth_pair() {
    host_left=$1
    host_right=$2
    left_namespace=$3
    left_name=$4
    right_namespace=$5
    right_name=$6

    ip link add "$host_left" type veth peer name "$host_right"
    LAB_HOST_LINKS="${LAB_HOST_LINKS:-} $host_left $host_right"
    ip link set "$host_left" netns "$left_namespace"
    ip link set "$host_right" netns "$right_namespace"
    ip -n "$left_namespace" link set "$host_left" name "$left_name"
    ip -n "$right_namespace" link set "$host_right" name "$right_name"
}

create_topology() {
    for namespace in "$NS_CLIENT" "$NS_ROUTER" "$NS_WAN" "$NS_VPN" "$NS_INTERNET"; do
        ip netns add "$namespace"
        LAB_NAMESPACES="${LAB_NAMESPACES:-} $namespace"
        ip -n "$namespace" link set lo up
    done

    create_veth_pair "${LINK_PREFIX}c" "${LINK_PREFIX}r" "$NS_CLIENT" c0 "$NS_ROUTER" lan0
    create_veth_pair "${LINK_PREFIX}w" "${LINK_PREFIX}x" "$NS_ROUTER" wan0 "$NS_WAN" wan0
    create_veth_pair "${LINK_PREFIX}v" "${LINK_PREFIX}a" "$NS_ROUTER" vpn0 "$NS_VPN" edge0
    create_veth_pair "${LINK_PREFIX}b" "${LINK_PREFIX}i" "$NS_VPN" edge1 "$NS_INTERNET" int0

    ip -n "$NS_CLIENT" addr add "$CLIENT4/24" dev c0
    ip -n "$NS_CLIENT" addr add "$WORK4/24" dev c0
    ip -n "$NS_CLIENT" -6 addr add "$CLIENT6/64" dev c0 nodad
    ip -n "$NS_CLIENT" -6 addr add "$WORK6/64" dev c0 nodad
    ip -n "$NS_CLIENT" link set c0 up

    ip -n "$NS_ROUTER" addr add "$ROUTER_LAN4/24" dev lan0
    ip -n "$NS_ROUTER" -6 addr add "$ROUTER_LAN6/64" dev lan0 nodad
    ip -n "$NS_ROUTER" addr add "$ROUTER_WAN4/24" dev wan0
    ip -n "$NS_ROUTER" -6 addr add "$ROUTER_WAN6/64" dev wan0 nodad
    ip -n "$NS_ROUTER" addr add "$ROUTER_VPN4/24" dev vpn0
    ip -n "$NS_ROUTER" -6 addr add "$ROUTER_VPN6/64" dev vpn0 nodad
    ip -n "$NS_ROUTER" link set lan0 up
    ip -n "$NS_ROUTER" link set wan0 up
    ip -n "$NS_ROUTER" link set vpn0 up

    ip -n "$NS_WAN" addr add "$WAN_LINK4/24" dev wan0
    ip -n "$NS_WAN" addr add "$DIRECT4/32" dev wan0
    ip -n "$NS_WAN" addr add "$VPN4/32" dev wan0
    ip -n "$NS_WAN" -6 addr add "$WAN_LINK6/64" dev wan0 nodad
    ip -n "$NS_WAN" -6 addr add "$DIRECT6/128" dev wan0 nodad
    ip -n "$NS_WAN" -6 addr add "$VPN6/128" dev wan0 nodad
    ip -n "$NS_WAN" link set wan0 up

    ip -n "$NS_VPN" link add tunbr0 type bridge
    ip -n "$NS_VPN" link set edge0 master tunbr0
    ip -n "$NS_VPN" link set edge1 master tunbr0
    ip -n "$NS_VPN" link set edge0 up
    ip -n "$NS_VPN" link set edge1 up
    ip -n "$NS_VPN" link set tunbr0 up

    ip -n "$NS_INTERNET" addr add "$VPN_LINK4/24" dev int0
    ip -n "$NS_INTERNET" addr add "$VPN4/32" dev int0
    ip -n "$NS_INTERNET" -6 addr add "$VPN_LINK6/64" dev int0 nodad
    ip -n "$NS_INTERNET" -6 addr add "$VPN6/128" dev int0 nodad
    ip -n "$NS_INTERNET" link set int0 up

    ip -n "$NS_CLIENT" route add default via "$ROUTER_LAN4"
    ip -n "$NS_CLIENT" -6 route add default via "$ROUTER_LAN6"
    ip -n "$NS_ROUTER" route add default via "$WAN_LINK4" dev wan0
    ip -n "$NS_ROUTER" -6 route add default via "$WAN_LINK6" dev wan0

    ip netns exec "$NS_ROUTER" sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec "$NS_ROUTER" sysctl -q -w net.ipv6.conf.all.forwarding=1
    ip netns exec "$NS_ROUTER" sysctl -q -w net.ipv4.conf.all.rp_filter=0
    ip netns exec "$NS_ROUTER" sysctl -q -w net.ipv4.conf.default.rp_filter=0
    for interface in lan0 wan0 vpn0; do
        ip netns exec "$NS_ROUTER" sysctl -q -w "net.ipv4.conf.${interface}.rp_filter=0"
    done

    ip netns exec "$NS_ROUTER" nft -f - <<'EOF'
table inet lab_nat {
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "lan0" oifname "wan0" counter comment "lab-wan-egress"
    iifname "lan0" oifname "vpn0" counter comment "lab-vpn-egress"
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname { "wan0", "vpn0" } masquerade
  }
}
EOF
}
