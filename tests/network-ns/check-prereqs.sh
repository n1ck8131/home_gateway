#!/bin/sh
set -eu

for command in ip nft dnsmasq jq dig tcpdump timeout sha256sum awk sed grep du cp go; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing command: $command" >&2
        exit 1
    fi
done

if [ "$(id -u)" -ne 0 ]; then
    echo "root is required for the network namespace safety suite" >&2
    exit 2
fi

if ! dnsmasq --version 2>&1 | grep -qw nftset; then
    echo "dnsmasq with nftset support (dnsmasq-full) is required" >&2
    exit 3
fi

echo "NETWORK_LAB_PREREQUISITES_PASS"
