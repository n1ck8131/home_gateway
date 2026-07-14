#!/bin/sh
set -eu

missing=""
for command in awk curl du find go gzip jq qemu-img qemu-system-x86_64 \
    rsync scp sha256sum ssh timeout; do
    if ! command -v "$command" >/dev/null 2>&1; then
        missing="$missing $command"
    fi
done

if [ -n "$missing" ]; then
    printf 'missing OpenWrt QEMU prerequisites:%s\n' "$missing" >&2
    exit 1
fi

printf 'OPENWRT_QEMU_PREREQS_OK\n'
