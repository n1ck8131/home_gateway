#!/bin/sh
set -eu

missing=""
for command in awk curl du find go grep gzip head jq mkfifo qemu-img \
    qemu-system-x86_64 rsync scp sha256sum sort ssh tar timeout uniq wc; do
    if ! command -v "$command" >/dev/null 2>&1; then
        missing="$missing $command"
    fi
done

if [ -n "$missing" ]; then
    printf 'missing OpenWrt QEMU prerequisites:%s\n' "$missing" >&2
    exit 1
fi

printf 'OPENWRT_QEMU_PREREQS_OK\n'
