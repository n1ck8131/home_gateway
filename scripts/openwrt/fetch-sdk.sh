#!/bin/sh
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
lock="$root/manifest/versions.lock.yaml"
url="$(jq -er '.artifacts.openwrt_sdk.url' "$lock")"
expected="$(jq -er '.artifacts.openwrt_sdk.sha256' "$lock")"

mkdir -p "$root/.cache/downloads" "$root/.cache/openwrt-sdk"
archive="$root/.cache/downloads/$(basename "$url")"
if [ ! -f "$archive" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$archive.partial"
    echo "$expected  $archive.partial" | sha256sum --check - 1>&2
    mv "$archive.partial" "$archive"
fi
echo "$expected  $archive" | sha256sum --check - 1>&2
content="$root/.cache/openwrt-sdk/$expected"
marker="$content/.complete"
valid_cache=false
if [ -f "$marker" ] && [ "$(cat "$marker")" = "$expected" ]; then
    count="$(find "$content" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    if [ "$count" = 1 ]; then
        candidate="$(find "$content" -mindepth 1 -maxdepth 1 -type d -print)"
        [ -f "$candidate/include/toplevel.mk" ] && valid_cache=true
    fi
fi
if [ "$valid_cache" != true ]; then
    rm -rf "$content"
    mkdir -p "$content"
    tar --zstd -xf "$archive" -C "$content"
    count="$(find "$content" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    [ "$count" = 1 ]
    candidate="$(find "$content" -mindepth 1 -maxdepth 1 -type d -print)"
    test -f "$candidate/include/toplevel.mk"
    printf '%s\n' "$expected" > "$marker"
fi
sdk="$(find "$content" -mindepth 1 -maxdepth 1 -type d -print)"
test -f "$sdk/include/toplevel.mk"
printf '%s\n' "$sdk"
