#!/bin/sh
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
lock="$root/manifest/versions.lock.yaml"
url="$(jq -er '.artifacts.awg_go_source.url' "$lock")"
locked_sha="$(jq -er '.artifacts.awg_go_source.sha256' "$lock")"
locked_commit="$(jq -er '.amneziawg.go_commit' "$lock")"
test "$locked_commit" = '1cc94272ca8e9e223a5fe76382f5880f09d3c12d'

output_dir="${OUTPUT_DIR:-$root/artifacts/openwrt/aarch64_cortex-a53}"
case "$output_dir" in
	"$root"/*) ;;
	*) echo "OUTPUT_DIR must be inside repository root" >&2; exit 1 ;;
esac
rm -rf "$output_dir"
mkdir -p "$output_dir" "$root/.cache/downloads"

archive="$root/.cache/downloads/awg-go-$locked_sha.tar.gz"
if [ ! -f "$archive" ]; then
	curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$archive.partial"
	echo "$locked_sha  $archive.partial" | sha256sum --check -
	mv "$archive.partial" "$archive"
fi
echo "$locked_sha  $archive" | sha256sum --check -

source_root="$root/.cache/awg-go-source/$locked_sha"
rm -rf "$source_root"
mkdir -p "$source_root"
tar -xf "$archive" -C "$source_root"
set -- "$source_root"/*
test "$#" -eq 1
source_dir="$1"
test -f "$source_dir/go.mod"

go_bin="$root/.tools/go/bin/go"
if [ ! -x "$go_bin" ]; then
	go_bin="$(command -v go)"
fi
test "$("$go_bin" env GOVERSION)" = 'go1.26.5'

export GOWORK=off
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export GOSUMDB=sum.golang.org
cd "$source_dir"
"$go_bin" mod verify
"$go_bin" test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	"$go_bin" build -buildvcs=false -trimpath -ldflags="-s -w" \
	-o "$output_dir/amneziawg-go" .

binary_sha="$(sha256sum "$output_dir/amneziawg-go" | awk '{print $1}')"
binary_size="$(wc -c < "$output_dir/amneziawg-go" | tr -d ' ')"
{
	printf '%s\n' \
		"source_url=$url" \
		"source_sha256=$locked_sha" \
		'tag=v0.2.19' \
		"commit=$locked_commit" \
		'go_version=go1.26.5' \
		'GOOS=linux' \
		'GOARCH=arm64' \
		'CGO_ENABLED=0' \
		'build_flags=-buildvcs=false -trimpath -ldflags=-s -w' \
		"byte_size=$binary_size" \
		"binary_sha256=$binary_sha"
	(cd "$output_dir" && "$go_bin" version -m amneziawg-go)
} > "$output_dir/amneziawg-go.buildinfo"
(cd "$output_dir" && sha256sum amneziawg-go > amneziawg-go.sha256)
