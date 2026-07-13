#!/bin/sh
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
validator="$root/scripts/openwrt/apk-validation.jq"
kernel_dependency='kernel=6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1'

validate() {
	mode="$1"
	expected="$2"
	jq -e --arg mode "$mode" --arg expected "$expected" -f "$validator"
}

assert_rejected() {
	label="$1"
	mode="$2"
	expected="$3"
	payload="$4"
	if printf '%s\n' "$payload" | validate "$mode" "$expected" >/dev/null 2>&1; then
		echo "$label unexpectedly passed APK dependency validation" >&2
		exit 1
	fi
}

printf '%s\n' '{"info":{"depends":["ip","kmod-amneziawg","libc"]}}' |
	validate 'package-dependency' 'kmod-amneziawg' >/dev/null
kernel_tuple="$(printf '%s\n' "{\"info\":{\"depends\":[\"libc\",\"$kernel_dependency\"]}}" |
	validate 'kernel' '')"
test "$(printf '%s\n' "$kernel_tuple" | jq -r '.kernel')" = '6.12.94'
test "$(printf '%s\n' "$kernel_tuple" | jq -r '.vermagic')" = '5a6c1f71be683ae9980b15d3ce73e24d'

assert_rejected 'missing package dependency' 'package-dependency' 'kmod-amneziawg' '{"info":{"depends":["ip"]}}'
assert_rejected 'duplicate package dependency' 'package-dependency' 'kmod-amneziawg' '{"info":{"depends":["kmod-amneziawg","kmod-amneziawg"]}}'
assert_rejected 'versioned package dependency' 'package-dependency' 'kmod-amneziawg' '{"info":{"depends":["kmod-amneziawg=1"]}}'
assert_rejected 'conflicting package dependency' 'package-dependency' 'kmod-amneziawg' '{"info":{"depends":["kmod-amneziawg","!kmod-amneziawg"]}}'
assert_rejected 'non-string package dependency' 'package-dependency' 'kmod-amneziawg' '{"info":{"depends":[{"name":"kmod-amneziawg"}]}}'
assert_rejected 'non-array package dependency' 'package-dependency' 'kmod-amneziawg' '{"info":{"depends":"kmod-amneziawg"}}'

assert_rejected 'missing kernel dependency' 'kernel' '' '{"info":{"depends":["libc"]}}'
assert_rejected 'duplicate kernel dependency' 'kernel' '' "{\"info\":{\"depends\":[\"$kernel_dependency\",\"$kernel_dependency\"]}}"
assert_rejected 'non-equality kernel dependency' 'kernel' '' '{"info":{"depends":["kernel>6.12.94"]}}'
assert_rejected 'conflicting kernel dependency' 'kernel' '' "{\"info\":{\"depends\":[\"$kernel_dependency\",\"!$kernel_dependency\"]}}"
assert_rejected 'malformed kernel dependency' 'kernel' '' "{\"info\":{\"depends\":[\"${kernel_dependency}-extra\"]}}"
assert_rejected 'non-string kernel dependency' 'kernel' '' '{"info":{"depends":[{"name":"kernel"}]}}'
