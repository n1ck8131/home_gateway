#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
helper="$root/packaging/openwrt-awg2/amneziawg-tools/files/amneziawg.sh"

for key in awg_s3 awg_s4 awg_i1 awg_i2 awg_i3 awg_i4 awg_i5; do
	grep -q "proto_config_add_.* \"$key\"" "$helper"
	grep -q "config_get $key" "$helper"
	upper="$(printf '%s' "${key#awg_}" | tr '[:lower:]' '[:upper:]')"
	grep -q "$upper = \${$key}" "$helper"
done
for key in awg_h1 awg_h2 awg_h3 awg_h4 awg_i1 awg_i2 awg_i3 awg_i4 awg_i5; do
	grep -q "proto_config_add_string \"$key\"" "$helper"
	if grep -q "proto_config_add_int \"$key\"" "$helper"; then exit 1; fi
done
grep -Eq 'config_get_bool route_allowed_ips .* 0$' "$helper"
grep -q 'renew_handler=1' "$helper"
grep -q 'peer_detect=1' "$helper"
grep -q 'proto_config_add_string "addresses"' "$helper"
grep -q 'proto_amneziawg_renew' "$helper"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
if INCLUDE_ONLY=1 WG="$tmp/missing" sh "$helper" >/dev/null 2>&1; then
	echo 'missing backend unexpectedly succeeded' >&2
	exit 1
else
	test "$?" -eq 1
fi
printf '#!/bin/sh\nexit 0\n' > "$tmp/awg"
chmod +x "$tmp/awg"
printf '#!/bin/sh\nprintf "%%s\\n" "$0 $*" >> "$TRACE"\n' > "$tmp/ip"
printf '#!/bin/sh\nprintf "%%s\\n" "$0 $*" >> "$TRACE"\n' > "$tmp/modprobe"
chmod +x "$tmp/ip" "$tmp/modprobe"
TRACE="$tmp/trace" PATH="$tmp:$PATH" INCLUDE_ONLY=1 WG="$tmp/awg" sh -c '. "$1"; proto_amneziawg_teardown awg-test' sh "$helper"
if grep -Eq 'modprobe|/awg([[:space:]]|$)' "$tmp/trace"; then
	echo 'teardown invoked a setup-time backend command' >&2
	exit 1
fi
