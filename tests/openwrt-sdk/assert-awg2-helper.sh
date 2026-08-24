#!/bin/sh
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
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
grep -q 'proto_config_add_string "private_key_file"' "$helper"
grep -q 'config_get private_key_file' "$helper"
grep -q '/etc/routerd/secrets' "$helper"
grep -q "stat -c '%u:%a'" "$helper"
grep -q '0:600' "$helper"
grep -q 'mktemp -d /tmp/amneziawg.XXXXXX' "$helper"
grep -q "trap 'proto_amneziawg_cleanup_runtime_config' EXIT HUP INT TERM" "$helper"
if grep -q '/etc/routerd/secrets/runtime' "$helper"; then exit 1; fi
grep -q 'proto_amneziawg_renew' "$helper"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
if INCLUDE_ONLY=1 WG=/bin/true sh -c '. "$1"; proto_amneziawg_resolve_private_key key /etc/routerd/secrets/key /etc/routerd/secrets' sh "$helper" >/dev/null 2>&1; then
	echo 'simultaneous inline and file keys unexpectedly succeeded' >&2
	exit 1
fi
if INCLUDE_ONLY=1 WG=/bin/true sh -c '. "$1"; proto_amneziawg_resolve_private_key "" /etc/routerd/secrets/../shadow /etc/routerd/secrets' sh "$helper" >/dev/null 2>&1; then
	echo 'private key traversal unexpectedly succeeded' >&2
	exit 1
fi
mkdir -p "$tmp/bin" "$tmp/secrets"
: > "$tmp/secrets/awg-test.key"
cat > "$tmp/bin/stat" <<'EOF'
#!/bin/sh
printf '%s\n' '0:600'
EOF
cat > "$tmp/bin/cat" <<'EOF'
#!/bin/sh
printf '%s\n' 'fixture-value'
EOF
chmod +x "$tmp/bin/stat" "$tmp/bin/cat"
resolved_key="$(PATH="$tmp/bin:$PATH" INCLUDE_ONLY=1 WG=/bin/true sh -c '. "$1"; proto_amneziawg_resolve_private_key "" "$2" "$3"' sh "$helper" "$tmp/secrets/awg-test.key" "$tmp/secrets")"
[ "$resolved_key" = 'fixture-value' ] || {
	echo 'private key file did not resolve through the guarded path' >&2
	exit 1
}

if INCLUDE_ONLY=1 WG="$tmp/missing" sh "$helper" >/dev/null 2>&1; then
	echo 'missing backend unexpectedly succeeded' >&2
	exit 1
else
	test "$?" -eq 1
fi
printf '#!/bin/sh\nexit 0\n' > "$tmp/awg"
chmod +x "$tmp/awg"
# Runtime variables must remain literal in these generated command fixtures.
# shellcheck disable=SC2016
printf '#!/bin/sh\nprintf "%%s\\n" "$0 $*" >> "$TRACE"\n' > "$tmp/ip"
# shellcheck disable=SC2016
printf '#!/bin/sh\nprintf "%%s\\n" "$0 $*" >> "$TRACE"\n' > "$tmp/modprobe"
chmod +x "$tmp/ip" "$tmp/modprobe"
TRACE="$tmp/trace" PATH="$tmp:$PATH" INCLUDE_ONLY=1 WG="$tmp/awg" sh -c '. "$1"; proto_amneziawg_teardown awg-test' sh "$helper"
if grep -Eq 'modprobe|/awg([[:space:]]|$)' "$tmp/trace"; then
	echo 'teardown invoked a setup-time backend command' >&2
	exit 1
fi
