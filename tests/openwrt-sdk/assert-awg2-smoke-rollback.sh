#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
remote=$repo/scripts/openwrt/smoke-awg2-remote.sh
work=/tmp/home-gateway-p0

if [ -e "$work" ]; then
	echo "$work already exists; refusing to disturb it" >&2
	exit 1
fi

fixture=$(mktemp -d)
state=$fixture/state
bin=$fixture/bin
log=$fixture/cleanup.log
mkdir "$state" "$bin"
owns_work=0
cleanup_fixture() {
	rm -rf "$fixture"
	if [ "$owns_work" -eq 1 ]; then rm -rf /tmp/home-gateway-p0; fi
}
trap cleanup_fixture EXIT
trap 'exit 130' INT TERM

cat > "$bin/apk" <<'EOF'
#!/bin/sh
set -eu
if [ "${1-} ${2-}" = 'info -e' ]; then
	if [ "${AWG_FAKE_APK_PROBE_ERROR-0}" -eq 1 ]; then exit 42; fi
	if [ -e "$AWG_FAKE_STATE/package-$3" ]; then exit 0; else exit 1; fi
fi
if [ "${1-}" = del ]; then
	printf 'apk-del:%s\n' "$2" >> "$AWG_FAKE_LOG"
	rm -f "$AWG_FAKE_STATE/package-$2"
	exit 0
fi
exit 99
EOF

cat > "$bin/lsmod" <<'EOF'
#!/bin/sh
set -eu
if [ "${AWG_FAKE_LSMOD_ERROR-0}" -eq 1 ]; then exit 43; fi
echo 'Module Size Used by'
if [ -e "$AWG_FAKE_STATE/module" ]; then echo 'amneziawg 1 0'; fi
EOF

cat > "$bin/ip" <<'EOF'
#!/bin/sh
set -eu
if [ "${1-} ${2-} ${3-}" = 'link show awg-p0' ]; then
	if [ -e "$AWG_FAKE_STATE/interface" ]; then exit 0; else exit 1; fi
fi
if [ "${1-} ${2-} ${3-}" = 'link delete awg-p0' ]; then
	echo 'ip-delete' >> "$AWG_FAKE_LOG"
	rm -f "$AWG_FAKE_STATE/interface"
	exit 0
fi
exit 99
EOF

cat > "$bin/rmmod" <<'EOF'
#!/bin/sh
set -eu
test "${1-}" = amneziawg
echo 'rmmod' >> "$AWG_FAKE_LOG"
if [ -e "$AWG_FAKE_STATE/rmmod-fail-once" ]; then
	rm -f "$AWG_FAKE_STATE/rmmod-fail-once"
	exit 55
fi
rm -f "$AWG_FAKE_STATE/module"
EOF

chmod +x "$bin/apk" "$bin/lsmod" "$bin/ip" "$bin/rmmod"
PATH=$bin:$PATH
export PATH
AWG_FAKE_STATE=$state
AWG_FAKE_LOG=$log
export AWG_FAKE_STATE AWG_FAKE_LOG

nonce=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
wrong_nonce=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
probe_nonce=cccccccccccccccccccccccccccccccc

sh "$remote" prepare "$nonce"
owns_work=1
touch "$state/package-kmod-amneziawg" "$state/package-amneziawg-tools" "$state/module" "$state/interface"
sed \
	-e 's/^created_kmod=0$/created_kmod=1/' \
	-e 's/^created_tools=0$/created_tools=1/' \
	-e 's/^created_module=0$/created_module=1/' \
	-e 's/^created_interface=0$/created_interface=1/' \
	"$work/owner" > "$work/owner.new"
mv "$work/owner.new" "$work/owner"

if sh "$remote" recover "$wrong_nonce"; then
	echo 'recovery accepted a wrong nonce' >&2
	exit 1
fi
test -f "$work/owner"

touch "$state/rmmod-fail-once"
if sh "$remote" cleanup "$nonce"; then
	echo 'cleanup unexpectedly ignored rmmod failure' >&2
	exit 1
fi
test -f "$work/owner"
test "$(sed -n '1p' "$log")" = ip-delete
test "$(sed -n '2p' "$log")" = rmmod

sh "$remote" recover "$nonce"
test ! -e "$work"
owns_work=0
test ! -e "$state/package-kmod-amneziawg"
test ! -e "$state/package-amneziawg-tools"
test ! -e "$state/module"
test ! -e "$state/interface"

actual_order=$(sed -n 'p' "$log")
expected_order=$(printf '%s\n' ip-delete rmmod rmmod apk-del:amneziawg-tools apk-del:kmod-amneziawg)
test "$actual_order" = "$expected_order"

owns_work=1
if AWG_FAKE_APK_PROBE_ERROR=1 sh "$remote" prepare "$probe_nonce"; then
	echo 'prepare treated a probe error as expected absence' >&2
	exit 1
fi
test ! -e "$work"
owns_work=0
