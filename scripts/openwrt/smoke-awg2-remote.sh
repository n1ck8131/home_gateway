#!/bin/sh
set -eu

work=/tmp/home-gateway-p0
owner=$work/owner
mode=${1-}
nonce=${2-}

case "$nonce" in
	*[!0-9a-f]*|'') echo 'invalid recovery token' >&2; exit 2 ;;
esac
test "${#nonce}" -eq 32
test "$work" = /tmp/home-gateway-p0

package_present() {
	if apk info -e "$1" >/dev/null 2>&1; then printf '1'; else printf '0'; fi
}

module_present() {
	if lsmod | awk '{print $1}' | grep -qx amneziawg; then printf '1'; else printf '0'; fi
}

interface_present() {
	if ip link show awg-p0 >/dev/null 2>&1; then printf '1'; else printf '0'; fi
}

write_owner() {
	(umask 077; cat > "$owner" <<EOF
nonce=$nonce
pre_kmod=$pre_kmod
pre_tools=$pre_tools
pre_module=$pre_module
pre_interface=$pre_interface
created_kmod=$created_kmod
created_tools=$created_tools
created_module=$created_module
created_interface=$created_interface
EOF
	)
}

read_owner() {
	test -f "$owner"
	stored_nonce=$(sed -n 's/^nonce=//p' "$owner")
	test "$stored_nonce" = "$nonce"
	for name in pre_kmod pre_tools pre_module pre_interface created_kmod created_tools created_module created_interface; do
		value=$(sed -n "s/^$name=//p" "$owner")
		case "$value" in 0|1) ;; *) echo "invalid owner marker: $name" >&2; exit 1 ;; esac
		eval "$name=\$value"
	done
}

assert_state() {
	test "$(package_present kmod-amneziawg)" = "$pre_kmod"
	test "$(package_present amneziawg-tools)" = "$pre_tools"
	test "$(module_present)" = "$pre_module"
	test "$(interface_present)" = "$pre_interface"
}

cleanup_owned() {
	read_owner
	if [ "$created_interface" = 1 ] && [ "$pre_interface" = 0 ] && [ "$(interface_present)" = 1 ]; then
		ip link delete awg-p0
	fi
	if [ "$created_tools" = 1 ] && [ "$pre_tools" = 0 ] && [ "$(package_present amneziawg-tools)" = 1 ]; then
		apk del amneziawg-tools
	fi
	if [ "$created_kmod" = 1 ] && [ "$pre_kmod" = 0 ] && [ "$(package_present kmod-amneziawg)" = 1 ]; then
		apk del kmod-amneziawg
	fi
	if [ "$created_module" = 1 ] && [ "$pre_module" = 0 ] && [ "$(module_present)" = 1 ]; then
		rmmod amneziawg
	fi
	assert_state
	rm -rf "$work"
	test ! -e "$work"
}

case "$mode" in
	prepare)
		test ! -e "$work"
		mkdir -m 0700 "$work"
		pre_kmod=$(package_present kmod-amneziawg)
		pre_tools=$(package_present amneziawg-tools)
		pre_module=$(module_present)
		pre_interface=$(interface_present)
		created_kmod=0
		created_tools=0
		created_module=0
		created_interface=0
		write_owner
		;;
	smoke)
		kmod=${3-}
		tools=${4-}
		kernel_abi=${5-}
		case "$kmod" in *[!A-Za-z0-9._+-]*) exit 2 ;; esac
		case "$tools" in *[!A-Za-z0-9._+-]*) exit 2 ;; esac
		test "$kernel_abi" = 'kernel-6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1'
		read_owner
		trap 'status=$?; trap - EXIT INT TERM; cleanup_owned || status=1; exit "$status"' EXIT
		trap 'exit 130' INT TERM
		cd "$work"
		test "$(find . -maxdepth 1 -type f -name '*.apk' | wc -l)" -eq 2
		sha256sum -c SHA256SUMS
		simulation=$(apk add --simulate --no-network --allow-untrusted "./$kmod" "./$tools" 2>&1)
		printf '%s\n' "$simulation" | grep -F "$kernel_abi"
		created_kmod=1
		created_tools=1
		write_owner
		apk add --no-network --allow-untrusted "./$kmod" "./$tools"
		created_module=1
		write_owner
		modprobe amneziawg
		created_interface=1
		write_owner
		ip link add awg-p0 type amneziawg
		awg genkey | awg set awg-p0 private-key /dev/stdin
		awg set awg-p0 jc 4 jmin 10 jmax 50 s1 142 s2 41 s3 56 s4 11 \
			h1 '684141592-1751861769' h2 '1957920865-2010016669' \
			h3 '2043550980-2107134838' h4 '2127672251-2132651859' \
			i1 '<r 2>' i2 '<r 3>' i3 '<rd 4>' i4 '<rc 4>' i5 '<b 0x0102>'
		awg show awg-p0
		trap - EXIT INT TERM
		cleanup_owned
		;;
	cleanup|recover)
		cleanup_owned
		;;
	*)
		echo 'expected prepare, smoke, cleanup or recover mode' >&2
		exit 2
		;;
esac
