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
	if apk info -e "$1" >/dev/null 2>&1; then
		printf '1'
		return 0
	else
		probe_status=$?
	fi
	if [ "$probe_status" -eq 1 ]; then
		printf '0'
		return 0
	fi
	echo "package probe failed for $1 with exit $probe_status" >&2
	return "$probe_status"
}

module_present() {
	if modules=$(lsmod); then :; else
		probe_status=$?
		echo "module probe failed with exit $probe_status" >&2
		return "$probe_status"
	fi
	if module_names=$(printf '%s\n' "$modules" | awk '{print $1}'); then :; else
		probe_status=$?
		echo "module probe parser failed with exit $probe_status" >&2
		return "$probe_status"
	fi
	if printf '%s\n' "$module_names" | grep -qx amneziawg; then
		printf '1'
		return 0
	else
		probe_status=$?
	fi
	if [ "$probe_status" -eq 1 ]; then
		printf '0'
		return 0
	fi
	echo "module matcher failed with exit $probe_status" >&2
	return "$probe_status"
}

interface_present() {
	if ip link show awg-p0 >/dev/null 2>&1; then
		printf '1'
		return 0
	else
		probe_status=$?
	fi
	if [ "$probe_status" -eq 1 ]; then
		printf '0'
		return 0
	fi
	echo "interface probe failed with exit $probe_status" >&2
	return "$probe_status"
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
	if [ ! -f "$owner" ]; then
		echo 'owner marker is missing' >&2
		return 1
	fi
	stored_nonce=$(sed -n 's/^nonce=//p' "$owner") || return 1
	if [ "$stored_nonce" != "$nonce" ]; then
		echo 'recovery token does not own temporary state' >&2
		return 1
	fi
	for name in pre_kmod pre_tools pre_module pre_interface created_kmod created_tools created_module created_interface; do
		value=$(sed -n "s/^$name=//p" "$owner") || return 1
		case "$value" in 0|1) ;; *) echo "invalid owner marker: $name" >&2; return 1 ;; esac
		eval "$name=\$value"
	done
}

assert_state() {
	actual_kmod=$(package_present kmod-amneziawg) || return 1
	actual_tools=$(package_present amneziawg-tools) || return 1
	actual_module=$(module_present) || return 1
	actual_interface=$(interface_present) || return 1
	assert_state_value kmod "$actual_kmod" "$pre_kmod" || return 1
	assert_state_value tools "$actual_tools" "$pre_tools" || return 1
	assert_state_value module "$actual_module" "$pre_module" || return 1
	assert_state_value interface "$actual_interface" "$pre_interface" || return 1
}

assert_state_value() {
	if [ "$2" != "$3" ]; then
		echo "cleanup state mismatch for $1: expected $3, got $2" >&2
		return 1
	fi
}

cleanup_owned() {
	read_owner || return 1
	current_interface=$(interface_present) || return 1
	if [ "$created_interface" = 1 ] && [ "$pre_interface" = 0 ] && [ "$current_interface" = 1 ]; then
		ip link delete awg-p0 || return 1
	fi
	current_module=$(module_present) || return 1
	if [ "$created_module" = 1 ] && [ "$pre_module" = 0 ] && [ "$current_module" = 1 ]; then
		rmmod amneziawg || return 1
	fi
	current_tools=$(package_present amneziawg-tools) || return 1
	if [ "$created_tools" = 1 ] && [ "$pre_tools" = 0 ] && [ "$current_tools" = 1 ]; then
		apk del amneziawg-tools || return 1
	fi
	current_kmod=$(package_present kmod-amneziawg) || return 1
	if [ "$created_kmod" = 1 ] && [ "$pre_kmod" = 0 ] && [ "$current_kmod" = 1 ]; then
		apk del kmod-amneziawg || return 1
	fi
	assert_state || return 1
	rm -rf "$work" || return 1
	if [ -e "$work" ]; then
		echo 'temporary state removal was not confirmed' >&2
		return 1
	fi
}

case "$mode" in
	prepare)
		test ! -e "$work"
		pre_kmod=$(package_present kmod-amneziawg) || exit $?
		pre_tools=$(package_present amneziawg-tools) || exit $?
		pre_module=$(module_present) || exit $?
		pre_interface=$(interface_present) || exit $?
		created_kmod=0
		created_tools=0
		created_module=0
		created_interface=0
		mkdir -m 0700 "$work"
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
		smoke_status=0
		trap 'smoke_status=$?; trap - EXIT INT TERM; cleanup_owned || smoke_status=1; exit "$smoke_status"' EXIT
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
