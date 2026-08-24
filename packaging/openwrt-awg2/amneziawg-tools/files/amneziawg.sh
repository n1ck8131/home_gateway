#!/bin/sh
# Copyright 2016-2017 Dan Luedtke <mail@danrl.com>
# Licensed to the public under the Apache License 2.0.

# shellcheck disable=SC1091,SC3003,SC3043

WG="${WG:-/usr/bin/awg}"
if [ ! -x "$WG" ]; then
	logger -t "amneziawg" "error: missing amneziawg-tools (${WG})"
	exit 1
fi

[ -n "${INCLUDE_ONLY:-}" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

proto_amneziawg_init_config() {
	# netifd consumes these protocol globals after initialization returns.
	# shellcheck disable=SC2034
	renew_handler=1
	# shellcheck disable=SC2034
	peer_detect=1
	proto_config_add_string "private_key"
	proto_config_add_string "private_key_file"
	proto_config_add_int "listen_port"
	proto_config_add_int "mtu"
	proto_config_add_string "fwmark"
	proto_config_add_string "addresses"
	proto_config_add_int "awg_jc"
	proto_config_add_int "awg_jmin"
	proto_config_add_int "awg_jmax"
	proto_config_add_int "awg_s1"
	proto_config_add_int "awg_s2"
	proto_config_add_int "awg_s3"
	proto_config_add_int "awg_s4"
	proto_config_add_string "awg_h1"
	proto_config_add_string "awg_h2"
	proto_config_add_string "awg_h3"
	proto_config_add_string "awg_h4"
	proto_config_add_string "awg_i1"
	proto_config_add_string "awg_i2"
	proto_config_add_string "awg_i3"
	proto_config_add_string "awg_i4"
	proto_config_add_string "awg_i5"
	# shellcheck disable=SC2034
	available=1
	# shellcheck disable=SC2034
	no_proto_task=1
}

proto_amneziawg_is_kernel_mode() {
	if [ ! -e /sys/module/amneziawg ]; then
		modprobe amneziawg >/dev/null 2>&1 || true
	fi
	if [ -e /sys/module/amneziawg ]; then
		return 0
	fi
	if ! command -v "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" >/dev/null 2>&1; then
		echo "Please install either kernel module (kmod-amneziawg package) or user-space implementation in /usr/bin/amneziawg-go."
		exit 1
	fi
	return 1
}

proto_amneziawg_setup_peer() {
	local peer_config="$1"
	local disabled public_key preshared_key allowed_ips route_allowed_ips
	local endpoint_host endpoint_port persistent_keepalive endpoint allowed_ip

	config_get_bool disabled "${peer_config}" "disabled" 0
	config_get public_key "${peer_config}" "public_key"
	config_get preshared_key "${peer_config}" "preshared_key"
	config_get allowed_ips "${peer_config}" "allowed_ips"
	config_get_bool route_allowed_ips "${peer_config}" "route_allowed_ips" 0
	config_get endpoint_host "${peer_config}" "endpoint_host"
	config_get endpoint_port "${peer_config}" "endpoint_port"
	config_get persistent_keepalive "${peer_config}" "persistent_keepalive"

	[ "${disabled}" -eq 1 ] && return 0
	if [ -z "$public_key" ]; then
		echo "Skipping peer config $peer_config because public key is not defined."
		return 0
	fi

	echo "[Peer]" >> "${wg_cfg}"
	echo "PublicKey=${public_key}" >> "${wg_cfg}"
	[ -n "${preshared_key}" ] && echo "PresharedKey=${preshared_key}" >> "${wg_cfg}"
	for allowed_ip in $allowed_ips; do
		echo "AllowedIPs=${allowed_ip}" >> "${wg_cfg}"
	done
	if [ -n "${endpoint_host}" ]; then
		case "${endpoint_host}" in
			*:*) endpoint="[${endpoint_host}]" ;;
			*) endpoint="${endpoint_host}" ;;
		esac
		endpoint="${endpoint}:${endpoint_port:-51820}"
		echo "Endpoint=${endpoint}" >> "${wg_cfg}"
	fi
	[ -n "${persistent_keepalive}" ] && echo "PersistentKeepalive=${persistent_keepalive}" >> "${wg_cfg}"

	if [ "${route_allowed_ips}" -ne 0 ]; then
		for allowed_ip in ${allowed_ips}; do
			case "${allowed_ip}" in
				*:*/*) proto_add_ipv6_route "${allowed_ip%%/*}" "${allowed_ip##*/}" ;;
				*.*/*) proto_add_ipv4_route "${allowed_ip%%/*}" "${allowed_ip##*/}" ;;
				*:*) proto_add_ipv6_route "${allowed_ip%%/*}" "128" ;;
				*.*) proto_add_ipv4_route "${allowed_ip%%/*}" "32" ;;
			esac
		done
	fi
}

ensure_key_is_generated() {
	local private_key private_key_file ucitmp oldmask
	config_get private_key_file "$1" "private_key_file"
	[ -n "$private_key_file" ] && return 0
	private_key="$(uci get network."$1".private_key)"
	if [ "$private_key" = "generate" ]; then
		oldmask="$(umask)"
		umask 077
		ucitmp="$(mktemp -d)"
		private_key="$("${WG}" genkey)"
		uci -q -t "$ucitmp" set network."$1".private_key="$private_key" && \
			uci -q -t "$ucitmp" commit network
		rm -rf "$ucitmp"
		umask "$oldmask"
	fi
}

proto_amneziawg_resolve_private_key() {
	local private_key="$1"
	local private_key_file="$2"
	local secrets_root="$3"
	local key_name metadata resolved_key

	if [ -n "$private_key" ] && [ -n "$private_key_file" ]; then
		echo "amneziawg private key and private key file are mutually exclusive" >&2
		return 1
	fi
	if [ -z "$private_key_file" ]; then
		[ -n "$private_key" ] || {
			echo "amneziawg private key is missing" >&2
			return 1
		}
		printf '%s\n' "$private_key"
		return 0
	fi

	case "$secrets_root" in
		/*) ;;
		*) echo "amneziawg secret root is invalid" >&2; return 1 ;;
	esac
	case "$private_key_file" in
		"$secrets_root"/*) ;;
		*) echo "amneziawg private key file is outside the secret root" >&2; return 1 ;;
	esac
	key_name="${private_key_file#"$secrets_root"/}"
	case "$key_name" in
		'' | *..* | *[!A-Za-z0-9._-]*)
			echo "amneziawg private key file name is invalid" >&2
			return 1
			;;
	esac
	if [ -L "$private_key_file" ] || [ ! -f "$private_key_file" ]; then
		echo "amneziawg private key file must be a regular non-symlink file" >&2
		return 1
	fi
	metadata="$(stat -c '%u:%a' "$private_key_file")" || {
		echo "amneziawg private key file metadata is unavailable" >&2
		return 1
	}
	if [ "$metadata" != "0:600" ]; then
		echo "amneziawg private key file must be owned by root with mode 0600" >&2
		return 1
	fi
	resolved_key="$(cat "$private_key_file")" || {
		echo "amneziawg private key file cannot be read" >&2
		return 1
	}
	if [ -z "$resolved_key" ]; then
		echo "amneziawg private key file is empty" >&2
		return 1
	fi
	printf '%s\n' "$resolved_key"
}

proto_amneziawg_cleanup_runtime_config() {
	if [ -n "${AWG_RUNTIME_CONFIG:-}" ]; then
		rm -f "$AWG_RUNTIME_CONFIG"
		rmdir "${AWG_RUNTIME_CONFIG%/*}" 2>/dev/null || true
		AWG_RUNTIME_CONFIG=
	fi
}

proto_amneziawg_setup() {
	local config="$1"
	local wg_dir wg_cfg oldmask
	local private_key private_key_file listen_port addresses mtu fwmark ip6prefix nohostroute tunlink
	local awg_jc awg_jmin awg_jmax awg_s1 awg_s2 awg_s3 awg_s4
	local awg_h1 awg_h2 awg_h3 awg_h4 awg_i1 awg_i2 awg_i3 awg_i4 awg_i5
	local address prefix

	ensure_key_is_generated "${config}"
	config_load network
	config_get private_key "${config}" "private_key"
	config_get private_key_file "${config}" "private_key_file"
	config_get listen_port "${config}" "listen_port"
	config_get addresses "${config}" "addresses"
	config_get mtu "${config}" "mtu"
	config_get fwmark "${config}" "fwmark"
	config_get ip6prefix "${config}" "ip6prefix"
	config_get nohostroute "${config}" "nohostroute"
	config_get tunlink "${config}" "tunlink"
	config_get awg_jc "${config}" "awg_jc"
	config_get awg_jmin "${config}" "awg_jmin"
	config_get awg_jmax "${config}" "awg_jmax"
	config_get awg_s1 "${config}" "awg_s1"
	config_get awg_s2 "${config}" "awg_s2"
	config_get awg_s3 "${config}" "awg_s3"
	config_get awg_s4 "${config}" "awg_s4"
	config_get awg_h1 "${config}" "awg_h1"
	config_get awg_h2 "${config}" "awg_h2"
	config_get awg_h3 "${config}" "awg_h3"
	config_get awg_h4 "${config}" "awg_h4"
	config_get awg_i1 "${config}" "awg_i1"
	config_get awg_i2 "${config}" "awg_i2"
	config_get awg_i3 "${config}" "awg_i3"
	config_get awg_i4 "${config}" "awg_i4"
	config_get awg_i5 "${config}" "awg_i5"
	private_key="$(proto_amneziawg_resolve_private_key \
		"$private_key" "$private_key_file" "/etc/routerd/secrets")" || {
		proto_setup_failed "${config}"
		exit 1
	}
	oldmask="$(umask)"
	umask 077
	wg_dir="$(mktemp -d /tmp/amneziawg.XXXXXX)" || {
		umask "$oldmask"
		proto_setup_failed "${config}"
		exit 1
	}
	wg_cfg="${wg_dir}/setconf.conf"
	AWG_RUNTIME_CONFIG="$wg_cfg"
	trap 'proto_amneziawg_cleanup_runtime_config' EXIT HUP INT TERM

	if proto_amneziawg_is_kernel_mode; then
		logger -t "amneziawg" "info: using kernel-space kmod-amneziawg for ${WG}"
		ip link del dev "${config}" 2>/dev/null || true
		ip link add dev "${config}" type amneziawg
	else
		logger -t "amneziawg" "info: using user-space amneziawg-go for ${WG}"
		rm -f "/var/run/amneziawg/${config}.sock"
		"${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" "${config}"
	fi
	[ -n "${mtu}" ] && ip link set mtu "${mtu}" dev "${config}"
	proto_init_update "${config}" 1

	echo "[Interface]" > "${wg_cfg}"
	chmod 0600 "${wg_cfg}"
	umask "$oldmask"
	echo "PrivateKey=${private_key}" >> "${wg_cfg}"
	[ -n "${listen_port}" ] && echo "ListenPort=${listen_port}" >> "${wg_cfg}"
	[ -n "${fwmark}" ] && echo "FwMark=${fwmark}" >> "${wg_cfg}"
	[ -n "${awg_jc}" ] && echo "Jc = ${awg_jc}" >> "${wg_cfg}"
	[ -n "${awg_jmin}" ] && echo "Jmin = ${awg_jmin}" >> "${wg_cfg}"
	[ -n "${awg_jmax}" ] && echo "Jmax = ${awg_jmax}" >> "${wg_cfg}"
	[ -n "${awg_s1}" ] && echo "S1 = ${awg_s1}" >> "${wg_cfg}"
	[ -n "${awg_s2}" ] && echo "S2 = ${awg_s2}" >> "${wg_cfg}"
	[ -n "${awg_s3}" ] && echo "S3 = ${awg_s3}" >> "${wg_cfg}"
	[ -n "${awg_s4}" ] && echo "S4 = ${awg_s4}" >> "${wg_cfg}"
	[ -n "${awg_h1}" ] && echo "H1 = ${awg_h1}" >> "${wg_cfg}"
	[ -n "${awg_h2}" ] && echo "H2 = ${awg_h2}" >> "${wg_cfg}"
	[ -n "${awg_h3}" ] && echo "H3 = ${awg_h3}" >> "${wg_cfg}"
	[ -n "${awg_h4}" ] && echo "H4 = ${awg_h4}" >> "${wg_cfg}"
	[ -n "${awg_i1}" ] && echo "I1 = ${awg_i1}" >> "${wg_cfg}"
	[ -n "${awg_i2}" ] && echo "I2 = ${awg_i2}" >> "${wg_cfg}"
	[ -n "${awg_i3}" ] && echo "I3 = ${awg_i3}" >> "${wg_cfg}"
	[ -n "${awg_i4}" ] && echo "I4 = ${awg_i4}" >> "${wg_cfg}"
	[ -n "${awg_i5}" ] && echo "I5 = ${awg_i5}" >> "${wg_cfg}"

	config_foreach proto_amneziawg_setup_peer "amneziawg_${config}"
	"${WG}" setconf "${config}" "${wg_cfg}"
	local WG_RETURN=$?
	proto_amneziawg_cleanup_runtime_config
	trap - EXIT HUP INT TERM
	if [ ${WG_RETURN} -ne 0 ]; then
		sleep 5
		proto_setup_failed "${config}"
		exit 1
	fi

	for address in ${addresses}; do
		case "${address}" in
			*:*/*) proto_add_ipv6_address "${address%%/*}" "${address##*/}" ;;
			*.*/*) proto_add_ipv4_address "${address%%/*}" "${address##*/}" ;;
			*:*) proto_add_ipv6_address "${address%%/*}" "128" ;;
			*.*) proto_add_ipv4_address "${address%%/*}" "32" ;;
		esac
	done
	for prefix in ${ip6prefix}; do
		proto_add_ipv6_prefix "$prefix"
	done
	if [ "${nohostroute}" != "1" ]; then
		"${WG}" show "${config}" endpoints | \
			sed -E 's/\[?([0-9.:a-f]+)\]?:([0-9]+)/\1 \2/' | \
			while IFS=$'\t ' read -r _ address port; do
				[ -n "${port}" ] || continue
				proto_add_host_dependency "${config}" "${address}" "${tunlink}"
			done
	fi
	proto_send_update "${config}"
}

proto_amneziawg_renew() {
	local interface="$1"
	proto_amneziawg_setup "$interface"
}

proto_amneziawg_teardown() {
	local config="$1"
	ip link del dev "${config}" >/dev/null 2>&1 || true
	rm -f "/var/run/amneziawg/${config}.sock"
}

[ -n "${INCLUDE_ONLY:-}" ] || {
	add_protocol amneziawg
}
