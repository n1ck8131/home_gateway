#!/bin/sh
set -eu

fail() {
	echo "routerd lifecycle: $*" >&2
	exit 1
}

if [ "$#" -ne 4 ]; then
	fail 'usage: assert-routerd-lifecycle.sh APK_HOST ROUTERD_R1 ROUTERD_R2 PACKAGE_ARCH'
fi

apk_host="$(realpath -e -- "$1")"
routerd_r1="$(realpath -e -- "$2")"
routerd_r2="$(realpath -e -- "$3")"
package_arch="$4"

[ -x "$apk_host" ] || fail 'SDK host apk is not executable'
[ -f "$routerd_r1" ] || fail 'routerd r1 APK is missing'
[ -f "$routerd_r2" ] || fail 'routerd r2 APK is missing'
[ "$routerd_r1" != "$routerd_r2" ] || fail 'upgrade evidence requires distinct r1 and r2 APKs'
[ "$package_arch" = 'aarch64_cortex-a53' ] || fail 'unexpected package architecture'

temp_parent="${TMPDIR:-/tmp}"
case "$temp_parent" in
	/*) ;;
	*) fail 'TMPDIR must be absolute' ;;
esac
temp_parent="$(realpath -e -- "$temp_parent")"
[ -d "$temp_parent" ] || fail 'temporary parent is not a directory'
[ "$temp_parent" != '/' ] || fail 'temporary parent must not be filesystem root'

lifecycle_root=''
cleanup() {
	cleanup_path="$lifecycle_root"
	lifecycle_root=''
	[ -n "$cleanup_path" ] || return 0
	if [ ! -e "$cleanup_path" ] && [ ! -L "$cleanup_path" ]; then
		return 0
	fi
	resolved_cleanup_path="$(realpath -e -- "$cleanup_path")" || {
		echo "refusing unresolved lifecycle cleanup path: $cleanup_path" >&2
		return 1
	}
	[ "$resolved_cleanup_path" = "$cleanup_path" ] || {
		echo "refusing redirected lifecycle cleanup path: $cleanup_path" >&2
		return 1
	}
	case "$resolved_cleanup_path" in
		"$temp_parent"/routerd-apk-lifecycle.*) ;;
		*) echo "refusing unsafe lifecycle cleanup path: $resolved_cleanup_path" >&2; return 1 ;;
	esac
	rm -rf -- "$resolved_cleanup_path"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

lifecycle_root="$(mktemp -d "$temp_parent/routerd-apk-lifecycle.XXXXXX")"
case "$lifecycle_root" in
	"$temp_parent"/routerd-apk-lifecycle.*) ;;
	*) fail 'mktemp returned an unconfined lifecycle root' ;;
esac

keys_dir="$lifecycle_root/keys"
repositories_file="$lifecycle_root/repositories"
mkdir -p "$keys_dir"
: > "$repositories_file"

apk_run() {
	command_name="$1"
	shift
	"$apk_host" \
		--root "$lifecycle_root" \
		--keys-dir "$keys_dir" \
		--no-logfile \
		--preserve-env \
		"$command_name" \
		--no-network \
		--no-cache \
		--no-scripts \
		--arch "$package_arch" \
		--repositories-file "$repositories_file" \
		--allow-untrusted \
		"$@"
}

owned_binary="$lifecycle_root/usr/bin/routerd"
owned_init="$lifecycle_root/etc/init.d/routerd"
uci_state="$lifecycle_root/etc/config/routerd"
state_fixture="$lifecycle_root/etc/routerd/dataplane/lifecycle-state.json"

apk_run add --initdb "$routerd_r1"
[ -x "$owned_binary" ] || fail 'r1 install did not create executable /usr/bin/routerd'
[ -x "$owned_init" ] || fail 'r1 install did not create executable /etc/init.d/routerd'

binary_clean_hash="$(sha256sum "$owned_binary" | awk '{print $1}')"
init_clean_hash="$(sha256sum "$owned_init" | awk '{print $1}')"
mkdir -p "$(dirname -- "$uci_state")" "$(dirname -- "$state_fixture")"
printf '%s\n' 'config routerd "lifecycle"' > "$uci_state"
printf '%s\n' '{"revision":"state-fixture"}' > "$state_fixture"
uci_hash="$(sha256sum "$uci_state" | awk '{print $1}')"
state_fixture_hash="$(sha256sum "$state_fixture" | awk '{print $1}')"

printf '%s\n' 'corrupted-owned-binary' > "$owned_binary"
chmod 755 "$owned_binary"
[ "$(sha256sum "$owned_binary" | awk '{print $1}')" != "$binary_clean_hash" ] || fail 'binary corruption fixture was ineffective'

apk_run add --upgrade "$routerd_r2"
[ "$(sha256sum "$owned_binary" | awk '{print $1}')" = "$binary_clean_hash" ] || fail 'r2 upgrade did not restore the owned binary'
[ "$(sha256sum "$owned_init" | awk '{print $1}')" = "$init_clean_hash" ] || fail 'r2 upgrade did not restore the owned init entry'
[ "$(sha256sum "$uci_state" | awk '{print $1}')" = "$uci_hash" ] || fail 'r2 upgrade changed mock UCI state'
[ "$(sha256sum "$state_fixture" | awk '{print $1}')" = "$state_fixture_hash" ] || fail 'r2 upgrade changed mock dataplane state'

apk_run del routerd
[ ! -e "$owned_binary" ] || fail 'remove retained owned /usr/bin/routerd'
[ ! -e "$owned_init" ] || fail 'remove retained owned /etc/init.d/routerd'
[ "$(sha256sum "$uci_state" | awk '{print $1}')" = "$uci_hash" ] || fail 'remove changed mock UCI state'
[ "$(sha256sum "$state_fixture" | awk '{print $1}')" = "$state_fixture_hash" ] || fail 'remove changed mock dataplane state'

printf '%s\n' 'routerd isolated APK install/upgrade/remove lifecycle passed'
