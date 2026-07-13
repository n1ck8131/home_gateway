#!/bin/sh
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
lock="$root/manifest/versions.lock.yaml"
locked_epoch="$(jq -er '.openwrt.source_date_epoch' "$lock")"
if [ "${SOURCE_DATE_EPOCH+x}" = x ] && [ "$SOURCE_DATE_EPOCH" != "$locked_epoch" ]; then
	echo "SOURCE_DATE_EPOCH conflicts with manifest lock" >&2
	exit 1
fi
export SOURCE_DATE_EPOCH="$locked_epoch"

output_dir="${OUTPUT_DIR:-$root/artifacts/openwrt/aarch64_cortex-a53}"
case "$output_dir" in
	"$root"/*) ;;
	*) echo "OUTPUT_DIR must be inside repository root" >&2; exit 1 ;;
esac
rm -rf "$output_dir"
mkdir -p "$output_dir"

sdk="$("$root/scripts/openwrt/fetch-sdk.sh")"
rm -rf "$sdk/package/home-gateway"
mkdir -p "$sdk/package/home-gateway"
cp -a "$root/packaging/openwrt-awg2/." "$sdk/package/home-gateway/"
printf '%s\n' \
	'CONFIG_PACKAGE_kmod-amneziawg=m' \
	'CONFIG_PACKAGE_amneziawg-tools=m' \
	>> "$sdk/.config"
make -C "$sdk" defconfig
grep -qx 'CONFIG_PACKAGE_kmod-amneziawg=m' "$sdk/.config"
grep -qx 'CONFIG_PACKAGE_amneziawg-tools=m' "$sdk/.config"

rm -rf "$sdk/package/home-gateway"
mkdir -p "$sdk/package/home-gateway"
cp -a "$root/packaging/openwrt-awg2/." "$sdk/package/home-gateway/"
make -C "$sdk" package/kmod-amneziawg/clean
make -C "$sdk" package/amneziawg-tools/clean
make -C "$sdk" package/kmod-amneziawg/compile V=s
make -C "$sdk" package/amneziawg-tools/compile V=s

revision="$(make -s -C "$sdk" val.REVISION)"
architecture="$(make -s -C "$sdk" val.ARCH_PACKAGES)"
test "$revision" = 'r33051-f5dae5ece4'
test "$architecture" = 'aarch64_cortex-a53'

find_single_apk() {
	apk_matches="$(find "$sdk/bin" -type f -name "$1")"
	case "$apk_matches" in
		'' | *'
'*) return 1 ;;
	esac
	printf '%s\n' "$apk_matches"
}
kmod_apk="$(find_single_apk 'kmod-amneziawg-*.apk')"
tools_apk="$(find_single_apk 'amneziawg-tools-*.apk')"
apk_host="$sdk/staging_dir/host/bin/apk"
apk_validator="$root/scripts/openwrt/apk-validation.jq"
test -x "$apk_host"
test -f "$apk_validator"
kmod_dump="$("$apk_host" adbdump --format json "$kmod_apk")"
tools_dump="$("$apk_host" adbdump --format json "$tools_apk")"

require_apk_info_field() {
	field="$1"
	expected="$2"
	jq -e --arg field "$field" --arg expected "$expected" '
		(.info | type) == "object" and
		(.info[$field] | type) == "string" and
		.info[$field] == $expected
	' >/dev/null
}

require_single_dependency() {
	expected="$1"
	jq -e --arg mode 'package-dependency' --arg expected "$expected" -f "$apk_validator" >/dev/null
}

require_single_payload_file() {
	directory="$1"
	filename="$2"
	jq -e --arg directory "$directory" --arg filename "$filename" '
		.paths as $paths |
		($paths | type) == "array" and
		all($paths[];
			type == "object" and
			(.name | type) == "string" and
			(.files | type) == "array" and
			all(.files[]; type == "object" and (.name | type) == "string")
		) and
		([
			$paths[] |
			select(.name == $directory) |
			.files[] |
			select(.name == $filename)
		] | length) == 1
	' >/dev/null
}

kernel_tuple="$(printf '%s\n' "$kmod_dump" | jq -ec --arg mode 'kernel' --arg expected '' -f "$apk_validator")"
kernel="$(printf '%s\n' "$kernel_tuple" | jq -er '.kernel | select(type == "string")')"
vermagic="$(printf '%s\n' "$kernel_tuple" | jq -er '.vermagic | select(type == "string")')"
test "$kernel" = '6.12.94'
test "$vermagic" = '5a6c1f71be683ae9980b15d3ce73e24d'

printf '%s\n' "$kmod_dump" | require_apk_info_field name 'kmod-amneziawg'
printf '%s\n' "$tools_dump" | require_apk_info_field name 'amneziawg-tools'
printf '%s\n' "$kmod_dump" | require_apk_info_field arch "$architecture"
printf '%s\n' "$tools_dump" | require_apk_info_field arch "$architecture"
printf '%s\n' "$tools_dump" | require_single_dependency 'kmod-amneziawg'
printf '%s\n' "$kmod_dump" | require_single_payload_file "lib/modules/$kernel" 'amneziawg.ko'
printf '%s\n' "$tools_dump" | require_single_payload_file 'usr/bin' 'awg'
printf '%s\n' "$tools_dump" | require_single_payload_file 'usr/bin' 'amneziawg_watchdog'
printf '%s\n' "$tools_dump" | require_single_payload_file 'lib/netifd/proto' 'amneziawg.sh'

cp "$kmod_apk" "$tools_apk" "$output_dir/"
(cd "$output_dir" && sha256sum ./*.apk | sed 's#  \./#  #' | LC_ALL=C sort > SHA256SUMS)
cat > "$output_dir/build-metadata.txt" <<EOF
kernel_source_version=1.0.20260611
kernel_source_sha256=e062ecc9f1d89eeafa9f56a29473372a1d796ee061eaa8c7b61eeb51c38b80d6
tools_source_version=1.0.20260618-2
tools_source_sha256=cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10
openwrt_revision=$revision
kernel_version=$kernel
kernel_vermagic=$vermagic
package_architecture=$architecture
source_date_epoch=$SOURCE_DATE_EPOCH
EOF
