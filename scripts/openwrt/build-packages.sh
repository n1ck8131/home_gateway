#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
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

sdk="$($root/scripts/openwrt/fetch-sdk.sh)"
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
kernel="$(make -s -C "$sdk" val.LINUX_VERSION)"
vermagic="$(make -s -C "$sdk" val.LINUX_VERMAGIC)"
architecture="$(make -s -C "$sdk" val.ARCH_PACKAGES)"
test "$revision" = 'r33051-f5dae5ece4'
test "$kernel" = '6.12.94'
test "$vermagic" = '5a6c1f71be683ae9980b15d3ce73e24d'
test "$architecture" = 'aarch64_cortex-a53'

set -- $(find "$sdk/bin" -type f -name 'kmod-amneziawg-*.apk')
test "$#" -eq 1
kmod_apk="$1"
set -- $(find "$sdk/bin" -type f -name 'amneziawg-tools-*.apk')
test "$#" -eq 1
tools_apk="$1"
apk_host="$sdk/staging_dir/host/bin/apk"
test -x "$apk_host"
kmod_dump="$($apk_host adbdump "$kmod_apk")"
tools_dump="$($apk_host adbdump "$tools_apk")"
printf '%s\n' "$kmod_dump" | grep -F 'aarch64_cortex-a53'
printf '%s\n' "$tools_dump" | grep -F 'aarch64_cortex-a53'
printf '%s\n' "$kmod_dump" | grep -F 'kernel=6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1'
printf '%s\n' "$tools_dump" | grep -F 'kmod-amneziawg'
printf '%s\n' "$kmod_dump" | grep -F '/lib/modules/6.12.94/amneziawg.ko'
printf '%s\n' "$tools_dump" | grep -F '/usr/bin/awg'
printf '%s\n' "$tools_dump" | grep -F '/usr/bin/amneziawg_watchdog'
printf '%s\n' "$tools_dump" | grep -F '/lib/netifd/proto/amneziawg.sh'

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
