#!/bin/sh
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)"
lock="$root/manifest/versions.lock.yaml"
locked_epoch="$(jq -er '.openwrt.source_date_epoch' "$lock")"
routerd_version="$(jq -er '.routerd.version' "$lock")"
routerd_release="$(jq -er '.routerd.release' "$lock")"
locked_go_version="$(jq -er '.routerd.go_version' "$lock")"
routerd_architecture="$(jq -er '.routerd.package_arch' "$lock")"
routerd_artifact_name="$(jq -er '.routerd.artifact.filename' "$lock")"
locked_routerd_artifact_sha256="$(jq -er '.routerd.artifact.sha256' "$lock")"
routerd_lifecycle_r1_name="$(jq -er '.routerd.lifecycle_r1.filename' "$lock")"
locked_routerd_lifecycle_r1_sha256="$(jq -er '.routerd.lifecycle_r1.sha256' "$lock")"

test "$routerd_version" = '0.3.4'
test "$routerd_release" = '2'
test "$locked_go_version" = '1.26.6'
test "$routerd_architecture" = 'aarch64_cortex-a53'
test "$routerd_artifact_name" = 'routerd_0.3.4_aarch64_cortex-a53.apk'
test "$routerd_lifecycle_r1_name" = 'routerd-0.3.4-r1.apk'
printf '%s\n' "$locked_routerd_artifact_sha256" | grep -Eq '^[0-9a-f]{64}$'
printf '%s\n' "$locked_routerd_lifecycle_r1_sha256" | grep -Eq '^[0-9a-f]{64}$'

if [ "${SOURCE_DATE_EPOCH+x}" = x ] && [ "$SOURCE_DATE_EPOCH" != "$locked_epoch" ]; then
	echo "SOURCE_DATE_EPOCH conflicts with manifest lock" >&2
	exit 1
fi
export SOURCE_DATE_EPOCH="$locked_epoch"

artifacts_root="$root/artifacts"
mkdir -p "$artifacts_root"
resolved_artifacts_root="$(realpath -e -- "$artifacts_root")"
if [ "$resolved_artifacts_root" != "$artifacts_root" ]; then
	echo "repository artifacts directory must not be a symlink" >&2
	exit 1
fi
requested_output_dir="${OUTPUT_DIR:-$artifacts_root/openwrt/aarch64_cortex-a53}"
case "$requested_output_dir" in
	/*) ;;
	*) echo "OUTPUT_DIR must be absolute" >&2; exit 1 ;;
esac
lexical_output_dir="$(realpath -ms -- "$requested_output_dir")"
output_dir="$(realpath -m -- "$requested_output_dir")"
if [ "$output_dir" != "$lexical_output_dir" ]; then
	echo "OUTPUT_DIR must not contain symlinks or redirected path components" >&2
	exit 1
fi
case "$output_dir" in
	"$resolved_artifacts_root"/*) ;;
	*) echo "OUTPUT_DIR must resolve to a child of repository artifacts" >&2; exit 1 ;;
esac
rm -rf "$output_dir"
mkdir -p "$output_dir" "$root/.cache"

cache_root="$(realpath -e -- "$root/.cache")"
if [ "$cache_root" != "$root/.cache" ]; then
	echo "repository cache directory must not be a symlink" >&2
	exit 1
fi

package_work="$(mktemp -d "$cache_root/routerd-package.XXXXXX")"
cleanup() {
	cleanup_path="$package_work"
	package_work=''
	[ -n "$cleanup_path" ] || return 0
	if [ ! -e "$cleanup_path" ] && [ ! -L "$cleanup_path" ]; then
		return 0
	fi
	resolved_cleanup_path="$(realpath -e -- "$cleanup_path")" || {
		echo "refusing unresolved package cleanup path: $cleanup_path" >&2
		return 1
	}
	[ "$resolved_cleanup_path" = "$cleanup_path" ] || {
		echo "refusing redirected package cleanup path: $cleanup_path" >&2
		return 1
	}
	case "$resolved_cleanup_path" in
		"$cache_root"/routerd-package.*) ;;
		*) echo "refusing unsafe package cleanup path: $resolved_cleanup_path" >&2; return 1 ;;
	esac
	rm -rf -- "$resolved_cleanup_path"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

go_bin="${GO_BIN:-$root/.tools/go/bin/go}"
if [ -z "${GO_BIN:-}" ] && [ ! -x "$go_bin" ]; then
	go_bin="$(command -v go)"
fi
test "$("$go_bin" env GOVERSION)" = "go$locked_go_version"
export GOWORK=off
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly

cd "$root"
"$go_bin" mod verify
source_files="$package_work/routerd-source-files.txt"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$go_bin" list -deps -json ./cmd/routerd |
	jq -r '
		select(.Module.Main == true) |
		.Dir as $dir |
		[(.GoFiles // []), (.EmbedFiles // []), (.SFiles // []), (.SysoFiles // [])] |
		add[] |
		"\($dir)/\(.)"
	' > "$source_files"
printf '%s\n' "$root/go.mod" "$root/go.sum" >> "$source_files"
LC_ALL=C sort -u "$source_files" > "$source_files.sorted"
mv "$source_files.sorted" "$source_files"
test -s "$source_files"

source_manifest="$package_work/routerd-source-manifest.txt"
: > "$source_manifest"
while IFS= read -r source_path; do
	case "$source_path" in
		"$root"/*) ;;
		*) echo "routerd source escaped repository root: $source_path" >&2; exit 1 ;;
	esac
	test -f "$source_path"
	relative_path="${source_path#"$root"/}"
	file_digest="$(sha256sum "$source_path" | awk '{print $1}')"
	printf '%s  %s\n' "$file_digest" "$relative_path" >> "$source_manifest"
done < "$source_files"
routerd_source_digest="$(sha256sum "$source_manifest" | awk '{print $1}')"
case "$routerd_source_digest" in
	????????????????????????????????????????????????????????????????) ;;
	*) echo "invalid routerd source digest" >&2; exit 1 ;;
esac

routerd_build_date="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
routerd_binary="$package_work/routerd"
routerd_ldflags="-buildid= -s -w -X github.com/vsevo/home-gateway/internal/buildinfo.Version=$routerd_version -X github.com/vsevo/home-gateway/internal/buildinfo.Commit=sha256:$routerd_source_digest -X github.com/vsevo/home-gateway/internal/buildinfo.BuildDate=$routerd_build_date"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	"$go_bin" build -trimpath -buildvcs=false -ldflags="$routerd_ldflags" \
	-o "$routerd_binary" ./cmd/routerd

binary_description="$(file -b "$routerd_binary")"
case "$binary_description" in
	*"ELF 64-bit LSB executable"*"ARM aarch64"*"statically linked"*) ;;
	*) echo "routerd is not a static Linux arm64 ELF: $binary_description" >&2; exit 1 ;;
esac
if readelf -lW "$routerd_binary" | grep -q '[[:space:]]INTERP[[:space:]]'; then
	echo "routerd unexpectedly contains an ELF interpreter" >&2
	exit 1
fi
if readelf -dW "$routerd_binary" | grep -q '(NEEDED)'; then
	echo "routerd unexpectedly contains a dynamic dependency" >&2
	exit 1
fi
strings "$routerd_binary" | grep -F "sha256:$routerd_source_digest" >/dev/null
strings "$routerd_binary" | grep -F "$routerd_build_date" >/dev/null
"$go_bin" version -m "$routerd_binary" | grep -F 'GOOS=linux' >/dev/null
"$go_bin" version -m "$routerd_binary" | grep -F 'GOARCH=arm64' >/dev/null
"$go_bin" version -m "$routerd_binary" | grep -F 'CGO_ENABLED=0' >/dev/null

sdk="$("$root/scripts/openwrt/fetch-sdk.sh")"

stage_packages() {
	rm -rf "$sdk/package/home-gateway"
	mkdir -p "$sdk/package/home-gateway"
	cp -a "$root/packaging/openwrt-awg2/." "$sdk/package/home-gateway/"
	cp -a "$root/packaging/openwrt-apk/routerd" "$sdk/package/home-gateway/routerd"
	cp "$routerd_binary" "$sdk/package/home-gateway/routerd/files/routerd"
	find "$sdk/package/home-gateway/routerd" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

stage_packages
: > "$sdk/.config"
printf '%s\n' \
	'# CONFIG_ALL is not set' \
	'# CONFIG_ALL_KMODS is not set' \
	'# CONFIG_ALL_NONSHARED is not set' \
	'CONFIG_PACKAGE_kmod-amneziawg=m' \
	'CONFIG_PACKAGE_amneziawg-tools=m' \
	'CONFIG_PACKAGE_routerd=m' \
	>> "$sdk/.config"
make -C "$sdk" defconfig
grep -qx '# CONFIG_ALL is not set' "$sdk/.config"
grep -qx '# CONFIG_ALL_KMODS is not set' "$sdk/.config"
grep -qx '# CONFIG_ALL_NONSHARED is not set' "$sdk/.config"
grep -qx 'CONFIG_PACKAGE_kmod-amneziawg=m' "$sdk/.config"
grep -qx 'CONFIG_PACKAGE_amneziawg-tools=m' "$sdk/.config"
grep -qx 'CONFIG_PACKAGE_routerd=m' "$sdk/.config"

stage_packages
make -C "$sdk" package/kmod-amneziawg/clean
make -C "$sdk" package/amneziawg-tools/clean
ROUTERD_PACKAGE_RELEASE=1 make -C "$sdk" package/routerd/clean
make -C "$sdk" package/kmod-amneziawg/compile V=s
make -C "$sdk" package/amneziawg-tools/compile V=s
ROUTERD_PACKAGE_RELEASE=1 make -C "$sdk" package/routerd/compile V=s

find_single_apk() {
	apk_matches="$(find "$sdk/bin" -type f -name "$1")"
	case "$apk_matches" in
		'' | *'
'*) return 1 ;;
	esac
	printf '%s\n' "$apk_matches"
}

routerd_r1_apk="$(find_single_apk 'routerd-0.3.4-r1.apk')"
routerd_r1_evidence="$package_work/routerd-0.3.4-r1.apk"
cp "$routerd_r1_apk" "$routerd_r1_evidence"
ROUTERD_PACKAGE_RELEASE=2 make -C "$sdk" package/routerd/clean
ROUTERD_PACKAGE_RELEASE=2 make -C "$sdk" package/routerd/compile V=s

revision="$(make -s -C "$sdk" val.REVISION)"
architecture="$(make -s -C "$sdk" val.ARCH_PACKAGES)"
test "$revision" = 'r33051-f5dae5ece4'
test "$architecture" = "$routerd_architecture"

kmod_apk="$(find_single_apk 'kmod-amneziawg-*.apk')"
tools_apk="$(find_single_apk 'amneziawg-tools-*.apk')"
routerd_r2_apk="$(find_single_apk 'routerd-0.3.4-r2.apk')"
apk_host="$sdk/staging_dir/host/bin/apk"
apk_validator="$root/scripts/openwrt/apk-validation.jq"
test -x "$apk_host"
test -f "$apk_validator"
kmod_dump="$("$apk_host" adbdump --format json "$kmod_apk")"
tools_dump="$("$apk_host" adbdump --format json "$tools_apk")"
routerd_r1_dump="$("$apk_host" adbdump --format json "$routerd_r1_evidence")"
routerd_r2_dump="$("$apk_host" adbdump --format json "$routerd_r2_apk")"

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
	jq -e \
		--arg mode 'package-dependency' \
		--arg expected "$expected" \
		-f "$apk_validator" >/dev/null
}

require_no_dependencies() {
	jq -e '
		(.info | type) == "object" and
		(
			(.info | has("depends") | not) or
			(
				(.info.depends | type) == "array" and
				all(.info.depends[]; type == "string") and
				(.info.depends | length) == 0
			)
		)
	' >/dev/null
}

require_routerd_maintainer_scripts() {
	jq -e '
		(.scripts | type) == "object" and
		(.scripts["post-install"] | type) == "string" and
		(.scripts["post-install"] | contains("pkgname=\"routerd\"")) and
		(.scripts["post-install"] | contains("default_postinst")) and
		(.scripts["post-upgrade"] | type) == "string" and
		(.scripts["post-upgrade"] | contains("PKG_UPGRADE=1")) and
		(.scripts["post-upgrade"] | contains("default_postinst")) and
		(.scripts["pre-deinstall"] | type) == "string" and
		(.scripts["pre-deinstall"] | contains("default_prerm"))
	' >/dev/null
}

require_single_payload_file() {
	expected="$1"
	jq -e \
		--arg mode 'payload' \
		--arg expected "$expected" \
		-f "$apk_validator" >/dev/null
}

routerd_payload_files() {
	jq -er '
		.paths as $paths |
		if ($paths | type) != "array" or (all($paths[]; type == "object") | not) then
			error("malformed routerd APK payload")
		else
			[
				$paths[] as $path |
				($path.files? // [])[] |
				if ($path.name? // "") == "" then .name else "\($path.name)/\(.name)" end
			] | sort | .[]
		end
	'
}

kernel_tuple="$(printf '%s\n' "$kmod_dump" | jq -ec \
	--arg mode 'kernel' \
	--arg expected '' \
	-f "$apk_validator")"
kernel="$(printf '%s\n' "$kernel_tuple" | jq -er '.kernel | select(type == "string")')"
vermagic="$(printf '%s\n' "$kernel_tuple" | jq -er '.vermagic | select(type == "string")')"
test "$kernel" = '6.12.94'
test "$vermagic" = '5a6c1f71be683ae9980b15d3ce73e24d'

printf '%s\n' "$kmod_dump" | require_apk_info_field name 'kmod-amneziawg'
printf '%s\n' "$tools_dump" | require_apk_info_field name 'amneziawg-tools'
printf '%s\n' "$kmod_dump" | require_apk_info_field arch "$architecture"
printf '%s\n' "$tools_dump" | require_apk_info_field arch "$architecture"
printf '%s\n' "$tools_dump" | require_single_dependency 'kmod-amneziawg'
printf '%s\n' "$kmod_dump" | require_single_payload_file "lib/modules/$kernel/amneziawg.ko"
printf '%s\n' "$tools_dump" | require_single_payload_file 'usr/bin/awg'
printf '%s\n' "$tools_dump" | require_single_payload_file 'usr/bin/amneziawg_watchdog'
printf '%s\n' "$tools_dump" | require_single_payload_file 'lib/netifd/proto/amneziawg.sh'

printf '%s\n' "$routerd_r1_dump" | require_apk_info_field name 'routerd'
printf '%s\n' "$routerd_r1_dump" | require_apk_info_field version '0.3.4-r1'
printf '%s\n' "$routerd_r1_dump" | require_apk_info_field arch "$architecture"
printf '%s\n' "$routerd_r1_dump" | require_no_dependencies
printf '%s\n' "$routerd_r1_dump" | require_routerd_maintainer_scripts
printf '%s\n' "$routerd_r2_dump" | require_apk_info_field name 'routerd'
printf '%s\n' "$routerd_r2_dump" | require_apk_info_field version '0.3.4-r2'
printf '%s\n' "$routerd_r2_dump" | require_apk_info_field arch "$architecture"
printf '%s\n' "$routerd_r2_dump" | require_no_dependencies
printf '%s\n' "$routerd_r2_dump" | require_routerd_maintainer_scripts

expected_routerd_payload='etc/init.d/routerd
lib/apk/packages/routerd.list
usr/bin/routerd'
test "$(printf '%s\n' "$routerd_r1_dump" | routerd_payload_files)" = "$expected_routerd_payload"
test "$(printf '%s\n' "$routerd_r2_dump" | routerd_payload_files)" = "$expected_routerd_payload"
printf '%s\n' "$routerd_r2_dump" | require_single_payload_file 'etc/init.d/routerd'
printf '%s\n' "$routerd_r2_dump" | require_single_payload_file 'usr/bin/routerd'

sh "$root/tests/openwrt-sdk/assert-routerd-lifecycle.sh" \
	"$apk_host" "$routerd_r1_evidence" "$routerd_r2_apk" "$architecture"

cp "$kmod_apk" "$tools_apk" "$output_dir/"
cp "$routerd_r2_apk" "$output_dir/$routerd_artifact_name"
(cd "$output_dir" && sha256sum ./*.apk | sed 's#  \./#  #' | LC_ALL=C sort > SHA256SUMS)
lifecycle_output="$output_dir/lifecycle"
mkdir -p "$lifecycle_output"
cp "$routerd_r1_evidence" "$lifecycle_output/$routerd_lifecycle_r1_name"
(cd "$lifecycle_output" && sha256sum "$routerd_lifecycle_r1_name" > SHA256SUMS)
routerd_binary_sha256="$(sha256sum "$routerd_binary" | awk '{print $1}')"
routerd_apk_sha256="$(sha256sum "$output_dir/$routerd_artifact_name" | awk '{print $1}')"
routerd_lifecycle_r1_sha256="$(sha256sum "$lifecycle_output/$routerd_lifecycle_r1_name" | awk '{print $1}')"
if [ "$routerd_apk_sha256" != "$locked_routerd_artifact_sha256" ]; then
	echo "routerd r2 APK SHA256 differs from manifest lock" >&2
	exit 1
fi
if [ "$routerd_lifecycle_r1_sha256" != "$locked_routerd_lifecycle_r1_sha256" ]; then
	echo "routerd r1 lifecycle APK SHA256 differs from manifest lock" >&2
	exit 1
fi
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
routerd_version=$routerd_version
routerd_release=$routerd_release
routerd_go_version=go$locked_go_version
routerd_build_date=$routerd_build_date
routerd_source_digest=sha256:$routerd_source_digest
routerd_binary_sha256=$routerd_binary_sha256
routerd_artifact=$routerd_artifact_name
routerd_apk_sha256=$routerd_apk_sha256
routerd_lifecycle_r1_artifact=lifecycle/$routerd_lifecycle_r1_name
routerd_lifecycle_r1_sha256=$routerd_lifecycle_r1_sha256
EOF
