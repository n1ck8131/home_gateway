# Compatibility Matrix

| Component | Version | State | Evidence |
|---|---|---|---|
| OpenWrt target metadata | 25.12.5 / r33051-f5dae5ece4 | verified-upstream | Official profiles.json and sha256sums |
| AWG2 kernel source | v1.0.20260611 / 2a6e1a02ac024f54a23e18f894a279b7f870b8fb | verified-upstream | Official tag and source hash |
| AWG2 tools source | v1.0.20260618-2 / 61e741780e8465a67a7d7fb6cffe14a8a15d624a | verified-upstream | Official tag and source hash |
| AWG2 OpenWrt packages | `amneziawg-tools-1.0.20260618.2-r2.apk`; `kmod-amneziawg-6.12.94.1.0.20260611-r1.apk` | built-in-sdk | Local pinned validation and [hosted SDK run 32712734846](https://github.com/n1ck8131/home_gateway/actions/runs/32712734846) for commit `52a896717e0f01359d6eaedb4db9d9e949ac5000` produced two clean byte-identical output trees. Tools: 33,118 bytes, SHA-256 `2eae2da601281c8ece9bf86bb6245d1af42fa736f0b738e030dc2014a0930ff9`. Kmod: 40,954 bytes, SHA-256 `db46f2e467ff1d891bad7f83affdbde59ad05e53a9a4a2e53173a83586093205` |
| AWG2 userspace contingency | v0.2.19 / 1cc94272ca8e9e223a5fe76382f5880f09d3c12d | built-in-sdk | `linux/arm64`, `CGO_ENABLED=0`, 3,276,962 bytes, SHA-256 `e7f06b35cbc8523ef2db201afa64a15c4f7d56dbb8e2698da8bf727d0b5e10cb`; reproduced by the same local and hosted SDK gate |
| `routerd` OpenWrt APK | 0.3.4-r2 / Go 1.26.6 / `aarch64_cortex-a53` | built-in-sdk | P3.4 cross-builds a static `linux/arm64` binary, validates exact APK metadata/payload and maintainer scripts, exercises r1-to-r2 install/upgrade/remove in an isolated SDK-host root, preserves unowned UCI/dataplane fixtures and compares two clean output trees byte-for-byte. r2: 1,226,163 bytes, SHA-256 `b44a00d78849b697b29d2645fe3095bbf8de921777f62d7542d596191d108ee4`; r1 lifecycle fixture: 1,226,163 bytes, SHA-256 `4b06ec4b46968aa92a1911effd3da1c0e6cccd473c82b9e1b028ccd7f94b2c01` |
| AWG2 hardware UAPI | Exact Flint 2 kernel | prepared-for-hardware | P3 precondition |
| `routerd` physical lifecycle | Exact Flint 2 firmware/kernel | blocked | Static procd/package checks do not prove ARM execution, service boot ordering or LKG recovery on the router |
| Router-to-VPS handshake | Exact router and VPS | blocked | P3 owns this field gate |

The official OpenWrt 25.12 x86_64 feed served different bytes for `libelf1-0.192-r1.apk` under the same versioned filename on 2026-08-23. The P2 lock now records SHA-256 `708a8992361a5bd18e7158f92961569cb904dc74c0525d67c906ccedb8404334`. The QEMU harness downloads only the approved HTTPS URL, verifies the lock before installation and fails closed if that mutable upstream object changes again.

The run uploaded artifact `verified-openwrt-outputs` (artifact ID `8289217558`, archive SHA-256 `f9d922c057d0fa6d6b82d535a6eab6239c4f087ca85e6ca8bf2143348266c42a`). GitHub retention expires on 2026-07-20; the recorded output hashes remain the durable verification evidence.

`built-in-sdk` proves reproducible software output only. It does not prove ARM
execution, procd integration, boot ordering or LKG recovery. Exact-kernel
module/UAPI loading and a real router-to-VPS handshake remain
`prepared-for-hardware`/`blocked` P3 gates; no hardware or throughput result is
claimed.
