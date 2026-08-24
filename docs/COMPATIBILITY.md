# Compatibility Matrix

| Component | Version | State | Evidence |
|---|---|---|---|
| OpenWrt target metadata | 25.12.5 / r33051-f5dae5ece4 | verified-upstream | Official profiles.json and sha256sums |
| AWG2 kernel source | v1.0.20260611 / 2a6e1a02ac024f54a23e18f894a279b7f870b8fb | verified-upstream | Official tag and source hash |
| AWG2 tools source | v1.0.20260618-2 / 61e741780e8465a67a7d7fb6cffe14a8a15d624a | verified-upstream | Official tag and source hash |
| AWG2 OpenWrt packages | `amneziawg-tools-1.0.20260618.2-r1.apk`; `kmod-amneziawg-6.12.94.1.0.20260611-r1.apk` | built-in-sdk | [SDK run 29273568884](https://github.com/n1ck8131/home_gateway/actions/runs/29273568884), two clean output trees byte-identical. Tools: 32,434 bytes, SHA-256 `c22cb283a55e52b285bef68abfea18c9be908d1ff17f82d601bd919391570c7e`. Kmod: 40,954 bytes, SHA-256 `db46f2e467ff1d891bad7f83affdbde59ad05e53a9a4a2e53173a83586093205` |
| AWG2 userspace contingency | v0.2.19 / 1cc94272ca8e9e223a5fe76382f5880f09d3c12d | built-in-sdk | `linux/arm64`, `CGO_ENABLED=0`, 3,276,962 bytes, SHA-256 `e7f06b35cbc8523ef2db201afa64a15c4f7d56dbb8e2698da8bf727d0b5e10cb`; same reproducible SDK run |
| Windows P3 target | Windows 11 Pro 10.0.26200 x64; Windows PowerShell 5.1.26100.9168; PowerShell 7.6.4 | read-only-baseline | Latest preflight matched the active WireGuard/Amnezia adapter to both imported addresses and observed an endpoint host route, but remains blocked on authoritative routes, DNS/NRPT and tunnel status. Cisco was inactive in the latest snapshot; no project network mutation has been run |
| RedShield bootstrap config | External WireGuard/AmneziaWG `.conf` | format-qualified | One-interface/one-peer AWG fields and IPv4/IPv6 full-tunnel capability validated locally with key and endpoint values omitted from evidence |
| AWG2 hardware UAPI | Exact Flint 2 kernel | prepared-for-hardware | P12 gate |
| Router-to-VPS handshake | Exact router and self-hosted VPS | blocked | P12 owns this field gate after the P8 backend exists |

The official OpenWrt 25.12 x86_64 feed served different bytes for `libelf1-0.192-r1.apk` under the same versioned filename on 2026-08-23. The P2 lock now records SHA-256 `708a8992361a5bd18e7158f92961569cb904dc74c0525d67c906ccedb8404334`. The QEMU harness downloads only the approved HTTPS URL, verifies the lock before installation and fails closed if that mutable upstream object changes again.

The run uploaded artifact `verified-openwrt-outputs` (artifact ID `8289217558`, archive SHA-256 `f9d922c057d0fa6d6b82d535a6eab6239c4f087ca85e6ca8bf2143348266c42a`). GitHub retention expires on 2026-07-20; the recorded output hashes remain the durable verification evidence.

`built-in-sdk` proves reproducible software output only. Exact-kernel module/UAPI loading and a real router-to-VPS handshake remain `prepared-for-hardware`/`blocked` P12 gates; no hardware or throughput result is claimed by P0-P3.
