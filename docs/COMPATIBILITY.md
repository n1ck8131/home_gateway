# Compatibility Matrix

| Component | Version | State | Evidence |
|---|---|---|---|
| OpenWrt target metadata | 25.12.5 / r33051-f5dae5ece4 | verified-upstream | Official profiles.json and sha256sums |
| AWG2 kernel source | v1.0.20260611 / 2a6e1a02ac024f54a23e18f894a279b7f870b8fb | verified-upstream | Official tag and source hash |
| AWG2 tools source | v1.0.20260618-2 / 61e741780e8465a67a7d7fb6cffe14a8a15d624a | verified-upstream | Official tag and source hash |
| AWG2 OpenWrt packages | P0 build | prepared-for-hardware | SDK build evidence is added during Task 10 |
| AWG2 userspace contingency | v0.2.19 / 1cc94272ca8e9e223a5fe76382f5880f09d3c12d | blocked | Missing clean Linux build evidence for the reproducible linux/arm64 binary, measured size, and SHA-256 |
| AWG2 hardware UAPI | Exact Flint 2 kernel | prepared-for-hardware | P3 precondition |
| Router-to-VPS handshake | Exact router and VPS | blocked | P3 owns this field gate |
