# Project Status

Current phase: P3 RedShield-backed Windows pilot in progress
Release level: P2-software-verified; P3-read-only-baseline

## P0A Foundation

- State: complete
- Evidence: [CI run 29273568922](https://github.com/n1ck8131/home_gateway/actions/runs/29273568922) passed Linux `make verify`, `go test -race`, the `CAP_NET_ADMIN` network prerequisite, Windows bootstrap, and Windows dev verification for commit `cf1773955e3d796e425cb6d6b75053928d77de61`.

## P0B Compatibility

- State: complete
- Evidence: [OpenWrt SDK run 29273568884](https://github.com/n1ck8131/home_gateway/actions/runs/29273568884) produced byte-identical outputs from two clean build trees for the pinned AWG2 packages and userspace contingency at commit `cf1773955e3d796e425cb6d6b75053928d77de61`.

## P1 Deterministic Policy Core

- State: complete
- Evidence: [CI run 29280880251](https://github.com/n1ck8131/home_gateway/actions/runs/29280880251) passed Windows and Linux verification, `go test -race`, the `CAP_NET_ADMIN` network prerequisite, and rollback smoke for commit `4bba257cff13203191c73843229d5e79db905d52`.
- Compatibility regression: [OpenWrt SDK run 29280879151](https://github.com/n1ck8131/home_gateway/actions/runs/29280879151) reproduced byte-identical outputs for commit `4bba257cff13203191c73843229d5e79db905d52`.
- Local evidence: the complete `verify` batch passed, and both domain and CIDR normalization fuzz targets passed 15-second campaigns.

## P2 Production Dataplane

- State: complete for the software and emulated OpenWrt scope
- Plan: [P2 production dataplane implementation plan](docs/superpowers/plans/2026-07-13-p02-production-dataplane.md)
- Implementation: deterministic nftables, policy-routing and suffix-DNS rendering; transactional apply, commit-confirm watchdog, rollback and boot reconciliation
- DNS capability boundary: exact and wildcard domain matches fail before transaction staging because dnsmasq nftset cannot preserve those semantics; [ADR-0010](docs/adr/ADR-0010-dnsmasq-domain-match-capability.md) records the decision
- Local evidence on 2026-08-24: full Windows verification and focused Go tests passed with no callable Go vulnerabilities; the Ubuntu 24.04 network namespace suite passed all traffic assertions and 20 tunnel fault cycles; the pinned OpenWrt 25.12.5 QEMU suite passed validation faults, post-check rollback, watchdog rollback, crash recovery and reboot/LKG reconciliation
- Hosted evidence for commit `150ffffb13bb81d83c3425146e1604368ea7eda2`: [CI run 32672264290](https://github.com/n1ck8131/home_gateway/actions/runs/32672264290) passed Windows/Linux verification, Linux race tests and the `network-ns-evidence` gate; [OpenWrt QEMU run 32672264286](https://github.com/n1ck8131/home_gateway/actions/runs/32672264286) passed with `openwrt-qemu-evidence`; [OpenWrt SDK run 32672264264](https://github.com/n1ck8131/home_gateway/actions/runs/32672264264) reproduced the pinned package/userspace outputs and ShellCheck gate
- Branch: `phase/p2-dataplane`, based on completed `phase/p1-policy-core`

## P3 RedShield-backed Windows pilot

- State: P3.1 and P3.2 complete; P3.3 in progress; no live network mutation performed
- Plan: [P3 RedShield-backed Windows implementation plan](docs/superpowers/plans/2026-08-24-p03-redshield-windows.md)
- Architecture: [ADR-0011](docs/adr/ADR-0011-pc-first-platform-tunnel-boundary.md) keeps policy/API semantics independent from the Windows/OpenWrt platform and RedShield/self-hosted tunnel backends
- Real-config qualification on 2026-08-24: the user-supplied external `.conf` passed the strict one-interface/one-peer AmneziaWG importer with IPv4/IPv6 full-tunnel capability; key material was neither printed nor copied into repository evidence
- Latest read-only Windows preflight on 2026-08-24: one active WireGuard/Amnezia adapter matches both imported interface addresses, a physical endpoint host route was observed, and IPv4/IPv6 fail-closed prerequisites were identified. The command returned the expected blocked exit code `3`
- The preflight remains blocked because the current collector intentionally marks its route snapshot non-authoritative, does not yet inspect effective DNS/NRPT policy, and cannot authoritatively observe provider tunnel status. Apply is unavailable
- Cisco was active in an earlier read-only snapshot but inactive in the latest one. Its configuration, profile, service and routes were not changed; Cisco preservation field evidence remains open
- The external config inherits a broad read permission. It is acceptable for the bounded interactive inspection, but must be tightened before any unattended service can consume the file
- Local software evidence: full Go tests, 41 Pester tests, format, vet, staticcheck, gosec, govulncheck, repository and working-tree secret scans, governance smoke and reproducible four-target build passed
- Branch: `phase/p3-redshield-windows`, based on completed `phase/p2-dataplane`

## External gates

- P3 bounded live Windows canary and route/firewall/DNS mutation: not-run; requires offline rollback evidence and separate confirmation
- Own VPS: not available; first required by P8 and not a P3-P7 blocker
- GL-MT6000 hardware smoke, exact-kernel module/UAPI and router-to-VPS handshake: not-run; P12 gates and not P3-P11 blockers
- Second VPS failover: P9 gate
- Cisco field test: P7 gate

## Blockers

- P1 software blockers: none
- P2 software blockers: none
- P3.3 still requires authoritative structured `Get-NetRoute`, DNS/NRPT and provider-status inventory, stable adapter identities and trusted System32/module resolution. P3.4 then owns project-marked apply, snapshot, rollback and recovery; none of these mutations is implemented or enabled yet.
- `pc-core-ready` remains open until real direct/RedShield/Cisco, IPv4/IPv6 fail-closed, restart/recovery and full uninstall restoration evidence passes on the current Windows PC.
- P2 does not claim Windows field acceptance, Flint 2 hardware compatibility or throughput.
