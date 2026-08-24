# Project Status

Current phase: P2 Production Dataplane complete; P3 next
Release level: P2-software-verified; P3-hardware-not-run

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

## External gates

- GL-MT6000 hardware smoke, including exact-kernel module/UAPI verification: not-run
- Router-to-VPS AWG2 handshake: P3 gate
- Second VPS failover: P9 gate
- Cisco field test: P7 gate

## Blockers

- P1 software blockers: none
- P2 software blockers: none
- P3 still requires the exact GL-MT6000 kernel module/UAPI smoke, router package lifecycle and a real router-to-VPS AWG2 handshake. P2 does not claim hardware compatibility or throughput.
