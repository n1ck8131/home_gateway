# Project Status

Current phase: P3 Single-server AmneziaWG
Release level: P2-software-verified; P3.2/P3.3-software-verified; P3.4/P3.5-open; P3-hardware-not-run

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

## P3 Single-server AmneziaWG

- State: P3.1 through P3.3 software boundaries verified; P3.4, P3.5 and physical gates remain open
- Plan: [P3 single-server AmneziaWG implementation plan](docs/superpowers/plans/2026-08-24-p03-single-awg.md)
- First slice: `server-agent health --json` provides process-scoped liveness only; it does not claim AWG, VPS or tunnel health and exposes no network listener
- P3.1 evidence for commit `bdaec0b30f3152c47f37cca7f88f663b8b310976`: [CI run 32700597504](https://github.com/n1ck8131/home_gateway/actions/runs/32700597504), [OpenWrt QEMU run 32700597472](https://github.com/n1ck8131/home_gateway/actions/runs/32700597472) and [OpenWrt SDK run 32700597475](https://github.com/n1ck8131/home_gateway/actions/runs/32700597475) passed
- P3.2 software: hash-verified non-secret VPS bundle, pre-mutation snapshot/idempotent deployment saga, recovery-gated SSH hardening and redacted AWG transport health
- P3.3 software: strict OpenWrt peer/UCI plan, WAN endpoint host-route ordering, stale secret/mark cleanup, P2 fail-closed binding and guarded `private_key_file` support
- Local evidence: full Windows and Ubuntu repository `verify`, focused Go/Pester/shell checks, pinned ShellCheck, two clean byte-identical OpenWrt SDK outputs and independent QA/security audits passed
- Hosted evidence for commit `52a896717e0f01359d6eaedb4db9d9e949ac5000`: [CI run 32712734828](https://github.com/n1ck8131/home_gateway/actions/runs/32712734828) passed Windows/Linux verification, Linux race tests and the network namespace evidence gate; [OpenWrt QEMU run 32712734929](https://github.com/n1ck8131/home_gateway/actions/runs/32712734929) passed the rollback/LKG regression; [OpenWrt SDK run 32712734846](https://github.com/n1ck8131/home_gateway/actions/runs/32712734846) reproduced byte-identical clean package and userspace outputs and passed the helper ShellCheck gate
- Next implementation after this validation: P3.4 router package lifecycle, then P3.5 physical router/VPS acceptance
- Branch: `phase/p3-single-awg`, based on closed P2 commit `c5adeae`

## External gates

- GL-MT6000 hardware smoke, including exact-kernel module/UAPI verification: not-run
- Router-to-VPS AWG2 handshake: P3 gate
- Second VPS failover: P9 gate
- Cisco field test: P7 gate

## Blockers

- P1 software blockers: none
- P2 software blockers: none
- P3 still requires the exact GL-MT6000 kernel module/UAPI smoke, router package lifecycle and a real router-to-VPS AWG2 handshake. P2 does not claim hardware compatibility or throughput.
