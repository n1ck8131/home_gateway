# Project Status

Current phase: P3 RedShield-backed Windows pilot in progress
Release level: P2-software-verified; P3.5-persistent-sinks-offline-implementation-complete

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

- State: P3.1 through P3.5 complete for their offline/software scope; P3.5 live safety matrix and `pc-core-ready` remain pending separate authorization
- Plan: [P3 RedShield-backed Windows implementation plan](docs/superpowers/plans/2026-08-24-p03-redshield-windows.md)
- Architecture: [ADR-0011](docs/adr/ADR-0011-pc-first-platform-tunnel-boundary.md) keeps policy/API semantics independent from the Windows/OpenWrt platform and RedShield/self-hosted tunnel backends
- Offline mutation architecture: [ADR-0012](docs/adr/ADR-0012-windows-offline-mutation-ownership.md) defines strict project ownership, qualified endpoint binding, additive-first fail-closed ordering, durable commit-confirm/recovery states and exact restoration boundaries
- Persistent sink architecture: [ADR-0013](docs/adr/ADR-0013-windows-persistent-sink-routes.md) records the dedicated persistent loopback sink exception, emergency-disable retention, full-restore-last removal and the separate live mutation gate
- Real-config qualification on 2026-08-24: the user-supplied external `.conf` passed the strict one-interface/one-peer AmneziaWG importer with IPv4/IPv6 full-tunnel capability; key material was neither printed nor copied into repository evidence
- Latest read-only Windows preflight on 2026-08-24: one active WireGuard/Amnezia adapter matches both imported interface addresses, a physical endpoint host route was observed, and IPv4/IPv6 fail-closed prerequisites were identified. The command returned the expected blocked exit code `3`
- P3.3 live evidence on 2026-08-25: the production collector completed an opt-in read-only smoke against this Windows host and returned authoritative structured ActiveStore routes and metrics, stable adapter GUIDs and hardware markers, effective DNS servers and the effective NRPT rule count. No route, DNS, firewall, service, adapter, RedShield or Cisco state was changed
- `read_only_qualified` is separate from live apply readiness: provider handshake/egress remains unobserved until the P3.5 live canary, `ready` remains false, and no native/live mutation adapter or operator command is exposed
- A fresh combined preflight with the prior `Netherlands.conf` was not run because the external file is no longer present at the supplied path. The earlier importer/baseline evidence remains valid, but current-PC field acceptance is not claimed
- Cisco was active in an earlier read-only snapshot but inactive in the latest combined preflight. Its configuration, profile, service and routes were not changed; Cisco preservation field evidence remains open
- The previously inspected external config had a broad read permission. That was acceptable for bounded interactive inspection, but any replacement must have restrictive access before an unattended service can consume it
- Local P3.3 evidence on 2026-08-25: focused tests and the production live read-only collector smoke passed. The phase-closing `verify` batch passed all Go tests, 41 Pester tests, format, vet, staticcheck, gosec with zero issues, govulncheck with no callable vulnerabilities, repository and working-tree secret scans, governance/toolchain smokes and reproducible four-target builds
- Local P3.4 evidence on 2026-08-25: strict Windows route/firewall/NRPT artifacts, immutable revision manifests, hashed semantic snapshots, deterministic ownership, qualified provider endpoints, durable disable/restore intents and LKG rollback passed fault injection for activation, reload, post-check, pruning, timeout, process restart, missing pending manifests and persistent recovery faults. The final `verify` batch passed all Go tests, 41 Pester tests, format, vet, staticcheck, gosec with zero issues, govulncheck with no callable vulnerabilities, secret/workflow scans, governance/toolchain smokes and reproducible four-target builds. See the [P3.4 phase report](docs/reports/2026-08-25-p34-offline-mutation.md)
- Local P3.5 offline evidence on 2026-08-26: persistent fail-closed sink artifacts/backend, effective-route resolution, redacted CLI evidence and durable watchdog semantics passed focused Go tests, exact Windows PowerShell 5.1 and PowerShell 7 read-only Pester contracts, direct gitleaks and the full `verify` gate. The safe read-only preflight shape is `ready=true`, `exit_code=0`, PktMon stopped/no filters, zero exact Active/Persistent collisions, qualified IPv4 default, qualified IPv6 no-route and both loopbacks ready. No config contents, secrets, DNS addresses, target values, endpoints or adapter names are recorded. See the [P3.5 phase report](docs/reports/2026-08-26-p35-persistent-sinks.md)
- Branch: `phase/p3-redshield-windows`, based on completed `phase/p2-dataplane`

## External gates

- P3 bounded native Windows canary and route/firewall/DNS mutation: field-not-run; P3.5 offline persistent-sink evidence now passes, but live safety matrix execution, provider handshake/egress health, terminal `FullRestore` field evidence and `pc-core-ready` require separate authorization
- Own VPS: not available; first required by P8 and not a P3-P7 blocker
- GL-MT6000 hardware smoke, exact-kernel module/UAPI and router-to-VPS handshake: not-run; P12 gates and not P3-P11 blockers
- Second VPS failover: P9 gate
- Cisco field test: P7 gate

## Blockers

- P1 software blockers: none
- P2 software blockers: none
- P3.5 offline software blockers: none. Live Windows mutation, provider handshake/egress, reboot/reconcile field evidence and terminal `FullRestore` remain deliberately unavailable until separate confirmation.
- Fresh combined real-config replay remains an external evidence gap until the user-supplied config is available again. Provider handshake and egress are P3.5 field gates, not inferred P3.3 status.
- `pc-core-ready` remains open until real direct/RedShield/Cisco, IPv4/IPv6 fail-closed, restart/recovery and full uninstall restoration evidence passes on the current Windows PC.
- P2 does not claim Windows field acceptance, Flint 2 hardware compatibility or throughput.
