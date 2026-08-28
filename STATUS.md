# Project Status

Current phase: P3 self-hosted Windows pilot bootstrap
Release level: P2-software-verified; P3-self-hosted-server-bootstrap-complete; self-hosted-client-field-not-run

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

## P3 self-hosted Windows pilot

- State: `self-hosted-server-bootstrap-complete`; the provider-neutral AWG 3.1 importer, Windows tunnel path and DigitalOcean readiness guard passed the local software gate, and the bounded external bootstrap passed through Gate 6.3. UDP publication, guest/profile creation, Windows client activation, live safety matrix and `pc-core-ready` remain pending their separate gates
- Plan: [P3 Windows implementation plan](docs/superpowers/plans/2026-08-24-p03-redshield-windows.md) and [self-hosted DigitalOcean bootstrap plan](docs/superpowers/plans/2026-08-27-p3-self-hosted-digitalocean-bootstrap.md)
- Architecture: [ADR-0011](docs/adr/ADR-0011-pc-first-platform-tunnel-boundary.md) keeps policy/API semantics independent from platform/provider; [ADR-0016](docs/adr/ADR-0016-p3-self-hosted-digitalocean-bootstrap.md) moves the first own VPS and static PC peer into P3 while leaving automation, mobile lifecycle and telemetry in P8
- Offline mutation architecture: [ADR-0012](docs/adr/ADR-0012-windows-offline-mutation-ownership.md) defines strict project ownership, qualified endpoint binding, additive-first fail-closed ordering, durable commit-confirm/recovery states and exact restoration boundaries
- Persistent sink architecture: [ADR-0013](docs/adr/ADR-0013-windows-persistent-sink-routes.md) records the dedicated persistent loopback sink exception, emergency-disable retention, full-restore-last removal and the separate live mutation gate
- Historical RedShield config qualification on 2026-08-24: the user-supplied external `.conf` passed the strict one-interface/one-peer AmneziaWG importer with IPv4/IPv6 full-tunnel capability; key material was neither printed nor copied into repository evidence. This does not qualify the future self-hosted profile
- Historical RedShield read-only Windows preflight on 2026-08-24: one active WireGuard/Amnezia adapter matched both imported interface addresses, a physical endpoint host route was observed, and IPv4/IPv6 fail-closed prerequisites were identified. The command returned the expected blocked exit code `3`
- P3.3 live evidence on 2026-08-25: the production collector completed an opt-in read-only smoke against this Windows host and returned authoritative structured ActiveStore routes and metrics, stable adapter GUIDs and hardware markers, effective DNS servers and the effective NRPT rule count. No route, DNS, firewall, service, adapter, RedShield or Cisco state was changed
- `read_only_qualified` is separate from live apply readiness: self-hosted handshake/egress remains unobserved, `ready` remains false, and no self-hosted native/live mutation path is accepted
- A fresh combined preflight with the prior `Netherlands.conf` was not run because the external file is no longer present at the supplied path. The earlier importer/baseline evidence remains valid, but current-PC field acceptance is not claimed
- Cisco was active in an earlier read-only snapshot but inactive in the latest combined preflight. Its configuration, profile, service and routes were not changed; Cisco preservation field evidence remains open
- The previously inspected external config had a broad read permission. That was acceptable for bounded interactive inspection, but any replacement must have restrictive access before an unattended service can consume it
- Local P3.3 evidence on 2026-08-25: focused tests and the production live read-only collector smoke passed. The phase-closing `verify` batch passed all Go tests, 41 Pester tests, format, vet, staticcheck, gosec with zero issues, govulncheck with no callable vulnerabilities, repository and working-tree secret scans, governance/toolchain smokes and reproducible four-target builds
- Local P3.4 evidence on 2026-08-25: strict Windows route/firewall/NRPT artifacts, immutable revision manifests, hashed semantic snapshots, deterministic ownership, qualified provider endpoints, durable disable/restore intents and LKG rollback passed fault injection for activation, reload, post-check, pruning, timeout, process restart, missing pending manifests and persistent recovery faults. The final `verify` batch passed all Go tests, 41 Pester tests, format, vet, staticcheck, gosec with zero issues, govulncheck with no callable vulnerabilities, secret/workflow scans, governance/toolchain smokes and reproducible four-target builds. See the [P3.4 phase report](docs/reports/2026-08-25-p34-offline-mutation.md)
- Local P3.5 offline evidence on 2026-08-26: persistent fail-closed sink artifacts/backend, effective-route resolution, redacted CLI evidence and durable watchdog semantics passed focused Go tests, exact Windows PowerShell 5.1 and PowerShell 7 read-only Pester contracts, direct gitleaks and the full `verify` gate. The safe read-only preflight shape is `ready=true`, `exit_code=0`, PktMon stopped/no filters, zero exact Active/Persistent collisions, qualified IPv4 default, qualified IPv6 no-route and both loopbacks ready. No config contents, secrets, DNS addresses, target values, endpoints or adapter names are recorded. This provider-neutral safety work is retained for the self-hosted path. See the [P3.5 phase report](docs/reports/2026-08-26-p35-persistent-sinks.md)
- Owner decision on 2026-08-27: RedShield is retired as the target/required provider without changing its current live installation. Selected baseline: DigitalOcean Basic Regular $6, `ams3` (`fra1` fallback), Ubuntu 24.04 LTS x64, IPv6 and monitoring, dedicated SSH key, one PC peer, SSH plus one UDP tunnel port, no API token for the first manual Droplet. The supported installation path is hash-pinned AmneziaVPN 5.0.1.5 GUI with the actual server image ID/digest captured after install; no headless reproducibility claim is made. One owner-created resource now exists and billing is active
- Local self-hosted offline evidence on 2026-08-27: the shared strict importer preserves the historical path/hash/redaction suite and adds the complete bounded AWG 3.1 grammar; the active Windows CLI/runtime uses provider-neutral tunnel identity and generic protected config paths while legacy `redshield inspect` remains read-only; the DigitalOcean manifest and PowerShell 5.1/7 plan-only guard reject unsafe paths, mapped drives, reparse traversal and non-exact JSON before native validation. The final `verify` passed all Go tests, Pester 84/84, format, vet, staticcheck, gosec with zero issues, govulncheck with no vulnerabilities, secret/workflow scans, governance/toolchain smokes and reproducible four-target builds. Consolidated review closed all 9 Important findings and ended GO. See the [self-hosted offline report](docs/reports/2026-08-27-p3-selfhosted-offline.md)
- External server-bootstrap evidence on 2026-08-28: one SSH-only-firewalled DigitalOcean Droplet passed pinned-host-key key-only bootstrap, immutable AmneziaWG container observation, dedicated `homegateway` creation, independent fresh login and atomic SSH hardening. Root and password SSH are effectively disabled; `homegateway` public-key login and passwordless sudo were reproved after reload; the recovery channel committed and closed with exit `0`. UDP `38556` remains unexposed by the Cloud Firewall. See the [Gate 6.1-6.3 field report](docs/reports/2026-08-28-p3-gate63-bootstrap.md)
- Branch: `phase/p3-redshield-windows`, based on completed `phase/p2-dataplane`

## External gates

- P3 DigitalOcean resource and server bootstrap: Gates 6.1-6.3 passed; one billable Droplet exists, the Cloud Firewall remains SSH-only, AmneziaWG identity/service state is observed and SSH root/password login is disabled after independent `homegateway` key-only verification. Gate 6.4 UDP publication, guest creation and protected profile bootstrap remain separate operational gates
- P3 bounded native Windows canary and route/firewall/DNS mutation: self-hosted-field-not-run; P3.5 offline persistent-sink evidence passes, but exact-hash client import/activation, exact self-hosted Plan, Apply/Confirm and exact-candidate terminal journaled `FullRestore` require fresh separate authorizations; live safety, observed handshake/egress and `pc-core-ready` remain unproved
- GL-MT6000 hardware smoke, exact-kernel module/UAPI and router-to-VPS handshake: not-run; P12 gates and not P3-P11 blockers
- Second VPS failover: P9 gate
- Cisco field test: P7 gate

## Blockers

- P1 software blockers: none
- P2 software blockers: none
- P3 self-hosted offline software blockers: none. Server bootstrap passed through Gate 6.3; UDP publication, profile and live Windows gates remain separately authorized and not run.
- The DigitalOcean resource, dedicated SSH key and hardened operator access are available. The protected self-hosted PC profile does not yet exist; provider handshake and egress are field gates, never inferred from server/container or local adapter status.
- `pc-core-ready` remains open until real direct/self-hosted/Cisco, IPv4/IPv6 fail-closed, restart/recovery and terminal journaled `FullRestore` evidence passes on the current Windows PC.
- P2 does not claim Windows field acceptance, Flint 2 hardware compatibility or throughput.
