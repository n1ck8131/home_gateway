# Acceptance Matrix

Each requirement has one owning phase and one evidence type.

## P0 closure evidence

| Gate | State | Evidence |
|---|---|---|
| Foundation verification | automated-passed | [CI run 29273568922](https://github.com/n1ck8131/home_gateway/actions/runs/29273568922): Linux `make verify`, `go test -race`, `CAP_NET_ADMIN` network prerequisite, Windows bootstrap, and Windows dev verification passed for commit `cf1773955e3d796e425cb6d6b75053928d77de61` |
| OpenWrt compatibility build | automated-passed | [SDK run 29273568884](https://github.com/n1ck8131/home_gateway/actions/runs/29273568884): pinned packages and `amneziawg-go` built twice from clean output trees and compared byte-identical for commit `cf1773955e3d796e425cb6d6b75053928d77de61`; durable output hashes are recorded in `docs/COMPATIBILITY.md` |
| Exact Flint 2 kernel module/UAPI | hardware-not-run | P12 gate; P0 software evidence does not prove load/runtime compatibility |
| Real router-to-VPS AWG2 handshake | hardware-not-run | P12 gate after the P3 self-hosted backend and P8 managed lifecycle exist |

P0 is complete for its software scope. The hardware gates remain open and no P0 claim is made for hardware success or 300 Mbps throughput.

## P1 deterministic policy core

| Gate | State | Evidence |
|---|---|---|
| Policy contracts, normalization, precedence, explanation, and stable plans | automated-passed | [CI run 29280880251](https://github.com/n1ck8131/home_gateway/actions/runs/29280880251): Windows and Linux verification, `go test -race`, the `CAP_NET_ADMIN` prerequisite, and rollback smoke passed for commit `4bba257cff13203191c73843229d5e79db905d52` |
| OpenWrt compatibility regression | automated-passed | [SDK run 29280879151](https://github.com/n1ck8131/home_gateway/actions/runs/29280879151): byte-identical clean outputs passed for commit `4bba257cff13203191c73843229d5e79db905d52` |

P1 is complete for its pure software scope. DNS rendering/application, packet-policy enforcement, and hardware behavior remain owned by later phases.

## P2 production dataplane

| Gate | State | Evidence |
|---|---|---|
| Deterministic nft, policy-routing and suffix-dnsmasq rendering | automated-passed | [CI run 32672264290](https://github.com/n1ck8131/home_gateway/actions/runs/32672264290) passed Windows/Linux verification and Linux race tests for commit `150ffffb13bb81d83c3425146e1604368ea7eda2` |
| Exact and wildcard domain adapter boundary | automated-passed | The same CI run proves rejection before transaction staging; ADR-0010 records the hostname-aware adapter requirement |
| Transactional apply, commit-confirm and last-known-good recovery | automated-passed | [CI run 32672264290](https://github.com/n1ck8131/home_gateway/actions/runs/32672264290) and [OpenWrt QEMU run 32672264286](https://github.com/n1ck8131/home_gateway/actions/runs/32672264286) cover invalid candidates, post-check rollback, watchdog expiry, crash recovery and reboot reconciliation |
| Linux network namespace safety matrix | automated-passed | CI artifact `network-ns-evidence` records the Ubuntu 24.04 traffic matrix, real dnsmasq/nft suffix DNS checks and 20 consecutive tunnel fault cycles |
| OpenWrt x86_64 QEMU dataplane smoke | automated-passed | QEMU artifact `openwrt-qemu-evidence` records pinned OpenWrt 25.12.5 package/config, validation, rollback and reboot/LKG checks |

P2 is complete for its software and emulated OpenWrt scope at commit `150ffffb13bb81d83c3425146e1604368ea7eda2`. [OpenWrt SDK run 32672264264](https://github.com/n1ck8131/home_gateway/actions/runs/32672264264) also passed the pinned reproducibility and ShellCheck regression. P3 reuses this safety model on the current Windows PC with one self-hosted DigitalOcean AmneziaWG server. P12 owns physical GL-MT6000, exact-kernel AWG2 and router-to-VPS evidence.

## P3 Windows/self-hosted foundation

| Gate | State | Evidence |
|---|---|---|
| Provider-neutral tunnel contract and strict external-profile importer | transition-required | Existing RedShield parser/redaction/path-stability evidence is local-verified; P3.6 must remove the provider-identity dependency from the active self-hosted path and rerun the same tests without weakening the secret boundary |
| Historical user-supplied RedShield config qualification | historical-read-only-passed | One interface, one peer, IPv4/IPv6 full-tunnel and AWG capability were recognized without printing keys or retaining them in repository/evidence; this does not qualify the future self-hosted profile |
| Historical native Windows preflight baseline | historical-baseline-observed | The RedShield-imported addresses matched one active WireGuard/Amnezia adapter; a physical endpoint route and both IP-family prerequisites were observed. The preflight returned blocked exit code `3` |
| Authoritative routes, effective DNS/NRPT and local tunnel status | read-only-passed | On 2026-08-25 the production collector passed an opt-in live Windows smoke using structured ActiveStore routes and metrics, stable interface GUIDs and hardware markers, effective DNS servers and effective NRPT count. Provider health remains a separate observed field gate |
| DigitalOcean P3 baseline | owner-selected | On 2026-08-27 the owner selected the $6 Basic Regular size, `ams3` (`fra1` fallback), Ubuntu 24.04 LTS x64, IPv6, monitoring, one PC peer, dedicated SSH key and manual UI creation. The supported install path is hash-pinned AmneziaVPN 5.0.1.5 GUI plus observed server image identity; this is a design decision, not resource evidence |
| P3 DigitalOcean Droplet | not-created | Billable creation requires a separate immediate approval; no Droplet ID, address, billing start or cloud-side state is claimed |
| Self-hosted profile qualification | field-not-run | The protected PC peer profile does not yet exist; it must pass bounded parsing, file identity, ACL, hash-pinning and redaction checks outside Git |
| Self-hosted handshake and egress health | field-not-run | P3 live-canary gate; an interface being present is not treated as provider, handshake or egress proof |
| Offline Windows route/firewall/DNS mutation, commit-confirm and recovery | automated-passed | P3.4 strict artifacts and exact ownership passed activation/reload/post-check/prune fault injection, timeout/crash rollback, missing-manifest recovery, durable disable/restore retry and full `verify` on 2026-08-25 |
| Persistent fail-closed sink routes and redacted recovery evidence | offline-implemented | P3.5 native sink route artifacts/backend and CLI/watchdog behavior are implemented with fake-runner tests only: plan/status expose sink counts and readiness booleans, recovery exposes retain/remove counts, emergency disable retains sinks and full restore removes them last |
| Historical RedShield native Windows apply attempt | historical-field-precheck-blocked | The authorized 2026-08-26 sub-batch passed the fresh elevated sink preflight and protected bootstrap, but exact non-elevated Plan failed closed before candidate/challenge creation because an imported DNS target overlaps a Cisco protected prefix. Apply/Confirm were not invoked; no journal or owned network artifact was created |
| Self-hosted native Windows apply and bounded canary | field-not-run | Requires provider-neutral offline verification, separately approved guest creation and client-profile activation, a qualified server/profile, fresh exact Plan and separate Apply/Confirm approval; any DNS/Cisco overlap or other anomaly must block or roll back, followed by a freshly approved exact-candidate terminal journaled `FullRestore` |

P3.1 through P3.4 are complete for their existing software scope, and the P3.5 persistent-sink offline/native boundary is implemented. The RedShield Plan block and clean terminal inventory remain honest historical evidence: `FullRestore` was not state-machine-applicable without a journal and was not forced. ADR-0016 starts a new self-hosted qualification path; no Droplet, profile, live apply, field acceptance or `pc-core-ready` claim is made.

| Requirement | Owner phase | Evidence type |
|---|---|---|
| Domain, IDNA, public-suffix and CIDR normalization | P1 | automated |
| Duplicate and subsumed entries normalize deterministically | P1 | automated |
| Protected, manual, curated and external precedence pairs | P1 | automated |
| Most-specific domain and CIDR matching within one tier | P1 | automated |
| One logical device supports multiple network identities | P1 | automated |
| Protected work devices cannot select `always-vpn` | P1 | automated |
| Expired entries are excluded using an explicit evaluation time | P1 | automated |
| Shared-IP direct/VPN conflict resolves direct and remains visible | P1 | automated |
| Per-server marks and routing selections are stable and unique | P1 | automated |
| Route explanation includes ordered winning and losing evidence | P1 | automated |
| Repeated policy evaluation produces byte-stable output | P1 | automated |

## §30.1 Routing

| Requirement | Owner phase | Evidence type |
|---|---|---|
| Ordinary direct-class site uses the physical Windows egress | P3 | windows-field |
| `vpn` domain uses self-hosted AmneziaWG egress | P3 | windows-field |
| Manual `direct` overrides an external VPN source | P2 | automated |
| `auto-cisco` applies only to `work-pc` | P7 | external-service |
| Cisco gateway always uses WAN | P7 | field-soak |
| Internal work portal remains available through Cisco | P7 | external-service |
| Public work portal sees Russian WAN or corporate egress | P7 | external-service |
| VPS switching does not break Cisco by changing its egress | P9 | field-soak |
| HTTP/3 and UDP route correctly | P3 | windows-field |

## §30.2 Failure modes

| Requirement | Owner phase | Evidence type |
|---|---|---|
| Active self-hosted tunnel loss does not leak VPN domains to direct egress | P3 | windows-field |
| Direct and Cisco traffic continue during AWG failure | P7 | external-service |
| Auto-failover selects a healthy reserve server | P9 | external-service |
| Failover does not flap | P9 | field-soak |
| Corrupted list update is rejected | P6 | automated |
| Last-known-good source remains active | P6 | automated |
| Invalid nft or DNS configuration rolls back automatically | P2 | automated |
| Windows restart restores the last confirmed revision | P3 | windows-field |
| Router reboot restores the last applied revision | P12 | hardware |

## §30.3 IPv6 and DNS

| Requirement | Owner phase | Evidence type |
|---|---|---|
| VPN domains have no IPv6 leak on Windows | P3 | windows-field |
| Windows DNS follows the selected route or fails closed | P3 | windows-field |
| Client DNS passes through the router | P12 | hardware |
| A, AAAA and CNAME answers populate sets | P2 | automated |
| Browser DoH conflict is diagnosed | P5 | automated |
| Mobile full tunnel does not use mobile-operator DNS | P8 | hardware |

## §30.4 Mobile

| Requirement | Owner phase | Evidence type |
|---|---|---|
| New profile imports into AmneziaWG | P8 | hardware |
| Profile connects over a cellular network | P8 | hardware |
| Mobile client shows VPS egress | P8 | hardware |
| Peer is visible in the panel | P8 | hardware |
| Revoke stops access | P8 | hardware |
| Private key cannot be downloaded after one-time token expiry | P8 | automated |
| One device can be revoked without changing other devices | P8 | automated |

## §30.5 Backup

| Requirement | Owner phase | Evidence type |
|---|---|---|
| Encrypted backup is created | P11 | automated |
| Backup is verified | P11 | automated |
| Backup restores to a clean test installation | P11 | hardware |
| Secrets are not visible without decryption | P11 | automated |
| Sanitized export is safe for Git | P11 | automated |

## §30.6 Security

| Requirement | Owner phase | Evidence type |
|---|---|---|
| Panel is unavailable from WAN, Guest and VPN peers | P5 | automated |
| Server admin API does not listen on a public HTTP port | P8 | hardware |
| SSH password and root login are disabled after the P3 bootstrap | P3 | hardware |
| Support bundle excludes private keys and passwords | P11 | automated |
| External list input cannot execute commands | P6 | automated |
| Release artifacts include checksums, signatures and SBOM | P12 | automated |

## §30.7 Performance

| Requirement | Owner phase | Evidence type |
|---|---|---|
| Direct Ethernet approaches 500 Mbps and reaches target | P12 | hardware |
| VPN benchmark is documented | P12 | hardware |
| CPU and RAM remain within target | P12 | hardware |
| 100k-list apply reaches target or produces an optimization decision | P6 | hardware |

## §30.8 Cisco stability

| Requirement | Owner phase | Evidence type |
|---|---|---|
| Cisco connection remains stable under Windows selective routing | P7 | field-soak |
| Cisco endpoint remains direct | P7 | field-soak |
| Blocked non-work resources use router VPN | P7 | field-soak |
| Work portals do not see VPN country | P7 | field-soak |
