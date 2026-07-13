# Acceptance Matrix

Each requirement has one owning phase and one evidence type.

## P0 closure evidence

| Gate | State | Evidence |
|---|---|---|
| Foundation verification | automated-passed | [CI run 29273568922](https://github.com/n1ck8131/home_gateway/actions/runs/29273568922): Linux `make verify`, `go test -race`, `CAP_NET_ADMIN` network prerequisite, Windows bootstrap, and Windows dev verification passed for commit `cf1773955e3d796e425cb6d6b75053928d77de61` |
| OpenWrt compatibility build | automated-passed | [SDK run 29273568884](https://github.com/n1ck8131/home_gateway/actions/runs/29273568884): pinned packages and `amneziawg-go` built twice from clean output trees and compared byte-identical for commit `cf1773955e3d796e425cb6d6b75053928d77de61`; durable output hashes are recorded in `docs/COMPATIBILITY.md` |
| Exact Flint 2 kernel module/UAPI | hardware-not-run | P3 gate; P0 software evidence does not prove load/runtime compatibility |
| Real router-to-VPS AWG2 handshake | hardware-not-run | P3 gate |

P0 is complete for its software scope. The hardware gates remain open and no P0 claim is made for hardware success or 300 Mbps throughput.

## P1 deterministic policy core

| Gate | State | Evidence |
|---|---|---|
| Policy contracts, normalization, precedence, explanation, and stable plans | automated-passed | [CI run 29280880251](https://github.com/n1ck8131/home_gateway/actions/runs/29280880251): Windows and Linux verification, `go test -race`, the `CAP_NET_ADMIN` prerequisite, and rollback smoke passed for commit `4bba257cff13203191c73843229d5e79db905d52` |
| OpenWrt compatibility regression | automated-passed | [SDK run 29280263011](https://github.com/n1ck8131/home_gateway/actions/runs/29280263011): byte-identical clean outputs passed for the complete P1 product code at commit `92784c32c34eeea24d642f2814d4fffeaee702e6`; the follow-up commit changes only golden-test line ending normalization |

P1 is complete for its pure software scope. DNS rendering/application, packet-policy enforcement, and hardware behavior remain owned by later phases.

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
| Ordinary Russian site uses WAN IP | P3 | hardware |
| `vpn` domain uses VPN IP | P3 | hardware |
| Manual `direct` overrides an external VPN source | P2 | automated |
| `auto-cisco` applies only to `work-pc` | P7 | external-service |
| Cisco gateway always uses WAN | P7 | field-soak |
| Internal work portal remains available through Cisco | P7 | external-service |
| Public work portal sees Russian WAN or corporate egress | P7 | external-service |
| VPS switching does not break Cisco by changing its egress | P9 | field-soak |
| HTTP/3 and UDP route correctly | P3 | hardware |

## §30.2 Failure modes

| Requirement | Owner phase | Evidence type |
|---|---|---|
| AWG stop does not leak VPN domains to WAN | P3 | hardware |
| Direct and Cisco traffic continue during AWG failure | P7 | external-service |
| Auto-failover selects a healthy reserve server | P9 | external-service |
| Failover does not flap | P9 | field-soak |
| Corrupted list update is rejected | P6 | automated |
| Last-known-good source remains active | P6 | automated |
| Invalid nft or DNS configuration rolls back automatically | P2 | automated |
| Router reboot restores the last applied revision | P3 | hardware |

## §30.3 IPv6 and DNS

| Requirement | Owner phase | Evidence type |
|---|---|---|
| VPN domains have no IPv6 leak | P3 | hardware |
| Client DNS passes through the router | P3 | hardware |
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
| Server admin API does not listen on a public HTTP port | P3 | hardware |
| SSH password and root login are disabled after bootstrap | P3 | hardware |
| Support bundle excludes private keys and passwords | P12 | automated |
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
| Cisco connection remains stable under router routing | P7 | field-soak |
| Cisco endpoint remains direct | P7 | field-soak |
| Blocked non-work resources use router VPN | P7 | field-soak |
| Work portals do not see VPN country | P7 | field-soak |
