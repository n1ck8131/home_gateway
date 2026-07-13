# Project Status

Current phase: P2 Production Dataplane planning
Release level: P1-software-verified; P2-not-implemented

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

- State: planning
- Plan: [P2 production dataplane implementation plan](docs/superpowers/plans/2026-07-13-p02-production-dataplane.md)
- Implementation: awaiting explicit plan confirmation
- Branch: `phase/p2-dataplane`, based on completed `phase/p1-policy-core`

## External gates

- GL-MT6000 hardware smoke, including exact-kernel module/UAPI verification: not-run
- Router-to-VPS AWG2 handshake: P3 gate
- Second VPS failover: P9 gate
- Cisco field test: P7 gate

## Blockers

- P1 software blockers: none
- P2 planning blockers: none
- Hardware evidence remains intentionally deferred to the phase gates above; P1 does not claim hardware compatibility or throughput.
