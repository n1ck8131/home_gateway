# Home Gateway

Safety-first home gateway control plane for OpenWrt on GL.iNet Flint 2. The
deterministic policy engine owns routing decisions and keeps VPN-class traffic
fail-closed.

Current phase: P3 Single-server AmneziaWG. P3.4 covers the reproducible
`routerd` package boundary. P3.5 remains a physical router/VPS gate; repository
tests do not prove ARM execution, procd boot behavior, LKG recovery or a live
AWG2 handshake.

## Safety invariants

- The WAN default route in `main` is never replaced by a VPN default route.
- VPN-class traffic fails closed and never falls through to `main` when its selected transport is unavailable.
- Cisco discovery and direct-routing exceptions apply only to the logical `work-pc`; Cisco policy is never bypassed.

## Developer entrypoints

Windows PowerShell 5.1:

```powershell
.\scripts\bootstrap-dev.ps1
.\scripts\dev.ps1 -Command verify
```

Linux with PowerShell 7:

```sh
pwsh -NoProfile -File scripts/bootstrap-dev.ps1 -IncludePowerShell
make PWSH=./.tools/pwsh/pwsh verify
```

## Project documents

- [Specification](SPEC.md)
- [Development plan](PLAN.md)
- [Current status](STATUS.md)
- [Accepted decisions](DECISIONS.md)
- [Security model](docs/SECURITY.md)
- [Compatibility evidence](docs/COMPATIBILITY.md)
- [Acceptance matrix](docs/ACCEPTANCE_MATRIX.md)
- [P3 physical acceptance runbook](docs/P3_PHYSICAL_ACCEPTANCE.md)
