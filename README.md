# Home Gateway

Safety-first selective-routing control plane. It qualifies one self-hosted AmneziaWG tunnel on the current Windows PC while preserving the installed RedShield and Cisco paths, and migrates last to OpenWrt on GL.iNet Flint 2.

Current phase: P3 self-hosted Windows pilot. Gates 6.1-6.3 passed, Gate 6.4 requires a fresh read-only reconciliation of current host and Cloud Firewall state, and the Gate 6.5C Admin-peer attempt is `rollback-complete`. The protected PC profile is absent and every Windows field gate remains open; offline code or server presence does not establish `pc-core-ready`.

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
- [Active P3 implementation plan](docs/superpowers/plans/2026-08-24-p03-redshield-windows.md)
- [Current status](STATUS.md)
- [Accepted decisions](DECISIONS.md)
- [Security model](docs/SECURITY.md)
