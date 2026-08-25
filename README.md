# Home Gateway

Safety-first selective-routing control plane. It runs first on the current Windows PC with an imported RedShield WireGuard/AmneziaWG tunnel, moves to a self-hosted VPN after the PC pilot is stable, and migrates last to OpenWrt on GL.iNet Flint 2.

Current phase: P3 RedShield-backed Windows pilot. P3.4 offline apply, rollback and recovery is complete for its software scope; P3.5 current-PC safety evidence is next and still requires separate confirmation. No P3 live network mutation has been performed.

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
