# Home Gateway

Safety-first home gateway control plane for OpenWrt on GL.iNet Flint 2. The deterministic policy engine owns routing decisions; P0 builds only the reproducible foundation and compatibility evidence.

Current phase: P0 Foundation and Compatibility.

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
