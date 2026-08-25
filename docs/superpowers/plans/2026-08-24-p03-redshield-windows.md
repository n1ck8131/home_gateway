# P3 RedShield-backed Windows pilot implementation plan

Status: Active — P3.1 through P3.3 complete for their software scope; P3.4 next

## Goal

Deliver `pc-core-ready` on the current Windows PC by routing selected traffic through the existing RedShield WireGuard/AmneziaWG tunnel while preserving ordinary direct traffic, Cisco connectivity and the pre-install network state. Own VPS work is deferred to P8 and Flint 2 migration to P12.

## Safety boundary

- Never disconnect or restart the active RedShield or Cisco tunnel without separate confirmation.
- Do not mutate Windows routes, firewall, DNS, services or adapters during P3 read-only qualification.
- Treat the supplied `.conf` as an external secret: read locally, never copy to the repository, fixtures, logs or evidence.
- Do not apply `AllowedIPs = 0.0.0.0/0, ::/0` as Windows global default routes.
- The physical/provider endpoint and Cisco destinations must remain outside the project VPN route class.
- Every future mutation must have a deterministic dry-run, exact ownership markers, snapshot, last-known-good rollback and emergency-disable path.

## Work packages

### P3.1 Architecture and real-config qualification

Status: complete

- Accept ADR-0011.
- Validate the supplied config format without printing keys or field values.
- Record only redacted capabilities and required Windows prerequisites.

Exit: WireGuard or AmneziaWG config is supported; no secret enters repository state.

### P3.2 Importer and tunnel contract

Status: complete

- Add provider-neutral `TunnelBackend` capabilities and typed unsupported operations.
- Implement a bounded, strict RedShield config importer.
- Reject executable or unsafe WireGuard fields and prevent JSON/string/error leakage.
- Expose a read-only `hgctl redshield inspect` flow.

Exit: synthetic WireGuard/AmneziaWG tests pass and the real config produces redacted metadata only.

### P3.3 Windows routing adapter foundation

Status: complete for the read-only software scope. The production collector passed an opt-in live Windows inventory smoke on 2026-08-25; deterministic parser and planner fixtures pass. Exit code `0` means only `read_only_qualified`; `ready` remains false and apply remains blocked.

- Model Windows adapters, routes, DNS and tunnel status without executing mutation commands.
- Detect physical adapters from the authoritative Windows hardware marker, identify the active RedShield tunnel and Cisco adapter, and bind routes to stable interface GUIDs before apply work begins. Unknown virtual default adapters fail closed.
- Pin trusted Windows executable/module resolution before the collector can run in a privileged or unattended process.
- Produce a structured dry-run/readiness report; block when endpoint-direct, Cisco preservation or IPv4/IPv6 fail-closed prerequisites are unresolved.

Exit: read-only live inventory and deterministic fixture tests pass; apply remains unavailable.

Provider handshake and egress health are deliberately separate from local Windows adapter status. They remain P3.5 live-canary evidence and cannot be inferred from an interface being present.

### P3.4 Fail-closed apply and rollback

Status: next

- Implement project-owned Windows route/firewall/DNS operations with explicit ownership.
- Preserve the RedShield endpoint and protected Cisco/system routes on direct paths.
- Snapshot current state, validate candidate, arm commit-confirm, and restore last-known-good state on any failed check.

Exit: offline mutation tests and rollback fault injection pass. A live canary still requires separate confirmation.

### P3.5 Current-PC safety matrix

- Run a bounded live canary, then direct/RedShield/Cisco, DNS, IPv4/IPv6, MTU, TCP/UDP/QUIC and tunnel-down assertions.
- Test adapter loss, daemon crash, OS restart, recovery and emergency disable.
- Verify complete removal restores the pre-install network state.

Exit: `pc-core-ready`; own VPS and Flint 2 are not required.

### P3.6 Minimal operator flow

- Provide enable, inspect, confirm, rollback, disable and restore commands.
- Keep provider server-management controls explicitly unavailable until P8.

## Validation batch

Focused Go tests run during implementation. At the phase gate run `scripts/dev.ps1 -Command verify`, P2 regressions, Windows install/remove smoke and the separately approved live safety matrix. Real config contents must never appear in test or support artifacts.
