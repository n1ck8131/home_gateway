# P3 self-hosted Windows pilot implementation plan

Status: Active — P3.1 through the existing P3.5 offline/software scope are complete; the 2026-08-26 RedShield live sub-batch remains historical pre-mutation evidence; ADR-0016 now makes one self-hosted DigitalOcean server the P3 live target, and `pc-core-ready` remains open

## Goal

Deliver `pc-core-ready` on the current Windows PC by routing selected traffic through one owned DigitalOcean AmneziaWG server while preserving ordinary direct traffic, Cisco connectivity and the pre-install network state. P3 owns only the minimal manual self-hosted bootstrap and static PC peer; managed server/mobile lifecycle remains P8 and Flint 2 migration remains P12.

## Safety boundary

- Never disconnect, restart or reconfigure the installed RedShield or Cisco tunnel without separate confirmation. Retiring RedShield as the target backend is not authorization to change its live state.
- Do not create a billable Droplet, connect through SSH, publish a UDP port or use cloud credentials without the matching separate gate.
- Do not mutate Windows routes, firewall, DNS, services or adapters during P3 read-only qualification.
- Treat every retained RedShield or generated self-hosted `.conf` as an external secret: read locally, never copy to the repository, fixtures, logs or evidence.
- Do not apply `AllowedIPs = 0.0.0.0/0, ::/0` as Windows global default routes.
- The physical/self-hosted endpoint and Cisco destinations must remain outside the project VPN route class.
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

Status: complete for the offline software scope on 2026-08-25. Strict route/firewall/NRPT artifacts, qualified endpoint binding, exact ownership, additive-first ordering, commit-confirm, LKG rollback, durable disable/restore intent and crash recovery passed fault injection and the full repository verification gate. The runtime has only an injected structured backend; native/live apply remains unavailable.

- Implement project-owned Windows route/firewall/DNS operations with explicit ownership.
- Preserve the RedShield endpoint and protected Cisco/system routes on direct paths.
- Snapshot current state, validate candidate, arm commit-confirm, and restore last-known-good state on any failed check.

Exit: offline mutation tests and rollback fault injection pass. A live canary still requires separate confirmation.

### P3.5 Current-PC safety matrix

Status: offline implementation complete on 2026-08-26. Persistent fail-closed sinks, effective-route resolution, redacted CLI evidence and watchdog semantics passed focused Go tests, exact PowerShell 5.1/7 Pester contracts, direct gitleaks and the full `verify` gate. The imported-DNS/Cisco overlap diagnostic gap is now implemented offline with bounded redacted block classification; the imported-DNS/Cisco prerequisite and `pc-core-ready` remain open. The separately authorized bounded live sub-batch passed the fresh elevated sink preflight and protected bootstrap, then exact Plan failed closed before candidate/challenge creation because the imported DNS target overlaps a Cisco protected prefix. Apply/Confirm and recovery mutation were not invoked. Product `RestoreConfigAcl` passed, and terminal inventory/preflight proved no journal, lock, ownership registry, revision or owned network artifacts; RedShield and Cisco remained Up.

- Run a bounded live canary, then direct/RedShield/Cisco, DNS, IPv4/IPv6, MTU, TCP/UDP/QUIC and tunnel-down assertions.
- Test adapter loss, daemon crash, OS restart, recovery and emergency disable.
- Verify complete removal restores the pre-install network state.

Historical result: the RedShield candidate remains blocked and must not be revived by bypassing the DNS/Cisco isolation guard. It is not the new self-hosted acceptance path.

### P3.6 Minimal self-hosted DigitalOcean bootstrap and transition

Status: planned and design-approved; no resource or live change has been made

- Follow [ADR-0016](../../adr/ADR-0016-p3-self-hosted-digitalocean-bootstrap.md) and the [detailed bootstrap plan](2026-08-27-p3-self-hosted-digitalocean-bootstrap.md).
- Generalize the protected config importer, CLI and Windows planner from a RedShield identity to a qualified provider-neutral AmneziaWG tunnel without weakening redaction, file identity or Cisco/DNS overlap guards.
- Produce a deterministic non-secret create checklist; pin the official AmneziaVPN 5.0.1.5 Windows installer hash, use its supported GUI server flow, capture the installed container image identity, and document clear-server/rebuild limitations without claiming a supported headless bootstrap.
- Generate one protected static PC peer profile outside Git and observe handshake/egress before any Windows mutation.
- Run exact Plan, then separately authorize bounded Apply/Confirm, the complete safety matrix and terminal journaled `FullRestore`.

Exit: `pc-core-ready`; one own VPS is required, but P8 automation/mobile scope and Flint 2 are not. The exit remains open until the self-hosted server and profile are qualified, the live matrix passes, and terminal `FullRestore` field evidence passes after an actual journaled canary.

### P3.7 Minimal operator flow

- Provide enable, inspect, confirm, rollback, disable and restore commands.
- Keep automated provider/server-management controls explicitly unavailable until P8.

## Validation batch

Focused Go tests run during implementation. P3.5 offline persistent-sink work closed with focused Go integration, exact Windows PowerShell 5.1 and PowerShell 7 Pester contracts, direct gitleaks and `scripts/dev.ps1 -Command verify`. The RedShield live precheck/bootstrap attempt is recorded as a safe pre-mutation historical block, not live acceptance. P3.6 must add provider-neutral importer/planner/bootstrap tests and then pass the full repository gate before the separately approved self-hosted live matrix. No real config content or secret may appear in test or support artifacts. `RUFF_NOT_APPLICABLE_NO_PYTHON`.
