# ADR-0013: Windows persistent fail-closed sink routes

Status: Accepted

## Context

P3.4 kept project-managed Windows routes transient in `ActiveStore`. That remains correct for RedShield VPN-class routes because they must not silently survive a restart without reconciliation. P3.5 adds a deliberate exception for fail-closed sink routes: exact target prefixes need a persistent loopback path so a missing transient RedShield route cannot fall back to a physical/default route before startup reconciliation runs.

The P3.5 read-only evidence qualified this primitive on the current Windows PC, but did not authorize live mutation. All implementation and verification in this phase remains fake-runner/offline unless a later live canary gate is explicitly approved.

## Decision

Windows revisions include a separate immutable `windows-sinks.v1.json` artifact. Sinks are not represented as `ManagedRoute`; they use a dedicated `SinkRoute` and `SinkState` contract with exact `/32` or `/128` destinations, loopback interface index, unspecified next hop, `PersistentStore`, the reserved sink metric, the project route protocol and journal ownership.

Every VPN-class target has exactly one same-family persistent sink, and every sink covers exactly one VPN-class target. DNS targets are promoted into the same exact target set before artifacts are built. Broad prefixes, duplicates, endpoint/Cisco/system overlaps, non-loopback sinks, missing sinks and extra sinks fail validation before mutation.

Apply is additive-first:

- establish endpoint-direct assertions first;
- create and verify persistent sinks;
- validate firewall coverage;
- activate transient RedShield VPN-class routes;
- verify the effective route selects the qualified RedShield interface;
- publish DNS policy;
- prune stale NRPT, transient routes and firewall rules;
- prune stale sinks last.

Emergency disable intentionally removes project VPN-class routes, firewall and NRPT while retaining project sinks and endpoint-direct assertions. This keeps protected destinations fail-closed during operator investigation. Full restore is the terminal cleanup path: it removes project VPN routes, firewall, NRPT, endpoint-direct assertions and finally persistent sinks, then verifies the first-install state and disarms both owned watchdog tasks.

CLI evidence exposes only counts and booleans: `sink_count`, `persistent_sink_ready`, `retain_sinks` and `remove_sinks`. It must not print target prefixes, DNS addresses, adapter names, config paths or config contents. Existing confirmation tokens remain unchanged; sink artifact bytes are included in the existing confirmation challenge.

## Consequences

The transient-route rule from ADR-0012 still governs `ManagedRoute`. Persistent fail-closed behavior is isolated to the sink artifact/backend path and is therefore easier to validate, recover and remove without changing the P3.4 route-store contract.

A partial full restore remains retryable in durable `restoring` state. A retryable restoring failure keeps recovery watchdog coverage armed; a successful full restore disarms both recovery and reconcile scheduled tasks. Ambiguous native observations fail closed rather than claiming readiness.

`pc-core-ready` is not claimed by this ADR. The bounded live Windows canary, provider handshake, egress health, reboot/reconcile and terminal full-restore field evidence remain separate gates.

## Verification

Task 4 adds focused CLI and watchdog tests for redacted sink evidence, sink-bound confirmation challenge changes, emergency-disable sink retention counts, full-restore sink removal counts, retryable restoring watchdog coverage and exact owned-task disarm ordering. The acceptance matrix records this as offline implementation only; live mutation remains field-not-run.
