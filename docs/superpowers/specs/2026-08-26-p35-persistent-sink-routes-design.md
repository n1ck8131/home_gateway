# P3.5 persistent fail-closed sink routes design

Status: Approved for implementation

Decision authority: the owner approved the dedicated persistent-sink approach, selected `FullRestore` as the terminal state, and delegated the remaining design choices to the assistant on 2026-08-26.

## Context

The P3.5 canary already has strict transient RedShield host routes, persistent outbound firewall blocks, NRPT policy, exact ownership, commit-confirm, crash recovery and native Windows adapters. The current runtime nevertheless requires a fallback default route for every canary address family. That rejects this host's valid IPv6 baseline, where `Find-NetRoute` reports the exact Windows unreachable condition and no IPv6 default exists.

Relying only on firewall rules also leaves a timing gap when an adapter appears, the firewall service is degraded, or a transient RedShield route disappears after restart. The read-only P3.5 sink preflight qualified a safer Windows primitive on this PC: exact `/32` and `/128` routes can be bound to the connected loopback interface, while the existing target prefixes have no active or persistent exact-route collisions.

## Goals

- Give every canary target and every imported DNS target an exact persistent loopback sink before selective policy is activated.
- Keep the lower-metric transient RedShield route preferred while the tunnel path is healthy.
- Fail closed to loopback when the transient route is absent, including during boot and adapter changes.
- Preserve default routes, RedShield and Cisco adapters, protected prefixes, and every unowned route/rule.
- Make crash recovery, `EmergencyDisable`, revision replacement and `FullRestore` deterministic and retryable.
- End the field canary with a verified `FullRestore` to the first-install network baseline.

## Non-goals

- No global `0.0.0.0/0` or `::/0` route changes.
- No RedShield or Cisco disconnect, restart, profile change or adapter mutation.
- No general P3.6 operator redesign. Existing bounded canary and recovery commands remain the entry points.
- No claim of `pc-core-ready` from offline tests or read-only preflight alone.

## Decision

Introduce a fourth immutable Windows revision artifact, `windows-sinks.v1.json`, and a separate persistent-sink state/backend contract. Do not overload `ManagedRoute`: its `ActiveStore` semantics and P3.4 compatibility remain unchanged.

The sink artifact is manifest-bound with routes, firewall and NRPT. It has the common `version`, `owner` and `revision` header and a bounded list of `SinkRoute` values. Each value contains:

- the exact canonical host `family` and `destination`;
- unspecified same-family `next_hop` (`0.0.0.0` or `::`);
- loopback `interface_index` `1`;
- reserved high `metric` `65535`;
- `policy_store` `PersistentStore`, `protocol` `NetMgmt` and `journal_owned: true`.

The existing transient RedShield metric remains `42751`. This ordering is a necessary invariant, not sufficient evidence: activation also verifies the actual route selected for every target.

Every `vpn-class` route must have exactly one same-family sink with the same destination. Every sink must cover exactly one `vpn-class` route; therefore imported DNS addresses are covered because the canary planner first promotes them to target prefixes. Broad prefixes, duplicate tuples, endpoint/Cisco/system overlaps, non-loopback binding, extra sinks and missing sinks fail artifact validation.

## Runtime and native backend contract

`apply.Candidate` gains a Windows-only `Sinks` payload. Windows canonicalization, immutable staging and `manifest.v1.json` require all four Windows artifacts. Linux runtimes continue to ignore the Windows-only field.

`MutationSnapshot` gains logical sink state separate from transient routes. A sink observation records its artifact tuple, owner/revision, and whether the exact tuple is present in both `PersistentStore` and `ActiveStore`. It also records bounded effective-route resolution for the candidate targets. Project ownership still comes from the protected native ownership registry; an OS route is never claimed merely because its tuple resembles a sink.

`MutationBackend` gains explicit persistent-sink add and remove operations. The native implementation:

1. resolves only the pinned Windows PowerShell and `NetTCPIP` module paths;
2. writes a durable intent/tombstone before the OS mutation;
3. creates a sink with `New-NetRoute` persistence semantics that populate both stores;
4. post-checks the exact tuple in `PersistentStore` and its active copy in `ActiveStore`;
5. removes the owned exact tuple from both stores during full removal and verifies both are absent;
6. reconciles interrupted intent from observed OS state after reboot.

The implementation must follow the Windows route-store contracts in the Microsoft [`New-NetRoute`](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute), [`Get-NetRoute`](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute) and [`Remove-NetRoute`](https://learn.microsoft.com/en-us/powershell/module/nettcpip/remove-netroute) documentation. No command accepts caller-controlled executable paths or script fragments.

An exact unowned collision in either store blocks before mutation. An owned tuple whose registry, revision, store presence or active copy is incomplete enters recovery; it is not silently adopted or discarded.

## Transaction ordering

Activation remains additive-first:

1. validate immutable artifacts and capture the pending/first-install snapshots;
2. add and verify every persistent sink;
3. add and verify persistent firewall coverage;
4. take a fresh snapshot and repeat ownership, adapter and protected-prefix checks to close the TOCTOU window;
5. add transient RedShield routes;
6. verify that each effective target route selects the qualified RedShield interface, while the exact loopback sink remains present;
7. add NRPT and reload;
8. prune stale NRPT, transient routes and firewall rules, then prune stale sinks last;
9. perform the exact managed-state and foreign-state post-check before confirmation.

Any failure enters the existing rollback/recovery state machine. Rollback restores the prior revision using the same additive-first rule: its sinks are established before its transient policy, and no stale sink is removed until the prior effective path is verified. Ambiguous native results retain retryable intent.

## Restart and degraded behavior

Persistent sinks and firewall rules survive reboot. Transient RedShield routes do not. Before startup reconciliation completes, every protected destination therefore resolves to loopback instead of a physical/default path. Reconciliation verifies the sinks first, then restores firewall, transient RedShield routes and NRPT, and finally verifies the effective RedShield selection.

An absent IPv6 default is a valid baseline when the exact qualified `Find-NetRoute` unreachable result is observed and the IPv6 loopback sink is ready. Other route-resolution errors remain blocking. A new or reactivated adapter cannot bypass the exact sink; the firewall coverage remains defense in depth.

## Recovery modes

`EmergencyDisable` removes project VPN routes, NRPT and firewall rules but intentionally retains owned sinks and endpoint-direct assertions. Protected targets remain fail-closed while an operator investigates.

`FullRestore` is the selected P3.5 terminal state. It is ordered as follows:

1. remove transient VPN routes;
2. remove NRPT;
3. remove firewall rules;
4. remove any project-owned endpoint routes;
5. remove persistent sinks last from `PersistentStore` and verify their active copies are gone;
6. reload and compare the resulting network state with the first-install snapshot;
7. clear project active/LKG markers and disarm both owned watchdog tasks.

The completed state has no project-owned routes, sinks, firewall or NRPT policy, and all unowned route/firewall/NRPT keys equal the captured baseline. A partial full restore remains in durable `restoring` state and is retried; it is never reported as restored.

## Testing and evidence

Implementation follows red-green TDD and adds focused coverage for:

- strict sink schema, limits, exact target/DNS coverage, metric ordering and collision rejection;
- IPv4 with a physical default and IPv6 with the exact no-route baseline;
- activation, revision replacement and rollback ordering;
- sink add/remove faults, ambiguous native results, restart reconciliation and stale registry intent;
- effective RedShield selection with sink fallback and rejection when loopback wins unexpectedly;
- `EmergencyDisable` retaining sinks and `FullRestore` removing them last;
- native PowerShell request validation and exact Active/Persistent store post-checks;
- CLI plan/status counts without exposing config contents.

The phase validation batch is the focused Go tests first, then one full `scripts/dev.ps1 -Command verify` run. Because this change contains no Python, the phase report records `RUFF_NOT_APPLICABLE_NO_PYTHON`.

Read-only sink preflight evidence is already qualified on the current PC. It does not authorize mutation. The bounded live matrix remains a separate field gate and must collect redacted evidence for direct, RedShield, Cisco, DNS, IPv4/IPv6, MTU, TCP/UDP/QUIC, tunnel-down, adapter loss, process crash, reboot/reconcile, emergency disable and final full restore. No secret or target payload is written to repository evidence.

## Acceptance criteria

- All canary and imported DNS prefixes have one manifest-bound persistent loopback sink.
- No candidate can activate unless sinks and firewall coverage are present and the effective route selects RedShield.
- Loss of the transient RedShield route leaves the exact sink as the selected fail-closed path.
- Reboot reconciliation restores the committed candidate without a physical/default-path leak.
- `EmergencyDisable` retains sinks; `FullRestore` removes them last and reaches exact first-install state.
- Focused tests, the repository verification gate and consolidated review have no open Critical or Important findings.
- `pc-core-ready` is claimed only after the separately authorized live matrix and terminal `FullRestore` pass.
