# Diagnose P3.5 DNS and Cisco overlap without bypassing protection

Status: Draft for owner review

Decision authority: the owner approved the hard-rejection plus redacted-diagnostics direction on 2026-08-26. Implementation still requires approval of this written specification.

Content type: Conceptual design

Audience: P3.5 implementers, reviewers, and the operator running the Windows field gate.

Goal: Explain how P3.5 reports an imported Domain Name System (DNS) overlap with Cisco policy while preserving every existing mutation guard.

Content plan: define the conflict, the typed diagnostic contract, command behavior, safety boundaries, tests, and the external prerequisite for a future live retry.

Open questions: none. Obtaining a compatible provider profile remains an external prerequisite, not an implementation decision.

## Summary

P3.5 must keep rejecting any canary target that overlaps a qualified provider endpoint or Cisco protected prefix. The planner will classify that rejection with bounded counts and fixed enums, then `hgctl windows canary plan --json` will return redacted JSON with exit code `3`. The change will not add an exception, edit a profile, mutate Windows networking, or authorize a live retry.

## Problem

The authorized P3.5 live sub-batch reached exact non-elevated Plan and stopped before candidate or challenge creation. One DNS server imported from the approved RedShield profile overlaps a Cisco protected prefix. The existing generic error proves the safety gate worked, but it does not identify whether an explicit target or imported DNS target caused the block.

`BuildCanaryPlan` currently merges explicit targets and imported DNS servers into one canonical prefix slice. `validateCanaryTargetIsolation` then compares that slice with provider endpoint assertions and non-default Cisco routes. This merge discards target provenance before the overlap check.

The runtime repeats the same safety decision after artifact loading. It rejects VPN-class routes and firewall rules that overlap endpoint, system, or Cisco protected prefixes. It also requires every DNS nameserver to have VPN-class fail-closed coverage and verifies that the effective route selects RedShield.

## Safety invariants

This design preserves the contracts in [ADR-0011](../../adr/ADR-0011-pc-first-platform-tunnel-boundary.md), [ADR-0012](../../adr/ADR-0012-windows-offline-mutation-ownership.md), and [ADR-0013](../../adr/ADR-0013-windows-persistent-sink-routes.md):

- Cisco configuration and Cisco-owned routes remain outside project ownership
- provider endpoints and Cisco protected prefixes never enter the VPN route class
- Plan performs no filesystem or network mutation
- Apply and Confirm rebuild the exact plan before transaction initialization
- no confirmation challenge exists for a blocked candidate
- config paths, config contents, keys, endpoints, targets, DNS addresses, prefixes, adapter identities, and protected-route values never enter diagnostic output
- a diagnostic result never grants mutation authority

## Decision

Keep every planner and runtime overlap guard unchanged. Add a typed, redacted isolation error at the Windows canary planner boundary and serialize only that error for JSON Plan calls.

The implementation will not weaken `validateCanaryTargetIsolation`, add an allowlist, change route metrics, or reinterpret Cisco routes. The typed result explains why the existing hard rejection occurred.

### Track target provenance before merging

The planner will retain source membership for each canonical host prefix:

- `explicit_target`: a value supplied through `--target`
- `imported_dns`: a DNS server parsed from the hash-pinned RedShield profile

Explicit duplicate inputs keep their current validation error. Imported DNS duplicates remain compacted. If one canonical prefix belongs to both sources, the candidate union still contains it once, while diagnostic classification retains both source memberships.

The planner will also classify protected prefixes before comparison:

- `provider_endpoint`: a qualified endpoint direct-route assertion
- `cisco_prefix`: a parsable non-default route attributed to a Cisco adapter

This classification must use the same assertions, route filters, adapter identity checks, and overlap function as the current guard. Diagnostics must not create a second policy decision path.

### Return a typed isolation error

The Windows package will expose an internal typed error through the existing `error` return from `BuildCanaryPlan`. The error will carry only a fixed block code and bounded summaries.

Each summary contains:

| Field | Allowed values | Meaning |
| --- | --- | --- |
| `target_source` | `explicit_target`, `imported_dns` | Input class that contributed the blocked target |
| `protected_class` | `provider_endpoint`, `cisco_prefix` | Protected policy class that overlaps the target |
| `family` | `ipv4`, `ipv6` | Address family of the blocked target |
| `affected_target_count` | positive bounded integer | Distinct canonical target prefixes in this bucket |

`affected_target_count` counts each target once per `(target_source, protected_class, family)` bucket. Multiple protected routes in the same class do not increase the count. Bucket totals are not a global distinct-target total when one target has multiple sources or protected classes.

The error sorts summaries by fixed enum order and emits at most eight buckets. Its `Error()` text remains constant and contains no values derived from inventory, the profile, or command arguments.

### Emit structured JSON only for this block

`runCanaryPlan` will use `errors.As` to recognize the typed isolation error through existing wrapping. It will validate every enum, count, and bucket bound before serialization. Invalid typed data falls back to a generic fail-closed error and emits no diagnostic payload.

For a valid isolation block, Plan writes one JSON object to stdout, leaves stderr empty, and returns exit code `3`. The new block fields use `omitempty`, so successful Plan calls do not populate them. The existing `confirmation_challenge` and `confirm_timeout_seconds` fields also gain `omitempty`; their nonzero success values keep the successful object unchanged.

A blocked response has this shape:

```json
{
  "mode": "plan",
  "revision": "p35-canary-example",
  "ready_for_live_gate": false,
  "live_mutation_performed": false,
  "route_count": 0,
  "sink_count": 0,
  "persistent_sink_ready": false,
  "firewall_rule_count": 0,
  "dns_rule_count": 0,
  "block_code": "canary_target_isolation",
  "block_details": [
    {
      "target_source": "imported_dns",
      "protected_class": "cisco_prefix",
      "family": "ipv4",
      "affected_target_count": 1
    }
  ]
}
```

The blocked response omits `confirmation_challenge` and `confirm_timeout_seconds`. It never contains a candidate digest, address, prefix, endpoint, adapter value, config path, or config hash.

Other planner failures keep their current stderr and exit-code behavior. This scope does not turn every planner error into a public diagnostic taxonomy.

### Preserve the Plan result through PowerShell

The `Plan` path in `scripts/p35-canary.ps1` will forward the `hgctl` stdout object and native exit code through the supported child-process entry point. It will not replace exit code `3` with a generic terminating PowerShell exception.

Apply, Confirm, recovery, and status actions keep their existing launcher behavior. Windows PowerShell 5.1 and PowerShell 7 must produce the same JSON fields and exit code for the blocked Plan case.

### Keep Apply and Confirm closed

Apply and Confirm continue to call `collectCanaryPlan` before checking the challenge or creating a transaction. A typed isolation error therefore returns exit code `3` before candidate staging, journal creation, lock acquisition, ownership publication, watchdog arming, or native mutation.

The Plan diagnostic cannot be supplied as a confirmation token. No challenge is derived for a blocked candidate, and a challenge from another profile, hash, state root, revision, or target set remains invalid.

## Operator flow after a block

The blocked Plan result ends the live envelope. It does not continue automatically.

A future attempt requires these steps:

1. Obtain a separately supplied and approved RedShield profile whose imported DNS servers do not overlap qualified provider endpoints or Cisco protected prefixes.
2. Do not edit the current profile, substitute DNS servers, copy key material, or derive a new secret profile in project tooling.
3. Pin the new source by its own SHA-256 and run the full config-source, access-control, preflight, bootstrap, and non-elevated Plan gates again.
4. Review the new Plan result and obtain a new live authorization for its exact hash, targets, revision, state root, and confirmation challenge.
5. Run the bounded live matrix only under that new authorization, with rollback on anomaly and terminal `FullRestore` after an actual journaled canary.

The current profile remains incompatible with P3.5 Apply while the overlap exists.

## Rejected alternatives

### Protected-DNS exception

An exception would let a VPN-class route overlap Cisco policy. Windows destination routing cannot distinguish RedShield DNS use from Cisco use of the same destination. Preferring RedShield could divert Cisco traffic, while preferring Cisco would violate the canary DNS and fail-closed contracts.

### Automatic DNS substitution or profile editing

Substitution would change provider semantics and create unapproved secret material. It could also select a resolver that the tunnel provider does not support. P3.5 will inspect a supplied profile but will not rewrite it.

### RedShield-bound local DNS proxy

A local proxy could separate the local nameserver from the upstream destination. It would also add a service, listener security, upstream binding, boot ordering, recovery, and leak-prevention surface. That work requires a separate architecture decision and field gate.

## Implementation boundaries

The later implementation plan may change only these surfaces:

- `internal/system/windows/canary.go` and focused planner tests for provenance and typed classification
- `internal/hgctlcmd/canary.go` and focused command tests for redacted JSON and exit code `3`
- `internal/hgctlcmd/live_canary_test.go` for Apply and Confirm fail-before-mutation evidence
- `scripts/p35-canary.ps1` and `tests/windows-pester/P35Canary.Tests.ps1` for launcher forwarding in PowerShell 5.1 and 7
- P3.5 acceptance, report, and architecture records after implementation validation

The implementation must not modify RedShield or Cisco configuration, route selection policy, runtime overlap checks, artifact schemas, confirmation-token inputs, state-root semantics, or recovery ordering.

## Testing and evidence

Implementation follows red-green test-driven development. Focused tests must cover:

- explicit target overlap with a provider endpoint
- explicit target overlap with a Cisco prefix
- imported DNS overlap with a provider endpoint
- imported DNS overlap with a Cisco prefix
- IPv4 and IPv6 bucket classification
- deterministic ordering and per-bucket deduplication
- a target that belongs to both input sources
- a target that overlaps more than one protected prefix in one class
- rejection of invalid typed diagnostic data
- absence of target, DNS, endpoint, prefix, adapter, config path, config hash, and key material from stdout and stderr
- unchanged successful Plan fields and confirmation challenge
- blocked Plan exit code `3` with no confirmation challenge
- Apply and Confirm rejection before transaction creation or mutation
- PowerShell 5.1 and 7 forwarding of JSON and exit code `3`

The final implementation batch runs focused Go and Pester tests first, then one `scripts/dev.ps1 -Command verify` gate. The report records `RUFF_NOT_APPLICABLE_NO_PYTHON` unless implementation introduces Python, which this design does not require.

## Acceptance criteria

- The current collision scenario returns `block_code: canary_target_isolation` with an `imported_dns` and `cisco_prefix` bucket, without disclosing any address or prefix.
- Blocked Plan returns exit code `3`, sets both readiness and mutation booleans to `false`, and omits the confirmation challenge.
- The PowerShell launcher preserves that JSON and exit code.
- Successful Plan output and challenge binding remain compatible with the existing contract.
- Apply and Confirm cannot reach candidate staging, journal creation, watchdog arming, or native mutation for any isolation block.
- Planner and runtime Cisco/provider overlap guards remain active and unchanged in meaning.
- No tool edits the current profile or chooses a replacement DNS server.
- A compatible future profile must pass fresh gates and receive separate live authorization.
- Focused tests, the repository verification gate, and consolidated review have no open Critical or Important findings.
- `pc-core-ready` remains open until the separately authorized live matrix and terminal journaled `FullRestore` pass.
