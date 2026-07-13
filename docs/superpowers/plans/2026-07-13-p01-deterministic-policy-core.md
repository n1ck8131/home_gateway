# P1 Deterministic Policy Core Implementation Plan

## Goal

Implement a platform-independent policy compiler that normalizes route entries,
resolves every supported precedence conflict deterministically, emits a stable
plan, and explains the complete evidence chain for a route decision.

P1 does not render or apply nftables, `ip rule`, dnsmasq, OpenWrt, or tunnel
configuration.

## Source requirements

- `SPEC.md` sections 4, 6, 12, 23.2, 29.1, and 29.2.
- `PLAN.md` P1 exit gate.
- ADR-0003 routing ownership and marks.
- ADR-0004 DNS and precedence.

## Stable P1 contracts

### `pkg/contracts`

- `RouteClass`: `local`, `direct`, `vpn`.
- `DeviceMode`: `auto`, `always-direct`, `always-vpn`.
- `EntryKind`: domain and CIDR families supported by P1.
- `DomainMatch`: exact, suffix, wildcard.
- `OriginTier`: ordered protected/manual/curated/external tiers.
- `Scope`: global or device-scoped.
- `Device`: one logical device with multiple network identities and a protected
  work-device flag.
- `RouteEntry`: canonical policy input with stable ID, scope, origin, sequence,
  optional expiration, and selected server.
- `DesiredState`: devices, entries, active/default server information, mark
  allocation, and explicit evaluation time.
- `PolicyPlan`: canonical normalized entries, deterministic decisions, and
  per-server routing selections. It remains pure data.
- `RouteDecision`: winner, route/server selection, conflict state, and ordered
  evidence for `route explain`.

Enums reject unknown values through validation rather than silently defaulting.
Contracts contain no platform calls and no mutable global clock.

### Determinism rules

1. Protected `system-direct` wins before all specificity comparisons.
2. Scoped `auto-cisco` wins for the matching protected work device only.
3. Manual wins over curated and external origins.
4. Curated direct wins over external direct and VPN.
5. External direct wins over external VPN.
6. Specificity applies only inside the same origin tier: longest CIDR/domain,
   then exact over suffix over wildcard.
7. Equal manual keys use the greatest explicit `Sequence`; equal non-manual
   duplicates use a stable ID tie-break.
8. Unresolved shared-IP direct/VPN collision resolves to direct and remains
   visible as a conflict in explanation evidence.
9. Expiration uses `DesiredState.EvaluationTime`, never `time.Now()`.
10. Final plan and evidence slices use canonical stable ordering.

### Safety rules

- Protected work devices cannot use `always-vpn`.
- Local/reserved destinations cannot be assigned to VPN.
- Server marks must fit the reserved mask, be unique, and map one server to one
  stable routing table selection.
- Invalid or oversized input fails before a partial plan is returned.

## Files and TDD sequence

### 1. Contracts

Create:

- `pkg/contracts/policy.go`
- `pkg/contracts/policy_test.go`

Write failing validation tests first, then add the smallest contract types and
validation required by those tests.

### 2. List normalization

Create:

- `internal/lists/normalize.go`
- `internal/lists/normalize_test.go`
- `internal/lists/normalize_fuzz_test.go`

Test and implement:

- trim/lowercase and URL host extraction;
- IDNA ASCII canonicalization;
- exact/suffix/wildcard validation;
- public-suffix rejection;
- IPv4, IPv6, and CIDR canonicalization;
- limits for raw length and batch size;
- deterministic duplicate and subsumed-entry removal.

### 3. Policy engine

Create:

- `internal/routing/policy/engine.go`
- `internal/routing/policy/engine_test.go`
- `internal/routing/policy/golden_test.go`
- `internal/routing/policy/testdata/precedence.golden.json`

Write table-driven failing cases for every precedence pair, device mode, scope,
expiration, same-tier specificity, manual replacement, protected-device safety,
shared-IP collision, and server selection before implementation.

### 4. Explanation

Create:

- `internal/routing/explain/explain.go`
- `internal/routing/explain/explain_test.go`

The explanation builder receives policy evaluation data and emits an ordered
evidence chain. Tests prove that losing matches and the exact winning rule are
present and stable.

### 5. Traceability and status

Update:

- `docs/ACCEPTANCE_MATRIX.md`
- `STATUS.md`
- `DECISIONS.md` only if implementation discovers a durable decision not
  already covered by ADR-0003/0004.

## Commit boundaries

1. `docs: plan P1 deterministic policy core`
2. `feat: add policy contracts and list normalization`
3. `feat: add deterministic routing policy and explain`
4. `docs: close P1 policy core`

## Validation batch

Run once after implementation and review findings are resolved:

```powershell
go test ./pkg/contracts/... ./internal/lists/... ./internal/routing/...
go test ./internal/lists -run '^$' -fuzz '^FuzzNormalizeDomain$' -fuzztime 15s
go test ./internal/lists -run '^$' -fuzz '^FuzzNormalizeCIDR$' -fuzztime 15s
.\scripts\dev.ps1 verify
```

On Linux with `CAP_NET_ADMIN`, run the repository routing prerequisite gate:

```text
sudo tests/network-ns/check-prereqs.sh
```

P1 has no packet renderer or apply path, so the P2 packet-flow suite cannot be
meaningfully executed yet. Its prerequisite gate still proves the integration
environment remains available.

## Exit criteria

- All P1 contracts validate invalid states fail-closed.
- Normalization handles domain/IDNA/PSL/IP/CIDR cases and limits.
- Every precedence pair has deterministic evidence.
- Golden output is byte-stable across repeated evaluations.
- Protected work-device and shared-IP direct safety rules pass.
- Targeted tests, fuzz smoke, full repository verification, and Linux routing
  prerequisite gate pass.
- `STATUS.md` reports P1 complete only after validation evidence exists.
