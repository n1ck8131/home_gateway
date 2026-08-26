# ADR-0015: P3.5 redacted canary block diagnostics

Status: Accepted

## Context

P3.5 Plan rejects a target that overlaps a provider endpoint or Cisco protected prefix. Merged targets currently lose the source needed for a safe diagnosis.

## Decision

Retain target provenance only until the existing isolation classification. Return a typed isolation error with only fixed `target_source`, `protected_class`, `family`, and `affected_target_count` fields. Validate at most eight canonically ordered buckets, with each count no greater than `maxManagedRoutes`.

Emit structured JSON only for a typed Plan isolation failure. It returns exit code `3` and omits challenge fields. Apply and Confirm remain generic, hard-blocked, and pre-transaction.

This phase rejects bypasses, profile rewriting, DNS substitution, and local proxy work. It does not change the existing provider/Cisco overlap guard.

## Consequences

The guard has no bypass. The current profile remains incompatible. A future profile requires a new hash, preflight, Plan, and live authorization.

## Verification

Focused planner, CLI, live-boundary, and PowerShell tests prove redaction, deterministic counts, success compatibility, and no pre-transaction mutation.
