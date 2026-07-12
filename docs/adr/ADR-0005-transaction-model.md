# ADR-0005: Transaction model

Status: Accepted

## Context

Router configuration updates must preserve management access and recover from local or remote partial failure.

## Decision

Local apply uses lock, staging, validation, snapshot, commit-confirm watchdog and rollback. Router-to-VPS changes use an idempotent saga with compensation.

## Consequences

Every apply boundary needs an explicit compensation path and durable evidence. Cross-host operations are not presented as a single atomic transaction.

## Verification

No claim of distributed atomicity; failure injection covers every boundary.
