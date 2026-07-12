# ADR-0004: DNS and precedence

Status: Accepted

## Context

Manual, protected and external sources can overlap at domain and shared-IP levels. The policy must resolve conflicts deterministically without overstating DNS leak protection.

## Decision

Protected origin tier wins before specificity; specificity applies inside a tier; direct wins unresolved shared-IP collision. No-leak guarantee is scoped to managed DNS and explicit device policy.

## Consequences

Policy explanations must expose the winning tier and conflict rule. Unmanaged client DNS and browser DoH are diagnosed but are outside the no-leak guarantee.

## Verification

Table-driven policy tests and DNS cold-boot tests are mandatory.
