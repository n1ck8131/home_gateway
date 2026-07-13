# ADR-0004: DNS and precedence

Status: Accepted

## Context

Manual, protected and external sources can overlap at domain and shared-IP levels. The policy must resolve conflicts deterministically without overstating DNS leak protection.

## Decision

Origin tier wins before specificity. Inside a tier, longer domain/CIDR matches
win, then exact over suffix over wildcard. Equal manual matches use the greatest
persisted operation sequence; other equal matches use stable entry ID ordering.
Only a still-unresolved shared-IP tie is resolved to direct; a stronger manual
VPN rule is not overridden by that safety tie-break. Expiration is evaluated
against an explicit policy timestamp. No-leak guarantee is scoped to managed DNS
and explicit device policy.

## Consequences

Policy explanations must expose the winner, ordered losing evidence and the exact conflict rule. Unmanaged client DNS and browser DoH are diagnosed but are outside the no-leak guarantee.

## Verification

P1 table-driven and golden tests cover every tier pair, specificity, replacement,
expiration and shared-IP resolution. DNS cold-boot tests remain mandatory in P2.
