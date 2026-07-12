# ADR-0007: Mobile peer lifecycle

Status: Accepted

## Context

Mobile profiles contain private material that must not become a reusable download or couple the revocation of unrelated devices.

## Decision

One device/server pair has one keypair. One-time material is single-consumption with a ten-minute TTL; only public key and metadata persist.

## Consequences

Adding, rotating and revoking a peer is scoped to one device/server pair. Delivered private keys cannot be recovered from persistent application state.

## Verification

Reuse, expiry and revoke tests are mandatory.
