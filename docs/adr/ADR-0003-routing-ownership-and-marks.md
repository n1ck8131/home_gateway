# ADR-0003: Routing ownership and marks

Status: Accepted

## Context

Multiple tunnel processes and server changes must not compete for routes or silently move established sessions between egress paths.

## Decision

routerd is the sole policy owner. It reserves `0xff000000` as its mark mask.
Persistent server slots `1..255` map to mark `slot << 24` and routing table
`10000 + slot`. Slot zero is invalid. Per-server connection marks/tables keep
old healthy sessions on their selected egress instead of silently moving them.

## Consequences

Tunnel adapters cannot install global policy routes. Connection and packet marks become stable contracts shared by routing, health and failover components. Deployment validation must reject a collision with marks or tables owned by another service.

## Verification

P1 contract tests prove deterministic slot allocation, mask enforcement and uniqueness. P2 inventory and packet-capture tests prove ownership is collision-free and VPN lookup cannot fall through to `main`.
