# ADR-0003: Routing ownership and marks

Status: Accepted

## Context

Multiple tunnel processes and server changes must not compete for routes or silently move established sessions between egress paths.

## Decision

routerd is the sole policy owner. Reserve a mark mask and use per-server connection marks/tables so old healthy sessions drain instead of being silently moved.

## Consequences

Tunnel adapters cannot install global policy routes. Connection and packet marks become stable contracts shared by routing, health and failover components.

## Verification

P1 defines values; P2 packet-capture tests prove no fallback to main.
