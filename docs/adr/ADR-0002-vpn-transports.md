# ADR-0002: VPN transports

Status: Accepted

## Context

The gateway needs a primary high-performance VPN path and an independent censorship-resistant fallback without allowing either transport to own global routing policy.

## Decision

Official AWG2 kernel/tools are primary. A maintained OpenWrt package and netifd helper are project-owned adapters. amneziawg-go is contingency only. VLESS Reality TUN remains independent.

## Consequences

Kernel integration is preferred when the exact target passes qualification. Contingency and fallback transports remain replaceable adapters under routerd policy ownership.

## Verification

SDK build is P0; hardware module/UAPI is P3 precondition; throughput decides kernel versus contingency.
