# ADR-0002: VPN transports

Status: Accepted

## Context

The gateway needs a replaceable bootstrap VPN, a managed self-hosted primary path and an independent censorship-resistant fallback without allowing any transport to own global routing policy.

## Decision

P3-P7 use an imported RedShield WireGuard or AmneziaWG configuration as an opaque provider-backed client tunnel on Windows. P8 switches the same `TunnelBackend` contract to official self-hosted AWG. A maintained OpenWrt package and netifd helper are the final P12 adapter. amneziawg-go is contingency only. VLESS Reality TUN remains independent.

## Consequences

Provider-side RedShield management is unavailable and its configuration remains an external secret. Kernel integration is preferred on Flint 2 when the exact target passes qualification. Contingency and fallback transports remain replaceable adapters under routerd policy ownership.

## Verification

P3 validates the real RedShield config and Windows tunnel behavior. P8 validates the self-hosted server migration. SDK build is P0; Flint 2 hardware module/UAPI and throughput qualification are P12 gates.
