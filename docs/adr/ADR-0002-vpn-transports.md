# ADR-0002: VPN transports

Status: Accepted; provider sequencing amended by ADR-0016

## Context

The gateway needs a replaceable bootstrap VPN, a managed self-hosted primary path and an independent censorship-resistant fallback without allowing any transport to own global routing policy.

## Decision

P3 uses one manually bootstrapped self-hosted AmneziaWG server as the Windows qualification tunnel under ADR-0016. The existing RedShield importer remains historical compatibility code, not a required or automatic fallback. P8 operationalizes the same `TunnelBackend` contract with managed server/mobile lifecycle rather than creating the first own VPS. A maintained OpenWrt package and netifd helper are the final P12 adapter. amneziawg-go is contingency only. VLESS Reality TUN remains independent.

## Consequences

The self-hosted Windows profile and any retained RedShield configuration remain external secrets. Provider automation and public management endpoints are not introduced by the P3 bootstrap. Kernel integration is preferred on Flint 2 when the exact target passes qualification. Contingency and fallback transports remain replaceable adapters under routerd policy ownership.

## Verification

P3 validates a protected self-hosted profile, observed server handshake/egress and Windows tunnel behavior, then completes the safety matrix and terminal `FullRestore`. Earlier RedShield validation remains historical evidence only. P8 validates managed server/mobile lifecycle. SDK build is P0; Flint 2 hardware module/UAPI and throughput qualification are P12 gates.
