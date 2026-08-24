# ADR-0011: PC-first platform and tunnel boundary

Status: Accepted

## Context

The policy and recovery model was proven in Linux namespaces and OpenWrt QEMU during P2. The first production target is the current Windows PC, where an existing RedShield WireGuard or AmneziaWG configuration provides the bootstrap tunnel. A self-hosted VPN and the final Flint 2 gateway are later migrations and must not change policy or control-plane semantics.

The existing ADR-0010 number is already assigned to the dnsmasq domain-match capability boundary, so this decision uses ADR-0011.

## Decision

Policy, desired state, explanation, revisions and public control-plane contracts remain platform- and provider-neutral.

`RoutingBackend` owns only project-created routing, firewall and DNS state for one active platform. Windows is the production adapter for P3-P11. The P2 Linux/OpenWrt implementation remains the regression reference and becomes the Flint 2 adapter in P12.

`TunnelBackend` owns client-tunnel inspection and lifecycle behind explicit capabilities. P3-P7 import a user-supplied RedShield WireGuard or AmneziaWG configuration and treat provider-side server management as unavailable. P8 switches the same contract to a self-hosted backend. The raw RedShield config and key material remain external secrets and never enter Git, logs, evidence or subprocess arguments. Local inspection JSON may expose only bounded non-key metadata; it omits the source path, key material and raw obfuscation values.

Windows integration starts read-only. Inventory and a structured dry-run must prove that the physical default route, provider endpoint, active RedShield adapter and Cisco routes can be preserved. Mutating apply remains unavailable until rollback, last-known-good recovery and IPv4/IPv6 fail-closed operations pass offline tests and a separate live-change confirmation is recorded.

## Consequences

The absence of a VPS or Flint 2 does not block P3-P7. Provider-specific or OS-specific details cannot leak into policy/API contracts. Only one platform adapter may own project-created state on a host, and Cisco configuration remains outside project ownership.

Early VPS/router work can be retained as later-phase preparation, but it is not P3 acceptance evidence.

## Verification

P3 requires redaction and importer tests, Windows inventory and dry-run contract tests, real direct/RedShield/Cisco route evidence, IPv4/IPv6 fail-closed capture, restart/recovery and complete restoration of pre-install Windows state. P8 repeats the same decision fixtures against the self-hosted backend. P12 repeats the platform safety matrix on Flint 2.
