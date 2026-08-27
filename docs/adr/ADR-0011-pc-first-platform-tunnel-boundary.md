# ADR-0011: PC-first platform and tunnel boundary

Status: Accepted; provider sequencing amended by ADR-0016

## Context

The policy and recovery model was proven in Linux namespaces and OpenWrt QEMU during P2. The first production target is the current Windows PC. ADR-0016 changes its active qualification tunnel from the previously imported RedShield profile to one minimal self-hosted DigitalOcean AmneziaWG server. The final Flint 2 gateway remains a later migration and must not change policy or control-plane semantics.

The existing ADR-0010 number is already assigned to the dnsmasq domain-match capability boundary, so this decision uses ADR-0011.

## Decision

Policy, desired state, explanation, revisions and public control-plane contracts remain platform- and provider-neutral.

`RoutingBackend` owns only project-created routing, firewall and DNS state for one active platform. Windows is the production adapter for P3-P11. The P2 Linux/OpenWrt implementation remains the regression reference and becomes the Flint 2 adapter in P12.

`TunnelBackend` owns client-tunnel inspection and lifecycle behind explicit capabilities. P3 imports a protected static self-hosted AmneziaWG profile and treats automated server management as unavailable. P8 adds the restricted operational and mobile lifecycle behind the same contract. Raw self-hosted or retained RedShield profiles and key material remain external secrets and never enter Git, logs, evidence or subprocess arguments. Local inspection JSON may expose only bounded non-key metadata; it omits the source path, key material and raw obfuscation values.

Windows integration starts read-only. Inventory and a structured dry-run must prove that the physical default route, self-hosted endpoint, exactly one qualified active tunnel adapter and Cisco routes can be preserved. Mutating apply remains unavailable until rollback, last-known-good recovery and IPv4/IPv6 fail-closed operations pass offline tests and a separate live-change confirmation is recorded.

## Consequences

The absence of Flint 2 does not block P3-P11, but one own VPS is now an explicit external P3 field gate. Provider-specific or OS-specific details cannot leak into policy/API contracts. Only one platform adapter may own project-created state on a host, and Cisco configuration remains outside project ownership.

Droplet creation alone is not P3 acceptance evidence, and P3 bootstrap evidence is not P8 operational/mobile acceptance.

## Verification

P3 requires redaction and importer tests, a hash-pinned official client plus observed server image identity and clear/rebuild evidence, Windows inventory and dry-run contract tests, real direct/self-hosted/Cisco route evidence, observed handshake/egress, IPv4/IPv6 fail-closed capture, restart/recovery and complete restoration of pre-install Windows state. P8 repeats the same decision fixtures against the digest-pinned managed server/mobile lifecycle. P12 repeats the platform safety matrix on Flint 2.
