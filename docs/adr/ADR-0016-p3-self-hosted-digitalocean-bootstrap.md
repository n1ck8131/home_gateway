# ADR-0016: P3 self-hosted DigitalOcean bootstrap

Status: Accepted

## Context

P3 originally used a user-supplied RedShield WireGuard or AmneziaWG profile as the first Windows tunnel and deferred the first own VPS to P8. The RedShield path produced useful offline importer, planning, mutation and recovery evidence, but its bounded live attempt stopped before mutation on the imported-DNS/Cisco isolation guard.

On 2026-08-27 the owner decided to stop treating RedShield as the target provider and to qualify the product directly against an owned VPN. The selected starting resource is one DigitalOcean Basic Droplet at the $6 monthly baseline: 1 shared vCPU, 1 GiB RAM and 25 GiB SSD.

## Decision

P3 will bootstrap one self-hosted AmneziaWG server on a manually created DigitalOcean Droplet and use one static Windows PC peer for `pc-core-ready` qualification. The supported P3 installation path is the official AmneziaVPN 5.0.1.5 `Self-hosted VPN` GUI flow, installing only AmneziaWG and exporting one guest in native format.

The initial baseline is `ams3` (`fra1` fallback), Ubuntu 24.04 LTS x64, the $6 Basic Regular size, IPv6 and monitoring enabled, SSH restricted to the current owner management IPv4 `/32` and available IPv6 `/128`, and one public UDP tunnel port. The first Droplet is created through the DigitalOcean UI with a dedicated SSH public key. Initial key-only root access is replaced after bootstrap by the `homegateway` passwordless-sudo operator with root SSH disabled. No DigitalOcean API token or `doctl` is required. Cloud and host firewalls expose no web panel, public proxy or recursive DNS service.

The Windows installer asset is pinned by SHA-256, but the tagged Amnezia server Dockerfile references `amneziavpn/amneziawg-go:latest`. P3 records the actually installed container image ID/digest and stops if it cannot establish that identity; it does not claim an official pinned noninteractive bootstrap. P8 owns digest-pinned automation and reconciliation.

P3 owns only the supported manual bootstrap with recorded provenance, protected static profile, provider-neutral Windows integration and complete live safety/recovery matrix. P8 retains digest-pinned provisioning automation, restricted `server-agent`, operational lifecycle, mobile peer management and telemetry. P9 retains the second VPS and failover.

RedShield is retired as the required/target backend but is not disconnected, reconfigured or deleted by this decision. Its code and evidence remain historical compatibility assets. Any live RedShield change requires a later explicit authorization.

## Compatibility with earlier decisions

This ADR supersedes the provider-selection and phase-sequencing clauses in ADR-0002 and ADR-0011 that assign RedShield to P3-P7 and the first own VPS to P8, and the RedShield-specific adapter naming in ADR-0012/ADR-0013. Their provider-neutral `TunnelBackend`, platform ownership, fail-closed, Cisco non-interference, redaction, persistent-sink and recovery requirements remain binding.

The existing P3.5 RedShield pre-mutation block remains historical evidence. It does not qualify the self-hosted backend and does not justify bypassing the DNS/Cisco isolation guard.

## Consequences

- A billable cloud resource is now an external P3 gate, but documentation and offline implementation do not create it.
- P3 implementation must remove hard-coded RedShield identity from the active planner/runtime path and support the native AWG 3.1 profile exported by the current official client while retaining provider-neutral safety semantics.
- The owner must maintain one dedicated SSH key and one protected peer profile outside Git.
- The $6 size is accepted only after measured capacity evidence; powered-off billing and transfer overage are operational considerations.
- Initial backups stay disabled for the disposable canary unless separately approved because snapshots replicate secret-bearing server state.
- `pc-core-ready` remains open until observed handshake/egress, the complete Windows safety matrix, restart/recovery and a terminal journaled `FullRestore` pass.

## Verification

Verification is staged: documentation consistency; offline tests for the AWG 3.1 importer, create-plan guard and provider-neutral Windows behavior; manual billable creation; strict host-key verification; hash-pinned official GUI installation plus observed server image identity; separately authorized guest creation and redacted profile inspection; separately authorized Windows client import/activation with a profile-only rollback; exact non-mutating Windows Plan; separately authorized bounded Apply/Confirm; anomaly rollback; and a fresh exact-candidate approval before terminal `FullRestore`.

No phase may infer provider health from interface presence, bypass Cisco protection, expose secrets in evidence or treat Droplet creation as P8 operational acceptance.
