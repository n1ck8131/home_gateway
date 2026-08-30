# P3 self-hosted DigitalOcean transition design

Status: Accepted by the owner on 2026-08-27

## Scope

This design changes the P3 tunnel target from RedShield to one manually provisioned self-hosted DigitalOcean Droplet. It records architecture and gates only. It does not create a billable resource, generate or use credentials, connect to a server, expose a UDP port, mutate Windows networking, stop RedShield or change Cisco.

## Context

The RedShield-backed P3 path proved the strict config importer, Windows inventory, fail-closed artifacts, commit-confirm transaction and recovery mechanics offline. The authorized live sub-batch then stopped safely before mutation because imported DNS overlapped a Cisco-protected prefix. That result remains valid historical evidence; it is not a failed self-hosted test and is not rewritten as acceptance.

The owner has decided to retire RedShield as the target backend and test the product directly against an owned VPN. The selected service is a DigitalOcean Basic Droplet at the $6 monthly baseline shown in the owner-provided configuration.

## Decision

P3 will use one minimal, manually created DigitalOcean Droplet as the live Windows canary backend:

| Item | Selected baseline |
|---|---|
| Provider | DigitalOcean |
| Region | `ams3`; use `fra1` only if availability or a bounded latency check makes it preferable |
| Size | Basic Regular, 1 shared vCPU, 1 GiB RAM, 25 GiB SSD, 1,000 GiB transfer |
| Image | Ubuntu 24.04 LTS x64, slug `ubuntu-24-04-x64` |
| Tunnel | Official AmneziaVPN 5.0.1.5 `Self-hosted VPN` GUI path, current AWG 3.1; preserve the baseline Admin, add one `homegateway` Admin, and export one static PC Guest |
| Public ingress | SSH restricted to the current owner management IPv4 `/32` and, when available, IPv6 `/128`; one selected UDP tunnel port available to VPN clients |
| Access | Dedicated project SSH key; no password authentication; initial key-only root bootstrap followed by a `homegateway` passwordless-sudo operator and disabled root SSH |
| Network controls | DigitalOcean Cloud Firewall plus matching host firewall; IPv6 and monitoring enabled |
| Creation path | DigitalOcean UI for the first Droplet; no API token or `doctl` |
| Initial backups | Disabled for the disposable canary unless the owner separately approves secret-bearing snapshots |

The $6 size is a starting capacity hypothesis, not a throughput promise. CPU, memory, loss and throughput are measured before it is treated as a durable production size. A powered-off Droplet remains billable until destroyed, and transfer overage remains possible.

The official supported server installation path is interactive through AmneziaVPN. Version 5.0.1.5 is pinned by Windows asset SHA-256 `2e898bbd1d639f5066416961a2a458dba7c3455c0e8f49c7f130e9281d700377`, but its tagged server Dockerfile uses `amneziavpn/amneziawg-go:latest`. P3 must therefore record the actually installed container image ID/digest and must not claim a reproducible noninteractive bootstrap. If the exact image identity cannot be captured, installation stops before Windows activation. P8 owns a reviewed digest-pinned automation contract.

## Phase boundary

| P3 now owns | Still deferred |
|---|---|
| Dedicated local SSH-key preparation and public-key handoff | DigitalOcean API token and provisioning automation |
| One manual Droplet and one static Windows peer | Managed server lifecycle and mobile peer operations |
| Pinned client installer plus observed server image identity and clear-server/rebuild runbook | Digest-pinned noninteractive provisioning and restricted `server-agent` |
| Protected local self-hosted config import | Traffic accounting, alerts and billing integration |
| Provider-neutral Windows planning and bounded canary | Second VPS, failover and automatic provider selection |
| Handshake, egress, DNS, IPv4/IPv6, MTU and recovery evidence | Flint 2 migration and router-wide acceptance |

P8 no longer means “create the first own VPS”. It operationalizes and automates the already qualified self-hosted server, adds the restricted management boundary and implements mobile peer lifecycle. P9 continues to own multi-server failover.

The accepted P3 terminal peer topology is exact: the pre-existing baseline Admin remains unchanged, exactly one `homegateway` management Admin is added, and exactly one static PC Guest is added. Supported Admin rollback is official-UI removal of only the candidate peer. The reviewed candidate-bound direct rollback is emergency-only. Guest removal is a separately approved server mutation and is never implied by client-profile rollback.

## Security and secret handling

- The user never sends a private SSH key, VPN private key, password, recovery code or DigitalOcean API token through chat.
- Only a public SSH key is uploaded to DigitalOcean. The private half remains in protected local storage.
- The generated Windows peer profile remains outside Git, logs, command-line arguments and evidence bundles. Only its protected local path and content hash may enter an operator command.
- The initial server manifest stores only non-secret facts: Droplet ID/name, region, size, image slug/ID, public addresses, SSH host-key fingerprints, artifact versions and hashes.
- SSH host-key verification is strict. A changed fingerprint fails closed until separately reconciled.
- SSH is never opened to `0.0.0.0/0` or `::/0`; a changed owner source address requires a separately reviewed firewall update. The tunnel UDP port may be public because it is the client data-plane endpoint.
- No public web panel, proxy, recursive DNS resolver or unrestricted management endpoint is deployed.
- RedShield and Cisco remain untouched while the new server is prepared. RedShield disconnect/removal is a separate live decision after the self-hosted path is accepted.

## Execution gates

1. **Documentation gate** — this design, ADR-0016 and the implementation plan are reviewed and repository verification passes.
2. **Local credential gate** — generate a dedicated SSH key locally and record only the public-key fingerprint. This requires a separate execution step but no network mutation.
3. **Billable create gate** — the owner explicitly authorizes creation and billing immediately before clicking **Create Droplet**.
4. **Bootstrap gate** — verify immutable Droplet metadata and SSH host key, then use the hash-pinned AmneziaVPN 5.0.1.5 GUI `Self-hosted VPN` flow to install only AmneziaWG. Capture the observed container image ID/digest and selected UDP port; do not treat internal Amnezia shell scripts as a supported API. This requires separate authorization for the first SSH/server mutation.
5. **Peer/profile gate** — after current Gate 6.4 state is reconciled, separately authorize exactly one `homegateway` Admin discovery and exactly one static PC `Guest access`. Export `AmneziaWG native format`, store it locally with restrictive ACLs and validate it through the provider-neutral importer without exposing secrets.
6. **Client activation gate** — present the exact profile hash, supported Windows client and profile-only rollback; separately authorize import/connection, then prove adapter identity, handshake and egress without changing RedShield or Cisco.
7. **Windows plan gate** — collect a fresh inventory and exact Plan. Any endpoint, DNS/Cisco overlap, IPv4/IPv6, adapter or sink ambiguity blocks before mutation.
8. **Live canary gate** — separately authorize exact Apply/Confirm. Run direct/self-hosted/Cisco, DNS, leak, MTU, TCP/UDP/QUIC and tunnel-loss assertions; roll back on any anomaly.
9. **Terminal recovery gate** — present the exact restore candidate/hash and removal set, obtain a fresh explicit approval, then run and verify journaled `FullRestore`. Only this field evidence can close `pc-core-ready`.
10. **Retirement gate** — only after self-hosted acceptance may the owner separately authorize stopping, removing or otherwise changing RedShield.

## Owner inputs

Before the billable create gate, the owner needs only:

- a DigitalOcean account with billing enabled;
- acceptance of the $6 monthly baseline and possible transfer overage;
- the dedicated project **public** SSH key generated locally;
- confirmation that `ams3`, Ubuntu 24.04 x64, the Basic $6 size, IPv6 and monitoring are selected.

After creation, the owner may provide the public Droplet ID/name, public IPv4/IPv6 addresses and confirmation of region/image/size. No private key, password or token is requested.

## Acceptance

The transition is accepted only when:

- the client installer hash and observed server container image identity are recorded, the official clear-server/rebuild behavior is documented, and no stronger reproducibility claim is made;
- the Windows profile passes bounded parsing, redaction, local ACL and hash-pinning checks;
- provider handshake and public egress are observed rather than inferred from an adapter;
- direct and Cisco paths remain available and unmodified;
- VPN-class traffic is fail-closed for both IPv4 and IPv6 during tunnel loss;
- restart/reconcile and anomaly rollback pass;
- terminal journaled `FullRestore` leaves journal state `restored`, active/LKG/pending/recovery revisions empty, the ownership registry present but empty, and project-owned routes/sinks/firewall/NRPT/tasks at zero while retaining the install snapshot and terminal receipt for audit;
- protected-config ACL restoration is a separate independently candidate-bound operation after network `FullRestore`, and neither operation removes the source profile, local client profile or server Guest;
- evidence contains no secret or raw profile content.

## Non-goals

This P3 transition does not implement a public server API, digest-pinned headless server provisioning, mobile enrollment, automatic Droplet create/delete, backups, telemetry accounting, multi-VPS failover, TCP fallback, router migration or automatic RedShield fallback.

## Official references

- [DigitalOcean Droplet pricing](https://www.digitalocean.com/pricing/droplets)
- [Droplet billing details](https://docs.digitalocean.com/products/droplets/details/pricing/)
- [Regional availability](https://docs.digitalocean.com/platform/regional-availability/)
- [Linux images for Droplets](https://docs.digitalocean.com/products/droplets/details/images/)
- [Recommended Droplet setup](https://docs.digitalocean.com/products/droplets/getting-started/recommended-droplet-setup/)
- [Enable IPv6](https://docs.digitalocean.com/products/networking/ipv6/how-to/enable/)
- [Cloud Firewall rules](https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/)
- [Bandwidth billing](https://docs.digitalocean.com/platform/billing/bandwidth/)
- [Official Amnezia self-hosted installation](https://docs.amnezia.org/documentation/instructions/install-vpn-on-server/)
- [Official Amnezia guest access and native export](https://docs.amnezia.org/documentation/instructions/share-connection/)
- [AmneziaVPN 5.0.1.5 release](https://github.com/amnezia-vpn/amnezia-client/releases/tag/5.0.1.5)
- [Tagged AmneziaWG server Dockerfile](https://github.com/amnezia-vpn/amnezia-client/blob/5.0.1.5/client/server_scripts/awg/Dockerfile)
- [Tagged native guest profile template](https://github.com/amnezia-vpn/amnezia-client/blob/5.0.1.5/client/server_scripts/awg/template.conf)
- [Official AmneziaWG 3.1 parameter contract](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260814/README.md)
- [Supported VPS requirements](https://docs.amnezia.org/documentation/supported-linux-os-for-vps/)
