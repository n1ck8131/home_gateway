# Security Model

## Threats

The project treats the following as explicit threats:

- Compromised external list sources.
- Blocked GitHub or raw-content delivery.
- Substituted release artifacts.
- Misconfiguration.
- A hostile LAN client.
- A stolen mobile profile.
- Compromise of one VPS.
- VPN endpoint blocking.
- DNS poisoning.
- IPv6 leakage.
- Command injection through a domain, comment or source URL.
- Flash wear.
- Loss of access after a firewall reload.

## Trust boundaries

- Browsers and LAN clients are untrusted callers of the LAN-local router API.
- `routerd` policy and status code is separated from the privileged apply adapter.
- Router-to-VPS operations cross an authenticated remote boundary and use scoped, allowlisted operations.
- `cisco-discovery` is a read-only Windows observer with a scoped token and an offline queue.
- Every imported tunnel config is an external provider secret. P3 inspection and protected staging are local; provider-side credentials and server management cross a separately approved trust boundary. RedShield remains historical compatibility state and is never modified by the self-hosted workflow.
- External list sources and downloaded artifacts are untrusted until pinned, bounded and verified.
- Backup destinations are untrusted storage; backup confidentiality comes from `age` encryption.

## Secret locations

- Router secret bytes live only under `/etc/routerd/secrets/`; the directory is mode `0700` and files are mode `0600`.
- Per-server SSH keys are separate credentials and are never embedded in inventory files.
- Windows enrollment material uses Windows-protected storage rather than repository or configuration files.
- Source and exported `.conf` files remain outside the repository. The installed self-hosted profile is `secrets\tunnel.conf` under the protected runtime root and is pinned by lowercase SHA-256; evidence excludes source paths, keys, endpoints, addresses, DNS values and raw obfuscation values.
- Real infrastructure pins and transcripts remain only under root-ignored `.p3-vps-run/`; local Windows runtime evidence remains only under root-ignored `.p35-run/`. Tracked reports contain reviewed sanitized hashes, counts, booleans and classifications only.
- The interactive importer rejects UNC/device namespaces, remote or unknown Windows volumes, symlink/reparse traversal and unstable leaf snapshots. Before privileged or unattended consumption it additionally requires restrictive ACLs and handle-based final volume/file identity so snapshot races are outside the service threat boundary.
- Mobile private keys are one-time delivery material; only public keys and metadata persist.
- Logs, support bundles, command lines, process lists and Git must not contain secret bytes.

## Command execution

The P3 read-only collector uses `exec.CommandContext` with a fixed script and no caller-supplied executable or arguments. Windows APIs resolve the trusted Windows and System32 directories; Windows PowerShell and inbox module manifests use absolute paths, and the process receives a minimal sanitized environment with bounded output. Shell command strings must never be constructed from domains, comments, source URLs or other user-controlled input. Physical adapters require the authoritative Windows hardware marker, while routes and future operations bind to stable interface GUIDs.

P3 accepts only strict bounded JSON artifacts, binds every provider endpoint to an independently qualified host-prefix set, rejects virtual or unstable default paths, and exposes a native Windows `MutationBackend` behind offline-tested preflight, ownership, commit-confirm and recovery contracts. Project routes use reserved ownership metadata, firewall identities are revision-qualified and content-addressed, and generated NRPT identities are journaled exactly. Immutable revisions have SHA-256 manifests; recovery snapshots are hashed and semantically checked before replay. Foreign, Cisco and OS-owned state is neither persisted as project-owned nor eligible for removal. Native live use remains separately candidate-bound and gated.

Terminal restoration is monotonic rather than falsely atomic: exact network `FullRestore` completes first, then protected-config ACL restoration runs under its own plan hash and confirmation challenge. Terminal evidence retains journal state `restored`, an empty ownership registry, the install snapshot and receipt; active/LKG/pending/recovery revisions are empty and project-owned routes, sinks, firewall, NRPT and tasks are zero.

## Supply chain controls

- Production versions, commits, action revisions and artifact SHA-256 values are pinned.
- OpenWrt images and project releases are verified before use.
- Releases include `SHA256SUMS`, signatures, provenance, an SBOM, a license report and `THIRD_PARTY_NOTICES.md`.
- Production workflows do not use `curl | sh`.

## P0 exclusions

P0 creates locks, contracts, build evidence and compatibility probes only. It does not install firmware, mutate WAN, firewall, DNS or routing, deploy real credentials, expose a production API, issue mobile profiles or claim hardware and field acceptance owned by later phases.
