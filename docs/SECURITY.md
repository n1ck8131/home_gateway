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
- The imported RedShield config is an external provider secret. P3 inspection is local and read-only; provider-side credentials and server management are outside the project trust boundary.
- External list sources and downloaded artifacts are untrusted until pinned, bounded and verified.
- Backup destinations are untrusted storage; backup confidentiality comes from `age` encryption.

## Secret locations

- Router secret bytes live only under `/etc/routerd/secrets/`; the directory is mode `0700` and files are mode `0600`.
- Per-server SSH keys are separate credentials and are never embedded in inventory files.
- Windows enrollment material uses Windows-protected storage rather than repository or configuration files.
- The source RedShield `.conf` remains outside the repository. Local preflight metadata may contain normalized endpoint/address/DNS properties, but excludes the source path, keys and raw obfuscation values; support evidence redacts endpoint/address values. Later unattended use must copy secret bytes only into Windows-protected storage with a separately tested removal path.
- The interactive importer rejects UNC/device namespaces, remote or unknown Windows volumes, symlink/reparse traversal and unstable leaf snapshots. Before privileged or unattended consumption it additionally requires restrictive ACLs and handle-based final volume/file identity so snapshot races are outside the service threat boundary.
- Mobile private keys are one-time delivery material; only public keys and metadata persist.
- Logs, support bundles, command lines, process lists and Git must not contain secret bytes.

## Command execution

The P3 read-only collector uses `exec.CommandContext` with a fixed script and no caller-supplied executable or arguments. Windows APIs resolve the trusted Windows and System32 directories; Windows PowerShell and inbox module manifests use absolute paths, and the process receives a minimal sanitized environment with bounded output. Shell command strings must never be constructed from domains, comments, source URLs or other user-controlled input. Physical adapters require the authoritative Windows hardware marker, while routes and future operations bind to stable interface GUIDs. P3.3 exposes no network mutation path.

## Supply chain controls

- Production versions, commits, action revisions and artifact SHA-256 values are pinned.
- OpenWrt images and project releases are verified before use.
- Releases include `SHA256SUMS`, signatures, provenance, an SBOM, a license report and `THIRD_PARTY_NOTICES.md`.
- Production workflows do not use `curl | sh`.

## P0 exclusions

P0 creates locks, contracts, build evidence and compatibility probes only. It does not install firmware, mutate WAN, firewall, DNS or routing, deploy real credentials, expose a production API, issue mobile profiles or claim hardware and field acceptance owned by later phases.
