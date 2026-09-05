# P3 pre-live prerequisite and container boundary closure

Status: Owner-authorized offline correction on 2026-08-31

Audience: Home Gateway maintainers, the Task 6A implementation agent, and the P3 field operator

Content type: Corrective architecture design

Supersedes: Conflicting storage, baseline, bootstrap, and Cloud Firewall assumptions in `2026-08-30-p3-task6a-prelive-guard-design.md`

## Summary

Task 6A is not eligible for a live gate in its current form. The accepted runtime manifest hashes a 28-field server baseline while the remote helper validates a different 23-field identity. The helper also treats AmneziaWG container paths as host paths. A real reconciliation therefore cannot pass, and an emergency rollback could operate outside the authoritative AmneziaWG state.

This correction makes the helper container-aware, defines one 27-field canonical server baseline, removes candidate-only `prepared_syncconf_sha256` from that baseline, and adds a separately approved read-only prerequisite observation before runtime preparation. The prerequisite observation binds the current server, the exact DigitalOcean Firewall and Droplet resources, and the management/three-authority egress pins without writing to the server or activating a VPN.

No live action is authorized by this design or its implementation.

## Confirmed topology

For AmneziaVPN 5.0.1.5 and AmneziaWG 3.1:

- the expected container is `amnezia-awg2`;
- the authoritative persistent configuration is `/opt/amnezia/awg/awg0.conf` inside that container;
- the client metadata table is `/opt/amnezia/awg/clientsTable` inside that container;
- the live interface is `awg0`;
- the official container launch does not bind-mount `/opt/amnezia/awg` to the host;
- the official live update is `awg syncconf awg0 <(awg-quick strip /opt/amnezia/awg/awg0.conf)` inside the container;
- Python is not a required package in the official container image.

The host-installed helper must therefore use a bounded Docker adapter. It must not read or write `/opt/amnezia/awg` with host `pathlib`, invoke host `/usr/bin/awg`, assume `wg0.conf`, or assume a synthetic `peers.json` schema.

## Goals

The correction must:

- make PowerShell and Python hash exactly the same canonical server baseline;
- collect the actual AmneziaWG persistent, metadata, live, and temporary state through Docker;
- preserve raw peer keys, configuration, addresses, resource identifiers, and secrets outside tracked output;
- keep read-only prerequisite observation independent from the final protected runtime manifest;
- bind the exact DigitalOcean Firewall and Droplet resources plus inbound and outbound rule unions;
- bind one management `/32` and three distinct HTTPS egress authorities from one fresh observation batch;
- allow runtime preparation only from a separately accepted immutable prerequisite receipt;
- keep emergency rollback exact-one-candidate, container-scoped, recoverable, and separately approved;
- prove the complete path with behavioral tests rather than independent synthetic hashes.

## Non-goals

The correction does not:

- run SSH, HTTPS egress observation, or DigitalOcean UI inspection during implementation;
- install or remove the helper;
- create, remove, import, export, or activate a peer/profile;
- change Cloud Firewall, host firewall, Docker, services, routes, DNS, adapters, RedShield, or Cisco;
- reboot the server or Windows;
- make `clientsTable` authoritative for live peer state;
- introduce a remote service, timer, socket, package, API token, or stored passphrase.

## Decision 1: one canonical server baseline

The canonical baseline is schema `home-gateway/p3-server-baseline/v2` with exactly these 27 fields:

1. `atomic_leftover_count`
2. `candidate_leftover_count`
3. `container_count`
4. `container_identity_sha256`
5. `container_restart_count`
6. `container_running`
7. `firewall_identity_sha256`
8. `host_policy_loaded`
9. `host_policy_sha256`
10. `image_identity_sha256`
11. `ipv6_non_mutation`
12. `ipv6_policy_sha256`
13. `listener_identity_sha256`
14. `live_peer_set_sha256`
15. `metadata_peer_set_sha256`
16. `metadata_sha256`
17. `payload_sha256`
18. `peer_fingerprint_sha256`
19. `persistent_config_sha256`
20. `persistent_peer_set_sha256`
21. `protocol_sha256`
22. `public_listener_class_count`
23. `runtime_identity_sha256`
24. `temporary_leftover_count`
25. `temporary_state_sha256`
26. `udp_publication_count`
27. `udp_publication_sha256`

Both languages sort object keys ordinally, serialize compact UTF-8 JSON without a byte-order mark, preserve JSON booleans and integers as their native types, sort the peer fingerprint array ordinally, and compute lowercase SHA-256 over those bytes. PowerShell must validate exact keys and exact types before canonicalization. Python must reject missing or additional snapshot fields used by the identity.

`prepared_syncconf_sha256` is not a pre-live fact. It is generated only for one exact emergency rollback candidate and is bound to that rollback plan and confirmation challenge.

## Decision 2: bounded Docker adapter

The installed helper remains a regular root-owned host file and runs under `sudo`. Its adapter uses absolute host executables and exact argument arrays:

- `/usr/bin/docker ps`, `inspect`, `image inspect`, `port`, `exec`, and, only in a separately approved rollback, bounded stream copy/write operations;
- `/usr/sbin/iptables-save`, `/usr/sbin/ip6tables-save`, `/usr/sbin/nft`, `/usr/bin/ss`, and `/usr/bin/systemctl` for host observations.

Read-only collection must:

- resolve exactly one running `amnezia-awg2` and reject any ambiguous same-name/all-container shape;
- verify the accepted image identity/repository digest, restart policy, restart count, and exact UDP publication;
- read `awg0.conf` and `clientsTable` with `docker exec ... cat` under strict byte caps;
- read live peers with `docker exec ... awg show awg0 peers`;
- enumerate only bounded, name-validated `/tmp/*.tmp` candidate artifacts inside the container;
- parse exact `[Interface]`/`[Peer]` configuration and exact `clientsTable` JSON-list row shapes;
- hash decoded 32-byte public keys, never raw key text;
- require persistent/live/metadata set convergence for a baseline;
- apply the exact semantic normalization contract below before runtime identity hashing;
- emit only the canonical sanitized baseline plus operation-specific classes/counts.

`clientsTable` supplies metadata and a mutable display name, but the persistent config plus live `awg show` state remain authoritative. AmneziaVPN 5.0.1.5 stores no stable Admin/Guest role field in `clientsTable`; `clientName` can be renamed and is not an authorization property. A synthetic tracked `role` field, an `Admin [` prefix test, or a Guest-name prefix test is therefore prohibited.

The remote guard proves only one exact peer delta and its convergence. AmneziaVPN 5.0.1.5 exposes no supported read-only interface for the encrypted local `SelfHostedAdmin clientId`, and its full-access export deliberately omits that client config. P3 therefore does not claim a cryptographic server-side Admin role proof.

Management discovery is classified by a protected operation-context receipt that binds the pinned AmneziaVPN binary/version/source mapping, the exact separately approved **Self-hosted full access** UI sequence, the selected management-entry identity hash, the guard nonce, and the pre/post peer-set hashes. Its evidence labels are `owner_observed=true`, `server_role_confirmed=false`, and `classification=source_pinned_management_operation`. A generic connection/Guest export sequence cannot satisfy this receipt.

Guest acceptance is stronger: the protected native profile inspector decodes the exact 32-byte interface private key only in memory, derives the raw 32-byte X25519 public key, hashes those public bytes with SHA-256, immediately discards key buffers, and emits only the fingerprint hash. This value must equal the exact converged server candidate. The protected profile is already secret-bearing; deriving a non-secret public fingerprint does not add secret output or persistence.

The versioned receipts are:

- `home-gateway/p3-management-operation-context-receipt/v1` with exact client binary/version/source hashes, UI action-class hash, selected-entry hash, candidate nonce hash, pre/post peer-set hashes, candidate fingerprint hash, runtime identity hash, UTC observation, evidence labels, and `raw_identity_exposed=false`;
- `home-gateway/p3-guest-profile-identity-receipt/v1` with exact protected profile SHA-256/file identity/ACL identity, candidate nonce hash, pre/post peer-set hashes, derived public fingerprint hash, runtime identity hash, UTC observation, and `raw_key_exposed=false`.

Both receipts live under marker-owned non-reparse protected roots, bind the current manifest and candidate receipt SHA-256, expire after the gate window, and are single-use. A changed path/file identity, renamed/substituted profile, replayed nonce, different runtime, missing receipt, or non-matching Guest public fingerprint stops acceptance. Until the applicable receipt passes, the state is `CANDIDATE_PENDING_EXTERNAL_PROOF`.

## Decision 3: emergency rollback boundary

Emergency rollback remains unavailable without a new exact approval. Its production adapter must:

- revalidate the container identity, image, ports, baseline, candidate receipt, exact candidate key fingerprint, and stable runtime immediately before mutation;
- identify exactly one candidate in `awg0.conf`, live `awg0`, `clientsTable`, and any candidate-owned `/tmp` artifact;
- create root-only `O_EXCL` recovery files outside the container writable layer under one gate-owned host runtime directory;
- back up exact `awg0.conf`, `clientsTable`, and any exact candidate temporary artifact before writing;
- stream fixed-path atomic writes into the container without interpolating candidate data into shell code;
- run exactly one official container-side `awg syncconf` after removal;
- verify return to the complete pre-operation baseline;
- on failure, restore both authoritative files, run one recovery `syncconf`, and prove the pre-removal state;
- retain recovery material and report `ROLLBACK_UNPROVEN` if recovery cannot be proved;
- include both exact nonce-derived container staging paths in `inspect`, `recover`, `verify-recovery`, and terminal `cleanup`;
- require both staging paths absent before rollback, remove only those exact paths after success/recovery, and reobserve their absence;
- delete only gate-owned recovery files after a proved terminal state.

The helper must not depend on Python inside the container and must not use host `os.replace` for container files.

The rollback adapter resolves one exact running container ID before any file read and uses that immutable ID for every later Docker command. Its preflight requires exact regular files `awg0.conf` and `clientsTable`, `/bin/bash`, `/usr/bin/awg`, `/usr/bin/awg-quick`, `cat`, `mv`, `stat`, and `sync`; absence or a different resolved executable path stops before backup or write.

The only writable container staging names are `/opt/amnezia/awg/.p3-next-<32 lowercase hex>.conf` and `.clients`, derived from the candidate nonce. The fixed `/bin/bash -c` writer receives the target/staging paths as positional parameters, creates the staging file with no-clobber semantics and mode/owner copied from the target, reads at most the declared byte count from standard input, `fsync`s where supported, and performs same-directory `mv`. Candidate/config bytes never enter shell source or argv. A two-file update is not claimed atomic: a failure between writes immediately enters the proved recovery path using the external backups.

A trap attempts to remove only the active exact staging path on every writer exit, but trap execution is not treated as proof. Recovery and terminal verification independently enumerate the two nonce-derived paths, remove them if and only if their nonce/candidate binding matches, and require both absent. Any foreign `.p3-next-*` file, staging collision, or unproved staging cleanup retains external recovery material and returns `ROLLBACK_UNPROVEN`.

The only sync command is a fixed container command equivalent to:

```text
/bin/bash -c 'exec /usr/bin/awg syncconf awg0 <(/usr/bin/awg-quick strip /opt/amnezia/awg/awg0.conf)'
```

No caller-controlled value is interpolated. Preflight proves the required Bash process-substitution and both executables before mutation. Every Docker stdout/stderr stream has a mode-specific byte cap and timeout; unexpected stderr or truncation stops.

## Semantic observation normalization

The collector hashes command output only after strict parsing:

- Docker inspect is decoded from exact JSON fields, not delimiter-concatenated templates. Repo digests are validated strings, sorted ordinally, and deduplicated. Container identity is the SHA-256 of the exact container ID; image identity is the SHA-256 of canonical JSON containing image ID plus sorted repo digests.
- Docker port output must normalize to exactly two bindings for `udp/38556`: `all_ipv4` and `all_ipv6`. Lines are parsed, converted to these classes, sorted ordinally, and hashed as compact canonical JSON. Any specific address, other port/protocol, duplicate, or unparsed line stops.
- IPv4 `iptables-save` runs without `-c`. Normalize CRLF to LF, remove only exact generated/completed timestamp comment lines, and replace decimal packet/byte counters in exact chain declarations with `[0:0]`. Preserve chain names, policies, rule content, remaining line order and whitespace; require one terminal LF and reject counter-prefixed rules or unparsed timestamp variants.
- IPv6 retains its separately qualified normalization/classification: normalize chain counters, remove comment lines and supported decimal rule-counter prefixes, and require the existing parser/classification checks. The phase 3.5 IPv4 correction does not change this behavior.
- `nft list ruleset` normalizes CRLF to LF and replaces only the decimal values in exact `counter packets <n> bytes <n>` clauses with fixed zero tokens. It preserves line order, all other text, and one terminal LF; an unsupported volatile token stops.
- `ss -H -lntu` is parsed into protocol, state, receive queue, send queue, local endpoint, and peer endpoint. Queue values must be decimal and are normalized to zero. The remaining exact tuples are sorted ordinally; duplicates or additional columns stop.
- `host_policy_sha256` hashes normalized IPv4 `iptables-save`; `ipv6_policy_sha256` hashes normalized IPv6 output; `firewall_identity_sha256` hashes canonical JSON of those two hashes plus the normalized nft hash; `listener_identity_sha256` hashes canonical listener tuples.
- `runtime_identity_sha256` hashes canonical JSON of the container/image/restart, UDP publication, listener, firewall, and loaded-policy identities already present in the snapshot. It never hashes a second independently collected sample.

Golden raw fixtures for every command define accepted line grammar and prove that only the listed volatile values normalize away.

Amendment 2026-09-05, phase 3.5: chain-declaration counter normalization also applies to IPv4, whose previous implementation retained those counters. This changes payload and dependent policy identities. Keep the 27-field schema and public protocol only while their shapes remain unchanged; bind the new exact payload in new trust/manifest/agent/receipt artifacts. Preserve historical receipts unchanged and accept new baseline hashes only from a reviewed fresh observation. A historical aggregate hash cannot prove unchanged rules or reconstruct a new baseline.

## Decision 4: independent prerequisite observation

Add a tracked prerequisite driver separate from the protected runtime. It has four offline-testable actions:

| Action | Purpose | Live effect when separately approved |
|---|---|---|
| `Plan` | Build one sanitized exact candidate from ignored local seed paths and tracked code hashes | None |
| `AgentPlan` | Bind the prerequisite-only Git OpenSSH toolchain and one public-key fingerprint | None |
| `AgentStart` | Start one prerequisite-scoped memory-only agent and load one key after exact approval | Local ephemeral process/key state only |
| `AgentValidate` | Prove exact PID/socket/toolchain and exactly one expected key | None |
| `Observe` | Run the approved pinned read-only batch | SSH plus three controller-side HTTPS GETs only; no remote write |
| `AgentStop` | Delete the one key, stop the owned PID, remove its receipt, and reobserve absence | Local ephemeral cleanup only |
| `Assemble` | Validate bounded server/Cloud/egress inputs and create an immutable protected prerequisite receipt | Local protected-file write only |
| `Validate` | Reopen and revalidate the receipt and every bound file identity | None |

`Observe` streams an exact, size-bounded, hash-attested read-only observer to host Python through standard input. The remote loader validates the payload length and SHA-256 in memory before execution. It writes no remote file and exposes no raw server state. This transient observer is distinct from the regular-file attestation contract of the later installed helper.

The observation batch must use:

- one pinned Git OpenSSH toolchain and one memory-only agent key;
- one exact known-hosts file and ED25519 host-key fingerprint;
- one exact `homegateway` target and current management source `/32` hash;
- exactly three distinct pinned HTTPS authorities executed by the Windows controller, GET only, ten-second timeout, zero redirects;
- one owner-supplied bounded Cloud Firewall observation entered through standard input or a protected ignored file; no API token and no UI automation requirement.

The remote observer performs only host/Docker collection. It never makes an HTTPS request and its public server address is never compared with the management `/32`. All three controller-side HTTPS observations must agree on the Windows controller source `/32`, which must equal the Cloud Firewall TCP/22 source.

The prerequisite root owns a prerequisite manifest and agent receipt before the final runtime exists. The exact prerequisite approval binds `AgentStart`, `AgentValidate`, `Observe`, and mandatory `AgentStop`; `AgentStop` runs in `finally` on success, failure, or interruption. A stop failure is an emergency blocker and cannot be reported as a completed observation. The final runtime agent receipt is a later, different lifecycle and cannot be reused.

The batch stops on any SSH stderr outside the reviewed passphrase/host transport shape, non-zero child exit, malformed/oversized output, differing controller egress addresses, stale timestamp, server mismatch, agent mismatch, or unproved agent teardown.

## Decision 5: Cloud Firewall provenance

The Cloud Firewall observation schema v2 binds:

- `firewall_resource_sha256` from the exact DigitalOcean Firewall resource identifier;
- `droplet_resource_sha256` from the exact Droplet resource identifier;
- exactly one association between those resources;
- exactly one TCP 22 rule from the observed management `/32`;
- exactly one UDP 38556 rule from All IPv4;
- zero IPv6 UDP rules and zero extra inbound rules;
- the exact outbound union: ICMP, all TCP, and all UDP to All IPv4 and All IPv6, with zero extras;
- an ordinal canonical inbound-union SHA-256 and outbound-union SHA-256;
- observation timestamp, `owner_observed=true`, `server_confirmed=false`, and `live_mutation_performed=false`.

Raw resource identifiers and public addresses may exist only in protected ignored input. Receipts and tracked artifacts contain hashes.

## Decision 6: break the bootstrap cycle

`RecordCloudFirewall` and `RecordEgress` no longer require a final prepared runtime. The prerequisite driver records them under its own marker-owned protected root. `PreparePlan` accepts exactly one validated prerequisite receipt whose payload, SSH trust, management source, authority set, Cloud Firewall resources/rules, server baseline, and freshness are all bound.

The final runtime manifest contains the accepted prerequisite receipt SHA-256 and the 27-field server baseline SHA-256. It cannot accept a baseline assembled from its own later reconciliation output. A separate owner approval is required between prerequisite observation and runtime preparation.

## Behavioral proof

Tests must cover:

- a real collector-shaped 27-field snapshot passing through PowerShell `PreparePlan` and Python reconcile with the same baseline SHA-256;
- every one-field missing, extra, type-confused, malformed hash, and count/boolean mismatch;
- confirmed container paths/names and rejection of host-path reads;
- exact `clientsTable` list parsing and persistent/live/metadata convergence;
- Docker command argument arrays, byte caps, timeouts, stderr rejection, and no shell interpolation;
- default bridge plus custom bridge topology without treating network count as peer storage;
- read-only transient payload framing, truncation, extension, hash mismatch, replay, and remote-write prohibition;
- exact Firewall/Droplet resource binding, inbound union, outbound union, association, and freshness;
- management `/32` equality across Cloud Firewall and all three controller-side egress observations, plus a negative fixture proving Droplet egress is a distinct untrusted value;
- prerequisite-scoped agent start/validate/stop, one-key enforcement, `finally` teardown, and stop-failure blocking;
- prerequisite receipt provenance, immutable file identity, freshness, replay rejection, and final-manifest consumption;
- management operation-context receipt provenance with an explicit non-cryptographic evidence label;
- Guest X25519 public derivation from protected profile bytes, exact raw-public-byte SHA-256 matching, zero raw-key output, replay/path/ACL substitution rejection;
- container-scoped inspect/remove/recover/cleanup with injected Docker adapters;
- recovery after failures before write, between config/metadata writes, during `syncconf`, and during verify;
- recovery after interruption immediately after either staging-file creation, exact staging cleanup, collision rejection, and retained backups when staging absence is unproved;
- no live/native calls in offline Pester/Python tests.

## Migration

Existing ignored field evidence is preserved and never promoted to accepted current evidence. Existing protected runtime directories, if any, are not reused across schema versions. The corrected flow creates a new prerequisite schema and a new runtime manifest candidate after successful offline validation and review.

The installed helper path remains `/usr/local/libexec/home-gateway-p3-peer-guard`; no second observer is introduced. A pre-existing helper with an old hash is classified as `conflict` until a separately approved replacement plan exists.

## Live approval boundaries

After offline GO, the controller may only generate, not execute, the exact read-only prerequisite candidate. Execution requires a separate exact approval binding its plan SHA-256, challenge, payload hashes, toolchain hashes, expected resource hashes/classes, SSH/HTTPS-only scope, and stop conditions.

All later gates remain separate: runtime preparation, helper install/replacement, Admin creation, Guest creation/export, client activation, Windows Apply/Confirm, adapter loss, reboot, and FullRestore.

## Acceptance

This correction is complete only when:

- implementation is committed on a clean tracked tree;
- focused Python and Pester behavioral tests pass under PowerShell 5.1 and PowerShell 7;
- the complete repository validation batch passes;
- one independent consolidated QA/security review returns GO on committed HEAD;
- a fresh sanitized exact prerequisite candidate is generated but not executed;
- the candidate contains no raw public address, resource identifier, key, profile, passphrase, or secret.
