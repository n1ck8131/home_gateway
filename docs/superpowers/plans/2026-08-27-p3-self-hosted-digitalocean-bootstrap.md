# P3 Self-Hosted DigitalOcean Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` (recommended in this session) or `superpowers:executing-plans` to implement this plan task by task. Stop at every external/live gate; this document does not authorize cloud creation, SSH, server mutation or Windows network mutation.

**Goal:** Qualify the current Windows PC against one owner-controlled DigitalOcean AmneziaWG server and close `pc-core-ready` without changing Cisco, leaking VPN-class traffic, exposing secrets or treating RedShield as a required backend.

**Architecture:** Preserve the existing provider-neutral `TunnelBackend`, commit-confirm transaction, persistent sinks and exact restoration model. Extract the strict local profile parser from the RedShield package, add current AWG 3.1 fields, generalize Windows tunnel identity, and use the officially supported AmneziaVPN GUI for the first server. The first Droplet is manual and static; P8 retains digest-pinned automation, `server-agent`, mobile lifecycle and telemetry.

**Tech Stack:** Go 1.26.6; Windows PowerShell 5.1 and PowerShell 7.6.4; Pester 6.0.0; Windows 11; DigitalOcean Basic Droplet; Ubuntu 24.04 LTS x64; AmneziaVPN 5.0.1.5; AmneziaWG 3.1; Docker as installed by the official Amnezia flow.

**Spec:** [P3 self-hosted DigitalOcean transition design](../specs/2026-08-27-p3-self-hosted-digitalocean-transition-design.md) and [ADR-0016](../../adr/ADR-0016-p3-self-hosted-digitalocean-bootstrap.md).

## Global constraints

- Do not read, stage, delete or modify `.p35-run/`.
- Do not create or destroy a Droplet, start billing, use a DigitalOcean API token, connect with SSH, install server software, publish a UDP port, import/activate a profile, mutate Windows networking, reboot, simulate adapter loss, or change RedShield/Cisco unless the matching task explicitly reaches a fresh approval gate.
- Never request, print, persist in Git or place in process arguments any private SSH/VPN key, password, recovery code, API token or raw `.conf` content.
- RedShield code/evidence remains historical compatibility material. No implementation task may disconnect or remove the live product.
- An interface being Up is not handshake or egress proof.
- DNS/Cisco overlap, endpoint ambiguity, unknown adapters, IPv4/IPv6 uncertainty, missing persistent sinks or changed SSH host identity fail closed.
- The official Amnezia installer uses a rolling server image. P3 pins the Windows installer hash and records the observed image ID/digest; it must not claim reproducible headless provisioning.
- Run focused tests while implementing, then one full `scripts/dev.ps1 -Command verify` batch after all offline tasks.

---

## Task 1: Lock the supported AmneziaVPN/AWG 3.1 boundary

**Files:**

- Modify: `manifest/versions.lock.yaml`
- Modify: `manifest/checksums.lock`
- Modify: `docs/COMPATIBILITY.md`
- Create: `docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md`
- Modify: `scripts/check-governance.ps1`
- Modify: `tests/bootstrap/GovernanceChecker.Smoke.ps1`

**Step 1: Write the failing governance contract**

Add assertions that the lock contains:

- AmneziaVPN tag `5.0.1.5`, commit `7d4f3e0f5090b74903609179653d1f669d2ad08a`, Windows x64 asset URL, size `91991200` and SHA-256 `2e898bbd1d639f5066416961a2a458dba7c3455c0e8f49c7f130e9281d700377`;
- `amneziawg-go` tag `v3.1.20260814` and commit `1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1`;
- `amneziawg-tools` tag `v3.1.20260812` and commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`;
- `amneziawg-linux-kernel-module` tag `v3.1.20260812` and commit `46803204e7ec3b068199cd671143bec661d3fe21`;
- an explicit `server_image_pin_state: observed-after-install` value rather than an invented digest.

Run:

```powershell
& .\tests\bootstrap\GovernanceChecker.Smoke.ps1
```

Expected: FAIL because the current lock contains only the earlier OpenWrt AWG2 baseline.

**Step 2: Update the lock and compatibility matrix**

Keep the OpenWrt AWG2 pins unchanged for P12. Add a distinct `amnezia_self_hosted_p3` object for the current client/AWG 3.1 lineage. Record that the tagged client Dockerfile uses `amneziavpn/amneziawg-go:latest`, so the exact server digest is an observed field value, not a design-time value.

The runbook must use only the supported GUI lifecycle: `Self-hosted VPN` installation, AmneziaWG-only selection, `Guest access`, native export, remove-from-app versus destructive clear-server distinction. It must explicitly forbid calling internal Amnezia shell scripts as a stable API.

**Step 3: Validate**

Run:

```powershell
& .\scripts\check-governance.ps1
& .\tests\bootstrap\GovernanceChecker.Smoke.ps1
```

Expected: PASS with no download, installation or cloud action.

**Step 4: Commit**

```powershell
git add -- manifest/versions.lock.yaml manifest/checksums.lock docs/COMPATIBILITY.md docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md scripts/check-governance.ps1 tests/bootstrap/GovernanceChecker.Smoke.ps1
git commit -m "docs(p3): lock supported self-hosted Amnezia boundary"
```

## Task 2: Extract the strict profile importer and add AWG 3.1

**Files:**

- Create: `internal/providers/configfile/import.go`
- Create: `internal/providers/configfile/import_test.go`
- Create: `internal/providers/configfile/path_reparse_windows.go`
- Create: `internal/providers/configfile/path_reparse_other.go`
- Create: `internal/providers/configfile/path_volume_windows.go`
- Create: `internal/providers/configfile/path_volume_other.go`
- Create: `internal/providers/configfile/path_volume_windows_test.go`
- Create: `internal/providers/configfile/test_link_windows_test.go`
- Create: `internal/providers/configfile/test_link_other_test.go`
- Create: `internal/providers/selfhosted/backend.go`
- Create: `internal/providers/selfhosted/backend_test.go`
- Modify: `internal/providers/redshield/import.go`
- Modify: `internal/providers/redshield/import_test.go`
- Modify: `internal/providers/redshield/backend.go`
- Modify: `internal/providers/redshield/backend_test.go`
- Modify: `internal/tunnel/backend.go`
- Modify: `internal/tunnel/backend_test.go`

**Step 1: Write failing parser tests**

Create synthetic one-interface/one-peer fixtures only. Test the complete current AWG 3.1 allowlist:

- interface integers: `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `S3`, `S4` as unsigned 16-bit values;
- interface ranges: `H1`-`H4` as canonical unsigned 32-bit single/range values, and `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts` as canonical unsigned 16-bit single/range values;
- interface bounded opaque values: `I1`-`I5` with the tagged-junk syntax preserved only inside the package;
- interface key/bool values: `HeaderProtectionKey`, `RandomTrailers`, `DisableCookies`;
- peer `PersistentKeepalive` as a canonical unsigned 16-bit single/range value, including the official `25-35` default;
- existing keys, endpoint, addresses, full-tunnel flags and hash pinning.

Accept `I1`-`I5` only as optional bounded sequences of official `<b 0x…>`, `<r n>`, `<rd n>`, `<rc n>` and `<t>` tags. Reject empty present values, malformed tags, oversized tagged-junk strings, malformed/reversed ranges, values above `65535` for the timing/padding/keepalive ranges, invalid booleans, invalid keys, duplicate fields, multiple peers and all executable/network-owning directives including `Table`, `PreUp`, `PostUp`, `PreDown` and `PostDown`.

Assert every `String`, `GoString`, format verb and JSON path emits fixed redaction and never the source path, keys, AWG opaque values or raw profile.

Run:

```powershell
& .\.tools\go\bin\go.exe test ./internal/providers/configfile ./internal/providers/selfhosted ./internal/providers/redshield ./internal/tunnel
```

Expected: FAIL because the provider-neutral packages and AWG 3.1 support do not exist.

**Step 2: Implement the smallest shared parser**

Move bounded regular-file, path/reparse/volume, stable-identity and field parsing into `configfile`. Keep all key and opaque AWG material unexported. Expose only a constructor that receives the non-secret provider ID and returns redacted `tunnel.Metadata` plus private package state.

Make `selfhosted.Backend` return provider `selfhosted`; keep `redshield.Backend` as a compatibility wrapper returning provider `redshield`. Neither backend gains mutation or server-management capability.

**Step 3: Run focused tests and secret scans**

```powershell
& .\.tools\go\bin\go.exe test ./internal/providers/... ./internal/tunnel/...
& .\.tools\bin\gitleaks.exe git --no-banner --redact .
```

Expected: PASS; no fixture contains real endpoint or key material.

**Step 4: Commit**

```powershell
git add -- internal/providers/configfile internal/providers/selfhosted internal/providers/redshield internal/tunnel
git commit -m "feat(p3): support protected self-hosted AWG3 profiles"
```

## Task 3: Generalize the Windows canary from RedShield to one qualified tunnel

**Files:**

- Modify: `internal/system/windows/model.go`
- Modify: `internal/system/windows/collector.go`
- Modify: `internal/system/windows/collector_test.go`
- Modify: `internal/system/windows/planner.go`
- Modify: `internal/system/windows/planner_test.go`
- Modify: `internal/system/windows/canary.go`
- Modify: `internal/system/windows/canary_test.go`
- Modify: `internal/system/windows/runtime.go`
- Modify: `internal/system/windows/runtime_test.go`
- Modify: `internal/system/windows/canary_config_windows.go`
- Modify: `internal/system/windows/canary_config_windows_test.go`
- Modify: `internal/hgctlcmd/run.go`
- Modify: `internal/hgctlcmd/run_test.go`
- Modify: `internal/hgctlcmd/canary.go`
- Modify: `internal/hgctlcmd/live_canary.go`
- Modify: `internal/hgctlcmd/live_canary_test.go`
- Modify: `scripts/p35-bootstrap.ps1`
- Modify: `scripts/p35-bootstrap-elevated.ps1`
- Modify: `tests/windows-pester/P35Bootstrap.Tests.ps1`

**Step 1: Write failing provider-neutral tests**

Require:

- `AdapterTunnel` instead of an active `AdapterRedShield` semantic identity;
- exactly one Up WireGuard/Amnezia adapter whose stable GUID and addresses match the imported profile;
- provider-neutral `tunnel_*` finding/error codes and messages;
- direct host-route qualification for the imported endpoint;
- exact fail-closed coverage on every stable non-tunnel/non-loopback adapter;
- protected installed paths `secrets\tunnel.conf` and `secrets\tunnel.sha256`;
- `hgctl tunnel inspect --config <path> --json` as the active command;
- legacy `hgctl redshield inspect` retained read-only for historical compatibility, never selected by the Windows canary default dependencies.

Run:

```powershell
& .\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd
```

Expected: FAIL on current RedShield-specific names and paths.

**Step 2: Implement the semantic rename without weakening gates**

Use `selfhosted.Backend{}` in production CLI dependencies. Rename functions such as `canaryRedShieldAdapter` and `requireRedShieldEffectiveRoutes` to provider-neutral equivalents. Do not change ownership markers, route metrics, sink ordering, commit-confirm timeouts, Cisco protection, recovery tokens or terminal `FullRestore` semantics.

The bootstrap scripts may copy only the exact SHA-pinned source profile into the generic protected path, restore its ACL on failure and emit redacted count/hash evidence. They must not delete or alter any RedShield installation or source file.

**Step 3: Validate focused Go and Pester contracts**

```powershell
& .\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd
& .\scripts\dev.ps1 -Command pester
```

Expected: PASS on Windows PowerShell 5.1-compatible scripts; no live mutation is invoked by tests.

**Step 4: Commit**

```powershell
git add -- internal/system/windows internal/hgctlcmd scripts/p35-bootstrap.ps1 scripts/p35-bootstrap-elevated.ps1 tests/windows-pester/P35Bootstrap.Tests.ps1
git commit -m "refactor(p3): qualify a provider-neutral Windows tunnel"
```

## Task 4: Add a non-mutating DigitalOcean create and SSH readiness guard

**Files:**

- Create: `deploy/digitalocean/p3-droplet.v1.json`
- Create: `scripts/p3-digitalocean-plan.ps1`
- Create: `tests/windows-pester/P3DigitalOceanPlan.Tests.ps1`
- Create: `docs/runbooks/P3_DIGITALOCEAN_CREATE.md`
- Modify: `.gitignore`

**Step 1: Write failing Pester tests**

The tracked desired manifest contains only:

- provider `digitalocean`;
- primary region `ams3`, fallback `fra1`;
- image `ubuntu-24-04-x64`;
- Basic Regular 1 vCPU / 1 GiB / 25 GiB / 1,000 GiB baseline and expected $6 monthly label;
- IPv6 and monitoring enabled;
- backups, volumes, Marketplace/1-click images and API automation disabled;
- inbound SSH with source prefixes initially `pending-observation` but forbidden from default routes, plus exactly one observed AmneziaWG UDP port with the UDP rule initially `pending-observation`.

Tests require the script to accept only an absolute local `.pub` path, verify `ssh-ed25519` syntax with the absolute System32 OpenSSH tools, reject private-key markers, redact the path, reject token/password fields and produce a stable JSON checklist. Mock every native process and assert no network process, browser, `doctl`, REST call or DigitalOcean mutation is reachable.

Run:

```powershell
& .\scripts\dev.ps1 -Command pester
```

Expected: FAIL because the manifest/script/tests do not exist.

**Step 2: Implement plan-only behavior**

`p3-digitalocean-plan.ps1` must be read-only and support `-WhatIf`. It computes manifest/public-key hashes and emits the exact UI selections plus explicit `billable_action_performed=false`. It never generates a key, opens a browser or calls a provider API.

Add `.p3-vps-run/` to `.gitignore` for future redacted local evidence; do not reuse or touch `.p35-run/`.

**Step 3: Validate**

```powershell
& .\scripts\dev.ps1 -Command pester
& .\.tools\bin\gitleaks.exe git --no-banner --redact .
```

Expected: PASS and no secret-like manifest fields.

**Step 4: Commit**

```powershell
git add -- deploy/digitalocean/p3-droplet.v1.json scripts/p3-digitalocean-plan.ps1 tests/windows-pester/P3DigitalOceanPlan.Tests.ps1 docs/runbooks/P3_DIGITALOCEAN_CREATE.md .gitignore
git commit -m "feat(p3): add guarded DigitalOcean create plan"
```

## Task 5: Close the offline implementation gate

**Files:**

- Modify: `STATUS.md`
- Modify: `docs/ACCEPTANCE_MATRIX.md`
- Create: `docs/reports/2026-08-27-p3-selfhosted-offline.md`

**Step 1: Run the single offline validation batch**

```powershell
& .\scripts\dev.ps1 -Command verify
git diff --check
```

Expected: all Go/Pester tests, formatting, vet, staticcheck, gosec, govulncheck, secret/workflow scans, governance smokes and reproducible builds pass. `RUFF_NOT_APPLICABLE_NO_PYTHON`.

**Step 2: Independent review**

Review the complete diff for importer correctness, AWG 3.1 bounds, secret leakage, provider-neutral semantics, Cisco/fail-closed preservation, absence of cloud/live calls and exact rollback boundaries. Fix all Critical/Important findings once and rerun only affected focused tests plus `verify` once after changes.

**Step 3: Record honest status**

Mark only `self-hosted-offline-ready`. Keep Droplet, SSH, server, profile, handshake, exact Windows Plan, live canary and `pc-core-ready` as not run.

**Step 4: Commit**

```powershell
git add -- STATUS.md docs/ACCEPTANCE_MATRIX.md docs/reports/2026-08-27-p3-selfhosted-offline.md
git commit -m "docs(p3): record self-hosted offline gate"
```

## Task 6: Execute the external server gates with the owner

This task is deliberately operator-driven and must stop after each numbered gate. Repository tests do not authorize it.

**Gate 6.1: Dedicated SSH key**

Ask for approval to generate `C:\Users\HappyUser\.ssh\home_gateway_digitalocean_ed25519` interactively with a passphrase. The user uploads only `home_gateway_digitalocean_ed25519.pub`; no key content is pasted into chat. Run the plan-only script and review its redacted JSON.

**Gate 6.2: Billable Droplet creation**

Immediately before creation, obtain explicit approval for $6/month plus possible transfer overage. The user creates one Droplet in the UI with `ams3`, Ubuntu 24.04 x64, Basic Regular $6, IPv6 and monitoring on, backups/volume/Marketplace off, and the dedicated public key. First Cloud Firewall state is SSH-only and accepts only the freshly observed owner management IPv4 `/32` plus IPv6 `/128` when available; never use default prefixes for SSH.

Record only public Droplet ID/name, region, size, image, public IPv4/IPv6 and creation time in `.p3-vps-run/`. Do not record account, billing or credential data.

**Gate 6.3: First SSH and official Amnezia installation**

Obtain separate approval. Verify the SSH host-key fingerprint through the DigitalOcean console before accepting it locally. In AmneziaVPN 5.0.1.5, use `Self-hosted VPN`, user `root`, the Droplet IPv4 and the local dedicated key; choose AmneziaWG only. Do not pass a password or key through chat. After successful installation and recovery verification, create the exact `homegateway` passwordless-sudo operator, prove a second SSH session, then disable root and password SSH login; a failed second session leaves the original recovery path unchanged.

After installation, use a separately approved read-only SSH observation to record container name, immutable image ID/digest, selected UDP port, restart policy and service state. If the image identity is unavailable, multiple unexpected public ports exist, or the container is not the expected official AmneziaWG service, stop before profile activation.

**Gate 6.4: Firewall publication**

Obtain approval to add exactly the observed UDP port to the DigitalOcean Cloud Firewall and matching host policy. Audit Docker/host firewall union; SSH and that UDP port are the only public inbound services.

**Gate 6.5: Guest profile creation and protected bootstrap**

Obtain a separate approval for the server-mutating `Guest access` operation and exact protected destination. Create exactly one guest, export `AmneziaWG native format` directly to a protected local file, and bootstrap it into `C:\ProgramData\HomeGateway\p35\secrets\tunnel.conf`. Do not paste or attach it. Run `hgctl tunnel inspect` and capture only schema, provider, transport, family flags, counts and hashes.

**Gate 6.6: Windows client import and activation**

Present the exact profile hash, supported Windows client, intended single self-hosted adapter and profile-only rollback command. Obtain a fresh explicit approval before importing or connecting the profile. Import the protected profile into the supported client and activate only that self-hosted tunnel; do not disconnect, reconfigure or remove RedShield or Cisco. Prove the expected adapter identity, handshake and public egress separately. On any anomaly, deactivate and remove only the new self-hosted client profile using the approved rollback path, then verify RedShield and Cisco remain in their pre-gate state.

**Rollback:** Windows anomalies use the Windows rollback/recovery path. Server cleanup is not automatic: official **Clear server from Amnezia software** is broad/destructive and requires a fresh explicit destructive approval. Destroying the Droplet also requires a separate approval; powering it off does not stop billing.

## Task 7: Run the bounded self-hosted Windows gate and terminal restore

**Gate 7.1: Exact read-only Plan**

With RedShield and Cisco left untouched, run a fresh elevated sink preflight, protected config bootstrap, inventory and exact non-elevated `windows canary plan`. Require:

- one qualified self-hosted adapter binding;
- provider endpoint direct through one physical adapter;
- no Cisco/endpoint/DNS/target overlap;
- both IP-family semantics resolved;
- PktMon stopped with zero filters;
- zero owned/journal state before Apply;
- exact persistent sinks ready;
- observed self-hosted handshake and public egress recorded separately.

Any block ends the sub-batch without Apply.

**Gate 7.2: Apply/Confirm**

Present the exact immutable candidate hash, confirmation challenge, target classes, timeouts and rollback command. Obtain a new explicit approval for Apply/Confirm. Execute only the bounded candidate; on any anomaly run Rollback immediately.

Verify direct, self-hosted and Cisco paths; DNS; IPv4/IPv6 leak behavior; MTU; TCP/UDP/QUIC; tunnel-down fail-closed behavior; process restart and recovery. Reboot and adapter-loss tests remain separate approvals even inside this phase.

**Gate 7.3: Terminal `FullRestore`**

Before execution, present the exact restore candidate/hash and the exhaustive set of project-owned routes, sinks, firewall/NRPT rules, tasks, journal/ownership state and config ACL changes that will be removed or reverted. Obtain a fresh explicit approval for that exact `FullRestore`; approval for Apply/Confirm does not authorize it. Do not remove the source profile, the Amnezia client/profile or any RedShield/Cisco state without another separate authorization.

Run the approved journaled `FullRestore`, then prove no lock, journal, ownership registry, active revision, project route/sink/firewall/NRPT/task or changed config ACL remains. RedShield and Cisco must remain in their pre-gate state.

Create the final redacted field report, update `STATUS.md` and `docs/ACCEPTANCE_MATRIX.md`, rerun `git diff --check`, and commit only repository docs/evidence. Close `pc-core-ready` only if every required field assertion and terminal restore passes.

## User action summary

The owner should not create the Droplet yet. The next owner action occurs only after Tasks 1-5 pass review:

1. approve generation of the dedicated local SSH key;
2. upload only its `.pub` half to DigitalOcean;
3. confirm the $6 baseline and possible overage immediately before creating the Droplet;
4. create the exact UI configuration and return only public Droplet metadata;
5. approve first SSH/official Amnezia installation;
6. separately approve creation of one server-side guest, keep the exported `.conf` local and provide only its protected path;
7. approve import/activation of the exact hashed profile after reviewing its profile-only rollback;
8. approve the exact Windows Plan, then separately approve Apply/Confirm and the exact terminal `FullRestore` candidate.
