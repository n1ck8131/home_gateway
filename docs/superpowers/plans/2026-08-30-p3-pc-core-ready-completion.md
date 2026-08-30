# P3 `pc-core-ready` Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the current self-hosted Windows P3 pilot honestly at `pc-core-ready`, including one protected static PC profile, observed tunnel health, bounded Windows Apply/Confirm, failure/recovery evidence, and terminal `FullRestore`.

**Architecture:** Close all offline contract gaps before another live action. The live sequence is fail-closed and strictly ordered: reconcile the server baseline, establish the supported Amnezia management path, create exactly one Guest, stage and inspect its profile, activate it with profile-only rollback, run an exact candidate-bound Windows canary, and finish with a separately candidate-bound terminal restore. Real secrets and public infrastructure identifiers remain only in ignored runtime state; tracked code and evidence contain hashes, counts, booleans, and sanitized classifications.

**Tech Stack:** Go 1.26.6, Windows PowerShell 5.1 plus PowerShell 7 compatibility checks, Pester 6.0.0, Python 3.14 with Ruff for the remote guard payload, Windows native route/firewall/NRPT APIs through the existing `MutationBackend`, Git OpenSSH with a memory-only `ssh-agent`, official AmneziaVPN 5.0.1.5 GUI, Docker-hosted AmneziaWG 3.1.

**Spec:** `docs/superpowers/specs/2026-08-27-p3-self-hosted-digitalocean-transition-design.md`

**Reconciliation baseline:** [Gate 6.4/6.5C reconciliation](../../reports/2026-08-30-p3-gate64-65c-reconciliation.md) records Gates 6.1-6.3 passed, Gate 6.4 current state pending read-only reconciliation, Gate 6.5C `rollback-complete`, protected profile absent, and all Windows field gates open.

## Global Constraints

- Do not disconnect, restart, reconfigure, or remove RedShield or Cisco without a separately named approval.
- Do not reboot Windows, disable an adapter, restart Docker, clear the Amnezia server, delete the Droplet, or change billing without its own exact gate.
- Never place an SSH private key, SSH passphrase, VPN private key, raw profile, raw peer key, DigitalOcean token, or password in Git, logs, commands, or evidence.
- Use the existing dedicated SSH key only through the pinned host key and current qualified management source. The temporary `ssh-agent` keeps the decrypted key in RAM and must be destroyed on completion or emergency stop.
- P3 uses the official AmneziaVPN 5.0.1.5 GUI for service discovery, Guest creation, native export, import, connection, and supported peer removal. Direct server edits are emergency rollback only after an exact scoped candidate is proved.
- Keep all real infrastructure pins and live transcripts under ignored `.p3-vps-run/`; tracked evidence is sanitized.
- No Windows network mutation is allowed until the complete offline validation batch and consolidated review return GO.
- The accepted P3 server peer topology is explicit: retain the pre-existing baseline Admin peer unchanged, add exactly one `homegateway` management Admin peer, and add exactly one static PC Guest. Retirement of the baseline Admin peer is deferred to a separately approved lifecycle gate; it is not inferred from P3 completion.
- Any ambiguous state, unexpected peer/container/port, changing SSH host key, non-exact candidate, Cisco/DNS overlap, or unverifiable rollback stops the current live batch.
- A successful field run retains a terminal `restored` journal and an empty ownership registry as durable audit evidence; acceptance means zero active/pending revision and zero project-owned network artifacts, not deletion of the terminal receipt.

---

### Task 1: Reconcile P3 contracts and current field evidence

**Files:**
- Modify: `.gitignore`
- Create: `docs/reports/2026-08-30-p3-gate64-65c-reconciliation.md`
- Modify: `docs/superpowers/plans/2026-08-27-p3-self-hosted-digitalocean-bootstrap.md`
- Modify: `docs/superpowers/specs/2026-08-27-p3-self-hosted-digitalocean-transition-design.md`
- Modify: `docs/superpowers/plans/2026-08-24-p03-redshield-windows.md`
- Modify: `docs/adr/ADR-0016-p3-self-hosted-digitalocean-bootstrap.md`
- Modify: `docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md`
- Modify: `STATUS.md`
- Modify: `docs/ACCEPTANCE_MATRIX.md`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/SECURITY.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: sanitized Gate 6.3 tracked report and ignored Gate 6.4/6.5 runtime evidence.
- Produces: one non-secret current baseline and the accepted terminal-journal contract used by Tasks 5–9.

- [x] **Step 1: Write the reconciliation report from exact sanitized evidence**

  Record Gate 6.4 host-policy and Cloud Firewall facts as `confirmed`, `owner-observed`, or `needs-read-only-recheck`; do not infer missing evidence. Record Gate 6.5C as `rollback-complete`, including exactly one removed Admin peer, exactly one rollback `syncconf`, baseline peer-set hash restored, container restart delta zero, firewall unchanged, and SSH exit zero.

- [x] **Step 2: Correct the terminal restore contract**

  Replace the physical-absence requirement for `journal.json` and the ownership registry with this exact acceptance rule:

  ```text
  terminal journal state = restored
  active revision = empty
  last-known-good revision = empty
  pending/recovery revision = empty
  ownership registry = present but empty
  project-owned routes/sinks/firewall/NRPT/tasks = zero
  install snapshot and terminal receipt = retained for audit
  ```

- [x] **Step 3: Record the accepted peer topology and supported rollback paths**

  Update the ADR, accepted design, bootstrap plan, and GUI runbook so they all name the same P3 terminal topology: retain the pre-existing baseline Admin peer, add exactly one `homegateway` management Admin peer, and add exactly one static PC Guest. The supported Admin rollback is exact one-peer removal through the official Amnezia UI; the reviewed candidate-bound direct rollback is emergency-only. Guest removal is a separate server mutation and is never implied by client-profile rollback.

- [x] **Step 4: Define the local runtime-evidence boundary**

  Add the exact root-only `.p35-run/` runtime directory to `.gitignore`, matching the existing `.p3-vps-run/` policy. Preserve all existing files in both directories; never clean, move, stage, or rewrite them. Tracked reports may contain only reviewed sanitized extracts.

- [x] **Step 5: Synchronize status and security documentation**

  Mark Gates 6.1–6.3 passed, Gate 6.4 pending read-only reconciliation where evidence is not tracked, Gate 6.5C rolled back, protected profile absent, and all Windows field gates open. Remove stale claims that the native backend is unavailable.

- [x] **Step 6: Validate documentation consistency**

  Run:

  ```powershell
  rg -n "UDP publication.*not run|native backend.*unavailable|no journal|ownership registry.*absent" README.md STATUS.md docs
  git diff --check
  ```

  Expected: no stale active claim and no whitespace errors.

- [ ] **Step 7: Commit the contract reconciliation**

  ```powershell
  git add -- .gitignore README.md STATUS.md docs/ACCEPTANCE_MATRIX.md docs/COMPATIBILITY.md docs/SECURITY.md docs/adr/ADR-0016-p3-self-hosted-digitalocean-bootstrap.md docs/reports/2026-08-30-p3-gate64-65c-reconciliation.md docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md docs/superpowers/plans/2026-08-24-p03-redshield-windows.md docs/superpowers/plans/2026-08-27-p3-self-hosted-digitalocean-bootstrap.md docs/superpowers/specs/2026-08-27-p3-self-hosted-digitalocean-transition-design.md docs/superpowers/plans/2026-08-30-p3-pc-core-ready-completion.md
  git commit -m "docs(p3): reconcile field gates and restore contract"
  ```

### Task 2: Make the installed live profile provider-neutral end to end

**Files:**
- Modify: `scripts/p35-canary.ps1`
- Modify: `tests/windows-pester/P35Canary.Tests.ps1`
- Modify: `tests/windows-pester/P35Bootstrap.Tests.ps1`

**Interfaces:**
- Consumes: protected bootstrap files `secrets\tunnel.conf` and `secrets\tunnel.sha256`.
- Produces: `Resolve-InstalledConfig` returning the exact installed provider-neutral path and lowercase SHA-256 for Plan, Apply, and Confirm.

- [ ] **Step 1: Write failing Pester coverage for provider-neutral names**

  Add assertions equivalent to:

  ```powershell
  $text | Should -Match "secrets\\tunnel\.conf"
  $text | Should -Match "secrets\\tunnel\.sha256"
  $text | Should -Not -Match "secrets\\redshield\.conf"
  $text | Should -Not -Match "secrets\\redshield\.sha256"
  ```

  Cover Plan, Apply, Confirm, hash mismatch, regular-file enforcement, reparse rejection, and `-WhatIf` no-mutation behavior.

- [ ] **Step 2: Run the focused test and prove RED**

  ```powershell
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Command pester
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
  ```

  Expected: only the new provider-neutral launcher expectations fail.

- [ ] **Step 3: Replace only the stale installed names and labels**

  `Resolve-InstalledConfig` must resolve `secrets\tunnel.conf`, read `secrets\tunnel.sha256`, verify exact lowercase SHA-256, and use provider-neutral error labels. Preserve every existing ACL, file-identity, state-root, launcher-hash, elevation, and `ShouldProcess` guard.

- [ ] **Step 4: Run focused Pester and Go config validation**

  ```powershell
  & .\scripts\dev.ps1 -Command pester
  & .\.tools\go\bin\go.exe test ./internal/providers/configfile ./internal/providers/selfhosted ./internal/system/windows ./internal/hgctlcmd
  ```

  Expected: PASS.

- [ ] **Step 5: Commit the provider-neutral live path**

  ```powershell
  git add -- scripts/p35-canary.ps1 tests/windows-pester/P35Canary.Tests.ps1 tests/windows-pester/P35Bootstrap.Tests.ps1
  git commit -m "fix(p3): use protected self-hosted profile in live canary"
  ```

### Task 3: Add exact candidate and read-only terminal restore plans

**Files:**
- Modify: `internal/system/windows/canary.go`
- Modify: `internal/system/windows/canary_test.go`
- Modify: `internal/system/windows/runtime.go`
- Modify: `internal/system/windows/runtime_test.go`
- Modify: `internal/hgctlcmd/canary.go`
- Modify: `internal/hgctlcmd/live_canary.go`
- Modify: `internal/hgctlcmd/live_canary_test.go`
- Modify: `internal/hgctlcmd/run.go`
- Modify: `internal/hgctlcmd/run_test.go`
- Modify: `scripts/p35-bootstrap.ps1`
- Modify: `scripts/p35-bootstrap-elevated.ps1`
- Modify: `scripts/p35-canary.ps1`
- Modify: `tests/windows-pester/P35Bootstrap.Tests.ps1`
- Modify: `tests/windows-pester/P35Canary.Tests.ps1`

**Interfaces:**
- Produces: `CanaryPlan.CandidateSHA256() string` over a canonical private candidate envelope and `FullRestorePlan.IdentitySHA256() string` over a canonical redacted exact-identity envelope.
- Produces CLI: `windows canary full-restore-plan --state-root <path> --json`.
- Produces a separate read-only `RestoreConfigAclPlan` with its own identity hash/challenge. The terminal restore workflow is two monotonic candidate-bound operations: network `FullRestore`, then ACL restore; it is not falsely presented as one atomic transaction.
- Changes CLI: Plan, Apply, and Confirm accept the same exact `--candidate-sha256`; `windows canary full-restore` requires `--recovery-plan-sha256 <lowercase-sha256>` and a recovery-plan-derived `--confirm-recovery` challenge.

- [ ] **Step 1: Write failing Go tests for exact candidate hashing**

  Require deterministic lowercase SHA-256 over an explicit ordered private envelope equivalent to:

  ```go
  type canaryCandidateEnvelope struct {
      Schema                      string              `json:"schema"`
      StateRootIdentity           string              `json:"state_root_identity"`
      RevisionID                  string              `json:"revision_id"`
      ConfigSHA256                string              `json:"config_sha256"`
      QualifiedEndpointIdentities []artifactIdentity  `json:"qualified_endpoint_identities"`
      RouteIdentities             []artifactIdentity  `json:"route_identities"`
      SinkIdentities              []artifactIdentity  `json:"sink_identities"`
      FirewallIdentities          []artifactIdentity  `json:"firewall_identities"`
      NRPTIdentities              []artifactIdentity  `json:"nrpt_identities"`
      TargetClassCounts           targetClassCounts   `json:"target_class_counts"`
      WatchdogTimeoutSeconds      int                 `json:"watchdog_timeout_seconds"`
  }
  ```

  Each `artifactIdentity` contains only type/family/role plus a lowercase SHA-256 over the canonical exact object; arrays are sorted deterministically. The public JSON exposes identities and counts, never raw endpoints, routes, DNS addresses, adapter names, or profile material. Tests must prove a stable hash, a changed hash for any endpoint/artifact/timeout change, and no raw target value in output. The confirmation challenge is derived from `candidate_sha256`, and Apply/Confirm reject a missing or stale candidate hash before mutation.

- [ ] **Step 2: Write failing tests for exact network and ACL restore plans**

  Define one canonical redacted envelope whose sorted exact identity sets cover:

  ```text
  state-root identity
  journal state + journal file SHA-256
  ownership-registry SHA-256 + owned-entry identities
  registry version, boot-marker hash, and nonterminal-mutation flag
  install-snapshot SHA-256
  current managed-state and preserved foreign-state SHA-256 values
  FirewallEnforced state
  active/LKG/pending/recovery revision-manifest SHA-256 values
  remove/retain/restore route identities
  remove/retain/restore sink identities
  remove/restore firewall-rule identities
  remove/restore NRPT-rule identities
  watchdog scheduled-task identities and state hashes
  protected-config path identity, current ACL hash, baseline ACL hash, and restore operation
  hgctl binary SHA-256, canary launcher SHA-256, bootstrap driver SHA-256, and elevated bootstrap payload SHA-256
  lock/atomic-leftover identities
  ```

  Assert that plan mode returns the complete redacted envelope, exhaustive class counts, `recovery_plan_sha256`, ACL subplan hash, both derived confirmation challenges, `live_mutation_performed=false`, and zero backend or ACL mutation calls. Include fields that the current equality helpers omit, especially snapshot version and `FirewallEnforced`; preserve the existing intentional treatment of foreign NRPT state without claiming it was inventoried. Two states with the same counts but different object identities must hash differently. Assert that network `full-restore` and `RestoreConfigAcl` independently reject missing or stale subplan hashes before their respective mutations.

- [ ] **Step 3: Run focused Go tests and prove RED**

  ```powershell
  & .\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd
  ```

- [ ] **Step 4: Implement canonical hashes and candidate-bound confirmation**

  Use `encoding/json` plus `crypto/sha256`; return lowercase hex. The restore challenge format is public and non-secret:

  ```text
  P35-FULL-RESTORE-<first-16-uppercase-hex-of-SHA256(lowercase-state-root NUL plan-hash)>
  ```

  Under the existing operation lock, recompute the complete network-recovery envelope and exact hash immediately before `FullRestore`; mismatch exits without mutation. The bootstrap ACL action holds the same exclusive source-file handle used for identity/hash/ACL revalidation and mutation, revalidates the exact bootstrap driver and elevated payload hashes, and requires its independent exact ACL-plan hash/challenge. If network restore succeeds but ACL restore fails, keep the safer network-restored state, emit `NETWORK_RESTORE=COMPLETE` plus `ACL_RESTORE=PENDING`, do not reintroduce project routes/rules, and require a fresh ACL plan plus fresh exact approval before retry. P3 is not terminal until both operations pass.

- [ ] **Step 5: Expose complete redacted plan fields**

  Return all sorted stable object-identity hashes and their exhaustive counts, including remove VPN routes, retain/remove sinks, remove firewall, remove DNS/NRPT, remove endpoints, restore routes/sinks/firewall/NRPT, revisions, tasks, journal/registry/install snapshot, binaries, locks, and ACL operation. Never output raw route values, DNS addresses, adapter names, task command lines, ACL SDDL, infrastructure pins, or profile material.

- [ ] **Step 6: Update PowerShell routing and Pester contracts**

  Add `FullRestorePlan` and `RestoreConfigAclPlan` to the action set. Plan/Apply/Confirm pass the exact `--candidate-sha256`. Network `FullRestore` requires the exact recovery-plan hash/challenge; ACL restore requires the exact ACL-plan hash/challenge bound to both bootstrap code hashes. Both plan actions are read-only and valid under `-WhatIf`. Add injected child-failure tests proving that an ACL failure after successful network restore reports partial-safe state, rejects changed bootstrap code, and retries only ACL after a fresh exact approval, never network mutation or compensation.

- [ ] **Step 7: Run focused tests**

  ```powershell
  & .\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd
  & .\scripts\dev.ps1 -Command pester
  ```

- [ ] **Step 8: Commit exact live/restore planning**

  ```powershell
  git add -- internal/system/windows/canary.go internal/system/windows/canary_test.go internal/system/windows/runtime.go internal/system/windows/runtime_test.go internal/hgctlcmd/canary.go internal/hgctlcmd/live_canary.go internal/hgctlcmd/live_canary_test.go internal/hgctlcmd/run.go internal/hgctlcmd/run_test.go scripts/p35-bootstrap.ps1 scripts/p35-bootstrap-elevated.ps1 scripts/p35-canary.ps1 tests/windows-pester/P35Bootstrap.Tests.ps1 tests/windows-pester/P35Canary.Tests.ps1
  git commit -m "feat(p3): bind live and restore actions to exact plans"
  ```

### Task 4: Build the protected profile staging and client observation harnesses

**Files:**
- Create: `scripts/p3-profile-stage.ps1`
- Create: `scripts/p3-profile-stage-elevated.ps1`
- Create: `tests/windows-pester/P3ProfileStage.Tests.ps1`
- Create: `scripts/p3-client-gate.ps1`
- Create: `tests/windows-pester/P3ClientGate.Tests.ps1`
- Create: `docs/runbooks/P3_WINDOWS_CLIENT_ACTIVATION.md`
- Modify: `docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md`

**Interfaces:**
- Profile-stage actions: `Prepare`, `Verify`, `Cleanup`.
- Client-gate actions: `Preflight`, `PostConnect`, `PostRollback`.
- Produces only sanitized JSON schemas, hashes, counts, freshness booleans, adapter-class hashes, and before/after equality flags.

- [ ] **Step 1: Write Pester tests for `Prepare`**

  Require one marker-owned protected staging directory under `C:\ProgramData\HomeGateway\p35`, exact SYSTEM/Administrators/current-user ACL, no reparse component, absent export target, and no network/native client process. A second identical Prepare is idempotent; foreign content fails closed.

- [ ] **Step 2: Write Pester tests for `Verify` and `Cleanup`**

  `Verify` accepts exactly one newly exported regular non-reparse file, locks it against replacement, calculates SHA-256, runs the pinned `hgctl tunnel inspect`, and atomically installs `secrets\tunnel.conf` plus `secrets\tunnel.sha256`. P3 `Cleanup` removes only marker-owned temporary staging metadata that is neither the original export nor the installed profile. It never deletes the protected source export, `secrets\tunnel.conf`, its pin, or an Amnezia client profile; every such deletion is out of scope and requires a separate action/approval.

- [ ] **Step 3: Implement profile staging from the reviewed runtime prototype**

  Promote only provider-neutral logic from ignored `.p3-vps-run/gate-6.5-stage-*` and `gate-6.5-export-verify.ps1`. Remove real paths, peer identities, infrastructure pins, and timestamps from tracked code.

- [ ] **Step 4: Write the read-only client-gate tests**

  Require:

  ```text
  PRE: exact profile hash, client binary hash/signature, RedShield/Cisco snapshots, no self-hosted adapter
  POST_CONNECT: one expected self-hosted adapter, route attribution selects that adapter, server peer handshake fresh, RX/TX delta observed, three public-egress observations match the expected self-hosted egress identity hash
  POST_ROLLBACK: self-hosted profile/adapter absent, RedShield/Cisco snapshots equal PRE
  ```

  Server peer observation uses pinned key-only SSH and returns only the selected peer fingerprint hash, handshake freshness, and traffic-delta booleans. Route attribution returns only interface-class/identity hashes and match booleans. Neither path emits a raw key, epoch, public address, route, adapter name, or profile field.

- [ ] **Step 5: Implement `p3-client-gate.ps1` read-only actions**

  Pin AmneziaVPN file version, Authenticode signature, and SHA-256. Pin the expected Guest peer fingerprint hash from the Gate 6.5 sanitized receipt and the expected Droplet egress identity hash from the protected runtime pin. Query three predeclared HTTPS egress endpoints with bounded timeouts, require one agreed IPv4 result, compare its hash to the expected self-hosted egress hash, and prove the selected route belongs to the self-hosted adapter. Do not print either address and do not import, connect, disconnect, or remove a profile in this script.

- [ ] **Step 6: Document distinct server-peer and client-profile rollback paths**

  For a Gate 6.5 server anomaly, the runbook identifies the one candidate Admin/Guest by its gate-owned receipt and removes only that server peer through the official UI; a separately guarded direct `awg syncconf` path is emergency-only. Before mutation, require a source-pinned AmneziaVPN 5.0.1.5 capability mapping plus a read-only UI check that the exact one-peer removal control exists; otherwise stop before peer creation. For a Gate 6.6 client anomaly, remove only the new local Amnezia client profile and preserve the server Guest until a separate cleanup approval. `Clear server from Amnezia software` remains prohibited.

- [ ] **Step 7: Run Pester and parser checks under both engines**

  ```powershell
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Command pester
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command '$errors=$null; foreach($p in @(".\scripts\p3-profile-stage.ps1",".\scripts\p3-client-gate.ps1")){[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $p),[ref]$null,[ref]$errors)}; if($errors.Count){exit 1}'
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '$errors=$null; foreach($p in @(".\scripts\p3-profile-stage.ps1",".\scripts\p3-client-gate.ps1")){[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $p),[ref]$null,[ref]$errors)}; if($errors.Count){exit 1}'
  ```

  The Pester runner must report a non-zero discovered-test count and zero failures. Parser checks supplement, not replace, Pester execution.

- [ ] **Step 8: Commit profile/client gate tooling**

  ```powershell
  git add -- scripts/p3-profile-stage.ps1 scripts/p3-profile-stage-elevated.ps1 scripts/p3-client-gate.ps1 tests/windows-pester/P3ProfileStage.Tests.ps1 tests/windows-pester/P3ClientGate.Tests.ps1 docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md docs/runbooks/P3_WINDOWS_CLIENT_ACTIVATION.md
  git commit -m "feat(p3): add protected profile and client field gates"
  ```

### Task 5: Build the Gate 6.5 condition-based management/Guest guard

**Files:**
- Create: `scripts/p3-amnezia-peer-guard.py`
- Create: `scripts/p3-amnezia-peer-guard.ps1`
- Create: `tests/python/test_p3_amnezia_peer_guard.py`
- Create: `tests/windows-pester/P3AmneziaPeerGuard.Tests.ps1`
- Runtime only (ignored): `.p3-vps-run/gate65-pins.json`
- Runtime only (ignored): `.p3-vps-run/gate65-*.log`

**Interfaces:**
- Generic tracked code consumes only runtime-injected hashes/counts/timeouts and the memory-only SSH agent; it contains no real host, key path, peer, container digest, profile, or infrastructure pin.
- Produces two bounded operations: exactly one Admin discovery delta, then exactly one Guest delta; each has a candidate-specific official-UI rollback receipt and an emergency exact-one-peer rollback contract.

- [ ] **Step 1: Reproduce the two leading historical failure hypotheses offline**

  Add tests with injected snapshots proving:

  ```text
  raw iptables timestamps/counters or listener queue/order only -> semantic runtime remains equal
  partial persistent/live/metadata/tmp convergence -> wait, do not validate or roll back yet
  primary exception and rollback exception -> separate sanitized labels
  EOF or invalid control token -> no mutation and explicit transport label
  ```

  Treat timing convergence and raw-runtime drift as hypotheses only; the historical guard suppressed both exception labels, so the original root cause is not claimed as proven.

- [ ] **Step 2: Implement semantic normalization and stable convergence**

  Reuse the reviewed normalization contract from the successful standalone rollback: exact iptables timestamp/counter positions only, nft counters only, sorted unique port bindings, listener queue fields only. Poll every two seconds for at most 180 seconds and require two identical exact candidate snapshots separated by five seconds before success or rollback.

- [ ] **Step 3: Separate observation from rollback**

  A primary anomaly writes a sanitized candidate receipt and closes the UI action window. Rollback starts only after the candidate has stabilized and exact identity is revalidated. The emergency rollback may remove only the one identified candidate peer plus its exact temporary block, perform one `awg syncconf`, and prove return to the pre-operation P/M/L/tmp/runtime hashes.

- [ ] **Step 4: Add automatic control without storing secrets**

  The tracked launcher requires runtime pins from the ignored pin file, uses the existing memory-only `ssh-agent`, strict host-key pin, current egress `/32` check, and no private-key command-line material. It must not use `IdentityAgent=none`. It emits `READY_FOR_UI=YES`, detects the exact delta automatically, and needs no `ARM`/`VERIFY` keyboard input.

- [ ] **Step 5: Validate tracked guard code**

  Run:

  ```powershell
  python -m unittest discover -s .\tests\python -p "test_p3_amnezia_peer_guard.py"
  python -m py_compile .\scripts\p3-amnezia-peer-guard.py
  ruff check .\scripts\p3-amnezia-peer-guard.py .\tests\python\test_p3_amnezia_peer_guard.py
  ruff format --check .\scripts\p3-amnezia-peer-guard.py .\tests\python\test_p3_amnezia_peer_guard.py
  & .\scripts\dev.ps1 -Command pester
  ```

  Also run payload self-test, PowerShell 5.1/7 parser checks, corrupted-transport rejection, `-ValidateOnly`, payload-length bound, and secret scan. A reviewer must return GO before live UI use.

- [ ] **Step 6: Commit the reproducible guard before any live use**

  ```powershell
  git add -- scripts/p3-amnezia-peer-guard.py scripts/p3-amnezia-peer-guard.ps1 tests/python/test_p3_amnezia_peer_guard.py tests/windows-pester/P3AmneziaPeerGuard.Tests.ps1
  git commit -m "feat(p3): add bounded Amnezia peer guard"
  ```

### Task 6: Build, validate, and review the complete offline field package

**Files:**
- Create: `scripts/p3-windows-field-matrix.ps1`
- Create: `tests/windows-pester/P3WindowsFieldMatrix.Tests.ps1`
- Create: `docs/runbooks/P3_WINDOWS_FIELD_GATE.md`
- Modify: `scripts/p35-canary.ps1`
- Modify: `tests/windows-pester/P35Canary.Tests.ps1`

**Interfaces:**
- Matrix actions: `PreApply`, `PendingQuickCheck`, `CommittedMatrix`, `TunnelDown`, `ProcessRecovery`, `AdapterLoss`, `RebootRecovery`, `RollbackVerify`.
- All code, launchers, tests, and runbooks required by Gates 6.5–7.3 are tracked, committed, and reviewed before any live UI, peer, profile, or Windows-network action.

- [ ] **Step 1: Write fail-closed Pester contracts for the field matrix**

  Require synthetic injected observations for direct/self-hosted/Cisco egress, DNS, IPv4/IPv6, MTU, TCP/UDP/QUIC, tunnel-down blocking, process recovery, adapter loss, reboot recovery, and emergency disable. Assert timeout bounds, sanitized output, exact target hashes, and no native mutation in observation modes.

- [ ] **Step 2: Implement the bounded matrix harness**

  Each action writes one schema-versioned sanitized record. Public addresses, DNS servers, target names, adapter names, GUIDs, routes, and packet contents are represented only by classes/counts/hashes. Tunnel-down targets only the new self-hosted profile; RedShield and Cisco remain unchanged.

- [ ] **Step 3: Specify the two-session Apply/Confirm orchestration**

  The runbook requires two elevated PowerShell sessions. Session A starts exact candidate-bound Apply and waits; Session B runs `PendingQuickCheck` and exact candidate-bound Confirm. Capture both child exit codes. The combined quick-check budget must be less than the two-minute watchdog deadline with a documented safety margin; timeout or any failed check causes automatic rollback and no Confirm.

- [ ] **Step 4: Run the complete offline validation batch**

  ```powershell
  & .\.tools\go\bin\go.exe test ./internal/providers/configfile ./internal/providers/selfhosted ./internal/system/windows ./internal/hgctlcmd ./internal/revisions/apply
  python -m unittest discover -s .\tests\python -p "test_p3_amnezia_peer_guard.py"
  python -m py_compile .\scripts\p3-amnezia-peer-guard.py
  ruff check .\scripts\p3-amnezia-peer-guard.py .\tests\python\test_p3_amnezia_peer_guard.py
  ruff format --check .\scripts\p3-amnezia-peer-guard.py .\tests\python\test_p3_amnezia_peer_guard.py
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Command pester
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
  & .\scripts\dev.ps1 -Command verify
  git diff --check
  ```

  Expected: PASS, non-zero Go/Pester/Python test counts, zero callable vulnerabilities, zero secret findings, and PowerShell 5.1/7 compatibility.

- [ ] **Step 5: Commit the complete offline package**

  ```powershell
  git add -- scripts/p3-windows-field-matrix.ps1 scripts/p35-canary.ps1 tests/windows-pester/P3WindowsFieldMatrix.Tests.ps1 tests/windows-pester/P35Canary.Tests.ps1 docs/runbooks/P3_WINDOWS_FIELD_GATE.md
  git commit -m "feat(p3): add bounded Windows field acceptance harness"
  ```

- [ ] **Step 6: Obtain independent QA and security GO on committed HEAD**

  Review spec coverage, exact candidate/restore binding, secret handling, SSH trust, peer rollback, client profile-only rollback, two-session timing, RedShield/Cisco preservation, and all observation-only claims. Fix every Critical/Important finding, commit the fixes, rerun only affected focused checks plus the full validation batch once, and obtain final GO. No live gate starts on an uncommitted or unreviewed tree.

### Task 7: Run live Gate 6.5 and Gate 6.6

**Files:**
- Runtime evidence: ignored `.p3-vps-run/`
- Tracked evidence after PASS: `docs/reports/2026-08-30-p3-profile-client-field.md`

**Interfaces:**
- Consumes: committed Tasks 1–6 with QA/security GO, exact server baseline, protected staging root, and memory-only SSH agent.
- Produces: final accepted peer topology, protected static Guest profile, Guest/profile identity hashes, observed adapter/route/handshake/egress evidence, and tested client profile-only rollback.

- [ ] **Step 1: Perform read-only Gate 6.4/6.5 baseline reconciliation**

  Confirm one expected container/image/digest, one UDP publication, SSH plus UDP as the only public inbound union, persistent IPv4 host policy loaded, IPv6 UDP closed in Cloud Firewall, expected baseline peer set, no candidate/temp/atomic leftovers, and absent protected PC profile. Stop on any mismatch.

- [ ] **Step 2: Obtain exact Gate 6.5 approval**

  Present one Admin discovery, one Guest creation, one `syncconf` per official action, protected export destination, final peer topology, official exact-one-peer UI rollback, and the separately guarded emergency rollback. Approval does not authorize VPN activation.

- [ ] **Step 3: Run Admin discovery under the reviewed guard**

  Use the official AmneziaVPN GUI management entry for `homegateway`. Keep the existing baseline Admin unchanged. Accept only exact-plus-one Admin P/M/L/metadata state, one `syncconf`, no container restart/firewall drift, and remove only its exact sensitive temp artifact after successful verification.

- [ ] **Step 4: Create, export, and inspect exactly one Guest**

  Use `Guest access`, a gate-owned label, and `AmneziaWG native format`. Export directly into the prepared protected staging destination. Require exact-plus-one Guest state and one `syncconf`; install it as `secrets\tunnel.conf` plus its hash. Sanitized inspection must prove provider `selfhosted`, transport `amneziawg`, AWG 3.1 bounded fields, exact family flags/counts, regular-file identity, ACL, and matching SHA-256. Preserve the protected original export through Gate 7.3.

- [ ] **Step 5: Obtain exact Gate 6.6 approval**

  Present the exact profile hash, pinned client identity, intended single adapter identity class, expected self-hosted egress identity hash, Guest peer fingerprint hash, one bounded pinned-SSH peer observation, and official client profile-only rollback. This approval does not authorize server Guest deletion.

- [ ] **Step 6: Import and activate only the new client profile**

  Use the official GUI without disconnecting or modifying RedShield/Cisco. Run `PostConnect`; require one self-hosted adapter, route attribution to it, fresh exact Guest handshake, RX/TX delta, and three public-egress observations matching the expected self-hosted egress identity hash. On anomaly, remove only the new local client profile, run `PostRollback`, preserve the server Guest for a separately approved cleanup, and stop.

- [ ] **Step 7: Record Gate 6.5/6.6 evidence**

  Commit only hashes, counts, booleans, client version/hash, image identity hash, exact terminal peer topology, and PASS/rollback state. Never commit a raw public address, peer key, profile, host pin, or key path.

### Task 8: Run Gate 7 and candidate-bound terminal `FullRestore`

**Files:**
- Runtime evidence: ignored `.p35-run/` and `.p3-vps-run/`
- Tracked final report: `docs/reports/2026-08-30-p3-pc-core-ready.md`

**Interfaces:**
- Consumes: Gate 6.6 PASS, the committed reviewed field harness, current journal, install snapshot, protected config ACL snapshot, and exact live candidates.
- Produces: terminal `restored` receipt, empty ownership registry, zero project-owned network artifacts, restored protected-config ACL baseline, and unchanged RedShield/Cisco state.

- [ ] **Step 1: Run Gate 7.1 exact read-only Plan**

  Require one qualified self-hosted adapter, endpoint directness, no Cisco/DNS/target overlap, both family semantics, PktMon stopped/empty, zero pre-existing active/pending ownership, ready sinks, observed handshake and expected egress attribution, exact qualified-endpoint identities, full candidate SHA-256, target-class counts, watchdog timeout, confirmation challenge, and rollback command.

- [ ] **Step 2: Obtain exact Gate 7.2 Apply/Confirm approval**

  Present the candidate hash, challenge, qualified-endpoint identity hashes, target classes, two-session sequence, watchdog timeout/safety margin, pending quick checks, automatic rollback, and the exact committed subtests included. The approval applies to this candidate only.

- [ ] **Step 3: Execute the two-session Apply/Confirm gate**

  Session A starts Apply with the exact candidate hash and records its child exit. Session B completes `PendingQuickCheck` within the budget, then submits Confirm with the same candidate hash and records its child exit. Never Confirm on a timeout, mismatch, unexpected route/DNS/adapter state, or failed health check; prove automatic rollback instead.

- [ ] **Step 4: Execute the committed matrix**

  Prove direct/self-hosted/Cisco decisions, DNS, IPv4/IPv6 leak behavior, MTU, TCP/UDP/QUIC, tunnel-down fail-closed behavior, process-loss/watchdog recovery, reconnect, emergency disable, and rollback/restore semantics exactly as named in the Gate 7.2 approval. RedShield/Cisco remain connected and unchanged.

- [ ] **Step 5: Obtain separate adapter-loss and reboot approvals**

  For adapter loss, name and identity-hash only the self-hosted virtual adapter and prove that no physical, Cisco, or RedShield adapter can match. For reboot, require committed state, watchdog readiness, memory-only credential implications, and the post-boot emergency path. Neither action runs under the generic Gate 7.2 approval.

- [ ] **Step 6: Execute separately approved adapter/reboot recovery tests**

  After each action, require exact recovery-state convergence, expected egress/route attribution, fresh Guest handshake, unchanged RedShield/Cisco snapshots, and zero unexpected owned artifacts. Stop and recover on the first anomaly.

- [ ] **Step 7: Run `FullRestorePlan` read-only**

  Capture the complete sorted redacted identity envelope, exhaustive counts, exact network recovery-plan SHA-256/challenge, journal/registry/install/revision/task/binary hashes, and the independent protected ACL restore-plan SHA-256/challenge. Both subplans perform zero mutations.

- [ ] **Step 8: Obtain fresh exact Gate 7.3 approval**

  Present only both exact subplan hashes/challenges, exhaustive artifact classes/counts, and stable identity hashes. Approval covers the monotonic network `FullRestore` followed by candidate-bound protected ACL restoration; it does not cover source-profile deletion, Amnezia profile removal, RedShield/Cisco changes, server peer removal, server clearing, Droplet deletion, or billing changes.

- [ ] **Step 9: Execute and verify network `FullRestore`**

  Recompute the network identity envelope under the operation lock, require exact hash equality, perform the project-owned network transaction, disarm exact watchdog tasks, and run network terminal inventory. Any pre-mutation mismatch stops cleanly; any transaction failure must prove its existing retry/rollback state and must not claim terminal restore.

- [ ] **Step 10: Execute the independently bound ACL restore**

  Reopen the protected source through the exclusive file handle, revalidate file identity/content/current ACL/baseline ACL, both bootstrap code hashes, and exact ACL-plan hash, restore only that ACL, and post-check it through the same handle. If this step fails after network restore, retain the safer network-restored state, mark `ACL_RESTORE=PENDING`, obtain a fresh read-only ACL plan and fresh exact approval for its new hash/challenge, then retry only ACL. Never reuse the initial approval and never compensate by reintroducing project network artifacts.

- [ ] **Step 11: Prove terminal state**

  Require terminal journal `restored`; empty active/LKG/pending/recovery revisions; empty ownership registry; zero owned routes/sinks/firewall/NRPT/tasks; no locks or atomic leftovers; exact pre-install foreign state; RedShield/Cisco unchanged; source and Amnezia profiles preserved.

### Task 9: Close P3 honestly

**Files:**
- Create: `docs/reports/2026-08-30-p3-pc-core-ready.md`
- Modify: `STATUS.md`
- Modify: `docs/ACCEPTANCE_MATRIX.md`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/SECURITY.md`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-24-p03-redshield-windows.md`

**Interfaces:**
- Consumes: all Gate 6.5–7.3 sanitized PASS evidence and final repository verification.
- Produces: accepted `pc-core-ready` status or an honest blocker report; never a partial PASS.

- [ ] **Step 1: Write the final redacted field report**

  Separate implementation evidence, server/client observations, Windows Apply/Confirm, failure tests, adapter/reboot recovery, and terminal restore. Include exact commands, exit codes, hashes/counts, and unresolved gaps only.

- [ ] **Step 2: Destroy temporary credentials and runtime control state**

  Remove all keys from the dedicated memory-only `ssh-agent`, terminate only that exact agent PID, close gate-created helper windows, and add sanitized `AGENT_EMPTY=YES`/`AGENT_TERMINATED=YES` proof to the report. Do not delete the encrypted SSH private key, protected VPN profile, Droplet, Cloud Firewall, or Amnezia client profile. Cleanup failure blocks final acceptance.

- [ ] **Step 3: Run final verification once**

  ```powershell
  & .\scripts\dev.ps1 -Command verify
  git diff --check
  git status --short
  ```

- [ ] **Step 4: Obtain one consolidated read-only review**

  Review spec coverage, secrets, Cisco/RedShield preservation, candidate binding, rollback, field evidence, and terminal restore. Fix all Critical/Important findings once and rerun only affected focused checks plus the final `verify` batch.

- [ ] **Step 5: Commit final evidence and status**

  ```powershell
  git add -- README.md STATUS.md docs/ACCEPTANCE_MATRIX.md docs/COMPATIBILITY.md docs/SECURITY.md docs/reports/2026-08-30-p3-pc-core-ready.md docs/superpowers/plans/2026-08-24-p03-redshield-windows.md
  git commit -m "docs(p3): close pc-core-ready field acceptance"
  ```

## Self-Review

- Spec coverage: Tasks 1–9 cover profile creation, activation, observed health, exact Plan, Apply/Confirm, full Windows safety matrix, adapter/reboot recovery, terminal restore, evidence, and `pc-core-ready` closure.
- Scope boundary: P8 server automation/mobile lifecycle, P9 failover, P10 fallback, P11 release packaging, and P12 router migration remain excluded.
- Secret boundary: tracked code and evidence consume only paths, hashes, counts, booleans, and classes; raw credentials/configuration stay outside Git and logs.
- Live boundary: Gate 6.5, Gate 6.6, Gate 7.2, adapter loss, reboot, and Gate 7.3 remain separately approved actions even after this implementation plan is accepted.
- Reproducibility: every generic guard/harness/launcher is tracked, tested, committed, and reviewed before live use; only real pins and transcripts remain ignored.
- Type consistency: `CandidateSHA256`, `FullRestorePlan.IdentitySHA256`, `recovery_plan_sha256`, the candidate-derived Apply/Confirm challenge, and the recovery-plan-derived restore challenge are produced in Task 3 and consumed unchanged in Tasks 7–8.
