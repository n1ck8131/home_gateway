# P3 pre-live prerequisite closure implementation plan

**Goal:** Correct the Task 6A baseline/bootstrap/storage contracts, prove them offline, and produce but not execute the next exact read-only prerequisite candidate.

**Architecture:** One host-installed Python helper uses a bounded Docker adapter for all AmneziaWG container state. PowerShell and Python share one behaviorally verified 27-field canonical baseline. A separate protected prerequisite driver performs the later SSH/HTTPS/UI-observation batch before the final runtime manifest exists.

**Spec:** `docs/superpowers/specs/2026-08-31-p3-prelive-prerequisite-closure-design.md`

**Scope:** Offline implementation, tests, documentation, review, validation, and candidate generation only. No SSH, HTTPS egress observation, DigitalOcean UI mutation, peer/profile action, Docker/firewall/network/service mutation, adapter action, or reboot.

## Task 1: Write failing cross-language contract tests

**Files:**

- Modify `tests/python/test_p3_amnezia_peer_guard.py`
- Modify `tests/windows-pester/P3PreliveRuntime.Tests.ps1`
- Modify `tests/windows-pester/P3AmneziaPeerGuard.Tests.ps1`

Add a collector-shaped 27-field fixture and prove that its PowerShell canonical baseline hash is accepted unchanged by Python reconcile. Add missing/extra/type-confused/hash/count tests. Prove `prepared_syncconf_sha256` is absent from the pre-live baseline and remains candidate-only.

Run the focused tests and record the expected RED failures before production edits.

## Task 2: Correct the canonical baseline and runtime consumption

**Files:**

- Modify `scripts/p3-prelive-runtime.ps1`
- Modify `scripts/p3-amnezia-peer-guard.py`
- Modify `scripts/p3-amnezia-peer-guard.ps1`
- Modify corresponding tests

Define the exact 27-field v2 baseline, strict native JSON types, all SHA/count/boolean constraints, and identical canonicalization. Bind a validated prerequisite receipt into `PreparePlan`; remove the direct self-defining bootstrap path. Preserve existing schema rejection and protected-root controls.

## Task 3: Replace host-path collection with the Docker adapter

**Files:**

- Modify `scripts/p3-amnezia-peer-guard.py`
- Modify `tests/python/test_p3_amnezia_peer_guard.py`

Use exact container constants `amnezia-awg2`, `/opt/amnezia/awg/awg0.conf`, `/opt/amnezia/awg/clientsTable`, and `awg0`. Read config, metadata, live peers, and bounded `/tmp` artifacts through injected Docker commands. Reuse the proven strict config and clients-table semantics from the historical Gate 6.5C implementation without importing ignored scripts into production.

Reject host `pathlib` reads for container state, host `/usr/bin/awg`, ambiguous container shapes, wrong image/digest/restart/port state, malformed clients rows, and peer-set divergence.

Remove the synthetic metadata `role` requirement. Make the remote event an exact converged peer candidate only. For management discovery, require a protected source-pinned full-access UI operation-context receipt and label it owner-observed/non-cryptographic. For Guest, extend the protected profile inspection path to derive the X25519 public key from the interface private key in memory and emit only SHA-256 of the raw public bytes; require that fingerprint to match the server candidate. Add negative tests for renamed `clientName`, misleading `Admin [`/Guest labels, wrong UI action class, replay, substituted profile/path/ACL, mismatched derived key, and absent proof.

Create versioned exact receipt schemas in the PowerShell launcher/profile stage boundary. Bind manifest, candidate receipt, nonce, pre/post sets, runtime, file identity, ACL identity, timestamps, and one-time consumption. Never read or decrypt the AmneziaVPN registry/keychain settings directly.

## Task 4: Correct container-scoped emergency rollback

**Files:**

- Modify `scripts/p3-amnezia-peer-guard.py`
- Modify `tests/python/test_p3_amnezia_peer_guard.py`

Implement an injected container filesystem adapter. Back up exact authoritative bytes to a root-only host recovery directory, stream fixed-path atomic container writes, run one container-side official `syncconf`, verify baseline, and recover both files plus any exact candidate temp state on failure. Keep production rollback behind its existing exact plan/challenge and add failpoint tests for each mutation boundary.

Use one immutable resolved container ID. Preflight fixed `/bin/bash`, `/usr/bin/awg`, `/usr/bin/awg-quick`, target regular files, same-directory no-clobber staging, exact byte counts, owner/mode preservation, and process substitution before any backup/write. Include both exact nonce-derived staging paths in inspect/recover/verify/cleanup, require them absent before and after, and reject every foreign `.p3-next-*` path. Add injected tests for tool absence, output overflow, staging collision, second-stage write failure, process interruption after either staging create, partial two-file update, sync failure, recovery sync failure, unproved staging cleanup, and retained recovery material.

## Task 5: Add the prerequisite plan/observer/receipt boundary

**Files:**

- Create `scripts/p3-prelive-prerequisite.ps1`
- Create `scripts/p3-prelive-server-observer.py`
- Create `tests/windows-pester/P3PrelivePrerequisite.Tests.ps1`
- Create `tests/python/test_p3_pre_live_server_observer.py`
- Modify `scripts/p3-prelive-runtime.ps1`

Implement `Plan`, prerequisite-scoped `AgentPlan/AgentStart/AgentValidate/AgentStop`, `Observe`, `Assemble`, and `Validate` with bounded input/output and marker-owned protected files. Generalize the existing agent lifecycle so it binds either a prerequisite manifest or final runtime manifest without allowing receipt reuse between them. The exact prerequisite execution approval covers the memory-only key load, read-only SSH/three local HTTPS GETs, and mandatory `finally` teardown.

The server observer must share the baseline semantics, execute from a hash-attested in-memory frame, and perform read-only Docker/host observation only. The Windows controller alone runs the three HTTPS egress probes. Add exact Firewall/Droplet identity plus inbound/outbound-union provenance and equality between the Cloud Firewall management `/32` and all three controller egress observations; explicitly reject a Droplet egress value as management evidence.

Production native calls are injected or disabled in tests. Tests must prove no remote-write command appears in the read-only observer path.

Add golden raw-command fixtures and exact parsers for Docker JSON/ports, `iptables-save`, `ip6tables-save`, nft counters, and `ss` queues. Preserve semantically significant order and reject unknown volatility rather than normalizing it.

## Task 6: Update runbooks and phase state

**Files:**

- Modify `docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md`
- Modify `docs/superpowers/specs/2026-08-30-p3-task6a-prelive-guard-design.md`
- Modify `docs/superpowers/plans/2026-08-30-p3-task6a-prelive-guard.md`
- Modify `STATUS.md`

Mark the superseded assumptions explicitly. Document the two-approval sequence: exact read-only prerequisite observation, then exact runtime preparation. State the confirmed container storage boundary, preserved VPN/RedShield/Cisco state, and prohibition on treating old ignored evidence as current acceptance.

## Task 7: Focused validation and implementation commit

Run once after the implementation batch:

```powershell
python -m unittest discover -s .\tests\python -p "test_p3_amnezia_peer_guard.py"
python -m unittest discover -s .\tests\python -p "test_p3_pre_live_server_observer.py"
python -m py_compile .\scripts\p3-amnezia-peer-guard.py .\scripts\p3-prelive-server-observer.py
ruff check .\scripts\p3-amnezia-peer-guard.py .\scripts\p3-prelive-server-observer.py .\tests\python\test_p3_amnezia_peer_guard.py .\tests\python\test_p3_pre_live_server_observer.py
ruff format --check .\scripts\p3-amnezia-peer-guard.py .\scripts\p3-prelive-server-observer.py .\tests\python\test_p3_amnezia_peer_guard.py .\tests\python\test_p3_pre_live_server_observer.py
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Command pester
& pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
git diff --check
```

Commit only explicit scoped paths after PASS.

## Task 8: Consolidated review and fix wave

Give one read-only QA/security reviewer the corrective spec, committed diff, tests, and validation evidence. Require review of canonicalization, container trust boundary, command injection, secret/output handling, rollback recovery, prerequisite provenance, bootstrap-cycle closure, and no-live claims.

If findings exist, send one consolidated list to the same implementation agent, commit one fix wave, rerun affected focused checks, and repeat review until GO.

## Task 9: Full offline validation

On final committed HEAD run:

```powershell
& .\.tools\go\bin\go.exe test ./internal/providers/configfile ./internal/providers/selfhosted ./internal/system/windows ./internal/hgctlcmd ./internal/revisions/apply
python -m unittest discover -s .\tests\python
python -m py_compile .\scripts\p3-amnezia-peer-guard.py .\scripts\p3-prelive-server-observer.py
ruff check .\scripts\p3-amnezia-peer-guard.py .\scripts\p3-prelive-server-observer.py .\tests\python
ruff format --check .\scripts\p3-amnezia-peer-guard.py .\scripts\p3-prelive-server-observer.py .\tests\python
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Command pester
& pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
& .\scripts\dev.ps1 -Command verify
git diff --check
git status --short
```

Do not repeat a failed command until its cause or relevant state changes.

## Task 10: Generate, do not execute, the next exact candidate

Use only the reviewed tracked candidate generator and ignored local seed paths. Generate one sanitized `home-gateway/p3-prelive-prerequisite-plan/v2` artifact containing:

- current HEAD and tracked payload hashes;
- exact plan SHA-256 and confirmation challenge;
- pinned SSH toolchain/known-host/key-fingerprint hashes;
- expected Firewall/Droplet resource hashes and exact rule classes;
- expected server container/image/port/host-policy classes/hashes;
- three authority hashes, timeouts, freshness limits, no-write scope, rollback=`not-applicable`, and hard-stop conditions.

Scan the artifact for raw IP addresses, resource identifiers, key/profile material, paths outside allowed hashed classes, and secrets. Do not execute `Observe`, start an agent, open SSH, make HTTPS requests, or create the final runtime.

Stop and request the separate exact approval for this candidate.
