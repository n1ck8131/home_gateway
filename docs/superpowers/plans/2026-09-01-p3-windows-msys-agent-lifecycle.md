# Phase 3.4 Windows/MSYS Agent Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Phase 3.4 own and clean up the real Windows `ssh-agent.exe`
process even when Git for Windows emits a different MSYS `SSH_AGENT_PID`.

**Architecture:** Launch pinned `ssh-agent.exe -D -s` through a bounded
Windows process boundary that returns both its real `Process.Id` and emitted
shell records. Persist the emitted and Windows identifiers separately, and use
only the Windows identifier for process lifecycle operations. Load the key in a
visible, non-capturing console boundary.

**Tech Stack:** Windows PowerShell 5.1, PowerShell 7, Pester, .NET
`System.Diagnostics.Process`.

**Spec:** `docs/superpowers/specs/2026-09-01-p3-windows-msys-agent-lifecycle-design.md`

## Global Constraints

- Do not start a real `ssh-agent`, `ssh-add`, SSH, or HTTPS process in tests.
- Do not mutate VPN, routes, DNS, firewall, adapters, Cisco, server, or cloud.
- Preserve unrelated worktree changes and stage only explicit paths.
- `agent_pid` is emitted MSYS identity; `windows_process_id` is the only
  Windows lifecycle identity.
- A live retry is forbidden until a new exact candidate is separately approved.

---

### Task 1: Dual-PID regression contract

**Files:**
- Modify: `tests/windows-pester/P3SshAgent.Tests.ps1`
- Test: `tests/windows-pester/P3SshAgent.Tests.ps1`

**Interfaces:**
- Consumes: current `Start-P3Agent`, `Test-P3AgentState`, and `Stop-P3Agent`.
- Produces: executable fixtures for `agent_pid=77` and
  `windows_process_id=26484`, plus the structured launch-record contract.

- [ ] **Step 1: Write failing dual-PID lifecycle tests**

  Add literal launch records with schema
  `home-gateway/p3-windows-agent-launch/v1`, emitted PID `77`, Windows PID
  `26484`, and a literal pinned process observation. Assert environment/audit
  retains `77` while process validation and all cleanup runners receive only
  `26484`.

- [ ] **Step 2: Write failing malformed-output and identity tests**

  Assert malformed shell output after an exact process observation cleans up
  only Windows PID `26484`; zero, duplicate, wrong-ID, and wrong-path process
  observations prevent `AddRunner`, fail closed, and never call a PID-based
  stop because the PID may have been reused.

- [ ] **Step 3: Verify RED in both PowerShell engines**

  Run:

  ```powershell
  powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Invoke-Pester -Path '.\tests\windows-pester\P3SshAgent.Tests.ps1' -EnableExit"
  pwsh.exe -NoLogo -NoProfile -NonInteractive -Command "Invoke-Pester -Path '.\tests\windows-pester\P3SshAgent.Tests.ps1' -EnableExit"
  ```

  Expected: failures caused by the missing structured dual-PID contract, not
  syntax or fixture errors.

### Task 2: Owned foreground process and visible key loading

**Files:**
- Modify: `scripts/p3-ssh-agent.ps1`
- Modify: `tests/windows-pester/P3SshAgent.Tests.ps1`

**Interfaces:**
- Consumes: the launch-record contract from Task 1.
- Produces: `Start-P3WindowsAgentProcess`,
  `Invoke-P3InteractiveAgentAdd`, raw receipt v2, combined receipt v3, and
  `Start-P3Agent(..., ProcessRunner)`.

- [ ] **Step 1: Implement the minimal structured launcher**

  Build a `ProcessStartInfo` for the exact executable with arguments `-D -s`,
  `UseShellExecute=false`, `CreateNoWindow=true`, and bounded stdout collection.
  Return exactly the launch-record fields with `started_at_utc` derived from
  `Process.StartTime`; on failure kill/wait/dispose the owned process object and
  treat kill or bounded-wait failure as terminal.

- [ ] **Step 2: Implement the visible `ssh-add` boundary**

  Build a normal visible, non-redirected `ProcessStartInfo` for the exact
  `ssh-add.exe` and quoted dedicated key path. Wait for exit and reject every
  non-zero result without capturing standard input/output.

- [ ] **Step 3: Implement dual-PID receipts and lifecycle use**

  Parse `agent_pid` only from launch output, validate the observed process using
  `windows_process_id`, and route every process stop/wait/re-observation call to
  `windows_process_id`. Keep environment comparisons bound to `agent_pid`.

- [ ] **Step 4: Verify GREEN for the focused file**

  Run the two Task 1 Pester commands. Expected: all tests pass and no real agent
  process is created.

### Task 3: Atomic consumer and schema migration

**Files:**
- Modify: `scripts/p3-prelive-runtime.ps1`
- Modify: `scripts/p3-prelive-prerequisite.ps1`
- Modify: `scripts/p3-remote-helper.ps1`
- Modify: `scripts/p3-amnezia-peer-guard.ps1`
- Modify: `tests/windows-pester/P3PreliveRuntime.Tests.ps1`
- Modify: `tests/windows-pester/P3PrelivePrerequisite.Tests.ps1`
- Modify: `tests/windows-pester/P3RemoteHelper.Tests.ps1`
- Modify: `tests/windows-pester/P3AmneziaPeerGuard.Tests.ps1`

**Interfaces:**
- Consumes: raw receipt v2, combined receipt v3, structured `AgentRunner`, and
  the extended `Start-P3Agent` signature.
- Produces: one exact receipt schema and production boundaries shared by all
  Phase 3 paths.

- [ ] **Step 1: Add failing integration fixtures where needed**

  Migrate fixtures to use different emitted and Windows PIDs and assert that
  prerequisite, runtime, remote-helper, and guard cleanup sees only the Windows
  PID.

- [ ] **Step 2: Verify integration RED**

  Run the four affected Pester files in Windows PowerShell 5.1. Expected:
  failures identify old schema/boundary assumptions.

- [ ] **Step 3: Update exact schemas and production boundaries**

  Add `windows_process_id` and `windows_process_id_match`, advance schemas,
  supply `ProcessRunner` to start calls, and replace native `-s`/hidden
  `ssh-add` runners with the shared foreground/visible helpers.

- [ ] **Step 4: Verify focused integration GREEN in both engines**

  Run all five affected Pester files once under Windows PowerShell 5.1 and once
  under PowerShell 7. Expected: all pass with clean output.

### Task 4: Final verification, review, and candidate

**Files:**
- Modify only files already named above if verification finds a scoped defect.
- Create: one new commit containing the approved local fix.

**Interfaces:**
- Consumes: complete dual-PID implementation.
- Produces: clean verified commit and a new offline nonce-bound Phase 3.4
  candidate awaiting separate exact approval.

- [ ] **Step 1: Run the repository verification batch**

  Run:

  ```powershell
  .\scripts\dev.ps1 -Command verify
  ```

  Expected: every existing gate passes; record `RUFF_NOT_APPLICABLE_NO_PYTHON`
  if the verifier confirms there are no Python files.

- [ ] **Step 2: Perform independent correctness and security review**

  Review the complete diff for PID-space confusion, PID reuse, executable
  binding, cleanup gaps, passphrase leakage, schema drift, and test omissions.
  Resolve every Critical or Important finding and rerun only the affected
  focused checks plus one final repository gate.

- [ ] **Step 3: Commit explicit paths**

  ```powershell
  git add -- scripts/p3-ssh-agent.ps1 scripts/p3-prelive-runtime.ps1 scripts/p3-prelive-prerequisite.ps1 scripts/p3-remote-helper.ps1 scripts/p3-amnezia-peer-guard.ps1 tests/windows-pester/P3SshAgent.Tests.ps1 tests/windows-pester/P3PreliveRuntime.Tests.ps1 tests/windows-pester/P3PrelivePrerequisite.Tests.ps1 tests/windows-pester/P3RemoteHelper.Tests.ps1 tests/windows-pester/P3AmneziaPeerGuard.Tests.ps1 docs/superpowers/specs/2026-09-01-p3-windows-msys-agent-lifecycle-design.md docs/superpowers/plans/2026-09-01-p3-windows-msys-agent-lifecycle.md
  git commit -m "fix(p3): separate Windows and MSYS agent pids"
  ```

- [ ] **Step 4: Generate an offline replacement candidate**

  Revalidate clean HEAD, zero agent processes, and the protected base root;
  generate a new CSPRNG nonce-bound plan without executing live observation;
  independently verify canonical SHA-256 and return only hashes, challenges,
  counts, and approval text.
