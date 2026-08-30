# P3 Task 6A Pre-Live Guard Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tracked, fail-closed pre-live package that proves the complete P3 server/Cloud Firewall/local baseline, installs one exact inert remote helper, guards one Admin or Guest graphical user interface (GUI) delta, and supplies nonce-bound client observation without performing a live action during implementation.

**Architecture:** Keep four focused local boundaries: a protected runtime trust store, one dedicated Git OpenSSH agent, an exact remote-helper lifecycle driver, and the existing guard launcher. The existing Python payload becomes the only installed remote helper and implements attestation, reconciliation, streaming Admin/Guest observation, client observation, and separately approved emergency rollback. Production receipts are collected live and sanitized; fixture input exists only behind explicit test-only switches.

**Tech Stack:** Windows PowerShell 5.1 and PowerShell 7, Pester 6.0.0, Python 3.14, Ruff, Git for Windows Secure Shell (SSH), Ubuntu 24.04 system utilities, Docker-hosted AmneziaWG 3.1, official AmneziaVPN 5.0.1.5 GUI.

**Spec:** `docs/superpowers/specs/2026-08-30-p3-task6a-prelive-guard-design.md`

**Audience:** The Task 6A implementation agent, controller, and consolidated quality assurance (QA)/security reviewer.

**Content type:** Implementation plan.

**Canonical owner:** P3 `pc-core-ready` completion plan.

**Evidence status:** The owner accepted design commit `d7cd440`; implementation and live evidence do not yet exist.

## Global Constraints

- This plan is offline implementation only. It performs no SSH, DigitalOcean UI, peer, profile, VPN, Docker, firewall, service, route, DNS, adapter, task, reboot, or billing mutation.
- RedShield and Cisco remain connected and unchanged.
- The installed remote path is exactly `/usr/local/libexec/home-gateway-p3-peer-guard`; no second observer, service, socket, timer, or autostart entry is created.
- The remote helper is regular, `root:root`, mode `0755`, hash-exact, and inert between invocations.
- One pinned Git OpenSSH installation supplies `ssh-agent`, `ssh-add`, `ssh`, and `scp`; Windows OpenSSH must not be mixed with its agent socket.
- The agent contains exactly one expected dedicated key. Its passphrase is entered only into `ssh-add` and is never stored in a file, environment variable, command line, transcript, test fixture, or tracked artifact.
- Real hosts, addresses, paths, peer identities, profiles, keys, and infrastructure pins remain under ignored `.p3-vps-run/`; tracked output contains only schemas, hashes, counts, booleans, bounded durations, and state classes.
- One independently approved manifest SHA-256 binds static trust inputs. A fresh observation cannot define its own expected baseline.
- `READY_FOR_UI=YES` is emitted only after server reconciliation, owner-observed Cloud Firewall evidence, local profile/adapter absence, agent identity, current egress, and SSH trust all pass.
- A guard polls every two seconds for at most 180 seconds and accepts only two identical exact-plus-one snapshots separated by five seconds.
- The candidate receipt proves one semantic configuration transition; it does not claim an internal GUI `syncconf` call count.
- Emergency rollback is implemented and tested offline but remains a separately approved exact candidate action.
- P3 retains an exact inert helper through P3 completion. Windows `FullRestore` never implies its removal; P8 owns any later replacement or removal.
- The project `AGENTS.md` coordination rule overrides the generic fresh-agent-per-task default: one implementation agent owns Tasks 1-7 sequentially, then one consolidated read-only quality assurance (QA)/security reviewer checks the committed phase.

## File and responsibility map

- Create `scripts/p3-prelive-runtime.ps1`: protected runtime root, static trust manifest, Cloud Firewall/local receipts, strict file/ACL/identity validation, and scoped runtime cleanup.
- Create `scripts/p3-ssh-agent.ps1`: plan, start, validate, and destroy one exact Git OpenSSH agent containing one key.
- Create `scripts/p3-remote-helper.ps1`: `RemoteInstallPlan`, `RemoteInstall`, `RemoteRemovePlan`, and `RemoteRemove` using the pinned Git toolchain.
- Modify `scripts/p3-amnezia-peer-guard.py`: one-file Ubuntu helper with strict request/receipt schemas and five modes.
- Modify `scripts/p3-amnezia-peer-guard.ps1`: local reconcile, bounded newline-delimited JSON (NDJSON) guard orchestration, and candidate-bound emergency rollback entrypoint.
- Modify `scripts/p3-client-gate.ps1`: production live collection through `client-observe` and explicit test-only fixture isolation.
- Create `tests/windows-pester/P3PreliveRuntime.Tests.ps1`, `P3SshAgent.Tests.ps1`, and `P3RemoteHelper.Tests.ps1`.
- Modify `tests/python/test_p3_amnezia_peer_guard.py`, `tests/windows-pester/P3AmneziaPeerGuard.Tests.ps1`, and `P3ClientGate.Tests.ps1`.
- Modify `docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md`, `docs/runbooks/P3_WINDOWS_CLIENT_ACTIVATION.md`, `STATUS.md`, and the Task 6A SDD ledger/report.

---

### Task 1: Build the protected runtime trust bundle

**Files:**
- Create: `scripts/p3-prelive-runtime.ps1`
- Create: `tests/windows-pester/P3PreliveRuntime.Tests.ps1`

**Interfaces:**
- Consumes: one bounded UTF-8 candidate JSON document from standard input, local trusted file paths resolved at runtime, an independently approved lowercase manifest SHA-256, and an exact confirmation challenge.
- Produces: actions `PreparePlan`, `Prepare`, `Validate`, `RecordCloudFirewall`, `ObserveLocalBaseline`, `CleanupPlan`, and `Cleanup`.
- Produces runtime-only files under `.p3-vps-run/protected-v1/`: `.home-gateway-p3-runtime-owner.v1`, `trust.json`, `manifest.json`, `cloud-firewall-receipt.json`, and `local-baseline-receipt.json`.
- Produces tracked-safe schemas `home-gateway/p3-prelive-runtime-plan/v1`, `home-gateway/p3-prelive-runtime-receipt/v1`, `home-gateway/p3-prelive-cloud-firewall-receipt/v1`, and `home-gateway/p3-prelive-local-baseline-receipt/v1`.

- [ ] **Step 1: Write failing protected-root and strict-schema tests**

  Add behavioral Pester cases for a fixed local volume, clean absolute path, every existing ancestor non-reparse, no alternate data streams, protected non-inherited Access Control List (ACL), exact owner marker, bounded files, handle-stable identity, and exact property sets. Cover missing, extra, malformed, oversized, shared-write, Universal Naming Convention (UNC), removable-volume, and foreign-content failures.

  ```powershell
  It 'rejects an extra static trust property before creating the root' {
      $candidate = [ordered]@{
          schema = 'home-gateway/p3-prelive-trust-input/v1'
          ssh_host = 'host.invalid'
          ssh_user = 'homegateway'
          unexpected = $true
      } | ConvertTo-Json -Compress
      { $candidate | & $script:Runtime -Action PreparePlan -RuntimeRoot $script:Root } |
          Should -Throw '*trust input schema differs*'
      Test-Path -LiteralPath $script:Root | Should -BeFalse
  }

  It 'rejects a runtime root with inherited write access' {
      { & $script:Runtime -Action Validate -RuntimeRoot $script:Root `
          -ExpectedManifestSHA256 ('a' * 64) } | Should -Throw '*runtime ACL*'
  }
  ```

- [ ] **Step 2: Run the focused test and verify RED**

  ```powershell
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3PreliveRuntime.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: FAIL because `scripts/p3-prelive-runtime.ps1` does not exist.

- [ ] **Step 3: Implement canonical plans and protected file handling**

  Implement these entrypoint actions and exact internal interfaces:

  ```text
  Action: PreparePlan | Prepare | Validate | RecordCloudFirewall | ObserveLocalBaseline | CleanupPlan | Cleanup
  Resolve-P3FixedCleanPath(Path:string, Label:string) -> canonical local fixed-volume path:string
  Open-P3BoundedStableJson(Path:string, MaximumBytes:int, ExpectedProperties:string[]) -> parsed exact object
  Assert-P3ProtectedRuntimeRoot(Path:string, CurrentSID:SecurityIdentifier) -> validated directory item
  ConvertTo-P3CanonicalJson(Value:object) -> UTF-8 bytes with recursively ordinal-sorted object keys
  New-P3ManifestPlan(Trust:object, RuntimeRoot:string) -> sanitized plan object
  Install-P3ExactRuntimeFile(Bytes:byte[], Destination:string, ExpectedSHA256:string) -> installed file identity object
  ```

  Reuse the handle identity pattern already present in `scripts/p35-bootstrap-elevated.ps1`: open with reparse-point semantics, compare volume serial/file index before and during the exclusive read, and reject identity drift. Inspect `Get-Item -Stream *` and accept only the unnamed data stream. Create the root with protected ACL entries for SYSTEM, Administrators, and the current non-elevated user, with no inherited rule and no other identity.

  The canonical static manifest must have exactly these keys:

  ```json
  {
    "schema":"home-gateway/p3-prelive-trust-manifest/v1",
    "trust_sha256":"lowercase-64hex",
    "known_hosts_sha256":"lowercase-64hex",
    "public_key_fingerprint_sha256":"lowercase-64hex",
    "management_source_cidr_sha256":"lowercase-64hex",
    "git_ssh_agent_sha256":"lowercase-64hex",
    "git_ssh_add_sha256":"lowercase-64hex",
    "git_ssh_sha256":"lowercase-64hex",
    "git_scp_sha256":"lowercase-64hex",
    "local_payload_sha256":"lowercase-64hex",
    "remote_payload_sha256":"lowercase-64hex",
    "protocol_sha256":"lowercase-64hex",
    "accepted_server_baseline_sha256":"lowercase-64hex",
    "accepted_cloud_firewall_sha256":"lowercase-64hex"
  }
  ```

  `PreparePlan` computes and emits the prospective manifest/candidate hashes without creating a directory. `Prepare` requires `ExpectedManifestSHA256` plus a challenge matching `^P3-PRELIVE-RUNTIME-[0-9A-F]{16}$` and writes with create-new/atomic replacement semantics. `Cleanup` removes only the marker-owned child after a matching `CleanupPlan`; it never removes known-hosts, the SSH key, a profile, or any parent directory.

- [ ] **Step 4: Add Cloud Firewall and local baseline receipts**

  `RecordCloudFirewall` accepts only normalized owner-observed fields from standard input; it never calls DigitalOcean or stores an address. Require one Droplet association, Transmission Control Protocol (TCP) 22 with one `/32` source identity hash, User Datagram Protocol (UDP) 38556 from All IPv4, no UDP IPv6, no extra inbound rule, and observation age at most 900 seconds.

  `ObserveLocalBaseline` reads only local protected-profile existence and `Get-NetAdapter -IncludeHidden`. It stores zero/one counts and hashed adapter classes, never adapter names/GUIDs. Before Gate 6.5 it must prove `protected_profile_absent=true` and `selfhosted_adapter_count=0`; the action performs no native mutation.

  ```json
  {
    "schema":"home-gateway/p3-prelive-local-baseline-receipt/v1",
    "protected_profile_absent":true,
    "selfhosted_adapter_count":0,
    "redshield_class_count":1,
    "cisco_class_count":0,
    "observed_at_utc":"RFC3339 UTC",
    "live_mutation_performed":false
  }
  ```

- [ ] **Step 5: Run focused tests under both PowerShell engines**

  ```powershell
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3PreliveRuntime.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3PreliveRuntime.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: PASS with non-zero tests and no runtime directory outside `TestDrive`.

- [ ] **Step 6: Commit the runtime trust store**

  ```powershell
  git add -- scripts/p3-prelive-runtime.ps1 tests/windows-pester/P3PreliveRuntime.Tests.ps1
  git commit -m "feat(p3): add protected pre-live trust bundle"
  ```

### Task 2: Build the one-key Git OpenSSH agent lifecycle

**Files:**
- Create: `scripts/p3-ssh-agent.ps1`
- Create: `tests/windows-pester/P3SshAgent.Tests.ps1`

**Interfaces:**
- Consumes for `AgentPlan`: the prospective `PreparePlan` object, existing encrypted dedicated private/public key paths held in memory, expected public-key fingerprint hash, and candidate paths for Git `ssh-agent.exe`, `ssh-add.exe`, `ssh.exe`, and `scp.exe`.
- Consumes for `AgentStart`/`AgentValidate`/`AgentStop`: the prepared and validated protected runtime manifest plus the exact `AgentPlan` hash/challenge.
- Produces: actions `AgentPlan`, `AgentStart`, `AgentValidate`, and `AgentStop`; runtime-only `agent-receipt.json`; sanitized schema `home-gateway/p3-ssh-agent-receipt/v1`.

- [ ] **Step 1: Write failing toolchain, one-key, and cleanup tests**

  Use injected runners to prove that all four executables share one pinned Git installation root and match their hashes; pre-existing `SSH_AUTH_SOCK`/`SSH_AGENT_PID`, malformed agent output, zero/two keys, wrong fingerprint, process identifier (PID) reuse, and mixed Windows OpenSSH all stop. Prove every `AgentStart` failure calls cleanup only for the newly created PID and that `AgentStop` rejects a changed receipt.

  ```powershell
  It 'accepts exactly one expected key and the same Git toolchain root' {
      $receipt = Test-P3AgentState -Manifest $script:Manifest -AgentReceipt $script:Agent `
          -ListRunner { '256 SHA256:synthetic-key p3 (ED25519)' } `
          -ProcessRunner { [pscustomobject]@{ Id=4242; Path=$script:GitAgent } }
      $receipt.loaded_key_count | Should -Be 1
      $receipt.expected_key_match | Should -BeTrue
  }

  It 'destroys only the newly created agent when ssh-add fails' {
      { Start-P3Agent -Manifest $script:Manifest -AgentRunner $script:AgentRunner `
          -AddRunner { throw 'synthetic add failure' } -StopRunner $script:StopRunner } |
          Should -Throw '*ssh-add*'
      $script:StoppedPids | Should -Be @(4242)
  }
  ```

- [ ] **Step 2: Run the focused test and verify RED**

  ```powershell
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3SshAgent.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: FAIL because the agent lifecycle entrypoint does not exist.

- [ ] **Step 3: Implement plan/start/validate/stop**

  ```text
  Action: AgentPlan | AgentStart | AgentValidate | AgentStop
  Resolve-P3GitOpenSshToolchain(Manifest:object) -> exact four-tool identity object
  Start-P3Agent(Manifest:object, AgentRunner:scriptblock, AddRunner:scriptblock, StopRunner:scriptblock) -> agent receipt
  Test-P3AgentState(Manifest:object, AgentReceipt:object, ListRunner:scriptblock, ProcessRunner:scriptblock) -> sanitized validation receipt
  Stop-P3Agent(Manifest:object, AgentReceipt:object, DeleteRunner:scriptblock, StopRunner:scriptblock) -> stopped receipt
  ```

  `AgentPlan` is read-only, consumes the same prospective trust object as `PreparePlan`, and hashes the toolchain/public key before the runtime root exists; this removes any planning cycle. `AgentStart` revalidates those identities from the prepared manifest, requires a challenge matching `^P3-SSH-AGENT-[0-9A-F]{16}$`, refuses a pre-existing agent environment, starts the pinned agent, parses only one process identifier (PID)/socket pair, sets the current PowerShell process environment, then invokes pinned `ssh-add` with no passphrase argument or redirected passphrase. `AgentValidate` runs `ssh-add -l -E sha256`, requires exactly one expected fingerprint, and proves the PID/path/creation window. `AgentStop` runs `ssh-add -D`, terminates only that receipt-bound agent, clears only matching environment values, and removes only `agent-receipt.json`.

- [ ] **Step 4: Run focused tests under both engines**

  ```powershell
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3SshAgent.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3SshAgent.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: PASS; source/AST assertions find no passphrase channel, Windows OpenSSH path, private-key literal, `IdentityAgent=none`, or broad process termination.

- [ ] **Step 5: Commit the agent lifecycle**

  ```powershell
  git add -- scripts/p3-ssh-agent.ps1 tests/windows-pester/P3SshAgent.Tests.ps1
  git commit -m "feat(p3): add dedicated Git SSH agent lifecycle"
  ```

### Task 3: Build exact remote helper install and removal lifecycle

**Files:**
- Create: `scripts/p3-remote-helper.ps1`
- Create: `tests/windows-pester/P3RemoteHelper.Tests.ps1`

**Interfaces:**
- Consumes: validated runtime/agent receipts, the exact local Python payload, pinned Git `ssh`/`scp`, strict known-hosts, current `/32` consensus, and exact hash/challenge inputs.
- Produces: actions `RemoteInstallPlan`, `RemoteInstall`, `RemoteRemovePlan`, and `RemoteRemove`.
- Produces sanitized schemas `home-gateway/p3-remote-helper-install-plan/v1`, `home-gateway/p3-remote-helper-install-receipt/v1`, and `home-gateway/p3-remote-helper-remove-plan/v1`.

- [ ] **Step 1: Write failing absent/exact/conflict lifecycle tests**

  Drive the entrypoint through injected SSH/SCP runners. Require classifications:

  ```text
  absent  -> plan can produce one install candidate
  exact   -> install is an idempotent no-op and installed_by_gate=false
  conflict -> no scp, no remote write, no overwrite
  ```

  Cover wrong type, owner, group, mode, SHA-256, unexpected temporary file, stale plan, changed current egress, wrong agent receipt, failed upload hash, failed atomic move, and cleanup failure. Assert removal deletes only an `installed_by_gate=true` exact helper whose pre-install state was `absent`; a pre-existing exact helper is retained.

  ```powershell
  It 'never overwrites a conflicting remote path' {
      $plan = Invoke-P3RemoteInstallPlan -Context $script:Context -SshRunner {
          '{"state":"conflict","regular":true,"owner_match":false,"mode_match":true,"payload_sha256":"' + ('a' * 64) + '"}'
      }
      $plan.state | Should -BeExactly 'conflict'
      { Invoke-P3RemoteInstall -Context $script:Context -Plan $plan -ScpRunner { $script:ScpCalls++ } } |
          Should -Throw '*conflict*'
      $script:ScpCalls | Should -Be 0
  }
  ```

- [ ] **Step 2: Run the focused test and verify RED**

  ```powershell
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3RemoteHelper.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: FAIL because `scripts/p3-remote-helper.ps1` does not exist.

- [ ] **Step 3: Implement the shared pinned SSH argument contract**

  Build every SSH/SCP invocation from one function and reject arbitrary options:

  ```powershell
  function New-P3GitSshArguments([object]$Trust,[object]$Agent,[string[]]$RemoteCommand) {
      @(
          '-F','NUL',
          '-o','BatchMode=yes',
          '-o','IdentitiesOnly=yes',
          '-o','PreferredAuthentications=publickey',
          '-o','PasswordAuthentication=no',
          '-o','KbdInteractiveAuthentication=no',
          '-o','StrictHostKeyChecking=yes',
          '-o',"UserKnownHostsFile=$($Trust.known_hosts_path)",
          '-o','GlobalKnownHostsFile=NUL',
          '-o',"IdentityAgent=$($Agent.socket)",
          '-o','ConnectTimeout=10',
          "$($Trust.ssh_user)@$($Trust.ssh_host)"
      ) + $RemoteCommand
  }
  ```

  The contract requires exact user `homegateway`, strict IPv4 host grammar, three distinct HTTPS authorities with one current `/32` hash, exact known-hosts identity/hash, and the validated one-key agent before any SSH/SCP runner is called.

- [ ] **Step 4: Implement plan, atomic install, and scoped removal**

  Implement these exact internal interfaces before wiring the action switch:

  ```text
  Invoke-P3RemoteInstallPlan(Context:object, SshRunner:scriptblock) -> install plan
  Invoke-P3RemoteInstall(Context:object, Plan:object, ScpRunner:scriptblock, SshRunner:scriptblock) -> install receipt
  Invoke-P3RemoteRemovePlan(Context:object, InstallReceipt:object, SshRunner:scriptblock) -> remove plan
  Invoke-P3RemoteRemove(Context:object, InstallReceipt:object, RemovePlan:object, SshRunner:scriptblock) -> remove receipt
  ```

  `RemoteInstallPlan` uses only `sudo -n /usr/bin/stat` plus `/usr/bin/sha256sum` to return a sanitized classification for `/usr/local/libexec/home-gateway-p3-peer-guard`. `RemoteInstall` accepts only the matching plan hash and a challenge matching `^P3-REMOTE-INSTALL-[0-9A-F]{16}$`, uploads to one random gate-owned path, verifies it, installs to one create-new `.next` path as `root:root 0755`, then atomically renames to the final path. Traps remove upload/`.next` paths; cleanup failure is terminal.

  `RemoteRemovePlan` revalidates the installation receipt and exact current state. `RemoteRemove` requires a challenge matching `^P3-REMOTE-REMOVE-[0-9A-F]{16}$` and removes only the exact gate-installed hash when the receipt proves prestate `absent`. It never invokes `systemctl`, Docker, package tools, firewall tools, network tools, or peer commands.

  ```json
  {
    "schema":"home-gateway/p3-remote-helper-install-receipt/v1",
    "target_state":"exact",
    "payload_sha256":"lowercase-64hex",
    "owner_match":true,
    "mode_match":true,
    "installed_by_gate":true,
    "preinstall_state":"absent",
    "temporary_leftover_count":0
  }
  ```

- [ ] **Step 5: Run focused tests under both engines**

  ```powershell
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3RemoteHelper.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3RemoteHelper.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: PASS; fake runners prove no remote mutation for plan actions or conflict states.

- [ ] **Step 6: Commit the remote lifecycle**

  ```powershell
  git add -- scripts/p3-remote-helper.ps1 tests/windows-pester/P3RemoteHelper.Tests.ps1
  git commit -m "feat(p3): add exact remote helper lifecycle"
  ```

### Task 4: Turn the Python payload into the complete remote helper

**Files:**
- Modify: `scripts/p3-amnezia-peer-guard.py`
- Modify: `tests/python/test_p3_amnezia_peer_guard.py`

**Interfaces:**
- Consumes: one strict bounded JSON request on standard input, absolute allowlisted read-only Ubuntu commands, exact runtime selectors, expected hashes/counts, and a random operation nonce.
- Produces modes `attest`, `reconcile`, `guard admin`, `guard guest`, `client-observe`, and separately approved `emergency-rollback` under protocol `home-gateway/p3-peer-guard-protocol/v2`.
- Produces one JSON receipt for non-streaming modes and NDJSON events `ready_for_ui`, `candidate`, `stopped` for guard modes.

- [ ] **Step 1: Write failing strict request/collector tests**

  Add unit tests for exact keys/types/bounds, oversized input/output, invalid UTF-8, extra/missing fields, unsupported mode, command timeout/non-zero/stderr, raw-value redaction, exactly one container, immutable image/digest match, UDP 38556 publication, listener union, persistent IPv4 policy, IPv6 non-mutation, peer-set equality, and zero leftover counts.

  ```python
  def test_reconcile_rejects_one_mismatched_server_fact(self):
      request = reconcile_request()
      collector = FakeCollector(snapshot=server_snapshot(host_policy_loaded=False))
      with self.assertRaisesRegex(ValueError, "host policy"):
          guard.run_reconcile(request, collector=collector)

  def test_collector_never_emits_raw_peer_or_network_values(self):
      receipt = guard.run_reconcile(reconcile_request(), collector=FakeCollector())
      encoded = json.dumps(receipt, sort_keys=True)
      for forbidden in ("raw-peer", "172.18.", "docker0", "iptables -A"):
          self.assertNotIn(forbidden, encoded)
  ```

- [ ] **Step 2: Run the focused Python suite and verify RED**

  ```powershell
  python -m unittest discover -s .\tests\python -p "test_p3_amnezia_peer_guard.py"
  ```

  Expected: FAIL because protocol v2 modes and collectors are absent.

- [ ] **Step 3: Implement protocol v2 and strict dispatch**

  Replace `--automatic` with explicit subcommands while retaining `--self-test`. Define the test helpers `reconcile_request()`, `server_snapshot()`, and `FakeCollector` in the unit-test file; `FakeCollector` returns copied snapshots and records every requested collection mode.

  ```python
  from collections.abc import Callable, Iterator, Sequence
  from dataclasses import dataclass
  from typing import Any, BinaryIO, NamedTuple, TypeAlias

  @dataclass(frozen=True)
  class CommandResult:
      exit_code: int
      stdout: bytes
      stderr: bytes

  CommandRunner: TypeAlias = Callable[[Sequence[str], int, int], CommandResult]
  FileReader: TypeAlias = Callable[[pathlib.Path, int], bytes]
  Collector: TypeAlias = Callable[[dict[str, Any]], dict[str, Any]]
  Clock: TypeAlias = Callable[[], float]
  AtomicFilesystem: TypeAlias = Callable[[dict[str, Any]], dict[str, Any]]
  SyncconfRunner: TypeAlias = Callable[[pathlib.Path], None]

  PUBLIC_PROTOCOL = {
      "schema": "home-gateway/p3-peer-guard-protocol/v2",
      "modes": ["attest", "reconcile", "guard", "client-observe", "emergency-rollback"],
      "guard_operations": ["admin", "guest"],
      "events": ["ready_for_ui", "candidate", "stopped"],
      "poll_seconds": 2,
      "stable_seconds": 5,
      "maximum_guard_seconds": 180,
  }

  # Exact callable interfaces implemented in this task:
  # read_exact_request(BinaryIO, maximum_bytes=65536) -> dict[str, Any]
  # validate_request(mode:str, request:dict[str, Any]) -> dict[str, Any]
  # collect_server_snapshot(request, runner:CommandRunner, reader:FileReader) -> dict[str, Any]
  # run_reconcile(request, collector:Collector) -> dict[str, Any]
  # run_guard(operation, request, collector:Collector, clock:Clock) -> Iterator[dict[str, Any]]
  # run_client_observe(request, collector:Collector, clock:Clock) -> dict[str, Any]
  # run_emergency_rollback(request, filesystem:AtomicFilesystem, syncconf:SyncconfRunner) -> dict[str, Any]
  ```

  Use only absolute allowlisted executables: `/usr/bin/docker`, `/usr/bin/ss`, `/usr/sbin/iptables-save`, `/usr/sbin/ip6tables-save`, `/usr/bin/systemctl`, `/usr/bin/sha256sum`, and the resolved pinned `awg` executable. Commands have fixed argument templates, closed stdin, 10-second timeout, 128-KiB combined-output bound, and sanitized errors. Bounded exact config/metadata/temp paths come from the protected request, are validated under the selected container mounts, and are never returned.

- [ ] **Step 4: Implement complete reconciliation and guard streaming**

  `run_reconcile` returns hashes/counts/booleans only and fails on any mismatch. `run_guard` reconciles first, emits `ready_for_ui`, polls every two seconds, and accepts exact-plus-one only when persistent/live/metadata identities agree and two canonical snapshots match five seconds apart. Unknown removal/addition, runtime drift, restart delta, timeout, malformed state, or transport error emits one sanitized `stopped` event and exits non-zero.

  ```json
  {"event":"ready_for_ui","schema":"home-gateway/p3-peer-guard-event/v2","operation":"admin","pre_peer_count":1,"pre_peer_set_sha256":"lowercase-64hex","reconcile_sha256":"lowercase-64hex"}
  {"event":"candidate","schema":"home-gateway/p3-peer-guard-event/v2","operation":"admin","candidate_count":1,"candidate_fingerprint_sha256":"lowercase-64hex","pre_peer_set_sha256":"lowercase-64hex","post_peer_set_sha256":"lowercase-64hex","persistent_live_metadata_equal":true,"semantic_transition_count":1,"container_restart_delta":0,"firewall_equal":true,"listeners_equal":true,"official_ui_rollback_ready":true,"emergency_rollback_ready":true}
  ```

  Add deterministic tests for Admin and Guest metadata classification, partial convergence, replayed nonce, changing candidate, timeout at the exact deadline, extra event, EOF, and primary/rollback error separation.

- [ ] **Step 5: Implement nonce-bound client observation and exact emergency rollback**

  `client-observe` verifies the selected Guest fingerprint hash, samples handshake/counters before and after a 10-second bounded interval, and returns payload/protocol identities, nonce hash, freshness boolean, before/after counter hashes, traffic delta, and duration. No epoch or counter value is returned.

  `emergency-rollback` requires an exact candidate receipt hash, exact rollback-plan hash/challenge, unchanged candidate identity, and exact-plus-one state. It atomically removes one candidate block/metadata row/temp identity, invokes one `awg syncconf`, and proves restored persistent/live/metadata/temp/runtime hashes. Tests use temporary files and an injected syncconf runner; no system path is mutated.

- [ ] **Step 6: Run Python behavioral and static checks**

  ```powershell
  python -m unittest discover -s .\tests\python -p "test_p3_amnezia_peer_guard.py"
  python -m py_compile .\scripts\p3-amnezia-peer-guard.py
  ruff check .\scripts\p3-amnezia-peer-guard.py .\tests\python\test_p3_amnezia_peer_guard.py
  ruff format --check .\scripts\p3-amnezia-peer-guard.py .\tests\python\test_p3_amnezia_peer_guard.py
  python .\scripts\p3-amnezia-peer-guard.py --self-test
  ```

  Expected: PASS with non-zero unit tests and no remote/native mutation.

- [ ] **Step 7: Commit the complete helper**

  ```powershell
  git add -- scripts/p3-amnezia-peer-guard.py tests/python/test_p3_amnezia_peer_guard.py
  git commit -m "feat(p3): implement complete remote guard protocol"
  ```

### Task 5: Build local reconciliation and the bounded streaming launcher

**Files:**
- Modify: `scripts/p3-amnezia-peer-guard.ps1`
- Modify: `tests/windows-pester/P3AmneziaPeerGuard.Tests.ps1`

**Interfaces:**
- Consumes: validated runtime, Cloud Firewall, local-baseline, agent, and remote-install receipts plus protocol v2 request/receipt hashes.
- Produces: actions `ValidateOnly`, `Reconcile`, `GuardAdmin`, `GuardGuest`, `EmergencyRollbackPlan`, and `EmergencyRollback`.
- Produces `PRELIVE_READY=YES` only from `Reconcile`; emits `READY_FOR_UI=YES` only while a validated remote guard process remains armed.

- [ ] **Step 1: Replace attestation-only tests with full reconcile/streaming RED tests**

  Require that each mismatch in server/container/image/UDP/listener/host-policy/IPv6/peer/leftover, Cloud Firewall, local profile/adapter, agent, egress, host key, payload, or protocol blocks readiness. Add fake streaming SSH cases for ready→candidate, ready→stopped, candidate-before-ready, duplicate ready/candidate, malformed JSON, partial line, stderr, timeout, overflow, early EOF, and exit-code mismatch.

  ```powershell
  It 'prints READY only after all three reconciliation sources pass and the guard stays armed' {
      function New-FakeStreamingRunner([string[]]$Events) {
          return { param($Executable,$Arguments,$InputPath,$OutputPath,$ErrorPath) $Events }.GetNewClosure()
      }
      $events = @(
          '{"event":"ready_for_ui","schema":"home-gateway/p3-peer-guard-event/v2","operation":"guest"}',
          '{"event":"candidate","schema":"home-gateway/p3-peer-guard-event/v2","operation":"guest"}'
      )
      $result = Invoke-P3GuardStream -Context $script:Context -Operation guest `
          -Runner (New-FakeStreamingRunner $events)
      $result.ready_emitted | Should -BeTrue
      $result.candidate_received | Should -BeTrue
  }

  It 'never prints READY when the Cloud Firewall receipt is stale' {
      $script:Context.CloudFirewall.observed_at_utc = '2000-01-01T00:00:00Z'
      { Invoke-P3GuardStream -Context $script:Context -Operation admin `
          -Runner (New-FakeStreamingRunner @()) } | Should -Throw '*Cloud Firewall*'
  }
  ```

- [ ] **Step 2: Run the focused Pester test and verify RED**

  ```powershell
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3AmneziaPeerGuard.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: FAIL because current code accepts only attestation and exits before a guard window.

- [ ] **Step 3: Implement common pre-live context validation and request binding**

  ```text
  Action: ValidateOnly | Reconcile | GuardAdmin | GuardGuest | EmergencyRollbackPlan | EmergencyRollback
  Get-P3PreliveContext(RuntimeRoot:string, ExpectedManifestSHA256:string) -> validated context object
  Test-P3PreliveInputs(Context:object, NowUtc:DateTime) -> sanitized aggregate receipt
  New-P3RemoteRequest(Context:object, Mode:string, Operation:string, Nonce:string) -> exact request object
  Invoke-P3BoundedJsonSsh(Context:object, Request:object, TimeoutSeconds:int, MaximumBytes:int, Runner:scriptblock) -> exact receipt
  Invoke-P3GuardStream(Context:object, Operation:string, Runner:scriptblock) -> candidate receipt
  ```

  Revalidate protected root/manifest/file identities, exact agent PID/socket/key/toolchain, three-authority current `/32`, known-hosts identity, install receipt, payload/protocol hashes, Cloud Firewall age ≤900 seconds, local-baseline age ≤300 seconds, profile absence, and zero self-hosted adapters before SSH. Build only the fixed `attest`, `reconcile`, `guard admin`, `guard guest`, `client-observe`, and `emergency-rollback` remote commands. Send the bounded request through redirected standard input; no raw selector is placed in the command line.

- [ ] **Step 4: Implement bounded NDJSON streaming and exact terminal receipts**

  Use one `Start-Process` with redirected stdin/stdout/stderr, tail only complete UTF-8 lines, cap total output at 65536 bytes, and allow 190 seconds for the 180-second remote window plus transport shutdown. Reject any stderr byte. Validate exact event properties/order and bind every event to manifest, payload, protocol, nonce, operation, prestate, and installation receipt.

  The launcher writes `PRELIVE_READY=YES` after a successful standalone `Reconcile`. During `GuardAdmin`/`GuardGuest`, it writes `READY_FOR_UI=YES` only after the validated `ready_for_ui` event and while the child is alive; it returns success only after one validated `candidate` and clean SSH exit. A `stopped` event or abnormal transport returns sanitized failure without invoking rollback.

- [ ] **Step 5: Implement emergency rollback plan/apply separation**

  `EmergencyRollbackPlan` is read-only and binds the candidate receipt, current exact-plus-one observation, payload/protocol/install/manifest hashes, target fingerprint hash, rollback scope, and one expected `syncconf`. `EmergencyRollback` requires the exact plan SHA-256 and a challenge matching `^P3-EMERGENCY-ROLLBACK-[0-9A-F]{16}$`; no other action can select remote mutation mode.

- [ ] **Step 6: Run focused tests under both engines**

  ```powershell
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3AmneziaPeerGuard.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3AmneziaPeerGuard.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: PASS; `ValidateOnly` and all fake-runner tests make zero native network/SSH/UI mutation.

- [ ] **Step 7: Commit the local guard orchestrator**

  ```powershell
  git add -- scripts/p3-amnezia-peer-guard.ps1 tests/windows-pester/P3AmneziaPeerGuard.Tests.ps1
  git commit -m "feat(p3): gate UI readiness on complete reconciliation"
  ```

### Task 6: Bind the Windows client gate to the same attested helper

**Files:**
- Modify: `scripts/p3-client-gate.ps1`
- Modify: `tests/windows-pester/P3ClientGate.Tests.ps1`

**Interfaces:**
- Consumes: protected runtime/agent/install receipts, exact Guest/profile/client/known-hosts hashes, one protected PRE receipt for later equality checks, and the helper `client-observe` receipt.
- Produces existing actions `Preflight`, `PostConnect`, and `PostRollback`; production paths always collect current state. `ObservationPath` is legal only with `-TestOnlyFixture` and only under `TestDrive`/an injected test root.

- [ ] **Step 1: Write failing fixture-isolation and live-observer tests**

  Add tests that production `Preflight`, `PostConnect`, and `PostRollback` reject `ObservationPath`; test fixtures require `-TestOnlyFixture` plus an injected test root. Prove `PostConnect` rejects wrong/replayed nonce, stale duration, payload/protocol mismatch, selected Guest mismatch, no counter delta, wrong before/after counter hashes, extra fields, and the old `/usr/local/libexec/home-gateway-p3-peer-observe` path.

  ```powershell
  It 'rejects synthetic observation input outside explicit test mode' {
      { & $script:Gate -Action PostConnect -ObservationPath $script:Fixture `
          -ExpectedGuestPeerFingerprintSHA256 ('a' * 64) `
          -ExpectedEgressIdentitySHA256 ('b' * 64) `
          -ExpectedProfileSHA256 ('c' * 64) `
          -ExpectedClientSHA256 ('d' * 64) `
          -ExpectedKnownHostsSHA256 ('e' * 64) } | Should -Throw '*test-only*'
  }

  It 'binds client observation to one fresh nonce and protocol v2' {
      $receipt = Invoke-P3ClientPeerObservation -Context $script:Context `
          -Nonce $script:Nonce -Runner $script:ValidRunner
      $receipt.nonce_sha256 | Should -BeExactly $script:NonceSHA256
      $receipt.traffic_delta | Should -BeTrue
  }
  ```

- [ ] **Step 2: Run the focused Pester test and verify RED**

  ```powershell
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3ClientGate.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: FAIL because arbitrary observation files and the second remote observer are still accepted.

- [ ] **Step 3: Implement production/fixture separation and protected PRE equality**

  Add `[switch]$TestOnlyFixture`, `[string]$TestFixtureRoot`, `[string]$PreReceiptPath`, and `[string]$RuntimeRoot`. Require `ObservationPath` only when the switch is set and the path is a bounded regular non-reparse child of the injected test root. Production actions always call `Get-LiveClientObservation`.

  `Preflight` writes a protected PRE receipt containing current RedShield/Cisco class hashes and counts. `PostConnect`/`PostRollback` read that exact receipt through the protected runtime reader and compute equality themselves; remove `redshield_equals_pre` and `cisco_equals_pre` from runtime pins/fixture authority.

  ```powershell
  if (-not [string]::IsNullOrWhiteSpace($ObservationPath) -and -not $TestOnlyFixture) {
      throw 'ObservationPath is test-only'
  }
  if ($TestOnlyFixture -and [string]::IsNullOrWhiteSpace($ObservationPath)) {
      throw 'test-only fixture mode requires ObservationPath'
  }
  ```

- [ ] **Step 4: Replace the second observer with `client-observe`**

  Add the exact interface `Invoke-P3ClientPeerObservation(Context:object, Nonce:string, Runner:scriptblock) -> client-observe receipt`, then reuse the same validated Git SSH context and remote helper path as Task 5.

  Generate a cryptographically random 32-byte nonce, send it only in the bounded stdin request, and validate exact schema:

  ```json
  {
    "schema":"home-gateway/p3-peer-client-observe/v2",
    "payload_sha256":"lowercase-64hex",
    "protocol_sha256":"lowercase-64hex",
    "nonce_sha256":"lowercase-64hex",
    "selected_guest_match":true,
    "handshake_fresh":true,
    "before_counter_sha256":"lowercase-64hex",
    "after_counter_sha256":"lowercase-64hex",
    "traffic_delta":true,
    "observation_duration_seconds":10
  }
  ```

  Retain current read-only client binary/signature, adapter, route, and three HTTPS egress checks. Never import, connect, disconnect, remove a profile, mutate an adapter, or emit raw identities.

- [ ] **Step 5: Run focused tests under both engines**

  ```powershell
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3ClientGate.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '& { Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force; $r=Invoke-Pester -Path .\tests\windows-pester\P3ClientGate.Tests.ps1 -PassThru; if ($r.Result -ne "Passed" -or $r.TotalCount -eq 0) { exit 1 } }'
  ```

  Expected: PASS; source/AST scan contains no second observer, synthetic production bypass, raw host/address/profile output, or network mutation command.

- [ ] **Step 6: Commit the client observation closure**

  ```powershell
  git add -- scripts/p3-client-gate.ps1 tests/windows-pester/P3ClientGate.Tests.ps1
  git commit -m "fix(p3): bind client gate to attested peer observer"
  ```

### Task 7: Document, validate, and independently review Task 6A

**Files:**
- Modify: `docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md`
- Modify: `docs/runbooks/P3_WINDOWS_CLIENT_ACTIVATION.md`
- Modify: `STATUS.md`
- Runtime operator ledger (ignored): `.superpowers/sdd/2026-08-30-p3-pc-core-ready-completion/progress.md`
- Runtime phase report (ignored): `.superpowers/sdd/2026-08-30-p3-pc-core-ready-completion/task-6a-report.md`

**Interfaces:**
- Consumes: committed Tasks 1-6 and their focused RED/GREEN evidence.
- Produces: exact operator order, separately named live candidates, one validation report, and consolidated QA/security GO on committed HEAD.

- [ ] **Step 1: Update runbooks with the exact execution order**

  Document these separately approved future gates without marking any as run:

  ```text
  Gate 6.4L -> Prepare protected bundle; start/validate one-key agent
  Gate 6.4R-pre -> RemoteInstallPlan; owner-observed Cloud Firewall and local-baseline receipts
  Gate 6.4P -> Install one exact inert helper
  Gate 6.4R-post -> Attest the installed helper; run server and combined reconciliation
  Gate 6.5A -> Guarded one-Admin GUI action
  Gate 6.5B -> Guarded one-Guest GUI action and protected native export
  Gate 6.6  -> Exact profile import/connect plus nonce-bound client observation
  Gate 7.2, adapter loss, reboot, Gate 7.3 -> remain separately candidate-bound
  emergency rollback -> separate exact candidate only
  ```

  State that the helper remains installed and inert through P3, that `AgentStop` is mandatory at each terminal path, and that no live gate inherits authority from Task 6A approval.

- [ ] **Step 2: Run PowerShell parser checks before the full batch**

  ```powershell
  & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command '$errors=$null; Get-ChildItem .\scripts\p3-*.ps1 | ForEach-Object { [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$null,[ref]$errors) }; if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }'
  & pwsh.exe -NoLogo -NoProfile -NonInteractive -Command '$errors=$null; Get-ChildItem .\scripts\p3-*.ps1 | ForEach-Object { [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$null,[ref]$errors) }; if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }'
  ```

  Expected: both exit `0` with no parser errors.

- [ ] **Step 3: Run the complete offline validation batch once**

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

  Expected: five Go packages PASS; Python/Pester discover non-zero tests with zero failures; `py_compile`, Ruff, PS5/PS7 parser checks, full verify, govulncheck, gosec, gitleaks, governance, toolchain checks, and `git diff --check` PASS.

- [ ] **Step 4: Write the phase report and commit docs/status**

  Record exact commit range, RED/GREEN commands, test counts, exit codes, sanitized notable output, unresolved risks, and `LIVE_ACTION_PERFORMED=NO`. Do not copy runtime paths, hosts, addresses, keys, profiles, or transcripts.

  ```powershell
  git diff --check
  git add -- docs/runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md docs/runbooks/P3_WINDOWS_CLIENT_ACTIVATION.md STATUS.md
  git commit -m "docs(p3): record pre-live guard readiness"
  ```

  Keep the SDD ledger/report ignored and never force-add them.

- [ ] **Step 5: Obtain one consolidated independent QA/security review**

  Review the committed Task 6A range against the accepted spec for strict schema/provenance, protected runtime ACL and identity, one-key Git toolchain, shell/argument injection, host-key/egress trust, atomic install/removal, zero plan-mode mutation, complete reconcile coverage, NDJSON state machine, exact-plus-one semantics, nonce/replay resistance, emergency rollback scope, fixture isolation, secret leakage, PowerShell 5.1/7 behavior, and runbook/live-boundary accuracy.

  The reviewer returns `GO` only with no Critical/Important finding. If findings exist, the same implementation agent performs one consolidated fix pass, runs affected focused checks plus the full validation batch once, commits the fix, and the reviewer checks the new committed range.

- [ ] **Step 6: Stop at the first live approval boundary**

  After final committed QA/security GO, generate the exact sanitized `Gate 6.4L` candidate from `AgentPlan` plus `PreparePlan`. Present its manifest/toolchain/key-fingerprint hashes, challenge, scope, cleanup, and stop conditions. Do not execute `Prepare`, `AgentStart`, SSH, SCP, or DigitalOcean UI observation until that exact candidate receives separate approval.

---

## Plan self-review checklist

- Every accepted design section maps to Tasks 1-7.
- All production observation paths collect current state; fixture files require explicit test-only mode.
- The only persistent remote artifact is `/usr/local/libexec/home-gateway-p3-peer-guard`.
- Runtime preparation, agent mutation, read-only SSH/UI observation, remote install, Admin, Guest, client activation, Windows mutation, adapter loss, reboot, restore, and emergency rollback remain distinct approvals.
- The implementation phase ends with committed full validation and consolidated independent review, not with a live readiness claim based on offline tests alone.
