# Phase 3.4 Windows/MSYS Agent Lifecycle Design

## Goal

Eliminate the unsafe assumption that the `SSH_AGENT_PID` emitted by Git for
Windows is a Windows process identifier. Preserve that emitted value for the
agent environment while binding validation and cleanup to the independently
owned Windows process identifier.

## Approved scope

- Local code, tests, receipts, and offline candidate generation only.
- No live `ssh-agent`, `ssh-add`, SSH, HTTPS, VPN, route, DNS, firewall,
  adapter, Cisco, server, or cloud mutation during implementation and tests.
- A later live retry requires a fresh nonce-bound Phase 3.4 candidate and a
  separate exact approval.

## Identity contract

The lifecycle has two different identifiers:

- `agent_pid`: the positive integer parsed from emitted `SSH_AGENT_PID`; it is
  used only for `SSH_AGENT_PID`, environment comparison, and audit evidence.
- `windows_process_id`: the positive Windows `Process.Id` returned by the
  controller-owned process launch; it is the only identifier accepted by
  `Get-Process`, `Stop-Process`, wait, and re-observation boundaries.

The raw receipt advances to `home-gateway/p3-ssh-agent-receipt/v2` and includes
both identifiers. The combined receipt advances to
`home-gateway/p3-ssh-agent-combined-receipt/v3`, includes both identifiers, and
records `agent_pid_match` and `windows_process_id_match` separately.

## Launch contract

The injected `AgentRunner` returns exactly one structured launch record:

```text
schema: home-gateway/p3-windows-agent-launch/v1
output: bounded ssh-agent shell output records
started_at_utc: Windows process start instant in UTC
windows_process_id: positive Windows Process.Id
```

The production runner launches the already pinned and hash-validated
`ssh-agent.exe` as `-D -s`. Foreground mode prevents the launcher from losing
ownership through a fork. Output collection is bounded by time, record count,
and bytes. Any timeout, malformed launch record, wrong process identity, path,
hash, or start-time binding is terminal.

`Start-P3Agent` validates the observed Windows process before parsing emitted
shell output or loading the key. If a later startup step fails, PID-based
cleanup targets only the already validated `windows_process_id`; the emitted
`agent_pid` never reaches a Windows process boundary. A zero, ambiguous,
wrong-ID, wrong-path, or wrong-start-time observation performs no PID-based
stop because the identifier could already have been reused by a foreign
process. Native launcher failures are cleaned through the still-owned process
handle, and kill or bounded-wait failure is terminal.

## Interactive key loading

The production `AddRunner` starts the pinned `ssh-add.exe` in a normal visible
Windows console and waits for its exit code. Standard input/output are not
redirected, the passphrase is never passed as an argument or environment value,
and no passphrase or key material is captured or logged. A non-zero exit code is
terminal and triggers owned-agent cleanup.

## Compatibility and migration

All exact-property validators, protected receipts, runtime contexts, remote
helper paths, guard paths, and Pester fixtures migrate atomically to the new
schemas. No legacy protected agent receipt exists in the current Phase 3.4 base
root, so no on-disk compatibility reader is required.

## Acceptance criteria

1. A regression fixture with emitted `agent_pid=77` and
   `windows_process_id=26484` keeps `SSH_AGENT_PID=77` while every process
   validation, stop, wait, and re-observation call receives only `26484`.
2. Malformed output after an exact observation cleans up only `26484`.
3. Zero, multiple, wrong-path, wrong-start-time, or wrong-ID process
   observations fail closed before `ssh-add` and never call a PID-based stop.
4. The visible `ssh-add` boundary is argument-safe, does not redirect secrets,
   and treats non-zero exit as failure.
5. Focused Pester passes in Windows PowerShell 5.1 and PowerShell 7; the full
   repository verification gate and independent security/correctness review
   pass.
6. The worktree is committed and clean before generating a new offline
   nonce-bound Phase 3.4 candidate.
