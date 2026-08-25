# ADR-0012: Windows offline mutation ownership and recovery

Status: Accepted

## Context

P3.3 qualified the Windows inventory and dry-run boundary without exposing mutation. P3.4 needs a testable Windows apply model that preserves the RedShield provider endpoint, physical direct paths, Cisco/system routes and all unowned state, while keeping live changes behind a separate approval gate.

## Decision

Windows desired state is split into strict versioned route, firewall and NRPT artifacts. A candidate is accepted only when every provider endpoint matches an independently qualified canonical host prefix, every VPN-class route uses the active RedShield adapter, every live default path is a stable physical adapter, and every VPN-class prefix has an exact outbound block on every physical default interface. Default routes, protected-prefix overlaps, stale GUIDs and unowned ownership collisions fail before mutation.

Project-created routes use transient `ActiveStore`, `NetMgmt`, a reserved metric and journal ownership; they are reconciled before policy activation after restart. Fail-closed firewall rules use `PersistentStore` and deterministic revision-qualified identities. NRPT rules retain the exact OS-generated identity returned by the backend. Provider/OS-owned endpoint routes may be asserted as evidence but are never claimed or removed. These store semantics follow the Microsoft contracts for [New-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute) and [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule).

Apply is additive-first: endpoint protection, firewall blocks, VPN routes and NRPT are established before stale project state is pruned. Immutable revisions carry SHA-256 manifests. Before/LKG snapshots contain project-owned state only, carry digest sidecars and are semantically matched back to immutable artifacts before replay.

The shared transaction journal records pending confirmation, committed/LKG state, degraded rollback retry, disabling/disabled and restoring/restored intent. Timeout, process restart, incomplete pending publication and recovery-operation faults remain retryable. Emergency disable removes only project VPN routes, firewall and NRPT while preserving endpoint routes; full restore returns project state to the first-install snapshot.

## Consequences

P3.4 proves the mutation and recovery state machine offline, but does not make Windows apply available. `MutationBackend` is injected and structured; the runtime package has no native executor, PowerShell mutation, CLI integration or live network side effect. A protected runtime root is a deployment prerequisite. P3.5/P3.6 must implement and separately approve the native adapter, operator flow, bounded live canary and uninstall field evidence.

## Verification

Fault tests cover malformed artifacts, virtual-default TOCTOU, endpoint mismatch, ownership collisions, dual-stack ordering, replacement/pruning, activation/reload/post-check failures, timeout, mid-activation restart, missing manifests, persistent recovery faults, snapshot corruption, emergency disable and full restore. The 2026-08-25 phase gate passed focused Windows/apply/dataplane tests and the full repository `verify` batch without live mutation.
