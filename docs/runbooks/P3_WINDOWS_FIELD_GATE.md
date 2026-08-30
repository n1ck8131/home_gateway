# P3 Windows field gate

This is a tracked offline field package, not authorization to change a VPN, peer, profile, adapter, route, DNS, firewall, service, task or host. All live steps require their separate exact approval and a committed/reviewed HEAD.

## Evidence contract

`p3-windows-field-matrix.ps1` accepts one bounded observation for exactly one action and emits one `home-gateway/p3-windows-field-matrix/v1` record. Raw public addresses, DNS servers, targets, adapter names/GUIDs, routes and packet contents remain in memory/runtime-only inputs; tracked or retained evidence contains only hashes, counts, booleans and bounded elapsed seconds.

The actions are `PreApply`, `PendingQuickCheck`, `CommittedMatrix`, `TunnelDown`, `ProcessRecovery`, `AdapterLoss`, `RebootRecovery` and `RollbackVerify`. The package covers direct/self-hosted/Cisco egress, DNS, IPv4/IPv6, MTU, TCP/UDP/QUIC, tunnel-down blocking, process recovery, adapter loss, reboot recovery and emergency disable. Observation actions contain no mutation command. Tunnel-down may target only the new self-hosted client profile; RedShield and Cisco must remain equal to PRE.

## Two-session Apply/Confirm

Use two elevated PowerShell sessions after exact live approval:

1. Session A starts candidate-bound `p35-canary.ps1 -Action Apply` with the exact `CandidateSHA256` and `P35-APPLY-*` challenge. It waits for resolution. Record its child exit code.
2. Session B immediately captures the bounded observation and runs `p3-windows-field-matrix.ps1 -Action PendingQuickCheck -MaxDurationSeconds 90` with the exact `CandidateSHA256`, `StateRootIdentity` and pending deadline returned by the trusted `hgctl windows canary status` record. Save the single sanitized JSON record, calculate its SHA-256, and record the matrix child exit code.
3. Only if PendingQuickCheck exit is zero and elapsed time is at most 90 seconds, Session B invokes exact candidate-bound `Confirm` with `QuickCheckRecordPath` and `QuickCheckRecordSHA256`. Confirm re-reads trusted pending status immediately, strictly parses the hashed record, verifies candidate/root/deadline/creation-time binding, and calculates the remaining watchdog time itself; `QuickCheckElapsedSeconds`, when supplied for compatibility, must equal the record and is never the trusted clock.
4. The canary watchdog deadline is 120 seconds. The 90-second combined quick-check ceiling preserves at least a 30-second safety margin. Timeout, stale/missing record, any failed check or any nonzero child exit causes no Confirm; Session A must observe automatic rollback.
5. Capture the Confirm child exit code and Session A final exit code. Do not infer success from a launched process or partial output.

## Ordered matrix and rollback

Run `PreApply` before Apply, `CommittedMatrix` only after successful confirmation, then the explicitly approved fault observations one at a time. Process/tunnel/adapter/reboot manipulation is performed only by the operator under its own approval; the matrix merely observes the resulting bounded state.

For a client anomaly, remove only the new local Amnezia profile and preserve the server Guest pending separate approval. For a server anomaly, use the candidate-specific official-UI receipt; emergency exact-one-peer rollback is separate. `Clear server from Amnezia software` remains prohibited. Finish with `RollbackVerify`, requiring self-hosted absence, RedShield/Cisco equality to PRE and emergency-disable evidence where applicable.

P3 is terminal only after network `FullRestore` and the independently planned/approved `RestoreConfigAcl` both pass. Pass the completed network `RecoveryPlanSHA256` as `NetworkRestorePlanSHA256` to both `RestoreConfigAclPlan` and `RestoreConfigAcl`; the one-way binding preserves the monotonic network-then-ACL contract without retrying network restoration. Offline/Pester results are not live field acceptance.
