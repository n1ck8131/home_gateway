# P3.5 Persistent Sink Routes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add manifest-bound persistent loopback sink routes so every P3.5 canary and imported DNS target fails closed across tunnel loss and reboot, then restores the original Windows network state exactly.

**Architecture:** Keep transient RedShield routes in the existing `ManagedRoute` contract and add a separate `SinkArtifact`, logical sink snapshot state, and native sink mutation operations. Apply sinks first, verify the effective RedShield path after transient routes are present, retain sinks during emergency disable, and remove them last during full restore.

**Tech Stack:** Go 1.25, Windows PowerShell 5.1, NetTCPIP CIM cmdlets, Pester, existing immutable revision manifests and transaction journal.

**Spec:** `docs/superpowers/specs/2026-08-26-p35-persistent-sink-routes-design.md`

## Global Constraints

- Never disconnect, restart or reconfigure RedShield or Cisco.
- Do not run live route, firewall, NRPT, service, adapter or Task Scheduler mutation commands while implementing this plan.
- Keep `ManagedRoute` fixed to `ActiveStore`; sinks use their own `PersistentStore` contract.
- Every canary and imported DNS host prefix has exactly one `/32` or `/128` sink on loopback interface index `1`.
- Keep `ReservedRouteMetric = 42751`; use `ReservedSinkMetric = 65535` and verify actual route selection instead of trusting metrics alone.
- Preserve every unowned route, firewall rule and NRPT rule; exact collisions in either route store fail before mutation.
- Existing confirmation tokens, protected runtime root, pinned executable/module resolution, journal and watchdog boundaries remain mandatory.
- `EmergencyDisable` retains sinks. `FullRestore` removes sinks last and is the selected terminal state.
- Stage only explicit paths. Do not add `.p35-run/` or the external `Netherlands.conf` to Git.
- No Python files are in scope; record `RUFF_NOT_APPLICABLE_NO_PYTHON` in the phase report.

---

### Task 1: Immutable sink artifact and canary planner

**Files:**
- Modify: `internal/revisions/apply/transaction.go`
- Create: `internal/system/windows/sinks.go`
- Create: `internal/system/windows/sinks_test.go`
- Modify: `internal/system/windows/artifacts.go`
- Modify: `internal/system/windows/canary.go`
- Modify: `internal/system/windows/canary_test.go`
- Modify: `internal/system/windows/runtime.go`
- Modify: `internal/system/windows/runtime_test.go`

**Interfaces:**
- Consumes: existing `AddressFamily`, `artifactSet`, `apply.Candidate`, `ManagedRoute` and canary target normalization.
- Produces: `SinkArtifact`, `SinkRoute`, `SinkState`, `ResolvedRoute`, `sinkTupleKey`, `sinkForVPNRoute`, `apply.Candidate.Sinks`, and a four-file Windows revision manifest.

- [ ] **Step 1: Write failing schema and planner tests**

Add table tests that require exact host prefixes, loopback index `1`, same-family unspecified next hop, `PersistentStore`, `NetMgmt`, metric `65535`, journal ownership, no duplicates, and one-to-one coverage with every VPN route. Extend the happy-path canary test with:

```go
artifacts, err := parseArtifacts(
    plan.Candidate.RevisionID,
    plan.Candidate.Routes,
    plan.Candidate.Sinks,
    plan.Candidate.Firewall,
    plan.Candidate.DNS,
)
if err != nil {
    t.Fatal(err)
}
if len(artifacts.sinks.Routes) != len(plan.TargetPrefixes) {
    t.Fatalf("sink count = %d, targets = %d", len(artifacts.sinks.Routes), len(plan.TargetPrefixes))
}
for _, route := range artifacts.sinks.Routes {
    if route.InterfaceIndex != LoopbackInterfaceIndex || route.Metric != ReservedSinkMetric || route.PolicyStore != SinkPolicyStore {
        t.Fatalf("unsafe sink route: %#v", route)
    }
}
```

Add a regression where IPv6 has no default route but loopback is qualified; `BuildCanaryPlan` must succeed and generate the IPv6 sink. Add negative cases for omitted DNS sink, extra sink, `/64`, wrong next hop, wrong metric and duplicate destination.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
go test ./internal/system/windows -run 'Test(SinkArtifact|BuildCanaryPlan)' -count=1
```

Expected: compile failure because `Candidate.Sinks`, sink types and the five-argument `parseArtifacts` do not exist.

- [ ] **Step 3: Implement the strict sink contract**

Add the Windows-only candidate field:

```go
type Candidate struct {
    RevisionID string
    NFT        []byte
    Firewall   []byte
    DNS        []byte
    Routes     []byte
    Sinks      []byte
}
```

Define the sink types in `sinks.go`:

```go
const (
    ReservedSinkMetric    = uint32(65535)
    SinkPolicyStore       = "PersistentStore"
    LoopbackInterfaceIndex = 1
)

type SinkArtifact struct {
    Version  int         `json:"version"`
    Owner    string      `json:"owner"`
    Revision string      `json:"revision"`
    Routes   []SinkRoute `json:"routes"`
}

type SinkRoute struct {
    Family         AddressFamily `json:"family"`
    Destination    string        `json:"destination"`
    NextHop        string        `json:"next_hop"`
    InterfaceIndex int           `json:"interface_index"`
    Metric         uint32        `json:"metric"`
    PolicyStore    string        `json:"policy_store"`
    Protocol       string        `json:"protocol"`
    JournalOwned   bool          `json:"journal_owned"`
}
```

Add `sinks SinkArtifact` to `artifactSet`, require `windows-sinks.v1.json` in canonical staging/manifests, and enforce exact bidirectional VPN-route/sink coverage in `artifactSet.validate`. `BuildCanaryPlan` must build a sink for every normalized target after DNS targets are added, marshal it into `Candidate.Sinks`, include it in `ConfirmationChallenge`, expose `SinkCount`, and stop requiring a same-family physical default merely to prove fail-closed coverage.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run:

```powershell
go test ./internal/system/windows -run 'Test(SinkArtifact|BuildCanaryPlan|LoadQualifiedEndpoints)' -count=1
go test ./internal/revisions/apply -run 'TestTransaction' -count=1
```

Expected: both commands exit `0`; Windows manifests contain exactly four canonical artifacts, while generic transaction tests remain compatible with an unused `Sinks` field.

- [ ] **Step 5: Commit Task 1**

```powershell
git add -- internal/revisions/apply/transaction.go internal/system/windows/sinks.go internal/system/windows/sinks_test.go internal/system/windows/artifacts.go internal/system/windows/canary.go internal/system/windows/canary_test.go internal/system/windows/runtime.go internal/system/windows/runtime_test.go
git commit -m "feat: add P3.5 persistent sink artifacts"
```

### Task 2: Runtime ordering, recovery and exact restore

**Files:**
- Modify: `internal/system/windows/sinks.go`
- Modify: `internal/system/windows/runtime.go`
- Modify: `internal/system/windows/runtime_test.go`
- Modify: `internal/system/windows/production_test.go`

**Interfaces:**
- Consumes: Task 1 sink types and artifact coverage.
- Produces: `MutationBackend.PutSink`, `MutationBackend.RemoveSink`, `MutationBackend.ResolveRoute`, sink-aware snapshots, additive-first activation and sink-aware recovery modes.

- [ ] **Step 1: Write failing runtime and fault-injection tests**

Extend the fake backend with sink state, operation recording and route-resolution faults. Assert this successful ordering:

```go
wantOrder := []string{
    "put-sink", "put-firewall", "add-vpn-route", "resolve-redshield", "put-nrpt",
}
```

Add independent failures for sink add, sink post-check, resolver choosing loopback, resolver ambiguity, rollback sink restore, stale-sink pruning and sink removal. Add reboot state containing persistent sinks/firewall but no transient route; reconcile must reinstall the transient route without exposing a physical effective path. Assert `EmergencyDisable` leaves the sink keys unchanged and `FullRestore` records `remove-sink` after VPN route, NRPT, firewall and endpoint removal.

- [ ] **Step 2: Run the runtime tests and verify RED**

Run:

```powershell
go test ./internal/system/windows -run 'TestWindows.*(Sink|EmergencyDisable|FullRestore|Reconcile|Fault)' -count=1
```

Expected: compile failures for the three new backend methods and sink snapshot fields.

- [ ] **Step 3: Extend the structured backend and snapshots**

Use these exact signatures:

```go
type MutationBackend interface {
    Snapshot(context.Context) (MutationSnapshot, error)
    PutSink(context.Context, SinkState) error
    RemoveSink(context.Context, SinkState) error
    ResolveRoute(context.Context, AddressFamily, string) (ResolvedRoute, error)
    AddRoute(context.Context, RouteState) error
    RemoveRoute(context.Context, RouteState) error
    PutFirewall(context.Context, FirewallState) error
    RemoveFirewall(context.Context, FirewallState) error
    PutNRPT(context.Context, NRPTState) error
    RemoveNRPT(context.Context, NRPTState) error
    Reload(context.Context) error
}

type SinkState struct {
    Route             SinkRoute `json:"route"`
    Owner             string    `json:"owner,omitempty"`
    Revision          string    `json:"revision,omitempty"`
    PersistentPresent bool      `json:"persistent_present"`
    ActivePresent     bool      `json:"active_present"`
}

type ResolvedRoute struct {
    Family         AddressFamily `json:"family"`
    Destination    string        `json:"destination"`
    InterfaceGUID  string        `json:"interface_guid,omitempty"`
    InterfaceIndex int           `json:"interface_index"`
    NextHop        string        `json:"next_hop"`
    RouteMetric    uint32        `json:"route_metric"`
    NoRoute        bool          `json:"no_route,omitempty"`
}
```

Add `Sinks []SinkState` to `MutationSnapshot` and `managedSnapshot`. Ownership verification must reject unowned exact destination collisions from either store, incomplete owned store pairs, revision drift, non-loopback tuples and over-limit inventories.

- [ ] **Step 4: Implement transaction and recovery ordering**

Update `applyArtifacts` to put sinks before firewall, repeat snapshot validation after firewall, add transient VPN routes, then require `ResolveRoute` to return the exact qualified RedShield interface for every target before NRPT. Update `applyManagedSnapshot`, stale pruning, `filterManagedSnapshot`, semantic snapshot validation, equality helpers and foreign-state keys.

`removeSelectiveOwned` must leave sinks intact. `removeAllOwned` must remove sinks after VPN routes, NRPT, firewall and endpoint routes. Extend `RecoveryPlan` with `RetainSinks`, `RemoveSinks` and `RestoreSinks` counts. A partial sink operation returns an error and leaves durable recovery state unchanged for retry.

- [ ] **Step 5: Run the runtime package and verify GREEN**

Run:

```powershell
go test ./internal/system/windows -run 'TestWindows|TestSink|TestProduction' -count=1
```

Expected: exit `0`, including sink fault injection, reboot reconciliation, emergency disable and full restore ordering.

- [ ] **Step 6: Commit Task 2**

```powershell
git add -- internal/system/windows/sinks.go internal/system/windows/runtime.go internal/system/windows/runtime_test.go internal/system/windows/production_test.go
git commit -m "feat: integrate sinks with Windows recovery"
```

### Task 3: Native Windows persistent-store implementation

**Files:**
- Modify: `internal/system/windows/native_backend_windows.go`
- Modify: `internal/system/windows/native_backend_windows_test.go`
- Modify: `internal/system/windows/native_paths_windows.go`

**Interfaces:**
- Consumes: Task 2 `MutationBackend` additions and sink/effective-route types.
- Produces: bounded native `put_sink`, `remove_sink` and `resolve_route` operations; persistent-route inventory; registry/tombstone reconciliation.

- [ ] **Step 1: Write failing native request/response and recovery tests**

Add runner tests that inspect decoded requests rather than matching interpolated scripts. Cover:

```go
request.Operation == "put_sink"
request.Sink.Route.InterfaceIndex == LoopbackInterfaceIndex
request.Sink.Route.PolicyStore == SinkPolicyStore
```

Require snapshot parsing to join the exact persistent tuple with its ActiveStore copy, reject duplicate store records, and preserve unowned persistent routes for collision checks. Add tests for pre-mutation tombstones, success publication, command failure, post-check failure, reboot completion, stale intent and exact dual-store removal. Add resolver fixtures for RedShield, loopback, ambiguous output, and the exact Windows error `1231` as `NoRoute`; all other errors must fail closed.

- [ ] **Step 2: Run native tests and verify RED**

Run:

```powershell
go test ./internal/system/windows -run 'TestNativeMutationBackend.*(Sink|Resolve|Registry|Reboot)' -count=1
```

Expected: compile failures because native sink methods and raw JSON shapes do not exist.

- [ ] **Step 3: Implement bounded native sink operations**

Extend the ownership registry with a separate `sinks` map keyed by the canonical sink tuple. Keep a versioned reader that accepts the previous registry only as an empty-sink state and atomically publishes the current version without claiming any OS route. Persist intent before invoking PowerShell and reconcile only exact observed tuples.

The fixed PowerShell program must:

```powershell
NetTCPIP\New-NetRoute `
    -AddressFamily $family `
    -DestinationPrefix $destination `
    -InterfaceIndex 1 `
    -NextHop $nextHop `
    -RouteMetric 65535 `
    -Protocol NetMgmt `
    -Confirm:$false `
    -ErrorAction Stop
```

Omitting `-PolicyStore` is intentional for the documented persistent-plus-active creation behavior. Post-check exact canonical fields in both `Get-NetRoute -PolicyStore PersistentStore` and `Get-NetRoute -PolicyStore ActiveStore`. Removal first targets the owned PersistentStore tuple, then removes an exact remaining ActiveStore copy if present, and verifies both stores are empty. Never use wildcard removal or an unresolved interface identity.

`resolve_route` uses pinned `NetTCPIP\Find-NetRoute`, accepts exactly one selected route, maps the selected interface index back to the authoritative adapter snapshot, and returns only structured fields. Treat only the already-tested CIM error shape for Windows System Error `1231` as `NoRoute`.

- [ ] **Step 4: Run native and package tests and verify GREEN**

Run:

```powershell
go test ./internal/system/windows -run 'TestNativeMutationBackend|TestNativeMutationScript' -count=1
go test ./internal/system/windows -count=1
```

Expected: both commands exit `0`; no test invokes real NetTCPIP mutation.

- [ ] **Step 5: Commit Task 3**

```powershell
git add -- internal/system/windows/native_backend_windows.go internal/system/windows/native_backend_windows_test.go internal/system/windows/native_paths_windows.go
git commit -m "feat: add native Windows persistent sinks"
```

### Task 4: CLI evidence, watchdog semantics and architecture record

**Files:**
- Modify: `internal/hgctlcmd/live_canary.go`
- Modify: `internal/hgctlcmd/live_canary_test.go`
- Modify: `internal/system/windows/canary_watchdog_windows_test.go`
- Create: `docs/adr/ADR-0013-windows-persistent-sink-routes.md`
- Modify: `docs/adr/ADR-0012-windows-offline-mutation-ownership.md`
- Modify: `docs/ACCEPTANCE_MATRIX.md`

**Interfaces:**
- Consumes: sink counts, recovery plans and runtime state from Tasks 1-3.
- Produces: redacted plan/status JSON that reports sink readiness and restore counts; durable watchdog tests; accepted ADR for the deliberate P3.4 route-store exception.

- [ ] **Step 1: Write failing CLI and watchdog tests**

Require plan/status JSON to include `sink_count`, `persistent_sink_ready`, and `remove_sinks`/`retain_sinks` recovery counts without route destinations or config contents. Verify the apply confirmation challenge changes if the sink artifact changes. Verify successful full restore disarms both exact owned watchdog tasks, while a retryable restoring failure leaves recovery armed.

- [ ] **Step 2: Run CLI/watchdog tests and verify RED**

Run:

```powershell
go test ./internal/hgctlcmd ./internal/system/windows -run 'TestRunCanary|TestDurableCanaryWatchdog' -count=1
```

Expected: assertions fail because sink fields and the new recovery counts are not exposed.

- [ ] **Step 3: Implement redacted output and document the decision**

Add only counts/booleans to the CLI response; never serialize target prefixes, DNS server addresses, adapter names or config material. Keep all existing confirmation tokens unchanged.

ADR-0013 records the dedicated persistent-sink exception, exact loopback/store contract, additive-first ordering, emergency-disable retention, full-restore-last removal and the separate live mutation gate. Update ADR-0012 with a one-paragraph pointer that its transient-route rule still applies to `ManagedRoute`, while ADR-0013 governs sinks. Mark the acceptance matrix as `offline-implemented` only after the tests pass; keep live canary and `pc-core-ready` as `field-not-run`.

- [ ] **Step 4: Run CLI/watchdog tests and verify GREEN**

Run:

```powershell
go test ./internal/hgctlcmd ./internal/system/windows -run 'TestRunCanary|TestDurableCanaryWatchdog' -count=1
git diff --check
```

Expected: both commands exit `0` and output remains redacted.

- [ ] **Step 5: Commit Task 4**

```powershell
git add -- internal/hgctlcmd/live_canary.go internal/hgctlcmd/live_canary_test.go internal/system/windows/canary_watchdog_windows_test.go docs/adr/ADR-0013-windows-persistent-sink-routes.md docs/adr/ADR-0012-windows-offline-mutation-ownership.md docs/ACCEPTANCE_MATRIX.md
git commit -m "feat: expose P3.5 sink recovery evidence"
```

### Task 5: Phase verification and report

**Files:**
- Create: `docs/reports/2026-08-26-p35-persistent-sinks.md`
- Modify: `STATUS.md`
- Modify: `docs/superpowers/plans/2026-08-24-p03-redshield-windows.md`

**Interfaces:**
- Consumes: completed implementation and fresh validation output.
- Produces: bounded offline phase evidence and an explicit remaining live-field gate.

- [ ] **Step 1: Run the focused integration batch**

Run:

```powershell
go test ./internal/system/windows ./internal/hgctlcmd ./internal/revisions/apply -count=1
```

Expected: exit `0` with no real route/firewall/DNS/task mutations.

- [ ] **Step 2: Run exact PowerShell compatibility tests**

Run under Windows PowerShell 5.1:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "Invoke-Pester -Path '.\tests\windows-pester\P35SinkPreflight.Tests.ps1' -EnableExit"
```

Run under PowerShell 7:

```powershell
pwsh.exe -NoLogo -NoProfile -NonInteractive -Command "Invoke-Pester -Path '.\tests\windows-pester\P35SinkPreflight.Tests.ps1' -EnableExit"
```

Expected: both exit `0`. These tests are parser/contract evidence and must not invoke live mutation.

- [ ] **Step 3: Run the full repository gate once**

Run:

```powershell
.\scripts\dev.ps1 -Command verify
```

Expected: exit `0` for Go tests, Pester, formatting, vet, staticcheck, gosec, govulncheck, secret/workflow checks and reproducible builds.

- [ ] **Step 4: Write the evidence report and status boundary**

Record exact commands, exit codes, test counts and `RUFF_NOT_APPLICABLE_NO_PYTHON`. Record the already supplied read-only preflight as `ready=true`, `exit_code=0`, PktMon stopped/no filters, no exact active/persistent collisions, qualified IPv4 default, qualified IPv6 no-route, and connected IPv4/IPv6 loopback. Do not copy config contents or sensitive target data.

Set P3.5 status to `offline implementation complete; live safety matrix pending separate authorization`. Do not mark `pc-core-ready`. List the live matrix and terminal `FullRestore` as the only remaining P3.5 field evidence.

- [ ] **Step 5: Check the final diff and commit Task 5**

Run:

```powershell
git diff --check
git status --short
```

Confirm `.p35-run/` is the only untracked operational directory and is not staged. Then:

```powershell
git add -- docs/reports/2026-08-26-p35-persistent-sinks.md STATUS.md docs/superpowers/plans/2026-08-24-p03-redshield-windows.md
git commit -m "docs: record P3.5 offline sink evidence"
```

### Task 6: Consolidated phase review

**Files:**
- Review only: all commits after `313876d`
- Modify only if the consolidated reviewer reports a confirmed Critical or Important finding.

**Interfaces:**
- Consumes: the complete P3.5 implementation diff and phase report.
- Produces: one correctness/security/acceptance verdict and, if required, one consolidated fix pass.

- [ ] **Step 1: Dispatch one read-only consolidated reviewer**

The reviewer checks spec compliance, foreign-state preservation, route-store semantics, command injection boundaries, crash/reboot behavior, emergency-disable retention, full-restore ordering, secret redaction and fresh test evidence. The reviewer must return findings ordered Critical, Important, Minor and an explicit GO/NO-GO for offline completion.

- [ ] **Step 2: Apply at most one consolidated fix pass**

If Critical or Important findings are confirmed, send the complete list to the same implementation worker, require focused regression tests, then re-run only affected checks plus the full repository gate once after fixes. Commit the fix with explicit paths.

- [ ] **Step 3: Stop at the live mutation gate**

Report the offline result and exact remaining field command/rollback envelope. Do not run apply, adapter-loss, tunnel-down, reboot or full-restore mutations until the owner explicitly authorizes that live batch.
