# P3.5 Domain Name System (DNS) and Cisco overlap diagnostics implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Return a deterministic redacted Plan result when an explicit target or imported DNS server overlaps provider or Cisco protection, without weakening any P3.5 mutation guard.

**Architecture:** Retain provenance while the Windows planner normalizes and merges canary targets, then return a typed isolation error containing only fixed enums and bounded counts. The CLI recognizes only that typed error and emits JSON with exit code `3`; the PowerShell Plan launcher forwards both while Apply and Confirm continue to fail before transaction creation.

**Tech Stack:** Go 1.26.6, Go standard library `errors`, `encoding/json`, and `net/netip`, Windows PowerShell 5.1, PowerShell 7, Pester 6.0.0, existing P3.5 planner and CLI contracts.

**Spec:** `docs/superpowers/specs/2026-08-26-p35-dns-cisco-overlap-diagnostics-design.md`

**Content type:** How-to implementation plan

**Audience:** The single P3.5 implementation owner and the independent consolidated reviewer.

**Content plan:** Implement planner classification, CLI output, PowerShell forwarding, evidence, and one final review in that order.

**Open questions:** None. The approved specification fixes all architecture and live-safety decisions.

## Global constraints

- Never disconnect, restart, or reconfigure RedShield or Cisco.
- Do not run live route, firewall, Name Resolution Policy Table (NRPT), DNS, adapter, service, Task Scheduler, Apply, Confirm, rollback, recovery, or `FullRestore` commands while implementing this plan.
- Keep the current hash-pinned RedShield profile blocked. Diagnostics do not authorize a live retry.
- Keep planner and runtime provider, Cisco, and system overlap decisions unchanged in meaning.
- Plan remains non-elevated and read-only. Apply and Confirm must rebuild the exact plan before challenge checking or transaction creation.
- Never serialize config paths, config hashes, config contents, keys, endpoints, targets, DNS addresses, prefixes, adapter names, adapter GUIDs, or protected-route values.
- Successful Plan JSON keeps its existing field set and values. New block fields are absent on success.
- Only a typed canary isolation error receives structured block JSON. Every other planner error keeps its existing stderr behavior.
- The supported PowerShell child-process entry point returns native exit code `3` for a structured Plan block. Other live and recovery actions keep `Invoke-CheckedHgctl` semantics.
- One implementation owner executes Tasks 1 through 4 sequentially. One independent consolidated reviewer checks the completed diff. Neither agent delegates further.
- Stage only explicit paths. Never add or inspect `.p35-run/` or the external `C:\Users\HappyUser\Desktop\Netherlands.conf`.
- No Python file is in scope. Record `RUFF_NOT_APPLICABLE_NO_PYTHON` in implementation evidence.
- Before Task 1, the controller records the exact implementation base with `$implementationBase = (git rev-parse HEAD).Trim()` and gives that SHA to the final reviewer.

---

### Task 1: Typed Windows isolation classification

**Files:**
- Modify: `internal/system/windows/canary.go:17-249`
- Modify: `internal/system/windows/canary.go:361-415`
- Test: `internal/system/windows/canary_test.go:141-199`

**Interfaces:**
- Consumes: `AddressFamily`, `maxManagedRoutes`, `overlapsAny`, `canaryTargetPrefixes`, `addCanaryDNSTargets`, `DirectRouteAssertion`, and normalized Windows adapter attribution.
- Produces: `CanaryIsolationBlockCode`, `CanaryTargetSource`, `CanaryProtectedClass`, `CanaryIsolationBlock`, `CanaryIsolationError`, and `(*CanaryIsolationError).RedactedBlocks()`.
- Preserves: `BuildCanaryPlan(Inventory, tunnel.Inspection, CanaryRequest) (CanaryPlan, error)` and every existing success-path artifact.

- [ ] **Step 1: Write failing classification tests**

Add `errors` to `canary_test.go`. Add `TestBuildCanaryPlanClassifiesIsolationBlocks` with these exact cases:

```go
tests := []struct {
    name string
    request CanaryRequest
    mutate func(*Inventory, *tunnel.Inspection)
    want []CanaryIsolationBlock
}{
    {name: "explicit provider ipv4"},
    {name: "imported DNS provider ipv6"},
    {name: "explicit Cisco ipv6"},
    {name: "imported DNS Cisco ipv4"},
    {name: "same target from both sources"},
    {name: "multiple Cisco routes count one target"},
}
```

Use `qualifiedCanaryInput()` for every case. Start with this valid request, then apply the listed override:

```go
request := CanaryRequest{
    Revision: "p35-canary-isolation",
    TargetAddresses: []string{"198.51.100.10"},
    DNSNamespace: CanaryDNSNamespace,
}
```

Set exact synthetic values as follows:

- `explicit provider ipv4`: target `203.0.113.5`
- `imported DNS provider ipv6`: DNS `2001:db8:ffff::5`
- `explicit Cisco ipv6`: add Cisco route `2001:db8:abcd::/48`, target `2001:db8:abcd::53`
- `imported DNS Cisco ipv4`: DNS `10.50.0.53`, using the existing `10.50.0.0/16` Cisco route
- `same target from both sources`: add Cisco route `198.51.100.0/24`, use `198.51.100.10` as both explicit target and DNS
- `multiple Cisco routes count one target`: add Cisco routes `198.51.100.0/24` and `198.51.100.10/32`, use explicit target `198.51.100.10`

Require these exact redacted results:

| Case | Expected buckets |
| --- | --- |
| `explicit provider ipv4` | `explicit_target`, `provider_endpoint`, `ipv4`, count `1` |
| `imported DNS provider ipv6` | `imported_dns`, `provider_endpoint`, `ipv6`, count `1` |
| `explicit Cisco ipv6` | `explicit_target`, `cisco_prefix`, `ipv6`, count `1` |
| `imported DNS Cisco ipv4` | `imported_dns`, `cisco_prefix`, `ipv4`, count `1` |
| `same target from both sources` | two IPv4 Cisco buckets, one per source, each count `1` |
| `multiple Cisco routes count one target` | one explicit IPv4 Cisco bucket with count `1` |

Assert the typed error and its redacted blocks without printing the unsafe input:

```go
_, err := BuildCanaryPlan(inventory, inspection, test.request)
var blocked *CanaryIsolationError
if !errors.As(err, &blocked) {
    t.Fatalf("error type = %T, want *CanaryIsolationError", err)
}
blocks, ok := blocked.RedactedBlocks()
if !ok || !slices.Equal(blocks, test.want) {
    t.Fatalf("blocks = %#v, valid = %v", blocks, ok)
}
if blocked.Error() != "canary target isolation failed" {
    t.Fatalf("unsafe error text = %q", blocked.Error())
}
```

- [ ] **Step 2: Write failing validation and ordering tests**

Add `TestCanaryIsolationErrorValidatesRedactedBlocks`. Require rejection for an empty list, more than eight buckets, unknown enum values, count `0`, count above `maxManagedRoutes`, duplicate rank, and non-canonical order.

Use this canonical expected order:

```go
wantOrder := []CanaryIsolationBlock{
    {TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv4, AffectedTargetCount: 1},
    {TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv6, AffectedTargetCount: 1},
    {TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv4, AffectedTargetCount: 1},
    {TargetSource: CanaryTargetSourceExplicit, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv6, AffectedTargetCount: 1},
    {TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv4, AffectedTargetCount: 1},
    {TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassProviderEndpoint, Family: FamilyIPv6, AffectedTargetCount: 1},
    {TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv4, AffectedTargetCount: 1},
    {TargetSource: CanaryTargetSourceImportedDNS, ProtectedClass: CanaryProtectedClassCiscoPrefix, Family: FamilyIPv6, AffectedTargetCount: 1},
}
```

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```powershell
& .\.tools\go\bin\go.exe test ./internal/system/windows -run 'Test(BuildCanaryPlanClassifiesIsolationBlocks|CanaryIsolationErrorValidatesRedactedBlocks)$' -count=1
```

Expected: compile failure because the typed isolation constants and types do not exist.

- [ ] **Step 4: Add the typed redaction contract**

Add these declarations near the canary constants:

```go
const CanaryIsolationBlockCode = "canary_target_isolation"

type CanaryTargetSource string
const (
    CanaryTargetSourceExplicit CanaryTargetSource = "explicit_target"
    CanaryTargetSourceImportedDNS CanaryTargetSource = "imported_dns"
)

type CanaryProtectedClass string
const (
    CanaryProtectedClassProviderEndpoint CanaryProtectedClass = "provider_endpoint"
    CanaryProtectedClassCiscoPrefix CanaryProtectedClass = "cisco_prefix"
)
```

Add the bounded error payload:

```go
type CanaryIsolationBlock struct {
    TargetSource CanaryTargetSource `json:"target_source"`
    ProtectedClass CanaryProtectedClass `json:"protected_class"`
    Family AddressFamily `json:"family"`
    AffectedTargetCount int `json:"affected_target_count"`
}

type CanaryIsolationError struct {
    Blocks []CanaryIsolationBlock
}

func (*CanaryIsolationError) Error() string {
    return "canary target isolation failed"
}
```

Implement `RedactedBlocks()` so it returns a cloned slice only when all conditions hold:

- block count is between `1` and `8`
- every enum is one of the declared constants
- every count is between `1` and `maxManagedRoutes`
- every bucket rank is strictly greater than the previous rank
- no duplicate `(source, class, family)` bucket exists

Rank blocks as `sourceRank*4 + protectedRank*2 + familyRank`, with enum order matching `wantOrder`.

- [ ] **Step 5: Retain provenance through target normalization**

Use one unexported target record instead of a bare prefix:

```go
type canaryTarget struct {
    prefix netip.Prefix
    explicit bool
    importedDNS bool
}
```

Change `canaryTargetPrefixes` to return `[]canaryTarget` with `explicit: true`. Change `addCanaryDNSTargets` to set `importedDNS: true` on an existing record or append a new record. Keep explicit duplicate rejection, DNS compaction, address validation, and prefix sorting unchanged.

After DNS merge, return a generic bounded-limit error when `len(targets) > maxManagedRoutes`. Update route, sink, firewall, and `TargetPrefixes` loops to use `target.prefix`; do not alter the generated prefixes or artifact counts.

- [ ] **Step 6: Classify inside the existing isolation guard**

Change the guard signature to:

```go
func validateCanaryTargetIsolation(
    targets []canaryTarget,
    assertions []DirectRouteAssertion,
    inventory Inventory,
) error
```

Build separate provider and Cisco prefix slices using the current parsing and adapter checks. For each target, call the existing `overlapsAny` once per protected class, then increment each applicable source bucket once.

Construct `CanaryIsolationError.Blocks` by iterating fixed source, protected-class, and family slices in canonical order. Return the typed error when at least one bucket exists; otherwise return `nil`.

- [ ] **Step 7: Format, run focused tests, and verify GREEN**

Run:

```powershell
& .\.tools\go\bin\gofmt.exe -w internal\system\windows\canary.go internal\system\windows\canary_test.go
& .\.tools\go\bin\go.exe test ./internal/system/windows -run 'Test(BuildCanaryPlan|CanaryIsolationError)' -count=1
```

Expected: PASS. Existing bounded artifact and IPv6 sink tests must remain green.

- [ ] **Step 8: Commit Task 1**

```powershell
git add -- internal/system/windows/canary.go internal/system/windows/canary_test.go
git commit -m "feat: classify P3.5 canary isolation blocks"
```

---

### Task 2: Redacted CLI output and live fail-before-mutation proof

**Files:**
- Modify: `internal/hgctlcmd/canary.go:26-155`
- Test: `internal/hgctlcmd/run_test.go:231-310`
- Test: `internal/hgctlcmd/live_canary_test.go:187-310`

**Interfaces:**
- Consumes: `CanaryIsolationBlockCode`, `CanaryIsolationBlock`, `CanaryIsolationError`, and `(*CanaryIsolationError).RedactedBlocks()` from Task 1.
- Produces: optional `block_code` and `block_details` fields in `canaryPlanOutput`, plus `canaryBlockedPlanOutput(canaryPlanCommand, error) (canaryPlanOutput, bool)`.
- Preserves: success Plan fields, challenge inputs, `collectCanaryPlan` wrapping, and `runCanaryLive` transaction ordering.

- [ ] **Step 1: Write the failing blocked-Plan JSON test**

Add `commandCiscoGUID` beside the existing test GUIDs. Add `TestRunWindowsCanaryPlanReturnsRedactedIsolationJSON`.

Build the fixture from `commandCanaryInputs()`, append a Cisco adapter, and append this route:

```go
inventory.Adapters = append(inventory.Adapters, windowssystem.Adapter{
    Name: "Cisco", Index: 31, InterfaceGUID: commandCiscoGUID,
    Kind: windowssystem.AdapterCisco, Up: true,
})
inventory.Routes = append(inventory.Routes, windowssystem.Route{
    Family: windowssystem.FamilyIPv4, Destination: "10.20.30.0/24",
    NextHop: "0.0.0.0", InterfaceIndex: 31,
    InterfaceGUID: commandCiscoGUID, Metric: 1,
})
```

Run `runCanaryPlan` with the existing synthetic config path, state root, and public explicit target. Assert code `3`, empty stderr, and one JSON document. Assert `ready_for_live_gate` and `live_mutation_performed` are false, counts are zero, `block_code` is `canary_target_isolation`, and the only block is imported DNS, Cisco prefix, IPv4, count `1`.

Unmarshal a second time into `map[string]json.RawMessage` and require both challenge keys to be absent. Search stdout and stderr for every synthetic config path, state root, DNS address, Cisco prefix, provider endpoint, explicit target, adapter name, and adapter GUID; none may appear.

- [ ] **Step 2: Strengthen success compatibility and invalid-payload tests**

Extend `TestRunWindowsCanaryPlanIsReadOnlyRedactedAndChallengeBound` to require this exact success key set:

```go
wantKeys := []string{
    "mode", "revision", "ready_for_live_gate",
    "live_mutation_performed", "route_count", "sink_count",
    "persistent_sink_ready", "firewall_rule_count", "dns_rule_count",
    "confirmation_challenge", "confirm_timeout_seconds",
}
```

Sort the observed keys before comparison. Require `block_code` and `block_details` to be absent.

Add `TestCanaryBlockedPlanOutputRejectsInvalidTypedData`. Wrap a `CanaryIsolationError` containing an unknown source or zero count with `%w`, call `canaryBlockedPlanOutput`, and require `ok == false`.

- [ ] **Step 3: Write the failing Apply and Confirm guard test**

Add `TestRunCanaryLiveRejectsIsolationBeforeMutation` to `live_canary_test.go`. Use the same DNS and Cisco overlap fixture for both actions:

```go
deps := dependencies{
    backend: staticInspectionBackend{inspection: inspection},
    collect: staticCollector{inventory: inventory},
    resolve: func(context.Context, string) ([]string, error) {
        return []string{"203.0.113.5"}, nil
    },
    validateStateRoot: func(string) error { return nil },
    validateConfigSource: func(string) error { return nil },
}
for _, action := range []string{"apply", "confirm"} {
    t.Run(action, func(t *testing.T) {
        root := filepath.Join(t.TempDir(), "state")
        mutationCalls := 0
        deps.newMutation = func(string) (windowssystem.MutationBackend, error) {
            mutationCalls++
            return nil, errors.New("must not construct mutation backend")
        }
    })
}
```

Inside each subtest, run this exact command and assert the boundary:

```go
command := canaryLiveCommand{
    action: action,
    plan: canaryPlanCommand{
        configPath: `C:\private-provider-source.conf`,
        configSHA256: strings.Repeat("a", 64),
        stateRoot: root,
        revision: "p35-canary-blocked",
        targets: []string{"198.51.100.10"},
        dnsNamespace: windowssystem.CanaryDNSNamespace,
    },
    liveConfirm: "P35-APPLY-DOES-NOT-EXIST",
}
var stdout, stderr bytes.Buffer
if code := runCanaryLive(command, &stdout, &stderr, deps); code != 3 {
    t.Fatalf("code = %d, stderr = %q", code, stderr.String())
}
```

Require exit code `3`, zero mutation calls, empty stdout, no state root, no journal, and fixed redacted stderr. Search stderr for every synthetic address, prefix, path, adapter value, and config hash.

- [ ] **Step 4: Run the focused tests and verify RED**

Run:

```powershell
& .\.tools\go\bin\go.exe test ./internal/hgctlcmd -run 'Test(RunWindowsCanaryPlanReturnsRedactedIsolationJSON|CanaryBlockedPlanOutputRejectsInvalidTypedData|RunCanaryLiveRejectsIsolationBeforeMutation)$' -count=1
```

Expected: compile failure because `canaryBlockedPlanOutput` and block output fields do not exist, or assertion failure because Plan writes only stderr.

- [ ] **Step 5: Extend the Plan output without changing success**

Change only these tags and fields in `canaryPlanOutput`:

```go
ConfirmationChallenge string `json:"confirmation_challenge,omitempty"`
ConfirmTimeoutSeconds int `json:"confirm_timeout_seconds,omitempty"`
BlockCode string `json:"block_code,omitempty"`
BlockDetails []windowssystem.CanaryIsolationBlock `json:"block_details,omitempty"`
```

Implement the classifier:

```go
func canaryBlockedPlanOutput(
    command canaryPlanCommand,
    err error,
) (canaryPlanOutput, bool) {
    var blocked *windowssystem.CanaryIsolationError
    if !errors.As(err, &blocked) {
        return canaryPlanOutput{}, false
    }
    details, ok := blocked.RedactedBlocks()
    if !ok {
        return canaryPlanOutput{}, false
    }
    return canaryPlanOutput{
        Mode: "plan", Revision: command.revision,
        ReadyForLiveGate: false, LiveMutationPerformed: false,
        BlockCode: windowssystem.CanaryIsolationBlockCode,
        BlockDetails: details,
    }, true
}
```

In `runCanaryPlan`, handle this output before printing the generic error:

```go
if err != nil {
    if output, ok := canaryBlockedPlanOutput(command, err); ok {
        if code := encodeJSON(stdout, stderr, output); code != 0 {
            return code
        }
        return 3
    }
    fmt.Fprintln(stderr, err)
    return errorCode
}
```

Do not change `collectCanaryPlan`; its `%w` wrapping is required for `errors.As`. Do not add structured output to `runCanaryLive`.

- [ ] **Step 6: Format and verify the focused CLI/live tests GREEN**

Run:

```powershell
& .\.tools\go\bin\gofmt.exe -w internal\hgctlcmd\canary.go internal\hgctlcmd\run_test.go internal\hgctlcmd\live_canary_test.go
& .\.tools\go\bin\go.exe test ./internal/hgctlcmd -run 'Test(RunWindowsCanaryPlan|CanaryBlockedPlanOutput|RunCanaryLiveRejectsIsolation)' -count=1
```

Expected: PASS. The existing successful Plan and full fake Apply, Confirm, and `FullRestore` tests must remain unchanged.

- [ ] **Step 7: Run both affected Go packages together**

```powershell
& .\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd -count=1
```

Expected: PASS with no live Windows mutation.

- [ ] **Step 8: Commit Task 2**

```powershell
git add -- internal/hgctlcmd/canary.go internal/hgctlcmd/run_test.go internal/hgctlcmd/live_canary_test.go
git commit -m "feat: emit redacted P3.5 plan blocks"
```

---

### Task 3: PowerShell Plan exit forwarding

**Files:**
- Modify: `scripts/p35-canary.ps1:331-353`
- Test: `tests/windows-pester/P35Canary.Tests.ps1`

**Interfaces:**
- Consumes: the Task 2 contract that a valid isolation block writes one JSON object and returns native code `3`.
- Produces: `Invoke-HgctlPlan`, used only by the non-elevated Plan branch.
- Preserves: `Invoke-CheckedHgctl` for Apply, Confirm, status, and recovery actions.

- [ ] **Step 1: Write the failing cross-runtime forwarding test**

Set the platform flag at file scope. Extend `BeforeAll` to retain one parsed abstract syntax tree (AST) for the launcher:

```powershell
$script:IsNativeWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$script:Tokens = $null
$script:ParseErrors = $null
$script:Ast = [Management.Automation.Language.Parser]::ParseFile(
    $script:Canary,
    [ref]$script:Tokens,
    [ref]$script:ParseErrors
)
```

Add a Windows-only test:

```powershell
It 'forwards blocked Plan JSON and exit 3 in both PowerShell runtimes' -Skip:(-not $script:IsNativeWindows) {
    $engines = @(
        (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
        (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop).Source
    )
}
```

Inside the test, resolve the one function definition and write a TestDrive native stub plus a child driver:

```powershell
$definition = @($script:Ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-HgctlPlan'
}, $true))
$definition.Count | Should -Be 1
$expected = '{"mode":"plan","ready_for_live_gate":false}'
$stub = Join-Path $TestDrive 'fake-hgctl.cmd'
$stubText = "@echo off`r`necho $expected`r`nexit /b 3`r`n"
[IO.File]::WriteAllText($stub, $stubText, [Text.Encoding]::ASCII)
```

Build and run the child driver with the exact absolute stub path:

```powershell
$stubLiteral = $stub.Replace("'", "''")
$driver = Join-Path $TestDrive 'invoke-hgctl-plan.ps1'
$driverText = $definition[0].Extent.Text + "`r`n" +
    "Invoke-HgctlPlan -Executable '$stubLiteral' -Arguments @()`r`n"
[IO.File]::WriteAllText($driver, $driverText, [Text.UTF8Encoding]::new($false))
foreach ($engine in $engines) {
    $stderrPath = Join-Path $TestDrive ((Split-Path $engine -Leaf) + '.stderr')
    $output = @(& $engine -NoLogo -NoProfile -NonInteractive -File $driver 2>$stderrPath)
    $exitCode = $LASTEXITCODE
    $exitCode | Should -Be 3
    ($output -join [Environment]::NewLine) | Should -Be $expected
    [IO.File]::ReadAllText($stderrPath) | Should -BeNullOrEmpty
}
```

Add a cross-platform AST assertion:

```powershell
$commands = @($script:Ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst]
}, $true))
@($commands | Where-Object { $_.GetCommandName() -ceq 'Invoke-HgctlPlan' }).Count |
    Should -Be 1
@($commands | Where-Object { $_.GetCommandName() -ceq 'Invoke-CheckedHgctl' }).Count |
    Should -BeGreaterThan 1
```

Also require the launcher text to match the Plan branch call and retain `Invoke-CheckedHgctl` calls after the Plan branch.

- [ ] **Step 2: Run Pester and verify RED**

Run under both supported engines:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
```

Expected: failure because `Invoke-HgctlPlan` does not exist and Plan still maps code `3` to a generic exception.

- [ ] **Step 3: Add the Plan-only process boundary**

Add this function beside `Invoke-CheckedHgctl`:

```powershell
function Invoke-HgctlPlan {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $Executable @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 3) { exit 3 }
    if ($exitCode -ne 0) { throw "hgctl failed with exit code $exitCode" }
}
```

Replace only the Plan branch call:

```powershell
Invoke-HgctlPlan -Executable $resolvedHgctl -Arguments $arguments
return
```

Do not change `Invoke-CheckedHgctl` or any Apply, Confirm, status, or recovery branch.

- [ ] **Step 4: Run PowerShell syntax and behavior tests GREEN**

Run the same two `dev.ps1 -Command pester` commands from Step 2.

Expected: PASS in Windows PowerShell 5.1 and PowerShell 7. On Linux CI, the cross-runtime behavior test skips while AST and Go contract tests still run.

- [ ] **Step 5: Run affected Go and Pester checks once together**

```powershell
& .\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd -count=1
pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
```

Expected: PASS. No command may invoke the real config, protected state root, or Windows network mutation.

- [ ] **Step 6: Commit Task 3**

```powershell
git add -- scripts/p35-canary.ps1 tests/windows-pester/P35Canary.Tests.ps1
git commit -m "fix: preserve P3.5 plan block exit code"
```

---

### Task 4: Architecture evidence and final repository gate

**Files:**
- Create: `docs/adr/ADR-0014-p35-redacted-canary-block-diagnostics.md`
- Modify: `docs/ACCEPTANCE_MATRIX.md:48-50`
- Modify: `docs/reports/2026-08-26-p35-persistent-sinks.md`
- Modify: `docs/superpowers/plans/2026-08-24-p03-redshield-windows.md:3-81`

**Interfaces:**
- Consumes: the verified code and launcher behavior from Tasks 1 through 3.
- Produces: an accepted architecture record and honest offline evidence. It does not change the live gate status.
- Preserves: `field-precheck-blocked`, current-profile NO-GO, separate live authorization, and the open `pc-core-ready` gate.

- [ ] **Step 1: Write the architecture record**

Create ADR-0014 with this structure and exact safety conclusion:

```markdown
# ADR-0014: P3.5 redacted canary block diagnostics

Status: Accepted

## Context

P3.5 Plan rejects a target that overlaps a provider endpoint or Cisco protected prefix. Merged targets currently lose the source needed for a safe diagnosis.

## Decision

Retain target provenance until the existing isolation check. Return only fixed source, protected-class, family, and bounded count fields for a typed isolation error. JSON Plan returns exit code `3` and no challenge; Apply and Confirm remain blocked before transaction creation.

## Consequences

The guard has no bypass. The current profile remains incompatible. A future profile requires its own hash, preflight, Plan, and live authorization.

## Verification

Focused planner, CLI, live-boundary, and PowerShell tests prove redaction, deterministic counts, success compatibility, and no pre-transaction mutation.
```

The Decision section must also record these details:

- retain target provenance only until isolation classification
- return fixed source, protected-class, family, and affected-target-count fields
- validate at most eight canonically ordered buckets with counts no greater than `maxManagedRoutes`
- emit structured JSON only for typed Plan isolation failures
- return exit code `3` and omit challenge fields for a block
- keep Apply and Confirm generic, hard-blocked, and pre-transaction
- reject bypasses, profile rewriting, DNS substitution, and local proxy work in this phase

Set `Status: Accepted`. In Consequences, state that the current profile remains incompatible and a future profile requires a new hash, preflight, Plan, and authorization.

- [ ] **Step 2: Update acceptance and phase evidence without claiming live success**

Keep the acceptance row status `field-precheck-blocked`. Add that the offline diagnostic implementation now identifies `imported_dns` versus `explicit_target` and `cisco_prefix` versus `provider_endpoint` using counts only.

Add a report section named `DNS and Cisco overlap diagnostic follow-up`. Record:

- focused Go commands and PASS counts from Tasks 1 and 2
- PowerShell 5.1 and 7 Pester commands and PASS counts from Task 3
- full verify command and final exit code from Step 3 below
- `RUFF_NOT_APPLICABLE_NO_PYTHON`
- no live Apply, Confirm, recovery, network mutation, or current-profile retry

Update the P3 plan status to say the diagnostic gap is implemented offline while the imported-DNS/Cisco prerequisite and `pc-core-ready` remain open.

- [ ] **Step 3: Run the one full validation batch**

Run narrow checks first, then the repository gate once:

```powershell
& .\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd -count=1
powershell.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester
pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command verify
git diff --check
```

Expected: every command exits `0`. `verify` must cover format check, all Go tests, Pester, lint, build, governance, and bootstrap smoke checks.

- [ ] **Step 4: Reconcile documentation with observed evidence**

Write PASS only for commands that returned exit `0`. If a command fails, diagnose and fix the responsible task before updating the report. Do not convert offline tests into live field evidence.

Run:

```powershell
git status --short
git diff --check
```

Expected: only explicit Task 4 documentation paths plus the known untracked `.p35-run/`. Never stage `.p35-run/`.

- [ ] **Step 5: Commit Task 4**

```powershell
git add -- docs/adr/ADR-0014-p35-redacted-canary-block-diagnostics.md docs/ACCEPTANCE_MATRIX.md docs/reports/2026-08-26-p35-persistent-sinks.md docs/superpowers/plans/2026-08-24-p03-redshield-windows.md
git commit -m "docs: record P3.5 overlap diagnostic gate"
```

---

### Task 5: Consolidated safety review and completion gate

**Files:**
- Review only: every path changed since `$implementationBase`
- Modify only if the reviewer confirms a Critical or Important finding

**Interfaces:**
- Consumes: all Task 1 through Task 4 commits and their fresh validation output.
- Produces: one independent GO or NO-GO verdict for the offline implementation scope.
- Preserves: current-profile live NO-GO and the open `pc-core-ready` gate.

- [ ] **Step 1: Dispatch one read-only consolidated reviewer**

Give the reviewer the exact `$implementationBase` SHA and current HEAD. Require checks for:

- no provider or Cisco bypass
- exact source and protected-class attribution
- bounded deterministic counts and no value leakage
- success JSON compatibility
- exit code `3` and challenge omission on blocked Plan
- Apply and Confirm fail before transaction creation
- PowerShell 5.1, PowerShell 7, and Linux CI compatibility
- documentation that does not claim live acceptance

Require findings grouped as Critical, Important, and Minor with `file:line` evidence, followed by GO or NO-GO.

- [ ] **Step 2: Apply one bounded fix pass when required**

The implementation owner fixes only confirmed Critical or Important findings. Stage explicit paths and commit with a finding-specific message.

If Go or PowerShell code changes, rerun the affected focused tests and one fresh `pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command verify`. If only prose changes, run `git diff --check` and the relevant documentation assertions.

- [ ] **Step 3: Verify final repository state**

Run:

```powershell
git diff --check $implementationBase..HEAD
git status --short --branch
git log --oneline $implementationBase..HEAD
```

Expected: no staged or modified tracked files, only the known untracked `.p35-run/`, and logical Task commits. Do not push from an implementation or review agent.

- [ ] **Step 4: Report the exact gate boundary**

Report offline implementation PASS only after the reviewer returns GO and all required commands pass. Report the current profile as live NO-GO, state that no network mutation ran, and leave `pc-core-ready` open.
