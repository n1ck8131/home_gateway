# P0 Foundation and Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** создать воспроизводимый Git/Go/PowerShell foundation, executable lab и проверяемый OpenWrt 25.12.5 + AWG2 package prototype, не реализуя production routing.

**Architecture:** P0 разделён на P0A Foundation и P0B Compatibility. P0A фиксирует governance, toolchain, contracts, configs и CI. P0B собирает OpenWrt packages из pinned official AWG2 sources, проверяет netifd schema и создаёт безопасный hardware smoke; реальный router-to-VPS handshake остаётся входным gate P3.

**Tech Stack:** Git 2.52+; Go 1.26.5; Windows PowerShell 5.1 and PowerShell 7.6.2; Pester 6.0.0; OpenWrt 25.12.5 mediatek/filogic; package architecture aarch64_cortex-a53; Linux kernel 6.12.94 vermagic 5a6c1f71be683ae9980b15d3ce73e24d; official AmneziaWG kernel v1.0.20260611, tools v1.0.20260618-2 and userspace contingency v0.2.19.

## Global Constraints

- Do not add production routing, VPN orchestration, web UI, database or installer behavior in P0.
- Use github.com/vsevo/home-gateway as the Go module path for this phase; changing the future Git remote does not change P0 interfaces.
- All downloads use exact URLs and SHA-256 values from manifest/versions.lock.yaml; strings containing latest are rejected.
- Go module downloads are the only exception to direct artifact URLs: exact module versions are recorded in go.mod, content hashes in go.sum, and verification uses the public Go checksum database with GOTOOLCHAIN=local.
- Windows bootstrap is process-local and workspace-local; it does not change machine PATH, execution policy or system trust.
- PowerShell scripts run under Windows PowerShell 5.1; PowerShell 7.6.2 is an additional CI/runtime target.
- Go binaries are CGO-free in P0 and expose only the version contract.
- OpenWrt SDK artifacts are never committed.
- AWG packages are built from pinned official commits/tags; no remote script is executed.
- Hardware installation is dry-run by default and requires explicit ConfirmInstall plus PowerShell ShouldProcess confirmation; strict SSH host-key verification and default rollback are mandatory.
- No secrets, real IPs, SSH keys, private keys, profiles or backups enter Git.
- Every task ends in an independently testable commit.
- Every direct native invocation in a PowerShell plan block is checked immediately with `$LASTEXITCODE`; a later successful command must never mask an earlier failure.
- A green Pester gate requires `Result -eq 'Passed'` and `TotalCount -gt 0`; FailedCount alone is not sufficient.
- P0 completion permits P1 and P2. P3 remains blocked until exact-kernel module load/UAPI smoke and a real router-to-VPS handshake are completed.

## Phase deliverables

~~~
SPEC.md
README.md
PLAN.md
STATUS.md
DECISIONS.md
.editorconfig
.gitattributes
.gitignore
Makefile
go.mod
go.sum
go.work
api/openapi.yaml
cmd/
  routerd/main.go
  server-agent/main.go
  cisco-discovery/main.go
  hgctl/main.go
configs/
  defaults.yaml
  inventory.example.yaml
  routerd.example.yaml
  builtin-sources.yaml
docs/
  ACCEPTANCE_MATRIX.md
  COMPATIBILITY.md
  SECURITY.md
  adr/ADR-0001...ADR-0009
  superpowers/plans/2026-07-12-p00-foundation-compatibility.md
internal/
  buildinfo/buildinfo.go
  versioncmd/run.go
manifest/
  checksums.lock
  versions.lock.yaml
packaging/openwrt-awg2/
  kmod-amneziawg/Makefile
  amneziawg-tools/Makefile
  amneziawg-tools/files/amneziawg.sh
  amneziawg-tools/files/amneziawg_watchdog
scripts/
  bootstrap-dev.ps1
  check-governance.ps1
  dev.ps1
  openwrt/build-amneziawg-go.sh
  openwrt/build-packages.sh
  openwrt/smoke-awg2.ps1
tests/
  bootstrap/
  network-ns/
  openwrt-qemu/
  openwrt-sdk/
  windows-pester/
.github/workflows/
  ci.yml
  openwrt-sdk.yml
~~~

## Stable P0 interfaces

### Binary version contract

All four binaries accept:

~~~
routerd version --json
server-agent version --json
cisco-discovery version --json
hgctl version --json
~~~

and return one JSON object containing program, version, commit, build_date, go_version, goos and goarch. Unknown arguments return exit code 2 and a usage line on stderr.

### Developer entrypoints

~~~
.\scripts\bootstrap-dev.ps1
.\scripts\dev.ps1 -Command verify
make verify
~~~

### Compatibility states

docs/COMPATIBILITY.md uses only these states:

- verified-upstream
- built-in-sdk
- prepared-for-hardware
- verified-on-hardware
- blocked

P0 may finish with AWG2 marked prepared-for-hardware. P3 cannot start while it remains below verified-on-hardware.

---

## P0A — Foundation

### Task 1: Initialize Git and preserve the approved baseline

**Files:**

- Existing: HOME_GATEWAY_CODEX_SPEC.md
- Existing: PLAN.md
- Rename: HOME_GATEWAY_CODEX_SPEC.md to SPEC.md
- Modify: PLAN.md

**Interfaces:**

- Consumes: approved specification and master plan.
- Produces: main branch with an auditable baseline and canonical SPEC.md.

- [ ] **Step 1: Confirm the precondition**

Run:

~~~powershell
git --version
if ($LASTEXITCODE -ne 0) { throw 'git --version failed' }
$inside = git rev-parse --is-inside-work-tree 2>$null
if ($LASTEXITCODE -eq 0 -and $inside -eq 'true') {
    throw 'Repository is already initialized'
}
if (Test-Path -LiteralPath .git) {
    $entries = @(Get-ChildItem -LiteralPath .git -Force)
    if ($entries.Count -ne 0) {
        throw 'Non-empty invalid .git directory requires manual inspection'
    }
}
~~~

Expected: Git 2.52.0.windows.1 or newer; rev-parse reports no repository. The currently empty .git directory is accepted, while a non-empty invalid directory stops the task.

- [ ] **Step 2: Initialize the repository and local commit identity**

Run:

~~~powershell
git init -b main
if ($LASTEXITCODE -ne 0) { throw 'git init failed' }
if (-not (git config user.name)) {
    git config user.name "Codex"
    if ($LASTEXITCODE -ne 0) { throw 'git config user.name failed' }
}
if (-not (git config user.email)) {
    git config user.email "codex@local.invalid"
    if ($LASTEXITCODE -ne 0) { throw 'git config user.email failed' }
}
git config core.autocrlf false
if ($LASTEXITCODE -ne 0) { throw 'git config core.autocrlf failed' }
git config core.safecrlf true
if ($LASTEXITCODE -ne 0) { throw 'git config core.safecrlf failed' }
~~~

Expected: .git exists, branch is main, and identity is repository-local when no user identity was configured.

- [ ] **Step 3: Commit the exact approved inputs**

Run:

~~~powershell
git add -- HOME_GATEWAY_CODEX_SPEC.md PLAN.md docs/superpowers/plans/2026-07-12-p00-foundation-compatibility.md
if ($LASTEXITCODE -ne 0) { throw 'git add approved inputs failed' }
git commit -m "docs: add approved home gateway specification"
if ($LASTEXITCODE -ne 0) { throw 'initial specification commit failed' }
~~~

Expected: one root commit containing the specification, master plan and approved P0 phase plan.

- [ ] **Step 4: Rename the canonical specification**

Run:

~~~powershell
git mv -- HOME_GATEWAY_CODEX_SPEC.md SPEC.md
if ($LASTEXITCODE -ne 0) { throw 'git mv specification failed' }
~~~

Apply this exact PLAN.md patch; the approved master plan already has the corrected P0/P3 exit wording, so do not rewrite it again:

~~~diff
- Канонический input: `HOME_GATEWAY_CODEX_SPEC.md`, версия 1.0 от 2026-07-11.
+ Канонический input: `SPEC.md`, версия 1.0 от 2026-07-11.
~~~

Run `rg -n "HOME_GATEWAY_CODEX_SPEC" PLAN.md SPEC.md`; expected: no match in PLAN.md and any historical filename mention inside SPEC.md is preserved only if the specification itself contains one.

- [ ] **Step 5: Verify and commit the rename**

Run:

~~~powershell
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'git diff --check failed' }
git diff --name-status
if ($LASTEXITCODE -ne 0) { throw 'git diff --name-status failed' }
git add -- SPEC.md PLAN.md
if ($LASTEXITCODE -ne 0) { throw 'git add canonical spec failed' }
git commit -m "docs: make SPEC.md canonical"
if ($LASTEXITCODE -ne 0) { throw 'canonical spec commit failed' }
~~~

Expected: a tracked rename plus the matching PLAN.md adjustment; no whitespace errors.

### Task 2: Add repository hygiene and project status documents

**Files:**

- Create: .editorconfig
- Create: .gitattributes
- Create: .gitignore
- Create: README.md
- Create: STATUS.md
- Create: DECISIONS.md
- Create: tests/bootstrap/Governance.Smoke.ps1

**Interfaces:**

- Consumes: canonical SPEC.md and PLAN.md.
- Produces: stable paths used by every later task.

- [ ] **Step 1: Write the failing governance smoke**

Create tests/bootstrap/Governance.Smoke.ps1:

~~~powershell
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$required = @(
    'SPEC.md',
    'PLAN.md',
    'README.md',
    'STATUS.md',
    'DECISIONS.md',
    '.editorconfig',
    '.gitattributes',
    '.gitignore'
)
$missing = @($required | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $root $_))
})
if ($missing.Count -ne 0) {
    throw "Missing governance files: $($missing -join ', ')"
}
if ((Get-Content -LiteralPath (Join-Path $root 'STATUS.md') -Raw) -notmatch 'Current phase: P0') {
    throw 'STATUS.md must identify P0'
}
'GOVERNANCE_SMOKE_PASS'
~~~

- [ ] **Step 2: Run it and confirm failure**

Run:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\bootstrap\Governance.Smoke.ps1
if ($LASTEXITCODE -eq 0) { throw 'Expected governance smoke failure' }
~~~

Expected: non-zero exit with Missing governance files.

- [ ] **Step 3: Create the hygiene files**

Use apply_patch with these exact contents:

~~~ini
# .editorconfig
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true

[*.ps1]
end_of_line = crlf
indent_style = space
indent_size = 4

[*.go]
indent_style = tab
~~~

~~~gitattributes
* text=auto
*.go text eol=lf
*.md text eol=lf
*.yaml text eol=lf
*.yml text eol=lf
*.sh text eol=lf
*.ps1 text eol=crlf
*.psd1 text eol=crlf
*.psm1 text eol=crlf
*.png binary
*.zip binary
*.zst binary
*.apk binary
~~~

~~~gitignore
/.cache/
/.tools/
/.worktrees/
/artifacts/
/build/
/coverage/
/dist/
/tmp/
*.age
*.conf
*.key
*.log
*.p12
*.pfx
*.pem
*.test
inventory.local.yaml
routerd.local.yaml
secrets.local/
~~~

- [ ] **Step 4: Create the three project documents**

Create README.md with this exact initial content. Task 3 adds the SECURITY link in the same commit that creates the target file.

~~~markdown
# Home Gateway

Safety-first home gateway control plane for OpenWrt on GL.iNet Flint 2. The deterministic policy engine owns routing decisions; P0 builds only the reproducible foundation and compatibility evidence.

Current phase: P0 Foundation and Compatibility.

## Safety invariants

- The WAN default route in `main` is never replaced by a VPN default route.
- VPN-class traffic fails closed and never falls through to `main` when its selected transport is unavailable.
- Cisco discovery and direct-routing exceptions apply only to the logical `work-pc`; Cisco policy is never bypassed.

## Developer entrypoints

Windows PowerShell 5.1:

```powershell
.\scripts\bootstrap-dev.ps1
.\scripts\dev.ps1 -Command verify
```

Linux with PowerShell 7:

```sh
pwsh -NoProfile -File scripts/bootstrap-dev.ps1 -IncludePowerShell
make PWSH=./.tools/pwsh/pwsh verify
```

## Project documents

- [Specification](SPEC.md)
- [Development plan](PLAN.md)
- [Current status](STATUS.md)
- [Accepted decisions](DECISIONS.md)
~~~

STATUS.md must contain:

~~~markdown
# Project Status

Current phase: P0 Foundation and Compatibility
Release level: planning-approved

## P0A Foundation

- State: not-started

## P0B Compatibility

- State: not-started

## External gates

- GL-MT6000 hardware smoke: not-run
- Router-to-VPS AWG2 handshake: P3 gate
- Second VPS failover: P9 gate
- Cisco field test: P7 gate

## Blockers

- None at plan approval.
~~~

Create DECISIONS.md with this exact index:

~~~markdown
# Architecture Decisions

| ADR | Status | Subject |
|---|---|---|
| [ADR-0001](docs/adr/ADR-0001-supported-platform.md) | Accepted | Supported platform |
| [ADR-0002](docs/adr/ADR-0002-vpn-transports.md) | Accepted | VPN transports |
| [ADR-0003](docs/adr/ADR-0003-routing-ownership-and-marks.md) | Accepted | Routing ownership and marks |
| [ADR-0004](docs/adr/ADR-0004-dns-and-precedence.md) | Accepted | DNS and precedence |
| [ADR-0005](docs/adr/ADR-0005-transaction-model.md) | Accepted | Transaction model |
| [ADR-0006](docs/adr/ADR-0006-state-secrets-backup.md) | Accepted | State, secrets and backup |
| [ADR-0007](docs/adr/ADR-0007-mobile-peer-lifecycle.md) | Accepted | Mobile peer lifecycle |
| [ADR-0008](docs/adr/ADR-0008-cisco-discovery.md) | Accepted | Cisco discovery |
| [ADR-0009](docs/adr/ADR-0009-supply-chain-signing.md) | Accepted | Supply chain and signing |
~~~

- [ ] **Step 5: Run the smoke and commit**

Run:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\bootstrap\Governance.Smoke.ps1
if ($LASTEXITCODE -ne 0) { throw 'Governance smoke failed' }
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'git diff --check failed' }
git add -- .editorconfig .gitattributes .gitignore README.md STATUS.md DECISIONS.md tests/bootstrap/Governance.Smoke.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add governance files failed' }
git commit -m "chore: establish repository governance"
if ($LASTEXITCODE -ne 0) { throw 'governance commit failed' }
~~~

Expected: GOVERNANCE_SMOKE_PASS and a clean commit.

### Task 3: Record the nine accepted ADRs and verification matrix

**Files:**

- Create: docs/adr/ADR-0001-supported-platform.md
- Create: docs/adr/ADR-0002-vpn-transports.md
- Create: docs/adr/ADR-0003-routing-ownership-and-marks.md
- Create: docs/adr/ADR-0004-dns-and-precedence.md
- Create: docs/adr/ADR-0005-transaction-model.md
- Create: docs/adr/ADR-0006-state-secrets-backup.md
- Create: docs/adr/ADR-0007-mobile-peer-lifecycle.md
- Create: docs/adr/ADR-0008-cisco-discovery.md
- Create: docs/adr/ADR-0009-supply-chain-signing.md
- Create: docs/SECURITY.md
- Create: docs/COMPATIBILITY.md
- Create: docs/ACCEPTANCE_MATRIX.md
- Create: scripts/check-governance.ps1
- Create: tests/bootstrap/GovernanceChecker.Smoke.ps1
- Modify: README.md

**Interfaces:**

- Consumes: master-plan decisions.
- Produces: immutable decision boundaries used by P1-P12.

- [ ] **Step 1: Extend the smoke so it fails for missing ADRs**

Add the nine ADR paths and the three docs paths to the required array in tests/bootstrap/Governance.Smoke.ps1. Create tests/bootstrap/GovernanceChecker.Smoke.ps1 before the checker: it builds an isolated valid fixture, then runs five copies with one defect each—missing ADR, accepted-ADR placeholder, broken DECISIONS link, missing §30 row and two simultaneous defects. It requires non-zero exit, the exact path/diagnostic for every defect, and both messages for the aggregate case. Run it now and require failure because scripts/check-governance.ps1 is missing.

Run it.

Expected: failure listing the missing docs.

- [ ] **Step 2: Create every ADR with the same exact structure**

Each ADR contains Status, Context, Decision, Consequences and Verification. Use these decisions verbatim:

| ADR | Decision | Verification consequence |
|---|---|---|
| 0001 | OpenWrt 25.12.5, mediatek/filogic, glinet_gl-mt6000, aarch64_cortex-a53 and kernel 6.12.94 are the only first-release target tuple. Stock GL.iNet and upstream OpenWrt are separate recovery profiles. | Exact image, SDK, revision and vermagic appear in the lock and compatibility report. |
| 0002 | Official AWG2 kernel/tools are primary. A maintained OpenWrt package and netifd helper are project-owned adapters. amneziawg-go is contingency only. VLESS Reality TUN remains independent. | SDK build is P0; hardware module/UAPI is P3 precondition; throughput decides kernel versus contingency. |
| 0003 | routerd is the sole policy owner. Reserve a mark mask and use per-server connection marks/tables so old healthy sessions drain instead of being silently moved. | P1 defines values; P2 packet-capture tests prove no fallback to main. |
| 0004 | Protected origin tier wins before specificity; specificity applies inside a tier; direct wins unresolved shared-IP collision. No-leak guarantee is scoped to managed DNS and explicit device policy. | Table-driven policy tests and DNS cold-boot tests are mandatory. |
| 0005 | Local apply uses lock, staging, validation, snapshot, commit-confirm watchdog and rollback. Router-to-VPS changes use an idempotent saga with compensation. | No claim of distributed atomicity; failure injection covers every boundary. |
| 0006 | State uses an embedded transactional store; secret bytes are separate. Unattended backups use age recipient wrapping and portable recovery material. | Secret redaction and clean restore are required. |
| 0007 | One device/server pair has one keypair. One-time material is single-consumption with a ten-minute TTL; only public key and metadata persist. | Reuse, expiry and revoke tests are mandatory. |
| 0008 | cisco-discovery is read-only, uses a scoped token and offline queue, and never bypasses Cisco policy. work-pc is one logical device with Ethernet and Flint Wi-Fi identities and cannot be always-vpn. | Split and full tunnel have separate acceptance branches. |
| 0009 | Production inputs are pinned, checksummed and provenance-recorded. Development and release signing keys are separate. | CI rejects latest, bad SHA and secrets; P12 creates signatures and SBOM. |

- [ ] **Step 3: Create security, compatibility and acceptance documents**

docs/SECURITY.md must enumerate the §21 threats, trust boundaries, secret locations, prohibited command construction and P0 exclusions.

In the same apply_patch, add a README.md link to docs/SECURITY.md so no commit contains a broken local link.

docs/COMPATIBILITY.md must start with:

~~~markdown
# Compatibility Matrix

| Component | Version | State | Evidence |
|---|---|---|---|
| OpenWrt target metadata | 25.12.5 / r33051-f5dae5ece4 | verified-upstream | Official profiles.json and sha256sums |
| AWG2 kernel source | v1.0.20260611 / 2a6e1a02ac024f54a23e18f894a279b7f870b8fb | verified-upstream | Official tag and source hash |
| AWG2 tools source | v1.0.20260618-2 / 61e741780e8465a67a7d7fb6cffe14a8a15d624a | verified-upstream | Official tag and source hash |
| AWG2 OpenWrt packages | P0 build | prepared-for-hardware | SDK build evidence is added during Task 10 |
| AWG2 hardware UAPI | Exact Flint 2 kernel | prepared-for-hardware | P3 precondition |
| Router-to-VPS handshake | Exact router and VPS | blocked | P3 owns this field gate |
~~~

docs/ACCEPTANCE_MATRIX.md must map every §30 requirement to one owner phase and one evidence type: automated, hardware, external-service or field-soak. No row may say later without a phase number.

- [ ] **Step 4: Add the governance checker**

scripts/check-governance.ps1 must:

1. accept an optional `-Root` used by the isolated fixture and otherwise resolve repository root; require SPEC.md, PLAN.md, STATUS.md, DECISIONS.md and all ADR/docs paths;
2. reject unresolved placeholder markers in accepted ADRs;
3. verify DECISIONS.md links each ADR filename;
4. verify every §30.1 through §30.8 heading appears in docs/ACCEPTANCE_MATRIX.md;
5. exit non-zero with all missing items listed.

Use tests/bootstrap/Governance.Smoke.ps1 and GovernanceChecker.Smoke.ps1 as executable tests; the latter must prove all negative cases before the real repository happy path is accepted.

- [ ] **Step 5: Verify and commit**

Run:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\bootstrap\Governance.Smoke.ps1
if ($LASTEXITCODE -ne 0) { throw 'Governance.Smoke.ps1 failed' }
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\bootstrap\GovernanceChecker.Smoke.ps1
if ($LASTEXITCODE -ne 0) { throw 'GovernanceChecker.Smoke.ps1 failed' }
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-governance.ps1
if ($LASTEXITCODE -ne 0) { throw 'check-governance.ps1 failed' }
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'git diff --check failed' }
git add -- README.md DECISIONS.md docs/SECURITY.md docs/COMPATIBILITY.md docs/ACCEPTANCE_MATRIX.md `
    docs/adr/ADR-0001-supported-platform.md `
    docs/adr/ADR-0002-vpn-transports.md `
    docs/adr/ADR-0003-routing-ownership-and-marks.md `
    docs/adr/ADR-0004-dns-and-precedence.md `
    docs/adr/ADR-0005-transaction-model.md `
    docs/adr/ADR-0006-state-secrets-backup.md `
    docs/adr/ADR-0007-mobile-peer-lifecycle.md `
    docs/adr/ADR-0008-cisco-discovery.md `
    docs/adr/ADR-0009-supply-chain-signing.md `
    scripts/check-governance.ps1 tests/bootstrap/Governance.Smoke.ps1 tests/bootstrap/GovernanceChecker.Smoke.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add architecture decisions failed' }
git commit -m "docs: record foundation architecture decisions"
if ($LASTEXITCODE -ne 0) { throw 'architecture decision commit failed' }
~~~

Expected: both checks pass and all nine ADRs are indexed.

### Task 4: Pin and bootstrap the developer toolchain

**Files:**

- Create: manifest/versions.lock.yaml
- Create: manifest/checksums.lock
- Create: scripts/bootstrap-dev.ps1
- Create: tests/bootstrap/ToolchainLock.Smoke.ps1
- Create: tests/windows-pester/BootstrapDev.Tests.ps1

**Interfaces:**

- Consumes: Windows PowerShell 5.1 or Linux PowerShell 7 plus network access.
- Produces: workspace-local .tools containing exact OS-specific Go, Pester, Gitleaks and Actionlint; ShellCheck on Linux; optional PowerShell 7.

- [ ] **Step 1: Write the failing lock smoke**

Create tests/bootstrap/ToolchainLock.Smoke.ps1:

~~~powershell
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$lockPath = Join-Path $root 'manifest/versions.lock.yaml'
if (-not (Test-Path -LiteralPath $lockPath)) {
    throw 'versions lock missing'
}
$raw = Get-Content -LiteralPath $lockPath -Raw
if ($raw -match '(?i)latest') {
    throw 'versions lock contains latest'
}
$lock = $raw | ConvertFrom-Json
if ($lock.schema_version -ne 1) {
    throw 'unexpected lock schema'
}
$requiredArtifacts = @(
    'go_windows_amd64', 'go_linux_amd64',
    'powershell_windows_amd64', 'powershell_linux_amd64', 'pester',
    'gitleaks_windows_amd64', 'gitleaks_linux_amd64',
    'shellcheck_linux_amd64',
    'actionlint_windows_amd64', 'actionlint_linux_amd64',
    'openwrt_sdk', 'openwrt_factory', 'openwrt_sysupgrade',
    'awg_kernel_source', 'awg_tools_source', 'awg_go_source',
    'awg_openwrt_adapter_source'
)
$actualArtifacts = @($lock.artifacts.PSObject.Properties.Name | Sort-Object)
if (($actualArtifacts -join ',') -ne (($requiredArtifacts | Sort-Object) -join ',')) {
    throw 'artifact key set mismatch'
}
$requiredActions = @('checkout', 'setup_go', 'upload_artifact')
if ((@($lock.actions.PSObject.Properties.Name | Sort-Object) -join ',') -ne (($requiredActions | Sort-Object) -join ',')) {
    throw 'action key set mismatch'
}
foreach ($action in $lock.actions.PSObject.Properties.Value) {
    if ($action -notmatch '^[^@]+@[0-9a-f]{40}$') {
        throw "mutable or invalid action pin: $action"
    }
}
$requiredModules = @('gosec', 'govulncheck', 'staticcheck')
if ((@($lock.go_modules.PSObject.Properties.Name | Sort-Object) -join ',') -ne (($requiredModules | Sort-Object) -join ',')) {
    throw 'Go tool key set mismatch'
}
$expectedChecksums = @()
foreach ($property in $lock.artifacts.PSObject.Properties) {
    $artifact = $property.Value
    if ($artifact.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "invalid sha256 for $($artifact.url)"
    }
    if ($artifact.url -notmatch '^https://') {
        throw "non-HTTPS artifact $($artifact.url)"
    }
    $filename = if ($artifact.filename) {
        $artifact.filename
    } else {
        ([Uri]$artifact.url).Segments[-1]
    }
    $expectedChecksums += "$($artifact.sha256)  $filename"
}
$checksumPath = Join-Path $root 'manifest/checksums.lock'
if (-not (Test-Path -LiteralPath $checksumPath)) {
    throw 'checksums lock missing'
}
$actualChecksums = @(Get-Content -LiteralPath $checksumPath | Where-Object { $_ } | Sort-Object)
if (($actualChecksums -join "`n") -ne (($expectedChecksums | Sort-Object) -join "`n")) {
    throw 'checksums lock differs from versions lock'
}
'TOOLCHAIN_LOCK_SMOKE_PASS'
~~~

Run it.

Expected: failure with versions lock missing.

- [ ] **Step 2: Create the exact lock**

manifest/versions.lock.yaml is JSON syntax, which is a valid YAML subset and can be read by ConvertFrom-Json before Go dependencies exist. It must contain these exact values:

~~~json
{
  "schema_version": 1,
  "locked_at": "2026-07-12",
  "go_modules": {
    "govulncheck": "golang.org/x/vuln/cmd/govulncheck@v1.1.4",
    "staticcheck": "honnef.co/go/tools/cmd/staticcheck@2026.1",
    "gosec": "github.com/securego/gosec/v2/cmd/gosec@v2.27.1"
  },
  "actions": {
    "checkout": "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "setup_go": "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
    "upload_artifact": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
  },
  "openwrt": {
    "version": "25.12.5",
    "revision": "r33051-f5dae5ece4",
    "target": "mediatek/filogic",
    "profile": "glinet_gl-mt6000",
    "package_arch": "aarch64_cortex-a53",
    "kernel_version": "6.12.94",
    "kernel_vermagic": "5a6c1f71be683ae9980b15d3ce73e24d",
    "source_date_epoch": 1782737960
  },
  "amneziawg": {
    "kernel_commit": "2a6e1a02ac024f54a23e18f894a279b7f870b8fb",
    "tools_commit": "61e741780e8465a67a7d7fb6cffe14a8a15d624a",
    "go_commit": "1cc94272ca8e9e223a5fe76382f5880f09d3c12d",
    "openwrt_adapter_commit": "56bf9fed93df48d2b747edd6e7a7c5fbe2b01afe"
  },
  "artifacts": {
    "go_windows_amd64": {
      "url": "https://go.dev/dl/go1.26.5.windows-amd64.zip",
      "sha256": "97e6b2a833b6d89f9ff17d25419ac0a7e3b482a044e9ab18cdef834bd834fd38"
    },
    "go_linux_amd64": {
      "url": "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz",
      "sha256": "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
    },
    "powershell_windows_amd64": {
      "url": "https://github.com/PowerShell/PowerShell/releases/download/v7.6.2/PowerShell-7.6.2-win-x64.zip",
      "sha256": "32e0dd26752483ba3f0e40e9ae44150643cbff469c13210c93295d158bfd7b26"
    },
    "powershell_linux_amd64": {
      "url": "https://github.com/PowerShell/PowerShell/releases/download/v7.6.2/powershell-7.6.2-linux-x64.tar.gz",
      "sha256": "6cbcfbf20e376aa62ffd91c973493c41a7a52ddfd5a5db3ff9bc12f0d0fe9292"
    },
    "pester": {
      "filename": "Pester.6.0.0.nupkg",
      "url": "https://www.powershellgallery.com/api/v2/package/Pester/6.0.0",
      "sha256": "238d9aa37a55d7b4afcb66245f36fc7410774c067fec40084e00eea474de9862"
    },
    "gitleaks_windows_amd64": {
      "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
      "sha256": "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"
    },
    "gitleaks_linux_amd64": {
      "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
      "sha256": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    },
    "shellcheck_linux_amd64": {
      "url": "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz",
      "sha256": "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
    },
    "actionlint_windows_amd64": {
      "url": "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_windows_amd64.zip",
      "sha256": "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9"
    },
    "actionlint_linux_amd64": {
      "url": "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
      "sha256": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
    },
    "openwrt_sdk": {
      "url": "https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/filogic/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst",
      "sha256": "ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25"
    },
    "openwrt_factory": {
      "url": "https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/filogic/openwrt-25.12.5-mediatek-filogic-glinet_gl-mt6000-squashfs-factory.bin",
      "sha256": "d0c997128c3c775be10311f80b4c20c9f85bbc8c2ebb2601f5957b7290b71412"
    },
    "openwrt_sysupgrade": {
      "url": "https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/filogic/openwrt-25.12.5-mediatek-filogic-glinet_gl-mt6000-squashfs-sysupgrade.bin",
      "sha256": "4b506982cc4ae2e1ebdee85be637fdfd59ed7df83e9995e03ffd641c58954390"
    },
    "awg_kernel_source": {
      "url": "https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/archive/refs/tags/v1.0.20260611.tar.gz",
      "sha256": "e062ecc9f1d89eeafa9f56a29473372a1d796ee061eaa8c7b61eeb51c38b80d6"
    },
    "awg_tools_source": {
      "url": "https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/v1.0.20260618-2.tar.gz",
      "sha256": "cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10"
    },
    "awg_go_source": {
      "url": "https://github.com/amnezia-vpn/amneziawg-go/archive/refs/tags/v0.2.19.tar.gz",
      "sha256": "d2fde8df81199e2350b43f387fe79b3056a2278457504fa1f91cd170cb0f474b"
    },
    "awg_openwrt_adapter_source": {
      "url": "https://github.com/amnezia-vpn/amneziawg-openwrt/archive/56bf9fed93df48d2b747edd6e7a7c5fbe2b01afe.tar.gz",
      "sha256": "ad1f1c68efb4d4feb08e4a3df45dba2a22b0f33da2708826b02446362f39bff8"
    }
  }
}
~~~

Create manifest/checksums.lock with these exact sha256sum records, sorted by filename:

~~~text
ad1f1c68efb4d4feb08e4a3df45dba2a22b0f33da2708826b02446362f39bff8  56bf9fed93df48d2b747edd6e7a7c5fbe2b01afe.tar.gz
8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8  actionlint_1.7.12_linux_amd64.tar.gz
6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9  actionlint_1.7.12_windows_amd64.zip
551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  gitleaks_8.30.1_linux_x64.tar.gz
d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e  gitleaks_8.30.1_windows_x64.zip
5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053  go1.26.5.linux-amd64.tar.gz
97e6b2a833b6d89f9ff17d25419ac0a7e3b482a044e9ab18cdef834bd834fd38  go1.26.5.windows-amd64.zip
d0c997128c3c775be10311f80b4c20c9f85bbc8c2ebb2601f5957b7290b71412  openwrt-25.12.5-mediatek-filogic-glinet_gl-mt6000-squashfs-factory.bin
4b506982cc4ae2e1ebdee85be637fdfd59ed7df83e9995e03ffd641c58954390  openwrt-25.12.5-mediatek-filogic-glinet_gl-mt6000-squashfs-sysupgrade.bin
ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25  openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst
238d9aa37a55d7b4afcb66245f36fc7410774c067fec40084e00eea474de9862  Pester.6.0.0.nupkg
6cbcfbf20e376aa62ffd91c973493c41a7a52ddfd5a5db3ff9bc12f0d0fe9292  powershell-7.6.2-linux-x64.tar.gz
32e0dd26752483ba3f0e40e9ae44150643cbff469c13210c93295d158bfd7b26  PowerShell-7.6.2-win-x64.zip
8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198  shellcheck-v0.11.0.linux.x86_64.tar.xz
d2fde8df81199e2350b43f387fe79b3056a2278457504fa1f91cd170cb0f474b  v0.2.19.tar.gz
e062ecc9f1d89eeafa9f56a29473372a1d796ee061eaa8c7b61eeb51c38b80d6  v1.0.20260611.tar.gz
cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10  v1.0.20260618-2.tar.gz
~~~

- [ ] **Step 3: Make the lock smoke pass**

Run:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\bootstrap\ToolchainLock.Smoke.ps1
if ($LASTEXITCODE -ne 0) { throw 'Toolchain lock smoke failed' }
~~~

Expected: TOOLCHAIN_LOCK_SMOKE_PASS.

- [ ] **Step 4: Implement workspace-local bootstrap**

scripts/bootstrap-dev.ps1 must:

1. accept WhatIf and IncludePowerShell switches;
2. parse manifest/versions.lock.yaml with ConvertFrom-Json;
3. download to .cache/downloads/name.partial;
4. verify Get-FileHash SHA256 before atomic rename;
5. select only the matching windows_amd64 or linux_amd64 artifact keys from the lock, then extract Go to .tools/go, Pester to .tools/modules/Pester/6.0.0, Gitleaks and Actionlint to .tools/bin, ShellCheck to .tools/bin on Linux, and optional PowerShell to .tools/pwsh; rename the Pester NuGet payload to a zip before Expand-Archive;
6. select `.exe` suffix only when `$env:OS -eq 'Windows_NT'`, run the resolved `.tools/go/bin/go$suffix version`, require exactly go1.26.5, set process-local GOTOOLCHAIN=local and import the exact Pester module;
7. make a second invocation a no-op after re-verifying installed versions;
8. never update process-external PATH or execution policy.

Keep download, hash, extraction and version-probe logic in functions; execution is guarded so Pester can dot-source the script without running bootstrap. tests/windows-pester/BootstrapDev.Tests.ps1 uses a TestDrive root plus mocked downloads/extractors to prove: WhatIf creates no files and calls no network function; a corrupt cached hash fails closed; a second successful invocation performs zero downloads and zero replacements; Windows/Linux artifact selection is mutually exclusive.

The download helper uses this exact algorithm:

~~~powershell
function Get-VerifiedArtifact {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Artifact,
        [Parameter(Mandatory)][string]$DownloadDirectory
    )
    $final = Join-Path $DownloadDirectory $Name
    $partial = "$final.partial"
    New-Item -ItemType Directory -Force -Path $DownloadDirectory | Out-Null
    if (-not (Test-Path -LiteralPath $final)) {
        Invoke-WebRequest -UseBasicParsing -Uri $Artifact.url -OutFile $partial
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $partial).Hash.ToLowerInvariant()
        if ($actual -ne $Artifact.sha256) {
            Remove-Item -LiteralPath $partial -Force
            throw "SHA256 mismatch for $Name"
        }
        Move-Item -LiteralPath $partial -Destination $final
    }
    $installed = (Get-FileHash -Algorithm SHA256 -LiteralPath $final).Hash.ToLowerInvariant()
    if ($installed -ne $Artifact.sha256) {
        throw "Cached SHA256 mismatch for $Name"
    }
    return $final
}
~~~

- [ ] **Step 5: Verify dry-run, real bootstrap and idempotence**

Run:

~~~powershell
.\scripts\bootstrap-dev.ps1 -WhatIf
if (Test-Path -LiteralPath .tools) { throw 'WhatIf created .tools' }
.\scripts\bootstrap-dev.ps1
.\scripts\bootstrap-dev.ps1
.\.tools\go\bin\go.exe version
if ($LASTEXITCODE -ne 0) { throw 'pinned Go version probe failed' }
Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force
Get-Module Pester | Select-Object -ExpandProperty Version
.\.tools\bin\gitleaks.exe version
if ($LASTEXITCODE -ne 0) { throw 'Gitleaks version probe failed' }
.\.tools\bin\actionlint.exe -version
if ($LASTEXITCODE -ne 0) { throw 'Actionlint version probe failed' }
Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force
$result = Invoke-Pester -Path .\tests\windows-pester\BootstrapDev.Tests.ps1 -Output Detailed -PassThru
if ($result.Result -ne 'Passed' -or $result.TotalCount -eq 0) { throw "Bootstrap Pester gate failed: $($result.Result)" }
~~~

Expected: WhatIf does not create .tools; both real runs succeed; versions are Go 1.26.5, Pester 6.0.0, Gitleaks 8.30.1 and Actionlint 1.7.12.

- [ ] **Step 6: Commit only sources and locks**

Run:

~~~powershell
$status = @(git status --short)
if ($LASTEXITCODE -ne 0) { throw 'git status failed' }
if ($status -match '(^|[\\/])(\.tools|\.cache)([\\/]|$)') { throw 'ignored tool/cache path is visible to Git' }
git add -- manifest/versions.lock.yaml manifest/checksums.lock scripts/bootstrap-dev.ps1 tests/bootstrap/ToolchainLock.Smoke.ps1 tests/windows-pester/BootstrapDev.Tests.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add toolchain sources failed' }
git commit -m "build: pin developer and upstream toolchains"
if ($LASTEXITCODE -ne 0) { throw 'toolchain commit failed' }
~~~

Expected: .tools and .cache remain ignored.

### Task 5: Create the Go workspace and version-only binaries

**Files:**

- Create: go.mod
- Create: go.work
- Create: internal/buildinfo/buildinfo.go
- Create: internal/versioncmd/run.go
- Create: internal/versioncmd/run_test.go
- Create: cmd/routerd/main.go
- Create: cmd/server-agent/main.go
- Create: cmd/cisco-discovery/main.go
- Create: cmd/hgctl/main.go

**Interfaces:**

- Consumes: Go 1.26.5 from Task 4.
- Produces: the stable binary version contract.

- [ ] **Step 1: Create only the module metadata**

go.mod:

~~~go
module github.com/vsevo/home-gateway

go 1.26.0

toolchain go1.26.5
~~~

go.work:

~~~go
go 1.26.0

toolchain go1.26.5

use .
~~~

Run:

~~~powershell
.\.tools\go\bin\go.exe env GOMOD
if ($LASTEXITCODE -ne 0) { throw 'go env GOMOD failed' }
.\.tools\go\bin\go.exe env GOWORK
if ($LASTEXITCODE -ne 0) { throw 'go env GOWORK failed' }
~~~

Expected: absolute paths to go.mod and go.work.

- [ ] **Step 2: Write the failing version command tests**

Create internal/versioncmd/run_test.go:

~~~go
package versioncmd

import (
    "bytes"
    "encoding/json"
    "testing"
)

func TestRunVersionJSON(t *testing.T) {
    var stdout bytes.Buffer
    var stderr bytes.Buffer

    code := Run("routerd", []string{"version", "--json"}, &stdout, &stderr)

    if code != 0 {
        t.Fatalf("code = %d, stderr = %q", code, stderr.String())
    }
    var got map[string]string
    if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
        t.Fatal(err)
    }
    if got["program"] != "routerd" {
        t.Fatalf("program = %q", got["program"])
    }
    for _, key := range []string{"version", "commit", "build_date", "go_version", "goos", "goarch"} {
        if got[key] == "" {
            t.Fatalf("%s is empty", key)
        }
    }
}

func TestRunRejectsUnknownArguments(t *testing.T) {
    var stdout bytes.Buffer
    var stderr bytes.Buffer

    code := Run("routerd", []string{"serve"}, &stdout, &stderr)

    if code != 2 {
        t.Fatalf("code = %d", code)
    }
    if stdout.Len() != 0 {
        t.Fatalf("stdout = %q", stdout.String())
    }
    if stderr.String() != "usage: routerd version --json\n" {
        t.Fatalf("stderr = %q", stderr.String())
    }
}
~~~

Run:

~~~powershell
.\.tools\go\bin\go.exe test ./...
if ($LASTEXITCODE -eq 0) { throw 'Expected Go tests to fail before Run exists' }
~~~

Expected: compile failure because Run is undefined.

- [ ] **Step 3: Implement build metadata**

Create internal/buildinfo/buildinfo.go:

~~~go
package buildinfo

import "runtime"

var (
    Version   = "dev"
    Commit    = "unknown"
    BuildDate = "unknown"
)

func Current(program string) map[string]string {
    return map[string]string{
        "program":    program,
        "version":    Version,
        "commit":     Commit,
        "build_date": BuildDate,
        "go_version": runtime.Version(),
        "goos":       runtime.GOOS,
        "goarch":     runtime.GOARCH,
    }
}
~~~

Create internal/versioncmd/run.go:

~~~go
package versioncmd

import (
    "encoding/json"
    "fmt"
    "io"

    "github.com/vsevo/home-gateway/internal/buildinfo"
)

func Run(program string, args []string, stdout, stderr io.Writer) int {
    if len(args) != 2 || args[0] != "version" || args[1] != "--json" {
        fmt.Fprintf(stderr, "usage: %s version --json\n", program)
        return 2
    }
    encoder := json.NewEncoder(stdout)
    encoder.SetEscapeHTML(false)
    if err := encoder.Encode(buildinfo.Current(program)); err != nil {
        fmt.Fprintf(stderr, "encode version: %v\n", err)
        return 1
    }
    return 0
}
~~~

- [ ] **Step 4: Add the four thin main packages**

Each main.go differs only by program name. cmd/routerd/main.go is:

~~~go
package main

import (
    "os"

    "github.com/vsevo/home-gateway/internal/versioncmd"
)

func main() {
    os.Exit(versioncmd.Run("routerd", os.Args[1:], os.Stdout, os.Stderr))
}
~~~

cmd/server-agent/main.go:

~~~go
package main

import (
    "os"

    "github.com/vsevo/home-gateway/internal/versioncmd"
)

func main() {
    os.Exit(versioncmd.Run("server-agent", os.Args[1:], os.Stdout, os.Stderr))
}
~~~

cmd/cisco-discovery/main.go:

~~~go
package main

import (
    "os"

    "github.com/vsevo/home-gateway/internal/versioncmd"
)

func main() {
    os.Exit(versioncmd.Run("cisco-discovery", os.Args[1:], os.Stdout, os.Stderr))
}
~~~

cmd/hgctl/main.go:

~~~go
package main

import (
    "os"

    "github.com/vsevo/home-gateway/internal/versioncmd"
)

func main() {
    os.Exit(versioncmd.Run("hgctl", os.Args[1:], os.Stdout, os.Stderr))
}
~~~

- [ ] **Step 5: Run format and tests**

Run:

~~~powershell
.\.tools\go\bin\gofmt.exe -w .\cmd .\internal
if ($LASTEXITCODE -ne 0) { throw 'gofmt failed' }
.\.tools\go\bin\go.exe test ./...
if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
~~~

Expected: all tests pass. The race detector runs in Linux CI, where cc/ld versions are recorded; it is not a local Windows prerequisite.

- [ ] **Step 6: Commit**

Run:

~~~powershell
git add -- go.mod go.work `
    cmd/routerd/main.go cmd/server-agent/main.go cmd/cisco-discovery/main.go cmd/hgctl/main.go `
    internal/buildinfo/buildinfo.go internal/versioncmd/run.go internal/versioncmd/run_test.go
if ($LASTEXITCODE -ne 0) { throw 'git add Go contract failed' }
git commit -m "feat: add versioned binary entrypoints"
if ($LASTEXITCODE -ne 0) { throw 'Go contract commit failed' }
~~~

Expected: one commit containing only the Go contract.

### Task 6: Add cross-platform developer commands

**Files:**

- Create: scripts/dev.ps1
- Create: Makefile
- Create: tests/windows-pester/DevScript.Tests.ps1
- Modify: go.mod
- Create: go.sum

**Interfaces:**

- Consumes: Task 4 toolchain and Task 5 binaries.
- Produces: bootstrap, format, test, lint, build and verify commands.

- [ ] **Step 1: Write the failing Pester contract**

Create tests/windows-pester/DevScript.Tests.ps1:

~~~powershell
BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Dev = Join-Path $script:Root 'scripts/dev.ps1'
}

Describe 'scripts/dev.ps1' {
    It 'exists' {
        $script:Dev | Should -Exist
    }

    It 'rejects an unknown command' {
        { & $script:Dev -Command invalid } | Should -Throw
    }

    It 'builds all four target artifacts' {
        Remove-Item -LiteralPath (Join-Path $script:Root 'build') -Recurse -Force -ErrorAction SilentlyContinue
        & $script:Dev -Command build
        $LASTEXITCODE | Should -Be 0
        @(
            'build/routerd_linux_arm64',
            'build/server-agent_linux_amd64',
            'build/cisco-discovery_windows_amd64.exe',
            'build/hgctl_windows_amd64.exe'
        ) | ForEach-Object {
            Join-Path $script:Root $_ | Should -Exist
        }
        Join-Path $script:Root 'build/SHA256SUMS' | Should -Exist
    }

    It 'fails when a native verification tool fails' {
        $env:PESTER_TEST_ACTIVE = '1'
        $env:HOME_GATEWAY_TEST_FAIL_NATIVE = 'go-vet'
        try {
            { & $script:Dev -Command lint } | Should -Throw '*failed with exit code*'
        } finally {
            Remove-Item Env:HOME_GATEWAY_TEST_FAIL_NATIVE -ErrorAction SilentlyContinue
            Remove-Item Env:PESTER_TEST_ACTIVE -ErrorAction SilentlyContinue
        }
    }

    It 'restores cross-build environment variables' {
        $before = @($env:GOOS, $env:GOARCH, $env:CGO_ENABLED)
        & $script:Dev -Command build
        @($env:GOOS, $env:GOARCH, $env:CGO_ENABLED) | Should -BeExactly $before
    }

    It 'builds the exact target tuples and Windows program contracts' {
        $go = Join-Path $script:Root ".tools/go/bin/go$(if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' })"
        $targets = @(
            @{ Path = 'build/routerd_linux_arm64'; GOOS = 'linux'; GOARCH = 'arm64' },
            @{ Path = 'build/server-agent_linux_amd64'; GOOS = 'linux'; GOARCH = 'amd64' },
            @{ Path = 'build/cisco-discovery_windows_amd64.exe'; GOOS = 'windows'; GOARCH = 'amd64' },
            @{ Path = 'build/hgctl_windows_amd64.exe'; GOOS = 'windows'; GOARCH = 'amd64' }
        )
        foreach ($target in $targets) {
            $metadata = & $go version -m (Join-Path $script:Root $target.Path) 2>&1
            $LASTEXITCODE | Should -Be 0
            $text = $metadata -join "`n"
            $text | Should -Match "GOOS=$($target.GOOS)"
            $text | Should -Match "GOARCH=$($target.GOARCH)"
            $text | Should -Match 'CGO_ENABLED=0'
        }
        if ($env:OS -eq 'Windows_NT') {
            (& (Join-Path $script:Root 'build/cisco-discovery_windows_amd64.exe') version --json | ConvertFrom-Json).program | Should -Be 'cisco-discovery'
            (& (Join-Path $script:Root 'build/hgctl_windows_amd64.exe') version --json | ConvertFrom-Json).program | Should -Be 'hgctl'
        }
    }
}
~~~

Run:

~~~powershell
Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force
$result = Invoke-Pester -Path .\tests\windows-pester\DevScript.Tests.ps1 -Output Detailed -PassThru
if ($result.TotalCount -eq 0 -or $result.Result -ne 'Failed' -or $result.FailedCount -eq 0) {
    throw 'Expected discovered tests to fail because the dev script is missing'
}
~~~

Expected: failure because scripts/dev.ps1 does not exist.

- [ ] **Step 2: Implement scripts/dev.ps1**

The script accepts Command values bootstrap, format, format-check, test, lint, build, pester and verify. It locates .tools/go/bin/go.exe first and then a system go. It must use these build targets:

| Output | GOOS | GOARCH | Package |
|---|---|---|---|
| build/routerd_linux_arm64 | linux | arm64 | ./cmd/routerd |
| build/server-agent_linux_amd64 | linux | amd64 | ./cmd/server-agent |
| build/cisco-discovery_windows_amd64.exe | windows | amd64 | ./cmd/cisco-discovery |
| build/hgctl_windows_amd64.exe | windows | amd64 | ./cmd/hgctl |

Each build sets CGO_ENABLED=0 and uses -trimpath -buildvcs=false. Before each target it captures whether GOOS, GOARCH and CGO_ENABLED existed and their values; a try/finally restores the exact prior values or removes variables that were originally absent. The build command removes stale build output, compiles all four targets twice into separate temporary directories, writes sorted relative SHA256SUMS for each run, compares the complete hash lists, promotes one verified run to build and removes the temporary directories. A mismatch is fatal and retains both runs for diagnosis. scripts/dev.ps1 computes metadata exactly as follows:

~~~powershell
$commit = (git rev-parse HEAD).Trim()
$epoch = 1782737960
$buildDate = [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
$ldflags = @(
    '-s',
    '-w',
    '-X', 'github.com/vsevo/home-gateway/internal/buildinfo.Version=0.0.0-p0',
    '-X', "github.com/vsevo/home-gateway/internal/buildinfo.Commit=$commit",
    '-X', "github.com/vsevo/home-gateway/internal/buildinfo.BuildDate=$buildDate"
) -join ' '
~~~

bootstrap calls bootstrap-dev.ps1, sets GOTOOLCHAIN=local for child processes, downloads the exact module graph and prepares the pinned Go tools from go.mod/go.sum. lint runs go vet, staticcheck 2026.1, gosec 2.27.1, govulncheck 1.1.4, Gitleaks 8.30.1 and Actionlint 1.7.12. On Linux it also runs ShellCheck 0.11.0.

The HOME_GATEWAY_TEST_FAIL_NATIVE hook exists only under Pester and replaces the named native invocation with a child process that exits 17. Production execution rejects that environment variable unless `$env:PESTER_TEST_ACTIVE -eq '1'`; DevScript.Tests.ps1 sets and clears both variables around the failure test. This proves that Invoke-CheckedNative propagates non-zero exits without creating a production bypass.

verify runs, in order: bootstrap, format-check, test, pester, lint, build, scripts/check-governance.ps1 and both bootstrap smoke scripts.

Every native command uses this wrapper, because Windows PowerShell 5.1 does not convert a non-zero native exit code into a terminating error:

~~~powershell
function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$Arguments = @()
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}
~~~

Tool path selection is cross-platform from Task 6 onward:

~~~powershell
$suffix = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$go = Join-Path $root ".tools/go/bin/go$suffix"
$env:GOTOOLCHAIN = 'local'
if (-not (Test-Path -LiteralPath $go)) {
    throw 'Pinned Go toolchain is missing; run bootstrap'
}
~~~

Pester is always imported and checked explicitly:

~~~powershell
$pesterPath = Join-Path $root '.tools/modules/Pester/6.0.0/Pester.psd1'
Import-Module $pesterPath -Force
$result = Invoke-Pester -Path (Join-Path $root 'tests/windows-pester') -Output Detailed -PassThru
if ($result.Result -ne 'Passed' -or $result.TotalCount -eq 0) {
    throw "Pester failed or discovered no tests: $($result.Result)"
}
~~~

- [ ] **Step 3: Pin Go tools in the module graph**

Run with pinned Go 1.26.5:

~~~powershell
$env:GOTOOLCHAIN = 'local'
.\.tools\go\bin\go.exe get -tool golang.org/x/vuln/cmd/govulncheck@v1.1.4
if ($LASTEXITCODE -ne 0) { throw 'pin govulncheck failed' }
.\.tools\go\bin\go.exe get -tool honnef.co/go/tools/cmd/staticcheck@2026.1
if ($LASTEXITCODE -ne 0) { throw 'pin staticcheck failed' }
.\.tools\go\bin\go.exe get -tool github.com/securego/gosec/v2/cmd/gosec@v2.27.1
if ($LASTEXITCODE -ne 0) { throw 'pin gosec failed' }
.\.tools\go\bin\go.exe mod tidy
if ($LASTEXITCODE -ne 0) { throw 'go mod tidy failed' }
.\.tools\go\bin\go.exe mod verify
if ($LASTEXITCODE -ne 0) { throw 'go mod verify failed' }
~~~

Expected: go.mod contains three tool directives with exact versions, go.sum is created, and mod verify reports all modules verified. dev.ps1 invokes them through go tool, not through mutable binaries in PATH.

- [ ] **Step 4: Create the Makefile**

~~~make
PWSH ?= pwsh

.PHONY: bootstrap format format-check test lint build pester verify

bootstrap:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command bootstrap

format:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command format

format-check:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command format-check

test:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command test

lint:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command lint

build:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command build

pester:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command pester

verify:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command verify
~~~

- [ ] **Step 5: Make the Pester contract pass**

Run:

~~~powershell
Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force
$result = Invoke-Pester -Path .\tests\windows-pester\DevScript.Tests.ps1 -Output Detailed -PassThru
if ($result.Result -ne 'Passed' -or $result.TotalCount -eq 0) { throw "Pester gate failed: $($result.Result)" }
.\scripts\dev.ps1 -Command bootstrap
.\scripts\dev.ps1 -Command verify
~~~

Expected: six Pester tests pass, including forced native-failure propagation, environment restoration and exact target metadata, and verify exits 0.

- [ ] **Step 6: Inspect binary metadata and commit**

Run:

~~~powershell
.\build\cisco-discovery_windows_amd64.exe version --json
if ($LASTEXITCODE -ne 0) { throw 'cisco-discovery version probe failed' }
.\build\hgctl_windows_amd64.exe version --json
if ($LASTEXITCODE -ne 0) { throw 'hgctl version probe failed' }
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'git diff --check failed' }
git add -- scripts/dev.ps1 Makefile tests/windows-pester/DevScript.Tests.ps1 go.mod go.sum
if ($LASTEXITCODE -ne 0) { throw 'git add developer commands failed' }
git commit -m "build: add reproducible developer commands"
if ($LASTEXITCODE -ne 0) { throw 'developer commands commit failed' }
~~~

Expected: valid JSON with version 0.0.0-p0 and one focused commit.

### Task 7: Add safe configuration examples and the OpenAPI boundary

**Files:**

- Create: configs/defaults.yaml
- Create: configs/inventory.example.yaml
- Create: configs/routerd.example.yaml
- Create: configs/builtin-sources.yaml
- Create: api/openapi.yaml
- Create: tests/windows-pester/Configuration.Tests.ps1

**Interfaces:**

- Consumes: decisions from ADR-0004, ADR-0008 and the defaults in SPEC.md §38.
- Produces: secret-free examples and an intentionally empty API skeleton owned by P4.

- [ ] **Step 1: Write failing configuration tests**

Create tests/windows-pester/Configuration.Tests.ps1:

~~~powershell
BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

Describe 'configuration baseline' {
    It 'contains all safe defaults' {
        $text = Get-Content (Join-Path $script:Root 'configs/defaults.yaml') -Raw
        $expected = @(
            'schema_version: 1'
            'default_route: direct'
            'vpn_failure_policy: fail_closed_for_vpn_entries'
            'external_source_mode: staged_auto_for_trusted'
            'source_refresh: 6h'
            'source_jitter: 30m'
            'server_mode: manual_sticky'
            'health_failures_to_down: 3'
            'health_successes_to_up: 2'
            'failover_hold_down: 120s'
            'failback_stable_period: 10m'
            'one_time_profile_ttl: 10m'
            'dns_query_logging: false'
            'panel_wan_access: false'
            'panel_guest_access: false'
            'mobile_peer_to_peer: false'
            'ipv6_policy: route_or_block_no_leak'
            'backup_retention: 7d/4w/6m'
        ) -join "`n"
        (($text -replace "`r`n", "`n").Trim()) | Should -BeExactly $expected
    }

    It 'models both work PC identities' {
        $text = Get-Content (Join-Path $script:Root 'configs/inventory.example.yaml') -Raw
        $text | Should -Match 'kind: ethernet'
        $text | Should -Match 'kind: flint-wifi'
        $text | Should -Match 'allow_repeater: false'
        $text | Should -Match '(?s)id: work-pc.*kind: ethernet.*kind: flint-wifi'
    }

    It 'keeps router access local and built-in sources empty' {
        $router = Get-Content (Join-Path $script:Root 'configs/routerd.example.yaml') -Raw
        $router | Should -Match '(?m)^  wan: false$'
        $router | Should -Match '(?m)^  guest: false$'
        $router | Should -Match '(?m)^  mobile_peers: false$'
        $sources = Get-Content (Join-Path $script:Root 'configs/builtin-sources.yaml') -Raw
        $sources | Should -Match '(?m)^qualification_phase: P6$'
        $sources | Should -Match '(?m)^sources: \[\]$'
    }

    It 'contains no secret values' {
        $files = Get-ChildItem (Join-Path $script:Root 'configs') -File
        foreach ($file in $files) {
            $text = Get-Content $file.FullName -Raw
            $text | Should -Not -Match '(?im)^\s*(password|private_key|preshared_key|token):\s*\S+'
        }
    }

    It 'has a valid JSON-subset OpenAPI document' {
        $raw = Get-Content (Join-Path $script:Root 'api/openapi.yaml') -Raw
        $api = $raw | ConvertFrom-Json
        $api.openapi | Should -Be '3.0.3'
        $api.servers[0].url | Should -Be 'https://router.home.arpa:8443'
        @($api.paths.PSObject.Properties).Count | Should -Be 0
    }
}
~~~

Run:

~~~powershell
Import-Module .\.tools\modules\Pester\6.0.0\Pester.psd1 -Force
$result = Invoke-Pester -Path .\tests\windows-pester\Configuration.Tests.ps1 -Output Detailed -PassThru
if ($result.TotalCount -eq 0 -or $result.Result -ne 'Failed' -or $result.FailedCount -eq 0) {
    throw 'Expected discovered configuration tests to fail on missing files'
}
~~~

Expected: failure because the files do not exist.

- [ ] **Step 2: Add exact defaults**

configs/defaults.yaml:

~~~yaml
schema_version: 1
default_route: direct
vpn_failure_policy: fail_closed_for_vpn_entries
external_source_mode: staged_auto_for_trusted
source_refresh: 6h
source_jitter: 30m
server_mode: manual_sticky
health_failures_to_down: 3
health_successes_to_up: 2
failover_hold_down: 120s
failback_stable_period: 10m
one_time_profile_ttl: 10m
dns_query_logging: false
panel_wan_access: false
panel_guest_access: false
mobile_peer_to_peer: false
ipv6_policy: route_or_block_no_leak
backup_retention: 7d/4w/6m
~~~

- [ ] **Step 3: Add the inventory and router examples**

configs/inventory.example.yaml:

~~~yaml
schema_version: 1
project:
  name: home-gateway
  timezone: Europe/Kaliningrad
router:
  model: glinet_gl-mt6000
  address: 192.168.10.1
  admin_hostname: router.home.arpa
  openwrt_version: 25.12.5
  wan:
    mode: dhcp
    vlan_id: null
workstation:
  id: work-pc
  hostname: SET_DURING_INSTALL
  reserved_ip: 192.168.10.10
  allow_repeater: false
  identities:
    - kind: ethernet
      mac: SET_DURING_INSTALL
    - kind: flint-wifi
      mac: SET_DURING_INSTALL
servers:
  - id: primary-1
    host: SET_DURING_INSTALL
    ssh_user: bootstrap
    country: SET_DURING_INSTALL
    priority: 10
    transports:
      - amneziawg2
~~~

configs/routerd.example.yaml:

~~~yaml
schema_version: 1
listen:
  address: 192.168.10.1
  port: 8443
  hostname: router.home.arpa
paths:
  state: /etc/routerd
  runtime: /var/run/routerd
  secrets: /etc/routerd/secrets
access:
  wan: false
  guest: false
  mobile_peers: false
~~~

configs/builtin-sources.yaml:

~~~yaml
schema_version: 1
qualification_phase: P6
sources: []
~~~

The empty list is intentional: P0 does not ship mutable or semantically unverified upstream presets.

- [ ] **Step 4: Add the OpenAPI skeleton**

api/openapi.yaml:

~~~json
{
  "openapi": "3.0.3",
  "info": {
    "title": "Home Gateway Local API",
    "version": "0.0.0-p0",
    "description": "P0 contract boundary. P4 owns endpoint definitions."
  },
  "servers": [
    {
      "url": "https://router.home.arpa:8443"
    }
  ],
  "paths": {}
}
~~~

- [ ] **Step 5: Verify and commit**

Run:

~~~powershell
.\scripts\dev.ps1 -Command pester
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'git diff --check failed' }
git add -- configs/defaults.yaml configs/inventory.example.yaml configs/routerd.example.yaml configs/builtin-sources.yaml `
    api/openapi.yaml tests/windows-pester/Configuration.Tests.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add configuration contracts failed' }
git commit -m "chore: add safe configuration contracts"
if ($LASTEXITCODE -ne 0) { throw 'configuration contract commit failed' }
~~~

Expected: five Pester tests pass.

---

## P0B — Compatibility

### Task 8: Create the executable Linux network-lab prerequisite smoke

**Files:**

- Create: tests/network-ns/check-prereqs.sh
- Create: tests/network-ns/README.md
- Create: tests/openwrt-qemu/README.md

**Interfaces:**

- Consumes: Linux with root, iproute2, nftables, dnsmasq-full or dnsmasq, jq and curl.
- Produces: a proven privileged network-namespace capability prerequisite for P2; CAP_NET_ADMIN alone may be insufficient inside restricted containers.

- [ ] **Step 1: Create the prerequisite script**

tests/network-ns/check-prereqs.sh:

~~~sh
#!/bin/sh
set -eu

for command in ip nft dnsmasq jq curl; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing command: $command" >&2
        exit 1
    fi
done

if [ "$(id -u)" -ne 0 ]; then
    echo "root is required for network namespace smoke" >&2
    exit 2
fi

namespace="hg-p0-$$"
cleanup() {
    ip netns del "$namespace" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ip netns add "$namespace"
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" nft -c -f /dev/stdin <<'EOF'
table inet home_gateway_p0 {
    chain input {
        type filter hook input priority filter;
        policy accept;
    }
}
EOF
ip netns exec "$namespace" dnsmasq --version >/dev/null

ip netns del "$namespace"
trap - EXIT INT TERM
if ip netns list | awk '{print $1}' | grep -Fx "$namespace" >/dev/null; then
    echo "namespace cleanup failed: $namespace" >&2
    exit 3
fi

echo "NETWORK_LAB_PREREQUISITES_PASS"
~~~

- [ ] **Step 2: Document exact lab scope**

tests/network-ns/README.md states that P0 only proves tool/capability availability. P2 owns routing topology, packet capture, DNS nftsets, fault injection and no-leak assertions.

tests/openwrt-qemu/README.md states that P0 prepares package metadata and CI. P2 owns x86_64 OpenWrt QEMU runtime tests; filogic kernel module execution requires real GL-MT6000 hardware.

- [ ] **Step 3: Run the expected failure on Windows**

Run from PowerShell:

~~~powershell
wsl.exe -- sh -lc 'cd /mnt/c/Users/vsevo/AI-core/home_gateway && sudo tests/network-ns/check-prereqs.sh'
~~~

Expected in the current environment: a clear missing Linux distro/tool or missing-command failure. Record this as an environment prerequisite, not a product failure.

- [ ] **Step 4: Run it on the Linux CI/lab**

Run:

~~~sh
sudo tests/network-ns/check-prereqs.sh
~~~

Expected: NETWORK_LAB_PREREQUISITES_PASS and no namespace left by ip netns list.

- [ ] **Step 5: Commit**

Run:

~~~powershell
git add --chmod=+x -- tests/network-ns/check-prereqs.sh
if ($LASTEXITCODE -ne 0) { throw 'git add executable network smoke failed' }
git add -- tests/network-ns/README.md tests/openwrt-qemu/README.md
if ($LASTEXITCODE -ne 0) { throw 'git add network lab docs failed' }
$entry = git ls-files --stage tests/network-ns/check-prereqs.sh
if ($LASTEXITCODE -ne 0 -or $entry -notmatch '^100755 ') { throw 'network smoke Git mode is not 100755' }
git commit -m "test: add network lab prerequisite smoke"
if ($LASTEXITCODE -ne 0) { throw 'network smoke commit failed' }
~~~

Expected before commit: check-prereqs.sh has mode 100755.

### Task 9: Add the verified OpenWrt SDK fetch harness

**Files:**

- Create: scripts/openwrt/fetch-sdk.sh
- Create: tests/openwrt-sdk/LockMetadata.Smoke.ps1

**Interfaces:**

- Consumes: manifest/versions.lock.yaml, curl, jq, sha256sum, tar and zstd.
- Produces: .cache/openwrt-sdk containing the exact 25.12.5 filogic SDK.

- [ ] **Step 1: Write the failing metadata smoke**

tests/openwrt-sdk/LockMetadata.Smoke.ps1:

~~~powershell
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$lock = Get-Content (Join-Path $root 'manifest/versions.lock.yaml') -Raw | ConvertFrom-Json

if ($lock.openwrt.version -ne '25.12.5') { throw 'wrong OpenWrt version' }
if ($lock.openwrt.target -ne 'mediatek/filogic') { throw 'wrong target' }
if ($lock.openwrt.profile -ne 'glinet_gl-mt6000') { throw 'wrong profile' }
if ($lock.openwrt.package_arch -ne 'aarch64_cortex-a53') { throw 'wrong package arch' }
if ($lock.openwrt.kernel_vermagic -ne '5a6c1f71be683ae9980b15d3ce73e24d') { throw 'wrong vermagic' }
if (-not (Test-Path (Join-Path $root 'scripts/openwrt/fetch-sdk.sh'))) { throw 'fetch script missing' }

'OPENWRT_LOCK_METADATA_PASS'
~~~

Run it.

Expected: failure with fetch script missing.

- [ ] **Step 2: Implement fetch-sdk.sh**

The script reads the SDK URL and SHA from the JSON-subset lock, downloads to .cache/downloads with a partial suffix, verifies SHA-256, extracts to .cache/openwrt-sdk/$expected and verifies include/toplevel.mk. The cache directory is keyed by the locked SHA, must contain exactly one top-level SDK directory and is cleanly re-extracted when its marker or content is invalid. It always resolves the SDK path after the conditional extraction and prints that path as its last line.

Use this exact command sequence after computing root, url and expected:

~~~sh
mkdir -p "$root/.cache/downloads" "$root/.cache/openwrt-sdk"
archive="$root/.cache/downloads/$(basename "$url")"
if [ ! -f "$archive" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$archive.partial"
    echo "$expected  $archive.partial" | sha256sum --check -
    mv "$archive.partial" "$archive"
fi
echo "$expected  $archive" | sha256sum --check -
content="$root/.cache/openwrt-sdk/$expected"
marker="$content/.complete"
valid_cache=false
if [ -f "$marker" ] && [ "$(cat "$marker")" = "$expected" ]; then
    count="$(find "$content" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    if [ "$count" = 1 ]; then
        candidate="$(find "$content" -mindepth 1 -maxdepth 1 -type d -print)"
        [ -f "$candidate/include/toplevel.mk" ] && valid_cache=true
    fi
fi
if [ "$valid_cache" != true ]; then
    rm -rf "$content"
    mkdir -p "$content"
    tar --zstd -xf "$archive" -C "$content"
    count="$(find "$content" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    [ "$count" = 1 ]
    candidate="$(find "$content" -mindepth 1 -maxdepth 1 -type d -print)"
    test -f "$candidate/include/toplevel.mk"
    printf '%s\n' "$expected" > "$marker"
fi
sdk="$(find "$content" -mindepth 1 -maxdepth 1 -type d -print)"
test -f "$sdk/include/toplevel.mk"
printf '%s\n' "$sdk"
~~~

- [ ] **Step 3: Make metadata and fetch tests pass**

Run:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\openwrt-sdk\LockMetadata.Smoke.ps1
if ($LASTEXITCODE -ne 0) { throw 'OpenWrt lock metadata smoke failed' }
~~~

Run on Linux:

~~~sh
first="$(scripts/openwrt/fetch-sdk.sh)"
second="$(scripts/openwrt/fetch-sdk.sh)"
test "$first" = "$second"
test -f "$second/include/toplevel.mk"
~~~

Expected: OPENWRT_LOCK_METADATA_PASS, verified SDK extraction and a path ending in the 25.12.5 filogic SDK directory.

- [ ] **Step 4: Commit**

Run:

~~~powershell
git add --chmod=+x -- scripts/openwrt/fetch-sdk.sh
if ($LASTEXITCODE -ne 0) { throw 'git add executable SDK fetch failed' }
git add -- tests/openwrt-sdk/LockMetadata.Smoke.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add SDK metadata smoke failed' }
$entry = git ls-files --stage scripts/openwrt/fetch-sdk.sh
if ($LASTEXITCODE -ne 0 -or $entry -notmatch '^100755 ') { throw 'SDK fetch Git mode is not 100755' }
git commit -m "build: add verified OpenWrt SDK fetch"
if ($LASTEXITCODE -ne 0) { throw 'SDK fetch commit failed' }
~~~

Expected before commit: fetch-sdk.sh has mode 100755.

### Task 10: Port official AWG2 sources into OpenWrt packages

**Files:**

- Create: packaging/openwrt-awg2/kmod-amneziawg/Makefile
- Create: packaging/openwrt-awg2/amneziawg-tools/Makefile
- Create: packaging/openwrt-awg2/amneziawg-tools/files/amneziawg.sh
- Create: packaging/openwrt-awg2/amneziawg-tools/files/amneziawg_watchdog
- Create: scripts/openwrt/build-packages.sh
- Create: tests/openwrt-sdk/AWG2Package.Tests.ps1
- Create: tests/openwrt-sdk/assert-awg2-helper.sh

**Interfaces:**

- Consumes: pinned official kernel/tools sources and exact OpenWrt SDK.
- Produces: kmod-amneziawg and amneziawg-tools APKs plus an AWG2-capable netifd helper.

- [ ] **Step 1: Write failing package-layout tests**

tests/openwrt-sdk/AWG2Package.Tests.ps1 checks:

1. both package Makefiles exist;
2. kernel version is 1.0.20260611 and hash is e062ecc9f1d89eeafa9f56a29473372a1d796ee061eaa8c7b61eeb51c38b80d6;
3. tools version is 1.0.20260618-2 and hash is cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10;
4. the helper declares and renders S3, S4, I1, I2, I3, I4 and I5;
5. H1-H4 and I1-I5 use string config types;
6. route_allowed_ips defaults to 0;
7. the kernel package declares PKG_EXTMOD_SUBDIRS:=src;
8. the tools package uses SUBMENU:=VPN, conditional ip fallback and +kmod-amneziawg;
9. the helper contains the OpenWrt 25.12.5 renew_handler, peer_detect, addresses and renew contracts;
10. build-packages.sh selects both packages, validates actual SDK tuple/APK metadata and owns SOURCE_DATE_EPOCH/OUTPUT_DIR cleanup;
11. no source URL or Makefile contains latest.

Run it and expect missing-file failures.

- [ ] **Step 2: Create the kernel package Makefile**

Use this complete Makefile:

~~~make
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=kmod-amneziawg
PKG_VERSION:=1.0.20260611
PKG_RELEASE:=1
PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/archive/refs/tags/
PKG_HASH:=e062ecc9f1d89eeafa9f56a29473372a1d796ee061eaa8c7b61eeb51c38b80d6
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/amneziawg-linux-kernel-module-$(PKG_VERSION)
PKG_MAINTAINER:=Home Gateway Project
PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=COPYING
PKG_EXTMOD_SUBDIRS:=src

include $(INCLUDE_DIR)/package.mk

define KernelPackage/amneziawg
  SUBMENU:=Network Support
  TITLE:=AmneziaWG 2 kernel module
  URL:=https://github.com/amnezia-vpn/amneziawg-linux-kernel-module
  DEPENDS:=+kmod-crypto-lib-chacha20poly1305 +kmod-crypto-lib-curve25519 +kmod-udptunnel4 +IPV6:kmod-udptunnel6
  FILES:=$(PKG_BUILD_DIR)/src/amneziawg.ko
  AUTOLOAD:=$(call AutoProbe,amneziawg)
endef

define KernelPackage/amneziawg/description
  Official AmneziaWG 2 kernel module packaged for the pinned Home Gateway OpenWrt target.
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(KERNEL_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)/src" \
		WIREGUARD_VERSION="$(PKG_VERSION)" \
		modules
endef

$(eval $(call KernelPackage,amneziawg))
~~~

- [ ] **Step 3: Create the tools package Makefile**

Use this complete Makefile:

~~~make
include $(TOPDIR)/rules.mk

PKG_NAME:=amneziawg-tools
PKG_VERSION:=1.0.20260618-2
PKG_RELEASE:=1
PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/
PKG_HASH:=cbda09c90d0740b6c3d39622da9f96cfdc2b83459d45973aadd7bf77518fdf10
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_MAINTAINER:=Home Gateway Project
PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=COPYING

include $(INCLUDE_DIR)/package.mk

MAKE_PATH:=src
MAKE_VARS+=PLATFORM=linux WITH_WGQUICK=no WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no

define Package/amneziawg-tools
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=AmneziaWG 2 userspace tools
  URL:=https://github.com/amnezia-vpn/amneziawg-tools
  DEPENDS:= \
	+!BUSYBOX_CONFIG_IP:ip \
	+!BUSYBOX_CONFIG_FEATURE_IP_LINK:ip \
	+kmod-amneziawg
endef

define Package/amneziawg-tools/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/wg $(1)/usr/bin/awg
	$(INSTALL_BIN) ./files/amneziawg_watchdog $(1)/usr/bin/amneziawg_watchdog
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files/amneziawg.sh $(1)/lib/netifd/proto/amneziawg.sh
endef

$(eval $(call BuildPackage,amneziawg-tools))
~~~

- [ ] **Step 4: Port the pinned netifd helper with AWG2 fields**

Use the Apache-2.0 helper from amneziawg-openwrt commit 56bf9fed93df48d2b747edd6e7a7c5fbe2b01afe as the baseline and preserve its license header. Apply these exact schema changes:

~~~diff
+ proto_config_add_int "awg_s3"
+ proto_config_add_int "awg_s4"
- proto_config_add_int "awg_h1"
- proto_config_add_int "awg_h2"
- proto_config_add_int "awg_h3"
- proto_config_add_int "awg_h4"
+ proto_config_add_string "awg_h1"
+ proto_config_add_string "awg_h2"
+ proto_config_add_string "awg_h3"
+ proto_config_add_string "awg_h4"
+ proto_config_add_string "awg_i1"
+ proto_config_add_string "awg_i2"
+ proto_config_add_string "awg_i3"
+ proto_config_add_string "awg_i4"
+ proto_config_add_string "awg_i5"
~~~

Declare, config_get and render S3, S4 and I1-I5 exactly as the existing S1/S2 and H fields are handled. H1-H4 remain strings because current tools accept ranged values. Keep route_allowed_ips default 0.

Forward-port the adapter onto the OpenWrt 25.12.5 wireguard helper contract: preserve renew_handler=1, peer_detect=1, proto_config_add_string "addresses" and the renew handler from package/network/utils/wireguard-tools/files/wireguard.sh at tag v25.12.5. A missing backend must exit 1 explicitly; do not capture $? after ! command -v because that path returns zero. Teardown only removes the temporary link/socket and must not load the module or run a setup-time backend check.

Vendor amneziawg_watchdog from the same pinned adapter commit and preserve its GPL-2.0 header.

- [ ] **Step 5: Add executable helper assertions**

tests/openwrt-sdk/assert-awg2-helper.sh loops over awg_s3, awg_s4, awg_i1 through awg_i5 and requires each key in declaration, config_get and rendered output. It also rejects proto_config_add_int for awg_h1 through awg_h4, rejects a route_allowed_ips default other than 0, requires renew_handler, peer_detect, addresses and renew behavior, and executes a missing-backend fixture that must return 1. A teardown fixture must prove that neither modprobe nor awg is invoked.

Run:

~~~powershell
.\scripts\dev.ps1 -Command pester
wsl.exe -- sh -lc 'cd /mnt/c/Users/vsevo/AI-core/home_gateway && tests/openwrt-sdk/assert-awg2-helper.sh'
~~~

Expected: all package tests and executable helper fixtures pass. On a non-Linux workstation the executable assertion is deferred to the mandatory Linux CI/lab run; it is not waived.

- [ ] **Step 6: Implement the SDK build**

scripts/openwrt/build-packages.sh accepts OUTPUT_DIR, removes that directory before every build, reads and exports the locked SOURCE_DATE_EPOCH and rejects a conflicting caller-provided value. It then:

1. calls fetch-sdk.sh;
2. copies the two package directories into package/home-gateway in the extracted SDK;
3. writes CONFIG_PACKAGE_kmod-amneziawg=m and CONFIG_PACKAGE_amneziawg-tools=m to the SDK .config, then runs make defconfig and asserts both values remain selected;
4. removes `$sdk/package/home-gateway`, copies a fresh package tree, runs explicit clean targets for both packages and only then compiles them;
5. runs make package/kmod-amneziawg/compile V=s and make package/amneziawg-tools/compile V=s;
6. queries actual SDK values and requires revision r33051-f5dae5ece4, kernel 6.12.94, vermagic 5a6c1f71be683ae9980b15d3ce73e24d and package architecture aarch64_cortex-a53;
7. requires exactly one APK for each expected package, then uses the SDK host apk adbdump to prove both architectures, the kmod dependency `kernel=6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1`, the tools dependency on kmod-amneziawg, and the expected module/tool/helper/watchdog payload paths;
8. copies only those two APKs to OUTPUT_DIR;
9. writes sorted relative filenames to SHA256SUMS and measured build metadata containing source pins, actual OpenWrt revision, kernel, vermagic, architecture and SOURCE_DATE_EPOCH.

The build commands are:

~~~sh
rm -rf "$sdk/package/home-gateway"
mkdir -p "$sdk/package/home-gateway"
cp -a "$root/packaging/openwrt-awg2/." "$sdk/package/home-gateway/"
printf '%s\n' \
    'CONFIG_PACKAGE_kmod-amneziawg=m' \
    'CONFIG_PACKAGE_amneziawg-tools=m' \
    >> "$sdk/.config"
make -C "$sdk" defconfig
grep -qx 'CONFIG_PACKAGE_kmod-amneziawg=m' "$sdk/.config"
grep -qx 'CONFIG_PACKAGE_amneziawg-tools=m' "$sdk/.config"
make -C "$sdk" package/kmod-amneziawg/clean
make -C "$sdk" package/amneziawg-tools/clean
make -C "$sdk" package/kmod-amneziawg/compile V=s
make -C "$sdk" package/amneziawg-tools/compile V=s
test "$(make -s -C "$sdk" val.REVISION)" = 'r33051-f5dae5ece4'
test "$(make -s -C "$sdk" val.LINUX_VERSION)" = '6.12.94'
test "$(make -s -C "$sdk" val.LINUX_VERMAGIC)" = '5a6c1f71be683ae9980b15d3ce73e24d'
test "$(make -s -C "$sdk" val.ARCH_PACKAGES)" = 'aarch64_cortex-a53'
~~~

- [ ] **Step 7: Build twice and compare**

Run on Linux:

~~~sh
rm -rf artifacts/openwrt-run1 artifacts/openwrt-run2
OUTPUT_DIR="$PWD/artifacts/openwrt-run1" scripts/openwrt/build-packages.sh
rm -rf .cache/openwrt-sdk
OUTPUT_DIR="$PWD/artifacts/openwrt-run2" scripts/openwrt/build-packages.sh
diff -ru --no-dereference artifacts/openwrt-run1 artifacts/openwrt-run2
~~~

Expected: both package builds pass and SHA256SUMS is identical. If hashes differ, Task 10 fails: retain both artifacts, generate a diffoscope report, record it in docs/COMPATIBILITY.md and stop before commit. A separate reviewed fix plan must name the observed nondeterministic field; do not normalize bytes blindly or waive the comparison.

- [ ] **Step 8: Commit**

Run:

~~~powershell
git add --chmod=+x -- packaging/openwrt-awg2/amneziawg-tools/files/amneziawg.sh packaging/openwrt-awg2/amneziawg-tools/files/amneziawg_watchdog
if ($LASTEXITCODE -ne 0) { throw 'git add executable AWG helpers failed' }
git add --chmod=+x -- scripts/openwrt/build-packages.sh tests/openwrt-sdk/assert-awg2-helper.sh
if ($LASTEXITCODE -ne 0) { throw 'git add executable AWG build/tests failed' }
git add -- packaging/openwrt-awg2/kmod-amneziawg/Makefile packaging/openwrt-awg2/amneziawg-tools/Makefile tests/openwrt-sdk/AWG2Package.Tests.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add AWG package sources failed' }
$entries = @(git ls-files --stage packaging/openwrt-awg2/amneziawg-tools/files scripts/openwrt/build-packages.sh tests/openwrt-sdk/assert-awg2-helper.sh)
if ($LASTEXITCODE -ne 0 -or @($entries | Where-Object { $_ -notmatch '^100755 ' }).Count -ne 0) { throw 'AWG helper/build Git mode is not 100755' }
git commit -m "build: package official AmneziaWG 2 for OpenWrt"
if ($LASTEXITCODE -ne 0) { throw 'AWG package commit failed' }
~~~

Expected before commit: every shell/helper entry has mode 100755. Artifacts remain ignored.

### Task 11: Build and measure the userspace AWG contingency

**Files:**

- Create: scripts/openwrt/build-amneziawg-go.sh
- Create: tests/openwrt-sdk/AWGGo.Tests.ps1
- Modify: docs/COMPATIBILITY.md

**Interfaces:**

- Consumes: pinned amneziawg-go v0.2.19 source and Go 1.26.5.
- Produces: a linux/arm64 contingency binary and size/build metadata; it does not select the contingency for production.

- [ ] **Step 1: Write the failing contract**

tests/openwrt-sdk/AWGGo.Tests.ps1 requires:

- script path exists;
- script contains v0.2.19 source key lookup from the lock;
- GOOS=linux, GOARCH=arm64 and CGO_ENABLED=0;
- GOWORK=off, GOTOOLCHAIN=local, GOFLAGS=-mod=readonly and GOSUMDB=sum.golang.org;
- exact Go go1.26.5 check, go mod verify and -buildvcs=false;
- source extraction path keyed by the locked SHA and clean re-extraction on every invocation;
- output name artifacts/openwrt/aarch64_cortex-a53/amneziawg-go;
- no latest string.

Run it and expect missing-script failure.

- [ ] **Step 2: Implement the build script**

The script downloads and verifies awg_go_source, then removes and recreates `.cache/awg-go-source/$locked_sha` and extracts the verified archive into that SHA-keyed directory on every invocation. Reusing an extracted source tree is forbidden because go mod verify does not verify the main module's source files. It deliberately disables the repository workspace, accepts OUTPUT_DIR, removes that directory before each build, and uses the workspace-local Go binary when available; the system fallback is allowed only when it reports exactly go1.26.5. Use this exact preamble and build contract:

~~~sh
export GOWORK=off
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export GOSUMDB=sum.golang.org

go_bin="$root/.tools/go/bin/go"
if [ ! -x "$go_bin" ]; then
    go_bin="$(command -v go)"
fi
test "$("$go_bin" env GOVERSION)" = 'go1.26.5'
"$go_bin" mod verify
"$go_bin" test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    "$go_bin" build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "$output_dir/amneziawg-go" .
"$go_bin" version -m "$output_dir/amneziawg-go" \
    > "$output_dir/amneziawg-go.buildinfo"
sha256sum "$output_dir/amneziawg-go" \
    > "$output_dir/amneziawg-go.sha256"
~~~

The metadata file also records source URL, locked SHA-256, tag v0.2.19, commit 1cc94272ca8e9e223a5fe76382f5880f09d3c12d, exact Go version, GOOS/GOARCH/CGO values, build flags, byte size and binary SHA-256. It must be derived from measured output, not copied blindly from the lock.

- [ ] **Step 3: Run tests and record evidence**

Run:

~~~powershell
.\scripts\dev.ps1 -Command pester
~~~

Run twice on Linux into clean output directories:

~~~sh
rm -rf artifacts/awg-go-run1 artifacts/awg-go-run2
OUTPUT_DIR="$PWD/artifacts/awg-go-run1" scripts/openwrt/build-amneziawg-go.sh
OUTPUT_DIR="$PWD/artifacts/awg-go-run2" scripts/openwrt/build-amneziawg-go.sh
diff -ru --no-dereference artifacts/awg-go-run1 artifacts/awg-go-run2
file artifacts/awg-go-run2/amneziawg-go
stat -c '%s' artifacts/awg-go-run2/amneziawg-go
~~~

Expected: tests pass; both complete output trees are byte-identical; file reports a statically linked ARM aarch64 executable. Record byte size and SHA in docs/COMPATIBILITY.md. Do not claim the 300 Mbps target without P3 hardware benchmark.

- [ ] **Step 4: Commit**

Run:

~~~powershell
git add --chmod=+x -- scripts/openwrt/build-amneziawg-go.sh
if ($LASTEXITCODE -ne 0) { throw 'git add executable AWG Go build failed' }
git add -- tests/openwrt-sdk/AWGGo.Tests.ps1 docs/COMPATIBILITY.md
if ($LASTEXITCODE -ne 0) { throw 'git add AWG Go evidence failed' }
$entry = git ls-files --stage scripts/openwrt/build-amneziawg-go.sh
if ($LASTEXITCODE -ne 0 -or $entry -notmatch '^100755 ') { throw 'AWG Go build Git mode is not 100755' }
git commit -m "build: add measured AWG userspace contingency"
if ($LASTEXITCODE -ne 0) { throw 'AWG Go contingency commit failed' }
~~~

Expected before commit: build-amneziawg-go.sh has mode 100755.

### Task 12: Add pinned CI and security verification

**Files:**

- Create: .github/workflows/ci.yml
- Create: .github/workflows/openwrt-sdk.yml
- Create: tests/windows-pester/Workflow.Tests.ps1

**Interfaces:**

- Consumes: all P0A/P0B scripts and pinned action commit SHAs.
- Produces: Windows, Linux, network-lab, security and SDK evidence.

- [ ] **Step 1: Write failing workflow tests**

tests/windows-pester/Workflow.Tests.ps1 reads both workflow files and asserts:

- permissions contains contents: read;
- actions/checkout uses 9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0;
- actions/setup-go uses 924ae3a1cded613372ab5595356fb5720e22ba16;
- actions/upload-artifact uses 043fb46d1a93c77aae656e7c1c64a875d1fc6a0a;
- no uses reference ends in a mutable major tag;
- no latest string;
- every checkout sets fetch-depth: 0 and persist-credentials: false;
- Windows and Linux verify commands are present;
- Linux records `cc --version` and `ld --version`, then runs go test -race ./...;
- OpenWrt SDK workflow performs two clean package builds and two clean amneziawg-go builds, then compares complete output trees.

Run it and expect missing workflow failures.

- [ ] **Step 2: Create ci.yml**

Use this workflow structure:

~~~yaml
name: ci

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  windows:
    runs-on: windows-2025
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
        with:
          fetch-depth: 0
          persist-credentials: false
      - shell: powershell
        run: .\scripts\bootstrap-dev.ps1
      - shell: powershell
        run: .\scripts\dev.ps1 -Command verify

  linux:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16
        with:
          go-version: 1.26.5
          cache: true
      - shell: pwsh
        run: ./scripts/bootstrap-dev.ps1 -IncludePowerShell
      - run: make PWSH=./.tools/pwsh/pwsh verify
      - run: cc --version && ld --version
      - run: go test -race ./...
      - run: sudo apt-get update && sudo apt-get install --yes dnsmasq-base iproute2 jq nftables
      - run: sudo tests/network-ns/check-prereqs.sh
~~~

bootstrap-dev.ps1 must select Windows or Linux Go/Gitleaks artifacts based on runtime and use system Go when it is already exactly 1.26.5.

- [ ] **Step 3: Create openwrt-sdk.yml**

The workflow runs on ubuntu-24.04, uses the same pinned checkout with fetch-depth: 0 and persist-credentials: false, uses pinned setup-go with Go 1.26.5, calls bootstrap-dev.ps1 -IncludePowerShell, installs curl, jq, make, tar, xz-utils and zstd, and runs two clean reproducibility builds:

~~~sh
tests/openwrt-sdk/assert-awg2-helper.sh
OUTPUT_DIR="$PWD/artifacts/openwrt-run1" scripts/openwrt/build-packages.sh
rm -rf .cache/openwrt-sdk
OUTPUT_DIR="$PWD/artifacts/openwrt-run2" scripts/openwrt/build-packages.sh
diff -ru --no-dereference artifacts/openwrt-run1 artifacts/openwrt-run2
OUTPUT_DIR="$PWD/artifacts/awg-go-run1" scripts/openwrt/build-amneziawg-go.sh
OUTPUT_DIR="$PWD/artifacts/awg-go-run2" scripts/openwrt/build-amneziawg-go.sh
diff -ru --no-dereference artifacts/awg-go-run1 artifacts/awg-go-run2
.tools/bin/shellcheck scripts/openwrt/*.sh tests/network-ns/*.sh tests/openwrt-sdk/*.sh
~~~

and uploads only the verified `artifacts/openwrt-run2` and `artifacts/awg-go-run2` directories with the pinned upload-artifact action, `if-no-files-found: error` and retention-days: 7. It has contents: read only and timeout-minutes: 90. Workflow tests reject the stale path `artifacts/openwrt` and require both verified directories plus the fail-closed upload option.

- [ ] **Step 4: Run workflow tests and local security checks**

Run:

~~~powershell
.\scripts\dev.ps1 -Command pester
.\scripts\dev.ps1 -Command lint
~~~

Expected: workflow tests, go vet, staticcheck, gosec, govulncheck and Gitleaks pass.

Run the pinned local workflow validator:

~~~powershell
.\.tools\bin\actionlint.exe
if ($LASTEXITCODE -ne 0) { throw 'Actionlint failed' }
~~~

Expected: Actionlint 1.7.12 exits 0. A hosted GitHub run is recorded only after an origin exists; local Actionlint and equivalent commands are the P0 gate without a remote.

Run on Linux:

~~~sh
.tools/bin/shellcheck scripts/openwrt/*.sh tests/network-ns/*.sh tests/openwrt-sdk/*.sh
~~~

Expected: ShellCheck 0.11.0 exits 0.

- [ ] **Step 5: Commit**

Run:

~~~powershell
$shellFiles = @(
    @(rg --files scripts/openwrt tests/network-ns tests/openwrt-sdk packaging/openwrt-awg2 -g '*.sh')
    'packaging/openwrt-awg2/amneziawg-tools/files/amneziawg_watchdog'
)
foreach ($file in $shellFiles) {
    $entry = git ls-files --stage -- $file
    if ($LASTEXITCODE -ne 0 -or -not $entry) { throw "$file is not tracked" }
    $mode = $entry.Split()[0]
    if ($mode -ne '100755') { throw "$file is not executable in Git" }
}
git ls-files --stage scripts/openwrt tests/network-ns tests/openwrt-sdk packaging/openwrt-awg2/amneziawg-tools/files
if ($LASTEXITCODE -ne 0) { throw 'final shell mode inspection failed' }
git add -- .github/workflows/ci.yml .github/workflows/openwrt-sdk.yml tests/windows-pester/Workflow.Tests.ps1 scripts/bootstrap-dev.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add CI sources failed' }
git commit -m "ci: verify foundation and OpenWrt compatibility"
if ($LASTEXITCODE -ne 0) { throw 'CI commit failed' }
~~~

Expected: the fail-closed mode check proves every tracked shell entry was already committed as 100755 by its owning task, so Linux runners do not depend on the Windows filesystem executable bit.

### Task 13: Prepare hardware smoke and close P0

**Files:**

- Create: scripts/openwrt/smoke-awg2.ps1
- Create: scripts/openwrt/smoke-awg2-remote.sh
- Create: tests/windows-pester/AWGHardwareSmoke.Tests.ps1
- Modify: docs/COMPATIBILITY.md
- Modify: docs/ACCEPTANCE_MATRIX.md
- Modify: STATUS.md

**Interfaces:**

- Consumes: built APKs and a future explicit GL-MT6000 SSH target.
- Produces: dry-run-by-default hardware test and final P0 evidence.

- [ ] **Step 1: Write failing safety tests for the smoke script**

tests/windows-pester/AWGHardwareSmoke.Tests.ps1 uses fake ssh and scp commands placed first in a TestDrive PATH. Each fake records argv and returns fixture output or a requested non-zero exit. Tests invoke the public script as a child PowerShell process and assert behavior, not only source text:

1. RouterHost and KnownHostsFile are always mandatory; PackageDirectory is mandatory for Smoke, while Recover requires a 32-hex RecoveryToken; RouterHost and SshUser reject shell metacharacters;
2. ConfirmInstall defaults false and WhatIf performs no ssh/scp call;
3. every ssh/scp call contains BatchMode=yes, StrictHostKeyChecking=yes and the exact UserKnownHostsFile;
4. no ConfirmInstall performs read-only preflight only and never uploads or installs;
5. wrong board_name, OpenWrt version, kernel, package architecture, installed kernel ABI/vermagic, local SHA, pre-existing package/module or awg-p0 prevents upload;
6. ConfirmInstall without a successful ShouldProcess decision prevents upload;
7. failed scp and failed apk return non-zero and invoke the fixed cleanup path; an unavailable router returns the exact Recover command/token instead of claiming rollback;
8. successful smoke removes awg-p0, both smoke-installed packages, a smoke-loaded module and /tmp/home-gateway-p0;
9. the remote argv contains each I value as one argument: '<r 2>', '<r 3>', '<rd 4>', '<rc 4>' and '<b 0x0102>';
10. Recover refuses a missing/wrong ownership marker and removes only resources whose nonce and captured pre-state match;
11. scripts contain no firmware, sysupgrade, uci, /etc/config/network copy, WAN, firewall or DNS mutation and no password/private-key literal.

Run the tests and expect missing-script failures. The fixtures must also prove red/green behavior: first fail with missing scripts, then pass only after both scripts exist.

- [ ] **Step 2: Implement the dry-run-first smoke**

scripts/openwrt/smoke-awg2.ps1 accepts:

~~~powershell
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Smoke')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')]
    [string]$RouterHost,

    [Parameter(Mandatory, ParameterSetName = 'Smoke')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$PackageDirectory,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$KnownHostsFile,

    [ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')]
    [string]$SshUser = 'root',

    [Parameter(ParameterSetName = 'Smoke')]
    [switch]$ConfirmInstall,

    [Parameter(Mandatory, ParameterSetName = 'Recover')]
    [switch]$Recover,

    [Parameter(Mandatory, ParameterSetName = 'Recover')]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RecoveryToken
)
~~~

WhatIf and Confirm are common parameters supplied by SupportsShouldProcess; do not redeclare WhatIf. The script resolves PackageDirectory and KnownHostsFile to absolute paths, requires exactly one kmod-amneziawg APK, one amneziawg-tools APK and the matching SHA256SUMS, and rejects filenames outside `[A-Za-z0-9._+-]+`. Every native process is followed immediately by a LASTEXITCODE check. SSH/scp arguments are arrays containing:

~~~text
-o BatchMode=yes
-o StrictHostKeyChecking=yes
-o UserKnownHostsFile=<resolved KnownHostsFile>
-o ConnectTimeout=10
~~~

No command uses Invoke-Expression, cmd /c, an interpolated remote shell fragment or disabled host-key checking. WhatIf prints the local/read-only/mutation plan and returns before resolving or invoking ssh/scp.

Read-only preflight commands:

~~~text
ubus call system board
apk --print-arch
uname -r
cat /etc/openwrt_release
apk list -I 'kernel*'
apk info -e kmod-amneziawg
apk info -e amneziawg-tools
lsmod
ip link show awg-p0
~~~

Preflight requires board_name glinet,gl-mt6000, OpenWrt 25.12.5, uname 6.12.94, architecture aarch64_cortex-a53 and installed kernel package `kernel-6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1`. It stops if either AWG package, the module, awg-p0 or /tmp/home-gateway-p0 already exists. It also validates local SHA256SUMS and the kmod dependency measured in Task 10 before upload.

Mutation is permitted only when ConfirmInstall is true, preflight passed, and `$PSCmdlet.ShouldProcess("$SshUser@$RouterHost", 'temporarily install and roll back AWG2 smoke packages')` returns true. P0 has no KeepInstalled mode. The wrapper generates a random 32-hex nonce, prints it before mutation, and the remote script writes it with captured pre-state to `/tmp/home-gateway-p0/owner` before package upload. The fixed scripts/openwrt/smoke-awg2-remote.sh is sent to `ssh ... sh -s --` through UTF-8 standard input; user input is never embedded in its text. The mutation sequence is:

1. create /tmp/home-gateway-p0 with mode 0700 and copy only the two expected APKs plus SHA256SUMS;
2. verify every uploaded SHA-256;
3. run `apk add --simulate --no-network --allow-untrusted` for the two exact filenames and require the exact kernel ABI dependency;
4. run `apk add --no-network --allow-untrusted` for those same two filenames;
5. modprobe amneziawg, create awg-p0, generate an in-memory key, apply the fixed AWG2 parser/UAPI vector below and run awg show;
6. register idempotent cleanup as an EXIT/INT/TERM trap for failure paths; on success call cleanup explicitly, remove the trap, then compare package/module/interface state with the captured pre-state;
7. fail unless final state is identical to pre-state and /tmp/home-gateway-p0 is absent.

The local wrapper uses a finally block to invoke the fixed cleanup-only remote mode if scp or SSH transport fails after temporary-directory creation. If the router is unavailable, it returns non-zero and prints the exact `-Recover -RecoveryToken <nonce>` command; it never claims rollback. Recover requires ShouldProcess, reads the ownership marker, requires an exact nonce and captured pre-state, and removes only resources recorded as created by that smoke. Cleanup refuses to act unless the exact path is /tmp/home-gateway-p0. The scripts never copy /etc/config/network, create a peer, change routes, reload network/firewall/DNS or persist a private key.

Use this exact non-secret UAPI vector; every I field is non-empty because current tools reject explicit empty I values:

~~~text
Jc 4
Jmin 10
Jmax 50
S1 142
S2 41
S3 56
S4 11
H1 684141592-1751861769
H2 1957920865-2010016669
H3 2043550980-2107134838
H4 2127672251-2132651859
I1 '<r 2>'
I2 '<r 3>'
I3 '<rd 4>'
I4 '<rc 4>'
I5 '<b 0x0102>'
~~~

Each quoted I value is passed as one argv element. The remote command pipes awg genkey directly into awg set awg-p0 private-key /dev/stdin. It never places the generated key in an argument, log or persistent file.

- [ ] **Step 3: Verify dry-run locally**

Run:

~~~powershell
.\scripts\dev.ps1 -Command pester
New-Item -ItemType Directory -Force .\.cache\whatif-packages | Out-Null
New-Item -ItemType File -Force .\.cache\whatif-known-hosts | Out-Null
.\scripts\openwrt\smoke-awg2.ps1 `
    -RouterHost 192.0.2.1 `
    -PackageDirectory .\.cache\whatif-packages `
    -KnownHostsFile .\.cache\whatif-known-hosts `
    -WhatIf
~~~

Expected: Pester passes; WhatIf prints planned preflight and mutation commands without opening SSH.

- [ ] **Step 4: Commit the independently testable smoke harness**

Run:

~~~powershell
git add --chmod=+x -- scripts/openwrt/smoke-awg2-remote.sh
if ($LASTEXITCODE -ne 0) { throw 'git add executable remote smoke failed' }
git add -- scripts/openwrt/smoke-awg2.ps1 tests/windows-pester/AWGHardwareSmoke.Tests.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add hardware smoke sources failed' }
$entry = git ls-files --stage scripts/openwrt/smoke-awg2-remote.sh
if ($LASTEXITCODE -ne 0 -or $entry -notmatch '^100755 ') { throw 'remote smoke Git mode is not 100755' }
git commit -m "test: add rollback-safe AWG hardware smoke"
if ($LASTEXITCODE -ne 0) { throw 'hardware smoke commit failed' }
~~~

Expected before commit: the remote script has mode 100755 and Pester behavior tests pass.

- [ ] **Step 5: Run full verification from clean worktrees**

Create a detached clean Windows verification worktree after the smoke-harness commit:

~~~powershell
New-Item -ItemType Directory -Force .\.worktrees | Out-Null
$worktreesRoot = (Resolve-Path -LiteralPath .\.worktrees).Path
$verifyPath = Join-Path $worktreesRoot ("p0-verify-" + [Guid]::NewGuid().ToString('N'))
$fullVerifyPath = [IO.Path]::GetFullPath($verifyPath)
if (-not $fullVerifyPath.StartsWith($worktreesRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'verification worktree escaped .worktrees'
}
git worktree add --detach -- $fullVerifyPath HEAD
if ($LASTEXITCODE -ne 0) { throw 'git worktree add failed' }
try {
    Push-Location $fullVerifyPath
    try {
        .\scripts\bootstrap-dev.ps1
        .\scripts\dev.ps1 -Command verify
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\bootstrap\Governance.Smoke.ps1
        if ($LASTEXITCODE -ne 0) { throw 'Governance smoke failed' }
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\bootstrap\ToolchainLock.Smoke.ps1
        if ($LASTEXITCODE -ne 0) { throw 'Toolchain lock smoke failed' }
        git diff --exit-code
        if ($LASTEXITCODE -ne 0) { throw 'verification worktree has a diff' }
        $porcelain = @(git status --porcelain=v1 --untracked-files=all)
        if ($LASTEXITCODE -ne 0 -or $porcelain.Count -ne 0) { throw 'clean verification worktree became dirty' }
    } finally {
        Pop-Location
    }
} finally {
    if (Test-Path -LiteralPath $fullVerifyPath) {
        git worktree remove --force -- $fullVerifyPath
        if ($LASTEXITCODE -ne 0) { throw 'verification worktree cleanup failed' }
    }
    git worktree prune
    if ($LASTEXITCODE -ne 0) { throw 'git worktree prune failed' }
}
~~~

Run the pinned `openwrt-sdk.yml` workflow or the following equivalent from a separate clean Linux checkout with network-namespace privileges:

~~~sh
pwsh -NoProfile -File scripts/bootstrap-dev.ps1 -IncludePowerShell
make PWSH=./.tools/pwsh/pwsh verify
test "$(go env GOVERSION)" = 'go1.26.5'
cc --version
ld --version
go test -race ./...
sudo tests/network-ns/check-prereqs.sh
tests/openwrt-sdk/assert-awg2-helper.sh
rm -rf artifacts/openwrt-run1 artifacts/openwrt-run2
OUTPUT_DIR="$PWD/artifacts/openwrt-run1" scripts/openwrt/build-packages.sh
rm -rf .cache/openwrt-sdk
OUTPUT_DIR="$PWD/artifacts/openwrt-run2" scripts/openwrt/build-packages.sh
diff -ru --no-dereference artifacts/openwrt-run1 artifacts/openwrt-run2
rm -rf artifacts/awg-go-run1 artifacts/awg-go-run2
OUTPUT_DIR="$PWD/artifacts/awg-go-run1" scripts/openwrt/build-amneziawg-go.sh
OUTPUT_DIR="$PWD/artifacts/awg-go-run2" scripts/openwrt/build-amneziawg-go.sh
diff -ru --no-dereference artifacts/awg-go-run1 artifacts/awg-go-run2
git diff --exit-code
test -z "$(git status --porcelain=v1 --untracked-files=all)"
~~~

Expected: every command exits 0, both complete output-tree comparisons are empty and both clean checkouts remain unchanged outside ignored caches/artifacts. Linux-capable evidence is mandatory; absence of a GitHub origin only changes the evidence format, not this gate.

- [ ] **Step 6: Update P0 evidence and status**

docs/COMPATIBILITY.md records:

- source locks: verified-upstream;
- kernel/tools APKs: built-in-sdk with artifact SHA and a CI run link when an origin exists, otherwise commit SHA, exact command log, tool versions and output hashes from the Linux clean checkout;
- amneziawg-go: built-in-sdk with size and SHA;
- hardware smoke: prepared-for-hardware unless the user separately authorizes and provides access;
- router-to-VPS handshake: blocked with owner P3.

STATUS.md records P0A and P0B as complete only after both Windows and Linux software evidence passes. Without Linux evidence it records blocked and names the missing environment. It must not mark hardware or handshake complete without their separate evidence.

- [ ] **Step 7: Apply the repository Python convention conditionally**

Run:

~~~powershell
$pythonFiles = @(rg --files -g '*.py')
if ($pythonFiles.Count -eq 0) {
    'RUFF_NOT_APPLICABLE_NO_PYTHON'
} else {
    ruff check .
    if ($LASTEXITCODE -ne 0) { throw 'ruff check failed' }
    ruff format --check .
    if ($LASTEXITCODE -ne 0) { throw 'ruff format --check failed' }
}
~~~

Expected for P0: RUFF_NOT_APPLICABLE_NO_PYTHON.

- [ ] **Step 8: Commit P0 closure**

Run:

~~~powershell
$expected = @('STATUS.md', 'docs/ACCEPTANCE_MATRIX.md', 'docs/COMPATIBILITY.md') | Sort-Object
.\scripts\dev.ps1 -Command pester
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-governance.ps1
if ($LASTEXITCODE -ne 0) { throw 'governance failed after evidence update' }
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'git diff --check failed after evidence update' }
$changed = @(git diff --name-only | Sort-Object)
if (($changed -join ',') -ne ($expected -join ',')) { throw "unexpected closure files: $($changed -join ', ')" }
git add -- docs/COMPATIBILITY.md docs/ACCEPTANCE_MATRIX.md STATUS.md
if ($LASTEXITCODE -ne 0) { throw 'git add closure files failed' }
$staged = @(git diff --cached --name-only | Sort-Object)
if (($staged -join ',') -ne ($expected -join ',')) { throw "unexpected staged files: $($staged -join ', ')" }
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'staged closure diff check failed' }
git commit -m "docs: close P0 foundation and compatibility"
if ($LASTEXITCODE -ne 0) { throw 'P0 closure commit failed' }
git status --short
if ($LASTEXITCODE -ne 0 -or (git status --porcelain=v1)) { throw 'worktree is not clean after closure commit' }
git log --oneline --decorate --max-count=20
if ($LASTEXITCODE -ne 0) { throw 'git log failed' }
~~~

Expected: clean worktree and a small logical commit series covering Tasks 1-13. The closure commit is forbidden if Windows or Linux evidence failed or was not run.

## P0 exit checklist

- [ ] Git main branch contains the canonical spec, master plan and phase plan.
- [ ] STATUS.md, DECISIONS.md and ADR-0001 through ADR-0009 are consistent.
- [ ] Go 1.26.5 builds all four version-only binaries reproducibly.
- [ ] Windows PowerShell 5.1 and PowerShell 7.6.2 paths pass Pester 6.0.0.
- [ ] manifest/versions.lock.yaml has no mutable version reference and all downloaded bytes are SHA-verified.
- [ ] Linux namespace prerequisite smoke passes in a real CAP_NET_ADMIN environment.
- [ ] OpenWrt 25.12.5 filogic SDK builds kernel/tools APKs from official AWG2 sources.
- [ ] AWG2 helper supports S3, S4, ranged H1-H4 and I1-I5 while route_allowed_ips defaults to 0.
- [ ] amneziawg-go contingency builds for linux/arm64 and is recorded without an unmeasured performance claim.
- [ ] CI definitions pass pinned Actionlint and all equivalent local commands; a hosted green run is linked when a GitHub origin exists.
- [ ] Hardware smoke is prepared; its actual state is reported honestly.
- [ ] Router-to-VPS handshake remains a P3 field gate.
- [ ] No production routing, secrets or unrelated features entered P0.

## Execution handoff

Recommended execution mode: Subagent-Driven. Use one fresh implementer per task, then run spec-compliance review and code-quality review before accepting each commit. Add an explicit security review for Tasks 12-13. Tasks 8-12 require a Linux-capable agent/environment; Task 13 is coordinated from Windows but cannot close without the Linux evidence produced by Tasks 8-12 and rerun at closure.

Inline Execution remains valid if the user prefers one session with review checkpoints after P0A and P0B.
