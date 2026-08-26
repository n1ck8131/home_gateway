# P3.5 persistent sink routes offline evidence report

Date: 2026-08-26

Result: PASS for the offline implementation scope; SAFE BLOCK for the authorized bounded live sub-batch. Exact Plan stopped before candidate/challenge creation, so live mutation, provider handshake, egress health, reboot and terminal journaled `FullRestore` evidence remain open.

## Delivered

- Persistent fail-closed sink artifacts, validation and recovery integration for exact target/DNS prefixes.
- Native Windows fake-runner coverage for persistent store sinks, effective-route resolution and protected ownership registry behavior.
- CLI plan/status/recovery evidence limited to counts and booleans.
- Durable watchdog behavior for retryable restoring failures and successful full restore disarm.
- ADR/status boundary for the deliberate persistent-sink exception while `ManagedRoute` remains transient.
- Narrow secret-scanner ruling for public P3.5 operator confirmation tokens and marker identifiers, preserving all other gitleaks coverage.

## Validation

| Command | Exit | Material result |
|---|---:|---|
| `.\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd ./internal/revisions/apply -count=1` | 0 | Focused Windows sink/runtime/CLI/apply integration passed: `internal/system/windows` 4.350s, `internal/hgctlcmd` 0.781s, `internal/revisions/apply` 0.912s |
| `powershell.exe -NoLogo -NoProfile -NonInteractive -Command "Invoke-Pester -Path '.\tests\windows-pester\P35SinkPreflight.Tests.ps1' -EnableExit"` | 0 | Windows PowerShell 5.1 read-only contract passed: 13 passed, 0 failed |
| `pwsh.exe -NoLogo -NoProfile -NonInteractive -Command "Invoke-Pester -Path '.\tests\windows-pester\P35SinkPreflight.Tests.ps1' -EnableExit"` | 0 | PowerShell 7 read-only contract passed: 13 passed, 0 failed |
| `.\.tools\bin\gitleaks.exe git --no-banner --redact .` | 0 | 109 commits scanned; no leaks found |
| `.\scripts\dev.ps1 -Command verify` | 0 | Go tests passed; Pester v6 passed 66 tests; staticcheck, gosec with 0 issues, govulncheck, gitleaks, actionlint, governance/toolchain smokes and reproducible builds passed |
| `ruff check .` / `ruff format --check .` | N/A | `RUFF_NOT_APPLICABLE_NO_PYTHON` |

The successful full gate followed diagnosed fix cycles for Pester 3.4 compatibility, a PowerShell 5.1 StrictMode parser defect, staticcheck diagnostics, gosec diagnostics, and verified public-token gitleaks false positives. Affected checks passed before the final full gate.

## Read-only preflight shape

The current P3.5 preflight evidence is recorded only as this safe shape:

- `ready=true`
- `exit_code=0`
- PktMon stopped / no filters
- zero exact Active/Persistent collisions
- qualified IPv4 default
- qualified IPv6 default
- IPv4 and IPv6 loopbacks ready

No config contents, secrets, DNS server addresses, target values, endpoints or adapter names are recorded in this report.

## Authorized bounded live sub-batch

The 2026-08-26 owner-authorized envelope prohibited RedShield/Cisco disconnect, restart or reconfiguration, reboot and adapter loss. A refreshed hash-pinned elevated preflight passed, the protected bootstrap installed exact pinned launcher/hgctl/config artifacts, and the exact non-elevated Plan then failed closed before producing a candidate or confirmation challenge.

The redacted cause classification was unambiguous: the two explicit public probe targets had zero provider/Cisco collisions, while the single DNS address imported from the config had one Cisco protected-prefix collision. Config and Cisco route values remain omitted. Because imported DNS targets are mandatory candidate targets, changing only the explicit probes cannot make this Plan safe.

Apply/Confirm were never invoked. `journal.json`, `operation.lock`, the native ownership registry and revision root remained absent. Terminal elevated inventory found zero reserved P3.5 routes/sinks, owned firewall rules, owned NRPT rules and owned scheduled tasks; both default route families remained present and the RedShield/Cisco adapters remained Up. Product `RestoreConfigAcl` passed and the source hash/ACL baseline was confirmed.

`FullRestore` was not forced: with an existing bootstrap root and no transaction journal, the product recovery path would create/open an operation lock and then fail journal loading. Fabricating a journal would create authority for a transaction that never ran. Independent safety review therefore ruled Apply and forced FullRestore `NO-GO`, and accepted closure as a safe pre-mutation abort. The final hash-pinned preflight matched the pre-bootstrap proof for boot marker, PktMon hashes/count, default path states, exact collision counts and loopback readiness.

## Security ruling and rollback

Independent review confirmed the three historical scanner hits are public/non-secret values. The committed `.gitleaksignore` contains exactly those three fingerprints and no patterns, wildcards, path/rule allowlists or config exclusions. The current `P35-EMERGENCY-DISABLE` confirmation token has a same-line `gitleaks:allow` comment because it is a public operator confirmation token, not a credential.

Rollback for this scanner ruling: delete `.gitleaksignore`, remove the same-line `gitleaks:allow` comment from `internal/hgctlcmd/live_canary.go`, then rerun `.\.tools\bin\gitleaks.exe git --no-banner --redact .`.

## Commits

- `6e4ce2b46f29508eaaa38e72b70a475c945c57c8` — `fix: close P3.5 static and pester gaps`
- `da5e9de732f4253f5ed561ce7f594ae657295326` — `chore: allow verified P3.5 public tokens`
- `18b58660664ddb8c7f299c1417a0b38e8979354a` — `fix: verify emergency sink retention`
- `0133ea189128` — `fix: shorten launcher`
- `dd03945be6f4` — `fix: embed P3.5 bootstrap request`
- `7bfa7708f211` — `fix: accept canonical config ACL rights`

## DNS and Cisco overlap diagnostic follow-up

The offline diagnostic implementation classifies `imported_dns` and `explicit_target` targets against `cisco_prefix` and `provider_endpoint` protected classes using redacted counts only. It returns one typed Plan JSON document with exit code `3`, no challenge fields, and no provider, network, adapter, config, or target values.

| Command | Exit | Material result |
|---|---:|---|
| `& .\.tools\go\bin\go.exe test ./internal/system/windows -run 'Test(BuildCanaryPlan\|CanaryIsolationError)' -count=1` | 0 | Task 1 focused planner PASS; all selected tests passed |
| `& .\.tools\go\bin\go.exe test ./internal/hgctlcmd -run 'Test(RunWindowsCanaryPlan\|CanaryBlockedPlanOutput\|RunCanaryLiveRejectsIsolation)' -count=1` | 0 | Task 2 focused CLI/live-boundary PASS; all selected tests passed |
| `& .\.tools\go\bin\go.exe test ./internal/system/windows ./internal/hgctlcmd -count=1` | 0 | Final focused packages PASS: `internal/system/windows` 4.279s, `internal/hgctlcmd` 0.750s |
| `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Command pester` | 0 | Windows PowerShell 5.1 Pester PASS: 70 passed, 0 failed, 0 skipped |
| `pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command pester` | 0 | PowerShell 7 Pester PASS: 70 passed, 0 failed, 0 skipped |
| `pwsh.exe -NoLogo -NoProfile -NonInteractive -File .\scripts\dev.ps1 -Command verify` | 0 | Full repository gate PASS: all Go tests, Pester 70/0, `gosec` 0 issues, `govulncheck` no vulnerabilities, `gitleaks` no leaks, governance, smoke, and toolchain-lock gates |
| `git diff --check` | 0 | No whitespace errors |
| `ruff check .` / `ruff format --check .` | N/A | `RUFF_NOT_APPLICABLE_NO_PYTHON` |

No live Apply, Confirm, recovery, network mutation, or current-profile retry was performed.

## Remaining live-field gates

P3.5 is offline implementation complete only. The live safety matrix is now blocked by the imported-DNS/Cisco protected-prefix conflict and must not bypass that guard. A new approved prerequisite resolution and live envelope are required. `pc-core-ready` remains pending until direct/RedShield/Cisco, DNS, IPv4/IPv6, MTU, TCP/UDP/QUIC, tunnel-down, adapter-loss, process-crash, reboot/reconcile, emergency-disable and final journaled full-restore field evidence pass on the current Windows PC.
