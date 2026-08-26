# P3.5 persistent sink routes offline evidence report

Date: 2026-08-26

Result: PASS for the offline implementation scope. Live Windows mutation, provider handshake, egress health, reboot field evidence and terminal `FullRestore` field evidence were not run.

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
- qualified IPv6 no-route
- IPv4 and IPv6 loopbacks ready

No config contents, secrets, DNS server addresses, target values, endpoints or adapter names are recorded in this report.

## Security ruling and rollback

Independent review confirmed the three historical scanner hits are public/non-secret values. The committed `.gitleaksignore` contains exactly those three fingerprints and no patterns, wildcards, path/rule allowlists or config exclusions. The current `P35-EMERGENCY-DISABLE` confirmation token has a same-line `gitleaks:allow` comment because it is a public operator confirmation token, not a credential.

Rollback for this scanner ruling: delete `.gitleaksignore`, remove the same-line `gitleaks:allow` comment from `internal/hgctlcmd/live_canary.go`, then rerun `.\.tools\bin\gitleaks.exe git --no-banner --redact .`.

## Commits

- `6e4ce2b46f29508eaaa38e72b70a475c945c57c8` — `fix: close P3.5 static and pester gaps`
- `da5e9de732f4253f5ed561ce7f594ae657295326` — `chore: allow verified P3.5 public tokens`

## Remaining live-field gates

P3.5 is offline implementation complete only. The live safety matrix and terminal `FullRestore` field evidence still require separate authorization. `pc-core-ready` remains pending until direct/RedShield/Cisco, DNS, IPv4/IPv6, MTU, TCP/UDP/QUIC, tunnel-down, adapter-loss, process-crash, reboot/reconcile, emergency-disable and final full-restore field evidence pass on the current Windows PC.
