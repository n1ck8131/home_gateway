# P3.4 offline mutation phase report

Date: 2026-08-25

Result: PASS for the offline software scope. Native Windows mutation and live canary were not run.

## Delivered

- Strict bounded v1 route, firewall and NRPT artifacts with exact project ownership.
- Independent qualified endpoint binding, physical-default revalidation, protected Cisco/system exclusions and dual-stack fail-closed coverage.
- Additive-first apply, immutable revision manifests, semantic before/LKG snapshots, commit-confirm and automatic rollback.
- Durable degraded retry, emergency-disable and full-restore journal states with restart convergence.
- Recovery from timeout, mid-activation process loss and a missing/corrupt pending manifest without deleting foreign state.
- Structured injected `MutationBackend`; no native executor, shell/PowerShell mutation or operator command.

## Validation

| Command | Exit | Material result |
|---|---:|---|
| `.\.tools\go\bin\go.exe test -count=1 ./internal/system/windows ./internal/revisions/apply ./internal/dataplane` | 0 | Focused mutation, transaction and compatibility regressions passed |
| `.\scripts\dev.ps1 -Command verify` | 0 | All Go tests and 41 Pester tests passed; format, vet, staticcheck, gosec (0 issues), govulncheck (no callable vulnerabilities), gitleaks, actionlint, governance/toolchain smokes and reproducible four-target builds passed |
| `ruff check .` / `ruff format --check .` | N/A | `RUFF_NOT_APPLICABLE_NO_PYTHON` |

The final successful `verify` followed one fix cycle for two `staticcheck` error-string diagnostics and two `gosec` path-flow diagnostics; affected checks passed before the final full gate.

## Safety boundary and remaining gates

No Windows route, firewall, DNS, service, adapter, RedShield or Cisco state was changed. `ReadOnlyController` remains typed-unsupported and the production controller is not wired to the offline runtime. P3.5/P3.6 own the production `MutationBackend`, operator commands, separately confirmed bounded canary, restart/adapter-loss field matrix and complete uninstall evidence. `pc-core-ready` is not claimed.
