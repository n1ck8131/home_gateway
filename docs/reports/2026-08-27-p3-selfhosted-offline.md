# P3 self-hosted offline implementation report

Date: 2026-08-27

Result: PASS for the offline software scope. State is `self-hosted-offline-ready`; no DigitalOcean, SSH, server, profile activation or Windows network field gate was run.

## Delivered boundary

- Locked the AmneziaVPN 5.0.1.5 client asset and AWG 3.1 source lineage while retaining the existing OpenWrt AWG2 pins. The official rolling server image is recorded only as `observed-after-install`.
- Moved bounded local-file, stable-identity, reparse/volume, hash-pin, strict profile parsing and secret redaction ownership into provider-neutral `configfile`. The RedShield backend is a read-only compatibility wrapper.
- Added the complete canonical AWG 3.1 allowlist and rejection matrix, including bounded tagged junk, header protection, booleans and keepalive ranges, without exposing private or opaque values.
- Generalized the active Windows planner/runtime/CLI to one qualified `AdapterTunnel`, generic `tunnel.conf`/`tunnel.sha256` protected paths and `hgctl tunnel inspect`. Ownership, persistent sinks, Cisco protection, commit-confirm timeouts and terminal `FullRestore` semantics are unchanged.
- Added an exact DigitalOcean desired manifest and PowerShell 5.1/7 plan-only guard. It rejects remote/mapped/device/reparse paths, malformed public keys and non-exact or duplicate JSON before one absolute System32 OpenSSH validation. It performs no provider or billable action.

## Validation

| Command or gate | Exit | Result |
|---|---:|---|
| `./.tools/go/bin/go.exe test ./internal/providers/configfile ./internal/providers/redshield ./internal/providers/selfhosted ./internal/tunnel` | 0 | Strict parser, compatibility and backend tests passed |
| `GOOS=linux go test -c` for `internal/providers/configfile` to a temporary output outside the repository | 0 | Non-Windows helper and package compile passed |
| P3 DigitalOcean Pester under Windows PowerShell 5.1 and PowerShell 7 | 0 | 14/14 passed in each runtime |
| `./scripts/dev.ps1 -Command verify` | 0 | All Go tests; Pester 84/84; format, vet, staticcheck; gosec 0 issues; govulncheck no vulnerabilities; gitleaks/actionlint; governance/toolchain smokes; reproducible four-target builds passed |
| `git diff --check` | 0 | No whitespace errors |
| Python/Ruff applicability | n/a | `RUFF_NOT_APPLICABLE_NO_PYTHON` |

The first integration run exposed unused legacy helper files after parser ownership moved to `configfile`; they were removed and focused tests/staticcheck passed. The next run exposed four gosec G115 narrowing conversions in private parser state; the private storage was widened while retaining the exact uint16/uint32 validation bounds. The final complete `verify` then passed.

## Independent review

The consolidated review initially returned NO-GO with 9 Important findings: Windows PowerShell 5.1 compatibility, governance exceptions, lost parser regressions, AWG classification/canonical grammar, legacy provider selection and DigitalOcean local-path/schema/native-boundary gaps. One coordinated fix wave restored the historical tests, added the full AWG 3.1 matrix and hardened the plan-only script. Two scoped re-reviews closed the cross-platform helper and mapped-drive/reparse ordering residuals. A final cleanup review found no Critical or Important issues and returned GO.

## Open field gates

- Droplet creation/billing and public metadata: not run.
- Dedicated SSH key generation/upload, host-key verification and server bootstrap: not run.
- UDP publication, server image identity observation and guest profile creation: not run.
- Protected real profile inspection, client import/activation and observed handshake/egress: not run.
- Exact Windows Plan, Apply/Confirm, live safety matrix and exact-candidate terminal `FullRestore`: not run.
- `pc-core-ready`: open.

No private key, password, token, raw profile, real endpoint or cloud account data was added to repository evidence. RedShield and Cisco were not disconnected, reconfigured or removed.
