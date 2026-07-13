# P2 Production Dataplane Implementation Plan

## Goal

Implement the production routing backend that consumes the deterministic P1
`PolicyPlan`, renders IPv4/IPv6 nftables, policy-routing and dnsmasq artifacts,
and applies them transactionally with commit-confirm and last-known-good
rollback.

P2 proves packet-policy safety in Linux network namespaces and OpenWrt x86_64
QEMU. It does not configure a real GL-MT6000, establish an AmneziaWG tunnel, or
implement production API/UI, Cisco discovery, source downloads, or failover.

## Source requirements

- `SPEC.md` sections 4.1-4.7, 9, 19, 28, 29.3-29.4 and 30.1-30.3.
- `PLAN.md` P2 exit gate and dataplane invariants.
- ADR-0003 routing ownership and marks.
- ADR-0004 DNS and precedence.
- ADR-0005 transaction model.

## Stable P2 boundaries

### Production backend

- `RoutingBackend` accepts validated P1 `PolicyPlan` plus explicit runtime
  inventory; it never re-resolves policy precedence.
- Rendering is pure and deterministic. System mutation is isolated behind an
  argv-based Linux runner and filesystem adapter; no shell-built commands.
- `routerd` owns one named nft table, reserved mark mask `0xff000000`, and
  routing tables `10000 + slot`. Startup rejects ownership collisions.
- The system `main` default route remains WAN. Every VPN table always contains
  an IPv4 and IPv6 terminal `blackhole` or `unreachable` default when its
  tunnel is unavailable.
- Connection marks preserve the selected server for established flows. Rules
  are protocol-agnostic and therefore cover TCP, UDP and QUIC.

### DNS rendering

- Generate separate IPv4 and IPv6 nft sets and deterministic chunked
  `dnsmasq-full` nftset directives for exact, suffix and wildcard domains.
- A/AAAA/CNAME population and expiry are verified against a real dnsmasq in
  the integration lab.
- nft set default timeouts and dnsmasq cache limits are explicit and aligned;
  P2 does not claim exact copying of upstream DNS TTLs.
- Shared-IP conflicts are rendered from the already resolved P1 plan with
  direct precedence preserved.

### Transaction and recovery

- Apply order is lock, stage complete candidate, validate, snapshot, arm
  watchdog, atomic activation, reload, post-check, commit or rollback.
- nft validation uses the complete `fw4 print` candidate plus the staged
  include and `nft -c -f`. DNS validation uses `dnsmasq --test` against the
  staged configuration.
- A durable journal records the active revision, last-known-good revision,
  pending deadline and rollback result. Secrets and packet payloads are never
  journaled.
- Crash, timeout, invalid nft, invalid dnsmasq and failed post-check all restore
  last-known-good state. Boot recovery resolves an unconfirmed revision before
  normal reconciliation.

## Files and TDD sequence

### 1. Dataplane contracts and pure renderers

Create:

- `internal/routing/nft/render.go` and focused tests/golden fixtures;
- `internal/routing/iprule/plan.go` and focused tests/golden fixtures;
- `internal/dns/dnsmasq/render.go` and focused tests/golden fixtures;
- `internal/system/linux/runner.go` and tests for argv, exit status and
  cancellation boundaries.

Write failing tests first for owned names, mark/table collision rejection,
stable output, IPv4/IPv6 parity, terminal routes, connection marks,
protocol-independent rules, domain chunking and timeout alignment. Then add the
smallest renderer and runner implementation needed to pass.

### 2. Transactional apply and boot recovery

Create:

- `internal/revisions/apply/backend.go`;
- `internal/revisions/apply/transaction.go`;
- `internal/revisions/apply/journal.go`;
- focused unit tests with a fake filesystem, clock and command runner.

Tests cover every state transition and compensation boundary before
implementation: validation failure, snapshot failure, activation failure,
reload failure, post-check failure, watchdog expiry, process crash, explicit
confirm, explicit rollback and cold-boot recovery. A failed rollback is reported
as a terminal degraded state and must not delete the last-known-good snapshot.

### 3. Linux network namespace safety suite

Replace the P0 placeholder with:

- `tests/network-ns/run.sh` as the single entrypoint;
- topology and cleanup helpers under `tests/network-ns/lib/`;
- deterministic fixtures under `tests/network-ns/fixtures/`;
- packet-flow assertions and a 20-loop fault-injection runner.

The topology is `client -> router -> WAN` and `router -> VPN -> internet`, with
a fake tunnel adapter only at the lab boundary. Assertions cover direct,
system-direct, scoped work-PC direct, VPN mark, tunnel-down blackhole, no IPv6
leak, active-server marks, TCP/UDP/QUIC, A/AAAA/CNAME nftset population and
expiry, invalid apply rollback, crash recovery and cleanup after failure.

The suite emits a compact evidence bundle containing nft counters, `ip rule`
and route dumps, interface-scoped captures, revision logs and the fault-loop
summary. It never mutates the Windows host network.

### 4. OpenWrt x86_64 QEMU smoke

Create under `tests/openwrt-qemu/`:

- a checksum-pinned image/bootstrap script;
- package/config staging helpers;
- runtime smoke and reboot/LKG assertions;
- CI entrypoint and artifact collection.

Extend `manifest/versions.lock.yaml` only with the exact official OpenWrt
x86_64 image URL, revision and SHA256 used by the test. QEMU proves OpenWrt
`fw4`, `nft`, `dnsmasq-full`, package/config lifecycle, reboot persistence and
rollback semantics. It does not claim filogic kernel-module compatibility.

### 5. CI, traceability and status

Update:

- `Makefile`, `scripts/dev.ps1` and `.github/workflows/ci.yml` with explicit
  P2 unit/netns entrypoints;
- a dedicated QEMU workflow only if its runtime makes the main CI gate
  impractical;
- `docs/ACCEPTANCE_MATRIX.md`, `STATUS.md` and `DECISIONS.md`;
- ADR-0003/0004/0005 only if implementation changes an accepted consequence.

No hardware mutation, router SSH or real-VPS operation is authorized in P2.

## Commit boundaries

1. `docs: plan P2 production dataplane`
2. `feat: add deterministic dataplane renderers`
3. `feat: add transactional apply and recovery`
4. `test: add network namespace safety suite`
5. `test: add OpenWrt QEMU dataplane smoke`
6. `docs: close P2 production dataplane`

## Validation batch

Run focused package tests during TDD. After implementation, consolidated review
and the single fix pass, run the final batch once:

```powershell
go test ./internal/routing/nft/... ./internal/routing/iprule/... ./internal/dns/dnsmasq/... ./internal/revisions/apply/... ./internal/system/linux/...
.\scripts\dev.ps1 -Command verify
```

On Linux with root and the required networking tools:

```text
sudo tests/network-ns/run.sh
```

Expected: the complete safety matrix passes, followed by at least 20
consecutive fault-injection iterations with zero leaks and zero flakes.

In the pinned OpenWrt x86_64 QEMU lab:

```text
tests/openwrt-qemu/run.sh
```

Expected: package/config smoke, full candidate validation, invalid nft and DNS
rollback, commit-confirm timeout, crash recovery and reboot/LKG persistence pass.

Run `ruff check .` and `ruff format --check .` only if P2 adds Python. Otherwise
record `RUFF_NOT_APPLICABLE_NO_PYTHON` in the phase report.

## Review gates

- Implementation review: renderer correctness, deterministic artifacts and
  test coverage.
- Security review: command execution, path traversal/symlink handling,
  privileges, ownership collisions, journal permissions and secret redaction.
- Architecture/adversarial review: fail-closed VPN lookup, WAN-management
  preservation, transaction state machine, crash/reboot behavior and P1/P3
  boundary compliance.

All Critical and Important findings require one consolidated fix pass and a
repeat of the affected checks plus the final regression batch.

## Exit criteria

- P1 `PolicyPlan` produces byte-stable nft, ip-rule and dnsmasq candidates.
- WAN remains the system default; VPN-class IPv4/IPv6 cannot fall through to
  `main` when the tunnel is absent.
- Owned marks/tables/chains are collision-checked and established flows retain
  their server mark.
- A/AAAA/CNAME nftset population, expiry and direct-over-VPN collision behavior
  pass with real dnsmasq/nft in netns.
- Invalid nft/DNS, post-check failure, watchdog expiry, crash and boot recovery
  restore last-known-good state without losing WAN management.
- Netns and pinned OpenWrt QEMU gates pass, including 20 consecutive fault
  loops; evidence is linked from `STATUS.md` and `docs/ACCEPTANCE_MATRIX.md`.
- Real GL-MT6000 and AWG2 handshake claims remain blocked for P3.
