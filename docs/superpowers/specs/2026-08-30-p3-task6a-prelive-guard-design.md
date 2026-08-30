# Close P3 pre-live guard gaps

Status: Draft for owner review

Audience: Home Gateway maintainers and the P3 field operator

Content type: Conceptual design

Canonical owner: P3 `pc-core-ready` completion plan

Evidence status: Two independent read-only reviews found live blockers on commit `1ad8dc7`

## Summary

This design inserts Task 6A before the first P3 live gate. Task 6A adds one attested remote helper, a protected runtime trust bundle, and a complete reconciliation path. No peer or Windows network action starts until this package passes offline tests and independent review.

## Problem

The current launcher prints `READY_FOR_UI=YES` after payload self-attestation. It does not collect the server baseline or observe an Admin or Guest change. Its 25-second process cannot enforce the planned 180-second guard window.

Two remote paths also lack a tracked install and identity contract:

- `/usr/local/libexec/home-gateway-p3-peer-guard`
- `/usr/local/libexec/home-gateway-p3-peer-observe`

Task 7 Step 1 requires a wider baseline. The current code does not reconcile the container, image, published port, host policy, Cloud Firewall, peer set, temporary state, protected profile, and self-hosted adapter.

The runtime pin file and dedicated memory-only Secure Shell (SSH) agent are absent. The existing key loader stores no passphrase. It requires one interactive passphrase entry after a dedicated agent starts.

## Goals

Task 6A must:

- make `READY_FOR_UI` mean that the complete pre-live baseline passed
- keep one guard active while the official graphical user interface (GUI) changes one peer
- detect exactly one Admin or Guest delta without keyboard control tokens
- produce sanitized, candidate-bound receipts
- replace the second remote observer with the same attested helper
- create runtime pins from independently accepted inputs
- bind SSH to one host key, one management source, and one expected agent key
- define exact install, rollback, and cleanup behavior for the remote helper
- preserve RedShield, Cisco, Docker, firewall, services, and Windows networking

## Non-goals

Task 6A does not:

- create or remove a server peer
- import or activate a client profile
- change a Cloud Firewall or host firewall rule
- restart Docker or install a service
- automate DigitalOcean through an application programming interface (API)
- implement the P8 managed `server-agent`
- store an SSH passphrase

## Decision

P3 will install one inert, root-owned helper at `/usr/local/libexec/home-gateway-p3-peer-guard`. The helper has no service, socket, timer, or autostart entry. Every invocation uses pinned SSH and `sudo`.

The helper owns four read-only modes and one separately approved emergency mode:

| Mode | Purpose | Mutation |
|---|---|---|
| `attest` | Verify payload and protocol identity | None |
| `reconcile` | Collect the sanitized server baseline | None |
| `guard admin\|guest` | Hold the GUI action window and observe one peer delta | None |
| `client-observe` | Observe one selected peer with a nonce and before/after counters | None |
| `emergency-rollback` | Remove one exact candidate and run one `syncconf` | Separate exact approval |

The client gate will stop using `/usr/local/libexec/home-gateway-p3-peer-observe`.

## Protected runtime trust bundle

The local runtime bundle remains under ignored `.p3-vps-run/`. A marker-owned child directory receives a restrictive Access Control List (ACL). The scripts reject inherited write access, reparse ancestors, network paths, alternate data streams, oversized files, and unstable file identities.

The bundle contains runtime-only values:

- SSH host and exact `homegateway` user
- pinned known-hosts file identity and SHA-256
- expected dedicated public-key fingerprint hash
- expected management source `/32` hash
- three distinct HTTPS egress authorities
- local and remote payload hashes
- canonical protocol hash
- accepted container image and published-port identities
- accepted host-policy and peer-baseline identities
- Cloud Firewall observation identity

One independently approved manifest SHA-256 binds the bundle. A fresh observation cannot define and validate its own expected baseline.

Tracked output contains only schema names, hashes, counts, booleans, bounded durations, and state classes.

## Dedicated SSH agent

Each live batch starts one Git OpenSSH `ssh-agent` in a persistent PowerShell session. The same pinned Git OpenSSH installation supplies `ssh-agent`, `ssh-add`, `ssh`, and `scp`. Mixing its Unix-domain socket with Windows OpenSSH is prohibited. The operator enters the dedicated key passphrase once into `ssh-add`. No file, environment variable, command line, log, or chat message stores the passphrase.

The launcher requires:

- one exact agent process identifier and socket
- exactly one loaded key
- the expected public-key fingerprint hash
- exact Git OpenSSH executable hashes
- agent cleanup on success or emergency stop

The terminal cleanup removes all agent keys and terminates only that agent process.

## Remote helper lifecycle

The tracked local lifecycle driver exposes four actions:

- `RemoteInstallPlan`
- `RemoteInstall`
- `RemoteRemovePlan`
- `RemoteRemove`

`RemoteInstallPlan` performs bounded read-only SSH. It classifies the target as `absent`, `exact`, or `conflict`.

`RemoteInstall` accepts only an exact candidate hash and challenge:

- `absent`: upload to one gate-owned temporary path, verify SHA-256, then install atomically
- `exact`: perform an idempotent no-op after owner, mode, type, and hash checks
- `conflict`: stop without overwrite

The installed file must be regular, root-owned, mode `0755`, and hash-exact. Installation cannot create a service or change Docker, firewall, networking, peers, or packages.

`RemoteRemove` removes only the helper installed by this gate. It requires the installation receipt, an exact target hash, and a matching `RemoteRemovePlan`. A pre-existing exact helper remains untouched.

Any temporary upload uses a random gate-owned name. A trap removes it on every terminal path. Cleanup failure blocks the next gate.

## Server reconciliation

The helper's `reconcile` mode collects one bounded server snapshot. It returns only sanitized fields:

- expected container count and running state
- container identity, image identity, and restart count hashes
- exact User Datagram Protocol (UDP) publication count and identity
- public listener class counts
- persistent IPv4 host-policy loaded state and identity
- IPv6 host-policy non-mutation state
- baseline peer count and set hash
- candidate, temporary, and atomic leftover counts
- payload and protocol identities

The helper does not expose peer keys, addresses, raw firewall rules, network names, container JavaScript Object Notation (JSON), or timestamps.

DigitalOcean Cloud Firewall state cannot come from the Droplet. A separate read-only GUI observation records the normalized rule union, Droplet association, and observation freshness in the protected runtime bundle. It does not use an API token. The final receipt labels this evidence as owner-observed rather than server-confirmed. Any ambiguous UI state stops reconciliation.

The local reconciler combines three inputs:

1. attested server receipt
2. protected Cloud Firewall observation
3. local profile and adapter absence receipt

It emits `PRELIVE_READY=YES` only when all expected identities and counts match.

## Guarded Admin and Guest actions

The local launcher starts one bounded SSH process for `guard admin` or `guard guest`. The helper collects and validates the baseline before it emits a ready event.

The protocol uses newline-delimited JSON events:

1. `ready_for_ui`: complete reconciliation passed and the guard is armed
2. `candidate`: exactly one expected delta reached stable convergence
3. `stopped`: the bounded window ended without an accepted candidate

The guard polls every two seconds for at most 180 seconds. It requires two identical candidate snapshots separated by five seconds. The launcher keeps the process open and reads events as they arrive.

The candidate receipt binds:

- operation type
- random nonce hash
- pre-operation peer-set hash
- post-operation peer-set hash
- one candidate fingerprint hash
- persistent, live, and metadata equality
- one accepted semantic configuration transition
- container restart delta
- firewall and listener equality
- candidate-specific official UI rollback identity
- emergency rollback readiness boolean

Any unknown delta, baseline loss, timeout, malformed event, output overflow, or transport failure closes the GUI window and stops the gate.

## Client peer observation

`client-observe` replaces the untracked second helper. It accepts an operation nonce and selected Guest fingerprint hash. It returns:

- payload and protocol identities
- nonce hash
- selected Guest fingerprint match
- bounded handshake freshness
- before and after counter hashes
- traffic delta boolean
- observation duration

The client gate verifies these fields before it accepts `PostConnect`.

Production client actions always perform current live collection. Synthetic `ObservationPath` input remains available only behind an explicit test-only switch. Runtime paths must remain inside the protected ignored root.

## Failure handling

All mismatches fail before peer or Windows mutation. The package handles failures as follows:

| Failure | Required result |
|---|---|
| Runtime bundle mismatch | No SSH |
| Agent mismatch | No SSH |
| Host key or egress mismatch | No SSH |
| Remote target conflict | No overwrite |
| Install failure | Target remains absent or exact; remove temporary file |
| Reconciliation mismatch | No GUI peer action |
| Guard transport failure | Close GUI window; preserve candidate for exact recovery decision |
| Official UI rollback failure | Stop; do not run emergency rollback without approval |
| Client observation mismatch | Remove only the local client profile after its approval |

The emergency rollback remains candidate-bound. It can remove only one proved candidate peer and can run one `awg syncconf`.

## Execution sequence

Task 6A must pass before Task 7:

1. Implement and review the tracked package offline.
2. Create the protected runtime trust bundle and load one key after exact approval.
3. Run `RemoteInstallPlan` and read-only Cloud Firewall observation.
4. Install the exact helper only after a separate hash-bound approval.
5. Run complete server, Cloud Firewall, profile, and adapter reconciliation.
6. Present the exact Gate 6.5 Admin candidate.
7. Prove the exact one-peer rollback control before creation, then run guarded Admin creation. Invoke rollback only on anomaly.
8. Present and run the exact Guest candidate and protected export.
9. Continue with Gate 6.6 and Gate 7 only after their candidate approvals.

## Approval boundaries

The implementation package is offline. It does not authorize these later actions:

- `Gate 6.4L`: create the protected runtime bundle and load one dedicated key
- `Gate 6.4R`: perform bounded read-only SSH and DigitalOcean UI observations
- `Gate 6.4P`: install one exact remote helper
- `Gate 6.5A`: create one management Admin under the armed guard
- `Gate 6.5B`: create and export one static PC Guest under the armed guard
- `Gate 6.6`: import and connect one exact local profile
- `Gate 7.2`: run exact candidate-bound Apply and Confirm
- adapter loss and reboot tests
- `Gate 7.3`: run network `FullRestore` and independent ACL restore
- emergency direct rollback

Each approval binds the current candidate hashes, challenges, scope, rollback, and stop conditions.

## Offline acceptance

Task 6A requires behavioral tests for:

- absent, exact, and conflicting remote target states
- atomic install and exact scoped removal
- malformed, stale, extra, oversized, and replayed receipts
- protected runtime root, ACL, reparse, and file-identity checks
- exact one-key agent validation
- every reconciliation mismatch
- streaming ready, candidate, timeout, and transport events
- Admin and Guest exact-plus-one convergence
- nonce-bound client observation with before and after counters
- test-only fixture isolation
- PowerShell 5.1 and PowerShell 7 compatibility
- Python syntax, Ruff, unit tests, and secret scan

The complete repository verification and one independent QA/security review must return GO on committed HEAD.

## Compatibility and migration

Task 6A preserves the official AmneziaVPN 5.0.1.5 GUI path. It does not call internal Amnezia installation scripts as a stable API. The remote helper observes the installed AWG 3.1 state but does not manage Docker.

The helper remains an inert P3 operator tool with an exact retained hash. It does not become the P8 `server-agent`. P8 may replace or remove it through a later migration. P3 never infers helper removal from Windows `FullRestore`.

Task 6A removes the client gate's dependency on `/usr/local/libexec/home-gateway-p3-peer-observe`. Existing ignored runtime evidence remains untouched.

## Alternatives considered

### Use one transient remote file

A transient file still mutates the remote filesystem. It adds cleanup-failure state and does not solve the missing reconciliation logic. This option is rejected.

### Run the payload from standard input

The current self-attestation requires one bounded regular file. Standard input cannot provide the same file-identity contract. This option is rejected.

### Continue with manual runtime scripts

Ignored runtime scripts do not satisfy the tracked, committed, and reviewed guard requirement. This option is rejected.

## Open questions

No open architecture question blocks implementation planning. The owner must review this written design before the implementation plan is amended.
