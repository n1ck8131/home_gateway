# P3 Gate 6.4 / 6.5C reconciliation

Date: 2026-08-30

Result: Gates 6.1-6.3 remain passed; Gate 6.4 is pending a fresh bounded read-only reconciliation; Gate 6.5C is `rollback-complete`. No protected PC profile exists and no Windows field gate is accepted.

## Evidence classification

| Scope | Classification | Sanitized fact |
|---|---|---|
| Gate 6.1-6.3 tracked checkpoint | `confirmed` | The tracked bootstrap report proves one approved Droplet, one observed AmneziaWG container, hardened key-only `homegateway` access, root/password SSH disabled, and recovery SSH exit `0` |
| Gate 6.4 checkpoint | `confirmed` | At the Gate 6.3 checkpoint the Cloud Firewall exposed only restricted management SSH while one container UDP publication was observed; this is a historical checkpoint, not current-state proof |
| Gate 6.4 later runtime observations | `owner-observed` | Ignored local evidence exists but is not promoted to a tracked current-state claim because its complete host/Cloud Firewall union is not represented in sanitized tracked evidence |
| Gate 6.4 current host/Cloud Firewall union | `needs-read-only-recheck` | Recheck the expected container/publication, persistent host policy, IPv4/IPv6 Cloud Firewall rules and the complete public ingress union before any peer or profile action |
| Gate 6.5C Admin candidate | `rollback-complete` | Exactly one Admin peer removed; exactly one rollback `syncconf`; baseline peer-set hash restored; container restart delta zero; firewall unchanged; SSH exit zero |

Gate 6.5C proves a bounded rollback, not a successful management-peer or Guest gate. The accepted terminal topology remains: preserve the pre-existing baseline Admin peer, add exactly one `homegateway` management Admin peer, and add exactly one static PC Guest. The supported Admin rollback is exact one-peer removal through the official Amnezia UI. The reviewed candidate-bound direct rollback is emergency-only. Guest removal is a separate server mutation and is never implied by local client-profile rollback.

## Terminal restore contract

```text
terminal journal state = restored
active revision = empty
last-known-good revision = empty
pending/recovery revision = empty
ownership registry = present but empty
project-owned routes/sinks/firewall/NRPT/tasks = zero
install snapshot and terminal receipt = retained for audit
```

Network `FullRestore` and protected-config ACL restore are two monotonic, independently candidate-bound operations. If ACL restoration fails after network restore, the safer restored network state remains in place and only ACL restoration may be retried from a fresh exact plan and approval.

## Preserved boundary

- The protected PC profile is absent.
- No client profile was imported or activated by this reconciliation.
- No SSH, cloud, server, firewall, route, DNS, adapter, service, task or reboot action was performed.
- Real pins, transcripts, profiles and secrets remain outside tracked files.
- Direct, self-hosted, Cisco, DNS, IPv4/IPv6, MTU, transport, failure, restart and terminal restore field gates remain open.
