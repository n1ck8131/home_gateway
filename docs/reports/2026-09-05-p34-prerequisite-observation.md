# Phase 3.4 prerequisite observation

Phase 3.4 is closed. Live observation passed on 2026-09-05 at 09:26 UTC; independent read-only receipt validation passed at 09:28 UTC. The protected receipt validates the server baseline, freshly observed Cloud Firewall, and three independent external-IP authorities. The full offline verification gate also passed. The server boundary remained read-only except for the explicitly authorized, recoverable quarantine below. Phase 3.5 has not started.

## Original blocker evidence

The bounded baseline-facts diagnostic returned the following on 2026-09-05:

| Baseline field | Observed |
| --- | --- |
| container_count / container_running / container_restart_count | 1 / true / 0 |
| udp_publication_count | 1 |
| public_listener_class_count | 9 |
| host_policy_loaded / ipv6_non_mutation | true / true |
| candidate_leftover_count / atomic_leftover_count | 0 / 0 |
| temporary_leftover_count | **1** |

`Get-P3ServerBaselineSHA256` rejects this baseline because it requires zero
temporary leftovers. The remote observation succeeded; this is a local
acceptance rejection, not evidence of failed SSH or changed Docker rules.
The earlier explanations attributing this repeated rejection to IPv4 hashes,
derived manifest hashes, or non-project IPv6 drift were not substantiated.

A second bounded read-only metadata diagnostic identified one regular
container `/tmp/*.tmp` file: 150 bytes, root-owned, mode `401`, approximately
eight days old. Its basename does not follow project candidate naming. Basename SHA256:
`3febfedd98c016aa02c631b74a5080202ec0edb532920e36e57ff033c1aae782`.
Its purpose and ownership beyond filesystem metadata are unproven. File
contents were not read or exported during this initial diagnostic, and the file was not modified or removed at that point.

Both diagnostic attempts stopped deliberately after safe facts were obtained,
before HTTPS. Each used one SSH connection and completed agent cleanup:
zero ssh-agent/ssh-add processes, no agent receipt, no observation batch.
Those initial diagnostics performed no server, VPN, firewall, route, DNS, adapter or reboot mutation.

The earlier protected IPv6 diagnostic v8 receipt is historical evidence only:
`1af673c2e642f2d07d22678a62d11f391d72072e20a2a7a10f2862dd38893671`.
It does not close Phase 3.4 or establish the current purpose of the temporary
file. The known failed final candidates and diagnostic runners remain ignored
local artifacts; they must not be reused as current approved release runners.

## Authorized quarantine and verification

The owner explicitly requested removal of the unknown `/tmp/*.tmp` file. Independent review approved an exact-target, recoverable quarantine before execution. The helper checked the basename hash, regular-file type, root ownership, mode `401`, 150-byte size, container identity, and inode before moving the original.

The quarantine is inside the container at `/tmp/.home-gateway-p34-quarantine-20260905-3febfedd98c016aa`, mode `700`. It contains an independent mode `400` snapshot, the retained original, and a mode `600` restore manifest. The operation hashed the bytes locally on the server but did not export or display their contents. The no-clobber restore helper remains a protected local operational artifact; rollback was not executed.

The protected cleanup receipt records `status=quarantined`, `remaining_tmp_count=0`, `recoverable=true`, `container_restart_delta=0`, and `agent_stopped=true`. Receipt SHA256: `68f10de7a03323622b59ecc8726d64b34b6d73c71f657d668d108e48ac2ec132`. This operation was a server filesystem mutation, not a read-only check. It did not change VPN, firewall, routes, DNS, adapters, services, or container restart state.

The subsequent IPv6 diagnostic v9 returned three identical policy samples, an empty DOCKER-USER chain, one first unconditional FORWARD hook, no project-owned rules, and no parse failures. Receipt SHA256: `2e51869db895539e0014c964bff70292bf0cf3e51b1fcdcce4b398f9b77ee757`. It confirms structural eligibility for the observed IPv6 identity, not final phase acceptance. Its ten-minute freshness window must not be extended by substituting the receipt timestamp for the execution clock.

## Review and corrections

Independent review identified an exact-IPv6-pin regression, ownership checks
limited to the filter table, and a diagnostic receipt hash not checked against
its bytes. The local fix pass restores observed/expected IPv6 hash equality,
checks project ownership and declared rule sources across tables, requires an
unconditional first FORWARD hook, and verifies the canonical receipt hash.
Regression tests cover these cases. IPv4 normalization remains unchanged.

The production rebase wrapper now revalidates protected receipt hashes, freshness, server/key identity, payload/protocol, and driver hashes before agent startup and immediately before SSH. The positive execution test verifies scope resolution and rejects evidence that expires during interactive key loading. Receipt hashing preserves empty arrays and normalizes PowerShell 7 DateTime conversion to the writer's UTC round-trip string.

The old ignored final-runner template synthesized a Cloud Firewall observation from manifest values and assigned a new timestamp. This did not establish freshness. The corrected builders require an independently collected Cloud observation, pin its file hash, and preserve its actual observation time. The final observation used a fresh read-only inspection through the authenticated owner's DigitalOcean browser session, not a refreshed historical attestation.

Candidate v18 reached egress validation but failed because the local observer compared HTTPS response timestamps with a clock captured before SSH. The corrected observer reads the current clock for each egress check and records batch completion time. A regression test covers 50 seconds of SSH/HTTPS delay and still rejects timestamps older than ten minutes or over five seconds ahead. The failed v18 attempt left no accepted receipt and cleaned its SSH agent.

## Final live evidence

The refreshed IPv6 diagnostic v10 confirmed the same eligible policy identity, followed by the v19 final runner. Each diagnostic/final SSH call verified the pinned host key and dedicated key identity. The final runner returned `status=validated`, exit `0`.

| Evidence | Result |
| --- | --- |
| Cloud Firewall, 09:19 UTC | One firewall; one unique Droplet attached directly and by tag; two inbound rules; three outbound rows covering six protocol/address-family combinations; no inbound UDP IPv6 rule |
| Management egress | The observed management IPv4 `/32` matched the manifest and all three HTTPS authorities |
| Server leftovers | Candidate `0`, atomic `0`, temporary `0` |
| IPv6 policy | Exact expected identity matched; structural non-mutation checks passed |
| Container restarts | Count `0`; cleanup restart delta `0` |
| Egress | Three distinct authorities, one matching management source |
| Protected final state | Six expected files; no agent receipt or pending directory; zero ssh-agent/ssh-add processes |
| Final observation mutation | `false`; no raw identities emitted by the observation runner |

The identity chain is:

- IPv6 diagnostic receipt: `0bab5942b7177dbd133ca07133f4bb412a8856e624f0e549cf101f9000278ad6`
- Browser Cloud observation: `c64b46eef544a4f84f5f4c0eb9c0900cca40c187c2e7b0fb71688b47e1250005`
- Final runner: `e43e7c8598e94b15cad7b2f0a831faf4c759e63fcb4f9571dc5f681b02f1ea09`
- Rebased plan: `7266056baf5ddd33edf8b2cc10053e52e01c5b4fac3a8aa776f60bc1a5cbc582`
- Manifest: `9c3d90857686484c1d0293232482f20433898988b9c1fc4982fc2622f2c2f8a4`
- Observer payload: `233c0672c524afade23d9afb01e01cfb28e0c5f50493f0fcf85fa3ad724c9f79`
- Server baseline: `ea611479698f1970704e00b437e7f19769d2fda7927dc3bf7c09eed0d7cd54e9`
- Prerequisite receipt: `a87dd9aaa441a1e2657ac90e4a1d30a35db5e5ebea672bcf19cacc8cae765101`

Raw operational manifests, runner inputs, and protected receipts remain in ignored local storage. Only sanitized evidence belongs in Git. The final receipt records `owner_observed=true` and `server_confirmed=true`; the browser observation itself records `server_confirmed=false`, since SSH cannot attest the Cloud Firewall configuration.

## Validation

| Check | Result |
| --- | --- |
| `scripts/dev.ps1 -Command verify` | Exit 0 after the clock fix; Go suite, 240 Pester tests, build, analysis, secret and governance checks passed |
| `python -m unittest discover -s tests/python -q` | Exit 0; 56 tests passed |
| `ruff check .` | Exit 0 after correcting the review fix's loop variable lint |
| `ruff format --check` on the two changed Python files | Exit 0 |
| `ruff format --check .` | Exit 1: existing Python-block formatting in unchanged `docs/superpowers/plans/2026-08-30-p3-task6a-prelive-guard.md`; not modified |
| `git diff --check` | Exit 0 |
| Focused prerequisite suite, Windows PowerShell 5.1 and PowerShell 7 | Exit 0; 32 tests each after the clock fix |
| Independent read-only re-review | GO for code and runtime acceptance; no remaining must-fix findings |

The independent reviewer ran the normal read-only `Validate` action at `2026-09-05T09:28:13Z`, inside the Cloud evidence freshness window. Validation returned exit `0` and confirmed the exact final receipt, baseline, Cloud, and egress identities. The reviewer also verified the six-file state and agent cleanup. No additional server connection or network mutation was needed for this review.

## Next phase boundary

Phase 3.4 does not create management/Guest profiles, install a runtime helper, activate a tunnel, or alter Windows networking. Those actions remain separate later phases. The receipt is point-in-time evidence, not indefinite approval: later phases must enforce freshness or obtain a new read-only observation. The quarantine remains available for rollback; its original purpose is still unproven, and the file has not been irreversibly destroyed.
