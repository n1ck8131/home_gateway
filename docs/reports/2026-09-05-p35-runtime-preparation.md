# Phase 3.5 runtime preparation

Phase 3.5 is in progress and has not passed its live gates. The protected prerequisite from 3.4 is intact but expired for runtime preparation. The failed-Prepare ownership correction passed final offline verification and independent review. The owner approved read-only refresh candidate V2; its first execution stopped before SSH because key unlocking did not complete before Cloud evidence expired.

This report serves the P3 controller and independent reviewer. Its single purpose is to record preparation evidence against the [phase execution plan](../superpowers/plans/2026-09-05-p35-runtime-helper-lifecycle.md). It is not runtime acceptance.

## Verified starting state

Work uses branch `phase/p3-5-runtime-lifecycle` in the existing `p3-redshield-windows` worktree, based on `2bb8171aa7087ca7e4021b64ad115e289a9d5f27`. Root `main` and its modified `PLAN.md` are outside this change. Existing untracked Python caches and `testResults.xml` are preserved.

The [3.4 report](2026-09-05-p34-prerequisite-observation.md) remains the historical acceptance record. A local read-only readiness probe at `2026-09-05T09:45:27.9253263Z` returned:

| Check | Result |
| --- | --- |
| Actual `New-P3ManifestPlan` | `blocked_prerequisite_expired` |
| Prerequisite observation | `2026-09-05T09:26:22.7940861Z` |
| Age at probe / allowed age | 1145 / 600 seconds |
| Receipt SHA-256 | `a87dd9aaa441a1e2657ac90e4a1d30a35db5e5ebea672bcf19cacc8cae765101`, unchanged |
| Protected prerequisite files | Six |
| Consumption marker | Absent |
| Proposed runtime root | Absent |
| SSH-agent / ssh-add process counts | 0 / 0 |
| Live action | None |

The probe validated the protected file set and static trust bindings before testing freshness. It did not substitute an earlier clock, edit a timestamp, start an agent, or open a server connection.

## Failed-Prepare correction

The original `Invoke-P3RuntimePrepare` rejected an existing runtime root inside a `try` block. Its `catch` then recursively deleted that root. Synthetic regression tests reproduced deletion of an existing directory and sentinel, and deletion of foreign nested content after an injected failure.

The correction creates the directory exclusively with its protected ACL and holds root and ancestor handles without delete sharing during preparation. A failed operation retains partial state and the consumed prerequisite, preventing ambiguous replay. A retained partial root requires inspected, separately approved recovery; the normal validator does not certify an incomplete bundle.

The native API contract was checked against Microsoft's [NtCreateFile reference](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) and [CreateFileW reference](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew). Native local tests cover file/directory collisions, racing creation, root and ancestor rename rejection, handle release, and a trailing directory separator. Final runtime script SHA-256: `e7446351afe211b63580359cfaa4f6c5a74dc478c4b71efe77e0667dd03eb096`.

## Prepared read-only refresh candidate

The local builder `build-phase35-refresh-candidate-v2.ps1` produced a protected five-file package under ignored `.p3-vps-run/p35-refresh-candidate-v2/`. It contains a sanitized candidate contract, prerequisite and agent plans, and a CurrentUser DPAPI-encrypted observation input. At candidate creation, the source receipt was unchanged and the observation directory was absent. That state is historical: the later attempts below created the initial three-file root and consumed the one-time resume claim. The earlier v1 package is preserved but superseded because a trailing-separator compatibility correction changed the driver hash.

| Identity | SHA-256 or challenge |
| --- | --- |
| Candidate contract | `f6fe3f6d56ffbf820819027a6d6291ef6bfeb6f63c373dfca643432abcba96e1` |
| Prerequisite plan | `c86c29a46f4aef5277d65d9b5f869472cf79864add0192e23c6f4c3254117fec` |
| Prerequisite challenge | `P3-PRELIVE-PREREQUISITE-C86C29A46F4AEF52` |
| Agent plan | `dc1087ceeff3901c260cf4131e149fab2b089929817a292974e25d276f5a413c` |
| Agent challenge | `P3-SSH-AGENT-DC1087CEEFF3901C` |

The contract pins the encrypted input and five production driver hashes. It permits one SSH observation and three HTTPS authorities, requires fresh authenticated Cloud Firewall evidence, and stops on baseline drift. Freeze the new Cloud observation file hash before agent startup and revalidate it before SSH and receipt assembly. Mandatory `finally` teardown applies to the dedicated memory-only agent. The package explicitly excludes runtime preparation and helper installation.

The package contains observation inputs and approval bindings, not a fresh receipt. The subsequently prepared executor uses the pinned production prerequisite driver. A runtime manifest/challenge does not yet exist.

## Validation evidence

| Check | Result |
| --- | --- |
| Initial focused regression cases | RED reproduced: 1 passed, 3 failed; only synthetic TestDrive paths |
| Candidate builder, Windows PowerShell 5.1 | Exit 0; five protected files; readback passed; no live action |
| `python -B -m unittest discover -s tests/python -q` | Exit 0; 56 tests passed |
| `ruff check .` | Exit 0 |
| `ruff format --check .` | Exit 1; inherited formatting in unchanged `2026-08-30-p3-task6a-prelive-guard.md`; 59 files already formatted |
| Focused runtime Pester, Windows PowerShell 5.1 and PowerShell 7 | 43/43 each; the final trailing-separator test also passed separately in both versions |
| Initial `scripts/dev.ps1 -Command verify` | Exit 0; 248 Pester tests; Go suite, analysis, secret, reproducible build, governance and toolchain gates passed |
| Final `scripts/dev.ps1 -Command verify` after trailing-separator correction | Exit 0; 248 passed, 0 failed/skipped; Go suite, build, static analysis, gosec 0, vulnerability/secret scans, governance and toolchain gates passed |
| Final candidate readback | Five driver hashes match; candidate/source receipt hashes unchanged; runtime and observation roots absent; zero agent processes |
| Consolidated independent review | GO for offline correction and requesting exact read-only refresh approval; 0 Critical, 0 Important, 0 Minor |

No Python source changed. The inherited Ruff formatting failure also appears in the 3.4 report; this phase does not reformat that historical plan.

The independent reviewer decrypted the V2 input only in memory and verified canonical plan/challenge equality, the encrypted input hash, all five driver hashes, restrictive ACLs, absent observation root, and zero agent processes. No additional server connection or live action was used for review.

## Remaining gates

The V2 observation budget and one-time resume claim are consumed. The SSH1/HTTPS0 resume stopped on baseline hash mismatch; V2 must not be executed again. A new exact diagnostic candidate requires its own owner approval and fresh Cloud evidence. Previously accepted hashes remain expected identities only; observed differences must be retained and reviewed before any baseline acceptance or further prerequisite refresh.

Only that fresh receipt can produce the exact runtime manifest and challenge. Runtime preparation and helper installation keep their own approval gates. Phase 3.6 profiles, phase 3.7 activation, and later network/recovery work remain outside this report.

## Approved refresh attempt

The owner approved V2 in the task. A new local executor, `phase35-approved-refresh-runner-v2.ps1`, reuses the inspected console-launch code and binds the approved candidate, five driver hashes, encrypted input, system PowerShell, and interactive wrapper. A preflight-only parameter-scope error was corrected before agent startup. Independent review also reproduced and corrected an `AddRunner.GetNewClosure()` function-lookup failure by capturing `CommandInfo`. Final preflight and independent review returned GO.

| Artifact | SHA-256 |
| --- | --- |
| Reviewed executor | `9161b445eda049d3bfb9fdd890855bd0c3448249f82f869ee666cf1bef88ad4d` |
| Interactive key wrapper | `ad84341f3e5adfe55350c15870d9fc5f57ce063d8c3f40a36873dde0669c0bd9` |
| Fresh browser Cloud observation | `2bc3a6ee0d7fb67d7ab77ec21ef4f0e7d70d91d6400d39be241dccc4c9e87ed4` |
| Protected attempt receipt | `385446c5971612dd0f56a4613016acd831476d12c58f3b658164a92f67ffe0c1` |

Authenticated browser inspection observed the Rules page at `10:16:15.628 UTC` and the Droplets association at `10:16:43 UTC`. The firewall identity, management source, and unique Droplet identity matched the accepted hashes. Two inbound rules and three outbound rows remained unchanged; no inbound IPv6 UDP rule was present. The same Droplet appeared directly and through its tag, yielding one unique association. The protected Cloud record preserves the earlier observation time and expired at `10:26:15.628 UTC`.

Execution began at `10:17:39 UTC` and started one temporary agent. The interactive key-unlock window did not complete. After expiry, the controller stopped only that invocation's wrapper, validating its parent, creation times, and exact command identity. Its console child was identified before cleanup. CIM creation timestamps truncate sub-microsecond precision; the final process-handle check used the separately observed exact `Process.StartTime`, without relaxing identity checks. The parent runner then performed its normal start-failure teardown.

The runner returned exit `23`, `failed_closed`, SSH calls `0`, HTTPS calls `0`, and agent starts `1`. Final readback confirmed zero agent, ssh-add, runner, wrapper, or console processes. The observation root contains only its three initial protected files; no agent receipt, observation batch, or prerequisite receipt exists. The 3.4 receipt hash is unchanged. Runtime and helper actions were not performed.

Historical disposition after the first, zero-SSH attempt: the encrypted V2 input and failed-attempt evidence were retained for an inspected one-time resume under the original approval. That resume has now run and stopped on baseline drift, as recorded below. This paragraph no longer authorizes a retry; the claim is consumed. Runtime preparation and helper installation remain separately gated.

The next runtime-candidate builder has a static independent GO, but has not run because the required fresh prerequisite receipt does not exist. No network configuration, profile, service, firewall, Docker configuration, route, DNS, adapter, RedShield, or Cisco state was changed.

## Повторный read-only запуск: остановка на baseline

После сообщения владельца «Готов» выполнен один повторный запуск в пределах одобренного V2. Предыдущий результат с SSH0/HTTPS0 проверен по точному hash; сохранённый root допущен только с исходными тремя файлами, защитным ACL и совпадающими manifest/agent manifest. Независимый reviewer потребовал одноразовый durable claim, поскольку новый сбой после SSH мог оставить те же три файла. Исправленный executor создаёт отдельный каталог claim через exclusive `FILE_CREATE` до agent/network и сохраняет его при любом исходе. Финальный review: GO, открытых замечаний нет.

| Артефакт | SHA-256 |
| --- | --- |
| `phase35-approved-refresh-runner-v2-resume1.ps1` | `a79aeb85f8974d109cb2416288d15094c5090c0b7d2547ab36558ad354e299a6` |
| Новый Cloud observation | `642890fea8e8f53715e65cdfd2726d1cd920fbc1fba34ec8513a5e4e1666b83b` |
| `p35-refresh-resume1-result/attempt.json` | `cff46cc4081eede897cf56c03a58d84fb5cde16d516c580b1dbd5cf35e544120` |

Rules наблюдались через authenticated browser в `10:48:47.052 UTC`, привязка Droplet — в `10:49:13 UTC` 2026-09-05. Firewall, management source, единственный Droplet, две inbound rules и три outbound rows совпали с принятой конфигурацией. Cloud record сохраняет время первого наблюдения.

Ввод passphrase завершился; выполнено **SSH1, HTTPS0, agent starts1**. SSH process вернул успешный ограниченный JSON-ответ без stderr, но `server_baseline_sha256` не совпал с ожидаемым `ea611479698f1970704e00b437e7f19769d2fda7927dc3bf7c09eed0d7cd54e9`. Executor остановился на строке 245 с `failed_closed`; hash сообщения `accepted server baseline drifted` равен `7e6f0656405f0dcdf6618b93c7bc8f77083eb4c52dabb016699c9b8feb8c9134`. Tool зафиксировал process exit 1. Новый baseline не сохранялся перед исключением, поэтому его hash и изменившиеся поля неизвестны; причина расхождения ещё не установлена.

Teardown завершён: агент, ssh-add и принадлежащие запуску wrapper/runner отсутствуют. Исходный receipt 3.4 неизменён. В root остались три начальных файла, batch и новый receipt отсутствуют. Claim сохранён; контрольный `PreflightOnly` отклонил повтор на строке 193 до agent/network, с SSH0/HTTPS0/agent starts0. Runtime Prepare и helper не выполнялись. Фаза 3.5 остаётся открытой.

Следующий шаг — отдельный точный read-only diagnostic candidate с новым nonce и одним SSH-наблюдением, которое сохраняет обезличенный baseline и различия. Принятие нового baseline и повторное выполнение refresh не разрешены автоматически после stop-on-drift.
