# Phase 3.5 runtime preparation

Фаза 3.5 открыта. Compact migration V4, Runtime V5 и helper templates получили независимый technical offline GO. Владелец делегировал все оставшиеся разрешения внутри фазы 3.5. Opera открыта и подключена к авторизованной Cloud-сессии; свежие Cloud rules/association совпали. V4 остановлен после ожидания разблокировки SSH-ключа и истечения freshness: SSH0/HTTPS0, агент завершён. Receipt/runtime/helper gates не получены. Текущий технический блокер — доступный штатный key unlock; результат и сохранённые claims описаны в конце отчёта.

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

Предыдущие refresh и diagnostic claims сохранены. Policy V2 остановилась до SSH; её отдельно рассмотренный повтор V3 использовал SSH-бюджет и завершился ошибкой. Прямой replay запрещён. Baseline diff выделяет три изменённых hash, но не доказывает неизменность IPv4/nft rules. Независимая проверка допускает после normalization fix сразу штатный prerequisite collector с новым payload и безопасной регистрацией отказов; дополнительные policy-only samples не обязательны. Принятие baseline и runtime остаются NO_GO до соответствующих evidence и approvals.

Точный runtime manifest и challenge можно получить только из нового принятого свежего prerequisite receipt. Runtime preparation и helper installation сохраняют свои approval gates. Путь до приёмки записан в [phase plan](../superpowers/plans/2026-09-05-p35-runtime-helper-lifecycle.md#текущий-путь-к-закрытию). Профили 3.6 и активация 3.7 остаются вне этой фазы.

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

## Подготовка diagnostic candidate

Диагностический сценарий использует прежние pinned host/key/payload и отдельные nonce, observation root и durable claim. Он допускает один SSH и ноль HTTPS, проверяет envelope, nonce, payload/protocol и canonical baseline hash, сохраняет защищённый обезличенный ответ и различия с историческим baseline, затем останавливается. Production `finally` завершает агент. Сценарий не принимает новый baseline, не собирает prerequisite receipt и не выполняет runtime/helper actions. Для запуска нужны свежий Cloud record и отдельное exact approval.

Первый локальный пакет V1 сохранён как superseded и не выполнялся. Независимый reviewer обнаружил, что dot-source production scripts очищает параметр `Confirmation`; первоначальный preflight не проверял этот случай. Исправленная версия использует `DiagnosticConfirmation` и проверяет переданное подтверждение после imports также в `PreflightOnly`. Memory-only synthetic check подтвердил: корректный envelope даёт два synthetic evidence records и ожидаемую остановку; изменение restart count отражается одним отличающимся полем; подменённый nonce отклоняется до любых записей. Эти проверки не выполняют filesystem writes, SSH/HTTPS или agent start.

На момент подготовки V2 был собран локально в `.p3-vps-run/p35-diagnostic-candidate-v2/`; пять защищённых файлов содержали contract/plans и DPAPI input. Новый observation root, claim и Cloud record тогда отсутствовали. Windows PowerShell 5.1 preflight с правильным `DiagnosticConfirmation` прошёл; неверное подтверждение отклонено до agent/network. V1 сохранён побайтно.

| Артефакт V2 | SHA-256 или challenge |
| --- | --- |
| Diagnostic candidate | `69cb0397d6176b8e1e0e74f06bfc3fb0e8212b7f0873b0f9439ff13d3c13029a` |
| Diagnostic challenge | `P35-DIAGNOSTIC-7073247BC0713953` |
| `phase35-diagnostic-runner-v2.ps1` | `a57b3375aa3d93057aaff36a7c4931743b85388d85061ae71396655849cf0935` |
| `phase35-build-diagnostic-candidate-v2.ps1` | `f71a4365ed48cbe817537df38b7aaa75c03688c2cc6fb3af8bd85a9e92081729` |

При подготовке будущий frozen Cloud file был определён как `.p3-vps-run/p35-cloud-evidence-diagnostic-v2/observation.json`. Статус immutable candidate contract — `awaiting_exact_diagnostic_approval`; факт последующего одобрения и исполнения записан в следующем разделе и protected attempt, без перезаписи исходного contract.

Независимый финальный review V2: **GO для запроса отдельного exact approval, открытых замечаний 0**. Reviewer подтвердил DPAPI input, canonical plans/challenges, historical baseline binding, пять driver hashes, path pins, защищённый пятифайловый package, отсутствующие observation/claim roots и ноль agent processes. Review не выполнял live-действий. `git diff --check` прошёл.

## Результат diagnostic V2

Владелец подтвердил `P35-DIAGNOSTIC-7073247BC0713953`. Свежие Rules наблюдались в authenticated browser в `11:06:04.633 UTC`, привязка Droplet — в `11:06:23 UTC` 2026-09-05. Идентичности и union правил совпали с принятыми. Hash нового Cloud record: `628ae718cf8b2207002a9ec6f63a80f4e7c8ec7990e6ca44fcaaf5f1fa9d0592`.

Запуск завершился с exit 0, `diagnostic_captured_stopped`: SSH1, HTTPS0, agent starts1, teardown verified. Защищённые evidence находятся в `.p3-vps-run/p35-diagnostic-claim-v2/`; claim использован, повтор этого кандидата не допускается.

| Evidence | SHA-256 |
| --- | --- |
| `server-observation.json` | `e6c8c36fffd736c925397a9d3595a19e419a1a235c90076fb1b84f08a939df40` |
| `baseline-diff.json` | `6bed13cc1f832b3ae781061a219decade33da91a3b3ec11a981c7bfdf94a2007` |
| `attempt.json` | `7592ea88a17a26bcccd5a39fe3386dc0bac6dd49ab2dea34844cea2dc1c5c11a` |
| Observed baseline | `b773a5bd035dc5a924f3e06effa6378a92e894b124fe834a52c6662c703b5458` |

С историческим baseline `ea611479698f1970704e00b437e7f19769d2fda7927dc3bf7c09eed0d7cd54e9` отличаются ровно три поля: `host_policy_sha256`, `firewall_identity_sha256`, `runtime_identity_sha256`. Остальные 24 поля совпадают. Изменение IPv4 hash может менять оба агрегата, но отдельный nft hash не выводится в baseline: его неизменность отдельно не доказана.

В `scripts/p3-amnezia-peer-guard.py:564` IPv4 `_normalize_policy` сохраняет chain declaration counters вида `:INPUT ACCEPT [n:n]`. Memory-only fixture с одинаковыми правилами и единственным изменением `[10:640]` → `[11:704]` через фактический `collect_server_snapshot` воспроизвёл ровно те же три отличающихся поля. IPv6 normalizer обнуляет такие counters. Проверка выполнена с injected runner, без subprocess/network/filesystem writes; exit 0. Независимый reviewer отдельно подтвердил этот механизм на pure-memory fixture.

Это доказанный недостаток устойчивости IPv4 identity, **но не доказательство counter-only причины live drift**: исторические IPv4 rules не сохранены. Независимый review результата: **GO для diagnostic evidence; NO_GO для baseline promotion и продолжения runtime**. Проверены canonical hashes, nonce/payload/protocol, diff, защищённые ACL/file sets, отсутствие agent processes и promotion. Runtime Prepare, helper installation и сетевые изменения не выполнялись.

Следующий разрешённый offline шаг — подготовить отдельный policy diagnostic candidate с несколькими bounded IPv4/nft samples, раздельными structural/counter identities и project invariants. Его SSH требует нового exact approval. Автоматическое принятие baseline по совпадению synthetic pattern запрещено.

## Подготовка policy diagnostic

Следующий сценарий ограничен одним SSH-сеансом с тремя парами read-only IPv4/nft samples, без HTTPS. Новый candidate должен отдельно связывать фактические payload, loader, SSH argv и stdin frame hashes; прежний prerequisite plan не считается разрешением для нового payload. Исходные driver files и evidence не изменяются.

Classifier разделяет structural/counter hashes и проверяет стабильность samples. Его parse scope ограничен framing, формой counters и наблюдаемыми признаками project rules; это не полная грамматика firewall и не полная приёмка policy invariants. Opaque noncounter значения целиком участвуют в structural hash. Даже совпавшие структурные samples не доказывают исторический counter-only drift; baseline promotion остаётся отдельным закрытым gate.

Первичные локальные fixtures подтвердили invariant structural hashes при росте counters, обнаружение изменения правила и отклонение неподдерживаемых форматов. Live policy-наблюдение не выполнялось; сначала требуются финальная фиксация candidate, независимый review и его отдельное exact approval.

Ruff check и format check прошли только для пяти новых Python-файлов. Fixtures подтвердили counter-only invariance, changed-rule detection и отклонение трёх unsupported cases. PowerShell parser прошёл; PowerShell и Python дали одинаковый protocol SHA для вложенных command arrays. AST семи включённых guard functions совпадает с исходным production code. Полный repository suite повторно не запускался: production файлы не менялись. Статический review нового payload/transport/runner/builder завершён без must-fix; финальный GO требует readback собранного package.

Первый policy package V1 не прошёл локальный Windows PowerShell 5.1 preflight: `ConvertTo-Json` по-разному экранирует quoted remote command в PowerShell 5.1 и 7, поэтому argv-template SHA различался при одинаковых аргументах. Agent/network actions не выполнялись. V1 сохраняется как superseded. Для V2 transport identity рассчитывается по явно обозначенному NUL-separated UTF-8 представлению с запретом NUL внутри аргументов; сами SSH arguments не меняются. До фиксации V2 требуется равенство emitted invocation hashes в обеих версиях PowerShell.

При подготовке финальный policy V2 был собран в `.p3-vps-run/p35-policy-candidate-v2/`. Exact argv/frame hashes совпали в PowerShell 5.1 и 7; NUL injection отклонён. Windows PowerShell 5.1 preflight с правильным supplied `PolicyConfirmation` прошёл; неправильный отклонён с SSH0/HTTPS0/agent starts0. Пять защищённых файлов были прочитаны обратно, future observation/claim roots тогда отсутствовали.

| Policy V2 identity | SHA-256 или challenge |
| --- | --- |
| Candidate | `7a246839e0f8c0f7a68f7e66968e20a63fcc4fa56c0ff1f11b4e9861d60776eb` |
| Challenge | `P35-POLICY-0AE7B886B8D0A19D` |
| Runner | `c6147ab889dc78b49479badcc82bae79935551a18c7df38f2385a5db05b60f3d` |
| Builder | `0d63f651fba225e824cc36c2bdefcdc8c71d67e846df6ddea0b9e9cb078bc59c` |
| Transport | `e91e29ce01a1e97bb3e9a50d720d263128130f4a3309a92e75ef9804f743933b` |
| Payload | `c799eebf860686dfbebe8f8358fb1443c127bb157cba296390131ddfb01e41cf` |
| Loader | `317fef9808970cf6bf28a11d7af11f83ae7d7d6f17e93e6bac73af6c441cf922` |

Контракт разрешает один SSH, ноль HTTPS, три пары `/usr/sbin/iptables-save` и `/usr/sbin/nft -j list ruleset`. Каждый внутренний вызов ограничен четырьмя секундами и 65536 bytes. Raw остаётся в памяти; сохраняются validated hashes/counts/classes, stability flags и project-marker observations. Baseline promotion, assembly, runtime/helper не разрешены. Перед будущим запуском нужен новый authenticated Cloud record `.p3-vps-run/p35-cloud-evidence-policy-v2/observation.json` с frozen SHA.

Финальный независимый review перед запуском: **GO только для запроса exact approval policy V2, must-fix 0**. Проверены DPAPI input, canonical plans/challenges, baseline binding, component/driver hashes, actual argv/frame/payload/loader/protocol pins и paths, ACL/file set и отсутствие agent processes. На момент review policy V2 не выполнялся. Фаза 3.5 остаётся открытой; технический NO_GO для baseline/runtime сохраняется.

## Одобренная policy V2: остановка до SSH

Владелец подтвердил `P35-POLICY-0AE7B886B8D0A19D`. Существующий вход DigitalOcean восстановлен через сохранённый Google account; новая регистрация и расширение доступа не выполнялись. Rules наблюдались в `11:55:36.756 UTC`, привязка единственного Droplet — в `11:55:59 UTC` 2026-09-05. Идентичности и union правил совпали с принятыми. Frozen Cloud SHA: `f0159231b9ae62f6fab659cc03b2b8ef15cea3a69957557959d4c8b6e251371a`; expiry — `12:05:36.756 UTC`.

Ввод passphrase не завершился до expiry. В `12:06:08 UTC` controller остановил только принадлежащий этой попытке wrapper PID 18488: проверены parent PID 35140, command/candidate identity, точный `Process.StartTime` `11:56:36.2832526 UTC` и удерживаемый process handle. Parent runner завершил агент через штатный start-failure teardown.

Runner вернул `diagnostic_failed_closed`, **SSH0/HTTPS0/agent starts1**, agent/add processes0; tool process exit1. Protected attempt `.p3-vps-run/p35-policy-claim-v2/attempt.json` имеет SHA `0f5742a7cab7e909750d82258376946c2326b63780aa70e5d4fd16c20133103b`. Error hash `3cecd83f2d364a6e1d3e0f15ea814ede737826931f4e3c6c4620a02a83db137c` относится к незавершённой загрузке ключа. Policy samples и `policy-observation.json` не созданы.

Final readback: claim root содержит marker/claim/attempt, observation root — три начальных manifest files; agent receipt отсутствует. Агент, ssh-add и owned wrapper/runner завершены. Исходный receipt 3.4 `a87dd9aaa441a1e2657ac90e4a1d30a35db5e5ebea672bcf19cacc8cae765101` неизменён, runtime root отсутствует. Сетевые настройки и серверные файлы не менялись.

Одобрение владельца записано; сетевой бюджет этой попыткой не использован, но durable claim создан и сохранён. Прямой повтор исходного runner запрещён. Перед новой попыткой нужны проверка сохранённого zero-SSH состояния и рассмотренный recovery/resume path; старые evidence не удалять и не обновлять их timestamps. Продолжение ожидает доступного интерактивного ввода ключа. Фаза 3.5 остаётся открытой.

Независимый review результата: **GO для фиксации failed-attempt evidence**. Подтверждены attempt SHA, key-load failure, SSH0/HTTPS0, завершение процессов, ACL и оба трёхфайловых root, отсутствие новых samples/receipt/runtime и неизменность receipt 3.4. Новых выводов о policy stability нет; baseline/runtime NO_GO сохранён.

## Повтор policy diagnostic V3: ошибка SSH process result

По указанию владельца «Повтори» подготовлен отдельный V3. Его recovery predicate проверяет точные hashes предыдущей SSH0-попытки, защищённые file sets и отсутствие receipt. Старые candidate, claim и observation не изменены. Новый wrapper сразу вызывает `ssh-add`, без предварительного `Read-Host`; ввод passphrase скрыт. Независимый review разрешил один эквивалентный повтор: **GO, 0 must-fix**. Исправление динамического shadowing `agent_manifest` проверено локально под Windows PowerShell 5.1; PS5/PS7 preflight и отклонение неверного confirmation прошли до agent/network.

| Артефакт | SHA-256 |
| --- | --- |
| `phase35-policy-runner-v3.ps1` | `f97ba37669a220e862432ebce18b1cb7383c942166cd26419095785f894319d6` |
| `phase35-policy-build-candidate-v3.ps1` | `572f1dcdb825666ed3886deb75f78ca6bdf2bdd64ea7caa4eb76cbfb90d4cb22` |
| `phase35-policy-key-unlock-v3.ps1` | `b54465676b075a427c44b01fe1579c8bc565a1bcec67cf8a6bb829bd91fe223d` |
| `p35-policy-candidate-v3/candidate.json` | `2dee2147a3c9e549abc55dd14533777a3129c8b314b8ce331c0ceba2da14e312` |
| `p35-cloud-evidence-policy-v3/observation.json` | `e7f1a083d0c002fd46a0dc9feb47177704780aab432260c643f0f204f54387d8` |
| `p35-policy-claim-v3/attempt.json` | `a7f464e20e3147f55ad9e38d97024026943fb655e1b563ebb97929b323811e48` |

Challenge: `P35-POLICY-75B27502319101AA`. Payload, loader, protocol и argv template сохранены от V2; новый stdin frame SHA — `b261478c4c1be6c058f88cc0d614119fbb61520427bc73b719c12429f5590f60`. Fresh Cloud rules наблюдались `12:22:39.035 UTC`, association — `12:22:58.597 UTC` 2026-09-05; expiry `12:32:39.035 UTC`. Идентичности и правила совпали с принятыми.

Ключ загрузился. Выполнено **SSH1/HTTPS0/agent starts1**; runner вернул `diagnostic_failed_closed`, stage `agent_and_diagnostic`, `RuntimeException` на строке 113. Hash сообщения `policy SSH process failed` — `fad7dc0d1fa82de30f44c64de57cda0cd53517c145be0d9d60acf6f84d8b04c2`. Tool process exit — 1; это не сохранённый exit code удалённого SSH-процесса.

Строка 113 объединяет `TimedOut`, `Oversized`, ненулевой `ExitCode` и непустой `StdErr`. Ни отдельные flags/exit code, ни stdout/stderr не попали в evidence. Поэтому точная причина live-сбоя и число фактически выполненных внутренних policy-команд неизвестны. Успешное получение шести samples не подтверждено; `policy-observation.json` отсутствует. Это также выявляет ограничение диагностического executor: общий exception hash недостаточен для различения transport и remote observer failure.

После завершения отдельно проверены agent/add/owned wrapper/runner0. Claim root содержит marker, claim и attempt; observation root — только marker, manifest и agent manifest. Agent receipt отсутствует, исходный receipt 3.4 сохранил SHA `a87dd9aaa441a1e2657ac90e4a1d30a35db5e5ebea672bcf19cacc8cae765101`. Runtime Prepare/helper actions не выполнялись. Разрешённый payload содержит только read-only команды; серверные или сетевые изменения этой попыткой не выполнялись.

V3 budget использован, durable claim сохранён; повторное исполнение этого runner запрещено. Phase 3.5 остаётся открытой, baseline promotion/runtime — **NO_GO**. Следующий live-запуск требует рассмотренного исправления с безопасной классификацией ошибок и отдельного exact candidate; текущий исход такого запуска не разрешает.

Локальная диагностика implementer без изменения файлов и без сети: exact frozen loader/payload с mocked subprocess прошли для шести команд, включая допустимые nft warnings. Дополнительно Windows PowerShell 5.1 native stdin → frozen loader → frozen payload с mocked `Popen` вернул `ExitCode=0`, `TimedOut=false`, `Oversized=false`, stderr0 и шесть mock calls; SSH/HTTPS/agent0. Детерминированный framing/BOM defect не воспроизведён. Эти проверки не устанавливают причину live-сбоя. Минимальное исправление следующего executor должно сохранять отдельные безопасные flags, exit code и ограниченную классификацию ошибки, без raw policy/stderr.

Независимый review результата: **GO для фиксации evidence, 0 must-fix**. Reviewer проверил шесть hashes таблицы, protected file sets/ACL, сохранённые claims, отсутствие новых receipts/runtime, неизменность receipt 3.4 и завершение процессов. `git diff --check` прошёл. Это не acceptance фазы 3.5; неизвестная live-причина и baseline/runtime NO_GO сохранены.

## Исправление IPv4 counter normalization и переход к новому prerequisite

По поручению владельца продолжить и закрыть фазу исправлен доказанный локальный дефект `_normalize_policy`: только decimal counters точных chain declarations заменяются на `[0:0]`. Имена цепочек, policy, правила и их порядок сохраняются; counter-prefixed IPv4 rules по-прежнему отклоняются. Три строки production code не меняют public protocol или 27-field schema. Новый guard SHA — `ee7407fc16dbb4ab72fd02b3cd5f1f8f637ad9497bef51e05de73aa08ff17191`; tests SHA — `7f8e24fe2f19d109f32eb535e9995d83f1f93e33dc1a9fda6729a55f2bdc57df`.

Две целевые проверки сначала воспроизвели проблему, затем прошли. Regression сравнивает полный результат production collector при counter-only изменении и проверяет изменение host/firewall/runtime identity при изменении правила. Дополнительно проверена чувствительность к policy, chain name, order и неподдерживаемой counter форме. Scoped module: 54 passed; все Python tests: 57 passed. Scoped Ruff check/format и общий `ruff check .` прошли. Общий `ruff format --check .` сохраняет единственную прежнюю ошибку в неизменённом `2026-08-30-p3-task6a-prelive-guard.md:372`.

`scripts/dev.ps1 -Command verify` завершился с exit 0: 248 Pester passed, остальные Go/build/static/security/governance/toolchain gates прошли; gosec issues0, govulncheck vulnerabilities0, secret scan leaks0. Независимый reviewer принял source/tests и изменения plan/spec/report: **GO, 0 must-fix**. Это приёмка локального исправления, не live candidate и не фазы.

Следующий путь — новый migration prerequisite candidate, SSH1/HTTPS3, с новой manifest/agent/trust цепочкой. Шесть дополнительных policy-only samples не являются требованием закрытия. Штатный collector сохраняет свои IPv6 samples и invariants; runner должен до HTTPS/assembly требовать равенство 23 исторических полей и точное соответствие нового payload. Три policy-dependent hash сохраняются как текущее наблюдение. Новое состояние и исторический evidence gap принимаются отдельно вместе с exact runtime Prepare approval; исторические hashes не пересчитываются.

Rollback локального исправления — отдельный revert correction commit после проверки текущего diff; без reset и без изменения historical evidence. Возврат старого payload делает новые source-bound candidates непригодными и требует новой подготовки. Сервер ещё не изменялся этим исправлением. Будущее удаление helper допустимо только по доказательству `installed_by_gate` и отдельному exact removal plan; существующий exact helper сохраняется.

## Migration prerequisite candidate v1

Подготовлен новый защищённый пятифайловый package `.p3-vps-run/p35-migration-candidate-v1`. Он использует исправление из commit `51c9de6` и новую trust/manifest/agent/nonce цепочку. Historical receipt 3.4 и V3 failed attempt сохранены как provenance; их timestamps, hashes и claims не меняются. Candidate разрешает только после собственного exact approval **SSH1/HTTPS3/agent starts1**. Runtime Prepare, helper installation и принятие нового baseline не входят в этот запуск.

| Identity | SHA-256 |
| --- | --- |
| Candidate | `73f2bc5d62fa0a273259a5a01bdfa9b46e0547d8dac395e94756d06827af844f` |
| Prerequisite plan | `bc7487ad80a8ebfcdef1133f50176f6508fea717c8470bff1888aea0db65babe` |
| Agent plan | `da145b61ecb3361db13f8d165ef7613d0b9e4e941c892b62c3e8cc7f902a7967` |
| Runner | `781411a2b29063def516c049003612c6980a480fceeacdcd4eec3a62d652b556` |
| Builder | `c02dc1056cbc2754a67934bd61be37ab8492c2f125e9be552e52884fe5271501` |
| Support | `f96b399e675261a24055772ddad47540342f7146cb23296352cb85f4e95d493b` |
| Loader | `d3b64ac054b0d1509550d4c65554caceb931b50f265cd466dfef1b63567e1741` |
| Key wrapper | `4368a22ea962c972aef6ee7d54e51c30243a0db5a6e33ca6244d5071f30bda62` |
| Cloud recorder | `e3da894b45856934b43649c36695bdcc8e4f24e6e2ced2ca64d21a40407a21a4` |

Challenge — `P35-MIGRATION-BC7487AD80A8EBFC`. Новый payload SHA — `ee7407fc16dbb4ab72fd02b3cd5f1f8f637ad9497bef51e05de73aa08ff17191`; public protocol SHA сохранён: `efa9e5c6d152dfa3dd41cc3f80972792618265c3b00a927a580e808862ed626c`. Frame SHA — `c4040507453a409e98ae5bf581b5fc881af63e309f125726ffeef06acd339f0a`; argv template SHA — `17c2373031b25c0f07cbe3cbbde26a8d5cad6e4cc3da5707df36e446a3db86e9`, encoding `utf8-count-nul-argv-terminal-nul/v1`.

Runner сначала сохраняет protected safe process metadata: exit code, timeout/overflow flags, размеры и prefix hashes stdout/stderr. Loader возвращает только ограниченные error classes, без raw policy или текста exception. Затем runner проверяет envelope, nonce/payload/protocol, canonical baseline и 23 точных historical fields. Drift любого из них прекращает batch до HTTPS и receipt assembly. Новый payload hash проверяется отдельно; три policy-dependent hash только сохраняются. Успех завершается штатными Observe → Assemble → Validate и статусом `migration_observed_validated_not_accepted` после teardown. Durable claim создаётся до agent/network и сохраняется при любом исходе.

Локальные fixtures в Windows PowerShell 5.1 и PowerShell 7 прошли: девять native process случаев, четыре production Observe случая, Assemble/Validate для четырёх обоснованных hash differences, три отказа до HTTPS и четыре replay rejects. Exact transport → loader → production collector проверен с mocked subprocess; frame/argv identities совпали между версиями. Loader fixtures: один success, пять failures, три invalid frames. Реальные SSH/HTTPS/agent starts во всех fixtures — 0.

Reviewer выявил два соседних deadline дефекта нового native adapter: inherited output pipes и pending inherited stdin после выхода parent. Оба воспроизведены RED → GREEN; общий deadline теперь охватывает весь drain/write loop. Это исправления нового executor, не доказанная причина исторической V3 ошибки. Cloud recorder отдельно отклоняет истёкший исторический input в PS5/PS7 до создания root; свежие данные не подставлялись.

На момент freeze observation, claim и Cloud roots отсутствуют. Fresh authenticated Cloud evidence собирается только перед одобренным запуском; время исторического record не обновляется. Окно ввода ключа нового wrapper называется `Home Gateway Phase 3.5 - Prerequisite key unlock`, сразу вызывает `ssh-add` и скрывает ввод passphrase.

Frozen package preflight с правильным confirmation прошёл в PS5/PS7. Неверный confirmation отклонён с exit23 и SSH0/HTTPS0/agent0. Пять package files проверены; source receipt 3.4 и V3 attempt сохранили hashes, старые V3 claim/observation содержат прежние три файла каждый. Live observation ещё не выполнялась.

Независимый final immutable readback: **GO для запроса exact SSH1/HTTPS3 approval, 0 must-fix**. Reviewer расшифровал DPAPI input только в памяти, заново сформировал точные plans/frame/argv, проверил пять drivers и все launcher hashes, ACL/file sets и provenance. Historical trust отличается только новым `observer_payload_sha256`; historical baseline сохранён. Observation/claim/Cloud/runtime roots отсутствуют, agent/add0; acceptance/promotion/runtime/helper flags — false. Разрешение на живой запуск и приёмка фазы этим review не выдавались.

## Одобренное migration observation: успех

После подтверждения владельца выполнен точный candidate `P35-MIGRATION-BC7487AD80A8EBFC`. Fresh authenticated Cloud rules прочитаны `2026-09-05T13:24:17.544Z`, единственная привязка Droplet — `13:24:51.575Z`. Обе inbound rules и три outbound rows, management source и resource identities совпали с принятыми. Protected Cloud SHA — `4773fd236ba28407001b04ef5870979fd9984470d2cb1812d9700da4ee1b1eef`; старые records не менялись.

Runner завершился с exit 0: `migration_observed_validated_not_accepted`, **SSH1/HTTPS3/agent starts1**, teardown verified. Receipt наблюдался `13:28:09.4044786 UTC` 2026-09-05; его десятиминутная freshness граница для Prepare — `13:38:09.4044786 UTC`.

| Evidence | SHA-256 |
| --- | --- |
| `p35-migration-observation-v1/prerequisite-receipt.json` | `ae2c95f4f18d43d0adaed95636fcf7068df6b7d5bf3b5ecf0956346e99fbf889` |
| Новый server baseline | `f8c9731908e71daef942916fba05eeaf5311bd96abdae9a47f16a03e303b196e` |
| `p35-migration-claim-v1/server-observation.json` | `f17b92e3f3b93c8b4eb1d64c962921eb9f94ad328fbc13c3956cf7b7baa59e96` |
| `p35-migration-claim-v1/baseline-diff.json` | `4c5c8093d4cb0cdfa0befdb657e4fe11159927d346b033a82ce46e64212ef93c` |
| Safe process result | `90467897e3ae03900ad3749396cbf52dbc77f3999574a816f8f2489c55c77e75` |
| `p35-migration-claim-v1/attempt.json` | `e89783643eb76efa61ba240a9c1553af36c25fdc8901398071e95b29956bacd1` |

Совпали все 23 fixed fields. Четыре различия с историческим baseline — `payload_sha256`, `host_policy_sha256`, `firewall_identity_sha256`, `runtime_identity_sha256`. Новый payload соответствует reviewed normalization fix; остальные три hashes получены штатным collector. Это новое наблюдаемое состояние; историческая причина drift по-прежнему не доказана. `baseline_accepted`, `runtime_prepared`, `helper_installed` — false. Прямой replay migration runner запрещён: one-shot budget использован, claim сохранён.

Независимая проверка receipt — **GO**: Windows PowerShell 5.1 `Validate` прошёл с текущим временем `13:37:50 UTC`. Отдельный integrity recomputation из неизменных protected batch/Cloud и исходного receipt time воспроизвёл точный SHA; это не refresh и не продление freshness. Подтверждены 23 fixed fields, четыре различия, nonce/payload, ACL/file sets (шесть observation и шесть claim files), исходный receipt 3.4, ноль agent/add/owned runner/wrapper и отсутствие consumption/runtime. PS7 иначе сериализовал DateTime при дополнительной проверке byte reproduction; для точного SHA использован основной PS5 runtime. Ошибочный дополнительный probe reviewer вызвал pre-assembly-only helper на уже собранном root и получил отказ из-за существующего final receipt; это не ошибка рабочего observation.

## Runtime candidate V2 и истечение окна Prepare

За время действия receipt подготовлен `.p3-vps-run/p35-runtime-candidate-v2`: шесть protected files с DPAPI trust, runtime/agent plans и неисполняемым rollback proposal. Candidate SHA `b9c99f65d0a5eea93e2b2f7f129a461fd9048f858ee1f32f74afa5bf054ba624`, manifest SHA `b8fd73abbc0c76a08d0675908f893983dfca9e184bcccf3a7c3e703e98df6c43`, challenge `P3-PRELIVE-RUNTIME-480D02A117CE506D`. Executor SHA `2cbc0bcdcab45fd6c4debb7963af6dea5f68d662fa7c3cb19ef1a26dd31b0f34`, builder SHA `d0459430d6ab63a0cf3c22c2ffc413a429304c1aa1ee13fc2713fa40bcf2623d`.

Executor требует отдельного exact runtime confirmation, принятия baseline `f8c9731908e71daef942916fba05eeaf5311bd96abdae9a47f16a03e303b196e` и явного признания, что historical counter-only cause не доказана. До этого он выполняет только preflight. Исправлена обнаруженная до запуска коллизия `$RuntimeRoot` при dot-source: используется отдельное имя `$proposedRuntimeTarget`. Runtime AgentPlan пересчитывается полностью.

Полный `PreflightOnly` прошёл в PS5/PS7 до expiry. Независимый immutable readback принял package offline: exact DPAPI/trust/manifest/receipt, шесть files/ACL, plans и rollback projection совпали, **GO, 0 must-fix**. Controller не успел закончить подготовку и представить exact approval владельцу до `13:38:09 UTC`; approval на этот Prepare не выдавалось, сам Prepare не выполнялся. Последующий negative-ack probe остановился раньше на штатной freshness; он доказывает stale rejection, а не проверку неверного acknowledgement.

Runtime и consumption отсутствуют. Candidate V2 теперь исторический, **live NO_GO**; его receipt и timestamp не продлеваются. Для следующего окна заранее готовятся paths/pins variants проверенного observation и runtime executor. Следующий refresh будет проверять уже наблюдавшийся normalized baseline на полное равенство, сохраняя отдельное exact approval для runtime. Код и проверяемые templates готовятся до нового сбора, чтобы не расходовать его freshness window на реализацию.

## Следующий refresh и заранее проверенный Prepare

Подготовлен отдельный `.p3-vps-run/p35-migration-candidate-v2`, SHA `3dc4497fb921ca59c17dd8a7738ac107b958d22d89ed9a35526ec5b06e6beffd`, challenge `P35-MIGRATION-B5A1E349DEF11EF1`. Scope после exact approval: SSH1/HTTPS3/agent starts1, обязательный teardown. Runner `e92c514d62b195cb5640c4f36415c718ea5acfb6b428769b9c64aec26c6cfe3c`, builder `9639990045fcdb30aca986f0fe90dcbdf74d708d6caa2c79e0de144b22405e29`. Новый plan SHA `b5a1e349def11ef18526c88cd37fae0ac29e8220611882164421d29428d956a5`, frame SHA `e2785bfb7832a8b0007e6e17467d61b1a6676765a1d7be7b3d658f50a827aa62`; agent plan и argv template сохранены от V1.

Дельта исполнителя ограничена новыми roots/pins и дополнительным полным совпадением normalized baseline `f8c9731908e71daef942916fba05eeaf5311bd96abdae9a47f16a03e303b196e` до HTTPS/assembly. V1 receipt/attempt pinned как immutable provenance; continuity не означает принятие baseline владельцем. Новые observation/claim/Cloud roots имеют суффикс `v2`. Cloud recorder SHA `eeb5c82bada20c6f602d0151f8142fa46353e6c24373da8187c998fce4f0d68a` отличается от V1 только root. Предыдущие artifacts не изменялись.

Migration V2 preflight с правильным и неправильным confirmation проверен в PS5/PS7 без сетевых вызовов или agent. Отдельная fixture подтвердила, что drift normalized baseline останавливает batch до HTTPS/assembly. Независимый immutable readback: **GO, 0 must-fix**; проверены пять protected files/ACL, DPAPI plans, frame/argv, все pins, новый nonce и сохранённые manifests/provenance. Новые рабочие roots отсутствуют.

Заранее проверены runtime V3 templates, привязанные только к exact migration V2 candidate:

| Файл | SHA-256 |
| --- | --- |
| `phase35-runtime-build-candidate-v3.ps1` | `80037d01050a2ed378c312505eb6dbfb6cb13d3b02d8f568d78d7e98eac29d4e` |
| `phase35-runtime-prepare-v3.ps1` | `7d581c3e54682ed6ffa91712528343c333cc18ce4f9bf0e2ae98e52fcc4a4f79` |

Их дельта — новые paths и exact migration pin. Runtime target — `p35-protected-runtime-v3`, будущий package — `p35-runtime-candidate-v3`. После successful observation builder получает фактические `SourceReceiptSHA256` и `MigrationAttemptSHA256`; code edits не требуются. Будущие runtime candidate/manifest/challenge зависят от свежего receipt и ещё не созданы.

AST-selected executor preflight на новых synthetic receipts: PS5 4/4 и PS7 4/4 — fresh input, wrong acknowledgement, receipt mismatch и stale receipt. Fixture явно задаёт artifact root/self pin; исправлены только harness context и длина synthetic path. Реальные historical timestamps не менялись, Prepare/consumption/agent/SSH/HTTPS — 0. Это предварительная проверка templates; actual fresh runtime package всё ещё требует readback и отдельного exact owner approval вместе с принятием baseline и historical evidence gap.

Final scoped review migration V2 и runtime V3 templates — **GO, 0 must-fix**. Последний fixture gap закрыт без изменения frozen builder/executor. Разрешено запросить exact migration V2 approval; будущее runtime approval и приёмка фазы не выданы.

## Migration V2: отказ на normalized baseline continuity

После exact owner approval выполнен candidate `3dc4497fb921ca59c17dd8a7738ac107b958d22d89ed9a35526ec5b06e6beffd` / `P35-MIGRATION-B5A1E349DEF11EF1`. Authenticated Cloud association прочитана `2026-09-05T14:30:39.928Z`, rules — `14:31:17.858Z`; identities и rules совпали. Frozen Cloud SHA — `164ddaf5a571627f4c4b313dc00556586447a86da4e248a2310f8808b764efa0`. Предыдущее чтение rules с истёкшим временем не использовалось; новые данные получены повторным чтением UI.

Ключ загрузился до expiry. Native SSH завершился с exit 0, timeout/overflow — false, stderr — 0 bytes, UTF-8 valid. Runner сохранил process evidence, server observation и diff, затем остановился на `normalized observation continuity drifted` (line 89). Итог — `diagnostic_failed_closed`, **SSH1/HTTPS0/agent starts1**, agent/add0. Tool session завершилась с exit 1; внутренний failure outcome сохранён. Receipt assembly не выполнялась, one-shot claim сохранён, прямой replay запрещён.

| Evidence | SHA-256 |
| --- | --- |
| `p35-migration-claim-v2/attempt.json` | `e89e8b5216741044e2744f4cd1e83e49e57b4d14819cb4cefbc5755a68e80d06` |
| `server-observation.json` | `cc51e7da1d46b1fbfc903a244b83e779c2eb5cef60caaf8abc7daa2510790ca6` |
| `baseline-diff.json` | `fad76ce28a472bd81c56ca80e193d870d6fdd4df38d73c947c539ea0ba92727c` |
| `ssh-process.json` | `63905e165a48cc9f2c05abbf635b884c3410b16ebde1d21dba6b2589764b4bb9` |
| Новый observed baseline | `fecfd5d2739189e0db7b00af1ce32b104340af0c0b6284bf6b26c33d29a0aa5a` |

Относительно successful migration V1 совпали **24/27 fields**. Изменились `host_policy_sha256` (`88afd674f14a5b1a4c8c243c93a666a47e5e06c484a1bb87844d39d1f174f5ab`), `firewall_identity_sha256` (`eeb32d04ec3cf2041ab52a14f056cb2ad23ec82d89e650cf93122bf276cd87fc`) и `runtime_identity_sha256` (`37ad6870267e65db38ca51f7ebb98d24ca451f16444743ede9d3d7360661f08c`). Payload не менялся. Сохранённый historical diff отдельно подтверждает 23 исходных fixed fields и четыре различия относительно фазы 3.4; он не является diff между V1 и V2.

Observation root содержит три файла, claim root — шесть. Runtime V3 package, runtime и consumption не созданы. Свежий сбор опроверг continuity предположение для baseline `f8c973…`; он не устанавливает причину изменения policy. Одних aggregate hashes недостаточно, чтобы отличить оставшуюся volatility от реального изменения правил. Baseline promotion/Prepare и закрытие фазы остаются **NO_GO** до отдельной проверки причины и нового exact candidate.

Независимый PS5 readback — **GO для failure evidence / NO_GO для continuity и runtime**: все четыре hashes, nonce/Cloud bindings, ACL и file sets совпали. Подтверждены 24 одинаковых fields относительно V1 и 23 historical pins; исходные receipt 3.4, V1 receipt/attempt не менялись. Agent/add и exact runner/wrapper — 0; новых receipt/consumption/runtime/package нет.

При source review найден отдельный normalization gap: regex удалял `# Completed by … on …`, но сохранял стандартный footer `# Completed on <ctime>`. Формат подтверждён [исходными fixtures Netfilter](https://git.netfilter.org/iptables/commit/tests/options-ipv4.rules?h=v1.4.19.1&id=6a74dc80fcdf48e2b149e92aee08f3445055ea3b). Он входит в IPv4 policy hash и затем в firewall/runtime hashes, поэтому смена времени способна менять ровно эту тройку. Проверка и точечное исправление выполняются offline; это не доказывает причину конкретных исторических live differences.

## Исправление стандартного completion footer

`scripts/p3-amnezia-peer-guard.py` теперь удаляет стандартный `# Completed on <ctime>` только при точном соответствии weekday/month/day/time/year. Malformed ctime-like строки с известным weekday отклоняются; произвольные и near-match policy comments сохраняются. Правила, chain-counter normalization и IPv6 behavior не менялись. Legacy `Generated/Completed by` regex остаётся permissive: эта отдельная существующая граница не исправлялась и не объявляется квалифицированной.

Payload SHA — `186a69d9cb4ed7ccbe42bff6810cb1da955332e77385a8f510aea9570c6bc25a`; test file SHA — `fae1bf3f0a3e871812cdec88919c37c540349c559bfc12fe10549b0f65c14021`. Два focused regression cases воспроизведены RED → GREEN. Один проверяет grammar/сохранение comments и чувствительность к реальному rule change; другой сравнивает все 27 полей полного collector при изменении только footer time. Все Python tests — **58 passed**. `ruff check .` и format-check двух затронутых Python files прошли. Global `ruff format --check .` сохранил известный отказ только в неизменённом historical markdown `2026-08-30-p3-task6a-prelive-guard.md:372` (59 files already formatted).

Независимый focused source review — **GO, 0 must-fix**. Новый payload требует нового exact observation candidate. Предлагаемый sampler выполняет два полных штатных snapshot в одном SSH с паузой минимум 1 s, прежними общими limits 30 s / 64 KiB и обязательным teardown. Он сохраняет обе sanitized observations до проверки полного равенства, проверяет historical 23 pins и новый payload, а затем допускает три HTTPS/assembly. Предыдущие hashes остаются provenance. Это готовящийся offline contract; новый live запуск и baseline acceptance не разрешены.

Полный `scripts/dev.ps1 -Command verify` после footer fix завершился с exit 0: Go/tests/build и repository gates прошли, gosec — 0 issues, govulncheck — no vulnerabilities, gitleaks — no leaks, governance/toolchain smokes — PASS. Sanitized log сохранён в `.p3-vps-run/p35-footer-final-verify.log`.

## Migration V3: candidate с двумя snapshot

Footer fix и failure checkpoint зафиксированы в `5029aaf904f5a48cd465e8424c7475c6e0496fdd`. Подготовлен новый immutable package `.p3-vps-run/p35-migration-candidate-v3` из пяти protected files. Candidate SHA — `4dd28f30be759619ff5792dffc1e46633453cbda4f0722982cecbf39bda48965`, challenge — `P35-MIGRATION-F99E84BB25DFF358`. Разрешение владельца на этот новый запуск ещё не получено.

| Artifact | SHA-256 |
| --- | --- |
| Prerequisite plan | `f99e84bb25dff3581d5f2370a1547a8b8c3b002a9b1fb265dcd57ac706547a82` |
| Agent plan | `234e79e27dad9fbbacd96f837eda00ebd6c1cabe937472b7a4a891ab5c74922b` |
| Runner V3 | `70f4552282b1fe9f422e3bec7346383247ffde10a6f714cbb1119e27e72bd023` |
| Builder V3 | `ccb976154ba385f16c3f10d62a5342f2e003b9acdb37e7e334d9676998d2279e` |
| Support V2 | `cc8058fdda5b069a57748ff0c1627e303badf4d15ebe2aaf066192734d36ec24` |
| Loader V2 | `1ae8fc1f6e5cfcab7687728c12a22ef8f3626804b467e804c1bec858c0127bcf` |
| Cloud recorder V3 | `e849855b4d068a47c2cbfc14dc8f4e849c10b21c316512b901d20c03eaff7b0e` |

Frame SHA — `35a1ab7d0f026a0956dfc69af25ae3be57cbdd6ad4e3a6b4d12ffc8a7da3d031`, argv template SHA — `174d7ee8b342abc3665c4607f4bad57162a4d659996934e5a0e2f50fb550d52b`. Payload — reviewed `186a69…`; public protocol и NUL argv framing не менялись. V1 receipt/attempt и failed V2 candidate/attempt закреплены как immutable provenance. Старые baseline hashes не используются как новое принятое состояние.

Scope будущего exact approval — **SSH1 с двумя полными read-only snapshots, HTTPS3, agent starts1 и обязательный teardown**. Loader ждёт 1.05 s между завершением первого snapshot и началом второго; monotonic gap проверяется как integer 1000..30000 ms. Общий native deadline остаётся 30 s, output cap — 64 KiB. Длительность двух реальных collector calls под этим пределом ещё не измерена; timeout прекращает batch. В каждом snapshot сохраняются три штатные IPv6 samples и invariants.

Runner сохраняет sanitized stability envelope до comparison gate. Оба стандартных observation envelopes проходят exact schema/nonce/payload/protocol/selfhash и historical 23 checks; перед первым HTTPS требуется совпадение всех 27 полей. Production Observe получает только второй согласованный стандартный snapshot. При ошибке второго snapshot loader failure/v2 сохраняет доступную первую observation; при общем native timeout сохраняется только доступный bounded process evidence. Любой отказ оставляет one-shot claim и блокирует assembly. Success claim содержит семь файлов, включая `stability-observation.json`; acceptance/runtime/helper flags остаются false.

Offline validation: Python loader success1/failure6/unequal1/invalid frames3; PS5/PS7 production Observe → Assemble → Validate success1 и pre-HTTPS rejects6, replay rejects7. Exact frame → native adapter → loader fixtures дали одинаковые identities между версиями. Полный native adapter не менялся; его ранее проверенные deadline/drain cases не повторялись. Correct frozen preflight прошёл в PS5/PS7, wrong confirmation отклонён с exit23, SSH0/HTTPS0/agent0. Новые live roots не созданы.

Runtime V4 подготовлен заранее и привязан к exact migration V3 SHA. Builder проверяет successful attempt, DPAPI packet pin, содержимое обоих snapshots, historical pins, truthful equality и совпадение receipt baseline со вторым snapshot. В prospective package копируется exact stability proof, всего семь файлов; executor проверяет его SHA перед Prepare. Actual runtime candidate будет создан только после successful свежего receipt. Его отдельный approval требует принятия наблюдаемого baseline и acknowledgement `ACCEPT-OBSERVED-BASELINE-HISTORICAL-POLICY-CAUSE-UNPROVEN`.

| Runtime template | SHA-256 |
| --- | --- |
| `phase35-runtime-build-candidate-v4.ps1` | `8a79b024daa42d3893542179c41c7325439230eb91f40d90cc461c89f83f93db` |
| `phase35-runtime-prepare-v4.ps1` | `1e5599edb16fbb37ceb593000cbf1d8b9d1fab8140a4568d45d43cdec65d58b6` |
| `phase35-runtime-template-fixtures-v4.ps1` | `2c6a03e31ffe865a631b03f269a177dc2f7cce70e3697d1a8600bdb3d45a22f3` |

Final-pin PS5/PS7 fixtures: по пять executor cases и шесть builder-proof cases — PASS. Проверены свежий preflight, wrong acknowledgement, receipt binding, stale receipt, copied-proof tamper, hash mismatch, truthful unequal pair, false equality summary, wrong nonce и receipt/sample mismatch. Реальные Prepare/consumption/agent/network calls — 0. Независимый static review migration/runtime templates — GO, 0 must-fix; final immutable readback выполняется отдельно.

Final immutable PS5 readback — **GO, 0 must-fix**. Reviewer проверил candidate `4dd28f…`, ACL/file set5, DPAPI input, byte-exact prerequisite/agent plans, все driver/local pins и реально emitted frame/argv/loader/protocol. Новый nonce и historical/V1/V2 provenance совпали. Runtime V4 содержит фактический migration pin; builder/executor/fixture hashes подтверждены. Новые observation/claim/Cloud/runtime/package roots отсутствуют, agent/add0. Разрешено запросить exact observation approval; future runtime readback, принятие baseline, Prepare и закрытие фазы остаются отдельными gates.

## Migration V3: native process failure до observation envelope

После exact owner approval candidate `4dd28f30be759619ff5792dffc1e46633453cbda4f0722982cecbf39bda48965` / `P35-MIGRATION-F99E84BB25DFF358` выполнен один раз. Fresh authenticated Cloud rules прочитаны `2026-09-05T17:15:11.832Z`, единственная Droplet association — `17:15:39.164Z`. Protected Cloud SHA — `45bcd30c80b6b5fe92ebdca5d4e2b4e1eef77e63750ce99ab5cb7341c0002f51`; правила и identities совпали. Candidate/runner/runtime template hashes до запуска оставались неизменными.

Key load завершился. Runner остановился на проверке native process result (line 79): **SSH1/HTTPS0/agent starts1**, native exit code **2**, stdout **0 bytes**, stderr **64 bytes**, timeout/overflow — false, UTF-8 valid. SSH-agent/add остановлены; operation tool exit1. Standard observation, stability envelope, remote-failure envelope, diff и prerequisite receipt отсутствуют. Raw stderr не сохранялся, поэтому по process audit причина пока не установлена.

| Evidence | SHA-256 |
| --- | --- |
| `p35-migration-claim-v3/attempt.json` | `df04a00c762c9eec40d3626f69efe126b1906ecdc5fd3111d44397613a25e189` |
| `ssh-process.json` | `a08331895b49c81882fac3efad21648972521d02857cc6d229b90b732839324c` |
| Stderr retained-prefix hash | `45ec0788fd363c41c13428404cf17b154443aa44a9f514987c4624df17c63693` |

Claim содержит четыре файла. One-shot budget использован, прямой replay запрещён. Runtime V4 package, Prepare и consumption не создавались. Продолжение требует отдельной диагностики transport, нового exact candidate и его approval; закрытие фазы остаётся NO_GO.

Пересмотр test context выявил ограничение предыдущей full-frame fixture: она проверяла frame/native stdin/loader, но запускала Python `--stdin-loader`, не передавая реальный `invocation.arguments` native child. Byte-exact вычисление argv само по себе не доказывает его передачу через Windows/MSYS и remote shell. Новый loader вырос с 5200 до 6474 bytes (base64 с 6936 до 8632 characters). Это повод проверить length/quoting path, а не доказательство конкретного лимита. Сам native adapter использует `UseShellExecute=false`; участие `cmd.exe` в нём не установлено.

Независимый PS5 review failure evidence — **GO для сохранённого отказа / NO_GO для receipt, baseline и runtime**. Проверены exact claim4/observation3 files и ACL, attempt/process schemas и hashes, nonce/Cloud binding, исходные driver/launcher pins и семь provenance hashes; все совпали. Новых envelopes, receipt/consumption/runtime нет, agent/add0.

Независимо восстановленная известная статическая ошибка Bash о незакрытой двойной кавычке дала точное совпадение всех 64 bytes по SHA `45ec0788…`. Восстановление выполнено из публичного текста diagnostic, без чтения raw stderr или identities. Это устанавливает error class `Bash unterminated double quote`, но само по себе не локализует потерю кавычки. Для проверки новой межсистемной причины использован отдельный профиль `cc_astra_high` по текущему project routing; reviewer — `cc_sol_review`. Новых разрешений на live-действия это не даёт.

## Локальная первопричина native transport

В отдельной fixture воспроизведено усечение quoted argument на границе native Windows parent → установленный MSYS child. Native Python receiver получает полные V1/V2 arguments, а реальный Git Bash/MSYS получает V1 command 7006 bytes целиком и только первые 8186 bytes V2 command длиной 8702 bytes. Теряется конечная двойная кавычка; shell exit2. Значение 8186 относится к проверенному UTF-8 окружению, не ко всем локалям/argv.

Approved SSH trust расшифрован только в памяти и сверен: `git_ssh_sha256` и фактический установленный Git SSH совпали — `ff3de79218b536e7460e14f470cefca2c2516f2320ee8a54114c015254f37cef`. Соседний MSYS DLL SHA — `2ea49553e4c03055dcf1c4a2bef54668081a07663fba283f4b34cf70f2157191`, version `3.6.9-b4195d69133078c498a1bf811c4fb0c61fc3c8af`. В [pinned MSYS glob.cc](https://github.com/git-for-windows/msys2-runtime/blob/b4195d69133078c498a1bf811c4fb0c61fc3c8af/winsup/cygwin/glob.cc#L95) используется fixed `MAXPATHLEN=8192`; [dcrt0.cc](https://github.com/git-for-windows/msys2-runtime/blob/b4195d69133078c498a1bf811c4fb0c61fc3c8af/winsup/cygwin/dcrt0.cc#L194) проводит quoted Windows arguments через `globify`. Это подтверждённый локальный transport defect и сильная причинная связь с live failure. Фактический argv внутри уже завершившегося SSH процесса не наблюдался.

PS5 и PS7 прошли по пять asserted cases: короткий V1 GREEN; длинный V2 и padded V2 RED с проверкой truncation; compact prototype GREEN с byte-exact restored loader; compact full-frame GREEN через реальный native/MSYS/shell/CLI bootstrap/frozen loader/production collector с mocked subprocess. Prototype command длиной 2580 bytes не усекался. Реальные SSH handshake, sudo и remote environment эта fixture не эмулирует. Диагностика и результаты сохранены в `.p3-vps-run/phase35-transport-diagnostic-v1.*`; Ruff/parser checks прошли, production source и прежние frozen scripts не изменены.

Исправление готовится как новый compact transport: заранее сжатые immutable loader bytes, отдельные compressed/decompressed pins и проверка длины remote argument не более 4096 ASCII bytes до claim/agent/network. Общие 30s/64KiB, две выборки, historical pins и отдельные approvals сохраняются; глобальные настройки MSYS не меняются.

Независимый causal-diagnostic review — **GO, 0 must-fix**. PS5/PS7 results совпали по всем пяти cases; проверены реальные binary hashes, import `msys-2.0.dll` в SSH/Bash, pinned source и границы mock subprocess. Прототип не объявлен production fix, а локальное воспроизведение не подменяет новые live postconditions. Full suite, fixtures и сеть reviewer повторно не запускал.

## Compact migration V4 и Runtime V5

Владелец поручил: «Закончи фазу без моего участия, все разрешения есть». Controller принимает оставшиеся exact authorizations внутри 3.5 после независимого technical review. Повторное участие владельца для hash/challenge не требуется. Freshness, one-shot claims, baseline comparison, retention, teardown и независимая приёмка сохраняются.

| Immutable artifact | SHA-256 |
| --- | --- |
| Migration V4 candidate | `5af42133ff00fefa0aeb507051f1cbe832075e52f210539935a2a69012e30165` |
| Support V3 | `39213702a56e1c41611bd6ba7ccca0043202d5f217ad10e604b0cc269505dee4` |
| Runner V4 | `ae04140cc3cb58d93a8a43685761a8855e848da4d78f9c1f9af6427bd6ff56af` |
| Candidate builder V4 | `9020fd4b2e673b15aced8f8dbb8eabf2aad28154b27cb29711aaeb676695109e` |
| Compressed-loader artifact | `9763a6f946d9030e0c3da32fb81767d1a4c90aa9c6c50a4ccd32f9773fdb0186` |
| Frozen restored loader | `1ae8fc1f6e5cfcab7687728c12a22ef8f3626804b467e804c1bec858c0127bcf` |
| Runtime candidate builder V5 | `a9821370ffc60d1780e9482bf91350c074f0fa6893455d5956ebe7bfe21641b4` |
| Runtime executor V5 | `eb219809895362c049983d0480cd491d11913cb5ce1b794072de46b0aaf6808b` |
| Runtime fixtures V5 | `1f38cef1183f9a023c6c00880f92f0854bc41cc1fc307cf7f76a49e5ac1e6376` |

Challenge — `P35-MIGRATION-382F9A4189150FA8`. В рамках делегированных полномочий controller разрешает этот exact candidate после свежего Cloud readback: SSH1, HTTPS3, agent1, без runtime/helper mutation внутри migration runner. Compact command имеет 2768 ASCII bytes. Сжатие выполнено заранее; local и remote bootstrap проверяют точные длины и hashes restored loader. Аргумент больше 4096 UTF-8 bytes отклоняется до claim/agent/network. MSYS DLL pin проверяется до запуска. Protocol/frame, два полных snapshots, gap, 30s/64KiB и historical23 не изменены.

PS5/PS7: реальные native/MSYS argv переданы byte-exact; compact bootstrap прошёл frozen loader и production collector с mocked subprocess. Проверки небезопасных argv, порчи artifact и конечных stderr classes прошли. Production Observe fixtures: success1 до Assemble/Validate, pre-HTTPS rejects6, replay rejects7. Correct frozen preflight PASS в обеих версиях; wrong challenge в последовательных проверках даёт ожидаемый exit23. Parser/Ruff PASS. Runtime V5: пять executor и шесть builder-proof cases PASS в PS5/PS7; actual migration pin закреплён.

Первоначальные параллельные PS5/PS7 fixture/readback вызвали sharing violation из-за `Read-P3BoundedStableBytes` с `FileShare.None`. Эти неуспешные outputs сохранены. После прекращения конкурирующих чтений последовательные проверки прошли без изменения source. Проверки protected/source files, reviewer readback и executors далее строго сериализованы.

Независимый Sol/high final immutable readback — **TECHNICAL GO, 0 must-fix**: ACL и exact five-file package, DPAPI input, prerequisite/agent plans, 29 argv, frame, compact/compressed/restored loader pins, MSYS DLL, drivers и десять provenance pins совпали. Runtime V5 hashes и фактический migration pin подтверждены. Reviewer прекратил все чтения перед передачей управления. Live roots, runtime package и runtime на этой границе отсутствуют; agent/add0. Это готовность кандидатов, не завершение live gates.

## Доступ к fresh Cloud evidence

После передачи управления CUA inventory содержит только In-app Browser, без прежнего Opera browser connection. Новый переход на Cloud Firewall привёл к DigitalOcean login; вход через предложенный существующий Google account вернул `An unknown error has occurred.`. Новые правила и association не наблюдались. Старые timestamps не изменялись, новый Cloud receipt не создан, Migration V4 не запускался и one-shot budget не использован. Наличие разрешения владельца не заменяет аутентифицированное наблюдение.

Повторный CUA inventory также показал только In-app Browser. Дополнительная локальная проверка доступного альтернативного интерфейса: `Get-Command doctl` не нашёл CLI; `DIGITALOCEAN_ACCESS_TOKEN` и `DIGITALOCEAN_TOKEN` в текущем процессе не заданы, callable DigitalOcean connector отсутствует. Проверялись наличие команды и переменных, без чтения/вывода credentials или поиска browser secret stores. Это граница доступных интерфейсов, а не утверждение об отсутствии любых credentials на машине.

Доступная независимая работа завершена: offline helper executors подготовлены и независимо приняты, как описано ниже. Закрытие фазы остаётся **NO_GO** до fresh prerequisite, Prepare и helper install/attestation/reconcile с независимым GO.

## Helper gates: подготовленные offline templates

Новые ignored `phase35-helper-*` готовят 6.4R-pre/P/post через существующие production owned actions. Author handoff — `.p3-vps-run/phase35-helper-handoff-v1.md`, SHA `6b27c04b0c4c12d97fb575500fd2d0d910da7c876b871bcee997ce9bd9f52cc0`. Полный manifest — `phase35-helper-review-manifest-v1.json`, SHA `0d789f6cd161a1477c6bb560098123e93f48e6597e901a61f05e8e8def14719e`; bundle SHA `de0b3c3e5d894afb451972bf0fed2f806bf44e28e71cb3b2c28c5f1800f116ef`. Production и frozen migration/runtime files не изменены.

Шаблоны привязывают каждый exact step plan к будущим фактическим Runtime V5 candidate/manifest, bundle, предыдущему egress, claim root и нужным install/Cloud/profile artifacts. Claims одноразовые, создаются исключительно; failure сохраняет историю. Три fresh HTTPS observations предшествуют архивации старого receipt. Exact старый receipt переносится native handle в protected claim без замены назначения, с проверкой file ID, volume, SHA и native final paths; новый receipt записывается штатным no-overwrite writer. Remote bootstrap сжат заранее и проверяет restored payload. SSH/SCP аргументы ограничены и проверены; helper install сохраняет pre-existing exact file, cleanup удаляет только staging. Post требует exact 27-field reconcile, свежие Cloud/local evidence и отсутствие профиля/selfhosted adapters. Agent teardown остаётся штатным и terminal при ошибке.

Author validation: **37 cases в PS5 и 37 в PS7 — PASS**: lifecycle17, native9, archive5, rollback3, binding3. Native receiver использует настоящий локальный Git Bash/MSYS, включая shell parsing и SCP argv; classify/install/cleanup команды имеют 2168/2167/2167 bytes, reconcile — 63. Fixture-only `MSYS2_ARG_CONV_EXCL=*` выключает преобразование Unix paths при передаче в локальный Python receiver; executor такого override не делает. Это проверка сериализации, не live SSH/SCP. Ruff check/format двух Python fixtures и parser всех новых PowerShell scripts прошли.

Исправлены и сохранены evidence двух author defects: недостающий terminal WCHAR в `FILE_RENAME_INFO` buffer и конфликт локальной `$Action` с ValidateSet dot-sourced production guard. Final archive дополнительно проверяет native source/destination paths. Полный repository suite не повторялся: production source неизменен, прежний full verify остаётся отдельным evidence.

Автор прекратил все команды и чтения; background fixtures0, agent/add0. Независимый Sol/high reviewer в эксклюзивном окне подтвердил **HELPER TEMPLATE TECHNICAL OFFLINE GO, 0 must-fix**. Independently recomputed bundle совпал; все 14 owned source/fixture files и 10 evidence files совпали с manifest. Проверены native rename offsets/terminator/file identity/final paths, SSH/SCP full argv и граница MSYS fixture, freshness, pre→install provenance, post/reconcile, одноразовые claims, teardown и ограничение rollback. Причин повторять успешные тесты не найдено. Reviewer прекратил все чтения; собственных edits/live/network/agent действий не выполнял.

Actual positive Runtime V5/DPAPI binding, live transport/helper operation и unattended key unlock — **NOT_CONFIRMED**. `BundleOnly` прошёл; actual `PlanOnly`/action не исполнялись, runtime отсутствует. Штатный key unlock может потребовать passphrase для encrypted key; новых секретов или способов хранения не добавлено. Live remove recovery executor не входит в эти три gate templates: удаление допустимо только после отдельной проверки exact owned-install receipt/remove plan. Fresh Cloud недоступен через подключённые браузеры. Эти gaps не закрываются fixture success или delegated authorization.

Точка продолжения после восстановления authenticated Cloud access: собрать новое фактическое Cloud observation, выполнить неиспользованный migration V4; последовательно проверить receipt, сформировать и проверить actual Runtime V5 candidate, выполнить Prepare/Validate в пределах freshness. Затем провести actual helper binding/readback, exact pre/install/post plans и live actions с новыми receipts, после чего получить независимую phase acceptance. Controller authorization уже делегировано; повторный запрос разрешений владельцу не требуется. При недоступном штатном key unlock live batch прекращается с сохранением точного состояния и обязательным teardown. Фазы 3.6/3.7 не начаты.

Final controller readback: новые migration V4 Cloud/observation/claim, Runtime V5 candidate/runtime и три helper action claims отсутствуют; SSH-agent/ssh-add — 0/0. `git diff --check` прошёл. Фаза 3.5 остаётся открыта с техническим блокером authenticated Cloud access; её закрытие не заявляется.

## Opera: доступ восстановлен, Migration V4 запущен

В следующем продолжении Opera успешно запущена через `@oai/sky` Computer Use. Computer Use остановил дальнейшую capture из-за невозможности уверенно определить URL; после указанного владельцем `https://www.digitalocean.com/` подключение Browser Use обнаружило Opera и открыло сайт. Переход `Log in` использовал существующую авторизованную сессию, без ввода credentials. Никаких изменений Cloud Firewall не выполнялось.

Fresh rules прочитаны `2026-09-05T23:13:07.764Z`, association — `23:13:25.185Z`. Firewall/Droplet/management hashes совпали с pins; inbound TCP22 management IPv4 и UDP38556 all IPv4, три outbound rows с IPv4/IPv6 совпали. Direct/tag associations указывают на одну уникальную Droplet. Новый protected Cloud SHA — `225192b683cedcefdff3180bcb58ea7de7583acf1682c32c41c2f103e0ae68e7`. Существующие historical timestamps не менялись.

Controller исполнил exact V4 candidate `5af42133ff00fefa0aeb507051f1cbe832075e52f210539935a2a69012e30165` / `P35-MIGRATION-382F9A4189150FA8` со свежим Cloud SHA. Открыт штатный key-unlock wrapper; наблюдались agent1/add1/SSH0. `ssh-add` ожидает ввод; владельцу предложено ввести passphrase только в защищённом окне и сообщить результат без секрета. Это техническая зависимость от ключа, не новый permission gate. Итог batch ещё не получен; дальнейшее действие зависит от фактической разблокировки и freshness.

Разблокировка не завершилась. Наличие окна `Home Gateway Phase 3.5*` подтверждено через process metadata: его отображал Windows Terminal. После истечения freshness controller остановил только exact owned `ssh-add`, сверив PID, creation time, parent wrapper/runner и удерживая process handle. Wrapper продолжал ожидание, поэтому так же проверен и остановлен только этот owned wrapper. Windows Terminal и unrelated процессы не останавливались. В tool output сохранена краткая native agent diagnostic `Connection reset by peer` после отмены add; она не содержит identities.

Штатный runner `finally` завершил agent teardown. Итог: tool exit1, `diagnostic_failed_closed`, stage `agent_and_diagnostic`, `RuntimeException`, error SHA `3cecd83f2d364a6e1d3e0f15ea814ede737826931f4e3c6c4620a02a83db137c`, line326, **SSH0/HTTPS0/agent starts1, agent/add0**. `live_mutation_performed=false`; native SSH result и server/stability/diff envelopes отсутствуют.

Attempt SHA — `6377d16b8d50df2298d6478e485e95a74cc4280e7111074b4615e6398a396ca5`. Claim V4 содержит marker, `claim.json`, `attempt.json`; observation V4 — prerequisite marker, `agent-manifest.json`, `manifest.json`. Prerequisite receipt, runtime V5 candidate/runtime и helper action claims отсутствуют. Одноразовый claim использован; V4 напрямую не повторять. Последующий запуск требует нового candidate и обновлённых runtime/helper bindings, свежего Cloud observation и доступной штатной разблокировки ключа. Повторное owner permission approval не требуется. Независимая проверка сохранённого отказа запрошена; phase/runtime остаются NO_GO.

Независимый Sol/high readback завершён: **failure-evidence GO, 0 must-fix; runtime/phase NO_GO**. Подтверждены exact claim3/observation3 regular/non-reparse files, protected ACL/owner/markers, candidate/Cloud/nonce/budget bindings, canonical manifest/SSH trust и attempt SHA. Observation/receipt/Prepare/runtime отсутствуют. Current process readback: agent/add0, exact owned add/wrapper/runner PIDs отсутствуют; agent receipt не остался. Одноразовый claim сохранён, повтор V4 запрещён. Controller cancellation evidence и независимый нулевой process readback подтверждают ограниченный teardown; отсутствие key unlock не трактуется как успех. Reviewer прекратил все чтения, edits/network/agent действий не выполнял.
