# Phase 3.5 runtime preparation

Фаза 3.5 открыта: offline runtime correction прошла verification и независимый review, но runtime/helper gates ещё не выполнены. Receipt 3.4 сохранён и истёк. Read-only refresh остановился на baseline drift; последняя policy diagnostic V3 выполнила SSH1/HTTPS0 и завершилась без policy receipt. По поручению владельца продолжить и закрыть фазу готовится исправление IPv4 counter normalization и отдельный migration prerequisite candidate; baseline/runtime остаются NO_GO.

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
