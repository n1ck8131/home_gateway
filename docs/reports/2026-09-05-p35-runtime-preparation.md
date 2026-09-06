# Phase 3.5 runtime preparation

**Фаза 3.5 закрыта 2026-09-06: FINAL ACCEPTANCE GO, 0 Critical / 0 Important.** Приняты protected runtime (6.4L), helper pre/install (6.4R-pre/6.4P), Final Observe V4 и исправленный post-install reconcile (6.4R-post). Все 24 поля финального receipt согласованы с accepted baseline; helper exact/root:root0755, container running без restart, leftovers0. Временные receipts архивированы, agent/add/env0, защищённый профиль отсутствует. VPN, Cisco, adapters, routes, DNS, firewall и Docker configuration не менялись. Фазы 3.6/3.7 не начаты.

## Итоговая приёмка

Controller выполнил exact PostPlan/Post после static GO и независимого actual Observe GO. Финальный reviewer проверил result вместе с attempt, request binding, SSH evidence, cleanup и архивами; один успешный процесс не использовался как замена приёмке.

| Evidence | SHA-256 |
| --- | --- |
| Accepted runtime manifest | `1b4bf3826c7056d9c166d40b135bdb99ab13783625d503e3e01802566e9f2d02` |
| Accepted server baseline | `716e53095d7cb666dc3c3dca93a9265656e64c8c77268e8cbd3c5deea2d84718` |
| Installed helper receipt | `0ac52e24de92c81224f5a047c4dd364297c31894d2cd089389bd3c3acb4ae542` |
| Final Observe V4 result | `7d943a02d065eb53951e8d73d19b1669ad43188023147c925adaf5d3d78feae7` |
| Final POST V4 result | `0bfb3b8ff0deff4c1d469fa88081401a75cfecc25dc73673883089da71165dbd` |
| Final POST attempt | `37944109a71d21251775808e30ae22a3ade61641efe5bad9023f91c0c38f1046` |
| Original/corrected request binding | `7fde89de4cb686acb5503be805c3977d43ccab75131f63344ae18da822d89464` |
| Final SSH evidence | `2f0ea71c62898918c53b32f88a1f64900c0bb47638dfb95a5f37aafa722fe4e6` |
| Ephemeral cleanup | `10658328a5d7fc453d992b25606a5e868d822e60327b35428fd22655bf32929f` |
| Archived Cloud receipt | `debc72c0ed15f208efd6259b111aa2e9aa84d7c5218dcf5befe5b5821547ad08` |
| Archived local projection | `db91d3e0960ab8fafc7f50f2e7e4368b58cae3ee59473c140cb2aa80c8b0a97d` |
| Final runtime egress | `df11af23ec85778c93e8ae6e2da18aa6f5ed26b9e28a53d8cdd2e4266f2a6302` |

Protected POST claim содержит 12 exact files. Runtime содержит только пять файлов: ownership marker, manifest, DPAPI trust, accepted install receipt и egress; Cloud/local/agent receipts отсутствуют. SSHexit0, stderr0, UTF8valid, timeout/overflowfalse; SSH1/HTTPS3/agent1/SCP0. Cleanup completed, exact-owned archives подтверждены, foreign deletion=false. Original request и Cloud validation сохранены; corrected remote request меняет только `expected_firewall_identity_sha256` на independently accepted HOST SHA. Source TTL300 проверен перед действием, timestamps не продлевались.

Verification включает ранее принятый полный repository `verify` и 248 Pester tests, а также focused native/contract/cleanup checks диагностического и V4 packages в PowerShell 5.1/7. Новых production source changes после принятого checkpoint нет; успешные unchanged suites не повторялись. Исторический inherited formatting gap ниже не выдаётся за PASS. Операционные artifacts и consumed claims остаются под restrictive ACL в ignored `.p3-vps-run/`; secrets и profiles в Git не добавлены.

Границы evidence сохраняются: provider текущего non-target tunnel UNKNOWN, loaded-module identity UNPROVEN, историческая причина policy drift и historical third-party identity не доказаны; исчерпывающее знание DNS/NAT aliases и target client reachability не заявляется. Эти ограничения не блокируют принятую фазу 3.5, но не подтверждают готовность Management/Guest, profile export или activation. Future live actions требуют собственных fresh inputs и exact reviewed candidates; текущие consumed claims не разрешают replay.

## Final V3–V4 evidence, 2026-09-06

Final V3 static package получил independent GO, 0 must-fix: manifest `da51321156bb117e3c13782f69b83ecd21c5b4b34755b409447a81bc18ecd3b4` (36 files), package identity `2fae1c42051daceacd002ca1cd0d9f470359d294f8dcbff2294a2dff05fe7dd3`, runner `9afdf206930ba16f2eefb1e0228e382c52adfe7abde0422f4e8d64531b550d90`. Fixed command SHA `7e7d8573c79c369c4b906d725d6145455e19442df7317d1a7c28cc6f3691a046` привязан к package/PostPlan; installed helper bytes не менялись. PS5/PS7 full native Reconcile: по 5 focused cases PASS, включая actual frozen request builder, native factory, MSYS и explicit Python с synthetic CRLF file. Parser6, PlanOnly, BundleOnly и provenance readback PASS. Эти fixtures не доказывают actual server reconcile.

Первое Cloud V3 observation истекло перед Observe; runner остановился до создания claim и SSH. Старые files/timestamps сохранены. Independent GO разрешил отдельный CreateNew writer V3b, SHA `65a2ed9a278ca904bd5cfe15e1402ab57653e76045640670a55e3048d90174ca`; единственное отличие от V3 writer: новый input root. Unchanged V3 package использует новые exact input hashes.

Fresh Opera UI: Overview `16:10:25.659Z`, Reserved IP disabled `16:10:49.263Z`, Firewall Rules `16:11:00.533Z`, association `16:11:18.611Z`. Resource/address/management pins совпали; unique Droplet1, known additional mappings0, DNS/NAT exhaustiveness не заявляется. Firewall V8 SHA `104b320dc5f5b2b3775e37864d7685d9edbdf2c70bdf2b6a59c34e8776332708`; Cloud V3b SHA `27b6ec9055ca3185dffa0153dc6c9d0b3822d8413a2211a0ee4b80b9a3b78e9e`. TTL300 отсчитывается от самого раннего source clock.

Actual Observe V3: plan `57e934014da9936f6403688c52eeab2a833d14be4c9a081da23c4950a81c82b6`, result `47d4cbd6cb56431a4fcd32ca723c24bb910c2ab54edcb1ad73032ab16712a55e`, completed, SSH1/HTTPS3/agent1/SCP0. Target12 commands, snapshots2 equal, endpoints2/image aggregate valid; SSHexit0/stderr0. Fresh UAPI GET2/peer1/two equal snapshots, nonce `b9a804245e0845d49c864369ebfc5fe9`, held process/service/pipe/DACL bindings valid, loaded_module UNPROVEN. Native inventory21/fallback3, raw selfhosted1/Cisco1. Compatibility `22509bf36c2069bb5af15275446b231466ba51c763f9957526f9190a189c0276`, wire `1c23fc67e5c1bcddd8e022138c2e0d76aa26552503f4388baf12e885ee12d36f`; key and both endpoints differ, current existing_non_target/provider UNKNOWN. Actual Observe/PostPlan independent GO, 0 findings; agent/env0.

Controller повторно получил exact PostPlan `6dfa1cd24961e2cae4eb23f5a83eaf7e7b7b2ba1ee497c0d393c71a5bee29f9c` / `P35-FINAL-POST-6DFA1CD24961E2CA`, затем исполнил POST с встроенными freshness rechecks. SSH exit1, stdout0, stderr28 bytes, UTF8valid, timeout/overflowfalse; stderr SHA `47adfc471ed32df0e050cd7f3c546bf59a52119cc0f613bcb01028a53dae4e4b`. Attempt final_post_failed, result отсутствует; claim V3 consumed. Actual cleanup completed: оба exact receipts архивированы, runtime cloud/local/agent paths отсутствуют, agent/add/env0, foreign deletion=false. Archives: Cloud `bf25f1d1147f91f1749c42290d23b4d3432e77625002726fd9508110e8163850`, local `1c23fc67e5c1bcddd8e022138c2e0d76aa26552503f4388baf12e885ee12d36f`; binding `2d0407bd1517f662fbed0e07f52fd7f3a466eb6a85e4a6e4a7a7c9606abc0da8`. Independent failure/cleanup review GO, 0 must-fix; это acceptance сохранённого evidence, POST/phase пока NO_GO. Причина нового отказа проверяется offline; replay запрещён.

Actual stderr28 точно соответствует общему `{"error":"P3_GUARD_FAILED"}` с newline. Offline counterexample выявил mapping defect: PowerShell выбирает Cloud Firewall SHA для `request.expected_firewall_identity_sha256`, а Python сравнивает это поле с hash host firewall. Source-selected validation принимает исходный 20-field request, но отклоняет его против exact accepted baseline с `firewall identity differs`; замена только этого request field на `accepted_server_baseline.firewall_identity_sha256` проходит. Cloud receipt должен продолжать проверяться по Cloud SHA, поэтому глобальная подмена `ExpectedCloudFirewallSHA256` недопустима. Generic actual error не доказывает, что collector дошёл до этого predicate. Перед новым POST готовится отдельная one-shot read-only диагностика request/collector/baseline с finite error enums, без raw exceptions/configs и без изменения helper.

Diagnostic V1 подготовлен offline: manifest `1a7c9889c2e80e2ccf11535aaa1686c0168c5c3ec4e1f80c7b079b0c9a6cf375` (15 new files плюс immutable refs), package `e90c9c763d99b47f2ad861ce713aabbed9dac6fa4a6e56521a68bac41970fa45`, runner `960c9b8488f184a70fdb3b6b7e13d486ab89a058cdccbc613e2d7255a22d6d64`. Exact installed helper читается и проверяется до загрузки; один collector snapshot используется для original Cloud и corrected accepted HOST request. Бюджеты SSH1/HTTPS3/agent1, native58s/collector40s/output64KiB; runtime Cloud/local projections не публикуются. Python7 и PS5/PS7 native4/response8/mocked lifecycle4, parser4, Ruff3 PASS. Actual Linux loader/collector ещё не выполнялись; claim отсутствует. Пакет передан на independent review, свежие Cloud inputs собираются после GO.

Diagnostic V1 получил independent technical GO, 0 must-fix. Fresh Firewall V9: rules `16:40:11.484Z`, association `16:40:25.660Z`, SHA `49d3dc68da4b79dc5ca198a693040ea42b25f92c6f0b6d93f29dd27c494827be`. Controller проверил PlanOnly `1a8636a67ac5bc23bc0bc3cc791c00f1d238af758a99d5acdb3e256414fe3243` / `P35-RECONCILE-DIAGNOSTIC-1A8636A67AC5BC23` и исполнил exact Execute. Actual exit0, diagnostic_completed, result `489786e66f2a71efec2dee18f3bb2b85c49cedd1877d9c72ec4fab3bed9b7f2d`, SSH1/HTTPS3/agent1/SCP0, teardown confirmed, post=false. Actual cause-evidence передано на отдельное readback review; успешный диагностический процесс сам по себе не закрывает POST.

Actual diagnostic cause-evidence получил independent GO, 0 must-fix. На одном snapshot выполнены все causal criteria: request_valid/collector_completed/current_baseline_matches_accepted/current_host_matches_accepted_host=true, command_count15, current_host_matches_cloud=false; original validation отклонена с finite ValueError/firewall_identity, corrected accepted-host validation=true. Installed helper exact, mutation/post=false. Attempt `e97dc2676a69ab161470fa012fc29cb5b4b0898a298951e0884a3947fff18a2f`, result наблюдён в `16:41:30Z`, SSHexit0/stderr0/UTF8valid/timeoutfalse/overflowfalse; protected ACL, budgets и teardown прошли, agent/add/env0. Current egress SHA `3d2cbe025082008f9c508bef85d777ad3a50519ea6d399cf10ea3d5363fb80d9`. Это доказывает mapping defect на current accepted state; ретроспективный earliest predicate generic POST V3 не заявляется. Следующий V4 candidate отдельно связывает accepted host SHA для remote request/validation, сохраняя accepted Cloud SHA для Cloud receipt; новый POST требует static review и новых fresh observations.

Final V4 подготовлен для отдельного review: manifest `f91f2d213591c56fa7fd53c53099de8945e2060e2ddb1c47bb327a00a9e7dc8f` (55 artifacts), package identity `b1070f976714f8e94de85f187aaaa913b12375dfcba9aac84cc3a277effab06b`, package file `e4dccd161b563c5b6d584f993d432f412fb95dbe005963dd4a5a43ded35585c8`. Runner `53d85df1a318b12867c27651867fbbb823193bbd0fb0d50c0277499b1edb568c`, reconcile supplement `db18469c607e10fca3b30ac2cf0e98122683aad7da31e6912660d8bad9bd2776`; fresh UAPI nonce `af10d6d5ca1e4013a956b5bbe377c885`. Accepted HOST SHA отдельно включён в package/PostPlan. Original request восстанавливается из protected Context; только remote firewall field меняется, original/corrected hashes сохраняются в protected evidence. Cloud preflight и frozen 24-field receipt validator не меняются.

V4 PS5/PS7: actual frozen Python `run_reconcile`/baseline/receipt functions на accepted snapshot и actual PowerShell bounded JSON SSH/receipt validation прошли full native path. Четыре negatives проверяют wrong original field, wrong accepted HOST, Cloud receipt mismatch и receipt baseline drift. Отдельный actual filesystem/native archive case подтвердил cleanup при correction failure до SSH в обеих версиях. Parser6/PlanOnly/BundleOnly/provenance/current-egress/Ruff PASS; unchanged nine cleanup cases и full suites не повторялись. V2 ephemeral functions byte-identical, V3 dependencies unchanged, actual SSH/agent/UAPI0, новые roots отсутствуют. Это static evidence, actual V4 POST ещё не выполнен.

Final V4 static review: GO, 0 must-fix. Fresh authenticated Opera observations: Overview `16:55:16.759Z`, Reserved IP disabled `16:55:23.680Z`, Rules `16:55:26.988Z`, association `16:55:30.132Z`; resource/address/management pins совпали. Новые exact protected inputs: Firewall V10 `a8fdf9d38fcc38f35f01122fbcb1e15f7e44aaabd06244a6ba356c2132e3a4ca`, Cloud V4 `e2026cde1aaf00c32ccde95d08fb7d9b991959c3002328b66e6d726cee047a15`.

Actual Observe V4 plan `a40b6175fa4ae219200ea3f2495ff77c9ae8f72a4d975c5784537803f533cf2b` / `P35-FINAL-OBSERVE-A40B6175FA4AE219` выполнен: result `7d943a02d065eb53951e8d73d19b1669ad43188023147c925adaf5d3d78feae7`, completed, SSH1/HTTPS3/agent1/SCP0. Independent actual GO0 подтвердил target2 equal/12 commands/image/endpoints2, UAPI GET2/equal projections, native21/fallback3, exact existing_non_target/providerUNKNOWN attribution и teardown. Compatibility `2582175318e4357910222927a860a7ce1568f6570626efd03aa61f31b37db222`; wire `db91d3e0960ab8fafc7f50f2e7e4368b58cae3ee59473c140cb2aa80c8b0a97d`. Самый ранний source timestamp сохранён, TTL300 не продлевался.

Controller повторно получил и сверил exact PostPlan `f52832df1c9f08b67d3d701446c81a3fa8106868b6b4a0eff9dc588667f2eeb6` / `P35-FINAL-POST-F52832DF1C9F08B6` с independently reviewed plan. Actual Post V4 завершился exit0, `final_post_completed`, result `0bfb3b8ff0deff4c1d469fa88081401a75cfecc25dc73673883089da71165dbd`, SSH1/HTTPS3/agent1/SCP0. Built-in checks повторили freshness, native inventory, Cloud receipt и accepted HOST request binding перед SSH. Result/attempt/cleanup/archives переданы на итоговую независимую приёмку; один result не заменяет её.

## Предыдущие checkpoints

Фаза 3.5 открыта: runtime и helper приняты, итоговый POST требует доказанного уточнения local baseline. Migration V7 и runtime Prepare/Validate прошли с независимым GO; загрузка ключа из разрешённого локального `.env` работает без вывода секрета. Helper V4 установлен и независимо принят: exact payload, root:root0755, leftovers0 и agent/add0. POSTV4 остановился до SSH на пустых описаниях адаптеров; native resolution сохранил все 21 записи и выявил один generic WireGuard-интерфейс.

Final Observe V2 фактически выполнен и независимо принят: server public key/оба Cloud endpoints отличаются от свежей UAPI-проекции; native inventory сохраняет21 записи, affected adapter доказан как `current existing_non_target`. Provider остаётся UNKNOWN, loaded-module identity UNPROVEN. POST V2 достиг сервера, но завершился exit127 из-за CRLF shebang; причина установлена exact stderr hash reconstruction. Временный агент завершён, оба ephemeral receipts архивированы, runtime paths отсутствуют; failure/cleanup evidence независимо принято. Готовится новый explicit-Python invocation candidate без изменения установленного helper. Runtime/helper/claims сохранены; успешный reconcile и phase acceptance пока NO_GO. Все разрешения внутри фазы делегированы controller.

This report serves the P3 controller and independent reviewer. Its single purpose is to record preparation evidence against the [phase execution plan](../superpowers/plans/2026-09-05-p35-runtime-helper-lifecycle.md). The current verdict above distinguishes accepted runtime/helper evidence from the still-open final phase acceptance.

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

## Продолжение 2026-09-06: загрузка ключа без ручного ввода

Migration V5 candidate `5eb446eca04c7e86e3ea5e1dbb1cb26c193e31d8b5249e6ea60644e66e6fbf15` и Runtime templates V6 получили independent technical GO с нулём must-fix. Проверены DPAPI/plans, immutable pins, V4 failure provenance и совместимость ещё не созданных runtime paths V5 с Helper V1. Live V5 не запускался.

Владелец затем сообщил о локальном `.env` с переменной `PASSPHRASE` для продолжения без ручного ввода. Controller подтвердил только metadata: файл существует, Git его не отслеживает, reparse attribute отсутствует, Allow rules для Everyone/AuthUsers/BuiltinUsers/Guests отсутствуют. Содержимое, значение и hash секрета не выводились. Файл не удалён и не скопирован в evidence.

Изменение key-unlock contract готовится отдельно от frozen V5/V6: bounded askpass читает secret как данные и передаёт его только через pipe в pinned `ssh-add`; argv, журналы и evidence не должны содержать passphrase. Controller разрешил один isolated synthetic agent для проверки полного askpass пути с тестовым ключом, без actual `.env`, рабочего ключа и сети, с обязательным exact owned-process teardown. Это локальная проверка, не live prerequisite. Actual key load, fresh migration, Prepare и helper gates пока не подтверждены; phase acceptance остаётся NO_GO.

Новый offline комплект сформирован: Migration V6 candidate `c937a94f7e93ff4242a8d90176687f655051aceb2174b6dd13920ad5791b29e9`, Runtime templates V7 с ещё не использованными runtime paths V5 и Helper V2 bundle `db9ec8cd1318fff418f19c82ee855551bdb5411ba8800c0c6c4fe3df6a32f5ba`. Handoff `phase35-env-unlock-v1-handoff.md` SHA `c7a3b0399ace90af03db2fb17a3e80381641572d9f4d2136e8a49c6aa2bd8f8f`; review manifest SHA `e630eb725a626b7d42009bb5adb14e72e5e35c81d66771d25c6142c5f5479889`.

Final synthetic unlock evidence: 18 checks PASS, включая реальный Git `ssh-add` с тестовым encrypted RSA PEM в PS5/PS7 и отказ при неверной тестовой passphrase; final agent/add0. Parser, ACL/locked-source, standalone refusal и consumed-claim проверки входят в эти 18. Migration correct/wrong preflight дали ожидаемые exit0/23 в PS5/PS7; Runtime V7 — 11 cases в каждой версии; Helper V2 binding — 3 cases в каждой; parser/Ruff PASS. Production и прежний helper transport не изменены, повтор полного suite не выполнялся. Development failures сохранены: недоступный bcrypt обойдён сменой только synthetic key format без установки dependency, fixture UTC/local assertion исправлен, PS5 reflection lock устранён отдельной synthetic assembly copy. Автор остановил все команды и чтения; комплект передан на независимый source/candidate review. Actual `.env`/key и live server не использовались.

Independent review нашёл один must-fix до live: успешный `ssh-add` не требовал фактического `consumed` marker от askpass. Незашифрованный ключ мог дать exit0 без обязательной проверки `.env` и однократной передачи. Controller принял finding; автор готовит новую версию с проверкой exact regular/non-reparse one-byte marker и synthetic unencrypted/no-askpass negative. Текущий комплект не получил final GO и не запускался. Frozen artifacts сохраняются; дополнительные owner approvals не требуются.

Remediation handoff `phase35-env-unlock-v2-handoff.md` SHA `923edc8115c91d8efec58a818c00e46074c9a34dab1631e58eaf7b033e0e235a` и manifest SHA `30cfd947e67f5d6422ea5aa4d2e2f6b9504911309b01156690db3cb2276a3c78` переданы на повторный review. Migration V7 candidate `7afe789b61703a3ae55c47cec773a908645ed6a167ad5d9e2c7d1c809fd64c0c`; Runtime V8 сохраняет неиспользованные runtime paths V5; Helper V3 bundle `2af80680e905567f670c2cc3a0d00f3e37e2a565cffb08cfcef7a65ba08505bf`. Семь targeted RED/GREEN cases подтвердили прежний пропуск, новый отказ для unencrypted/no-askpass и сохранение encrypted success/wrong-pass failure с teardown в PS5/PS7. Migration0/23, Runtime11 и Helper3 в каждой PowerShell прошли; Git metadata/parser/Ruff PASS. Marker читается принятым `Read-P3BoundedStableBytes` под защищённым claim root; reviewer отдельно подтвердил соответствие project trust model. Native no-follow flag не заявляется, теоретическая same-owner path-swap граница primitive сохраняется. Live ещё не запускался.

Final independent technical GO: 0 must-fix, все 17 source pins и 13 evidence pins совпали; DPAPI/plans/provenance/ACL и неиспользованные roots подтверждены. После STOP ALL READS controller собрал fresh Cloud rules `2026-09-06T10:59:43.239Z` и association `10:59:56.004Z`, совпавшие с expected hashes/rule union/единственной Droplet. Protected Cloud SHA `3ab111ed5be5a7bcfc8fce69e7612fac429254dddc10efe86318c0898b1ebc9d`.

Actual Migration V7 завершилась с exit0: `migration_observed_validated_not_accepted`, SSH1/HTTPS3/agent1, `agent_teardown_verified=true`, `live_mutation_performed=false`, `raw_identity_exposed=false`. Reviewed askpass загрузил рабочий ключ из разрешённого `.env`; secret не выводился. Receipt SHA `fd012a8d0d77740069fac8f25fe1763639089ea08efb9b993172d9c09c00ca6d`; attempt `1a01bad1b9931cb29b73a100fbfd7fda6c5b2192cbc9cf2e1de66aa19c0b44f1`; baseline `716e53095d7cb666dc3c3dca93a9265656e64c8c77268e8cbd3c5deea2d84718`; stability `715a1dc15a73f0bc1d9a906c39768edd51e23582e304c7a271e9be00da19691f`. Fresh receipt передан на независимую проверку перед runtime assembly/Prepare; baseline acceptance/runtime/helper пока false.

Live receipt получил independent GO: 27 fields в обеих выборках совпали, gap1050ms, historical23 сохранены, изменены ровно четыре разрешённых observed hash-поля. Process exit0/UTF8 valid/stderr empty/no timeout или overflow, stdout hash совпадает со stability; exact ACL/provenance и agent/add0 подтверждены. Runtime V5 package, созданный builder V8, также получил independent GO: 7 files, candidate `8c0e20ecf3a5118cfb3026b57b6b70639dbf9ace6e3cf51068beb7b524b63900`, manifest `1b4bf3826c7056d9c166d40b135bdb99ab13783625d503e3e01802566e9f2d02`, CurrentUser DPAPI и планы связаны с fresh receipt/baseline. Controller принял baseline под делегированными полномочиями с `ACCEPT-OBSERVED-BASELINE-HISTORICAL-POLICY-CAUSE-UNPROVEN`; историческая причина четырёх изменений не считается доказанной.

`Prepare/Validate` V8 завершился до expiry с exit0 и `runtime_prepared_validated`: runtime3files, `prerequisite_consumed=true`, accepted baseline `716e5309…`, agent/SSH/HTTPS0. Cleanup plan SHA `5e9c9ded31b9fbf244a69c7ffeeea83d8181d313c0489291506e49123d03b2e7` сохранён, cleanup не исполнялся. Actual Helper V3 `PlanOnly pre` прошёл: plan `b8d9bfd011f9377812ffc85662c513a47769ef9f854cd0748685c0cd1baa89d7`, fresh Cloud `3ab111ed…`, previous egress/install artifacts0, budgets SSH1/HTTPS3/SCP0/agent1. Actual runtime readback и этот pre plan переданы на независимую проверку; live helper ещё не выполнялся.

Independent runtime/pre-plan GO получен. Helper V3 pre action прошёл: SSH1/HTTPS3/SCP0/agent1; result `0c9a94f1ab4236dec04a1cc9cd7f24b4fbae2a455813b43ae47f42dc08614f07` сообщает `absent` и leftovers0, remote install plan `5865290f8139e66e24e4e71d6aa7376041713fbc93e3f960efbfbf0d54d39431`. Reviewer подтвердил protected claim/files, native exit0/stderr empty и agent/add0. Новое Cloud observation `a25e515e665bc13eb3e1487d439f2691643ad82ffe4a168694362849d91c8312` основано на actual rules `11:10:41.636Z` / association `11:10:54.060Z`. Exact install plan `d59fa5c0a64c34dc7409c5dd93222abb40e2dfc4562bac5b66cb8da2a0430ef0` получил independent GO перед записью helper.

Helper V3 install action остановился с exit1: `helper_gate_failed_closed`, error SHA `fd1ebfca7f5777b5a3e8bf95c986b371ffa276494b9920334b26f890b8485c89`, counts SSH3/SCP1/HTTPS3/agent1. Classify SSH1 exit0, SCP exit0; install SSH2 exit1 со stderr260/SHA `21c625f57e9ec5f356887285fda116dc3dcce75abf6369c8491828289f33317b`; cleanup SSH3 exit0. Classify/cleanup stdout206 имеют одинаковый hash `9975dfdae7774a050e0ddc72b678077d202e1cc68ef85f9b8cce5fd7af4c9351`; raw stderr не сохранялся и не выводился. Это подтверждённый отказ install-команды, не установленная первопричина. Root process readback agent/add0. Claim9files и prior egress archive сохранены; result/install receipt отсутствуют, runtime содержит marker/manifest/trust/новый egress. Повтор consumed install claim запрещён. Ближайшая разрешённая работа — bounded diagnosis и новый exact recovery candidate при необходимости; phase closure остаётся NO_GO.

Independent failure-evidence GO подтвердил эти 9 protected files и успешный cleanup: target absent, leftovers0, agent/add0. Полный attempt SHA `6d9778d0ce06d7c3716329fe2553252b75bbaf6cde1757ed386389e45149be44`; original egress `7a1bfab8…` сохранён в archive, current egress `a94aeee880619634fa00bd76ecc6ea738ebdf602740ee3a63ece13602e3f1919`. Source diagnosis выявил отсутствие создания parent перед staging open. Exact frozen adapter локально отказал при отсутствующем synthetic parent и прошёл при существующем; Linux traceback этого случая согласуется с 260 bytes, но original stderr SHA не восстановлен из-за несохранённого случайного token. Историческая live-причина остаётся гипотезой.

## Helper V4: parent-bound recovery и Linux qualification

Новый ignored комплект передан на independent review: handoff `phase35-helper-v4-handoff.md` SHA `42f63f228972a02dafbf8f3521daa1a886dcb46f9b00b29879511d12ec0e8d5e`, manifest29files SHA `b45b6800dd4db9050b3115975cbfccb881cf8eda3ac55278175d425174ff6b6e`, bundle `99aff72563da24176a12a71bbab4c3a5f9ebfd0dc062be523e3f39e85746c6c2`. Production, runtime и frozen V3 bundle сохранены. Adapter V2 SHA `10b4cd12d69c08f645dfefbd7089e89567ca21b820aa5bca79f279c68ed3d145` проверяет ancestors/parent через held no-follow directory handles, создаёт только отсутствующий leaf `/usr/local/libexec`, требует root:root0755 и связывает PRE/install с точным наблюдённым parent state. При ошибке parent удаляется только при собственном создании, прежней identity и пустом каталоге; существующий/изменившийся/непустой parent сохраняется. Успешная установка сохраняет parent.

Outer parent envelopes сохраняют canonical inner remote receipts. Compressed adapter передаётся как pinned bounded stdin с EOF; encoded/compressed/source lengths и SHA проверяются до exec, распаковка ограничена и допускает один завершённый zlib stream. Команды classify/install/cleanup — 761/760/760 bytes, reconcile63. Parent freshness600s и egress120s проверяются отдельно; source observation timestamps не меняются.

Offline evidence: model11 и decompression5 PASS; PS5/PS7 native13, helper lifecycle7, parent contracts9, POSIX owned-wrapper2 и POSIX native3 PASS; Ruff/parser PASS. Это не POSIX kernel acceptance. Исправлены и сохранены development negatives: противоречивый created-success envelope с zero identity, пропущенная инициализация mock counters и UTC DateTime roundtrip в PS7.

Для actual Linux qualification подготовлен отдельный one-shot candidate `2b45bc7071b756b5477c1b52c7ac4baceeb328061e5ef95dd6c7ff7d39181581`. Он заранее резервирует `/tmp/.home-gateway-p35-parent-fixture-288fa9605aca4d7f90c676cba315c380`; stdin script SHA `ee872e92f364f0ce4bca0b9839475bbd080714575721e1da23b4f6acc7f0bf2a`, 26347 bytes, command248. Двенадцать POSIX cases используют synthetic payload без его исполнения, finite cleanup по names/inode/content proof и individual unlink/rmdir. Нет запуска WSL/Docker, service/network/peer/config commands. Controller `PlanOnly` прошёл с actual runtime: plan `99dc2a4e6f53d1433144e5f6088063cee8f9659fa46942a6bdb5dbd7bff72d72`, SSH1/HTTPS3/agent1, truthful filesystem mutation scope; prior egress `a94aeee8…` и V3 failed attempt входят в identity. Actual fixture ещё не выполнена; helper install V4 ждёт её acceptance и свежий parent-bound PREV4.

Комплект и exact POSIX plan получили independent technical GO, 0 must-fix. Actual fixture затем прошла с exit0: SSH1/HTTPS3/agent1, все 12 cases PASS, `scratch_cleaned=true`, filesystem mutation true; внутри fixture network/service/helper-payload-execution0. Result SHA `206522b0198ce19a5d12471f102988d7fceb1c2db90e41430e2e00cbf6645110`, attempt `a3cb8d71d2cf3a8e498ca4e7ef6152284703632f7aea950632b79f63590cea53`. Independent actual POSIX acceptance GO подтвердил protected claim8files, process exit0/stderr empty и точный canonical stdout+LF, cleanup, egress archive и agent/add0.

Новые actual Cloud rules `2026-09-06T12:06:51.428Z` / association `12:07:05.884Z` совпали; Cloud SHA `e19cdf9ec280963cf0386cef845246f91225c81db5c82378ebd7279f9c27f634`. PREV4 plan `dcb1f0e60b609cacd0220f74fd3947f9dea516243f522fcbb7380c4c476fe45e` получил independent GO и прошёл live. Result `43ee1450c7982bf651687d859d477627e7f038980efa106004134b6535d11188`: helper absent/leftovers0, parent absent при проверенной identity `/usr/local`, observed `12:09:42.395928Z`, parent SHA `8aebe2553c6ade916c79b47a9e8a160c749c9b144479beac69f0f0df909384de`. Reviewer подтвердил actual PRE и exact install plan `2b8a38583e9beb0d9fbb15329d360e101b48b479eea47baf9161256dae989004` до записи.

INSTALLV4 прошёл с exit0, SSH3/SCP1/HTTPS3/agent1. Result и runtime install receipt имеют SHA `0ac52e24de92c81224f5a047c4dd364297c31894d2cd089389bd3c3acb4ae542`: `installed_by_gate=true`, `target_state=exact`, owner/group/mode match, payload `186a69d9cb4ed7ccbe42bff6810cb1da955332e77385a8f510aea9570c6bc25a`, leftovers0. Attempt SHA `28976575664bc66861fe6da5510fe6151c64be3a359ee1d471a367d6733c517f`. Parent создан и сохранён с identity `e98dbbbf47e037b772168e8a9d465a39b8af517003ca6d91fc75796d0481e65a`; cleanup подтвердил ту же identity, exact regular helper и leftovers0. Post PlanOnly `444802cf626f5e02a81288d45552f9c8079b92d339c83d771ea04507620886ac` связывает exact install receipt/current egress/Cloud/profile. Independent review подтвердил actual INSTALLV4 и POST plan с GO, 0 findings.

POSTV4 остановился до SSH/agent: exit1, `helper_gate_failed_closed`, error SHA `350f88a2178feefd8f5476db7a5ae3e22da88d61c3ca400ac50134e527bc9362`, counts SSH0/SCP0/HTTPS3/agent0. Это отдельный локальный отказ итоговой проверки; accepted installation не отменяется. Claim и receipts сохраняются для bounded diagnosis и отдельного POST recovery; повтор consumed claim не разрешён. Итоговый reconcile и phase acceptance пока ожидаются.

Ошибка POSTV4 точно сопоставлена по SHA с `adapter description is empty` в строгом local-baseline classifier. Из 21 записей `Get-NetAdapter -IncludeHidden` три имеют пустое поле и в raw CIM; обычный CIM query пропускает hidden entries и не подходит как замена полного inventory. Read-only lookup через [`GetIfEntry2` / `MIB_IF_ROW2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2) вернул непустое native Description для каждой из трёх записей с проверкой returned index/GUID/LUID. Готовится отдельный POST-only recovery; runtime и frozen helper V4 не меняются, неизвестные или несовпадающие записи должны по-прежнему отклоняться.

Следующее Cloud observation V5 получено в существующей authenticated Opera: rules `2026-09-06T12:28:37.580Z`, association `12:28:49.830Z`, SHA `65bf9bfe0cc071cb329c82749741f889ce0877b1488e900560855d723e43949c`. Rules/resources/единственный Droplet совпали; это browser owner observation, не server-confirmed API evidence. Старые наблюдения сохранены без изменения timestamp.

## Итоговый POST: локальный evidence gap, фаза не закрыта

POSTV4 failed attempt SHA `1ab3f9a13ca16d3eed003a80de0bcc7391757dc79684246cbaee50747c8aad55` и новый egress SHA `943683e7abebbf024788a7a6929fcd9ec03e90f588cfddd512c2b46639038840` сохранены. Runtime по-прежнему содержит marker/manifest/trust/egress/install receipt; cloud/local/agent receipts не созданы. Install receipt `0ac52e24…` не изменён. Повтор POSTV4 claim не выполнялся.

Отдельный ignored POST-only supplement `6d4720941fabe9b17b97713ff67065977d955878800c054b5473644aae3a519e` дополняет пустые CIM descriptions через read-only `GetIfEntry2`, проверяя returned index/GUID/LUID. Frozen V4 bundle и production classifier не изменены. Handoff `phase35-helper-post-handoff-v1.md` SHA `e58941dfad302f496ee19c28eaab8034bd4b3fdae28411d7bcfd95436c64b99b`; final review manifest `phase35-helper-post-review-manifest-v2.json` SHA `87724b739ca87854b55dc0044f30e48775bd8d0224dda2fc0ebe3e159ada9224`, 10 files. Targeted metadata9 и lifecycle6 прошли в PS5/PS7: реальный inventory отклоняется до HTTPS/agent; synthetic допустимый baseline проходит полный Reconcile и teardown. Reconcile request имеет 20 properties, receipt24, SSH argv27; это отдельно от 27-field migration baseline. Эти fixtures не означают actual POST success.

Redacted actual inventory receipt `phase35-helper-post-inventory-diagnostic-v1.json` SHA `9faca84293c5ab051214ecd356d1d65d584918a511718de874debf9dfef62f1c`: все 21 записи сохранены, native fallback3 относятся к `other`; итоговые classes19 other/1 Cisco/1 classifier-selfhosted. Последняя запись имеет исходное непустое generic WireGuard description. Regex classifier распознаёт протокол, но не доказывает provider identity. Доступные native metadata не содержат peer endpoint/public key; bounded поиск штатного read-only CLI не дал подходящего инструмента. Config/pipe/credential discovery не выполнялся. Принадлежность интерфейса Home Gateway или стороннему VPN остаётся `UNKNOWN`.

Independent architecture verdict: текущий POST — `NO_GO`. Нельзя исключить интерфейс или разрешить его по alias/description. Допустимый дальнейший путь без VPN mutation требует отдельного versioned collector contract: authoritative adapter-to-live-tunnel binding, sanitized public peer/endpoint identity, совпадение с ранее принятой third-party identity и отличие от Home Gateway, protected provenance/freshness, отказ при любой неоднозначности. При отсутствии такого evidence ограниченная диагностика останавливается. Общее owner permission уже есть и не заменяет identity proof.

Actual POSTV5 не запускался; Cloud V5 не был использован для live POST и истёк естественно. Runtime/helper остаются принятыми, финальный reconcile и закрытие фазы — `NO_GO`. VPN, services, firewall, Docker configuration, routes, DNS, adapters, RedShield и Cisco не изменялись. Фазы 3.6/3.7 не начинались.

Финальный independent checkpoint review — `GO`, 0 must-fix, только для документального/failure-evidence checkpoint. Reviewer подтвердил 10/10 manifest files, exact bundle/supplement hashes, пятифайловые protected sets failed POST claim и runtime, неизменный install receipt, owner/ACL, отсутствие cloud/local/agent receipts и текущие agent/add0. Inventory и PS5/PS7 fixture summaries совпали; STATUS/report/plan согласованы. Это не live approval supplement и не phase acceptance: POST и фаза 3.5 остаются `NO_GO` до устранения описанного identity gap.

## Возобновление: authoritative non-target attribution

После повторного поручения владельца продолжена bounded read-only диагностика. Найдена ровно одна RUNNING служба AmneziaWGTunnel, suffix которой совпадает с alias известного WireGuard-интерфейса. Установленные signed AmneziaVPN/service имеют version 5.0.1.5; backend использует Wintun/userspace, а PE exports tunnel.dll не содержат WireGuardNT GetConfiguration. Это связь с приложением, а не установленный VPN provider.

В [исходнике Amnezia 5.0.1.5](https://raw.githubusercontent.com/amnezia-vpn/amnezia-client/5.0.1.5/client/platforms/windows/daemon/windowstunnelservice.cpp) найден read-only UAPI getter. Wrapper не создавался: его constructor останавливает существующий tunnel. Сам getter также не вызывался: raw response может содержать private/preshared material. Готовится отдельный bounded byte-stream collector, сохраняющий только публичную проекцию и обнуляющий секретные поля, с обязательной привязкой adapter/service/pipe server process и двумя одинаковыми наблюдениями.

Независимый architecture review уточнил требование: историческое название RedShield не обязательно для доказательства отсутствия project target adapter. Отдельный reviewed contract может установить `existing_non_target`, provider=`UNKNOWN`, если и public peer identity, и canonical endpoint доказанно отличаются от independently accepted Home Gateway target identities. Любая неоднозначность блокирует POST. Принятый runtime содержит SSH identity и fingerprint серверного client peer, но не VPN SERVER public key/canonical endpoint; потребуется отдельная публичная read-only target projection.

Native metadata preflight текущего Windows token: effective_admin=false, elevated=false, elevation type Limited. OpenProcess с PROCESS_QUERY_LIMITED_INFORMATION для точного SCM service PID вернул ERROR_ACCESS_DENIED (5); required held-process image/creation-time proof недоступен. Pipe/config не читались, token handle закрыт, изменений нет. Готовится конкретный independently reviewed диагностический запуск через обычный Windows UAC; обход elevation, смена service/adapter/VPN state и вывод конфигурации не разрешены. Пока это подготовка, не actual observation и не phase acceptance.

Installed Go buildinfo квалифицировал зависимость amneziawg-go/v3 v3.1.20260814; exact-tag UAPI source evidence SHA `7a88ac0cc50ea932336042d963183760e38a48fd8e055e0c0d00a4324cf1ef32`. Новый ignored UAPI candidate V1: handoff SHA `92d9e4255fbdd85a0fab75228bba3addb2bd6092b882f373f633fc22b39bc560`, review manifest SHA `c2f2b8a67f33585ede5353df47471b546529e52683a4c107dc36b5e2e7adbd74` (9 files), EXE `b368fb61d89a37484a42d2626b043deb54ab07df0bac3ba1bab7a72390656e0d`, source `72a3f0a7a43079dc5eea556f063bd979b2a5e02ee5bce718206dfba26ba88c59`, runner `6ea5669473eb30b344cb43700dfbd0de4a60eaf6eaa7482cd82f284cefb8106a`. Reserved claim V1 отсутствует; nonce `7bb2ed6225134b5abafa5f9193116c2b`.

Author validation: PS5/PS7 — synthetic13, signature pins2, native metadata binding, self-deadline, PlanOnly/parser, CreateNew/duplicate и held-write/delete rejection PASS. Actual GET/UAC/agent/network0, probe processes0. Elevated EXE имеет внутренний deadline25s; parent ждёт30s и не предполагает права на kill повышенного процесса. OS consent wait считается отдельно. Normal paths обнуляют buffers; catastrophic Environment.Exit завершает процесс без crash dump, но не доказывает выполнение managed finally. Candidate передан на independent review перед обычным UAC. Даже успешная публичная observation не является target classification или разрешением POST.

Independent review V1: NO_GO для Execute, один Important finding — Process-only clearing не доказывает окружение, переданное через RunAs/AppInfo, а child не проверяет его до GET. Проверены manifest, отсутствие claim/processes, parser/identity/deadline contracts; semantic rebuild подтвердил IL всех 18 probe types и assembly refs/resources, кроме ожидаемых nondeterministic compiler-generated GUID names. Actual UAC/GET не выполнялись.

Разрешён один bounded fix cycle V2: name-only fail-closed checks Process/User/Machine до UAC, повторная проверка Process после временной очистки и самый ранний child environment check до claim/service/pipe/GET. Отдельный ordinary-UAC preflight mode должен дать protected environment/admin/identity evidence без GET. Managed Main не является доказательством защиты от malicious pre-Main CLR injection; сохраняется явно принятая same-owner/OS-runtime trust boundary. User/Machine env не меняются, V1 artifacts остаются неизменными.

V2 передан на focused review: manifest SHA `83353cd28d2742a08540f64eaafc7b193ec4333778d5287d96cd7a88a7bf9d15`, handoff `29a2271b3756b424f3ea8fc3736ad5deaee4a356d7a93731650e7c996a8e27b1`, EXE `384f501a6456ba3c088c046ef3614ac9275db472695c692a712cacd072712dc6`, source `b798ab582eb009c39362f273530b6f18c86c84ffdd89be2d1e81bf9967cfade5`, runner `69c71b6dbd631c0aa14eb576a2a9c5a588fedad6e681d0ace79989bc2b31a224`. PS5/PS7 targeted checks подтвердили отказы для трёх env scopes, clean paths, два actual-child early-reject cases, два PlanOnly modes и сохранность девяти V1 files. UAC/GET0, новых claims нет. Reserved nonce `88145f49656a46c1a2b157e1caea61de`; первый отдельный preflight получает свой claim и не обращается к pipe. Будущее observation требует SHA independently reviewed preflight receipt.

Focused independent V2 review — GO, 0 must-fix, только для одного ordinary-UAC non-GET preflight. Controller проверил exact runner и PS5 hashes и выполнил Execute/PreflightOnly. Launcher получил child exit2, consumed=false, observation=false; claim содержит только launcher-outcome.json SHA `3b91a11b500abc2a47caf725474e9bcdc46a8cc94c6716a0c23fe4a8767073bd`. Probe processes0. GET/pipe0 следуют из отдельного preflight code path. Дочерний stdout со stage не сохранён RunAs launcher; факт и точный результат elevation, env check и конкретный failed predicate по этому receipt не доказаны. Текущие корректные owner/ACL claim не доказывают прошлое состояние. V2 не повторяется и не очищается.

Подготовлен отдельный preflight-only V3 для устранения diagnostic gap: без parser/pipe imports/GET entrypoint, с заранее проверенным protected sink и CreateNew finite failure receipt, статическим stage, точным native error при его наличии и отдельными observed/unknown признаками env/admin. Это новый проверяемый диагностический candidate, а не переинтерпретация V2 success или разрешение ослабить baseline.

V3 не запускался: independent review обнаружил потерю native error после `WaitForSingleObject / WAIT_FAILED`. V4 сохраняет result и немедленный `GetLastError`; signaled state не наследует stale error. PS5/PS7 — четыре targeted cases, включая actual invalid handle/error6 и typed failure readback, PASS. Semantic rebuild: 13 types, zero IL differences. Manifest `2ef4c3d25dee94f7daf3ef36851f269a3b7ef464c468bbcf89ad992796e1f125`, runner `a77155e417a3b1f77a51f10bb3a250f4623fb38be40a04ab9da5e79b640c73d8`, EXE `4650344b4fb761ae10afae3e52ff015cf75e9a6ceb4d196cd5c332d0d0b62188` получили independent GO для одного ordinary-UAC non-GET preflight.

Actual V4 завершился child exit2. Protected failure receipt `dc32f3c680e0dc40b6c787b12a228f33ec47d5eb9da9f770a6efe01bd62d8b52` фиксирует `ProcessOpen / native_error=5`, `environment_checked/clean=true`, `admin_checked/effective_admin=true`, `sink_verified=true`, pipe0/get0, mutation=false. Claim V4 consumed; exact три файла сохранены, launcher outcome `04aa7da8edbcd1c45a296da01aed5411c7bcba9de827eccf46dbe9c9d7ee7240`, probe processes0. Reviewer подтвердил failure-evidence GO, 0 findings; actual preflight и последующие gates остаются NO_GO. Этот результат не устанавливает причину отдельного V2 failure.

Следующий bounded candidate использует только `PROCESS_QUERY_LIMITED_INFORMATION (0x1000)` вместо `0x101000`, с `GetExitCodeProcess`, creation time и image identity. `SeDebugPrivilege` не используется: process DACL не обходится. При повторном отказе этот путь прекращается. Независимый architecture review допускает отдельную честно ограниченную SCM/protected-pipe identity proof без process handle и без утверждения loaded-module identity; для неё нужны собственные candidate review и actual receipts. Ни один диагностический результат сам по себе не разрешает target classification или POST.

V5 подготовлен: manifest `1c6666ce886010ed3c3a9225f30449d8be66a824a03eddb28b07c210e397a48c`, runner `7cf57984a853aaa5e5fac75d155e0a3ebfa3aa628177ea37e309d15427ad9ebd`, EXE `a540a9fa11a4e55f6c7820ad5b5e81c3f969653478824facefa451a45bd300bc`. PS5/PS7 — по шесть focused cases PASS, включая actual owned-process handle с `0x1000`, три query APIs, invalid handle/error6 и typed failure readback. Это не подтверждает доступ к службе AmneziaWG. Module enumeration остаётся отдельным непроверенным правом; отказ не разрешает его обход. V4 и consumed claim сохранены, UAC/GET0, V5 claim отсутствует. Candidate передан на independent review.

V5 independent review — GO, 0 must-fix; semantic rebuild 13 types без method-body differences. Actual запуск exact runner/PS5 завершился child exit2 уже на `ModuleSnapshot / native_error=5`. Предшествующие query-limited process checks пройдены; module enumeration запрещена. Failure `f91dd4cc26b7664b000e1adb614bb5365453e34bd5aa47d4f2e96c47ab6b2799` (370 bytes) фиксирует admin/environment/sink true, pipe0/get0, mutation=false. Launcher outcome `9e538ad9fd182340de894f3284e6cb87732cef82dab41f20ab43ccbd2a0ccd73`; claim V5 consumed, exact три файла, process0. Повтор V5 и обход module DACL не выполняются.

Независимый V5 failure readback — GO, 0 must-fix. Следующий V6 observation candidate сохраняет query-limited process proof и exact adapter/SCM binding, проверяет owner/DACL и PID на held protected pipe до двух fixed GET и после ответов. Module enumeration/SCM command line отсутствуют; installed-file pin не выдаётся за loaded-module evidence. Manifest `dee4c51494d8e614e0e6ec7888bc92785e5d568ec23479ec6891136a38aeadce` (12 artifacts), runner `51f9c5b0617c28b4cdad2e976d6fd6428cf80f48432510caf9fd925dde9e1a9b`, EXE `cd08a0313de01871ad53f8ab9a4f6a8076777c108de0c47604782f2a158f6d6b`. PS5/PS7 — по 24 synthetic cases PASS, включая wrong PID/broad DACL/READ_CONTROL denial перед GET, timeout и post-response drift. Parser соответствует ранее проверенному V2 после нормализации CRLF. Actual UAC/GET0, claim отсутствует; candidate передан на independent review. Реальный pipe ACL ещё не квалифицирован.

V6 independent review — GO, 0 must-fix; semantic rebuild 21 types без method-body differences. Controller исполнил exact runner через pinned PS5: exit0, два GET/two equal snapshots `2026-09-06T14:41:40.0039718Z` → `14:41:41.0670702Z`, один peer. Protected observation `ebae0132c478edbeba87112b9567130f9b69b8767b01376cf2a1d3cb64973b1f` (1337 bytes), launcher `cf29eaf044e162792b80743355ce578cde396305c07c47bfd04b2fc554988756` (278 bytes), consumed marker сохранены; failure/raw response отсутствуют, process0. Независимый actual readback — observation-evidence GO, 0 findings: environment/admin, held process/SCM/pipe PID, pipe owner/DACL и before/after equality, adapter/image/signature checks true. `loaded_module=UNPROVEN`, provider UNKNOWN, classification=false, mutation=false. Это фактический успешный сбор публичной проекции, ещё не target comparison или POST.

Fresh authenticated Droplet Overview подтвердил public IPv4 и public IPv6 одной accepted Droplet; Networking показывает не включённый Reserved IP и прежний Firewall. Поэтому target comparison должен включать обе public endpoint identities. Это соответствует уже принятой dual-wildcard Docker publication (IPv4 + IPv6); blocked IPv6 inbound Cloud policy фиксируется отдельно и не исключает IPv6 из консервативного comparison set. Hash format совпадает с V6: ASCII `p35-uapi-endpoint-v1` + NUL, family byte 4/6, raw address bytes, uint16 big-endian port. Дополнительные известные authoritative addresses/ports должны входить в набор; полное знание DNS/NAT alternatives не заявляется. Public-only server payload готовится отдельно, live target receipt пока отсутствует.

Подготовительный target-public V1 получил independent GO, 0 must-fix: manifest `d019ddc15028d694da938e285e2dae1914c975efc2f71e1d0adb6c88d51a8ac5` (6 artifacts), payload `18804feb6d31ef83931d65792c54ed922d27083442e88abcce52715cccb4deb7`, contract `080b2ff21a92b61066ab31f300aab0e202a76d60270bb06e9d637e7371d070ed`. Fixture-only 22 synthetic + 2 targeted teardown, Ruff PASS; actual Docker/SSH/UAPI0. Linux execution и outer SSH/Cloud/endpoint-set completeness остаются UNQUALIFIED. Payload не выполняет классификацию и не читает private config.

При подготовке интеграции обнаружено несовпадение image pin semantics: accepted baseline хранит SHA canonical `{"image_id": image_id, "repo_digests": sorted(digests)}`, подготовительный V1 ожидает SHA одного image ID. V1 не запускался и не изменяется. Новый final-target variant должен читать только Id/RepoDigests через restricted `docker image inspect --format`, вычислять исходный canonical aggregate и сравнивать aggregate с aggregate до/после; два дополнительных read-only commands входят в отдельный bounded budget. Final package готовится с target observation, fresh local UAPI/native inventory, versioned attribution/compatibility и exact POST. Live target/POST пока не выполнялись.

Final V1 package зафиксирован и передан на независимое review: manifest `31b26825852540eabed87684c253347fbeb5d0bd9df2a8ea9b7668bc8a80d10d` (32 файла), package identity `5c4bd70c9ceb1c587097dc50f34102442ec87b5175250d32655ef429166bcfc5`, package file `09a6b2f2e768af79fee688cca03e24502d12833cc415184e105eb7c2aa4a449c`, handoff `26e7b88c2b91ba4fad05ba98388d049710c25947c44ac355f2e8ce70c1d2fbed`, runner `132385e8f6743affe14129b8803b63118b2c25e4960e0be96fee1dde36695181`. Новая UAPI-пара использует nonce `f34f83b322334f3e8df3f50933c196b7`; V6 не повторяется. Четыре новые claim/input roots отсутствуют, owned processes0, actual final target/UAPI/POST0.

Final focused evidence: PS5/PS7 attribution12 + inventory negatives3 + parser5; native MSYS stdin/frame4 в обеих версиях (remote command 663 bytes); POST4 с actual frozen 20-field request builder/24-field receipt validator. Python aggregate-image target23 и Ruff PASS. Actual read-only native inventory:21, fallback3, raw selfhosted1/Cisco1/other19; exact WG GUID/index/LUID hash совпал с V6. Это metadata qualification, не fresh attribution. Whole Observe stage не выполнялся и не полностью lifecycle-mocked; Linux Docker execution UNQUALIFIED; ownership агента/archive в integration fixtures mocked. Существующий owned lifecycle source не менялся, fixture success не выдаётся за live teardown. Новые actual receipts и phase acceptance остаются необходимыми.

Independent final V1 review: **NO_GO, 1 Important**. `phase35-final-operations-v1.ps1:149–166` оставляет derived v1 wire projection в runtime `local-baseline-receipt.json` вместе с Cloud receipt после success или позднего failure. Frozen standalone consumer не проверяет compatibility envelope, поэтому сохранённая projection приобретает неподтверждённую самостоятельную authority. Live Observe/Post V1 не выполнялись; четыре roots отсутствуют, agent/env0. Остальная статика согласована (manifest32/32, target aggregate/image, UAPI nonce, обе endpoint inequalities, oldest TTL300, one-shot и lifecycle bindings). First-live Linux/Observe gaps не объявлены дополнительными static blockers.

Назначен один V2 fix pass: оба POST runtime receipts временные, exact hashes/paths привязаны к envelope и POST plan в protected claim до записи; после единственного controlled guard action на всех paths выполняется exact-owned archive с проверкой отсутствия в runtime и typed cleanup/consumption evidence. Cleanup failure сохраняет NO_GO и claim; чужие/подменённые файлы не удаляются. Agent teardown обязателен независимо от receipt cleanup. Проверки ограничены success, failure после записи до SSH и transport/receipt failures в PS5/PS7. V1 artifacts остаются неизменными; broader consumer refactor и successor phase не начинаются.

Final V2 исправление подготовлено: manifest `8f9b69323fa63cd7d15973a8e7d95c4623bea1e47a2743ee9c5daa6304d7e097` включает 171 файл с retained native fixture evidence; handoff `7745eb788c618277babe0c51b33a394cfbbda8423012b92e8ca0430015878b5a`. Package identity `38595689162866ef8f880e7f61a9618ec0809a514bc80fd8cb6d878a512b5124`, package file `e827f86776af47e7951853fc136db2d54cac79d2051893cd8c83b200309d43e6`, runner `9e22c7aea683f2ea0fb4c2ce51e3d21434884c54f8aa0773bcd8ef9c3eb736e1`, operations `79f6f945bd0d5ef7368482122462f06e8f52e957d2a04bf18257928c000a0e8f`. Fresh UAPI EXE `b5f56a3607e71499706e60428c545c00ab6dfc407e83c3773e7346b7fa274b51`, nonce `e9f24298bd6b41bf9b60245890136a19`; изменения клона ограничены nonce/path.

PS5/PS7 — по 9 targeted cases PASS с реальными protected synthetic files/native archive, включая first/second write failure, after-publish failure и tamper preservation. Parser5/PlanOnly/BundleOnly и Ruff PASS; 32 V1 artifact hashes неизменны. Agent ownership в fixtures остаётся mocked; Whole Observe/Linux first-live gaps сохранены. New live roots отсутствуют, actual SSH/agent/UAC/GET0. V2 передан на focused independent review; acceptance требует result, attempt и ephemeral-cleanup evidence вместе.

Final V2 static review — **GO, 0 must-fix**, manifest171/171 exact; Important V1 устранён. Root собрал fresh authenticated Cloud: Overview `15:43:33.185Z`, Reserved IP disabled `15:43:58.051Z`, Rules `15:44:01.345Z`, association `15:44:14.454Z` (2026-09-06). Firewall/resources/address pins совпали, known additional mappings0; DNS/NAT exhaustiveness не заявлялась. Новые protected Cloud files: firewall `669b41c553d9c3569c9229d780a5f2a68105339fb58ac6715c086cf163a6dc3c`, addresses `3e38ce0eeed3467d6539e30a1a55feb7a233c76095306da2cc43dd9325466aea`. Исторические timestamps/files не менялись.

Actual Observe plan `de9a2d11d8504634a92928bfff366b40a968047bd89bbe2069a7d01279ca44c5` / `P35-FINAL-OBSERVE-DE9A2D11D8504634` проверен и выполнен: exit0, SSH1/HTTPS3/agent1/SCP0. Result `c557d0e74c40b5dfee108ca0042dc89be7891c8b5e617c4ca9f98b9d5b5ea24e` и attempt фиксируют `final_observe_completed`. Target: 12 read-only commands, две равные публичные проекции, accepted image aggregate, endpoint set2; Linux SSH exit0, stderr0, timeout/overflowfalse. Fresh UAPI: GET2/two equal snapshots, peer1, held process/service/pipe/DACL bindings, loaded_module UNPROVEN. Native inventory21/fallback3/raw selfhosted1/Cisco1. Compatibility `2254895a7f01a76d9df4259eb02880bfabffa3cec0964450a37ad6791011efda` сохраняет20 unchanged/21 total и доказывает key inequality + inequality обоих endpoints; derived `existing_non_target`, provider UNKNOWN. Wire projection `ad3c6a7de5f0015ea84c221762a17ab30859e346093e4be4781d8d529a218757`, selfhosted0. Actual independent Observe/PostPlan review — **GO, 0 findings**, agent/add/env0.

Root повторно получил exact PostPlan `321180a66a60893696539d224fdf65b41307bb12455e001fd8db722d9b6389ee` / `P35-FINAL-POST-321180A66A608936` и исполнил POST с action-time freshness rechecks. SSH завершился exit127, stdout0, stderr114 bytes, timeout/overflowfalse, UTF8true. SSH evidence `bcf5b8e52a8eb707c5748491280422423ae63c5614d0d41a4dc02f83d9132bdb`; stderr SHA `dfff65efc56ece8fbe8dd087fca05539784abf712f088229216cc86736fc562c`. Attempt `bf2c14cc95d47dc15732380a7c4164d2aa0ff40248d4534a8d1cd1ca2d8e460f` имеет `final_post_failed`, error SHA `e67e76e0ea360c78f93faaf2ea93739dfdc042adcae25024da10f17a73ab699e`; result отсутствует.

Actual ephemeral cleanup `f3b3d7306bbc72637863bcd368bfc445b138fe37ad27366073eb0b9b9ecb6c1a` — completed, runtime_receipts_absent=true, controlled_action_entered=true, foreign deletion=false. Binding `d5837645ab6f782baf32f9faea312a2c38e73ed9daf977b20c67cae54068f3c2`; exact archives: cloud `aef4528ae0b363a13085e1c267c2a455187cb88e7c39c6217a0c1dbd4172824a`, local/wire `ad3c6a7de5f0015ea84c221762a17ab30859e346093e4be4781d8d529a218757`. Claim10 files с protected ACL сохранён, runtime cloud/local/agent receipts отсутствуют, agent/add/env0. Runtime manifest/install/trust сохранены; current egress `88f7cbb3ef2cd9b08f56a9f5b43084390c5d92beb4625ebad78c48b8f4bd72ee`. Independent failure/cleanup review — **GO, 0 must-fix**; POST/phase NO_GO, claim consumed без replay.

Последующая offline диагностика установила точную причину: pinned payload `186a69d9cb4ed7ccbe42bff6810cb1da955332e77385a8f510aea9570c6bc25a` содержит CRLF shebang. Exact install сохраняет bytes, а Reconcile запускает helper напрямую; GNU env получает имя interpreter `python3\r`. Статически восстановленный GNU diagnostic совпал с actual stderr114/SHA полностью. Existing fixtures не выполняли этот shebang: target transport использовал Python bootstrap, POST mock подменял JsonRunner. Минимальный новый V3 candidate вызывает `sudo -n /usr/bin/python3 /usr/local/libexec/home-gateway-p3-peer-guard reconcile` (80 bytes, SHA `7e7d8573c79c369c4b906d725d6145455e19442df7317d1a7c28cc6f3691a046`). Это ранее использованный absolute interpreter path, не новый binary-hash pin. Helper payload/runtime/install не меняются. Нужны full native Reconcile regression, independent review, новые nonce/claims и fresh observations.
