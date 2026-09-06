# Phase 3.5: prepare the protected runtime and server helper

**Goal:** Validate one protected runtime and install or attest the exact inert server helper, then reconcile the server baseline.

**Audience:** P3 controller, implementer, and independent reviewer. **Content type:** execution plan. **Evidence status:** CLOSED, 2026-09-06, FINAL ACCEPTANCE GO0. Migration V7, runtime Prepare/Validate, Helper V4 pre/install, Final Observe V4 and corrected POST V4 passed independent review. All 24 final receipt fields match the accepted baseline. Runtime temporary receipts are archived and absent, agent/add/env0, profile absent. The [phase report](../../reports/2026-09-05-p35-runtime-preparation.md) records exact receipts, tested corrections and retained evidence limits. Phase 3.6/3.7 has not started.

**Base:** `2bb8171aa7087ca7e4021b64ad115e289a9d5f27`, branch `phase/p3-5-runtime-lifecycle`, existing `p3-redshield-windows` worktree. Preserve the unrelated untracked Python caches and `testResults.xml`.

## Phase boundary

This is phase 3.5 of the owner-approved release sequence recorded on 2026-09-01. Historical documents use P3.5 for persistent Windows sink routes; those reports do not close this phase.

The [current prerequisite report](../../reports/2026-09-05-p34-prerequisite-observation.md) closes 3.4. The [GUI bootstrap runbook](../../runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md) defines the executable gates: 6.4L, 6.4R-pre, 6.4P, and 6.4R-post. The [prerequisite contract](../specs/2026-08-31-p3-prelive-prerequisite-closure-design.md) supersedes the historical Task 6A bootstrap assumptions.

Phase 3.5 permits protected local runtime preparation, an exact one-shot memory-only SSH agent, and installation or attestation of `/usr/local/libexec/home-gateway-p3-peer-guard`. The helper must be inert, regular, root-owned, mode `0755`, and hash-exact.

Management/Guest actions and profile export belong to 3.6. Activation belongs to 3.7. This phase does not change VPN, services, firewall, Docker configuration, routes, DNS, adapters, RedShield, or Cisco.

## Files and ownership

- Implementer: `scripts/p3-prelive-runtime.ps1` and `tests/windows-pester/P3PreliveRuntime.Tests.ps1`, limited to failed-Prepare ownership and retention safety.
- Controller: this plan, the phase preparation report, and the current status link. Operational candidates stay under ignored `.p3-vps-run/` with restrictive ACLs.
- Independent reviewer: read-only review of the complete change and candidate boundary after implementation.

## Выполненный путь к закрытию

### Уточнение полномочий владельцем, 2026-09-05

Владелец прямо поручил: «Закончи фазу без моего участия, все разрешения есть». Это последующее указание заменяет повторные запросы owner hash/challenge approval в пределах оставшейся фазы 3.5. Controller вправе выполнить новый reviewed prerequisite candidate, принять независимо проверенный свежий observed baseline с сохранением известного historical evidence gap, подготовить runtime и выполнить reviewed helper install/attestation/reconcile. Точные hashes/challenges по-прежнему вычисляются из фактических artifacts и проверяются исполнителями; независимый technical review, freshness, one-shot budgets, stop conditions, retention и teardown обязательны. Это delegated authorization, а не заявление, что владелец лично подтверждал каждый будущий hash. Разрешение не распространяется на 3.6/3.7 или изменение VPN/routes/DNS/firewall/сервисов.

Protected/source verification и live batches выполняются последовательно: `Read-P3BoundedStableBytes` открывает файлы с `FileShare.None`. Одновременные чтения из разных PS processes/reviewer могут вызвать fail-closed sharing violation. Reviewer получает отдельное окно readback; controller начинает следующий executor только после завершения его чтений. Обычная работа с независимыми docs и browser UI может идти параллельно.

Владелец поручил продолжить и закрыть фазу 3.5. Migration V7, runtime Prepare и Helper V4 installation приняты; Final Observe/Post V4 завершили оставшийся gate. Fresh доказательство `current existing_non_target` использует неравенство peer key и обоих authoritative target endpoints; provider остаётся UNKNOWN. Operational supplement сохраняет полный inventory и source provenance. Previous evidence и consumed claims сохраняются без replay. Фазы 3.6/3.7, profile export и VPN mutation не выполнялись.

| Условие | Текущее evidence | Что требуется |
| --- | --- | --- |
| Offline runtime safety | Независимый GO; 248 Pester и repository verification passed | Сохранить принятую реализацию |
| Причина policy drift | V7: 23 исторических поля сохранены; две новые выборки совпали по всем 27 полям | Новый baseline принят с явным historical-gap acknowledgement; историческую причину не считать доказанной |
| Новый prerequisite | V7 SSH1/HTTPS3, independent receipt GO, agent/add0 | Receipt использован Prepare; сохранить provenance |
| 6.4L | Runtime V5 package/Prepare/Validate и actual readback получили GO | Сохранить runtime и consumption |
| 6.4R-pre/P/post | Helper V4 pre/install и Final Observe/Post V4 независимо приняты; final result `0bfb3b8ff0deff4c1d469fa88081401a75cfecc25dc73673883089da71165dbd` | Выполнено; сохранить exact receipts/claims и rollback evidence |
| Приёмка фазы | FINAL ACCEPTANCE GO0, 2026-09-06 | Выполнено: helper identity/owner/mode, baseline equality, leftovers/agents0, exact cleanup, independent GO |

После checkpoint `618c88c` actual UAPI V6 collector получил два одинаковых публичных снимка существующего AmneziaWG tunnel через обычный UAC. Source-pinned grammar, native adapter/SCM/query-limited process/protected-pipe binding и secret-buffer zeroing независимо проверены. Final Observe V4 заново собрал UAPI и target public data и доказал неравенство ключа и обоих endpoints относительно local projection. Provider остаётся UNKNOWN, loaded module UNPROVEN; обход OS access controls и service/VPN mutations не выполнялся. Исходные failures, runtime/install и consumed claims сохраняются; фазы 3.6/3.7 не начаты.

Actual V6 сохранил прошедшие V5 held process image/creation/liveness checks (`0x1000`), exact SCM/native adapter binding и добавил owner/DACL/server-PID проверки на удерживаемом UAPI handle. Module enumeration удалена без альтернативного доступа; receipt явно содержит `loaded_module=UNPROVEN`. SCM configuration arguments не читались. Один bounded observation с preconditions перед GET выполнен и независимо принят; отдельного preparatory UAC не было.

Принятый public-only target collector связывает fresh authenticated Cloud Droplet public IPv4 с numeric pinned-key SSH destination, а оба public IPv4/IPv6 — с той же Droplet, exact running container/image, server public key (`awg show awg0 public-key`), listen port и принятой dual-wildcard UDP38556 publication. Два публичных наблюдения и before/after identity checks совпали. Private config и profile export для этой атрибуции не нужны. Консервативный canonical target set включает обе address families даже при blocked Cloud IPv6 inbound; дополнительные известные authoritative addresses/ports включаются либо блокируют классификацию. Полное знание DNS/NAT alternatives не заявляется. Reserved IP проверен через authenticated Droplet Networking.

Совместимость POST оформляется отдельным versioned attribution/compatibility envelope: исходный native inventory и raw v1 classifier receipt (`selfhosted=1`) сохраняются. Единственное допустимое доказанное уточнение — exact adapter `selfhosted → existing_non_target`, provider UNKNOWN, при неравенстве и peer key, и каждого authoritative target endpoint. Все остальные adapters/classes неизменны; второй generic WG, extra peer или drift дают NO_GO. Exact POST plan связывает raw receipt, attribution, UAPI/target/native evidence и derivation implementation hashes; eight-field wire projection передаётся frozen reconciler только после проверки envelope. Projection не выдаётся за необработанный результат regex classifier. Freshness определяется самым старым source observation и ограничена существующим local TTL300s, с повторной проверкой перед действием.

POST wire projection и Cloud receipt в RuntimeRoot существуют только для одного controlled guard action. Их expected hashes/owned paths и envelope/plan bindings записываются в protected claim до exposure. На любом выходе exact-owned receipts архивируются в claim, отсутствие runtime paths проверяется и фиксируется typed consumption/cleanup evidence. Это предотвращает позднее standalone чтение projection как raw v1 receipt. Cleanup failure блокирует закрытие, сохраняет claim и не разрешает удалять подменённый файл; teardown агента остаётся обязательным.

Каждый кандидат сначала готовится и проверяется локально. По последующему прямому поручению владельца controller самостоятельно фиксирует exact authorization на фактические hash/challenge в пределах фазы 3.5. Новый migration candidate допускает один SSH и три HTTPS. До HTTPS/assembly проверяются 23 исторических baseline поля и точный новый payload hash; три policy-dependent hash сохраняются только как новое наблюдение. Полученный receipt остаётся evidence prerequisite; runtime/helper исполняются собственными проверенными gates. Принятие нового baseline и исторического evidence gap фиксируется в точном runtime Prepare authorization.

Исправление нормализации меняет hash guard payload. Поэтому следующая цепочка использует новые `ssh_trust`, prerequisite manifest, agent manifest, plan, nonce и root. SSH/key/toolchain/Cloud/egress/expected-IPv6 identities сохраняются. Receipt 3.4 служит только историческим provenance. Для будущего baseline comparison ожидаются 23 неизменных поля; `payload_sha256` и три policy-dependent hash рассматриваются отдельно по текущему evidence. Исторический baseline не преобразуется в новый и не получает обновлённый timestamp. Helper installation не входит в 27-field baseline и сама по себе не требует rebaseline.

После runtime Prepare потребуются свежие evidence для отдельных actions: helper context ограничивает egress возрастом 120 секунд; Reconcile — local observation 300 секундами и Cloud observation 900 секундами. Их собирают перед соответствующим действием, не продлевая старые receipts.

## Execution steps

1. Verify the exact 3.4 receipt and protected file set without starting an agent. Attempt `New-P3ManifestPlan` against the real clock. Preserve expired evidence without changing its timestamp or consuming it.
2. Reproduce the failed-Prepare defect with synthetic local fixtures. A pre-existing target must survive unchanged. Fix exclusive creation and failure handling; preserve ambiguous or partially prepared state for reviewed recovery.
3. Run the focused runtime tests in Windows PowerShell 5.1 and PowerShell 7. Run the final repository verification once after the fix, then obtain consolidated independent review.
4. If the prerequisite expired, prepare a new exact read-only observation candidate using the previously accepted identities as expected pins. They are not fresh evidence. After independent review, the controller records exact authorization under the owner's delegated scope before one SSH observation and three HTTPS observations; collect fresh Cloud Firewall evidence through the authenticated owner interface. Stop on identity drift.
5. From the newly validated receipt, generate the exact `PreparePlan` and agent plan. After independent candidate review, the controller records exact runtime authorization and runs `Prepare` within the receipt's ten-minute window. Verify `Validate`, restrictive ACLs, exact trust/manifest hashes, and one-time prerequisite consumption.
6. Run 6.4R-pre in its own bounded agent batch. Read the helper state and collect fresh Cloud Firewall, egress, and local baseline receipts. Always tear down the agent in `finally`.
7. Independently review the observed helper install/attestation candidate. The controller records exact authorization under the delegated scope, then runs 6.4P and 6.4R-post. Preserve a pre-existing exact helper; reject a foreign or conflicting target.
8. Independently review runtime receipts, helper identity, baseline equality, zero unexpected leftovers, and completed agent teardown. Update status only after this evidence passes.

The owner's subsequent instruction delegates the remaining phase 3.5 authorizations to the controller. The [runbook](../../runbooks/P3_AMNEZIA_GUI_BOOTSTRAP.md) still separates prerequisite observation, runtime preparation, and helper installation as independently validated exact-candidate gates. Do not invent a runtime manifest hash before fresh evidence exists or request the same permission again.

## Verification and acceptance

Meaningful regression cases cover pre-existing directory and file targets, a failure after owned creation, injected foreign content or replacement, and receipt replay. Production SSH, GUI, and network boundaries are disabled in tests.

Run the focused `P3PreliveRuntime.Tests.ps1` suite under both PowerShell versions, both parsers, and `git diff --check`. At the offline completion boundary, run `scripts/dev.ps1 -Command verify`, Python unit tests, and the repository Ruff checks. Record inherited check failures separately from changed-file failures.

Phase 3.5 closes only after 6.4L and 6.4R-pre/P/post have passed with exact protected receipts, matching helper ownership/hash/mode, reconciled baseline, zero agent processes, and independent GO. Offline tests and a prepared candidate alone do not meet these criteria.

## Recovery and stop conditions

Agent teardown is mandatory; teardown failure is terminal. Preserve an uncertain partial runtime and its consumed prerequisite instead of deleting an unproved directory or enabling replay. Recover retained partial state only after inspecting its exact identity and obtaining a scoped recovery approval.

For a valid runtime, `CleanupPlan` and `Cleanup` require their own exact hash/challenge; cleanup leaves prerequisite consumption intact. Helper removal requires `RemoteRemovePlan` and proof that this gate installed the exact helper. Do not remove a pre-existing helper or infer removal from Windows restoration.

Expired evidence, changed source files, unexpected peers or helper state, invalid ACLs, failed identity checks, or unproved rollback stop the current live gate. Refresh only the evidence that expired; 3.4 remains historically closed.
