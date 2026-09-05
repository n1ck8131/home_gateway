# Phase 3.5: prepare the protected runtime and server helper

**Goal:** Validate one protected runtime and install or attest the exact inert server helper, then reconcile the server baseline.

**Audience:** P3 controller, implementer, and independent reviewer. **Content type:** execution plan. **Evidence status:** offline runtime/counter/footer corrections accepted. Migration V1 passed then expired; V2 stopped on drift, V3 failed in native transport before an observation envelope. Compact V4 and Runtime V5 templates have independent technical GO. V4 is NOT EXECUTED: fresh Cloud evidence is unavailable through the currently connected browser. Runtime V5 package/runtime and helper gates remain absent/open.

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

## Текущий путь к закрытию

### Уточнение полномочий владельцем, 2026-09-05

Владелец прямо поручил: «Закончи фазу без моего участия, все разрешения есть». Это последующее указание заменяет повторные запросы owner hash/challenge approval в пределах оставшейся фазы 3.5. Controller вправе выполнить новый reviewed prerequisite candidate, принять независимо проверенный свежий observed baseline с сохранением известного historical evidence gap, подготовить runtime и выполнить reviewed helper install/attestation/reconcile. Точные hashes/challenges по-прежнему вычисляются из фактических artifacts и проверяются исполнителями; независимый technical review, freshness, one-shot budgets, stop conditions, retention и teardown обязательны. Это delegated authorization, а не заявление, что владелец лично подтверждал каждый будущий hash. Разрешение не распространяется на 3.6/3.7 или изменение VPN/routes/DNS/firewall/сервисов.

Protected/source verification и live batches выполняются последовательно: `Read-P3BoundedStableBytes` открывает файлы с `FileShare.None`. Одновременные чтения из разных PS processes/reviewer могут вызвать fail-closed sharing violation. Reviewer получает отдельное окно readback; controller начинает следующий executor только после завершения его чтений. Обычная работа с независимыми docs и browser UI может идти параллельно.

Владелец поручил продолжить и закрыть фазу 3.5. Предыдущие V2/V3 evidence сохраняются; их claims не допускают повторного использования. Ближайшая разрешённая локальная работа — отдельный migration prerequisite candidate с безопасной регистрацией process result. Ownership implementer дополнен новыми operational artifacts под `.p3-vps-run/`, исправлением IPv4 chain-counter normalization в `scripts/p3-amnezia-peer-guard.py` и соответствующими Python regression tests. Остальные правила parser и historical evidence сохраняются. Дополнительный policy-only live diagnostic не является обязательным gate; штатный collector сохраняет свои IPv6 samples и invariants.

| Условие | Текущее evidence | Что требуется |
| --- | --- | --- |
| Offline runtime safety | Независимый GO; 248 Pester и repository verification passed | Сохранить принятую реализацию |
| Причина policy drift | Новый collector сохранил 23 поля; четыре изменения включают новый payload и policy-dependent hashes | Принять текущее наблюдаемое состояние явно, не объявляя исторические rules неизменными |
| Новый prerequisite | V1 receipt истёк; V2 drift fail; V3 transport fail; compact V4 technical GO, NOT EXECUTED | Получить fresh Cloud evidence; выполнить V4 с полным совпадением 27 полей двух snapshots |
| 6.4L | Runtime V5 templates technical GO; package/runtime отсутствуют | Из свежего receipt сформировать exact `PreparePlan`, независимо проверить bindings, зафиксировать controller authorization и выполнить Prepare/Validate |
| 6.4R-pre/P/post | Не выполнялись | Прочитать состояние helper, согласовать точный install/attestation plan, выполнить и сверить baseline |
| Приёмка фазы | NO_GO | Защищённые receipts, helper identity/owner/mode, согласованный baseline, ноль leftovers/agents и независимый GO |

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
