# AGENTS.md — Home Gateway

Этот файл — краткий operational context для Codex и субагентов. Его цель — не перечитывать всю спецификацию и не тратить токены на повторные исследования.

## Язык и стиль

- Всегда отвечать по-русски.
- Код, identifiers и технические термины — на English.
- Писать лаконично, без повторного резюме и больших вставок из уже прочитанных файлов.

## Sources of truth

Читать в таком порядке и только по необходимости:

1. `AGENTS.md` — рабочие правила.
2. Task brief, переданный controller.
3. Файлы, перечисленные в task brief.
4. `STATUS.md` и `DECISIONS.md` — текущее состояние и принятые решения.
5. Текущий phase plan в `docs/superpowers/plans/`.
6. `PLAN.md` и `SPEC.md` — только когда brief не даёт ответа или нужен exact requirement.

Не перечитывать `SPEC.md` целиком для локальной задачи. Сначала использовать `rg` по конкретным терминам и открывать небольшой релевантный диапазон.

## Экономный workflow

- Один implementation subagent на фазу и один consolidated reviewer после реализации всей фазы.
- Не запускать полный test/lint/build suite после каждого изменения.
- Во время реализации применять только дешёвую focused-проверку, без которой опасно продолжать: parser, syntax check или один regression test.
- Полный suite запускать один раз в конце фазы, затем исправить найденное и повторить только затронутые проверки плюс финальный suite.
- Не дублировать tool output в chat и report. В report оставлять command, exit code и короткий существенный fragment.
- Не вставлять большие файлы в prompt. Передавать task brief, report и diff-package через paths.
- Не делать повторный web research для уже pinned facts. Проверять интернет только если значение изменяемо, отсутствует в lock или есть конкретное сомнение.
- Не создавать speculative abstractions и файлы вне phase scope.

## Рабочий цикл фазы

1. Controller утверждает phase plan и branch/worktree.
2. Implementer выполняет phase tasks последовательно и делает логические commits.
3. В конце implementer запускает полный verification gate и пишет один phase report.
4. Read-only reviewer проверяет весь phase diff: spec compliance, quality, security и tests.
5. Один fix pass закрывает все Critical/Important findings.
6. После повторного review controller push-ит branch.

## Git

- Не работать с feature implementation на `main`.
- Использовать branch `phase/<phase-name>` и отдельный worktree.
- Stage только explicit paths; не использовать `git add -A` в mixed worktree.
- Не переписывать history и не применять destructive commands.
- Субагент не делает push. Push выполняет controller после phase review.
- Текущий remote: `git@github.com:n1ck8131/home_gateqay.git`.

## Safety invariants

- Не добавлять secrets, private keys, реальные credentials, profiles или backups в Git.
- Не менять firmware, WAN, firewall, DNS или routing вне явно указанной phase task.
- VPN-class traffic должен оставаться fail-closed; WAN default route в `main` не подменяется.
- Cisco policy не обходится. `work-pc` подключается напрямую к Flint 2 по Ethernet или Flint Wi-Fi и никогда через repeater.
- Hardware mutations требуют explicit confirmation, strict SSH host-key verification и rollback.

## Platform conventions

- Основная локальная shell: Windows PowerShell 5.1; PowerShell 7 используется дополнительно.
- Перед редактированием существующего файла прочитать его.
- Для ручных edits использовать `apply_patch`.
- Python: `str | None` вместо `Optional[str]`.
- User-visible строки хранить в `labels.py` или `constants.py`.
- В конце фазы: `ruff check .`, `ruff format --check .` и все существующие tests. Если Python-файлов нет, записать `RUFF_NOT_APPLICABLE_NO_PYTHON`.
- Вся конфигурация Codex находится только в `C:\Users\vsevo\AI-core\.Codex\`; не создавать `C:\Users\vsevo\.Codex\`.

## P0 commands после bootstrap

```powershell
.\scripts\dev.ps1 -Command verify
```

```sh
make PWSH=./.tools/pwsh/pwsh verify
```

До появления этих entrypoints использовать только exact commands из P0 phase plan.
