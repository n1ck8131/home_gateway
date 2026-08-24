# Довести Windows-приложение до собственного VPN на DigitalOcean

Status: planned for 2026-08-26

Этот план продолжает текущий P3.3. Сначала Windows PC работает через RedShield. Затем приложение получает управление, обновляемые списки и Cisco-aware routing. После этого P8 переводит тот же control plane на один собственный VPN-сервер DigitalOcean. Покупка роутера и домашняя сеть начинаются только после отдельного PC-first acceptance gate.

## Контракт документа

- **Тип**: execution plan
- **Аудитория**: владелец проекта и implementation agents
- **Одна задача**: довести текущий P3.3 до принятого Windows-приложения с одним собственным VPN
- **Canonical roadmap**: [PLAN.md](../../../PLAN.md)
- **Текущий phase plan**: [P3 RedShield-backed Windows pilot](2026-08-24-p03-redshield-windows.md)
- **Evidence status**: repository state и официальная документация DigitalOcean проверены 2026-08-25
- **Не входит в разрешение**: покупка Droplet, изменение Windows routes, DNS, firewall, adapters, RedShield или Cisco

## Зафиксированная последовательность

1. Завершить selective routing на Windows через текущий RedShield config.
2. Добавить локальное приложение управления, revisions, rollback и понятный status.
3. Отдельно исследовать GitHub-проекты со списками для РФ.
4. Реализовать безопасное обновление принятых списков.
5. Подтвердить работу direct, RedShield и Cisco без изменения Cisco config.
6. Развернуть один собственный VPN на DigitalOcean.
7. Переключить Windows-приложение с RedShield на собственный VPN без смены policy semantics.
8. Добавить учёт общего и per-peer трафика, прогноз лимита и уведомления.
9. Пройти PC-first acceptance и только затем покупать роутер.

RedShield остаётся bootstrap backend до успешной приёмки собственного VPN. Он не становится автоматическим fallback. Router work остаётся за P12.

## Целевой DigitalOcean baseline

Скриншот соответствует Basic Droplet Regular за $6 в месяц. По официальной странице на 2026-08-25 этот размер содержит 1 shared vCPU, 1 GiB RAM, 25 GiB SSD и 1,000 GiB transfer. Дополнительный outbound transfer стоит $0.01 за GiB. Эти значения остаются planning baseline до обязательной проверки `/v2/sizes` перед provisioning.

| Параметр | Плановый выбор | Gate |
|---|---|---|
| Size | Basic Regular, 1 vCPU, 1 GiB RAM, 25 GiB SSD | Подтвердить через `/v2/sizes` перед созданием |
| Image | Ubuntu 24.04 LTS x64 | Pin image slug и текущий image ID в deployment manifest |
| Region | AMS или FRA candidate | Выбрать после latency, packet-loss и availability preflight |
| Transfer | 1,000 GiB plan allowance | Показывать accrued team allowance, а не безусловный статический лимит |
| Public services | SSH и один UDP tunnel port | Не публиковать web panel, DNS resolver или proxy |
| Access | SSH key, non-root sudo, root password login disabled | Проверить recovery до закрытия initial SSH path |
| Firewall | DigitalOcean Cloud Firewall и host firewall | Правила должны совпадать и не образовывать неожиданный union |
| Backups | Отдельное решение перед production | Не считать выключенный Droplet бесплатным |

Official references:

- [Droplet pricing](https://www.digitalocean.com/pricing/droplets)
- [Linux images for Droplets](https://docs.digitalocean.com/products/droplets/details/images/)
- [Production-ready Droplet setup](https://docs.digitalocean.com/products/droplets/getting-started/recommended-droplet-setup/)
- [DigitalOcean Cloud Firewall rules](https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/)
- [Bandwidth billing](https://docs.digitalocean.com/platform/billing/bandwidth/)
- [DigitalOcean Acceptable Use Policy](https://www.digitalocean.com/legal/acceptable-use-policy)

1 GiB RAM достаточно только как стартовая гипотеза для одного AmneziaWG server, restricted `server-agent` и малой telemetry workload. P8 обязан измерить memory, CPU, packet loss, throughput и out-of-memory risk. Resize остаётся rollback-compatible capacity action, а не скрытым изменением бюджета.

## Phase 1: завершить P3.3 read-only foundation

Эта фаза закрывает безопасное наблюдение Windows state. Она не применяет routes или DNS.

### Scope

- заменить `route print` на structured `Get-NetRoute -PolicyStore ActiveStore`
- собирать interface metrics, route metrics и effective metric
- собирать effective DNS server state и NRPT summary без вывода corporate namespaces
- связывать adapters через stable `InterfaceGuid`; использовать `ifIndex` только внутри одного snapshot
- собирать numeric admin и operational status локального RedShield adapter
- запускать только absolute System32 PowerShell и absolute module manifests
- отделить local adapter status от provider handshake health
- оставить mutation API typed-unsupported

### Exit gate

- fixture tests отклоняют malformed, duplicate, stale и oversized snapshots
- реальный `Netherlands.conf` проходит read-only preflight без вывода keys или config path
- direct endpoint, RedShield binding, IPv4, IPv6 и Cisco state имеют явные findings
- apply остаётся недоступным

## Phase 2: завершить P3.4 offline apply, rollback и recovery

Эта фаза создаёт mutation engine, но не запускает его на текущей сети.

### Scope

- владеть только project-marked routes, firewall и DNS state
- хранить before-snapshot, candidate, confirmed revision и last-known-good state
- реализовать validate, stage, apply, post-check, commit-confirm и rollback
- оставить RedShield endpoint и protected system destinations на direct path
- не менять Cisco profile, service, adapter или OS-owned routes
- добавить emergency-disable и full restore plan

### Exit gate

- offline fixtures и isolated Windows test environment проходят fault injection
- process crash, timeout и failed post-check восстанавливают snapshot
- unowned state никогда не удаляется
- live canary остаётся заблокированным отдельным approval gate

## Phase 3: закрыть P3.5 и P3.6 на текущем PC

Эта фаза превращает RedShield foundation в первый рабочий PC dataplane.

### Scope

- выполнить отдельно подтверждённый bounded live canary
- проверить direct и RedShield egress, DNS, IPv4, IPv6, MTU, TCP, UDP и QUIC
- проверить tunnel-down fail-closed без утечки VPN-class traffic в WAN
- проверить adapter loss, service crash, restart, recovery и emergency disable
- проверить uninstall и восстановление pre-install state
- предоставить `enable`, `inspect`, `confirm`, `rollback`, `disable` и `restore`

### Exit gate

- `pc-core-ready`
- frozen `PC-DP-SAFE` regression suite
- RedShield остаётся активным bootstrap backend
- ни один тест не обходит Cisco policy

## Phase 4: реализовать P4 control plane

Эта фаза создаёт headless application core до web UI.

### Scope

- embedded database для policies, revisions, audits и telemetry metadata
- versioned loopback API и server-sent events
- dry-run diff до каждого apply
- optimistic concurrency и idempotency keys
- `hgctl` для inspect, explain, apply, confirm, rollback и emergency disable
- Windows service с restart reconciliation
- protected local storage для tokens и private configuration

### Exit gate

- полный headless flow работает на Windows PC
- active configuration меняется только через revision transaction
- restart восстанавливает только confirmed revision

## Phase 5: реализовать P5 Windows management application

Эта фаза даёт локальное web-приложение. Оно слушает loopback по умолчанию и использует P4 API.

### Основные экраны

- **Overview**: current backend, direct/VPN/Cisco status, active revision и safety alerts
- **Policies**: domains, CIDRs и manual overrides с explanation
- **Apply**: diff, validation, confirm timer и rollback
- **Sources**: freshness, accepted digest, diff и last-known-good source
- **Server**: VPN health, endpoint, version и last handshake
- **Traffic**: month usage, forecast, per-peer usage и data freshness
- **Recovery**: emergency disable, restore preview и support export

### Exit gate

- browser flow выполняет add, explain, dry-run, apply, confirm и rollback
- UI не показывает private keys, raw public keys, DigitalOcean token или config path
- screen-reader, keyboard и narrow-window smoke проходят
- traffic screen работает на deterministic fixtures до появления собственного VPS

## Phase 6A: исследовать GitHub-проекты со списками для РФ

Это отдельная read-only research phase. Она не загружает списки в active routing.

### Research questions

- что означает каждый список: blocked in РФ, available only in РФ, direct-only или другое
- какие данные представлены: domain, wildcard, CIDR, ASN, geosite или binary database
- кто формирует source of truth и как проверяется provenance
- есть ли immutable releases, commit pin, checksum или signature
- какова update cadence и история breaking changes
- какая license разрешает хранение, преобразование и распространение
- есть ли default routes, private ranges, bare suffixes, HTML error pages или poisoned entries
- сколько записей и сколько памяти займут parse, normalize, diff и apply
- как списки пересекаются и какой precedence требуется
- какие false positives видны на representative fixtures

### Candidate discovery

- начать с уже отмеченных Runet Freedom и Re:filter
- найти maintained GitHub alternatives и upstream dependencies
- не принимать stars, popularity или свежий commit как доказательство качества
- не исполнять converters, release binaries или GitHub Actions из исследуемых repositories

### Deliverables

- source scorecard с URLs, owner, license, format, semantics, cadence и immutable reference
- fixture-only comparison для accepted candidates
- ADR с решениями `accept`, `reject` или `observe`
- threat model для supply-chain, poisoning, takeover и anomalous diff

### Exit gate

- минимум один candidate для VPN class и один direct/protected candidate имеют доказуемую семантику
- ни один mutable branch URL не считается production artifact
- нерешённая license или provenance автоматически даёт `reject`

## Phase 6B: реализовать P6 source ingestion и обновления

Эта фаза автоматизирует только принятые источники из Phase 6A.

### Scope

- bounded streaming parsers и isolated converters
- immutable download, digest verification и schema validation
- normalize, deduplicate, precedence resolution и effective diff
- reject HTML, empty files, default routes, private ranges и anomalous change size
- stage new revision и требовать review policy до activation
- сохранять last-known-good source при любой ошибке
- использовать direct, active VPN, immutable mirror и manual upload fallback chain

### Exit gate

- broken или compromised upstream не меняет active routing
- UI показывает source time, digest, additions, removals, conflicts и effective result
- 100,000-domain benchmark проходит PC resource budget или фиксирует blocking optimization decision

## Phase 7: подтвердить P7 Cisco coexistence

Эта фаза наблюдает Cisco и сохраняет его OS-owned behavior.

### Scope

- собирать adapters, routes, DNS, suffixes, NRPT и endpoint metadata read-only
- различать Cisco off, split tunnel, full tunnel и stale state
- оставлять Cisco endpoint direct
- запрещать unsafe `always-vpn`, пока Cisco state не определён
- показывать диагноз в UI, не меняя Cisco config

### Exit gate

- split-tunnel flow сохраняет internal routes и Cisco endpoint
- full-tunnel flow подтверждает только diagnosis и non-interference
- Cisco workday soak не показывает reconnect или route churn, вызванный проектом

## Phase 8A: подготовить и развернуть DigitalOcean Droplet

Эта фаза создаёт billable resource только после отдельного подтверждения.

### User inputs at the gate

- DigitalOcean account с настроенным billing
- выбранный region после latency preflight
- SSH public key; private key не передаётся в chat
- локально сохранённый scoped API token, если automation использует DigitalOcean API
- подтверждение $6 monthly plan и возможного transfer overage

### Scope

- pin image, size, region и deployment artifact hashes
- создать Droplet idempotently через reviewed `doctl` или API plan
- создать non-root operator и отключить password/root SSH login
- применить Cloud Firewall до публикации tunnel port
- установить signed or checksummed AmneziaWG artifacts
- запустить restricted `server-agent` через forced SSH command без `shell.exec`
- настроить automatic security updates, time sync, log rotation и recovery access
- запретить open proxy и open recursive DNS

### Exit gate

- повторный provision не меняет healthy server
- unknown command, malformed JSON и replay отклоняются
- только registered peer keys могут передавать traffic
- backup и full rebuild восстанавливают server без копирования private keys в repository

## Phase 8B: переключить Windows с RedShield на собственный VPN

Эта фаза меняет только `TunnelBackend`. Policy, UI и routing semantics остаются прежними.

### Scope

- создать отдельный PC peer
- установить endpoint-direct route до DigitalOcean server
- проверить handshake, egress, DNS, IPv6, MTU и fail-closed
- сравнить решения RedShield и self-hosted backend на общих fixtures
- сохранить RedShield как manual diagnostic option на период миграции
- rollback возвращает confirmed RedShield revision без автоматического переключения

### Exit gate

- self-hosted VPN становится primary backend
- полный `PC-DP-SAFE` проходит без policy regression
- RedShield больше не требуется для normal operation

## Phase 8C: добавить traffic accounting и прогноз

Эта фаза реализует данные, похожие на второй скриншот. Web UI является primary surface. Telegram notification остаётся optional read-only adapter поверх того же API.

### Источники данных

```text
Windows application
├─ restricted server-agent: AmneziaWG per-peer counters and handshakes
├─ server host counters: public interface ingress and egress deltas
├─ DigitalOcean Monitoring API: sampled public bandwidth cross-check
└─ local database: history, aggregation, forecast and alert state
```

`server-agent` читает counters и возвращает allowlisted JSON. DigitalOcean API token хранится только на Windows PC в protected storage. Server не получает billing token.

### Метрики в приложении

| Группа | Поля |
|---|---|
| Server | alias, region, masked IP, status, version, uptime, last sample |
| Transfer | estimated public egress, accrued allowance, percent, remaining estimate |
| Forecast | GiB per day, projected calendar-month GiB, estimated overage |
| VPN | total RX, TX, current throughput, latest handshake |
| Peer | local alias, RX, TX, total, last handshake, freshness |
| Quality | counter resets, missing intervals, server/API discrepancy, stale-data warning |

### Семантика расчётов

- `peer_logical_usage = positive_delta(rx_bytes) + positive_delta(tx_bytes)` показывает двусторонний VPN payload конкретного peer
- `server_public_egress = positive_delta(public_interface_tx_bytes)` оценивает outbound usage относительно DigitalOcean allowance
- DigitalOcean public outbound samples дают третий independent billing cross-check, а не точный invoice total
- UI показывает эти три величины отдельно и никогда не складывает host egress с peer totals
- сумма per-peer traffic не обязана совпадать с server public egress из-за SSH, updates, retransmits и tunnel overhead
- allowance учитывает Droplet lifetime и DigitalOcean 28-day accrual formula
- team transfer pool отображается отдельно от per-Droplet estimate
- counter reset после reboot или interface recreate начинает новую generation и не создаёт отрицательный usage
- timestamps хранятся в UTC; UI форматирует их в local timezone

### Privacy and retention

- не сохранять packet payloads, visited domains, DNS answers или public keys в telemetry store
- связывать peer с локальным alias через opaque peer ID
- хранить raw intervals ограниченное время и агрегировать старые данные
- показывать freshness и incomplete intervals рядом с прогнозом
- support export содержит aggregates без IP, token, key и endpoint secrets

### Alerts

- 50%, 75%, 90% и 100% accrued allowance
- projected overage до конца billing period
- stale telemetry
- server unavailable
- peer без handshake дольше configured threshold
- расхождение server estimate и DigitalOcean cross-check выше принятого порога

### Exit gate

- fixture tests покрывают reboot, reset, duplicate sample, missing sample и month boundary
- каждый per-peer logical total равен сумме accepted RX/TX deltas без double count
- server public egress считается отдельно и не выводится из суммы peer totals
- UI показывает usage, limit, percent, pace, forecast, remaining days и per-peer breakdown
- Telegram, если включён, только читает агрегаты и не получает management token

## Phase 8D: принять PC application с одним собственным VPN

Эта фаза завершает requested milestone. Она не начинает router work.

### Acceptance matrix

- direct, VPN и Cisco decisions совпадают с policy explanations
- tunnel failure не отправляет VPN-class traffic в direct route
- DNS и IPv6 leak tests проходят
- restart восстанавливает confirmed state
- update и uninstall имеют rollback и full restore
- source outage сохраняет last-known-good lists
- server rebuild и client re-enrollment проходят runbook
- traffic totals переживают service и server restart без silent loss или double count
- 1 GiB Droplet выдерживает measured workload или resize decision задокументирован
- минимум один многодневный soak не показывает unexplained route churn, OOM или counter drift

### Exit gate before router purchase

Router purchase разрешается только после принятого PC application и own-VPS evidence bundle. Текущий master roadmap также содержит P9 multi-server, P10 TCP fallback и P11 installer, backup и hardening. Их нельзя молча удалить из `pc-first-qualified`: перед покупкой router нужно либо завершить P9–P11, либо отдельно утвердить narrower single-server gate и обновить `PLAN.md`.

## Завтрашний execution slice

26 августа не следует обещать завершение всех фаз. Live canary, reboot, Cisco soak и billable provisioning требуют отдельных gates и реального времени наблюдения.

Завтрашняя последовательность:

1. Закрыть software scope P3.3 и повторить redacted read-only preflight.
2. Зафиксировать P3.4 ownership, transaction и rollback contracts; начать offline tests.
3. Создать Phase 6A source scorecard и candidate discovery protocol.
4. Зафиксировать P8 provisioning, server-agent и telemetry data contracts.
5. Подготовить DigitalOcean create plan без создания Droplet.
6. Выпустить end-of-day gate report с passed evidence, blockers и следующим approval request.

Ожидаемый результат дня: P3.3 software-complete или точный blocker; P3.4 implementation started; GitHub research protocol; reviewed DigitalOcean and traffic-accounting design. Готовое приложение, live traffic mutation и работающий billable VPN не являются обещанием одного дня.

## Approval gates

| Gate | Требует отдельного подтверждения |
|---|---|
| Windows live canary | Да |
| RedShield restart or disconnect | Да |
| Cisco state change | Не разрешается этим планом |
| Droplet creation and billing start | Да |
| DigitalOcean API token use | Да, token остаётся локальным |
| Self-hosted backend activation | Да |
| Router purchase | Да, после pre-router acceptance |

## Open decisions

- выбрать AMS или FRA после измерения с текущего connection
- включать DigitalOcean backups или использовать independent encrypted backup
- нужен ли Telegram read-only notifier в первом own-VPS milestone
- сохранять ли обязательные P9 second-VPS и P10 fallback gates до router purchase
- определить retention и alert thresholds после первого telemetry benchmark
