# Home Gateway: умная выборочная маршрутизация для OpenWrt, AmneziaWG и Cisco Secure Client

**Статус:** техническое задание для реализации с нуля в пустом репозитории  
**Версия:** 1.0  
**Дата фиксации требований:** 2026-07-11  
**Основная платформа:** GL.iNet Flint 2 / GL-MT6000 + OpenWrt 25.12.x  
**Язык интерфейса и документации:** русский; идентификаторы, API и код — английский

---

## 0. Инструкция для Codex

Ты выступаешь как ведущий инженер проекта. Не ограничивайся прототипом: создай воспроизводимую, тестируемую и безопасно обновляемую систему, которую можно установить и администрировать с компьютера Windows.

Перед написанием кода:

1. Прочитай этот документ полностью.
2. Создай `PLAN.md`, `STATUS.md`, `DECISIONS.md` и каталог `docs/adr/`.
3. Зафиксируй архитектурные решения в ADR, особенно:
   - выбор VPN-реализации;
   - интеграцию с OpenWrt `netifd`, `firewall4`, `nftables` и `dnsmasq-full`;
   - модель хранения секретов;
   - механизм транзакционного применения и отката;
   - механизм управления peer-профилями AmneziaWG;
   - модель обнаружения Cisco-маршрутов на Windows.
4. Реализуй проект небольшими логическими коммитами.
5. Все команды установки и обновления должны быть идемпотентными.
6. Не используй `latest` в production-конфигурациях. Версии, образы, пакеты и SHA-256 должны быть зафиксированы в lock-файле/manifest.
7. Не выполняй загруженные из интернета shell-скрипты. Внешние списки являются **данными**, а не исполняемым кодом.
8. Не изобретай VPN-протокол, криптографию или собственный шифр. Используй официальные реализации AmneziaWG и XRay/sing-box как внешние компоненты.
9. Не изменяй политики Cisco Secure Client, не подменяй корпоративные сертификаты, не инспектируй TLS и не пытайся обходить корпоративные средства контроля.
10. Не помещай пароли, приватные ключи, мобильные профили и полные резервные копии в Git.
11. Не считай работу завершённой, пока не выполнены критерии приёмки из этого документа.

При недостатке конкретного пользовательского значения создай безопасный шаблон и интерактивный запрос в установщике. Не хардкодь секреты и не блокируй разработку вопросами, на которые можно ответить разумным значением по умолчанию.

---

# 1. Цель проекта

Создать домашний шлюз, который автоматически и предсказуемо разделяет трафик:

- обычные и российские ресурсы — напрямую через интернет-провайдера;
- ресурсы, заблокированные в России или ограничивающие российские IP, — через личный зарубежный VPN;
- корпоративные ресурсы — через Cisco Secure Client на рабочем Windows-компьютере либо напрямую через российский WAN, если это публичный рабочий портал;
- мобильные устройства вне дома — напрямую подключаются к тому же личному серверу через приложение AmneziaWG/совместимый клиент;
- администрирование выполняется с Windows через локальную Go-панель.

Главный пользовательский результат:

```text
Дома:

обычный/российский сайт         -> WAN Ростелекома
заблокированный ресурс          -> выбранный зарубежный VPN-сервер
внутренний SAP/Jira/Wiki        -> Cisco на Windows -> корпоративная сеть
публичный рабочий SSO/портал    -> WAN Ростелекома

Вне дома:

iPhone/Mac/iPad -> AmneziaWG -> личный VPS -> Интернет
```

Система должна переживать блокировки VPN, недоступность GitHub/raw-ресурсов, повреждённые внешние списки, падение одного VPS, обновление IP/CDN и ошибочную конфигурацию без утечки VPN-классифицированного трафика в WAN.

---

# 2. Что предоставляет пользователь

Пользователь предоставляет только:

1. **Роутер** — рекомендуемая и целевая модель GL.iNet Flint 2 / GL-MT6000.
2. **Один зарубежный VPS** на первом этапе; архитектура сразу поддерживает два и более.
3. Доступ к текущему роутеру/ONT Ростелекома и параметры WAN, если они требуются:
   - DHCP, PPPoE или статический адрес;
   - логин PPPoE;
   - VLAN ID;
   - параметры IPTV/VoIP, если используются.
4. Windows-компьютер с Cisco Secure Client для администрирования.
5. При установке — публичные IP/имена VPS, SSH-доступ и желаемые имена Wi-Fi.

Секреты вводятся интерактивно установщиком и никогда не записываются в репозиторий.

---

# 3. Что должен создать Codex

Codex должен разработать и упаковать:

1. Go-сервис `routerd`, работающий на OpenWrt:
   - веб-панель;
   - локальный API;
   - управление правилами;
   - управление VPN-серверами;
   - мониторинг;
   - обновление внешних списков;
   - управление мобильными peer-профилями;
   - резервное копирование и восстановление;
   - транзакционное применение и откат.
2. Go-утилиту `server-agent` для VPS:
   - установка и проверка AmneziaWG;
   - добавление/отзыв peer;
   - состояние туннеля;
   - экспорт зашифрованного серверного состояния;
   - управление резервным транспортом;
   - строго ограниченный командный интерфейс через SSH.
3. Windows-агент `cisco-discovery.exe` и PowerShell-обвязку:
   - сбор сетевого состояния до/после подключения Cisco;
   - обнаружение корпоративных маршрутов, DNS-суффиксов и VPN endpoint;
   - безопасная передача кандидатов в `auto-cisco`;
   - диагностика конфликтов.
4. PowerShell-установщик для всего решения.
5. Пакет OpenWrt `routerd.apk` для `aarch64_cortex-a53`/целевой архитектуры GL-MT6000.
6. Воспроизводимый серверный deployment bundle.
7. Документацию, recovery-инструкции, тесты, CI, SBOM и подписанные release-артефакты.

---

# 4. Непереговорные архитектурные принципы

## 4.1. Маршрут по умолчанию — WAN

VPN не должен становиться системным default route OpenWrt.

Для AWG-интерфейсов:

```text
AllowedIPs = 0.0.0.0/0, ::/0
route_allowed_ips = 0
```

Маршрутизация в VPN выполняется только метками/таблицей маршрутов, сформированными `routerd`.

## 4.2. Control plane и data plane разделены

**Control plane:** собственный Go-код, панель, API, компилятор списков, ревизии, проверки и rollback.

**Data plane:** проверенные системные компоненты:

- OpenWrt `netifd`;
- `firewall4`;
- `nftables`;
- `dnsmasq-full` с nftset;
- официальные AmneziaWG kernel module/tools;
- при необходимости отдельный `sing-box`/XRay TUN для TCP-fallback.

Go-код не реализует шифрование и не проксирует пользовательский трафик сам.

## 4.3. Только один владелец policy routing

В production-режиме нельзя одновременно запускать `routerd`, `pbr`, Podkop, HomeProxy, mwan-плагины или другие сервисы, изменяющие те же `nftables`/`ip rule` цепочки.

`routerd` должен при установке:

- обнаруживать конфликтующие сервисы;
- останавливать установку до явного решения пользователя;
- уметь импортировать простые правила из `pbr`, но не работать параллельно с ним.

## 4.4. Fail closed только для VPN-класса

Если VPN недоступен:

- трафик из эффективного списка `vpn` блокируется;
- обычный WAN, российские сервисы, Cisco endpoint и работа продолжают работать напрямую;
- пользователь видит понятное состояние и причину.

Нельзя применять глобальный killswitch, отключающий весь домашний интернет.

## 4.5. Рабочий Cisco не вкладывается в домашний VPN

Пакеты к Cisco VPN gateway всегда должны идти напрямую через WAN.

Корпоративные сети, добавленные Cisco в таблицу маршрутов Windows, обрабатываются самой Windows и обычно вообще не видны домашнему роутеру в открытом виде.

Техническая гарантия системы: Cisco endpoint и одобренные рабочие порталы не маршрутизируются через зарубежный VPS. Система не обещает скрыть сетевую активность от корпоративного EDR/агента, установленного непосредственно на компьютере.

## 4.6. Транзакционное применение

Любое изменение проходит:

```text
Desired state
  -> нормализация
  -> разрешение конфликтов
  -> staging
  -> syntactic validation
  -> snapshot
  -> atomic apply
  -> post-check
  -> commit revision

при ошибке -> automatic rollback to last-known-good
```

Нельзя напрямую редактировать активный конфиг без staging и резервной копии.

## 4.7. IPv6 — часть проекта

Нельзя настроить только IPv4 и оставить неконтролируемый IPv6.

Допустимы два режима:

1. полноценная IPv4/IPv6 маршрутизация через VPN;
2. управляемое блокирование IPv6 для VPN-класса до появления IPv6 на VPS.

Утечка VPN-домена по IPv6 при маршрутизации IPv4 через VPN считается критической ошибкой.

---

# 5. Логическая архитектура

```text
                                  +-----------------------------+
                                  | VPS #1: nl-1                |
                                  | AmneziaWG 2 primary         |
                                  | XRay Reality TCP fallback   |
                                  | DNS for mobile peers        |
                                  | restricted server-agent     |
                                  +---------------+-------------+
                                                  |
                                  +---------------+-------------+
                                  | VPS #2: optional            |
                                  | another provider / ASN      |
                                  | another country             |
                                  +---------------+-------------+
                                                  |
Internet / Rostelecom ONT ---- GL-MT6000 / OpenWrt / routerd ---- Wi-Fi/LAN
                                  |       |       |
                                  |       |       +-- Home-VPN subnet
                                  |       +---------- Home-Direct subnet
                                  +------------------ Home / automatic subnet

Windows work PC on Home:
  Cisco routes/internal DNS -> Cisco virtual adapter
  public work portal        -> router -> WAN
  blocked public site       -> router -> selected VPN

Windows admin components:
  browser -> https://router.home.arpa:8443
  cisco-discovery.exe -> authenticated local API
  PowerShell installer/backup client -> SSH/API
```

---

# 6. Маршрутные классы и приоритеты

Пользователь видит три основных списка, но система содержит также защищённый системный класс.

## 6.1. `system-direct` — скрытый, обязательный

Назначение: предотвратить рекурсивный VPN, потерю управления и поломку базовых сервисов.

Содержит:

- IP/FQDN всех VPN-серверов;
- SSH endpoints серверов;
- Cisco VPN gateway;
- выбранные DNS/DoH/DoT endpoints;
- NTP endpoints;
- адреса обновлений/зеркал, необходимые для восстановления;
- локальные сети и адрес самого роутера;
- endpoints резервного копирования.

Редактируется только через специализированные формы, а не как обычный текстовый список.

## 6.2. `auto-cisco` — рабочие исключения

Назначение: гарантировать российский/корпоративный egress для рабочих ресурсов.

По умолчанию применяется **только к рабочему Windows-компьютеру**, идентифицированному по DHCP reservation + MAC/client-id.

Содержит:

- публичный FQDN/IP Cisco gateway;
- корпоративные SSO/auth endpoints;
- публичные Jira/Wiki/SAP/VDI/почтовые порталы, которые не входят во внутренние маршруты Cisco;
- одобренные корпоративные DNS-суффиксы;
- вручную подтверждённые пользователем домены.

Внутренние сети `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` и маршруты Cisco отображаются для диагностики, но не добавляются в домашнюю WAN-маршрутизацию.

## 6.3. `direct` — явные WAN-исключения

Назначение: переопределить внешние VPN-списки и гарантировать российский IP.

Примеры:

- банки;
- Госуслуги;
- российские стриминговые сервисы;
- магазины и сервисы, блокирующие иностранные IP;
- категория `ru-available-only-inside` из доверенного источника;
- пользовательские исключения.

Поскольку default route уже WAN, этот список нужен прежде всего для разрешения конфликтов с внешними VPN-источниками.

## 6.4. `vpn` — выбранный зарубежный outbound

Содержит:

- заблокированные в России домены;
- сервисы, ограничивающие российские IP;
- пользовательские домены;
- опциональные CIDR;
- записи доверенных внешних источников.

## 6.5. Порядок принятия решения

Для устройства в режиме `auto`:

```text
1. local/reserved destinations -> local
2. system-direct               -> WAN
3. auto-cisco for work PC      -> WAN
4. manual most-specific rule   -> route selected by user
5. external direct             -> WAN
6. external vpn                -> active VPN
7. default                     -> WAN
```

Дополнительные правила:

- более специфичный домен выигрывает у родительского;
- более длинный CIDR prefix выигрывает у короткого;
- ручное правило выигрывает у внешнего источника;
- при неразрешимом конфликте общего IP/CDN приоритет получает `direct`, чтобы рабочий/российский ресурс не вышел через иностранный IP;
- конфликт обязательно показывается в UI.

Пример:

```text
example.com             -> VPN
login.example.com       -> DIRECT
```

`login.example.com` должен идти напрямую.

## 6.6. Режимы устройств/SSID

Поддержать:

- `auto` — списки и default WAN;
- `always-direct` — всё через WAN, кроме локальной сети;
- `always-vpn` — всё через активный VPN, кроме `system-direct` и явно разрешённых device exceptions.

Создать три подсети/SSID:

```text
Home          -> auto
Home-Direct   -> always-direct
Home-VPN      -> always-vpn
```

Служебные SSID можно скрыть, но они должны оставаться доступными для диагностики.

Рекомендуемые подсети:

```text
Home          192.168.10.0/24
Home-Direct   192.168.20.0/24
Home-VPN      192.168.30.0/24
Guest         192.168.40.0/24  # optional, isolated
```

---

# 7. Аппаратная и сетевая база

## 7.1. Роутер

Целевая модель:

```text
GL.iNet Flint 2 / GL-MT6000
CPU: MediaTek quad-core 2 GHz
RAM: 1 GB
Storage: 8 GB eMMC
Ports: 2 x 2.5G + 4 x 1G
Wi-Fi 6
```

Целевая версия на дату этого ТЗ — OpenWrt 25.12.5. Использовать последнюю проверенную стабильную версию ветки 25.12 только после прохождения compatibility suite. OpenWrt 25.12 использует `apk`.

Не выполнять автоматический major/minor upgrade OpenWrt. Kernel module AmneziaWG должен совпадать с ядром. Панель лишь показывает обновление и запускает управляемую процедуру:

```text
compatibility check -> backup -> package verification -> upgrade -> smoke tests -> commit/rollback
```

## 7.2. VPS

Минимум для каждого сервера:

```text
2 vCPU preferred, 1 vCPU minimum
2 GB RAM preferred, 1 GB minimum
20 GB disk
public static IPv4
IPv6 strongly preferred
network >= 500 Mbps
traffic >= 2 TB/month, preferably 5 TB+
Debian 13/12 or supported Ubuntu LTS
```

Второй сервер должен находиться у другого провайдера/ASN и желательно в другой стране. Два VPS в одном дата-центре не считаются полноценным резервированием.

## 7.3. Ростелеком

Установщик должен поддерживать два режима:

1. **Безопасный первый запуск:** Flint 2 за роутером/ONT Ростелекома; двойной NAT допустим для исходящих AWG и Cisco.
2. **Основной шлюз:** Flint 2 получает WAN напрямую через DHCP/PPPoE/VLAN; устройство Ростелекома работает как bridge/ONT.

Нельзя автоматически отключать старый роутер до проверки:

- PPPoE/VLAN;
- IPTV multicast/IGMP;
- VoIP;
- прямого доступа в интернет;
- recovery-пути.

## 7.4. Xiaomi-ретранслятор

Глобальная доменная маршрутизация должна работать независимо от ретранслятора.

Обязательная диагностика:

- сохраняет ли ретранслятор реальные MAC/IP клиентов;
- работает ли он как bridge, proxy-ARP или NAT;
- видит ли роутер рабочий Windows-компьютер как отдельное устройство.

Если ретранслятор скрывает клиентов за одним MAC/IP:

- per-device policy и scoped `auto-cisco` за ним ненадёжны;
- рабочий компьютер рекомендуется подключить напрямую к Flint 2, по Ethernet или через полноценную точку доступа/mesh с bridge;
- сам ретранслятор всё равно можно использовать для обычного `Home`.

Не обещать, что один «мощный» роутер гарантированно пробьёт железобетонные стены. В будущем предпочтителен проводной access point/mesh backhaul.

---

# 8. Программный стек

## 8.1. На OpenWrt

Обязательные компоненты:

```text
OpenWrt 25.12.x
firewall4 / nftables
netifd
ubus / uci
dnsmasq-full
https-dns-proxy or equivalent local encrypted upstream adapter
official AmneziaWG OpenWrt module/tools
curl only for diagnostics, not for executing installers
ca-bundle
routerd (Go)
```

Опциональный fallback:

```text
sing-box or XRay-compatible TUN adapter
```

Не устанавливать одновременно другой policy-routing manager.

## 8.2. На VPS

```text
Debian/Ubuntu
nftables
Docker/Podman only if required by the pinned official Amnezia deployment
official AmneziaWG 2 implementation
server-agent
Unbound or another local tunnel-only DNS resolver
XRay VLESS Reality on TCP/443 as optional independent fallback
systemd
SSH key authentication
```

## 8.3. На Windows

```text
PowerShell 7 preferred; Windows PowerShell 5.1 compatibility where practical
OpenSSH Client
browser
Cisco Secure Client
cisco-discovery.exe
optional Git for development only
```

---

# 9. Data plane на OpenWrt

## 9.1. Собственный минимальный routing backend

Основной backend должен использовать стандартные `nftables` + `ip rule`/routing tables. Не зависеть от внутренних имён цепочек стороннего проекта.

Пример логики:

```text
nft prerouting:
  local/reserved -> return
  destination in system_direct -> return
  work_pc + destination in auto_cisco -> return
  source subnet Home-Direct -> return
  source subnet Home-VPN -> set VPN_MARK
  destination in direct -> return
  destination in vpn -> set VPN_MARK
  otherwise -> return/default WAN

ip rule:
  fwmark VPN_MARK -> table routerd_vpn

table routerd_vpn:
  VPN healthy -> default dev active_awg
  VPN unhealthy -> blackhole default
```

Ключевое требование: при отсутствии маршрута lookup не должен проваливаться в `main` и утекать в WAN. Для этого при падении VPN в VPN-таблице должен оставаться terminal `blackhole/unreachable default`.

Поддержать IPv4 и IPv6 таблицы.

## 9.2. Интеграция с firewall4

Генерировать отдельный include, например:

```text
/usr/share/nftables.d/ruleset-post/50-routerd.nft
```

Не редактировать вручную основной файл `firewall4`.

Перед применением:

1. построить полный `fw4 print` со staging include;
2. выполнить `nft -c -f`;
3. проверить отсутствие пересечения с зарезервированными marks;
4. атомарно заменить include;
5. выполнить `fw4 reload`;
6. проверить chains, sets, rules и тестовые маршруты;
7. откатить при ошибке.

## 9.3. Метки соединений

Использовать `ct mark`, чтобы все пакеты одного соединения сохраняли выбранный outbound. Не менять маршрут активной сессии при каждом DNS update.

Зарезервировать собственную mask и проверять конфликты с SQM/QoS/mwan.

## 9.4. DNS-to-nftset

Клиенты получают роутер как DNS. `dnsmasq-full` добавляет A/AAAA-ответы доменов в соответствующие nft sets.

Требования:

- поддержка CNAME;
- TTL/timeout;
- A и AAAA;
- домены и поддомены;
- chunking конфигурации, чтобы не превышать длины аргументов/строк;
- рекомендуемый chunk — 500–1000 доменов, измерить и зафиксировать тестом;
- атомарная замена конфигурации;
- `dnsmasq --test` до reload;
- cache flush/prefetch только при необходимости.

## 9.5. Shared CDN limitation

Маршрутизация по DNS-IP не всегда различает два домена на одном IP/CDN.

Система должна:

- обнаруживать IP, одновременно попавшие в `direct` и `vpn`;
- показывать конфликт;
- защищать `direct` приоритетом;
- предлагать on-demand тест;
- поддерживать будущий `proxy-domain` adapter через sing-box/SNI/TUN для сложных доменов;
- не обещать безошибочное определение hostname без TLS MITM.

## 9.6. HTTP/3/QUIC

Правила должны быть protocol-agnostic или включать TCP и UDP. Нельзя строить маршрутизацию только на TCP/443.

## 9.7. MTU/MSS

Для каждого сервера хранить измеренный MTU. Реализовать безопасный probe и опциональный MSS clamp только для VPN-path.

Cisco трафик не должен попадать под VPN MSS/MTU правила.

---

# 10. VPN-архитектура с учётом России 2026

## 10.1. Основной транспорт

**AmneziaWG 2** — основной транспорт роутера и мобильных устройств.

Использовать только официальные репозитории/пакеты AmneziaWG. Версии kernel module, tools и server component должны быть совместимы и зафиксированы.

Не использовать обычный WireGuard как единственный production-транспорт.

## 10.2. Независимый fallback

На каждом VPS архитектурно предусмотреть второй транспорт:

```text
XRay VLESS Reality over TCP/443
```

Причина: блокировка/деградация UDP, сигнатур или конкретного endpoint не должна полностью останавливать доступ.

Fallback должен быть независим от AWG dataplane:

- отдельный процесс/контейнер;
- отдельная health-модель;
- отдельная конфигурация;
- отдельный TUN/outbound на роутере;
- переключение в панели.

MVP обязан иметь интерфейс адаптера и рабочий AWG. Production release должен включить рабочий TCP fallback до закрытия проекта.

## 10.3. Никакой гарантии «вечной неблокируемости»

В документации явно указать: любой протокол или IP может быть заблокирован. Устойчивость достигается сочетанием:

- собственного малопубличного VPS;
- AWG2;
- независимого TCP fallback;
- двух провайдеров/ASN;
- смены endpoint/port;
- локальных last-known-good конфигураций;
- отсутствия зависимости от одного GitHub URL.

## 10.4. Endpoint direct route

Для каждого VPN-сервера создавать host route через WAN и включать его в `system-direct` до поднятия туннеля.

Это правило не удаляется при переключении серверов.

## 10.5. Серверная сеть

Каждый VPS получает отдельный tunnel subnet, например:

```text
nl-1: 10.201.0.0/24
fi-1: 10.202.0.0/24
```

Peer получает уникальный `/32` и, при IPv6, `/128`.

На сервере:

- forwarding;
- nftables masquerade/SNAT;
- tunnel-only DNS;
- запрет peer-to-peer по умолчанию;
- минимальные логи без истории посещений;
- rate limiting;
- SSH passwords off;
- root login off после bootstrap;
- kernel updates не должны автоматически ломать AWG module.

---

# 11. Управление несколькими серверами

Панель должна поддерживать неограниченное число server profiles.

Для каждого сервера хранить:

```text
id
name
country
provider
ASN (detected/displayed)
public endpoints
transport capabilities
router peer
health state
latency/loss
handshake age
egress IPv4/IPv6/country
last success/failure
failure reason
MTU
priority
cost/traffic notes
```

## 11.1. Режимы выбора

- `manual` — пользователь выбирает сервер;
- `active-standby` — выбранный основной + резервные;
- `auto-health` — выбирается здоровый по приоритету, затем latency;
- `sticky` — не менять IP активной сессии без необходимости;
- `manual-sticky` — ручной выбор сохраняется, пока сервер здоров.

## 11.2. Health checks

Нельзя считать сервер здоровым только по ping.

Минимум:

1. интерфейс up;
2. свежий AWG handshake;
3. DNS через конкретный outbound;
4. TCP/TLS canary через конкретный outbound;
5. egress IP не равен WAN IP;
6. egress country ожидаемый;
7. packet loss/latency;
8. опциональный throughput micro-test с лимитом.

Использовать hysteresis:

```text
unhealthy after >= 3 consecutive failures
healthy after >= 2 consecutive successes
hold-down after switch >= 120 seconds
no automatic failback until stable >= 10 minutes
```

Значения конфигурируемы.

## 11.3. Безопасное переключение

1. Поднять candidate tunnel.
2. Выполнить health checks через него.
3. Атомарно заменить default route в `routerd_vpn` table.
4. Повторить egress check.
5. Зафиксировать revision.
6. При ошибке вернуть старый server.

Переключение VPN-сервера не должно менять WAN-маршрут Cisco.

---

# 12. Списки и модель данных

## 12.1. Типы entries

Поддержать:

- exact domain;
- suffix domain;
- wildcard domain;
- IPv4;
- IPv6;
- CIDR;
- category/reference to external rule set;
- device-scoped entry;
- temporary entry with expiration.

Пример модели:

```yaml
id: uuid
pattern: login.example.com
kind: domain
match: suffix
route: direct
scope:
  type: device
  device_id: work-pc
origin:
  type: manual
  source_id: null
comment: Corporate SSO
confidence: 1.0
enabled: true
created_at: 2026-07-11T10:00:00Z
expires_at: null
```

## 12.2. Нормализация

Обязательно:

- lowercase;
- trim;
- удаление схемы, path, query и port;
- IDNA/punycode;
- проверка Public Suffix List;
- запрет bare suffix вроде `com`, `ru`, `co.uk`;
- canonical CIDR;
- удаление duplicate/subsumed rules;
- комментарии и пустые строки;
- проверка wildcard;
- лимиты размера.

## 12.3. Разрешение конфликтов

Алгоритм должен быть детерминирован и покрыт unit/property tests.

Порядок:

1. `system-direct` immutable;
2. `auto-cisco` для соответствующего scope;
3. manual rule;
4. built-in curated direct;
5. external direct;
6. external VPN;
7. default direct.

Внутри одного уровня:

- most-specific domain/CIDR;
- explicit exact > suffix > wildcard;
- при полном совпадении последняя ручная операция заменяет предыдущую;
- внешние записи не удаляют manual override.

## 12.4. История

Каждое изменение создаёт revision с:

- автором/источником;
- diff;
- timestamp;
- результатом validation;
- результатом apply;
- состоянием post-check;
- rollback link.

---

# 13. Внешние источники списков

## 13.1. Поддерживаемые форматы

- plain domain list;
- hosts/adblock format;
- plain IP/CIDR;
- JSON/YAML descriptor;
- sing-box `.srs` через проверенный converter/reader;
- V2Ray `geosite.dat`/`geoip.dat` через изолированный converter;
- GitHub release asset selector;
- HTTP(S) с ETag/Last-Modified.

Парсер внешнего формата должен быть fuzz-tested.

## 13.2. Встроенные источники

Добавить как presets, но дать пользователю возможность отключить:

### VPN presets

1. `runetfreedom/russia-v2ray-rules-dat`:
   - `ru-blocked`;
   - `ru-blocked-community`;
   - категории популярных сервисов по выбору.
2. `1andrevich/Re-filter-lists`:
   - blocked domains;
   - `community.lst` для ресурсов, ограничивающих российские IP;
   - IP lists только opt-in.
3. `community.antifilter.download` — curated community list.

### Direct presets

1. `ru-available-only-inside` из `runetfreedom`.
2. Локальный curated список критических российских сервисов.
3. Ручные пользовательские overrides.

### Не включать по умолчанию

- `ru-blocked-all` на сотни тысяч доменов;
- полный `antifilter.download` без фильтрации;
- огромные IP-наборы CDN;
- BGP feed;
- рекламные списки, не относящиеся к маршрутизации.

Причина: расход RAM/flash, collateral routing, shared CDN и риск ложных срабатываний.

## 13.3. Безопасное обновление

Алгоритм:

```text
scheduled event + random jitter
  -> fetch direct
  -> if unavailable, fetch through active VPN
  -> if unavailable, try configured mirror/cache
  -> verify HTTPS/host
  -> verify checksum/signature when available
  -> enforce byte/line limits
  -> parse in sandboxed data path
  -> normalize
  -> compare with previous version
  -> safety gates
  -> stage
  -> optional approval / trusted auto-apply
  -> transactional apply
  -> retain last-known-good
```

## 13.4. Safety gates

Отклонять update, если:

- формат неожиданно изменился;
- загрузилась HTML error page;
- список пуст;
- количество записей изменилось более чем на заданный процент, например 50%, без ручного подтверждения;
- присутствует `0.0.0.0/0` или `::/0`;
- источник неожиданно добавил private/reserved ranges;
- обнаружен bare public suffix;
- размер превышает configured limit;
- SHA/signature не совпадает;
- источник старше допустимого срока.

Показывать diff: added, removed, conflicts, effective entries.

## 13.5. Обновление при блокировке GitHub

Роутер не должен зависеть от доступа к `raw.githubusercontent.com`.

Поддержать цепочку:

1. direct URL;
2. active VPN;
3. alternate mirror;
4. получение через `server-agent` по SSH;
5. загрузка файла с Windows через панель;
6. last-known-good без остановки маршрутизации.

UI и установщик не используют CDN для JavaScript/CSS — assets встроены в binary.

---

# 14. «Умное» поведение

Система не должна молча менять маршруты после одного неудачного запроса.

## 14.1. On-demand probe

Для домена панель умеет проверить:

- DNS через локальный resolver;
- direct TCP/TLS/HTTP HEAD;
- тот же тест через каждый VPN outbound;
- status code/category, без сохранения содержимого;
- latency;
- egress IP;
- TLS hostname/expiry;
- IPv4/IPv6.

Результат:

```text
direct works, VPN fails/403       -> suggest DIRECT
VPN works, direct blocked/reset   -> suggest VPN
both work                         -> keep current/default
both fail                         -> diagnostics, no route change
```

## 14.2. Safe auto-classification

По умолчанию только предложения.

Опциональный auto-mode допустим только для entries доверенного внешнего источника и требует:

- минимум 3 последовательных одинаковых наблюдения;
- cooldown;
- отсутствие manual override;
- отсутствие `auto-cisco`/`system-direct`;
- audit event;
- автоматический rollback при ухудшении.

Manual, work и system entries никогда не переклассифицируются автоматически.

## 14.3. Privacy

По умолчанию не хранить историю DNS-запросов/посещений.

Хранить только:

- агрегированные bytes/packets по route class;
- health metrics;
- результаты явно запущенных диагностик;
- краткосрочный debug log с автоматическим отключением/удалением.

---

# 15. Интеграция с Cisco Secure Client на Windows

## 15.1. Назначение

`cisco-discovery` не управляет Cisco и не меняет его профиль. Он только наблюдает сетевое состояние Windows и предлагает direct exceptions.

## 15.2. Что собирать

До подключения, после подключения и при network-change:

- `Get-NetAdapter`;
- `Get-NetIPConfiguration`;
- `Get-NetRoute` IPv4/IPv6;
- `Get-DnsClientServerAddress`;
- DNS suffix search list;
- `Get-DnsClientNrptPolicy`;
- active Cisco adapter/interface;
- Cisco gateway endpoint/FQDN/IP, если доступен;
- active sockets Cisco service/process с фильтрацией только endpoint metadata;
- Cisco client status через документированный CLI, если он установлен;
- public egress IP diagnostic по явному запросу.

Не собирать:

- логины/пароли;
- cookies;
- страницы браузера;
- TLS content;
- полный DNS browsing history;
- корпоративные документы.

## 15.3. Сравнение snapshots

```text
BeforeCisco vs AfterCisco
  -> added routes
  -> changed route metrics
  -> added DNS servers/suffixes/NRPT
  -> Cisco remote endpoint
  -> potential public corporate domains
```

## 15.4. Автоматически доверенные кандидаты

Можно автоматически добавить в `system-direct`:

- активный Cisco VPN gateway IP;
- подтверждённый FQDN gateway;
- IP, к которому подключён подписанный Cisco process;
- endpoint до установления туннеля.

## 15.5. Кандидаты с подтверждением

Публичные Jira/Wiki/SAP/SSO домены добавляются в `auto-cisco` после подтверждения, если они:

- соответствуют корпоративному suffix allowlist;
- найдены в NRPT/DNS suffix/profile;
- вручную введены пользователем;
- обнаружены в отфильтрованном DNS cache по корпоративным suffixes.

Не обещать магическое обнаружение SaaS-домена без корпоративного suffix или маршрута. Такой портал пользователь добавляет вручную один раз.

## 15.6. Scope

`auto-cisco` по умолчанию действует только для work PC.

Требования к identity:

- DHCP reservation;
- stable MAC/client-id;
- предупреждение о Windows Random Hardware Address для домашнего SSID;
- предупреждение, если Xiaomi repeater скрывает реальный source.

## 15.7. Проверка результата

Панель должна показывать:

```text
Cisco endpoint route: WAN
WAN public IP: Russian ISP
active VPN egress: expected foreign IP
corporate routes: handled by Windows/Cisco
public work portal: WAN or Cisco according to OS route
nested VPN detected: no
```

Если Cisco запрещает local LAN access, система не пытается обходить эту корпоративную политику. Администрирование выполняется при отключённом Cisco либо с разрешённого локального устройства.

---

# 16. Go-панель управления

## 16.1. Размещение

Панель работает на роутере и не требует включённого Windows-компьютера.

Адрес:

```text
https://router.home.arpa:8443
```

Требования:

- bind только на admin LAN/IP;
- firewall deny from WAN, Guest и VPN peers;
- локальный CA;
- Windows installer добавляет CA только в `CurrentUser` trust после показа fingerprint;
- self-contained HTML/CSS/JS;
- без CDN;
- responsive UI;
- русский интерфейс; английский optional.

Предпочтительный frontend:

```text
Go html/template + HTMX/малый vendored JS
```

Не тащить тяжёлый SPA runtime без необходимости.

## 16.2. Аутентификация

- initial admin enrollment через SSH/one-time token;
- Argon2id password hash;
- secure, HttpOnly, SameSite cookies;
- CSRF protection;
- session timeout;
- login rate limit;
- optional TOTP;
- audit login/logout/failures;
- password reset только через локальный SSH/recovery command.

## 16.3. Dashboard

Показывать:

- WAN state, IP, ISP/ASN/country;
- active server;
- transport;
- tunnel handshake;
- VPN egress IPv4/IPv6/country;
- latency/loss;
- DNS health;
- Cisco status from last Windows snapshot;
- counts direct/vpn/auto-cisco;
- source freshness;
- last applied revision;
- pending diff;
- backup age;
- OpenWrt/AWG compatibility warning;
- aggregate traffic by outbound;
- alerts.

## 16.4. Lists

Функции:

- search/filter;
- add/edit/delete/disable;
- bulk paste/import;
- route selector;
- scope selector;
- comments/tags;
- expiration;
- source attribution;
- conflict visualization;
- effective route preview;
- test domain through all paths;
- pending changes;
- Apply/Discard/Rollback.

## 16.5. External Sources

- presets;
- custom URL/release asset;
- format selector/auto-detect;
- route target;
- schedule+jitter;
- checksum/signature;
- line/size limits;
- last update/status;
- diff preview;
- enable/disable;
- manual refresh;
- mirror chain;
- trust mode: manual approval / trusted auto-apply.

## 16.6. Servers

- add/edit/remove;
- bootstrap status;
- manual activate;
- failover mode;
- transport list;
- health details;
- server diagnostics;
- rotate router peer;
- rotate endpoint/port;
- update check;
- traffic notes;
- maintenance mode.

## 16.7. Mobile Access

- create device peer;
- select one/all servers;
- one-time QR/config;
- profile name;
- expiration optional;
- allowed IP mode, default full tunnel;
- last handshake;
- Tx/Rx;
- disable;
- revoke;
- rotate;
- audit trail.

## 16.8. Devices

- DHCP leases;
- friendly names;
- reserved IP;
- current SSID/subnet;
- mode auto/direct/VPN;
- warning for hidden clients behind repeater;
- current aggregate route statistics.

## 16.9. Cisco

- agent enrollment;
- last snapshot;
- detected endpoint;
- added routes;
- DNS suffixes;
- candidates;
- approved `auto-cisco` entries;
- test direct egress;
- stale snapshot alert.

## 16.10. Backups

- Create encrypted backup;
- Download;
- Schedule;
- Retention;
- Verify;
- Restore dry-run;
- Restore;
- Export sanitized configuration without secrets.

## 16.11. Diagnostics

- route decision for domain/IP/device;
- DNS resolution and set membership;
- nft rules/counters;
- route tables;
- tunnel health;
- direct and VPN egress;
- MTU test;
- source fetch test;
- Cisco endpoint direct test;
- support bundle with secret redaction.

---

# 17. Мобильные peer-профили

## 17.1. Базовый формат

Основной формат — native AmneziaWG `.conf`, импортируемый в приложение **AmneziaWG** на iOS/macOS и совместимые клиенты.

Опциональный adapter для `vpn://`/полного AmneziaVPN реализовывать только после проверки актуального официального формата. Не выдавать full/admin access key.

## 17.2. Один peer — одно устройство

Нельзя повторно использовать один private key на нескольких устройствах.

Для каждого device/server pair:

- unique keypair;
- unique tunnel IP;
- name;
- created_at;
- optional expires_at;
- status;
- last handshake;
- bytes;
- revoked_at.

## 17.3. Private key handling

Предпочтительный поток:

1. keypair создаётся в памяти trusted component;
2. public key сохраняется на сервере;
3. private key включается в одноразовый config/QR;
4. one-time token живёт не более 10 минут;
5. после первого скачивания private material удаляется;
6. в DB остаётся только public key и metadata.

Если безопасная client-side генерация для выбранного клиента реализуема, предусмотреть режим «submit public key».

## 17.4. Отзыв

Revoke должен:

1. удалить peer из серверного AWG config;
2. применить config через `awg syncconf`/официальный механизм без полного простоя;
3. подтвердить отсутствие peer;
4. удалить one-time artifacts;
5. сохранить audit event;
6. прекратить доступ не позднее 10 секунд после успешной операции.

Удаление записи только из UI без изменения сервера недопустимо.

## 17.5. Mobile DNS

Мобильный full-tunnel профиль использует DNS на tunnel gateway/VPS, доступный только из VPN subnet. DNS-запросы не должны утекать в сеть мобильного оператора.

## 17.6. Несколько серверов

Панель умеет:

- выдать отдельный профиль на каждый server;
- показать, какой профиль основной/резервный;
- массово отозвать device на всех servers;
- в будущем сформировать совместимый multi-server subscription, если официальный клиент это надёжно поддерживает.

---

# 18. `server-agent`

## 18.1. Security model

Не поднимать публичный HTTP admin API на VPS.

`routerd` управляет VPS через SSH:

- отдельный ключ на server;
- host key pinning;
- user `vpnctl`;
- forced command;
- no shell;
- allowlisted JSON operations;
- минимальный sudoers;
- rate limit;
- audit journal.

Пример protocol:

```json
{"version":1,"request_id":"...","method":"peer.add","params":{...}}
```

Ответ:

```json
{"version":1,"request_id":"...","ok":true,"result":{...}}
```

## 18.2. Allowlisted methods

```text
status
health
transport.list
transport.configure
peer.list
peer.add
peer.disable
peer.revoke
peer.rotate
config.validate
backup.export
backup.verify
upgrade.check
```

Никакого метода `shell.exec`.

## 18.3. Транзакции на сервере

Изменение peer/config:

```text
lock -> backup -> render -> validate -> apply -> handshake/status check -> commit
                                              \-> rollback on failure
```

---

# 19. DNS и защита от обхода правил

## 19.1. Клиентский DNS

DHCP выдаёт только роутер как DNS.

TCP/UDP 53 с LAN можно перенаправлять на роутер, кроме:

- корпоративных пакетов внутри Cisco tunnel;
- явно разрешённых diagnostic devices;
- local resolver инфраструктуры.

## 19.2. Encrypted upstream

`dnsmasq-full` остаётся front resolver для nftset, а upstream encryption выполняет `https-dns-proxy`/эквивалент.

Поддержать несколько upstreams и health checks. Не зависеть от одного публичного resolver.

## 19.3. Client DoH/Private Relay

Панель диагностирует вероятный DoH/Private Relay/WARP, потому что они обходят dnsmasq-based domain routing.

Режимы:

- `observe/warn` — default;
- `enforce known DoH blocklist` — optional;
- device exception.

Не блокировать DoH вслепую на рабочем компьютере без подтверждения.

## 19.4. DNSSEC и poisoning

Использовать валидирующий/доверенный upstream. При direct DNS failure для заблокированного домена разрешить повтор через VPN upstream, сохраняя маршрутный класс.

---

# 20. Резервное копирование и восстановление

## 20.1. Формат

Единый versioned archive, зашифрованный `age` passphrase/recipient через Go-библиотеку.

Содержимое:

- routerd DB;
- manual lists;
- source descriptors и cached last-known-good;
- server metadata;
- encrypted router tunnel keys;
- OpenWrt UCI config subset;
- Wi-Fi/DHCP/firewall config;
- certificate/CA material;
- revision history;
- Cisco approved metadata;
- package/version manifest;
- server peer/config backup через `server-agent`, если выбран full backup.

Private mobile keys, уже выданные пользователю, не должны сохраняться, если их нет в active system state.

## 20.2. Retention

Default:

```text
7 daily
4 weekly
6 monthly
```

## 20.3. Targets

- download to Windows;
- Windows scheduled backup client;
- optional SFTP target;
- optional encrypted object storage adapter;
- Git only for sanitized non-secret export.

## 20.4. Restore

Перед восстановлением:

- decrypt verify;
- checksum;
- schema version;
- router model/architecture;
- OpenWrt compatibility;
- package compatibility;
- dry-run diff;
- emergency backup current state.

После восстановления — полный acceptance smoke test.

## 20.5. Recovery

Создать `docs/RECOVERY.md`:

- OpenWrt failsafe;
- возврат last-known-good nft include;
- отключение `routerd`;
- восстановление WAN/direct mode;
- recovery через Ethernet;
- возврат factory/sysupgrade image;
- восстановление из backup;
- смена admin password/SSH key.

---

# 21. Security requirements

## 21.1. Threat model

Учитывать:

- компрометацию внешнего list source;
- блокировку GitHub/raw;
- подмену release artifact;
- ошибочную конфигурацию;
- LAN attacker;
- украденный mobile profile;
- компрометацию одного VPS;
- VPN endpoint blocking;
- DNS poisoning;
- IPv6 leak;
- command injection через domain/comment/source URL;
- flash wear;
- потерю доступа после firewall reload.

## 21.2. Secrets

- `/etc/routerd/secrets/` mode `0700`;
- files `0600`;
- no secrets in logs;
- no secrets in support bundle;
- no secrets in command line/process list;
- no private keys in Git;
- encrypted backups;
- per-server SSH key;
- key rotation.

## 21.3. Supply chain

- pinned versions/digests/checksums;
- verify OpenWrt image SHA-256;
- verify own release signatures;
- generate `SHA256SUMS` and signature;
- SBOM SPDX/CycloneDX;
- `govulncheck`;
- dependency license report;
- `THIRD_PARTY_NOTICES.md`;
- no production `curl | sh`;
- Windows downloads bundle, verifies it, then uploads locally if router cannot reach source.

## 21.4. Command execution

Все external commands вызываются через `exec.CommandContext` с фиксированными аргументами. Не строить shell строки из пользовательского ввода.

## 21.5. Web security

- CSP;
- no inline unsafe scripts where practical;
- X-Frame-Options/frame-ancestors;
- HSTS только после корректной local CA установки;
- CSRF;
- input validation;
- upload size limits;
- session rotation;
- audit.

## 21.6. Least privilege

`routerd` может нуждаться в root на OpenWrt, но архитектурно отделить:

- read-only web/status code;
- privileged apply adapter;
- strict allowlist;
- procd sandbox/ujail, если совместимо;
- минимальный filesystem access.

---

# 22. Хранение состояния

Использовать SQLite с pure-Go driver либо другой embedded transactional store, обоснованный ADR.

Для SQLite:

- schema migrations;
- WAL/batched writes с учётом flash;
- periodic checkpoint;
- corruption check;
- backup API;
- no high-frequency metric writes в постоянное хранилище;
- ring buffer/`tmpfs` для коротких metrics.

Минимальные сущности:

```text
settings
servers
server_transports
peers
devices
route_entries
external_sources
source_versions
source_entries
cisco_snapshots
cisco_candidates
revisions
apply_runs
health_samples
audit_events
backups
secrets_metadata
```

Секретное содержимое хранится отдельно от основной DB либо шифруется ключом устройства.

---

# 23. Go-архитектура

## 23.1. Структура репозитория

```text
home-gateway/
├── SPEC.md
├── README.md
├── PLAN.md
├── STATUS.md
├── DECISIONS.md
├── Makefile
├── go.work
├── cmd/
│   ├── routerd/
│   ├── server-agent/
│   ├── cisco-discovery/
│   └── hgctl/
├── internal/
│   ├── api/
│   ├── auth/
│   ├── audit/
│   ├── backup/
│   ├── cisco/
│   ├── config/
│   ├── devices/
│   ├── dns/
│   ├── health/
│   ├── inventory/
│   ├── lists/
│   ├── mobile/
│   ├── routing/
│   ├── revisions/
│   ├── secrets/
│   ├── servers/
│   ├── sources/
│   ├── sshagent/
│   ├── system/
│   └── web/
├── pkg/
│   └── contracts/
├── web/
│   ├── templates/
│   ├── static/
│   └── locales/
├── configs/
│   ├── builtin-sources.yaml
│   ├── defaults.yaml
│   ├── inventory.example.yaml
│   └── routerd.example.yaml
├── deploy/
│   ├── openwrt/
│   ├── server/
│   └── windows/
├── packaging/
│   ├── openwrt-apk/
│   ├── systemd/
│   └── release/
├── scripts/
│   ├── bootstrap.ps1
│   ├── install-router.ps1
│   ├── install-server.ps1
│   ├── install-cisco-agent.ps1
│   ├── backup.ps1
│   └── recovery.ps1
├── docs/
│   ├── INSTALL.md
│   ├── OPERATIONS.md
│   ├── CISCO.md
│   ├── SOURCES.md
│   ├── SECURITY.md
│   ├── RECOVERY.md
│   ├── TROUBLESHOOTING.md
│   └── adr/
├── tests/
│   ├── fixtures/
│   ├── integration/
│   ├── network-ns/
│   ├── openwrt-qemu/
│   └── windows-pester/
└── .github/workflows/
```

## 23.2. Основные interfaces

```go
type RoutingBackend interface {
    Plan(ctx context.Context, desired DesiredState) (ApplyPlan, error)
    Validate(ctx context.Context, plan ApplyPlan) error
    Apply(ctx context.Context, plan ApplyPlan) (AppliedRevision, error)
    Rollback(ctx context.Context, revisionID string) error
    Explain(ctx context.Context, query RouteQuery) (RouteDecision, error)
    Status(ctx context.Context) (RoutingStatus, error)
}

type TunnelBackend interface {
    Configure(ctx context.Context, server ServerProfile) error
    Up(ctx context.Context, serverID string) error
    Down(ctx context.Context, serverID string) error
    Health(ctx context.Context, serverID string) (TunnelHealth, error)
    Activate(ctx context.Context, serverID string) error
}

type SourceAdapter interface {
    Fetch(ctx context.Context, source Source) (Artifact, error)
    Parse(ctx context.Context, artifact Artifact) ([]RawEntry, error)
    Verify(ctx context.Context, artifact Artifact) error
}

type PeerManager interface {
    Issue(ctx context.Context, req IssuePeerRequest) (OneTimeProfile, error)
    List(ctx context.Context, serverID string) ([]Peer, error)
    Revoke(ctx context.Context, peerID string) error
    Rotate(ctx context.Context, peerID string) (OneTimeProfile, error)
}
```

Business logic не должна зависеть от shell/OpenWrt напрямую; все platform calls через adapters.

---

# 24. API

Создать versioned REST API и OpenAPI 3 spec.

Минимум:

```text
GET    /api/v1/status
GET    /api/v1/route/explain
POST   /api/v1/route/probe

GET    /api/v1/entries
POST   /api/v1/entries
PATCH  /api/v1/entries/{id}
DELETE /api/v1/entries/{id}
POST   /api/v1/changes/plan
POST   /api/v1/changes/apply
POST   /api/v1/revisions/{id}/rollback

GET    /api/v1/sources
POST   /api/v1/sources
POST   /api/v1/sources/{id}/refresh
GET    /api/v1/sources/{id}/diff

GET    /api/v1/servers
POST   /api/v1/servers
POST   /api/v1/servers/{id}/activate
POST   /api/v1/servers/{id}/health

GET    /api/v1/peers
POST   /api/v1/peers
DELETE /api/v1/peers/{id}
POST   /api/v1/peers/{id}/rotate
GET    /api/v1/one-time/{token}

GET    /api/v1/devices
PATCH  /api/v1/devices/{id}

POST   /api/v1/cisco/enroll
POST   /api/v1/cisco/snapshots
GET    /api/v1/cisco/candidates
POST   /api/v1/cisco/candidates/{id}/approve

GET    /api/v1/backups
POST   /api/v1/backups
POST   /api/v1/backups/verify
POST   /api/v1/backups/restore-plan
POST   /api/v1/backups/restore

GET    /api/v1/audit
GET    /api/v1/events       # SSE
GET    /metrics             # disabled or LAN-only by default
```

Windows agent использует отдельный scoped token, не admin cookie.

---

# 25. Пример конфигурации

## 25.1. `inventory.example.yaml`

```yaml
project:
  name: home-gateway
  timezone: Europe/Amsterdam

router:
  model: glinet_gl-mt6000
  address: 192.168.10.1
  admin_hostname: router.home.arpa
  openwrt_version: 25.12.5
  wan:
    mode: dhcp # dhcp | pppoe | static
    vlan_id: null
  wifi:
    auto_ssid: Home
    direct_ssid: Home-Direct
    vpn_ssid: Home-VPN

workstation:
  name: work-pc
  hostname: CHANGE_ME
  mac: CHANGE_ME
  reserved_ip: 192.168.10.10

servers:
  - id: nl-1
    name: Netherlands primary
    host: CHANGE_ME
    ssh_user: bootstrap
    country: NL
    priority: 10
    transports:
      - amneziawg2
      - xray-reality
```

Этот файл не содержит паролей/ключей и может храниться локально. `inventory.local.yaml` должен быть в `.gitignore` по умолчанию.

## 25.2. `builtin-sources.yaml`

```yaml
sources:
  - id: runetfreedom-ru-blocked
    title: Runet Freedom RU blocked
    kind: github-release
    repository: runetfreedom/russia-v2ray-rules-dat
    category: ru-blocked
    route: vpn
    enabled_by_default: true
    trust: staged-auto
    refresh: 6h
    max_entries: 250000

  - id: runetfreedom-ru-inside
    title: Available only inside Russia
    kind: github-release
    repository: runetfreedom/russia-v2ray-rules-dat
    category: ru-available-only-inside
    route: direct
    enabled_by_default: true
    trust: staged-auto
    refresh: 12h
    max_entries: 100000

  - id: refilter-community
    title: Re-filter community geo restrictions
    kind: github-release
    repository: 1andrevich/Re-filter-lists
    asset_selector: community.lst
    route: vpn
    enabled_by_default: true
    trust: staged-auto
    refresh: 6h
    max_entries: 100000

  - id: huge-all-blocked
    title: Full all-known blocked list
    enabled_by_default: false
    requires_explicit_warning: true
```

Codex обязан проверить фактические asset names/API при реализации; descriptor должен уметь адаптироваться к GitHub release metadata без исполнения чужого кода.

---

# 26. Установка и администрирование с Windows

Основная команда пользователя:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\bootstrap.ps1
```

Установщик должен:

1. Проверить SHA/signature bundle.
2. Проверить модель роутера и текущую прошивку.
3. Создать/найти SSH key пользователя.
4. Снять backup текущего роутера.
5. Не прошивать автоматически без явного подтверждения и recovery path.
6. Установить официальный OpenWrt image либо продолжить на совместимой версии.
7. Загрузить проверенные APK локально, не требуя GitHub на роутере.
8. Установить AWG module/tools, `dnsmasq-full`, `routerd`.
9. Настроить LAN/SSID, не отключая старую сеть до smoke test.
10. Bootstrap VPS через SSH.
11. Создать router peer.
12. Поднять туннель без default route.
13. Применить тестовые правила.
14. Создать local CA и показать fingerprint.
15. Установить CA в Windows CurrentUser после подтверждения.
16. Создать admin enrollment.
17. Установить `cisco-discovery` как Scheduled Task/service.
18. Открыть панель.
19. Выполнить acceptance smoke tests.
20. Создать первый encrypted backup.

Все шаги имеют `-WhatIf`/dry-run и resumable state.

Пример CLI для разработчика/аварийного управления:

```powershell
.\hgctl.exe status
.\hgctl.exe route explain chatgpt.com --device work-pc
.\hgctl.exe server activate nl-1
.\hgctl.exe source refresh runetfreedom-ru-blocked
.\hgctl.exe backup create --output .\backups
```

---

# 27. Monitoring и уведомления

Локальный monitoring:

- tunnel states;
- handshake age;
- egress identity;
- DNS health;
- source age;
- apply/rollback failures;
- disk/RAM/CPU;
- nft set sizes;
- route packet/byte counters;
- backup age;
- certificate expiry;
- OpenWrt/AWG mismatch.

Поддержать optional notification adapters:

- Telegram;
- email/webhook;
- Windows toast via polling client.

Они выключены по умолчанию и не должны быть single point of failure.

---

# 28. Performance requirements

На GL-MT6000 и проводном клиенте:

- direct WAN target: не менее 450 Mbps на линии 500 Mbps при отсутствии ограничений провайдера;
- AWG2 target: не менее 300 Mbps, stretch target 400+ Mbps; результат зависит от VPS и маршрута;
- UI idle RAM: желательно < 80 MB;
- UI idle CPU: < 2% average;
- apply 100 000 domains: target < 15 seconds без потери WAN;
- source parse должен быть streaming и иметь memory limits;
- huge 700k list не входит в default acceptance;
- routerd crash не удаляет last applied rules;
- flash writes агрегируются.

Каждый benchmark сохраняет условия: client, Ethernet/Wi-Fi, server, RTT, CPU, protocol, MTU.

---

# 29. Тестирование

## 29.1. Unit tests

Обязательно:

- domain normalization;
- IDNA;
- PSL rejection;
- CIDR normalization;
- precedence;
- most-specific matching;
- manual override;
- external diff safety gates;
- source parsers;
- health state machine/hysteresis;
- one-time profile lifecycle;
- backup encryption;
- secret redaction;
- Cisco snapshot diff;
- route explanation.

## 29.2. Fuzz/property tests

- external list parsers;
- URL/domain input;
- backup decoder;
- server-agent JSON protocol;
- config migration.

## 29.3. Network namespace integration

Создать Linux network namespace topology:

```text
client -> router namespace -> WAN namespace
                         \-> VPN namespace -> Internet namespace
```

Проверить:

- direct;
- VPN mark;
- system-direct;
- work PC auto-cisco scope;
- blackhole when tunnel down;
- no IPv6 leak;
- active server switch;
- DNS nftset population;
- QUIC UDP;
- rollback.

## 29.4. OpenWrt tests

- QEMU x86_64 package smoke;
- target cross-compile;
- GL-MT6000 hardware smoke checklist;
- reboot persistence;
- failsafe/recovery;
- apk install/upgrade/remove;
- exact kernel/AWG compatibility.

## 29.5. Windows tests

Pester/fixtures для:

- no Cisco;
- split tunnel;
- full tunnel detection warning;
- route/dns changes;
- Cisco endpoint discovery;
- NRPT;
- randomized MAC warning;
- stale snapshot;
- signed agent binary/service install.

## 29.6. Web/API tests

- auth/session/CSRF;
- privilege boundaries;
- OpenAPI conformance;
- one-time link expiry;
- upload limits;
- backup/restore UI;
- Playwright end-to-end в CI.

## 29.7. Security CI

```text
go test ./...
go test -race ./...
govulncheck ./...
gosec ./...
staticcheck ./...
license/SBOM generation
secret scanning
shellcheck
Pester
```

---

# 30. Критерии приёмки

Проект не считается завершённым, пока одновременно не выполнено следующее.

## 30.1. Маршрутизация

- обычный российский сайт показывает WAN IP;
- домен из `vpn` показывает VPN IP;
- домен из `direct`, одновременно присутствующий во внешнем VPN source, показывает WAN IP;
- `auto-cisco` действует только на work PC;
- Cisco gateway всегда WAN;
- внутренний портал продолжает работать через Cisco;
- публичный рабочий портал видит российский WAN/корпоративный exit;
- переключение VPS не разрывает Cisco из-за смены его egress;
- HTTP/3/UDP маршрутизируется корректно.

## 30.2. Failure modes

- при остановке AWG VPN-домены не утекают в WAN;
- direct/Cisco продолжают работать;
- auto-failover выбирает резервный здоровый сервер;
- flapping отсутствует;
- повреждённый list update отклоняется;
- last-known-good остаётся активным;
- invalid nft/dns config автоматически откатывается;
- перезагрузка роутера восстанавливает last applied revision.

## 30.3. IPv6/DNS

- нет IPv6 leak для VPN domain;
- DNS клиента проходит через роутер;
- A/AAAA/CNAME заполняют sets;
- browser DoH conflict диагностируется;
- mobile full tunnel не использует DNS мобильного оператора.

## 30.4. Mobile

- новый profile импортируется в AmneziaWG;
- подключается с мобильной сети;
- показывает VPS egress;
- peer виден в панели;
- revoke прекращает доступ;
- private key нельзя повторно скачать после истечения one-time token;
- один device можно отозвать без изменения остальных.

## 30.5. Backup

- encrypted backup создаётся;
- проверяется;
- восстанавливается на чистой тестовой установке;
- secrets не видны без decryption;
- sanitized export безопасен для Git.

## 30.6. Security

- панель недоступна с WAN/Guest/VPN peer;
- server admin API не слушает публичный HTTP port;
- SSH password/root login отключены после bootstrap;
- support bundle не содержит private keys/passwords;
- external list не может выполнить команду;
- release artifacts имеют checksums/signatures/SBOM.

## 30.7. Performance

- direct Ethernet benchmark близок к 500 Mbps и достигает target;
- VPN benchmark задокументирован;
- CPU/RAM не перегружены;
- 100k-list apply проходит target или имеется обоснованный ADR/оптимизация.

## 30.8. Cisco stability

Провести длительный тест не менее рабочего дня:

- Cisco соединение не отваливается из-за маршрутизации роутера;
- Cisco endpoint остаётся direct;
- blocked non-work resources открываются через router VPN;
- work portals не видят VPN country.

---

# 31. Deliverables

Codex должен выдать:

```text
dist/
├── routerd_<version>_aarch64.apk
├── server-agent_<version>_linux_amd64
├── cisco-discovery_<version>_windows_amd64.exe
├── hgctl_<version>_windows_amd64.exe
├── bootstrap.ps1
├── server-bundle.tar.zst
├── SHA256SUMS
├── SHA256SUMS.sig
├── SBOM.spdx.json
├── THIRD_PARTY_NOTICES.md
└── RELEASE_NOTES.md
```

Также:

- исходный код;
- CI;
- reproducible build instructions;
- install docs;
- operations runbook;
- recovery guide;
- security model;
- migration guide;
- test report;
- compatibility matrix;
- sanitized example config.

---

# 32. Порядок реализации

Этапы — порядок разработки, а не перенос требований «на потом». Первый полноценный release включает панель, списки, Cisco, mobile peers, backup и multi-server model.

## Milestone 0 — foundation

- repo scaffold;
- ADR;
- config/inventory;
- release pipeline;
- test namespace framework;
- security baseline.

## Milestone 1 — VPN/server + OpenWrt dataplane

- pinned AWG2 deployment;
- server-agent;
- router tunnel;
- native nft/ip-rule backend;
- system-direct;
- direct/VPN routes;
- IPv4/IPv6 policy;
- killswitch for VPN class.

## Milestone 2 — Go panel and transactional config

- auth/TLS;
- dashboard;
- lists;
- revisions;
- staging/apply/rollback;
- diagnostics;
- device/SSID modes.

## Milestone 3 — external sources and smart probes

- adapters;
- presets;
- safety gates;
- LKG;
- mirrors;
- route probe/suggestions.

## Milestone 4 — Cisco integration

- Windows agent;
- snapshot diff;
- endpoint discovery;
- scoped auto-cisco;
- installer/service;
- acceptance test.

## Milestone 5 — mobile access

- peer lifecycle;
- one-time config/QR;
- revocation;
- stats;
- multi-server peer management.

## Milestone 6 — backup/failover/fallback

- encrypted backup/restore;
- multiple VPS;
- health/hysteresis;
- active switch;
- XRay Reality fallback;
- update/recovery workflow.

## Milestone 7 — hardening and release

- performance;
- security audit;
- fault injection;
- hardware test;
- docs;
- signed artifacts.

---

# 33. Изученные готовые решения и что из них взять

Состояние источников проверено на дату этого ТЗ. Не копировать код без проверки лицензии.

## 33.1. OpenWrt `pbr`

Repository/docs:

- https://docs.mossdef.org/pbr/
- https://github.com/mossdef-org/pbr

Полезные практики:

- domain routing через `dnsmasq.nftset`;
- strict enforcement;
- nft/firewall4 include;
- WireGuard без default route;
- IPv4/IPv6 policies;
- custom user sets;
- validation/rollback patterns.

Решение проекта: использовать как reference implementation и test oracle, но production `routerd` владеет своими chains/tables для точного порядка и multi-server switching.

## 33.2. Podkop

- https://github.com/itdoginfo/podkop

Полезные практики:

- OpenWrt UI;
- sing-box routing;
- remote lists;
- diagnostics;
- chunking больших импортов.

Ограничение: проект помечен beta, меняет dnsmasq/sing-box configs и поэтому не должен быть обязательной зависимостью критического шлюза.

## 33.3. Re:HomeProxy / homeproxy-hiddify

- https://github.com/1andrevich/homeproxy-hiddify

Полезные практики:

- multiple cores/transports;
- URLTest/failover;
- RU routing presets;
- subscriptions;
- diagnostics;
- optional Zapret2/ByeDPI;
- OpenWrt 25.12/apk support.

Ограничение: быстро развивающийся проект; брать архитектурные идеи и optional adapters, не делать единственным control plane.

## 33.4. keen-pbr

- https://github.com/maksimkurb/keen-pbr

Полезные практики:

- policy routing daemon;
- failover chains;
- health checks;
- domains/IP/ports;
- API/UI;
- embedded-router orientation.

Использовать как источник идей для health state machine и diagnostics.

## 33.5. Runet Freedom rules

- https://github.com/runetfreedom/russia-v2ray-rules-dat
- https://github.com/runetfreedom/russia-blocked-geosite

Полезно:

- автоматически обновляемые категории;
- `ru-blocked`;
- `ru-blocked-community`;
- `ru-available-only-inside`;
- formats для V2Ray/sing-box;
- обновления примерно каждые 6 часов.

Не включать огромный `ru-blocked-all` без предупреждения.

## 33.6. Re:filter lists

- https://github.com/1andrevich/Re-filter-lists

Полезно:

- blocked domain/IP lists;
- community domains, которые ограничивают российские IP;
- SRS/geo formats;
- регулярные releases.

## 33.7. AntiFilter

- https://antifilter.download/
- https://community.antifilter.download/

Полезно:

- domain/IP data;
- community list;
- дополнительные mirrors/sources.

Полные списки требуют ограничений размера и staged validation.

## 33.8. wg-easy

- https://github.com/wg-easy/wg-easy

Полезные UX-паттерны:

- peer create/revoke;
- QR/config;
- one-time links;
- expiration;
- handshake/traffic stats;
- IPv6;
- metrics.

Не копировать AGPL-код без осознанного лицензионного решения; реализовать аналогичные функции для AmneziaWG самостоятельно.

## 33.9. Официальные компоненты Amnezia

- https://github.com/amnezia-vpn/amnezia-client
- https://github.com/amnezia-vpn/amneziawg-openwrt
- https://github.com/amnezia-vpn/amneziawg-linux-kernel-module
- https://github.com/amnezia-vpn/amneziawg-tools
- https://github.com/amnezia-vpn/amneziawg-go
- https://github.com/amnezia-vpn/amneziawg-apple

Использовать официальный формат и команды peer management. При интеграции с существующим Amnezia container учитывать актуальные пути конфигурации и `awg syncconf`; не зависеть от undocumented path без adapter/version test.

---

# 34. Дополнительные возможности после основного release

Архитектура должна позволять, но не обязана включать в первый стабильный релиз:

1. Route class `dpi-direct` через Zapret2/ByeDPI для throttling без VPN.
2. Tailscale/NetBird admin overlay, выключенный по умолчанию.
3. Local notification integrations.
4. Per-domain bandwidth statistics с privacy opt-in.
5. Subscription/bundle для нескольких mobile servers.
6. Ansible/Terraform provisioning VPS.
7. Второй физический access point/802.11r mesh management.
8. IPTV-specific VLAN/multicast wizard.

Ни одна из этих функций не должна задерживать или усложнять core reliability.

---

# 35. Явные non-goals

Не реализовывать:

- собственную криптографию/VPN protocol;
- TLS MITM;
- перехват корпоративных credentials;
- модификацию Cisco profile/policy;
- скрытый сбор browsing history;
- публичную cloud-панель;
- открытый admin port на VPS;
- автоматический OpenWrt upgrade без проверки;
- исполнение remote scripts;
- гарантию обхода любой будущей блокировки;
- автоматическое добавление всех `.ru` или всех иностранных доменов;
- full-Russia IP geolocation как основной алгоритм;
- зависимость от одного GitHub/raw URL;
- хранение mobile private keys в Git/обычной DB.

---

# 36. Финальный пользовательский сценарий

После установки пользователь с Windows открывает:

```text
https://router.home.arpa:8443
```

И видит:

```text
WAN: OK, Russian IP
VPN nl-1: OK, Netherlands IP
VPN fi-1: standby
Cisco endpoint: direct
Blocked list: current
Russia-only direct list: current
Backup: today
```

Чтобы добавить сайт:

1. Вводит домен.
2. Нажимает `Проверить`.
3. Видит direct/VPN результаты.
4. Выбирает `Напрямую`, `Через VPN` или `Работа/Cisco`.
5. Нажимает `Применить`.
6. Панель показывает diff, validation, revision и итоговый egress.

Чтобы выдать доступ iPhone:

1. `Мобильный доступ` -> `Новое устройство`.
2. Имя `iPhone`.
3. Выбирает server(s).
4. Сканирует одноразовый QR в AmneziaWG.
5. Профиль появляется со handshake/traffic.
6. При потере телефона нажимает `Отозвать на всех серверах`.

Чтобы переключить сервер:

1. `Серверы` -> выбрать healthy server.
2. `Активировать`.
3. Система тестирует candidate, атомарно переключает VPN routing table и подтверждает новый egress.
4. Cisco/WAN route остаются неизменными.

---

# 37. Определение готовности Codex

Codex должен закончить работу только после того, как:

- исходники собираются одной командой;
- release bundle создаётся воспроизводимо;
- установка выполняется с Windows;
- все core-компоненты работают на GL-MT6000;
- сервер bootstrap воспроизводим;
- панель реализует все обязательные разделы;
- внешние источники безопасно обновляются;
- Cisco endpoint/work routes не попадают в VPN;
- мобильные peers реально выдаются и отзываются;
- multi-server переключение и failover работают;
- backups проверены восстановлением;
- IPv6/DNS leak tests пройдены;
- security/performance test report приложен;
- `STATUS.md` не содержит незакрытых blocker/critical TODO.

При обнаружении несовместимости конкретного upstream компонента Codex должен:

1. зафиксировать проблему и версию;
2. предложить adapter/замену;
3. сохранить публичные контракты проекта;
4. не обходить проблему небезопасным shell-hack;
5. добавить regression test.

---

# 38. Первичные значения по умолчанию

Использовать как безопасный старт:

```yaml
default_route: direct
vpn_failure_policy: fail_closed_for_vpn_entries
external_source_mode: staged_auto_for_trusted
source_refresh: 6h
source_jitter: 30m
server_mode: manual_sticky
health_failures_to_down: 3
health_successes_to_up: 2
failover_hold_down: 120s
failback_stable_period: 10m
one_time_profile_ttl: 10m
dns_query_logging: false
panel_wan_access: false
panel_guest_access: false
mobile_peer_to_peer: false
ipv6_policy: route_or_block_no_leak
backup_retention: 7d/4w/6m
```

---

**Конец технического задания.**
