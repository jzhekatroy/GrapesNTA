# Развёртывание GrapesNTA с нуля

Инструкция для инженера на **новом стенде**. Один проход: ClickHouse → коллекторы → Docker-воркеры → UI.

Текстовая копия для передачи: [`INSTALL.txt`](INSTALL.txt).

Это не дневник конкретной машины. Историю стенда `nta` см. [`FIRST_INSTALL_NTA_2026-07-20.md`](FIRST_INSTALL_NTA_2026-07-20.md). Восстановление уже живой базы после потери volume — [`CLICKHOUSE_DB_SETUP_RUNBOOK.md`](CLICKHOUSE_DB_SETUP_RUNBOOK.md). Cutover с `ipt_NETFLOW` — [`PERMANENT_XDPFLOWD_RUNBOOK.md`](PERMANENT_XDPFLOWD_RUNBOOK.md).

Секреты в git не класть. Пароли генерировать заново на каждом стенде.

---

## 1. Что это за система

Четыре роли. Их можно совмещать на одном хосте, но в проде обычно разделены.

| Роль | Что | Как живёт |
|------|-----|-----------|
| ClickHouse | сырые потоки, DNS, BMP, справочники, агрегаты | отдельный сервер или Docker **с persistent volume** |
| Коллекторы | `xdpflowd`, `dnsflowd`, `flowcollectord`, `bmpgrapes` | systemd на хосте с зеркалом / sFlow / BMP |
| Воркеры | `grapes-worker` (роллапы + наблюдения), `grapes-enrichment` (geo/ASN/SNMP) | Docker, `network_mode: host` |
| UI | NTAdmin | Docker `grapes-nta` из этого репо **или** отдельный процесс из `mavotronik/NTAdmin`, порт **3000** |

Профиль площадки выбирает **какие демоны включить**, не форму БД. Схема одна: `./deploy/schema/apply.sh`.

```text
зеркало NIC ──► xdpflowd ──► flows_raw
DNS mirror  ──► dnsflowd ──► dns_log
sFlow/NFv9  ──► flowcollectord ──► flows_raw
роутеры BMP ──► bmpgrapes ──► bmp_* ──► grapes-enrichment ──► bgp_prefix_origin_current

grapes-worker ──► traffic_* / observation_rollups_5m
UI :3000      ──► читает CH (ui_read / ui_admin)
```

**Не включать** хостовые таймеры `traffic-rollups`, `traffic-talkers-rollups`, `geoloaderd`, `bgp-origin-refresh`, `asn-names-loader`, `snmp-iface-sync`, `iptoasn-loader` и сервис `grapes-analytics`. Их работу делают контейнеры. Два писателя в одни таблицы дают порчу агрегатов.

---

## 2. Порядок

1. ClickHouse с диском, пользователи, схема.
2. Checkout репозитория на хосте коллекторов / воркеров.
3. Коллекторы (только те, что нужны площадке).
4. `grapes-worker` и `grapes-enrichment`.
5. UI на `:3000`.
6. Справочники в UI (источники, L3, VLAN) и проверка данных.

---

## 3. ClickHouse (база с нуля)

Канонический DDL — [`deploy/schema/`](../deploy/schema/). Один скрипт создаёт все слои: flows, DNS, BMP, enrichment, net-каталоги, traffic-агрегаты, observations, RBAC.

`deploy/clickhouse/*.sql` — не схема, а ops/ALTER для уже живой базы. На пустой CH их не гонять списком из старых runbook'ов: части файлов больше нет.

### 3.1. Сервер и диск

Пакет или Docker — неважно. Обязательно:

| Путь в контейнере/пакете | Зачем |
|--------------------------|--------|
| `/var/lib/clickhouse` | данные; без volume recreate контейнера = пустая база |
| `/etc/clickhouse-server` | `users.xml`, `config.d` |

Порты по умолчанию: native **9000**, HTTP **8123**. Если снаружи другие (на текущем стенде HTTP `6123`, native `6124`) — дальше везде подставляйте фактические.

Часовой пояс сервера:

```xml
<!-- /etc/clickhouse-server/config.d/timezone.xml -->
<clickhouse>
  <timezone>Europe/Moscow</timezone>
</clickhouse>
```

UI и `grapes-worker` читают `CLICKHOUSE_TIMEZONE=Europe/Moscow`. Если сервер UTC, а клиенты Moscow (или наоборот), графики наблюдений и explorer разъедутся на ±3 часа.

Проверка после старта:

```bash
clickhouse-client --host 127.0.0.1 --port 9000 -q "SELECT timezone(), now(), now('UTC')"
```

`now()` и `timezone()` должны быть Москва; `now('UTC')` на 3 часа меньше.

### 3.2. Репозиторий

С машины, откуда есть доступ к native или HTTP ClickHouse:

```bash
apt install -y clickhouse-client gettext-base curl git
git clone https://github.com/jzhekatroy/GrapesNTA.git /opt/GrapesNTA
cd /opt/GrapesNTA
git checkout main
git pull --ff-only origin main
```

Нужны `clickhouse-client` **или** HTTP (`curl`) плюс `envsubst` (пакет `gettext` / `gettext-base`).

### 3.3. Накатить схему

Словари (`*_dict.sql`) подставляют `CH_DICT_*` через `envsubst`. SOURCE словаря — как **сервер ClickHouse ходит сам в себя**: loopback native, обычно `127.0.0.1:9000`. Не ставьте сюда внешний IP зеркала.

HTTP (как с админ-порта на проде):

```bash
cd /opt/GrapesNTA
export CH_URL='http://127.0.0.1:8123'   # или http://CH_HOST:6123
export CH_USER='default'
export CH_PASS='...'                    # bootstrap-админ
export CH_DICT_HOST=127.0.0.1
export CH_DICT_PORT=9000
export CH_DICT_USER="$CH_USER"
export CH_DICT_PASSWORD="$CH_PASS"
./deploy/schema/apply.sh
```

Native:

```bash
cd /opt/GrapesNTA
export CH_HOST=127.0.0.1 CH_PORT=9000
export CH_USER=default CH_PASS='...'
export CH_DICT_HOST=127.0.0.1 CH_DICT_PORT=9000
export CH_DICT_USER="$CH_USER" CH_DICT_PASSWORD="$CH_PASS"
./deploy/schema/apply.sh
```

Слои по отдельности, если нужно: `./deploy/schema/apply.sh 10_flows 60_traffic`.

Скрипт идемпотентен (`IF NOT EXISTS`), но **не** мигрирует уже изменённые колонки. Повторный прогон на пустой базе безопасен.

Проверка, что каркас на месте:

```bash
clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" --password "$CH_PASS" -q "
SELECT name FROM system.tables
WHERE database = 'default'
  AND name IN (
    'flows_raw', 'dns_log', 'dns_answers',
    'bmp_peers', 'bmp_route_events', 'bgp_prefix_origin_current',
    'geo_prefix_country', 'net_flow_sources', 'net_l3_prefixes',
    'traffic_dashboard_1m', 'traffic_rollup_state',
    'observations', 'observation_rollups_5m', 'users'
  )
ORDER BY name
FORMAT TSV"
```

Должно вернуться 14 имён. Словари:

```bash
clickhouse-client ... -q "
SELECT name, status FROM system.dictionaries
WHERE database = 'default'
  AND name IN ('geo_country_dict', 'bgp_origin_asn_dict', 'net_interfaces_dict')
FORMAT PrettyCompact"
```

Пустой SOURCE у словаря на свежей базе нормален (`NOT_LOADED` / ошибка загрузки), пока enrichment не заполнит таблицы. Сами объекты должны существовать.

### 3.4. Пользователи и GRANT

Три роли. Пароли — свои на каждом стенде, не из другого хоста.

| User | Кто им ходит |
|------|----------------|
| `collector_write` | xdpflowd, dnsflowd, flowcollectord, bmpgrapes |
| `ui_read` | UI SELECT |
| `ui_admin` | UI запись справочников, grapes-worker, grapes-enrichment, `SYSTEM RELOAD DICTIONARY` |

Лимиты — только `*_overflow_mode = 'throw'`. Режим `'break'` тихо обрезает ответ, агрегаты выглядят успешными.

1. В [`deploy/clickhouse/bootstrap_users.sql`](../deploy/clickhouse/bootstrap_users.sql) заменить `CHANGE_ME_COLLECTOR` / `CHANGE_ME_UI_READ` / `CHANGE_ME_UI_ADMIN`.
2. Накатить от bootstrap-админа:

```bash
clickhouse-client --host "$CH_HOST" --port "$CH_PORT" \
  --user "$CH_USER" --password "$CH_PASS" \
  --multiquery < /opt/GrapesNTA/deploy/clickhouse/bootstrap_users.sql
```

3. Проверить, что ни у кого нет `break`:

```sql
SELECT user_name, setting_name, value
FROM system.settings_profile_elements
WHERE user_name IN ('ui_read', 'ui_admin', 'collector_write')
  AND setting_name LIKE '%overflow_mode%'
  AND value = 'break';
```

Должно быть **0 строк**.

4. Проверить вход:

```bash
clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user collector_write --password '...' -q "SELECT currentUser()"
clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user ui_read --password '...' -q "SELECT count() FROM system.tables WHERE database='default'"
clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user ui_admin --password '...' -q "SELECT currentUser()"
```

`GRANT ON default.*` покрывает будущие таблицы (`traffic_*`, `observation_*`, `enrichment_job_status`). Отдельный INSERT коллектору нужен на конкретные таблицы — он уже в `bootstrap_users.sql`.

### 3.5. Firewall

Снаружи открывать только то, что нужно:

- native/HTTP ClickHouse — **не** в интернет, только коллекторы, worker, UI, админ;
- sFlow `:6343/udp`, BMP TCP (часто не дефолт `5000`), UI `:3000` — по allowlist.

---

---

## 4. Хост коллекторов

Linux (Debian 12/13), root, Go 1.23+, `clang`, `libbpf-dev`, `linux-libc-dev`, Docker CE с плагином compose.

```bash
apt install -y clang llvm libbpf-dev linux-libc-dev build-essential git docker-ce docker-compose-plugin
cd /opt/GrapesNTA
make build                 # xdpflowd + bpf/xdp_flow.o
make build-dns             # dnsflowd, если будет DNS-зеркало
make build-flowcollectord  # sFlow / NetFlow UDP
make build-bmp             # BMP от роутеров
```

Бинарники: `/opt/GrapesNTA/bin/`. Unit-файлы рассчитаны на `REPO_ROOT=/opt/GrapesNTA`.

### 4.1. xdpflowd (зеркало / TAP)

Только на **mirror**-интерфейсе. На routing/management `-xdp-action drop` ломает форвардинг.

```bash
sudo mkdir -p /etc/xdpflowd /var/lib/xdpflowd/ch-spool
sudo cp deploy/systemd/xdpflowd.env.example /etc/xdpflowd/xdpflowd.env
sudo chmod 0600 /etc/xdpflowd/xdpflowd.env
# заполнить: IFACE, REPO_ROOT, XDP_CH_DSN, XDPFLOWD_SOURCE_ID
sudo cp deploy/systemd/xdpflowd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xdpflowd
```

Обязательное в env:

```bash
REPO_ROOT=/opt/GrapesNTA
IFACE=ens1np0                          # зеркало, не management
XDP_CH_DSN=clickhouse://collector_write:PASS@CH_HOST:9000/default
XDP_CH_TABLE=default.flows_raw
XDPFLOWD_SOURCE_ID=netflow             # уникален на весь стенд
XDP_CH_SPOOL_MODE=required
XDP_CH_SPOOL_DIR=/var/lib/xdpflowd/ch-spool
XDP_CLASSIFIER=1                       # после появления справочников в CH
XDP_EXCLUSIONS=1
```

Пароль в DSN URL-кодировать. Native-порт — тот, что слушает CH с этой машины.

Классификатор читает `net_l3_prefixes_enabled` / `net_l2_vlans_enabled` / `bgp_prefix_origin_current`. Без BMP+enrichment `src_asn`/`dst_asn` будут 0.

Профиль XDP: [`PERMANENT_XDPFLOWD_RUNBOOK.md`](PERMANENT_XDPFLOWD_RUNBOOK.md). Cutover с `ipt_NETFLOW` — `attic/scripts/`; на чистом хосте не нужен.

### 4.2. dnsflowd / flowcollectord / bmpgrapes

Тот же шаблон: `env.example` → `/etc/<daemon>/`, unit из `deploy/systemd/`, `enable --now`.

| Демон | Env | Когда нужен |
|-------|-----|-------------|
| `dnsflowd` | `/etc/dnsflowd/dnsflowd.env` | DNS-зеркало → `dns_log` / `dns_answers` (нужен `XDP_DNS_PASSTHROUGH=1` у xdpflowd на том же IFACE) |
| `flowcollectord` | `/etc/flowcollectord/flowcollectord.env` | sFlow `:6343/udp` / NFv9 → `flows_raw` |
| `bmpgrapes` | `/etc/bmpgrapes/bmpgrapes.env` | BMP от роутеров; без него ASN в потоках пустые |

```bash
# dnsflowd
sudo mkdir -p /etc/dnsflowd
sudo cp deploy/systemd/dnsflowd.env.example /etc/dnsflowd/dnsflowd.env
sudo cp deploy/systemd/dnsflowd.service /etc/systemd/system/
# DNS_CH_DSN=clickhouse://collector_write:PASS@CH_HOST:9000/default
# DNSFLOWD_SOURCE_ID=dns-netflow

# flowcollectord
sudo mkdir -p /etc/flowcollectord
sudo cp deploy/systemd/flowcollectord.env.example /etc/flowcollectord/flowcollectord.env
sudo cp deploy/systemd/flowcollectord.service /etc/systemd/system/
# FC_CH_DSN=...  FC_SFLOW_SOURCE_ID=sflow-default

# bmpgrapes
sudo mkdir -p /etc/bmpgrapes
sudo cp deploy/systemd/bmpgrapes.env.example /etc/bmpgrapes/bmpgrapes.env
sudo cp deploy/systemd/bmpgrapes.service /etc/systemd/system/
# BMP_CH_DSN=...  BMP_LISTEN=0.0.0.0:10179   # порт как на роутерах, не обязательно 5000

sudo chmod 0600 /etc/dnsflowd/dnsflowd.env /etc/flowcollectord/flowcollectord.env /etc/bmpgrapes/bmpgrapes.env
sudo systemctl daemon-reload
sudo systemctl enable --now dnsflowd flowcollectord bmpgrapes   # только нужные
```

У каждого коллектора свой `source_id`. Два процесса с одним id дважды учтут один трафик.

---

## 5. Docker-воркеры

На хосте, который видит ClickHouse по HTTP (часто тот же, что коллекторы).

```bash
cd /opt/GrapesNTA/deploy/worker
cp -n env.example .env
# CLICKHOUSE_URL, пароли ui_admin/ui_read, TRAFFIC_ROLLUP_CH_*
# CLICKHOUSE_TIMEZONE=Europe/Moscow
mkdir -p logs data
chown -R 1001:1001 data

cd /opt/GrapesNTA/deploy/enrichment
cp -n env.example .env
# GEOLOADERD_CH_*, BGPORIGIN_CH_*, пароли
mkdir -p logs

cd /opt/GrapesNTA
./deploy/deploy.sh worker
./deploy/deploy.sh enrichment
# или: ./deploy/deploy.sh          # оба
```

Если ClickHouse **не** на localhost:

- клиентские `*_CH_HOST` / `CLICKHOUSE_URL` / `CLICKHOUSE_HTTP_PORT` — внешний адрес (например HTTP `6123`);
- `*_DICT_SOURCE_HOST=127.0.0.1` и `*_DICT_SOURCE_PORT=9000` — как **сервер CH ходит сам в себя**. Внешний IP здесь даёт `ALL_CONNECTION_TRIES_FAILED`.

Не запускать два `grapes-worker` на одну базу.

Проверка:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
docker logs --since 5m grapes-worker 2>&1 | grep -E 'analytics started|run complete|precheck ok'
docker logs --since 10m grapes-enrichment | tail
```

Первые минуты роллапов пустые — safety lag ~5 минут плюс пустой `flows_raw`.

---

## 6. UI

Порт **3000**. Исходники продукта — приватный `mavotronik/NTAdmin`; в этом репо лежит вендорная копия `deploy/ui/app`.

### Вариант A — контейнер из GrapesNTA

```bash
cd /opt/GrapesNTA
cp -n deploy/ui/env.example deploy/ui/.env
# CLICKHOUSE_URL=http://CH_HOST:8123  (или :6123)
# CLICKHOUSE_READ_USER / WRITE_USER, пароли
# CLICKHOUSE_TIMEZONE=Europe/Moscow
./deploy/deploy.sh ui
```

### Вариант B — NTAdmin как отдельный процесс

```bash
cd /path/to/NTAdmin
cp -n .env.example .env
# те же CLICKHOUSE_* и CLICKHOUSE_TIMEZONE=Europe/Moscow
PORT=3000 npm run dev    # или production start
```

Оба варианта ходят в **тот же** ClickHouse. Не поднимать два UI-писателя справочников без нужды.

После старта: логин (таблица `users` создаётся сама), страница диагностик, дашборд.

---

## 7. Первый трафик в UI

Пока оператор не заполнит справочники, классификатор и дашборд слепые.

В UI:

1. Локации / коллекторы / источники (`net_flow_sources`, `include_in_total`).
2. L3-префиксы своих сетей и сущности.
3. VLAN, если нужны.
4. SNMP-агенты — если нужны имена интерфейсов (опрос делает `grapes-enrichment`).
5. BMP-пиры на роутерах → `bmpgrapes` → job `bgp-origin` в enrichment.

Ожидание: сырой `flows_raw` — секунды; дашборд `traffic_*` — 5–10 минут.

---

## 8. Чеклист

```bash
# схема
clickhouse-client ... -q "SELECT name FROM system.tables WHERE database='default' AND name IN ('flows_raw','traffic_dashboard_1m','dns_log','observations') FORMAT TSV"

# коллекторы
systemctl is-active xdpflowd dnsflowd flowcollectord bmpgrapes
journalctl -u xdpflowd -n 30 --no-pager

# нет двойных писателей
systemctl list-timers --all | grep -Ei 'traffic|geo|asn|snmp|bgp|iptoasn' || true
docker ps --format '{{.Names}}'

# данные
clickhouse-client ... -q "SELECT source_id, count() FROM flows_raw WHERE time_received_ns > now() - 300 GROUP BY source_id"
clickhouse-client ... -q "SELECT max(minute), dateDiff('second', max(minute), now()) FROM traffic_dashboard_1m"
```

Дашборд, наблюдения и explorer должны показывать **московское** время, близкое к `now()`. Если наблюдения −3 ч, а explorer +3 ч — не совпал `CLICKHOUSE_TIMEZONE` у UI и worker (нужен `Europe/Moscow`).

---

## 9. Куда смотреть дальше

| Тема | Документ |
|------|----------|
| Слои схемы | [`../deploy/schema/README.md`](../deploy/schema/README.md) |
| Ops SQL на живой базе | [`../deploy/clickhouse/README.md`](../deploy/clickhouse/README.md) |
| Worker / enrichment | [`../deploy/worker/README.md`](../deploy/worker/README.md), [`../deploy/enrichment/README.md`](../deploy/enrichment/README.md) |
| Обновление контейнеров | [`../deploy/deploy.sh`](../deploy/deploy.sh) (`./deploy/deploy.sh status`) |
| SNMP | [`SNMP_INTERFACES_RUNBOOK.md`](SNMP_INTERFACES_RUNBOOK.md) |
| DNS-коллектор | [`DNSFLOWD_OPERATIONS.md`](DNSFLOWD_OPERATIONS.md) |
| BMP / origin ASN | [`BMPGRAPES_MVP.md`](BMPGRAPES_MVP.md) |
