# Runbook: восстановление ClickHouse после потери схемы

Документ фиксирует опыт восстановления аналитической БД после потери схемы
(июнь 2026, сервер `m61`, ClickHouse `95.215.1.30:6124`). Цель — не повторять
те же ошибки при следующем развёртывании.

**Новый стенд с нуля** — не этот файл, а [`INSTALL.md`](INSTALL.md).

Связанные документы:

- [`CLICKHOUSE_SCHEMA.md`](CLICKHOUSE_SCHEMA.md) — общая топология Kafka/goflow2/flows_raw
- [`geoip_country.md`](geoip_country.md) — RIR geo loader и dictionary
- [`NEW_COLLECTOR_START_RUNBOOK.md`](NEW_COLLECTOR_START_RUNBOOK.md) — cutover, classifier, spool (§18)
- [`UI_CLICKHOUSE_QUERIES.md`](UI_CLICKHOUSE_QUERIES.md) — запросы UI
- [`NET_ANALYTICS_OPERATIONS.md`](NET_ANALYTICS_OPERATIONS.md) — L3/L2 classifier deploy

Канонический DDL — [`deploy/schema/`](../deploy/schema/). Скрипты `deploy/clickhouse/*.sql` в старых разделах ниже — одноразовые ALTER/ops; `CREATE TABLE` оттуда перенесены в `deploy/schema`. Свежая установка: `./deploy/schema/apply.sh`. См. [`deploy/clickhouse/README.md`](../deploy/clickhouse/README.md).

---

## 1. Что случилось

После пересоздания Docker-контейнера ClickHouse пропали:

- пользовательские таблицы и materialized views (MV);
- справочники (`net_flow_sources`, `geo_prefix_country`, …);
- словарь `geo_country_dict`;
- созданные пользователи и grants.

**Причина:** `/var/lib/clickhouse` внутри контейнера не был примонтирован к
постоянному volume на хосте. При `docker rm` / recreate контейнера всё
пользовательское состояние исчезает. Таблица `flows_raw` могла остаться только
если она была создана образом/скриптом при старте контейнера, но аналитика UI
(`traffic_*`, views, dictionaries) — нет.

**Обязательное требование для админов:** перед любым recreate контейнера
настроить persistent volume:

```text
/var/lib/clickhouse  →  host:/data/clickhouse  (или аналог)
/etc/clickhouse-server →  host:/data/clickhouse-config  (users.xml, config.d)
```

Без этого любой «подъём с нуля» по этому runbook придётся повторять.

---

## 2. Топология (как должно работать)

```text
mirror NIC
  → xdpflowd (direct INSERT + ch-spool)
  → ClickHouse default.flows_raw          ← hot path: только INSERT, без sync MV

dnsflowd → default.dns_log
bmpgrapes → default.bmp_*
classifier читает net_l3_prefixes / net_l2_vlans / bgp_prefix_origin_current

collector m61:
  traffic-rollups.timer (каждую минуту)
    → scripts/traffic_rollup_async.py
    → INSERT в traffic_* (1m/1h/1d)
    → watermark в default.traffic_rollup_state

UI читает traffic_*_1m, net_flow_sources_enabled, system.dictionaries
```

На `m61` запись идёт **напрямую** из `xdpflowd` (без Kafka/goflow2). Схема
`flows_raw` и **таблицы** `traffic_*` должны существовать до cutover.
**Sync materialized views на `flows_raw` не используются** — они блокируют ingest.

Ожидаемый лаг агрегатов: **5–10 минут** (safety lag 5 min + timer 1 min).

---

## 3. Подключение

```bash
export CH_HOST=95.215.1.30
export CH_PORT=6124          # native TCP с хоста коллектора
export CH_USER=develop       # bootstrap-админ с GRANT OPTION
export CH_PASS='***'         # не коммитить

ch() {
  clickhouse-client --host "$CH_HOST" --port "$CH_PORT" \
    --user "$CH_USER" --password "$CH_PASS" "$@"
}
```

Проверка:

```bash
ch -q "SELECT version(), now()"
```

---

## 4. Пользователи и права

Создавали три роли (пароли — в vault, здесь только имена и назначение):

| User | Назначение |
|------|------------|
| `collector_write` | INSERT в `flows_raw`, `dns_log`, BMP-таблицы; без DDL |
| `ui_read` | SELECT на аналитику + ограниченный SELECT на `system.*` для UI |
| `ui_admin` | DDL справочников, geo loader, `CREATE DICTIONARY`, `SYSTEM RELOAD DICTIONARY` |

Пример bootstrap (от `develop`):

```sql
CREATE USER IF NOT EXISTS collector_write IDENTIFIED BY '***';
CREATE USER IF NOT EXISTS ui_read IDENTIFIED BY '***'
  SETTINGS
    max_execution_time = 120,
    timeout_overflow_mode = 'throw',
    max_rows_to_read = 0,
    max_bytes_to_read = 0,
    read_overflow_mode = 'throw',
    max_result_rows = 0,
    result_overflow_mode = 'throw';
CREATE USER IF NOT EXISTS ui_admin IDENTIFIED BY '***'
  SETTINGS
    max_execution_time = 30,
    timeout_overflow_mode = 'throw',
    max_rows_to_read = 100000000,
    max_bytes_to_read = 20000000000,
    read_overflow_mode = 'throw',
    max_result_rows = 500000,
    result_overflow_mode = 'throw';

GRANT INSERT ON default.flows_raw TO collector_write;
GRANT INSERT ON default.dns_log TO collector_write;
GRANT INSERT ON default.bmp_peers TO collector_write;
GRANT INSERT ON default.bmp_route_events TO collector_write;

GRANT SELECT ON default.* TO ui_read;
GRANT SELECT ON system.tables TO ui_read;
GRANT SELECT ON system.columns TO ui_read;
GRANT SELECT ON system.dictionaries TO ui_read;

GRANT SELECT, INSERT, CREATE TABLE, ALTER TABLE, DROP TABLE ON default.* TO ui_admin;
GRANT CREATE DICTIONARY, DROP DICTIONARY ON default.* TO ui_admin;
GRANT SYSTEM RELOAD DICTIONARY ON *.* TO ui_admin;
GRANT SELECT ON system.* TO ui_admin;
```

### Политика лимитов: только `throw`, никогда `break`

Лимиты (`max_execution_time`, `max_rows_to_read`, `max_bytes_to_read`,
`max_result_rows`) ставить можно и нужно. Режим при достижении лимита —
**только** `throw`.

| Режим | Поведение | Допустимо? |
|-------|-----------|------------|
| `throw` | запрос падает с ошибкой | да |
| `break` | запрос «успешен», но ответ обрезан | **нет** |

`break` опасен тем, что агрегаты и сверки выглядят корректными, хотя часть
входных строк уже отброшена. Это уже ловили на проде у `ui_admin`:
`max_rows_to_read = 100M` + `read_overflow_mode = 'break'` тихо обрезал
тяжёлые `INSERT … SELECT` / сверки.

Правило для всех инсталляций:

1. При создании UI-пользователей всегда явно задавать `*_overflow_mode = 'throw'`.
2. Не копировать с прода `SHOW CREATE USER` без проверки режимов.
3. После bootstrap — проверочный запрос ниже должен вернуть **0 строк**.

```sql
-- Должно быть пусто. Любая строка = мина на инсталляции.
SELECT
  user_name,
  setting_name,
  value
FROM system.settings_profile_elements
WHERE user_name IN ('ui_read', 'ui_admin', 'collector_write', 'develop')
  AND setting_name IN (
    'read_overflow_mode',
    'result_overflow_mode',
    'timeout_overflow_mode'
  )
  AND value = 'break'
ORDER BY user_name, setting_name;
```

Если на уже живом сервере нашёлся `break` — поправить идемпотентно
(пароль не трогать):

```sql
ALTER USER ui_admin SETTINGS
  max_execution_time = 30,
  timeout_overflow_mode = 'throw',
  max_rows_to_read = 100000000,
  max_bytes_to_read = 20000000000,
  read_overflow_mode = 'throw',
  max_result_rows = 500000,
  result_overflow_mode = 'throw';

ALTER USER ui_read SETTINGS
  max_execution_time = 120,
  timeout_overflow_mode = 'throw',
  max_rows_to_read = 0,
  max_bytes_to_read = 0,
  read_overflow_mode = 'throw',
  max_result_rows = 0,
  result_overflow_mode = 'throw';
```

Права (GRANT) по-прежнему вынесены в `NTAdmin/scripts/grant-ui-users.sql`;
настройки пользователей живут здесь, в bootstrap, а не «набиваются руками»
после установки.

### Проблема: `ACCESS_DENIED` у UI

**Симптом:** UI не открывается, в логах `ACCESS_DENIED` на
`system.dictionaries`, `system.tables`, `system.columns`.

**Фикс:** добавить `ui_read` явные grants на перечисленные `system`-таблицы
(см. выше). Для geo loader — `ui_admin` нужен `CREATE DICTIONARY` и
`SYSTEM RELOAD DICTIONARY`.

---

## 5. Порядок применения SQL (с нуля)

**Новый стенд:** не этот список, а [`INSTALL.md`](INSTALL.md) §3 —
`./deploy/schema/apply.sh`, затем `deploy/clickhouse/bootstrap_users.sql`.
Файлы `deploy/clickhouse/net_*.sql` / `traffic_*.sql` / `dns_log.sql` удалены
как дубли схемы.

Ниже — исторический порядок восстановления **уже живой** базы (июнь 2026).
Часть путей в командах устарела; для ALTER на существующей установке смотрите
`deploy/clickhouse/migrate_*.sql` и `flows_raw_*.sql`.

### 5.1. База raw и enrichment

```bash
REPO=/opt/GrapesNTA   # или путь к клону

for f in \
  flows_raw_extensions.sql \
  net_flow_sources.sql \
  flows_raw_source_id.sql \
  net_entities.sql \
  net_l3_prefixes.sql \
  net_special_ip_prefixes.sql \
  net_l2_vlans.sql \
  geo_country.sql \
  bmp.sql \
  bgp_origin_asn.sql \
  dns_log.sql \
  port_services.sql
do
  echo "=== $f ==="
  ch --multiquery < "$REPO/deploy/clickhouse/$f"
done
```

`flows_raw` сама по себе уже должна существовать (создана ранее на prod).
`flows_raw_extensions.sql` добавляет колонки classifier (`direction`, roles,
`vlan_id`, `source_id`, …) — без неё rollup jobs не соберутся.

### 5.2. Таблицы traffic_* (без sync MV)

Скрипты `traffic_*.sql` создают **только таблицы** `traffic_*`. Они **не**
создают `CREATE MATERIALIZED VIEW` — SELECT-тела живут в
`scripts/traffic_rollup_jobs.py`.

```bash
for f in \
  traffic_direction_1m.sql \
  traffic_protocol_1m.sql \
  traffic_dashboard_1m.sql \
  traffic_dashboard_1d.sql \
  traffic_role_1m.sql \
  traffic_entity_1m.sql \
  traffic_vlan_1m.sql \
  traffic_service_1m.sql \
  traffic_unknown_port_1m.sql \
  traffic_country_1m.sql \
  traffic_talkers_1m.sql \
  traffic_talkers_1h.sql \
  net_reports.sql
do
  echo "=== $f ==="
  ch --multiquery < "$REPO/deploy/clickhouse/$f"
done

ch --multiquery < "$REPO/deploy/clickhouse/traffic_rollup_state.sql"
ch --multiquery < "$REPO/deploy/clickhouse/detach_traffic_mvs.sql"
```

Полный порядок также описан в комментариях
[`deploy/clickhouse/apply_net_analytics.sql`](../deploy/clickhouse/apply_net_analytics.sql).

### 5.3. Проверка что схема на месте

```sql
SELECT name, engine
FROM system.tables
WHERE database = 'default'
  AND (
    name LIKE 'traffic_%'
    OR name LIKE 'net_%'
    OR name IN ('flows_raw', 'dns_log', 'geo_prefix_country', 'bmp_peers')
  )
ORDER BY name;
```

Ожидаемо: таблицы `traffic_*` есть, **ни одной** attached `traffic_*_mv`:

```sql
SELECT name, engine
FROM system.tables
WHERE database = 'default'
  AND engine = 'MaterializedView'
  AND name LIKE 'traffic_%';
-- пусто
```

UI без таблиц `traffic_*` падает с `Unknown table expression identifier`.

---

## 6. Geo: RIR loader и dictionary

### 6.1. Таблицы

```bash
ch --multiquery < "$REPO/deploy/clickhouse/geo_country.sql"
```

### 6.2. Загрузка данных

```bash
sudo mkdir -p /var/lib/geoloaderd/cache

python3 "$REPO/scripts/load_rir_geo.py" \
  --host "$CH_HOST" --port 9000 \
  --user ui_admin --password '***' \
  --database default \
  --dictionary-source-host 127.0.0.1 \
  --dictionary-source-port 9000 \
  --dictionary-source-user develop \
  --dictionary-source-password '***' \
  --cache-dir /var/lib/geoloaderd/cache
```

**Важно:** `--dictionary-source-host` — это адрес, с которого **сам ClickHouse
внутри Docker** читает `geo_prefix_country`. Не внешний IP `95.215.1.30:6124`.

### Проблема: `geo_country_dict` в статусе `FAILED`

**Симптом:**

```text
All connection tries failed. Timeout exceeded while connecting to socket
(host: 95.215.1.30:6124)
```

**Причина:** dictionary source указывал на внешний IP. Из контейнера CH не
может достучаться до себя по публичному адресу.

**Фикс:** `dictionary-source-host=127.0.0.1`, `dictionary-source-port=9000`
(native внутри контейнера), user с правами SELECT на `geo_prefix_country`.

Проверка:

```sql
SELECT name, status, last_exception
FROM system.dictionaries
WHERE name = 'geo_country_dict';

SELECT dictGet('default.geo_country_dict', 'country_code', toIPv6('8.8.8.8'));
```

---

## 7. Async traffic rollups (production)

### 7.1. Почему не sync MV

**Подтверждено на m61 (2026-06-11..12):** любые sync MV на `INSERT flows_raw`
дают fan-out: `lag_segments` 28+, `writer_lag_rows` 20M+, ClickHouse 100% CPU.
Даже «лёгкие» `traffic_dashboard_1m_mv` читают миллиарды строк на insert.

**Решение:** hot path = только `flows_raw` INSERT. Все `traffic_*` агрегаты
считаются **асинхронно** на коллекторе через `traffic_rollup_async.py`.

| Компонент | Путь |
|-----------|------|
| Runner | `scripts/traffic_rollup_async.py` |
| Job SQL | `scripts/traffic_rollup_jobs.py` (15 jobs) |
| State | `deploy/clickhouse/traffic_rollup_state.sql` |
| Detach legacy MV | `deploy/clickhouse/detach_traffic_mvs.sql` |
| systemd | archived in `attic/systemd/`; production uses `grapes-worker` |

Jobs (порядок выполнения): `traffic_dashboard_1m`, `traffic_protocol_1m`,
`traffic_direction_1m`, `traffic_role_1m`, `traffic_entity_1m`,
`traffic_vlan_1m`, `traffic_country_1m`, `traffic_service_1m`,
`traffic_unknown_port_1m`, `traffic_talker_1m`, `traffic_pair_1m`,
`traffic_dashboard_1h`, `traffic_talker_1h`, `traffic_pair_1h`,
`traffic_dashboard_1d`.

### 7.2. Установка на коллекторе (m61)

**Предусловие:** `lag_segments ~ 0`, `flows_raw lag_s < 120`.

```bash
sudo mkdir -p /etc/grapesnta /var/log/grapesnta

ch --multiquery < deploy/clickhouse/traffic_rollup_state.sql
ch --multiquery < deploy/clickhouse/detach_traffic_mvs.sql

sudo cp deploy/systemd/traffic-rollups.env.example /etc/grapesnta/traffic-rollups.env
# TRAFFIC_ROLLUP_CH_PASSWORD=...
# TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB=1

sudo cp deploy/systemd/traffic-rollups.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now traffic-rollups.timer
```

Проверка:

```bash
systemctl list-timers traffic-rollups.timer --no-pager
journalctl -u traffic-rollups.service -n 30 --no-pager
```

Ожидаемо за запуск: `run complete ok=9` (lightweight jobs only), `elapsed_s` < 30,
без `failed`. Не включайте `traffic_talker_*` / `traffic_pair_*` в основной timer —
они тяжёлые.

### 7.2b. Top talkers / pairs (отдельный timer)

Виджет «Топ-говорящие» читает `traffic_talker_1m` / `traffic_talker_1h`. Эти jobs
обслуживаются отдельным systemd timer (каждые 5 минут):

```bash
sudo cp deploy/systemd/traffic-talkers-rollups.{service,timer} /etc/systemd/system/
sudo cp deploy/systemd/traffic-talkers-rollups.env.example /etc/grapesnta/traffic-talkers-rollups.env
# TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
sudo systemctl daemon-reload
sudo systemctl enable --now traffic-talkers-rollups.timer
```

Проверка lag:

```sql
SELECT max(minute), dateDiff('minute', max(minute), now()) AS lag_min
FROM default.traffic_talker_1m;
```

`lag_min` должен быть < 10 при активном timer.

### 7.2c. L3 origin ASN для локальных префиксов

ASN ваших `provider_public` / customer префиксов задаётся в `net_l3_prefixes`,
не через fake BMP events. Миграция:

```bash
ch --multiquery < deploy/clickhouse/migrate_net_l3_prefixes_origin_asn.sql
```

Пример seed (замените ASN):

```sql
INSERT INTO default.net_l3_prefixes
(prefix, family, entity_id, role, origin_asn, display_name, enabled, source, updated_at)
VALUES
('188.143.128.0/17', 4, 'isp:pin', 'provider_public', 34665, 'gb', 1, 'manual', now());
```

После deploy/restart `xdpflowd` новые `flows_raw` строки получают `src_asn` /
`dst_asn` для matched L3 prefixes. Старые строки не пересчитываются.

### 7.3. Режим «только с текущего момента» (без backfill)

Если исторический backlog не нужен, сдвинуть watermark всех jobs на последнюю
безопасную минуту:

```sql
INSERT INTO default.traffic_rollup_state
(job, last_bucket, status, last_error, rows_written, duration_ms, updated_at)
SELECT job, last_bucket, 'skipped_backfill', '', 0, 0, now()
FROM
(
    SELECT arrayJoin([
        'traffic_dashboard_1m','traffic_protocol_1m','traffic_direction_1m',
        'traffic_role_1m','traffic_entity_1m','traffic_vlan_1m',
        'traffic_country_1m','traffic_service_1m','traffic_unknown_port_1m',
        'traffic_talker_1m','traffic_pair_1m'
    ]) AS job,
    toStartOfMinute(now('UTC') - INTERVAL 5 MINUTE) - INTERVAL 1 MINUTE AS last_bucket

    UNION ALL

    SELECT arrayJoin([
        'traffic_dashboard_1h','traffic_talker_1h','traffic_pair_1h'
    ]) AS job,
    toStartOfHour(now('UTC') - INTERVAL 5 MINUTE) - INTERVAL 1 HOUR AS last_bucket

    UNION ALL

    SELECT 'traffic_dashboard_1d' AS job,
    toStartOfDay(now('UTC') - INTERVAL 5 MINUTE) - INTERVAL 1 DAY AS last_bucket
);
```

Следующие запуски обрабатывают только новые закрытые бакеты.

### 7.4. Ручной запуск и throttle

```bash
python3 /opt/GrapesNTA/scripts/traffic_rollup_async.py \
  --host 95.215.1.30 --port 6124 \
  --user develop --password '***' \
  --jobs traffic_dashboard_1m,traffic_protocol_1m,traffic_direction_1m \
  --max-buckets-per-job 1 \
  --log-file /var/log/grapesnta/traffic_rollups.log --verbose
```

Для backfill (осторожно — грузит CH):

```bash
python3 scripts/traffic_rollup_async.py ... \
  --max-buckets-per-job 5 \
  --sleep-between-buckets 5
```

### 7.5. Мониторинг rollups

Watermark:

```sql
SELECT job, last_bucket, status, updated_at
FROM default.traffic_rollup_state FINAL
ORDER BY job
FORMAT PrettyCompact;
```

Data quality health-check (read-only):

```bash
cd /opt/GrapesNTA
set -a
source /etc/grapesnta/traffic-rollups.env
source /etc/grapesnta/traffic-talkers-rollups.env 2>/dev/null || true
set +a

python3 scripts/check_traffic_data_quality.py \
  --source-id netflow \
  --local-asn 34665 \
  --max-rollup-lag-minutes 45
```

Exit codes:

- `0` - all checks OK.
- `1` - WARN only. Typical WARN is remote ASN coverage: `remote_asn_zero_gb`
  when BGP/BMP is partial.
- `2` - FAIL. Investigate before trusting the dashboard.

Important FAIL examples:

- fresh `netflow` rows have `direction = unknown`;
- local/customer endpoints have ASN `0`;
- rollup lag is above threshold;
- table has empty IP fields;
- raw `flows_raw` and `traffic_direction_1m` diverge.

Expected WARN examples:

- `xdp-default` is present in aggregate tables but `include_in_total = 0`;
- remote endpoints have ASN `0` while BGP coverage is partial.

Свежесть агрегатов:

```sql
SELECT
    'traffic_dashboard_1m' AS tbl, max(minute) AS last_bucket FROM default.traffic_dashboard_1m
UNION ALL
SELECT 'traffic_protocol_1m', max(minute) FROM default.traffic_protocol_1m
UNION ALL
SELECT 'traffic_direction_1m', max(minute) FROM default.traffic_direction_1m;
```

Диагностика sync MV (должно быть пусто / нулевой total_ms):

```sql
SELECT
    view_name,
    count() AS inserts,
    round(sum(view_duration_ms)) AS total_ms
FROM system.query_views_log
WHERE event_time >= now() - INTERVAL 10 MINUTE
  AND view_name LIKE 'traffic_%'
GROUP BY view_name
ORDER BY total_ms DESC;
```

### 7.6. Известные проблемы

- **`clickhouse-client not found` на m61:** бинарник не в `/usr/bin/` — скрипт
  ищет через `PATH`; или задать `TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT`.
- **`traffic_vlan_1m` застревал на старом бакете:** баг парсера state (пустой
  `last_error` в последней строке TSV) — исправлен в `013454f`.
- **Прерывание `systemctl stop` во время run:** watermark сохраняется после
  каждого бакета; job догонит на следующем тике.

---

## 8. Заполнение справочников для classifier и UI

После пустой БД classifier пишет `direction=unknown`, роли пустые.

Нужно загрузить (через UI admin или SQL):

- `net_l3_prefixes` — локальные/клиентские префиксы
- `net_l2_vlans` — VLAN → entity
- `bgp_prefix_origin_current` — BGP origin (если есть bmpgrapes)
- `ip_asn_prefixes_current` — optional public IP→ASN fallback when BMP/BGP is
  not full-view
- `net_flow_sources` — registry source_id (`netflow`, `dns-netflow`, …)

Проверка classifier на коллекторе:

```bash
grep -E '^(XDP_CLASSIFIER|XDP_CLASSIFIER_)' /etc/xdpflowd/xdpflowd.env
journalctl -u xdpflowd -n 50 --no-pager | grep -i classifier
```

Ожидаем: `traffic classifier enabled`, `has_local_config=true`.
Если включён fallback, в логе также должен быть ненулевой
`ip_asn_prefixes=...`.

---

## 9. Проверка живого пайплайна

### 9.1. xdpflowd / spool

```bash
journalctl -u xdpflowd --since '10 minutes ago' --no-pager \
  | grep -E 'spool pipeline|health degraded|insert_errs|lag_segments|map_full|flow drainer'
```

Здорово: `map_full=0`, `insert_errs=0`, `lag_segments` 0–2, `flow drainer mode=atomic`.

### 9.2. Свежесть flows_raw

```sql
SELECT
    now() AS now,
    max(time_received_ns) AS max_received,
    dateDiff('second', max(time_received_ns), now64(9)) AS lag_s,
    countIf(time_received_ns >= now64(9) - INTERVAL 5 MINUTE) AS raw_5m
FROM default.flows_raw;
```

`lag_s` должен быть в пределах десятков секунд, `raw_5m` > 0 при живом зеркале.

### 9.3. Агрегаты для UI

```sql
SELECT max(minute) AS last_minute, sum(bytes) AS bytes_5m
FROM default.traffic_protocol_1m
WHERE minute >= now() - INTERVAL 10 MINUTE;
```

```sql
SELECT job, last_bucket, status
FROM default.traffic_rollup_state FINAL
WHERE job IN ('traffic_dashboard_1m', 'traffic_protocol_1m', 'traffic_direction_1m');
```

`last_minute` и `last_bucket` должны отставать от `now()` не более чем на
~5–10 минут (safety lag + timer).

---

## 10. Смежные проблемы (не CH, но всплыли в тот же период)

### 10.1. nfcapd Sequence Errors

**Симптом:** `nfcapd` считает sequence errors, `netstat -su` показывает миллионы
`receive buffer errors` на UDP 9996, при `xdpflowd send_errs=0`.

**Причина:** ядро дропает UDP до userspace — маленький `rmem`.

**Фикс:**

```bash
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.rmem_default=134217728
# persist in /etc/sysctl.d/99-udp-buffers.conf

# restart nfcapd with larger socket buffer
nfcapd -B 134217728 ...   # 128 MiB
```

### 10.2. xdpflowd: boolean flag ломал CH DSN

**Симптом:** после добавления `XDP_FINAL_FLUSH=0` xdpflowd перестал писать в CH.

**Причина:** в `xdpflowd-exec.sh` передавали `-final-flush 0` (отдельный аргумент).
Go `flag.Parse()` воспринимает это как `-final-flush` со значением по умолчанию
`true`, а `0` становится **позиционным** аргументом → всё после него (включая
`-ch-dsn`) игнорируется.

**Фикс:** `-final-flush="$XDP_FINAL_FLUSH"` (формат `-flag=value`).

### 10.3. UI query: `DECIMAL_OVERFLOW` на DateTime64(9)

**Симптом:** запрос с `toUnixTimestamp64Nano(now64() - INTERVAL 5 MINUTE)` падает.

**Фикс:** сравнивать `DateTime64(9)` напрямую:

```sql
WHERE time_received_ns >= now64(9) - INTERVAL 5 MINUTE
```

Не использовать `toUnixTimestamp64Nano()` для фильтра по `DateTime64` колонкам.

### 10.4. Долгий `systemctl stop xdpflowd`

**Симптом:** рестарт висит минутами.

**Причина:** final flush сканирует всю BPF map (миллионы flow).

**Фикс:** `XDP_FINAL_FLUSH=0` и `XDP_CH_SPOOL_SHUTDOWN_DRAIN=0s` для operational
рестартов (см. [`NEW_COLLECTOR_START_RUNBOOK.md`](NEW_COLLECTOR_START_RUNBOOK.md) §17).

### 10.5. UI показывает `unknown` / `??` из-за старого source_id

**Симптом:** в `traffic_pair_1m` / `traffic_talker_1m` видны строки с
`source_id = 'xdp-default'`, `direction = 'unknown'`, scope `unknown`, ASN `0`.

**Причина:** `xdpflowd` раньше стартовал с дефолтным `source_id=xdp-default`, а
после изменения `/etc/xdpflowd/xdpflowd.env` на `XDPFLOWD_SOURCE_ID=netflow`
старый процесс мог продолжать писать старую метку до рестарта. Это не второй
коллектор, а тот же collector с другим label.

**Фикс:**

```bash
grep '^XDPFLOWD_SOURCE_ID=' /etc/xdpflowd/xdpflowd.env
sudo systemctl restart xdpflowd

clickhouse-client ... --query "
SELECT source_id, max(time_received_ns), count()
FROM default.flows_raw
WHERE time_received_ns >= now64(9) - INTERVAL 5 MINUTE
GROUP BY source_id"
```

Ожидаем только production source (`netflow`). После этого старые `xdp-default`
строки можно удалить из `traffic_*` таблиц фоновой мутацией, а UI должен всегда
фильтровать `net_flow_sources_enabled.include_in_total = 1`.

---

## 11. Чеклист «БД поднята»

- [ ] Persistent volume для ClickHouse настроен (или осознанно принят риск)
- [ ] `flows_raw` + extensions + `net_flow_sources` + classifier tables
- [ ] `dns_log`, `bmp_*` (если используются)
- [ ] Таблицы `traffic_*` созданы (`deploy/clickhouse/traffic_*.sql`)
- [ ] **Нет** attached `traffic_*` MV (`detach_traffic_mvs.sql`)
- [ ] `traffic_rollup_state` создана, `traffic-rollups.timer` active
- [ ] `traffic_rollup_state FINAL`: `last_bucket` двигается каждую минуту
- [ ] `geo_country_dict` — `LOADED`, тест `dictGet` работает
- [ ] Users: `collector_write`, `ui_read`, `ui_admin` + grants
- [ ] Users: у `ui_read` / `ui_admin` нет `*_overflow_mode = 'break'`
      (проверочный SELECT из §4 должен вернуть 0 строк)
- [ ] `xdpflowd`: `lag_segments` ≈ 0, `map_full=0`, `raw_5m` > 0
- [ ] UI открывается без `Unknown table`

---

## 12. Быстрый one-liner мониторинга (m61)

```bash
watch -n 30 "
ch -q \"SELECT now(), max(time_received_ns), dateDiff('second', max(time_received_ns), now64(9)) lag_s, countIf(time_received_ns >= now64(9) - INTERVAL 5 MINUTE) raw_5m FROM default.flows_raw\" 2>/dev/null
ch -q \"SELECT job, last_bucket FROM default.traffic_rollup_state FINAL WHERE job IN ('traffic_dashboard_1m','traffic_protocol_1m') ORDER BY job\" 2>/dev/null
journalctl -u xdpflowd --since '2 minutes ago' --no-pager 2>/dev/null | grep -E 'health degraded|lag_segments' | tail -3
journalctl -u traffic-rollups.service --since '3 minutes ago' --no-pager 2>/dev/null | grep -E 'run complete|failed' | tail -2
"
```

---

*Последнее обновление: 2026-06-12 — async rollups в production, sync MV убраны
из deploy SQL, hot path = flows_raw + traffic-rollups.timer.*
