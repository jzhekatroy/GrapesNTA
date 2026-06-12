# Runbook: поднятие ClickHouse с нуля (GrapesNTA)

Документ фиксирует опыт восстановления аналитической БД после потери схемы
(июнь 2026, сервер `m61`, ClickHouse `95.215.1.30:6124`). Цель — не повторять
те же ошибки при следующем развёртывании.

Связанные документы:

- [`CLICKHOUSE_SCHEMA.md`](CLICKHOUSE_SCHEMA.md) — общая топология Kafka/goflow2/flows_raw
- [`geoip_country.md`](geoip_country.md) — RIR geo loader и dictionary
- [`NEW_COLLECTOR_START_RUNBOOK.md`](NEW_COLLECTOR_START_RUNBOOK.md) — разделы 15–18 (classifier, MV, spool)
- [`UI_CLICKHOUSE_QUERIES.md`](UI_CLICKHOUSE_QUERIES.md) — запросы UI

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
  → ClickHouse default.flows_raw
  → лёгкие MV (dashboard/protocol/direction) — синхронно
  → тяжёлые MV (talker/pair/country/service/…) — НЕ на hot path

dnsflowd → default.dns_log
bmpgrapes → default.bmp_*
classifier читает net_l3_prefixes / net_l2_vlans / bgp_prefix_origin_current
UI читает traffic_*_1m, net_flow_sources_enabled, system.dictionaries
```

На `m61` запись идёт **напрямую** из `xdpflowd` (без Kafka/goflow2). Схема
`flows_raw` и аналитические MV должны существовать до cutover.

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
CREATE USER IF NOT EXISTS ui_read IDENTIFIED BY '***';
CREATE USER IF NOT EXISTS ui_admin IDENTIFIED BY '***';

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

### Проблема: `ACCESS_DENIED` у UI

**Симптом:** UI не открывается, в логах `ACCESS_DENIED` на
`system.dictionaries`, `system.tables`, `system.columns`.

**Фикс:** добавить `ui_read` явные grants на перечисленные `system`-таблицы
(см. выше). Для geo loader — `ui_admin` нужен `CREATE DICTIONARY` и
`SYSTEM RELOAD DICTIONARY`.

---

## 5. Порядок применения SQL (с нуля)

Все скрипты: `deploy/clickhouse/*.sql`. Применять `--multiquery` от `develop`
или `ui_admin`.

### 5.1. База raw и enrichment

```bash
REPO=/opt/GrapesNTA   # или путь к клону

for f in \
  flows_raw_extensions.sql \
  net_flow_sources.sql \
  flows_raw_source_id.sql \
  net_entities.sql \
  net_l3_prefixes.sql \
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
`vlan_id`, `source_id`, …) — без неё MV не соберутся.

### 5.2. Минутные агрегаты (traffic_*)

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

UI без этих объектов падает с `Unknown table expression identifier`.

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

## 7. Materialized Views: что включать на ingest

### 7.1. Безопасный набор (оставлять ATTACHed)

Синхронно на `INSERT flows_raw` держим только лёгкие MV:

- `traffic_dashboard_1m_mv`, `traffic_dashboard_1h_mv`, `traffic_dashboard_1d_mv`
- `traffic_protocol_1m_mv`
- `traffic_direction_1m_mv`

После detach тяжёлых MV ingest стабилизировался: `lag_segments` падает,
`raw_5m` свежий, `lag_s` в секундах.

### 7.2. Тяжёлые MV — DETACH на production ingest

**Подтверждено экспериментом (2026-06-11):** включение `traffic_talker_*` /
`traffic_pair_*` сразу даёт рост `lag_segments` (до 28+), `writer_lag_rows`
(20M+), `xdpflowd health degraded`. ClickHouse не успевает синхронно считать
fan-out на каждый insert.

Отцепить:

```sql
DETACH TABLE default.traffic_talker_1m_mv;
DETACH TABLE default.traffic_pair_1m_mv;
DETACH TABLE default.traffic_talker_1h_mv;
DETACH TABLE default.traffic_pair_1h_mv;
DETACH TABLE default.traffic_unknown_port_1m_mv;
DETACH TABLE default.traffic_country_1m_mv;
DETACH TABLE default.traffic_service_1m_mv;
DETACH TABLE default.traffic_role_1m_mv;
DETACH TABLE default.traffic_entity_1m_mv;
DETACH TABLE default.traffic_vlan_1m_mv;
```

Данные в `flows_raw` при DETACH **не теряются**. Агрегаты можно досчитать
позже async job / refreshable MV / отдельным ETL.

Диагностика узкого места:

```sql
SELECT
    view_name,
    count() AS inserts,
    sum(read_rows) AS read_rows,
    sum(written_rows) AS written_rows,
    round(avg(view_duration_ms)) AS avg_ms,
    round(sum(view_duration_ms)) AS total_ms
FROM system.query_views_log
WHERE event_time >= now() - INTERVAL 10 MINUTE
GROUP BY view_name
ORDER BY total_ms DESC;
```

### 7.3. Постоянное решение (TODO для архитектуры)

Перевести `talker/pair/country/service/role/entity/vlan` на асинхронный
пересчёт с лагом 1–5 минут. Hot path = только `flows_raw` + 3–5 лёгких MV.

---

## 8. Заполнение справочников для classifier и UI

После пустой БД classifier пишет `direction=unknown`, роли пустые.

Нужно загрузить (через UI admin или SQL):

- `net_l3_prefixes` — локальные/клиентские префиксы
- `net_l2_vlans` — VLAN → entity
- `bgp_prefix_origin_current` — BGP origin (если есть bmpgrapes)
- `net_flow_sources` — registry source_id (`netflow`, `dns-netflow`, …)

Проверка classifier на коллекторе:

```bash
grep -E '^(XDP_CLASSIFIER|XDP_CLASSIFIER_)' /etc/xdpflowd/xdpflowd.env
journalctl -u xdpflowd -n 50 --no-pager | grep -i classifier
```

Ожидаем: `traffic classifier enabled`, `has_local_config=true`.

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
SELECT max(bucket) AS last_bucket, sum(bytes) AS bytes_5m
FROM default.traffic_protocol_1m
WHERE bucket >= now() - INTERVAL 5 MINUTE;
```

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

---

## 11. Чеклист «БД поднята»

- [ ] Persistent volume для ClickHouse настроен (или осознанно принят риск)
- [ ] `flows_raw` + extensions + `net_flow_sources` + classifier tables
- [ ] `dns_log`, `bmp_*` (если используются)
- [ ] `traffic_dashboard_*`, `traffic_protocol_1m`, `traffic_direction_1m` — ATTACHed
- [ ] Тяжёлые MV — DETACHed на ingest
- [ ] `geo_country_dict` — `LOADED`, тест `dictGet` работает
- [ ] Users: `collector_write`, `ui_read`, `ui_admin` + grants
- [ ] `xdpflowd`: `lag_segments` ≈ 0, `map_full=0`, `raw_5m` > 0
- [ ] UI открывается без `Unknown table`

---

## 12. Быстрый one-liner мониторинга (m61)

```bash
watch -n 30 "
ch -q \"SELECT now(), max(time_received_ns), dateDiff('second', max(time_received_ns), now64(9)) lag_s, countIf(time_received_ns >= now64(9) - INTERVAL 5 MINUTE) raw_5m FROM default.flows_raw\" 2>/dev/null
journalctl -u xdpflowd --since '2 minutes ago' --no-pager 2>/dev/null | grep -E 'health degraded|lag_segments' | tail -3
"
```

---

*Последнее обновление: 2026-06-11 — восстановление после потери Docker volume,
подтверждение bottleneck на sync MV talker/pair.*
