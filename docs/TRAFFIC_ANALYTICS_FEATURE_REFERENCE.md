# Network Analytics — полное описание фичи

Справочник по пайплайну трафиковой аналитики: ingest → classifier → rollups → UI.
Собран из реального деплоя на `m61` (июнь 2026). Используй как «не забыть».

Связанные документы:

- `UI_CLICKHOUSE_QUERIES.md` — SQL для дашборда
- `UI_TOP_TALKERS_TZ.md` — SQL для Top Talkers / Pairs
- `NET_ANALYTICS_OPERATIONS.md` — пошаговый деплой
- `XDPFLOWD_CLASSIFIER.md` — детали classifier
- `MVP_DASHBOARD_DATA_DESIGN.md` — модель данных

---

## 1. Что делает фича

Система принимает flow-данные, обогащает их (направление, ASN, страна, scope),
пишет в ClickHouse и строит минутные/часовые/дневные агрегаты для UI:

| Экран UI | Что показывает |
|----------|----------------|
| Дашборд (график, KPI) | трафик in/out/transit/internal по времени |
| Top Talkers → Источники | топ IP по src-стороне |
| Top Talkers → Назначения | топ IP по dst-стороне |
| Top Talkers → Пары | топ пар src→dst |
| Страны, протоколы, сервисы | донаты и heatmap |

**Единственный writer flow-трафика в production:** `xdpflowd` с `source_id=netflow`.

---

## 2. Архитектура (pipeline)

```
XDP mirror → xdpflowd (classifier) → flows_raw (ClickHouse)
                                         ↓
                              async rollups (systemd timers)
                                         ↓
                    traffic_*_1m → traffic_*_1h → traffic_*_1d
                                         ↓
                                    API / UI
```

Ключевые принципы:

1. **Обогащение один раз** — classifier пишет direction/ASN/scope/country в колонки
   `flows_raw` при ingest. Роллапы только группируют, не пересчитывают ASN.
2. **Минутная таблица = база** — часовые/дневные строятся из минутных, а не из
   повторного скана `flows_raw` (кроме `dashboard_1m`, который единственный читает raw
   по оси flow-start).
3. **Async rollups, не MV** — синхронные Materialized View отключены на горячем пути.
   Заполнение через `scripts/traffic_rollup_async.py` + systemd timers.
4. **Два непересекающихся таймера** — основной (9+2 джоба) и talkers (4 джоба).
   Джоб, которого нет ни в одном списке, тихо устаревает.

---

## 3. Источники данных (`source_id`)

| source_id | Кто пишет | В UI totals |
|-----------|-----------|-------------|
| `netflow` | `xdpflowd` (`XDPFLOWD_SOURCE_ID=netflow`) | да (`include_in_total=1`) |
| `dns-netflow` | `dnsflowd` | отдельно (DNS) |
| `xdp-default` | **LEGACY, не использовать** | нет |

### Проблема `xdp-default` (урок)

`xdp-default` — дефолтный `source_id` xdpflowd, когда `XDPFLOWD_SOURCE_ID` не задан.
Такие flows **не классифицированы**: `direction=unknown`, `scope=unknown`, ASN=0,
страна `??`. Если xdpflowd писал и `netflow`, и `xdp-default` параллельно, UI без
фильтра показывал «битые» данные.

**Сейчас:** в `/etc/xdpflowd/xdpflowd.env` стоит `XDPFLOWD_SOURCE_ID=netflow`.
Проверка:

```sql
SELECT source_id, max(time_received_ns), dateDiff('second', max(time_received_ns), now()) age_sec
FROM flows_raw WHERE time_received_ns > now() - INTERVAL 10 MINUTE
GROUP BY source_id;
-- ожидаем: только netflow, age_sec < 60
```

---

## 4. Classifier (обогащение)

Файл: `internal/flowingest/classifier.go`, конфиг: `/etc/xdpflowd/xdpflowd.env`.

### Порядок определения ASN

```
L3 prefixes (net_l3_prefixes)  →  BGP (bgp_prefix_origin_current)  →  IP→ASN fallback (ip_asn_prefixes_current)
```

### Таблицы-справочники

| Таблица | Назначение |
|---------|------------|
| `net_l3_prefixes` | локальные/клиентские префиксы |
| `bgp_prefix_origin_current` | BMP/BGP full-view |
| `ip_asn_prefixes_current` | fallback public IP→ASN (iptoasn.com) |
| geo dictionaries | страна по IP |

### Включение IP→ASN fallback

```bash
# DDL
clickhouse-client ... --multiquery < deploy/clickhouse/ip_asn_prefixes.sql
# загрузка
sudo systemctl start iptoasn-loader.service
# в xdpflowd.env (опционально, после загрузки таблицы):
XDP_CLASSIFIER_IP_ASN_TABLE=default.ip_asn_prefixes_current
sudo systemctl restart xdpflowd
```

Проверка в логах:

```
traffic classifier refreshed bgp_prefixes=... ip_asn_prefixes=1009325 ...
```

### Колонки enrichment в `flows_raw`

`direction`, `src_asn`, `dst_asn`, `src_endpoint_scope`, `dst_endpoint_scope`,
`src_ip_country`, `dst_ip_country`, и др. — см. `deploy/clickhouse/flows_raw_extensions.sql`.

---

## 5. Rollup-таблицы

### 5.1. Полный список джобов (15)

| job_id | dest_table | Источник | bucket | Кто гоняет |
|--------|------------|----------|--------|------------|
| `traffic_dashboard_1m` | `traffic_dashboard_1m` | `flows_raw` (received) | minute | rollups |
| `traffic_protocol_1m` | `traffic_protocol_1m` | `flows_raw` (received) | minute | rollups |
| `traffic_direction_1m` | `traffic_direction_1m` | `flows_raw` | minute | rollups |
| `traffic_role_1m` | `traffic_role_1m` | `flows_raw` | minute | rollups |
| `traffic_entity_1m` | `traffic_entity_1m` | `flows_raw` | minute | rollups |
| `traffic_vlan_1m` | `traffic_vlan_1m` | `flows_raw` | minute | rollups |
| `traffic_country_1m` | `traffic_country_1m` | `flows_raw` | minute | rollups |
| `traffic_service_1m` | `traffic_service_1m` | `flows_raw` | minute | rollups |
| `traffic_unknown_port_1m` | `traffic_unknown_port_1m` | `flows_raw` | minute | rollups |
| `traffic_dashboard_1h` | `traffic_dashboard_1h` | **`traffic_dashboard_1m`** | hour | rollups |
| `traffic_dashboard_1d` | `traffic_dashboard_1d` | **`traffic_dashboard_1m`** | day | rollups |
| `traffic_asn_1m` | `traffic_asn_1m` | `flows_raw` | minute | talkers |
| `traffic_asn_pair_1m` | `traffic_asn_pair_1m` | `flows_raw` | minute | talkers |
| `traffic_asn_1h` | `traffic_asn_1h` | **`traffic_asn_1m`** | hour | talkers |
| `traffic_asn_pair_1h` | `traffic_asn_pair_1h` | **`traffic_asn_pair_1m`** | hour | talkers |

### 5.2. Иерархия «прочитать raw один раз, дальше вокруг»

```
flows_raw
  ├─ dashboard_1m (единственный flow-start скан, с received-guard)
  │    ├─ dashboard_1h  (sum из 1m, ~60 строк/час)
  │    └─ dashboard_1d  (sum из 1m, ~1440 строк/сутки)
  ├─ protocol/direction/country/..._1m  (лёгкие, по received_ns)
  ├─ asn_1m
  │    └─ asn_1h
  └─ asn_pair_1m
       └─ asn_pair_1h
```

**Не делаем** единую staging-таблицу для всех минутных джобов: разные GROUP BY,
ClickHouse колоночный, минутные сканы уже дешёвые (~100–500 ms).

### 5.3. TTL

| Таблица | TTL |
|---------|-----|
| `*_1m` (talker, pair, dashboard) | 2 дня |
| `*_1h` (talker, pair, dashboard) | 90 дней |

Часовой/дневной джоб **должен досчитаться, пока минутные строки живы** (в пределах 2 суток).

### 5.4. Dashboard time axis: `time_received_ns`

`traffic_dashboard_1m` группирует по `time_received_ns` (момент экспорта /
прихода в ClickHouse), как остальные минутные `traffic_*` rollups.

Раньше ось была `time_flow_start_ns`. При `XDP_NF_ACTIVE=120s` часть байт
уезжала за левую границу выбранного UI-окна (~2–3%), и смена active timeout
меняла уровень графика без изменения реального трафика.

`dashboard_1h`/`1d` по-прежнему суммируют `dashboard_1m` и не читают `flows_raw`
напрямую.

---

## 6. Systemd: таймеры и env

### 6.1. Файлы

| Файл на хосте | Назначение |
|---------------|------------|
| `/etc/systemd/system/traffic-rollups.service` | основные rollups |
| `/etc/systemd/system/traffic-rollups.timer` | каждую 1 мин |
| `/etc/systemd/system/traffic-talkers-rollups.service` | talker/pair rollups |
| `/etc/systemd/system/traffic-talkers-rollups.timer` | каждую 1 мин (было 5 мин) |
| `/etc/grapesnta/traffic-rollups.env` | CH creds, MAX_BUCKETS=5 |
| `/etc/grapesnta/traffic-talkers-rollups.env` | опционально, наследует rollups.env |

### 6.2. ExecStart (обязательно полные и непересекающиеся!)

**traffic-rollups.service:**

```
--jobs traffic_dashboard_1m,traffic_protocol_1m,traffic_direction_1m,
       traffic_role_1m,traffic_entity_1m,traffic_vlan_1m,traffic_country_1m,
       traffic_service_1m,traffic_unknown_port_1m,
       traffic_dashboard_1h,traffic_dashboard_1d
```

**traffic-talkers-rollups.service:**

```
--jobs traffic_asn_1m,traffic_asn_1h,traffic_asn_pair_1m,traffic_asn_pair_1h
```

### 6.3. Ключевые env-переменные

```ini
TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB=5    # самодогон мелких отставаний
TRAFFIC_ROLLUP_SAFETY_LAG_MINUTES=5     # не rollup'ить последние 5 мин
TRAFFIC_ROLLUP_MAX_RAW_LAG_SECONDS=120  # пропуск если flows_raw отстаёт
```

### 6.4. Деплой юнитов из репо

```bash
cd /opt/GrapesNTA && git pull
sudo cp deploy/systemd/traffic-rollups.service /etc/systemd/system/
sudo cp deploy/systemd/traffic-talkers-rollups.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart traffic-rollups.timer traffic-talkers-rollups.timer
```

---

## 7. UI: какая таблица для какого периода

### 7.1. Дашборд (график, KPI)

| Период UI | Таблица |
|-----------|---------|
| до 7 дней | `traffic_dashboard_1m` (5-мин бакеты) |
| > 7 дней total/avg | `traffic_dashboard_1d` |
| > 7 дней peak | `traffic_dashboard_1h` |

Live-edge guard: `ts_to = now() - INTERVAL 30 SECOND` (не `now()`).

### 7.2. Top Talkers (ASN)

| Период UI | Talkers | Pairs |
|-----------|---------|-------|
| ≤ 1 час | `traffic_asn_1m` | `traffic_asn_pair_1m` |
| 3h / 6h / 12h / 24h+ | `traffic_asn_1h` | `traffic_asn_pair_1h` |

| Вкладка | Фильтр |
|---------|--------|
| Источники | `endpoint_side = 'src'` |
| Назначения | `endpoint_side = 'dst'` |
| Пары | отдельная таблица `traffic_asn_pair_*` (`src_asn → dst_asn`) |

| Фильтр направления UI | SQL |
|-----------------------|-----|
| Всего | `direction IN ('in','out','transit','internal','unknown')` |
| Входящий | `direction IN ('in')` |
| Исходящий | `direction IN ('out')` |

**Нет** `direction = 'total'` в таблицах!

По умолчанию: `INNER JOIN net_flow_sources_enabled WHERE include_in_total = 1`.

> UI NTAdmin пока может ссылаться на legacy `traffic_talker_*` / `traffic_pair_*`
> — переключение на ASN-таблицы отдельной задачей.

### 7.3. Семантика направлений для Top Talkers

| direction | endpoint_side | Смысл |
|-----------|---------------|-------|
| `out` | `src` | кто из нашей сети отправляет наружу |
| `in` | `dst` | кто снаружи отправляет к нам |
| `in` | `src` | внешний отправитель входящего |
| `out` | `dst` | внешнее назначение исходящего |

---

## 8. Операции

### 8.1. Чистый старт (старые данные не нужны)

```bash
sudo systemctl stop traffic-rollups.timer traffic-talkers-rollups.timer
set -a; . /etc/grapesnta/traffic-rollups.env; set +a
CH="clickhouse-client --host $TRAFFIC_ROLLUP_CH_HOST --port $TRAFFIC_ROLLUP_CH_PORT \
  --user $TRAFFIC_ROLLUP_CH_USER --password $TRAFFIC_ROLLUP_CH_PASSWORD"

for T in traffic_dashboard_1m traffic_dashboard_1h traffic_dashboard_1d \
         traffic_protocol_1m traffic_direction_1m traffic_role_1m \
         traffic_entity_1m traffic_vlan_1m traffic_country_1m \
         traffic_service_1m traffic_unknown_port_1m \
         traffic_asn_1m traffic_asn_1h traffic_asn_pair_1m traffic_asn_pair_1h; do
  $CH --query "TRUNCATE TABLE default.$T"
done

# state = текущий край
$CH --query "INSERT INTO traffic_rollup_state (job,last_bucket,status,last_error,updated_at)
SELECT arrayJoin([...минутные джобы...]), toStartOfMinute(now()),'ok','',now()"
# аналогично для *_1h (toStartOfHour) и dashboard_1d (toStartOfDay)

sudo systemctl start traffic-rollups.timer traffic-talkers-rollups.timer
```

### 8.2. Skip-backfill (перескочить backlog, создаёт дырку в истории)

```sql
INSERT INTO traffic_rollup_state (job, last_bucket, status, last_error, updated_at)
SELECT job, toStartOfHour(now() - INTERVAL 1 HOUR), 'ok', 'skip backlog', now()
FROM (SELECT arrayJoin(['traffic_dashboard_1h','traffic_asn_1h','traffic_asn_pair_1h']) AS job);
```

### 8.3. Backfill с реального максимума (без дырки)

```sql
INSERT INTO traffic_rollup_state (job,last_bucket,status,last_error,updated_at)
SELECT 'traffic_dashboard_1h', max(hour), 'ok', '', now() FROM traffic_dashboard_1h;
```

Затем таймеры с `MAX_BUCKETS_PER_JOB=5` догонят сами.

---

## 9. Мониторинг

### 9.1. Lag (главный индикатор «захлёбывается»)

```bash
watch -n 30 "$CH --query \"
SELECT job, dateDiff('minute', last_bucket, now()) lag_min, status
FROM traffic_rollup_state FINAL WHERE job LIKE 'traffic_%'
ORDER BY lag_min DESC FORMAT PrettyCompact\""
```

| lag_min | Норма? |
|---------|--------|
| `*_1m`: 5–7 | да (SAFETY_LAG=5) |
| `*_1m`: растёт | захлёбывается |
| `*_1h`: ~60 (текущий час) | да |
| `*_1d`: ~1440 (текущие сутки) | да |

### 9.2. Скорость роллапов

```bash
journalctl -u traffic-rollups.service --since '10 min ago' --no-pager \
  | grep -E 'dashboard_1m|run complete|duration_ms'
```

Норма: `dashboard_1m` < 500 ms, `run complete elapsed_s` < 60.

### 9.3. Health-check

```bash
python3 scripts/check_traffic_data_quality.py
```

| Результат | Значение |
|-----------|----------|
| `freshness.* OK` | таблица свежая |
| `rollup_state.* OK` | джоб двигается |
| `sources.*xdp-default FAIL` | появился legacy-источник |
| `raw_vs_direction_agg FAIL` | raw и агрегаты расходятся |
| `remote_asn_zero_gb FAIL/WARN` | transit ASN coverage |
| `freshness.vlan_1m empty` | нет VLAN в трафике (не баг) |

---

## 10. Полная диагностика (чеклист)

Выполнять по порядку. Все OK → пайплайн здоров, проблема в API/UI.

1. **Ingest:** только `netflow` в `flows_raw` за 10 мин, `age_sec < 60`
2. **Classifier:** direction без `unknown`, scope без `unknown`, local ASN не ноль
3. **IP→ASN:** `ip_asn_prefixes_current` > 0 rows, xdpflowd logs `ip_asn_prefixes=...`
4. **Timers:** оба active, job lists полные и непересекающиеся
5. **Lag:** `*_1m` ~5–7, не растёт
6. **Speed:** `dashboard_1m` < 500 ms, `elapsed_s` < timer interval
7. **Sources:** rollups только `netflow`, нет `xdp-default`
8. **Top Talkers CH:** запрос 30m/Источники совпадает с UI (если нет → API/cache)
9. **Dashboard CH:** график/KPI за 30m свежие
10. **Health-check:** без FAIL

---

## 11. Известные ограничения

| Тема | Статус | Действие |
|------|--------|----------|
| Transit `remote_asn_zero` ~10% | WARN/FAIL | топ IP с `src_asn=0`, расширить fallback |
| VLAN в трафике = 0 | ожидаемо | SPAN без VLAN tags; `vlan_1m` пустая |
| `dashboard_1d` lag ~500 min | норма | дневной джоб ждёт закрытия суток |
| UI старые данные при свежем CH | баг API | проверить endpoint, cache, CH host |
| `flows_raw` xdp-default остаток | не критично | TTL уйдёт; роллапы после truncate не читают |
| `ip_asn_prefixes` snapshot 2 дня | ок | iptoasn-loader timer ежедневно |

---

## 12. История инцидентов (кратко)

| Проблема | Причина | Fix |
|----------|---------|-----|
| Top Talkers одинаковые для всех направлений | `xdp-default` без classifier | `XDPFLOWD_SOURCE_ID=netflow`, truncate |
| `??`, ASN=0, scope=unknown | unclassified `xdp-default` в rollups | чистка + фильтр `include_in_total` |
| Rollups захлёбываются | `dashboard_1m` сканировал всю `flows_raw` по flow-start | received-guard (`004c048`) |
| `dashboard_1h/1d` старые | джобы не были в systemd `--jobs` | явные списки (`32f9134`) |
| UI старый при свежем CH | API/cache/не тот backend | диагностика API отдельно |
| `dashboard_1h` медленный | повторный скан `flows_raw` | sum из `dashboard_1m` (`6e5eff0`) |

---

## 13. Git commits (feature/dnsflowd-mvp)

| Commit | Что |
|--------|-----|
| `0a97284` | IP→ASN fallback loader + classifier |
| `004c048` | received-time guard для dashboard_1m/_1h |
| `32f9134` | systemd job lists + MAX_BUCKETS=5 |
| `6e5eff0` | dashboard_1h/1d из dashboard_1m |

---

## 14. Быстрые команды (copy-paste)

```bash
cd /opt/GrapesNTA
set -a; . /etc/grapesnta/traffic-rollups.env; set +a
CH="clickhouse-client --host $TRAFFIC_ROLLUP_CH_HOST --port $TRAFFIC_ROLLUP_CH_PORT \
  --user $TRAFFIC_ROLLUP_CH_USER --password $TRAFFIC_ROLLUP_CH_PASSWORD"

# свежесть
$CH --query "SELECT job, dateDiff('minute', last_bucket, now()) lag FROM traffic_rollup_state FINAL WHERE job LIKE 'traffic_%' ORDER BY lag DESC FORMAT PrettyCompact"

# только netflow?
$CH --query "SELECT source_id, count() FROM flows_raw WHERE time_received_ns > now()-600 GROUP BY source_id FORMAT PrettyCompact"

# health
python3 scripts/check_traffic_data_quality.py

# top ASN talkers 30m (эталон для UI)
$CH --query "
WITH now() AS ts_to, ts_to - INTERVAL 30 MINUTE AS ts_from
SELECT endpoint_asn, any(endpoint_as_name) AS name, round(sum(bytes)/1e9,1) gb
FROM traffic_asn_1m t
JOIN net_flow_sources_enabled s ON t.source_id=s.source_id
WHERE s.include_in_total=1 AND t.minute>=ts_from AND t.minute<ts_to
  AND t.endpoint_side='src'
  AND t.direction IN ('in','out','transit','internal','unknown')
GROUP BY endpoint_asn ORDER BY gb DESC LIMIT 10 FORMAT PrettyCompact"
```

---

*Последнее обновление: 2026-07-13, ASN talkers/pairs вместо IP.*
