# Laravel + MoonShine: Traffic In/Out bps

Инструкция для разработчика Laravel + MoonShine. Цель — построить график
`Traffic In/Out, bps` без тяжелого чтения `default.flows_raw` при каждом
открытии страницы.

## Ключевая идея

API должен читать pivot-агрегат:

```text
default.traffic_chart_1m
```

Одна строка = одна минута со всеми направлениями уже в колонках (`in_bytes`,
`out_bytes`, ...). Это быстрее, чем каждый раз делать `sumIf(direction = ...)`
по `default.traffic_direction_1m`.

`traffic_direction_1m` остаётся нормализованным агрегатом для аналитики и
fallback/debug. Не использовать его как основной источник графика.

Direction (`in/out/internal/transit`) считает `xdpflowd` до записи в
ClickHouse по правилу:

```text
VLAN > local ASN > local prefix
```

Laravel не должен делать `dictGet`, `arrayExists` или пересчитывать direction
при чтении графика.

## Что применить в ClickHouse

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/local_networks.sql

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/local_asns.sql

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/vlan_map.sql

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/flows_raw_extensions.sql

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/traffic_direction_1m.sql

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/traffic_chart_1m.sql
```

`traffic_chart_1m.sql` создает:

```text
default.traffic_chart_1m
default.traffic_chart_1m_mv
```

После DDL — backfill истории из уже заполненной `traffic_direction_1m`:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --database default \
  --queries-file deploy/clickhouse/backfill_traffic_chart_1m.sql
```

Перед backfill отредактировать `WHERE minute >= ...` в
`backfill_traffic_chart_1m.sql` под нужное окно.

Проверка:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --queries-file deploy/clickhouse/traffic_chart_1m_validate.sql
```

(каждый запрос из validate-файла выполнять отдельно, если клиент не поддерживает
multi-statement).

## Проверка агрегата

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" --query "
SELECT
    minute,
    formatReadableSize(sum(total_bytes)) AS total,
    formatReadableSize(sum(in_bytes)) AS in_traffic,
    formatReadableSize(sum(out_bytes)) AS out_traffic,
    sum(total_flows) AS flows
FROM default.traffic_chart_1m
WHERE minute >= now() - INTERVAL 10 MINUTE
GROUP BY minute
ORDER BY minute DESC
LIMIT 10
FORMAT PrettyCompactMonoBlock
"
```

## Backfill истории direction (если нужно)

MV `traffic_direction_1m` считает только новые flow после создания MV.
Для истории из `flows_raw`:

```bash
python3 scripts/backfill_traffic_direction.py \
  --host 95.215.1.30 \
  --port 6124 \
  --user develop \
  --password "$CH_PASS" \
  --from "2026-05-18 10:00:00" \
  --to   "2026-05-18 11:00:00" \
  --chunk-minutes 15
```

Затем повторить `backfill_traffic_chart_1m.sql` за тот же период.

## API Endpoint

```text
GET /api/traffic/in-out
```

Параметры:

```text
from   ISO-8601 UTC timestamp, optional, default now - 1 hour
to     ISO-8601 UTC timestamp, optional, default now
scale  one of: 1m, 5m, 15m, 1h; optional, default 1m
```

Ограничение MVP: максимальное окно UI — **200 минут**. API должен отклонять
более длинные диапазоны или автоматически увеличивать `scale`.

Маппинг `scale`:

```php
$bucketSeconds = match ($scale) {
    '1m' => 60,
    '5m' => 300,
    '15m' => 900,
    '1h' => 3600,
    default => throw ValidationException::withMessages([
        'scale' => 'Invalid scale',
    ]),
};
```

`scale` обязательно валидировать whitelist-ом. В SQL подставлять только
проверенное число `$bucketSeconds`.

## SQL Для API (primary)

Источник: `default.traffic_chart_1m`. Без inner subquery и без `sumIf` по
direction на чтении.

Подставить:

```text
{bucket_seconds}  60 / 300 / 900 / 3600
{from_utc}        UTC timestamp
{to_utc}          UTC timestamp
```

```sql
WITH {bucket_seconds} AS bucket_seconds
SELECT
    toDateTime(intDiv(toUInt32(minute), bucket_seconds) * bucket_seconds, 'UTC') AS ts,

    sum(total_bytes)     * 8 / bucket_seconds AS total_bps,
    sum(in_bytes)        * 8 / bucket_seconds AS in_bps,
    sum(out_bytes)       * 8 / bucket_seconds AS out_bps,
    sum(transit_bytes)   * 8 / bucket_seconds AS transit_bps,
    sum(internal_bytes)  * 8 / bucket_seconds AS internal_bps,
    sum(unknown_bytes)   * 8 / bucket_seconds AS unknown_bps,

    sum(total_packets)   / bucket_seconds AS total_pps,
    sum(in_packets)      / bucket_seconds AS in_pps,
    sum(out_packets)     / bucket_seconds AS out_pps,
    sum(transit_packets) / bucket_seconds AS transit_pps,
    sum(internal_packets)/ bucket_seconds AS internal_pps,
    sum(unknown_packets) / bucket_seconds AS unknown_pps,

    sum(total_flows)     / bucket_seconds AS flows_per_sec,

    if(sum(total_bytes) > 0,
       sum(unknown_bytes) * 100.0 / sum(total_bytes),
       0) AS unknown_percent,
    if(sum(total_packets) > 0,
       sum(total_bytes) / sum(total_packets),
       0) AS avg_packet_size

FROM default.traffic_chart_1m
WHERE minute >= toDateTime('{from_utc}', 'UTC')
  AND minute <  toDateTime('{to_utc}', 'UTC')
GROUP BY ts
ORDER BY ts
SETTINGS
    max_memory_usage = 500000000,
    max_threads = 4
```

Важно: `traffic_chart_1m` — `SummingMergeTree`, поэтому в запросе всегда
нужны `sum(in_bytes)`, `sum(out_bytes)` и т.д.

## Smoke test (последний час, bucket 60s)

```sql
WITH 60 AS bucket_seconds
SELECT
    toDateTime(intDiv(toUInt32(minute), bucket_seconds) * bucket_seconds, 'UTC') AS ts,
    sum(total_bytes) * 8 / bucket_seconds AS total_bps,
    sum(in_bytes) * 8 / bucket_seconds AS in_bps,
    sum(out_bytes) * 8 / bucket_seconds AS out_bps,
    sum(transit_bytes) * 8 / bucket_seconds AS transit_bps,
    sum(total_packets) / bucket_seconds AS total_pps,
    sum(total_flows) / bucket_seconds AS flows_per_sec
FROM default.traffic_chart_1m
WHERE minute >= now('UTC') - INTERVAL 1 HOUR
  AND minute < now('UTC')
GROUP BY ts
ORDER BY ts;
```

## Fallback SQL (debug)

Если `traffic_chart_1m` еще не развернута, временно можно использовать
`traffic_direction_1m`:

```sql
WITH {bucket_seconds} AS bucket_seconds
SELECT
    bucket AS ts,
    sumIf(bytes, direction = 'in')       * 8 / bucket_seconds AS in_bps,
    sumIf(bytes, direction = 'out')      * 8 / bucket_seconds AS out_bps,
    sumIf(bytes, direction = 'transit')  * 8 / bucket_seconds AS transit_bps,
    sumIf(bytes, direction = 'internal') * 8 / bucket_seconds AS internal_bps,
    sum(bytes)                           * 8 / bucket_seconds AS total_bps,
    sumIf(packets, direction = 'in')       / bucket_seconds AS in_pps,
    sumIf(packets, direction = 'out')      / bucket_seconds AS out_pps,
    sumIf(packets, direction = 'transit')  / bucket_seconds AS transit_pps,
    sum(flows_count) / bucket_seconds AS flows_per_sec
FROM
(
    SELECT
        toDateTime(intDiv(toUInt32(minute), bucket_seconds) * bucket_seconds, 'UTC') AS bucket,
        bytes,
        packets,
        flows_count,
        direction
    FROM default.traffic_direction_1m
    WHERE minute >= toDateTime('{from_utc}', 'UTC')
      AND minute <  toDateTime('{to_utc}', 'UTC')
)
GROUP BY bucket
ORDER BY bucket;
```

## Ответ API

```json
{
  "from": "2026-05-15T10:00:00Z",
  "to": "2026-05-15T11:00:00Z",
  "scale": "1m",
  "series": [
    {
      "ts": "2026-05-15T10:00:00Z",
      "in_bps": 123456789.0,
      "out_bps": 98765432.0,
      "transit_bps": 4567890123.0,
      "internal_bps": 12345.0,
      "unknown_bps": 0.0,
      "total_bps": 4788762689.0,
      "in_pps": 12000.0,
      "out_pps": 9000.0,
      "transit_pps": 450000.0,
      "total_pps": 500000.0,
      "flows_per_sec": 123456.0,
      "unknown_percent": 0.5,
      "avg_packet_size": 1200.0
    }
  ]
}
```

В Laravel заполнить отсутствующие bucket-ы нулями, чтобы линия на графике не
рвалась.

## UI

На первом экране:

- по умолчанию рисовать `total_bps`;
- `in_bps`, `out_bps`, `transit_bps`, `internal_bps` сделать toggle-сериями;
- `total_pps` / `in_pps` / `out_pps` — второй график или toggle;
- `flows_per_sec` показывать в tooltip или summary card;
- `unknown_bps` и `unknown_percent` — diagnostic toggle, не default.

Не складывать `transit` в `out`, если classifier уже включен.

## MoonShine Admin

Нужны resources для:

```text
default.local_operators
default.local_networks
default.local_asns
default.vlan_map
```

Поля:

```text
local_operators: operator_id, name, source, enabled
local_networks:  prefix, family, operator_id, kind, name, source, enabled
local_asns:      asn, operator_id, name, source, enabled
vlan_map:        vlan_id, kind, label, operator_id, source, enabled
```

Изменения справочников влияют на новые flow после следующего refresh
`xdpflowd`. Историю пересчитывать отдельным backfill, если нужно.

## Ограничение MVP

`traffic_asn_pair_1m` оставлен только как deprecated fallback. Новые экраны
строить по `traffic_chart_1m` (график), `traffic_uplink_1m`,
`traffic_customer_1m`.
