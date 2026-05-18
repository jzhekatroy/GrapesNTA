# Laravel + MoonShine: Traffic In/Out bps

Инструкция для разработчика Laravel + MoonShine. Цель — построить график
`Traffic In/Out, bps` без тяжелого чтения `default.flows_raw` при каждом
открытии страницы.

## Ключевая идея

API должен читать агрегат:

```text
default.traffic_direction_1m
```

а не `default.flows_raw`.

Агрегат содержит уже классифицированный трафик:

```text
minute
direction
bytes
packets
flows_count
```

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
```

`traffic_direction_1m.sql` создает:

```text
default.traffic_direction_1m
default.traffic_direction_1m_mv
```

MV делает только легкий `GROUP BY minute, direction`.

## Проверка агрегата

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" --query "
SELECT
    minute,
    direction,
    formatReadableSize(sum(bytes)) AS traffic,
    sum(bytes) AS bytes_total,
    sum(flows_count) AS flows
FROM default.traffic_direction_1m
WHERE minute >= now() - INTERVAL 10 MINUTE
GROUP BY
    minute,
    direction
ORDER BY minute DESC, bytes_total DESC
LIMIT 20
FORMAT PrettyCompactMonoBlock
"
```

## Backfill истории

MV считает только новые flow после создания MV. Чтобы заполнить историю из уже
обогащенных строк `flows_raw`, использовать скрипт:

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

Старые строки без classifier-полей попадут как `direction='unknown'`.

## API Endpoint

Сделать endpoint:

```text
GET /api/traffic/in-out
```

Параметры:

```text
from   ISO-8601 UTC timestamp, optional, default now - 1 hour
to     ISO-8601 UTC timestamp, optional, default now
scale  one of: 1m, 5m, 15m, 1h; optional, default 1m
```

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

## SQL Для API

Подставить:

```text
{bucket_seconds}  60 / 300 / 900 / 3600
{from_utc}        UTC timestamp
{to_utc}          UTC timestamp
```

Запрос:

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
    sum(flows_count) AS flows
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
ORDER BY bucket
SETTINGS
    max_memory_usage = 1000000000,
    max_threads = 4
```

Важно: `traffic_direction_1m` — `SummingMergeTree`, поэтому в запросе всегда
нужны `sum(bytes)`, `sum(packets)`, `sum(flows_count)`. Не читать строки как
уже финальные значения без агрегации.

## Ответ API

Вернуть JSON:

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
      "total_bps": 4788762689.0,
      "in_pps": 12000.0,
      "out_pps": 9000.0,
      "transit_pps": 450000.0,
      "flows": 123456
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
- `flows` показывать в tooltip или summary card.

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
строить по `traffic_direction_1m`, `traffic_uplink_1m`,
`traffic_customer_1m`.
