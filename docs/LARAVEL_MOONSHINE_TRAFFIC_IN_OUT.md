# Laravel + MoonShine: Traffic In/Out bps

Инструкция для разработчика Laravel + MoonShine. Цель — построить график
`Traffic In/Out, bps` без тяжелого чтения `default.flows_raw` при каждом
открытии страницы.

## Ключевая идея

API должен читать агрегат:

```text
default.traffic_asn_pair_1m
```

а не `default.flows_raw`.

Агрегат содержит трафик по парам origin ASN:

```text
minute
src_asn
dst_asn
bytes
packets
flows_count
```

Direction (`in/out/internal/transit`) считается уже в API-запросе по списку
локальных ASN из:

```text
default.local_asns_enabled
```

Почему так: если завтра оператор добавит `AS50509 TRANSROUTE` или другой
customer/downstream ASN в список локальных, старую историю не надо
пересчитывать. Мы просто иначе классифицируем те же `src_asn/dst_asn` пары.

## Что применить в ClickHouse

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/local_networks.sql

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/traffic_asn_pair_1m.sql
```

`traffic_asn_pair_1m.sql` создает:

```text
default.traffic_asn_pair_1m
default.traffic_asn_pair_1m_mv
```

MV будет заполнять агрегат только для IPv4 (`etype = 0x0800`), используя уже
рабочий dictionary:

```text
default.bgp_origin_asn_dict
```

## Проверка агрегата

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" --query "
SELECT
    minute,
    src_asn,
    dst_asn,
    formatReadableSize(sum(bytes)) AS traffic,
    sum(bytes) AS bytes_total,
    sum(flows_count) AS flows
FROM default.traffic_asn_pair_1m
WHERE minute >= now() - INTERVAL 10 MINUTE
GROUP BY
    minute,
    src_asn,
    dst_asn
ORDER BY minute DESC, bytes_total DESC
LIMIT 20
FORMAT PrettyCompactMonoBlock
"
```

## Backfill истории

MV считает только новые flow после создания MV. Чтобы заполнить последние 15
минут истории:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" --query "
INSERT INTO default.traffic_asn_pair_1m
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    dictGetUInt32(
        'default.bgp_origin_asn_dict',
        'origin_asn',
        tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))
    ) AS src_asn,
    dictGetUInt32(
        'default.bgp_origin_asn_dict',
        'origin_asn',
        tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))
    ) AS dst_asn,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
WHERE etype = 0x0800
  AND time_received_ns >= now() - INTERVAL 15 MINUTE
GROUP BY
    minute,
    src_asn,
    dst_asn
SETTINGS
    max_memory_usage = 4000000000,
    max_bytes_before_external_group_by = 2000000000,
    max_threads = 4
"
```

Для больших периодов делать backfill маленькими окнами, например по 15 минут
или 1 часу.

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
WITH
    (SELECT groupArray(asn) FROM default.local_asns_enabled) AS local_asns,
    length(local_asns) AS local_asns_count,
    {bucket_seconds} AS bucket_seconds
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
        multiIf(
            local_asns_count = 0, 'out',
            has(local_asns, src_asn) AND has(local_asns, dst_asn), 'internal',
            has(local_asns, src_asn) AND NOT has(local_asns, dst_asn), 'out',
            NOT has(local_asns, src_asn) AND has(local_asns, dst_asn), 'in',
            'transit'
        ) AS direction
    FROM default.traffic_asn_pair_1m
    WHERE minute >= toDateTime('{from_utc}', 'UTC')
      AND minute <  toDateTime('{to_utc}', 'UTC')
)
GROUP BY bucket
ORDER BY bucket
SETTINGS
    max_memory_usage = 1000000000,
    max_threads = 4
```

Важно: `traffic_asn_pair_1m` — `SummingMergeTree`, поэтому в запросе всегда
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

- рисовать `in_bps`;
- рисовать `out_bps`;
- `transit_bps` вернуть в API сразу и сделать отдельным toggle;
- `total_bps` показывать в tooltip или summary card.

У нас в текущих данных `transit` большой, потому что много трафика идет через
`AS50509 TRANSROUTE`. Не надо молча складывать `transit` в `out`, если
`local_asns_enabled` уже настроен.

## MoonShine Admin

Позже можно сделать resource для:

```text
default.local_asns
```

Поля:

```text
asn        UInt32
name       String
source     String
enabled    UInt8 / bool
updated_at DateTime
```

Если оператор включает дополнительный local/customer ASN, график сразу
переклассифицирует историю на чтении, потому что агрегат хранит ASN-пары, а не
готовый direction.

## Ограничение MVP

`traffic_asn_pair_1m` покрывает IPv4-сценарий для операторов, у которых есть
ASN или customer/downstream ASN. Для операторов без AS нужен prefix-based
direction:

- либо ClickHouse `local_networks_dict` (`IP_TRIE`);
- либо prefix trie в collector-е до записи в ClickHouse.

Без одного из этих механизмов нельзя быстро и универсально считать direction
по произвольным локальным сетям на больших объемах.
