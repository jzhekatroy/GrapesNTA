# Laravel + MoonShine: Traffic In/Out bps

This is the implementation contract for the first traffic dashboard chart.

## Goal

Build a `Traffic In/Out, bps` time-series chart with:

- default time range: last 1 hour;
- selectable scale/bucket: `1m`, `5m`, `15m`, `1h`;
- series: `in_bps`, `out_bps`, and optional `transit_bps`;
- fallback rule: if no local ASNs are configured, show all traffic as
  `out_bps`/total so the chart is not empty.

## ClickHouse Config Tables

Apply:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password "$CH_PASS" \
  --multiquery < deploy/clickhouse/local_networks.sql
```

Important objects:

```text
default.local_asns
default.local_asns_enabled
default.local_networks
default.local_networks_enabled
default.bgp_origin_asn_dict
default.flows_raw
```

`local_asns_enabled` is the primary direction config for IPv4. The loader adds
`AS34665 PINDC-AS` automatically. MoonShine should allow operators to enable
additional customer/downstream ASNs such as `AS50509 TRANSROUTE` if they should
count as local rather than transit.

## MoonShine Admin

Create a resource for `default.local_asns`:

```text
asn        UInt32
name       String
source     String
enabled    UInt8 / bool
updated_at DateTime
```

Recommended UI:

- list columns: `asn`, `name`, `source`, `enabled`, `updated_at`;
- filters: `enabled`, `source`, text search by `asn`/`name`;
- actions: enable/disable ASN;
- do not delete rows for normal changes; insert a newer row with
  `enabled = 0` or `enabled = 1` because the table uses
  `ReplacingMergeTree(updated_at)`.

When an ASN is added or disabled, the dashboard query sees it immediately
through `default.local_asns_enabled`.

## API Endpoint

Suggested route:

```text
GET /api/traffic/in-out
```

Query parameters:

```text
from   ISO-8601 UTC timestamp, optional, default now - 1 hour
to     ISO-8601 UTC timestamp, optional, default now
scale  one of: 1m, 5m, 15m, 1h; optional, default 1m
```

Map `scale` to bucket seconds in Laravel after validation:

```php
$bucketSeconds = match ($scale) {
    '1m' => 60,
    '5m' => 300,
    '15m' => 900,
    '1h' => 3600,
};
```

Only interpolate `$bucketSeconds` after this whitelist. Bind or safely format
`from`/`to` as UTC timestamps.

## ClickHouse Query

This query returns one row per bucket. It computes direction on the fly:

- IPv4: origin ASN from `bgp_origin_asn_dict`; local when ASN is in
  `local_asns_enabled`;
- IPv6: prefix match against the small IPv6 list in `local_networks_enabled`;
- empty `local_asns_enabled`: every flow becomes `out`.

Replace `{bucket_seconds}`, `{from_utc}`, and `{to_utc}` from validated API
parameters.

```sql
WITH
    (SELECT groupArray(asn) FROM default.local_asns_enabled) AS local_asns,
    length(local_asns) AS local_asns_count,
    (SELECT groupArray(prefix) FROM default.local_networks_enabled WHERE family = 6) AS local_v6,
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
    sum(flows) AS flows
FROM
(
    SELECT
        toDateTime(intDiv(toUInt32(time_received_ns), bucket_seconds) * bucket_seconds, 'UTC') AS bucket,
        bytes,
        packets,
        1 AS flows,
        multiIf(
            local_asns_count = 0, 'out',
            src_is_local AND dst_is_local, 'internal',
            src_is_local AND NOT dst_is_local, 'out',
            NOT src_is_local AND dst_is_local, 'in',
            'transit'
        ) AS direction
    FROM
    (
        SELECT
            time_received_ns,
            bytes,
            packets,
            multiIf(
                etype = 0x0800,
                    has(
                        local_asns,
                        dictGetUInt32(
                            'default.bgp_origin_asn_dict', 'origin_asn',
                            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))
                        )
                    ),
                etype = 0x86DD,
                    arrayExists(p -> isIPAddressInRange(IPv6NumToString(src_addr), p), local_v6),
                0
            ) AS src_is_local,
            multiIf(
                etype = 0x0800,
                    has(
                        local_asns,
                        dictGetUInt32(
                            'default.bgp_origin_asn_dict', 'origin_asn',
                            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))
                        )
                    ),
                etype = 0x86DD,
                    arrayExists(p -> isIPAddressInRange(IPv6NumToString(dst_addr), p), local_v6),
                0
            ) AS dst_is_local
        FROM default.flows_raw
        WHERE time_received_ns >= toDateTime64('{from_utc}', 9, 'UTC')
          AND time_received_ns <  toDateTime64('{to_utc}', 9, 'UTC')
    )
)
GROUP BY bucket
ORDER BY bucket
SETTINGS
    max_memory_usage = 4000000000,
    max_bytes_before_external_group_by = 2000000000,
    max_threads = 4
```

For the current deployment, use short windows first (`1h` default). A 15-minute
manual test over raw flows worked after switching IPv4 matching to
`bgp_origin_asn_dict`; the prefix-array-only approach OOMed and must not be
used for IPv4.

## Response Shape

Return JSON like:

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

In the chart:

- render `in_bps` and `out_bps` by default;
- render `transit_bps` as a third optional line/toggle because current data
  shows large real transit traffic through `AS50509 TRANSROUTE`;
- show `total_bps` in tooltip or a small stat card;
- fill missing buckets in Laravel with zeros before returning JSON.

## Validation Queries

Configured local ASNs:

```sql
SELECT asn, name, source
FROM default.local_asns_enabled
ORDER BY asn;
```

Top ASN pairs, useful to decide whether an ASN should be local or transit:

```sql
SELECT
    t.src_asn,
    src.name AS src_name,
    t.dst_asn,
    dst.name AS dst_name,
    formatReadableSize(t.bytes_total) AS traffic,
    t.bytes_total,
    t.flows
FROM
(
    SELECT
        dictGetUInt32('default.bgp_origin_asn_dict', 'origin_asn',
            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))) AS src_asn,
        dictGetUInt32('default.bgp_origin_asn_dict', 'origin_asn',
            tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))) AS dst_asn,
        sum(bytes) AS bytes_total,
        count() AS flows
    FROM default.flows_raw
    WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
      AND etype = 0x0800
    GROUP BY src_asn, dst_asn
    ORDER BY bytes_total DESC
    LIMIT 30
) AS t
LEFT JOIN default.asn_registry_enriched AS src ON src.asn = t.src_asn
LEFT JOIN default.asn_registry_enriched AS dst ON dst.asn = t.dst_asn
ORDER BY t.bytes_total DESC
SETTINGS max_memory_usage = 4000000000, max_threads = 4;
```
