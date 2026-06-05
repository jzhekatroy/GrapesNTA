# UI ClickHouse Queries

This document contains ClickHouse query templates for Grapes NTA UI widgets.

All dashboard totals must use `default.net_flow_sources_enabled` and
`include_in_total = 1` by default. Do not blindly sum all sources, because future
collectors can observe the same traffic and double-count it.

## Period Parameters

Use explicit `ts_from` and `ts_to` in API code:

```sql
WITH
    toDateTime('2026-05-01 00:00:00') AS ts_from,
    toDateTime('2026-06-01 00:00:00') AS ts_to
```

For UI presets, map enum values to fixed SQL intervals. Do not pass an arbitrary
interval string from user input.

```text
30m -> ts_to - INTERVAL 30 MINUTE
1h  -> ts_to - INTERVAL 1 HOUR
3h  -> ts_to - INTERVAL 3 HOUR
6h  -> ts_to - INTERVAL 6 HOUR
12h -> ts_to - INTERVAL 12 HOUR
24h -> ts_to - INTERVAL 24 HOUR
7d  -> ts_to - INTERVAL 7 DAY
30d -> ts_to - INTERVAL 30 DAY
90d -> ts_to - INTERVAL 90 DAY
```

Optional source filter:

```sql
AND m.source_id IN ('netflow')
```

Use it only when the user explicitly selects sources. Default mode should use
all enabled sources where `include_in_total = 1`.

## Aggregate Selection

| UI data | Period | Source table |
|---------|--------|--------------|
| KPI summary: max/avg/total | up to 7d | `traffic_dashboard_1m` with 5-minute buckets |
| KPI summary: total/avg | over 7d | `traffic_dashboard_1d` |
| KPI summary: max | over 7d | `traffic_dashboard_1h` |
| Time series chart | up to 7d | `traffic_dashboard_1m` with 5-minute buckets |
| Time series chart | over 7d | `traffic_dashboard_1h` or `traffic_dashboard_1d` |
| IP protocol donut | current dashboard window | `traffic_protocol_1m` |
| Service/application donut | current dashboard window | `traffic_service_1m` |
| Country heatmap / top countries | current dashboard window | `traffic_country_1m` |

`traffic_dashboard_1d` stores daily totals. It is correct for total traffic and
average speed across long windows. It is not a precise peak-speed source:
day-level rows would turn peak into "average of the busiest day". For month
views, calculate peak from `traffic_dashboard_1h`.

## KPI Summary Up To 7d

Use complete 5-minute buckets from `traffic_dashboard_1m`. UI speed values must
match chart semantics:

- `max_gbps` is the maximum 5-minute average speed in the selected interval;
- `avg_gbps` is the average speed across all complete 5-minute buckets;
- incomplete first and last buckets are excluded.

Example: last 1 hour. Change only `INTERVAL 1 HOUR`.

Returns:

- `max_gbps`, `avg_gbps`
- `max_pps`, `avg_pps`
- `total_gb`, `total_tb`, `total_packets`
- rows for `total`, `in`, `out`, `transit`, `internal`, `unknown`

```sql
WITH
    now() AS raw_ts_to,
    raw_ts_to - INTERVAL 1 HOUR AS raw_ts_from,
    toStartOfInterval(raw_ts_from + INTERVAL 5 MINUTE - INTERVAL 1 SECOND, INTERVAL 5 MINUTE) AS ts_from,
    toStartOfInterval(raw_ts_to, INTERVAL 5 MINUTE) AS ts_to,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    direction,
    round(max(bucket_bytes * 8 / 300) / 1e9, 3) AS max_gbps,
    round((sum(bucket_bytes) * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
    round(max(bucket_packets / 300), 0) AS max_pps,
    round(sum(bucket_packets) / window_seconds, 0) AS avg_pps,
    round(sum(bucket_bytes) / 1000 / 1000 / 1000, 3) AS total_gb,
    round(sum(bucket_bytes) / 1000 / 1000 / 1000 / 1000, 3) AS total_tb,
    sum(bucket_packets) AS total_packets
FROM
(
    SELECT
        bucket,
        direction,
        sum(bucket_bytes) AS bucket_bytes,
        sum(bucket_packets) AS bucket_packets
    FROM
    (
        SELECT
            toStartOfInterval(minute, INTERVAL 5 MINUTE) AS bucket,
            'total' AS direction,
            total_bytes AS bucket_bytes,
            total_packets AS bucket_packets
        FROM default.traffic_dashboard_1m AS m
        INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
        WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

        UNION ALL
        SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'in', in_bytes, in_packets
        FROM default.traffic_dashboard_1m AS m
        INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
        WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

        UNION ALL
        SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'out', out_bytes, out_packets
        FROM default.traffic_dashboard_1m AS m
        INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
        WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

        UNION ALL
        SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'transit', transit_bytes, transit_packets
        FROM default.traffic_dashboard_1m AS m
        INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
        WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

        UNION ALL
        SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'internal', internal_bytes, internal_packets
        FROM default.traffic_dashboard_1m AS m
        INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
        WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

        UNION ALL
        SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'unknown', unknown_bytes, unknown_packets
        FROM default.traffic_dashboard_1m AS m
        INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
        WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to
    )
    GROUP BY
        bucket,
        direction
)
GROUP BY direction
ORDER BY indexOf(['total', 'in', 'out', 'transit', 'internal', 'unknown'], direction);
```

Preset replacements:

```sql
raw_ts_to - INTERVAL 30 MINUTE AS raw_ts_from
raw_ts_to - INTERVAL 1 HOUR AS raw_ts_from
raw_ts_to - INTERVAL 24 HOUR AS raw_ts_from
raw_ts_to - INTERVAL 7 DAY AS raw_ts_from
```

If `ts_from >= ts_to`, the interval has no complete 5-minute buckets. Return an
empty result.

## KPI Summary Over 7d

For long periods, read totals and average speed from `traffic_dashboard_1d`, and
peak speed from `traffic_dashboard_1h`.

Example: last 30 days. Change only `INTERVAL 30 DAY`.

```sql
WITH
    toStartOfHour(now()) AS ts_to,
    ts_to - INTERVAL 30 DAY AS ts_from,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    totals.direction,
    peaks.max_gbps,
    totals.avg_gbps,
    peaks.max_pps,
    totals.avg_pps,
    totals.total_gb,
    totals.total_tb,
    totals.total_packets
FROM
(
    SELECT
        direction,
        round((sum(bytes) * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
        round(sum(packets) / window_seconds, 0) AS avg_pps,
        round(sum(bytes) / 1000 / 1000 / 1000, 3) AS total_gb,
        round(sum(bytes) / 1000 / 1000 / 1000 / 1000, 3) AS total_tb,
        sum(packets) AS total_packets
    FROM
    (
        SELECT 'total' AS direction, total_bytes AS bytes, total_packets AS packets
        FROM default.traffic_dashboard_1d AS d
        INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
        WHERE s.include_in_total = 1 AND day >= toStartOfDay(ts_from) AND day < toStartOfDay(ts_to)

        UNION ALL
        SELECT 'in', in_bytes, in_packets
        FROM default.traffic_dashboard_1d AS d
        INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
        WHERE s.include_in_total = 1 AND day >= toStartOfDay(ts_from) AND day < toStartOfDay(ts_to)

        UNION ALL
        SELECT 'out', out_bytes, out_packets
        FROM default.traffic_dashboard_1d AS d
        INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
        WHERE s.include_in_total = 1 AND day >= toStartOfDay(ts_from) AND day < toStartOfDay(ts_to)

        UNION ALL
        SELECT 'transit', transit_bytes, transit_packets
        FROM default.traffic_dashboard_1d AS d
        INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
        WHERE s.include_in_total = 1 AND day >= toStartOfDay(ts_from) AND day < toStartOfDay(ts_to)

        UNION ALL
        SELECT 'internal', internal_bytes, internal_packets
        FROM default.traffic_dashboard_1d AS d
        INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
        WHERE s.include_in_total = 1 AND day >= toStartOfDay(ts_from) AND day < toStartOfDay(ts_to)

        UNION ALL
        SELECT 'unknown', unknown_bytes, unknown_packets
        FROM default.traffic_dashboard_1d AS d
        INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
        WHERE s.include_in_total = 1 AND day >= toStartOfDay(ts_from) AND day < toStartOfDay(ts_to)
    )
    GROUP BY direction
) AS totals
LEFT JOIN
(
    SELECT
        direction,
        round(max(hour_bytes * 8 / 3600) / 1e9, 3) AS max_gbps,
        round(max(hour_packets / 3600), 0) AS max_pps
    FROM
    (
        SELECT hour, 'total' AS direction, sum(total_bytes) AS hour_bytes, sum(total_packets) AS hour_packets
        FROM default.traffic_dashboard_1h AS h
        INNER JOIN default.net_flow_sources_enabled AS s ON h.source_id = s.source_id
        WHERE s.include_in_total = 1 AND hour >= ts_from AND hour < ts_to
        GROUP BY hour

        UNION ALL
        SELECT hour, 'in', sum(in_bytes), sum(in_packets)
        FROM default.traffic_dashboard_1h AS h
        INNER JOIN default.net_flow_sources_enabled AS s ON h.source_id = s.source_id
        WHERE s.include_in_total = 1 AND hour >= ts_from AND hour < ts_to
        GROUP BY hour

        UNION ALL
        SELECT hour, 'out', sum(out_bytes), sum(out_packets)
        FROM default.traffic_dashboard_1h AS h
        INNER JOIN default.net_flow_sources_enabled AS s ON h.source_id = s.source_id
        WHERE s.include_in_total = 1 AND hour >= ts_from AND hour < ts_to
        GROUP BY hour

        UNION ALL
        SELECT hour, 'transit', sum(transit_bytes), sum(transit_packets)
        FROM default.traffic_dashboard_1h AS h
        INNER JOIN default.net_flow_sources_enabled AS s ON h.source_id = s.source_id
        WHERE s.include_in_total = 1 AND hour >= ts_from AND hour < ts_to
        GROUP BY hour

        UNION ALL
        SELECT hour, 'internal', sum(internal_bytes), sum(internal_packets)
        FROM default.traffic_dashboard_1h AS h
        INNER JOIN default.net_flow_sources_enabled AS s ON h.source_id = s.source_id
        WHERE s.include_in_total = 1 AND hour >= ts_from AND hour < ts_to
        GROUP BY hour

        UNION ALL
        SELECT hour, 'unknown', sum(unknown_bytes), sum(unknown_packets)
        FROM default.traffic_dashboard_1h AS h
        INNER JOIN default.net_flow_sources_enabled AS s ON h.source_id = s.source_id
        WHERE s.include_in_total = 1 AND hour >= ts_from AND hour < ts_to
        GROUP BY hour
    )
    GROUP BY direction
) AS peaks
    ON totals.direction = peaks.direction
ORDER BY indexOf(['total', 'in', 'out', 'transit', 'internal', 'unknown'], totals.direction);
```

If the UI does not display `max_gbps` / `max_pps` on long periods, the `peaks`
subquery can be removed and the query will read only `traffic_dashboard_1d`.

## Traffic Volume Only

Example: last 1 hour.

```sql
WITH
    toStartOfMinute(now()) AS ts_to,
    ts_to - INTERVAL 1 HOUR AS ts_from
SELECT
    direction,
    round(sum(bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb,
    round(sum(bytes) / 1000 / 1000 / 1000 / 1000, 3) AS traffic_tb,
    sum(packets) AS packets
FROM
(
    SELECT direction, bytes, packets
    FROM default.traffic_direction_1m AS d
    INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
    WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

    UNION ALL
    SELECT 'total', bytes, packets
    FROM default.traffic_direction_1m AS d
    INNER JOIN default.net_flow_sources_enabled AS s ON d.source_id = s.source_id
    WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to
)
GROUP BY direction
ORDER BY indexOf(['total', 'in', 'out', 'transit', 'internal', 'unknown'], direction);
```

## Time Series Chart Up To 7d

Use 5-minute buckets from `traffic_dashboard_1m` for chart periods up to 7 days.
This gives enough detail without generating too many points:

```text
1h  -> 12 buckets per direction
24h -> 288 buckets per direction
7d  -> 2016 buckets per direction
```

The query excludes incomplete edge buckets:

- first bucket is rounded up to the next complete 5-minute boundary;
- last bucket is rounded down to the latest complete 5-minute boundary.

For example, if the user selects `12:03:20..13:11:10`, the chart range becomes
`12:05:00..13:10:00`.

The UI can show all directions or only selected directions by changing only the
`direction IN (...)` list. To show all directions:

```sql
AND direction IN ('total', 'in', 'out', 'transit', 'internal', 'unknown')
```

To show only selected directions:

```sql
AND direction IN ('in', 'out')
```

Example: 5-minute chart for last 1 hour, all directions.

```sql
WITH
    now() AS raw_ts_to,
    raw_ts_to - INTERVAL 1 HOUR AS raw_ts_from,
    toStartOfInterval(raw_ts_from + INTERVAL 5 MINUTE - INTERVAL 1 SECOND, INTERVAL 5 MINUTE) AS ts_from,
    toStartOfInterval(raw_ts_to, INTERVAL 5 MINUTE) AS ts_to,
    300 AS bucket_seconds
SELECT
    bucket,
    direction,
    round(sum(bucket_bytes) * 8 / bucket_seconds / 1e9, 3) AS gbps,
    round(sum(bucket_packets) / bucket_seconds, 0) AS pps,
    round(sum(bucket_bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb,
    sum(bucket_packets) AS total_packets
FROM
(
    SELECT
        toStartOfInterval(minute, INTERVAL 5 MINUTE) AS bucket,
        'total' AS direction,
        total_bytes AS bucket_bytes,
        total_packets AS bucket_packets
    FROM default.traffic_dashboard_1m AS m
    INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
    WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

    UNION ALL
    SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'in', in_bytes, in_packets
    FROM default.traffic_dashboard_1m AS m
    INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
    WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

    UNION ALL
    SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'out', out_bytes, out_packets
    FROM default.traffic_dashboard_1m AS m
    INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
    WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

    UNION ALL
    SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'transit', transit_bytes, transit_packets
    FROM default.traffic_dashboard_1m AS m
    INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
    WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

    UNION ALL
    SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'internal', internal_bytes, internal_packets
    FROM default.traffic_dashboard_1m AS m
    INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
    WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to

    UNION ALL
    SELECT toStartOfInterval(minute, INTERVAL 5 MINUTE), 'unknown', unknown_bytes, unknown_packets
    FROM default.traffic_dashboard_1m AS m
    INNER JOIN default.net_flow_sources_enabled AS s ON m.source_id = s.source_id
    WHERE s.include_in_total = 1 AND minute >= ts_from AND minute < ts_to
)
WHERE direction IN ('total', 'in', 'out', 'transit', 'internal', 'unknown')
GROUP BY
    bucket,
    direction
ORDER BY
    bucket,
    indexOf(['total', 'in', 'out', 'transit', 'internal', 'unknown'], direction);
```

For a custom UI interval, replace `raw_ts_from` and `raw_ts_to` with explicit
parameters:

```sql
WITH
    toDateTime('2026-06-01 10:03:20') AS raw_ts_from,
    toDateTime('2026-06-01 13:11:10') AS raw_ts_to,
    toStartOfInterval(raw_ts_from + INTERVAL 5 MINUTE - INTERVAL 1 SECOND, INTERVAL 5 MINUTE) AS ts_from,
    toStartOfInterval(raw_ts_to, INTERVAL 5 MINUTE) AS ts_to,
    300 AS bucket_seconds
```

If `ts_from >= ts_to`, the selected interval does not contain a complete
5-minute bucket. Return an empty chart or ask the UI to widen the period.

For periods over 7 days, switch chart buckets to `traffic_dashboard_1h` or
`traffic_dashboard_1d` depending on target point count.

## IP Protocol Donut

This is for network/IP protocols: TCP, UDP, ICMP, GRE, ESP, SCTP, etc.
The donut percentage is calculated inside the selected time window and selected
directions.

Direction filter rules:

```sql
-- all traffic directions except synthetic "total"
AND direction IN ('in', 'out', 'transit', 'internal', 'unknown')

-- selected directions
AND direction IN ('in', 'out')
```

Do not include `total` here: `traffic_protocol_1m` stores real flow directions,
not synthetic total rows. The total denominator is `sum(bytes)` after the same
time/source/direction filters.

Example: last 1 hour, all real directions.

```sql
WITH
    toStartOfMinute(now()) AS ts_to,
    ts_to - INTERVAL 1 HOUR AS ts_from,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    protocol,
    proto,
    round(proto_bytes * 100 / nullIf(sum(proto_bytes) OVER (), 0), 3) AS percent,
    round(proto_bytes * 8 / window_seconds / 1e9, 3) AS avg_gbps,
    round(proto_packets / window_seconds, 0) AS avg_pps,
    round(proto_bytes / 1000 / 1000 / 1000, 3) AS traffic_gb,
    proto_packets AS packets,
    proto_flows AS flows
FROM
(
    SELECT
        multiIf(
            proto = 1, 'ICMP',
            proto = 2, 'IGMP',
            proto = 4, 'IPv4-in-IP',
            proto = 6, 'TCP',
            proto = 17, 'UDP',
            proto = 41, 'IPv6-in-IP',
            proto = 47, 'GRE',
            proto = 50, 'ESP',
            proto = 51, 'AH',
            proto = 58, 'ICMPv6',
            proto = 89, 'OSPF',
            proto = 132, 'SCTP',
            concat('IP-', toString(proto))
        ) AS protocol,
        proto,
        sum(bytes) AS proto_bytes,
        sum(packets) AS proto_packets,
        sum(flows_count) AS proto_flows
    FROM default.traffic_protocol_1m AS p
    INNER JOIN default.net_flow_sources_enabled AS s
        ON p.source_id = s.source_id
    WHERE
        s.include_in_total = 1
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN ('in', 'out', 'transit', 'internal', 'unknown')
    GROUP BY proto
)
ORDER BY traffic_gb DESC
LIMIT 20;
```

Use `percent` for donut slices. Use `traffic_gb` or `avg_gbps` for tooltips.

## Service / Application Donut

This is for applications inferred from `transport + port`: HTTPS, QUIC, DNS,
NTP, SSH, SIP, etc.

Rules:

- donut groups by `service_code` only (`https src` + `https dst` merge into one HTTPS slice);
- `service_code = 'unknown'` is shown as a single slice `other` / `Остальное`;
- percent is calculated inside the selected interval and selected directions;
- step 2 drill-down for `other` uses `traffic_unknown_port_1m` and returns TOP
  20 ports.

Direction filter:

```sql
AND direction IN ('in', 'out', 'transit', 'internal', 'unknown')
```

### Step 1: Donut By Service

Example: last 1 hour.

```sql
WITH
    toStartOfMinute(now()) AS ts_to,
    ts_to - INTERVAL 1 HOUR AS ts_from,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    s.service_code,
    s.service_name,
    s.category,
    round(s.slice_bytes * 100 / nullIf(t.total_bytes, 0), 3) AS percent,
    round(s.slice_bytes * 8 / window_seconds / 1e9, 3) AS avg_gbps,
    round(s.slice_packets / window_seconds, 0) AS avg_pps,
    round(s.slice_bytes / 1000 / 1000 / 1000, 3) AS traffic_gb,
    s.slice_packets AS packets,
    s.slice_flows AS flows
FROM
(
    SELECT
        if(service_code = 'unknown', 'other', service_code) AS service_code,
        if(service_code = 'unknown', 'Other', argMax(service_name, bytes)) AS service_name,
        if(service_code = 'unknown', 'unknown', argMax(category, bytes)) AS category,
        sum(bytes) AS slice_bytes,
        sum(packets) AS slice_packets,
        sum(flows_count) AS slice_flows
    FROM default.traffic_service_1m AS t
    INNER JOIN default.net_flow_sources_enabled AS src
        ON t.source_id = src.source_id
    WHERE
        src.include_in_total = 1
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN ('in', 'out', 'transit', 'internal', 'unknown')
    GROUP BY service_code
) AS s
CROSS JOIN
(
    SELECT
        sum(bytes) AS total_bytes
    FROM default.traffic_service_1m AS t
    INNER JOIN default.net_flow_sources_enabled AS src
        ON t.source_id = src.source_id
    WHERE
        src.include_in_total = 1
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN ('in', 'out', 'transit', 'internal', 'unknown')
) AS t
ORDER BY
    if(s.service_code = 'other', 1, 0),
    traffic_gb DESC;
```

UI mapping:

- `service_code = 'other'` -> label `Остальное`;
- all other `service_code` values -> HTTPS, DNS, SIP, SSH, etc.

Preset replacements:

```sql
ts_to - INTERVAL 30 MINUTE AS ts_from
ts_to - INTERVAL 1 HOUR AS ts_from
ts_to - INTERVAL 24 HOUR AS ts_from
ts_to - INTERVAL 7 DAY AS ts_from
ts_to - INTERVAL 14 DAY AS ts_from
```

For periods over 7 days this query scans many minute rows. Prefer shorter windows
for the service donut, or add a future `traffic_service_1h` rollup.

### Step 2: Drill-Down `Остальное` -> TOP 20 Ports

`traffic_service_1m` stores `service_port = 0` for unknown flows.
`traffic_unknown_port_1m` stores the same `other` traffic grouped by transport
and port, so this drill-down does not scan `flows_raw`.

Use the same `ts_from`, `ts_to`, and `direction` filters as step 1.

```sql
WITH
    toStartOfMinute(now()) AS ts_to,
    ts_to - INTERVAL 1 HOUR AS ts_from,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    p.transport,
    p.port,
    p.port_side,
    round(p.port_bytes * 100 / nullIf(t.other_bytes, 0), 3) AS percent_within_other,
    round(p.port_bytes * 8 / window_seconds / 1e9, 3) AS avg_gbps,
    round(p.port_bytes / 1000 / 1000 / 1000, 3) AS traffic_gb,
    p.port_packets AS packets,
    p.port_flows AS flows
FROM
(
    SELECT
        transport,
        port,
        port_side,
        sum(bytes) AS port_bytes,
        sum(packets) AS port_packets,
        sum(flows_count) AS port_flows
    FROM default.traffic_unknown_port_1m AS u
    INNER JOIN default.net_flow_sources_enabled AS src_en
        ON u.source_id = src_en.source_id
    WHERE
        src_en.include_in_total = 1
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN ('in', 'out', 'transit', 'internal', 'unknown')
        AND port > 0
    GROUP BY
        transport,
        port,
        port_side
) AS p
CROSS JOIN
(
    SELECT
        sum(bytes) AS other_bytes
    FROM default.traffic_unknown_port_1m AS u
    INNER JOIN default.net_flow_sources_enabled AS src_en
        ON u.source_id = src_en.source_id
    WHERE
        src_en.include_in_total = 1
        AND minute >= ts_from
        AND minute < ts_to
        AND direction IN ('in', 'out', 'transit', 'internal', 'unknown')
) AS t
ORDER BY traffic_gb DESC
LIMIT 20;
```

Interpretation:

- step 1 `percent` is share of all selected traffic;
- step 2 `percent_within_other` is share only inside the `other` slice;
- `transport + port + port_side` is the drill-down key, for example
  `tcp / 54321 / dst`.

## Country Heatmap

Source table: `default.traffic_country_1m`.

Parameters (set in API code, not from raw user SQL):

```text
ts_from, ts_to           explicit UTC DateTime bounds
country_basis            ip (default) | asn
map_side                 remote (default) | src | dst
directions               in,out,transit by default; add internal only when selected
```

Semantics:

- `country_basis = 'ip'` — prefix country from `geo_country_dict` (default map).
- `country_basis = 'asn'` — ASN allocation country from `asn_registry_enriched`.
- `map_side = 'remote'` — peer country: `in` uses `src`, `out` uses `dst`,
  `transit` uses `src`; `internal` has no remote peer unless the UI includes it
  explicitly (then use `src` or `dst` mode instead).
- `map_side = 'src'` / `dst'` — always source or destination country side.

Color intensity: `traffic_gb` or `percent`. Tooltip: `avg_gbps`, `packets`,
`flows`.

Example: last 24 hours, IP country, remote peers, inbound+outbound+transit.

Replace `country_basis`, `map_side`, and the `direction IN (...)` list in API
code.

IP-country, 24 hours, `remote` map side. UI field names in the outer SELECT.

```sql
WITH
    now() AS ts_to,
    ts_to - INTERVAL 24 HOUR AS ts_from,
    dateDiff('second', ts_from, ts_to) AS window_seconds
SELECT
    agg.country_code,
    agg.country_basis,
    agg.map_side,
    agg.traffic_gb,
    round(100 * agg.traffic_gb / sum(agg.traffic_gb) OVER (), 2) AS share_percent,
    round((agg.total_bytes * 8 / window_seconds) / 1e9, 3) AS avg_gbps,
    round(agg.packet_count / window_seconds, 0) AS avg_pps,
    agg.packet_count,
    agg.flow_count
FROM
(
    SELECT
        c.country_code,
        'ip' AS country_basis,
        'remote' AS map_side,
        sum(c.bytes) AS total_bytes,
        round(sum(c.bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb,
        sum(c.packets) AS packet_count,
        sum(c.flows_count) AS flow_count
    FROM default.traffic_country_1m AS c
    INNER JOIN default.net_flow_sources_enabled AS s ON c.source_id = s.source_id
    WHERE
        s.include_in_total = 1
        AND c.minute >= ts_from
        AND c.minute < ts_to
        AND c.country_basis = 'ip'
        AND c.direction IN ('in', 'out', 'transit')
        AND (
            (c.direction = 'in' AND c.country_side = 'src')
            OR (c.direction = 'out' AND c.country_side = 'dst')
            OR (c.direction = 'transit' AND c.country_side = 'src')
        )
    GROUP BY c.country_code
) AS agg
ORDER BY traffic_gb DESC;
```

ASN-country: same query, use `'asn'` for `country_basis` in the inner WHERE and SELECT literal.

ASN-country mode: set `country_basis = 'asn'` and keep the same `map_side`
logic. Label the UI control as registry/allocation country, not IP geolocation.

Always use `src` or `dst` map side when the user selects `internal` traffic and
needs both endpoints visible on the map.

## Country Aggregate Server Rollout

Prerequisites on the server:

1. Geo tables and dictionary are loaded (`geo_country.sql` + geoloaderd).
2. Flow source tracking is applied (`net_flow_sources.sql`,
   `flows_raw_source_id.sql`).

Apply aggregate (new servers or after `git pull`):

```bash
cd /opt/GrapesNTA   # or /root/GrapesNTA
git pull

clickhouse-client --url "$XDP_CH_DSN" --multiquery < deploy/clickhouse/geo_country.sql
clickhouse-client --url "$XDP_CH_DSN" --multiquery < deploy/clickhouse/traffic_country_1m.sql
```

Validate dictionary:

```sql
SELECT dictGetString('default.geo_country_dict', 'cc', tuple(toIPv4('8.8.8.8')));
```

Validate recent aggregate rows:

```sql
SELECT
    country_basis,
    country_side,
    country_code,
    sum(bytes) AS bytes
FROM default.traffic_country_1m
WHERE minute >= now() - INTERVAL 10 MINUTE
GROUP BY country_basis, country_side, country_code
ORDER BY bytes DESC
LIMIT 20;
```

Backfill one hour (stop `xdpflowd` only if MV + live ingest double-count is a
concern; otherwise run while collector is active and dedupe by time window):

```bash
sudo systemctl stop xdpflowd

clickhouse-client --url "$XDP_CH_DSN" --query "
INSERT INTO default.traffic_country_1m
SELECT
    minute,
    source_id,
    country_basis,
    country_side,
    direction,
    if(length(trimBoth(country_raw)) = 0, '??', trimBoth(country_raw)) AS country_code,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM
(
    SELECT
        toStartOfMinute(f.time_received_ns) AS minute,
        f.source_id,
        f.direction,
        f.bytes,
        f.packets,
        row.1 AS country_basis,
        row.2 AS country_side,
        row.3 AS country_raw
    FROM default.flows_raw AS f
    LEFT JOIN default.asn_registry_enriched AS src_as ON src_as.asn = f.src_asn
    LEFT JOIN default.asn_registry_enriched AS dst_as ON dst_as.asn = f.dst_asn
    ARRAY JOIN arrayZip(
        ['ip', 'ip', 'asn', 'asn'],
        ['src', 'dst', 'src', 'dst'],
        [
            if(
                f.etype = 2048,
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4)))))
                ),
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv6(IPv6NumToString(f.src_addr)))
                )
            ),
            if(
                f.etype = 2048,
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4)))))
                ),
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv6(IPv6NumToString(f.dst_addr)))
                )
            ),
            if(f.src_asn = 0, '', toString(src_as.cc)),
            if(f.dst_asn = 0, '', toString(dst_as.cc))
        ]
    ) AS row
    WHERE f.time_received_ns >= now() - INTERVAL 1 HOUR
      AND f.time_received_ns < now()
) AS expanded
GROUP BY
    minute,
    source_id,
    country_basis,
    country_side,
    direction,
    country_code
"

sudo systemctl start xdpflowd
```

Cross-check top countries against `flows_raw` for the same hour (IP, remote,
in+out+transit) before running a longer backfill.

## Source Selector

Use this for UI source filters:

```sql
SELECT
    source_id,
    display_name,
    source_type,
    location,
    include_in_total
FROM default.net_flow_sources_enabled
ORDER BY source_type, display_name, source_id;
```

## Operational Sanity Checks

Recent raw flow source distribution:

```sql
SELECT
    source_id,
    count() AS flows,
    round(sum(bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 10 MINUTE
GROUP BY source_id
ORDER BY traffic_gb DESC;
```

Recent service aggregate activity:

```sql
SELECT
    source_id,
    count() AS rows,
    round(sum(bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb
FROM default.traffic_service_1m
WHERE minute >= now() - INTERVAL 10 MINUTE
GROUP BY source_id
ORDER BY traffic_gb DESC;
```

Recent country aggregate activity:

```sql
SELECT
    source_id,
    country_basis,
    count() AS rows,
    round(sum(bytes) / 1000 / 1000 / 1000, 3) AS traffic_gb
FROM default.traffic_country_1m
WHERE minute >= now() - INTERVAL 10 MINUTE
GROUP BY source_id, country_basis
ORDER BY traffic_gb DESC;
```
