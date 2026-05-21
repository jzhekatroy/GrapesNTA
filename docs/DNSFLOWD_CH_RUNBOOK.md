# dnsflowd ClickHouse Runbook

Queries for capacity troubleshooting on `netflow` when `dnsflowd` reports
`answers_writer_lag_rows` or `dns_answers` freshness degrades.

## dns_answers Freshness (Primary)

```sql
SELECT
    toString(now('UTC')) AS now_utc,
    toString(max(ts)) AS max_ts,
    dateDiff('second', max(ts), now('UTC')) AS lag_sec,
    count() AS rows
FROM default.dns_answers
FORMAT PrettyCompact;
```

Success: `lag_sec < 60-120` under normal load.

Recent rows:

```sql
SELECT count() AS rows_1m
FROM default.dns_answers
WHERE ts >= now('UTC') - INTERVAL 1 MINUTE
FORMAT PrettyCompact;
```

## dns_log Freshness (Audit, Secondary)

```sql
SELECT
    toString(max(ts)) AS max_ts,
    countIf(ts >= now('UTC') - INTERVAL 1 MINUTE) AS rows_1m
FROM default.dns_log
FORMAT PrettyCompact;
```

Raw can lag behind answers during peaks when auto raw shed is active.

## Table Size And Parts

```sql
SELECT
    table,
    formatReadableQuantity(sum(rows)) AS rows,
    formatReadableSize(sum(bytes_on_disk)) AS disk,
    count() AS parts
FROM system.parts
WHERE database = 'default'
  AND table IN ('dns_answers', 'dns_log')
  AND active
GROUP BY table
ORDER BY table
FORMAT PrettyCompact;
```

High `parts` count on `dns_log` often means merge pressure from heavy inserts.

## Recent Insert Activity

```sql
SELECT
    table,
    sum(written_rows) AS written_rows,
    sum(rows) AS rows_in_parts
FROM system.parts
WHERE database = 'default'
  AND table IN ('dns_answers', 'dns_log')
  AND modification_time >= now() - INTERVAL 5 MINUTE
GROUP BY table
ORDER BY table
FORMAT PrettyCompact;
```

## Merge Backlog

```sql
SELECT
    database,
    table,
    count() AS merges_running
FROM system.merges
WHERE database = 'default'
  AND table IN ('dns_answers', 'dns_log')
GROUP BY database, table
FORMAT PrettyCompact;
```

## dnsflowd Journal Signals

```bash
sudo journalctl -u dnsflowd --since "10 minutes ago" --no-pager \
  | grep -E 'dnsflowd clickhouse|raw shed|health degraded|queue full'
```

Watch:

- `answers_queue_drops` must stay `0`.
- `answers_writer_lag_rows` should fall after peaks.
- `raw_shed_active=true` means raw audit is paused to protect UI.
- `answers_dedup_suppressed` growing fast means dedup is reducing insert volume.

## Operational Actions

1. Confirm `dns_answers.lag_sec` first.
2. If answers lag grows: ensure `DNS_CH_ANSWERS_WRITERS=4` and auto shed enabled.
3. If still overloaded: `DNS_CH_RAW_ENABLED=0` (UI-first).
4. If ClickHouse merge/parts on `dns_log` is extreme: consider shorter TTL for
   `dns_log` only (schema change, not automatic today).
