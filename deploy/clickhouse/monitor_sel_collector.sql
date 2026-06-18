-- monitor_sel_collector.sql — ingest health + volume for sel collector.
--
-- Apply: none (read-only queries). Use in Grafana, cron, or clickhouse-client.
--
--   clickhouse-client --host 95.215.1.30 --port 6124 --user ui_read --password '...' \
--     --multiquery < deploy/clickhouse/monitor_sel_collector.sql
--
-- Alert rule: any row in section 1 = unhealthy.

-- ---------------------------------------------------------------------------
-- 1) ALERT PANEL — returns rows only when something is wrong
-- ---------------------------------------------------------------------------
SELECT *
FROM (
    -- xdp-sel: no rows in 5m OR last flow older than 2 min
    SELECT
        'flows_xdp_sel_stale' AS alert,
        'xdp-sel' AS source_id,
        if(
            max_flow IS NULL,
            toInt64(999999),
            dateDiff('second', max_flow, now64(9))
        ) AS age_sec,
        coalesce(rows_5m, 0) AS rows_5m,
        'expected: xdpflowd on sel, sampler 95.215.0.26' AS hint
    FROM (
        SELECT
            count() AS rows_5m,
            max(time_flow_start_ns) AS max_flow
        FROM default.flows_raw
        WHERE source_id = 'xdp-sel'
          AND time_flow_start_ns >= now64(9) - INTERVAL 5 MINUTE
    )
    WHERE coalesce(rows_5m, 0) = 0
       OR dateDiff('second', max_flow, now64(9)) > 120

    UNION ALL

    -- xdp-sel never ingested (lifetime)
    SELECT
        'xdp_sel_zero_lifetime' AS alert,
        'xdp-sel' AS source_id,
        toInt64(0) AS age_sec,
        toUInt64(0) AS rows_5m,
        'check XDPFLOWD_SOURCE_ID and restart xdpflowd' AS hint
    FROM system.one
    WHERE (SELECT count() FROM default.flows_raw WHERE source_id = 'xdp-sel') = 0

    UNION ALL

    -- dns-sel: stale > 30s or no rows in 5m
    SELECT
        'dns_sel_stale' AS alert,
        'dns-sel' AS source_id,
        if(
            max_ts IS NULL,
            toInt64(999999),
            dateDiff('second', max_ts, now64(6))
        ) AS age_sec,
        coalesce(rows_5m, 0) AS rows_5m,
        'expected: dnsflowd on sel' AS hint
    FROM (
        SELECT
            count() AS rows_5m,
            max(ts) AS max_ts
        FROM default.dns_log
        WHERE source_id = 'dns-sel'
          AND ts >= now64(6) - INTERVAL 5 MINUTE
    )
    WHERE coalesce(rows_5m, 0) = 0
       OR dateDiff('second', max_ts, now64(6)) > 30

    UNION ALL

    -- sel sampler writing under wrong source_id (misconfiguration)
    SELECT
        'sel_sampler_wrong_source_id' AS alert,
        source_id,
        dateDiff('second', max(time_flow_start_ns), now64(9)) AS age_sec,
        count() AS rows_5m,
        'sampler 95.215.0.26 should use xdp-sel, not legacy ids' AS hint
    FROM default.flows_raw
    WHERE source_id IN ('xdp-default', 'netflow')
      AND IPv6NumToString(sampler_address) LIKE '5fd7:1a%'
      AND time_flow_start_ns >= now64(9) - INTERVAL 5 MINUTE
    GROUP BY source_id
)
ORDER BY alert, source_id;

-- ---------------------------------------------------------------------------
-- 2) VOLUME DASHBOARD — flows (5 min / 1 h)
-- ---------------------------------------------------------------------------
SELECT
    '5m' AS window,
    source_id,
    count() AS rows,
    sum(bytes) AS sum_bytes,
    round(sum(bytes) / greatest(dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)), 1) / 1024 / 1024, 3) AS mb_per_sec,
    round(count() / greatest(dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)), 1) * 60, 0) AS flows_per_min,
    round(sum(bytes) / greatest(dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)), 1) * 86400 / 1024 / 1024 / 1024, 1) AS gb_per_day_est,
    dateDiff('second', max(time_flow_start_ns), now64(9)) AS flow_age_sec,
    quantile(0.95)(dateDiff('second', time_flow_start_ns, time_received_ns)) AS p95_recv_lag_sec
FROM default.flows_raw
WHERE time_flow_start_ns >= now64(9) - INTERVAL 5 MINUTE
  AND source_id IN ('xdp-sel', 'netflow', 'xdp-default')
GROUP BY source_id
ORDER BY source_id;

SELECT
    '1h' AS window,
    source_id,
    count() AS rows,
    sum(bytes) AS sum_bytes,
    round(sum(bytes) / greatest(dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)), 1) / 1024 / 1024, 3) AS mb_per_sec,
    round(count() / greatest(dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)), 1) * 60, 0) AS flows_per_min,
    round(sum(bytes) / greatest(dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)), 1) * 86400 / 1024 / 1024 / 1024, 1) AS gb_per_day_est,
    dateDiff('second', max(time_flow_start_ns), now64(9)) AS flow_age_sec,
    quantile(0.95)(dateDiff('second', time_flow_start_ns, time_received_ns)) AS p95_recv_lag_sec
FROM default.flows_raw
WHERE time_flow_start_ns >= now64(9) - INTERVAL 1 HOUR
  AND source_id IN ('xdp-sel', 'netflow', 'xdp-default')
GROUP BY source_id
ORDER BY source_id;

-- ---------------------------------------------------------------------------
-- 3) VOLUME DASHBOARD — DNS (5 min / 1 h)
-- ---------------------------------------------------------------------------
SELECT
    '5m' AS window,
    source_id,
    count() AS rows,
    sum(raw_size) AS sum_raw_bytes,
    round(sum(raw_size) / greatest(dateDiff('second', min(ts), max(ts)), 1) / 1024 / 1024, 3) AS mb_per_sec,
    round(count() / greatest(dateDiff('second', min(ts), max(ts)), 1) * 60, 0) AS rows_per_min,
    round(sum(raw_size) / greatest(dateDiff('second', min(ts), max(ts)), 1) * 86400 / 1024 / 1024 / 1024, 1) AS gb_per_day_est,
    dateDiff('second', max(ts), now64(6)) AS ts_age_sec
FROM default.dns_log
WHERE ts >= now64(6) - INTERVAL 5 MINUTE
  AND source_id IN ('dns-sel', 'dns-netflow')
GROUP BY source_id
ORDER BY source_id;

SELECT
    '1h' AS window,
    source_id,
    count() AS rows,
    sum(raw_size) AS sum_raw_bytes,
    round(sum(raw_size) / greatest(dateDiff('second', min(ts), max(ts)), 1) / 1024 / 1024, 3) AS mb_per_sec,
    round(count() / greatest(dateDiff('second', min(ts), max(ts)), 1) * 60, 0) AS rows_per_min,
    round(sum(raw_size) / greatest(dateDiff('second', min(ts), max(ts)), 1) * 86400 / 1024 / 1024 / 1024, 1) AS gb_per_day_est,
    dateDiff('second', max(ts), now64(6)) AS ts_age_sec
FROM default.dns_log
WHERE ts >= now64(6) - INTERVAL 1 HOUR
  AND source_id IN ('dns-sel', 'dns-netflow')
GROUP BY source_id
ORDER BY source_id;

-- ---------------------------------------------------------------------------
-- 4) SAMPLER MAP — who writes what (24h)
-- ---------------------------------------------------------------------------
SELECT
    'flows' AS kind,
    source_id,
    IPv6NumToString(sampler_address) AS sampler_v6,
    count() AS rows,
    max(time_flow_start_ns) AS max_event
FROM default.flows_raw
WHERE time_flow_start_ns >= now64(9) - INTERVAL 24 HOUR
GROUP BY kind, source_id, sampler_v6
ORDER BY rows DESC
LIMIT 30;

SELECT
    'dns' AS kind,
    source_id,
    IPv6NumToString(sampler_address) AS sampler_v6,
    count() AS rows,
    max(ts) AS max_event
FROM default.dns_log
WHERE ts >= now64(6) - INTERVAL 24 HOUR
  AND source_id IN ('dns-sel', 'dns-netflow')
GROUP BY kind, source_id, sampler_v6
ORDER BY rows DESC;
