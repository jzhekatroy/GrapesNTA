-- Validation queries for traffic_chart_1m vs traffic_direction_1m.
-- Run each statement separately (no multi-statement in some clients).

-- 1) Row count: chart table should have ~1 row per minute in the window.
SELECT
    count() AS chart_rows,
    min(minute) AS min_minute,
    max(minute) AS max_minute
FROM default.traffic_chart_1m
WHERE minute >= now('UTC') - INTERVAL 1 HOUR;

-- 2) Total bytes in last hour: chart vs direction aggregate (should match).
SELECT
    'traffic_chart_1m' AS source,
    sum(total_bytes) AS bytes
FROM default.traffic_chart_1m
WHERE minute >= now('UTC') - INTERVAL 1 HOUR

UNION ALL

SELECT
    'traffic_direction_1m' AS source,
    sum(bytes) AS bytes
FROM default.traffic_direction_1m
WHERE minute >= now('UTC') - INTERVAL 1 HOUR;

-- 3) Per-direction bytes in last 10 minutes (detailed diff).
SELECT
    sum(in_bytes) AS chart_in,
    sum(out_bytes) AS chart_out,
    sum(transit_bytes) AS chart_transit,
    sum(internal_bytes) AS chart_internal,
    sum(unknown_bytes) AS chart_unknown
FROM default.traffic_chart_1m
WHERE minute >= now('UTC') - INTERVAL 10 MINUTE;

SELECT
    sumIf(bytes, direction = 'in') AS dir_in,
    sumIf(bytes, direction = 'out') AS dir_out,
    sumIf(bytes, direction = 'transit') AS dir_transit,
    sumIf(bytes, direction = 'internal') AS dir_internal,
    sumIf(bytes, direction = 'unknown') AS dir_unknown
FROM default.traffic_direction_1m
WHERE minute >= now('UTC') - INTERVAL 10 MINUTE;

-- 4) Minutes where totals diverge (should return 0 rows after backfill + MV).
SELECT
    minute,
    chart_bytes,
    direction_bytes,
    chart_bytes - direction_bytes AS diff
FROM
(
    SELECT
        minute,
        sum(total_bytes) AS chart_bytes
    FROM default.traffic_chart_1m
    WHERE minute >= now('UTC') - INTERVAL 1 HOUR
    GROUP BY minute
) AS c
FULL OUTER JOIN
(
    SELECT
        minute,
        sum(bytes) AS direction_bytes
    FROM default.traffic_direction_1m
    WHERE minute >= now('UTC') - INTERVAL 1 HOUR
    GROUP BY minute
) AS d USING (minute)
WHERE abs(chart_bytes - direction_bytes) > 0
ORDER BY minute DESC
LIMIT 20;
