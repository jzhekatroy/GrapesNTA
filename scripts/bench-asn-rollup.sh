#!/usr/bin/env bash
# Сверяет готовую сводку traffic_asn_pair_* с сырым журналом: свежесть,
# совпадение цифр и время ответа на типовой вопрос «топ ASN за сутки».
set -uo pipefail

CH() { sudo -n docker exec -i grapes-clickhouse clickhouse-client "$@"; }

echo "=== свежесть ==="
CH -q "
SELECT 'flows_raw' AS t, toString(max(time_received_ns)) AS last_point FROM default.flows_raw
  WHERE date >= today() - 1
UNION ALL SELECT 'asn_pair_1m', toString(max(minute)) FROM default.traffic_asn_pair_1m
UNION ALL SELECT 'asn_pair_1h', toString(max(hour)) FROM default.traffic_asn_pair_1h
FORMAT TSV"

echo
echo "=== сходятся ли цифры за позавчерашние сутки ==="
CH -q "
WITH toStartOfDay(now() - INTERVAL 2 DAY) AS d0, d0 + INTERVAL 1 DAY AS d1
SELECT 'flows_raw' AS src, formatReadableSize(sum(bytes)) AS total
FROM default.flows_raw
WHERE date >= toDate(d0) - 1 AND date <= toDate(d1)
  AND time_received_ns >= d0 AND time_received_ns < d1
UNION ALL
SELECT 'asn_pair_1h', formatReadableSize(sum(bytes))
FROM default.traffic_asn_pair_1h WHERE hour >= d0 AND hour < d1
FORMAT TSV"

bench() {
  local tag=$1 sql=$2
  local qid="rollup-${tag}-$RANDOM"
  CH --query_id "$qid" -q "$sql" >/dev/null 2>&1
  CH -q "SYSTEM FLUSH LOGS" >/dev/null 2>&1
  CH -q "
    SELECT '$tag' AS variant, round(query_duration_ms/1000, 2) AS sec,
           formatReadableQuantity(read_rows) AS rows_read,
           formatReadableSize(read_bytes) AS bytes_read
    FROM system.query_log WHERE query_id = '$qid' AND type = 'QueryFinish' FORMAT TSV"
}

echo
echo "=== топ 25 пар ASN за сутки ==="
bench "raw" "
  WITH toStartOfDay(now() - INTERVAL 2 DAY) AS d0, d0 + INTERVAL 1 DAY AS d1
  SELECT src_asn, dst_asn, sum(bytes) AS b
  FROM default.flows_raw
  PREWHERE date >= toDate(d0) - 1 AND date <= toDate(d1)
  WHERE time_received_ns >= d0 AND time_received_ns < d1
  GROUP BY src_asn, dst_asn ORDER BY b DESC LIMIT 25"
bench "rollup_1h" "
  WITH toStartOfDay(now() - INTERVAL 2 DAY) AS d0, d0 + INTERVAL 1 DAY AS d1
  SELECT src_asn, dst_asn, sum(bytes) AS b
  FROM default.traffic_asn_pair_1h
  WHERE hour >= d0 AND hour < d1
  GROUP BY src_asn, dst_asn ORDER BY b DESC LIMIT 25"

echo
echo "=== динамика по одному ASN за сутки, 5-минутные точки ==="
bench "raw_series" "
  WITH toStartOfDay(now() - INTERVAL 2 DAY) AS d0, d0 + INTERVAL 1 DAY AS d1
  SELECT toStartOfInterval(time_received_ns, INTERVAL 300 SECOND) AS b, sum(bytes)
  FROM default.flows_raw
  PREWHERE date >= toDate(d0) - 1 AND date <= toDate(d1)
  WHERE time_received_ns >= d0 AND time_received_ns < d1 AND src_asn = 13238
  GROUP BY b ORDER BY b"
bench "rollup_series_1h" "
  WITH toStartOfDay(now() - INTERVAL 2 DAY) AS d0, d0 + INTERVAL 1 DAY AS d1
  SELECT hour AS b, sum(bytes)
  FROM default.traffic_asn_pair_1h
  WHERE hour >= d0 AND hour < d1 AND src_asn = 13238
  GROUP BY b ORDER BY b"
