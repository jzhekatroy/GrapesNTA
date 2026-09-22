#!/usr/bin/env bash
# Вторая часть сравнения раскладок: запросы с фильтром по времени, как в UI.
# Без него первый столбец ключа сортировки не ограничен и индекс бесполезен,
# поэтому именно так видно настоящий отсев гранул.
# Таблицы layout_a/b/c готовит bench-schema-layout.sh.
set -uo pipefail

CH() { sudo -n docker exec -i grapes-clickhouse clickhouse-client --max_execution_time 900 "$@"; }
DB=default

read -r SAMP IF_RAW <<<"$(CH -q "SELECT hex(sampler_address), toString(in_if) FROM ${DB}.layout_a
  WHERE in_if > 0 AND bitShiftRight(in_if, 30) = 0
  GROUP BY sampler_address, in_if ORDER BY sum(bytes) DESC LIMIT 1" --format TSV)"
IF_NAME=$(CH -q "SELECT any(if_name) FROM ${DB}.net_interfaces_current
  WHERE switch_ip = toString(toIPv4(reinterpretAsUInt32(reverse(substring(unhex('$SAMP'), 1, 4)))))
    AND if_index = bitAnd($IF_RAW, 1073741823)")

# Окно в 30 минут внутри выборки — так же, как их задаёт интерфейс.
TA_FROM="(SELECT min(time_received_ns) + INTERVAL 10 MINUTE FROM ${DB}.layout_a)"
TA_TO="(SELECT min(time_received_ns) + INTERVAL 40 MINUTE FROM ${DB}.layout_a)"
TC_FROM="(SELECT min(TimeReceived) + INTERVAL 10 MINUTE FROM ${DB}.layout_c)"
TC_TO="(SELECT min(TimeReceived) + INTERVAL 40 MINUTE FROM ${DB}.layout_c)"

WA="time_received_ns >= $TA_FROM AND time_received_ns < $TA_TO"
WC="TimeReceived >= $TC_FROM AND TimeReceived < $TC_TO"
FA="sampler_address = unhex('$SAMP') AND in_if = $IF_RAW"
FC="InIfName = '$IF_NAME'"

echo "### порт: ifIndex=$(( IF_RAW & 1073741823 )), имя='$IF_NAME', окно 30 минут"

bench() {
  tag=$1; sql=$2; qid="lay2-$tag-$RANDOM"
  CH --query_id "$qid" -q "$sql" >/dev/null 2>&1
  CH -q "SYSTEM FLUSH LOGS" >/dev/null
  CH -q "SELECT '$tag' AS variant, round(query_duration_ms/1000,3) AS sec,
    formatReadableQuantity(read_rows) AS rows_read, formatReadableSize(read_bytes) AS bytes_read
    FROM system.query_log WHERE query_id='$qid' AND type='QueryFinish' FORMAT TSV"
}

echo
echo "### итог по одному порту за окно"
bench "A_seychas"   "SELECT sum(bytes),sum(packets),count() FROM ${DB}.layout_a WHERE $WA AND $FA"
bench "B_kluch_akv" "SELECT sum(bytes),sum(packets),count() FROM ${DB}.layout_b WHERE $WA AND $FA"
bench "C_vsyo_akv"  "SELECT sum(Bytes),sum(Packets),count() FROM ${DB}.layout_c WHERE $WC AND $FC"

echo
echo "### топ ASN по этому порту за окно"
bench "A_seychas"   "SELECT src_asn,sum(bytes) b FROM ${DB}.layout_a WHERE $WA AND $FA GROUP BY src_asn ORDER BY b DESC LIMIT 25"
bench "B_kluch_akv" "SELECT src_asn,sum(bytes) b FROM ${DB}.layout_b WHERE $WA AND $FA GROUP BY src_asn ORDER BY b DESC LIMIT 25"
bench "C_vsyo_akv"  "SELECT SrcAS,sum(Bytes) b FROM ${DB}.layout_c WHERE $WC AND $FC GROUP BY SrcAS ORDER BY b DESC LIMIT 25"

echo
echo "### сходятся ли ответы"
CH -q "SELECT 'A' AS v, formatReadableSize(sum(bytes)) AS total, count() AS rows FROM ${DB}.layout_a WHERE $WA AND $FA FORMAT TSV"
CH -q "SELECT 'B' AS v, formatReadableSize(sum(bytes)) AS total, count() AS rows FROM ${DB}.layout_b WHERE $WA AND $FA FORMAT TSV"
CH -q "SELECT 'C' AS v, formatReadableSize(sum(Bytes)) AS total, count() AS rows FROM ${DB}.layout_c WHERE $WC AND $FC FORMAT TSV"

echo
echo "### отсев гранул — сейчас"
CH -q "EXPLAIN indexes=1 SELECT sum(bytes) FROM ${DB}.layout_a WHERE $WA AND $FA" | grep -A5 'PrimaryKey'
echo "### отсев гранул — ключ Akvorado, те же типы"
CH -q "EXPLAIN indexes=1 SELECT sum(bytes) FROM ${DB}.layout_b WHERE $WA AND $FA" | grep -A6 'PrimaryKey'
echo "### отсев гранул — раскладка Akvorado целиком"
CH -q "EXPLAIN indexes=1 SELECT sum(Bytes) FROM ${DB}.layout_c WHERE $WC AND $FC" | grep -A6 'PrimaryKey'

echo
echo "### во что обходятся отдельные колонки"
CH -q "SELECT table AS variant, name AS col,
  formatReadableSize(sum(data_compressed_bytes)) AS on_disk,
  round(sum(data_uncompressed_bytes)/sum(data_compressed_bytes),1) AS ratio
FROM system.parts_columns
WHERE database='$DB' AND table IN ('layout_a','layout_b','layout_c') AND active
  AND name IN ('in_if','InIfName','src_asn','SrcAS','sampler_address','ExporterAddress','time_received_ns','TimeReceived','bytes','Bytes')
GROUP BY table, name ORDER BY col, variant FORMAT PrettyCompactMonoBlock"
