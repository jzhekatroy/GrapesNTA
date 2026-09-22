#!/usr/bin/env bash
# Итоговое сравнение раскладок при одинаковом фильтре во всех вариантах.
# Таблицы layout_a/b/c готовит bench-schema-layout.sh.
set -uo pipefail

CH() { sudo -n docker exec -i grapes-clickhouse clickhouse-client --max_execution_time 900 "$@"; }
DB=default

read -r SAMP IF_RAW <<<"$(CH -q "SELECT hex(sampler_address), toString(in_if) FROM ${DB}.layout_a
  WHERE in_if > 0 AND bitShiftRight(in_if, 30) = 0
  GROUP BY sampler_address, in_if ORDER BY sum(bytes) DESC LIMIT 1" --format TSV)"
SW=$(CH -q "SELECT toString(toIPv4(reinterpretAsUInt32(reverse(substring(unhex('$SAMP'), 1, 4)))))")
IF_NAME=$(CH -q "SELECT any(if_name) FROM ${DB}.net_interfaces_current
  WHERE switch_ip = '$SW' AND if_index = bitAnd($IF_RAW, 1073741823)")
echo "порт: $SW / $IF_NAME (ifIndex $(( IF_RAW & 1073741823 )))"

WA="time_received_ns >= (SELECT min(time_received_ns) + INTERVAL 10 MINUTE FROM ${DB}.layout_a)
    AND time_received_ns < (SELECT min(time_received_ns) + INTERVAL 40 MINUTE FROM ${DB}.layout_a)"
WC="TimeReceived >= (SELECT min(TimeReceived) + INTERVAL 10 MINUTE FROM ${DB}.layout_c)
    AND TimeReceived < (SELECT min(TimeReceived) + INTERVAL 40 MINUTE FROM ${DB}.layout_c)"
FA="sampler_address = unhex('$SAMP') AND in_if = $IF_RAW"
# В раскладке Akvorado тот же порт задаётся адресом экспортёра и именем.
FC="ExporterAddress = toIPv6('$SW') AND InIfName = '$IF_NAME'"

bench() {
  qid="m-$1-$RANDOM"
  CH --query_id "$qid" -q "$2" >/dev/null 2>&1
  CH -q "SYSTEM FLUSH LOGS" >/dev/null
  CH -q "SELECT '$1' AS v, round(query_duration_ms/1000,3) AS sec,
    formatReadableQuantity(read_rows) AS rows_read, formatReadableSize(read_bytes) AS bytes_read
    FROM system.query_log WHERE query_id='$qid' AND type='QueryFinish' FORMAT TSV"
}

echo
echo "### ответы должны совпасть"
CH -q "SELECT 'A' AS v, formatReadableSize(sum(bytes)) AS total, count() AS rows FROM ${DB}.layout_a WHERE $WA AND $FA FORMAT TSV"
CH -q "SELECT 'C' AS v, formatReadableSize(sum(Bytes)) AS total, count() AS rows FROM ${DB}.layout_c WHERE $WC AND $FC FORMAT TSV"

echo
echo "### итог по порту за 30 минут, по три прогона"
for i in 1 2 3; do bench "A_seychas"  "SELECT sum(bytes),sum(packets),count() FROM ${DB}.layout_a WHERE $WA AND $FA"; done
for i in 1 2 3; do bench "B_kluch"    "SELECT sum(bytes),sum(packets),count() FROM ${DB}.layout_b WHERE $WA AND $FA"; done
for i in 1 2 3; do bench "C_akvorado" "SELECT sum(Bytes),sum(Packets),count() FROM ${DB}.layout_c WHERE $WC AND $FC"; done

echo
echo "### топ-25 ASN по этому порту"
for i in 1 2 3; do bench "A_seychas"  "SELECT src_asn,sum(bytes) b FROM ${DB}.layout_a WHERE $WA AND $FA GROUP BY src_asn ORDER BY b DESC LIMIT 25"; done
for i in 1 2 3; do bench "C_akvorado" "SELECT SrcAS,sum(Bytes) b FROM ${DB}.layout_c WHERE $WC AND $FC GROUP BY SrcAS ORDER BY b DESC LIMIT 25"; done

echo
echo "### без фильтра по порту: топ-25 ASN за окно"
for i in 1 2; do bench "A_seychas"  "SELECT src_asn,sum(bytes) b FROM ${DB}.layout_a WHERE $WA GROUP BY src_asn ORDER BY b DESC LIMIT 25"; done
for i in 1 2; do bench "C_akvorado" "SELECT SrcAS,sum(Bytes) b FROM ${DB}.layout_c WHERE $WC GROUP BY SrcAS ORDER BY b DESC LIMIT 25"; done
