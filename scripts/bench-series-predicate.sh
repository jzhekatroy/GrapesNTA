#!/usr/bin/env bash
# Сравнивает старую (сравнение подписи) и новую (сравнение сырой колонки)
# форму предиката детализации в разборе трафика.
set -uo pipefail

CH() { sudo -n docker exec -i grapes-clickhouse clickhouse-client "$@"; }

FROM=${FROM:-"now() - INTERVAL 6 HOUR"}
TO=${TO:-"now()"}
TS=time_received_ns

ASN=$(CH -q "SELECT src_asn FROM default.flows_raw
  WHERE $TS >= $FROM AND $TS < $TO AND src_asn > 0
  GROUP BY src_asn ORDER BY count() DESC LIMIT 1")
echo "asn=$ASN window=[$FROM .. $TO]"

run() {
  local tag=$1 pred=$2
  local qid="bench-${tag}-$RANDOM"
  CH --query_id "$qid" -q "
    SELECT toStartOfInterval($TS, INTERVAL 300 SECOND) AS bucket, sum(bytes)
    FROM default.flows_raw
    PREWHERE date >= toDate($FROM) - 1 AND date <= toDate($TO)
    WHERE $TS >= $FROM AND $TS < $TO AND ($pred)
    GROUP BY bucket ORDER BY bucket
  " >/dev/null 2>&1
  CH -q "SYSTEM FLUSH LOGS" >/dev/null 2>&1
  CH -q "
    SELECT '$tag' AS variant,
           round(query_duration_ms/1000, 2) AS sec,
           formatReadableQuantity(read_rows) AS rows_read,
           formatReadableSize(memory_usage) AS mem
    FROM system.query_log
    WHERE query_id = '$qid' AND type = 'QueryFinish'
    FORMAT TSV"
}

LABEL="multiIf(src_asn = 0, 'AS0', src_asn > 0, concat('AS', toString(src_asn)), '—')"

echo "--- одиночный ASN ---"
run "old_label_asn" "toString($LABEL) = 'AS$ASN'"
run "new_raw_asn"   "src_asn = $ASN"

echo "--- прочерк: старый код гнал этот запрос, новый его не шлёт ---"
run "old_label_dash" "toString($LABEL) = '—'"

echo "--- 25 строк детализации, как шлёт UI ---"
IN_LIST=$(CH -q "SELECT arrayStringConcat(groupArray(toString(src_asn)), ',') FROM (
  SELECT src_asn FROM default.flows_raw
  WHERE $TS >= $FROM AND $TS < $TO AND src_asn > 0
  GROUP BY src_asn ORDER BY count() DESC LIMIT 25)")
OLD_OR=$(python3 - "$IN_LIST" <<'PY'
import sys
label = "multiIf(src_asn = 0, 'AS0', src_asn > 0, concat('AS', toString(src_asn)), '\u2014')"
print(" OR ".join(f"toString({label}) = 'AS{a}'" for a in sys.argv[1].split(",")))
PY
)
run "old_label_25" "$OLD_OR"
run "new_raw_25"   "src_asn IN ($IN_LIST)"

echo "--- MAC: подпись против сырой колонки ---"
MACLABEL="lower(arrayStringConcat(arrayMap(i -> substring(hex(src_mac), (i - 1) * 2 + 1, 2), range(1, 7)), ':'))"
MAC=$(CH -q "SELECT $MACLABEL FROM default.flows_raw
  WHERE $TS >= $FROM AND $TS < $TO GROUP BY src_mac ORDER BY count() DESC LIMIT 1")
echo "mac=$MAC"
run "old_label_mac" "toString($MACLABEL) = '$MAC'"
run "new_raw_mac"   "src_mac = unhex('$(echo "$MAC" | tr -d ':')')"
