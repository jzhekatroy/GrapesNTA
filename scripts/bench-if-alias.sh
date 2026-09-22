#!/usr/bin/env bash
# Сравнивает два способа выполнить фильтр по alias порта в разборе трафика:
# JOIN с инвентарём SNMP по каждой строке (как сейчас) и сопоставление
# пары «адрес коммутатора + порт» с сырыми колонками (предлагаемое).
set -uo pipefail

CH() { sudo -n docker exec -i grapes-clickhouse clickhouse-client "$@"; }

ALIAS=${ALIAS:-'cogent-fv='}
HOURS=${HOURS:-3}
TS=time_received_ns
FROM="now() - INTERVAL $HOURS HOUR"
TO="now()"
IFACES=default.net_interfaces_current

SWITCH_IP_EXPR="if(
        length(f.sampler_address) = 16
          AND substring(f.sampler_address, 5) = unhex('000000000000000000000000'),
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.sampler_address, 1, 4))))),
        IPv6NumToString(f.sampler_address)
      )"
IFIDX="if(toUInt32OrZero(toString(f.in_if)) > 0 AND bitShiftRight(toUInt32OrZero(toString(f.in_if)), 30) = 0, bitAnd(toUInt32OrZero(toString(f.in_if)), 1073741823), toUInt32(0))"
# Обратное преобразование адреса коммутатора в сырые байты.
SAMPLER_FROM_IP="if(isIPv4String(switch_ip),
        toFixedString(reverse(reinterpretAsFixedString(toUInt32(toIPv4(switch_ip)))), 16),
        toFixedString(IPv6StringToNum(switch_ip), 16))"

OLD_FILTER="toString(ifNull(nullIf(snmp_in.if_alias, ''), '')) = '$ALIAS'"
OLD_JOIN="LEFT JOIN $IFACES AS snmp_in
    ON snmp_in.switch_ip = $SWITCH_IP_EXPR
    AND snmp_in.if_index = $IFIDX"
NEW_FILTER="(f.sampler_address, $IFIDX) IN (
      SELECT $SAMPLER_FROM_IP, if_index FROM $IFACES WHERE if_alias = '$ALIAS')"

bench() {
  local tag=$1 sql=$2
  local qid="ifa2-${tag}-$RANDOM"
  CH --query_id "$qid" -q "$sql" >/dev/null 2>&1
  CH -q "SYSTEM FLUSH LOGS" >/dev/null 2>&1
  CH -q "
    SELECT '$tag' AS variant, round(query_duration_ms/1000, 2) AS sec,
           formatReadableQuantity(read_rows) AS rows_read,
           formatReadableSize(memory_usage) AS mem
    FROM system.query_log WHERE query_id = '$qid' AND type = 'QueryFinish' FORMAT TSV"
}

# Итоговая сводка — ровно тот запрос, что висел 66 секунд.
SUMMARY_SELECT="SELECT sum(f.bytes) AS total_bytes, sum(f.packets) AS total_packets,
    sum(1) AS total_flows, sumIf(f.bytes, f.direction = 'in') AS in_bytes,
    sumIf(f.bytes, f.direction = 'out') AS out_bytes, topK(5)(f.proto) AS top_proto"
WINDOW="PREWHERE f.date >= toDate($FROM) - 1 AND f.date <= toDate($TO)
  WHERE f.$TS >= $FROM AND f.$TS < $TO"

echo "=== итоговая сводка, окно $HOURS ч, alias=$ALIAS ==="
bench "old_join"  "$SUMMARY_SELECT FROM default.flows_raw AS f $OLD_JOIN $WINDOW AND $OLD_FILTER"
bench "new_pair"  "$SUMMARY_SELECT FROM default.flows_raw AS f $WINDOW AND $NEW_FILTER"

echo
echo "=== таблица: группировка по src_asn ==="
bench "old_join_grp" "SELECT f.src_asn AS g0, sum(f.bytes) AS b FROM default.flows_raw AS f $OLD_JOIN $WINDOW AND $OLD_FILTER GROUP BY g0 ORDER BY b DESC LIMIT 50"
bench "new_pair_grp" "SELECT f.src_asn AS g0, sum(f.bytes) AS b FROM default.flows_raw AS f $WINDOW AND $NEW_FILTER GROUP BY g0 ORDER BY b DESC LIMIT 50"

echo
echo "=== совпадают ли ответы (один и тот же фиксированный интервал) ==="
FIXED_FROM="toStartOfHour(now() - INTERVAL $((HOURS+1)) HOUR)"
FIXED_TO="toStartOfHour(now() - INTERVAL 1 HOUR)"
FW="PREWHERE f.date >= toDate($FIXED_FROM) - 1 AND f.date <= toDate($FIXED_TO)
  WHERE f.$TS >= $FIXED_FROM AND f.$TS < $FIXED_TO"
CH -q "SELECT 'старый способ' AS how, formatReadableSize(sum(f.bytes)) AS total, count() AS rows
  FROM default.flows_raw AS f $OLD_JOIN $FW AND $OLD_FILTER FORMAT TSV"
CH -q "SELECT 'новый способ' AS how, formatReadableSize(sum(f.bytes)) AS total, count() AS rows
  FROM default.flows_raw AS f $FW AND $NEW_FILTER FORMAT TSV"
