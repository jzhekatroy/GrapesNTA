#!/usr/bin/env bash
# Проверяет, во что обходится сопоставление сетей клиента внутри arrayFirst:
# повторяется ли преобразование адреса на каждом правиле и что даёт замена
# разбора CIDR-строк на сравнение числовых границ. Правил для сетей на стенде
# нет, поэтому массив правил берётся синтетический.
set -uo pipefail

FROM=${PROBE_FROM:-'2026-09-22 03:55:00'}
TO=${PROBE_TO:-'2026-09-22 03:56:00'}
RULES=${PROBE_RULES:-500}
OUT=${PROBE_OUT:-/tmp/probe-prefix}

ch() {
  sudo -n docker exec -i grapes-clickhouse clickhouse-client --max_execution_time 600 "$@"
}

mkdir -p "$OUT"

IP_STR="if(length(src_addr) = 16 AND substring(src_addr, 5) = unhex('000000000000000000000000'), toString(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4))))), IPv6NumToString(src_addr))"
IP_NUM="reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))"
SCAN="FROM default.flows_raw
  PREWHERE date >= toDate(toDateTime('$FROM')) - 1 AND date <= toDate(toDateTime('$TO'))
  WHERE time_received_ns >= toDateTime('$FROM') AND time_received_ns < toDateTime('$TO')"

rules_cte() {
  cat <<SQL
WITH
  arrayMap(i -> tuple(concat('client:', toString(i)),
                      concat(toString(i % 223 + 10), '.', toString(i % 251), '.0.0/16')),
           range(1, $RULES + 1)) AS prefix_rules,
  arrayMap(i -> tuple(concat('client:', toString(i)),
                      toUInt32(tupleElement(IPv4CIDRToRange(toIPv4(concat(toString(i % 223 + 10), '.', toString(i % 251), '.0.0')), toUInt8(16)), 1)),
                      toUInt32(tupleElement(IPv4CIDRToRange(toIPv4(concat(toString(i % 223 + 10), '.', toString(i % 251), '.0.0')), toUInt8(16)), 2))),
           range(1, $RULES + 1)) AS prefix_ranges_v4
SQL
}

# 1. Как сейчас: преобразование адреса записано прямо внутри лямбды.
{
  rules_cte
  echo "SELECT uniqExact(tupleElement(arrayFirst(x -> isIPAddressInRange($IP_STR, x.2), prefix_rules), 1)) AS clients"
  echo "$SCAN"
} > "$OUT/inline.sql"

# 2. Адрес посчитан один раз во вложенном запросе, разбор CIDR остался.
{
  rules_cte
  echo "SELECT uniqExact(tupleElement(arrayFirst(x -> isIPAddressInRange(ip_str, x.2), prefix_rules), 1)) AS clients"
  echo "FROM (SELECT $IP_STR AS ip_str"
  echo "$SCAN"
  echo ')'
} > "$OUT/hoisted.sql"

# 3. Предлагаемый вариант: числовые границы, внутри лямбды нет вызовов функций.
{
  rules_cte
  echo "SELECT uniqExact(tupleElement(arrayFirst(x -> (ip_num >= x.2) AND (ip_num <= x.3), prefix_ranges_v4), 1)) AS clients"
  echo "FROM (SELECT $IP_NUM AS ip_num"
  echo "$SCAN"
  echo ')'
} > "$OUT/ranges.sql"

echo "окно: $FROM .. $TO, правил: $RULES"
for tag in inline hoisted ranges; do
  case $tag in
    inline)  label='разбор строк внутри лямбды (как сейчас)' ;;
    hoisted) label='адрес посчитан один раз' ;;
    ranges)  label='сравнение числовых границ' ;;
  esac
  start=$(date +%s%N)
  if ! ch --format TSV < "$OUT/$tag.sql" > "$OUT/$tag.tsv" 2> "$OUT/$tag.err"; then
    printf '  %-42s ОТКАЗ: %s\n' "$label" "$(tail -2 "$OUT/$tag.err" | head -1 | cut -c1-160)"
    continue
  fi
  end=$(date +%s%N)
  el=$(( (end - start) / 1000000 ))
  printf '  %-42s %s.%03d с   клиентов: %s\n' "$label" "$((el / 1000))" "$((el % 1000))" "$(cut -f1 "$OUT/$tag.tsv")"
done
