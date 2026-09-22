#!/usr/bin/env bash
# Раскладывает стоимость ключа группировки по клиенту кабинета на части:
# сколько стоит подстраховка по сетям, сколько сам поиск по портам.
# Нужно, чтобы решать, есть ли смысл убирать ветку сетей из запроса, когда
# привязок по сетям нет ни у одного клиента.
set -uo pipefail

FROM=${PROBE_FROM:-'2026-09-22 03:40:00'}
TO=${PROBE_TO:-'2026-09-22 04:05:00'}
REPEAT=${PROBE_REPEAT:-2}
OUT=${PROBE_OUT:-/tmp/probe-key-cost}

ch() {
  sudo -n docker exec -i grapes-clickhouse clickhouse-client --max_execution_time 300 "$@"
}

mkdir -p "$OUT"

cte() {
  cat <<SQL
WITH
  toDateTime('$FROM') AS ts_from,
  toDateTime('$TO') AS ts_to,
  (SELECT groupArray(tuple(p.client_id, p.prefix))
   FROM default.net_client_prefixes_enabled AS p
   INNER JOIN default.net_clients_enabled AS c
     ON c.client_id = p.client_id AND c.bind_mode = 'prefixes') AS prefix_rules,
  (SELECT groupArray(port_key) FROM (
     SELECT concat(p.switch_ip, '|', toString(p.if_index)) AS port_key, min(p.client_id) AS client_id
     FROM default.net_client_ports_enabled AS p
     INNER JOIN default.net_clients_enabled AS c
       ON c.client_id = p.client_id AND c.bind_mode = 'ports'
     GROUP BY port_key ORDER BY port_key)) AS port_keys,
  (SELECT groupArray(client_id) FROM (
     SELECT concat(p.switch_ip, '|', toString(p.if_index)) AS port_key, min(p.client_id) AS client_id
     FROM default.net_client_ports_enabled AS p
     INNER JOIN default.net_clients_enabled AS c
       ON c.client_id = p.client_id AND c.bind_mode = 'ports'
     GROUP BY port_key ORDER BY port_key)) AS port_values
SQL
}

SRC_IP="if(length(f.src_addr) = 16 AND substring(f.src_addr, 5) = unhex('000000000000000000000000'), toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4))))), IPv6NumToString(f.src_addr))"
DST_IP="if(length(f.dst_addr) = 16 AND substring(f.dst_addr, 5) = unhex('000000000000000000000000'), toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4))))), IPv6NumToString(f.dst_addr))"
SAMPLER="if(length(f.sampler_address) = 16 AND substring(f.sampler_address, 5) = unhex('000000000000000000000000'), toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.sampler_address, 1, 4))))), IPv6NumToString(f.sampler_address))"
IN_IDX="if(f.in_if > 0 AND bitShiftRight(f.in_if, 30) = 0, bitAnd(f.in_if, 1073741823), toUInt32(0))"
OUT_IDX="if(f.out_if > 0 AND bitShiftRight(f.out_if, 30) = 0, bitAnd(f.out_if, 1073741823), toUInt32(0))"

PFX_SRC="nullIf(tupleElement(arrayFirst(x -> isIPAddressInRange($SRC_IP, x.2), prefix_rules), 1), '')"
PFX_DST="nullIf(tupleElement(arrayFirst(x -> isIPAddressInRange($DST_IP, x.2), prefix_rules), 1), '')"
PFX_SRC_LAZY="if(empty(prefix_rules), '', $PFX_SRC)"
PFX_DST_LAZY="if(empty(prefix_rules), '', $PFX_DST)"
PORT_IN="transform(concat($SAMPLER, '|', toString($IN_IDX)), port_keys, port_values, '')"
PORT_OUT="transform(concat($SAMPLER, '|', toString($OUT_IDX)), port_keys, port_values, '')"

key_full() {
  cat <<SQL
multiIf(
  f.src_client != '', f.src_client,
  f.dst_client != '', f.dst_client,
  $PFX_SRC != '', $PFX_SRC,
  $PFX_DST != '', $PFX_DST,
  $PORT_IN != '', $PORT_IN,
  $PORT_OUT != '', $PORT_OUT,
  '---')
SQL
}

key_lazy() {
  cat <<SQL
multiIf(
  f.src_client != '', f.src_client,
  f.dst_client != '', f.dst_client,
  $PFX_SRC_LAZY != '', $PFX_SRC_LAZY,
  $PFX_DST_LAZY != '', $PFX_DST_LAZY,
  $PORT_IN != '', $PORT_IN,
  $PORT_OUT != '', $PORT_OUT,
  '---')
SQL
}

key_noprefix() {
  cat <<SQL
multiIf(
  f.src_client != '', f.src_client,
  f.dst_client != '', f.dst_client,
  $PORT_IN != '', $PORT_IN,
  $PORT_OUT != '', $PORT_OUT,
  '---')
SQL
}

for tag in full lazy noprefix; do
  {
    cte
    echo 'SELECT'
    echo "  $(key_$tag) AS k,"
    echo '  sum(f.bytes) AS bytes'
    cat <<'SQL'
FROM default.flows_raw AS f
PREWHERE f.date >= toDate(ts_from) - 1 AND f.date <= toDate(ts_to)
WHERE f.time_received_ns >= ts_from AND f.time_received_ns < ts_to
GROUP BY k
ORDER BY bytes DESC, k
LIMIT 30
SQL
  } > "$OUT/$tag.sql"
done

echo "окно: $FROM .. $TO, лучший из $REPEAT"
for tag in full lazy noprefix; do
  case $tag in
    full)     label='как сейчас (ветка сетей считается)' ;;
    lazy)     label='ветка сетей под пустой проверкой' ;;
    noprefix) label='ветки сетей нет вовсе' ;;
  esac
  best=''
  for _ in $(seq "$REPEAT"); do
    start=$(date +%s%N)
    if ! ch --format TSV < "$OUT/$tag.sql" > "$OUT/$tag.tsv" 2> "$OUT/$tag.err"; then
      printf '  %-38s ОТКАЗ: %s\n' "$label" "$(tail -2 "$OUT/$tag.err" | head -1 | cut -c1-140)"
      best=''; break
    fi
    end=$(date +%s%N)
    el=$(( (end - start) / 1000000 ))
    if [ -z "$best" ] || [ "$el" -lt "$best" ]; then best=$el; fi
  done
  [ -n "$best" ] && printf '  %-38s %s.%03d с\n' "$label" "$((best / 1000))" "$((best % 1000))"
done

echo 'сверка: все три варианта должны дать одинаковый top-30'
if diff -q "$OUT/full.tsv" "$OUT/lazy.tsv" >/dev/null 2>&1 \
   && diff -q "$OUT/full.tsv" "$OUT/noprefix.tsv" >/dev/null 2>&1; then
  echo "  совпадает, строк: $(wc -l < "$OUT/full.tsv")"
else
  echo '  РАСХОЖДЕНИЕ:'
  diff "$OUT/full.tsv" "$OUT/lazy.tsv" | head -10
  diff "$OUT/full.tsv" "$OUT/noprefix.tsv" | head -10
fi
