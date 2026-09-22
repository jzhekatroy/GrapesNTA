#!/usr/bin/env bash
# Сравнивает два способа определить клиента кабинета по порту коммутатора:
# линейный перебор правил внутри arrayFirst и поиск по таблице соответствий
# через transform. Проверяет совпадение результата и разницу во времени.
set -uo pipefail

FROM=${PROBE_FROM:-'2026-09-22 03:55:00'}
TO=${PROBE_TO:-'2026-09-22 03:57:00'}
REPEAT=${PROBE_REPEAT:-2}
OUT=${PROBE_OUT:-/tmp/probe-cabinet}

ch() {
  sudo -n docker exec -i grapes-clickhouse clickhouse-client --max_execution_time 600 "$@"
}

mkdir -p "$OUT"

cte() {
  cat <<SQL
WITH
  toDateTime('$FROM') AS ts_from,
  toDateTime('$TO') AS ts_to,
  (SELECT groupArray(tuple(p.client_id, p.switch_ip, p.if_index))
   FROM default.net_client_ports_enabled AS p
   INNER JOIN default.net_clients_enabled AS c
     ON c.client_id = p.client_id AND c.bind_mode = 'ports') AS port_rules,
  (SELECT groupArray(k) FROM (
     SELECT concat(p.switch_ip, '|', toString(p.if_index)) AS k, min(p.client_id) AS cid
     FROM default.net_client_ports_enabled AS p
     INNER JOIN default.net_clients_enabled AS c
       ON c.client_id = p.client_id AND c.bind_mode = 'ports'
     GROUP BY k ORDER BY k)) AS port_keys,
  (SELECT groupArray(cid) FROM (
     SELECT concat(p.switch_ip, '|', toString(p.if_index)) AS k, min(p.client_id) AS cid
     FROM default.net_client_ports_enabled AS p
     INNER JOIN default.net_clients_enabled AS c
       ON c.client_id = p.client_id AND c.bind_mode = 'ports'
     GROUP BY k ORDER BY k)) AS port_vals,
  if(length(f.sampler_address) = 16
       AND substring(f.sampler_address, 5) = unhex('000000000000000000000000'),
     toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.sampler_address, 1, 4))))),
     IPv6NumToString(f.sampler_address)) AS sampler_str,
  if(f.in_if > 0 AND bitShiftRight(f.in_if, 30) = 0,
     bitAnd(f.in_if, 1073741823), toUInt32(0)) AS in_idx,
  if(f.out_if > 0 AND bitShiftRight(f.out_if, 30) = 0,
     bitAnd(f.out_if, 1073741823), toUInt32(0)) AS out_idx
SQL
}

old_key() {
  cat <<'SQL'
multiIf(
  nullIf(tupleElement(arrayFirst(x -> (x.2 = sampler_str) AND (x.3 = in_idx), port_rules), 1), '') != '',
    nullIf(tupleElement(arrayFirst(x -> (x.2 = sampler_str) AND (x.3 = in_idx), port_rules), 1), ''),
  nullIf(tupleElement(arrayFirst(x -> (x.2 = sampler_str) AND (x.3 = out_idx), port_rules), 1), '') != '',
    nullIf(tupleElement(arrayFirst(x -> (x.2 = sampler_str) AND (x.3 = out_idx), port_rules), 1), ''),
  '---')
SQL
}

new_key() {
  cat <<'SQL'
multiIf(
  transform(concat(sampler_str, '|', toString(in_idx)), port_keys, port_vals, '') != '',
    transform(concat(sampler_str, '|', toString(in_idx)), port_keys, port_vals, ''),
  transform(concat(sampler_str, '|', toString(out_idx)), port_keys, port_vals, '') != '',
    transform(concat(sampler_str, '|', toString(out_idx)), port_keys, port_vals, ''),
  '---')
SQL
}

tail_sql() {
  cat <<'SQL'
FROM default.flows_raw AS f
PREWHERE f.date >= toDate(ts_from) - 1 AND f.date <= toDate(ts_to)
WHERE f.time_received_ns >= ts_from AND f.time_received_ns < ts_to
GROUP BY k
ORDER BY bytes DESC, k
LIMIT 30
SQL
}

for tag in old new; do
  key=$([ "$tag" = old ] && old_key || new_key)
  {
    cte
    echo "SELECT"
    echo "  $key AS k,"
    echo "  sum(f.bytes) AS bytes,"
    echo "  sum(f.packets) AS packets"
    tail_sql
  } > "$OUT/$tag.sql"
done

echo "окно: $FROM .. $TO, лучший из $REPEAT"
for tag in old new; do
  label=$([ "$tag" = old ] && echo 'перебор правил (как сейчас)' || echo 'поиск по соответствиям (transform)')
  best=''
  for _ in $(seq "$REPEAT"); do
    start=$(date +%s%N)
    if ! ch --format TSV < "$OUT/$tag.sql" > "$OUT/$tag.tsv" 2> "$OUT/$tag.err"; then
      echo "  $label: ОТКАЗ: $(head -1 "$OUT/$tag.err")"
      best=''
      break
    fi
    end=$(date +%s%N)
    el=$(( (end - start) / 1000000 ))
    if [ -z "$best" ] || [ "$el" -lt "$best" ]; then best=$el; fi
  done
  [ -n "$best" ] && printf '  %-34s %s.%03d с\n' "$label" "$((best / 1000))" "$((best % 1000))"
done

echo 'сверка результата:'
if [ -s "$OUT/old.tsv" ] && [ -s "$OUT/new.tsv" ]; then
  if diff -q "$OUT/old.tsv" "$OUT/new.tsv" > /dev/null; then
    echo "  совпадает, строк: $(wc -l < "$OUT/new.tsv")"
  else
    echo '  РАСХОЖДЕНИЕ:'
    diff "$OUT/old.tsv" "$OUT/new.tsv" | head -20
  fi
else
  echo '  нечего сверять: один из вариантов не отдал результат'
fi
