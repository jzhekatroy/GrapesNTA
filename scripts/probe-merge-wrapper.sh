#!/usr/bin/env bash
# Гейт миграции flows_raw: годится ли таблица-обёртка ENGINE = Merge поверх двух
# таблиц с разными типами времени и разными ключами сортировки.
#
# Проверяем ровно то, на что опирается боевой код:
#   1. чтение через обёртку вообще работает;
#   2. DateTime64(9) в старой таблице и DateTime в новой сводятся к одному типу;
#   3. PREWHERE по date не отвергается (код использует его во всех запросах);
#   4. партиции отсекаются, то есть обёртка не читает лишние дни;
#   5. скип-индексы подхватываются;
#   6. суммы через обёртку равны сумме по двум таблицам по отдельности.
#
# Ничего боевого не трогает: работает в базе probe_merge, в конце удаляет её.
set -uo pipefail

CH() { sudo -n docker exec -i grapes-clickhouse clickhouse-client "$@"; }
DB=probe_merge

ok=0; fail=0
check() { # check <имя> <ожидание> <факт>
  if [ "$2" = "$3" ]; then printf 'OK    %-46s %s\n' "$1" "$3"; ok=$((ok+1));
  else printf 'СБОЙ  %-46s ожидалось %s, получено %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}

CH -q "DROP DATABASE IF EXISTS ${DB}" >/dev/null 2>&1
CH -q "CREATE DATABASE ${DB}" || exit 1

# Старая раскладка: наносекундное время, сортировка по времени прихода.
CH -q "CREATE TABLE ${DB}.probe_v1
(
  date Date,
  time_received_ns DateTime64(9) CODEC(DoubleDelta, ZSTD(1)),
  time_flow_start_ns DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
  sampler_address FixedString(16),
  in_if UInt32,
  out_if UInt32,
  src_asn UInt32,
  src_port UInt32,
  bytes UInt64,
  packets UInt64,
  src_client LowCardinality(String),
  direction LowCardinality(String),
  INDEX idx_src_port src_port TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree PARTITION BY date ORDER BY time_received_ns
SETTINGS index_granularity = 8192" || exit 1

# Новая раскладка: секундное время, сортировка по пятиминутке и портам.
CH -q "CREATE TABLE ${DB}.probe_v2
(
  date Date,
  time_received_ns DateTime,
  time_flow_start_ns DateTime,
  sampler_address FixedString(16),
  in_if UInt32,
  out_if UInt32,
  src_asn UInt32,
  src_port UInt32,
  bytes UInt64,
  packets UInt64,
  src_client LowCardinality(String),
  direction LowCardinality(String),
  INDEX idx_src_port src_port TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree PARTITION BY date
ORDER BY (toStartOfFiveMinutes(time_received_ns), sampler_address, in_if, out_if)
SETTINGS index_granularity = 8192" || exit 1

# По 4 суток в каждую таблицу, периоды не пересекаются. Шаг по времени подобран
# так, чтобы данные реально распались на отдельные партиции по дням.
fill() { # fill <имя> <дата начала>
  CH -q "INSERT INTO ${DB}.$1
  SELECT toDate(t), t, t - 1,
         toFixedString(reverse(reinterpretAsFixedString(toUInt32(number % 8 + 1))), 16),
         number % 64, number % 32, number % 1000, number % 65535,
         100 + number % 900, 1 + number % 10,
         concat('client', toString(number % 50)), if(number % 2 = 0, 'in', 'out')
  FROM (
    SELECT number, toDateTime('$2 00:00:00') + intDiv(number * 4 * 86400, 800000) AS t
    FROM numbers(800000)
  )"
}

fill probe_v1 2026-09-10 || exit 1
fill probe_v2 2026-09-14 || exit 1

echo "строк в probe_v1: $(CH -q "SELECT count() FROM ${DB}.probe_v1")"
echo "строк в probe_v2: $(CH -q "SELECT count() FROM ${DB}.probe_v2")"
echo "партиций v1/v2:   $(CH -q "SELECT uniq(partition) FROM system.parts WHERE database='${DB}' AND table='probe_v1' AND active") / $(CH -q "SELECT uniq(partition) FROM system.parts WHERE database='${DB}' AND table='probe_v2' AND active")"
echo

# Обёртка объявляется с секундным временем: это конечное состояние после миграции,
# поэтому проверяем сразу его, а не промежуточный вариант.
CH -q "CREATE TABLE ${DB}.probe_all
(
  date Date,
  time_received_ns DateTime,
  time_flow_start_ns DateTime,
  sampler_address FixedString(16),
  in_if UInt32,
  out_if UInt32,
  src_asn UInt32,
  src_port UInt32,
  bytes UInt64,
  packets UInt64,
  src_client LowCardinality(String),
  direction LowCardinality(String)
)
ENGINE = Merge(${DB}, '^probe_v[12]\$')" \
  && echo "1. обёртка создана" || { echo "1. СБОЙ: обёртку создать не удалось"; exit 1; }

total=$(CH -q "SELECT count() FROM ${DB}.probe_all")

# --- 1. чтение и приведение типов -------------------------------------------
got=$(CH -q "SELECT count() FROM ${DB}.probe_all" 2>&1)
want=$(CH -q "SELECT (SELECT count() FROM ${DB}.probe_v1) + (SELECT count() FROM ${DB}.probe_v2)")
check "чтение через обёртку" "$want" "$got"

got=$(CH -q "SELECT toTypeName(time_received_ns) FROM ${DB}.probe_all LIMIT 1" 2>&1)
check "тип времени сведён к одному" "DateTime" "$got"

# --- 2. суммы совпадают ------------------------------------------------------
got=$(CH -q "SELECT sum(bytes) FROM ${DB}.probe_all" 2>&1)
want=$(CH -q "SELECT (SELECT sum(bytes) FROM ${DB}.probe_v1) + (SELECT sum(bytes) FROM ${DB}.probe_v2)")
check "сумма байт через обёртку" "$want" "$got"

# --- 3. PREWHERE по date -----------------------------------------------------
got=$(CH -q "SELECT count() FROM ${DB}.probe_all PREWHERE date >= '2026-09-12' AND date <= '2026-09-14' WHERE bytes > 0" 2>&1)
want=$(CH -q "SELECT count() FROM ${DB}.probe_all WHERE date >= '2026-09-12' AND date <= '2026-09-14' AND bytes > 0")
check "PREWHERE по date" "$want" "$got"

# --- 4. отсечение партиций ---------------------------------------------------
echo "=== A. отсечение партиций ==="
probe_prune() { # probe_prune <подпись> <условие>
  qid="prune-$RANDOM$RANDOM"
  CH --query_id "$qid" -q "SELECT sum(bytes) FROM ${DB}.probe_all PREWHERE $2 WHERE bytes > 0" >/dev/null 2>&1
  CH -q "SYSTEM FLUSH LOGS" >/dev/null
  rr=$(CH -q "SELECT read_rows FROM system.query_log WHERE query_id='$qid' AND type='QueryFinish' ORDER BY event_time DESC LIMIT 1")
  expect=$(CH -q "SELECT count() FROM ${DB}.probe_all WHERE $2")
  pct=$(CH -q "SELECT round(100 * $rr / $total, 1)")
  printf '  %-34s прочитано %-9s строк (%s%% таблицы), подходит %s\n' "$1" "$rr" "$pct" "$expect"
}
probe_prune "один день из старой таблицы" "date = '2026-09-11'"
probe_prune "один день из новой таблицы"  "date = '2026-09-15'"
probe_prune "два дня на стыке таблиц"     "date >= '2026-09-13' AND date <= '2026-09-14'"
probe_prune "весь период"                 "date >= '2026-09-01'"

echo
echo "  для сравнения, те же дни напрямую по физическим таблицам:"
qid="prune-direct-$RANDOM"
CH --query_id "$qid" -q "SELECT sum(bytes) FROM ${DB}.probe_v1 PREWHERE date = '2026-09-11' WHERE bytes > 0" >/dev/null 2>&1
CH -q "SYSTEM FLUSH LOGS" >/dev/null
echo "  напрямую из probe_v1, один день:   прочитано $(CH -q "SELECT read_rows FROM system.query_log WHERE query_id='$qid' AND type='QueryFinish' ORDER BY event_time DESC LIMIT 1") строк"

echo

# --- 5. скип-индекс ----------------------------------------------------------
qid="probe-skip-$RANDOM"
CH --query_id "$qid" -q "SELECT sum(bytes) FROM ${DB}.probe_all WHERE src_port = 443" >/dev/null 2>&1
CH -q "SYSTEM FLUSH LOGS" >/dev/null
skip_rows=$(CH -q "SELECT read_rows FROM system.query_log WHERE query_id='$qid' AND type='QueryFinish' ORDER BY event_time DESC LIMIT 1")
echo "5. скип-индекс по src_port: прочитано $skip_rows из $total"
if [ "$skip_rows" -lt "$total" ]; then
  printf 'OK    %-46s %s < %s\n' "скип-индекс работает" "$skip_rows" "$total"; ok=$((ok+1))
else
  printf 'СБОЙ  %-46s прочитано всё: %s\n' "скип-индекс не подхватился" "$skip_rows"; fail=$((fail+1))
fi

# --- 6. сравнение времени с DateTime64, как это делает обнаружение атак -------
# Обнаружение атак сравнивает колонку с литералом DateTime64. Проверяем, что
# через обёртку такое сравнение даёт то же, что и обычное строковое.
got=$(CH -q "SELECT count() FROM ${DB}.probe_all
  WHERE time_received_ns >= toDateTime64('2026-09-13 00:00:00', 9, 'UTC')
    AND time_received_ns <  toDateTime64('2026-09-13 01:00:00', 9, 'UTC')" 2>&1)
check "сравнение с литералом DateTime64" \
  "$(CH -q "SELECT count() FROM ${DB}.probe_all WHERE time_received_ns >= '2026-09-13 00:00:00' AND time_received_ns < '2026-09-13 01:00:00'")" \
  "$got"

# --- 7. группировка по времени, как в графиках -------------------------------
got=$(CH -q "SELECT count() FROM (SELECT toStartOfInterval(time_received_ns, INTERVAL 300 second) AS b, sum(bytes)
  FROM ${DB}.probe_all PREWHERE date >= '2026-09-10' WHERE bytes > 0 GROUP BY b)" 2>&1)
check "группировка по пятиминуткам" "$(CH -q "SELECT count() FROM (SELECT toStartOfInterval(time_received_ns, INTERVAL 300 second) AS b FROM ${DB}.probe_v1 GROUP BY b UNION DISTINCT SELECT toStartOfInterval(time_received_ns, INTERVAL 300 second) AS b FROM ${DB}.probe_v2 GROUP BY b)")" "$got"

# --- 8. JOIN со справочником, как в разборе трафика --------------------------
got=$(CH -q "SELECT count() FROM ${DB}.probe_all AS f
  LEFT JOIN (SELECT 1 AS k, 'x' AS v) AS d ON d.k = f.in_if
  PREWHERE f.date >= '2026-09-10' WHERE f.bytes > 0" 2>&1)
check "LEFT JOIN через обёртку" "$total" "$got"

echo "=== B. последствия ALTER через обёртку ==="
if CH -q "ALTER TABLE ${DB}.probe_all ADD COLUMN src_as_path Array(UInt32) DEFAULT []" >/dev/null 2>&1; then
  echo "  ALTER ADD COLUMN на обёртке: прошёл"
  echo "  колонка появилась в обёртке:      $(CH -q "SELECT count() FROM system.columns WHERE database='${DB}' AND table='probe_all' AND name='src_as_path'")"
  echo "  колонка появилась в probe_v1:     $(CH -q "SELECT count() FROM system.columns WHERE database='${DB}' AND table='probe_v1' AND name='src_as_path'")"
  echo "  колонка появилась в probe_v2:     $(CH -q "SELECT count() FROM system.columns WHERE database='${DB}' AND table='probe_v2' AND name='src_as_path'")"
  echo -n "  чтение этой колонки через обёртку: "
  out=$(CH -q "SELECT count() FROM ${DB}.probe_all WHERE length(src_as_path) = 0" 2>&1)
  if [ $? -eq 0 ]; then echo "работает, вернулось $out (значения по умолчанию)"
  else echo "ПАДАЕТ: $(echo "$out" | head -2 | tr '\n' ' ')"; fi
else
  echo "  ALTER ADD COLUMN на обёртке: отклонён"
fi

echo
echo "  а что делает ALTER MODIFY TTL, который дёргает интерфейс:"
out=$(CH -q "ALTER TABLE ${DB}.probe_all MODIFY TTL date + toIntervalDay(7)" 2>&1)
if [ $? -eq 0 ]; then echo "  MODIFY TTL на обёртке: прошёл (и ничего не сделал с данными)"
else echo "  MODIFY TTL на обёртке: отклонён — $(echo "$out" | grep -o 'DB::Exception[^,]*' | head -1)"; fi

echo
echo "  INSERT в обёртку (коллектор так не делает, но проверим):"
out=$(CH -q "INSERT INTO ${DB}.probe_all (date, time_received_ns, bytes) VALUES ('2026-09-20', '2026-09-20 00:00:00', 1)" 2>&1)
if [ $? -eq 0 ]; then echo "  INSERT прошёл — это было бы опасно"
else echo "  INSERT отклонён — $(echo "$out" | grep -o 'Table function .Merge. cannot be used[^.]*\|DB::Exception:[^,]*' | head -1)"; fi

echo
echo "итог: успешно $ok, сбоев $fail"
CH -q "DROP DATABASE ${DB}" >/dev/null 2>&1
[ "$fail" -eq 0 ]
