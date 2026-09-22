#!/usr/bin/env bash
# Готовит и прогоняет замер разбора трафика на стенде.
#
# SQL генерируется внутри контейнера интерфейса — там есть node, задеплоенный код
# и доступ к базе, поэтому набор колонок определяется честно, а не по догадке.
# Сам замер гоняется с хоста питоном.
#
#   bench-run-stand.sh <метка>:<таблица> [<метка>:<таблица> ...]
#
# Пример: bench-run-stand.sh старая:flows_raw
#         bench-run-stand.sh старая:flows_v1 новая:flows_raw
set -uo pipefail

WINDOW_HOURS=${WINDOW_HOURS:-1}
LAG_MINUTES=${LAG_MINUTES:-10}
REPEAT=${REPEAT:-2}
TIMEOUT=${TIMEOUT:-300}
IF_ALIAS=${IF_ALIAS:-'he-c27296-fv='}

CH() { sudo -n docker exec -i grapes-clickhouse clickhouse-client "$@"; }

# Окно считаем от самого свежего времени в данных, а не от часов машины:
# у коллектора есть задержка экспорта, и последние минуты неполные.
# toString даёт 'YYYY-MM-DD hh:mm:ss' — ровно тот вид, что приходит из интерфейса.
# Разделитель — перевод строки: в самих значениях есть пробел.
FROM=$(CH -q "
  WITH toStartOfMinute(max(time_received_ns)) - INTERVAL ${LAG_MINUTES} MINUTE AS t_to
  SELECT toString(toDateTime(t_to) - INTERVAL ${WINDOW_HOURS} HOUR)
  FROM ${BENCH_TIME_TABLE:-default.flows_raw} WHERE date >= today() - 1")
TO=$(CH -q "
  WITH toStartOfMinute(max(time_received_ns)) - INTERVAL ${LAG_MINUTES} MINUTE AS t_to
  SELECT toString(toDateTime(t_to))
  FROM ${BENCH_TIME_TABLE:-default.flows_raw} WHERE date >= today() - 1")

if [ -z "$FROM" ] || [ -z "$TO" ]; then echo "не удалось определить окно замера"; exit 1; fi

echo "окно замера: $FROM .. $TO"
echo "фильтр по описанию порта: $IF_ALIAS"
echo

specs=()
for arg in "$@"; do
  label="${arg%%:*}"; table="${arg#*:}"
  out="/tmp/bench-${label}.json"
  echo "готовлю запросы для раскладки «$label» (таблица $table)"
  sudo -n docker exec \
    -e CLICKHOUSE_FLOWS_RAW_TABLE="$table" \
    -e BENCH_SERVER_DIR=/app/server \
    -e BENCH_IF_ALIAS="$IF_ALIAS" \
    -i grapes-nta node /tmp/gen-bench-queries.js "$FROM" "$TO" "/tmp/bench.json" >/dev/null 2>&1
  sudo -n docker cp grapes-nta:/tmp/bench.json "$out" >/dev/null 2>&1
  if [ ! -s "$out" ]; then echo "  НЕ УДАЛОСЬ подготовить $out"; exit 1; fi
  echo "  запросов: $(python3 -c "import json;print(len(json.load(open('$out'))))")"
  # Проверяем, что таблица в SQL действительно та, которую просили.
  if ! grep -q "\`${table}\`" "$out"; then
    echo "  ВНИМАНИЕ: в SQL нет таблицы $table — проверьте CLICKHOUSE_FLOWS_RAW_TABLE"
  fi
  specs+=("${label}=${out}")
done

echo
python3 /tmp/bench-flows-layout.py "${specs[@]}" --repeat "$REPEAT" --timeout "$TIMEOUT"
