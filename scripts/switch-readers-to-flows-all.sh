#!/usr/bin/env bash
# Переводит читателей на обёртку flows_all и обратно.
#
# Обёртка нужна на время, пока прежняя таблица flows_v1 доживает свой TTL:
# через неё видно и новые, и старые данные, поэтому история не рвётся.
# Имя для изменения схемы остаётся физическим: обёртка ALTER не поддерживает.
#
#   switch-readers-to-flows-all.sh on   # перевести на обёртку
#   switch-readers-to-flows-all.sh off  # вернуть на физическую таблицу
set -euo pipefail

ROOT=${ROOT:-/opt/GrapesNTA}
MODE=${1:-}
[ "$MODE" = "on" ] || [ "$MODE" = "off" ] || { echo "нужно: $0 on|off"; exit 2; }

set_var() { # set_var <файл> <имя> <значение>
  local f=$1 k=$2 v=$3
  if grep -qE "^${k}=" "$f"; then
    sed -i -E "s|^${k}=.*|${k}=${v}|" "$f"
  else
    printf '%s=%s\n' "$k" "$v" >> "$f"
  fi
}

drop_var() { # drop_var <файл> <имя>
  sed -i -E "/^$2=/d" "$1"
}

for svc in ui worker detection; do
  f="${ROOT}/deploy/${svc}/.env"
  [ -f "$f" ] || { echo "пропускаю ${svc}: нет ${f}"; continue; }
  cp -n "$f" "${f}.before-flows-all" 2>/dev/null || true

  if [ "$MODE" = "on" ]; then
    set_var "$f" CLICKHOUSE_FLOWS_RAW_TABLE flows_all
    set_var "$f" CLICKHOUSE_FLOWS_RAW_WRITE_TABLE flows_raw
    [ "$svc" = "worker" ] && set_var "$f" TRAFFIC_ROLLUP_FLOWS_TABLE default.flows_all
  else
    set_var "$f" CLICKHOUSE_FLOWS_RAW_TABLE flows_raw
    drop_var "$f" CLICKHOUSE_FLOWS_RAW_WRITE_TABLE
    drop_var "$f" TRAFFIC_ROLLUP_FLOWS_TABLE
  fi

  echo "=== ${svc} ==="
  grep -E '^(CLICKHOUSE_FLOWS_RAW_TABLE|CLICKHOUSE_FLOWS_RAW_WRITE_TABLE|TRAFFIC_ROLLUP_FLOWS_TABLE)=' "$f" \
    | sed 's/^/  /'
done
