#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
export CLICKHOUSE_HTTP_HOST="${TRAFFIC_ROLLUP_CH_HOST:-127.0.0.1}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_HTTP_USER="${TRAFFIC_ROLLUP_CH_USER:-default}"
export CLICKHOUSE_HTTP_PASSWORD="${TRAFFIC_ROLLUP_CH_PASSWORD:-}"
export FLOW_THINNING_LOG_FILE="${FLOW_THINNING_LOG_FILE:-/var/log/grapesnta/flow_thinning.log}"

# Счёт строк за сутки идёт десятки секунд, сама мутация возвращается сразу.
# Без потолка зависший запрос держит flock и молчит до перезапуска контейнера.
TIMEOUT="${FLOW_THINNING_TIMEOUT_SEC:-1200}"

exec timeout -k 30 "$TIMEOUT" python3 /app/scripts/flow_thinning.py
