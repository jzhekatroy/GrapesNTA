#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

mkdir -p /app/analytics/server/data/observation_runs /var/log/grapesnta 2>/dev/null || true

echo "grapes-worker: starting rollups supercronic"
supercronic /etc/grapesnta/rollups.crontab &
SUP_PID=$!

echo "grapes-worker: starting observations loop"
cd /app/analytics
node server/analytics.js loop &
NODE_PID=$!

cleanup() {
  kill "$SUP_PID" "$NODE_PID" 2>/dev/null || true
  wait "$SUP_PID" "$NODE_PID" 2>/dev/null || true
}
trap cleanup INT TERM

# Keep the shell as PID 1 so it reaps supercronic's clickhouse-client/curl
# children. `exec node` left ~1500 zombies because Node does not wait() on
# processes it did not spawn, and supercronic disables reaping when not PID 1.
wait "$NODE_PID"
status=$?
kill "$SUP_PID" 2>/dev/null || true
wait "$SUP_PID" 2>/dev/null || true
exit "$status"
