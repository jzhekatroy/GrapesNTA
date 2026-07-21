#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

mkdir -p /app/analytics/server/data/observation_runs /var/log/grapesnta

echo "grapes-worker: starting rollups supercronic"
supercronic /etc/grapesnta/rollups.crontab &
SUP_PID=$!

cleanup() {
  kill "$SUP_PID" 2>/dev/null || true
}
trap cleanup INT TERM

echo "grapes-worker: starting observations loop"
cd /app/analytics
exec node server/analytics.js loop
