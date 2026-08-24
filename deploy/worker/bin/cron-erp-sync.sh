#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

# trigger=cron makes runSync honour the "Ночной прогон" checkbox stored in
# default.app_erp_sync_settings: with cron_enabled=0 it logs a skipped run and
# exits, so toggling the checkbox in the UI needs no container restart.
export ERP_SYNC_TRIGGER=cron
export ERP_SYNC_ACTOR="${ERP_SYNC_ACTOR:-worker}"

# ERP paginates over thousands of clients, so the budget is far larger than the
# rollup ones. It still exists because supercronic holds the flock for the whole
# script and a wedged HTTPS read would block every later night.
TIMEOUT="${ERP_SYNC_TIMEOUT_SEC:-1800}"

cd /app/analytics
exec timeout -k 30 "$TIMEOUT" node scripts/erp-piterix-sync.js --full
