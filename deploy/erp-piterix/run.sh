#!/bin/bash
set -euo pipefail
# Полный ночной прогон: выгрузка ERP piter_ix, upsert, отключение пропавших.
if [ -f /etc/grapes/erp-piterix.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/grapes/erp-piterix.env
  set +a
fi
export ERP_SYNC_TRIGGER="${ERP_SYNC_TRIGGER:-cron}"
export ERP_SYNC_ACTOR="${ERP_SYNC_ACTOR:-timer}"
if [ -x /usr/local/bin/node ] || command -v node >/dev/null; then
  if [ -f /opt/grapes/erp-piterix/scripts/erp-piterix-sync.js ]; then
    exec node /opt/grapes/erp-piterix/scripts/erp-piterix-sync.js --full
  fi
fi
# CLI must live in /app/scripts/ so require('../server/erp-piterix-run') resolves.
exec docker exec -w /app \
  -e NODE_PATH=/app/node_modules \
  -e ERP_SYNC_TRIGGER \
  -e ERP_SYNC_ACTOR \
  -e ERP_API_BASE \
  -e ERP_API_HOST \
  -e ERP_API_TOKEN \
  -e ERP_API_INSECURE \
  -e ERP_API_PAGE_LIMIT \
  grapes-nta node /app/scripts/erp-piterix-sync.js --full
