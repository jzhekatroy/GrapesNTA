#!/usr/bin/env bash
# Apply net_interfaces_dict with real ClickHouse credentials.
#
# Usage (prefer on the ClickHouse host via native client):
#   export CH_DICT_USER=ui_admin
#   export CH_DICT_PASSWORD='...'
#   export CH_CLIENT='docker exec -i kcg-main-db-1 clickhouse-client'
#   ./deploy/clickhouse/apply_net_snmp_interfaces_dict.sh
#
# External HTTP proxies on :6124 often reject CREATE DICTIONARY.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEMPLATE="$ROOT/deploy/schema/50_net/23_net_interfaces_dict.sql"
CH_CLIENT="${CH_CLIENT:-clickhouse-client}"

if [[ -z "${CH_DICT_USER:-}" || -z "${CH_DICT_PASSWORD:-}" ]]; then
  echo "Set CH_DICT_USER and CH_DICT_PASSWORD (account that can SELECT net_interfaces_current)." >&2
  exit 1
fi

if [[ ! -f "$TEMPLATE" ]]; then
  echo "Missing template: $TEMPLATE" >&2
  exit 1
fi

echo "Applying dictionary as SOURCE USER=${CH_DICT_USER} via: $CH_CLIENT"
python3 - "$TEMPLATE" <<'PY' | $CH_CLIENT --multiquery
import os, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("${CH_DICT_USER}", os.environ["CH_DICT_USER"])
text = text.replace("${CH_DICT_PASSWORD}", os.environ["CH_DICT_PASSWORD"])
sys.stdout.write(text)
PY

echo "Done. If UI roles use dictGet, run as a grant admin:"
echo "  GRANT dictGet ON default.net_interfaces_dict TO ui_read;"
