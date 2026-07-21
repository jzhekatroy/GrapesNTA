#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export ASNNAMES_CLICKHOUSE_CLIENT="${ASNNAMES_CLICKHOUSE_CLIENT:-clickhouse-client}"

exec python3 /app/scripts/load_asn_names.py
