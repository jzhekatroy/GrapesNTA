#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export BGPORIGIN_CLICKHOUSE_CLIENT="${BGPORIGIN_CLICKHOUSE_CLIENT:-clickhouse-client}"

exec python3 /app/scripts/rebuild_bgp_origin_asn.py
