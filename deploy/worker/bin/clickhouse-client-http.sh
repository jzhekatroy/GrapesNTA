#!/bin/sh
# HTTP shim for clickhouse-client when the native binary is unavailable
# (e.g. Illegal instruction on older CPUs). Supports:
#   clickhouse-client --host --port --user --password --query 'SQL'
#   clickhouse-client --query 'INSERT ... FORMAT TabSeparated' < data.tsv

set -eu

HOST="${CLICKHOUSE_HTTP_HOST:-127.0.0.1}"
PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
USER="${CLICKHOUSE_HTTP_USER:-default}"
PASSWORD="${CLICKHOUSE_HTTP_PASSWORD:-}"
# A hung ClickHouse must not become a hung caller: the rollup cron holds a flock
# for the whole run, so a request that waits an hour silently kills every tick
# in that hour. Fail fast and let the next tick retry.
MAX_TIME="${CLICKHOUSE_HTTP_MAX_TIME:-180}"
DATABASE=""
QUERY=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --user) USER="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --database) DATABASE="$2"; shift 2 ;;
    -q|--query) QUERY="$2"; shift 2 ;;
    --multiquery) shift ;;
    --version)
      echo "clickhouse-client-http shim"
      exit 0
      ;;
    *)
      if [ "${1#-}" != "$1" ] && [ "$#" -ge 2 ]; then
        shift 2
      else
        shift
      fi
      ;;
  esac
done

if [ "$PORT" = "9000" ] || [ "$PORT" = "6124" ]; then
  PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
fi

BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT

if [ -n "$QUERY" ]; then
  printf '%s' "$QUERY" > "$BODY"
  # Append stdin payload when present (INSERT FORMAT TabSeparated).
  if [ ! -t 0 ]; then
    printf '\n' >> "$BODY"
    cat >> "$BODY"
  fi
else
  cat > "$BODY"
fi

if [ ! -s "$BODY" ]; then
  echo "clickhouse-client-http: empty query" >&2
  exit 1
fi

URL="http://${HOST}:${PORT}/?user=$(printf %s "$USER" | sed 's/ /%20/g')"
if [ -n "$PASSWORD" ]; then
  URL="${URL}&password=$(printf %s "$PASSWORD" | sed 's/ /%20/g')"
fi
if [ -n "$DATABASE" ]; then
  URL="${URL}&database=$(printf %s "$DATABASE" | sed 's/ /%20/g')"
fi

curl -sS -f --max-time "$MAX_TIME" -X POST "$URL" --data-binary @"$BODY"
# Ensure trailing newline like clickhouse-client
echo
