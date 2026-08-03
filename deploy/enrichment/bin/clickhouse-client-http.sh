#!/bin/sh
# HTTP shim — same behaviour as deploy/worker/bin/clickhouse-client-http.sh
set -eu

HOST="${CLICKHOUSE_HTTP_HOST:-127.0.0.1}"
PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
USER="${CLICKHOUSE_HTTP_USER:-default}"
PASSWORD="${CLICKHOUSE_HTTP_PASSWORD:-}"
# See the worker copy: an hour-long wait on a hung ClickHouse turns into a
# stuck cron job. Enrichment loads are heavier than rollup buckets, so give
# them more room while still bounding the wait.
MAX_TIME="${CLICKHOUSE_HTTP_MAX_TIME:-900}"
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
    --version) echo "clickhouse-client-http shim"; exit 0 ;;
    *)
      if [ "${1#-}" != "$1" ] && [ "$#" -ge 2 ]; then shift 2; else shift; fi
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
echo
