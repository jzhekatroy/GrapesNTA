#!/usr/bin/env bash
# One-shot unblock for fresh stand: apply missing schema bits, speed up rollups,
# run traffic-rollups until dashboard has recent minutes.
#
# Run on collector host as root (nta example):
#   bash /opt/GrapesNTA/scripts/nta-unblock-rollups.sh
set -euo pipefail

REPO="${REPO_ROOT:-/opt/GrapesNTA}"
SCHEMA="${SCHEMA_DIR:-/opt/grapes/schema}"

clickhouse-client() {
  command clickhouse-client --host 127.0.0.1 --port 9000 \
    --user "${CH_DEFAULT_USER:-default}" \
    --password "${CH_DEFAULT_PASSWORD:?set CH_DEFAULT_PASSWORD or source /opt/grapes/clickhouse/.env}" \
    "$@"
}

if [[ -f /opt/grapes/clickhouse/.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source /opt/grapes/clickhouse/.env
  set +a
fi

echo "=== $(date) apply missing schema objects ==="
for f in \
  "$SCHEMA/40_enrichment/08_asn_registry_staging.sql" \
  "$SCHEMA/40_enrichment/09_asn_registry_enriched.sql" \
  "$SCHEMA/60_traffic/17_traffic_talker_1m.sql" \
  "$SCHEMA/60_traffic/18_traffic_talker_1h.sql" \
  "$SCHEMA/60_traffic/19_traffic_pair_1m.sql" \
  "$SCHEMA/60_traffic/20_traffic_pair_1h.sql"
do
  if [[ ! -f "$f" ]]; then
    echo "missing $f — copy deploy/schema from GrapesNTA main first" >&2
    exit 1
  fi
  clickhouse-client --multiquery < "$f"
  echo "applied $(basename "$f")"
done

echo "=== speed up rollups temporarily ==="
ENV_FILE=/etc/grapesnta/traffic-rollups.env
if grep -q '^TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB=' "$ENV_FILE"; then
  sed -i 's/^TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB=.*/TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB=60/' "$ENV_FILE"
else
  echo 'TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB=60' >> "$ENV_FILE"
fi

echo "=== git pull rollup script (skip_forward + empty bootstrap) ==="
if [[ -d "$REPO/.git" ]]; then
  git -C "$REPO" pull --ff-only || true
fi

echo "=== run traffic-rollups in a loop (max 20 passes) ==="
for i in $(seq 1 20); do
  echo "--- pass $i ---"
  systemctl start traffic-rollups.service || true
  sleep 2
  MX=$(clickhouse-client -q "SELECT ifNull(max(minute), toDateTime('1970-01-01 00:00:00', 'UTC')) FROM traffic_dashboard_1m")
  CNT=$(clickhouse-client -q "SELECT count() FROM traffic_dashboard_1m")
  LAG=$(clickhouse-client -q "
    SELECT dateDiff(
      'minute',
      (SELECT ifNull(max(minute), toDateTime('1970-01-01 00:00:00', 'UTC')) FROM traffic_dashboard_1m),
      toStartOfMinute(now()) - INTERVAL 5 MINUTE
    )
  ")
  echo "dashboard_1m rows=$CNT max_minute=$MX lag_minutes=$LAG"
  if [[ "$CNT" -gt 0 && "$LAG" -le 10 ]]; then
    echo "ROLLUP_UNBLOCK_OK $(date)"
    break
  fi
  sleep 3
done

echo "=== talkers rollups ==="
systemctl start traffic-talkers-rollups.service || true

echo "=== verify ==="
clickhouse-client -q "
SELECT
  'flows_raw' AS t, count() c, max(time_received_ns) mx FROM flows_raw
UNION ALL
SELECT 'traffic_dashboard_1m', count(), toString(max(minute)) FROM traffic_dashboard_1m
UNION ALL
SELECT 'traffic_talker_1m', count(), toString(max(minute)) FROM traffic_talker_1m
FORMAT PrettyCompact
"
