#!/usr/bin/env bash
# Migrate IP talkers/pairs -> ASN talkers/pairs on collector (m61 / netflow-test).
#
# Run from GrapesNTA repo root after git pull:
#   sudo bash deploy/clickhouse/migrate_asn_talkers.sh
#
# Requires: /etc/grapesnta/traffic-rollups.env with CH credentials,
#           clickhouse-client on PATH (or TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="${TRAFFIC_ROLLUP_ENV:-/etc/grapesnta/traffic-rollups.env}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
fi

CH_BIN="${TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT:-clickhouse-client}"
CH_HOST="${TRAFFIC_ROLLUP_CH_HOST:-127.0.0.1}"
CH_PORT="${TRAFFIC_ROLLUP_CH_PORT:-9000}"
CH_USER="${TRAFFIC_ROLLUP_CH_USER:-default}"
CH_PASS="${TRAFFIC_ROLLUP_CH_PASSWORD:-}"
CH_DB="${TRAFFIC_ROLLUP_CH_DATABASE:-default}"

ch() {
  if [[ -n "$CH_PASS" ]]; then
    "$CH_BIN" --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" --password "$CH_PASS" --database "$CH_DB" "$@"
  else
    "$CH_BIN" --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" --database "$CH_DB" "$@"
  fi
}

echo "== stop talkers timer =="
systemctl stop traffic-talkers-rollups.timer || true
systemctl stop traffic-talkers-rollups.service || true

echo "== create ASN tables =="
ch --multiquery < "$REPO_ROOT/deploy/clickhouse/traffic_asn_1m.sql"
ch --multiquery < "$REPO_ROOT/deploy/clickhouse/traffic_asn_1h.sql"

echo "== deploy rollup jobs + systemd =="
install -m 0644 "$REPO_ROOT/scripts/traffic_rollup_jobs.py" /opt/GrapesNTA/scripts/traffic_rollup_jobs.py
install -m 0644 "$REPO_ROOT/deploy/systemd/traffic-talkers-rollups.service" /etc/systemd/system/traffic-talkers-rollups.service
systemctl daemon-reload

echo "== drop legacy IP talker/pair tables + state =="
ch --multiquery < "$REPO_ROOT/deploy/clickhouse/drop_traffic_talkers_ip.sql"

echo "== start talkers timer =="
systemctl enable --now traffic-talkers-rollups.timer
systemctl start traffic-talkers-rollups.service || true

echo "== verify state (may be empty until first successful bucket) =="
ch --query "
SELECT job, last_bucket, status, dateDiff('minute', last_bucket, now()) AS lag_min
FROM default.traffic_rollup_state FINAL
WHERE job IN ('traffic_asn_1m','traffic_asn_1h','traffic_asn_pair_1m','traffic_asn_pair_1h')
ORDER BY job
FORMAT PrettyCompact
"

echo "Done. Wait 1–2 timer ticks, then check:"
echo "  SELECT max(minute), count() FROM default.traffic_asn_1m;"
echo "  SELECT max(minute), count() FROM default.traffic_asn_pair_1m;"
echo "  journalctl -u traffic-talkers-rollups.service -n 40 --no-pager"
