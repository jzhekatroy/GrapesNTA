#!/usr/bin/env bash
# Seed system-defined local/private L3 prefixes used by the traffic classifier.
#
# These prefixes should never be classified as remote Internet endpoints. They
# are inserted with source='system' so operators can distinguish them from
# manually managed customer/provider prefixes.

set -euo pipefail

ENV_FILE="${TRAFFIC_ROLLUP_ENV_FILE:-/etc/grapesnta/traffic-rollups.env}"
if [[ -r "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

CH_HOST="${CH_HOST:-${TRAFFIC_ROLLUP_CH_HOST:-127.0.0.1}}"
CH_PORT="${CH_PORT:-${TRAFFIC_ROLLUP_CH_PORT:-9000}}"
CH_USER="${CH_USER:-${TRAFFIC_ROLLUP_CH_USER:-default}}"
CH_PASSWORD="${CH_PASSWORD:-${TRAFFIC_ROLLUP_CH_PASSWORD:-}}"
CH_DATABASE="${CH_DATABASE:-${TRAFFIC_ROLLUP_CH_DATABASE:-default}}"
CLICKHOUSE_CLIENT="${CLICKHOUSE_CLIENT:-${TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT:-clickhouse-client}}"

CH=(
  "$CLICKHOUSE_CLIENT"
  --host "$CH_HOST"
  --port "$CH_PORT"
  --user "$CH_USER"
  --database "$CH_DATABASE"
)
if [[ -n "$CH_PASSWORD" ]]; then
  CH+=( --password "$CH_PASSWORD" )
fi

echo "Target ClickHouse: ${CH_HOST}:${CH_PORT}/${CH_DATABASE}"
echo "Seeding system local/private networks into default.net_l3_prefixes..."

"${CH[@]}" --query "
INSERT INTO default.net_l3_prefixes
    (prefix, family, entity_id, role, origin_asn, display_name, comment, enabled, source, updated_at)
VALUES
    ('10.0.0.0/8',      4, 'system:local-private', 'internal', 0, 'RFC1918 private 10/8',       'System local/private IPv4 prefix', 1, 'system', now()),
    ('172.16.0.0/12',   4, 'system:local-private', 'internal', 0, 'RFC1918 private 172.16/12',  'System local/private IPv4 prefix', 1, 'system', now()),
    ('192.168.0.0/16',  4, 'system:local-private', 'internal', 0, 'RFC1918 private 192.168/16', 'System local/private IPv4 prefix', 1, 'system', now()),
    ('100.64.0.0/10',   4, 'system:local-private', 'internal', 0, 'RFC6598 CGNAT 100.64/10',    'System local/CGNAT IPv4 prefix',   1, 'system', now()),
    ('169.254.0.0/16',  4, 'system:local-private', 'internal', 0, 'IPv4 link-local 169.254/16', 'System link-local IPv4 prefix',    1, 'system', now()),
    ('127.0.0.0/8',     4, 'system:local-private', 'internal', 0, 'IPv4 loopback 127/8',        'System loopback IPv4 prefix',      1, 'system', now()),
    ('fc00::/7',        6, 'system:local-private', 'internal', 0, 'IPv6 ULA fc00::/7',          'System local/private IPv6 prefix', 1, 'system', now()),
    ('fe80::/10',       6, 'system:local-private', 'internal', 0, 'IPv6 link-local fe80::/10',  'System link-local IPv6 prefix',    1, 'system', now()),
    ('::1/128',         6, 'system:local-private', 'internal', 0, 'IPv6 loopback ::1/128',      'System loopback IPv6 prefix',      1, 'system', now())
"

echo
echo "Enabled system local/private prefixes:"
"${CH[@]}" --query "
SELECT prefix, family, role, display_name, source
FROM default.net_l3_prefixes_enabled
WHERE source = 'system'
ORDER BY family, prefix
FORMAT PrettyCompact
"

echo
echo "Done. xdpflowd refreshes classifier data periodically; restart it if you need immediate effect."
