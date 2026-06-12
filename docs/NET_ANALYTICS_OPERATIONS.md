# Network Analytics Operations

Step-by-step deployment and verification for the new L3/L2 model.

## Prerequisites

- ClickHouse access (`clickhouse-client` or HTTP)
- `xdpflowd` running with ClickHouse ingest
- GrapesNTA repo updated on collector host

## Step 1. Disable Classifier

```bash
sudo sed -i 's/^XDP_CLASSIFIER=.*/XDP_CLASSIFIER=0/' /etc/xdpflowd/xdpflowd.env
sudo systemctl restart xdpflowd
sudo journalctl -u xdpflowd -n 30 --no-pager
```

Expected: xdpflowd healthy, no classifier refresh errors.

## Step 2. Cleanup Legacy Tables

```bash
clickhouse-client --host HOST --user USER --password PASS \
  --multiquery < deploy/clickhouse/cleanup_old_classification.sql
```

Verify:

```sql
SHOW TABLES FROM default LIKE 'local_%';
SHOW TABLES FROM default LIKE 'vlan_%';
SHOW TABLES FROM default LIKE 'traffic_%';
```

Expected: old `local_*`, `vlan_map*`, legacy traffic tables are gone.
`flows_raw` must still exist.

## Step 3. Apply New DDL

`traffic_*.sql` create aggregate **tables only** (no sync materialized views).
Rollups are filled by `scripts/traffic_rollup_async.py` on the collector.

```bash
for f in \
  deploy/clickhouse/flows_raw_extensions.sql \
  deploy/clickhouse/net_entities.sql \
  deploy/clickhouse/net_l3_prefixes.sql \
  deploy/clickhouse/net_l2_vlans.sql \
  deploy/clickhouse/traffic_direction_1m.sql \
  deploy/clickhouse/traffic_role_1m.sql \
  deploy/clickhouse/traffic_entity_1m.sql \
  deploy/clickhouse/traffic_vlan_1m.sql \
  deploy/clickhouse/traffic_protocol_1m.sql \
  deploy/clickhouse/traffic_dashboard_1m.sql \
  deploy/clickhouse/traffic_dashboard_1d.sql \
  deploy/clickhouse/traffic_talkers_1m.sql \
  deploy/clickhouse/traffic_talkers_1h.sql \
  deploy/clickhouse/net_reports.sql \
  deploy/clickhouse/traffic_rollup_state.sql \
  deploy/clickhouse/detach_traffic_mvs.sql
do
  clickhouse-client --host HOST --user USER --password PASS --multiquery < "$f"
done
```

Verify:

```sql
DESCRIBE TABLE default.flows_raw;
SELECT name FROM system.tables WHERE database='default' AND name LIKE 'net_%';
SELECT name FROM system.tables WHERE database='default' AND name LIKE 'traffic_%';
```

Expected columns in `flows_raw`: `src_role`, `dst_role`, `src_entity`, `dst_entity`.

## Step 4. Seed Test Configuration

```sql
INSERT INTO default.net_entities
(entity_id, display_name, comment, enabled, source, updated_at)
VALUES
('provider:core', 'Provider Core', 'test seed', 1, 'manual', now());

INSERT INTO default.net_l3_prefixes
(prefix, family, entity_id, role, origin_asn, display_name, comment, enabled, source, updated_at)
VALUES
('10.0.0.0/8', 4, 'provider:core', 'internal', 0, 'Provider RFC1918', 'test seed', 1, 'manual', now());

INSERT INTO default.net_l2_vlans
(vlan_id, entity_id, attachment_type, boundary, display_name, comment, enabled, source, updated_at)
VALUES
(100, 'provider:core', 'core', 'internal', 'Core VLAN 100', 'test seed', 1, 'manual', now());
```

## Step 5. Deploy xdpflowd Binary

On build host:

```bash
cd /opt/GrapesNTA
go build -o bin/xdpflowd ./cmd/xdpflowd
```

Copy binary to collector if needed, then enable classifier:

```bash
sudo sed -i 's/^XDP_CLASSIFIER=.*/XDP_CLASSIFIER=1/' /etc/xdpflowd/xdpflowd.env
sudo sed -i 's|^XDP_CLASSIFIER_L3_PREFIXES_VIEW=.*|XDP_CLASSIFIER_L3_PREFIXES_VIEW=default.net_l3_prefixes_enabled|' /etc/xdpflowd/xdpflowd.env
sudo sed -i 's|^XDP_CLASSIFIER_L2_VLANS_VIEW=.*|XDP_CLASSIFIER_L2_VLANS_VIEW=default.net_l2_vlans_enabled|' /etc/xdpflowd/xdpflowd.env
sudo systemctl restart xdpflowd
sudo journalctl -u xdpflowd -n 50 --no-pager | rg 'traffic classifier'
```

Expected log:

```text
traffic classifier refreshed bgp_prefixes=... ip_asn_prefixes=... l3_prefixes=... vlans=...
```

Verify new fields:

```sql
SELECT
  toString(time_received_ns) AS ts,
  direction,
  src_role,
  dst_role,
  src_entity,
  dst_entity
FROM default.flows_raw
WHERE time_received_ns > now() - INTERVAL 5 MINUTE
  AND (src_role != '' OR dst_role != '')
ORDER BY time_received_ns DESC
LIMIT 20;
```

## Step 5b. L3 origin ASN (local prefixes)

Existing deployments need the `origin_asn` column on `net_l3_prefixes`:

```bash
clickhouse-client --host HOST --user USER --password PASS \
  --multiquery < deploy/clickhouse/migrate_net_l3_prefixes_origin_asn.sql
```

Set operator ASN on provider/customer prefixes that BMP does not export:

```sql
INSERT INTO default.net_l3_prefixes
(prefix, family, entity_id, role, origin_asn, display_name, comment, enabled, source, updated_at)
VALUES
('188.143.128.0/17', 4, 'isp:pin', 'provider_public', 34665, 'gb', '', 1, 'manual', now());
```

Replace `34665` with your real ASN. Rebuild `xdpflowd` and restart, or wait for
classifier refresh (`XDP_CLASSIFIER_REFRESH`).

Verify local outbound ASN on new rows only (old `flows_raw` rows stay `0`):

```sql
SELECT
    src_asn,
    src_role,
    count() AS flows,
    round(sum(bytes)/1e9, 1) AS gb
FROM default.flows_raw
WHERE time_received_ns >= now64(9) - INTERVAL 5 MINUTE
  AND source_id = 'netflow'
  AND direction = 'out'
GROUP BY src_asn, src_role
ORDER BY gb DESC;
```

Expected: `src_role = provider_public`, `src_asn = <your ASN>`.

## Step 6. Enable Async Rollups

**Only after** `xdpflowd` spool is caught up (`lag_segments ~ 0`).

```bash
sudo mkdir -p /etc/grapesnta /var/log/grapesnta
sudo cp deploy/systemd/traffic-rollups.env.example /etc/grapesnta/traffic-rollups.env
# edit TRAFFIC_ROLLUP_CH_HOST, TRAFFIC_ROLLUP_CH_PASSWORD, etc.

sudo cp deploy/systemd/traffic-rollups.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now traffic-rollups.timer
```

Dry-run first:

```bash
python3 scripts/traffic_rollup_async.py \
  --host HOST --port PORT --user USER --password PASS \
  --dry-run --verbose
```

See [`CLICKHOUSE_DB_SETUP_RUNBOOK.md`](CLICKHOUSE_DB_SETUP_RUNBOOK.md) §7 for
backfill skip, throttle, and monitoring.

Lightweight dashboard timer should **not** include heavy talker/pair jobs. Use the
separate top talkers timer:

```bash
sudo cp deploy/systemd/traffic-talkers-rollups.{service,timer} /etc/systemd/system/
sudo install -m 0600 deploy/systemd/traffic-talkers-rollups.env.example /etc/grapesnta/traffic-talkers-rollups.env
sudo systemctl daemon-reload
sudo systemctl enable --now traffic-talkers-rollups.timer
```

Catch-up once after deploy:

```bash
python3 scripts/traffic_rollup_async.py \
  --jobs traffic_talker_1m,traffic_talker_1h,traffic_pair_1m,traffic_pair_1h \
  --max-buckets-per-job 30
```

Verify top talkers lag and outbound source ASN:

```sql
SELECT
    max(minute) AS last_minute,
    dateDiff('minute', max(minute), now()) AS lag_min
FROM default.traffic_talker_1m;

SELECT
    endpoint_ip,
    endpoint_asn,
    endpoint_scope,
    round(sum(bytes)/1e9, 2) AS gb
FROM default.traffic_talker_1m AS t
INNER JOIN default.net_flow_sources_enabled AS s ON t.source_id = s.source_id
WHERE s.include_in_total = 1
  AND t.minute >= now() - INTERVAL 1 HOUR
  AND t.direction = 'out'
  AND t.endpoint_side = 'src'
GROUP BY endpoint_ip, endpoint_asn, endpoint_scope
ORDER BY gb DESC
LIMIT 10;
```

## Step 7. Verify Aggregates

Wait 5–10 minutes after rollups timer is active (safety lag 5 min + timer), then:

If remote ASN coverage is poor, apply and refresh the optional fallback IP→ASN
table before restarting `xdpflowd`:

```bash
clickhouse-client --host HOST --user USER --password PASS --multiquery \
  < deploy/clickhouse/ip_asn_prefixes.sql

sudo mkdir -p /etc/iptoasn-loader
sudo cp deploy/systemd/iptoasn-loader.env.example /etc/iptoasn-loader/iptoasn-loader.env
sudo chmod 0600 /etc/iptoasn-loader/iptoasn-loader.env
# edit /etc/iptoasn-loader/iptoasn-loader.env or inherit GEOLOADERD_CH_*.

sudo cp deploy/systemd/iptoasn-loader.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start iptoasn-loader.service
sudo systemctl enable --now iptoasn-loader.timer

clickhouse-client --host HOST --user USER --password PASS --query "
SELECT count() AS prefixes, uniq(origin_asn) AS asns, max(snapshot_ts) AS snapshot
FROM default.ip_asn_prefixes_current
FORMAT PrettyCompact"

sudo grep -q '^XDP_CLASSIFIER_IP_ASN_TABLE=' /etc/xdpflowd/xdpflowd.env || \
  echo 'XDP_CLASSIFIER_IP_ASN_TABLE=default.ip_asn_prefixes_current' | sudo tee -a /etc/xdpflowd/xdpflowd.env
sudo systemctl restart xdpflowd
```

Do not set `XDP_CLASSIFIER_IP_ASN_TABLE` before the table is created and loaded.
Without this env var the classifier keeps the older behavior: L3 origin ASN,
then BMP/BGP, then ASN `0`.

Run the read-only data quality health-check:

```bash
cd /opt/GrapesNTA
set -a
source /etc/grapesnta/traffic-rollups.env
source /etc/grapesnta/traffic-talkers-rollups.env 2>/dev/null || true
set +a

python3 scripts/check_traffic_data_quality.py \
  --source-id netflow \
  --local-asn 34665 \
  --max-rollup-lag-minutes 45
```

Interpretation:

- `OK` - the checked invariant is healthy.
- `WARN` - usable but incomplete:
  - Small `remote_asn_zero_gb` - expected when BGP/BMP/fallback IP→ASN
    coverage is partial. Large amounts are `FAIL` by default; refresh
    `default.ip_asn_prefixes_current` with `scripts/load_iptoasn_prefixes.py`.
  - `as_country_unknown_for_known_asn_gb` - ASN is known but `asn_registry_enriched.cc`
    has no country; fill the registry to clear it.
  - `ip_country_unknown_gb` / `country_rollup.unknown_country` - `??` IP country;
    small amounts are normal (private/bogon ranges), large amounts mean the geo
    dict is stale or missing.
- `FAIL` - fix before trusting the dashboard. Examples:
  - `direction_rollup.unknown_direction` or `*_quality.* unknown_direction` -
    classifier did not set a direction.
  - `*_quality.* unknown_scope` - classifier did not set endpoint scope.
  - `local_asn_zero_gb`, large `remote_asn_zero_gb`, empty IP fields,
    excessive lag, raw/aggregate mismatch.
  - `sources.<table>.<source_id> excluded source present` - a source with
    `include_in_total=0` is polluting the rollups (e.g. a second collector or a
    stale `source_id` label). Stop its writer and purge those rows. This is a
    `FAIL` by default; pass `--allow-excluded-sources` to downgrade to `WARN`
    if you intentionally keep an excluded source.

Useful thresholds (defaults shown): `--max-unknown-direction-gb 0.1`,
`--max-unknown-scope-gb 0.1`, `--max-remote-asn-zero-gb 10.0`,
`--max-ip-country-unknown-gb 5.0`,
`--max-as-country-unknown-gb 5.0`, `--max-country-unknown-pct 5.0`.

```sql
SELECT direction, sum(bytes) AS bytes
FROM default.traffic_direction_1m
WHERE minute >= now() - INTERVAL 10 MINUTE
GROUP BY direction
ORDER BY direction;

SELECT max(minute) AS latest_minute
FROM default.traffic_dashboard_1m;

SELECT job, last_bucket, status
FROM default.traffic_rollup_state FINAL
WHERE job IN ('traffic_dashboard_1m', 'traffic_direction_1m')
ORDER BY job;
```

Cross-check:

```sql
SELECT direction, sum(bytes) AS bytes
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 10 MINUTE
GROUP BY direction;
```

Totals should match within async rollup lag (~5–10 minutes).

## Step 8. UI (Laravel + MoonShine)

MoonShine app lives in a separate repository. Configure ClickHouse
access in MoonShine `.env` and add resources/dashboards for:

- `net_entities`
- `net_l3_prefixes`
- `net_l2_vlans`
- `traffic_dashboard_1m` (pivot)
- `traffic_entity_1m`, `traffic_role_1m`, `traffic_vlan_1m`
- `net_reports`

CRUD inserts new rows into ReplacingMergeTree base tables with
`updated_at = now()`; disable via `enabled = 0`. Read from the
`*_enabled` views.

Smoke test from CLI (no UI required):

```bash
clickhouse-client --host HOST --user USER --password PASS \
  --query "SELECT direction, sum(bytes) FROM default.traffic_dashboard_1m
           WHERE minute >= now() - INTERVAL 5 MINUTE
           GROUP BY direction"
```

## Step 9. Async Reports

Reports are stored in `default.net_reports`. Queue, run, and read
results from the MoonShine app or via direct INSERT/SELECT:

```sql
INSERT INTO default.net_reports
(id, type, filters_json, period_from, period_to, status, created_by, updated_at)
VALUES (generateUUIDv4(), 'top_bytes', '{"dimension":"entity","limit":20}',
        toDateTime('2026-05-01 00:00:00'),
        toDateTime('2026-05-25 00:00:00'),
        'queued', 'admin', now());

SELECT id, status, toString(updated_at) FROM default.net_reports
ORDER BY updated_at DESC LIMIT 10;
```

A worker (Laravel scheduler or systemd timer) picks `status='queued'`,
runs the underlying query, writes `result_json`, sets
`status='completed'`/`'failed'`, and updates `updated_at`.

## Rollback

If classifier breaks ingest:

```bash
sudo sed -i 's/^XDP_CLASSIFIER=.*/XDP_CLASSIFIER=0/' /etc/xdpflowd/xdpflowd.env
sudo systemctl restart xdpflowd
```

`flows_raw` ingest continues without role/direction enrichment.

## Monitoring Checklist

- `xdpflowd`: `traffic classifier refreshed` every ~60s; `lag_segments` ≈ 0
- `traffic-rollups.service`: `run complete` every minute, no `failed`
- `traffic-talkers-rollups.service`: `run complete` every 5 minutes, no `failed`
- `traffic_rollup_state FINAL`: `last_bucket` advances for 1m jobs
- `traffic_dashboard_1m`: `max(minute)` within ~10 minutes of now
- `traffic_talker_1m`: `max(minute)` within ~10 minutes of now
- No attached `traffic_*` MV in `system.tables`
- `bgp_prefix_origin_current`: refreshed by `bgp-origin-refresh` timer
- `ip_asn_prefixes_current`: loaded when remote ASN coverage needs fallback
- `net_l3_prefixes.origin_asn`: set for provider/customer prefixes used in top talkers
- Outbound `flows_raw.src_asn` non-zero on new rows after L3 ASN seed
- API `/api/network/dashboard`: response < 1s for 1-hour window
