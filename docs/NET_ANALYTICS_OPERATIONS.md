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
  deploy/clickhouse/traffic_dashboard_1m.sql \
  deploy/clickhouse/net_reports.sql
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
(prefix, family, entity_id, role, display_name, comment, enabled, source, updated_at)
VALUES
('10.0.0.0/8', 4, 'provider:core', 'internal', 'Provider RFC1918', 'test seed', 1, 'manual', now());

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
traffic classifier refreshed bgp_prefixes=... l3_prefixes=... vlans=...
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

## Step 6. Verify Aggregates

Wait 2–3 minutes after classifier is enabled, then:

```sql
SELECT direction, sum(bytes) AS bytes
FROM default.traffic_direction_1m
WHERE minute >= now() - INTERVAL 5 MINUTE
GROUP BY direction
ORDER BY direction;

SELECT max(minute) AS latest_minute
FROM default.traffic_dashboard_1m;
```

Cross-check:

```sql
SELECT direction, sum(bytes) AS bytes
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
GROUP BY direction;
```

Totals should match within normal MV lag (1–2 minutes).

## Step 7. UI (Laravel + MoonShine)

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

## Step 8. Async Reports

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

- `xdpflowd`: `traffic classifier refreshed` every ~60s
- `traffic_dashboard_1m`: `max(minute)` within 2 minutes of now
- `bgp_prefix_origin_current`: refreshed by `bgp-origin-refresh` timer
- API `/api/network/dashboard`: response < 1s for 1-hour window
