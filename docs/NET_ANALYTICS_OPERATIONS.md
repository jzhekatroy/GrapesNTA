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

## Step 7. Configure Next.js API

Add to app environment:

```env
CLICKHOUSE_URL=http://HOST:8123
CLICKHOUSE_USER=USER
CLICKHOUSE_PASSWORD=PASS
CLICKHOUSE_DATABASE=default
```

Smoke test (SUPER_ADMIN token):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://APP/api/network/dashboard?from=2026-05-25T00:00:00Z&to=2026-05-25T01:00:00Z"
```

## Step 8. Async Reports

Create report:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"type":"top_bytes","from":"2026-05-01T00:00:00Z","to":"2026-05-25T00:00:00Z","filters":{"dimension":"entity","limit":20}}' \
  https://APP/api/network/reports
```

Process queue (cron or manual):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://APP/api/network/reports/tick
```

Fetch result:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://APP/api/network/reports/REPORT_ID/result
```

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
