# Plan: Flow Sources / Observation Points

Goal: make every flow/DNS row traceable to a concrete observation point, so the
UI can filter by data source and avoid double-counting when multiple collectors
or external flow sources are enabled.

This is an implementation plan for another agent. Do the steps one by one and
verify after each step.

## Terms

`source_id` means the logical traffic observation point, not just a process name.

Examples:

```text
xdp-core-mirror-1
xdp-border-mirror-1
netflow-border-r1
sflow-core-sw1
```

`collector` means the service/host that writes rows:

```text
xdpflowd on host-a
dnsflowd on host-a
flowcollectd on host-b
```

For analytics, `source_id` is the important field. Collector details belong in a
dictionary/config table.

## Target Model

Add exactly one source field to high-volume tables:

```text
source_id LowCardinality(String)
```

Keep metadata in a separate table:

```text
net_flow_sources
```

Do not add `source_type`, `collector_id`, `location`, etc. directly to
`flows_raw`, `dns_log`, `dns_answers`, or aggregates unless there is a strong
reason later. Those values repeat on every row and should be read from the
source dictionary.

## ClickHouse DDL

Create a new file:

```text
deploy/clickhouse/net_flow_sources.sql
```

Recommended table:

```sql
CREATE TABLE IF NOT EXISTS default.net_flow_sources
(
    source_id          String,
    display_name       String,
    source_type        LowCardinality(String),
    collector_id       String,
    location           String,
    description        String,
    include_in_total   UInt8 DEFAULT 1,
    enabled            UInt8 DEFAULT 1,
    updated_at         DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY source_id;

CREATE OR REPLACE VIEW default.net_flow_sources_enabled AS
SELECT
    source_id,
    display_name,
    source_type,
    collector_id,
    location,
    description,
    include_in_total,
    updated_at
FROM default.net_flow_sources
WHERE enabled = 1;
```

Allowed `source_type` values for UI/API validation:

```text
xdp
dns
netflow
ipfix
sflow
manual
```

Initial rows:

```sql
INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location, description, include_in_total, enabled)
VALUES
    ('xdp-default', 'Default XDP mirror', 'xdp', '', '', 'Initial xdpflowd source', 1, 1),
    ('dns-default', 'Default DNS mirror', 'dns', '', '', 'Initial dnsflowd source', 0, 1);
```

`dns-default` should usually not participate in total traffic, because DNS rows
are not traffic volume rows for the main flow dashboard.

## Step 1. Add `source_id` To Raw Tables

Add nullable-safe defaults so deployment does not require immediate service
restart:

```sql
ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS source_id LowCardinality(String) DEFAULT 'xdp-default';

ALTER TABLE default.dns_log
    ADD COLUMN IF NOT EXISTS source_id LowCardinality(String) DEFAULT 'dns-default';

ALTER TABLE default.dns_answers
    ADD COLUMN IF NOT EXISTS source_id LowCardinality(String) DEFAULT 'dns-default';
```

Acceptance:

- new rows can be inserted without changing services yet;
- old queries keep working;
- `SELECT source_id, count() ... GROUP BY source_id` returns default values.

## Step 2. Update `xdpflowd`

Add a configured source ID to `xdpflowd`.

Suggested CLI flag:

```text
-source-id xdp-default
```

Implementation points:

- Add `SourceID string` to `FlowRow`.
- Add `sourceID string` to `flowRowMapper`.
- Extend `newFlowRowMapper(...)` to receive the configured source ID.
- In `flowRowFromKV`, set `SourceID: m.sourceID`.
- Update `clickhouse_sink.go` INSERT column list and `batch.Append(...)` order.
- Keep default value `xdp-default` for backward compatibility.
- Log the source ID on startup.

Do not derive `source_id` from hostname automatically as the primary value.
Hostname may be useful for `collector_id`, but `source_id` must represent the
traffic observation point and should be configured explicitly.

Acceptance:

```sql
SELECT source_id, count()
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
GROUP BY source_id;
```

Expected: rows from `xdpflowd` have the configured `source_id`.

## Step 3. Update `dnsflowd`

Add a configured source ID to `dnsflowd`.

Suggested CLI/env setting:

```text
-source-id dns-default
DNS_SOURCE_ID=dns-default
```

Implementation points:

- Add `SourceID string` to `DNSRow`.
- Add `SourceID string` to `DNSAnswerRow`.
- Add source ID to sink config.
- Update raw DNS insert:
  - include `source_id` in the INSERT column list;
  - append `r.SourceID`.
- Update answers insert:
  - include `source_id` in the INSERT column list;
  - append `r.SourceID`.
- Log the source ID together with sink startup settings.

Use a separate DNS source ID even if `dnsflowd` runs on the same mirror as
`xdpflowd`. DNS rows are a different dataset from flow rows.

Acceptance:

```sql
SELECT source_id, count()
FROM default.dns_log
WHERE ts >= now() - INTERVAL 5 MINUTE
GROUP BY source_id;

SELECT source_id, count()
FROM default.dns_answers
WHERE ts >= now() - INTERVAL 5 MINUTE
GROUP BY source_id;
```

Expected: rows from `dnsflowd` have the configured `source_id`.

## Step 4. Add `source_id` To Dashboard Aggregates

Current `traffic_dashboard_1m` and `traffic_dashboard_1h` are global aggregates
without source dimension. For multiple collectors, they need to be grouped by
`source_id`.

Because old data is not important for this project stage, prefer rebuilding the
dashboard aggregates instead of layering compatibility hacks.

Update `deploy/clickhouse/traffic_dashboard_1m.sql`:

- add `source_id LowCardinality(String)` to `traffic_dashboard_1m`;
- change `ORDER BY minute` to `ORDER BY (minute, source_id)`;
- add `source_id` to the MV SELECT;
- add `source_id` to `GROUP BY minute, source_id`;
- do the same for `traffic_dashboard_1h` using `(hour, source_id)`.

Example shape:

```sql
CREATE TABLE IF NOT EXISTS default.traffic_dashboard_1m
(
    minute DateTime('UTC'),
    source_id LowCardinality(String),
    ...
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id);
```

Dashboard queries should filter sources using `net_flow_sources_enabled`:

```sql
WHERE source_id IN
(
    SELECT source_id
    FROM default.net_flow_sources_enabled
    WHERE include_in_total = 1
)
```

Acceptance:

- one row per minute per source;
- sums across included sources match expected total;
- UI can filter by one source or by all included sources.

## Step 5. Update Other Aggregates

Any aggregate used by UI must carry `source_id` if the UI may filter by source
or if totals must avoid double-counting.

Update these files after `traffic_dashboard_1m.sql`:

```text
traffic_direction_1m.sql
traffic_role_1m.sql
traffic_entity_1m.sql
traffic_vlan_1m.sql
traffic_protocol_1m.sql
traffic_service_1m.sql
traffic_unknown_port_1m.sql
traffic_country_1m.sql
future flow_summary_1m / rollups
```

Rule:

```text
Every aggregate key starts with time bucket + source_id.
```

Examples:

```text
minute, source_id, direction
minute, source_id, src_role, dst_role
minute, source_id, src_entity, dst_entity
minute, source_id, src_vlan, dst_vlan
minute, source_id, proto, direction
minute, source_id, service_code, service_port, direction
```

Acceptance:

- every dashboard/explorer aggregate can filter by `source_id`;
- default dashboard uses only `include_in_total = 1` sources.

## Step 6. UI/API Behavior

Add a UI settings section:

```text
Data Sources
```

Fields:

```text
source_id          required, unique, lowercase slug
display_name       required
source_type        xdp / dns / netflow / ipfix / sflow / manual
collector_id       optional
location           optional
description        optional
include_in_total   boolean
enabled            boolean
```

Dashboard behavior:

- default: use enabled sources where `include_in_total = 1`;
- allow source filter dropdown/multiselect;
- show warning if no source is included in total;
- show source name in drill-down/debug screens.

Important: do not blindly sum all sources. Future NetFlow/sFlow sources may
observe the same traffic as XDP mirrors and would double-count totals.

## Step 7. Operations / Config

Update systemd env examples:

```text
XDPFLOWD_SOURCE_ID=xdp-core-mirror-1
DNSFLOWD_SOURCE_ID=dns-core-mirror-1
```

Update service wrapper scripts to pass:

```text
-source-id "$XDPFLOWD_SOURCE_ID"
-source-id "$DNSFLOWD_SOURCE_ID"
```

Add operational checks:

```sql
-- Recent flow sources.
SELECT source_id, count(), formatReadableSize(sum(bytes)) AS traffic
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 10 MINUTE
GROUP BY source_id
ORDER BY traffic DESC;

-- Recent DNS sources.
SELECT source_id, count()
FROM default.dns_log
WHERE ts >= now() - INTERVAL 10 MINUTE
GROUP BY source_id
ORDER BY count() DESC;

-- Sources configured but not seen recently.
SELECT s.source_id, s.display_name, s.source_type
FROM default.net_flow_sources_enabled AS s
LEFT JOIN
(
    SELECT source_id, max(time_received_ns) AS last_seen
    FROM default.flows_raw
    WHERE time_received_ns >= now() - INTERVAL 1 HOUR
    GROUP BY source_id
) AS f USING source_id
WHERE s.source_type IN ('xdp', 'netflow', 'ipfix', 'sflow')
  AND f.last_seen IS NULL;
```

## Step 8. Migration Order

Recommended implementation order:

```text
1. Create net_flow_sources.sql and insert default xdp/dns sources.
2. ALTER flows_raw, dns_log, dns_answers with DEFAULT source_id.
3. Update xdpflowd to write source_id.
4. Deploy/restart xdpflowd and verify flows_raw.
5. Update dnsflowd to write source_id.
6. Deploy/restart dnsflowd and verify dns tables.
7. Rebuild traffic_dashboard_1m / 1h with source_id.
8. Update direction/role/entity/vlan/protocol/service aggregates with source_id.
9. Update UI/API queries to filter by source_id/include_in_total.
10. Document operations checks.
```

Stop after each step and verify before continuing.

## Non-Goals For This Step

- Do not implement NetFlow/IPFIX/sFlow ingestion yet.
- Do not build deduplication between sources yet.
- Do not add `collector_id` directly to raw flow rows.
- Daily dashboard aggregate is useful once dashboard periods exceed one day.

## Server Apply (implemented)

```bash
cd /opt/GrapesNTA
for f in deploy/clickhouse/net_flow_sources.sql \
         deploy/clickhouse/flows_raw_source_id.sql \
         deploy/clickhouse/apply_flow_sources.sql \
         deploy/clickhouse/traffic_direction_1m.sql \
         deploy/clickhouse/traffic_role_1m.sql \
         deploy/clickhouse/traffic_entity_1m.sql \
         deploy/clickhouse/traffic_vlan_1m.sql \
         deploy/clickhouse/port_services.sql \
         deploy/clickhouse/traffic_protocol_1m.sql \
         deploy/clickhouse/traffic_service_1m.sql \
         deploy/clickhouse/geo_country.sql \
         deploy/clickhouse/traffic_unknown_port_1m.sql \
         deploy/clickhouse/traffic_country_1m.sql \
         deploy/clickhouse/traffic_dashboard_1m.sql \
         deploy/clickhouse/traffic_dashboard_1d.sql; do
  clickhouse-client --multiquery < "$f"
done

make xdpflowd dnsflowd
sudo systemctl restart xdpflowd dnsflowd
```

Verify:

```sql
SELECT source_id, count()
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
GROUP BY source_id;

SELECT source_id, count()
FROM default.traffic_dashboard_1m
WHERE minute >= now() - INTERVAL 10 MINUTE
GROUP BY source_id;
```

Dashboard queries should filter by enabled sources with `include_in_total = 1`:

```sql
WHERE source_id IN (
    SELECT source_id FROM default.net_flow_sources_enabled WHERE include_in_total = 1
)
```

