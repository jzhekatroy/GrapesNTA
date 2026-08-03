-- Flow exclusion rules: traffic matched by an enabled rule is dropped by the
-- collectors before it reaches ClickHouse or the NetFlow v9 export.
--
-- Apply on an existing installation:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_flow_exclusions.sql
--
-- Rules take effect within one classifier refresh (~60 s) and only affect
-- traffic observed after that: already stored rows and rollups are untouched.

CREATE TABLE IF NOT EXISTS default.net_flow_exclusions
(
    rule_id      String,
    prefix       String DEFAULT '',
    family       UInt8 DEFAULT 0,
    match_side   LowCardinality(String) DEFAULT 'any',
    proto        UInt8 DEFAULT 0,
    port_from    UInt16 DEFAULT 0,
    port_to      UInt16 DEFAULT 0,
    port_side    LowCardinality(String) DEFAULT 'any',
    vlan_id      UInt16 DEFAULT 0,
    switch_ip    String DEFAULT '',
    if_index     UInt32 DEFAULT 0,
    source_id    LowCardinality(String) DEFAULT '',
    display_name String DEFAULT '',
    comment      String DEFAULT '',
    enabled      UInt8,
    source       LowCardinality(String) DEFAULT 'manual',
    updated_at   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY rule_id
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_flow_exclusions_enabled;

CREATE VIEW default.net_flow_exclusions_enabled AS
SELECT
    rule_id,
    prefix,
    family,
    match_side,
    proto,
    port_from,
    port_to,
    port_side,
    vlan_id,
    switch_ip,
    if_index,
    source_id,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        rule_id,
        argMax(prefix, updated_at) AS prefix,
        argMax(family, updated_at) AS family,
        argMax(match_side, updated_at) AS match_side,
        argMax(proto, updated_at) AS proto,
        argMax(port_from, updated_at) AS port_from,
        argMax(port_to, updated_at) AS port_to,
        argMax(port_side, updated_at) AS port_side,
        argMax(vlan_id, updated_at) AS vlan_id,
        argMax(switch_ip, updated_at) AS switch_ip,
        argMax(if_index, updated_at) AS if_index,
        argMax(source_id, updated_at) AS source_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_flow_exclusions
    GROUP BY rule_id
)
WHERE enabled_latest = 1;

-- Excluded volume must be reported, otherwise the XDP-vs-ClickHouse
-- completeness check reads the dropped traffic as ingest loss.
ALTER TABLE default.collector_health_snapshots
    ADD COLUMN IF NOT EXISTS flow_rows_excluded UInt64 DEFAULT 0;
ALTER TABLE default.collector_health_snapshots
    ADD COLUMN IF NOT EXISTS flow_packets_excluded UInt64 DEFAULT 0;
ALTER TABLE default.collector_health_snapshots
    ADD COLUMN IF NOT EXISTS flow_bytes_excluded UInt64 DEFAULT 0;
ALTER TABLE default.collector_health_snapshots
    ADD COLUMN IF NOT EXISTS exclusion_rules UInt32 DEFAULT 0;
