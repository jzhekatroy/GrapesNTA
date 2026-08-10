-- Create customer-client catalog (cabinet clients).
-- Independent from net_entities. Safe to re-run.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_net_clients.sql

CREATE TABLE IF NOT EXISTS default.net_clients
(
    `client_id` LowCardinality(String),
    `display_name` String,
    `comment` String DEFAULT '',
    `bind_mode` LowCardinality(String) DEFAULT 'prefixes',
    `enabled` UInt8,
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY client_id
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.net_clients_enabled;
CREATE VIEW default.net_clients_enabled
(
    `client_id` LowCardinality(String),
    `display_name` String,
    `comment` String,
    `bind_mode` LowCardinality(String),
    `updated_at` DateTime
)
AS SELECT
    client_id,
    display_name,
    comment,
    bind_mode,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        client_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(bind_mode, updated_at) AS bind_mode,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_clients
    GROUP BY client_id
)
WHERE enabled_latest = 1;

CREATE TABLE IF NOT EXISTS default.net_client_prefixes
(
    `client_id` LowCardinality(String),
    `prefix` String,
    `family` UInt8,
    `enabled` UInt8,
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.net_client_prefixes_enabled;
CREATE VIEW default.net_client_prefixes_enabled
(
    `client_id` LowCardinality(String),
    `prefix` String,
    `family` UInt8,
    `updated_at` DateTime
)
AS SELECT
    client_id,
    prefix,
    family,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        family,
        prefix,
        argMax(client_id, updated_at) AS client_id,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_client_prefixes
    GROUP BY family, prefix
)
WHERE enabled_latest = 1
  AND client_id IN (SELECT client_id FROM default.net_clients_enabled WHERE bind_mode = 'prefixes');

CREATE TABLE IF NOT EXISTS default.net_client_ports
(
    `client_id` LowCardinality(String),
    `switch_ip` String,
    `if_index` UInt32,
    `comment` String DEFAULT '',
    `enabled` UInt8,
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (switch_ip, if_index)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.net_client_ports_enabled;
CREATE VIEW default.net_client_ports_enabled
(
    `client_id` LowCardinality(String),
    `switch_ip` String,
    `if_index` UInt32,
    `comment` String,
    `updated_at` DateTime
)
AS SELECT
    client_id,
    switch_ip,
    if_index,
    comment,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        switch_ip,
        if_index,
        argMax(client_id, updated_at) AS client_id,
        argMax(comment, updated_at) AS comment,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_client_ports
    GROUP BY switch_ip, if_index
)
WHERE enabled_latest = 1
  AND client_id IN (SELECT client_id FROM default.net_clients_enabled WHERE bind_mode = 'ports');
