-- Editable list of local/customer operators.
--
-- Operators group prefixes, ASNs and customer VLANs under one stable id used by
-- dashboards and xdpflowd traffic classification.

CREATE TABLE IF NOT EXISTS default.local_operators
(
    operator_id LowCardinality(String),
    name        String,
    source      LowCardinality(String),
    enabled     UInt8,
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY operator_id
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.local_operators_enabled;

CREATE VIEW default.local_operators_enabled AS
SELECT
    operator_id,
    name,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        operator_id,
        argMax(name, updated_at) AS name,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.local_operators
    GROUP BY operator_id
)
WHERE enabled_latest = 1;
