CREATE VIEW IF NOT EXISTS default.net_client_prefixes_enabled
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
