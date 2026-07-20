CREATE VIEW IF NOT EXISTS default.port_services_enabled
(
    `transport` LowCardinality(String),
    `port_from` UInt16,
    `port_to` UInt16,
    `port_label` String,
    `port` UInt16,
    `service_code` String,
    `service_name` String,
    `category` String,
    `description` String,
    `updated_at` DateTime
)
AS SELECT
    transport,
    port_from,
    port_to,
    if(port_from = port_to, toString(port_from), concat(toString(port_from), '-', toString(port_to))) AS port_label,
    if(port_from = port_to, port_from, toUInt16(0)) AS port,
    service_code,
    service_name,
    category,
    description,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        transport,
        port_from,
        port_to,
        argMax(service_code, updated_at) AS service_code,
        argMax(service_name, updated_at) AS service_name,
        argMax(category, updated_at) AS category,
        argMax(description, updated_at) AS description,
        argMax(is_enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.port_services
    GROUP BY
        transport,
        port_from,
        port_to
)
WHERE (enabled_latest = 1) AND (port_from <= port_to);
