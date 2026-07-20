CREATE VIEW IF NOT EXISTS default.port_services_expanded_enabled
(
    `transport` LowCardinality(String),
    `port` UInt16,
    `port_from` UInt16,
    `port_to` UInt16,
    `port_label` String,
    `service_code` String,
    `service_name` String,
    `category` String,
    `description` String,
    `updated_at` DateTime
)
AS SELECT
    transport,
    toUInt16(arrayJoin(range(toUInt32(port_from), toUInt32(port_to) + 1))) AS port,
    port_from,
    port_to,
    port_label,
    service_code,
    service_name,
    category,
    description,
    updated_at
FROM default.port_services_enabled;
