-- L3 prefix classification: provider_public | internal | customer_allocated | customer_transit.
--
-- Apply after net_entities.sql:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_l3_prefixes.sql

CREATE TABLE IF NOT EXISTS default.net_l3_prefixes
(
    prefix       String,
    family       UInt8,
    entity_id    LowCardinality(String) DEFAULT '',
    role         LowCardinality(String) DEFAULT 'remote',
    origin_asn   UInt32 DEFAULT 0,
    display_name String DEFAULT '',
    comment      String DEFAULT '',
    enabled      UInt8,
    source       LowCardinality(String) DEFAULT 'manual',
    updated_at   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_l3_prefixes_enabled;

CREATE VIEW default.net_l3_prefixes_enabled AS
SELECT
    prefix,
    family,
    entity_id,
    role,
    origin_asn,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        prefix,
        family,
        argMax(entity_id, updated_at) AS entity_id,
        argMax(role, updated_at) AS role,
        argMax(origin_asn, updated_at) AS origin_asn,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_l3_prefixes
    GROUP BY
        family,
        prefix
)
WHERE enabled_latest = 1;

-- Built-in local/private networks. These prefixes should never fall through to
-- remote/transit classification. Operators can override/disable a prefix by
-- inserting a newer row for the same (family, prefix).
INSERT INTO default.net_l3_prefixes
    (prefix, family, entity_id, role, origin_asn, display_name, comment, enabled, source, updated_at)
VALUES
    ('10.0.0.0/8',      4, 'system:local-private', 'internal', 0, 'RFC1918 private 10/8',       'System local/private IPv4 prefix', 1, 'system', now()),
    ('172.16.0.0/12',   4, 'system:local-private', 'internal', 0, 'RFC1918 private 172.16/12',  'System local/private IPv4 prefix', 1, 'system', now()),
    ('192.168.0.0/16',  4, 'system:local-private', 'internal', 0, 'RFC1918 private 192.168/16', 'System local/private IPv4 prefix', 1, 'system', now()),
    ('100.64.0.0/10',   4, 'system:local-private', 'internal', 0, 'RFC6598 CGNAT 100.64/10',    'System local/CGNAT IPv4 prefix',   1, 'system', now()),
    ('169.254.0.0/16',  4, 'system:local-private', 'internal', 0, 'IPv4 link-local 169.254/16', 'System link-local IPv4 prefix',    1, 'system', now()),
    ('127.0.0.0/8',     4, 'system:local-private', 'internal', 0, 'IPv4 loopback 127/8',        'System loopback IPv4 prefix',      1, 'system', now()),
    ('fc00::/7',        6, 'system:local-private', 'internal', 0, 'IPv6 ULA fc00::/7',          'System local/private IPv6 prefix', 1, 'system', now()),
    ('fe80::/10',       6, 'system:local-private', 'internal', 0, 'IPv6 link-local fe80::/10',  'System link-local IPv6 prefix',    1, 'system', now()),
    ('::1/128',         6, 'system:local-private', 'internal', 0, 'IPv6 loopback ::1/128',      'System loopback IPv6 prefix',      1, 'system', now());
