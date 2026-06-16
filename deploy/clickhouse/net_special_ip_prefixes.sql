-- Special-use IP prefix catalog for data-quality interpretation.
--
-- Unlike net_l3_prefixes (direction/classification), this table does NOT drive
-- in/out/transit. It records blocks where missing ASN or country is expected:
-- private, multicast, reserved, documentation, benchmark, etc.
--
-- Apply after net_l3_prefixes.sql:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_special_ip_prefixes.sql
--
-- Operators can override/disable a prefix by inserting a newer row for the same
-- (family, prefix) with enabled=0 or different flags.

CREATE TABLE IF NOT EXISTS default.net_special_ip_prefixes
(
    prefix            String,
    family            UInt8,
    kind              LowCardinality(String),
    asn_expected      UInt8,
    country_expected  UInt8,
    publicly_routable UInt8,
    display_name      String DEFAULT '',
    comment           String DEFAULT '',
    enabled           UInt8,
    source            LowCardinality(String) DEFAULT 'system',
    updated_at        DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

-- Older ClickHouse versions drop ordinary views via DROP TABLE, not DROP VIEW.
DROP TABLE IF EXISTS default.net_special_ip_prefixes_enabled;

CREATE VIEW default.net_special_ip_prefixes_enabled AS
SELECT
    prefix,
    family,
    kind,
    asn_expected,
    country_expected,
    publicly_routable,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        prefix,
        family,
        argMax(kind, updated_at) AS kind,
        argMax(asn_expected, updated_at) AS asn_expected,
        argMax(country_expected, updated_at) AS country_expected,
        argMax(publicly_routable, updated_at) AS publicly_routable,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM
    (
        -- Manual/operator rows. Insert a newer row for the same (family, prefix)
        -- to override or disable one of the built-in rows below.
        SELECT
            prefix,
            family,
            kind,
            asn_expected,
            country_expected,
            publicly_routable,
            display_name,
            comment,
            enabled,
            source,
            updated_at
        FROM default.net_special_ip_prefixes

        -- Built-in rows are embedded in the view (not INSERTed) because some
        -- deployments use a very old clickhouse-client against a newer server
        -- and cannot reliably execute INSERT over the native protocol.
        UNION ALL SELECT '10.0.0.0/8', toUInt8(4), 'private', toUInt8(0), toUInt8(0), toUInt8(0), 'RFC1918 private 10/8', 'Private IPv4; no public ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '172.16.0.0/12', toUInt8(4), 'private', toUInt8(0), toUInt8(0), toUInt8(0), 'RFC1918 private 172.16/12', 'Private IPv4; no public ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '192.168.0.0/16', toUInt8(4), 'private', toUInt8(0), toUInt8(0), toUInt8(0), 'RFC1918 private 192.168/16', 'Private IPv4; no public ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '100.64.0.0/10', toUInt8(4), 'private', toUInt8(0), toUInt8(0), toUInt8(0), 'RFC6598 CGNAT 100.64/10', 'Carrier-grade NAT; no public geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT 'fc00::/7', toUInt8(6), 'private', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv6 ULA fc00::/7', 'Unique local IPv6; no public geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')

        UNION ALL SELECT '169.254.0.0/16', toUInt8(4), 'link_local', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv4 link-local 169.254/16', 'Link-local; no ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '127.0.0.0/8', toUInt8(4), 'loopback', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv4 loopback 127/8', 'Loopback; no ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '0.0.0.0/8', toUInt8(4), 'unspecified', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv4 this-network 0/8', 'Unspecified; no ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT 'fe80::/10', toUInt8(6), 'link_local', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv6 link-local fe80::/10', 'Link-local; no ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '::1/128', toUInt8(6), 'loopback', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv6 loopback ::1/128', 'Loopback; no ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '::/128', toUInt8(6), 'unspecified', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv6 unspecified ::/128', 'Unspecified; no ASN/geo', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')

        UNION ALL SELECT '224.0.0.0/4', toUInt8(4), 'multicast', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv4 multicast 224/4', 'Multicast; no origin ASN or country', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '240.0.0.0/4', toUInt8(4), 'reserved', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv4 reserved 240/4', 'Reserved/broadcast; no ASN/country', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT 'ff00::/8', toUInt8(6), 'multicast', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv6 multicast ff00::/8', 'Multicast; no origin ASN or country', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')

        UNION ALL SELECT '192.0.2.0/24', toUInt8(4), 'documentation', toUInt8(0), toUInt8(0), toUInt8(0), 'TEST-NET-1 192.0.2/24', 'Documentation block', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '198.51.100.0/24', toUInt8(4), 'documentation', toUInt8(0), toUInt8(0), toUInt8(0), 'TEST-NET-2 198.51.100/24', 'Documentation block', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '203.0.113.0/24', toUInt8(4), 'documentation', toUInt8(0), toUInt8(0), toUInt8(0), 'TEST-NET-3 203.0.113/24', 'Documentation block', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '198.18.0.0/15', toUInt8(4), 'benchmark', toUInt8(0), toUInt8(0), toUInt8(0), 'Benchmark 198.18/15', 'Benchmarking block', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
        UNION ALL SELECT '2001:db8::/32', toUInt8(6), 'documentation', toUInt8(0), toUInt8(0), toUInt8(0), 'IPv6 documentation', 'Documentation block', toUInt8(1), 'system', toDateTime('1970-01-01 00:00:00')
    )
    GROUP BY
        family,
        prefix
)
WHERE enabled_latest = 1;

-- kind values:
--   private, link_local, loopback, unspecified, multicast, reserved,
--   documentation, benchmark
--
-- asn_expected / country_expected: 1 = lookup expected, 0 = missing value is OK
-- publicly_routable: 0 = special-use, 1 = normal global unicast (none seeded here)

-- Built-in rows live in the view. The table is intentionally empty until
-- operators add manual overrides.
