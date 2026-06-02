-- Minute-level traffic by country for heatmaps and top-country tables.
--
-- Each flow contributes four logical rows:
--   ip + src, ip + dst, asn + src, asn + dst
--
-- IP country uses default.geo_country_dict (prefix allocation country).
-- ASN country uses default.asn_registry_enriched.cc (registry country).
-- Empty or missing lookups are stored as ??.

DROP TABLE IF EXISTS default.traffic_country_1m_mv;
DROP TABLE IF EXISTS default.traffic_country_1m;

CREATE TABLE default.traffic_country_1m
(
    minute        DateTime('UTC'),
    source_id     LowCardinality(String),
    country_basis LowCardinality(String), -- ip / asn
    country_side  LowCardinality(String), -- src / dst
    direction     LowCardinality(String),
    country_code  LowCardinality(String),
    bytes         UInt64,
    packets       UInt64,
    flows_count   UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, country_basis, country_side, direction, country_code)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW default.traffic_country_1m_mv
TO default.traffic_country_1m
AS
SELECT
    minute,
    source_id,
    country_basis,
    country_side,
    direction,
    if(length(trimBoth(country_raw)) = 0, '??', trimBoth(country_raw)) AS country_code,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM
(
    SELECT
        toStartOfMinute(f.time_received_ns) AS minute,
        f.source_id,
        f.direction,
        f.bytes,
        f.packets,
        row.1 AS country_basis,
        row.2 AS country_side,
        row.3 AS country_raw
    FROM default.flows_raw AS f
    LEFT JOIN default.asn_registry_enriched AS src_as ON src_as.asn = f.src_asn
    LEFT JOIN default.asn_registry_enriched AS dst_as ON dst_as.asn = f.dst_asn
    ARRAY JOIN arrayZip(
        ['ip', 'ip', 'asn', 'asn'],
        ['src', 'dst', 'src', 'dst'],
        [
            if(
                f.etype = 2048,
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4)))))
                ),
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv6(IPv6NumToString(f.src_addr)))
                )
            ),
            if(
                f.etype = 2048,
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv4(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4)))))
                ),
                dictGetString(
                    'default.geo_country_dict',
                    'cc',
                    tuple(toIPv6(IPv6NumToString(f.dst_addr)))
                )
            ),
            if(f.src_asn = 0, '', toString(src_as.cc)),
            if(f.dst_asn = 0, '', toString(dst_as.cc))
        ]
    ) AS row
) AS expanded
GROUP BY
    minute,
    source_id,
    country_basis,
    country_side,
    direction,
    country_code;
