-- Minute-level top-talkers aggregates for UI tables.
--
-- traffic_talker_1m:
--   one logical row per endpoint side (src and dst) per raw flow.
--   UI tabs:
--     Sources      -> endpoint_side = 'src'
--     Destinations -> endpoint_side = 'dst'
--
-- traffic_pair_1m:
--   one row per src -> dst pair per minute.
--   UI tab:
--     Pairs -> src endpoint + dst endpoint.

DROP TABLE IF EXISTS default.traffic_talker_1m_mv;
DROP TABLE IF EXISTS default.traffic_pair_1m_mv;
DROP TABLE IF EXISTS default.traffic_talker_1m;
DROP TABLE IF EXISTS default.traffic_pair_1m;

CREATE TABLE default.traffic_talker_1m
(
    minute                DateTime('UTC'),
    source_id             LowCardinality(String),
    endpoint_side         LowCardinality(String), -- src / dst
    direction             LowCardinality(String),
    endpoint_ip           String,
    endpoint_asn          UInt32,
    endpoint_as_name      String,
    endpoint_ip_country   LowCardinality(String),
    endpoint_as_country   LowCardinality(String),
    endpoint_scope        LowCardinality(String),
    endpoint_label        String,
    endpoint_network_name String,
    endpoint_network_role LowCardinality(String),
    bytes                 UInt64,
    packets               UInt64,
    flows_count           UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (
    minute,
    source_id,
    endpoint_side,
    direction,
    endpoint_ip,
    endpoint_asn,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_network_role
)
TTL minute + INTERVAL 2 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW default.traffic_talker_1m_mv
TO default.traffic_talker_1m
AS
SELECT
    minute,
    source_id,
    endpoint_side,
    direction,
    endpoint_ip,
    endpoint_asn,
    endpoint_as_name,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_label,
    endpoint_network_name,
    endpoint_network_role,
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
        tupleElement(row, 1) AS endpoint_side,
        tupleElement(row, 2) AS endpoint_ip,
        tupleElement(row, 3) AS endpoint_asn,
        tupleElement(row, 4) AS endpoint_as_name,
        if(length(trimBoth(tupleElement(row, 5))) = 0, '??', trimBoth(tupleElement(row, 5))) AS endpoint_ip_country,
        if(length(trimBoth(tupleElement(row, 6))) = 0, '??', trimBoth(tupleElement(row, 6))) AS endpoint_as_country,
        tupleElement(row, 7) AS endpoint_scope,
        tupleElement(row, 8) AS endpoint_label,
        tupleElement(row, 9) AS endpoint_network_name,
        tupleElement(row, 10) AS endpoint_network_role
    FROM default.flows_raw AS f
    LEFT JOIN default.asn_registry_enriched AS src_as ON src_as.asn = f.src_asn
    LEFT JOIN default.asn_registry_enriched AS dst_as ON dst_as.asn = f.dst_asn
    ARRAY JOIN arrayZip(
        ['src', 'dst'],
        [
            if(
                f.etype = 2048,
                toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4))))),
                IPv6NumToString(f.src_addr)
            ),
            if(
                f.etype = 2048,
                toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4))))),
                IPv6NumToString(f.dst_addr)
            )
        ],
        [f.src_asn, f.dst_asn],
        [
            multiIf(f.src_asn = 0, '', src_as.asn != 0 AND src_as.name != '', src_as.name, concat('AS', toString(f.src_asn))),
            multiIf(f.dst_asn = 0, '', dst_as.asn != 0 AND dst_as.name != '', dst_as.name, concat('AS', toString(f.dst_asn)))
        ],
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
            )
        ],
        [
            if(f.src_asn = 0 OR src_as.asn = 0, '', toString(src_as.cc)),
            if(f.dst_asn = 0 OR dst_as.asn = 0, '', toString(dst_as.cc))
        ],
        [f.src_endpoint_scope, f.dst_endpoint_scope],
        [f.src_label, f.dst_label],
        [f.src_network_name, f.dst_network_name],
        [f.src_network_role, f.dst_network_role]
    ) AS row
) AS expanded
GROUP BY
    minute,
    source_id,
    endpoint_side,
    direction,
    endpoint_ip,
    endpoint_asn,
    endpoint_as_name,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_label,
    endpoint_network_name,
    endpoint_network_role;

CREATE TABLE default.traffic_pair_1m
(
    minute          DateTime('UTC'),
    source_id       LowCardinality(String),
    direction       LowCardinality(String),
    src_ip          String,
    dst_ip          String,
    src_asn         UInt32,
    dst_asn         UInt32,
    src_as_name     String,
    dst_as_name     String,
    src_ip_country  LowCardinality(String),
    dst_ip_country  LowCardinality(String),
    src_as_country  LowCardinality(String),
    dst_as_country  LowCardinality(String),
    src_scope       LowCardinality(String),
    dst_scope       LowCardinality(String),
    src_label       String,
    dst_label       String,
    bytes           UInt64,
    packets         UInt64,
    flows_count     UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (
    minute,
    source_id,
    direction,
    src_ip,
    dst_ip,
    src_asn,
    dst_asn,
    src_ip_country,
    dst_ip_country
)
TTL minute + INTERVAL 2 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW default.traffic_pair_1m_mv
TO default.traffic_pair_1m
AS
WITH
    if(
        f.etype = 2048,
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.src_addr, 1, 4))))),
        IPv6NumToString(f.src_addr)
    ) AS src_ip,
    if(
        f.etype = 2048,
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(f.dst_addr, 1, 4))))),
        IPv6NumToString(f.dst_addr)
    ) AS dst_ip,
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
    ) AS src_ip_country_raw,
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
    ) AS dst_ip_country_raw
SELECT
    toStartOfMinute(f.time_received_ns) AS minute,
    f.source_id,
    f.direction,
    src_ip,
    dst_ip,
    f.src_asn,
    f.dst_asn,
    multiIf(f.src_asn = 0, '', src_as.asn != 0 AND src_as.name != '', src_as.name, concat('AS', toString(f.src_asn))) AS src_as_name,
    multiIf(f.dst_asn = 0, '', dst_as.asn != 0 AND dst_as.name != '', dst_as.name, concat('AS', toString(f.dst_asn))) AS dst_as_name,
    if(length(trimBoth(src_ip_country_raw)) = 0, '??', trimBoth(src_ip_country_raw)) AS src_ip_country,
    if(length(trimBoth(dst_ip_country_raw)) = 0, '??', trimBoth(dst_ip_country_raw)) AS dst_ip_country,
    if(f.src_asn = 0 OR src_as.asn = 0, '??', trimBoth(toString(src_as.cc))) AS src_as_country,
    if(f.dst_asn = 0 OR dst_as.asn = 0, '??', trimBoth(toString(dst_as.cc))) AS dst_as_country,
    f.src_endpoint_scope AS src_scope,
    f.dst_endpoint_scope AS dst_scope,
    f.src_label,
    f.dst_label,
    sum(f.bytes) AS bytes,
    sum(f.packets) AS packets,
    count() AS flows_count
FROM default.flows_raw AS f
LEFT JOIN default.asn_registry_enriched AS src_as ON src_as.asn = f.src_asn
LEFT JOIN default.asn_registry_enriched AS dst_as ON dst_as.asn = f.dst_asn
GROUP BY
    minute,
    f.source_id,
    f.direction,
    src_ip,
    dst_ip,
    f.src_asn,
    f.dst_asn,
    src_as_name,
    dst_as_name,
    src_ip_country,
    dst_ip_country,
    src_as_country,
    dst_as_country,
    src_scope,
    dst_scope,
    f.src_label,
    f.dst_label;
