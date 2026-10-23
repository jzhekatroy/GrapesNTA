-- Cabinet traffic of IX clients by minute, split by IX site, the IX client on the
-- other side and the remote ASN. Filled only while IX mode is on.
-- direction is from the client's point of view, as in traffic_client_1m.
-- ix_location is the site name from net_l2_vlans_enabled, empty when the VLAN is
-- not an IX VLAN. peer_client_id is empty when the other side is not a known IX
-- client. Rows are not folded to a top, so sums by location match the client total.
--
-- A separate table rather than extra key columns on traffic_client_1m: the
-- detector reads per-row quantiles from the client tables, and splitting their
-- rows would change its baselines.
--
-- About 50k rows a minute on PiterIX. The codecs cut a day from 790 MB to 340 MB
-- there, which matters because the 14 days have to fit next to flows_raw.
CREATE TABLE IF NOT EXISTS default.traffic_client_ix_1m
(
    `minute` DateTime('UTC') CODEC(Delta, ZSTD(3)),
    `client_id` LowCardinality(String) CODEC(ZSTD(3)),
    `ix_location` LowCardinality(String) CODEC(ZSTD(3)),
    `direction` LowCardinality(String) CODEC(ZSTD(3)),
    `peer_client_id` LowCardinality(String) CODEC(ZSTD(3)),
    `remote_asn` UInt32 CODEC(ZSTD(3)),
    `bytes` UInt64 CODEC(T64, ZSTD(3)),
    `packets` UInt64 CODEC(T64, ZSTD(3)),
    `flows_count` UInt64 CODEC(T64, ZSTD(3)),
    INDEX idx_minute minute TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (client_id, minute, ix_location, direction, peer_client_id, remote_asn)
TTL minute + toIntervalDay(14)
SETTINGS index_granularity = 8192;
