-- Feeds bmp_route_state from the raw event stream.
--
-- prefix_len = 0 is dropped here because the origin rebuild ignores the default
-- route anyway, and prefix_len is part of the state key, so those rows would sit
-- in their own keys forever without ever being read.
CREATE MATERIALIZED VIEW IF NOT EXISTS default.bmp_route_state_mv TO default.bmp_route_state
(
    `ts` DateTime64(6, 'UTC'),
    `router_addr` FixedString(16),
    `peer_addr` FixedString(16),
    `peer_asn` UInt32,
    `event_type` LowCardinality(String),
    `family` UInt8,
    `prefix` FixedString(16),
    `prefix_len` UInt8,
    `next_hop` FixedString(16),
    `origin_asn` UInt32,
    `as_path` Array(UInt32)
)
AS SELECT
    ts,
    router_addr,
    peer_addr,
    peer_asn,
    event_type,
    family,
    prefix,
    prefix_len,
    next_hop,
    origin_asn,
    as_path
FROM default.bmp_route_events
WHERE prefix_len > 0;
