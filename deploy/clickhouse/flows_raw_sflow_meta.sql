-- sFlow switch/router metadata + L3/L4 attribute columns for flows_raw.
--
-- Populated by flowcollectord from the sFlow flow-sample header and the inner
-- sampled packet:
--   in_if / out_if  -- SNMP ifIndex of the ingress/egress physical switch ports
--                      (from the flow sample; out_if=0 unknown, 2147483650=flood)
--   tcp_flags       -- inner TCP flags byte (FIN,SYN,RST,PSH,ACK,URG,ECE,CWR)
--   ip_ttl          -- inner IPv4 TTL / IPv6 hop limit
--   ip_tos          -- inner IPv4 DSCP+ECN / IPv6 traffic class
--
-- xdpflowd (mirror) and BMP leave these zero. None are part of any rollup
-- GROUP BY, so existing rollups and materialized views are unaffected.
--
-- MUST be applied BEFORE deploying the binaries that write these columns — the
-- INSERT column list references them, so a binary running ahead of this
-- migration would fail with "unknown column". Existing rows keep the zero
-- default and stay readable.
--
--   clickhouse-client ... --multiquery < deploy/clickhouse/flows_raw_sflow_meta.sql

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS in_if     UInt32 DEFAULT 0,
    ADD COLUMN IF NOT EXISTS out_if    UInt32 DEFAULT 0,
    ADD COLUMN IF NOT EXISTS tcp_flags UInt8  DEFAULT 0,
    ADD COLUMN IF NOT EXISTS ip_ttl    UInt8  DEFAULT 0,
    ADD COLUMN IF NOT EXISTS ip_tos    UInt8  DEFAULT 0;
