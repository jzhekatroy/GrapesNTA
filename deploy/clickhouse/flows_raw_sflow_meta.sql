-- sFlow switch/router metadata and L3/L4 attribute columns for flows_raw.
--
-- Populated by flowcollectord from the sFlow flow-sample header and the inner
-- sampled packet:
--   in_if, out_if  = SNMP ifIndex of ingress/egress physical switch ports
--   tcp_flags      = inner TCP flags byte (FIN,SYN,RST,PSH,ACK,URG,ECE,CWR)
--   ip_ttl         = inner IPv4 TTL / IPv6 hop limit
--   ip_tos         = inner IPv4 DSCP+ECN / IPv6 traffic class
--
-- xdpflowd (mirror) and BMP leave these zero. None are part of any rollup
-- GROUP BY, so existing rollups and materialized views are unaffected.
--
-- Apply BEFORE deploying the binary that writes these columns.
--
--   clickhouse-client ... --multiquery < deploy/clickhouse/flows_raw_sflow_meta.sql

ALTER TABLE default.flows_raw ADD COLUMN IF NOT EXISTS in_if UInt32 DEFAULT 0;
ALTER TABLE default.flows_raw ADD COLUMN IF NOT EXISTS out_if UInt32 DEFAULT 0;
ALTER TABLE default.flows_raw ADD COLUMN IF NOT EXISTS tcp_flags UInt8 DEFAULT 0;
ALTER TABLE default.flows_raw ADD COLUMN IF NOT EXISTS ip_ttl UInt8 DEFAULT 0;
ALTER TABLE default.flows_raw ADD COLUMN IF NOT EXISTS ip_tos UInt8 DEFAULT 0;
