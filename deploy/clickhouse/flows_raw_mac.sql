-- Layer-2 MAC columns for flows_raw.
--
-- Populated by xdpflowd (mirror capture) and flowcollectord (sFlow sampled
-- frame). BMP has no L2 and leaves these zero. Stored raw as FixedString(6);
-- format for display with hex()/arrayStringConcat rather than storing text.
--
-- MUST be applied BEFORE deploying the binaries that write src_mac/dst_mac —
-- the INSERT column list references these columns, so a binary that runs ahead
-- of this migration would fail with "unknown column". Existing rows keep the
-- zero default and stay readable; rollups do not reference these columns.
--
--   clickhouse-client ... --multiquery < deploy/clickhouse/flows_raw_mac.sql

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS src_mac FixedString(6) DEFAULT '',
    ADD COLUMN IF NOT EXISTS dst_mac FixedString(6) DEFAULT '';
