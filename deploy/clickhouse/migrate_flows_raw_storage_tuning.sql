-- Storage tuning for the high-volume default.flows_raw table.
--
-- This migration documents the production change made to reduce ClickHouse
-- merge I/O:
--   * numeric/time columns get explicit codecs for new parts and future merges;
--   * legacy src_as/dst_as duplicate columns are dropped after writers stop
--     inserting them (use src_asn/dst_asn instead).
--
-- WARNING: On existing large tables, MODIFY COLUMN CODEC and DROP COLUMN can
-- create mutations that rewrite old parts. Run during a quiet window or monitor
-- system.mutations / system.merges and stop unwanted rewrite work.
--
-- Apply after deploying binaries that no longer write src_as/dst_as:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_flows_raw_storage_tuning.sql

ALTER TABLE default.flows_raw
    MODIFY COLUMN time_flow_start_ns DateTime64(9) CODEC(DoubleDelta, ZSTD(1)),
    MODIFY COLUMN time_received_ns DateTime64(9) CODEC(DoubleDelta, ZSTD(1)),
    MODIFY COLUMN time_inserted_ns DateTime64(9) CODEC(DoubleDelta, ZSTD(1)),
    MODIFY COLUMN src_port UInt32 CODEC(T64, ZSTD(1)),
    MODIFY COLUMN dst_port UInt32 CODEC(T64, ZSTD(1)),
    MODIFY COLUMN bytes UInt64 CODEC(T64, ZSTD(1)),
    MODIFY COLUMN packets UInt64 CODEC(T64, ZSTD(1)),
    MODIFY COLUMN src_asn UInt32 CODEC(T64, ZSTD(1)),
    MODIFY COLUMN dst_asn UInt32 CODEC(T64, ZSTD(1)),
    MODIFY COLUMN src_vlan UInt16 CODEC(T64, ZSTD(1)),
    MODIFY COLUMN dst_vlan UInt16 CODEC(T64, ZSTD(1)),
    MODIFY COLUMN proto UInt32 CODEC(T64, ZSTD(1));

ALTER TABLE default.flows_raw
    DROP COLUMN IF EXISTS src_as,
    DROP COLUMN IF EXISTS dst_as;
