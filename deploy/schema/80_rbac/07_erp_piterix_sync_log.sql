-- Journal of ERP client sync runs. Safe to re-run. No DROP.

CREATE TABLE IF NOT EXISTS default.erp_piterix_sync_log
(
    `run_id` String,
    `started_at` DateTime,
    `finished_at` DateTime,
    `trigger` LowCardinality(String),
    `full` UInt8,
    `limit_n` UInt32,
    `fetched` UInt32,
    `active` UInt32,
    `labelable` UInt32,
    `upserted` UInt32,
    `ports` UInt32,
    `disabled` UInt32,
    `skipped` UInt32,
    `skipped_json` String,
    `error` String,
    `actor` String
)
ENGINE = MergeTree
ORDER BY (started_at, run_id)
TTL started_at + toIntervalDay(180)
SETTINGS index_granularity = 8192;
