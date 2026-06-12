-- Async rollup job state (replaces sync traffic_*_mv on hot ingest path).
-- One row per job; ReplacingMergeTree keeps the latest updated_at per job name.

CREATE TABLE IF NOT EXISTS default.traffic_rollup_state
(
    job         String,
    last_bucket DateTime('UTC'),
    status      LowCardinality(String) DEFAULT 'ok',
    last_error  String DEFAULT '',
    rows_written UInt64 DEFAULT 0,
    duration_ms UInt32 DEFAULT 0,
    updated_at  DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY job
SETTINGS index_granularity = 8192;
