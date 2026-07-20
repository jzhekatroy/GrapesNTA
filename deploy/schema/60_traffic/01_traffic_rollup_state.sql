CREATE TABLE IF NOT EXISTS default.traffic_rollup_state
(
    `job` String,
    `last_bucket` DateTime('UTC'),
    `status` LowCardinality(String) DEFAULT 'ok',
    `last_error` String DEFAULT '',
    `rows_written` UInt64 DEFAULT 0,
    `duration_ms` UInt32 DEFAULT 0,
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY job
SETTINGS index_granularity = 8192;
