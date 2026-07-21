CREATE TABLE IF NOT EXISTS default.enrichment_job_status
(
    `job` LowCardinality(String),
    `status` LowCardinality(String) DEFAULT 'idle',
    `started_at` Nullable(DateTime64(3)),
    `finished_at` Nullable(DateTime64(3)),
    `duration_ms` Nullable(UInt32),
    `exit_code` Nullable(Int32),
    `message` String DEFAULT '',
    `log_tail` String DEFAULT '',
    `metrics_json` String DEFAULT '{}',
    `host` String DEFAULT '',
    `updated_at` DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY job
SETTINGS index_granularity = 8192;
