CREATE TABLE IF NOT EXISTS default.analytics_worker_status
(
    `worker_id` LowCardinality(String) DEFAULT 'default',
    `host` String DEFAULT '',
    `pid` UInt32 DEFAULT 0,
    `mode` LowCardinality(String) DEFAULT 'loop',
    `last_heartbeat_at` DateTime64(3),
    `last_tick_at` Nullable(DateTime64(3)),
    `last_tick_ms` Nullable(UInt32),
    `last_error` String DEFAULT '',
    `started_at` Nullable(DateTime64(3)),
    `payload_json` String DEFAULT '{}',
    `updated_at` DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY worker_id
SETTINGS index_granularity = 8192;
