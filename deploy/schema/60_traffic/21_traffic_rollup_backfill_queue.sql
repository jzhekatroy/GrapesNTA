CREATE TABLE IF NOT EXISTS default.traffic_rollup_backfill_queue
(
    `request_id` String,
    `created_at` DateTime64(3, 'UTC') DEFAULT now64(3),
    `from_minute` DateTime('UTC'),
    `to_minute` DateTime('UTC'),
    `jobs` Array(String) DEFAULT [],
    `include_observations` UInt8 DEFAULT 1,
    `status` LowCardinality(String) DEFAULT 'pending',
    `error` String DEFAULT '',
    `progress_job` String DEFAULT '',
    `progress_minute` DateTime('UTC') DEFAULT toDateTime(0, 'UTC'),
    `updated_at` DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY request_id
TTL toDateTime(created_at) + toIntervalDay(30)
SETTINGS index_granularity = 8192;
