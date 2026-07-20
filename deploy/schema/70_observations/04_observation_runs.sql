CREATE TABLE IF NOT EXISTS default.observation_runs
(
    `id` String,
    `observation_id` String,
    `started_at` DateTime64(3),
    `finished_at` Nullable(DateTime64(3)),
    `status` LowCardinality(String) DEFAULT '',
    `period` LowCardinality(String) DEFAULT '',
    `window_from` Nullable(DateTime64(3)),
    `window_to` Nullable(DateTime64(3)),
    `artifact_path` String DEFAULT '',
    `payload_json` String DEFAULT '{}',
    `error` String DEFAULT '',
    `deleted` UInt8 DEFAULT 0,
    `updated_at` DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (observation_id, id)
SETTINGS index_granularity = 8192;
