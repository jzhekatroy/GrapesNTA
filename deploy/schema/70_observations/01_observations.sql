CREATE TABLE IF NOT EXISTS default.observations
(
    `id` String,
    `owner_id` String,
    `is_shared` UInt8 DEFAULT 0,
    `name` String,
    `description` String DEFAULT '',
    `folder` String DEFAULT '',
    `lookback` LowCardinality(String) DEFAULT '1h',
    `filters_json` String DEFAULT '[]',
    `widgets_json` String DEFAULT '[]',
    `live_json` String DEFAULT '{}',
    `materialize_json` String DEFAULT '{}',
    `report_json` String DEFAULT '{}',
    `deleted` UInt8 DEFAULT 0,
    `created_at` DateTime64(3) DEFAULT now64(3),
    `updated_at` DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id
SETTINGS index_granularity = 8192;
