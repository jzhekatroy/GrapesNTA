CREATE TABLE IF NOT EXISTS default.user_permissions
(
    `user_id` String,
    `resource` String,
    `mode` String,
    `updated_at` DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY (user_id, resource)
SETTINGS index_granularity = 8192;
