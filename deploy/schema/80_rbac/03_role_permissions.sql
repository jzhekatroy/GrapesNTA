CREATE TABLE IF NOT EXISTS default.role_permissions
(
    `role_id` String,
    `resource` String,
    `allowed` UInt8,
    `can_write` UInt8 DEFAULT 1,
    `updated_at` DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY (role_id, resource)
SETTINGS index_granularity = 8192;
