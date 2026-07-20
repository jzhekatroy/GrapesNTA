CREATE TABLE IF NOT EXISTS default.users
(
    `id` String,
    `username` String,
    `full_name` String,
    `password_hash` String,
    `role_id` String DEFAULT 'Administrator',
    `force_password_change` UInt8 DEFAULT 0,
    `created_at` DateTime64(3) DEFAULT now64(3),
    `updated_at` DateTime64(3) DEFAULT now64(3),
    `password_changed_at` Nullable(DateTime64(3)) DEFAULT NULL
)
ENGINE = MergeTree
ORDER BY id
SETTINGS index_granularity = 8192;
