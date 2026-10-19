CREATE TABLE IF NOT EXISTS default.roles
(
    `id` String,
    `name` String,
    `display_name` String,
    `start_page` String DEFAULT 'dashboard',
    `created_at` DateTime64(3) DEFAULT now64(3),
    `updated_at` DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY id
SETTINGS index_granularity = 8192;
