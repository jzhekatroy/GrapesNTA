CREATE TABLE IF NOT EXISTS default.app_smtp_settings
(
    `settings_id` String DEFAULT 'global',
    `host` String DEFAULT '',
    `port` UInt16 DEFAULT 587,
    `secure` UInt8 DEFAULT 0,
    `username` String DEFAULT '',
    `password` String DEFAULT '',
    `from_email` String DEFAULT '',
    `from_name` String DEFAULT 'GrapesNTA',
    `enabled` UInt8 DEFAULT 0,
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
SETTINGS index_granularity = 8192;
