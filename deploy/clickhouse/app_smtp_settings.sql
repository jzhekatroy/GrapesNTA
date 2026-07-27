-- SMTP settings for observation report delivery (single global row).

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

CREATE VIEW IF NOT EXISTS default.app_smtp_settings_current
(
    `settings_id` String,
    `host` String,
    `port` UInt16,
    `secure` UInt8,
    `username` String,
    `password` String,
    `from_email` String,
    `from_name` String,
    `enabled` UInt8,
    `updated_at` DateTime('UTC')
)
AS SELECT
    settings_id,
    host,
    port,
    secure,
    username,
    password,
    from_email,
    from_name,
    enabled,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        settings_id,
        argMax(host, updated_at) AS host,
        argMax(port, updated_at) AS port,
        argMax(secure, updated_at) AS secure,
        argMax(username, updated_at) AS username,
        argMax(password, updated_at) AS password,
        argMax(from_email, updated_at) AS from_email,
        argMax(from_name, updated_at) AS from_name,
        argMax(enabled, updated_at) AS enabled,
        max(updated_at) AS updated_at_latest
    FROM default.app_smtp_settings
    GROUP BY settings_id
);

ALTER TABLE default.observation_runs
    ADD COLUMN IF NOT EXISTS email_status String DEFAULT '',
    ADD COLUMN IF NOT EXISTS email_to String DEFAULT '',
    ADD COLUMN IF NOT EXISTS email_error String DEFAULT '';
