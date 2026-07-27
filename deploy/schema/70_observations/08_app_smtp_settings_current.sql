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
