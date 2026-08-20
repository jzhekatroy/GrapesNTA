-- UI audit journal: login, page views, mutating API calls.
-- Safe to re-run. No DROP.

CREATE TABLE IF NOT EXISTS default.app_audit_log
(
    `id` String,
    `event_at` DateTime64(3) DEFAULT now64(3),
    `actor_user_id` String DEFAULT '',
    `actor_username` String DEFAULT '',
    `actor_role` LowCardinality(String) DEFAULT '',
    `ip` String DEFAULT '',
    `user_agent` String DEFAULT '',
    `action` LowCardinality(String),
    `resource` LowCardinality(String) DEFAULT '',
    `method` LowCardinality(String) DEFAULT '',
    `path` String DEFAULT '',
    `object_id` String DEFAULT '',
    `object_label` String DEFAULT '',
    `result` LowCardinality(String) DEFAULT 'ok',
    `detail` String DEFAULT '',
    `session_id` String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_at)
ORDER BY (event_at, actor_username, id)
TTL toDateTime(event_at) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
