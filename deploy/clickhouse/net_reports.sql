-- Async network report jobs stored in ClickHouse.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_reports.sql

CREATE TABLE IF NOT EXISTS default.net_reports
(
    id           String,
    type         LowCardinality(String),
    filters_json String DEFAULT '{}',
    period_from  DateTime('UTC'),
    period_to    DateTime('UTC'),
    status       LowCardinality(String) DEFAULT 'queued',
    result_json  String DEFAULT '',
    error        String DEFAULT '',
    created_by   String DEFAULT '',
    created_at   DateTime('UTC') DEFAULT now(),
    started_at   DateTime('UTC') DEFAULT toDateTime(0),
    finished_at  DateTime('UTC') DEFAULT toDateTime(0),
    updated_at   DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id
SETTINGS index_granularity = 8192;
