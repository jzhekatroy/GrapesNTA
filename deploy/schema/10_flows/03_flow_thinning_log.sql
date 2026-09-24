-- Журнал прореживания суток flows_raw. Одна строка на каждую смену состояния;
-- последнее состояние суток — argMax(..., updated_at) по day.
--
-- Сутки со статусом done или running повторно не берутся: второй проход
-- по уже прореженным суткам снова умножил бы оставшиеся потоки. Вторая защита
-- в самом запросе: переписываются только строки с sampling_rate = 1.
-- Safe to re-run. No DROP.

CREATE TABLE IF NOT EXISTS default.flow_thinning_log
(
    `day` Date,
    `source_ids` Array(String),
    `rate` UInt16,
    `threshold_bytes` UInt64,
    `mode` LowCardinality(String),
    -- waiting | running | done | failed | skipped
    `status` LowCardinality(String),
    `rows_before` UInt64 DEFAULT 0,
    `bytes_before` UInt64 DEFAULT 0,
    -- Для done — факт после мутации.
    `rows_after` UInt64 DEFAULT 0,
    `bytes_after` UInt64 DEFAULT 0,
    `eligible_rows` UInt64 DEFAULT 0,
    `mutation_id` String DEFAULT '',
    `started_at` DateTime('UTC') DEFAULT now(),
    `finished_at` Nullable(DateTime('UTC')),
    `message` String DEFAULT '',
    `updated_at` DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY (day, updated_at)
TTL toDateTime(updated_at) + INTERVAL 400 DAY
SETTINGS index_granularity = 8192;
