-- Настройки прореживания старых суток flows_raw (страница «Сроки хранения»).
-- Читает scripts/flow_thinning.py при каждом запуске, поэтому смена настроек
-- не требует перезапуска worker. Прореживаются только источники xdpflowd:
-- NetFlow и sFlow хранятся точно весь срок.
-- Safe to re-run. No DROP.

CREATE TABLE IF NOT EXISTS default.app_flow_storage_settings
(
    `settings_id` String DEFAULT 'global',
    -- off: ничего не делать; on: прореживать.
    `mode` LowCardinality(String) DEFAULT 'off',
    -- Сколько полных суток до текущих хранить без прореживания.
    `hot_days` UInt16 DEFAULT 1,
    -- Потоки меньше порога оставляются с вероятностью 1/xdp_rate.
    `xdp_rate` UInt16 DEFAULT 64,
    `xdp_threshold_bytes` UInt64 DEFAULT 100000,
    -- Начало ночного окна, местное время worker (Europe/Moscow). Окно 3 часа.
    `run_at` String DEFAULT '04:30',
    `updated_by` String DEFAULT '',
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
SETTINGS index_granularity = 8192;
