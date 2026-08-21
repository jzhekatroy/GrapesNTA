-- ERP sync settings: cron on/off and which by-category endpoints to pull.
-- Safe to re-run. No DROP.

CREATE TABLE IF NOT EXISTS default.app_erp_sync_settings
(
    `settings_id` String DEFAULT 'global',
    `cron_enabled` UInt8 DEFAULT 0,
    `cat_piter_ix` UInt8 DEFAULT 1,
    `cat_dc` UInt8 DEFAULT 0,
    `cat_bb` UInt8 DEFAULT 0,
    `api_base` String DEFAULT 'https://195.2.241.23:8443',
    `api_host` String DEFAULT 'erp.bth.su',
    `api_token` String DEFAULT 'aBZFW5bH1tG80pxqon5S0noQXBX1wni0',
    `api_insecure` UInt8 DEFAULT 1,
    `bind_mode` LowCardinality(String) DEFAULT 'ports',
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
SETTINGS index_granularity = 8192;
