-- Observation definitions + report run metadata (shared across UI instances).
-- Applied automatically by NTAdmin analytics worker / UI on start; this file is
-- for manual apply on the ClickHouse host.
-- Artifacts (HTML/CSV) stay on disk under NTAdmin server/data/observation_runs/.

CREATE TABLE IF NOT EXISTS default.observations
(
  id String,
  owner_id String,
  is_shared UInt8 DEFAULT 0,
  name String,
  description String DEFAULT '',
  folder String DEFAULT '',
  lookback LowCardinality(String) DEFAULT '1h',
  filters_json String DEFAULT '[]',
  widgets_json String DEFAULT '[]',
  live_json String DEFAULT '{}',
  materialize_json String DEFAULT '{}',
  report_json String DEFAULT '{}',
  deleted UInt8 DEFAULT 0,
  created_at DateTime64(3) DEFAULT now64(3),
  updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS default.observation_runs
(
  id String,
  observation_id String,
  started_at DateTime64(3),
  finished_at Nullable(DateTime64(3)),
  status LowCardinality(String) DEFAULT '',
  period LowCardinality(String) DEFAULT '',
  window_from Nullable(DateTime64(3)),
  window_to Nullable(DateTime64(3)),
  artifact_path String DEFAULT '',
  payload_json String DEFAULT '{}',
  error String DEFAULT '',
  deleted UInt8 DEFAULT 0,
  updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (observation_id, id);

-- Live materialize target (also ensured by NTAdmin worker).
CREATE TABLE IF NOT EXISTS default.observation_rollups_5m
(
  observation_id String,
  minute DateTime,
  dim0 LowCardinality(String) DEFAULT '',
  dim1 LowCardinality(String) DEFAULT '',
  bytes UInt64,
  packets UInt64,
  flows UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (observation_id, minute, dim0, dim1)
TTL minute + INTERVAL 14 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.analytics_worker_status
(
  worker_id LowCardinality(String) DEFAULT 'default',
  host String DEFAULT '',
  pid UInt32 DEFAULT 0,
  mode LowCardinality(String) DEFAULT 'loop',
  last_heartbeat_at DateTime64(3),
  last_tick_at Nullable(DateTime64(3)),
  last_tick_ms Nullable(UInt32),
  last_error String DEFAULT '',
  started_at Nullable(DateTime64(3)),
  payload_json String DEFAULT '{}',
  updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY worker_id;
