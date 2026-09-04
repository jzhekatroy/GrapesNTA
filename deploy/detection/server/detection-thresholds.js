'use strict';

const { query, executeCommand, insertRows, config } = require('./clickhouse');

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

const TABLE = 'app_detection_object_thresholds';
const VIEW = 'app_detection_object_thresholds_current';
const DEFAULT_GROWTH_THRESHOLD = 1.6;

let ensurePromise = null;

function objectKey(scope, scopeId) {
  return `${scope}|${scopeId}`;
}

function tableRef() {
  return `${config.database}.${TABLE}`;
}

function viewRef() {
  return `${config.database}.${VIEW}`;
}

function normalizeGrowthThreshold(value, fallback = DEFAULT_GROWTH_THRESHOLD) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || n > 1000) return Number(fallback) || DEFAULT_GROWTH_THRESHOLD;
  return n;
}

function readOverride(scope, scopeId, thresholdByKey) {
  const key = objectKey(scope, scopeId);
  const override = thresholdByKey instanceof Map
    ? thresholdByKey.get(key)
    : thresholdByKey?.[key];
  if (override == null || override === '') return null;
  const n = Number(override);
  if (!Number.isFinite(n) || n <= 0 || n > 1000) return null;
  return n;
}

function resolveGrowthThreshold(scope, scopeId, fallback, thresholdByKey) {
  const override = readOverride(scope, scopeId, thresholdByKey);
  if (override == null) return normalizeGrowthThreshold(fallback);
  return override;
}

function hasGrowthOverride(scope, scopeId, thresholdByKey) {
  return readOverride(scope, scopeId, thresholdByKey) != null;
}

async function ensureThresholdTables() {
  if (!ensurePromise) {
    ensurePromise = (async () => {
      await executeCommand(`
        CREATE TABLE IF NOT EXISTS ${tableRef()}
        (
          scope LowCardinality(String),
          scope_id String,
          growth_threshold Float64,
          -- Milliseconds, not seconds: the threshold is edited inline in the
          -- table, so "set 4" and "clear" land in the same second and argMax
          -- would pick between them at random.
          updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (scope, scope_id)
        SETTINGS index_granularity = 8192
      `, {}, { name: 'detection/thresholds-ensure-table' });

      await executeCommand(`
        CREATE OR REPLACE VIEW ${viewRef()}
        (
          scope String,
          scope_id String,
          growth_threshold Float64,
          updated_at DateTime64(3, 'UTC')
        )
        AS SELECT
          scope,
          scope_id,
          growth_threshold,
          updated_at_latest AS updated_at
        FROM
        (
          SELECT
            scope,
            scope_id,
            argMax(growth_threshold, updated_at) AS growth_threshold,
            max(updated_at) AS updated_at_latest
          FROM ${tableRef()}
          GROUP BY scope, scope_id
        )
        WHERE growth_threshold > 0
      `, {}, { name: 'detection/thresholds-ensure-view' });
    })().catch((err) => {
      ensurePromise = null;
      throw err;
    });
  }
  return ensurePromise;
}

async function loadThresholdMap() {
  await ensureThresholdTables();
  const { rows } = await query(`
    SELECT scope, scope_id, growth_threshold
    FROM ${viewRef()}
  `, {}, { name: 'detection/thresholds-list' });
  const map = new Map();
  for (const row of rows) {
    const n = Number(row.growth_threshold);
    if (!Number.isFinite(n) || n <= 0) continue;
    map.set(objectKey(row.scope, row.scope_id), n);
  }
  return map;
}

async function listObjectThresholds() {
  await ensureThresholdTables();
  const { rows } = await query(`
    SELECT scope, scope_id, growth_threshold
    FROM ${viewRef()}
    ORDER BY scope, scope_id
  `, {}, { name: 'detection/thresholds-list-ui' });
  return rows.map((row) => ({
    scope: String(row.scope || ''),
    scopeId: String(row.scope_id || ''),
    growthThreshold: Number(row.growth_threshold),
  }));
}

async function saveObjectThreshold(payload = {}) {
  const scope = payload.scope;
  const scopeId = payload.scopeId ?? payload.scope_id;
  const growthThreshold = payload.growthThreshold ?? payload.growth_threshold;
  const kind = String(scope || '').trim();
  const id = String(scopeId || '').trim();
  if (kind !== 'client' && kind !== 'net') {
    throw apiError('Порог: объект — абонент или сеть');
  }
  if (!id) throw apiError('Порог: не задан id объекта');
  const raw = growthThreshold == null || growthThreshold === '' ? 0 : Number(growthThreshold);
  if (raw !== 0 && (!Number.isFinite(raw) || raw <= 0 || raw > 1000)) {
    throw apiError('Порог роста: число от 0.01 до 1000, пусто — общий');
  }
  await ensureThresholdTables();
  await insertRows(TABLE, [{
    scope: kind,
    scope_id: id,
    growth_threshold: raw,
  }], { name: 'detection/thresholds-save' });
  return {
    scope: kind,
    scopeId: id,
    growthThreshold: raw > 0 ? raw : null,
  };
}

module.exports = {
  TABLE,
  VIEW,
  DEFAULT_GROWTH_THRESHOLD,
  objectKey,
  normalizeGrowthThreshold,
  resolveGrowthThreshold,
  hasGrowthOverride,
  ensureThresholdTables,
  loadThresholdMap,
  listObjectThresholds,
  saveObjectThreshold,
};
