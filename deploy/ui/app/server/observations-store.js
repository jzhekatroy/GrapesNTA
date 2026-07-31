'use strict';

const fs = require('fs');
const path = require('path');
const { query, executeCommand, insertRows, config } = require('./clickhouse');
const {
  parseObservationFiltersEnvelope,
  serializeObservationFiltersEnvelope,
} = require('./explorer-thresholds');

const OBSERVATIONS_TABLE = 'observations';
const RUNS_TABLE = 'observation_runs';
const LEGACY_STORE_FILE = path.join(__dirname, 'data', 'observations.json');
const LEGACY_RUNS_FILE = path.join(__dirname, 'data', 'observation-runs.json');

let ensurePromise = null;

function clickhouseDateTime(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  if (!Number.isFinite(d.getTime())) {
    return new Date().toISOString().replace('T', ' ').replace('Z', '');
  }
  return d.toISOString().replace('T', ' ').replace('Z', '');
}

function toIso(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date) return value.toISOString();
  const s = String(value).trim();
  if (!s) return null;
  if (s.includes('T')) return s.endsWith('Z') ? s : `${s}Z`;
  return `${s.replace(' ', 'T')}Z`;
}

function safeJsonParse(raw, fallback) {
  if (raw == null || raw === '') return fallback;
  if (typeof raw === 'object') return raw;
  try {
    return JSON.parse(String(raw));
  } catch {
    return fallback;
  }
}

function rowToObservation(row) {
  const live = safeJsonParse(row.live_json, {});
  const layout = live.layout && typeof live.layout === 'object'
    ? live.layout
    : { order: 0, width: 1 };
  const liveClean = { ...live };
  delete liveClean.layout;
  const envelope = parseObservationFiltersEnvelope(safeJsonParse(row.filters_json, []));
  // Migrate legacy report.cron/timezone → schedule is done in normalizeObservation on write.
  return {
    id: String(row.id ?? ''),
    name: String(row.name ?? ''),
    description: String(row.description ?? ''),
    folder: String(row.folder ?? ''),
    ownerId: String(row.owner_id ?? ''),
    isShared: Number(row.is_shared) === 1,
    filters: envelope.filters,
    thresholds: envelope.thresholds,
    lookback: String(row.lookback || '1h'),
    widgets: safeJsonParse(row.widgets_json, []),
    layout,
    live: liveClean,
    materialize: safeJsonParse(row.materialize_json, {}),
    report: safeJsonParse(row.report_json, {}),
    createdAt: toIso(row.created_at) || new Date().toISOString(),
    updatedAt: toIso(row.updated_at) || new Date().toISOString(),
  };
}

function observationToRow(item, { deleted = 0 } = {}) {
  return {
    id: String(item.id),
    owner_id: String(item.ownerId || ''),
    is_shared: item.isShared ? 1 : 0,
    name: String(item.name || ''),
    description: String(item.description || ''),
    folder: String(item.folder || ''),
    lookback: String(item.lookback || '1h'),
    filters_json: JSON.stringify(serializeObservationFiltersEnvelope(item.filters, item.thresholds)),
    widgets_json: JSON.stringify(item.widgets || []),
    live_json: JSON.stringify({ ...(item.live || {}), layout: item.layout || { order: 0, width: 1 } }),
    materialize_json: JSON.stringify(item.materialize || {}),
    report_json: JSON.stringify(item.report || {}),
    deleted: deleted ? 1 : 0,
    created_at: clickhouseDateTime(item.createdAt || new Date()),
    updated_at: clickhouseDateTime(item.updatedAt || new Date()),
  };
}

function rowToRun(row) {
  const payload = safeJsonParse(row.payload_json, {});
  return {
    id: String(row.id ?? ''),
    observationId: String(row.observation_id ?? ''),
    startedAt: toIso(row.started_at),
    finishedAt: toIso(row.finished_at),
    status: String(row.status || ''),
    period: String(row.period || ''),
    window: {
      from: toIso(row.window_from) || payload.window?.from || null,
      to: toIso(row.window_to) || payload.window?.to || null,
    },
    artifactPath: String(row.artifact_path || payload.artifactPath || ''),
    tables: payload.tables || [],
    previewWidgetCount: payload.previewWidgetCount ?? 0,
    error: String(row.error || '') || null,
    emailStatus: String(row.email_status || payload.emailStatus || ''),
    emailTo: String(row.email_to || payload.emailTo || ''),
    emailError: String(row.email_error || payload.emailError || ''),
  };
}

function runToRow(run, { deleted = 0 } = {}) {
  const payload = {
    tables: run.tables || [],
    previewWidgetCount: run.previewWidgetCount ?? 0,
    artifactPath: run.artifactPath || '',
    window: run.window || {},
    emailStatus: run.emailStatus || '',
    emailTo: run.emailTo || '',
    emailError: run.emailError || '',
  };
  return {
    id: String(run.id),
    observation_id: String(run.observationId),
    started_at: clickhouseDateTime(run.startedAt || new Date()),
    finished_at: run.finishedAt ? clickhouseDateTime(run.finishedAt) : null,
    status: String(run.status || ''),
    period: String(run.period || ''),
    window_from: run.window?.from ? clickhouseDateTime(run.window.from) : null,
    window_to: run.window?.to ? clickhouseDateTime(run.window.to) : null,
    artifact_path: String(run.artifactPath || ''),
    payload_json: JSON.stringify(payload),
    error: String(run.error || ''),
    email_status: String(run.emailStatus || ''),
    email_to: String(run.emailTo || ''),
    email_error: String(run.emailError || ''),
    deleted: deleted ? 1 : 0,
    updated_at: clickhouseDateTime(run.finishedAt || run.startedAt || new Date()),
  };
}

function readLegacyJsonArray(filePath) {
  if (!fs.existsSync(filePath)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function ensureObservationsStore() {
  if (!ensurePromise) {
    ensurePromise = (async () => {
      await executeCommand(`
        CREATE TABLE IF NOT EXISTS ${config.database}.${OBSERVATIONS_TABLE}
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
        ORDER BY id
      `, {}, { name: 'observations/ensure-store' });

      await executeCommand(`
        CREATE TABLE IF NOT EXISTS ${config.database}.${RUNS_TABLE}
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
          email_status String DEFAULT '',
          email_to String DEFAULT '',
          email_error String DEFAULT '',
          deleted UInt8 DEFAULT 0,
          updated_at DateTime64(3) DEFAULT now64(3)
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (observation_id, id)
      `, {}, { name: 'observations/ensure-runs' });

      await executeCommand(`
        ALTER TABLE ${config.database}.${RUNS_TABLE}
          ADD COLUMN IF NOT EXISTS email_status String DEFAULT '',
          ADD COLUMN IF NOT EXISTS email_to String DEFAULT '',
          ADD COLUMN IF NOT EXISTS email_error String DEFAULT ''
      `, {}, { name: 'observations/ensure-runs-email' }).catch(() => {});

      await migrateFromJsonIfEmpty();
    })().catch((err) => {
      ensurePromise = null;
      throw err;
    });
  }
  return ensurePromise;
}

async function migrateFromJsonIfEmpty() {
  const { rows: countRows } = await query(
    `SELECT count() AS c FROM ${config.database}.${OBSERVATIONS_TABLE}`,
    {},
    { name: 'observations/store-count' },
  );
  if (Number(countRows[0]?.c) > 0) return { migrated: false };

  const legacy = readLegacyJsonArray(LEGACY_STORE_FILE);
  if (legacy.length) {
    const rows = legacy.map((item) => observationToRow({
      ...item,
      updatedAt: item.updatedAt || item.createdAt || new Date().toISOString(),
    }));
    await insertRows(OBSERVATIONS_TABLE, rows, { name: 'observations/migrate-from-json' });
    console.log(`[observations] migrated ${rows.length} definition(s) from ${LEGACY_STORE_FILE}`);
  }

  const { rows: runCountRows } = await query(
    `SELECT count() AS c FROM ${config.database}.${RUNS_TABLE}`,
    {},
    { name: 'observations/runs-count' },
  );
  if (Number(runCountRows[0]?.c) === 0) {
    const legacyRuns = readLegacyJsonArray(LEGACY_RUNS_FILE);
    if (legacyRuns.length) {
      const rows = legacyRuns.map((run) => runToRow(run));
      await insertRows(RUNS_TABLE, rows, { name: 'observations/migrate-runs-from-json' });
      console.log(`[observations] migrated ${rows.length} run(s) from ${LEGACY_RUNS_FILE}`);
    }
  }

  return { migrated: Boolean(legacy.length) };
}

async function loadAllObservations() {
  await ensureObservationsStore();
  const { rows } = await query(`
    WITH latest AS (
      SELECT
        *,
        row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
      FROM ${config.database}.${OBSERVATIONS_TABLE}
    )
    SELECT *
    FROM latest
    WHERE rn = 1 AND deleted = 0
    ORDER BY updated_at DESC
  `, {}, { name: 'observations/list-all' });
  return rows.map(rowToObservation);
}

async function loadObservationById(id) {
  await ensureObservationsStore();
  const { rows } = await query(`
    WITH latest AS (
      SELECT
        *,
        row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
      FROM ${config.database}.${OBSERVATIONS_TABLE}
      WHERE id = {id:String}
    )
    SELECT *
    FROM latest
    WHERE rn = 1 AND deleted = 0
    LIMIT 1
  `, { id: String(id) }, { name: 'observations/get-by-id' });
  return rows[0] ? rowToObservation(rows[0]) : null;
}

async function upsertObservation(item) {
  await ensureObservationsStore();
  const row = observationToRow(item, { deleted: 0 });
  await insertRows(OBSERVATIONS_TABLE, [row], { name: 'observations/upsert' });
  return item;
}

async function softDeleteObservation(item) {
  await ensureObservationsStore();
  const row = observationToRow({
    ...item,
    updatedAt: new Date().toISOString(),
  }, { deleted: 1 });
  await insertRows(OBSERVATIONS_TABLE, [row], { name: 'observations/soft-delete' });
}

async function loadRunsForObservation(observationId) {
  await ensureObservationsStore();
  const { rows } = await query(`
    WITH latest AS (
      SELECT
        *,
        row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
      FROM ${config.database}.${RUNS_TABLE}
      WHERE observation_id = {id:String}
    )
    SELECT *
    FROM latest
    WHERE rn = 1 AND deleted = 0
    ORDER BY started_at DESC
  `, { id: String(observationId) }, { name: 'observations/list-runs' });
  return rows.map(rowToRun);
}

async function loadRunById(observationId, runId) {
  await ensureObservationsStore();
  const { rows } = await query(`
    WITH latest AS (
      SELECT
        *,
        row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
      FROM ${config.database}.${RUNS_TABLE}
      WHERE observation_id = {obsId:String} AND id = {runId:String}
    )
    SELECT *
    FROM latest
    WHERE rn = 1 AND deleted = 0
    LIMIT 1
  `, { obsId: String(observationId), runId: String(runId) }, { name: 'observations/get-run' });
  return rows[0] ? rowToRun(rows[0]) : null;
}

async function insertRun(run) {
  await ensureObservationsStore();
  await insertRows(RUNS_TABLE, [runToRow(run)], { name: 'observations/insert-run' });
  return run;
}

async function lastSuccessfulRunAt(observationId) {
  const runs = await loadRunsForObservation(observationId);
  const ok = runs
    .filter((r) => r.status === 'ok')
    .sort((a, b) => String(b.finishedAt || b.startedAt).localeCompare(String(a.finishedAt || a.startedAt)));
  return ok[0]?.finishedAt || ok[0]?.startedAt || null;
}

module.exports = {
  OBSERVATIONS_TABLE,
  RUNS_TABLE,
  LEGACY_STORE_FILE,
  LEGACY_RUNS_FILE,
  ensureObservationsStore,
  loadAllObservations,
  loadObservationById,
  upsertObservation,
  softDeleteObservation,
  loadRunsForObservation,
  loadRunById,
  insertRun,
  lastSuccessfulRunAt,
};
