'use strict';

const fs = require('fs');
const path = require('path');
const { query, executeCommand, insertRows, config, formatDateTime64 } = require('./clickhouse');
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
  return formatDateTime64(date);
}

function latestByIdCte(table, extraWhere = '') {
  return `
    WITH latest AS (
      SELECT
        *,
        row_number() OVER (
          PARTITION BY id
          ORDER BY updated_at DESC, deleted DESC
        ) AS rn
      FROM ${config.database}.${table}
      ${extraWhere}
    )
  `;
}

function zoneOffsetMs(instantMs, timeZone) {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const p = Object.fromEntries(
    fmt.formatToParts(new Date(instantMs)).map((part) => [part.type, part.value]),
  );
  const asUtc = Date.UTC(
    Number(p.year), Number(p.month) - 1, Number(p.day),
    Number(p.hour), Number(p.minute), Number(p.second),
  );
  return asUtc - instantMs;
}

/**
 * DateTime64 columns here carry no timezone, and writes serialize local wall
 * clock in CLICKHOUSE_TIMEZONE (formatDateTime64). Reading that string as UTC
 * shifted the instant by one offset, and because every save re-serialized the
 * shifted value, created_at crept forward by +offset per write until it landed
 * in the future and froze the materialize cursor.
 */
function naiveChToIso(naive, timeZone) {
  const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?$/.exec(naive);
  if (!m) return `${naive.replace(' ', 'T')}Z`;
  const millis = Number(String(m[7] ?? '0').padEnd(3, '0'));
  // Offsets are resolved on whole seconds — Intl drops the fractional part, so
  // milliseconds are re-applied afterwards instead of skewing the offset.
  const wall = Date.UTC(
    Number(m[1]), Number(m[2]) - 1, Number(m[3]),
    Number(m[4]), Number(m[5]), Number(m[6]),
  );
  let instant = wall;
  // Second pass settles DST boundaries, where the offset differs before/after.
  for (let i = 0; i < 2; i += 1) instant = wall - zoneOffsetMs(instant, timeZone);
  return new Date(instant + millis).toISOString();
}

function toIso(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date) return value.toISOString();
  const s = String(value).trim();
  if (!s) return null;
  if (s.includes('T')) return s.endsWith('Z') ? s : `${s}Z`;
  return naiveChToIso(s, config.dataTimezone || 'UTC');
}

/** Recover created_at values that drifted into the future before the fix above. */
function sanitizeCreatedAt(createdIso, id, updatedIso) {
  const now = Date.now();
  const created = Date.parse(String(createdIso || ''));
  if (Number.isFinite(created) && created <= now) return new Date(created).toISOString();
  const stamp = Number(/^[a-z]+-(\d{13})-/.exec(String(id || ''))?.[1]);
  if (Number.isFinite(stamp) && stamp > 0 && stamp <= now) return new Date(stamp).toISOString();
  const updated = Date.parse(String(updatedIso || ''));
  if (Number.isFinite(updated) && updated <= now) return new Date(updated).toISOString();
  return new Date(now).toISOString();
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
    createdAt: sanitizeCreatedAt(toIso(row.created_at), row.id, toIso(row.updated_at)),
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
    ${latestByIdCte(OBSERVATIONS_TABLE)}
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
    ${latestByIdCte(OBSERVATIONS_TABLE, 'WHERE id = {id:String}')}
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
  // Stamp the tombstone with ClickHouse now64() (server TZ). JSONEachRow +
  // toISOString() writes UTC wall-clock, ~3h behind Europe/Moscow now64 values,
  // so the live row stays "latest" and the observation comes back after DELETE.
  await executeCommand(`
    INSERT INTO ${config.database}.${OBSERVATIONS_TABLE}
    (
      id, owner_id, is_shared, name, description, folder, lookback,
      filters_json, widgets_json, live_json, materialize_json, report_json,
      deleted, created_at, updated_at
    )
    SELECT
      id,
      owner_id,
      is_shared,
      name,
      description,
      folder,
      lookback,
      filters_json,
      widgets_json,
      live_json,
      materialize_json,
      report_json,
      1,
      created_at,
      if(
        updated_at >= now64(3),
        updated_at + INTERVAL 1 MILLISECOND,
        now64(3)
      )
    FROM (
      SELECT
        *,
        row_number() OVER (
          PARTITION BY id
          ORDER BY updated_at DESC, deleted DESC
        ) AS rn
      FROM ${config.database}.${OBSERVATIONS_TABLE}
      WHERE id = {id:String}
    )
    WHERE rn = 1
  `, { id: String(item.id) }, { name: 'observations/soft-delete' });
}

async function loadRunsForObservation(observationId) {
  await ensureObservationsStore();
  const { rows } = await query(`
    ${latestByIdCte(RUNS_TABLE, 'WHERE observation_id = {id:String}')}
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
    ${latestByIdCte(RUNS_TABLE, 'WHERE observation_id = {obsId:String} AND id = {runId:String}')}
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
  naiveChToIso,
  sanitizeCreatedAt,
};
