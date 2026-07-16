'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const STORE_FILE = path.join(__dirname, 'data', 'analytics-diagnostics.json');
const MAX_QUERIES = Math.min(Math.max(Number(process.env.ANALYTICS_DIAG_MAX_QUERIES) || 80, 20), 200);
const STALE_SEC = Math.max(90, Number(process.env.ANALYTICS_WORKER_STALE_SEC) || 120);
const WORKER_ID = String(process.env.ANALYTICS_WORKER_ID || 'default');
const HEARTBEAT_TABLE = 'analytics_worker_status';

let ensureHeartbeatPromise = null;

function ensureDir() {
  const dir = path.dirname(STORE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

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

function defaultState() {
  return {
    worker: {
      pid: null,
      startedAt: null,
      lastHeartbeatAt: null,
      lastTickAt: null,
      lastTickMs: null,
      lastError: null,
      mode: 'loop',
      host: null,
      source: 'file',
    },
    lastTick: null,
    queries: [],
  };
}

function readState() {
  ensureDir();
  if (!fs.existsSync(STORE_FILE)) return defaultState();
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
    return {
      ...defaultState(),
      ...parsed,
      worker: { ...defaultState().worker, ...(parsed.worker || {}) },
      queries: Array.isArray(parsed.queries) ? parsed.queries : [],
    };
  } catch {
    return defaultState();
  }
}

function writeState(mutator) {
  const state = readState();
  mutator(state);
  ensureDir();
  fs.writeFileSync(STORE_FILE, JSON.stringify(state, null, 2));
}

async function ensureHeartbeatTable() {
  if (!ensureHeartbeatPromise) {
    ensureHeartbeatPromise = (async () => {
      const { executeCommand, config } = require('./clickhouse');
      await executeCommand(`
        CREATE TABLE IF NOT EXISTS ${config.database}.${HEARTBEAT_TABLE}
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
        ORDER BY worker_id
      `, {}, { name: 'analytics/ensure-heartbeat' });
    })().catch((err) => {
      ensureHeartbeatPromise = null;
      throw err;
    });
  }
  return ensureHeartbeatPromise;
}

function publishHeartbeatToClickHouse(state) {
  // Fire-and-forget — never block the worker loop on diagnostics.
  setImmediate(() => {
    (async () => {
      try {
        const { insertRows } = require('./clickhouse');
        await ensureHeartbeatTable();
        const w = state.worker || {};
        await insertRows(HEARTBEAT_TABLE, [{
          worker_id: WORKER_ID,
          host: String(w.host || os.hostname()),
          pid: Number(w.pid) || process.pid || 0,
          mode: String(w.mode || 'loop'),
          last_heartbeat_at: clickhouseDateTime(w.lastHeartbeatAt || new Date()),
          last_tick_at: w.lastTickAt ? clickhouseDateTime(w.lastTickAt) : null,
          last_tick_ms: w.lastTickMs != null ? Number(w.lastTickMs) : null,
          last_error: String(w.lastError || ''),
          started_at: w.startedAt ? clickhouseDateTime(w.startedAt) : null,
          payload_json: JSON.stringify(state.lastTick || {}),
          updated_at: clickhouseDateTime(),
        }], { name: 'analytics/heartbeat' });
      } catch {
        // ignore — local file still has the status for co-located UI
      }
    })();
  });
}

function markWorkerStart(mode = 'loop') {
  const now = new Date().toISOString();
  writeState((s) => {
    s.worker = {
      ...s.worker,
      pid: process.pid,
      host: os.hostname(),
      startedAt: now,
      lastHeartbeatAt: now,
      mode,
      lastError: null,
      source: 'file',
    };
  });
  publishHeartbeatToClickHouse(readState());
}

function markHeartbeat() {
  const now = new Date().toISOString();
  writeState((s) => {
    s.worker.lastHeartbeatAt = now;
    s.worker.host = s.worker.host || os.hostname();
    if (!s.worker.startedAt) s.worker.startedAt = now;
    if (!s.worker.pid) s.worker.pid = process.pid;
  });
  publishHeartbeatToClickHouse(readState());
}

function recordTick({ rollup, reports, elapsedMs, error = null }) {
  const now = new Date().toISOString();
  writeState((s) => {
    s.worker.lastTickAt = now;
    s.worker.lastHeartbeatAt = now;
    s.worker.lastTickMs = elapsedMs;
    s.worker.lastError = error;
    s.worker.host = s.worker.host || os.hostname();
    s.lastTick = {
      at: now,
      elapsedMs,
      rollup: rollup || [],
      reports: reports || null,
      error,
    };
  });
  publishHeartbeatToClickHouse(readState());
}

function recordQuery({
  name,
  sql,
  params = {},
  rows = 0,
  elapsedMs = 0,
  error = null,
  kind = 'query',
}) {
  const at = new Date().toISOString();
  writeState((s) => {
    const entry = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      at,
      name: name || 'query',
      kind,
      sql: String(sql || '').trim(),
      params: params && typeof params === 'object' ? params : {},
      rows: Number(rows) || 0,
      elapsedMs: Number(elapsedMs) || 0,
      error: error ? String(error) : null,
    };
    s.queries.unshift(entry);
    if (s.queries.length > MAX_QUERIES) s.queries.length = MAX_QUERIES;
    s.worker.lastHeartbeatAt = at;
  });
}

function workerAlive(state = readState(), now = Date.now()) {
  const hb = state.worker?.lastHeartbeatAt;
  if (!hb) return { alive: false, reason: 'нет heartbeat' };
  const ageSec = Math.floor((now - Date.parse(hb)) / 1000);
  if (!Number.isFinite(ageSec)) return { alive: false, reason: 'нет heartbeat' };
  if (ageSec <= STALE_SEC) return { alive: true, ageSec };
  return { alive: false, ageSec, reason: `нет heartbeat ${ageSec}с` };
}

function decorateWorker(state) {
  const alive = workerAlive(state);
  return {
    ...state.worker,
    alive: alive.alive,
    heartbeatAgeSec: alive.ageSec ?? null,
    staleAfterSec: STALE_SEC,
    status: alive.alive ? 'running' : (state.worker.lastHeartbeatAt ? 'stale' : 'offline'),
    statusReason: alive.reason || null,
  };
}

function getDiagnosticsPayload() {
  const state = readState();
  return {
    worker: decorateWorker(state),
    lastTick: state.lastTick,
    queries: state.queries,
    storePath: 'server/data/analytics-diagnostics.json',
    updatedAt: new Date().toISOString(),
  };
}

async function loadWorkerStatusFromClickHouse() {
  try {
    const { query, config } = require('./clickhouse');
    await ensureHeartbeatTable();
    const { rows } = await query(`
      WITH latest AS (
        SELECT
          *,
          row_number() OVER (PARTITION BY worker_id ORDER BY updated_at DESC) AS rn
        FROM ${config.database}.${HEARTBEAT_TABLE}
        WHERE worker_id = {id:String}
      )
      SELECT *
      FROM latest
      WHERE rn = 1
      LIMIT 1
    `, { id: WORKER_ID }, { name: 'analytics/heartbeat-read' });
    const row = rows[0];
    if (!row) return null;
    let lastTick = null;
    try {
      lastTick = row.payload_json ? JSON.parse(row.payload_json) : null;
    } catch {
      lastTick = null;
    }
    const state = {
      worker: {
        pid: Number(row.pid) || null,
        host: String(row.host || '') || null,
        startedAt: toIso(row.started_at),
        lastHeartbeatAt: toIso(row.last_heartbeat_at),
        lastTickAt: toIso(row.last_tick_at),
        lastTickMs: row.last_tick_ms != null ? Number(row.last_tick_ms) : null,
        lastError: String(row.last_error || '') || null,
        mode: String(row.mode || 'loop'),
        source: 'clickhouse',
      },
      lastTick,
      queries: [],
    };
    return {
      worker: decorateWorker(state),
      lastTick,
      queries: [],
      storePath: `clickhouse:${HEARTBEAT_TABLE}`,
      updatedAt: new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

/** Prefer fresh local file; otherwise use shared CH heartbeat (remote worker). */
async function getMergedDiagnosticsPayload() {
  const local = getDiagnosticsPayload();
  if (local.worker?.alive) return local;
  const remote = await loadWorkerStatusFromClickHouse();
  if (!remote) return local;
  if (!remote.worker?.lastHeartbeatAt) return local;
  const localAge = local.worker?.heartbeatAgeSec;
  const remoteAge = remote.worker?.heartbeatAgeSec;
  if (remote.worker.alive) return { ...local, ...remote, queries: local.queries };
  if (local.worker?.lastHeartbeatAt == null) return { ...local, ...remote, queries: local.queries };
  if (remoteAge != null && (localAge == null || remoteAge < localAge)) {
    return { ...local, ...remote, queries: local.queries };
  }
  return local;
}

module.exports = {
  markWorkerStart,
  markHeartbeat,
  recordTick,
  recordQuery,
  getDiagnosticsPayload,
  getMergedDiagnosticsPayload,
  loadWorkerStatusFromClickHouse,
  workerAlive,
  STORE_FILE,
  HEARTBEAT_TABLE,
  STALE_SEC,
};
