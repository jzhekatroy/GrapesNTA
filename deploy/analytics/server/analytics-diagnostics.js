'use strict';

const fs = require('fs');
const path = require('path');

const STORE_FILE = path.join(__dirname, 'data', 'analytics-diagnostics.json');
const MAX_QUERIES = Math.min(Math.max(Number(process.env.ANALYTICS_DIAG_MAX_QUERIES) || 80, 20), 200);
const STALE_SEC = Math.max(90, Number(process.env.ANALYTICS_WORKER_STALE_SEC) || 120);

function ensureDir() {
  const dir = path.dirname(STORE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
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

function markWorkerStart(mode = 'loop') {
  const now = new Date().toISOString();
  writeState((s) => {
    s.worker = {
      ...s.worker,
      pid: process.pid,
      startedAt: now,
      lastHeartbeatAt: now,
      mode,
      lastError: null,
    };
  });
}

function markHeartbeat() {
  const now = new Date().toISOString();
  writeState((s) => {
    s.worker.lastHeartbeatAt = now;
    if (!s.worker.startedAt) s.worker.startedAt = now;
    if (!s.worker.pid) s.worker.pid = process.pid;
  });
}

function recordTick({ rollup, reports, elapsedMs, error = null }) {
  const now = new Date().toISOString();
  writeState((s) => {
    s.worker.lastTickAt = now;
    s.worker.lastHeartbeatAt = now;
    s.worker.lastTickMs = elapsedMs;
    s.worker.lastError = error;
    s.lastTick = {
      at: now,
      elapsedMs,
      rollup: rollup || [],
      reports: reports || null,
      error,
    };
  });
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
  if (ageSec <= STALE_SEC) return { alive: true, ageSec };
  return { alive: false, ageSec, reason: `нет heartbeat ${ageSec}с` };
}

function getDiagnosticsPayload() {
  const state = readState();
  const alive = workerAlive(state);
  return {
    worker: {
      ...state.worker,
      alive: alive.alive,
      heartbeatAgeSec: alive.ageSec ?? null,
      staleAfterSec: STALE_SEC,
      status: alive.alive ? 'running' : (state.worker.lastHeartbeatAt ? 'stale' : 'offline'),
      statusReason: alive.reason || null,
    },
    lastTick: state.lastTick,
    queries: state.queries,
    storePath: 'server/data/analytics-diagnostics.json',
    updatedAt: new Date().toISOString(),
  };
}

module.exports = {
  markWorkerStart,
  markHeartbeat,
  recordTick,
  recordQuery,
  getDiagnosticsPayload,
  workerAlive,
  STORE_FILE,
};
