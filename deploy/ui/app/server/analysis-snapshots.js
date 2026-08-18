'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { DatabaseSync } = require('node:sqlite');

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
const MAX_SNAPSHOTS_PER_USER = 50;
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const ALLOWED_KINDS = new Set(['explorer', 'dns-explorer']);

let db = null;
let cleanupTimer = null;
let testDbPath = null;

function getDbPath() {
  if (testDbPath) return testDbPath;
  return process.env.ANALYSIS_SNAPSHOTS_DB
    || path.join(__dirname, 'data', 'analysis-snapshots.db');
}

function gzipJson(value) {
  const raw = JSON.stringify(value);
  const bytes = Buffer.byteLength(raw, 'utf8');
  if (bytes > MAX_PAYLOAD_BYTES) {
    const err = new Error(
      `Snapshot слишком большой (${Math.round(bytes / 1024 / 1024)} МБ, максимум ${Math.round(MAX_PAYLOAD_BYTES / 1024 / 1024)} МБ)`,
    );
    err.statusCode = 413;
    throw err;
  }
  return { blob: zlib.gzipSync(raw), bytes };
}

function gunzipJson(blob) {
  const raw = zlib.gunzipSync(blob).toString('utf8');
  return JSON.parse(raw);
}

function newId() {
  return crypto.randomBytes(16).toString('hex');
}

function newToken() {
  return crypto.randomBytes(24).toString('base64url');
}

function cleanupExpired(now = Date.now()) {
  const database = ensureStore();
  database.prepare('DELETE FROM analysis_snapshots WHERE expires_at < ?').run(now);
}

function ensureStore() {
  if (db) return db;
  const dbPath = getDbPath();
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS analysis_snapshots (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      client_id TEXT,
      query_json BLOB NOT NULL,
      payload_json BLOB NOT NULL,
      payload_bytes INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      shared_at INTEGER,
      share_token TEXT UNIQUE
    );
    CREATE INDEX IF NOT EXISTS idx_snapshots_expires ON analysis_snapshots(expires_at);
    CREATE INDEX IF NOT EXISTS idx_snapshots_owner ON analysis_snapshots(owner_id, kind);
    CREATE INDEX IF NOT EXISTS idx_snapshots_token ON analysis_snapshots(share_token) WHERE share_token IS NOT NULL;
  `);
  cleanupExpired();
  if (!cleanupTimer) {
    cleanupTimer = setInterval(cleanupExpired, CLEANUP_INTERVAL_MS);
    if (typeof cleanupTimer.unref === 'function') cleanupTimer.unref();
  }
  return db;
}

function countActiveForUser(ownerId, kind) {
  const now = Date.now();
  const row = ensureStore().prepare(
    'SELECT COUNT(*) AS cnt FROM analysis_snapshots WHERE owner_id = ? AND kind = ? AND expires_at >= ?',
  ).get(ownerId, kind, now);
  return Number(row?.cnt) || 0;
}

function buildExplorerStoredQuery(body = {}, meta = {}) {
  const range = meta.windowFrom && meta.windowTo
    ? 'custom'
    : (body.range || body.timeRange || '1h');
  return {
    metric: body.metric,
    groupBy: body.groupBy || [],
    filters: body.filters || [],
    thresholds: body.thresholds || [],
    limit: body.limit,
    range,
    from: meta.windowFrom || body.from || null,
    to: meta.windowTo || body.to || null,
    windowAnchor: meta.windowAnchor || body.windowAnchor || null,
    collectorId: body.collectorId || null,
  };
}

function buildExplorerStoredPayload(data = {}, meta = {}, elapsedMs) {
  return {
    rows: data.rows || [],
    summary: data.summary || null,
    timeseries: data.timeseries || null,
    resultSeries: data.resultSeries || null,
    breakdowns: data.breakdowns || {},
    meta: meta || null,
    loadMs: null,
    serverMs: elapsedMs ?? meta?.elapsedMs ?? null,
  };
}

function buildDnsExplorerStoredQuery(body = {}, meta = {}) {
  const range = meta.from && meta.to
    ? 'custom'
    : (body.range || body.timeRange || '24h');
  return {
    metric: body.metric || meta.metric,
    groupBy: body.groupBy || meta.groupBy || [],
    filters: body.filters || [],
    limit: body.limit,
    range,
    from: meta.from || body.from || null,
    to: meta.to || body.to || null,
    collectorId: body.collectorId || null,
  };
}

function buildDnsExplorerStoredPayload(data = {}, meta = {}, elapsedMs) {
  return {
    rows: data.rows || [],
    timeseries: data.timeseries || [],
    resultSeries: data.resultSeries || null,
    meta: meta || null,
    loadMs: null,
    serverMs: elapsedMs ?? meta?.elapsedMs ?? null,
  };
}

function tryCreateSnapshot({
  kind,
  ownerId,
  clientId = null,
  query,
  payload,
}) {
  try {
    return createSnapshot({ kind, ownerId, clientId, query, payload });
  } catch (err) {
    console.warn(`[analysis-snapshots] save failed (${kind}): ${err.message}`);
    return null;
  }
}

function createSnapshot({
  kind,
  ownerId,
  clientId = null,
  query,
  payload,
}) {
  if (!ALLOWED_KINDS.has(kind)) {
    const err = new Error('Неподдерживаемый тип snapshot');
    err.statusCode = 400;
    throw err;
  }
  if (!ownerId) {
    const err = new Error('Не указан владелец snapshot');
    err.statusCode = 400;
    throw err;
  }
  cleanupExpired();
  if (countActiveForUser(ownerId, kind) >= MAX_SNAPSHOTS_PER_USER) {
    const err = new Error('Достигнут лимит сохранённых результатов');
    err.statusCode = 429;
    throw err;
  }
  const { blob: payloadBlob, bytes: payloadBytes } = gzipJson(payload);
  const { blob: queryBlob } = gzipJson(query);
  const id = newId();
  const now = Date.now();
  const expiresAt = now + DEFAULT_TTL_MS;
  ensureStore().prepare(`
    INSERT INTO analysis_snapshots (
      id, kind, owner_id, client_id, query_json, payload_json, payload_bytes,
      created_at, expires_at, shared_at, share_token
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
  `).run(
    id,
    kind,
    ownerId,
    clientId || null,
    queryBlob,
    payloadBlob,
    payloadBytes,
    now,
    expiresAt,
  );
  return {
    id,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
  };
}

function getSnapshotRow(id, { kind } = {}) {
  cleanupExpired();
  const row = ensureStore().prepare('SELECT * FROM analysis_snapshots WHERE id = ?').get(id);
  if (!row) return null;
  if (kind && row.kind !== kind) return null;
  if (row.expires_at < Date.now()) return { expired: true, row };
  return row;
}

function shareSnapshot(id, ownerId, { kind } = {}) {
  const row = getSnapshotRow(id, { kind });
  if (!row) {
    const err = new Error('Snapshot не найден');
    err.statusCode = 404;
    throw err;
  }
  if (row.expired) {
    const err = new Error('Срок действия snapshot истёк');
    err.statusCode = 410;
    throw err;
  }
  if (row.owner_id !== ownerId) {
    const err = new Error('Недостаточно прав');
    err.statusCode = 403;
    throw err;
  }
  const expiresAt = row.created_at + DEFAULT_TTL_MS;
  if (expiresAt < Date.now()) {
    const err = new Error('Срок действия snapshot истёк');
    err.statusCode = 410;
    throw err;
  }
  const now = Date.now();
  if (row.share_token) {
    ensureStore().prepare('UPDATE analysis_snapshots SET expires_at = ? WHERE id = ?').run(expiresAt, id);
    return {
      token: row.share_token,
      expiresAt: new Date(expiresAt).toISOString(),
      sharedAt: row.shared_at ? new Date(row.shared_at).toISOString() : new Date(now).toISOString(),
    };
  }
  const token = newToken();
  ensureStore().prepare(
    'UPDATE analysis_snapshots SET share_token = ?, shared_at = ?, expires_at = ? WHERE id = ?',
  ).run(token, now, expiresAt, id);
  return {
    token,
    expiresAt: new Date(expiresAt).toISOString(),
    sharedAt: new Date(now).toISOString(),
  };
}

function revokeShare(id, ownerId, { kind } = {}) {
  const row = getSnapshotRow(id, { kind });
  if (!row || row.expired) {
    const err = new Error('Snapshot не найден');
    err.statusCode = 404;
    throw err;
  }
  if (row.owner_id !== ownerId) {
    const err = new Error('Недостаточно прав');
    err.statusCode = 403;
    throw err;
  }
  ensureStore().prepare(
    'UPDATE analysis_snapshots SET share_token = NULL, shared_at = NULL WHERE id = ?',
  ).run(id);
  return { ok: true };
}

function assertReaderClientScope(row, readerClientId) {
  const readerId = String(readerClientId || '').trim();
  const snapshotClientId = String(row.client_id || '').trim();
  if (readerId !== snapshotClientId) {
    const err = new Error('Недостаточно прав');
    err.statusCode = 403;
    throw err;
  }
}

function getActiveShareLinkStats(now = Date.now()) {
  cleanupExpired(now);
  const database = ensureStore();
  const activeWhere = 'share_token IS NOT NULL AND expires_at >= ?';
  const totalRow = database.prepare(
    `SELECT COUNT(*) AS cnt FROM analysis_snapshots WHERE ${activeWhere}`,
  ).get(now);
  const kindRows = database.prepare(
    `SELECT kind, COUNT(*) AS cnt FROM analysis_snapshots WHERE ${activeWhere} GROUP BY kind`,
  ).all(now);
  const oldestRow = database.prepare(
    `SELECT created_at, expires_at FROM analysis_snapshots WHERE ${activeWhere} ORDER BY created_at ASC LIMIT 1`,
  ).get(now);
  const byKind = Object.fromEntries(kindRows.map((row) => [row.kind, Number(row.cnt) || 0]));
  return {
    total: Number(totalRow?.cnt) || 0,
    explorer: byKind.explorer || 0,
    dnsExplorer: byKind['dns-explorer'] || 0,
    oldest: oldestRow ? {
      createdAt: new Date(oldestRow.created_at).toISOString(),
      expiresAt: new Date(oldestRow.expires_at).toISOString(),
      expiresInMs: Math.max(0, oldestRow.expires_at - now),
      expiresInSec: Math.max(0, Math.floor((oldestRow.expires_at - now) / 1000)),
    } : null,
    checkedAt: new Date(now).toISOString(),
  };
}

function getSharedSnapshot(token, { kind, readerClientId = null, readerUserId = null } = {}) {
  const row = ensureStore().prepare(
    'SELECT * FROM analysis_snapshots WHERE share_token = ? AND kind = ?',
  ).get(token, kind);
  if (!row) {
    const err = new Error('Ссылка не найдена или отозвана');
    err.statusCode = 404;
    throw err;
  }
  if (row.expires_at < Date.now()) {
    cleanupExpired();
    const err = new Error('Срок действия ссылки истёк');
    err.statusCode = 410;
    throw err;
  }
  assertReaderClientScope(row, readerClientId);
  if (readerUserId) {
    console.log(
      `[analysis-snapshots] shared read kind=${kind} snapshot=${row.id} user=${readerUserId}`,
    );
  }
  return {
    query: gunzipJson(row.query_json),
    payload: gunzipJson(row.payload_json),
    meta: {
      id: row.id,
      kind: row.kind,
      ownerId: row.owner_id,
      clientId: row.client_id || null,
      createdAt: new Date(row.created_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString(),
      sharedAt: row.shared_at ? new Date(row.shared_at).toISOString() : null,
    },
  };
}

function closeStore() {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
  if (db) {
    db.close();
    db = null;
  }
}

function resetStoreForTests(dbPath) {
  closeStore();
  testDbPath = dbPath || null;
  if (dbPath && fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
}

module.exports = {
  ALLOWED_KINDS,
  DEFAULT_TTL_MS,
  MAX_PAYLOAD_BYTES,
  MAX_SNAPSHOTS_PER_USER,
  ensureStore,
  cleanupExpired,
  createSnapshot,
  tryCreateSnapshot,
  shareSnapshot,
  revokeShare,
  getSharedSnapshot,
  getActiveShareLinkStats,
  buildExplorerStoredQuery,
  buildExplorerStoredPayload,
  buildDnsExplorerStoredQuery,
  buildDnsExplorerStoredPayload,
  closeStore,
  resetStoreForTests,
  getDbPath,
};
