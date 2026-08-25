'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { summarizeBody } = require('./logger');

const DEFAULT_TTL_MS = 3 * 24 * 60 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const MAX_BODY_CHARS = Math.min(Math.max(Number(process.env.FAILED_REQUESTS_MAX_BODY_CHARS) || 32_000, 1000), 200_000);
const MAX_SQL_CHARS = Math.min(Math.max(Number(process.env.FAILED_REQUESTS_MAX_SQL_CHARS) || 20_000, 500), 200_000);
const DEFAULT_MAX_ROWS = Math.min(Math.max(Number(process.env.FAILED_REQUESTS_MAX_ROWS) || 2000, 100), 20_000);

let db = null;
let cleanupTimer = null;
let testDbPath = null;

function getDbPath() {
  if (testDbPath) return testDbPath;
  return process.env.FAILED_REQUESTS_DB
    || path.join(__dirname, 'data', 'failed-requests.db');
}

function getTtlMs() {
  const raw = Number(process.env.FAILED_REQUESTS_TTL_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TTL_MS;
}

function getMaxRows() {
  const raw = Number(process.env.FAILED_REQUESTS_MAX_ROWS);
  return Number.isFinite(raw) && raw > 0 ? Math.min(raw, 20_000) : DEFAULT_MAX_ROWS;
}

function newId() {
  return crypto.randomBytes(16).toString('hex');
}

function truncateText(value, maxChars) {
  const text = String(value ?? '');
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}… (${text.length} chars)`;
}

function jsonOrNull(value, maxChars = MAX_BODY_CHARS) {
  if (value == null) return null;
  if (typeof value === 'string') {
    const text = value;
    if (text.length <= maxChars) return text;
    return JSON.stringify({ _truncated: true, preview: text.slice(0, maxChars - 120) });
  }
  try {
    const text = JSON.stringify(value);
    if (text.length <= maxChars) return text;
    return JSON.stringify({ _truncated: true, preview: text.slice(0, maxChars - 120) });
  } catch {
    return null;
  }
}

function parseJsonField(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function cleanupExpired(now = Date.now()) {
  const database = ensureStore();
  database.prepare('DELETE FROM failed_requests WHERE expires_at < ?').run(now);
}

function trimToMaxRows(maxRows = getMaxRows()) {
  const database = ensureStore();
  const row = database.prepare('SELECT COUNT(*) AS cnt FROM failed_requests').get();
  const total = Number(row?.cnt) || 0;
  if (total <= maxRows) return 0;
  const excess = total - maxRows;
  database.prepare(`
    DELETE FROM failed_requests
    WHERE id IN (
      SELECT id FROM failed_requests
      ORDER BY created_at ASC
      LIMIT ?
    )
  `).run(excess);
  return excess;
}

function ensureStore() {
  if (db) return db;
  const dbPath = getDbPath();
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS failed_requests (
      id TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      method TEXT NOT NULL,
      route TEXT NOT NULL,
      query_json TEXT,
      body_json TEXT,
      status_code INTEGER NOT NULL,
      error_message TEXT NOT NULL,
      user_id TEXT,
      elapsed_ms INTEGER,
      sql_name TEXT,
      sql_template TEXT,
      sql_params_json TEXT,
      sql_inlined TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_failed_expires ON failed_requests(expires_at);
    CREATE INDEX IF NOT EXISTS idx_failed_created ON failed_requests(created_at DESC);
  `);
  cleanupExpired();
  if (!cleanupTimer) {
    cleanupTimer = setInterval(() => {
      cleanupExpired();
      trimToMaxRows();
    }, CLEANUP_INTERVAL_MS);
    if (typeof cleanupTimer.unref === 'function') cleanupTimer.unref();
  }
  return db;
}

const SKIPPED_STATUS_CODES = new Set([401, 403]);

function shouldRecordFailedRequest(entry = {}) {
  const route = String(entry.route || '');
  if (route.startsWith('/api/diagnostics/failed-requests')) return false;
  const statusCode = Number(entry.statusCode) || 500;
  if (SKIPPED_STATUS_CODES.has(statusCode)) return false;
  return true;
}

function rowToItem(row) {
  return {
    id: row.id,
    at: new Date(row.created_at).toISOString(),
    expiresAt: new Date(row.expires_at).toISOString(),
    method: row.method,
    route: row.route,
    query: parseJsonField(row.query_json),
    body: parseJsonField(row.body_json),
    statusCode: row.status_code,
    error: row.error_message,
    userId: row.user_id || null,
    elapsedMs: row.elapsed_ms ?? null,
    sql: row.sql_template ? {
      name: row.sql_name || null,
      template: row.sql_template,
      params: parseJsonField(row.sql_params_json) || {},
      inlined: row.sql_inlined || '',
      error: null,
    } : null,
  };
}

function recordFailedRequest(entry = {}) {
  try {
    if (!shouldRecordFailedRequest(entry)) return null;

    const now = Date.now();
    const ttlMs = getTtlMs();
    const failedSql = entry.failedSql || null;
    const body = entry.body && typeof entry.body === 'object'
      ? summarizeBody(entry.body)
      : entry.body;

    ensureStore();
    cleanupExpired();

    const id = newId();
    const route = String(entry.route || '');
    ensureStore().prepare(`
      INSERT INTO failed_requests (
        id, created_at, expires_at, method, route, query_json, body_json,
        status_code, error_message, user_id, elapsed_ms,
        sql_name, sql_template, sql_params_json, sql_inlined
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      now,
      now + ttlMs,
      String(entry.method || 'GET').toUpperCase(),
      route,
      jsonOrNull(entry.query),
      jsonOrNull(body),
      Number(entry.statusCode) || 500,
      truncateText(entry.error || 'Unknown error', 4000),
      entry.userId ? String(entry.userId) : null,
      entry.elapsedMs != null ? Number(entry.elapsedMs) : null,
      failedSql?.name ? String(failedSql.name) : null,
      failedSql?.sql ? truncateText(failedSql.sql, MAX_SQL_CHARS) : null,
      failedSql?.params ? jsonOrNull(failedSql.params, MAX_BODY_CHARS) : null,
      failedSql?.sqlInlined ? truncateText(failedSql.sqlInlined, MAX_SQL_CHARS) : null,
    );

    trimToMaxRows();
    return id;
  } catch (err) {
    console.error('[Grapes · failed-requests] record error:', err?.message || err);
    return null;
  }
}

function listFailedRequests({ limit = 50, offset = 0 } = {}) {
  cleanupExpired();
  const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const safeOffset = Math.max(Number(offset) || 0, 0);
  const database = ensureStore();
  const totalRow = database.prepare(`
    SELECT COUNT(*) AS cnt
    FROM failed_requests
    WHERE status_code NOT IN (401, 403)
  `).get();
  const rows = database.prepare(`
    SELECT *
    FROM failed_requests
    WHERE status_code NOT IN (401, 403)
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(safeLimit, safeOffset);

  return {
    items: rows.map(rowToItem),
    total: Number(totalRow?.cnt) || 0,
    limit: safeLimit,
    offset: safeOffset,
    checkedAt: new Date().toISOString(),
    retentionDays: getTtlMs() / (24 * 60 * 60 * 1000),
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
  if (dbPath && dbPath !== ':memory:' && fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
}

module.exports = {
  DEFAULT_TTL_MS,
  ensureStore,
  cleanupExpired,
  trimToMaxRows,
  shouldRecordFailedRequest,
  recordFailedRequest,
  listFailedRequests,
  closeStore,
  resetStoreForTests,
  getDbPath,
  getTtlMs,
  getMaxRows,
};
