'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const LAYOUT_VERSION = 1;
const MAX_LAYOUT_BYTES = 32 * 1024;
const MAX_OBSERVATION_IDS = 500;

const DEFAULT_LAYOUT = {
  version: LAYOUT_VERSION,
  observationIds: [],
  hiddenObservationIds: [],
};

let db = null;
let testDbPath = null;

function getDbPath() {
  if (testDbPath) return testDbPath;
  return process.env.OBSERVATIONS_BOARD_LAYOUTS_DB
    || path.join(__dirname, 'data', 'observations-board-layouts.db');
}

function normalizeObservationIds(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    const id = String(item || '').trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
    if (out.length >= MAX_OBSERVATION_IDS) break;
  }
  return out;
}

function validateLayout(layout) {
  if (!layout || typeof layout !== 'object') {
    const err = new Error('Некорректная раскладка');
    err.statusCode = 400;
    throw err;
  }

  const observationIds = normalizeObservationIds(layout.observationIds);
  const orderedIds = new Set(observationIds);
  const hiddenObservationIds = normalizeObservationIds(layout.hiddenObservationIds)
    .filter((id) => orderedIds.has(id));
  const normalized = {
    version: LAYOUT_VERSION,
    observationIds,
    hiddenObservationIds,
  };

  const raw = JSON.stringify(normalized);
  if (Buffer.byteLength(raw, 'utf8') > MAX_LAYOUT_BYTES) {
    const err = new Error('Раскладка слишком большая');
    err.statusCode = 413;
    throw err;
  }

  if (Array.isArray(layout.observationIds)) {
    const input = layout.observationIds.map((x) => String(x || '').trim()).filter(Boolean);
    if (input.length !== new Set(input).size) {
      const err = new Error('Дублирующиеся id наблюдений');
      err.statusCode = 400;
      throw err;
    }
  }

  if (Array.isArray(layout.hiddenObservationIds)) {
    const input = layout.hiddenObservationIds.map((x) => String(x || '').trim()).filter(Boolean);
    if (input.length !== new Set(input).size) {
      const err = new Error('Дублирующиеся id скрытых наблюдений');
      err.statusCode = 400;
      throw err;
    }
  }

  return normalized;
}

function ensureStore() {
  if (db) return db;
  const dbPath = getDbPath();
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS observations_board_layouts (
      user_id TEXT PRIMARY KEY,
      layout_json TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);
  return db;
}

function parseStoredLayout(row) {
  if (!row) return null;
  let parsed;
  try {
    parsed = JSON.parse(String(row.layout_json || '{}'));
  } catch {
    return null;
  }
  return validateLayout(parsed);
}

function layoutStorageKey(userId, clientId = '') {
  const uid = String(userId || '').trim();
  const cid = String(clientId || '').trim();
  if (!uid) return '';
  if (!cid) return uid;
  return `cabinet:${cid}:u:${uid}`;
}

function getLayout(userId, clientId = '') {
  const id = layoutStorageKey(userId, clientId);
  if (!id) return null;
  ensureStore();
  const row = db.prepare(
    'SELECT layout_json, updated_at FROM observations_board_layouts WHERE user_id = ?',
  ).get(id);
  if (!row) return null;
  const layout = parseStoredLayout(row);
  if (!layout) return null;
  return {
    layout,
    updatedAt: Number(row.updated_at) || null,
  };
}

function putLayout(userId, layout, clientId = '') {
  const id = layoutStorageKey(userId, clientId);
  if (!id) {
    const err = new Error('userId обязателен');
    err.statusCode = 400;
    throw err;
  }
  const normalized = validateLayout(layout);
  const now = Date.now();
  ensureStore();
  db.prepare(`
    INSERT INTO observations_board_layouts (user_id, layout_json, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      layout_json = excluded.layout_json,
      updated_at = excluded.updated_at
  `).run(id, JSON.stringify(normalized), now);
  return { layout: normalized, updatedAt: now };
}

function resetStoreForTests(dbPath = null) {
  if (db) {
    try { db.close(); } catch { /* ignore */ }
  }
  db = null;
  testDbPath = dbPath;
}

module.exports = {
  LAYOUT_VERSION,
  DEFAULT_LAYOUT,
  validateLayout,
  normalizeObservationIds,
  layoutStorageKey,
  getLayout,
  putLayout,
  resetStoreForTests,
};
