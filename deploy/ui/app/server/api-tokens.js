'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DEFAULT_TOKEN_TTL_SEC = 3600;
const DEFAULT_CLEANUP_INTERVAL_MS = 15 * 60 * 1000;

function defaultDbPath() {
  return process.env.API_TOKENS_DB_PATH
    || path.join(__dirname, 'data', 'api-tokens.db');
}

function defaultTtlSec() {
  const raw = Number(process.env.API_TOKEN_TTL_SEC);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : DEFAULT_TOKEN_TTL_SEC;
}

function generateToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function createApiTokenStore({
  dbPath = defaultDbPath(),
  cleanupIntervalMs = DEFAULT_CLEANUP_INTERVAL_MS,
  ttlSec = defaultTtlSec(),
} = {}) {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS api_tokens (
      token TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_api_tokens_expires ON api_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS idx_api_tokens_client ON api_tokens(client_id);
  `);

  const select = db.prepare('SELECT client_id, expires_at FROM api_tokens WHERE token = ?');
  const insert = db.prepare(
    'INSERT INTO api_tokens (token, client_id, expires_at) VALUES (?, ?, ?)',
  );
  const remove = db.prepare('DELETE FROM api_tokens WHERE token = ?');
  const removeExpired = db.prepare('DELETE FROM api_tokens WHERE expires_at < ?');
  const removeByClient = db.prepare('DELETE FROM api_tokens WHERE client_id = ?');

  const store = {
    ttlSec,

    issue(clientId, { ttlSec: ttlOverride } = {}) {
      const id = String(clientId || '');
      if (!id) throw new TypeError('client_id обязателен для выпуска токена');
      const ttl = Number.isFinite(ttlOverride)
        ? Math.floor(ttlOverride)
        : ttlSec;
      const token = generateToken();
      const expiresAt = Date.now() + ttl * 1000;
      insert.run(token, id, expiresAt);
      return { token, clientId: id, expiresAt };
    },

    verify(token) {
      const value = String(token || '');
      if (!value) return null;
      const row = select.get(value);
      if (!row) return null;
      if (Number(row.expires_at) <= Date.now()) {
        remove.run(value);
        return null;
      }
      return { clientId: String(row.client_id), expiresAt: Number(row.expires_at) };
    },

    revoke(token) {
      if (!token) return false;
      return remove.run(String(token)).changes > 0;
    },

    revokeByClientId(clientId) {
      const id = String(clientId || '');
      if (!id) return 0;
      return removeByClient.run(id).changes;
    },

    cleanupExpired(now = Date.now()) {
      return removeExpired.run(Number(now)).changes;
    },

    close() {
      if (cleanupTimer) clearInterval(cleanupTimer);
      db.close();
    },
  };

  store.cleanupExpired();
  const cleanupTimer = cleanupIntervalMs > 0
    ? setInterval(() => store.cleanupExpired(), cleanupIntervalMs)
    : null;
  if (typeof cleanupTimer?.unref === 'function') cleanupTimer.unref();

  return store;
}

module.exports = {
  createApiTokenStore,
  defaultDbPath,
  defaultTtlSec,
  DEFAULT_TOKEN_TTL_SEC,
};
