'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DEFAULT_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

function defaultDbPath() {
  return process.env.SESSIONS_DB_PATH
    || path.join(__dirname, 'data', 'sessions.db');
}

function parseImpersonation(raw) {
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function createSessionStore({
  dbPath = defaultDbPath(),
  cleanupIntervalMs = DEFAULT_CLEANUP_INTERVAL_MS,
} = {}) {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      impersonation_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
  `);

  const select = db.prepare(
    'SELECT user_id, expires_at, impersonation_json FROM sessions WHERE id = ?',
  );
  const upsert = db.prepare(`
    INSERT INTO sessions (id, user_id, expires_at, impersonation_json)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      user_id = excluded.user_id,
      expires_at = excluded.expires_at,
      impersonation_json = excluded.impersonation_json
  `);
  const remove = db.prepare('DELETE FROM sessions WHERE id = ?');
  const removeExpired = db.prepare('DELETE FROM sessions WHERE expires_at < ?');

  const store = {
    get(sessionId) {
      if (!sessionId) return undefined;
      const row = select.get(String(sessionId));
      if (!row) return undefined;
      const record = {
        userId: String(row.user_id),
        expiresAt: Number(row.expires_at),
      };
      const impersonation = parseImpersonation(row.impersonation_json);
      if (impersonation) record.impersonation = impersonation;
      return record;
    },

    set(sessionId, record) {
      const id = String(sessionId || '');
      const userId = String(record?.userId || '');
      const expiresAt = Number(record?.expiresAt);
      if (!id || !userId || !Number.isFinite(expiresAt)) {
        throw new TypeError('Некорректная запись сессии');
      }
      const impersonationJson = record.impersonation
        ? JSON.stringify(record.impersonation)
        : null;
      upsert.run(id, userId, expiresAt, impersonationJson);
      return store;
    },

    delete(sessionId) {
      if (!sessionId) return false;
      return remove.run(String(sessionId)).changes > 0;
    },

    cleanupExpired(now = Date.now()) {
      return removeExpired.run(Number(now)).changes;
    },

    deleteByUserIds(userIds = []) {
      const ids = [...new Set(userIds.map((id) => String(id || '')).filter(Boolean))];
      if (!ids.length) return 0;
      const placeholders = ids.map(() => '?').join(', ');
      const stmt = db.prepare(`DELETE FROM sessions WHERE user_id IN (${placeholders})`);
      return stmt.run(...ids).changes;
    },

    deleteByImpersonationClientId(clientId) {
      const targetId = String(clientId || '');
      if (!targetId) return 0;
      const rows = db.prepare(
        'SELECT id, impersonation_json FROM sessions WHERE impersonation_json IS NOT NULL',
      ).all();
      let removed = 0;
      for (const row of rows) {
        try {
          const impersonation = parseImpersonation(row.impersonation_json);
          if (impersonation?.clientId === targetId && remove.run(String(row.id)).changes > 0) {
            removed += 1;
          }
        } catch {
          // ignore malformed impersonation payloads
        }
      }
      return removed;
    },

    revokeClientSessions({ userIds = [], clientId } = {}) {
      let removed = store.deleteByUserIds(userIds);
      if (clientId) removed += store.deleteByImpersonationClientId(clientId);
      return removed;
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
  createSessionStore,
  defaultDbPath,
};
