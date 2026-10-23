'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DEFAULT_TOKEN_TTL_SEC = 3600;
const DEFAULT_CLEANUP_INTERVAL_MS = 15 * 60 * 1000;
// Как часто счётчики «Монитора» сбрасываются из памяти в SQLite (на запрос ERP
// записи нет — dirty-статистика живёт в памяти и флешится не чаще этого интервала).
const DEFAULT_STATS_FLUSH_MS = 60 * 1000;

function defaultStatsDayKey(date = new Date()) {
  // «Сутки» статистики считаем по Москве — как и весь вывод времени в UI.
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Moscow',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(date);
}

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
  statsFlushIntervalMs = DEFAULT_STATS_FLUSH_MS,
  statsDayKeyFn = defaultStatsDayKey,
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
    CREATE TABLE IF NOT EXISTS api_client_stats (
      client_id TEXT PRIMARY KEY,
      last_used_at INTEGER NOT NULL DEFAULT 0,
      stats_day TEXT NOT NULL DEFAULT '',
      tokens_issued_today INTEGER NOT NULL DEFAULT 0,
      requests_today INTEGER NOT NULL DEFAULT 0
    );
  `);

  const select = db.prepare('SELECT client_id, expires_at FROM api_tokens WHERE token = ?');
  const insert = db.prepare(
    'INSERT INTO api_tokens (token, client_id, expires_at) VALUES (?, ?, ?)',
  );
  const remove = db.prepare('DELETE FROM api_tokens WHERE token = ?');
  const removeExpired = db.prepare('DELETE FROM api_tokens WHERE expires_at < ?');
  const removeByClient = db.prepare('DELETE FROM api_tokens WHERE client_id = ?');
  const listActive = db.prepare(
    `SELECT client_id, count() AS count, min(expires_at) AS expires_soonest
     FROM api_tokens WHERE expires_at > ? GROUP BY client_id`,
  );
  const selectStats = db.prepare(
    'SELECT last_used_at, stats_day, tokens_issued_today, requests_today FROM api_client_stats WHERE client_id = ?',
  );
  const upsertStats = db.prepare(
    `INSERT INTO api_client_stats (client_id, last_used_at, stats_day, tokens_issued_today, requests_today)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(client_id) DO UPDATE SET
       last_used_at = excluded.last_used_at,
       stats_day = excluded.stats_day,
       tokens_issued_today = excluded.tokens_issued_today,
       requests_today = excluded.requests_today`,
  );

  // Счётчики «Монитора»: копятся в памяти, во флеш уходят не чаще
  // statsFlushIntervalMs на клиента. Рестарт теряет не более минуты статистики.
  const statsCache = new Map();

  function loadStats(clientId) {
    const cached = statsCache.get(clientId);
    if (cached) return cached;
    const row = selectStats.get(clientId);
    const dayKey = statsDayKeyFn();
    const sameDay = row && row.stats_day === dayKey;
    const entry = {
      lastUsedAt: row ? Number(row.last_used_at) || 0 : 0,
      dayKey,
      tokensIssued: sameDay ? Number(row.tokens_issued_today) || 0 : 0,
      requests: sameDay ? Number(row.requests_today) || 0 : 0,
      dirty: false,
      lastFlushAt: Date.now(),
    };
    statsCache.set(clientId, entry);
    return entry;
  }

  function flushStatsEntry(clientId, entry) {
    upsertStats.run(clientId, entry.lastUsedAt, entry.dayKey, entry.tokensIssued, entry.requests);
    entry.dirty = false;
    entry.lastFlushAt = Date.now();
  }

  function rolloverIfNeeded(entry) {
    const dayKey = statsDayKeyFn();
    if (entry.dayKey !== dayKey) {
      entry.dayKey = dayKey;
      entry.tokensIssued = 0;
      entry.requests = 0;
    }
  }

  function touchStats(clientId, kind) {
    const entry = loadStats(clientId);
    rolloverIfNeeded(entry);
    entry.lastUsedAt = Date.now();
    if (kind === 'issue') entry.tokensIssued += 1;
    else entry.requests += 1;
    entry.dirty = true;
    if (Date.now() - entry.lastFlushAt >= statsFlushIntervalMs) {
      flushStatsEntry(clientId, entry);
    }
  }

  function flushAllStats() {
    for (const [clientId, entry] of statsCache) {
      if (entry.dirty) flushStatsEntry(clientId, entry);
    }
  }

  const store = {
    ttlSec,

    issue(clientId, { ttlSec: ttlOverride, skipStats } = {}) {
      const id = String(clientId || '');
      if (!id) throw new TypeError('client_id обязателен для выпуска токена');
      const ttl = Number.isFinite(ttlOverride)
        ? Math.floor(ttlOverride)
        : ttlSec;
      const token = generateToken();
      const expiresAt = Date.now() + ttl * 1000;
      insert.run(token, id, expiresAt);
      // skipStats — для самотеста «Монитора»: тестовый токен не должен
      // накручивать счётчик «обменов токеном» за сутки.
      if (!skipStats) touchStats(id, 'issue');
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
      touchStats(String(row.client_id), 'request');
      return { clientId: String(row.client_id), expiresAt: Number(row.expires_at) };
    },

    listActiveTokens() {
      return listActive.all(Date.now()).map((row) => ({
        clientId: String(row.client_id),
        count: Number(row.count),
        expiresSoonestAt: Number(row.expires_soonest),
      }));
    },

    getClientStats(clientIds) {
      const result = {};
      for (const raw of clientIds ?? []) {
        const clientId = String(raw || '');
        if (!clientId) continue;
        const entry = loadStats(clientId);
        rolloverIfNeeded(entry);
        result[clientId] = {
          lastUsedAt: entry.lastUsedAt || null,
          tokensIssuedToday: entry.tokensIssued,
          requestsToday: entry.requests,
        };
      }
      return result;
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
      flushAllStats();
      db.close();
    },
  };

  store.cleanupExpired();
  const cleanupTimer = cleanupIntervalMs > 0
    ? setInterval(() => {
        store.cleanupExpired();
        flushAllStats();
      }, cleanupIntervalMs)
    : null;
  if (typeof cleanupTimer?.unref === 'function') cleanupTimer.unref();

  return store;
}

module.exports = {
  createApiTokenStore,
  defaultDbPath,
  defaultTtlSec,
  defaultStatsDayKey,
  DEFAULT_TOKEN_TTL_SEC,
};
