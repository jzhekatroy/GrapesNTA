'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const {
  createSnapshot,
  shareSnapshot,
  revokeShare,
  getSharedSnapshot,
  getActiveShareLinkStats,
  cleanupExpired,
  resetStoreForTests,
  ensureStore,
  DEFAULT_TTL_MS,
  MAX_PAYLOAD_BYTES,
  MAX_SNAPSHOTS_PER_USER,
  buildExplorerStoredQuery,
  buildExplorerStoredPayload,
  buildDnsExplorerStoredQuery,
  buildDnsExplorerStoredPayload,
} = require('./analysis-snapshots');

function tempDbPath(name) {
  return path.join(os.tmpdir(), `grapes-snapshots-${name}-${process.pid}-${Date.now()}.db`);
}

function sampleExplorerPayload(extraRows = 0) {
  const rows = [{ id: 'row-1', values: ['10.0.0.1'], metric: 100 }];
  for (let i = 0; i < extraRows; i += 1) {
    rows.push({ id: `row-${i + 2}`, values: [`10.0.0.${i + 2}`], metric: i });
  }
  return {
    rows,
    summary: { totalBytes: 1000 },
    timeseries: [{ bucket: '2026-01-01T00:00:00Z', value: 1 }],
    resultSeries: null,
    breakdowns: {},
    meta: { windowFrom: '2026-01-01T00:00:00Z', windowTo: '2026-01-01T01:00:00Z' },
    loadMs: null,
    serverMs: 12,
  };
}

test.afterEach(() => {
  resetStoreForTests();
});

test('gzip round-trip stores and restores explorer snapshot', () => {
  const dbPath = tempDbPath('roundtrip');
  resetStoreForTests(dbPath);
  const query = buildExplorerStoredQuery(
    { metric: 'bps', groupBy: ['src_ip'], filters: [], range: '1h', limit: 25 },
    { windowFrom: '2026-01-01T00:00:00Z', windowTo: '2026-01-01T01:00:00Z' },
  );
  const payload = buildExplorerStoredPayload(sampleExplorerPayload(), { elapsedMs: 15 }, 15);
  const created = createSnapshot({
    kind: 'explorer',
    ownerId: 'user-1',
    query,
    payload,
  });
  assert.ok(created.id);
  const shared = shareSnapshot(created.id, 'user-1', { kind: 'explorer' });
  assert.ok(shared.token);
  const loaded = getSharedSnapshot(shared.token, { kind: 'explorer', readerUserId: 'user-2' });
  assert.deepEqual(loaded.query, query);
  assert.deepEqual(loaded.payload.rows, payload.rows);
  assert.equal(loaded.meta.ownerId, 'user-1');
});

test('share extends TTL to 24h from creation and reuses token', () => {
  const dbPath = tempDbPath('share-ttl');
  resetStoreForTests(dbPath);
  const created = createSnapshot({
    kind: 'dns-explorer',
    ownerId: 'owner',
    query: buildDnsExplorerStoredQuery({ metric: 'queries_per_sec', groupBy: [], filters: [], range: '24h' }, {}),
    payload: buildDnsExplorerStoredPayload({ rows: [], timeseries: [] }, { elapsedMs: 1 }, 1),
  });
  const first = shareSnapshot(created.id, 'owner', { kind: 'dns-explorer' });
  const second = shareSnapshot(created.id, 'owner', { kind: 'dns-explorer' });
  assert.equal(first.token, second.token);
  const expiresMs = new Date(second.expiresAt).getTime();
  const createdMs = new Date(created.createdAt).getTime();
  assert.equal(expiresMs - createdMs, DEFAULT_TTL_MS);
});

test('revoke share makes token unreadable', () => {
  const dbPath = tempDbPath('revoke');
  resetStoreForTests(dbPath);
  const created = createSnapshot({
    kind: 'explorer',
    ownerId: 'owner',
    query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
    payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
  });
  const shared = shareSnapshot(created.id, 'owner', { kind: 'explorer' });
  revokeShare(created.id, 'owner', { kind: 'explorer' });
  assert.throws(
    () => getSharedSnapshot(shared.token, { kind: 'explorer' }),
    (err) => err.statusCode === 404,
  );
});

test('expired snapshots return 410 on read', () => {
  const dbPath = tempDbPath('expired');
  resetStoreForTests(dbPath);
  const created = createSnapshot({
    kind: 'explorer',
    ownerId: 'owner',
    query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
    payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
  });
  const shared = shareSnapshot(created.id, 'owner', { kind: 'explorer' });
  ensureStore().prepare('UPDATE analysis_snapshots SET expires_at = ? WHERE id = ?').run(Date.now() - 1000, created.id);
  assert.throws(
    () => getSharedSnapshot(shared.token, { kind: 'explorer' }),
    (err) => err.statusCode === 410,
  );
});

test('enforces per-user snapshot limit', () => {
  const dbPath = tempDbPath('limit');
  resetStoreForTests(dbPath);
  for (let i = 0; i < MAX_SNAPSHOTS_PER_USER; i += 1) {
    createSnapshot({
      kind: 'explorer',
      ownerId: 'heavy-user',
      query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
      payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
    });
  }
  assert.throws(
    () => createSnapshot({
      kind: 'explorer',
      ownerId: 'heavy-user',
      query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
      payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
    }),
    (err) => err.statusCode === 429,
  );
});

test('rejects oversized payload', () => {
  const dbPath = tempDbPath('oversized');
  resetStoreForTests(dbPath);
  const huge = 'x'.repeat(MAX_PAYLOAD_BYTES + 1);
  assert.throws(
    () => createSnapshot({
      kind: 'explorer',
      ownerId: 'owner',
      query: { metric: 'bps' },
      payload: { rows: [{ id: '1', blob: huge }] },
    }),
    (err) => err.statusCode === 413,
  );
});

test('share tokens are unique across snapshots', () => {
  const dbPath = tempDbPath('tokens');
  resetStoreForTests(dbPath);
  const ids = [];
  const tokens = new Set();
  for (let i = 0; i < 5; i += 1) {
    const created = createSnapshot({
      kind: 'explorer',
      ownerId: 'owner',
      query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
      payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
    });
    ids.push(created.id);
  }
  for (const id of ids) {
    const shared = shareSnapshot(id, 'owner', { kind: 'explorer' });
    assert.ok(!tokens.has(shared.token));
    tokens.add(shared.token);
  }
});

test('client scoped snapshots require matching reader clientId', () => {
  const dbPath = tempDbPath('client-scope');
  resetStoreForTests(dbPath);
  const created = createSnapshot({
    kind: 'explorer',
    ownerId: 'owner',
    clientId: 'client:demo',
    query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
    payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
  });
  const shared = shareSnapshot(created.id, 'owner', { kind: 'explorer' });
  assert.throws(
    () => getSharedSnapshot(shared.token, { kind: 'explorer', readerClientId: 'client:other' }),
    (err) => err.statusCode === 403,
  );
  const loaded = getSharedSnapshot(shared.token, {
    kind: 'explorer',
    readerClientId: 'client:demo',
  });
  assert.equal(loaded.meta.clientId, 'client:demo');
});

test('foreign owner cannot share snapshot', () => {
  const dbPath = tempDbPath('foreign-owner');
  resetStoreForTests(dbPath);
  const created = createSnapshot({
    kind: 'explorer',
    ownerId: 'owner',
    query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
    payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
  });
  assert.throws(
    () => shareSnapshot(created.id, 'intruder', { kind: 'explorer' }),
    (err) => err.statusCode === 403,
  );
});

test('explorer and dns-explorer tokens do not cross-read', () => {
  const dbPath = tempDbPath('kind-separation');
  resetStoreForTests(dbPath);
  const created = createSnapshot({
    kind: 'dns-explorer',
    ownerId: 'owner',
    query: buildDnsExplorerStoredQuery({ metric: 'queries_per_sec', groupBy: [], filters: [], range: '24h' }, {}),
    payload: buildDnsExplorerStoredPayload({ rows: [], timeseries: [] }, {}, 1),
  });
  const shared = shareSnapshot(created.id, 'owner', { kind: 'dns-explorer' });
  assert.throws(
    () => getSharedSnapshot(shared.token, { kind: 'explorer' }),
    (err) => err.statusCode === 404,
  );
});

test('getActiveShareLinkStats counts only published non-expired links', () => {
  const dbPath = tempDbPath('active-stats');
  resetStoreForTests(dbPath);
  const explorer = createSnapshot({
    kind: 'explorer',
    ownerId: 'owner',
    query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
    payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
  });
  createSnapshot({
    kind: 'dns-explorer',
    ownerId: 'owner',
    query: buildDnsExplorerStoredQuery({ metric: 'queries_per_sec', groupBy: [], filters: [], range: '24h' }, {}),
    payload: buildDnsExplorerStoredPayload({ rows: [], timeseries: [] }, {}, 1),
  });
  createSnapshot({
    kind: 'explorer',
    ownerId: 'owner',
    query: buildExplorerStoredQuery({ metric: 'bps', groupBy: [], filters: [], range: '1h' }, {}),
    payload: buildExplorerStoredPayload(sampleExplorerPayload(), {}, 1),
  });

  shareSnapshot(explorer.id, 'owner', { kind: 'explorer' });

  let stats = getActiveShareLinkStats();
  assert.equal(stats.total, 1);
  assert.equal(stats.explorer, 1);
  assert.equal(stats.dnsExplorer, 0);
  assert.ok(stats.oldest);
  assert.ok(stats.oldest.expiresInSec > 0);

  ensureStore().prepare(
    'UPDATE analysis_snapshots SET share_token = ?, shared_at = ? WHERE kind = ?',
  ).run('dns-token-1', Date.now(), 'dns-explorer');

  stats = getActiveShareLinkStats();
  assert.equal(stats.total, 2);
  assert.equal(stats.explorer, 1);
  assert.equal(stats.dnsExplorer, 1);
});

test('stored blobs are gzip compressed on disk', () => {
  const dbPath = tempDbPath('gzip-disk');
  resetStoreForTests(dbPath);
  createSnapshot({
    kind: 'explorer',
    ownerId: 'owner',
    query: buildExplorerStoredQuery({ metric: 'bps', groupBy: ['src_ip'], filters: [], range: '1h' }, {}),
    payload: buildExplorerStoredPayload(sampleExplorerPayload(10), {}, 1),
  });
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(dbPath);
  const row = db.prepare('SELECT payload_json FROM analysis_snapshots LIMIT 1').get();
  db.close();
  assert.ok(row?.payload_json);
  const decoded = JSON.parse(zlib.gunzipSync(row.payload_json).toString('utf8'));
  assert.ok(Array.isArray(decoded.rows));
  fs.unlinkSync(dbPath);
});
