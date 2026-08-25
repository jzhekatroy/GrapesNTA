'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  shouldRecordFailedRequest,
  recordFailedRequest,
  listFailedRequests,
  cleanupExpired,
  resetStoreForTests,
  getTtlMs,
  getMaxRows,
} = require('./failed-requests');

function tempDbPath(name) {
  return path.join(os.tmpdir(), `grapes-failed-${name}-${process.pid}-${Date.now()}.db`);
}

test.afterEach(() => {
  resetStoreForTests();
});

test('recordFailedRequest stores API and SQL fields', () => {
  const dbPath = tempDbPath('record');
  resetStoreForTests(dbPath);

  const id = recordFailedRequest({
    method: 'POST',
    route: '/api/explorer/flows',
    query: { range: '1h' },
    body: { metric: 'bps', password: 'secret' },
    statusCode: 502,
    error: 'ClickHouse timeout',
    userId: 'user-1',
    elapsedMs: 1200,
    failedSql: {
      name: 'explorer/flows',
      sql: 'SELECT 1 WHERE id = {id:String}',
      params: { id: 'x' },
      sqlInlined: "SELECT 1 WHERE id = 'x'",
    },
  });

  assert.ok(id);
  const { items, total } = listFailedRequests({ limit: 10 });
  assert.equal(total, 1);
  assert.equal(items[0].method, 'POST');
  assert.equal(items[0].route, '/api/explorer/flows');
  assert.equal(items[0].statusCode, 502);
  assert.equal(items[0].body.password, '***');
  assert.equal(items[0].sql.name, 'explorer/flows');
  assert.equal(items[0].sql.inlined, "SELECT 1 WHERE id = 'x'");
});

test('shouldRecordFailedRequest skips auth and diagnostics routes', () => {
  assert.equal(shouldRecordFailedRequest({
    route: '/api/diagnostics/failed-requests?limit=10',
    statusCode: 500,
  }), false);
  assert.equal(shouldRecordFailedRequest({
    route: '/api/dashboard/traffic',
    statusCode: 401,
    error: 'Требуется авторизация',
  }), false);
  assert.equal(shouldRecordFailedRequest({
    route: '/api/explorer/flows',
    statusCode: 403,
    error: 'Недостаточно прав',
  }), false);
  assert.equal(shouldRecordFailedRequest({
    route: '/api/explorer/flows',
    statusCode: 502,
    error: 'ClickHouse timeout',
  }), true);
});

test('recordFailedRequest skips auth failures', () => {
  resetStoreForTests(':memory:');
  assert.equal(recordFailedRequest({
    route: '/api/dashboard/traffic',
    statusCode: 401,
    error: 'Требуется авторизация',
  }), null);
  assert.equal(recordFailedRequest({
    route: '/api/explorer/flows',
    statusCode: 403,
    error: 'Недостаточно прав',
  }), null);
  assert.equal(listFailedRequests().total, 0);
});

test('listFailedRequests hides stored auth failures', () => {
  resetStoreForTests(':memory:');
  const database = require('./failed-requests').ensureStore();
  const now = Date.now();
  database.prepare(`
    INSERT INTO failed_requests (
      id, created_at, expires_at, method, route, query_json, body_json,
      status_code, error_message, user_id, elapsed_ms,
      sql_name, sql_template, sql_params_json, sql_inlined
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'auth-old', now, now + 86400000, 'GET', '/api/x', null, null,
    401, 'Требуется авторизация', null, null, null, null, null, null,
  );
  recordFailedRequest({ route: '/api/y', statusCode: 502, error: 'boom' });
  const { items, total } = listFailedRequests();
  assert.equal(total, 1);
  assert.equal(items[0].route, '/api/y');
});

test('listFailedRequests supports pagination', () => {
  resetStoreForTests(':memory:');
  for (let i = 1; i <= 5; i += 1) {
    recordFailedRequest({ route: `/api/${i}`, statusCode: 502, error: String(i) });
  }
  const page1 = listFailedRequests({ limit: 2, offset: 0 });
  assert.equal(page1.total, 5);
  assert.equal(page1.limit, 2);
  assert.equal(page1.offset, 0);
  assert.equal(page1.items.length, 2);

  const page2 = listFailedRequests({ limit: 2, offset: 2 });
  assert.equal(page2.items.length, 2);
  assert.equal(page2.offset, 2);

  const page1Routes = new Set(page1.items.map((item) => item.route));
  page2.items.forEach((item) => assert.equal(page1Routes.has(item.route), false));

  const page3 = listFailedRequests({ limit: 2, offset: 4 });
  assert.equal(page3.items.length, 1);
});

test('recordFailedRequest skips failed-requests diagnostics route', () => {
  resetStoreForTests(':memory:');
  const id = recordFailedRequest({
    route: '/api/diagnostics/failed-requests?limit=10',
    statusCode: 500,
    error: 'boom',
  });
  assert.equal(id, null);
  assert.equal(listFailedRequests().total, 0);
});

test('cleanupExpired removes old rows', () => {
  resetStoreForTests(':memory:');
  const now = Date.now();
  recordFailedRequest({ route: '/api/a', statusCode: 400, error: 'a' });
  cleanupExpired(now + getTtlMs() + 1);
  assert.equal(listFailedRequests().total, 0);
});

test('trimToMaxRows keeps newest entries', () => {
  resetStoreForTests(':memory:');
  const originalMax = process.env.FAILED_REQUESTS_MAX_ROWS;
  process.env.FAILED_REQUESTS_MAX_ROWS = '2';
  try {
    recordFailedRequest({ route: '/api/1', statusCode: 400, error: '1' });
    recordFailedRequest({ route: '/api/2', statusCode: 400, error: '2' });
    recordFailedRequest({ route: '/api/3', statusCode: 400, error: '3' });
    const { items, total } = listFailedRequests({ limit: 10 });
    assert.equal(total, 2);
    const routes = items.map((item) => item.route).sort();
    assert.deepEqual(routes, ['/api/2', '/api/3']);
  } finally {
    if (originalMax === undefined) delete process.env.FAILED_REQUESTS_MAX_ROWS;
    else process.env.FAILED_REQUESTS_MAX_ROWS = originalMax;
  }
});

test('getMaxRows respects env bounds', () => {
  const original = process.env.FAILED_REQUESTS_MAX_ROWS;
  process.env.FAILED_REQUESTS_MAX_ROWS = '500';
  try {
    assert.equal(getMaxRows(), 500);
  } finally {
    if (original === undefined) delete process.env.FAILED_REQUESTS_MAX_ROWS;
    else process.env.FAILED_REQUESTS_MAX_ROWS = original;
  }
});
