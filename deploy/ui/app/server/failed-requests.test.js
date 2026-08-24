'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
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
