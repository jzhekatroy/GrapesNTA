const test = require('node:test');
const assert = require('node:assert/strict');

const clickhouse = require('./clickhouse');
const calls = [];

clickhouse.query = async (sql, params, opts) => {
  calls.push({ sql, params, opts, kind: 'query' });
  if (/count\(\)/i.test(sql)) {
    return { rows: [{ total: 2 }], elapsedMs: 1 };
  }
  return {
    rows: [
      {
        id: 'e1',
        event_at: '2026-08-20 11:12:00',
        actor_user_id: 'u1',
        actor_username: 'odmen',
        actor_role: 'Administrator',
        ip: '185.1.1.1',
        user_agent: 'Mozilla',
        action: 'login',
        resource: 'auth',
        method: 'POST',
        path: '/api/auth/login',
        object_id: '',
        object_label: '',
        result: 'ok',
        detail: '',
      },
    ],
    elapsedMs: 2,
  };
};

clickhouse.executeCommand = async () => ({ elapsedMs: 1 });
clickhouse.insertRows = async (table, rows, opts) => {
  calls.push({ table, rows, opts, kind: 'insert' });
  return { elapsedMs: 1, rows: rows.length };
};

const {
  writeAuditEvent,
  listAuditEvents,
  shouldSkipPageView,
  sanitizeDetail,
  resolveWriteAction,
  shouldAuditMutatingRequest,
  isAuditWriteExempt,
  parseClickHouseDateTime,
} = require('./audit-log');
const { pageIds } = require('./rbac/resources');

test('pageIds includes audit admin page', () => {
  assert.ok(pageIds().includes('audit'));
});

test('sanitizeDetail redacts sensitive keys', () => {
  assert.equal(sanitizeDetail('password=secret'), '');
  assert.equal(sanitizeDetail('ok detail'), 'ok detail');
  assert.equal(sanitizeDetail({ note: 'token abc' }), '');
});

test('shouldSkipPageView deduplicates within window', () => {
  assert.equal(shouldSkipPageView('s1', 'dashboard'), false);
  assert.equal(shouldSkipPageView('s1', 'dashboard'), true);
  assert.equal(shouldSkipPageView('s1', 'explorer'), false);
});

test('resolveWriteAction maps known mutation paths', () => {
  assert.equal(resolveWriteAction('POST', '/api/users'), 'user_create');
  assert.equal(resolveWriteAction('PUT', '/api/users/u1'), 'user_update');
  assert.equal(resolveWriteAction('POST', '/api/users/u1/password'), 'password_change');
  assert.equal(resolveWriteAction('PUT', '/api/rbac/users/u1/role'), 'role_change');
  assert.equal(resolveWriteAction('POST', '/api/refs/l3-prefixes'), 'api_write');
});

test('shouldAuditMutatingRequest skips exempt and GET paths', () => {
  assert.equal(shouldAuditMutatingRequest('GET', '/api/dashboard/traffic'), false);
  assert.equal(shouldAuditMutatingRequest('POST', '/api/auth/login'), false);
  assert.equal(shouldAuditMutatingRequest('POST', '/api/audit/page'), false);
  assert.equal(shouldAuditMutatingRequest('POST', '/api/users/u1/password'), false);
  assert.equal(shouldAuditMutatingRequest('POST', '/api/users'), true);
  assert.equal(isAuditWriteExempt('/api/clients/demo/impersonate'), true);
});

test('writeAuditEvent inserts sanitized row', async () => {
  calls.length = 0;
  const result = await writeAuditEvent({
    actorUsername: 'odmen',
    action: 'login',
    resource: 'auth',
    method: 'POST',
    path: '/api/auth/login',
    detail: 'password=secret',
    result: 'ok',
  });
  assert.ok(result.id);
  const insert = calls.find((c) => c.kind === 'insert');
  assert.equal(insert.rows[0].action, 'login');
  assert.equal(insert.rows[0].detail, '');
});

test('parseClickHouseDateTime converts ISO strings for query params', () => {
  const parsed = parseClickHouseDateTime('2026-08-19T13:56:58.188Z');
  assert.match(parsed, /^2026-08-19 \d{2}:56:58\.188$/);
  assert.equal(parseClickHouseDateTime('2026-08-19 13:56:58.188'), '2026-08-19 13:56:58.188');
});

test('listAuditEvents applies kind filter and maps response', async () => {
  calls.length = 0;
  const result = await listAuditEvents({
    from: '2026-08-19T13:56:58.188Z',
    to: '2026-08-20T13:56:58.188Z',
    kind: 'login',
    result: 'ok',
    q: 'odmen',
    ip: '185.',
    limit: 50,
    offset: 0,
  });
  assert.equal(result.data.length, 1);
  assert.equal(result.data[0].actorUsername, 'odmen');
  assert.equal(result.meta.total, 2);
  const listQuery = calls.find((c) => c.kind === 'query' && /SELECT\s+id/i.test(c.sql));
  assert.match(listQuery.sql, /action IN/);
  assert.deepEqual(listQuery.params.actions, ['login']);
  assert.equal(listQuery.params.from, '2026-08-19 13:56:58.188');
  assert.equal(listQuery.params.to, '2026-08-20 13:56:58.188');
});
