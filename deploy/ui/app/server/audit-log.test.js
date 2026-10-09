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
  resolveClientIpFromReq,
  auditIpFilterVariants,
  buildListSql,
  auditContextFromReq,
  buildMutatingAuditDetail,
  redactAuditPayload,
  normalizeAuditApiPath,
} = require('./audit-log');
const { pageIds } = require('./rbac/resources');

test('pageIds includes audit admin page', () => {
  assert.ok(pageIds().includes('audit'));
});

test('sanitizeDetail redacts sensitive keys', () => {
  assert.equal(sanitizeDetail('password=secret'), '');
  assert.equal(sanitizeDetail('ok detail'), 'ok detail');
  assert.equal(sanitizeDetail({ note: 'token abc' }), '{"note":"token abc"}');
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
  assert.equal(isAuditWriteExempt('/api/explorer/query'), true);
  assert.equal(isAuditWriteExempt('/api/cabinet/explorer/query'), true);
  assert.equal(shouldAuditMutatingRequest('POST', '/api/explorer/query'), false);
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

test('redactAuditPayload hides password fields but keeps other keys', () => {
  const redacted = redactAuditPayload({
    username: 'demo',
    password: 'secret',
    forcePasswordChange: true,
  });
  assert.equal(redacted.username, 'demo');
  assert.equal(redacted.password, '[скрыто]');
  assert.equal(redacted.forcePasswordChange, true);
});

test('normalizeAuditApiPath avoids double /api prefix', () => {
  assert.equal(normalizeAuditApiPath({ path: '/refs/dns-resolvers/toggle' }), '/api/refs/dns-resolvers/toggle');
  assert.equal(
    normalizeAuditApiPath({ path: '/api/refs/interface-roles/delete' }),
    '/api/refs/interface-roles/delete',
  );
});

test('buildMutatingAuditDetail records dns resolver toggle diff', () => {
  const detail = buildMutatingAuditDetail(
    { method: 'POST', body: { resolverId: 'r1', enabled: 0 } },
    '/api/refs/dns-resolvers/toggle',
    'api_write',
    {
      kind: 'dnsResolver',
      toggle: true,
      snapshot: {
        resolverId: 'r1',
        prefix: '8.8.8.8/32',
        displayName: 'Google',
        enabled: 1,
        role: 'resolver',
      },
    },
  );
  const parsed = JSON.parse(detail);
  assert.ok(parsed.changes.some(
    (c) => c.label.includes('Google') && c.from === 'вкл' && c.to === 'выкл',
  ));
});

test('buildMutatingAuditDetail records interface role boundary diff', () => {
  const detail = buildMutatingAuditDetail(
    {
      method: 'POST',
      body: { switchIp: '10.0.0.1', ifIndex: 24, boundary: 'internal', connectivity: '' },
    },
    '/api/refs/interface-roles',
    'api_write',
    {
      kind: 'interfaceRoles',
      isDelete: false,
      entries: [{
        switchIp: '10.0.0.1',
        ifIndex: 24,
        port: { ifName: 'Gi0/24', boundary: 'external', connectivity: '' },
      }],
    },
  );
  const parsed = JSON.parse(detail);
  assert.ok(parsed.changes.some(
    (c) => c.label.includes('10.0.0.1:24') && c.from === 'Внешняя' && c.to === 'Наша сторона',
  ));
});

test('buildMutatingAuditDetail stores request and user field diffs', () => {
  const detail = buildMutatingAuditDetail(
    {
      method: 'PUT',
      body: { fullName: 'Новое имя', roleId: 'Operator' },
    },
    '/api/users/u1',
    'user_update',
    {
      kind: 'user',
      snapshot: {
        fullName: 'Старое имя',
        roleId: 'Administrator',
        active: true,
        clientId: '',
        username: 'demo',
      },
    },
  );
  const parsed = JSON.parse(detail);
  assert.equal(parsed.request.method, 'PUT');
  assert.equal(parsed.request.path, '/api/users/u1');
  assert.ok(parsed.changes.some((c) => c.label === 'ФИО' && c.from === 'Старое имя' && c.to === 'Новое имя'));
  assert.ok(parsed.changes.some((c) => c.label === 'Роль' && c.from === 'Administrator' && c.to === 'Operator'));
});

test('resolveClientIpFromReq uses X-Real-IP behind loopback peer', () => {
  const req = {
    ip: '127.0.0.1',
    headers: { 'x-real-ip': '185.2.3.4' },
  };
  assert.equal(resolveClientIpFromReq(req), '185.2.3.4');
  assert.equal(auditContextFromReq(req).ip, '185.2.3.4');
});

test('resolveClientIpFromReq uses X-Forwarded-For when X-Real-IP missing', () => {
  const req = {
    ip: '::ffff:127.0.0.1',
    headers: { 'x-forwarded-for': '10.0.0.1, 185.9.8.7' },
  };
  assert.equal(resolveClientIpFromReq(req), '10.0.0.1');
});

test('resolveClientIpFromReq ignores forwarded headers for external peer', () => {
  const req = {
    ip: '203.0.113.50',
    headers: { 'x-real-ip': '1.2.3.4', 'x-forwarded-for': '5.6.7.8' },
  };
  assert.equal(resolveClientIpFromReq(req), '203.0.113.50');
});

test('buildListSql matches IPv4 filter with mapped variant', () => {
  const { where, params } = buildListSql({ ip: '185.1.1.1' });
  assert.match(where, /startsWith\(ip, \{ipA:String\}\)/);
  assert.equal(params.ipA, '185.1.1.1');
  assert.equal(params.ipB, '::ffff:185.1.1.1');
});

test('buildListSql adds pageId and userId filters', () => {
  const { where, params } = buildListSql({ pageId: 'dashboard', userId: 'u-42' });
  assert.match(where, /resource = \{pageId:String\}/);
  assert.match(where, /actor_user_id = \{userId:String\}/);
  assert.equal(params.pageId, 'dashboard');
  assert.equal(params.userId, 'u-42');
});

test('listAuditEvents applies pageId and userId in query', async () => {
  calls.length = 0;
  await listAuditEvents({ pageId: 'users', userId: 'u1', limit: 10, offset: 0 });
  const listQuery = calls.find((c) => c.kind === 'query' && /SELECT\s+id/i.test(c.sql));
  assert.equal(listQuery.params.pageId, 'users');
  assert.equal(listQuery.params.userId, 'u1');
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
