const test = require('node:test');
const assert = require('node:assert/strict');
const { pathAllowedForClient, isReadOnlyCabinetPost, createCabinetGuard } = require('./guard');
const {
  resolveCabinetContext,
  requireScopedClientId,
  buildImpersonationSession,
  isCabinetScoped,
} = require('./context');
const { getResourceForPath, isResourceGuardExempt } = require('../rbac/api-map');

test('client allowlist permits cabinet and auth, denies operator APIs', () => {
  assert.equal(pathAllowedForClient('/api/cabinet/overview/series'), true);
  assert.equal(pathAllowedForClient('/api/auth/me'), true);
  assert.equal(pathAllowedForClient('/api/auth/stop-impersonation'), true);
  assert.equal(pathAllowedForClient('/api/audit/page'), true);
  assert.equal(pathAllowedForClient('/api/users/abc/password'), true);
  assert.equal(pathAllowedForClient('/api/dashboard/traffic-stats'), false);
  assert.equal(pathAllowedForClient('/api/explorer/query'), false);
  assert.equal(pathAllowedForClient('/api/users'), false);
  assert.equal(pathAllowedForClient('/api/clients/x/impersonate'), false);
  assert.equal(isReadOnlyCabinetPost('/api/cabinet/explorer/query'), true);
  assert.equal(isReadOnlyCabinetPost('/api/cabinet/explorer/flows'), true);
  assert.equal(isReadOnlyCabinetPost('/api/cabinet/explorer/export'), true);
  assert.equal(isReadOnlyCabinetPost('/api/cabinet/explorer/snapshots/x/share'), false);
});

test('api-map maps clients and exempts cabinet from resource guard', () => {
  assert.equal(getResourceForPath('/api/clients/foo/impersonate', 'POST'), 'clients');
  assert.equal(getResourceForPath('/api/clients/impersonation/audit', 'GET'), 'clients');
  assert.equal(getResourceForPath('/api/cabinet/overview/series', 'GET'), null);
  assert.equal(getResourceForPath('/api/audit', 'GET'), 'audit');
  assert.equal(getResourceForPath('/api/audit/page', 'POST'), null);
  assert.equal(isResourceGuardExempt('/api/cabinet/overview/series'), true);
});

test('resolveCabinetContext prefers impersonation over operator', () => {
  const user = { id: 'u1', roleId: 'Administrator', clientId: '' };
  const session = {
    impersonation: buildImpersonationSession({
      clientId: 'client:demo',
      clientDisplayName: 'Demo',
      auditId: 'a1',
      now: Date.now(),
    }),
  };
  const ctx = resolveCabinetContext(user, session);
  assert.equal(ctx.mode, 'impersonation');
  assert.equal(ctx.clientId, 'client:demo');
  assert.equal(ctx.readOnly, true);
  assert.equal(isCabinetScoped(ctx), true);
});

test('resolveCabinetContext scopes Client role to its clientId', () => {
  const ctx = resolveCabinetContext(
    { id: 'u2', roleId: 'Client', clientId: 'client:188-143-203-173' },
    {},
  );
  assert.equal(ctx.mode, 'client');
  assert.equal(ctx.clientId, 'client:188-143-203-173');
  assert.equal(ctx.readOnly, false);
});

test('requireScopedClientId ignores request-supplied ids by using context only', () => {
  const ctx = resolveCabinetContext(
    { id: 'u2', roleId: 'Client', clientId: 'client:real' },
    {},
  );
  assert.equal(requireScopedClientId(ctx), 'client:real');
  assert.throws(
    () => requireScopedClientId({ mode: 'client', clientId: '' }),
    (err) => err.statusCode === 403,
  );
});

test('cabinet guard strips client_id from query/body and blocks operator paths', async () => {
  const sessions = new Map();
  sessions.set('s1', {
    userId: 'u2',
    expiresAt: Date.now() + 60_000,
  });
  const guard = createCabinetGuard({
    sessions,
    getEnabledClientFn: async (clientId) => ({
      clientId,
      displayName: clientId,
      comment: '',
      bindMode: 'prefixes',
    }),
  });

  const denied = await new Promise((resolve) => {
    const req = {
      sessionId: 's1',
      user: { id: 'u2', roleId: 'Client', clientId: 'client:real', username: 'c1' },
      baseUrl: '/api',
      path: '/dashboard/traffic-stats',
      method: 'GET',
      query: { client_id: 'client:other' },
      body: { clientId: 'client:other' },
    };
    const res = {
      statusCode: 200,
      body: null,
      status(code) { this.statusCode = code; return this; },
      json(payload) { this.body = payload; resolve({ req, res }); },
    };
    guard(req, res, () => resolve({ req, res, next: true }));
  });
  assert.equal(denied.res.statusCode, 403);
  assert.equal(denied.next, undefined);

  const allowed = await new Promise((resolve) => {
    const req = {
      sessionId: 's1',
      user: { id: 'u2', roleId: 'Client', clientId: 'client:real', username: 'c1' },
      baseUrl: '/api',
      path: '/cabinet/overview/series',
      method: 'GET',
      query: { client_id: 'client:other', hours: '3' },
      body: { clientId: 'client:other' },
    };
    const res = {
      status(code) { this.statusCode = code; return this; },
      json(payload) { this.body = payload; resolve({ req, res, leaked: true }); },
    };
    guard(req, res, () => resolve({ req, res, next: true }));
  });
  assert.equal(allowed.next, true);
  assert.equal(allowed.req.query.client_id, undefined);
  assert.equal(allowed.req.query.clientId, undefined);
  assert.equal(allowed.req.body.clientId, undefined);
  assert.equal(allowed.req.query.hours, '3');
  assert.equal(allowed.req.cabinet.clientId, 'client:real');
});

test('impersonation guard blocks mutating cabinet calls', async () => {
  const sessions = new Map();
  const now = Date.now();
  sessions.set('s1', {
    userId: 'admin',
    expiresAt: now + 60_000,
    impersonation: buildImpersonationSession({
      clientId: 'client:real',
      clientDisplayName: 'Real',
      auditId: 'a1',
      now,
    }),
  });
  const guard = createCabinetGuard({
    sessions,
    getEnabledClientFn: async (clientId) => ({
      clientId,
      displayName: clientId,
      comment: '',
      bindMode: 'prefixes',
    }),
  });

  const result = await new Promise((resolve) => {
    const req = {
      sessionId: 's1',
      user: { id: 'admin', roleId: 'Administrator', clientId: '', username: 'admin' },
      baseUrl: '/api',
      path: '/cabinet/overview/series',
      method: 'POST',
      query: {},
      body: {},
    };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(payload) { this.body = payload; resolve({ res }); },
    };
    guard(req, res, () => resolve({ next: true }));
  });
  assert.equal(result.res.statusCode, 403);
  assert.match(result.res.body.error, /только чтение/i);
});

test('impersonation guard allows read-only cabinet explorer POSTs', async () => {
  const sessions = new Map();
  const now = Date.now();
  sessions.set('s1', {
    userId: 'admin',
    expiresAt: now + 60_000,
    impersonation: buildImpersonationSession({
      clientId: 'client:real',
      clientDisplayName: 'Real',
      auditId: 'a1',
      now,
    }),
  });
  const guard = createCabinetGuard({
    sessions,
    getEnabledClientFn: async (clientId) => ({
      clientId,
      displayName: clientId,
      comment: '',
      bindMode: 'prefixes',
    }),
  });

  for (const path of ['/cabinet/explorer/query', '/cabinet/explorer/flows', '/cabinet/explorer/export']) {
    const result = await new Promise((resolve) => {
      const req = {
        sessionId: 's1',
        user: { id: 'admin', roleId: 'Administrator', clientId: '', username: 'admin' },
        baseUrl: '/api',
        path,
        method: 'POST',
        query: {},
        body: {},
      };
      const res = {
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; resolve({ res }); },
      };
      guard(req, res, () => resolve({ next: true, req }));
    });
    assert.equal(result.next, true, path);
    assert.equal(result.req.cabinet.clientId, 'client:real');
  }
});

test('Client role page resources include cabinet pages only', () => {
  const { CLIENT_PAGE_RESOURCES } = require('./constants');
  assert.deepEqual([...CLIENT_PAGE_RESOURCES].sort(), ['cabinet-settings', 'dashboard', 'dns', 'explorer']);
});
