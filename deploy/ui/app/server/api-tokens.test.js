'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createApiTokenStore, DEFAULT_TOKEN_TTL_SEC } = require('./api-tokens');

function temporaryDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grapes-api-tokens-'));
  return {
    dir,
    dbPath: path.join(dir, 'api-tokens.db'),
  };
}

test('api token store issues verifiable unique tokens', (t) => {
  const store = createApiTokenStore({ dbPath: ':memory:', cleanupIntervalMs: 0 });
  t.after(() => store.close());

  const issued = store.issue('nta-client-1');
  assert.equal(issued.clientId, 'nta-client-1');
  assert.ok(issued.expiresAt > Date.now());
  assert.ok(issued.token.length >= 40);

  const verified = store.verify(issued.token);
  assert.deepEqual(verified, {
    clientId: 'nta-client-1',
    expiresAt: issued.expiresAt,
  });

  const second = store.issue('nta-client-1');
  assert.notEqual(second.token, issued.token);
  assert.equal(store.verify('no-such-token'), null);
  assert.equal(store.verify(''), null);
});

test('api token store rejects expired tokens', (t) => {
  const store = createApiTokenStore({ dbPath: ':memory:', cleanupIntervalMs: 0 });
  t.after(() => store.close());

  const expired = store.issue('nta-client-1', { ttlSec: -1 });
  assert.equal(store.verify(expired.token), null);

  const active = store.issue('nta-client-2');
  assert.equal(store.verify(active.token)?.clientId, 'nta-client-2');
});

test('api token store cleanup drops only expired rows', (t) => {
  const store = createApiTokenStore({ dbPath: ':memory:', cleanupIntervalMs: 0 });
  t.after(() => store.close());

  const expired = store.issue('nta-client-1', { ttlSec: -1 });
  const active = store.issue('nta-client-2');

  assert.equal(store.cleanupExpired(Date.now()), 1);
  assert.equal(store.verify(expired.token), null);
  assert.equal(store.verify(active.token)?.clientId, 'nta-client-2');
});

test('api token store revokes single tokens and whole clients', (t) => {
  const store = createApiTokenStore({ dbPath: ':memory:', cleanupIntervalMs: 0 });
  t.after(() => store.close());

  const one = store.issue('nta-client-1');
  const two = store.issue('nta-client-2');
  const three = store.issue('nta-client-2');

  assert.equal(store.revoke(one.token), true);
  assert.equal(store.verify(one.token), null);
  assert.equal(store.revoke(one.token), false);

  assert.equal(store.revokeByClientId('nta-client-2'), 2);
  assert.equal(store.verify(two.token), null);
  assert.equal(store.verify(three.token), null);
});

test('api token store survives reopening', (t) => {
  const { dir, dbPath } = temporaryDb();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const first = createApiTokenStore({ dbPath, cleanupIntervalMs: 0 });
  const issued = first.issue('nta-client-1');
  first.close();

  const second = createApiTokenStore({ dbPath, cleanupIntervalMs: 0 });
  t.after(() => second.close());
  assert.deepEqual(second.verify(issued.token), {
    clientId: 'nta-client-1',
    expiresAt: issued.expiresAt,
  });
});

test('api token store default ttl matches contract', () => {
  assert.equal(DEFAULT_TOKEN_TTL_SEC, 3600);
});

test('listActiveTokens groups live tokens by client without token values', (t) => {
  const store = createApiTokenStore({ dbPath: ':memory:', cleanupIntervalMs: 0 });
  t.after(() => store.close());

  const expired = store.issue('nta-client-1', { ttlSec: -1 });
  const one = store.issue('nta-client-1');
  const two = store.issue('nta-client-2');
  store.issue('nta-client-2');

  const active = store.listActiveTokens().sort((a, b) => a.clientId.localeCompare(b.clientId));
  assert.deepEqual(active, [
    { clientId: 'nta-client-1', count: 1, expiresSoonestAt: one.expiresAt },
    { clientId: 'nta-client-2', count: 2, expiresSoonestAt: two.expiresAt },
  ]);
  for (const row of active) {
    assert.equal('token' in row, false);
  }
  assert.equal(store.verify(expired.token), null);
  assert.ok(!store.listActiveTokens().some((row) => row.count !== Math.floor(row.count)));
});

test('getClientStats counts token issues and api requests', (t) => {
  const store = createApiTokenStore({ dbPath: ':memory:', cleanupIntervalMs: 0 });
  t.after(() => store.close());

  const issued = store.issue('nta-client-1');
  store.issue('nta-client-1');
  store.verify(issued.token);
  store.verify(issued.token);
  store.verify('unknown-token');

  const stats = store.getClientStats(['nta-client-1', 'nta-never-seen']);
  assert.equal(stats['nta-client-1'].tokensIssuedToday, 2);
  assert.equal(stats['nta-client-1'].requestsToday, 2);
  assert.ok(stats['nta-client-1'].lastUsedAt <= Date.now());
  // Клиент без активности: нули и пустая метка, а не undefined.
  assert.deepEqual(stats['nta-never-seen'], {
    lastUsedAt: null,
    tokensIssuedToday: 0,
    requestsToday: 0,
  });
});

test('client stats survive reopen via close flush', (t) => {
  const { dir, dbPath } = temporaryDb();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const first = createApiTokenStore({ dbPath, cleanupIntervalMs: 0 });
  const issued = first.issue('nta-client-1');
  first.verify(issued.token);
  first.close();

  const second = createApiTokenStore({ dbPath, cleanupIntervalMs: 0 });
  t.after(() => second.close());
  const stats = second.getClientStats(['nta-client-1']);
  assert.equal(stats['nta-client-1'].tokensIssuedToday, 1);
  assert.equal(stats['nta-client-1'].requestsToday, 1);
  assert.ok(stats['nta-client-1'].lastUsedAt > 0);
});

test('client stats reset when the stats day changes', (t) => {
  let dayKey = '2026-10-22';
  const store = createApiTokenStore({
    dbPath: ':memory:',
    cleanupIntervalMs: 0,
    statsDayKeyFn: () => dayKey,
  });
  t.after(() => store.close());

  const issued = store.issue('nta-client-1');
  store.verify(issued.token);
  assert.equal(store.getClientStats(['nta-client-1'])['nta-client-1'].requestsToday, 1);

  dayKey = '2026-10-23';
  const nextDay = store.getClientStats(['nta-client-1'])['nta-client-1'];
  assert.equal(nextDay.tokensIssuedToday, 0);
  assert.equal(nextDay.requestsToday, 0);
  // lastUsedAt — исторический факт, при смене дня не обнуляется.
  assert.ok(nextDay.lastUsedAt > 0);
  store.issue('nta-client-1');
  assert.equal(store.getClientStats(['nta-client-1'])['nta-client-1'].tokensIssuedToday, 1);
});
