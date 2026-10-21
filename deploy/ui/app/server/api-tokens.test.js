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
