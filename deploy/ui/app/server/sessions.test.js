'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createSessionStore } = require('./sessions');

function temporaryDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grapes-sessions-'));
  return {
    dir,
    dbPath: path.join(dir, 'sessions.db'),
  };
}

test('session store survives reopening and preserves impersonation', (t) => {
  const { dir, dbPath } = temporaryDb();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const sessionExpiresAt = Date.now() + 60_000;
  const impersonationExpiresAt = Date.now() + 30_000;

  const first = createSessionStore({ dbPath, cleanupIntervalMs: 0 });
  first.set('session-1', {
    userId: 'user-1',
    expiresAt: sessionExpiresAt,
    impersonation: {
      clientId: 'client-1',
      auditId: 'audit-1',
      expiresAt: impersonationExpiresAt,
    },
  });
  first.close();

  const second = createSessionStore({ dbPath, cleanupIntervalMs: 0 });
  t.after(() => second.close());
  assert.deepEqual(second.get('session-1'), {
    userId: 'user-1',
    expiresAt: sessionExpiresAt,
    impersonation: {
      clientId: 'client-1',
      auditId: 'audit-1',
      expiresAt: impersonationExpiresAt,
    },
  });
});

test('session store deletes expired sessions', (t) => {
  const store = createSessionStore({ dbPath: ':memory:', cleanupIntervalMs: 0 });
  t.after(() => store.close());

  store.set('expired', { userId: 'user-1', expiresAt: 100 });
  store.set('active', { userId: 'user-2', expiresAt: 300 });

  assert.equal(store.cleanupExpired(200), 1);
  assert.equal(store.get('expired'), undefined);
  assert.equal(store.get('active').userId, 'user-2');
});

test('session store persists updates and deletion', (t) => {
  const store = createSessionStore({ dbPath: ':memory:', cleanupIntervalMs: 0 });
  t.after(() => store.close());

  store.set('session-1', { userId: 'user-1', expiresAt: 100 });
  const record = store.get('session-1');
  record.expiresAt = 200;
  store.set('session-1', record);

  assert.equal(store.get('session-1').expiresAt, 200);
  assert.equal(store.delete('session-1'), true);
  assert.equal(store.get('session-1'), undefined);
});
