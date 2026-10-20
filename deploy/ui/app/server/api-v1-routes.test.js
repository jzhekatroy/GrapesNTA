'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  apiError,
  toContractUser,
  parseDeleteFields,
  requireAccount,
  requireLogin,
} = require('./api-v1-routes');

test('parseDeleteFields prefers body over query and trims values', () => {
  assert.deepEqual(
    parseDeleteFields({ account: ' 111 ', login: ' a@b.ru ' }, {}),
    { account: '111', login: 'a@b.ru' },
  );
  assert.deepEqual(
    parseDeleteFields({}, { account: '222', login: 'c@d.io' }),
    { account: '222', login: 'c@d.io' },
  );
  assert.deepEqual(
    parseDeleteFields({ account: '111' }, { account: '222', login: 'c@d.io' }),
    { account: '111', login: 'c@d.io' },
  );
  assert.deepEqual(parseDeleteFields({}, {}), { account: '', login: '' });
});

test('requireAccount rejects empty values with contract error', () => {
  assert.equal(requireAccount(' 111 '), '111');
  for (const empty of ['', '   ', null, undefined]) {
    assert.throws(
      () => requireAccount(empty),
      (err) => err.statusCode === 400 && err.code === 'validation_failed',
    );
  }
});

test('requireLogin enforces email format', () => {
  assert.equal(requireLogin(' user@corp.ru '), 'user@corp.ru');
  for (const bad of ['', 'not-an-email', 'a@b', 'a b@c.ru', '@c.ru']) {
    assert.throws(
      () => requireLogin(bad),
      (err) => err.statusCode === 400 && err.code === 'validation_failed',
    );
  }
});

test('toContractUser maps internal user to contract shape', () => {
  assert.deepEqual(
    toContractUser({ username: 'x@y.ru', fullName: 'X Y', createdAt: '2026-10-20 10:00:00', active: true }),
    { login: 'x@y.ru', fullName: 'X Y', createdAt: '2026-10-20 10:00:00', active: true },
  );
  assert.deepEqual(
    toContractUser({ username: 'z@y.ru', fullName: '', createdAt: null }),
    { login: 'z@y.ru', fullName: '', createdAt: null, active: true },
  );
});

test('apiError carries status and machine code', () => {
  const err = apiError(409, 'login_taken', 'занят');
  assert.equal(err.statusCode, 409);
  assert.equal(err.code, 'login_taken');
  assert.equal(err.message, 'занят');
});
