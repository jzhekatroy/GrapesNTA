const test = require('node:test');
const assert = require('node:assert/strict');

const clickhouse = require('../clickhouse');
const calls = [];

clickhouse.query = async (sql, params, opts) => {
  calls.push({ sql, params, opts });
  return {
    rows: [{
      id: 'u1',
      username: 'client-user',
      full_name: 'Client User',
      role_id: 'Client',
      client_id: 'client:demo',
      active: 1,
      force_password_change: 0,
      created_at: '2026-01-01 00:00:00',
      updated_at: '2026-01-01 00:00:00',
    }],
    elapsedMs: 1,
  };
};

const { listUsers } = require('../users');

test('listUsers filters by clientId and returns quota meta', async () => {
  calls.length = 0;
  const result = await listUsers({ clientId: 'client:demo' });
  assert.equal(result.data.length, 1);
  assert.equal(result.data[0].clientId, 'client:demo');
  assert.equal(result.meta.clientId, 'client:demo');
  assert.equal(result.meta.limit, 5);
  assert.equal(result.meta.used, 1);
  assert.equal(result.meta.remaining, 4);
  assert.match(calls[0].sql, /client_id = \{clientId:String\}/);
  assert.equal(calls[0].params.clientId, 'client:demo');
});

test('listUsers without clientId omits quota meta', async () => {
  calls.length = 0;
  const result = await listUsers();
  assert.equal(result.data.length, 1);
  assert.equal(result.meta.used, undefined);
  assert.equal(result.meta.limit, undefined);
  assert.doesNotMatch(calls[0].sql, /client_id = \{clientId:String\}/);
});
