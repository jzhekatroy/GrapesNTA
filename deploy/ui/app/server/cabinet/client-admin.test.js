const test = require('node:test');
const assert = require('node:assert/strict');

const clickhouse = require('../clickhouse');
const calls = [];
let queryResults = [];

clickhouse.query = async (sql, params, opts) => {
  calls.push({ sql, params, opts });
  const next = queryResults.shift();
  if (next instanceof Error) throw next;
  return next || { rows: [], elapsedMs: 1 };
};

clickhouse.insertRows = async (table, rows, opts) => {
  calls.push({ table, rows, opts, kind: 'insert' });
  return { elapsedMs: 1, rows: rows.length };
};

clickhouse.executeCommand = async (sql, params, opts) => {
  calls.push({ sql, params, opts, kind: 'command' });
  return { elapsedMs: 1 };
};

const {
  normalizeBindMode,
  normalizeClientId,
  mapClientRow,
  createClient,
  updateClient,
  syncClientPrefixes,
  syncClientPorts,
  listPrefixOptions,
} = require('./client-admin');

function resetCalls() {
  calls.length = 0;
  queryResults = [];
}

test('normalizeBindMode accepts prefixes and ports only', () => {
  assert.equal(normalizeBindMode('prefixes'), 'prefixes');
  assert.equal(normalizeBindMode('ports'), 'ports');
  assert.throws(() => normalizeBindMode('both'), /prefixes или ports/i);
});

test('normalizeClientId validates format', () => {
  assert.equal(normalizeClientId('client:demo-1'), 'client:demo-1');
  assert.throws(() => normalizeClientId(''), /clientId/i);
  assert.throws(() => normalizeClientId('bad-id'), /client:/i);
});

test('mapClientRow maps counts and enabled flag', () => {
  const row = mapClientRow({
    client_id: 'client:demo',
    display_name: 'Demo',
    comment: 'x',
    bind_mode: 'prefixes',
    enabled: 0,
    prefix_count: 2,
    port_count: 0,
    user_count: 1,
    updated_at: '2026-08-10 10:00:00',
  });
  assert.deepEqual(row, {
    clientId: 'client:demo',
    displayName: 'Demo',
    comment: 'x',
    bindMode: 'prefixes',
    enabled: false,
    source: 'manual',
    prefixCount: 2,
    portCount: 0,
    userCount: 1,
    updatedAt: '2026-08-10 10:00:00',
    bindingPreview: [],
    bindingPrefixes: [],
    bindingSearch: '',
  });
});

test('mapClientRow accepts ClickHouse qualified c.client_id keys', () => {
  const row = mapClientRow({
    'c.client_id': 'client:demo',
    'c.display_name': 'Demo',
    'c.comment': '',
    'c.bind_mode': 'prefixes',
    'c.enabled': 1,
    user_count: 2,
    updated_at: '2026-08-10 10:00:00',
  });
  assert.equal(row.clientId, 'client:demo');
  assert.equal(row.displayName, 'Demo');
  assert.equal(row.userCount, 2);
  assert.equal(row.source, 'manual');
});

test('clientSource marks ERP clients by id prefix', () => {
  const { clientSource, isErpClientId } = require('./client-admin');
  assert.equal(clientSource('1234567'), 'erp');
  assert.equal(clientSource('client:demo'), 'manual');
  assert.equal(isErpClientId('1234567'), true);
  assert.equal(isErpClientId('client:demo'), false);
});

test('updateClient keeps ERP displayName from catalog', async () => {
  resetCalls();
  queryResults.push(
    {
      rows: [{
        client_id: '1234567',
        display_name: 'ERP Name',
        comment: 'erp:piter_ix',
        bind_mode: 'prefixes',
        enabled: 1,
      }],
    },
    {
      rows: [{
        client_id: '1234567',
        display_name: 'ERP Name',
        comment: 'erp:piter_ix',
        bind_mode: 'prefixes',
        enabled: 1,
        updated_at: '2026-08-10 10:00:00',
        prefix_count: 0,
        port_count: 0,
        user_count: 0,
      }],
    },
    { rows: [{ count: 0 }] },
    { rows: [{ count: 0 }] },
  );
  const result = await updateClient('1234567', { displayName: 'Manual Override', comment: 'note' });
  const insert = calls.find((c) => c.kind === 'insert');
  assert.equal(insert.rows[0].display_name, 'ERP Name');
  assert.equal(result.data.displayName, 'ERP Name');
});

test('createClient rejects duplicate clientId', async () => {
  resetCalls();
  queryResults.push({ rows: [{ client_id: 'client:demo' }] });
  await assert.rejects(
    () => createClient({ clientId: 'client:demo', displayName: 'Demo', bindMode: 'prefixes' }),
    (err) => err.statusCode === 409,
  );
});

test('createClient inserts enabled client row', async () => {
  resetCalls();
  queryResults.push(
    { rows: [] },
    { rows: [{
      client_id: 'client:demo',
      display_name: 'Demo',
      comment: '',
      bind_mode: 'prefixes',
      enabled: 1,
      updated_at: '2026-08-10 10:00:00',
    }] },
    { rows: [{ count: 0 }] },
    { rows: [{ count: 0 }] },
    { rows: [{
      client_id: 'client:demo',
      display_name: 'Demo',
      comment: '',
      bind_mode: 'prefixes',
      enabled: 1,
      updated_at: '2026-08-10 10:00:00',
      prefix_count: 0,
      port_count: 0,
      user_count: 0,
    }] },
  );
  const result = await createClient({
    clientId: 'client:demo',
    displayName: 'Demo',
    bindMode: 'prefixes',
  });
  assert.equal(result.data.clientId, 'client:demo');
  const insert = calls.find((c) => c.kind === 'insert');
  assert.equal(insert.table, 'net_clients');
  assert.equal(insert.rows[0].enabled, 1);
  assert.match(insert.rows[0].updated_at, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
});

test('updateClient forbids changing clientId', async () => {
  resetCalls();
  queryResults.push({
    rows: [{
      client_id: 'client:demo',
      display_name: 'Demo',
      comment: '',
      bind_mode: 'prefixes',
      enabled: 1,
      updated_at: '2026-08-10 10:00:00',
    }],
  });
  await assert.rejects(
    () => updateClient('client:demo', { clientId: 'client:other', displayName: 'Demo' }),
    /нельзя изменить/i,
  );
});

test('updateClient disables instead of deleting', async () => {
  resetCalls();
  queryResults.push(
    {
      rows: [{
        client_id: 'client:demo',
        display_name: 'Demo',
        comment: '',
        bind_mode: 'prefixes',
        enabled: 1,
        updated_at: '2026-08-10 10:00:00',
      }],
    },
    { rows: [{ count: 0 }] },
    { rows: [{ count: 0 }] },
    { rows: [{
      client_id: 'client:demo',
      display_name: 'Demo',
      comment: '',
      bind_mode: 'prefixes',
      enabled: 0,
      updated_at: '2026-08-10 11:00:00',
      prefix_count: 0,
      port_count: 0,
      user_count: 0,
    }] },
  );
  const result = await updateClient('client:demo', { displayName: 'Demo', enabled: false });
  assert.equal(result.data.enabled, false);
  const insert = calls.find((c) => c.kind === 'insert');
  assert.equal(insert.rows[0].enabled, 0);
});

test('listPrefixOptions reads owner from client prefix bindings', async () => {
  resetCalls();
  queryResults.push({
    rows: [{
      prefix: '10.0.0.0/24',
      family: 4,
      owner_client_id: 'client:other',
      owner_display_name: 'Other',
    }],
  });
  const result = await listPrefixOptions({ q: '10.0', limit: 10 });
  assert.equal(result.data[0].prefix, '10.0.0.0/24');
  assert.equal(result.data[0].ownerClientId, 'client:other');
  assert.equal(result.data[0].available, false);
  const sql = calls[0].sql;
  assert.match(sql, /cp\.client_id AS owner_client_id/);
});

test('syncClientPrefixes inserts new prefix bindings', async () => {
  resetCalls();
  queryResults.push(
    {
      rows: [{
        client_id: 'client:demo',
        display_name: 'Demo',
        comment: '',
        bind_mode: 'prefixes',
        enabled: 1,
        updated_at: '2026-08-10 10:00:00',
      }],
    },
    { rows: [{ prefix: '10.0.0.0/24', family: 4 }] },
    { rows: [] },
    { rows: [] },
    {
      rows: [{
        client_id: 'client:demo',
        display_name: 'Demo',
        comment: '',
        bind_mode: 'prefixes',
        enabled: 1,
        updated_at: '2026-08-10 10:00:00',
      }],
    },
    { rows: [{ prefix: '10.0.0.0/24', family: 4, enabled: 1 }] },
  );
  const result = await syncClientPrefixes('client:demo', { items: [{ prefix: '10.0.0.0/24' }] });
  assert.equal(result.data.length, 1);
  assert.equal(result.data[0].prefix, '10.0.0.0/24');
  const currentQuery = calls.find((c) => c.opts?.name === 'cabinet/client-prefixes-current');
  assert.match(currentQuery.sql, /SELECT prefix, family, enabled/);
  assert.doesNotMatch(currentQuery.sql, /comment/);
  const insert = calls.find((c) => c.kind === 'insert' && c.table === 'net_client_prefixes');
  assert.equal(insert.rows[0].enabled, 1);
});

test('syncClientPrefixes rejects occupied prefix with owner name', async () => {
  resetCalls();
  queryResults.push(
    {
      rows: [{
        client_id: 'client:demo',
        display_name: 'Demo',
        comment: '',
        bind_mode: 'prefixes',
        enabled: 1,
        updated_at: '2026-08-10 10:00:00',
      }],
    },
    { rows: [{ prefix: '10.0.0.0/24', family: 4 }] },
    {
      rows: [{
        client_id: 'client:other',
        display_name: 'Other Client',
      }],
    },
  );
  await assert.rejects(
    () => syncClientPrefixes('client:demo', { items: [{ prefix: '10.0.0.0/24' }] }),
    (err) => err.statusCode === 409 && /Other Client/.test(err.message),
  );
});

test('syncClientPorts rejects occupied port with owner name', async () => {
  resetCalls();
  queryResults.push(
    {
      rows: [{
        client_id: 'client:demo',
        display_name: 'Demo',
        comment: '',
        bind_mode: 'ports',
        enabled: 1,
        updated_at: '2026-08-10 10:00:00',
      }],
    },
    {
      rows: [{
        client_id: 'client:other',
        display_name: 'Other Client',
      }],
    },
  );
  await assert.rejects(
    () => syncClientPorts('client:demo', { items: [{ switchIp: '10.0.0.1', ifIndex: 10 }] }),
    (err) => err.statusCode === 409 && /Other Client/.test(err.message),
  );
});
