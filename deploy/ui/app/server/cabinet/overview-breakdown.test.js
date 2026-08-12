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

const { overviewCountries, overviewServices } = require('./data');

function resetCalls() {
  calls.length = 0;
  queryResults = [];
}

test('overviewCountries returns totalBytes from the same vitrine', async () => {
  resetCalls();
  queryResults.push(
    {
      rows: [
        { country_code: 'RU', direction: 'in', bytes: 70, packets: 1, flows_count: 1 },
        { country_code: 'DE', direction: 'in', bytes: 30, packets: 1, flows_count: 1 },
      ],
    },
    { rows: [{ data_until: '2026-08-10 11:00:00' }] },
    { rows: [{ bytes: 150 }] },
  );
  const result = await overviewCountries('client:demo', { hours: '24', direction: 'in', limit: 20 });
  assert.equal(result.meta.totalBytes, 150);
  assert.equal(result.meta.breakdownGranularity, 'hour');
  assert.match(calls[0].sql, /traffic_client_country_1h/);
  assert.match(calls[2].sql, /sum\(bytes\)/);
});

test('overviewServices uses daily vitrine for long ranges', async () => {
  resetCalls();
  queryResults.push(
    { rows: [{ service_code: 'https', service_name: 'HTTPS', transport: 'tcp', category: 'web', direction: 'in', service_port: 0, port_owner: '', bytes: 10, packets: 1, flows_count: 1 }] },
    { rows: [{ data_until: '2026-08-10 00:00:00' }] },
    { rows: [{ bytes: 10 }] },
  );
  await overviewServices('client:demo', {
    from: '2025-01-01T00:00:00Z',
    to: '2026-01-01T00:00:00Z',
    direction: 'in',
    limit: 20,
  });
  assert.match(calls[0].sql, /traffic_client_service_1d/);
  assert.match(calls[0].sql, /day >=/);
});
