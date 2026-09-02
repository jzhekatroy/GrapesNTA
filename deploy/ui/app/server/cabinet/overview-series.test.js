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

const { overviewSeries, parseRange } = require('./data');

function resetCalls() {
  calls.length = 0;
  queryResults = [];
}

test('parseRange defaults to relative hours', () => {
  assert.deepEqual(parseRange({ hours: '12' }), { hours: 12, mode: 'relative' });
});

test('overviewSeries auto uses minute table for short ranges', async () => {
  resetCalls();
  queryResults.push(
    { rows: [] },
    { rows: [{ data_until: '2026-08-10 12:00:00' }] },
  );
  await overviewSeries('client:demo', { hours: '3', granularity: 'auto' });
  const seriesCall = calls.find((c) => c.opts?.name === 'cabinet/overview-series');
  assert.match(seriesCall.sql, /traffic_client_1m/);
  assert.match(seriesCall.sql, /bucket/);
  assert.match(seriesCall.sql, /toUnixTimestamp\(/);
  assert.match(seriesCall.sql, /formatDateTime\(/);
});

test('overviewSeries day granularity uses daily table', async () => {
  resetCalls();
  queryResults.push(
    { rows: [] },
    { rows: [{ data_until: '2026-08-10 00:00:00' }] },
  );
  await overviewSeries('client:demo', {
    from: '2025-01-01T00:00:00Z',
    to: '2026-01-01T00:00:00Z',
    granularity: 'day',
  });
  const seriesCall = calls.find((c) => c.opts?.name === 'cabinet/overview-series');
  assert.match(seriesCall.sql, /traffic_client_1d/);
  assert.match(seriesCall.sql, /parseDateTimeBestEffort\(\{from:String\}, '/);
  assert.match(seriesCall.sql, /parseDateTimeBestEffort\(\{to:String\}, '/);
});

test('overviewSeries totals match summed points', async () => {
  resetCalls();
  queryResults.push(
    {
      rows: [
        { bucket: '2026-08-10 11:00:00', bucket_ts: 1786359600, direction: 'in', bytes: 100, packets: 10, flows_count: 1 },
        { bucket: '2026-08-10 11:00:00', bucket_ts: 1786359600, direction: 'out', bytes: 50, packets: 5, flows_count: 1 },
        { bucket: '2026-08-10 12:00:00', bucket_ts: 1786363200, direction: 'in', bytes: 200, packets: 20, flows_count: 2 },
      ],
    },
    { rows: [{ data_until: '2026-08-10 12:00:00' }] },
  );
  const result = await overviewSeries('client:demo', { hours: '24', granularity: 'hour' });
  assert.deepEqual(result.meta.totals, { in: 300, out: 50 });
  assert.equal(result.meta.granularity, 'hour');
  assert.equal(result.data.reduce((sum, row) => sum + row.bytes, 0), 350);
  assert.equal(result.data[0].bucketMs, 1786359600 * 1000);
  assert.equal(result.data[2].bucketMs, 1786363200 * 1000);
});
