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

const { overviewSeries, overviewIxRankings, parseRange } = require('./data');

function resetCalls() {
  calls.length = 0;
  queryResults = [];
}

test('parseRange defaults to relative hours', () => {
  assert.deepEqual(parseRange({ hours: '12' }), { hours: 12, mode: 'relative' });
});

test('overviewSeries auto uses 5-minute buckets for short ranges', async () => {
  resetCalls();
  queryResults.push(
    { rows: [] },
    { rows: [{ data_until: '2026-08-10 12:00:00' }] },
  );
  const result = await overviewSeries('client:demo', { hours: '3', granularity: 'auto' });
  const seriesCall = calls.find((c) => c.opts?.name === 'cabinet/overview-series');
  assert.match(seriesCall.sql, /traffic_client_1m/);
  assert.match(seriesCall.sql, /INTERVAL 5 MINUTE/);
  assert.match(seriesCall.sql, /inner_bucket/);
  assert.match(seriesCall.sql, /toUnixTimestamp\(inner_bucket\) AS bucket_ts/);
  assert.match(seriesCall.sql, /formatDateTime\(inner_bucket/);
  assert.doesNotMatch(seriesCall.sql, /toUnixTimestamp\(bucket\)/);
  assert.equal(result.meta.granularity, '5m');
});

test('overviewSeries auto uses 5-minute buckets for 24h', async () => {
  resetCalls();
  queryResults.push(
    { rows: [] },
    { rows: [{ data_until: '2026-08-10 12:00:00' }] },
  );
  const result = await overviewSeries('client:demo', { hours: '24', granularity: 'auto' });
  const seriesCall = calls.find((c) => c.opts?.name === 'cabinet/overview-series');
  assert.match(seriesCall.sql, /traffic_client_1m/);
  assert.match(seriesCall.sql, /INTERVAL 5 MINUTE/);
  assert.match(seriesCall.sql, /toUnixTimestamp\(inner_bucket\) AS bucket_ts/);
  assert.equal(result.meta.granularity, '5m');
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
  assert.equal(result.meta.ix, false);
});

test('overviewSeries marks an IX client', async () => {
  resetCalls();
  queryResults.push(
    { rows: [] },
    { rows: [{ data_until: '2026-08-10 12:00:00' }] },
    { rows: [{ ix_enabled: 1, ix_client: 1 }] },
  );
  const result = await overviewSeries('client:demo', { hours: '24', granularity: 'hour' });
  const ixCall = calls.find((c) => c.opts?.name === 'cabinet/ix-client');
  assert.match(ixCall.sql, /comment = 'erp:piter_ix'/);
  assert.equal(ixCall.params.clientId, 'client:demo');
  assert.equal(result.meta.ix, true);
});

test('overviewSeries filters a subset of IX sites on the minute table', async () => {
  resetCalls();
  queryResults.push(
    { rows: [] },
    { rows: [{ data_until: '2026-08-10 12:00:00' }] },
  );
  await overviewSeries('client:demo', { hours: '6', location: ['Рига', 'Москва'] });
  const seriesCall = calls.find((c) => c.opts?.name === 'cabinet/overview-series');
  assert.match(seriesCall.sql, /default\.traffic_client_ix_1m/);
  assert.doesNotMatch(seriesCall.sql, /default\.traffic_client_1m\b/);
  assert.match(seriesCall.sql, /ix_location IN \{locations:Array\(String\)\}/);
  assert.deepEqual(seriesCall.params.locations, ['Рига', 'Москва']);
});

test('overviewSeries rejects an IX location range past 14 days', async () => {
  resetCalls();
  await assert.rejects(
    () => overviewSeries('client:demo', {
      from: '2026-01-01T00:00:00Z',
      to: '2026-03-01T00:00:00Z',
      location: 'Рига',
    }),
    (err) => err.statusCode === 400,
  );
  assert.equal(calls.length, 0);
});

test('overviewIxRankings stays off for a client that is not IX', async () => {
  resetCalls();
  queryResults.push({ rows: [{ ix_enabled: 0, ix_client: 0 }] });
  const result = await overviewIxRankings('client:demo', { hours: '24' });
  assert.equal(result.meta.enabled, false);
  assert.equal(calls.length, 1);
});

test('overviewIxRankings orders peers by the selected direction', async () => {
  resetCalls();
  queryResults.push(
    { rows: [{ ix_enabled: 1, ix_client: 1 }] },
    { rows: [{ id: 'peer-1', name: 'Питер', in_bytes: 10, out_bytes: 0 }], elapsedMs: 3 },
    { rows: [{ id: '0', name: '', in_bytes: 0, out_bytes: 4 }], elapsedMs: 4 },
    { rows: [{ in_bytes: 100, out_bytes: 40 }], elapsedMs: 2 },
  );
  const result = await overviewIxRankings('client:demo', { hours: '24', direction: 'out', location: 'Рига' });
  const peerCall = calls.find((c) => c.opts?.name === 'cabinet/ix-peers-rank');
  assert.match(peerCall.sql, /ORDER BY out_bytes DESC/);
  assert.match(peerCall.sql, /traffic_client_ix_1m/);
  assert.deepEqual(peerCall.params.locations, ['Рига']);
  assert.equal(result.meta.enabled, true);
  assert.equal(result.data.peers[0].name, 'Питер');
  assert.equal(result.data.asns[0].id, '0');
  assert.equal(result.data.asns[0].name, '');
  assert.deepEqual(result.meta.totals, { inBytes: 100, outBytes: 40 });
});
