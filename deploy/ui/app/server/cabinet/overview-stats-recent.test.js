const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

const clickhouse = require('../clickhouse');
const calls = [];
let queryResults = [];

clickhouse.query = async (sql, params, opts) => {
  calls.push({ sql, params, opts });
  const next = queryResults.shift();
  if (next instanceof Error) throw next;
  return next || { rows: [], elapsedMs: 1 };
};

const { overviewStats, overviewRecentFlows } = require('./data');
const { createCabinetRouter } = require('./routes');

function resetCalls() {
  calls.length = 0;
  queryResults = [];
}

test('overviewStats returns UI units for in/out and reports its source granularity', async () => {
  resetCalls();
  queryResults.push(
    {
      rows: [
        {
          direction: 'in',
          max_bps: 8000,
          avg_bps: 4000,
          max_pps: 80,
          avg_pps: 40,
          total_bytes: 2_500_000_000,
          total_packets: 1234,
        },
      ],
      elapsedMs: 7,
    },
    { rows: [{ data_until: '2026-08-18 12:34:00' }] },
  );

  const result = await overviewStats('client:real', { hours: '6' });

  assert.deepEqual(result.data.max.in, { bps: 8000, pps: 80 });
  assert.deepEqual(result.data.avg.in, { bps: 4000, pps: 40 });
  assert.deepEqual(result.data.volume.in, { gb: 2.5, tb: 0.0025, packets: 1234 });
  assert.deepEqual(result.data.max.out, { bps: 0, pps: 0 });
  assert.equal(result.meta.granularity, 'minute');
  assert.equal(result.meta.dataUntil, '2026-08-18 12:34:00');

  const statsCall = calls.find((call) => call.opts?.name === 'cabinet/overview-stats');
  const untilCall = calls.find((call) => String(call.opts?.name || '').startsWith('cabinet/data-until/'));
  assert.match(statsCall.sql, /traffic_client_1m/);
  assert.match(statsCall.sql, /max\(bucket_bytes \* 8/);
  assert.match(untilCall.sql, /formatDateTime\(/);
  assert.equal(statsCall.params.clientId, 'client:real');
  assert.equal(statsCall.params.bucketSeconds, 60);
  assert.equal(statsCall.params.windowSeconds, 6 * 3600);
});

test('overviewStats uses hourly buckets after minute retention', async () => {
  resetCalls();
  queryResults.push(
    { rows: [], elapsedMs: 2 },
    { rows: [{ data_until: '2026-08-18 12:00:00' }] },
  );

  const result = await overviewStats('client:real', { hours: String(15 * 24) });

  assert.equal(result.meta.granularity, 'hour');
  assert.match(calls[0].sql, /traffic_client_1h/);
  assert.equal(calls[0].params.bucketSeconds, 3600);
});

test('overviewRecentFlows scopes raw flows and maps only the cabinet contract', async () => {
  resetCalls();
  queryResults.push({
    rows: [{
      ts: '2026-08-18 12:34:56.123',
      src_ip: '192.0.2.1',
      dst_ip: '198.51.100.2',
      src_port: '443',
      dst_port: '52100',
      proto: 6,
      bytes: '2048',
      packets: '12',
      src_asn: '64500',
      dst_asn: '64501',
      src_as_name: 'Source AS',
      dst_as_name: 'Destination AS',
      src_country: 'RU',
      dst_country: 'DE',
      client_side: 'src',
    }],
    elapsedMs: 4,
  });

  const result = await overviewRecentFlows('client:real', {
    limit: '500',
    clientId: 'client:other',
  });

  assert.deepEqual(result.data, [{
    ts: '2026-08-18 12:34:56.123',
    srcIp: '192.0.2.1',
    dstIp: '198.51.100.2',
    srcPort: 443,
    dstPort: 52100,
    proto: 'TCP',
    bytes: 2048,
    pkts: 12,
    srcAsn: 64500,
    dstAsn: 64501,
    srcAsName: 'Source AS',
    dstAsName: 'Destination AS',
    srcCountry: 'RU',
    dstCountry: 'DE',
    clientSide: 'src',
  }]);
  assert.match(calls[0].sql, /FROM `default`\.`flows_raw` AS f/);
  assert.match(calls[0].sql, /formatDateTime\(/);
  assert.match(calls[0].sql, /f\.src_client = \{clientId:String\} OR f\.dst_client = \{clientId:String\}/);
  assert.equal(calls[0].params.clientId, 'client:real');
  assert.equal(calls[0].params.limit, 100);
  assert.equal(Object.hasOwn(calls[0].params, 'client:other'), false);
});

test('overview routes take clientId from cabinet session context', async () => {
  resetCalls();
  queryResults.push(
    { rows: [], elapsedMs: 1 },
    { rows: [{ data_until: '2026-08-18 12:00:00' }] },
  );

  const app = express();
  app.use((req, _res, next) => {
    req.cabinet = { mode: 'client', clientId: 'client:session' };
    next();
  });
  app.use('/api/cabinet', createCabinetRouter({ sessions: new Map() }));
  const server = app.listen(0);

  try {
    const { port } = server.address();
    const response = await fetch(
      `http://127.0.0.1:${port}/api/cabinet/overview/stats?clientId=client:other&hours=3`,
    );
    assert.equal(response.status, 200);
    const statsCall = calls.find((call) => call.opts?.name === 'cabinet/overview-stats');
    assert.equal(statsCall.params.clientId, 'client:session');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
