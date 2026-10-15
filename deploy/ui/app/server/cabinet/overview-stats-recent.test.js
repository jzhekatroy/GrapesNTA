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
  assert.equal(result.meta.granularity, '5m');
  assert.equal(result.meta.dataUntil, '2026-08-18 12:34:00');

  const statsCall = calls.find((call) => call.opts?.name === 'cabinet/overview-stats');
  const untilCall = calls.find((call) => String(call.opts?.name || '').startsWith('cabinet/data-until/'));
  assert.match(statsCall.sql, /traffic_client_1m/);
  assert.match(statsCall.sql, /max\(bucket_bytes \* 8/);
  assert.match(untilCall.sql, /formatDateTime\(/);
  assert.equal(statsCall.params.clientId, 'client:real');
  // Минутные строки собираются в пятиминутки, поэтому пик считается на 300 с.
  assert.equal(statsCall.params.bucketSeconds, 300);
  assert.equal(statsCall.params.windowSeconds, 6 * 3600);
  // Незакрытая пятиминутка занизила бы пик, её нужно отбрасывать.
  assert.match(statsCall.sql, /toStartOfInterval\(minute, INTERVAL 5 MINUTE\)/);
  assert.match(statsCall.sql, /toIntervalSecond\(300\) < now\(\) - INTERVAL 30 SECOND/);
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

function recentFlowRow(overrides = {}) {
  return {
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
    ...overrides,
  };
}

const mappedRecentFlow = {
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
};

test('overviewRecentFlows keeps the short window when it already fills the limit', async () => {
  resetCalls();
  queryResults.push({
    rows: Array.from({ length: 20 }, (_, i) => recentFlowRow({ src_port: String(1000 + i) })),
    elapsedMs: 4,
  });

  const result = await overviewRecentFlows('client:real', { limit: '20' });

  assert.equal(calls.length, 1);
  assert.equal(result.data.length, 20);
  assert.equal(result.data[0].srcPort, 1000);
  assert.equal(result.meta.elapsedMs, 4);
  assert.equal(result.meta.rows, 20);
  assert.match(calls[0].sql, /f\.`TimeReceived` >= now\(\) - INTERVAL \{recentMinutes:UInt32\} MINUTE/);
  assert.match(calls[0].sql, /f\.date >= today\(\) - 1/);
  assert.match(calls[0].sql, /f\.src_client = \{clientId:String\} OR f\.dst_client = \{clientId:String\}/);
  assert.equal(calls[0].params.recentMinutes, 15);
  assert.equal(calls[0].params.limit, 20);
  assert.equal(calls[0].params.clientId, 'client:real');
  assert.equal(calls[0].opts.name, 'cabinet/overview-recent-flows');
});

test('overviewRecentFlows falls back to two days and maps only the cabinet contract', async () => {
  resetCalls();
  queryResults.push(
    { rows: [recentFlowRow({ src_ip: '203.0.113.9' })], elapsedMs: 3 },
    { rows: [recentFlowRow()], elapsedMs: 4 },
  );

  const result = await overviewRecentFlows('client:real', {
    limit: '500',
    clientId: 'client:other',
  });

  assert.equal(calls.length, 2);
  assert.deepEqual(result.data, [mappedRecentFlow]);
  assert.equal(result.meta.elapsedMs, 7);
  assert.match(calls[0].sql, /INTERVAL \{recentMinutes:UInt32\} MINUTE/);
  assert.doesNotMatch(calls[1].sql, /INTERVAL \{recentMinutes:UInt32\} MINUTE/);
  assert.match(calls[1].sql, /FROM `default`\.`flows_raw` AS f/);
  assert.match(calls[1].sql, /formatDateTime\(/);
  assert.match(calls[1].sql, /f\.date >= today\(\) - 1/);
  assert.match(calls[1].sql, /f\.src_client = \{clientId:String\} OR f\.dst_client = \{clientId:String\}/);
  assert.equal(calls[1].opts.name, 'cabinet/overview-recent-flows-full');
  assert.equal(calls[0].params.clientId, 'client:real');
  assert.equal(calls[1].params.clientId, 'client:real');
  assert.equal(calls[1].params.limit, 100);
  assert.equal(Object.hasOwn(calls[1].params, 'recentMinutes'), false);
  assert.equal(Object.hasOwn(calls[1].params, 'client:other'), false);
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
