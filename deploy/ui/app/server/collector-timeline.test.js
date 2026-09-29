'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  parseRange,
  chooseBucketSeconds,
  problemIntervals,
  mergeIncidents,
  clusterIncidents,
  buildTimeline,
} = require('./collector-timeline');

const MIN = 60000;
const HOUR = 60 * MIN;
const T0 = Date.parse('2026-07-21T12:00:00Z');

function run(cat, startMs, endMs, extra = {}) {
  return {
    cat,
    start_ms: startMs,
    end_ms: endMs,
    alive: 0,
    codes: [cat],
    input: 0,
    written: 0,
    lost: 0,
    ...extra,
  };
}

const bounds = (extra = {}) => ({
  firstMs: T0 - 10 * HOUR,
  lastMs: T0 + 6 * HOUR,
  priorMs: T0 - MIN,
  nextMs: null,
  firstInMs: T0,
  lastInMs: T0 + 6 * HOUR,
  isXdp: false,
  daemon: 'flowcollectord',
  lastReasons: [],
  ...extra,
});

const incidentsFor = (runs, b, range, now) => mergeIncidents(problemIntervals(runs, b, range, now), now);

const boundsRow = (extra = {}) => ({
  first_ms: T0 - HOUR,
  last_ms: T0 + 3 * HOUR - MIN,
  prior_ms: T0 - MIN,
  first_in_ms: T0,
  last_in_ms: T0 + 3 * HOUR - MIN,
  last_daemon: 'xdpflowd',
  last_stages: [],
  last_reasons: [],
  ...extra,
});

describe('collector timeline range', () => {
  it('picks a cell size that keeps the strip readable', () => {
    assert.equal(chooseBucketSeconds(24 * HOUR), 600);
    assert.equal(chooseBucketSeconds(7 * 24 * HOUR), 3600);
    assert.equal(chooseBucketSeconds(30 * 24 * HOUR), 10800);
    assert.equal(chooseBucketSeconds(90 * 24 * HOUR), 43200);
  });

  it('clamps to retention and now, rejects tiny ranges', () => {
    const now = T0;
    const r = parseRange(now - 200 * 24 * HOUR, now + HOUR, now);
    assert.equal(r.toMs, now);
    assert.equal(r.fromMs, now - 90 * 24 * HOUR);
    assert.throws(() => parseRange(now - MIN, now, now), /слишком короткий/);
  });
});

describe('collector incidents', () => {
  it('a silence with growing counters means ClickHouse was down, not the collector', () => {
    // stand, 2026-07-21: 13:54 → 16:55 without snapshots, datagrams 171.9M → 244.4M
    const range = { fromMs: T0, toMs: T0 + 6 * HOUR };
    const gap = run('gap', T0 + 2 * HOUR, T0 + 2 * HOUR + 181 * MIN, { alive: 1, input: 72454889 });
    const [inc] = incidentsFor([gap], bounds(), range, range.toMs);
    assert.equal(inc.severity, 'down');
    assert.equal(inc.aliveDuringGap, true);
    assert.equal(inc.title, 'ClickHouse был недоступен');
    assert.equal(inc.durationSec, 181 * 60);
  });

  it('runs of one kind a few minutes apart are one incident', () => {
    const range = { fromMs: T0, toMs: T0 + 6 * HOUR };
    const runs = [
      run('no_input', T0, T0 + HOUR),
      run('no_input', T0 + HOUR + 5 * MIN, T0 + 3 * HOUR),
    ];
    const incidents = incidentsFor(runs, bounds(), range, range.toMs);
    assert.equal(incidents.length, 1);
    assert.equal(incidents[0].category, 'no_input');
    assert.equal(incidents[0].durationSec, 3 * 3600);
  });

  it('overlapping causes are one outage named by the longest one', () => {
    // mirror, netflow, 2026-09-28: silence 04:17–09:20, writes rejected 04:05–04:17 and 04:36–05:18
    const range = { fromMs: T0, toMs: T0 + 6 * HOUR };
    const runs = [
      run('write_blocked', T0, T0 + 12 * MIN),
      run('gap', T0 + 12 * MIN, T0 + 315 * MIN, { alive: 1 }),
      run('write_blocked', T0 + 31 * MIN, T0 + 73 * MIN),
    ];
    const clusters = clusterIncidents(incidentsFor(runs, bounds(), range, range.toMs));
    assert.equal(clusters.length, 1);
    assert.equal(clusters[0].title, 'ClickHouse был недоступен');
    assert.equal(clusters[0].durationSec, 315 * 60);
    assert.deepEqual(clusters[0].alsoCauses.map((c) => c.title), ['ClickHouse не принимал запись']);
  });

  it('silence up to now is an ongoing incident', () => {
    const now = T0 + 6 * HOUR;
    const range = { fromMs: T0, toMs: now };
    const b = bounds({ lastInMs: T0 + 2 * HOUR, lastMs: T0 + 2 * HOUR });
    const [inc] = incidentsFor([], b, range, now);
    assert.equal(inc.severity, 'down');
    assert.equal(inc.ongoing, true);
    assert.equal(inc.startMs, T0 + 2 * HOUR);
  });
});

describe('collector timeline', () => {
  it('chronic side errors do not make incidents or break "data is collected"', () => {
    // mirror, netflow: NetFlow send errors every minute, data flows into ClickHouse
    const now = T0 + 3 * HOUR;
    const tl = buildTimeline({
      bucketRows: [0, 1, 2].map((h) => ({
        bucket: (T0 + h * HOUR) / 1000, data_bad_n: 0, other_n: 60, no_input_n: 0, input: 1, written: 1, reasons: ['netflow_send_errors'],
      })),
      runRows: [],
      otherRows: [{ code: 'netflow_send_errors', n: 180, last_ms: now - MIN }],
      boundsRow: boundsRow({ last_ms: now - MIN, last_in_ms: now - MIN, last_reasons: ['netflow_send_errors'] }),
      range: { fromMs: T0, toMs: now },
      bucketSec: 3600,
      nowMs: now,
    });
    assert.equal(tl.current.state, 'ok');
    assert.deepEqual(tl.current.otherNow.map((r) => r.code), ['netflow_send_errors']);
    assert.equal(tl.incidents.length, 0);
    assert.equal(tl.summary.collectedPct, 100);
    assert.equal(tl.summary.completenessPct, null);
    assert.deepEqual(tl.buckets.map((b) => b.state), ['warning', 'warning', 'warning']);
    assert.deepEqual(tl.otherEvents.map((e) => [e.code, e.count, e.unit]), [['netflow_send_errors', 180, 'minutes']]);
  });

  it('short failures go to other events, long ones and data loss colour the strip', () => {
    const now = T0 + 3 * HOUR;
    const tl = buildTimeline({
      bucketRows: [
        { bucket: T0 / 1000, data_bad_n: 2, other_n: 0, no_input_n: 0, input: 1, written: 1, seen: 1000, non_ip: 0, acked: 990, excluded: 0, phy: 1000, nf_records: 40, reasons: ['clickhouse_insert_errors'] },
        { bucket: (T0 + HOUR) / 1000, data_bad_n: 20, other_n: 0, no_input_n: 20, input: 1, written: 1, seen: 500, non_ip: 0, acked: 250, excluded: 0, phy: 500, nf_records: 10, reasons: [] },
      ],
      runRows: [
        run('write_blocked', T0 + 29 * MIN, T0 + 31 * MIN),
        run('no_input', T0 + 70 * MIN, T0 + 90 * MIN),
      ],
      boundsRow: boundsRow({ last_ms: T0 + 2 * HOUR - MIN, last_in_ms: T0 + 2 * HOUR - MIN }),
      range: { fromMs: T0, toMs: now },
      bucketSec: 3600,
      nowMs: now,
    });
    assert.deepEqual(tl.buckets.map((b) => b.state), ['critical', 'critical', 'down']);
    assert.deepEqual(tl.incidents.map((i) => [i.severity, i.ongoing]), [['down', true], ['critical', false]]);
    assert.equal(tl.incidents[1].title, 'Нет входящего потока');
    assert.equal(tl.current.state, 'gap');
    assert.equal(tl.otherEvents.length, 1);
    assert.equal(tl.otherEvents[0].count, 1);
    assert.equal(tl.otherEvents[0].unit, 'times');
    assert.equal(tl.summary.completenessPct, 82.67);
    assert.equal(tl.summary.phy, 1500);
    assert.equal(tl.summary.nfRecords, 50);
    assert.equal(tl.buckets[0].completenessPct, 99);
  });
});
