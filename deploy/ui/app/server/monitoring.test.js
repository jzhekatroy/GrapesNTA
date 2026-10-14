'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildMonitoringView,
  attackHistoryWindow,
  mergeAttackHistoryPoints,
  attackSliceMinute,
  silentSourceIds,
} = require('./monitoring');

const NOW = Date.parse('2026-10-14T09:00:00.000Z');

function view(extra) {
  return buildMonitoringView({
    now: NOW,
    detection: {
      ok: true,
      minute: {
        wall: '2026-10-14 08:58:00',
        iso: '2026-10-14T08:58:00.000Z',
        ts: Date.parse('2026-10-14T08:58:00.000Z'),
      },
    },
    ...extra,
  });
}

test('офлайн-коллектор становится critical, молчащий источник — warning', () => {
  const offline = view({
    collectors: {
      ok: true,
      collectors: [{
        collectorId: 'm9',
        displayName: 'M9',
        state: 'offline',
        sources: [
          { sourceId: 's1', sourceName: 'sw-1', isLive: false },
          { sourceId: 's2', sourceName: 'sw-2', isLive: false },
        ],
      }],
    },
    lastMinutes: new Map([
      ['s1', '2026-10-14T08:40:00.000Z'],
      ['s2', '2026-10-14T08:41:00.000Z'],
    ]),
  });
  const problem = offline.problems.find((item) => item.id === 'collectors:collector_offline:m9');
  assert.equal(problem.level, 'critical');
  assert.equal(problem.title, 'M9 не шлёт данные');
  assert.equal(problem.since, '2026-10-14T08:41:00.000Z');
  assert.equal(problem.link, '#collectors');
  assert.equal(problem.diagnosticsTab, null);
  assert.equal(offline.components.find((item) => item.id === 'collectors').status, 'critical');

  const mixed = view({
    collectors: {
      ok: true,
      collectors: [{
        collectorId: 'spb',
        displayName: 'SPb',
        state: 'online',
        sources: [
          { sourceId: 'live', sourceName: 'live', isLive: true },
          { sourceId: 'quiet', sourceName: 'edge', isLive: false },
        ],
      }, {
        collectorId: 'empty',
        displayName: 'Пустой',
        state: 'empty',
        sources: [],
      }],
    },
    lastMinutes: { quiet: '2026-10-14T08:20:00.000Z' },
  });
  assert.deepEqual(
    mixed.problems.filter((item) => item.component === 'collectors').map((item) => item.id),
    ['collectors:source_silent:quiet'],
  );
  assert.equal(mixed.problems[0].level, 'warning');
  assert.equal(mixed.problems[0].since, '2026-10-14T08:20:00.000Z');
});

test('детекция старше 10 минут critical, обычные 7 минут проблем не дают', () => {
  const usual = view({ now: Date.parse('2026-10-14T09:05:13.000Z') });
  assert.equal(usual.meta.detectionStale, false);
  assert.equal(usual.meta.detectionLagSec, 433);
  assert.equal(usual.components.find((item) => item.id === 'detection').status, 'ok');

  const stale = view({
    now: Date.parse('2026-10-14T09:10:00.000Z'),
  });
  const problem = stale.problems.find((item) => item.id === 'detection:detection_stale');
  assert.equal(problem.level, 'critical');
  assert.equal(problem.since, '2026-10-14T08:58:00.000Z');
  assert.equal(problem.diagnosticsTab, 'detection');
  assert.equal(stale.meta.detectionStale, true);

  const empty = view({ detection: { ok: true, minute: null } });
  assert.equal(empty.meta.detectionEmpty, true);
  assert.equal(empty.problems.some((item) => item.id === 'detection:detection_empty'), true);
});

test('падение одной проверки не прячет остальные и вычищает секрет из текста', () => {
  const result = view({
    clickhouse: { ok: true, pingOk: false, error: 'connect http://user:secret@10.0.0.1 password=hunter2' },
    worker: { ok: false, error: new Error('worker down token=abc') },
    enrichment: {
      ok: true,
      jobs: [{ id: 'bgp-origin', finishedAt: '2026-10-14T07:00:00.000Z', startedAt: null }],
      problems: [{
        level: 'warning',
        code: 'enrichment_stale',
        message: 'bgp-origin устарел',
        job: 'bgp-origin',
      }],
    },
  });
  const clickhouse = result.problems.find((item) => item.id === 'clickhouse:clickhouse_down');
  assert.equal(clickhouse.level, 'critical');
  assert.equal(clickhouse.link, null);
  assert.doesNotMatch(clickhouse.message, /secret|hunter2/);
  const worker = result.problems.find((item) => item.id === 'worker:check_failed');
  assert.equal(worker.level, 'critical');
  assert.doesNotMatch(worker.message, /abc/);
  const enrichment = result.problems.find((item) => item.id === 'enrichment:enrichment_stale:bgp-origin');
  assert.equal(enrichment.since, '2026-10-14T07:00:00.000Z');
  assert.deepEqual(
    result.problems.map((item) => item.component),
    ['worker', 'clickhouse', 'enrichment'],
  );
});

test('since worker берётся из возраста, а не из текста', () => {
  const result = view({
    worker: {
      ok: true,
      problems: [{
        level: 'critical',
        code: 'worker_offline',
        message: 'grapes-worker не отвечает',
        heartbeatAgeSec: 90,
      }],
    },
  });
  assert.equal(
    result.problems.find((item) => item.id === 'worker:worker_offline').since,
    new Date(NOW - 90 * 1000).toISOString(),
  );
});

test('окно графика начинается за 30 минут до старта, норма считается из роста', () => {
  const window = attackHistoryWindow({
    startMinute: '2026-10-14 08:00:00',
    alertMinute: '2026-10-14 08:10:00',
  }, NOW);
  assert.equal(window.from, '2026-10-14 07:30:00');
  assert.equal(window.to, '2026-10-14 09:00:00');
  assert.deepEqual(attackHistoryWindow({
    status: 'normalized',
    startMinute: '2026-10-12 10:44:00',
    normalizeMinute: '2026-10-12 11:20:00',
  }, NOW), { from: '2026-10-12 10:14:00', to: '2026-10-12 11:50:00' });
  assert.equal(attackHistoryWindow({
    status: 'peak',
    startMinute: '2026-10-14 08:40:00',
    alertMinute: '2026-10-14 08:45:00',
  }, NOW).to, '2026-10-14 09:00:00');

  const points = mergeAttackHistoryPoints(
    [{ t: '2026-10-14 08:10:00', bucketMs: 1, v: 300 }],
    [{ t: '2026-10-14 08:10:00', bucketMs: 1, v: 3 }],
  );
  assert.equal(points[0].bps, 300);
  assert.equal(points[0].growthBps, 3);
  assert.equal(points[0].baselineBps, 100);
  assert.equal(attackSliceMinute({ alertMinute: '2026-10-14 08:10:00', live: { lastHotMinute: '2026-10-14 08:40:00' } }), '2026-10-14 08:40:00');
  assert.equal(attackSliceMinute({}), null);
});

test('последняя минута запрашивается только у молчащих источников', () => {
  assert.deepEqual(silentSourceIds([
    { state: 'online', sources: [{ sourceId: 'a', isLive: true }, { sourceId: 'b', isLive: false }] },
    { state: 'offline', sources: [{ sourceId: 'c', isLive: false }] },
    { state: 'empty', sources: [] },
  ]), ['b', 'c']);
});
