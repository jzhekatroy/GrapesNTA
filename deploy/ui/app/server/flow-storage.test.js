'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getResourceForPath } = require('./rbac/api-map');
const { forecastStorage, validateSettings, measuredNote } = require('./flow-storage');

test('flow storage uses the ttl page permission', () => {
  assert.equal(getResourceForPath('/api/admin/flow-storage'), 'ttl');
  assert.equal(getResourceForPath('/api/admin/flow-storage', 'PUT'), 'ttl');
});

test('defaults and presets pass, the rest is rejected', () => {
  const ok = validateSettings({
    mode: 'on', hotDays: 1, xdpRate: 64, xdpThresholdBytes: 100000, runAt: '04:30',
  });
  assert.equal(ok.error, undefined);
  assert.equal(ok.value.mode, 'on');

  assert.match(validateSettings({ mode: 'always', hotDays: 1, xdpRate: 64, xdpThresholdBytes: 100000, runAt: '04:30' }).error, /Режим/);
  assert.match(validateSettings({ mode: 'on', hotDays: 0, xdpRate: 64, xdpThresholdBytes: 100000, runAt: '04:30' }).error, /срок/);
  assert.match(validateSettings({ mode: 'on', hotDays: 1, xdpRate: 10, xdpThresholdBytes: 100000, runAt: '04:30' }).error, /Частота/);
  assert.match(validateSettings({ mode: 'on', hotDays: 1, xdpRate: 64, xdpThresholdBytes: 100, runAt: '04:30' }).error, /Порог/);
  assert.match(validateSettings({ mode: 'on', hotDays: 1, xdpRate: 64, xdpThresholdBytes: 100000, runAt: '4:30' }).error, /Время/);
});

test('a day is full while it is fresh, compressed after success, and shows the failure', () => {
  const { describeFlowDay } = require('./flow-storage');
  assert.equal(describeFlowDay('2026-09-24', null, { today: '2026-09-25', hotDays: 1 }).state, 'full');
  assert.equal(describeFlowDay('2026-09-25', null, { today: '2026-09-25', hotDays: 1 }).state, 'full');
  assert.equal(describeFlowDay('2026-09-23', { status: 'done' }, { today: '2026-09-25', hotDays: 1 }).state, 'done');
  const failed = describeFlowDay('2026-09-22', { status: 'failed', message: 'мало места' }, { today: '2026-09-25', hotDays: 1 });
  assert.equal(failed.state, 'failed');
  assert.equal(failed.error, 'мало места');
  assert.equal(describeFlowDay('2026-09-22', null, { today: '2026-09-25', hotDays: 1 }).state, 'pending');
});

test('forecast uses the measured shrink and falls back to the log', () => {
  const measured = forecastStorage({
    exactBytes: 151 * 1024 ** 3, ttlDays: 10, hotDays: 1, rate: 64, thresholdBytes: 100000,
  });
  assert.equal(measured.exactDays, 2);
  assert.equal(measured.warmDays, 8);
  assert.equal(measured.thinnedBytes, Math.round(151 * 1024 ** 3 / 34));
  assert.equal(measured.measured, true);
  assert.match(measuredNote(64, 100000), /0,002%/);

  const other = forecastStorage({
    exactBytes: 1000, ttlDays: 5, hotDays: 1, rate: 16, thresholdBytes: 100000,
  });
  assert.equal(other.thinnedBytes, null);
  assert.equal(other.note, 'не замерено');

  const fromLog = forecastStorage({
    exactBytes: 1000, ttlDays: 5, hotDays: 1, rate: 16, thresholdBytes: 100000, averagedBytes: 40,
  });
  assert.equal(fromLog.thinnedBytes, 40);
  assert.equal(fromLog.totalBytes, 1000 * 2 + 40 * 3);
});
