'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeSchedule,
  getZonedYmdHm,
  zonedLocalToUtcIso,
  reportWindowForPeriod,
  lastScheduledSlot,
  isScheduleDue,
} = require('./observation-schedule');

describe('normalizeSchedule', () => {
  it('migrates legacy cron 0 8 * * * to daily 08:00 Moscow', () => {
    const s = normalizeSchedule({ cron: '0 8 * * *' });
    assert.equal(s.kind, 'daily');
    assert.equal(s.time, '08:00');
    assert.equal(s.timezone, 'Europe/Moscow');
  });

  it('ignores arbitrary cron and falls back to daily 08:00', () => {
    const s = normalizeSchedule({ cron: '30 14 * * 1' });
    assert.equal(s.kind, 'daily');
    assert.equal(s.time, '08:00');
  });

  it('preserves explicit schedule object', () => {
    const s = normalizeSchedule({
      schedule: { kind: 'weekly', time: '09:30', weekday: 3, timezone: 'Europe/Moscow' },
    });
    assert.equal(s.kind, 'weekly');
    assert.equal(s.time, '09:30');
    assert.equal(s.weekday, 3);
  });
});

describe('reportWindowForPeriod yesterday Moscow', () => {
  it('uses local calendar day boundaries, not UTC midnight', () => {
    const schedule = { kind: 'daily', time: '08:00', timezone: 'Europe/Moscow' };
    const now = new Date('2026-07-26T10:00:00.000Z');
    const win = reportWindowForPeriod('yesterday', schedule, now);

    assert.equal(win.period, 'yesterday');
    assert.equal(win.range, 'custom');
    assert.equal(win.from, '2026-07-24T21:00:00.000Z');
    assert.equal(win.to, '2026-07-25T21:00:00.000Z');
    assert.match(win.label, /25 июля 2026, 00:00–24:00 \(Europe\/Moscow\)/);
  });

  it('getZonedYmdHm matches Moscow local components', () => {
    const z = getZonedYmdHm(new Date('2026-07-26T10:00:00.000Z'), 'Europe/Moscow');
    assert.deepEqual(z, { year: 2026, month: 7, day: 26, hour: 13, minute: 0 });
  });

  it('zonedLocalToUtcIso round-trips midnight Moscow', () => {
    const iso = zonedLocalToUtcIso(2026, 7, 25, 0, 0, 'Europe/Moscow');
    assert.equal(iso, '2026-07-24T21:00:00.000Z');
    const z = getZonedYmdHm(new Date(iso), 'Europe/Moscow');
    assert.deepEqual(z, { year: 2026, month: 7, day: 25, hour: 0, minute: 0 });
  });
});

describe('isScheduleDue daily', () => {
  const schedule = { kind: 'daily', time: '08:00', timezone: 'Europe/Moscow' };

  it('is due after scheduled time when there was no successful run', () => {
    const now = new Date('2026-07-26T06:00:00.000Z');
    assert.equal(isScheduleDue(schedule, null, now), true);
  });

  it('is not due before scheduled local time', () => {
    const now = new Date('2026-07-26T04:00:00.000Z');
    assert.equal(isScheduleDue(schedule, null, now), false);
  });

  it('is not due when last success covers the current slot', () => {
    const now = new Date('2026-07-26T06:00:00.000Z');
    const lastSuccess = '2026-07-26T05:30:00.000Z';
    assert.equal(isScheduleDue(schedule, lastSuccess, now), false);
  });
});

describe('isScheduleDue grace skip', () => {
  const schedule = { kind: 'daily', time: '08:00', timezone: 'Europe/Moscow' };

  it('skips missed slots older than grace window', () => {
    const now = new Date('2026-07-26T20:00:00.000Z');
    assert.equal(isScheduleDue(schedule, null, now, { graceHours: 6 }), false);
  });

  it('lastScheduledSlot returns today 08:00 Moscow when now is 09:00 Moscow', () => {
    const now = new Date('2026-07-26T06:00:00.000Z');
    const slot = lastScheduledSlot(schedule, now);
    assert.equal(slot.toISOString(), '2026-07-26T05:00:00.000Z');
  });
});
