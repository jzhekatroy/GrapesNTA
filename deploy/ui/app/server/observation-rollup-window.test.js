'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  computeSafeTo,
  widenForRecheck,
  floorToBucket,
  SAFETY_BUCKETS,
  RECHECK_BUCKETS,
} = require('./observations-rollup');

const BUCKET_MS = 5 * 60 * 1000;

describe('computeSafeTo', () => {
  it('по умолчанию доходит до только что закрытого бакета', () => {
    assert.equal(SAFETY_BUCKETS, 0);
    const now = new Date('2026-08-17T02:07:31.000Z');
    assert.equal(computeSafeTo(now).toISOString(), '2026-08-17T02:05:00.000Z');
  });

  it('на границе бакета не заглядывает в незакрытый бакет', () => {
    const now = new Date('2026-08-17T02:05:00.000Z');
    assert.equal(computeSafeTo(now).toISOString(), '2026-08-17T02:05:00.000Z');
  });
});

describe('widenForRecheck', () => {
  const started = new Date('2026-08-17T00:00:00.000Z');

  it('откатывает окно на один записанный бакет', () => {
    assert.equal(RECHECK_BUCKETS, 1);
    const from = new Date('2026-08-17T02:05:00.000Z');
    const job = { cursorMinute: from.toISOString(), startedAt: started.toISOString() };
    assert.equal(widenForRecheck(job, from).toISOString(), '2026-08-17T02:00:00.000Z');
  });

  it('не уходит раньше создания наблюдения', () => {
    const from = floorToBucket(started);
    const job = { cursorMinute: from.toISOString(), startedAt: started.toISOString() };
    assert.equal(widenForRecheck(job, from).getTime(), started.getTime());
  });

  it('на первом шоте без курсора окно не расширяет', () => {
    const from = new Date('2026-08-17T02:05:00.000Z');
    const job = { startedAt: started.toISOString() };
    assert.equal(widenForRecheck(job, from).getTime(), from.getTime());
  });

  it('перепроверка не двигает правый край окна', () => {
    const now = new Date('2026-08-17T02:07:31.000Z');
    const safeTo = computeSafeTo(now);
    const cursor = new Date(safeTo.getTime() - BUCKET_MS);
    const job = { cursorMinute: cursor.toISOString(), startedAt: started.toISOString() };
    const from = widenForRecheck(job, cursor);
    assert.equal(safeTo.getTime() - from.getTime(), 2 * BUCKET_MS);
  });
});
