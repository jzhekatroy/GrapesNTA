'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { resolveObservationBackfill, BACKFILL_HOURS } = require('./observations');

const createdAt = '2026-08-18T05:00:00.000Z';

describe('resolveObservationBackfill', () => {
  it('по умолчанию не пересчитывает сутки до создания', () => {
    const mat = resolveObservationBackfill({
      materializeEnabled: true,
      wasEnabled: false,
      createdAt,
      rawMat: { enabled: true },
    });
    assert.equal(mat.backfillFrom, null);
    assert.equal(mat.backfillCursor, null);
    assert.equal(mat.backfillDone, true);
  });

  it('историю включает только явный materialize.backfill', () => {
    const mat = resolveObservationBackfill({
      materializeEnabled: true,
      wasEnabled: false,
      createdAt,
      rawMat: { enabled: true, backfill: true },
    });
    assert.equal(mat.backfillDone, false);
    assert.ok(mat.backfillFrom);
    const from = Date.parse(mat.backfillFrom);
    const created = Date.parse(createdAt);
    assert.equal(created - from, BACKFILL_HOURS * 3600 * 1000);
  });

  it('не сбрасывает уже идущий backfill', () => {
    const mat = resolveObservationBackfill({
      materializeEnabled: true,
      wasEnabled: true,
      createdAt,
      existingMat: {
        backfillFrom: '2026-08-17T05:00:00.000Z',
        backfillCursor: '2026-08-17T08:00:00.000Z',
        backfillDone: false,
      },
    });
    assert.equal(mat.backfillFrom, '2026-08-17T05:00:00.000Z');
    assert.equal(mat.backfillCursor, '2026-08-17T08:00:00.000Z');
    assert.equal(mat.backfillDone, false);
  });
});
