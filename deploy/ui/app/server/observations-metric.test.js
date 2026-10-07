const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  observationRollupBucketRate,
  observationWindowAverage,
  ROLLUP_BUCKET_SEC,
} = require('./observations');

describe('observation chart metric values', () => {
  it('считает пакеты/с из rollup-бакета', () => {
    const rate = observationRollupBucketRate(
      { bytes: 8000, packets: 900, flows: 10 },
      'pps',
      ROLLUP_BUCKET_SEC,
    );
    assert.equal(rate, 3);
  });

  it('считает бит/с из rollup-бакета', () => {
    const rate = observationRollupBucketRate(
      { bytes: 375000000, packets: 900, flows: 10 },
      'bps',
      ROLLUP_BUCKET_SEC,
    );
    assert.equal(rate, Math.round((375000000 * 8) / ROLLUP_BUCKET_SEC));
  });

  it('усредняет метрику за окно топа', () => {
    const avg = observationWindowAverage(
      { bytes: 9000, packets: 6000, flows: 120 },
      'pps',
      3600,
    );
    assert.equal(avg, Math.round(6000 / 3600));
  });
});
