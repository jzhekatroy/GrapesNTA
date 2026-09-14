'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { resolveGrowthThreshold, hasGrowthOverride, objectKey } = require('./detection-thresholds');

describe('detection-thresholds', () => {
  it('без исключения берёт общий порог', () => {
    assert.equal(resolveGrowthThreshold('client', '71764', 1.6), 1.6);
    assert.equal(resolveGrowthThreshold('client', '71764', 1.6, new Map()), 1.6);
  });

  it('исключение перекрывает общий порог', () => {
    const map = new Map([[objectKey('client', '71764'), 4]]);
    assert.equal(resolveGrowthThreshold('client', '71764', 1.6, map), 4);
    assert.equal(resolveGrowthThreshold('client', '1', 1.6, map), 1.6);
  });

  it('нулевой и битый override не считаются исключением', () => {
    const map = new Map([
      [objectKey('client', 'a'), 0],
      [objectKey('client', 'b'), -1],
      [objectKey('client', 'c'), 'x'],
    ]);
    assert.equal(resolveGrowthThreshold('client', 'a', 1.6, map), 1.6);
    assert.equal(resolveGrowthThreshold('client', 'b', 1.6, map), 1.6);
    assert.equal(resolveGrowthThreshold('client', 'c', 1.6, map), 1.6);
    assert.equal(hasGrowthOverride('client', 'a', map), false);
    assert.equal(hasGrowthOverride('client', 'c', map), false);
  });

  it('hasGrowthOverride видит исключение', () => {
    const map = new Map([[objectKey('net', '10.0.0.0/24'), 8]]);
    assert.equal(hasGrowthOverride('net', '10.0.0.0/24', map), true);
    assert.equal(hasGrowthOverride('net', '10.0.1.0/24', map), false);
  });
});
