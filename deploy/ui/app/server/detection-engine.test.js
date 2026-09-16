'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { BASELINE_CACHE_MS, isBaselineCacheFresh } = require('./detection-engine');

describe('detection-engine baselines cache', () => {
  it('кэш живой только при данных внутри TTL', () => {
    const now = BASELINE_CACHE_MS * 2;
    const map = new Map([['net|10.0.0.0/24|all', { bps: 1 }]]);
    assert.equal(isBaselineCacheFresh({ at: now, map }, now), true);
    assert.equal(isBaselineCacheFresh({ at: now - BASELINE_CACHE_MS + 1, map }, now), true);
    assert.equal(isBaselineCacheFresh({ at: now - BASELINE_CACHE_MS, map }, now), false);
    assert.equal(isBaselineCacheFresh({ at: now, map: new Map() }, now), false);
    assert.equal(isBaselineCacheFresh({ at: 0, map }, now), false);
  });
});
