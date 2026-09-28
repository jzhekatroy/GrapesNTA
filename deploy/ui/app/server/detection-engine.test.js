'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { BASELINE_CACHE_MS, isBaselineCacheFresh, dedupeClientsByDisplayName, clampClosedMinute } = require('./detection-engine');

describe('detection-engine closed minute', () => {
  const now = Date.parse('2026-09-28T13:23:40Z');

  it('оставляет минуту, которая уже старше запаса', () => {
    const ts = Date.parse('2026-09-28T13:10:00Z');
    assert.equal(clampClosedMinute(ts, now), ts);
  });

  it('обрезает минуту моложе четырёх минут до начала закрытой минуты', () => {
    const ts = Date.parse('2026-09-28T13:23:00Z');
    assert.equal(clampClosedMinute(ts, now), Date.parse('2026-09-28T13:19:00Z'));
  });

  it('пустую минуту не берёт', () => {
    assert.equal(clampClosedMinute(0, now), null);
    assert.equal(clampClosedMinute(NaN, now), null);
  });
});

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

describe('detection-engine client dedupe', () => {
  it('склеивает одно display_name и оставляет меньший числовой id', () => {
    const rows = dedupeClientsByDisplayName([
      { client_id: '106740', display_name: 'WEST CALL' },
      { client_id: '81993', display_name: 'WEST CALL' },
      { client_id: '1', display_name: 'Other' },
    ]);
    assert.deepEqual(
      rows.map((r) => r.client_id).sort((a, b) => Number(a) - Number(b)),
      ['1', '81993'],
    );
  });

  it('пустые имена не склеивает', () => {
    const rows = dedupeClientsByDisplayName([
      { client_id: '10', display_name: '' },
      { client_id: '11', display_name: '  ' },
    ]);
    assert.equal(rows.length, 2);
  });
});
