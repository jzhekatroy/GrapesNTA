'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  explorerFlows,
  explorerSummary,
  explorerResultSeries,
} = require('./explorer');

const WINDOW = {
  range: 'custom',
  from: '2026-08-14 04:40:00',
  to: '2026-08-14 05:35:00',
  metric: 'bps',
  limit: 25,
};

describe('explorer query shape', () => {
  it('filters direction as a raw column and aggregates once', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['dst_entity'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    });
    assert.match(spec.sql, /f\.`direction` = \{filter_0:String\}/);
    assert.doesNotMatch(spec.sql, /toString\(toString/);
    assert.doesNotMatch(spec.sql, /grouped_total/);
    assert.match(spec.sql, /sum\(a\.bytes\) OVER \(\)/);
  });

  it('keeps proto/ASN series matching on labels', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['dst_entity', 'proto'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    }, [
      { id: 'r1', rawValues: ['isp:pin', 'TCP'], values: ['PIN', 'TCP'] },
    ]);
    assert.match(spec.sql, /f\.`dst_entity` = \{series_g_0:String\}/);
    assert.match(spec.sql, /toString\(/);
    assert.equal(spec.params.series_g_0, 'isp:pin');
  });

  it('matches single dst_entity series by raw key IN', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['dst_entity'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    }, [
      { id: 'r1', rawValues: ['isp:pin'], values: ['PIN'] },
      { id: 'r2', rawValues: ['isp:arbital'], values: ['Arbital'] },
    ]);
    assert.match(spec.sql, /f\.`dst_entity` IN \{series_ids:Array\(String\)\}/);
    assert.deepEqual(spec.params.series_ids, ['isp:pin', 'isp:arbital']);
  });

  it('omits unique IP sketches from the default summary', async () => {
    const spec = await explorerSummary({
      ...WINDOW,
      groupBy: ['dst_entity'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    });
    assert.doesNotMatch(spec.sql, /uniqCombined\(f\.`src_addr`\) AS uniq_src/);
    assert.doesNotMatch(spec.sql, /uniqCombined\(f\.`dst_addr`\) AS uniq_dst/);
    const mapped = await spec.map([{}]);
    assert.equal(mapped.uniqSrc, null);
    assert.equal(mapped.uniqDst, null);
  });
});
