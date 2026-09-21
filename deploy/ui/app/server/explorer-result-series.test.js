'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { explorerResultSeries } = require('./explorer');

const WINDOW = {
  range: 'custom',
  from: '2026-08-14 04:40:00',
  to: '2026-08-14 05:35:00',
  metric: 'bps',
  limit: 25,
};

describe('explorer result series drill-down', () => {
  it('сравнивает ASN по числовой колонке, а не по подписи', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['src_asn'],
      filters: [],
    }, [
      { id: 'r1', rawValues: ['AS15169'], values: ['AS15169 Google'] },
    ]);
    assert.match(spec.sql, /f\.`SrcAS` = \{series_g_0:UInt32\}/);
    assert.equal(spec.params.series_g_0, 15169);
    assert.doesNotMatch(spec.sql, /toString\(multiIf\(/);
  });

  it('сравнивает MAC по сырой колонке, а не по собранной строке', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['src_mac'],
      filters: [],
    }, [
      { id: 'r1', rawValues: ['00:11:22:33:44:55'], values: ['00:11:22:33:44:55'] },
    ]);
    assert.match(spec.sql, /f\.`src_mac` = unhex\(\{series_g_0:String\}\)/);
    assert.equal(spec.params.series_g_0, '001122334455');
    assert.doesNotMatch(spec.sql, /toString\(lower\(arrayStringConcat/);
  });

  it('не строит запрос, если все строки — прочерки', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['src_asn', 'dst_asn', 'src_mac', 'dst_mac'],
      filters: [],
    }, [
      { id: 'r1', rawValues: ['—', '—', '—', '—'], values: ['—', '—', '—', '—'] },
    ]);
    assert.equal(spec.sql, undefined);
    const out = await spec.map([]);
    assert.deepEqual(out.seriesByRow, { r1: [] });
  });

  it('оставляет в запросе только строки, которые могут совпасть', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['src_asn'],
      filters: [],
    }, [
      { id: 'r1', rawValues: ['—'], values: ['—'] },
      { id: 'r2', rawValues: ['AS174'], values: ['AS174 Cogent'] },
    ]);
    assert.equal(spec.params.series_g_1, 174);
    assert.equal(spec.params.series_g_0, undefined);
    assert.equal((spec.sql.match(/f\.`SrcAS` = \{series_g_\d+:UInt32\}/g) || []).length, 1);
  });
});
