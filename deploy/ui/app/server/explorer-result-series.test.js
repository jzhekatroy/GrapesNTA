'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { explorerResultSeries, explorerTrafficChart } = require('./explorer');

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

describe('explorer traffic chart', () => {
  it('считает общий ряд и ряды строк одним проходом, без отбора только выбранных портов', async () => {
    const spec = await explorerTrafficChart({
      ...WINDOW,
      groupBy: ['src_port'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    }, [
      { id: 'r1', rawValues: ['443'], values: ['443'] },
      { id: 'r2', rawValues: ['80'], values: ['80'] },
    ]);
    assert.match(spec.sql, /f\.`direction` = \{filter_0:String\}/);
    assert.match(spec.sql, /sumIf\(/);
    assert.match(spec.sql, /GROUP BY bucket/);
    assert.doesNotMatch(spec.sql, /GROUP BY bucket,/);
    const out = await spec.map([{
      bucket: '2026-08-14 04:40:00',
      bucket_ts: 1780000000,
      bytes: 1000,
      packets: 10,
      flows: 2,
      bps: 100,
      metric_value: 100,
      s0_bytes: 400,
      s0_packets: 4,
      s0_flows: 1,
      s1_bytes: 0,
      s1_packets: 0,
      s1_flows: 0,
    }]);
    assert.equal(out.timeseries.length, 1);
    assert.equal(out.timeseries[0].bytes, 1000);
    assert.equal(out.seriesByRow.r1.length, 1);
    assert.equal(out.seriesByRow.r1[0].bytes, 400);
    assert.equal(out.seriesByRow.r2.length, 0);
  });
});
