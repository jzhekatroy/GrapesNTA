'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { explorerFlows, explorerResultSeries, explorerTrafficChart } = require('./explorer');

function withSeriesKey(row, values, types) {
  Object.defineProperty(row, 'seriesKey', { value: { values, types }, enumerable: false });
  return row;
}

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

  const keyedRows = () => {
    const types = ['FixedString(16)', 'UInt32'];
    return [
      withSeriesKey({ id: 'r1', rawValues: ['8.8.8.8', '443'], values: ['8.8.8.8', '443'] },
        ['08080808000000000000000000000000', '343433'], types),
      withSeriesKey({ id: 'r2', rawValues: ['1.1.1.1', '53'], values: ['1.1.1.1', '53'] },
        ['01010101000000000000000000000000', '3533'], types),
    ];
  };

  it('находит ряд по сырым ключам строки, без toString() измерений и sumIf', async () => {
    const spec = await explorerTrafficChart({
      ...WINDOW,
      groupBy: ['src_ip', 'dst_port'],
      filters: [],
    }, keyedRows());
    assert.match(spec.sql, /CAST\(unhex\('08080808000000000000000000000000'\) AS FixedString\(16\)\)/);
    assert.match(spec.sql, /tuple\([^)]*\) IN \(tuple\(CAST/);
    assert.match(spec.sql, /GROUP BY bucket, bucket_ts, series_hit, series_k0, series_k1/);
    assert.match(spec.sql, /groupArrayIf\(\s*tuple\(\[hex\(toString\(series_k0\)\), hex\(toString\(series_k1\)\)\], s_bytes, s_packets, s_flows\),\s*series_hit\s*\)/);
    assert.doesNotMatch(spec.sql, /sumIf\(/);
    assert.doesNotMatch(spec.sql, /series_g_/);
    assert.doesNotMatch(spec.sql, /toString\(if\(/);
  });

  it('раскладывает ряды из массива по строкам таблицы', async () => {
    const spec = await explorerTrafficChart({
      ...WINDOW,
      groupBy: ['src_ip', 'dst_port'],
      filters: [],
    }, keyedRows());
    const out = await spec.map([{
      bucket: '2026-08-14 04:40:00',
      bucket_ts: 1780000000,
      bytes: '1000',
      packets: '10',
      flows: '3',
      bps: 27,
      metric_value: 27,
      series: [[['01010101000000000000000000000000', '3533'], '300', '3', '1']],
    }]);
    assert.equal(out.timeseries[0].bytes, 1000);
    assert.equal(out.seriesByRow.r1.length, 0);
    assert.equal(out.seriesByRow.r2.length, 1);
    assert.equal(out.seriesByRow.r2[0].bytes, 300);
    assert.equal(out.seriesByRow.r2[0].packets, 3);
  });

  it('один числовой ключ ищет через transform и раскладывает ряд по номеру', async () => {
    const spec = await explorerTrafficChart({
      ...WINDOW,
      groupBy: ['src_asn'],
      filters: [],
    }, [
      withSeriesKey({ id: 'r1', rawValues: ['AS15169'], values: ['AS15169'] }, ['3135313639'], ['UInt32']),
      withSeriesKey({ id: 'r2', rawValues: ['AS174'], values: ['AS174'] }, ['313734'], ['UInt32']),
    ]);
    assert.match(spec.sql, /transform\([^\n]*\[CAST\(unhex\('3135313639'\) AS UInt32\), CAST\(unhex\('313734'\) AS UInt32\)\], \[1, 2\], 0\) AS series_idx/);
    assert.match(spec.sql, /GROUP BY bucket, bucket_ts, series_hit, series_k0/);
    assert.doesNotMatch(spec.sql, / IN \(tuple/);
    const out = await spec.map([{
      bucket: '2026-08-14 04:40:00',
      bucket_ts: 1780000000,
      bytes: '900',
      packets: '9',
      flows: '3',
      bps: 24,
      metric_value: 24,
      series: [[['1'], '500', '5', '2'], [['2'], '100', '1', '1']],
    }]);
    assert.equal(out.seriesByRow.r1[0].bytes, 500);
    assert.equal(out.seriesByRow.r2[0].bytes, 100);
  });

  it('для uniq_src оставляет sumIf: уникальных нельзя сложить из рядов', async () => {
    const spec = await explorerTrafficChart({
      ...WINDOW,
      metric: 'uniq_src',
      groupBy: ['src_ip', 'dst_port'],
      filters: [],
    }, keyedRows());
    assert.doesNotMatch(spec.sql, /series_hit/);
    assert.match(spec.sql, /uniqCombined/);
  });

  it('без ключей хотя бы у одной строки сравнивает подписи, как раньше', async () => {
    const spec = await explorerTrafficChart({
      ...WINDOW,
      groupBy: ['src_ip', 'dst_port'],
      filters: [],
    }, [
      withSeriesKey({ id: 'r1', rawValues: ['8.8.8.8', '443'], values: ['8.8.8.8', '443'] },
        ['08080808000000000000000000000000', '343433'], ['FixedString(16)', 'UInt32']),
      { id: 'r2', rawValues: ['1.1.1.1', '53'], values: ['1.1.1.1', '53'] },
    ]);
    assert.doesNotMatch(spec.sql, /series_hit/);
    assert.match(spec.sql, /series_g_0/);
  });
});

describe('explorer flows series keys', () => {
  it('отдаёт сырые ключи строк графику, но не в JSON ответа', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip', 'dst_port'],
      filters: [],
    });
    assert.match(spec.sql, /hex\(toString\(a\.k0\)\) AS series_key_0/);
    assert.match(spec.sql, /toTypeName\(a\.k1\) AS series_key_type_1/);
    const rows = await spec.map([{
      g0: '8.8.8.8',
      g1: '443',
      metric_value: 1,
      pct: 100,
      bytes: 10,
      avg_bps: 1,
      packets: 1,
      flows: 1,
      series_key_0: '08080808000000000000000000000000',
      series_key_type_0: 'FixedString(16)',
      series_key_1: '343433',
      series_key_type_1: 'LowCardinality(String)',
    }]);
    assert.deepEqual(rows[0].seriesKey, {
      values: ['08080808000000000000000000000000', '343433'],
      types: ['FixedString(16)', 'String'],
    });
    assert.equal(JSON.stringify(rows[0]).includes('seriesKey'), false);
  });

  it('не прикрепляет ключ с подозрительным типом', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [],
    });
    const rows = await spec.map([{
      g0: '8.8.8.8',
      metric_value: 1,
      pct: 100,
      bytes: 10,
      avg_bps: 1,
      packets: 1,
      flows: 1,
      series_key_0: '08080808000000000000000000000000',
      series_key_type_0: "FixedString(16)'; DROP",
    }]);
    assert.equal(rows[0].seriesKey, undefined);
  });
});
