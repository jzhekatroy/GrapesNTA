'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  explorerFlows,
  explorerResultSeries,
  parseExplorerAsPathRaw,
  parseExplorerAsPathHops,
  formatExplorerAsPathRawValue,
  formatExplorerAsPathDisplayLabel,
  explorerClickhouseGroupKey,
  explorerDimensions,
} = require('./explorer');

const WINDOW = {
  range: 'custom',
  from: '2026-08-14 04:40:00',
  to: '2026-08-14 05:35:00',
  metric: 'bps',
  limit: 25,
};

describe('explorer AS path filters', () => {
  it('builds has() with origin fallback for dst_as_path contains numeric ASN', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [{ field: 'dst_as_path', op: 'contains', value: '1299' }],
    });
    assert.match(
      spec.sql,
      /\(has\(f\.`dst_as_path`, \{filter_0:UInt32\}\) OR \(empty\(f\.`dst_as_path`\) AND \(f\.`\w+` = \{filter_0:UInt32\}\)\)\)/,
    );
    assert.equal(spec.params.filter_0, 1299);
    assert.doesNotMatch(spec.sql, /LIKE.*dst_as_path/i);
  });

  it('builds hasAny() with origin fallback for src_as_path in list', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [{ field: 'src_as_path', op: 'in', value: '1299, 174' }],
    });
    assert.match(
      spec.sql,
      /\(hasAny\(f\.`src_as_path`, \{filter_0:Array\(UInt32\)\}\) OR \(empty\(f\.`src_as_path`\) AND \(f\.`\w+` IN \{filter_0:Array\(UInt32\)\}\)\)\)/,
    );
    assert.deepEqual(spec.params.filter_0, [1299, 174]);
  });

  it('builds array equality for exact path match', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [{ field: 'src_as_path', op: '=', value: '6939 12389 34665' }],
    });
    assert.match(spec.sql, /f\.`src_as_path` = \{filter_0:Array\(UInt32\)\}/);
    assert.deepEqual(spec.params.filter_0, [6939, 12389, 34665]);
  });

  it('uses empty() for exact empty path match', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [{ field: 'src_as_path', op: '=', value: '' }],
    });
    assert.match(spec.sql, /empty\(f\.`src_as_path`\)/);
  });

  it('uses name lookup subquery for contains by organization name', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [{ field: 'dst_as_path', op: 'contains', value: 'Telia' }],
    });
    assert.match(spec.sql, /hasAny\(f\.`dst_as_path`, \(SELECT groupArray\(asn\) FROM/);
    assert.match(spec.sql, /positionCaseInsensitive\(name/);
    assert.doesNotMatch(spec.sql, /LIKE.*dst_as_path/i);
  });

  it('adds false clause for invalid path filter value', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [{ field: 'src_as_path', op: 'contains', value: '' }],
    });
    assert.match(spec.sql, /\b0\b/);
  });

  it('groups by raw AS path array column', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_as_path'],
    });
    assert.match(spec.sql, /f\.`src_as_path`/);
    assert.doesNotMatch(spec.sql, /arrayStringConcat\(.*GROUP BY/i);
  });

  it('matches result series by AS path array, not display label', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['src_as_path'],
      filters: [],
    }, [
      {
        id: 'r1',
        rawValues: ['6939 12389'],
        values: ['AS6939 → AS12389'],
      },
    ]);
    assert.match(spec.sql, /f\.`src_as_path` = \{series_g_0:Array\(UInt32\)\}/);
    assert.deepEqual(spec.params.series_g_0, [6939, 12389]);
  });

  it('пришивает точки динамики к строке, когда ClickHouse отдал массив hop', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['src_asn', 'dst_as_path', 'dst_asn'],
      filters: [],
    }, [
      {
        id: 'r1',
        rawValues: ['AS15169', '1299 3356', 'AS13335'],
        values: ['AS15169 Google', 'AS1299 Telia → AS3356 Level3', 'AS13335 Cloudflare'],
      },
    ]);
    const out = await spec.map([
      {
        g0: 'AS15169',
        g1: [1299, 3356],
        g2: 'AS13335',
        bucket: '2026-08-14 04:40:00',
        bucket_ts: 1723610400,
        bytes: 1000,
        packets: 10,
        flows: 1,
        bps: 8000,
        pps: 1,
        fps: 1,
      },
      {
        g0: 'AS15169',
        g1: '1299,3356',
        g2: 'AS13335',
        bucket: '2026-08-14 04:41:00',
        bucket_ts: 1723610460,
        bytes: 2000,
        packets: 20,
        flows: 1,
        bps: 16000,
        pps: 2,
        fps: 1,
      },
    ]);
    assert.equal(out.seriesByRow.r1.length, 2);
    assert.equal(out.seriesByRow.r1[0].bps, 8000);
    assert.equal(out.seriesByRow.r1[1].bps, 16000);
  });
});

describe('explorer AS path helpers', () => {
  it('parses hop lists from space and comma separated input', () => {
    assert.deepEqual(parseExplorerAsPathHops('6939 12389 34665'), { hops: [6939, 12389, 34665] });
    assert.deepEqual(parseExplorerAsPathHops('6939,12389,34665'), { hops: [6939, 12389, 34665] });
    assert.deepEqual(parseExplorerAsPathHops(''), { empty: true, hops: [] });
    assert.equal(parseExplorerAsPathHops('foo bar'), null);
  });

  it('formats display labels with arrow separators', () => {
    const label = formatExplorerAsPathDisplayLabel([6939, 12389], new Map([
      [6939, 'Hurricane Electric'],
      [12389, 'Rostelecom'],
    ]));
    assert.equal(label, 'AS6939 Hurricane Electric → AS12389 Rostelecom');
    assert.equal(formatExplorerAsPathDisplayLabel([], new Map()), '—');
    assert.equal(formatExplorerAsPathRawValue([6939, 12389]), '6939 12389');
  });

  it('parses raw path values from arrays and strings', () => {
    assert.deepEqual(parseExplorerAsPathRaw([6939, 12389]), [6939, 12389]);
    assert.deepEqual(parseExplorerAsPathRaw('6939 12389'), [6939, 12389]);
    assert.deepEqual(parseExplorerAsPathRaw('—'), []);
  });

  it('нормализует AS path из массива и из строки с запятыми к одному ключу', () => {
    const dims = explorerDimensions();
    const groups = ['src_asn', 'dst_as_path', 'dst_asn'];
    const fromArray = explorerClickhouseGroupKey(groups, dims, {
      g0: 'AS15169',
      g1: [1299, 3356],
      g2: 'AS13335',
    });
    const fromComma = explorerClickhouseGroupKey(groups, dims, {
      g0: 'AS15169',
      g1: '1299,3356',
      g2: 'AS13335',
    });
    const fromSpaces = explorerClickhouseGroupKey(groups, dims, {
      g0: 'AS15169',
      g1: '1299 3356',
      g2: 'AS13335',
    });
    assert.equal(fromArray, 'AS15169|1299 3356|AS13335');
    assert.equal(fromComma, fromArray);
    assert.equal(fromSpaces, fromArray);
  });
});
