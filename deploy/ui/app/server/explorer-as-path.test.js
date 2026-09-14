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
} = require('./explorer');

const WINDOW = {
  range: 'custom',
  from: '2026-08-14 04:40:00',
  to: '2026-08-14 05:35:00',
  metric: 'bps',
  limit: 25,
};

describe('explorer AS path filters', () => {
  it('builds has() for dst_as_path contains numeric ASN', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [{ field: 'dst_as_path', op: 'contains', value: '1299' }],
    });
    assert.match(spec.sql, /has\(f\.`dst_as_path`, \{filter_0:UInt32\}\)/);
    assert.equal(spec.params.filter_0, 1299);
    assert.doesNotMatch(spec.sql, /LIKE.*dst_as_path/i);
  });

  it('builds hasAny() for src_as_path in list', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip'],
      filters: [{ field: 'src_as_path', op: 'in', value: '1299, 174' }],
    });
    assert.match(spec.sql, /hasAny\(f\.`src_as_path`, \{filter_0:Array\(UInt32\)\}\)/);
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
});
