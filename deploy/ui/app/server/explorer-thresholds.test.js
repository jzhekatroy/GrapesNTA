'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeExplorerThreshold,
  normalizeExplorerThresholds,
  wrapSqlWithThresholdFilter,
  buildThresholdWhereParts,
  explorerThresholdWarning,
  describeThresholds,
  serializeObservationFiltersEnvelope,
  parseObservationFiltersEnvelope,
  thresholdAvgColumnSql,
  thresholdPeakColumnSql,
} = require('./explorer-thresholds');
const { explorerFlows, normalizeExplorerQuery } = require('./explorer');

describe('normalizeExplorerThreshold', () => {
  it('normalizes bps threshold with unit', () => {
    const t = normalizeExplorerThreshold({
      metric: 'bps',
      op: 'gt',
      value: 100,
      unit: 'mbps',
      aggregate: 'avg',
    });
    assert.equal(t.metric, 'bps');
    assert.equal(t.value, 100);
    assert.equal(t.unit, 'mbps');
    assert.equal(t.aggregate, 'avg');
  });

  it('swaps between range boundaries', () => {
    const t = normalizeExplorerThreshold({
      metric: 'volume',
      op: 'between',
      value: 500,
      value2: 100,
      unit: 'gb',
    });
    assert.equal(t.value, 100);
    assert.equal(t.value2, 500);
  });

  it('drops invalid metrics and empty values', () => {
    assert.equal(normalizeExplorerThreshold({ metric: 'unknown', value: 1 }), null);
    assert.equal(normalizeExplorerThreshold({ metric: 'bps', value: '' }), null);
    assert.equal(normalizeExplorerThreshold({ metric: 'bps', op: 'between', value: 10 }), null);
  });

  it('downgrades peak on unsupported metrics', () => {
    const t = normalizeExplorerThreshold({
      metric: 'pct',
      aggregate: 'peak',
      op: 'gt',
      value: 5,
      unit: 'pct',
    });
    assert.equal(t.aggregate, 'avg');
    assert.equal(t.peakWindow, null);
  });

  it('keeps peak window for supported metrics', () => {
    const t = normalizeExplorerThreshold({
      metric: 'bps',
      aggregate: 'peak',
      peakWindow: '1h',
      op: 'gte',
      value: 1e9,
      unit: 'bps',
    });
    assert.equal(t.aggregate, 'peak');
    assert.equal(t.peakWindow, '1h');
  });

  it('accepts flows count with thousand and million units', () => {
    const k = normalizeExplorerThreshold({ metric: 'flows', op: 'gt', value: 100, unit: 'k' });
    const m = normalizeExplorerThreshold({ metric: 'flows', op: 'gt', value: 2, unit: 'm' });
    assert.equal(k.unit, 'k');
    assert.equal(m.unit, 'm');
  });
});

describe('normalizeExplorerThresholds', () => {
  it('filters invalid entries silently', () => {
    const list = normalizeExplorerThresholds([
      { metric: 'bps', op: 'gt', value: 1, unit: 'mbps' },
      { metric: 'bad', value: 2 },
      { metric: 'pps', op: 'lt', value: 1000, unit: 'pps' },
    ]);
    assert.equal(list.length, 2);
    assert.equal(list[0].metric, 'bps');
    assert.equal(list[1].metric, 'pps');
  });
});

describe('wrapSqlWithThresholdFilter', () => {
  it('applies outer WHERE before LIMIT', () => {
    const thresholds = normalizeExplorerThresholds([
      { metric: 'bps', op: 'gt', value: 1e6, unit: 'bps' },
    ]);
    const wrapped = wrapSqlWithThresholdFilter({
      innerSql: 'SELECT 1 AS avg_bps',
      thresholds,
      orderBy: 'avg_bps DESC',
      limitParam: '{limit:UInt32}',
      offsetParam: '{offset:UInt32}',
    });
    assert.match(wrapped.sql, /WHERE .*avg_bps/);
    assert.match(wrapped.sql, /ORDER BY avg_bps DESC/);
    assert.match(wrapped.sql, /LIMIT \{limit:UInt32\}/);
    assert.match(wrapped.sql, /rows_before_threshold/);
    assert.match(wrapped.sql, /rows_hidden/);
    assert.equal(wrapped.hasThresholdWrap, true);
    assert.ok(wrapped.thresholdParams.thr_0_v0 != null);
  });

  it('passes through when no thresholds', () => {
    const wrapped = wrapSqlWithThresholdFilter({
      innerSql: 'SELECT 1',
      thresholds: [],
    });
    assert.equal(wrapped.hasThresholdWrap, false);
    assert.match(wrapped.sql, /LIMIT \{limit:UInt32\}/);
  });
});

describe('buildThresholdWhereParts', () => {
  it('combines multiple thresholds with AND semantics via separate parts', () => {
    const thresholds = normalizeExplorerThresholds([
      { metric: 'bps', op: 'gt', value: 1, unit: 'mbps' },
      { metric: 'pct', op: 'lt', value: 50, unit: 'pct' },
    ]);
    const params = {};
    const parts = buildThresholdWhereParts(thresholds, params, { i: 0 });
    assert.equal(parts.length, 2);
    assert.match(parts[0], /t\.avg_bps/);
    assert.match(parts[1], /t\.pct/);
    assert.ok(params.thr_0_v0 != null);
    assert.ok(params.thr_1_v0 != null);
  });
});

describe('threshold column sql', () => {
  it('maps avg and peak columns', () => {
    assert.equal(thresholdAvgColumnSql('avg_packet_size'), 'avg_packet_size');
    assert.equal(thresholdPeakColumnSql('pps'), 'peak_pps');
  });
});

describe('explorerThresholdWarning', () => {
  it('warns on peak + IP grouping + long window', () => {
    const msg = explorerThresholdWarning({
      thresholds: normalizeExplorerThresholds([
        { metric: 'bps', aggregate: 'peak', peakWindow: '5m', op: 'gt', value: 1, unit: 'mbps' },
      ]),
      groupBy: ['src_ip'],
      windowSeconds: 90000,
    });
    assert.match(msg, /длинном периоде/);
  });

  it('returns null for short windows', () => {
    const msg = explorerThresholdWarning({
      thresholds: normalizeExplorerThresholds([
        { metric: 'bps', aggregate: 'peak', peakWindow: '5m', op: 'gt', value: 1, unit: 'mbps' },
      ]),
      groupBy: ['src_ip'],
      windowSeconds: 3600,
    });
    assert.equal(msg, null);
  });
});

describe('observation filters envelope', () => {
  it('keeps legacy array format', () => {
    const env = parseObservationFiltersEnvelope([{ field: 'proto', op: '=', value: 'UDP' }]);
    assert.equal(env.filters.length, 1);
    assert.deepEqual(env.thresholds, []);
  });

  it('round-trips filters and thresholds', () => {
    const filters = [{ field: 'vlan', op: '=', value: '100' }];
    const thresholds = normalizeExplorerThresholds([
      { metric: 'bps', op: 'gt', value: 1000000, unit: 'bps' },
    ]);
    const raw = serializeObservationFiltersEnvelope(filters, thresholds);
    const parsed = parseObservationFiltersEnvelope(raw);
    assert.equal(parsed.filters.length, 1);
    assert.equal(parsed.thresholds.length, 1);
    assert.equal(parsed.thresholds[0].metric, 'bps');
  });

  it('stores plain filters array when no thresholds', () => {
    const raw = serializeObservationFiltersEnvelope([{ field: 'proto', op: '=', value: 'TCP' }], []);
    assert.ok(Array.isArray(raw));
    assert.equal(raw.length, 1);
  });
});

describe('normalizeExplorerQuery thresholds', () => {
  it('parses thresholds from body', () => {
    const q = normalizeExplorerQuery({
      metric: 'bps',
      groupBy: ['src_ip'],
      thresholds: [{ metric: 'bps', op: 'gt', value: 1, unit: 'mbps' }],
      range: '1h',
    });
    assert.equal(q.thresholds.length, 1);
    assert.equal(q.thresholds[0].metric, 'bps');
  });
});

describe('explorerFlows uniq_src thresholds', () => {
  it('selects uniq_src_count when uniq_src is only a threshold metric', async () => {
    const spec = await explorerFlows({
      metric: 'bps',
      groupBy: ['src_ip', 'dst_ip'],
      thresholds: [
        { metric: 'uniq_src', aggregate: 'avg', op: 'gt', value: 1, unit: 'count' },
      ],
      range: '30m',
      limit: 25,
    });

    assert.match(spec.sql, /uniqCombined\(f\.`[^`]+`\) AS uniq_src_count/);
    assert.match(spec.sql, /WHERE t\.uniq_src_count > \{thr_0_v0:Float64\}/);
    assert.doesNotMatch(spec.sql, /inner_agg AS \(/);
  });

  it('selects uniq_src_count when combined with a peak threshold', async () => {
    const spec = await explorerFlows({
      metric: 'bps',
      groupBy: ['src_ip', 'dst_ip'],
      thresholds: [
        { metric: 'bps', aggregate: 'peak', peakWindow: '5m', op: 'gt', value: 1, unit: 'bps' },
        { metric: 'uniq_src', aggregate: 'avg', op: 'gt', value: 1, unit: 'count' },
      ],
      range: '30m',
      limit: 25,
    });

    assert.match(spec.sql, /uniqCombinedMerge\(uniq_src_state\) AS uniq_src_count/);
    assert.match(spec.sql, /WHERE t\.peak_bps > \{thr_0_v0:Float64\} AND t\.uniq_src_count > \{thr_1_v0:Float64\}/);
  });
});

describe('describeThresholds', () => {
  it('formats human-readable summary', () => {
    const text = describeThresholds([
      { metric: 'bps', aggregate: 'avg', op: 'gt', value: 1000000, unit: 'bps' },
    ]);
    assert.match(text, /больше/);
    assert.match(text, /бит/);
  });
});
