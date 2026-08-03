'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const T = require('../public/data/explorer-thresholds.js');

const schemaMetrics = T.EXPLORER_THRESHOLD_DEFAULT_METRICS;

describe('Explorer threshold DSL', () => {
  it('parses avg threshold with unit', () => {
    const draft = T.parseExplorerThresholdDslLine('threshold avg bps > 100 mbps', schemaMetrics);
    assert.equal(draft.metric, 'bps');
    assert.equal(draft.aggregate, 'avg');
    assert.equal(draft.op, 'gt');
    assert.equal(draft.value, '100');
    assert.equal(draft.unit, 'mbps');
  });

  it('parses peak threshold with window', () => {
    const draft = T.parseExplorerThresholdDslLine('threshold peak bps 5m > 1 gbps', schemaMetrics);
    assert.equal(draft.aggregate, 'peak');
    assert.equal(draft.peakWindow, '5m');
    assert.equal(draft.op, 'gt');
    assert.equal(draft.value, '1');
    assert.equal(draft.unit, 'gbps');
  });

  it('parses between range with trailing unit', () => {
    const draft = T.parseExplorerThresholdDslLine('threshold avg volume between 1 and 10 gb', schemaMetrics);
    assert.equal(draft.metric, 'volume');
    assert.equal(draft.op, 'between');
    assert.equal(draft.value, '1');
    assert.equal(draft.value2, '10');
    assert.equal(draft.unit, 'gb');
  });

  it('parses outside pct range', () => {
    const draft = T.parseExplorerThresholdDslLine('threshold avg pct outside 5 and 25 pct', schemaMetrics);
    assert.equal(draft.metric, 'pct');
    assert.equal(draft.op, 'outside');
    assert.equal(draft.value, '5');
    assert.equal(draft.value2, '25');
    assert.equal(draft.unit, 'pct');
  });

  it('serializes threshold drafts back to DSL', () => {
    const draft = {
      metric: 'bps',
      aggregate: 'avg',
      op: 'gt',
      value: '100',
      value2: '',
      unit: 'mbps',
      peakWindow: '5m',
    };
    assert.equal(
      T.serializeExplorerThresholdDraftToDsl(draft, schemaMetrics),
      'threshold avg bps > 100 mbps',
    );
  });

  it('round-trips peak threshold DSL', () => {
    const line = 'threshold peak volume 1h >= 500 mb';
    const draft = T.parseExplorerThresholdDslLine(line, schemaMetrics);
    assert.equal(T.serializeExplorerThresholdDraftToDsl(draft, schemaMetrics), line);
  });

  it('throws on unknown metric with message', () => {
    assert.throws(
      () => T.parseExplorerThresholdDslLine('threshold avg unknown_metric > 1 mbps', schemaMetrics),
      /неизвестная метрика порога/i,
    );
  });

  it('throws on invalid unit', () => {
    assert.throws(
      () => T.parseExplorerThresholdDslLine('threshold avg bps > 100 xyz', schemaMetrics),
      /неизвестная единица/i,
    );
  });

  it('throws on peak for unsupported metric', () => {
    assert.throws(
      () => T.parseExplorerThresholdDslLine('threshold peak pct 5m > 1 pct', schemaMetrics),
      /не поддерживает peak/i,
    );
  });
});

describe('Explorer threshold DSL autocomplete', () => {
  it('detects value stage for bps threshold', () => {
    const ctx = T.analyzeExplorerThresholdDslPartial('threshold avg bps > ', schemaMetrics);
    assert.equal(ctx.stage, 'value');
    assert.equal(ctx.metric, 'bps');
    assert.equal(ctx.op, '>');
  });

  it('detects unit completion stage without falling back to count', () => {
    const ctx = T.analyzeExplorerThresholdDslPartial('threshold avg bps > 100 m', schemaMetrics);
    assert.equal(ctx.stage, 'unit');
    assert.equal(ctx.metric, 'bps');
    assert.deepEqual(ctx.units, ['mbps']);
  });

  it('suggests value presets for bps, not count', () => {
    const items = T.buildExplorerThresholdDslSuggestions('threshold avg bps > ', '', schemaMetrics);
    assert.ok(items.length > 0);
    assert.ok(items.some((item) => item.label.includes('mbps')));
    assert.ok(!items.some((item) => item.label === 'count'));
  });

  it('suggests matching units while typing partial unit', () => {
    const items = T.buildExplorerThresholdDslSuggestions('threshold avg bps > 100 m', '', schemaMetrics);
    assert.ok(items.some((item) => item.label === 'mbps'));
    assert.ok(items.every((item) => item.insert.includes('100 mbps')));
    assert.ok(!items.some((item) => item.label === 'count'));
  });

  it('keeps metric stage for partial metric names', () => {
    const ctx = T.analyzeExplorerThresholdDslPartial('threshold avg bp', schemaMetrics);
    assert.equal(ctx.stage, 'metric');
    assert.deepEqual(ctx.metricCandidates, ['bps']);
  });
});
