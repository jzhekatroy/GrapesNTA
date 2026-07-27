'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { resolveTrafficWindow } = require('./queries');
const {
  normalizeExplorerQuery,
  EXPLORER_MAX_LIMIT,
  EXPLORER_MAX_EXPORT_ROWS,
  explorerAggPctColumn,
} = require('./explorer');

describe('normalizeExplorerQuery limit', () => {
  it('caps UI limit at EXPLORER_MAX_LIMIT', () => {
    const q = normalizeExplorerQuery({ limit: 500 });
    assert.equal(q.limit, EXPLORER_MAX_LIMIT);
  });

  it('allows export limit up to EXPLORER_MAX_EXPORT_ROWS', () => {
    const q = normalizeExplorerQuery({ limit: EXPLORER_MAX_EXPORT_ROWS }, { maxLimit: EXPLORER_MAX_EXPORT_ROWS });
    assert.equal(q.limit, EXPLORER_MAX_EXPORT_ROWS);
  });

  it('preserves windowAnchor in normalized query', () => {
    const q = normalizeExplorerQuery({ range: '30m', windowAnchor: '2026-07-27 10:00:00' });
    assert.equal(q.windowAnchor, '2026-07-27 10:00:00');
  });
});

describe('resolveTrafficWindow anchor', () => {
  it('uses anchor param for relative ranges', () => {
    const spec = resolveTrafficWindow({ range: '30m', anchor: '2026-07-27 10:00:00' });
    assert.equal(spec.params.anchor, '2026-07-27 10:00:00');
    assert.match(spec.cteHead, /\{anchor:String\}/);
    assert.doesNotMatch(spec.cteHead, /now\(\) - INTERVAL 30 SECOND/);
  });

  it('does not attach anchor param for custom range', () => {
    const spec = resolveTrafficWindow({
      range: 'custom',
      from: '2026-07-27 09:00:00',
      to: '2026-07-27 10:00:00',
      anchor: '2026-07-27 10:00:00',
    });
    assert.equal(spec.params.from, '2026-07-27 09:00:00');
    assert.equal(spec.params.to, '2026-07-27 10:00:00');
    assert.equal(spec.params.anchor, undefined);
  });
});

describe('explorerAggPctColumn', () => {
  it('maps metrics to aggregate columns', () => {
    assert.equal(explorerAggPctColumn('bps'), 'bytes');
    assert.equal(explorerAggPctColumn('volume'), 'bytes');
    assert.equal(explorerAggPctColumn('pps'), 'packets');
    assert.equal(explorerAggPctColumn('fps'), 'flows');
    assert.equal(explorerAggPctColumn('flows'), 'flows');
  });
});
