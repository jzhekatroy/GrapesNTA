'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

function computeChartStackBands(pt, lines, getValue, stackMode) {
  const rawValues = lines.map((ln) => Math.max(0, getValue(pt, ln.key) ?? 0));
  const total = rawValues.reduce((s, v) => s + v, 0);
  const bands = [];
  let cum = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const raw = rawValues[i];
    const bottom = stackMode === 'share'
      ? (total > 0 ? (cum / total) * 100 : 0)
      : cum;
    cum += raw;
    const top = stackMode === 'share'
      ? (total > 0 ? (cum / total) * 100 : 0)
      : cum;
    bands.push({ raw, bottom, top, share: total > 0 ? (raw / total) * 100 : 0 });
  }
  return { bands, total };
}

test('stack sum cumulative bands', () => {
  const pt = { a: 10, b: 20, c: 5 };
  const lines = [{ key: 'a' }, { key: 'b' }, { key: 'c' }];
  const getValue = (p, k) => p[k];
  const { bands, total } = computeChartStackBands(pt, lines, getValue, 'sum');
  assert.equal(total, 35);
  assert.deepEqual(bands.map((b) => b.top), [10, 30, 35]);
});

test('stack share normalized to 100', () => {
  const pt = { a: 25, b: 75 };
  const lines = [{ key: 'a' }, { key: 'b' }];
  const getValue = (p, k) => p[k];
  const { bands } = computeChartStackBands(pt, lines, getValue, 'share');
  assert.equal(bands[1].top, 100);
  assert.equal(bands[0].share, 25);
  assert.equal(bands[1].share, 75);
});

test('stack share zero total', () => {
  const pt = { a: 0, b: 0 };
  const lines = [{ key: 'a' }, { key: 'b' }];
  const getValue = (p, k) => p[k];
  const { bands } = computeChartStackBands(pt, lines, getValue, 'share');
  assert.deepEqual(bands.map((b) => b.top), [0, 0]);
});
