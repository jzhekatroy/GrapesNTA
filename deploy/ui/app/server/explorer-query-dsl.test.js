const test = require('node:test');
const assert = require('node:assert/strict');

const Q = require('../public/data/explorer-query-dsl.js');

const schema = {
  metricKeys: ['bps', 'volume', 'pps', 'fps', 'flows', 'uniq_src'],
  maxLimit: 10000,
};

test('parseExplorerMetricDslLine accepts known metrics', () => {
  assert.equal(Q.parseExplorerMetricDslLine('metric pps', schema), 'pps');
  assert.equal(Q.parseExplorerMetricDslLine('metric PPS', schema), 'pps');
  assert.equal(Q.parseExplorerMetricDslLine('metric bps', schema), 'bps');
});

test('parseExplorerMetricDslLine rejects unknown metric', () => {
  assert.throws(
    () => Q.parseExplorerMetricDslLine('metric unknown_metric', schema),
    /неизвестная метрика/,
  );
});

test('parseExplorerLimitDslLine accepts valid limits', () => {
  assert.equal(Q.parseExplorerLimitDslLine('limit 25', schema), 25);
  assert.equal(Q.parseExplorerLimitDslLine('limit 100', schema), 100);
});

test('parseExplorerLimitDslLine rejects invalid limits', () => {
  assert.throws(() => Q.parseExplorerLimitDslLine('limit abc', schema), /неверный лимит/);
  assert.throws(() => Q.parseExplorerLimitDslLine('limit 0', schema), /неверный лимит/);
});

test('isExplorerMetricDslLine and isExplorerLimitDslLine do not match filter lines', () => {
  assert.equal(Q.isExplorerMetricDslLine('metric pps'), true);
  assert.equal(Q.isExplorerMetricDslLine('direction = in'), false);
  assert.equal(Q.isExplorerLimitDslLine('limit 25'), true);
  assert.equal(Q.isExplorerLimitDslLine('src_ip = 10.0.0.1'), false);
});

test('full audit-style filter lines parse as directives', () => {
  assert.equal(Q.isExplorerMetricDslLine('metric pps'), true);
  assert.equal(Q.isExplorerLimitDslLine('limit 25'), true);
  assert.equal(Q.parseExplorerMetricDslLine('metric pps', schema), 'pps');
  assert.equal(Q.parseExplorerLimitDslLine('limit 25', schema), 25);
});
