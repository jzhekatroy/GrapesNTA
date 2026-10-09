const test = require('node:test');
const assert = require('node:assert/strict');

const {
  classifyExplorerQueryResult,
  buildExplorerAuditFiltersText,
  trimExplorerAuditDetail,
  AUDIT_DETAIL_MAX_LEN,
} = require('./explorer-query-audit');

test('classifyExplorerQueryResult maps timeout and OOM', () => {
  assert.equal(classifyExplorerQueryResult(null), 'ok');
  assert.equal(classifyExplorerQueryResult(undefined), 'ok');
  assert.equal(classifyExplorerQueryResult(new Error('Timeout exceeded')), 'timeout');
  assert.equal(classifyExplorerQueryResult(Object.assign(new Error('slow'), { code: 159 })), 'timeout');
  assert.equal(classifyExplorerQueryResult(new Error('Memory limit exceeded')), 'oom');
  assert.equal(classifyExplorerQueryResult(Object.assign(new Error('oom'), { code: 241 })), 'oom');
  assert.equal(classifyExplorerQueryResult(new Error('syntax error')), 'fail');
});

test('buildExplorerAuditFiltersText serializes period, metric, group and nested filters', () => {
  const text = buildExplorerAuditFiltersText({
    timeRange: '1h',
    metric: 'bps',
    groupBy: ['src_ip', 'dst_ip'],
    filters: [
      {
        type: 'group',
        logic: 'and',
        children: [
          { field: 'src_ip', op: '=', value: '10.0.0.1', logic: 'and' },
          { field: 'dst_port', op: '=', value: '443', logic: 'or' },
        ],
      },
    ],
    limit: 100,
  });
  assert.match(text, /^time range 1h/);
  assert.match(text, /metric bps/);
  assert.match(text, /group by src_ip, dst_ip/);
  assert.match(text, /src_ip = 10\.0\.0\.1/);
  assert.match(text, /ИЛИ dst_port = 443/);
  assert.match(text, /limit 100/);
});

test('trimExplorerAuditDetail keeps filters when SQL is huge', () => {
  const longSql = `SELECT ${'x'.repeat(AUDIT_DETAIL_MAX_LEN)}`;
  const detailObj = {
    explorer: {
      filtersText: 'time range 1h\nmetric bps',
      elapsedMs: 900,
      queries: [{ name: 'explorer/flows', elapsedMs: 900, sql: longSql, error: null }],
      error: null,
    },
  };
  const trimmed = trimExplorerAuditDetail(detailObj);
  assert.ok(trimmed.length <= AUDIT_DETAIL_MAX_LEN);
  const parsed = JSON.parse(trimmed);
  assert.equal(parsed.explorer.filtersText, 'time range 1h\nmetric bps');
  assert.ok(parsed.explorer.queries[0].sql.endsWith('…'));
});
