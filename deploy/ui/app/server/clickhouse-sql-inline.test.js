'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { inlineClickHouseParams, formatLiteral } = require('./clickhouse-sql-inline');

test('inlineClickHouseParams substitutes common scalar types', () => {
  const sql = `
    SELECT *
    FROM flows
    WHERE client_id = {clientId:String}
      AND limit_val = {limit:UInt32}
      AND event_at >= {from:DateTime64(3)}
  `;
  const inlined = inlineClickHouseParams(sql, {
    clientId: 'client-1',
    limit: 25,
    from: '2026-01-01T00:00:00.000Z',
  });
  assert.match(inlined, /client_id = 'client-1'/);
  assert.match(inlined, /limit_val = 25/);
  assert.match(inlined, /event_at >= '2026-01-01 00:00:00.000'/);
});

test('inlineClickHouseParams substitutes arrays', () => {
  const sql = 'WHERE asn IN {asns:Array(UInt32)} AND entity_id IN {ids:Array(String)}';
  const inlined = inlineClickHouseParams(sql, {
    asns: [64512, 64513],
    ids: ['a', 'b'],
  });
  assert.match(inlined, /asn IN \[64512, 64513\]/);
  assert.match(inlined, /entity_id IN \['a', 'b'\]/);
});

test('inlineClickHouseParams leaves missing params unchanged', () => {
  const sql = 'WHERE id = {missing:String} AND ok = {ok:String}';
  const inlined = inlineClickHouseParams(sql, { ok: 'yes' });
  assert.match(inlined, /\{missing:String\}/);
  assert.match(inlined, /ok = 'yes'/);
});

test('formatLiteral escapes strings and handles null', () => {
  assert.equal(formatLiteral(null, 'String'), 'NULL');
  assert.equal(formatLiteral("O'Reilly", 'String'), "'O\\'Reilly'");
});

test('inlineClickHouseParams handles explorer-like fragment', () => {
  const sql = `
    PREWHERE f.date >= toDate(ts_from) - 1
    WHERE f.src_client = {cabinet_client_id:String}
      AND series_ids IN {series_ids:Array(String)}
    LIMIT {limit:UInt32}
  `;
  const inlined = inlineClickHouseParams(sql, {
    cabinet_client_id: 'cab-42',
    series_ids: ['10.0.0.1', '10.0.0.2'],
    limit: 100,
  });
  assert.match(inlined, /f\.src_client = 'cab-42'/);
  assert.match(inlined, /series_ids IN \['10\.0\.0\.1', '10\.0\.0\.2'\]/);
  assert.match(inlined, /LIMIT 100/);
});
