'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { explorerFlows, explorerSummary } = require('./explorer');

const WINDOW = {
  range: 'custom',
  from: '2026-08-14 04:40:00',
  to: '2026-08-14 05:35:00',
  metric: 'bps',
  limit: 25,
};

const flowsSql = async (filters, groupBy = ['src_asn']) => (
  await explorerFlows({ ...WINDOW, groupBy, filters })
).sql;

describe('interface label filters match stored columns', () => {
  it('resolves in_if_alias through the inventory instead of joining it', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_asn'],
      filters: [{ field: 'in_if_alias', op: '=', value: 'cogent-fv=' }],
    });
    assert.match(spec.sql, /IN \(SELECT[\s\S]*if_alias = \{filter_0:String\}\)/);
    assert.doesNotMatch(spec.sql, /snmp_in\.if_alias/);
    assert.doesNotMatch(spec.sql, /LEFT JOIN[\s\S]*AS snmp_in/);
    assert.equal(spec.params.filter_0, 'cogent-fv=');
  });

  it('applies to the summary query, which reads the same window', async () => {
    const spec = await explorerSummary({
      ...WINDOW,
      filters: [{ field: 'in_if_alias', op: '=', value: 'cogent-fv=' }],
    });
    assert.doesNotMatch(spec.sql, /LEFT JOIN[\s\S]*AS snmp_in/);
    assert.match(spec.sql, /if_alias = \{filter_0:String\}/);
  });

  it('covers both directions and both label columns', async () => {
    for (const [field, column, alias] of [
      ['in_if_name', 'if_name', 'snmp_in'],
      ['in_if_alias', 'if_alias', 'snmp_in'],
      ['out_if_name', 'if_name', 'snmp_out'],
      ['out_if_alias', 'if_alias', 'snmp_out'],
    ]) {
      const sql = await flowsSql([{ field, op: '=', value: 'xe-0/0/1' }]);
      assert.match(sql, new RegExp(`${column} = \\{filter_0:String\\}`), field);
      assert.doesNotMatch(sql, new RegExp(`LEFT JOIN[\\s\\S]*AS ${alias}`), field);
    }
  });

  it('negates by excluding the matching ports', async () => {
    const sql = await flowsSql([{ field: 'in_if_alias', op: '!=', value: 'uplink' }]);
    assert.match(sql, /NOT IN \(SELECT/);
  });

  it('keeps in / not_in / contains on the same path', async () => {
    const inSql = await flowsSql([{ field: 'in_if_alias', op: 'in', value: 'a,b' }]);
    assert.match(inSql, /if_alias IN \{filter_0:Array\(String\)\}/);
    assert.doesNotMatch(inSql, /NOT IN \(SELECT/);

    const notInSql = await flowsSql([{ field: 'in_if_alias', op: 'not_in', value: 'a,b' }]);
    assert.match(notInSql, /NOT IN \(SELECT/);

    const containsSql = await flowsSql([{ field: 'in_if_alias', op: 'contains', value: 'cogent' }]);
    assert.match(containsSql, /positionCaseInsensitive\(if_alias, \{filter_0:String\}\) > 0/);

    const notContainsSql = await flowsSql([{ field: 'in_if_alias', op: 'not_contains', value: 'cogent' }]);
    assert.match(notContainsSql, /NOT IN \(SELECT[\s\S]*positionCaseInsensitive/);
  });

  it('compares the sampler as stored, without formatting it per row', async () => {
    const sql = await flowsSql([{ field: 'in_if_alias', op: '=', value: 'cogent-fv=' }]);
    // Inventory text is converted to bytes once, not flow bytes to text per row.
    assert.match(sql, /reinterpretAsFixedString\(toUInt32\(toIPv4\(switch_ip\)\)\)/);
    assert.doesNotMatch(sql, /IPv6NumToString\(f\.`?sampler_address`?\)/);
  });

  it('still joins when grouping by the label, only the filter changes', async () => {
    const sql = await flowsSql(
      [{ field: 'in_if_alias', op: '=', value: 'cogent-fv=' }],
      ['in_if_alias'],
    );
    assert.match(sql, /snmp_in\.if_alias/);
    assert.match(sql, /if_alias = \{filter_0:String\}/);
  });

  it('falls back to the join for an empty label, which also means "not in inventory"', async () => {
    const sql = await flowsSql([{ field: 'in_if_alias', op: '=', value: '' }]);
    assert.doesNotMatch(sql, /IN \(SELECT[\s\S]*if_alias/);
  });

  it('numbers later filter params without leaving a gap', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_asn'],
      filters: [
        { field: 'in_if_alias', op: '=', value: 'cogent-fv=' },
        { field: 'direction', op: '=', value: 'in' },
      ],
    });
    assert.equal(spec.params.filter_0, 'cogent-fv=');
    assert.equal(spec.params.filter_1, 'in');
  });
});
