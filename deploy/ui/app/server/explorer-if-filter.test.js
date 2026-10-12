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

  it('compares the raw interface number so the sort key applies', async () => {
    const sql = await flowsSql([{ field: 'out_if_name', op: '=', value: 'Ethernet1/48' }]);
    assert.match(sql, /\(f\.`sampler_address`, f\.`out_if`\) IN \(SELECT/);
    assert.match(sql, /if_index BETWEEN 1 AND 1073741823/);
    assert.doesNotMatch(sql, /toUInt32OrZero\(toString\(f\.`out_if`\)\)/);
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

describe('switch_ip filter compares stored sampler bytes', () => {
  const samplerEq = /f\.`sampler_address` = toFixedString\(reverse\(reinterpretAsFixedString\(toUInt32\(toIPv4\(\{filter_0:String\}\)\)\)\), 16\)/;

  it('uses the stored bytes for an IPv4 address', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_asn'],
      filters: [{ field: 'switch_ip', op: '=', value: '172.18.19.55' }],
    });
    assert.match(spec.sql, samplerEq);
    assert.equal(spec.params.filter_0, '172.18.19.55');
    assert.doesNotMatch(spec.sql, /toString\(if\(\s*length\(f\.`sampler_address`\)/);
  });

  it('uses IPv6 bytes only for an IPv6 address', async () => {
    const sql = await flowsSql([{ field: 'switch_ip', op: '=', value: '2001:db8::1' }]);
    assert.match(sql, /f\.`sampler_address` = toFixedString\(IPv6StringToNum\(\{filter_0:String\}\), 16\)/);
    assert.doesNotMatch(sql, /toIPv4\(\{filter_0:String\}\)/);
  });

  it('keeps a non-address on the text path', async () => {
    const sql = await flowsSql([{ field: 'switch_ip', op: '=', value: 'core-1' }]);
    assert.match(sql, /toString\(if\(\s*length\(f\.`sampler_address`\)/);
    assert.doesNotMatch(sql, /toIPv4\(\{filter_0:String\}\)/);
  });

  it('builds an IN list when every value is an address', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_asn'],
      filters: [{ field: 'switch_ip', op: 'in', value: '172.18.19.55, 2001:db8::1' }],
    });
    assert.match(spec.sql, /f\.`sampler_address` IN \(toFixedString\(reverse\(reinterpretAsFixedString\(toUInt32\(toIPv4\(\{filter_0_0:String\}\)\)\)\), 16\), toFixedString\(IPv6StringToNum\(\{filter_0_1:String\}\), 16\)\)/);
    assert.equal(spec.params.filter_0_0, '172.18.19.55');
    assert.equal(spec.params.filter_0_1, '2001:db8::1');
  });

  it('falls back when an IN list mixes an address and a name', async () => {
    const sql = await flowsSql([{ field: 'switch_ip', op: 'in', value: '172.18.19.55, core-1' }]);
    assert.match(sql, /IN \{filter_0:Array\(String\)\}/);
    assert.doesNotMatch(sql, /toIPv4\(\{filter_0/);
  });

  it('negates a real address against the stored bytes', async () => {
    const sql = await flowsSql([{ field: 'switch_ip', op: '!=', value: '172.18.19.55' }]);
    assert.match(sql, /f\.`sampler_address` != toFixedString\(reverse\(reinterpretAsFixedString\(toUInt32\(toIPv4\(\{filter_0:String\}\)\)\)\), 16\)/);
  });

  it('leaves cidr on the range check', async () => {
    const sql = await flowsSql([{ field: 'switch_ip', op: 'cidr', value: '172.18.19.0/24' }]);
    assert.match(sql, /isIPAddressInRange\(/);
    assert.doesNotMatch(sql, /f\.`sampler_address` = toFixedString/);
  });
});
