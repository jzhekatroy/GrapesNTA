'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  explorerFlows,
  explorerSummary,
  explorerResultSeries,
} = require('./explorer');

const WINDOW = {
  range: 'custom',
  from: '2026-08-14 04:40:00',
  to: '2026-08-14 05:35:00',
  metric: 'bps',
  limit: 25,
};

describe('explorer query shape', () => {
  it('l3_owner читает владельца из потока, а не перебирает префиксы', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'l3_owner', op: '=', value: 'isp:pin' }],
    });
    assert.match(spec.sql, /f\.`src_entity` = \{l3_owner_0:String\}/);
    assert.match(spec.sql, /OR f\.`dst_entity` = \{l3_owner_0:String\}/);
    assert.equal(spec.params.l3_owner_0, 'isp:pin');
    assert.doesNotMatch(spec.sql, /isIPAddressInRange/);
  });

  it('filters direction as a raw column and aggregates once', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['dst_entity'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    });
    assert.match(spec.sql, /f\.`direction` = \{filter_0:String\}/);
    assert.doesNotMatch(spec.sql, /toString\(toString/);
    assert.doesNotMatch(spec.sql, /grouped_total/);
    assert.match(spec.sql, /sum\(a\.bytes\) OVER \(\)/);
  });

  it('keeps proto/ASN series matching on labels', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['dst_entity', 'proto'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    }, [
      { id: 'r1', rawValues: ['isp:pin', 'TCP'], values: ['PIN', 'TCP'] },
    ]);
    assert.match(spec.sql, /f\.`dst_entity` = \{series_g_0:String\}/);
    assert.match(spec.sql, /toString\(/);
    assert.equal(spec.params.series_g_0, 'isp:pin');
  });

  it('matches single dst_entity series by raw key IN', async () => {
    const spec = await explorerResultSeries({
      ...WINDOW,
      groupBy: ['dst_entity'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    }, [
      { id: 'r1', rawValues: ['isp:pin'], values: ['PIN'] },
      { id: 'r2', rawValues: ['isp:arbital'], values: ['Arbital'] },
    ]);
    assert.match(spec.sql, /f\.`dst_entity` IN \{series_ids:Array\(String\)\}/);
    assert.deepEqual(spec.params.series_ids, ['isp:pin', 'isp:arbital']);
  });

  it('groups flows by collector id resolved from the source catalog', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['collector'],
    });
    assert.match(spec.sql, /net_flow_sources_enabled/);
    assert.match(spec.sql, /mapFromArrays/);
    assert.match(spec.sql, /collector_id/);
    assert.match(spec.sql, /f\.`source_id`/);
    assert.equal(spec.meta.groupBy[0].id, 'collector');
    assert.match(spec.meta.groupBy[0].label, /Коллектор/);
  });

  it('groups IPv4 by prefix when groupBy is src_ip/24', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_ip/24'],
    });
    assert.match(spec.sql, /IPv4CIDRToRange\(/);
    assert.match(spec.sql, /\/24/);
    assert.equal(spec.meta.groupBy[0].id, 'src_ip/24');
    assert.match(spec.meta.groupBy[0].label, /\/24/);
  });

  it('compares an exact source IP as stored bytes', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'src_ip', op: '=', value: '0.0.0.0' }],
    });
    assert.match(spec.sql, /toFixedString\(unhex\(\{filter_0:String\}\), 16\)/);
    assert.match(spec.sql, /\{filter_0_etype:UInt32\}/);
    assert.equal(spec.params.filter_0, '00000000000000000000000000000000');
    assert.equal(spec.params.filter_0_etype, 2048);
    assert.doesNotMatch(spec.sql, /toString\(toIPv4\(reinterpretAsUInt32\(reverse\(substring\(f\.`[^`]+`, 1, 4\)\)\)\)\) = \{filter_0:String\}/);
  });

  it('keeps IPv4 0.0.0.0 distinct from IPv6 ::', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'dst_ip', op: '=', value: '::' }],
    });
    assert.equal(spec.params.filter_0, '00000000000000000000000000000000');
    assert.equal(spec.params.filter_0_etype, 0x86DD);
  });

  it('compares a list of exact IPs without formatting each row', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'src_ip', op: 'in', value: '8.8.8.8, 2001:db8::1' }],
    });
    assert.equal(spec.params.filter_0_0, `08080808${'0'.repeat(24)}`);
    assert.equal(spec.params.filter_0_0_etype, 2048);
    assert.equal(spec.params.filter_0_1, '20010db8000000000000000000000001');
    assert.equal(spec.params.filter_0_1_etype, 0x86DD);
    assert.match(spec.sql, / OR /);
  });

  it('negates an exact IP match', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'src_ip', op: '!=', value: '0.0.0.0' }],
    });
    assert.match(spec.sql, /NOT \(f\.`[^`]+` = toFixedString\(unhex\(\{filter_0:String\}\), 16\)/);
    assert.equal(spec.params.filter_0_etype, 2048);
  });

  it('keeps a CIDR filter as a range check', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'src_ip', op: 'cidr', value: '10.0.0.0/8' }],
    });
    assert.match(spec.sql, /isIPAddressInRange\(/);
    assert.equal(spec.params.filter_0, '10.0.0.0/8');
    assert.doesNotMatch(spec.sql, /toFixedString\(unhex/);
  });

  it('кладёт сумму всех групп в окно таблицы, до отсечения лимитом', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_port'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    });
    assert.match(spec.sql, /sum\(a\.bytes\) OVER \(\) AS total_bytes/);
    assert.match(spec.sql, /sum\(a\.packets\) OVER \(\) AS total_packets/);
    assert.match(spec.sql, /sum\(a\.flows\) OVER \(\) AS total_flows/);
    spec.meta.flowTotals = null;
    await spec.map([{
      g0: '443', total_bytes: '1000', total_packets: '10', total_flows: '2',
      bytes: 400, packets: 4, flows: 1, metric_value: 1, pct: 40, avg_bps: 1,
    }]);
    assert.equal(spec.meta.flowTotals.totalBytes, 1000);
    assert.equal(spec.meta.flowTotals.totalPackets, 10);
    assert.equal(spec.meta.flowTotals.totalFlows, 2);
  });

  it('omits unique IP sketches from the default summary', async () => {
    const spec = await explorerSummary({
      ...WINDOW,
      groupBy: ['dst_entity'],
      filters: [{ field: 'direction', op: '=', value: 'in' }],
    });
    assert.doesNotMatch(spec.sql, /uniqCombined\(f\.`src_addr`\) AS uniq_src/);
    assert.doesNotMatch(spec.sql, /uniqCombined\(f\.`dst_addr`\) AS uniq_dst/);
    const mapped = await spec.map([{}]);
    assert.equal(mapped.uniqSrc, null);
    assert.equal(mapped.uniqDst, null);
  });
});
