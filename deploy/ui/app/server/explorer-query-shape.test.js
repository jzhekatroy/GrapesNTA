'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  explorerFlows,
  explorerSummary,
  explorerTimeseries,
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

  it('groups destination ports by hundreds when groupBy is dst_port/100', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['dst_port/100'],
    });
    assert.match(spec.sql, /intDiv\(/);
    assert.match(spec.sql, /65535/);
    assert.doesNotMatch(spec.sql, /IPv4CIDRToRange\(/);
    assert.equal(spec.meta.groupBy[0].id, 'dst_port/100');
    assert.match(spec.meta.groupBy[0].label, /\/100/);
  });

  it('groups source ports by a custom bucket width', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['src_port/512'],
    });
    assert.match(spec.sql, /intDiv\(.+512\) \* 512/);
    assert.equal(spec.meta.groupBy[0].id, 'src_port/512');
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

  it('keeps a CIDR filter as a range check on the stored address', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'src_ip', op: 'cidr', value: '10.0.0.0/8' }],
    });
    assert.match(spec.sql, /substring\(f\.`[^`]+`, 1, 1\) = unhex\('0a'\)/);
    assert.match(spec.sql, /etype` = 2048/);
    assert.equal(spec.params.filter_0, '10.0.0.0/8');
    assert.doesNotMatch(spec.sql, /isIPAddressInRange/);
    assert.doesNotMatch(spec.sql, /toFixedString\(unhex/);
  });

  it('masks the leftover bits of a CIDR that is not on a byte boundary', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'dst_ip', op: 'cidr', value: '213.230.115.0/25' }],
    });
    assert.match(spec.sql, /substring\(f\.`[^`]+`, 1, 3\) = unhex\('d5e673'\)/);
    assert.match(spec.sql, /bitAnd\(reinterpretAsUInt8\(substring\(f\.`[^`]+`, 4, 1\)\), 128\) = 0/);
  });

  it('сравнивает свою подсеть с адресом, а не с его текстом', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['proto'],
      filters: [{ field: 'own_network', op: '=', value: '2001:db8::/32' }],
    });
    assert.match(spec.sql, /unhex\('20010db8'\)/);
    assert.match(spec.sql, /etype` = 34525/);
    assert.equal(spec.params.prefix_0, '2001:db8::/32');
    assert.doesNotMatch(spec.sql, /IPv6NumToString\(f\.`/);
  });

  it('берёт сумму и ряд без фильтров из минутных rollup', async () => {
    const summary = await explorerSummary({ ...WINDOW });
    assert.match(summary.sql, /traffic_direction_1m/);
    assert.match(summary.sql, /traffic_protocol_1m/);
    assert.match(summary.sql, /topKWeighted\(5\)\(proto, bytes\)/);
    assert.match(summary.sql, /rollup_closed/);
    const series = await explorerTimeseries({ ...WINDOW, metric: 'bps' });
    assert.match(series.sql, /traffic_direction_1m/);
    assert.equal(series.meta.rollup, 'traffic_direction_1m');
  });

  it('не подменяет rollup, если есть фильтр или уникальные IP', async () => {
    const filtered = await explorerSummary({
      ...WINDOW,
      filters: [{ field: 'vlan', op: '=', value: '447' }],
    });
    assert.doesNotMatch(filtered.sql, /traffic_direction_1m/);
    assert.match(filtered.sql, /topK\(5\)/);
    const uniq = await explorerTimeseries({ ...WINDOW, metric: 'uniq_src' });
    assert.doesNotMatch(uniq.sql, /traffic_direction_1m/);
    assert.match(uniq.sql, /uniqCombined/);
  });

  it('в режиме IX группирует отправителя отдельно от порта клиента', async () => {
    const spec = await explorerFlows({
      ...WINDOW,
      groupBy: ['ix_src_client'],
      filters: [{ field: 'ix_dst_client', op: '=', value: '80249' }],
    }, { ix: true });
    assert.match(spec.sql, /if\(f\.ix_src_client = '', '—', f\.ix_src_client\)/);
    assert.match(spec.sql, /f\.ix_dst_client = \{ix_client_0:String\}/);
    assert.equal(spec.params.ix_client_0, '80249');
    assert.doesNotMatch(spec.sql, /f\.src_client = \{ix_client_0:String\}/);
    const plain = await explorerFlows({
      ...WINDOW,
      groupBy: ['client_direction'],
    });
    assert.doesNotMatch(plain.sql, /ix_src_client|ix_dst_client/);
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
