'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  getParameter,
  listParameterIds,
  monitoringSeriesValues,
  protocolProtoSql,
} = require('./monitoring-intervals');

describe('monitoring protocol parameters', () => {
  it('registers TCP, UDP and Other with distinct feature names', () => {
    const ids = listParameterIds();
    assert.ok(ids.includes('protocol_in_tcp'));
    assert.ok(ids.includes('protocol_in_udp'));
    assert.ok(ids.includes('protocol_in_other'));
    assert.equal(getParameter('protocol_in_tcp').featureName, 'protocol_tcp');
    assert.equal(getParameter('protocol_in_other').featureName, 'protocol_oth');
  });

  it('builds protocol traffic SQL with selected period and proto filter', () => {
    const spec = monitoringSeriesValues({
      parameter: 'protocol_in_udp',
      from: '2026-07-30 00:00:00',
      to: '2026-07-31 00:00:00',
    });
    assert.match(spec.sql, /traffic_protocol_1m/);
    assert.match(spec.sql, /proto = 17/);
    assert.match(spec.sql, /direction = 'in'/);
    assert.match(spec.sql, /source_id = \{source_id:String\}/);
    assert.equal(spec.params.from, '2026-07-30 00:00:00');
    assert.equal(spec.params.to, '2026-07-31 00:00:00');
  });

  it('uses NOT IN filter for Other protocol', () => {
    const spec = monitoringSeriesValues({
      parameter: 'protocol_in_other',
      from: '2026-07-30 00:00:00',
      to: '2026-07-31 00:00:00',
    });
    assert.match(spec.sql, /proto NOT IN \(6, 17\)/);
  });
});

describe('protocolProtoSql', () => {
  it('maps protocol filters to SQL predicates', () => {
    assert.equal(protocolProtoSql('tcp'), 'proto = 6');
    assert.equal(protocolProtoSql('udp'), 'proto = 17');
    assert.equal(protocolProtoSql('other'), 'proto NOT IN (6, 17)');
  });
});
