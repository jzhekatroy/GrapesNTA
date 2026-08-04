'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  getParameter,
  listParameterIds,
  monitoringSeriesValues,
  monitoringSeriesCi,
  monitoringParameters,
  monitoringDeviations,
  monitoringLiveDeviationsBranchSql,
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

describe('monitoring live deviations SQL', () => {
  it('builds TCP branch with traffic join, CI bounds and outside check', () => {
    const sql = monitoringLiveDeviationsBranchSql(getParameter('protocol_in_tcp'));
    assert.match(sql, /traffic_protocol_1m/);
    assert.match(sql, /proto = 6/);
    assert.match(sql, /direction = 'in'/);
    assert.match(sql, /`feature_name` = 'protocol_tcp'/);
    assert.match(sql, /INNER JOIN/);
    assert.match(sql, /value < c\.ci_low OR t\.value > c\.ci_high/);
    assert.doesNotMatch(sql, /intervals_control/);
  });

  it('monitoringParameters counts live deviations grouped by feature_name', () => {
    const spec = monitoringParameters();
    assert.match(spec.sql, /count\(\) AS deviations/);
    assert.match(spec.sql, /GROUP BY feature_name/);
    assert.match(spec.sql, /UNION ALL/);
    assert.match(spec.sql, /proto = 6/);
    assert.doesNotMatch(spec.sql, /outside_ci/);
    assert.doesNotMatch(spec.sql, /intervals_control/);
    assert.equal(spec.params.source_id, 'netflow');
    assert.equal(spec.meta.source, 'live');
  });

  it('monitoringDeviations lists live deviations without intervals_control', () => {
    const spec = monitoringDeviations({ limit: 10 });
    assert.match(spec.sql, /ORDER BY dt DESC, feature_name/);
    assert.match(spec.sql, /LIMIT \{limit:UInt32\}/);
    assert.match(spec.sql, /UNION ALL/);
    assert.match(spec.sql, /value < c\.ci_low OR t\.value > c\.ci_high/);
    assert.doesNotMatch(spec.sql, /intervals_control/);
    assert.doesNotMatch(spec.sql, /outside_ci/);
    assert.equal(spec.params.limit, 10);
    assert.equal(spec.params.source_id, 'netflow');
  });

  it('monitoringSeriesCi filters by Moscow timezone in WHERE clause', () => {
    const spec = monitoringSeriesCi({
      parameter: 'protocol_in_tcp',
      from: '2026-08-04 00:00:00',
      to: '2026-08-05 00:00:00',
    });
    assert.match(spec.sql, /toTimeZone\(`dt`, 'Europe\/Moscow'\) >= parseDateTimeBestEffort/);
    assert.match(spec.sql, /toTimeZone\(`dt`, 'Europe\/Moscow'\) < parseDateTimeBestEffort/);
    assert.doesNotMatch(spec.sql, /WHERE `dt` >= parseDateTimeBestEffort/);
  });
});
