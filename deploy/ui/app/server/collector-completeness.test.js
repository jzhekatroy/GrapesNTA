'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { classifyCompleteness, mapCompletenessRow } = require('./collector-completeness');

function row(overrides = {}) {
  return {
    snapshot_count: 5,
    seen_snapshot_count: 5,
    ack_snapshot_count: 5,
    pipeline_stages: ['collector', 'clickhouse'],
    seen_packets: 1000,
    xdp_non_ip_pass: 0,
    ch_packets: 940,
    excluded_packets: 10,
    insert_errs_delta: 0,
    queue_drops_delta: 0,
    spool_corruption_delta: 0,
    nf_send_errs_delta: 0,
    ...overrides,
  };
}

describe('classifyCompleteness', () => {
  it('uses excluded packets and non_ip adjusted denominator', () => {
    const result = classifyCompleteness(row({
      seen_packets: 1000,
      xdp_non_ip_pass: 0,
      ch_packets: 940,
      excluded_packets: 10,
    }));
    assert.equal(result.measurable, true);
    assert.equal(result.completenessPct, 95);
    assert.equal(result.status, 'warning');
  });

  it('caps completeness at 100%', () => {
    const result = classifyCompleteness(row({
      seen_packets: 100,
      ch_packets: 90,
      excluded_packets: 20,
    }));
    assert.equal(result.completenessPct, 100);
    assert.equal(result.status, 'ok');
  });

  it('marks flowcollectord as not measurable', () => {
    const result = classifyCompleteness(row({
      pipeline_stages: ['receiver', 'clickhouse'],
      seen_packets: 0,
      records_parsed: 800,
      ch_packets: 790,
    }));
    assert.equal(result.measurable, false);
    assert.equal(result.status, 'na');
    assert.equal(result.completenessPct, undefined);
    assert.ok(result.tooltip);
  });

  it('requires snapshots in both windows', () => {
    const result = classifyCompleteness(row({ seen_snapshot_count: 1 }));
    assert.equal(result.measurable, false);
    assert.equal(result.status, 'unknown');
  });

  it('marks critical on technical errors regardless of pct', () => {
    const result = classifyCompleteness(row({
      ch_packets: 999,
      excluded_packets: 0,
      insert_errs_delta: 1,
    }));
    assert.equal(result.status, 'critical');
    assert.ok(result.reasons.includes('technical_errors'));
  });
});

describe('mapCompletenessRow exporterStatus', () => {
  it('maps no_connection when snapshot is stale', () => {
    const mapped = mapCompletenessRow({
      source_id: 'src1',
      snapshot_count: 5,
      seen_snapshot_count: 5,
      ack_snapshot_count: 5,
      snapshot_age_minutes: 10,
      pipeline_stages: ['collector', 'clickhouse'],
      seen_packets: 100,
      ch_packets: 99,
      excluded_packets: 0,
      collector_id: 'c1',
      daemon: 'xdpflowd',
      insert_errs_delta: 0,
      queue_drops_delta: 0,
      spool_corruption_delta: 0,
      nf_send_errs_delta: 0,
    });
    assert.equal(mapped.exporterStatus, 'no_connection');
  });

  it('maps working when snapshots are fresh and counters grow', () => {
    const mapped = mapCompletenessRow({
      source_id: 'src1',
      snapshot_count: 5,
      seen_snapshot_count: 5,
      ack_snapshot_count: 5,
      snapshot_age_minutes: 1,
      pipeline_stages: ['collector', 'clickhouse'],
      seen_packets: 500,
      ch_packets: 490,
      excluded_packets: 5,
      collector_id: 'c1',
      daemon: 'xdpflowd',
      insert_errs_delta: 0,
      queue_drops_delta: 0,
      spool_corruption_delta: 0,
      nf_send_errs_delta: 0,
    });
    assert.equal(mapped.exporterStatus, 'working');
  });
});
