'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  parsePipelineStages,
  buildRawCounters,
  buildPacketFunnel,
  buildAggregationLine,
  buildLossBreakdown,
  buildVerdict,
  buildSpoolCard,
  buildNetflowCard,
  computeCompletenessPct,
  computeUnconfirmedPackets,
  capCompletenessPct,
  resolveExporterStatus,
  isXdpMeasurable,
  hasCompletenessSnapshots,
} = require('./collector-pipeline');

function baseCounters(overrides = {}) {
  return {
    seen_packets: 1000,
    xdp_non_ip_pass: 0,
    phy_rx_packets: 1000,
    phy_rx_discards: 0,
    xdp_total_packets: 1000,
    xdp_map_full: 0,
    xdp_parse_errors: 0,
    flow_packets_excluded: 0,
    flow_packets_acked: 995,
    records_spooled: 200,
    records_acked: 198,
    insert_errs: 0,
    ch_queue_drops: 0,
    spool_corruption_frames: 0,
    lag_segments: 0,
    drainer_progress_age_sec: 0,
    nf_send_errs: 0,
    ...overrides,
  };
}

describe('parsePipelineStages', () => {
  it('parses array', () => {
    assert.deepEqual(parsePipelineStages(['interface', 'collector']), ['interface', 'collector']);
  });

  it('parses JSON string', () => {
    assert.deepEqual(parsePipelineStages('["receiver","clickhouse"]'), ['receiver', 'clickhouse']);
  });
});

describe('hasCompletenessSnapshots', () => {
  it('requires at least two snapshots in both windows', () => {
    assert.equal(hasCompletenessSnapshots({ seen_snapshot_count: 2, ack_snapshot_count: 2 }), true);
    assert.equal(hasCompletenessSnapshots({ seen_snapshot_count: 1, ack_snapshot_count: 2 }), false);
  });
});

describe('computeCompletenessPct', () => {
  it('uses seen minus non_ip as denominator and includes excluded in numerator', () => {
    const pct = computeCompletenessPct({
      seen_packets: 1000,
      xdp_non_ip_pass: 50,
      flow_packets_acked: 930,
      flow_packets_excluded: 15,
    });
    assert.equal(pct, 99.4737);
  });

  it('caps at 100%', () => {
    const pct = computeCompletenessPct({
      seen_packets: 100,
      xdp_non_ip_pass: 0,
      flow_packets_acked: 90,
      flow_packets_excluded: 20,
    });
    assert.equal(pct, 100);
  });

  it('returns null when denominator is zero', () => {
    assert.equal(computeCompletenessPct({
      seen_packets: 10,
      xdp_non_ip_pass: 10,
      flow_packets_acked: 5,
      flow_packets_excluded: 0,
    }), null);
  });
});

describe('computeUnconfirmedPackets', () => {
  it('returns remainder after L-shift formula', () => {
    const counters = baseCounters({ flow_packets_acked: 995, flow_packets_excluded: 0 });
    assert.equal(computeUnconfirmedPackets(counters), 5);
  });
});

describe('buildVerdict', () => {
  it('does not call unconfirmed gap a loss and lists explicit losses separately', () => {
    const meta = { pipelineStages: ['interface', 'collector', 'clickhouse'], phyCounterSource: 'ethtool:mlx5' };
    const counters = baseCounters({
      phy_rx_discards: 14800,
      phy_rx_packets: 1_000_000_000,
      flow_packets_acked: 999_000_000,
    });
    const verdict = buildVerdict(counters, meta, 30);
    assert.match(verdict.headline, /Полнота .* за 30 минут/);
    assert.ok(verdict.losses.some((l) => l.id === 'phy_discards'));
    assert.equal(verdict.lossesFooter, 'в коллекторе и ClickHouse — нет');
    assert.ok(verdict.unconfirmed);
    assert.equal(verdict.unconfirmed.tone, 'neutral');
    assert.doesNotMatch(JSON.stringify(verdict), /потеряно/);
  });
});

describe('buildPacketFunnel', () => {
  it('shows bpf zero line and ch processing note', () => {
    const meta = { pipelineStages: ['collector', 'clickhouse'], phyCounterSource: '' };
    const counters = baseCounters();
    const funnel = buildPacketFunnel(counters, meta);
    const xdpLoss = funnel.find((l) => l.id === 'xdp_loss');
    const ch = funnel.find((l) => l.id === 'clickhouse');
    assert.equal(xdpLoss.value, 0);
    assert.equal(xdpLoss.lossPctLabel, '0%');
    assert.match(ch.note, /обработке/);
  });

  it('formats small discard pct as lt 0.01', () => {
    const meta = { pipelineStages: ['interface', 'collector'], phyCounterSource: 'ethtool:mlx5' };
    const counters = baseCounters({ phy_rx_packets: 10_000_000, phy_rx_discards: 100 });
    const funnel = buildPacketFunnel(counters, meta);
    const wireLoss = funnel.find((l) => l.id === 'wire_loss');
    assert.equal(wireLoss.lossPctLabel, '<0.01%');
  });
});

describe('buildLossBreakdown', () => {
  const meta = { pipelineStages: ['collector', 'clickhouse'] };

  it('returns detail sections without formula text', () => {
    const breakdown = buildLossBreakdown(baseCounters(), meta);
    assert.ok(breakdown.sections);
    assert.equal(breakdown.formula, undefined);
    const completeness = breakdown.sections.find((s) => s.id === 'completeness');
    const unconfirmed = breakdown.sections.find((s) => s.id === 'unconfirmed');
    assert.ok(completeness);
    assert.ok(unconfirmed);
    assert.equal(unconfirmed.rows[0].value, 5);
  });

  it('caps breakdown row pct at 100%', () => {
    const breakdown = buildLossBreakdown(baseCounters({
      seen_packets: 1000,
      flow_packets_acked: 1100,
      flow_packets_excluded: 0,
    }), meta);
    const ackedRow = breakdown.sections
      .find((s) => s.id === 'completeness')
      .rows.find((r) => r.key === 'acked');
    assert.equal(ackedRow.pctOfBase, 100);
  });
});

describe('buildNetflowCard', () => {
  it('includes socket drops only when observed', () => {
    const withSocket = buildNetflowCard(
      { nf_records_out: 1, nf_packets_out: 10000, nf_send_errs: 0, nf_socket_drops: 3 },
      { pipelineStages: ['netflow'], nfSocketObserved: 1, nfDsts: '10.0.0.1' },
    );
    assert.equal(withSocket.nfSocketDrops, 3);
    assert.equal(withSocket.nfSocketDropTone, 'healthy');
  });
});
