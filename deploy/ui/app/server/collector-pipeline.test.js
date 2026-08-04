'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  parsePipelineStages,
  buildRawCounters,
  buildPipelineStages,
  enrichStages,
  classifyStage,
  buildPipelineFromCounters,
} = require('./collector-pipeline');
const { DEFAULT_THRESHOLDS } = require('./collector-pipeline-thresholds');
const { resolveInputPackets, classifyCompleteness } = require('./collector-completeness');

describe('parsePipelineStages', () => {
  it('parses array', () => {
    assert.deepEqual(parsePipelineStages(['interface', 'collector']), ['interface', 'collector']);
  });

  it('parses JSON string', () => {
    assert.deepEqual(parsePipelineStages('["receiver","clickhouse"]'), ['receiver', 'clickhouse']);
  });
});

describe('buildRawCounters', () => {
  it('clamps negative deltas to zero', () => {
    const counters = buildRawCounters({
      xdp_total_packets_delta: -100,
      phy_rx_packets_delta: 50,
    });
    assert.equal(counters.xdp_total_packets, 0);
    assert.equal(counters.phy_rx_packets, 50);
  });
});

describe('buildPipelineStages', () => {
  it('includes only declared pipeline stages', () => {
    const meta = {
      pipelineStages: ['receiver', 'clickhouse'],
      phyCounterSource: '',
      nfSocketObserved: 0,
    };
    const counters = {
      phy_rx_packets: 1000,
      records_parsed: 900,
      flow_packets_acked: 880,
      flow_packets_excluded: 0,
      records_spooled: 900,
      spool_corruption_frames: 0,
      insert_errs: 0,
      ch_queue_drops: 0,
      udp_queue_drops: 0,
      receiver_parse_errors: 0,
    };
    const stages = buildPipelineStages({}, meta, counters);
    const ids = stages.map((s) => s.id);
    assert.deepEqual(ids, ['receiver', 'spool', 'clickhouse']);
  });

  it('skips interface when phy_counter_source is empty', () => {
    const meta = {
      pipelineStages: ['interface', 'collector'],
      phyCounterSource: '',
      nfSocketObserved: 0,
    };
    const counters = {
      phy_rx_packets: 100,
      xdp_total_packets: 90,
      xdp_map_full: 0,
      xdp_parse_errors: 0,
      flow_packets_excluded: 0,
      records_spooled: 80,
      spool_corruption_frames: 0,
    };
    const stages = buildPipelineStages({}, meta, counters);
    assert.equal(stages.some((s) => s.id === 'interface'), false);
    assert.equal(stages.some((s) => s.id === 'collector'), true);
  });

  it('skips socket when nf_socket_observed is 0', () => {
    const meta = {
      pipelineStages: ['netflow'],
      phyCounterSource: '',
      nfSocketObserved: 0,
    };
    const counters = {
      nf_packets_out: 100,
      nf_send_errs: 0,
      nf_socket_drops: 5,
      flow_packets_excluded: 0,
    };
    const stages = buildPipelineStages({}, meta, counters);
    assert.equal(stages.some((s) => s.id === 'netflow'), true);
    assert.equal(stages.some((s) => s.id === 'socket'), false);
  });

  it('includes socket when nf_socket_observed is 1', () => {
    const meta = {
      pipelineStages: ['netflow'],
      phyCounterSource: '',
      nfSocketObserved: 1,
    };
    const counters = {
      nf_packets_out: 100,
      nf_send_errs: 0,
      nf_socket_drops: 2,
      flow_packets_excluded: 0,
    };
    const stages = buildPipelineStages({}, meta, counters);
    assert.equal(stages.some((s) => s.id === 'socket'), true);
  });

  it('shows exclusions as info stage when delta > 0', () => {
    const meta = {
      pipelineStages: ['collector', 'clickhouse'],
      phyCounterSource: 'ethtool:mlx5',
      nfSocketObserved: 0,
    };
    const counters = {
      phy_rx_packets: 1000,
      phy_rx_discards: 0,
      xdp_total_packets: 990,
      xdp_map_full: 0,
      xdp_parse_errors: 0,
      flow_packets_excluded: 10,
      records_spooled: 980,
      spool_corruption_frames: 0,
      flow_packets_acked: 970,
      insert_errs: 0,
      ch_queue_drops: 0,
    };
    const stages = buildPipelineStages({}, meta, counters);
    const ex = stages.find((s) => s.id === 'exclusions');
    assert.ok(ex);
    assert.equal(ex.isExclusion, true);
    assert.equal(ex.passed, 10);
  });
});

describe('enrichStages root cause', () => {
  it('adds passPct note when counter units differ', () => {
    const raw = [
      { id: 'collector', label: 'XDP', passed: 1000, lost: 0 },
      { id: 'spool', label: 'Spool', passed: 30, lost: 0 },
    ];
    const stages = enrichStages(raw, DEFAULT_THRESHOLDS);
    assert.equal(stages[1].passPctLabel, 'от предыдущего звена');
    assert.match(stages[1].passPctNote, /разные счётчики/);
  });

  it('marks first exceeding stage as root cause', () => {
    const raw = [
      { id: 'interface', label: 'IF', passed: 1000, lost: 0 },
      { id: 'collector', label: 'XDP', passed: 990, lost: 5 },
      { id: 'clickhouse', label: 'CH', passed: 900, lost: 50 },
    ];
    const thresholds = {
      ...DEFAULT_THRESHOLDS,
      interface: { warnPct: 0.01, critPct: 0.1 },
      collector: { warnPct: 0.01, critPct: 0.1 },
      clickhouse: { warnPct: 0.01, critPct: 0.1 },
    };
    const stages = enrichStages(raw, thresholds);
    const root = stages.find((s) => s.isRootCause);
    assert.equal(root.id, 'collector');
  });

  it('ignores exclusions for root cause', () => {
    const raw = [
      { id: 'interface', label: 'IF', passed: 1000, lost: 0 },
      { id: 'exclusions', label: 'Ex', passed: 50, lost: 0, isExclusion: true },
      { id: 'collector', label: 'XDP', passed: 950, lost: 0 },
    ];
    const stages = enrichStages(raw, DEFAULT_THRESHOLDS);
    assert.equal(stages.filter((s) => s.isRootCause).length, 0);
  });
});

describe('classifyStage', () => {
  it('classifies spool corruption as critical', () => {
    assert.equal(classifyStage('spool', { lost: 1 }, DEFAULT_THRESHOLDS), 'critical');
  });

  it('classifies exclusions as info when passed > 0', () => {
    assert.equal(classifyStage('exclusions', { passed: 5 }, DEFAULT_THRESHOLDS), 'info');
  });
});

describe('resolveInputPackets (completeness fix)', () => {
  it('uses xdp for collector pipeline', () => {
    const r = resolveInputPackets({
      pipeline_stages: ['interface', 'collector', 'clickhouse'],
      xdp_packets: 1000,
      records_parsed: 0,
    });
    assert.equal(r.inputKind, 'xdp');
    assert.equal(r.inputPackets, 1000);
  });

  it('uses records_parsed for receiver-only flowcollectord', () => {
    const r = resolveInputPackets({
      pipeline_stages: ['receiver', 'clickhouse'],
      xdp_packets: 0,
      records_parsed: 800,
    });
    assert.equal(r.inputKind, 'receiver');
    assert.equal(r.inputPackets, 800);
  });

  it('returns unknown when no applicable stage', () => {
    const r = resolveInputPackets({
      pipeline_stages: ['clickhouse'],
      xdp_packets: 0,
      records_parsed: 0,
    });
    assert.equal(r.inputKind, null);
  });

  it('does not mark critical for flowcollectord with zero xdp', () => {
    const result = classifyCompleteness({
      snapshot_count: 5,
      pipeline_stages: ['receiver', 'clickhouse'],
      xdp_packets: 0,
      records_parsed: 1000,
      ch_packets: 990,
      packets_pct: 99,
      bytes_pct: 99,
      map_full_delta: 0,
      insert_errs_delta: 0,
      queue_drops_delta: 0,
      udp_drops_delta: 0,
    });
    assert.equal(result.status, 'ok');
  });
});

describe('buildPipelineFromCounters integration', () => {
  it('builds full xdpflowd chain', () => {
    const meta = {
      pipelineStages: ['interface', 'collector', 'clickhouse', 'netflow'],
      phyCounterSource: 'ethtool:mlx5',
      nfSocketObserved: 1,
    };
    const counters = {
      phy_rx_packets: 10000,
      phy_rx_discards: 1,
      xdp_total_packets: 9990,
      xdp_map_full: 0,
      xdp_parse_errors: 0,
      flow_packets_excluded: 0,
      records_spooled: 9980,
      spool_corruption_frames: 0,
      flow_packets_acked: 9970,
      insert_errs: 0,
      ch_queue_drops: 0,
      nf_packets_out: 9960,
      nf_send_errs: 0,
      nf_socket_drops: 0,
    };
    const stages = buildPipelineFromCounters(meta, counters);
    assert.ok(stages.length >= 5);
    assert.equal(stages[0].id, 'interface');
  });
});
