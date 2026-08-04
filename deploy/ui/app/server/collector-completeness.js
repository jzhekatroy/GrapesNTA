const { query, collectorHealthSnapshotsTableRef } = require('./clickhouse');
const { parsePipelineStages } = require('./collector-pipeline');

function envInt(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function envFloat(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

const settings = {
  windowMinutes: envInt('COMPLETENESS_WINDOW_MINUTES', 5),
  lagMinutes: envInt('COMPLETENESS_LAG_MINUTES', 2),
  warnBytesPct: envFloat('COMPLETENESS_WARN_BYTES_PCT', 95),
  warnPacketsPct: envFloat('COMPLETENESS_WARN_PACKETS_PCT', 95),
  criticalBytesPct: envFloat('COMPLETENESS_CRITICAL_BYTES_PCT', 90),
  criticalPacketsPct: envFloat('COMPLETENESS_CRITICAL_PACKETS_PCT', 90),
};

function num(row, key) {
  const v = Number(row[key]);
  return Number.isFinite(v) ? v : 0;
}

function resolveInputPackets(row) {
  const stages = parsePipelineStages(row.pipeline_stages);
  const stageSet = new Set(stages);
  const xdpPackets = num(row, 'xdp_packets');
  const parsedPackets = num(row, 'records_parsed');

  if (stageSet.has('collector') && xdpPackets > 0) {
    return { inputPackets: xdpPackets, inputKind: 'xdp' };
  }
  if (stageSet.has('receiver') && parsedPackets > 0) {
    return { inputPackets: parsedPackets, inputKind: 'receiver' };
  }
  if (stageSet.has('collector')) {
    return { inputPackets: xdpPackets, inputKind: 'xdp' };
  }
  if (stageSet.has('receiver')) {
    return { inputPackets: parsedPackets, inputKind: 'receiver' };
  }
  return { inputPackets: 0, inputKind: null };
}

function classifyCompleteness(row) {
  const reasons = [];
  const snapshotCount = num(row, 'snapshot_count');
  const packetsPct = num(row, 'packets_pct');
  const bytesPct = num(row, 'bytes_pct');
  const { inputKind } = resolveInputPackets(row);

  if (snapshotCount < 2) {
    return { status: 'unknown', reasons: ['insufficient_snapshots'] };
  }

  if (!inputKind) {
    return { status: 'unknown', reasons: ['insufficient_snapshots'] };
  }

  const add = (reason) => {
    if (!reasons.includes(reason)) reasons.push(reason);
  };

  if (num(row, 'map_full_delta') > 0) add('xdp_map_full');
  if (num(row, 'insert_errs_delta') > 0) add('insert_errors');
  if (num(row, 'queue_drops_delta') > 0) add('queue_drops');
  if (num(row, 'udp_drops_delta') > 0) add('udp_drops');

  if (reasons.length > 0) {
    return { status: 'critical', reasons };
  }

  if (
    bytesPct < settings.criticalBytesPct
    || packetsPct < settings.criticalPacketsPct
  ) {
    return { status: 'critical', reasons: ['low_completeness'] };
  }

  if (
    bytesPct < settings.warnBytesPct
    || packetsPct < settings.warnPacketsPct
  ) {
    return { status: 'warning', reasons: ['low_completeness'] };
  }

  return { status: 'ok', reasons: [] };
}

function mapCompletenessRow(row) {
  const classified = classifyCompleteness(row);
  const { inputKind } = resolveInputPackets(row);
  return {
    sourceId: String(row.source_id ?? ''),
    collectorId: String(row.collector_id ?? ''),
    daemon: String(row.daemon ?? ''),
    status: classified.status,
    reasons: classified.reasons,
    inputKind,
    windowMinutes: settings.windowMinutes,
    lagMinutes: settings.lagMinutes,
    snapshotCount: num(row, 'snapshot_count'),
    windowFrom: row.window_from ?? null,
    windowTo: row.window_to ?? null,
    xdpPackets: num(row, 'xdp_packets'),
    chPackets: num(row, 'ch_packets'),
    xdpBytes: num(row, 'xdp_bytes'),
    chBytes: num(row, 'ch_bytes'),
    recordsParsed: num(row, 'records_parsed'),
    packetsPct: num(row, 'packets_pct'),
    bytesPct: num(row, 'bytes_pct'),
    mapFullDelta: num(row, 'map_full_delta'),
    insertErrsDelta: num(row, 'insert_errs_delta'),
    queueDropsDelta: num(row, 'queue_drops_delta'),
    udpDropsDelta: num(row, 'udp_drops_delta'),
    recordsAckedDelta: num(row, 'records_acked_delta'),
    lastSnapshotAt: row.last_snapshot_at ?? null,
    lastDaemonStatus: String(row.last_daemon_status ?? ''),
  };
}

async function fetchCollectorCompleteness() {
  const table = collectorHealthSnapshotsTableRef();
  const windowPlusLag = settings.windowMinutes + settings.lagMinutes;

  const { rows, elapsedMs } = await query(
    `
      SELECT
        source_id,
        argMax(collector_id, ts) AS collector_id,
        argMax(daemon, ts) AS daemon,
        argMax(status, ts) AS last_daemon_status,
        argMax(pipeline_stages, ts) AS pipeline_stages,
        max(ts) AS last_snapshot_at,
        greatest(max(xdp_total_packets) - min(xdp_total_packets), 0) AS xdp_packets,
        greatest(max(flow_packets_acked) - min(flow_packets_acked), 0) AS ch_packets,
        greatest(max(xdp_total_bytes) - min(xdp_total_bytes), 0) AS xdp_bytes,
        greatest(max(flow_bytes_acked) - min(flow_bytes_acked), 0) AS ch_bytes,
        greatest(max(records_parsed) - min(records_parsed), 0) AS records_parsed,
        if(
          has(argMax(pipeline_stages, ts), 'collector')
            AND greatest(max(xdp_total_packets) - min(xdp_total_packets), 0) > 0,
          (greatest(max(flow_packets_acked) - min(flow_packets_acked), 0))
            / greatest(max(xdp_total_packets) - min(xdp_total_packets), 0) * 100,
          if(
            has(argMax(pipeline_stages, ts), 'receiver')
              AND greatest(max(records_parsed) - min(records_parsed), 0) > 0,
            (greatest(max(flow_packets_acked) - min(flow_packets_acked), 0))
              / greatest(max(records_parsed) - min(records_parsed), 0) * 100,
            0
          )
        ) AS packets_pct,
        if(
          has(argMax(pipeline_stages, ts), 'collector')
            AND greatest(max(xdp_total_bytes) - min(xdp_total_bytes), 0) > 0,
          (greatest(max(flow_bytes_acked) - min(flow_bytes_acked), 0))
            / greatest(max(xdp_total_bytes) - min(xdp_total_bytes), 0) * 100,
          if(
            has(argMax(pipeline_stages, ts), 'receiver')
              AND greatest(max(records_parsed) - min(records_parsed), 0) > 0,
            (greatest(max(flow_bytes_acked) - min(flow_bytes_acked), 0))
              / greatest(max(records_parsed) - min(records_parsed), 0) * 100,
            0
          )
        ) AS bytes_pct,
        greatest(max(xdp_map_full) - min(xdp_map_full), 0) AS map_full_delta,
        greatest(max(insert_errs) - min(insert_errs), 0) AS insert_errs_delta,
        greatest(max(ch_queue_drops) - min(ch_queue_drops), 0) AS queue_drops_delta,
        greatest(max(udp_queue_drops) - min(udp_queue_drops), 0) AS udp_drops_delta,
        greatest(max(records_acked) - min(records_acked), 0) AS records_acked_delta,
        count() AS snapshot_count,
        min(ts) AS window_from,
        max(ts) AS window_to
      FROM ${table}
      WHERE ts >= now64(3) - INTERVAL {window_plus_lag:UInt32} MINUTE
        AND ts <  now64(3) - INTERVAL {lag_minutes:UInt32} MINUTE
      GROUP BY source_id
    `,
    {
      window_plus_lag: windowPlusLag,
      lag_minutes: settings.lagMinutes,
    },
    { name: 'collectors/completeness' },
  );

  const data = rows.map(mapCompletenessRow);

  return {
    data,
    meta: {
      elapsedMs,
      rows: data.length,
      enabled: true,
      windowMinutes: settings.windowMinutes,
      lagMinutes: settings.lagMinutes,
      thresholds: {
        warnBytesPct: settings.warnBytesPct,
        warnPacketsPct: settings.warnPacketsPct,
        criticalBytesPct: settings.criticalBytesPct,
        criticalPacketsPct: settings.criticalPacketsPct,
      },
    },
  };
}

module.exports = {
  fetchCollectorCompleteness,
  classifyCompleteness,
  mapCompletenessRow,
  resolveInputPackets,
};
