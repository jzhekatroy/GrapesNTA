const { query, collectorHealthSnapshotsTableRef } = require('./clickhouse');
const {
  COMPLETENESS_GREEN_PCT,
  COMPLETENESS_YELLOW_PCT,
  parsePipelineStages,
  isXdpMeasurable,
  computeCompletenessPct,
  resolveExporterStatus,
  buildCompletenessDeltaSql,
  windowsRelativeToNow,
  hasCompletenessSnapshots,
  resolveCompletenessTiming,
  META_COLUMNS_SQL,
} = require('./collector-pipeline');

const settings = {
  ...resolveCompletenessTiming(),
  greenPct: COMPLETENESS_GREEN_PCT,
  yellowPct: COMPLETENESS_YELLOW_PCT,
};

const NON_MEASURABLE_TOOLTIP = 'не измеряется: sFlow приходит уже агрегированным';

function num(row, key) {
  const v = Number(row[key]);
  return Number.isFinite(v) ? v : 0;
}

function hasCriticalErrors(row) {
  return num(row, 'insert_errs_delta') > 0
    || num(row, 'queue_drops_delta') > 0
    || num(row, 'spool_corruption_delta') > 0
    || num(row, 'nf_send_errs_delta') > 0;
}

function classifyCompleteness(row) {
  const meta = { pipelineStages: parsePipelineStages(row.pipeline_stages) };
  const measurable = isXdpMeasurable(meta);

  if (!hasCompletenessSnapshots(row)) {
    return { status: 'unknown', tone: 'idle', measurable: false, reasons: ['insufficient_snapshots'] };
  }

  if (!measurable) {
    return { status: 'na', tone: 'idle', measurable: false, reasons: [], tooltip: NON_MEASURABLE_TOOLTIP };
  }

  const completenessPct = computeCompletenessPct({
    seen_packets: num(row, 'seen_packets'),
    xdp_non_ip_pass: num(row, 'xdp_non_ip_pass'),
    flow_packets_acked: num(row, 'ch_packets'),
    flow_packets_excluded: num(row, 'excluded_packets'),
  });

  if (completenessPct == null) {
    return { status: 'unknown', tone: 'idle', measurable: true, reasons: ['insufficient_snapshots'] };
  }

  const reasons = [];
  if (hasCriticalErrors(row)) reasons.push('technical_errors');
  if (completenessPct < settings.yellowPct) reasons.push('low_completeness');

  if (hasCriticalErrors(row) || completenessPct < settings.yellowPct) {
    return { status: 'critical', tone: 'critical', measurable: true, reasons, completenessPct };
  }
  if (completenessPct < settings.greenPct) {
    return { status: 'warning', tone: 'warning', measurable: true, reasons, completenessPct };
  }
  return { status: 'ok', tone: 'healthy', measurable: true, reasons, completenessPct };
}

function mapCompletenessRow(row) {
  const classified = classifyCompleteness(row);
  const meta = {
    pipelineStages: parsePipelineStages(row.pipeline_stages),
  };
  const counters = {
    seen_packets: num(row, 'seen_packets'),
    xdp_total_packets: num(row, 'seen_packets'),
    records_parsed: num(row, 'records_parsed'),
  };
  const exporterStatus = resolveExporterStatus(
    meta,
    counters,
    num(row, 'snapshot_count'),
    num(row, 'snapshot_age_minutes'),
  );

  return {
    sourceId: String(row.source_id ?? ''),
    collectorId: String(row.collector_id ?? ''),
    daemon: String(row.daemon ?? ''),
    status: classified.status,
    tone: classified.tone,
    measurable: classified.measurable,
    completenessPct: classified.measurable ? classified.completenessPct ?? null : null,
    tooltip: classified.tooltip || null,
    reasons: classified.reasons,
    exporterStatus,
    windowMinutes: settings.windowMinutes,
    lagMinutes: settings.lagMinutes,
    ackOffsetMinutes: settings.ackOffsetMinutes,
    snapshotCount: num(row, 'snapshot_count'),
    snapshotAgeMinutes: num(row, 'snapshot_age_minutes'),
    windowFrom: row.window_from ?? null,
    windowTo: row.window_to ?? null,
    seenPackets: num(row, 'seen_packets'),
    nonIpPackets: num(row, 'xdp_non_ip_pass'),
    chPackets: num(row, 'ch_packets'),
    excludedPackets: num(row, 'excluded_packets'),
    recordsParsed: num(row, 'records_parsed'),
    insertErrsDelta: num(row, 'insert_errs_delta'),
    queueDropsDelta: num(row, 'queue_drops_delta'),
    spoolCorruptionDelta: num(row, 'spool_corruption_delta'),
    nfSendErrsDelta: num(row, 'nf_send_errs_delta'),
    lastSnapshotAt: row.last_snapshot_at ?? null,
    lastDaemonStatus: String(row.last_daemon_status ?? ''),
  };
}

async function fetchCollectorCompleteness() {
  const table = collectorHealthSnapshotsTableRef();
  const windows = windowsRelativeToNow(settings.windowMinutes, settings.lagMinutes, settings.ackOffsetMinutes);
  const fetchSpan = settings.windowMinutes + settings.lagMinutes + settings.ackOffsetMinutes + 5;

  const { rows, elapsedMs } = await query(
    `
      SELECT
        source_id,
        argMax(collector_id, ts) AS collector_id,
        argMax(daemon, ts) AS daemon,
        argMax(status, ts) AS last_daemon_status,
        argMax(pipeline_stages, ts) AS pipeline_stages,
        max(ts) AS last_snapshot_at,
        dateDiff('minute', max(ts), now64(3)) AS snapshot_age_minutes,
        count() AS snapshot_count,
        min(ts) AS window_from,
        max(ts) AS window_to,
        ${buildCompletenessDeltaSql(windows, {
          flow_packets_acked: 'ch_packets',
          flow_packets_excluded: 'excluded_packets',
          spool_corruption: 'spool_corruption_delta',
          queue_drops: 'queue_drops_delta',
        })}
      FROM ${table}
      WHERE ts >= now64(3) - INTERVAL {fetch_span:UInt32} MINUTE
        AND ts <  now64(3) - INTERVAL {lag_minutes:UInt32} MINUTE
      GROUP BY source_id
    `,
    {
      fetch_span: fetchSpan,
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
      ackOffsetMinutes: settings.ackOffsetMinutes,
      thresholds: {
        greenPct: settings.greenPct,
        yellowPct: settings.yellowPct,
      },
      nonMeasurableTooltip: NON_MEASURABLE_TOOLTIP,
    },
  };
}

module.exports = {
  settings,
  NON_MEASURABLE_TOOLTIP,
  fetchCollectorCompleteness,
  classifyCompleteness,
  mapCompletenessRow,
};
