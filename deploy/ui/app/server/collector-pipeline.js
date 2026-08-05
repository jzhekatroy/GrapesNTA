'use strict';

const { query, collectorHealthSnapshotsTableRef } = require('./clickhouse');

const LAG_MINUTES = 2;
/** L: лаг формирования flow — смещение seen_window назад относительно acked_window,
 *  чтобы пакеты успели пройти map → spool → ClickHouse до сравнения полноты. */
const ACK_OFFSET_MINUTES = 5;
const HISTORY_WINDOW_MINUTES = 1440;
const HISTORY_BUCKET_SECONDS = 900;
const COMPLETENESS_GREEN_PCT = 99;
const COMPLETENESS_YELLOW_PCT = 90;
const PHY_DISCARD_YELLOW_PCT = 0.01;
const PHY_DISCARD_RED_PCT = 0.1;
const NF_SOCKET_YELLOW_PCT = 0.1;
const NF_SOCKET_RED_PCT = 1;
const DRAINER_AGE_HEALTHY_SEC = 60;

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function parseSourceId(raw) {
  const id = String(raw || '').trim();
  if (!id) throw apiError('Укажите sourceId');
  return id;
}

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function delta(row, key) {
  return Math.max(0, num(row[`${key}_delta`]));
}

function pctOf(part, whole) {
  if (!whole || whole <= 0) return null;
  return Number(((part / whole) * 100).toFixed(6));
}

function capCompletenessPct(rawPct) {
  if (rawPct == null || !Number.isFinite(rawPct)) return null;
  return Number(Math.min(100, rawPct).toFixed(4));
}

function parsePipelineStages(raw) {
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw === 'string' && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed.map(String);
    } catch {
      // ClickHouse tuple-like string
    }
    return raw.replace(/^\[|\]$/g, '').split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
  }
  return [];
}

function counterSourceLabel(phyCounterSource) {
  const src = String(phyCounterSource || '').trim();
  if (!src) return null;
  if (src === 'sysfs') return 'sysfs (оценка)';
  if (src.startsWith('ethtool:')) return null;
  return src;
}

function isXdpMeasurable(meta) {
  return parsePipelineStages(meta.pipelineStages).includes('collector');
}

function deltaIf(column, startExpr, endExpr, alias) {
  return `greatest(maxIf(${column}, ts >= ${startExpr} AND ts < ${endExpr}) - minIf(${column}, ts >= ${startExpr} AND ts < ${endExpr}), 0) AS ${alias}`;
}

function envInt(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function resolveCompletenessTiming(windowMinutesOverride) {
  return {
    windowMinutes: windowMinutesOverride ?? envInt('COMPLETENESS_WINDOW_MINUTES', 30),
    lagMinutes: envInt('COMPLETENESS_LAG_MINUTES', LAG_MINUTES),
    ackOffsetMinutes: envInt('COMPLETENESS_ACK_OFFSET_MINUTES', ACK_OFFSET_MINUTES),
  };
}

function windowsRelativeToNow(windowMinutes, lagMinutes = LAG_MINUTES, ackOffsetMinutes = ACK_OFFSET_MINUTES) {
  const ackEnd = `now64(3) - INTERVAL ${lagMinutes} MINUTE`;
  const ackStart = `now64(3) - INTERVAL ${windowMinutes + lagMinutes} MINUTE`;
  const seenEnd = `now64(3) - INTERVAL ${lagMinutes + ackOffsetMinutes} MINUTE`;
  const seenStart = `now64(3) - INTERVAL ${windowMinutes + lagMinutes + ackOffsetMinutes} MINUTE`;
  return { ackStart, ackEnd, seenStart, seenEnd };
}

function windowsRelativeToBucketEnd(bucketEndExpr) {
  const ackEnd = `${bucketEndExpr} - INTERVAL {lag_minutes:UInt32} MINUTE`;
  const ackStart = `${ackEnd} - INTERVAL {window_minutes:UInt32} MINUTE`;
  const seenEnd = `${bucketEndExpr} - INTERVAL {lag_plus_offset:UInt32} MINUTE`;
  const seenStart = `${seenEnd} - INTERVAL {window_minutes:UInt32} MINUTE`;
  return { ackStart, ackEnd, seenStart, seenEnd };
}

function buildCompletenessDeltaSql(windows, aliases = {}) {
  const alias = (key, fallback) => aliases[key] || fallback;
  const { ackStart, ackEnd, seenStart, seenEnd } = windows;
  return `
    ${deltaIf('xdp_total_packets', seenStart, seenEnd, alias('seen_packets', 'seen_packets'))},
    ${deltaIf('xdp_non_ip_pass', seenStart, seenEnd, alias('xdp_non_ip_pass', 'xdp_non_ip_pass'))},
    countIf(ts >= ${seenStart} AND ts < ${seenEnd}) AS seen_snapshot_count,
    countIf(ts >= ${ackStart} AND ts < ${ackEnd}) AS ack_snapshot_count,
    ${deltaIf('flow_packets_acked', ackStart, ackEnd, alias('flow_packets_acked', 'flow_packets_acked_delta'))},
    ${deltaIf('flow_packets_excluded', ackStart, ackEnd, alias('flow_packets_excluded', 'flow_packets_excluded_delta'))},
    ${deltaIf('phy_rx_packets', seenStart, seenEnd, alias('phy_rx_packets', 'phy_rx_packets_delta'))},
    ${deltaIf('phy_rx_discards', seenStart, seenEnd, alias('phy_rx_discards', 'phy_rx_discards_delta'))},
    ${deltaIf('xdp_map_full', ackStart, ackEnd, alias('xdp_map_full', 'xdp_map_full_delta'))},
    ${deltaIf('xdp_parse_errors', ackStart, ackEnd, alias('xdp_parse_errors', 'xdp_parse_errors_delta'))},
    ${deltaIf('datagrams', ackStart, ackEnd, alias('datagrams', 'datagrams_delta'))},
    ${deltaIf('records_parsed', ackStart, ackEnd, alias('records_parsed', 'records_parsed_delta'))},
    ${deltaIf('udp_queue_drops', ackStart, ackEnd, alias('udp_queue_drops', 'udp_queue_drops_delta'))},
    ${deltaIf('receiver_parse_errors', ackStart, ackEnd, alias('receiver_parse_errors', 'receiver_parse_errors_delta'))},
    ${deltaIf('records_spooled', ackStart, ackEnd, alias('records_spooled', 'records_spooled_delta'))},
    ${deltaIf('spool_corruption_frames', ackStart, ackEnd, alias('spool_corruption', 'spool_corruption_frames_delta'))},
    ${deltaIf('records_acked', ackStart, ackEnd, alias('records_acked', 'records_acked_delta'))},
    ${deltaIf('insert_errs', ackStart, ackEnd, alias('insert_errs', 'insert_errs_delta'))},
    ${deltaIf('ch_queue_drops', ackStart, ackEnd, alias('queue_drops', 'ch_queue_drops_delta'))},
    ${deltaIf('nf_records_out', ackStart, ackEnd, alias('nf_records_out', 'nf_records_out_delta'))},
    ${deltaIf('nf_packets_out', ackStart, ackEnd, alias('nf_packets_out', 'nf_packets_out_delta'))},
    ${deltaIf('nf_send_errs', ackStart, ackEnd, alias('nf_send_errs', 'nf_send_errs_delta'))},
    ${deltaIf('nf_socket_drops', ackStart, ackEnd, alias('nf_socket_drops', 'nf_socket_drops_delta'))},
    ${deltaIf('xdp_total_packets', ackStart, ackEnd, alias('xdp_total_packets', 'xdp_total_packets_delta'))}
  `;
}

function computeCompletenessPct(counters) {
  const seen = num(counters.seen_packets);
  const nonIp = num(counters.xdp_non_ip_pass);
  const denominator = Math.max(0, seen - nonIp);
  if (denominator <= 0) return null;
  const accounted = num(counters.flow_packets_acked) + num(counters.flow_packets_excluded);
  return capCompletenessPct((accounted / denominator) * 100);
}

function computeCompletenessDenominator(counters) {
  return Math.max(0, num(counters.seen_packets) - num(counters.xdp_non_ip_pass));
}

function computeUnconfirmedPackets(counters) {
  const denominator = computeCompletenessDenominator(counters);
  if (denominator <= 0) return 0;
  const accounted = num(counters.flow_packets_acked) + num(counters.flow_packets_excluded);
  return Math.max(0, denominator - accounted);
}

function hasCompletenessSnapshots(row) {
  return num(row.seen_snapshot_count) >= 2 && num(row.ack_snapshot_count) >= 2;
}

function buildRawCounters(row) {
  const seenPackets = num(row.seen_packets);
  return {
    seen_packets: seenPackets,
    xdp_non_ip_pass: num(row.xdp_non_ip_pass),
    phy_rx_packets: delta(row, 'phy_rx_packets'),
    phy_rx_discards: delta(row, 'phy_rx_discards'),
    xdp_total_packets: seenPackets || delta(row, 'xdp_total_packets'),
    xdp_map_full: delta(row, 'xdp_map_full'),
    xdp_parse_errors: delta(row, 'xdp_parse_errors'),
    datagrams: delta(row, 'datagrams'),
    records_parsed: delta(row, 'records_parsed'),
    udp_queue_drops: delta(row, 'udp_queue_drops'),
    receiver_parse_errors: delta(row, 'receiver_parse_errors'),
    flow_packets_excluded: delta(row, 'flow_packets_excluded'),
    records_spooled: delta(row, 'records_spooled'),
    spool_corruption_frames: delta(row, 'spool_corruption_frames'),
    flow_packets_acked: delta(row, 'flow_packets_acked'),
    records_acked: delta(row, 'records_acked'),
    insert_errs: delta(row, 'insert_errs'),
    ch_queue_drops: delta(row, 'ch_queue_drops'),
    nf_records_out: delta(row, 'nf_records_out'),
    nf_packets_out: delta(row, 'nf_packets_out'),
    nf_send_errs: delta(row, 'nf_send_errs'),
    nf_socket_drops: delta(row, 'nf_socket_drops'),
    lag_segments: num(row.lag_segments),
    drainer_progress_age_sec: num(row.drainer_progress_age_sec),
    seen_snapshot_count: num(row.seen_snapshot_count),
    ack_snapshot_count: num(row.ack_snapshot_count),
  };
}

function toneFromPctThresholds(pct, yellowPct, redPct) {
  if (pct == null || pct <= 0) return 'healthy';
  if (pct >= redPct) return 'critical';
  if (pct >= yellowPct) return 'warning';
  return 'healthy';
}

function isSpoolHealthy(counters) {
  return counters.insert_errs === 0
    && counters.ch_queue_drops === 0
    && counters.spool_corruption_frames === 0
    && counters.lag_segments === 0
    && counters.drainer_progress_age_sec <= DRAINER_AGE_HEALTHY_SEC;
}

function mapMeta(row) {
  return {
    collectorId: String(row.collector_id ?? ''),
    daemon: String(row.daemon ?? ''),
    status: String(row.status ?? ''),
    statusReasons: String(row.status_reasons ?? ''),
    iface: String(row.iface ?? ''),
    nfDsts: String(row.nf_dsts ?? ''),
    phyCounterSource: String(row.phy_counter_source ?? ''),
    nfSocketObserved: num(row.nf_socket_observed),
    pipelineStages: parsePipelineStages(row.pipeline_stages),
    snapshotCount: num(row.snapshot_count),
    snapshotAgeMinutes: num(row.snapshot_age_minutes),
    windowFrom: row.window_from ?? null,
    windowTo: row.window_to ?? null,
    lastSnapshotAt: row.last_snapshot_at ?? null,
  };
}

function resolveGrowthCounter(meta, counters) {
  const stages = parsePipelineStages(meta.pipelineStages);
  if (stages.includes('collector')) return counters.seen_packets || counters.xdp_total_packets;
  if (stages.includes('receiver')) return counters.records_parsed;
  return counters.seen_packets || counters.xdp_total_packets || counters.records_parsed;
}

function resolveExporterStatus(meta, counters, snapshotCount, snapshotAgeMinutes) {
  if (snapshotAgeMinutes > 3) return 'no_connection';
  if (snapshotCount < 2) return 'no_data';
  if (resolveGrowthCounter(meta, counters) <= 0) return 'no_data';
  return 'working';
}

function buildPacketFunnel(counters, meta) {
  const stages = parsePipelineStages(meta.pipelineStages);
  const stageSet = new Set(stages);
  const lines = [];

  if (stageSet.has('interface') && String(meta.phyCounterSource || '').trim()) {
    lines.push({
      id: 'wire',
      label: 'Пришло на сетевую карту',
      sourceLabel: counterSourceLabel(meta.phyCounterSource),
      value: counters.phy_rx_packets,
      isEstimate: String(meta.phyCounterSource || '').trim() === 'sysfs',
    });
    if (counters.phy_rx_discards > 0 || counters.phy_rx_packets > 0) {
      const discardPct = pctOf(counters.phy_rx_discards, counters.phy_rx_packets);
      lines.push({
        id: 'wire_loss',
        kind: 'loss',
        label: 'Сетевая карта отбросила',
        value: counters.phy_rx_discards,
        lossPct: discardPct,
        lossPctLabel: formatPctLabel(discardPct),
        tone: toneFromPctThresholds(discardPct, PHY_DISCARD_YELLOW_PCT, PHY_DISCARD_RED_PCT),
      });
    }
  }

  if (stageSet.has('collector')) {
    lines.push({
      id: 'xdp',
      label: 'Получено коллектором',
      value: counters.seen_packets || counters.xdp_total_packets,
    });
    const bpfLost = counters.xdp_map_full + counters.xdp_parse_errors;
    const xdpBase = counters.seen_packets || counters.xdp_total_packets;
    const bpfPct = pctOf(bpfLost, xdpBase);
    lines.push({
      id: 'xdp_loss',
      kind: 'loss',
      label: 'Коллектор отбросил',
      value: bpfLost,
      lossPct: bpfPct,
      lossPctLabel: formatPctLabel(bpfPct),
      tone: bpfLost > 0 ? 'warning' : 'healthy',
    });
  }

  if (counters.flow_packets_excluded > 0) {
    lines.push({
      id: 'exclusions',
      kind: 'exclusion',
      label: 'Исключено правилами',
      value: counters.flow_packets_excluded,
      note: 'не потеря',
    });
  }

  if (stageSet.has('clickhouse')) {
    const completenessPct = computeCompletenessPct(counters);
    const chLine = {
      id: 'clickhouse',
      label: 'Учтено в ClickHouse',
      value: counters.flow_packets_acked,
      completenessPct,
    };
    if (counters.insert_errs === 0) {
      chLine.note = 'ещё может быть в обработке, не потеря';
    }
    lines.push(chLine);
  }

  return lines;
}

function buildSpoolCard(counters) {
  return {
    recordsAcked: counters.records_acked,
    spoolCorruptionFrames: counters.spool_corruption_frames,
    lagSegments: counters.lag_segments,
    drainerProgressAgeSec: counters.drainer_progress_age_sec,
    insertErrs: counters.insert_errs,
    chQueueDrops: counters.ch_queue_drops,
  };
}

function buildNetflowCard(counters, meta) {
  const stages = parsePipelineStages(meta.pipelineStages);
  if (!stages.includes('netflow')) return null;
  const card = {
    nfRecordsOut: counters.nf_records_out,
    nfPacketsOut: counters.nf_packets_out,
    nfSendErrs: counters.nf_send_errs,
    nfDsts: meta.nfDsts || '',
  };
  if (Number(meta.nfSocketObserved) === 1) {
    card.nfSocketDrops = counters.nf_socket_drops;
    card.nfSocketDropPct = pctOf(counters.nf_socket_drops, counters.nf_packets_out);
    card.nfSocketDropTone = toneFromPctThresholds(
      card.nfSocketDropPct,
      NF_SOCKET_YELLOW_PCT,
      NF_SOCKET_RED_PCT,
    );
  }
  return card;
}

function buildAggregationLine(counters) {
  const seen = counters.seen_packets || counters.xdp_total_packets;
  if (seen <= 0 || counters.records_spooled <= 0) return null;
  const ratio = seen / counters.records_spooled;
  return {
    packetsPerRecord: Number(ratio.toFixed(1)),
    fromPackets: seen,
    toRecords: counters.records_spooled,
    text: `агрегация: ${ratio.toFixed(1)} пакета на flow-запись (${seen.toLocaleString('ru-RU')} → ${counters.records_spooled.toLocaleString('ru-RU')})`,
  };
}

function breakdownRow(key, label, value, base, kind) {
  return {
    key,
    label,
    value,
    pctOfBase: capCompletenessPct(pctOf(value, base)),
    kind,
  };
}

function buildLossBreakdown(counters, meta) {
  if (!isXdpMeasurable(meta)) return null;
  const denominator = computeCompletenessDenominator(counters);
  if (denominator <= 0) return null;

  const stages = parsePipelineStages(meta.pipelineStages);
  const acked = counters.flow_packets_acked;
  const excluded = counters.flow_packets_excluded;
  const unconfirmed = computeUnconfirmedPackets(counters);

  const sections = [
    {
      id: 'completeness',
      title: 'Расчёт полноты',
      rows: [
        breakdownRow('seen', 'Получено коллектором', counters.seen_packets, denominator, 'base'),
        breakdownRow('non_ip', 'Служебные пакеты', counters.xdp_non_ip_pass, denominator, 'info'),
        breakdownRow('denominator', 'Пакеты для учёта', denominator, denominator, 'sum'),
        breakdownRow('acked', 'Подтверждено в ClickHouse', acked, denominator, 'accounted'),
        breakdownRow('excluded', 'Исключено правилами', excluded, denominator, 'exclusion'),
      ],
    },
    {
      id: 'losses',
      title: 'Явные потери',
      rows: [
        ...(stages.includes('interface')
          ? [breakdownRow('phy_discards', 'Сетевая карта отбросила', counters.phy_rx_discards, denominator, 'loss')]
          : []),
        breakdownRow('map_full', 'Коллектор: map_full', counters.xdp_map_full, denominator, 'loss'),
        breakdownRow('parse_errors', 'Коллектор: parse_errors', counters.xdp_parse_errors, denominator, 'loss'),
        breakdownRow('insert_errs', 'Ошибки INSERT', counters.insert_errs, denominator, 'critical'),
        breakdownRow('ch_queue_drops', 'Сбросы очереди CH', counters.ch_queue_drops, denominator, 'critical'),
        breakdownRow('spool_corruption', 'Повреждённые кадры спула', counters.spool_corruption_frames, denominator, 'critical'),
        breakdownRow('nf_send_errs', 'Ошибки отправки NetFlow', counters.nf_send_errs, denominator, 'critical'),
      ],
    },
    {
      id: 'unconfirmed',
      title: 'Не подтверждено',
      rows: [
        breakdownRow('unconfirmed', 'Остаток', unconfirmed, denominator, 'unconfirmed'),
      ],
    },
    {
      id: 'spool',
      title: 'Кеш и запись',
      rows: [
        breakdownRow('records_spooled', 'Записей в спул', counters.records_spooled, denominator, 'info'),
        breakdownRow('records_acked', 'Записей подтверждено', counters.records_acked, denominator, 'info'),
        breakdownRow('lag_segments', 'Отставание сегментов', counters.lag_segments, null, 'info'),
        breakdownRow('drainer_age', 'Возраст прогресса, с', counters.drainer_progress_age_sec, null, 'info'),
      ],
    },
  ];

  return { sections };
}

function buildExplicitLosses(counters, meta) {
  const losses = [];
  const stages = parsePipelineStages(meta.pipelineStages);

  if (stages.includes('interface') && counters.phy_rx_discards > 0) {
    const pct = pctOf(counters.phy_rx_discards, counters.phy_rx_packets);
    losses.push({
      id: 'phy_discards',
      label: 'Сетевая карта отбросила',
      value: counters.phy_rx_discards,
      pct,
      pctLabel: formatPctLabel(pct),
      tone: toneFromPctThresholds(pct, PHY_DISCARD_YELLOW_PCT, PHY_DISCARD_RED_PCT),
    });
  }

  const bpfLost = counters.xdp_map_full + counters.xdp_parse_errors;
  if (bpfLost > 0) {
    const xdpBase = counters.seen_packets || counters.xdp_total_packets;
    const pct = pctOf(bpfLost, xdpBase);
    losses.push({
      id: 'bpf',
      label: 'BPF отбросил',
      value: bpfLost,
      pct,
      pctLabel: formatPctLabel(pct),
      tone: 'warning',
    });
  }

  if (counters.insert_errs > 0) {
    losses.push({ id: 'insert_errs', label: 'ошибки INSERT', value: counters.insert_errs, tone: 'critical' });
  }
  if (counters.ch_queue_drops > 0) {
    losses.push({ id: 'ch_queue_drops', label: 'сбросы очереди CH', value: counters.ch_queue_drops, tone: 'critical' });
  }
  if (counters.spool_corruption_frames > 0) {
    losses.push({ id: 'spool_corruption', label: 'повреждение спула', value: counters.spool_corruption_frames, tone: 'critical' });
  }
  if (counters.nf_send_errs > 0) {
    losses.push({ id: 'nf_send_errs', label: 'ошибки отправки NetFlow', value: counters.nf_send_errs, tone: 'critical' });
  }

  return losses;
}

function buildVerdict(counters, meta, windowMinutes, ackOffsetMinutes = ACK_OFFSET_MINUTES) {
  const measurable = isXdpMeasurable(meta);
  const completenessPct = measurable ? computeCompletenessPct(counters) : null;
  if (!measurable || completenessPct == null) {
    return {
      headline: 'Полнота не измеряется',
      subline: 'sFlow приходит уже агрегированным',
      measurable: false,
    };
  }

  const losses = buildExplicitLosses(counters, meta);
  const unconfirmed = computeUnconfirmedPackets(counters);
  const spoolHealthy = isSpoolHealthy(counters);
  const collectorChLosses = losses.filter((l) => ['bpf', 'insert_errs', 'ch_queue_drops', 'spool_corruption', 'nf_send_errs'].includes(l.id));

  return {
    headline: `Полнота ${completenessPct.toFixed(1)}% за ${windowMinutes} минут`,
    measurable: true,
    completenessPct,
    losses,
    lossesFooter: collectorChLosses.length === 0 ? 'в коллекторе и ClickHouse — нет' : null,
    unconfirmed: {
      packets: unconfirmed,
      label: spoolHealthy ? 'скорее всего в обработке' : 'не подтверждено / возможны потери',
      tone: spoolHealthy ? 'neutral' : 'critical',
      hint: spoolHealthy
        ? 'спул здоров → хвост окна, не классифицируем как потерю'
        : 'есть ошибки или отставание спула/CH',
    },
  };
}

function formatCompactCount(value) {
  const n = Number(value) || 0;
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} млрд`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} млн`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} тыс`;
  return String(n);
}

function formatPctLabel(value) {
  if (value == null) return '—';
  if (value === 0) return '0%';
  if (value > 0 && value < 0.01) return '<0.01%';
  if (value < 1) return `${value.toFixed(3)}%`;
  return `${value.toFixed(2)}%`;
}

const META_COLUMNS_SQL = `
  argMax(collector_id, ts) AS collector_id,
  argMax(daemon, ts) AS daemon,
  argMax(status, ts) AS status,
  argMax(status_reasons, ts) AS status_reasons,
  argMax(iface, ts) AS iface,
  argMax(nf_dsts, ts) AS nf_dsts,
  argMax(phy_counter_source, ts) AS phy_counter_source,
  argMax(nf_socket_observed, ts) AS nf_socket_observed,
  argMax(pipeline_stages, ts) AS pipeline_stages,
  argMax(lag_segments, ts) AS lag_segments,
  argMax(drainer_progress_age_sec, ts) AS drainer_progress_age_sec,
  max(ts) AS last_snapshot_at,
  dateDiff('minute', max(ts), now64(3)) AS snapshot_age_minutes,
  count() AS snapshot_count,
  min(ts) AS window_from,
  max(ts) AS window_to
`;

async function fetchSnapshotRow(sourceId, windowMinutes, timing = resolveCompletenessTiming(windowMinutes)) {
  const table = collectorHealthSnapshotsTableRef();
  const windows = windowsRelativeToNow(timing.windowMinutes, timing.lagMinutes, timing.ackOffsetMinutes);
  const fetchSpan = timing.windowMinutes + timing.lagMinutes + timing.ackOffsetMinutes + 5;

  const { rows, elapsedMs } = await query(
    `
      SELECT
        source_id,
        ${META_COLUMNS_SQL},
        ${buildCompletenessDeltaSql(windows)}
      FROM ${table}
      WHERE source_id = {source_id:String}
        AND ts >= now64(3) - INTERVAL {fetch_span:UInt32} MINUTE
        AND ts <  now64(3) - INTERVAL {lag_minutes:UInt32} MINUTE
      GROUP BY source_id
    `,
    {
      source_id: sourceId,
      fetch_span: fetchSpan,
      lag_minutes: timing.lagMinutes,
    },
    { name: 'collectors/completeness/detail' },
  );

  return { row: rows[0] || null, elapsedMs };
}

function buildDetailFromRow(row, timing) {
  if (!row || !hasCompletenessSnapshots(row)) {
    return {
      insufficientData: true,
      meta: row ? mapMeta(row) : null,
    };
  }

  const meta = mapMeta(row);
  const counters = buildRawCounters(row);
  const measurable = isXdpMeasurable(meta);

  return {
    insufficientData: false,
    measurable,
    meta,
    counters,
    ackOffsetMinutes: timing.ackOffsetMinutes,
    exporterStatus: resolveExporterStatus(meta, counters, meta.snapshotCount, meta.snapshotAgeMinutes),
    completenessPct: measurable ? computeCompletenessPct(counters) : null,
    verdict: buildVerdict(counters, meta, timing.windowMinutes, timing.ackOffsetMinutes),
    packetFunnel: measurable ? buildPacketFunnel(counters, meta) : [],
    spool: buildSpoolCard(counters),
    netflow: buildNetflowCard(counters, meta),
    aggregation: buildAggregationLine(counters),
    lossBreakdown: measurable ? buildLossBreakdown(counters, meta) : null,
  };
}

async function fetchCompletenessDetail(sourceIdRaw, windowMinutes) {
  const sourceId = parseSourceId(sourceIdRaw);
  const timing = resolveCompletenessTiming(windowMinutes);
  const { row, elapsedMs } = await fetchSnapshotRow(sourceId, windowMinutes, timing);
  const detail = buildDetailFromRow(row, timing);
  return {
    sourceId,
    windowMinutes: timing.windowMinutes,
    lagMinutes: timing.lagMinutes,
    ackOffsetMinutes: timing.ackOffsetMinutes,
    ...detail,
    metaResponse: { elapsedMs, enabled: true },
  };
}

async function fetchCompletenessHistory(sourceIdRaw, windowMinutes = 30) {
  const sourceId = parseSourceId(sourceIdRaw);
  const timing = resolveCompletenessTiming(windowMinutes);
  const table = collectorHealthSnapshotsTableRef();
  const fetchSpan = HISTORY_WINDOW_MINUTES + timing.windowMinutes + timing.lagMinutes + timing.ackOffsetMinutes + 5;
  const bucketEndExpr = 'toStartOfInterval(ts, INTERVAL {bucket_sec:UInt32} SECOND) + INTERVAL {bucket_sec:UInt32} SECOND';
  const windows = windowsRelativeToBucketEnd(bucketEndExpr);

  const { rows, elapsedMs } = await query(
    `
      SELECT
        toStartOfInterval(ts, INTERVAL {bucket_sec:UInt32} SECOND) AS bucket_ts,
        ${buildCompletenessDeltaSql(windows)},
        argMax(pipeline_stages, ts) AS pipeline_stages
      FROM ${table}
      WHERE source_id = {source_id:String}
        AND ts >= now64(3) - INTERVAL {fetch_span:UInt32} MINUTE
        AND ts <  now64(3) - INTERVAL {lag_minutes:UInt32} MINUTE
      GROUP BY bucket_ts
      ORDER BY bucket_ts
    `,
    {
      source_id: sourceId,
      fetch_span: fetchSpan,
      lag_minutes: timing.lagMinutes,
      bucket_sec: HISTORY_BUCKET_SECONDS,
      window_minutes: timing.windowMinutes,
      lag_plus_offset: timing.lagMinutes + timing.ackOffsetMinutes,
    },
    { name: 'collectors/completeness/history' },
  );

  const buckets = rows
    .filter((row) => hasCompletenessSnapshots(row))
    .map((row) => {
      const meta = { pipelineStages: parsePipelineStages(row.pipeline_stages) };
      const counters = buildRawCounters(row);
      const measurable = isXdpMeasurable(meta);
      return {
        ts: row.bucket_ts,
        completenessPct: measurable ? computeCompletenessPct(counters) : null,
      };
    })
    .filter((b) => b.completenessPct != null);

  return {
    sourceId,
    windowMinutes: HISTORY_WINDOW_MINUTES,
    completenessWindowMinutes: timing.windowMinutes,
    ackOffsetMinutes: timing.ackOffsetMinutes,
    bucketSeconds: HISTORY_BUCKET_SECONDS,
    buckets,
    meta: { elapsedMs, enabled: true },
  };
}

module.exports = {
  LAG_MINUTES,
  ACK_OFFSET_MINUTES,
  resolveCompletenessTiming,
  envInt,
  HISTORY_WINDOW_MINUTES,
  COMPLETENESS_GREEN_PCT,
  COMPLETENESS_YELLOW_PCT,
  parseSourceId,
  parsePipelineStages,
  buildRawCounters,
  buildCompletenessDeltaSql,
  windowsRelativeToNow,
  hasCompletenessSnapshots,
  computeCompletenessDenominator,
  computeUnconfirmedPackets,
  isSpoolHealthy,
  mapMeta,
  isXdpMeasurable,
  computeCompletenessPct,
  capCompletenessPct,
  resolveExporterStatus,
  resolveGrowthCounter,
  buildPacketFunnel,
  buildSpoolCard,
  buildNetflowCard,
  buildAggregationLine,
  buildLossBreakdown,
  buildVerdict,
  buildDetailFromRow,
  fetchCompletenessDetail,
  fetchCompletenessHistory,
  META_COLUMNS_SQL,
};
