'use strict';

const { query, collectorHealthSnapshotsTableRef } = require('./clickhouse');
const { loadPipelineThresholds, DEFAULT_THRESHOLDS } = require('./collector-pipeline-thresholds');

const WINDOW_MINUTES = {
  '15m': 15,
  '1h': 60,
  '24h': 1440,
};

const LAG_MINUTES = 2;

const STAGE_LABELS = {
  interface: 'Интерфейс',
  collector: 'Коллектор (XDP)',
  receiver: 'Коллектор (приёмник)',
  exclusions: 'Исключения',
  spool: 'Спул',
  clickhouse: 'ClickHouse',
  netflow: 'NetFlow-экспорт',
  socket: 'Сокет получателя',
};

/** Тип счётчика «Прошло» — для подписи к проценту между звеньями. */
const STAGE_PASSED_UNIT = {
  interface: 'packets',
  collector: 'packets',
  receiver: 'records',
  exclusions: 'packets',
  spool: 'records',
  clickhouse: 'packets',
  netflow: 'packets',
  socket: null,
};

const PASSED_UNIT_LABELS = {
  packets: 'пакеты',
  records: 'flow-записи',
};

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function parseWindow(raw = '1h') {
  const key = String(raw || '1h').trim();
  const minutes = WINDOW_MINUTES[key];
  if (!minutes) throw apiError(`Недопустимое окно: ${key}. Допустимо: 15m, 1h, 24h`);
  return { key, minutes };
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

function parsePipelineStages(raw) {
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw === 'string' && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed.map(String);
    } catch {
      // ClickHouse may return tuple-like string; split on comma
    }
    return raw.replace(/^\[|\]$/g, '').split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
  }
  return [];
}

function counterSourceLabel(phyCounterSource) {
  const src = String(phyCounterSource || '').trim();
  if (!src) return null;
  if (src === 'sysfs') return 'sysfs (оценка)';
  if (src.startsWith('ethtool:')) return src;
  return src;
}

function stageSourceLabel(stageId, meta = {}) {
  if (stageId === 'interface') return counterSourceLabel(meta.phyCounterSource) || 'интерфейс';
  if (stageId === 'collector') return 'xdpflowd';
  if (stageId === 'receiver') return 'flowcollectord';
  if (stageId === 'exclusions') return 'коллектор';
  if (stageId === 'spool') return 'коллектор';
  if (stageId === 'clickhouse') return 'writer';
  if (stageId === 'netflow') return 'xdpflowd';
  if (stageId === 'socket') return 'ядро';
  return '';
}

function classifyStage(stageId, stage, thresholds) {
  if (stageId === 'exclusions') {
    return stage.passed > 0 ? 'info' : 'ok';
  }

  const t = thresholds[stageId] || {};

  if (stageId === 'spool') {
    if (stage.lost > 0) return 'critical';
    return 'ok';
  }

  if (stageId === 'clickhouse') {
    if (num(stage.insertErrs) > 0) return 'critical';
    if (stage.lost > 0) return 'warning';
    return 'ok';
  }

  if (stageId === 'netflow') {
    if (num(stage.sendErrs) > 0) return 'critical';
    return 'ok';
  }

  const lossPct = stage.lossPct ?? 0;
  if (t.critPct != null && lossPct >= t.critPct) return 'critical';
  if (t.warnPct != null && lossPct >= t.warnPct) return 'warning';
  if (stage.lost > 0 && t.warnAny) return 'warning';
  return 'ok';
}

function buildRawCounters(row) {
  return {
    phy_rx_packets: delta(row, 'phy_rx_packets'),
    phy_rx_discards: delta(row, 'phy_rx_discards'),
    xdp_total_packets: delta(row, 'xdp_total_packets'),
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
    insert_errs: delta(row, 'insert_errs'),
    ch_queue_drops: delta(row, 'ch_queue_drops'),
    nf_packets_out: delta(row, 'nf_packets_out'),
    nf_send_errs: delta(row, 'nf_send_errs'),
    nf_socket_drops: delta(row, 'nf_socket_drops'),
  };
}

function buildPipelineStages(row, meta, counters) {
  const stages = parsePipelineStages(meta.pipelineStages);
  const stageSet = new Set(stages);
  const built = [];

  const pushStage = (def) => {
    built.push(def);
  };

  if (stageSet.has('interface') && String(meta.phyCounterSource || '').trim()) {
    pushStage({
      id: 'interface',
      label: STAGE_LABELS.interface,
      sourceLabel: stageSourceLabel('interface', meta),
      passed: counters.phy_rx_packets,
      lost: counters.phy_rx_discards,
      isEstimate: String(meta.phyCounterSource || '').trim() === 'sysfs',
    });
  }

  if (stageSet.has('collector')) {
    pushStage({
      id: 'collector',
      label: STAGE_LABELS.collector,
      sourceLabel: stageSourceLabel('collector', meta),
      passed: counters.xdp_total_packets,
      lost: counters.xdp_map_full + counters.xdp_parse_errors,
      mapFull: counters.xdp_map_full,
      parseErrors: counters.xdp_parse_errors,
    });
  }

  if (stageSet.has('receiver')) {
    pushStage({
      id: 'receiver',
      label: STAGE_LABELS.receiver,
      sourceLabel: stageSourceLabel('receiver', meta),
      passed: counters.records_parsed,
      lost: counters.udp_queue_drops + counters.receiver_parse_errors,
      datagrams: counters.datagrams,
    });
  }

  if (counters.flow_packets_excluded > 0) {
    pushStage({
      id: 'exclusions',
      label: STAGE_LABELS.exclusions,
      sourceLabel: stageSourceLabel('exclusions', meta),
      passed: counters.flow_packets_excluded,
      lost: 0,
      isExclusion: true,
    });
  }

  if (stageSet.has('collector') || stageSet.has('receiver')) {
    pushStage({
      id: 'spool',
      label: STAGE_LABELS.spool,
      sourceLabel: stageSourceLabel('spool', meta),
      passed: counters.records_spooled,
      lost: counters.spool_corruption_frames,
    });
  }

  if (stageSet.has('clickhouse')) {
    pushStage({
      id: 'clickhouse',
      label: STAGE_LABELS.clickhouse,
      sourceLabel: stageSourceLabel('clickhouse', meta),
      passed: counters.flow_packets_acked,
      lost: counters.insert_errs + counters.ch_queue_drops,
      insertErrs: counters.insert_errs,
      queueDrops: counters.ch_queue_drops,
    });
  }

  if (stageSet.has('netflow')) {
    pushStage({
      id: 'netflow',
      label: STAGE_LABELS.netflow,
      sourceLabel: stageSourceLabel('netflow', meta),
      passed: counters.nf_packets_out,
      lost: counters.nf_send_errs,
      sendErrs: counters.nf_send_errs,
    });
  }

  if (stageSet.has('netflow') && Number(meta.nfSocketObserved) === 1) {
    pushStage({
      id: 'socket',
      label: STAGE_LABELS.socket,
      sourceLabel: stageSourceLabel('socket', meta),
      passed: 0,
      lost: counters.nf_socket_drops,
    });
  }

  return built;
}

function buildPassPctNote(prevUnit, currUnit, prevPassed, passed, passPctRaw) {
  if (prevUnit && currUnit && prevUnit !== currUnit) {
    return `разные счётчики (${PASSED_UNIT_LABELS[prevUnit]} → ${PASSED_UNIT_LABELS[currUnit]}), не потери`;
  }
  if (prevPassed != null && prevPassed > 0 && passed > prevPassed) {
    return 'текущий счётчик больше предыдущего — доля обрезана до 100%';
  }
  if (passPctRaw === 0 && passed === 0 && prevPassed != null && prevPassed > 0) {
    return 'на этом звене «Прошло» = 0';
  }
  return null;
}

function enrichStages(rawStages, thresholds) {
  let prevPassed = null;
  let prevUnit = null;
  const enriched = rawStages.map((stage) => {
    const currUnit = STAGE_PASSED_UNIT[stage.id] ?? null;
    const lossBase = prevPassed != null && prevPassed > 0
      ? prevPassed
      : (stage.passed > 0 ? stage.passed : 0);
    const lossPct = lossBase > 0 ? (stage.lost / lossBase) * 100 : 0;
    const passPctRaw = prevPassed != null && prevPassed > 0 && stage.passed > 0
      ? (stage.passed / prevPassed) * 100
      : (prevPassed == null ? 100 : 0);

    const out = {
      ...stage,
      passedUnit: currUnit,
      lossPct: Number(lossPct.toFixed(6)),
      passPct: Number(Math.min(100, passPctRaw).toFixed(4)),
      passPctRaw: Number(passPctRaw.toFixed(4)),
      passPctLabel: prevPassed == null ? null : 'от предыдущего звена',
      passPctNote: prevPassed == null
        ? null
        : buildPassPctNote(prevUnit, currUnit, prevPassed, stage.passed, passPctRaw),
      severity: classifyStage(stage.id, { ...stage, lossPct }, thresholds),
    };

    if (!stage.isExclusion) {
      if (stage.id === 'socket') {
        // только потери; база для следующего звена не меняется
      } else if (stage.passed > 0) {
        prevPassed = Math.max(0, stage.passed - stage.lost);
        prevUnit = currUnit;
      } else if (prevPassed == null) {
        prevPassed = stage.passed;
        prevUnit = currUnit;
      }
    }

    return out;
  });

  let rootCauseStageId = null;
  for (const stage of enriched) {
    if (stage.isExclusion) continue;
    if (stage.severity === 'warning' || stage.severity === 'critical') {
      rootCauseStageId = stage.id;
      break;
    }
  }

  return enriched.map((stage) => ({
    ...stage,
    isRootCause: stage.id === rootCauseStageId,
  }));
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
    windowFrom: row.window_from ?? null,
    windowTo: row.window_to ?? null,
    lastSnapshotAt: row.last_snapshot_at ?? null,
  };
}

const DELTA_COLUMNS_SQL = `
  greatest(max(phy_rx_packets) - min(phy_rx_packets), 0) AS phy_rx_packets_delta,
  greatest(max(phy_rx_discards) - min(phy_rx_discards), 0) AS phy_rx_discards_delta,
  greatest(max(xdp_total_packets) - min(xdp_total_packets), 0) AS xdp_total_packets_delta,
  greatest(max(xdp_map_full) - min(xdp_map_full), 0) AS xdp_map_full_delta,
  greatest(max(xdp_parse_errors) - min(xdp_parse_errors), 0) AS xdp_parse_errors_delta,
  greatest(max(datagrams) - min(datagrams), 0) AS datagrams_delta,
  greatest(max(records_parsed) - min(records_parsed), 0) AS records_parsed_delta,
  greatest(max(udp_queue_drops) - min(udp_queue_drops), 0) AS udp_queue_drops_delta,
  greatest(max(receiver_parse_errors) - min(receiver_parse_errors), 0) AS receiver_parse_errors_delta,
  greatest(max(flow_packets_excluded) - min(flow_packets_excluded), 0) AS flow_packets_excluded_delta,
  greatest(max(records_spooled) - min(records_spooled), 0) AS records_spooled_delta,
  greatest(max(spool_corruption_frames) - min(spool_corruption_frames), 0) AS spool_corruption_frames_delta,
  greatest(max(flow_packets_acked) - min(flow_packets_acked), 0) AS flow_packets_acked_delta,
  greatest(max(insert_errs) - min(insert_errs), 0) AS insert_errs_delta,
  greatest(max(ch_queue_drops) - min(ch_queue_drops), 0) AS ch_queue_drops_delta,
  greatest(max(nf_packets_out) - min(nf_packets_out), 0) AS nf_packets_out_delta,
  greatest(max(nf_send_errs) - min(nf_send_errs), 0) AS nf_send_errs_delta,
  greatest(max(nf_socket_drops) - min(nf_socket_drops), 0) AS nf_socket_drops_delta
`;

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
  max(ts) AS last_snapshot_at,
  count() AS snapshot_count,
  min(ts) AS window_from,
  max(ts) AS window_to
`;

function bucketSecondsForWindow(windowKey) {
  if (windowKey === '15m') return 15;
  if (windowKey === '24h') return 900;
  return 60;
}

async function fetchSnapshotRow(sourceId, windowMinutes) {
  const table = collectorHealthSnapshotsTableRef();
  const windowPlusLag = windowMinutes + LAG_MINUTES;

  const { rows, elapsedMs } = await query(
    `
      SELECT
        source_id,
        ${META_COLUMNS_SQL},
        ${DELTA_COLUMNS_SQL}
      FROM ${table}
      WHERE source_id = {source_id:String}
        AND ts >= now64(3) - INTERVAL {window_plus_lag:UInt32} MINUTE
        AND ts <  now64(3) - INTERVAL {lag_minutes:UInt32} MINUTE
      GROUP BY source_id
    `,
    {
      source_id: sourceId,
      window_plus_lag: windowPlusLag,
      lag_minutes: LAG_MINUTES,
    },
    { name: 'collectors/pipeline' },
  );

  return { row: rows[0] || null, elapsedMs };
}

async function fetchCollectorPipeline(sourceIdRaw, windowRaw) {
  const sourceId = parseSourceId(sourceIdRaw);
  const { key: window, minutes: windowMinutes } = parseWindow(windowRaw);
  const thresholds = await loadPipelineThresholds();

  const { row, elapsedMs } = await fetchSnapshotRow(sourceId, windowMinutes);

  if (!row || num(row.snapshot_count) < 2) {
    return {
      sourceId,
      window,
      windowMinutes,
      lagMinutes: LAG_MINUTES,
      stages: [],
      rootCauseStageId: null,
      meta: row ? mapMeta(row) : null,
      insufficientData: true,
      metaResponse: { elapsedMs, enabled: true },
    };
  }

  const meta = mapMeta(row);
  const counters = buildRawCounters(row);
  const rawStages = buildPipelineStages(row, meta, counters);
  const stages = enrichStages(rawStages, thresholds);

  const rootCauseStageId = stages.find((s) => s.isRootCause)?.id ?? null;

  return {
    sourceId,
    window,
    windowMinutes,
    lagMinutes: LAG_MINUTES,
    stages,
    rootCauseStageId,
    meta,
    insufficientData: false,
    metaResponse: { elapsedMs, enabled: true, thresholds },
  };
}

async function fetchCollectorPipelineHistory(sourceIdRaw, windowRaw) {
  const sourceId = parseSourceId(sourceIdRaw);
  const { key: window, minutes: windowMinutes } = parseWindow(windowRaw);
  const bucketSec = bucketSecondsForWindow(window);
  const table = collectorHealthSnapshotsTableRef();
  const windowPlusLag = windowMinutes + LAG_MINUTES;

  const { rows, elapsedMs } = await query(
    `
      SELECT
        toStartOfInterval(ts, INTERVAL {bucket_sec:UInt32} SECOND) AS bucket_ts,
        ${DELTA_COLUMNS_SQL},
        argMax(phy_counter_source, ts) AS phy_counter_source,
        argMax(nf_socket_observed, ts) AS nf_socket_observed,
        argMax(pipeline_stages, ts) AS pipeline_stages,
        count() AS snapshot_count
      FROM ${table}
      WHERE source_id = {source_id:String}
        AND ts >= now64(3) - INTERVAL {window_plus_lag:UInt32} MINUTE
        AND ts <  now64(3) - INTERVAL {lag_minutes:UInt32} MINUTE
      GROUP BY bucket_ts
      ORDER BY bucket_ts
    `,
    {
      source_id: sourceId,
      window_plus_lag: windowPlusLag,
      lag_minutes: LAG_MINUTES,
      bucket_sec: bucketSec,
    },
    { name: 'collectors/pipeline/history' },
  );

  const thresholds = await loadPipelineThresholds();
  const buckets = rows
    .filter((row) => num(row.snapshot_count) >= 2)
    .map((row) => {
      const meta = {
        pipelineStages: parsePipelineStages(row.pipeline_stages),
        phyCounterSource: String(row.phy_counter_source ?? ''),
        nfSocketObserved: num(row.nf_socket_observed),
      };
      const counters = buildRawCounters(row);
      const rawStages = buildPipelineStages(row, meta, counters);
      const stages = enrichStages(rawStages, thresholds);
      const stageLoss = {};
      for (const s of stages) {
        if (!s.isExclusion) stageLoss[s.id] = s.lossPct;
      }
      return {
        ts: row.bucket_ts,
        stages: stageLoss,
      };
    });

  return {
    sourceId,
    window,
    windowMinutes,
    bucketSeconds: bucketSec,
    buckets,
    meta: { elapsedMs, enabled: true },
  };
}

function buildPipelineFromCounters(meta, counters, thresholds = DEFAULT_THRESHOLDS) {
  const rawStages = buildPipelineStages({}, meta, counters);
  return enrichStages(rawStages, thresholds);
}

module.exports = {
  WINDOW_MINUTES,
  LAG_MINUTES,
  STAGE_LABELS,
  STAGE_PASSED_UNIT,
  buildPassPctNote,
  parseWindow,
  parseSourceId,
  parsePipelineStages,
  buildRawCounters,
  buildPipelineStages,
  enrichStages,
  classifyStage,
  buildPipelineFromCounters,
  fetchCollectorPipeline,
  fetchCollectorPipelineHistory,
};
