'use strict';

const EXPLORER_THRESHOLD_METRICS = new Set([
  'bps', 'volume', 'pps', 'fps', 'flows', 'uniq_src',
  'avg_packet_size', 'avg_flow_size', 'pct',
]);

const EXPLORER_THRESHOLD_PEAK_METRICS = new Set([
  'bps', 'volume', 'pps', 'fps', 'flows',
]);

const EXPLORER_THRESHOLD_OPS = new Set([
  'gt', 'gte', 'lt', 'lte', 'between', 'outside',
]);

const EXPLORER_THRESHOLD_AGGREGATES = new Set(['avg', 'peak']);

const EXPLORER_PEAK_WINDOWS = {
  '1m': 60,
  '5m': 300,
  '1h': 3600,
};

const EXPLORER_THRESHOLD_UNITS = {
  bps: ['bps', 'kbps', 'mbps', 'gbps'],
  volume: ['b', 'kb', 'mb', 'gb', 'tb'],
  pps: ['pps', 'kpps', 'mpps'],
  fps: ['fps'],
  flows: ['count'],
  uniq_src: ['count'],
  avg_packet_size: ['b'],
  avg_flow_size: ['b'],
  pct: ['pct'],
};

const EXPLORER_THRESHOLD_DEFAULT_UNIT = {
  bps: 'mbps',
  volume: 'gb',
  pps: 'pps',
  fps: 'fps',
  flows: 'count',
  uniq_src: 'count',
  avg_packet_size: 'b',
  avg_flow_size: 'b',
  pct: 'pct',
};

const EXPLORER_THRESHOLD_METRIC_META = [
  { id: 'bps', label: 'Средняя бит/с', peakSupported: true, defaultUnit: 'mbps' },
  { id: 'volume', label: 'Объём', peakSupported: true, defaultUnit: 'gb' },
  { id: 'pps', label: 'Пакеты/с', peakSupported: true, defaultUnit: 'pps' },
  { id: 'fps', label: 'Потоки/с', peakSupported: true, defaultUnit: 'fps' },
  { id: 'flows', label: 'Всего потоков', peakSupported: true, defaultUnit: 'count' },
  { id: 'uniq_src', label: 'Уникальных source IP', peakSupported: false, defaultUnit: 'count' },
  { id: 'avg_packet_size', label: 'Средний размер пакета', peakSupported: false, defaultUnit: 'b' },
  { id: 'avg_flow_size', label: 'Средний размер потока', peakSupported: false, defaultUnit: 'b' },
  { id: 'pct', label: 'Доля от общего', peakSupported: false, defaultUnit: 'pct' },
];

const EXPLORER_THRESHOLD_OP_LABELS = {
  gt: 'больше',
  gte: 'больше или равно',
  lt: 'меньше',
  lte: 'меньше или равно',
  between: 'между',
  outside: 'вне диапазона',
};

function thresholdMetricSupportsPeak(metric) {
  return EXPLORER_THRESHOLD_PEAK_METRICS.has(String(metric || '').trim());
}

function normalizePeakWindow(raw, fallbackSeconds = 300) {
  const key = String(raw || '').trim();
  if (EXPLORER_PEAK_WINDOWS[key]) return key;
  const fallback = Object.entries(EXPLORER_PEAK_WINDOWS)
    .find(([, sec]) => sec === fallbackSeconds);
  return fallback ? fallback[0] : '5m';
}

function peakWindowSeconds(key) {
  return EXPLORER_PEAK_WINDOWS[key] || 300;
}

function parseThresholdNumber(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function normalizeExplorerThreshold(raw, { defaultPeakWindow = '5m' } = {}) {
  if (!raw || typeof raw !== 'object') return null;
  const metric = String(raw.metric || '').trim();
  if (!EXPLORER_THRESHOLD_METRICS.has(metric)) return null;
  const op = String(raw.op || 'gt').trim().toLowerCase();
  if (!EXPLORER_THRESHOLD_OPS.has(op)) return null;

  let aggregate = String(raw.aggregate || 'avg').trim().toLowerCase();
  if (!EXPLORER_THRESHOLD_AGGREGATES.has(aggregate)) aggregate = 'avg';
  if (aggregate === 'peak' && !thresholdMetricSupportsPeak(metric)) aggregate = 'avg';

  const value = parseThresholdNumber(raw.value);
  if (value == null) return null;

  let value2 = raw.value2 != null && raw.value2 !== '' ? parseThresholdNumber(raw.value2) : null;
  if (op === 'between' || op === 'outside') {
    if (value2 == null) return null;
    if (value > value2) {
      return normalizeExplorerThreshold({
        ...raw,
        value: value2,
        value2: value,
      }, { defaultPeakWindow });
    }
  } else {
    value2 = null;
  }

  const unitRaw = String(raw.unit || EXPLORER_THRESHOLD_DEFAULT_UNIT[metric] || 'count').trim().toLowerCase();
  const allowedUnits = EXPLORER_THRESHOLD_UNITS[metric] || ['count'];
  const unit = allowedUnits.includes(unitRaw) ? unitRaw : EXPLORER_THRESHOLD_DEFAULT_UNIT[metric];

  let peakWindow = null;
  if (aggregate === 'peak') {
    peakWindow = normalizePeakWindow(raw.peakWindow, peakWindowSeconds(defaultPeakWindow));
  }

  return {
    metric,
    aggregate,
    peakWindow,
    op,
    value,
    value2,
    unit,
  };
}

function normalizeExplorerThresholds(rawList, options = {}) {
  if (!Array.isArray(rawList)) return [];
  const out = [];
  for (const item of rawList) {
    const norm = normalizeExplorerThreshold(item, options);
    if (norm) out.push(norm);
  }
  return out;
}

function explorerThresholdsNeedPeak(thresholds) {
  return (thresholds || []).some((t) => t.aggregate === 'peak');
}

function explorerThresholdsActive(thresholds) {
  return Array.isArray(thresholds) && thresholds.length > 0;
}

function thresholdCompareSql(columnExpr, op, paramBase, params) {
  switch (op) {
    case 'gt':
      params[`${paramBase}_v0`] = params[`${paramBase}_v0`];
      return `${columnExpr} > {${paramBase}_v0:Float64}`;
    case 'gte':
      return `${columnExpr} >= {${paramBase}_v0:Float64}`;
    case 'lt':
      return `${columnExpr} < {${paramBase}_v0:Float64}`;
    case 'lte':
      return `${columnExpr} <= {${paramBase}_v0:Float64}`;
    case 'between':
      return `${columnExpr} >= {${paramBase}_v0:Float64} AND ${columnExpr} <= {${paramBase}_v1:Float64}`;
    case 'outside':
      return `(${columnExpr} < {${paramBase}_v0:Float64} OR ${columnExpr} > {${paramBase}_v1:Float64})`;
    default:
      return '1';
  }
}

/** SQL column on aggregated row for threshold comparison (avg path). */
function thresholdAvgColumnSql(metric) {
  switch (metric) {
    case 'bps': return 'avg_bps';
    case 'volume': return 'bytes';
    case 'pps': return 'avg_pps';
    case 'fps': return 'avg_fps';
    case 'flows': return 'flows';
    case 'uniq_src': return 'uniq_src_count';
    case 'avg_packet_size': return 'avg_packet_size';
    case 'avg_flow_size': return 'avg_flow_size';
    case 'pct': return 'pct';
    default: return 'metric_value';
  }
}

/** SQL column on aggregated row for peak threshold comparison. */
function thresholdPeakColumnSql(metric) {
  switch (metric) {
    case 'bps': return 'peak_bps';
    case 'volume': return 'peak_bytes';
    case 'pps': return 'peak_pps';
    case 'fps': return 'peak_fps';
    case 'flows': return 'peak_flows';
    default: return thresholdAvgColumnSql(metric);
  }
}

function thresholdColumnSql(threshold) {
  return threshold.aggregate === 'peak'
    ? thresholdPeakColumnSql(threshold.metric)
    : thresholdAvgColumnSql(threshold.metric);
}

function buildThresholdWhereParts(thresholds, params, idxRef) {
  const parts = [];
  for (const t of thresholds) {
    const paramBase = `thr_${idxRef.i++}`;
    params[`${paramBase}_v0`] = t.value;
    if (t.value2 != null) params[`${paramBase}_v1`] = t.value2;
    const col = `t.${thresholdColumnSql(t)}`;
    parts.push(thresholdCompareSql(col, t.op, paramBase, params));
  }
  return parts;
}

function buildThresholdStatsExpr(thresholds, idxRefSeed = 0) {
  const idxRef = { i: idxRefSeed };
  const params = {};
  const parts = buildThresholdWhereParts(thresholds, params, idxRef);
  if (!parts.length) return { statsExpr: '1', params, whereSql: '1' };
  const whereSql = parts.join(' AND ');
  return {
    statsExpr: whereSql.replace(/\bt\./g, ''),
    whereSql,
    params,
  };
}

function wrapSqlWithThresholdFilter({
  innerSql,
  thresholds,
  orderBy = 'metric_value DESC',
  limitParam = '{limit:UInt32}',
  offsetParam = '{offset:UInt32}',
}) {
  if (!explorerThresholdsActive(thresholds)) {
    return {
      sql: `${innerSql}\nORDER BY ${orderBy}\nLIMIT ${limitParam} OFFSET ${offsetParam}`,
      thresholdParams: {},
      hasThresholdWrap: false,
    };
  }

  const idxRef = { i: 0 };
  const thresholdParams = {};
  const whereParts = buildThresholdWhereParts(thresholds, thresholdParams, idxRef);
  const whereSql = whereParts.join(' AND ');
  const statsParts = buildThresholdWhereParts(thresholds, { ...thresholdParams }, { i: 0 });
  const statsExpr = statsParts.join(' AND ').replace(/\bt\./g, '');

  const sql = `
    WITH aggregated AS (
      ${innerSql}
    ),
    stats AS (
      SELECT
        count() AS rows_before_threshold,
        countIf(${statsExpr || '1'}) AS rows_after_threshold
      FROM aggregated
    )
    SELECT
      t.*,
      s.rows_before_threshold,
      s.rows_before_threshold - s.rows_after_threshold AS rows_hidden
    FROM aggregated AS t
    CROSS JOIN stats AS s
    WHERE ${whereSql}
    ORDER BY ${orderBy}
    LIMIT ${limitParam} OFFSET ${offsetParam}
  `;

  return { sql, thresholdParams, hasThresholdWrap: true };
}

/** Extra SELECT columns for threshold metrics on avg aggregated rows. */
function thresholdExtraSelectColumns(scaled, windowSecondsExpr = 'window_seconds') {
  return `
    round(sum(${scaled.packets}) / ${windowSecondsExpr}, 0) AS avg_pps,
    round(sum(${scaled.flowWeight}) / ${windowSecondsExpr}, 2) AS avg_fps,
    round(sum(${scaled.bytes}) / nullIf(sum(${scaled.packets}), 0), 2) AS avg_packet_size,
    round(sum(${scaled.bytes}) / nullIf(sum(${scaled.flowWeight}), 0), 2) AS avg_flow_size`;
}

/** Extra peak columns after bucket aggregation. */
function thresholdPeakExtraSelectColumns() {
  return `
    max(bucket_bps) AS peak_bps,
    max(bucket_bytes) AS peak_bytes,
    max(bucket_pps) AS peak_pps,
    max(bucket_fps) AS peak_fps,
    max(bucket_flows) AS peak_flows`;
}

function peakBucketMetricExprs(scaled, peakWindowSec) {
  return `
    sum(${scaled.bytes}) AS bucket_bytes,
    sum(${scaled.packets}) AS bucket_packets,
    sum(${scaled.flowWeight}) AS bucket_flows,
    round(sum(${scaled.bytes}) * 8 / ${peakWindowSec}, 0) AS bucket_bps,
    round(sum(${scaled.packets}) / ${peakWindowSec}, 0) AS bucket_pps,
    round(sum(${scaled.flowWeight}) / ${peakWindowSec}, 2) AS bucket_fps`;
}

function explorerThresholdWarning({ thresholds, groupBy, windowSeconds }) {
  if (!explorerThresholdsNeedPeak(thresholds)) return null;
  const groups = Array.isArray(groupBy) ? groupBy : [];
  const ipPair = groups.includes('src_ip') || groups.includes('dst_ip')
    || (groups.includes('src_ip') && groups.includes('dst_ip'));
  if (!ipPair) return null;
  if (windowSeconds <= 86400) return null;
  return 'Режим пика при группировке по IP на длинном периоде может выполняться долго. Попробуйте увеличить окно пика (например, 1 час).';
}

function explorerThresholdSchemaExtras() {
  return {
    thresholdMetrics: EXPLORER_THRESHOLD_METRIC_META,
    thresholdOps: Object.entries(EXPLORER_THRESHOLD_OP_LABELS).map(([id, label]) => ({ id, label })),
    thresholdPeakWindows: Object.entries(EXPLORER_PEAK_WINDOWS).map(([id, seconds]) => ({
      id,
      label: id === '1m' ? 'за 1 мин' : id === '5m' ? 'за 5 мин' : 'за 1 час',
      seconds,
    })),
    thresholdUnits: EXPLORER_THRESHOLD_UNITS,
  };
}

function describeThresholdForReport(t) {
  const meta = EXPLORER_THRESHOLD_METRIC_META.find((m) => m.id === t.metric);
  const label = meta?.label || t.metric;
  const opLabel = EXPLORER_THRESHOLD_OP_LABELS[t.op] || t.op;
  const agg = t.aggregate === 'peak'
    ? `пик ${t.peakWindow === '1h' ? '1 час' : t.peakWindow === '1m' ? '1 мин' : '5 мин'}`
    : 'средняя';
  const val = t.value;
  const val2 = t.value2;
  if (t.op === 'between' || t.op === 'outside') {
    return `${agg} ${label} ${opLabel} ${val}–${val2}`;
  }
  return `${agg} ${label} ${opLabel} ${val}`;
}

function describeThresholds(thresholds) {
  const list = normalizeExplorerThresholds(thresholds);
  if (!list.length) return '';
  return list.map(describeThresholdForReport).join(' · ');
}

function serializeObservationFiltersEnvelope(filters, thresholds) {
  const filterList = Array.isArray(filters) ? filters : [];
  const thr = normalizeExplorerThresholds(thresholds);
  if (!thr.length) return filterList;
  return { filters: filterList, thresholds: thr };
}

function parseObservationFiltersEnvelope(raw) {
  if (Array.isArray(raw)) {
    return { filters: raw, thresholds: [] };
  }
  if (raw && typeof raw === 'object') {
    return {
      filters: Array.isArray(raw.filters) ? raw.filters : [],
      thresholds: normalizeExplorerThresholds(raw.thresholds),
    };
  }
  return { filters: [], thresholds: [] };
}

module.exports = {
  EXPLORER_THRESHOLD_METRICS,
  EXPLORER_THRESHOLD_PEAK_METRICS,
  EXPLORER_THRESHOLD_OPS,
  EXPLORER_THRESHOLD_METRIC_META,
  EXPLORER_THRESHOLD_OP_LABELS,
  EXPLORER_PEAK_WINDOWS,
  EXPLORER_THRESHOLD_DEFAULT_UNIT,
  thresholdMetricSupportsPeak,
  normalizePeakWindow,
  peakWindowSeconds,
  normalizeExplorerThreshold,
  normalizeExplorerThresholds,
  explorerThresholdsNeedPeak,
  explorerThresholdsActive,
  thresholdAvgColumnSql,
  thresholdPeakColumnSql,
  thresholdColumnSql,
  buildThresholdWhereParts,
  buildThresholdStatsExpr,
  wrapSqlWithThresholdFilter,
  thresholdExtraSelectColumns,
  thresholdPeakExtraSelectColumns,
  peakBucketMetricExprs,
  explorerThresholdWarning,
  explorerThresholdSchemaExtras,
  describeThresholds,
  serializeObservationFiltersEnvelope,
  parseObservationFiltersEnvelope,
};
