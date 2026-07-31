'use strict';

const EXPLORER_THRESHOLD_OPS = [
  { id: 'gt', label: 'больше' },
  { id: 'gte', label: 'больше или равно' },
  { id: 'lt', label: 'меньше' },
  { id: 'lte', label: 'меньше или равно' },
  { id: 'between', label: 'между' },
  { id: 'outside', label: 'вне диапазона' },
];

const EXPLORER_THRESHOLD_PEAK_WINDOWS = [
  { id: '1m', label: 'за 1 мин' },
  { id: '5m', label: 'за 5 мин' },
  { id: '1h', label: 'за 1 час' },
];

const EXPLORER_THRESHOLD_DEFAULT_METRICS = [
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

const UNIT_MULTIPLIERS = {
  bps: { bps: 1, kbps: 1000, mbps: 1e6, gbps: 1e9 },
  volume: { b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3, tb: 1024 ** 4 },
  pps: { pps: 1, kpps: 1000, mpps: 1e6 },
  fps: { fps: 1 },
  flows: { count: 1 },
  uniq_src: { count: 1 },
  avg_packet_size: { b: 1 },
  avg_flow_size: { b: 1 },
  pct: { pct: 1 },
};

const UNIT_LABELS = {
  bps: { bps: 'бит/с', kbps: 'Кбит/с', mbps: 'Мбит/с', gbps: 'Гбит/с' },
  volume: { b: 'Б', kb: 'КБ', mb: 'МБ', gb: 'ГБ', tb: 'ТБ' },
  pps: { pps: 'пакет/с', kpps: 'тыс./с', mpps: 'млн/с' },
  fps: { fps: 'поток/с' },
  flows: { count: 'шт.' },
  uniq_src: { count: 'шт.' },
  avg_packet_size: { b: 'байт' },
  avg_flow_size: { b: 'байт' },
  pct: { pct: '%' },
};

function thresholdMetricsFromSchema(schema) {
  if (Array.isArray(schema?.thresholdMetrics) && schema.thresholdMetrics.length) {
    return schema.thresholdMetrics;
  }
  return EXPLORER_THRESHOLD_DEFAULT_METRICS;
}

function thresholdUnitsForMetric(metric) {
  return Object.keys(UNIT_MULTIPLIERS[metric] || { count: 1 });
}

function defaultThresholdUnit(metric, schemaMetrics) {
  const meta = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics })
    .find((m) => m.id === metric);
  return meta?.defaultUnit || 'count';
}

function parseThresholdUiNumber(value) {
  const s = String(value ?? '').trim().replace(',', '.');
  if (!s) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function uiToBaseThresholdValue(value, unit, metric) {
  const n = parseThresholdUiNumber(value);
  if (n == null) return null;
  const mult = (UNIT_MULTIPLIERS[metric] || {})[unit] || 1;
  if (metric === 'pct') return n;
  return n * mult;
}

function baseToUiThresholdValue(baseValue, unit, metric) {
  const n = Number(baseValue);
  if (!Number.isFinite(n)) return '';
  const mult = (UNIT_MULTIPLIERS[metric] || {})[unit] || 1;
  if (metric === 'pct') return String(n);
  const v = n / mult;
  const digits = v < 10 ? 2 : v < 100 ? 1 : 0;
  return String(Number(v.toFixed(digits)));
}

function normalizeExplorerThresholdDraft(row, schemaMetrics) {
  if (!row || typeof row !== 'object') return null;
  const metric = String(row.metric || 'bps').trim();
  const unit = String(row.unit || defaultThresholdUnit(metric, schemaMetrics)).trim();
  const valueBase = uiToBaseThresholdValue(row.value, unit, metric);
  if (valueBase == null) return null;
  let value2Base = null;
  const op = String(row.op || 'gt').trim();
  if (op === 'between' || op === 'outside') {
    value2Base = uiToBaseThresholdValue(row.value2, unit, metric);
    if (value2Base == null) return null;
  }
  let aggregate = String(row.aggregate || 'avg').trim();
  const meta = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics }).find((m) => m.id === metric);
  if (aggregate === 'peak' && !meta?.peakSupported) aggregate = 'avg';
  const payload = {
    metric,
    aggregate,
    op,
    value: valueBase,
    value2: value2Base,
    unit,
  };
  if (aggregate === 'peak') {
    payload.peakWindow = row.peakWindow || '5m';
  }
  return payload;
}

function validateExplorerThresholdDrafts(rows, schemaMetrics) {
  const validThresholds = [];
  const inactiveIds = new Set();
  (rows || []).forEach((row) => {
    const norm = normalizeExplorerThresholdDraft(row, schemaMetrics);
    if (norm) validThresholds.push(norm);
    else if (String(row.value ?? '').trim()) inactiveIds.add(row.id);
  });
  return { validThresholds, inactiveIds };
}

function cloneExplorerThresholds(rows) {
  return (rows || []).map((r, i) => ({
    id: r.id ?? `thr-${i}-${Date.now()}`,
    metric: r.metric || 'bps',
    aggregate: r.aggregate || 'avg',
    peakWindow: r.peakWindow || '5m',
    op: r.op || 'gt',
    value: r.value ?? '',
    value2: r.value2 ?? '',
    unit: r.unit || defaultThresholdUnit(r.metric),
  }));
}

function thresholdDraftFromApi(t, schemaMetrics) {
  const unit = t.unit || defaultThresholdUnit(t.metric, schemaMetrics);
  return {
    id: `thr-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    metric: t.metric,
    aggregate: t.aggregate || 'avg',
    peakWindow: t.peakWindow || '5m',
    op: t.op || 'gt',
    value: baseToUiThresholdValue(t.value, unit, t.metric),
    value2: t.value2 != null ? baseToUiThresholdValue(t.value2, unit, t.metric) : '',
    unit,
  };
}

function formatThresholdChipLabel(t, schemaMetrics) {
  const meta = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics }).find((m) => m.id === t.metric);
  const unit = t.unit || defaultThresholdUnit(t.metric, schemaMetrics);
  const unitLabel = (UNIT_LABELS[t.metric] || {})[unit] || unit;
  const opMeta = EXPLORER_THRESHOLD_OPS.find((o) => o.id === t.op);
  const opLabel = opMeta?.label || t.op;
  const val = baseToUiThresholdValue(t.value, unit, t.metric);
  const val2 = t.value2 != null ? baseToUiThresholdValue(t.value2, unit, t.metric) : null;
  const aggPrefix = t.aggregate === 'peak'
    ? `пик ${t.peakWindow === '1h' ? '1 час' : t.peakWindow === '1m' ? '1 мин' : '5 мин'}`
    : null;
  const metricLabel = meta?.label || t.metric;
  if (t.op === 'between' || t.op === 'outside') {
    return `${aggPrefix ? `${aggPrefix} ` : ''}${metricLabel} ${opLabel} ${val}–${val2} ${unitLabel}`.trim();
  }
  return `${aggPrefix ? `${aggPrefix} ` : ''}${metricLabel} ${opLabel} ${val} ${unitLabel}`.trim();
}

function shouldShowThresholdPeakWarning({ thresholds, groupBy, timeRange, customPeriod }) {
  const peak = (thresholds || []).some((t) => t.aggregate === 'peak');
  if (!peak) return false;
  const groups = groupBy || [];
  const ipHeavy = groups.includes('src_ip') || groups.includes('dst_ip')
    || (groups.includes('src_ip') && groups.includes('dst_ip'));
  if (!ipHeavy) return false;
  let windowSec = 3600;
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    windowSec = (new Date(customPeriod.to) - new Date(customPeriod.from)) / 1000;
  } else {
    const map = { '30m': 1800, '1h': 3600, '3h': 10800, '6h': 21600, '12h': 43200, '24h': 86400, '2d': 172800, '7d': 604800, '14d': 1209600 };
    windowSec = map[timeRange] || 3600;
  }
  return windowSec > 86400;
}

window.ExplorerThresholds = {
  EXPLORER_THRESHOLD_OPS,
  EXPLORER_THRESHOLD_PEAK_WINDOWS,
  EXPLORER_THRESHOLD_DEFAULT_METRICS,
  thresholdMetricsFromSchema,
  thresholdUnitsForMetric,
  defaultThresholdUnit,
  parseThresholdUiNumber,
  uiToBaseThresholdValue,
  baseToUiThresholdValue,
  normalizeExplorerThresholdDraft,
  validateExplorerThresholdDrafts,
  cloneExplorerThresholds,
  thresholdDraftFromApi,
  formatThresholdChipLabel,
  shouldShowThresholdPeakWarning,
  UNIT_LABELS,
};
