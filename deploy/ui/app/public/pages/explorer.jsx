/* Historical Explorer Flows — расследование flow-событий через явные фильтры */

const DEFAULT_EXPLORER_PRESETS = [
  {
    id: 'udp-talkers',
    name: 'UDP src → dst',
    metric: 'pps',
    groupBy: ['src_ip', 'dst_ip'],
    filters: [{ id: 1, field: 'proto', op: '=', value: 'UDP' }],
    limit: 10,
    vis: 'stack',
  },
  {
    id: 'dns-candidates',
    name: 'DNS dst/53',
    metric: 'pps',
    groupBy: ['src_ip', 'dst_ip'],
    filters: [
      { id: 1, field: 'proto', op: '=', value: 'UDP' },
      { id: 2, field: 'dst_port', op: '=', value: '53' },
    ],
    limit: 25,
    vis: 'stack',
  },
  {
    id: 'top-dst-asn',
    name: 'Top destination ASN',
    metric: 'bps',
    groupBy: ['dst_asn'],
    filters: [],
    limit: 25,
    vis: 'stack',
  },
];

const EXPLORER_DEFAULT_VISUAL_LIMIT = 5;
/** Rollup наблюдений хранит четыре измерения разреза (dim0…dim3). */
const OBSERVATION_MAX_GROUP_BY = 4;
const EXPLORER_DEFAULT_FETCH_LIMIT = 25;
const EXPLORER_ON_DEMAND_FETCH_LIMITS = [50, 100];
const EXPLORER_CHART_HEIGHT = 196;
const EXPLORER_VIS_DEFAULT = 'stack';
const EXPLORER_MASKABLE_GROUPS = new Set(['src_ip', 'dst_ip']);
const EXPLORER_GROUP_MASK_DEFAULT = 32;

function parseExplorerGroupToken(token) {
  const raw = String(token ?? '').trim();
  const slash = raw.indexOf('/');
  const candidateId = slash < 0 ? raw : raw.slice(0, slash);
  if (!EXPLORER_MASKABLE_GROUPS.has(candidateId)) return { id: raw, mask: null };
  const value = slash < 0 ? EXPLORER_GROUP_MASK_DEFAULT : Number(raw.slice(slash + 1).trim());
  const mask = Number.isInteger(value) && value >= 1 && value <= 32
    ? value
    : EXPLORER_GROUP_MASK_DEFAULT;
  return { id: candidateId, mask };
}

function explorerGroupFieldId(token) {
  return parseExplorerGroupToken(token).id;
}

function explorerGroupMask(token) {
  return parseExplorerGroupToken(token).mask;
}

function formatExplorerGroupToken(id, mask) {
  const fieldId = String(id ?? '').trim();
  if (!EXPLORER_MASKABLE_GROUPS.has(fieldId)) return fieldId;
  const value = Number(String(mask ?? '').trim());
  const normalized = Number.isInteger(value) && value >= 1 && value <= 32
    ? value
    : EXPLORER_GROUP_MASK_DEFAULT;
  return normalized === EXPLORER_GROUP_MASK_DEFAULT ? fieldId : `${fieldId}/${normalized}`;
}

function normalizeExplorerGroupTokens(list) {
  const result = [];
  const seen = new Set();
  for (const token of Array.isArray(list) ? list : []) {
    const { id, mask } = parseExplorerGroupToken(token);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    result.push(formatExplorerGroupToken(id, mask));
  }
  return result;
}

function explorerGroupLabel(token, dimensionById) {
  const { id, mask } = parseExplorerGroupToken(token);
  const label = dimensionById[id]?.label || id;
  return mask != null && mask !== EXPLORER_GROUP_MASK_DEFAULT ? `${label} /${mask}` : label;
}

const VIS_TYPES = [
  { id: 'stack', label: 'Стек (сумма)', icon: 'layers', hint: 'Площади друг на друге, верхняя кромка = сумма выбранных серий' },
  { id: 'stackShare', label: 'Стек (доли)', icon: 'stackShare', hint: 'Тот же стек, нормализован к 100%' },
  { id: 'data', label: 'Данные', icon: 'menu', hint: 'График динамики и детальная таблица' },
];

const EXPLORER_DYNAMICS_VIS = new Set(['data', 'stack', 'stackShare']);

function isExplorerDynamicsVis(vis) {
  return EXPLORER_DYNAMICS_VIS.has(normalizeExplorerVis(vis));
}

function explorerVisToStackMode(vis) {
  const id = normalizeExplorerVis(vis);
  if (id === 'stack') return 'sum';
  if (id === 'stackShare') return 'share';
  return undefined;
}

function isExplorerStackVis(vis) {
  const id = normalizeExplorerVis(vis);
  return id === 'stack' || id === 'stackShare';
}

function explorerDefaultShowOthersOnChart(vis) {
  return isExplorerStackVis(vis);
}

const EXPLORER_VIS_LEGACY_MAP = {
  lines: 'data',
  dynamics: 'data',
  table: 'data',
  contribution: 'stack',
  donut: 'stack',
  bars: 'stack',
  sankey: 'stack',
  relations: 'stack',
};

function normalizeExplorerVis(vis) {
  const id = String(vis || '').trim();
  if (EXPLORER_VIS_LEGACY_MAP[id]) return EXPLORER_VIS_LEGACY_MAP[id];
  if (VIS_TYPES.some((v) => v.id === id)) return id;
  return EXPLORER_VIS_DEFAULT;
}

function resolveExplorerVisualCount(visualLimit, total) {
  if (visualLimit === 'all') return total;
  const n = Number(visualLimit);
  if (!Number.isFinite(n) || n <= 0) return Math.min(EXPLORER_DEFAULT_VISUAL_LIMIT, total);
  return Math.min(n, total);
}

function sliceExplorerVisualRows(rows, visualLimit) {
  return rows.slice(0, resolveExplorerVisualCount(visualLimit, rows.length));
}

function defaultDynamicsSeriesIds(rows, visualLimit) {
  return new Set(sliceExplorerVisualRows(rows, visualLimit).map((r) => r.id));
}


function resolveExplorerFetchLimit(queryLimit) {
  const n = Number(queryLimit);
  if (EXPLORER_ON_DEMAND_FETCH_LIMITS.includes(n)) return n;
  return EXPLORER_DEFAULT_FETCH_LIMIT;
}

function isExplorerDisplayLimitActive(buttonLimit, visualLimit, fetchLimit) {
  if (visualLimit === 'all') return buttonLimit === fetchLimit;
  return Number(visualLimit) === buttonLimit;
}

function explorerRowLabel(row) {
  return (row?.values || []).map((val, idx) => (
    row.asnMeta?.[idx] ? explorerAsnDisplayValue(row, idx, val) : (val ?? '—')
  )).join(' → ');
}

function parseExplorerAsnNumber(value) {
  const s = String(value ?? '').trim();
  if (!s || s === '—') return null;
  const prefixed = s.match(/^AS(\d+)$/i);
  if (prefixed) return Number(prefixed[1]);
  if (/^\d+$/.test(s)) return Number(s);
  return null;
}

function explorerAsnDisplayValue(row, valueIdx, fallback) {
  const meta = row.asnMeta?.[valueIdx];
  if (meta?.asName) return `${meta.asName} (AS${meta.asn})`;
  const val = fallback ?? row.values?.[valueIdx];
  if (val && String(val).includes('(') && /AS\d+/i.test(String(val))) return val;
  const asn = meta?.asn ?? parseExplorerAsnNumber(row.rawValues?.[valueIdx] ?? val);
  if (asn === 0) return 'AS0';
  if (asn) return `AS${asn}`;
  return val ?? '—';
}

function dedupeExplorerEntityItems(items) {
  const byId = new Map();
  for (const item of items || []) {
    const id = String(item?.id ?? item?.value ?? '');
    if (!id) continue;
    const prev = byId.get(id);
    if (!prev) {
      byId.set(id, item);
      continue;
    }
    const label = String(item.label || '');
    const prevLabel = String(prev.label || '');
    if (/^AS\d+$/i.test(prevLabel) && label && !/^AS\d+$/i.test(label)) {
      byId.set(id, item);
    }
  }
  return [...byId.values()];
}

function explorerUsesCabinetClient({ filters = [], groupBy = [] } = {}) {
  if ((filters || []).some((f) => String(f?.field || '').trim() === 'cabinet_client')) return true;
  return (groupBy || []).some((token) => explorerGroupFieldId(token) === 'cabinet_client');
}

function explorerCabinetClientPeriodOptions(schema) {
  const hours = Number(schema?.maxCabinetClientRangeHours) || 6;
  return {
    recommendedRangeMs: hours * 3600000,
    rangeWarningMessage: `Фильтр по клиенту считается по сырым потокам: рекомендуется период не более ${hours} часов`,
  };
}

function explorerPeriodDurationMs(timeRange, customPeriod) {
  if (timeRange === 'custom') {
    const fromMs = new Date(customPeriod?.from).getTime();
    const toMs = new Date(customPeriod?.to).getTime();
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || toMs <= fromMs) return null;
    return toMs - fromMs;
  }
  return timeRangePresetMs(timeRange);
}

function explorerCabinetClientPeriodWarning({ usesCabinetClient, cabinetClientPeriod, timeRange, customPeriod }) {
  if (!usesCabinetClient || !cabinetClientPeriod) return null;
  const durationMs = explorerPeriodDurationMs(timeRange, customPeriod);
  if (durationMs == null || durationMs <= cabinetClientPeriod.recommendedRangeMs) return null;
  return cabinetClientPeriod.rangeWarningMessage;
}

function explorerRowFilterValue(row, dimId, valueIdx, dimensionById) {
  const fieldId = explorerGroupFieldId(dimId);
  const kind = dimensionById[fieldId]?.kind;
  if (kind === 'tcp_flags' || fieldId === 'tcp_flags') {
    const raw = row.rawValues?.[valueIdx] ?? row.values[valueIdx];
    const num = Number(raw);
    if (Number.isFinite(num) && /^\d+$/.test(String(raw).trim())) {
      const names = EXPLORER_TCP_FLAG_NAMES.filter((name) => (num & EXPLORER_TCP_FLAG_BITS[name]) !== 0);
      return {
        value: names.join(','),
        label: tcpFlagsLabelFromRaw(num),
      };
    }
    const label = row.values[valueIdx];
    return {
      value: String(raw).replace(/\s+/g, ''),
      label: label && label !== raw ? label : null,
    };
  }
  if (kind === 'asn') {
    const meta = row.asnMeta?.[valueIdx];
    return {
      value: meta?.asn ?? parseExplorerAsnNumber(row.rawValues?.[valueIdx] ?? row.values[valueIdx]),
      label: meta?.asName || null,
    };
  }
  if (fieldId === 'cabinet_client') {
    const raw = row.rawValues?.[valueIdx] ?? row.values[valueIdx];
    const label = row.values[valueIdx];
    return {
      value: raw,
      label: label && String(label) !== String(raw) ? label : null,
    };
  }
  const raw = row.rawValues?.[valueIdx] ?? row.values[valueIdx];
  return { value: raw, label: null };
}

function explorerAsnSortKey(row, valueIdx) {
  const meta = row.asnMeta?.[valueIdx];
  if (meta?.asName) return meta.asName.toLowerCase();
  if (meta?.asn != null) return meta.asn;
  return row.rawValues?.[valueIdx] ?? row.values[valueIdx] ?? '';
}

const EMPTY_EXPLORER_SUMMARY = {
  totalBytes: 0,
  totalPackets: 0,
  totalFlows: 0,
  avgBps: 0,
  uniqSrc: null,
  uniqDst: null,
  inBytes: null,
  outBytes: null,
  topProtocols: [],
};

const EXPLORER_OTHERS_ID = 'row-others';
const EXPLORER_OTHERS_LABEL = 'Прочие';
const EXPLORER_OTHERS_COLOR = '#9aa0a6';

/** uniq metrics are not additive, so a remainder cannot be derived from them. */
const EXPLORER_OTHERS_METRIC = {
  bps: (t, ws) => (ws > 0 ? Math.round((t.bytes * 8) / ws) : 0),
  volume: (t) => t.bytes,
  pps: (t, ws) => (ws > 0 ? Math.round(t.packets / ws) : 0),
  fps: (t, ws) => (ws > 0 ? Math.round((t.flows / ws) * 100) / 100 : 0),
  flows: (t) => t.flows,
};

/**
 * Everything outside the displayed rows, derived from the unsliced summary so the
 * shown shares add up to 100%.
 */
function buildExplorerOthersRow({ shownRows, summary, meta, metric, groupBy }) {
  if (!groupBy?.length || !shownRows?.length) return null;
  if (meta?.pctScope && meta.pctScope !== 'full_filtered') return null;
  const metricFn = EXPLORER_OTHERS_METRIC[metric];
  if (!metricFn) return null;

  const totalBytes = Number(summary?.totalBytes) || 0;
  if (totalBytes <= 0) return null;
  const rest = {
    bytes: totalBytes - shownRows.reduce((s, r) => s + (Number(r.bytes) || 0), 0),
    packets: (Number(summary?.totalPackets) || 0) - shownRows.reduce((s, r) => s + (Number(r.packets) || 0), 0),
    flows: (Number(summary?.totalFlows) || 0) - shownRows.reduce((s, r) => s + (Number(r.flows) || 0), 0),
  };
  if (rest.bytes <= 0 || rest.bytes / totalBytes < 0.0001) return null;
  rest.packets = Math.max(0, rest.packets);
  rest.flows = Math.max(0, rest.flows);

  const windowSeconds = Number(meta?.windowSeconds) || 0;
  const values = groupBy.map((_, i) => (i === 0 ? EXPLORER_OTHERS_LABEL : ''));
  return {
    id: EXPLORER_OTHERS_ID,
    isOthers: true,
    values,
    rawValues: [...values],
    metric: metricFn(rest, windowSeconds),
    pct: Math.round((rest.bytes * 10000) / totalBytes) / 100,
    bytes: rest.bytes,
    packets: rest.packets,
    flows: rest.flows,
    avgBps: windowSeconds > 0 ? Math.round((rest.bytes * 8) / windowSeconds) : 0,
    pps: windowSeconds > 0 ? Math.round(rest.packets / windowSeconds) : 0,
    fps: windowSeconds > 0 ? Math.round((rest.flows / windowSeconds) * 100) / 100 : 0,
    color: EXPLORER_OTHERS_COLOR,
  };
}

const EXPLORER_RESULT_METRIC_COLUMNS = [
  {
    key: 'bytes',
    title: 'Объём',
    width: 120,
    sortAccessor: (r) => r.bytes,
    render: (r) => fmtBytes(r.bytes),
  },
  {
    key: 'avgBps',
    title: 'Средняя скорость / Average bitrate',
    width: 140,
    sortAccessor: (r, meta) => explorerAvgBps(r, meta),
    render: (r, meta) => fmtBits(explorerAvgBps(r, meta)),
  },
  {
    key: 'pps',
    title: 'Пакеты/с / Packets per second',
    width: 120,
    sortAccessor: (r) => r.pps,
    render: (r) => formatMetric(r.pps, 'pps'),
  },
  {
    key: 'fps',
    title: 'Потоки/с / Flows per second',
    width: 120,
    sortAccessor: (r) => r.fps,
    render: (r) => formatMetric(r.fps, 'fps'),
  },
  {
    key: 'flows',
    title: 'Потоков / Flows',
    width: 110,
    sortAccessor: (r) => r.flows,
    render: (r) => fmtNum(r.flows),
  },
  {
    key: 'packets',
    title: 'Пакетов / Packets',
    width: 120,
    sortAccessor: (r) => r.packets,
    render: (r) => fmtNum(r.packets),
  },
];

function enrichExplorerResultRow(row, meta) {
  const windowSeconds = Number(meta?.windowSeconds) || 0;
  const bytes = Number(row.bytes) || 0;
  const packets = Number(row.packets) || 0;
  const flows = Number(row.flows) || 0;
  const avgFromRow = Number(row.avgBps);
  const avgBps = Number.isFinite(avgFromRow) && avgFromRow > 0
    ? avgFromRow
    : (windowSeconds > 0 ? Math.round(bytes * 8 / windowSeconds) : 0);
  const ws = windowSeconds > 0 ? windowSeconds : 0;
  const values = [...(row.values || [])];
  (row.asnMeta || []).forEach((entry, idx) => {
    if (!entry?.asName) return;
    values[idx] = explorerAsnDisplayValue(row, idx, values[idx]);
  });
  return {
    ...row,
    values,
    bytes,
    packets,
    flows,
    avgBps,
    pps: Number.isFinite(Number(row.pps)) ? Number(row.pps) : (ws > 0 ? Math.round(packets / ws) : 0),
    fps: Number.isFinite(Number(row.fps)) ? Number(row.fps) : (ws > 0 ? Math.round((flows / ws) * 100) / 100 : 0),
  };
}

function buildExplorerMetricColumnDefs(meta) {
  return EXPLORER_RESULT_METRIC_COLUMNS.map((col) => ({
    key: col.key,
    title: col.title,
    align: 'right',
    width: col.width,
    minWidth: 64,
    maxWidth: 220,
    num: true,
    headerClassName: 'explorer-col-metric-extra',
    cellClassName: 'explorer-col-metric-extra',
    sortAccessor: (r) => (col.sortAccessor.length > 1 ? col.sortAccessor(r, meta) : col.sortAccessor(r)),
    render: (r) => (
      <span className="mono">{col.render.length > 1 ? col.render(r, meta) : col.render(r)}</span>
    ),
  }));
}

const EXPLORER_TABLE_CELL_PAD = 28;
const EXPLORER_TABLE_MONO_CHAR = 7.4;
const EXPLORER_TABLE_TEXT_CHAR = 8.2;
const EXPLORER_TABLE_DIM_EXTRA = 36;

function measureExplorerTableText(text, { mono = false, pad = EXPLORER_TABLE_CELL_PAD } = {}) {
  const sample = String(text ?? '');
  const charW = mono ? EXPLORER_TABLE_MONO_CHAR : EXPLORER_TABLE_TEXT_CHAR;
  return Math.ceil(sample.length * charW) + pad;
}

function fitExplorerTableColumnWidths(columns, rows, pinnedRows, { meta, metric, groupBy }) {
  const sampleRows = [...(rows || []), ...(pinnedRows || [])];
  if (!columns.length) return null;

  const widths = {};
  columns.forEach((col) => {
    const minW = Number(col.minWidth) || 72;
    const maxW = Number(col.maxWidth) || 800;

    if (col.key === 'actions') {
      widths[col.key] = Number(col.width) || 248;
      return;
    }

    let contentW = measureExplorerTableText(col.title);

    if (col.key.startsWith('dim-')) {
      const groupToken = col.key.slice(4);
      const dimId = explorerGroupFieldId(groupToken);
      const valueIdx = groupBy.indexOf(groupToken);
      const isAsn = dimId.endsWith('asn');
      const mono = dimId.endsWith('ip') || dimId.endsWith('_mac');
      sampleRows.forEach((row) => {
        if (row.isOthers && valueIdx !== 0) return;
        let text = '—';
        if (row.isOthers) text = EXPLORER_OTHERS_LABEL;
        else if (valueIdx >= 0) text = isAsn ? explorerAsnDisplayValue(row, valueIdx) : row.values[valueIdx];
        contentW = Math.max(contentW, measureExplorerTableText(text, { mono }) + EXPLORER_TABLE_DIM_EXTRA);
      });
    } else if (col.key === 'metric') {
      sampleRows.forEach((row) => {
        contentW = Math.max(contentW, measureExplorerTableText(formatMetric(row.metric, metric), { mono: true }));
      });
    } else if (col.key === 'pct') {
      contentW = Math.max(contentW, measureExplorerTableText(col.title, { mono: true }));
      sampleRows.forEach((row) => {
        contentW = Math.max(contentW, measureExplorerTableText(`${Number(row.pct || 0).toFixed(2)}%`, { mono: true }));
      });
    } else {
      const metricColDef = EXPLORER_RESULT_METRIC_COLUMNS.find((c) => c.key === col.key);
      if (metricColDef) {
        sampleRows.forEach((row) => {
          const rendered = metricColDef.render.length > 1
            ? metricColDef.render(row, meta)
            : metricColDef.render(row);
          contentW = Math.max(contentW, measureExplorerTableText(rendered, { mono: true }));
        });
      }
    }

    widths[col.key] = Math.max(minW, Math.min(maxW, contentW));
  });

  return widths;
}

function isBuiltinExplorerPreset(query) {
  return DEFAULT_EXPLORER_PRESETS.some((d) => d.id === query?.id);
}

function mergeExplorerSavedFilters(items) {
  return [...DEFAULT_EXPLORER_PRESETS, ...(items || []).filter((q) => !isBuiltinExplorerPreset(q))];
}

function explorerPresetFields(query) {
  return [
    ...(query?.groupBy || []).map(explorerGroupFieldId),
    ...(query?.filters || []).map((filter) => filter.field),
  ].filter(Boolean);
}

function builtinExplorerPresetsForSchema(schema) {
  const allowed = new Set([
    ...(schema?.dimensions || []).map((field) => field.id),
    ...(schema?.filterFields || []).map((field) => field.id),
  ]);
  return DEFAULT_EXPLORER_PRESETS.filter((preset) => (
    explorerPresetFields(preset).every((field) => allowed.has(field))
  ));
}

const EXPLORER_LAST_APPLIED_KEY = 'explorer.lastAppliedQuery';
const EXPLORER_RESULT_CACHE_KEY = 'explorer.resultCache';
const EXPLORER_CACHE_TTL_RELATIVE_MS = 15 * 60 * 1000;
const EXPLORER_CACHE_TTL_CUSTOM_MS = 30 * 60 * 1000;
const EXPLORER_FILTER_LOGIC_OPTIONS = [
  { id: 'and', label: 'И', altLabel: 'AND' },
  { id: 'or', label: 'ИЛИ', altLabel: 'OR' },
  { id: 'and_not', label: 'И НЕ', altLabel: 'AND NOT' },
  { id: 'or_not', label: 'ИЛИ НЕ', altLabel: 'OR NOT' },
];

const EXPLORER_OP_LABELS = {
  '=': 'равно',
  '!=': 'не равно',
  has_any: 'есть любой из',
  has_all: 'есть все из',
  eq: 'равно маске',
  neq: 'не равно маске',
  contains: 'содержит',
  not_contains: 'не содержит',
  in: 'один из',
  not_in: 'ни один из',
  cidr: 'в сети (CIDR)',
  between: 'между',
  '>': 'больше',
  '>=': 'больше или равно',
  '<': 'меньше',
  '<=': 'меньше или равно',
};

const EXPLORER_OP_CANONICAL = new Set([
  ...Object.keys(EXPLORER_OP_LABELS),
  '<>',
]);

function explorerOpLabel(op) {
  return EXPLORER_OP_LABELS[op] || op;
}

const EXPLORER_OP_CHIP_LABELS = {
  '=': '=',
  '!=': '≠',
  '>': '>',
  '>=': '≥',
  '<': '<',
  '<=': '≤',
  eq: '=',
  neq: '≠',
  in: '∈',
  not_in: '∉',
};

function explorerOpChipLabel(op) {
  return EXPLORER_OP_CHIP_LABELS[op] || explorerOpLabel(op);
}

function formatExplorerFilterValueDisplay(f, schema) {
  const meta = filterFieldMeta(schema, f.field);
  if (f.label) return f.label;
  if (f.value == null || f.value === '') return '…';
  if (f.field === 'direction') {
    return explorerDirectionSummaryLabel(directionFilterToMap(f.value));
  }
  if (f.field === 'collector') {
    const arr = collectorFilterToArray(f.value);
    if (!arr.length) return '…';
    if (arr.length === 1) return arr[0];
    return `${arr.length} колл.`;
  }
  if (f.field === 'tcp_flags' || meta?.type === 'tcp_flags') {
    const flags = parseTcpFlagsValue(f.value);
    if (!flags.length) return '…';
    return flags.join(', ');
  }
  const val = String(f.value);
  if (val.length > 28) return `${val.slice(0, 26)}…`;
  return val;
}

function formatExplorerFilterChipLabel(f, schema) {
  const meta = filterFieldMeta(schema, f.field);
  const fieldLabel = meta?.label || f.field;
  const shortField = fieldLabel.length > 18 ? f.field : fieldLabel;
  return `${shortField} ${explorerOpChipLabel(f.op)} ${formatExplorerFilterValueDisplay(f, schema)}`;
}

function formatExplorerThresholdChipLabel(row, schema) {
  const api = explorerThresholdApi();
  const schemaMetrics = api.thresholdMetricsFromSchema?.(schema) || [];
  if (api.formatThresholdChipLabel && String(row.value ?? '').trim() !== '') {
    return api.formatThresholdChipLabel(row, schemaMetrics);
  }
  const meta = schemaMetrics.find((m) => m.id === row.metric);
  const metricLabel = meta?.label || row.metric || 'метрика';
  const opMeta = (api.EXPLORER_THRESHOLD_OPS || []).find((o) => o.id === row.op);
  const opLabel = opMeta?.label || row.op || '>';
  const val = String(row.value ?? '').trim();
  if (!val) return `${metricLabel} ${opLabel} …`;
  return api.formatThresholdChipLabel?.(row, schemaMetrics) || `${metricLabel} ${opLabel} ${val}`;
}

const EXPLORER_TCP_FLAG_NAMES = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'];
const EXPLORER_TCP_FLAG_BITS = {
  FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16, URG: 32, ECE: 64, CWR: 128,
};

function parseTcpFlagsValue(value) {
  return String(value ?? '')
    .split(',')
    .map((v) => v.trim().toUpperCase())
    .filter((name) => EXPLORER_TCP_FLAG_NAMES.includes(name));
}

function tcpFlagsArrayToValue(flags) {
  return EXPLORER_TCP_FLAG_NAMES.filter((name) => flags.includes(name)).join(',');
}

function tcpFlagsMapFromValue(value) {
  const selected = parseTcpFlagsValue(value);
  return Object.fromEntries(EXPLORER_TCP_FLAG_NAMES.map((name) => [name, selected.includes(name)]));
}

function tcpFlagsSummaryLabel(value) {
  const flags = parseTcpFlagsValue(value);
  return flags.length ? flags.join(', ') : '—';
}

function tcpFlagsLabelFromRaw(raw) {
  const num = Number(raw);
  if (!Number.isFinite(num) || num === 0) return '—';
  const names = EXPLORER_TCP_FLAG_NAMES.filter((name) => (num & EXPLORER_TCP_FLAG_BITS[name]) !== 0);
  return names.length ? names.join(',') : '—';
}

function getExplorerOpTokens() {
  const entries = [];
  Object.entries(EXPLORER_OP_LABELS).forEach(([op, label]) => {
    entries.push({ token: op, op });
    entries.push({ token: label, op });
  });
  entries.push({ token: '<>', op: '!=' });
  return entries.sort((a, b) => b.token.length - a.token.length);
}

function resolveExplorerFieldId(token, schema) {
  const raw = String(token || '').trim();
  if (!raw) return raw;
  const fields = schema?.filterFields || [];
  if (fields.some((f) => f.id === raw)) return raw;
  const exactId = fields.find((f) => String(f.id).toLowerCase() === raw.toLowerCase());
  if (exactId) return exactId.id;
  const byAlias = fields.filter((f) => explorerFieldMatchesQuery(f, raw));
  if (byAlias.length === 1) return byAlias[0].id;
  const exact = fields.find((f) => String(f.label || '').toLowerCase() === raw.toLowerCase());
  if (exact) return exact.id;
  const partial = fields.filter((f) => String(f.label || '').toLowerCase().includes(raw.toLowerCase()));
  if (partial.length === 1) return partial[0].id;
  return raw;
}

function resolveExplorerOpToken(token) {
  const key = String(token || '').trim().toLowerCase();
  if (key === '<>') return '!=';
  if (EXPLORER_OP_CANONICAL.has(key)) return key;
  const fromLabel = Object.entries(EXPLORER_OP_LABELS).find(([, label]) => label.toLowerCase() === key);
  return fromLabel ? fromLabel[0] : key;
}

function explorerInterfaceScopeHint(fieldId, switchIpScope) {
  if (fieldId !== 'in_if_name' && fieldId !== 'out_if_name') return '';
  return switchIpScope
    ? 'Поиск по выбранному коммутатору'
    : 'Поиск по всем коммутаторам · уточните оборудование';
}

function isExplorerIpLikeValue(value) {
  const s = String(value || '').trim();
  if (!s) return true;
  return /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/.test(s)
    || /^[\da-f:]+(?:\/\d{1,3})?$/i.test(s);
}

function validateExplorerFilterRows(filters, schema) {
  const warnings = [];
  const rowErrors = {};
  const validFilters = [];

  (filters || []).forEach((f) => {
    const meta = filterFieldMeta(schema, f.field);
    const valueStr = String(f.value ?? '').trim();
    const fieldLabel = meta?.label || f.field;

    if (!valueStr && f.field !== 'direction' && f.field !== 'collector') {
      warnings.push(`Пустое значение: ${fieldLabel}`);
      rowErrors[f.id] = 'Укажите значение или удалите условие';
      return;
    }

    const type = meta?.type || meta?.filterType;
    if ((type === 'ip' || type === 'switch_ip' || f.op === 'cidr') && valueStr && !isExplorerIpLikeValue(valueStr)) {
      const msg = 'Проверьте формат IP или CIDR';
      warnings.push(`${fieldLabel}: ${msg}`);
      rowErrors[f.id] = msg;
    }

    if ((f.field === 'in_if_name' || f.field === 'out_if_name') && /^\d+$/.test(valueStr)) {
      const msg = 'Похоже на ifIndex, выберите ifName из списка';
      warnings.push(`${fieldLabel}: ${msg}`);
      rowErrors[f.id] = msg;
    }

    if ((meta?.type || meta?.filterType) === 'tcp_flags') {
      const flags = parseTcpFlagsValue(valueStr);
      if ((f.op === 'has_any' || f.op === 'has_all') && !flags.length) {
        const msg = 'Выберите хотя бы один TCP-флаг';
        warnings.push(`${fieldLabel}: ${msg}`);
        rowErrors[f.id] = msg;
      }
    }

    validFilters.push(f);
  });

  return { validFilters, warnings, rowErrors };
}

function explorerSwitchIpScopeFromText(text) {
  const ips = [];
  String(text || '').split('\n').forEach((line) => {
    const eq = line.match(/switch_ip\s+=\s+(\S+)/i);
    if (eq) ips.push(eq[1].replace(/^"|"$/g, ''));
    const list = line.match(/switch_ip\s+in\s*\(([^)]+)\)/i);
    if (list) {
      list[1].split(',').forEach((part) => {
        const v = part.trim().replace(/^"|"$/g, '');
        if (v) ips.push(v);
      });
    }
  });
  return [...new Set(ips)].join(',');
}

const EXPLORER_UI_TO_DIRECTION = {
  total: 'total',
  incoming: 'in',
  outgoing: 'out',
  transit: 'transit',
  internal: 'internal',
  unclassified: 'unknown',
};

function explorerDirectionDbValue(directionId) {
  return EXPLORER_UI_TO_DIRECTION[directionId] ?? directionId;
}

function normalizeFilterLogicValue(logic) {
  const key = String(logic || 'and').trim().toLowerCase();
  return EXPLORER_FILTER_LOGIC_OPTIONS.some((o) => o.id === key) ? key : 'and';
}

function readExplorerUrlGlobals() {
  const { pageId, params } = parseAppHash?.() || { pageId: '', params: new URLSearchParams() };
  if (pageId !== 'explorer') return {};
  return applyExplorerUrlGlobals?.(params) || {};
}

function explorerStorageKey(baseKey, cabinetMode) {
  return cabinetMode ? `${baseKey}.cabinet` : baseKey;
}

function loadLastAppliedExplorerQuery(cabinetMode = false) {
  try {
    const raw = localStorage.getItem(explorerStorageKey(EXPLORER_LAST_APPLIED_KEY, cabinetMode));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function saveLastAppliedExplorerQuery(snapshot, cabinetMode = false) {
  try {
    localStorage.setItem(explorerStorageKey(EXPLORER_LAST_APPLIED_KEY, cabinetMode), JSON.stringify(snapshot));
  } catch { /* ignore quota */ }
}

function resolveExplorerCacheTtlMs(timeRange) {
  return timeRange === 'custom' ? EXPLORER_CACHE_TTL_CUSTOM_MS : EXPLORER_CACHE_TTL_RELATIVE_MS;
}

function buildExplorerQueryKey(snapshot) {
  const migrated = migrateExplorerSnapshot(snapshot);
  if (!migrated) return '';
  const fetchLimit = resolveExplorerFetchLimit(migrated.fetchLimit ?? migrated.limit);
  const { validThresholds } = resolveExplorerThresholdPayload(migrated.thresholds, { thresholdMetrics: explorerThresholdApi().EXPLORER_THRESHOLD_DEFAULT_METRICS });
  return JSON.stringify({
    metric: migrated.metric || 'bps',
    groupBy: normalizeExplorerGroupTokens(migrated.groupBy || []),
    filters: (migrated.filters || []).map(normalizeExplorerFilter),
    thresholds: validThresholds,
    timeRange: migrated.timeRange || '1h',
    customPeriod: migrated.timeRange === 'custom' ? migrated.customPeriod : null,
    fetchLimit,
  });
}

function saveExplorerResultCache({ snapshot, payload, cabinetMode = false }) {
  try {
    const migrated = migrateExplorerSnapshot(snapshot);
    if (!migrated) return;
    const queryKey = buildExplorerQueryKey(migrated);
    const savedAt = new Date();
    const entry = {
      savedAt: savedAt.toISOString(),
      expiresAt: new Date(savedAt.getTime() + resolveExplorerCacheTtlMs(migrated.timeRange)).toISOString(),
      queryKey,
      snapshot: migrated,
      payload,
    };
    sessionStorage.setItem(explorerStorageKey(EXPLORER_RESULT_CACHE_KEY, cabinetMode), JSON.stringify(entry));
  } catch { /* ignore quota */ }
}

function loadExplorerResultCache(queryKey, cabinetMode = false) {
  try {
    const raw = sessionStorage.getItem(explorerStorageKey(EXPLORER_RESULT_CACHE_KEY, cabinetMode));
    if (!raw) return null;
    const entry = JSON.parse(raw);
    if (!entry || entry.queryKey !== queryKey) return null;
    if (entry.expiresAt && Date.now() > new Date(entry.expiresAt).getTime()) return null;
    return entry;
  } catch {
    return null;
  }
}

function updateExplorerResultCacheUi(patch, cabinetMode = false) {
  try {
    const raw = sessionStorage.getItem(explorerStorageKey(EXPLORER_RESULT_CACHE_KEY, cabinetMode));
    if (!raw) return;
    const entry = JSON.parse(raw);
    if (!entry?.snapshot) return;
    entry.snapshot = {
      ...entry.snapshot,
      ...patch,
      dynamicsSeriesIds: patch.dynamicsSeriesIds
        ? [...patch.dynamicsSeriesIds]
        : entry.snapshot.dynamicsSeriesIds,
    };
    sessionStorage.setItem(explorerStorageKey(EXPLORER_RESULT_CACHE_KEY, cabinetMode), JSON.stringify(entry));
  } catch { /* ignore quota */ }
}

function clearExplorerResultCache(cabinetMode = false) {
  try {
    sessionStorage.removeItem(explorerStorageKey(EXPLORER_RESULT_CACHE_KEY, cabinetMode));
  } catch { /* ignore */ }
}

function directionFilterToMap(value) {
  const raw = String(value ?? '').trim().replace(/^__total__$/, 'total');
  const vals = raw.split(',').map((s) => s.trim()).filter(Boolean);
  const map = Object.fromEntries(TRAFFIC_DIRECTIONS.map((d) => [d.id, false]));
  if (!vals.length) return map;
  TRAFFIC_DIRECTIONS.forEach((d) => {
    map[d.id] = vals.includes(explorerDirectionDbValue(d.id));
  });
  return map;
}

function defaultDirectionFilterValue() {
  return directionMapToFilterValue(defaultDirectionsEnabled());
}

function directionMapToFilterValue(directions) {
  return TRAFFIC_DIRECTIONS
    .filter((d) => directions?.[d.id])
    .map((d) => explorerDirectionDbValue(d.id))
    .filter(Boolean)
    .join(',');
}

function explorerDirectionSummaryLabel(directions) {
  const enabled = TRAFFIC_DIRECTIONS.filter((d) => directions[d.id]);
  if (enabled.length === TRAFFIC_DIRECTIONS.length) return 'Все направления';
  if (enabled.length === 0) return 'Нет направлений';
  return enabled.map((d) => d.label).join(', ');
}

function collectorFilterToArray(value) {
  return String(value || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function collectorArrayToFilterValue(arr) {
  return (arr || []).map(String).filter(Boolean).join(',');
}

function normalizeCollectorDslValue(value) {
  const normalized = String(value ?? '').trim().replace(/^"|"$/g, '');
  return normalized.toLowerCase() === 'all' ? '' : normalized;
}

function isAllDirectionsEnabled(directions) {
  return TRAFFIC_DIRECTIONS.every((d) => directions?.[d.id]);
}

function buildDirectionFilterFromState(directions) {
  if (!directions || isAllDirectionsEnabled(directions)) return null;
  const values = TRAFFIC_DIRECTIONS
    .filter((d) => directions[d.id])
    .map((d) => explorerDirectionDbValue(d.id))
    .filter(Boolean);
  if (!values.length) return null;
  if (values.length === 1) {
    return { field: 'direction', op: '=', value: values[0], logic: 'and' };
  }
  return { field: 'direction', op: 'in', value: values.join(','), logic: 'and' };
}

function migrateExplorerSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return snapshot;
  let filters = cloneExplorerFilters(snapshot.filters || []);
  const hasDirFilter = filters.some((f) => f.field === 'direction');
  const hasCollFilter = filters.some((f) => f.field === 'collector');
  const legacyFilters = [];
  if (!hasDirFilter && snapshot.directions && !isAllDirectionsEnabled(snapshot.directions)) {
    const dirFilter = buildDirectionFilterFromState(snapshot.directions);
    if (dirFilter) legacyFilters.push(dirFilter);
  }
  if (!hasCollFilter && Array.isArray(snapshot.collectorFilter) && snapshot.collectorFilter.length) {
    legacyFilters.push({
      id: Date.now(),
      field: 'collector',
      op: 'in',
      value: snapshot.collectorFilter.join(','),
      logic: 'and',
    });
  }
  filters = [...legacyFilters, ...filters];
  const { directions, collectorFilter, systemFiltersEnabled, ...rest } = snapshot;
  let thresholds = [];
  if (Array.isArray(snapshot.thresholds) && snapshot.thresholds.length) {
    const api = explorerThresholdApi();
    thresholds = snapshot.thresholds[0] != null && typeof snapshot.thresholds[0].value === 'number'
      ? snapshot.thresholds.map((t) => api.thresholdDraftFromApi?.(t) || t)
      : cloneExplorerThresholdsList(snapshot.thresholds);
  }
  return {
    ...rest,
    filters: filters.map(normalizeExplorerFilter),
    thresholds,
  };
}

function migrateExplorerUrlGlobals(globals = {}, urlFilters = []) {
  return migrateExplorerSnapshot({
    directions: globals.directions,
    collectorFilter: globals.collectorFilter,
    filters: urlFilters,
  }).filters;
}

const EXPLORER_QUICK_FILTERS = [
  { field: 'proto', label: 'TCP', val: 'TCP' },
  { field: 'proto', label: 'UDP', val: 'UDP' },
  { field: 'dst_port', label: 'DNS dst/53', val: '53' },
  { field: 'dst_port', label: 'HTTPS dst/443', val: '443' },
];

function explorerFieldMatchesQuery(field, q) {
  if (window.ExplorerFieldSearch?.explorerFieldMatchesQuery) {
    return window.ExplorerFieldSearch.explorerFieldMatchesQuery(field, q);
  }
  const needle = String(q ?? '').trim().toLocaleLowerCase();
  if (!needle) return true;
  const id = String(field?.id ?? '').toLocaleLowerCase();
  const label = String(field?.label ?? '').toLocaleLowerCase();
  return id.includes(needle) || label.includes(needle);
}

const EXPLORER_NESTED_MENU_SELECTOR = [
  '.direction-filter__menu--portal',
  '.collector-filter__menu--portal',
  '.explorer-entity-picker__menu--portal',
  '.explorer-filter-picker-menu--portal',
].join(', ');

function isExplorerNestedMenuTarget(target) {
  return target instanceof Element && Boolean(target.closest(EXPLORER_NESTED_MENU_SELECTOR));
}

function computeExplorerPopoverStyle(anchorEl, { minWidth = 280, maxHeight = 420, gap = 4 } = {}) {
  const rect = anchorEl.getBoundingClientRect();
  const pad = 8;
  const width = Math.max(rect.width, minWidth);
  const left = Math.min(Math.max(pad, rect.left), window.innerWidth - width - pad);
  const below = window.innerHeight - rect.bottom - gap - pad;
  const above = rect.top - gap - pad;
  const preferBelow = below >= above;
  const availableHeight = Math.max(120, Math.min(maxHeight, preferBelow ? below : above));
  const top = preferBelow
    ? rect.bottom + gap
    : Math.max(pad, rect.top - gap - availableHeight);
  return {
    position: 'fixed',
    top,
    left,
    width,
    maxHeight: availableHeight,
    zIndex: 1300,
    overflowY: 'auto',
  };
}

function explorerThresholdApi() {
  return window.ExplorerThresholds || {};
}

function explorerGroupDslApi() {
  return window.ExplorerGroupDsl || {};
}

function cloneExplorerThresholdsList(rows) {
  return explorerThresholdApi().cloneExplorerThresholds?.(rows) || [];
}

function resolveExplorerThresholdPayload(draftRows, schema) {
  const api = explorerThresholdApi();
  const schemaMetrics = api.thresholdMetricsFromSchema?.(schema) || [];
  return api.validateExplorerThresholdDrafts?.(draftRows, schemaMetrics) || { validThresholds: [], inactiveIds: new Set() };
}

function buildExplorerQuerySnapshot({
  timeRange, customPeriod, filters, thresholds, metric, groupBy, limit, vis,
  fetchLimit, visualLimit, dynamicsSeriesIds,
}) {
  return {
    timeRange,
    customPeriod: timeRange === 'custom' ? { ...(customPeriod || {}) } : null,
    filters: filters.map(normalizeExplorerFilter),
    thresholds: cloneExplorerThresholdsList(thresholds || []),
    metric,
    groupBy: normalizeExplorerGroupTokens(groupBy),
    limit,
    vis: normalizeExplorerVis(vis),
    fetchLimit: fetchLimit ?? resolveExplorerFetchLimit(limit),
    visualLimit: visualLimit ?? EXPLORER_DEFAULT_VISUAL_LIMIT,
    dynamicsSeriesIds: Array.isArray(dynamicsSeriesIds) ? [...dynamicsSeriesIds] : [],
    savedAt: new Date().toISOString(),
  };
}

function buildSnapshotFromUrl(urlState, urlGlobals) {
  return buildExplorerQuerySnapshot({
    timeRange: urlGlobals.timeRange || '1h',
    customPeriod: urlGlobals.customPeriod || defaultCustomPeriod(),
    filters: urlState.filters || [],
    thresholds: urlState.thresholds || [],
    metric: urlState.metric || 'bps',
    groupBy: normalizeExplorerGroupTokens(urlState.groupBy || ['src_ip', 'dst_ip']),
    limit: urlState.limit || EXPLORER_DEFAULT_FETCH_LIMIT,
    vis: urlState.vis,
  });
}

function hydrateExplorerFromCachedEntry(entry, handlers) {
  const { snapshot, payload } = entry;
  const migrated = restoreExplorerDraftFromSnapshot(snapshot, handlers.querySetters, handlers.draftRestoreOpts);
  if (!migrated) return false;

  if (migrated.fetchLimit != null) {
    handlers.setFetchLimit(resolveExplorerFetchLimit(migrated.fetchLimit));
  }
  if (migrated.visualLimit != null) {
    handlers.setVisualLimit(migrated.visualLimit);
    if (handlers.setLimit) handlers.setLimit(migrated.visualLimit);
  }
  if (migrated.dynamicsSeriesIds?.length) {
    handlers.setDynamicsSeriesIds(new Set(migrated.dynamicsSeriesIds));
  } else {
    const rowList = Array.isArray(payload.rows) ? payload.rows : [];
    const visualLim = migrated.visualLimit ?? EXPLORER_DEFAULT_VISUAL_LIMIT;
    handlers.setDynamicsSeriesIds(defaultDynamicsSeriesIds(rowList, visualLim));
  }
  handlers.skipDynamicsDefaultRef.current = true;

  handlers.setRows(Array.isArray(payload.rows) ? payload.rows : []);
  handlers.setSummary(
    payload.summary
      ? { ...EMPTY_EXPLORER_SUMMARY, ...payload.summary }
      : EMPTY_EXPLORER_SUMMARY,
  );
  handlers.setTimeseries?.(Array.isArray(payload.timeseries) ? payload.timeseries : []);
  handlers.setResultSeries(payload.resultSeries || null);
  handlers.setMeta(payload.meta || null);
  handlers.setSource('cache');
  handlers.setError(null);
  handlers.setLoadMs(payload.loadMs ?? null);
  handlers.setServerMs(payload.serverMs ?? null);
  handlers.setAppliedSnapshot(migrated);
  handlers.setHasAppliedQuery(true);
  handlers.setLastApplied(migrated);
  handlers.setShowOthersOnChart?.(explorerDefaultShowOthersOnChart(migrated.vis));
  saveLastAppliedExplorerQuery(migrated, handlers.cabinetMode);
  handlers.dynamicsQueryVersionRef.current = handlers.queryVersion ?? 0;
  return true;
}

function applyExplorerQuerySnapshot(snapshot, setters) {
  const migrated = migrateExplorerSnapshot(snapshot);
  if (!migrated) return;
  if (migrated.timeRange) setters.setTimeRange(migrated.timeRange);
  if (migrated.timeRange === 'custom' && migrated.customPeriod) {
    setters.setCustomPeriod(migrated.customPeriod);
  }
  if (migrated.filters) setters.setFilters(cloneExplorerFilters(migrated.filters));
  if (migrated.thresholds && setters.setThresholds) setters.setThresholds(cloneExplorerThresholdsList(migrated.thresholds));
  if (migrated.metric) setters.setMetric(migrated.metric);
  if (Array.isArray(migrated.groupBy)) setters.setGroupBy(normalizeExplorerGroupTokens(migrated.groupBy));
  if (migrated.limit) setters.setLimit(migrated.limit);
  if (migrated.vis) setters.setVis(normalizeExplorerVis(migrated.vis));
}

function resolveExplorerDraftSnapshot({ hasAppliedQuery, appliedSnapshot, lastApplied, source }) {
  if (hasAppliedQuery && appliedSnapshot && source !== 'error') {
    return migrateExplorerSnapshot(appliedSnapshot);
  }
  if (lastApplied) return migrateExplorerSnapshot(lastApplied);
  return null;
}

function restoreExplorerDraftFromSnapshot(snapshot, setters, { filterMode, setFilterText, schema } = {}) {
  if (!snapshot) return null;
  const migrated = migrateExplorerSnapshot(snapshot);
  if (!migrated) return null;
  applyExplorerQuerySnapshot(migrated, setters);
  if (filterMode === 'text' && setFilterText) {
    setFilterText(serializeExplorerFilterDsl({
      timeRange: migrated.timeRange,
      customPeriod: migrated.customPeriod,
      filters: migrated.filters,
      thresholds: migrated.thresholds,
      groupBy: migrated.groupBy,
      schema,
    }));
  }
  return migrated;
}

function parseLogicOnlyLine(line) {
  const trimmed = String(line || '').trim();
  if (/^(И\s+НЕ|AND\s+NOT)$/i.test(trimmed)) return 'and_not';
  if (/^(ИЛИ\s+НЕ|OR\s+NOT)$/i.test(trimmed)) return 'or_not';
  if (/^(ИЛИ|OR)$/i.test(trimmed)) return 'or';
  if (/^(И|AND)$/i.test(trimmed)) return 'and';
  return null;
}

function parseLogicPrefix(line) {
  const trimmed = line.trim();
  if (/^(И\s+НЕ|AND\s+NOT)\s+/i.test(trimmed)) {
    return { logic: 'and_not', rest: trimmed.replace(/^(И\s+НЕ|AND\s+NOT)\s+/i, '') };
  }
  if (/^(ИЛИ\s+НЕ|OR\s+NOT)\s+/i.test(trimmed)) {
    return { logic: 'or_not', rest: trimmed.replace(/^(ИЛИ\s+НЕ|OR\s+NOT)\s+/i, '') };
  }
  if (/^(ИЛИ|OR)\s+/i.test(trimmed)) {
    return { logic: 'or', rest: trimmed.replace(/^(ИЛИ|OR)\s+/i, '') };
  }
  if (/^(И|AND)\s+/i.test(trimmed)) {
    return { logic: 'and', rest: trimmed.replace(/^(И|AND)\s+/i, '') };
  }
  return { logic: 'and', rest: trimmed };
}

function serializeExplorerFilterDsl({
  timeRange, customPeriod, filters, thresholds, schema, groupBy,
}) {
  const lines = [];
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    lines.push(`time between "${customPeriod.from}" and "${customPeriod.to}"`);
  } else {
    lines.push(`time range ${timeRange}`);
  }

  const groupLine = explorerGroupDslApi().serializeExplorerGroupByDsl?.(
    normalizeExplorerGroupTokens(groupBy?.length ? groupBy : ['src_ip', 'dst_ip']),
  );
  if (groupLine) lines.push(groupLine);

  (filters || []).forEach((f, i) => {
    const logicOpt = EXPLORER_FILTER_LOGIC_OPTIONS.find((o) => o.id === normalizeFilterLogicValue(f.logic));
    const logicLabel = i === 0 ? '' : `${logicOpt?.label || 'И'} `;
    const quoteVal = (v) => (String(v).includes(' ') ? `"${v}"` : v);
    if (f.field === 'collector') {
      const values = collectorFilterToArray(f.value);
      const serializedValue = values.length
        ? values.map((value) => quoteVal(value)).join(', ')
        : 'all';
      if (f.op === 'in' || f.op === 'not_in') {
        lines.push(`${logicLabel}${f.field} ${f.op} (${serializedValue})`);
      } else {
        lines.push(`${logicLabel}${f.field} ${f.op} ${serializedValue}`);
      }
      return;
    }
    if (f.field === 'direction') {
      if (f.op === 'in' || f.op === 'not_in') {
        const vals = String(f.value).split(',').map((s) => quoteVal(s.trim())).join(', ');
        lines.push(`${logicLabel}${f.field} ${f.op} (${vals})`);
      } else {
        lines.push(`${logicLabel}${f.field} ${f.op} ${quoteVal(f.value ?? '')}`.trim());
      }
      return;
    }
    if (f.field === 'tcp_flags') {
      const vals = String(f.value).split(',').map((s) => s.trim()).filter(Boolean).join(', ');
      lines.push(`${logicLabel}${f.field} ${f.op} (${vals})`);
      return;
    }
    if (f.op === 'between') {
      const parts = String(f.value).split(',').map((s) => s.trim());
      lines.push(`${logicLabel}${f.field} between ${parts[0]} and ${parts[1] || parts[0]}`);
    } else if (f.op === 'in' || f.op === 'not_in') {
      const vals = String(f.value).split(',').map((s) => quoteVal(s.trim())).join(', ');
      lines.push(`${logicLabel}${f.field} ${f.op} (${vals})`);
    } else if (f.op === 'cidr') {
      lines.push(`${logicLabel}${f.field} cidr ${quoteVal(f.value)}`);
    } else {
      lines.push(`${logicLabel}${f.field} ${f.op} ${quoteVal(f.value ?? '')}`.trim());
    }
  });

  const schemaMetrics = explorerThresholdApi().thresholdMetricsFromSchema?.(schema) || [];
  explorerThresholdApi().serializeExplorerThresholdsToDsl?.(thresholds, schemaMetrics)
    .forEach((line) => lines.push(line));

  return lines.join('\n');
}

function parseExplorerFilterDsl(text, schema = null) {
  const rawLines = String(text || '').split('\n');
  const lines = [];
  const lineNumbers = [];
  rawLines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed) {
      lines.push(trimmed);
      lineNumbers.push(index + 1);
    }
  });
  if (!lines.length) throw new Error('Фильтр пуст');

  let timeRange = '1h';
  let customPeriod = defaultCustomPeriod();
  const filters = [];
  const thresholds = [];
  let groupBy;
  let groupBySeen = false;
  let conditionIndex = 0;
  let pendingLogic = null;
  const schemaMetrics = explorerThresholdApi().thresholdMetricsFromSchema?.(schema) || [];
  const dimensions = schema?.dimensions || [];
  const groupDsl = explorerGroupDslApi();

  const pushFilter = (partial) => {
    filters.push({
      id: Date.now() + conditionIndex++,
      logic: partial.logic ?? 'and',
      field: resolveExplorerFieldId(partial.field, schema),
      op: resolveExplorerOpToken(partial.op),
      value: partial.value,
      label: partial.label ?? null,
    });
  };

  const parseError = (lineNum, message) => {
    throw new Error(`Строка ${lineNum}: ${message}`);
  };

  for (let index = 0; index < lines.length; index += 1) {
    const rawLine = lines[index];
    const lineNum = lineNumbers[index];

    try {
      if (/^threshold\s+/i.test(rawLine)) {
        const draft = explorerThresholdApi().parseExplorerThresholdDslLine?.(rawLine, schemaMetrics);
        if (draft) {
          thresholds.push({
            ...draft,
            id: `thr-${Date.now()}-${index}-${Math.random().toString(36).slice(2, 6)}`,
          });
        }
        continue;
      }

      if (groupDsl.isExplorerGroupByDslLine?.(rawLine)) {
        if (groupBySeen) parseError(lineNum, 'строка group by указана более одного раза');
        groupBySeen = true;
        try {
          groupBy = groupDsl.parseExplorerGroupByDslLine?.(
            rawLine,
            dimensions,
          );
        } catch (err) {
          parseError(lineNum, err.message || 'ошибка группировки');
        }
        continue;
      }

      const logicOnly = parseLogicOnlyLine(rawLine);
      if (logicOnly) {
        pendingLogic = logicOnly;
        continue;
      }

      const lineLower = rawLine.toLowerCase();

      if (lineLower.startsWith('time ')) {
        const betweenMatch = rawLine.match(/^time\s+between\s+"([^"]+)"\s+and\s+"([^"]+)"/i);
        if (betweenMatch) {
          timeRange = 'custom';
          customPeriod = { from: betweenMatch[1], to: betweenMatch[2] };
          const err = validateExplorerCustomPeriod(customPeriod, 'custom', schema?.maxRangeDays);
          if (err) parseError(lineNum, err);
          continue;
        }
        const rangeMatch = rawLine.match(/^time\s+range\s+(\S+)/i);
        if (rangeMatch) {
          timeRange = rangeMatch[1];
          const limitDays = explorerRangeLimitDays(schema?.maxRangeDays);
          const presetMs = timeRangePresetMs(timeRange);
          if (presetMs != null && presetMs > limitDays * 86400000) {
            parseError(lineNum, `Период не может превышать ${limitDays} дней`);
          }
          continue;
        }
        parseError(lineNum, `неверный формат времени: ${rawLine}`);
      }

      const { logic: inlineLogic, rest } = parseLogicPrefix(rawLine);
      const logic = pendingLogic ?? (filters.length > 0 ? inlineLogic : 'and');
      pendingLogic = null;

      const systemInMatch = rest.match(/^(direction|collector)\s+(in|not_in|один из|ни один из)\s*\(([^)]+)\)/i);
      if (systemInMatch) {
        const field = systemInMatch[1].toLowerCase();
        if (!(schema?.filterFields || []).some((item) => item.id === field)) {
          parseError(lineNum, `поле недоступно: ${field}`);
        }
        const value = systemInMatch[3]
          .split(',')
          .map((s) => s.trim().replace(/^"|"$/g, ''))
          .join(',');
        pushFilter({
          field,
          op: resolveExplorerOpToken(systemInMatch[2]),
          value: field === 'collector' ? normalizeCollectorDslValue(value) : value,
          logic,
        });
        continue;
      }

      const systemSimpleMatch = rest.match(/^(direction|collector)\s*(=|!=|<>|равно|не равно)\s+(.+)$/i);
      if (systemSimpleMatch) {
        const field = systemSimpleMatch[1].toLowerCase();
        if (!(schema?.filterFields || []).some((item) => item.id === field)) {
          parseError(lineNum, `поле недоступно: ${field}`);
        }
        const value = systemSimpleMatch[3].trim().replace(/^"|"$/g, '');
        pushFilter({
          field,
          op: resolveExplorerOpToken(systemSimpleMatch[2]),
          value: field === 'collector' ? normalizeCollectorDslValue(value) : value,
          logic,
        });
        continue;
      }

      const cidrMatch = rest.match(/^([\w.]+)\s+(cidr|в сети \(CIDR\))\s+(.+)$/i);
      if (cidrMatch) {
        pushFilter({
          field: cidrMatch[1],
          op: 'cidr',
          value: cidrMatch[3].trim().replace(/^"|"$/g, ''),
          logic,
        });
        continue;
      }

      const betweenMatch = rest.match(/^([\w.]+)\s+(between|между)\s+(\S+)\s+and\s+(\S+)$/i);
      if (betweenMatch) {
        pushFilter({
          field: betweenMatch[1],
          op: 'between',
          value: `${betweenMatch[3]},${betweenMatch[4]}`,
          logic,
        });
        continue;
      }

      const tcpFlagsMatch = rest.match(/^([\w.]+)\s+(has_any|has_all|eq|neq|есть\s+любой\s+из|есть\s+все\s+из|равно\s+маске|не\s+равно\s+маске)\s*\(([^)]+)\)/i);
      if (tcpFlagsMatch) {
        pushFilter({
          field: tcpFlagsMatch[1],
          op: resolveExplorerOpToken(tcpFlagsMatch[2]),
          value: tcpFlagsMatch[3].split(',').map((s) => s.trim().replace(/^"|"$/g, '').toUpperCase()).filter(Boolean).join(','),
          logic,
        });
        continue;
      }

      const tcpFlagsSimpleMatch = rest.match(/^([\w.]+)\s+(has_any|has_all|eq|neq|есть\s+любой\s+из|есть\s+все\s+из|равно\s+маске|не\s+равно\s+маске)\s+(.+)$/i);
      if (tcpFlagsSimpleMatch) {
        pushFilter({
          field: tcpFlagsSimpleMatch[1],
          op: resolveExplorerOpToken(tcpFlagsSimpleMatch[2]),
          value: tcpFlagsSimpleMatch[3].trim().replace(/^"|"$/g, '').split(/[\s,]+/).map((s) => s.trim().toUpperCase()).filter(Boolean).join(','),
          logic,
        });
        continue;
      }

      const inMatch = rest.match(/^([\w.]+)\s+(in|not_in|один из|ни один из)\s*\(([^)]+)\)/i);
      if (inMatch) {
        pushFilter({
          field: inMatch[1],
          op: resolveExplorerOpToken(inMatch[2]),
          value: inMatch[3].split(',').map((s) => s.trim().replace(/^"|"$/g, '')).join(','),
          logic,
        });
        continue;
      }

      let simpleHandled = false;
      const fieldLead = rest.match(/^([\w.]+)\s+(.+)$/);
      if (fieldLead) {
        const remainder = fieldLead[2].trim();
        for (const { token, op } of getExplorerOpTokens()) {
          const opRe = new RegExp(`^${token.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}\\s+(.+)$`, 'i');
          const opMatch = remainder.match(opRe);
          if (opMatch) {
            pushFilter({
              field: fieldLead[1],
              op,
              value: opMatch[1].trim().replace(/^"|"$/g, ''),
              logic,
            });
            simpleHandled = true;
            break;
          }
        }
      }
      if (simpleHandled) continue;

      parseError(lineNum, `не удалось разобрать строку: ${rawLine}`);
    } catch (err) {
      if (/^Строка \d+:/.test(String(err.message || ''))) throw err;
      parseError(lineNum, err.message || 'ошибка разбора');
    }
  }

  if (pendingLogic) {
    throw new Error('После связки условия (И, ИЛИ, И НЕ, ИЛИ НЕ) ожидается фильтр');
  }

  const periodErr = validateExplorerCustomPeriod(
    timeRange === 'custom' ? customPeriod : {},
    timeRange,
    schema?.maxRangeDays,
  );
  if (periodErr) throw new Error(periodErr);

  return {
    timeRange,
    customPeriod,
    filters,
    thresholds,
    ...(groupBy !== undefined ? { groupBy } : {}),
  };
}

function explorerTextLineBounds(value, cursor) {
  const safeCursor = Math.max(0, Math.min(Number(cursor) || 0, String(value || '').length));
  const before = String(value || '').lastIndexOf('\n', safeCursor - 1);
  const after = String(value || '').indexOf('\n', safeCursor);
  return {
    start: before < 0 ? 0 : before + 1,
    end: after < 0 ? String(value || '').length : after,
  };
}

function explorerTextValueFragment(line) {
  const inMatch = line.match(/\(([^)]*)$/);
  if (inMatch) return inMatch[1].split(',').pop().trim().replace(/^"|"$/g, '');
  const parts = line.trim().split(/\s+/);
  return (parts[parts.length - 1] || '').replace(/^"|"$/g, '');
}

function getTextareaCaretCoordinates(textarea, pos) {
  const style = window.getComputedStyle(textarea);
  const rect = textarea.getBoundingClientRect();
  const mirror = document.createElement('div');
  const props = [
    'boxSizing', 'width', 'borderTopWidth', 'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth',
    'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft',
    'fontStyle', 'fontVariant', 'fontWeight', 'fontStretch', 'fontSize', 'lineHeight', 'fontFamily',
    'textAlign', 'textTransform', 'textIndent', 'textDecoration', 'letterSpacing', 'wordSpacing', 'tabSize',
  ];
  mirror.style.position = 'fixed';
  mirror.style.visibility = 'hidden';
  mirror.style.top = `${rect.top}px`;
  mirror.style.left = `${rect.left}px`;
  mirror.style.whiteSpace = 'pre-wrap';
  mirror.style.wordWrap = 'break-word';
  mirror.style.overflow = 'hidden';
  props.forEach((prop) => {
    mirror.style[prop] = style[prop];
  });
  mirror.style.width = `${rect.width}px`;

  const safePos = Math.max(0, Math.min(pos, textarea.value.length));
  const before = textarea.value.slice(0, safePos);
  mirror.textContent = before;
  const marker = document.createElement('span');
  marker.textContent = '\u200b';
  mirror.appendChild(marker);
  document.body.appendChild(mirror);
  const markerRect = marker.getBoundingClientRect();
  document.body.removeChild(mirror);

  const lineHeight = Number.parseFloat(style.lineHeight);
  return {
    top: markerRect.top - textarea.scrollTop,
    left: markerRect.left - textarea.scrollLeft,
    height: Number.isFinite(lineHeight) ? lineHeight : markerRect.height,
  };
}

function explorerLogicAutocompleteEntries() {
  return EXPLORER_FILTER_LOGIC_OPTIONS.flatMap((o) => ([
    { token: o.label, hint: `${o.altLabel} · logic` },
    { token: o.altLabel, hint: `${o.label} · связка` },
  ]));
}

function buildExplorerTextSuggestions({ value, cursor, schema, entityItems = [] }) {
  const { start, end } = explorerTextLineBounds(value, cursor);
  const rawLine = String(value || '').slice(start, end);
  const leading = rawLine.match(/^\s*/)?.[0] || '';
  const trimmed = rawLine.trim();
  const { logic, rest } = parseLogicPrefix(trimmed);
  const logicPrefix = trimmed === rest ? '' : trimmed.slice(0, trimmed.length - rest.length);
  const fields = schema?.filterFields || [];
  const fieldById = Object.fromEntries(fields.map((f) => [f.id, f]));
  const lowerRest = rest.toLowerCase();

  const lineSuggestion = (label, insert, hint) => ({ label, hint, insert: `${leading}${insert}`, mode: 'line' });
  const suggestions = [];

  if (!trimmed) return [];

  const needle = trimmed.toLowerCase();
  const matchesNeedle = (label, hint) => (
    String(label || '').toLowerCase().includes(needle)
    || String(hint || '').toLowerCase().includes(needle)
  );

  if (trimmed.toLowerCase().startsWith('threshold')) {
    const schemaMetrics = explorerThresholdApi().thresholdMetricsFromSchema?.(schema) || [];
    return explorerThresholdApi().buildExplorerThresholdDslSuggestions?.(trimmed, leading, schemaMetrics) || [];
  }

  if (explorerGroupDslApi().isExplorerGroupByDslContext?.(trimmed)) {
    return explorerGroupDslApi().buildExplorerGroupByDslSuggestions?.(
      trimmed,
      leading,
      schema?.dimensions || [],
    ) || [];
  }

  [
    lineSuggestion('time range', 'time range 1h', 'Период'),
    lineSuggestion('time between', 'time between "YYYY-MM-DDTHH:mm" and "YYYY-MM-DDTHH:mm"', 'Ручной диапазон'),
    lineSuggestion('group by', 'group by src_ip, dst_ip', 'Группировка'),
    ...(fieldById.direction ? [lineSuggestion('direction', 'direction in (in, out, transit)', 'Направления')] : []),
    ...(fieldById.collector ? [lineSuggestion('collector', 'collector in ("collector-id")', 'Коллекторы')] : []),
    ...explorerLogicAutocompleteEntries().map(({ token, hint }) => lineSuggestion(token, `${token} `, hint)),
  ]
    .filter((item) => matchesNeedle(item.label, item.hint))
    .forEach((item) => suggestions.push(item));

  if (!rest.includes(' ') && !['time', 'direction', 'collector'].some((k) => lowerRest.startsWith(k))
    && !explorerGroupDslApi().isExplorerGroupByDslContext?.(trimmed)) {
    const fieldNeedle = rest.toLowerCase();
    fields
      .filter((f) => fieldNeedle && explorerFieldMatchesQuery(f, fieldNeedle))
      .slice(0, 12)
      .forEach((f) => {
        const display = f.label && f.label !== f.id ? f.label : f.id;
        suggestions.push(lineSuggestion(
          display,
          `${logicPrefix}${f.id} = `,
          f.id !== display ? f.id : (f.valueHint || f.id),
        ));
      });
  }

  if (lowerRest.startsWith('time')) {
    ['30m', '1h', '3h', '6h', '12h', '24h', '7d', '30d'].forEach((range) => {
      suggestions.push(lineSuggestion(`time range ${range}`, `time range ${range}`, 'Готовый период'));
    });
    suggestions.push(lineSuggestion('time between ...', 'time between "YYYY-MM-DDTHH:mm" and "YYYY-MM-DDTHH:mm"', 'Ручной диапазон'));
  }

  if (fieldById.direction && lowerRest.startsWith('direction')) {
    ['total', 'in', 'out', 'transit', 'internal', 'unknown'].forEach((dir) => {
      suggestions.push(lineSuggestion(dir, `direction in (${dir})`, 'Значение direction'));
    });
    suggestions.push(lineSuggestion('total, in, out', 'direction in (total, in, out)', 'Несколько направлений'));
  }

  if (fieldById.collector && lowerRest.startsWith('collector')) {
    suggestions.push(lineSuggestion('Все коллекторы', 'collector in (all)', 'Без ограничения по коллекторам'));
    suggestions.push(lineSuggestion('collector in ("collector-id")', 'collector in ("collector-id")', 'ID коллектора или локации'));
  }

  if (lowerRest.startsWith('tcp_flags')) {
    EXPLORER_TCP_FLAG_NAMES.forEach((flag) => {
      suggestions.push(lineSuggestion(flag, `tcp_flags has_any (${flag})`, 'TCP flag'));
    });
    suggestions.push(lineSuggestion('SYN, ACK', 'tcp_flags has_all (SYN, ACK)', 'SYN+ACK'));
  }

  const fieldMatch = rest.match(/^([\w.]+)(?:\s+(\S+))?/);
  const fieldToken = fieldMatch?.[1];
  const field = fieldToken ? resolveExplorerFieldId(fieldToken, schema) : fieldToken;
  const op = fieldMatch?.[2]?.toLowerCase();
  const meta = fieldById[field] || fieldById[fieldToken];
  if (meta && (!op || rest.trim().split(/\s+/).length <= 2)) {
    (meta.ops || ['=', '!=', 'contains', 'not_contains']).forEach((candidateOp) => {
      suggestions.push(lineSuggestion(
        `${meta.label || field} ${explorerOpLabel(candidateOp)}`,
        `${logicPrefix}${field} ${candidateOp} `,
        meta.valueHint || explorerOpLabel(candidateOp),
      ));
    });
  }

  if (meta && op) {
    const fragment = explorerTextValueFragment(rest).toLowerCase();
    (meta.valueOptions || [])
      .filter((item) => String(item.value ?? item.id ?? item.label).toLowerCase().includes(fragment)
        || String(item.label ?? '').toLowerCase().includes(fragment))
      .slice(0, 8)
      .forEach((item) => {
        const v = item.value ?? item.id ?? item.label;
        suggestions.push(lineSuggestion(String(v), `${logicPrefix}${field} ${resolveExplorerOpToken(op)} ${v}`, item.label || item.hint || 'Значение'));
      });
    dedupeExplorerEntityItems(entityItems).slice(0, 8).forEach((item) => {
      const v = item.value ?? item.id;
      const resolvedOp = resolveExplorerOpToken(op);
      const formatted = /[:,\s]/.test(String(v)) ? `"${v}"` : String(v);
      suggestions.push(lineSuggestion(
        String(item.label || v),
        `${logicPrefix}${field} ${resolvedOp} ${formatted}`,
        item.sublabel || 'Сущность',
      ));
    });
  }

  const seen = new Set();
  return suggestions.filter((item) => {
    const key = `${item.label}|${item.insert}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 12);
}

function summarizeExplorerQuery(snapshot) {
  const parts = [timeRangeLabel(snapshot.timeRange, snapshot.customPeriod)];
  const migrated = migrateExplorerSnapshot(snapshot);
  const filters = migrated.filters || [];
  const dirCount = filters.filter((f) => f.field === 'direction').length;
  const collCount = filters.filter((f) => f.field === 'collector').length;
  if (dirCount) parts.push(`${dirCount} напр.`);
  if (collCount) parts.push(`${collCount} колл.`);
  const otherCount = filters.filter((f) => f.field !== 'direction' && f.field !== 'collector').length;
  if (otherCount) parts.push(`${otherCount} усл.`);
  return parts.join(' · ');
}

function cloneExplorerFilters(filters) {
  return (filters || []).map((f, i) => ({
    ...f,
    field: f.field || f.dim,
    logic: normalizeFilterLogicValue(f.logic),
    id: f.id ?? Date.now() + i + Math.random(),
  }));
}

function normalizeExplorerFilter(f) {
  let op = f.op || '=';
  if (f.field === 'tcp_flags') {
    if (!f.op || op === '=') op = 'eq';
    if (op === '!=') op = 'neq';
  }
  return {
    id: f.id,
    field: f.field || f.dim || 'src_ip',
    op,
    value: f.value ?? '',
    label: f.label || null,
    logic: normalizeFilterLogicValue(f.logic),
  };
}

function filterFieldMeta(schema, fieldId) {
  if (fieldId === 'collector') {
    const fromSchema = (schema?.filterFields || []).find((f) => f.id === 'collector');
    return fromSchema || {
      id: 'collector',
      label: 'Коллектор / Collector',
      group: 'Система / System',
      filterType: 'collector',
      ops: ['in', 'not_in', '=', '!='],
      valueHint: 'ID коллектора или loc:location-id',
    };
  }
  return (schema?.filterFields || []).find((f) => f.id === fieldId) || null;
}

function filterOpsForField(schema, fieldId) {
  if (fieldId === 'collector') return ['in', 'not_in', '=', '!='];
  if (fieldId === 'direction') return ['=', '!=', 'in', 'not_in'];
  if (fieldId === 'tcp_flags') return ['has_any', 'has_all', 'eq', 'neq'];
  const meta = filterFieldMeta(schema, fieldId);
  return meta?.ops || ['=', '!=', 'contains', 'not_contains'];
}

function defaultOpForField(schema, fieldId) {
  const ops = filterOpsForField(schema, fieldId);
  if (ops.includes('=')) return '=';
  if (ops.includes('eq')) return 'eq';
  return ops[0] || '=';
}

function normalizeFilterPickerItem(item) {
  if (item == null) return null;
  if (typeof item === 'string') return { id: item, label: item, hint: null, group: null };
  return {
    id: item.value ?? item.id,
    label: item.label ?? item.value ?? item.id,
    hint: item.hint || item.valueHint || null,
    group: item.group || null,
    aliases: item.aliases || [],
  };
}

function FilterSearchPicker({
  items = [],
  value,
  onChange,
  buttonLabel,
  searchPlaceholder = 'Поиск...',
  emptyLabel = 'Выбрать…',
  inputPlaceholder,
  grouped = false,
  allowCustom = false,
  mono = false,
  style,
  fullWidth = false,
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const anchorRef = React.useRef(null);
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);

  const normalized = useMemo(
    () => items.map(normalizeFilterPickerItem).filter(Boolean),
    [items],
  );

  const filtered = useMemo(() => {
    const needle = q.trim();
    if (!needle) return normalized;
    return normalized.filter((item) => explorerFieldMatchesQuery(item, needle));
  }, [normalized, q]);

  const groups = useMemo(() => {
    if (!grouped) return { '': filtered };
    return filtered.reduce((acc, item) => {
      const key = item.group || 'Прочее';
      acc[key] = acc[key] || [];
      acc[key].push(item);
      return acc;
    }, {});
  }, [filtered, grouped]);

  React.useLayoutEffect(() => {
    if (!open) return undefined;
    const anchor = anchorRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      setMenuStyle({
        position: 'fixed',
        top: rect.bottom + 4,
        left: Math.max(8, rect.left),
        width: Math.max(rect.width, 280),
        maxHeight: 320,
        zIndex: 1400,
        overflowY: 'auto',
      });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (panelRef.current?.contains(e.target) || anchorRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const selected = normalized.find((item) => String(item.id) === String(value));
  const display = buttonLabel || selected?.label || (value ? String(value) : emptyLabel);

  return (
    <>
      <button
        ref={anchorRef}
        type="button"
        className="input"
        onClick={() => { setOpen((v) => !v); setQ(''); }}
        style={{
          minWidth: 0,
          ...(fullWidth ? { width: '100%', flex: 'none' } : { flex: 1 }),
          textAlign: 'left',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 6,
          ...style,
        }}
      >
        <span className={mono ? 'mono' : undefined} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {display}
        </span>
        <Icon name="chevD" size={12} />
      </button>
      {open && menuStyle && ReactDOM.createPortal(
        <div
          ref={panelRef}
          className="explorer-filter-picker-menu--portal"
          style={{
            ...menuStyle,
            zIndex: 1400,
            background: 'var(--bg-surface)',
            border: '1px solid var(--bd-default)',
            borderRadius: 10,
            boxShadow: 'var(--pv-shadow-popover)',
            padding: 8,
          }}
        >
          <input
            className="input"
            placeholder={searchPlaceholder}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            autoFocus
            style={{ marginBottom: 6 }}
          />
          {allowCustom && (
            <input
              className="input mono"
              placeholder={inputPlaceholder || 'Своё значение…'}
              title={inputPlaceholder || undefined}
              value={value ?? ''}
              onChange={(e) => onChange(e.target.value)}
              style={{ marginBottom: 8 }}
            />
          )}
          {Object.keys(groups).length === 0 ? (
            <div style={{ padding: '8px 4px', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Ничего не найдено</div>
          ) : Object.entries(groups).map(([groupName, groupItems]) => (
            <div key={groupName || 'all'} className="explorer-picker-group">
              {grouped && groupName && (
                <div className="explorer-picker-group__heading">{groupName}</div>
              )}
              {groupItems.map((item) => {
                const active = String(item.id) === String(value);
                return (
                  <button
                    key={String(item.id)}
                    type="button"
                    onClick={() => { onChange(item.id); setOpen(false); }}
                    style={{
                      all: 'unset',
                      display: 'block',
                      width: '100%',
                      boxSizing: 'border-box',
                      padding: '8px 10px',
                      borderRadius: 8,
                      cursor: 'pointer',
                      background: active ? 'var(--surf-3)' : 'transparent',
                    }}
                  >
                    <span>{item.label}</span>
                    {grouped && (
                      <div className="mono" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: 2 }}>
                        {item.id}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>,
        document.body,
      )}
    </>
  );
}

function explorerSwitchIpScopeFromFilters(filters) {
  const ips = [];
  for (const f of filters || []) {
    if (f.field !== 'switch_ip') continue;
    if (!['=', 'in'].includes(f.op)) continue;
    String(f.value || '')
      .split(/[\s,]+/)
      .map((v) => v.trim())
      .filter(Boolean)
      .forEach((ip) => ips.push(ip));
  }
  return [...new Set(ips)].join(',');
}

function TcpFlagsFilter({ value, onChange, onClear }) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState(null);
  const rootRef = React.useRef(null);
  const addRef = React.useRef(null);
  const menuRef = React.useRef(null);
  const flags = tcpFlagsMapFromValue(value);
  const selected = EXPLORER_TCP_FLAG_NAMES.filter((name) => flags[name]);
  const allSelected = selected.length === EXPLORER_TCP_FLAG_NAMES.length;

  const toggleFlag = (name) => {
    const next = { ...flags, [name]: !flags[name] };
    const arr = EXPLORER_TCP_FLAG_NAMES.filter((n) => next[n]);
    onChange({ value: tcpFlagsArrayToValue(arr), label: null });
  };

  const setAllFlags = (on) => {
    onChange({
      value: on ? EXPLORER_TCP_FLAG_NAMES.join(',') : '',
      label: null,
    });
  };

  React.useLayoutEffect(() => {
    if (!open) {
      setMenuStyle(null);
      return undefined;
    }
    const anchor = addRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      setMenuStyle({
        position: 'fixed',
        top: rect.bottom + 6,
        left: Math.max(8, rect.left),
        width: 220,
        maxHeight: 360,
        zIndex: 1400,
        overflowY: 'auto',
      });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open]);

  React.useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (menuRef.current?.contains(e.target) || addRef.current?.contains(e.target)) return;
      if (rootRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const embeddedMenu = open && menuStyle ? ReactDOM.createPortal(
    <div
      ref={menuRef}
      className="direction-filter__menu direction-filter__menu--portal"
      style={menuStyle}
      role="menu"
    >
      <div className="time-filter__heading">
        <span>TCP flags</span>
        <button
          type="button"
          className="time-filter__link"
          onClick={() => setAllFlags(!allSelected)}
        >
          {allSelected ? 'Снять все' : 'Выбрать все'}
        </button>
      </div>
      <div className="time-filter__section time-filter__section--directions">
        {EXPLORER_TCP_FLAG_NAMES.map((name) => {
          const on = !!flags[name];
          return (
            <label key={name} className={`direction-option ${on ? 'is-on' : ''}`}>
              <input
                type="checkbox"
                checked={on}
                onChange={() => toggleFlag(name)}
              />
              <span className="direction-option__label mono">{name}</span>
            </label>
          );
        })}
      </div>
    </div>,
    document.body,
  ) : null;

  return (
    <div className="direction-filter direction-filter--embedded direction-filter--chips" ref={rootRef}>
      <div className="direction-filter__chips">
        {selected.map((name) => (
          <span key={name} className="badge badge--info direction-chip">
            <span className="direction-chip__label mono">{name}</span>
            <button
              type="button"
              className="direction-chip__remove"
              title={`Убрать ${name}`}
              onClick={() => toggleFlag(name)}
            >
              <Icon name="x" size={10} stroke={2.5} />
            </button>
          </span>
        ))}
        {selected.length === 0 && (
          <span className="direction-filter__empty-hint">Выберите флаги…</span>
        )}
        <div className="direction-filter__add" ref={addRef}>
          <Button
            kind="ghost"
            size="xs"
            icon="plus"
            type="button"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            Флаг
          </Button>
        </div>
        {selected.length > 0 && onClear && (
          <Button kind="ghost" size="xs" type="button" onClick={onClear}>Очистить</Button>
        )}
      </div>
      {embeddedMenu}
    </div>
  );
}

function FilterValueInput({ fieldId, meta, value, label, onChange, onClear, switchIpScope = '', fullWidth = false }) {
  const controlStyle = fullWidth ? { width: '100%', flex: 'none', minWidth: 0 } : { flex: 1, minWidth: 0 };
  const scopeHint = explorerInterfaceScopeHint(fieldId, switchIpScope);
  const valueControl = meta?.entityType ? (
    <EntityPicker
      entityType={meta.entityType}
      value={value}
      label={label}
      placeholder={meta.valueHint}
      switchIp={meta.entityType === 'if_name' ? switchIpScope : ''}
      onSelect={(item) => onChange({ value: item.value, label: item.label })}
      onClear={onClear}
      fullWidth={fullWidth}
    />
  ) : meta?.valueOptions?.length ? (
    <FilterSearchPicker
      items={meta.valueOptions}
      value={value}
      onChange={(next) => onChange({ value: next, label: null })}
      buttonLabel={value
        ? (meta.valueOptions.find((item) => String(item.value ?? item.id) === String(value))?.label || String(value))
        : undefined}
      searchPlaceholder="Поиск значения..."
      emptyLabel="Выбрать значение…"
      inputPlaceholder={meta.valueHint}
      allowCustom
      mono
      fullWidth={fullWidth}
      style={controlStyle}
    />
  ) : (
    <input
      className="input mono"
      value={value ?? ''}
      placeholder={meta?.valueHint || 'value'}
      title={meta?.valueHint || undefined}
      onChange={(e) => onChange({ value: e.target.value, label: null })}
      style={controlStyle}
    />
  );

  if (!scopeHint) return valueControl;

  return (
    <div className="explorer-filter-value-wrap">
      {valueControl}
      <div className="explorer-filter-scope-hint">{scopeHint}</div>
    </div>
  );
}

function ExplorerGroupCell({
  displayValue,
  monoClass,
  filterTitle,
  onAddFilter,
  showColorSwatch,
  color,
}) {
  const text = displayValue == null || displayValue === '' ? '—' : String(displayValue);

  return (
    <div className="explorer-dim-cell">
      {showColorSwatch && (
        <span className="explorer-dim-cell__swatch" style={{ background: color }} aria-hidden="true" />
      )}
      <div className="explorer-dim-cell__main">
        <button
          type="button"
          className="explorer-dim-cell__filter"
          onClick={(e) => {
            e.stopPropagation();
            onAddFilter();
          }}
          title={filterTitle}
        >
          <OverflowText
            value={text}
            mode="end"
            className={monoClass}
          />
        </button>
      </div>
    </div>
  );
}

function buildExplorerResultColumns({
  groupBy,
  dimensions,
  dimensionById,
  metricLabel,
  metric,
  meta,
  showAllMetrics,
  onAddFilter,
  onFocusRow,
  onExcludeRow,
  chartSeriesIds,
  onToggleDynamicsSeries,
  showOthersOnChart = false,
  onToggleOthersOnChart,
}) {
  const visibleDimensionIds = groupBy;
  const hasMaskedIpGroup = groupBy.some((token) => {
    const mask = explorerGroupMask(token);
    return mask != null && mask !== EXPLORER_GROUP_MASK_DEFAULT;
  });

  const groupCols = visibleDimensionIds.map((groupToken, colIdx) => {
    const dimId = explorerGroupFieldId(groupToken);
    const mask = explorerGroupMask(groupToken);
    const valueIdx = groupBy.indexOf(groupToken);
    const hasValue = valueIdx >= 0;
    const isAsn = dimId.endsWith('asn');
    return {
      key: `dim-${groupToken}`,
      title: explorerGroupLabel(groupToken, dimensionById),
      width: 160,
      minWidth: 72,
      maxWidth: 520,
      headerClassName: 'explorer-col-dim',
      cellClassName: 'explorer-col-dim',
      sortAccessor: (r) => {
        if (!hasValue) return '';
        if (isAsn) return explorerAsnSortKey(r, valueIdx);
        return r.values[valueIdx];
      },
      render: (r) => {
        if (!hasValue) {
          return <span style={{ color: 'var(--fg-secondary)' }}>—</span>;
        }
        if (r.isOthers) {
          return colIdx === 0
            ? (
              <span
                className="row"
                style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--fg-secondary)' }}
                title="Весь трафик за вычетом показанных строк"
              >
                <span style={{ width: 10, height: 10, borderRadius: 3, background: r.color, flexShrink: 0 }} />
                <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.values[valueIdx]}</span>
              </span>
            )
            : <span style={{ color: 'var(--fg-secondary)' }}>—</span>;
        }
        const filterVal = mask != null && mask !== EXPLORER_GROUP_MASK_DEFAULT
          ? { value: r.values[valueIdx], label: null }
          : explorerRowFilterValue(r, dimId, valueIdx, dimensionById);
        const monoClass = dimId.endsWith('ip') || dimId.endsWith('_mac') ? 'mono' : '';
        const isTcpFlags = dimId === 'tcp_flags';
        const rawTooltip = isTcpFlags && r.rawValues?.[valueIdx] != null
          ? ` · raw ${r.rawValues[valueIdx]}`
          : '';
        const showColorSwatch = dimId !== 'dst_ip' && (colIdx === 0 || chartSeriesIds?.has(r.id));
        const displayValue = isAsn ? explorerAsnDisplayValue(r, valueIdx) : r.values[valueIdx];
        return (
          <ExplorerGroupCell
            displayValue={displayValue}
            monoClass={monoClass}
            filterTitle={`Добавить в фильтры${rawTooltip}`}
            onAddFilter={() => onAddFilter(dimId, filterVal.value, filterVal.label, mask)}
            showColorSwatch={showColorSwatch}
            color={r.color}
          />
        );
      },
    };
  });

  const metricCol = {
    key: 'metric',
    title: metricLabel,
    align: 'right',
    width: 112,
    minWidth: 72,
    maxWidth: 220,
    num: true,
    headerClassName: 'explorer-col-metric',
    cellClassName: 'explorer-col-metric',
    sortAccessor: (r) => r.metric,
    render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{formatMetric(r.metric, metric)}</span>,
  };

  const pctCol = {
    key: 'pct',
    title: `Доля · ${metricLabel}`,
    align: 'right',
    width: 88,
    minWidth: 72,
    maxWidth: 200,
    num: true,
    headerClassName: 'explorer-col-pct',
    cellClassName: 'explorer-col-pct',
    sortAccessor: (r) => r.pct,
    render: (r) => <span className="mono">{r.pct.toFixed(2)}%</span>,
  };

  const actionsCol = {
    key: 'actions',
    title: 'Действия',
    width: 248,
    resizable: false,
    sortAccessor: () => '',
    headerClassName: 'explorer-col-actions',
    cellClassName: 'explorer-col-actions',
    render: (r) => (r.isOthers ? (
      <div className="explorer-row-actions row" onClick={(e) => e.stopPropagation()}>
        <ExplorerChartToggleButton
          onChart={showOthersOnChart}
          onClick={onToggleOthersOnChart}
        />
      </div>
    ) : (
      <ExplorerRowActions
        row={r}
        onFocus={onFocusRow}
        onExclude={hasMaskedIpGroup ? null : onExcludeRow}
        chartSeriesIds={chartSeriesIds}
        onToggleDynamicsSeries={onToggleDynamicsSeries}
      />
    )),
  };

  const baseCols = [...groupCols, metricCol, pctCol];
  if (!showAllMetrics) return [...baseCols, actionsCol];
  return [...baseCols, ...buildExplorerMetricColumnDefs(meta), actionsCol];
}

function createExplorerApi(cabinetMode) {
  if (!cabinetMode) {
    return {
      loadSchema: () => ApiClient.loadExplorerSchema(),
      loadQuery: (opts) => ApiClient.loadExplorerQuery(opts),
      exportCsv: (opts) => ApiClient.exportExplorerCsv(opts),
      loadSavedFilters: () => ApiClient.loadExplorerSavedFilters(),
      searchEntities: (opts) => ApiClient.searchExplorerEntities(opts),
      loadSharedSnapshot: (token) => ApiClient.loadExplorerSharedSnapshot(token, false),
      shareSnapshot: (id) => ApiClient.shareExplorerSnapshot(id, false),
      supportsSavedFilters: true,
      supportsObservations: true,
      maxRangeDays: EXPLORER_MAX_RANGE_DAYS,
    };
  }
  return {
    loadSchema: () => ApiClient.loadCabinetExplorerSchema(),
    loadQuery: (opts) => ApiClient.loadCabinetExplorerQuery(opts),
    exportCsv: (opts) => ApiClient.exportCabinetExplorerCsv(opts),
    loadSavedFilters: () => Promise.resolve([]),
    searchEntities: () => Promise.resolve([]),
    loadSharedSnapshot: (token) => ApiClient.loadExplorerSharedSnapshot(token, true),
    shareSnapshot: (id) => ApiClient.shareExplorerSnapshot(id, true),
    supportsSavedFilters: false,
    supportsObservations: false,
    maxRangeDays: 6,
  };
}

function formatSnapshotTimestamp(value, displayTimezone) {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString('ru-RU', displayTimezone ? { timeZone: displayTimezone } : undefined);
  } catch {
    return String(value);
  }
}

function PageExplorer({ onNavigate, displayTimezone, cabinetMode = false, readOnly = false }) {
  const explorerApi = useMemo(() => createExplorerApi(cabinetMode), [cabinetMode]);
  const canWrite = !cabinetMode && !readOnly && AuthAccess.canWritePage('explorer');
  const urlGlobals = useMemo(() => readExplorerUrlGlobals(), []);
  const urlState = useMemo(() => {
    const state = readExplorerPageParamsFromHash?.() || null;
    if (!state) return null;
    return {
      ...state,
      filters: migrateExplorerUrlGlobals(urlGlobals, state.filters),
    };
  }, []);
  const [schema, setSchema] = useState(null);
  const [observationCompose, setObservationCompose] = useState(() => {
    try {
      const raw = sessionStorage.getItem('grapes-observation-compose');
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return parsed?.active ? parsed : null;
    } catch {
      return null;
    }
  });
  const composeFilters = Array.isArray(observationCompose?.filters)
    ? observationCompose.filters
    : null;
  const composeGroupBy = Array.isArray(observationCompose?.groupBy) && observationCompose.groupBy.length
    ? observationCompose.groupBy
    : null;
  const composeLookback = observationCompose?.lookback || null;
  const composeThresholds = Array.isArray(observationCompose?.thresholds)
    ? observationCompose.thresholds
    : null;
  const [metric, setMetric] = useState(urlState?.metric || 'bps');
  const [groupBy, setGroupBy] = useState(
    normalizeExplorerGroupTokens(composeGroupBy
      || urlState?.groupBy
      || ['src_ip', 'dst_ip']),
  );
  const [filters, setFilters] = useState(() => {
    // Editing an observation must load THAT observation's filters, not last Explorer query.
    if (composeFilters) return cloneExplorerFilters(composeFilters);
    if (urlState?.filters?.length) return cloneExplorerFilters(urlState.filters);
    const last = loadLastAppliedExplorerQuery(cabinetMode);
    if (last) return cloneExplorerFilters(migrateExplorerSnapshot(last).filters);
    return cloneExplorerFilters(migrateExplorerUrlGlobals(urlGlobals, []));
  });
  const [thresholds, setThresholds] = useState(() => {
    if (composeThresholds) return cloneExplorerThresholdsList(composeThresholds);
    if (urlState?.thresholds?.length) return cloneExplorerThresholdsList(urlState.thresholds);
    const last = loadLastAppliedExplorerQuery(cabinetMode);
    if (last?.thresholds?.length) return cloneExplorerThresholdsList(migrateExplorerSnapshot(last).thresholds);
    return [];
  });
  const [limit, setLimit] = useState(urlState?.limit || EXPLORER_DEFAULT_FETCH_LIMIT);
  const [fetchLimit, setFetchLimit] = useState(EXPLORER_DEFAULT_FETCH_LIMIT);
  const [vis, setVis] = useState(() => normalizeExplorerVis(urlState?.vis));
  const [timeRange, setTimeRange] = useState(composeLookback || urlGlobals.timeRange || '1h');
  const [customPeriod, setCustomPeriod] = useState(urlGlobals.customPeriod || defaultCustomPeriod());
  const [filterMode, setFilterMode] = useState('graphic');
  const [filterText, setFilterText] = useState('');
  const [filterTextError, setFilterTextError] = useState(null);
  const [filterRowErrors, setFilterRowErrors] = useState({});
  const [filterPanel, setFilterPanel] = useState(true);
  const [showSave, setShowSave] = useState(false);
  const [showObservationSave, setShowObservationSave] = useState(false);
  const [editingSaved, setEditingSaved] = useState(null);
  const canWriteObservation = !cabinetMode && (AuthAccess.canWritePage('observations') || canWrite);
  const [hasAppliedQuery, setHasAppliedQuery] = useState(false);
  const [appliedSnapshot, setAppliedSnapshot] = useState(null);
  const [queryVersion, setQueryVersion] = useState(0);
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState(EMPTY_EXPLORER_SUMMARY);
  const [timeseries, setTimeseries] = useState([]);
  const [resultSeries, setResultSeries] = useState(null);
  const [source, setSource] = useState('idle');
  const [error, setError] = useState(null);
  const [meta, setMeta] = useState(null);
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);
  const [snapshotId, setSnapshotId] = useState(null);
  const [shareMeta, setShareMeta] = useState(null);
  const [sharing, setSharing] = useState(false);
  const urlSnapshotToken = urlState?.snapshot || null;
  const [savedFilters, setSavedFilters] = useState(() => (cabinetMode ? [] : DEFAULT_EXPLORER_PRESETS));
  const [lastApplied, setLastApplied] = useState(() => loadLastAppliedExplorerQuery(cabinetMode));
  const [exporting, setExporting] = useState(false);
  const [showAllResultColumns, setShowAllResultColumns] = useState(true);
  const [visualLimit, setVisualLimit] = useState(EXPLORER_DEFAULT_VISUAL_LIMIT);
  const [dynamicsSeriesIds, setDynamicsSeriesIds] = useState(() => new Set());
  const [showOthersOnChart, setShowOthersOnChart] = useState(
    () => explorerDefaultShowOthersOnChart(normalizeExplorerVis(urlState?.vis)),
  );
  const [refreshing, setRefreshing] = useState(false);
  const [periodZoomStack, setPeriodZoomStack] = useState([]);
  const periodRef = React.useRef({ timeRange, customPeriod });
  const dynamicsQueryVersionRef = React.useRef(queryVersion);
  const dynamicsVisualLimitRef = React.useRef(visualLimit);
  const skipDynamicsDefaultRef = React.useRef(false);
  const mountRestoreDoneRef = React.useRef(false);

  useEffect(() => {
    window.__GRAPES_CABINET_EXPLORER__ = cabinetMode;
    return () => { window.__GRAPES_CABINET_EXPLORER__ = false; };
  }, [cabinetMode]);

  useEffect(() => {
    periodRef.current = { timeRange, customPeriod };
  }, [timeRange, customPeriod]);

  const dimensions = schema?.dimensions || [];
  const metrics = schema?.metrics || [];
  const dimensionById = useMemo(() => Object.fromEntries(dimensions.map((d) => [d.id, d])), [dimensions]);
  const usesCabinetClient = useMemo(
    () => explorerUsesCabinetClient({ filters, groupBy }),
    [filters, groupBy],
  );
  const cabinetClientPeriod = useMemo(
    () => (usesCabinetClient ? explorerCabinetClientPeriodOptions(schema) : null),
    [usesCabinetClient, schema],
  );
  const maxRangeDays = explorerRangeLimitDays(schema?.maxRangeDays ?? explorerApi.maxRangeDays);
  const cabinetClientPeriodWarning = useMemo(
    () => explorerCabinetClientPeriodWarning({
      usesCabinetClient,
      cabinetClientPeriod,
      timeRange,
      customPeriod,
    }),
    [usesCabinetClient, cabinetClientPeriod, timeRange, customPeriod],
  );

  const querySetters = useMemo(() => ({
    setTimeRange, setCustomPeriod, setFilters, setThresholds, setMetric, setGroupBy, setLimit, setVis,
  }), []);

  const draftRestoreOpts = useMemo(() => ({ filterMode, setFilterText, schema }), [filterMode, schema]);

  const cacheHydrateHandlers = useMemo(() => ({
    cabinetMode,
    querySetters,
    draftRestoreOpts,
    setFetchLimit,
    setVisualLimit,
    setLimit,
    setDynamicsSeriesIds,
    setRows,
    setSummary,
    setTimeseries,
    setResultSeries,
    setMeta,
    setSource,
    setError,
    setLoadMs,
    setServerMs,
    setAppliedSnapshot,
    setHasAppliedQuery,
    setLastApplied,
    setShowOthersOnChart,
    skipDynamicsDefaultRef,
    dynamicsQueryVersionRef,
  }), [cabinetMode, querySetters, draftRestoreOpts]);

  useEffect(() => {
    if (mountRestoreDoneRef.current) return;
    mountRestoreDoneRef.current = true;

    if (urlSnapshotToken) {
      setSource('loading');
      let cancelled = false;
      explorerApi.loadSharedSnapshot(urlSnapshotToken).then((result) => {
        if (cancelled) return;
        if (!result.ok) {
          setSource('error');
          setError(result.message || ApiClient.LOAD_FAILED);
          return;
        }
        hydrateExplorerFromCachedEntry({
          snapshot: result.snapshot,
          payload: result.payload,
        }, { ...cacheHydrateHandlers, queryVersion: 0 });
        setSource('snapshot');
        setShareMeta(result.shareMeta || null);
        setSnapshotId(result.shareMeta?.id || null);
      }).catch((err) => {
        if (cancelled) return;
        setSource('error');
        setError(err.message || ApiClient.LOAD_FAILED);
      });
      return () => { cancelled = true; };
    }

    // Prefer observation filters when opened via «Изменить фильтры в Explorer».
    if (composeFilters) {
      restoreExplorerDraftFromSnapshot({
        filters: composeFilters,
        groupBy: composeGroupBy || groupBy,
        metric,
        timeRange: composeLookback || timeRange,
        customPeriod,
        limit,
        vis,
      }, querySetters, draftRestoreOpts);
      setFilterPanel(true);
      return;
    }

    const snapshot = urlState
      ? buildSnapshotFromUrl(urlState, urlGlobals)
      : lastApplied;
    if (!snapshot) return;

    const queryKey = buildExplorerQueryKey(snapshot);
    const cached = loadExplorerResultCache(queryKey, cabinetMode);
    const cachedGroupBy = normalizeExplorerGroupTokens(cached?.snapshot?.groupBy);
    const snapshotGroupBy = normalizeExplorerGroupTokens(snapshot.groupBy);
    if (cached && JSON.stringify(cachedGroupBy) === JSON.stringify(snapshotGroupBy)) {
      hydrateExplorerFromCachedEntry(cached, { ...cacheHydrateHandlers, queryVersion: 0 });
      return;
    }

    restoreExplorerDraftFromSnapshot(snapshot, querySetters, draftRestoreOpts);
  }, []);

  const openFilterPanel = () => {
    const snapshot = resolveExplorerDraftSnapshot({
      hasAppliedQuery, appliedSnapshot, lastApplied, source,
    });
    if (snapshot) {
      restoreExplorerDraftFromSnapshot(snapshot, querySetters, draftRestoreOpts);
    }
    setFilterPanel(true);
  };

  useEffect(() => {
    let cancelled = false;
    explorerApi.loadSchema().then((data) => {
      if (!cancelled && data) {
        setSchema(data);
        if (cabinetMode) {
          const allowedDimensions = new Set((data.dimensions || []).map((field) => field.id));
          const allowedFilters = new Set((data.filterFields || []).map((field) => field.id));
          setGroupBy((current) => current.filter((token) => allowedDimensions.has(explorerGroupFieldId(token))));
          setFilters((current) => current.filter((filter) => allowedFilters.has(filter.field)));
          setSavedFilters(builtinExplorerPresetsForSchema(data));
        }
      }
    }).catch(() => {});
    if (explorerApi.supportsSavedFilters) {
      explorerApi.loadSavedFilters().then((items) => {
        if (!cancelled && Array.isArray(items)) {
          setSavedFilters(mergeExplorerSavedFilters(items));
        }
      }).catch(() => {});
    }
    return () => { cancelled = true; };
  }, [explorerApi]);

  useEffect(() => {
    if (filterMode !== 'text') return;
    setFilterText(serializeExplorerFilterDsl({
      timeRange, customPeriod, filters, thresholds, groupBy, schema,
    }));
    setFilterTextError(null);
  }, [filterMode]);

  const applyParsedTextToDraft = (text) => {
    const parsed = parseExplorerFilterDsl(text, schema);
    setTimeRange(parsed.timeRange);
    if (parsed.timeRange === 'custom') setCustomPeriod(parsed.customPeriod);
    setFilters(cloneExplorerFilters(parsed.filters));
    setThresholds(cloneExplorerThresholdsList(parsed.thresholds || []));
    if (parsed.groupBy) setGroupBy(normalizeExplorerGroupTokens(parsed.groupBy));
    setFilterTextError(null);
    return parsed;
  };

  const changeFilterMode = (nextMode) => {
    if (nextMode === filterMode) return;
    if (filterMode === 'text' && nextMode === 'graphic') {
      if (String(filterText || '').trim()) {
        try {
          applyParsedTextToDraft(filterText);
        } catch (err) {
          setFilterTextError(err.message);
          pushToast({ kind: 'error', title: 'Ошибка фильтра', desc: err.message });
          return;
        }
      } else {
        setFilters([]);
        setThresholds([]);
        setFilterTextError(null);
      }
    }
    if (nextMode === 'text') {
      setFilterText(serializeExplorerFilterDsl({
        timeRange, customPeriod, filters, thresholds, groupBy, schema,
      }));
      setFilterTextError(null);
    }
    setFilterMode(nextMode);
  };

  const clearExplorerFilters = () => {
    setFilters([]);
    setGroupBy([]);
    setFilterText(serializeExplorerFilterDsl({
      timeRange,
      customPeriod,
      filters: [],
      thresholds,
      groupBy: [],
      schema,
    }));
    setFilterTextError(null);
    setFilterRowErrors({});
  };

  const availableMetrics = useMemo(
    () => (metrics.length ? metrics : [{ id: 'bps', label: 'Средняя бит/с' }])
      .filter((m) => !(m.id === 'uniq_src' && groupBy.some((g) => explorerGroupFieldId(g) === 'src_ip'))),
    [metrics, groupBy],
  );

  useEffect(() => {
    if (metric === 'uniq_src' && groupBy.some((g) => explorerGroupFieldId(g) === 'src_ip')) setMetric('bps');
  }, [groupBy, metric]);

  const activeQuery = useMemo(
    () => (hasAppliedQuery && appliedSnapshot ? migrateExplorerSnapshot(appliedSnapshot) : null),
    [hasAppliedQuery, appliedSnapshot],
  );

  const appliedMetric = activeQuery?.metric ?? metric;
  const appliedGroupBy = activeQuery?.groupBy ?? groupBy;
  const appliedTimeRange = activeQuery?.timeRange ?? timeRange;
  const appliedCustomPeriod = activeQuery?.customPeriod ?? customPeriod;

  useEffect(() => {
    if (!hasAppliedQuery || !appliedSnapshot || queryVersion === 0) return undefined;
    let cancelled = false;
    const isRefresh = rows.length > 0;
    if (isRefresh) setRefreshing(true);
    else {
      setSource('loading');
      setError(null);
    }
    const migrated = migrateExplorerSnapshot(appliedSnapshot);
    const {
      timeRange: qTimeRange,
      customPeriod: qCustomPeriod,
      filters: qFilters,
      thresholds: qThresholds,
      metric: qMetric,
      groupBy: qGroupBy,
    } = migrated;
    const { validThresholds } = resolveExplorerThresholdPayload(qThresholds, schema);
    explorerApi.loadQuery({
      metric: qMetric,
      groupBy: qGroupBy,
      filters: (qFilters || []).map(normalizeExplorerFilter),
      thresholds: validThresholds,
      limit: fetchLimit,
      timeRange: qTimeRange,
      customPeriod: qCustomPeriod,
      includeTimeseries: true,
      includeBreakdowns: false,
    }).then((r) => {
      if (cancelled) return;
      setRows(Array.isArray(r.rows) ? r.rows : []);
      if (r.source !== 'error') {
        const apiRows = Array.isArray(r.rows) ? r.rows : [];
        const resolvedSeriesIds = defaultDynamicsSeriesIds(apiRows, visualLimit);
        setDynamicsSeriesIds(resolvedSeriesIds);
        const snapshot = buildExplorerQuerySnapshot({
          timeRange: qTimeRange,
          customPeriod: qCustomPeriod,
          filters: qFilters,
          thresholds: qThresholds,
          metric: qMetric,
          groupBy: qGroupBy,
          limit: fetchLimit,
          vis,
          fetchLimit,
          visualLimit,
          dynamicsSeriesIds: [...resolvedSeriesIds],
        });
        saveLastAppliedExplorerQuery(snapshot, cabinetMode);
        setLastApplied(snapshot);
        saveExplorerResultCache({
          cabinetMode,
          snapshot,
          payload: {
            rows: Array.isArray(r.rows) ? r.rows : [],
            summary: r.summary || null,
            timeseries: Array.isArray(r.timeseries) ? r.timeseries : [],
            resultSeries: r.resultSeries || null,
            meta: r.meta || null,
            loadMs: r.loadMs ?? null,
            serverMs: r.serverMs ?? null,
          },
        });
        setSummary(r.summary ? { ...EMPTY_EXPLORER_SUMMARY, ...r.summary } : EMPTY_EXPLORER_SUMMARY);
      }
      setTimeseries(Array.isArray(r.timeseries) ? r.timeseries : []);
      setResultSeries(r.resultSeries || null);
      setMeta(r.meta || null);
      setSource(r.source || 'error');
      setError(r.error || null);
      setLoadMs(r.loadMs ?? null);
      setServerMs(r.serverMs ?? null);
      setSnapshotId(r.snapshotId || null);
      setRefreshing(false);
    }).catch((err) => {
      if (cancelled) return;
      setSource('error');
      setError(err.message || ApiClient.LOAD_FAILED);
      setRefreshing(false);
    });
    return () => { cancelled = true; };
  }, [queryVersion, hasAppliedQuery, appliedSnapshot, fetchLimit]);

  const results = useMemo(
    () => rows.map((row) => enrichExplorerResultRow(row, meta)),
    [rows, meta],
  );

  useEffect(() => {
    if (!hasAppliedQuery || !results.length) {
      if (!results.length) setDynamicsSeriesIds(new Set());
      return;
    }

    const queryChanged = dynamicsQueryVersionRef.current !== queryVersion;
    const limitChanged = dynamicsVisualLimitRef.current !== visualLimit;

    if (queryChanged) {
      dynamicsQueryVersionRef.current = queryVersion;
      dynamicsVisualLimitRef.current = visualLimit;
      setDynamicsSeriesIds(defaultDynamicsSeriesIds(results, visualLimit));
      return;
    }

    if (limitChanged) {
      dynamicsVisualLimitRef.current = visualLimit;
      setDynamicsSeriesIds(defaultDynamicsSeriesIds(results, visualLimit));
      return;
    }

    setDynamicsSeriesIds((prev) => {
      const resultIds = new Set(results.map((r) => r.id));
      const pruned = new Set([...prev].filter((id) => resultIds.has(id)));
      if (pruned.size === 0) return defaultDynamicsSeriesIds(results, visualLimit);
      return pruned;
    });
  }, [queryVersion, visualLimit, rows, hasAppliedQuery, results]);

  const dynamicsSeriesKey = [...dynamicsSeriesIds].sort().join('|');
  useEffect(() => {
    if (!hasAppliedQuery || source === 'error') return;
    updateExplorerResultCacheUi({
      vis,
      visualLimit,
      dynamicsSeriesIds: [...dynamicsSeriesIds],
    }, cabinetMode);
  }, [vis, visualLimit, dynamicsSeriesKey, hasAppliedQuery, source, cabinetMode]);

  const schemaMetrics = metrics.length ? metrics : [{ id: 'bps', label: 'Средняя бит/с' }];
  const metricLabel = availableMetrics.find((m) => m.id === metric)?.label || metric;
  const groupLabels = groupBy.map((g) => explorerGroupLabel(g, dimensionById));
  const appliedMetricLabel = schemaMetrics.find((m) => m.id === appliedMetric)?.label || appliedMetric;
  const appliedGroupLabels = appliedGroupBy.map((g) => explorerGroupLabel(g, dimensionById));
  const appliedDefaultSortKey = appliedMetric === 'volume' ? 'bytes' : appliedMetric === 'bps' ? 'avgBps' : appliedMetric === 'flows' ? 'flows' : 'metric';

  const requeryWithPeriod = (nextTimeRange, nextCustomPeriod) => {
    setTimeRange(nextTimeRange);
    setCustomPeriod(nextCustomPeriod);
    if (!hasAppliedQuery || !appliedSnapshot) return;
    const periodErr = validateExplorerCustomPeriod(
      nextTimeRange === 'custom' ? nextCustomPeriod : {},
      nextTimeRange,
      maxRangeDays,
    );
    if (periodErr) {
      pushToast({ kind: 'error', title: 'Неверный период', desc: periodErr });
      return;
    }
    setAppliedSnapshot({
      ...appliedSnapshot,
      timeRange: nextTimeRange,
      customPeriod: nextCustomPeriod,
    });
    setQueryVersion((v) => v + 1);
  };

  const applyExplorerChartRangeZoom = (range) => {
    if (!range?.from || !range?.to || validateExplorerCustomPeriod(range, 'custom', maxRangeDays)) return;
    setPeriodZoomStack((stack) => [...stack, periodRef.current]);
    requeryWithPeriod('custom', { from: range.from, to: range.to });
  };

  const resetExplorerChartRangeZoom = () => {
    if (!periodZoomStack.length) return;
    const prev = periodZoomStack[periodZoomStack.length - 1];
    setPeriodZoomStack((stack) => stack.slice(0, -1));
    requeryWithPeriod(prev.timeRange, prev.customPeriod);
  };

  const replaceExplorerUrl = (snapshot) => {
    if (cabinetMode || typeof buildExplorerShareUrl !== 'function') return;
    const url = buildExplorerShareUrl({
      metric: snapshot.metric,
      groupBy: snapshot.groupBy,
      filters: snapshot.filters,
      thresholds: snapshot.thresholds,
      limit: snapshot.limit,
      vis: snapshot.vis,
      timeRange: snapshot.timeRange,
      customPeriod: snapshot.customPeriod,
    });
    window.history.replaceState(window.history.state, '', url);
  };

  const runQuery = () => {
    let snapshot = buildExplorerQuerySnapshot({
      timeRange, customPeriod, filters, thresholds, metric, groupBy, limit, vis,
    });
    let activeFilters = filters;
    let activeThresholds = thresholds;
    if (filterMode === 'text') {
      try {
        const parsed = applyParsedTextToDraft(filterText);
        activeFilters = parsed.filters;
        activeThresholds = parsed.thresholds || [];
        const activeGroupBy = normalizeExplorerGroupTokens(parsed.groupBy ?? groupBy);
        snapshot = {
          ...snapshot,
          timeRange: parsed.timeRange,
          customPeriod: parsed.customPeriod,
          filters: parsed.filters,
          thresholds: cloneExplorerThresholdsList(activeThresholds),
          groupBy: activeGroupBy,
        };
      } catch (err) {
        setFilterTextError(err.message);
        pushToast({ kind: 'error', title: 'Ошибка фильтра', desc: err.message });
        return;
      }
    }

    const { validFilters, warnings, rowErrors } = validateExplorerFilterRows(activeFilters, schema);
    setFilterRowErrors(rowErrors);
    if (warnings.length) {
      pushToast({
        kind: 'warning',
        title: 'Проверьте фильтры',
        desc: warnings.slice(0, 3).join('; ') + (warnings.length > 3 ? ` (+${warnings.length - 3})` : ''),
      });
    } else {
      setFilterRowErrors({});
    }

    snapshot = { ...snapshot, filters: validFilters, thresholds: cloneExplorerThresholdsList(activeThresholds) };

    const periodErr = validateExplorerCustomPeriod(
      snapshot.timeRange === 'custom' ? snapshot.customPeriod : {},
      snapshot.timeRange,
      maxRangeDays,
    );
    if (periodErr) {
      pushToast({ kind: 'error', title: 'Неверный период', desc: periodErr });
      return;
    }
    const snapshotUsesCabinetClient = explorerUsesCabinetClient({
      filters: snapshot.filters,
      groupBy: snapshot.groupBy,
    });
    if (snapshotUsesCabinetClient) {
      const periodOpts = explorerCabinetClientPeriodOptions(schema);
      const durationMs = explorerPeriodDurationMs(snapshot.timeRange, snapshot.customPeriod);
      if (durationMs != null && durationMs > periodOpts.recommendedRangeMs) {
        pushToast({
          kind: 'warning',
          title: 'Длинный период',
          desc: periodOpts.rangeWarningMessage,
        });
      }
    }
    if (filterMode === 'graphic' && validFilters.length !== activeFilters.length) {
      setFilters(validFilters);
    }
    skipDynamicsDefaultRef.current = false;
    setDynamicsSeriesIds(new Set());
    setShowOthersOnChart(explorerDefaultShowOthersOnChart(snapshot.vis ?? vis));
    const nextAppliedSnapshot = buildExplorerQuerySnapshot({
      ...snapshot,
      limit: resolveExplorerFetchLimit(snapshot.limit ?? limit),
      fetchLimit: resolveExplorerFetchLimit(snapshot.limit ?? limit),
      visualLimit: EXPLORER_DEFAULT_VISUAL_LIMIT,
      dynamicsSeriesIds: [],
    });
    setGroupBy(nextAppliedSnapshot.groupBy);
    setAppliedSnapshot(nextAppliedSnapshot);
    replaceExplorerUrl(nextAppliedSnapshot);
    setHasAppliedQuery(true);
    setFetchLimit(resolveExplorerFetchLimit(snapshot.limit ?? limit));
    setVisualLimit(EXPLORER_DEFAULT_VISUAL_LIMIT);
    setLimit(EXPLORER_DEFAULT_VISUAL_LIMIT);
    setQueryVersion((v) => v + 1);
  };

  const applySavedQuery = (query) => {
    const q = query.query || query;
    const snapshot = migrateExplorerSnapshot({
      timeRange: q.timeRange || timeRange,
      customPeriod: q.customPeriod || customPeriod,
      directions: q.directions,
      collectorFilter: q.collectorFilter,
      filters: q.filters || query.filters || [],
      metric: q.metric || query.metric || 'bps',
      groupBy: Array.isArray(q.groupBy)
        ? q.groupBy
        : Array.isArray(query.groupBy)
          ? query.groupBy
          : ['src_ip'],
      limit: q.limit || query.limit || EXPLORER_DEFAULT_FETCH_LIMIT,
      vis: q.vis || query.vis || vis,
    });
    applyExplorerQuerySnapshot(snapshot, querySetters);
    setMetric(snapshot.metric);
    setGroupBy(normalizeExplorerGroupTokens(snapshot.groupBy));
    setFetchLimit(resolveExplorerFetchLimit(snapshot.limit));
    setVis(normalizeExplorerVis(snapshot.vis));
    setVisualLimit(EXPLORER_DEFAULT_VISUAL_LIMIT);
    setLimit(EXPLORER_DEFAULT_VISUAL_LIMIT);
    skipDynamicsDefaultRef.current = false;
    setDynamicsSeriesIds(new Set());
    setShowOthersOnChart(explorerDefaultShowOthersOnChart(snapshot.vis ?? vis));
    setAppliedSnapshot(snapshot);
    setHasAppliedQuery(true);
    setQueryVersion((v) => v + 1);
  };

  const applyLastApplied = () => {
    if (!lastApplied) return;
    const queryKey = buildExplorerQueryKey(lastApplied);
    const cached = loadExplorerResultCache(queryKey, cabinetMode);
    if (cached && hydrateExplorerFromCachedEntry(cached, { ...cacheHydrateHandlers, queryVersion })) {
      return;
    }
    applyExplorerQuerySnapshot(migrateExplorerSnapshot(lastApplied), querySetters);
    setMetric(lastApplied.metric || metric);
    setGroupBy(normalizeExplorerGroupTokens(lastApplied.groupBy || groupBy));
    setFetchLimit(resolveExplorerFetchLimit(lastApplied.fetchLimit ?? lastApplied.limit));
    setVis(normalizeExplorerVis(lastApplied.vis));
    setVisualLimit(lastApplied.visualLimit ?? EXPLORER_DEFAULT_VISUAL_LIMIT);
    setLimit(lastApplied.visualLimit ?? EXPLORER_DEFAULT_VISUAL_LIMIT);
    skipDynamicsDefaultRef.current = false;
    setDynamicsSeriesIds(new Set());
    setShowOthersOnChart(explorerDefaultShowOthersOnChart(lastApplied.vis));
    setAppliedSnapshot(lastApplied);
    setHasAppliedQuery(true);
    setQueryVersion((v) => v + 1);
  };

  const restoreLastAppliedToDraft = () => {
    if (!lastApplied) return;
    restoreExplorerDraftFromSnapshot(lastApplied, querySetters, draftRestoreOpts);
    pushToast({ kind: 'success', title: 'Фильтр загружен', desc: 'Последний применённый фильтр восстановлен в конструктор.' });
  };

  const saveCurrentQuery = async ({ name, description, folder, isShared, id }) => {
    const queryPayload = buildExplorerQuerySnapshot({
      timeRange, customPeriod, filters, thresholds, metric, groupBy, limit, vis,
    });
    try {
      if (id) {
        await ApiClient.updateExplorerFilter(id, {
          name: name.trim() || `${metricLabel} · ${groupLabels.join(' × ')}`,
          description,
          folder,
          isShared: Boolean(isShared),
          query: queryPayload,
        });
      } else {
        await ApiClient.saveExplorerFilter({
          name: name.trim() || `${metricLabel} · ${groupLabels.join(' × ')}`,
          description,
          folder,
          isShared: Boolean(isShared),
          query: queryPayload,
        });
      }
      const items = await ApiClient.loadExplorerSavedFilters();
      setSavedFilters(mergeExplorerSavedFilters(items));
      pushToast({ kind: 'success', title: id ? 'Фильтр обновлён' : 'Фильтр сохранён', desc: 'Он доступен в блоке «Сохранённые».' });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось сохранить', desc: err.message });
    }
  };

  const clearObservationCompose = () => {
    try { sessionStorage.removeItem('grapes-observation-compose'); } catch { /* ignore */ }
    setObservationCompose(null);
  };

  const openSaveAsObservation = () => {
    const { validThresholds } = resolveExplorerThresholdPayload(thresholds, schema);
    if (!filters?.length && !validThresholds.length) {
      pushToast({ kind: 'error', title: 'Нужен фильтр или порог', desc: 'Добавьте хотя бы одно условие или порог, затем «Добавить в наблюдения».' });
      return;
    }
    setShowObservationSave(true);
  };

  const saveAsObservation = async ({ name, lookback, materializeEnabled, reportEnabled, reportPeriod, topGroup }) => {
    const nextFilters = (filters || []).map((f, i) => ({
      id: f.id || `f-${i}`,
      field: f.field,
      op: f.op || '=',
      value: f.value ?? '',
      label: f.label ?? null,
      logic: f.logic || 'and',
    })).filter((f) => f.field);
    const { validThresholds } = resolveExplorerThresholdPayload(thresholds, schema);

    // Rollup наблюдений хранит только dim0/dim1 — глубже двух измерений разрез
    // не доедет до графика, поэтому режем здесь, а не молча теряем в воркере.
    const chartGroup = ((groupBy || []).length
      ? [...groupBy]
      : [topGroup || 'src_asn']).slice(0, OBSERVATION_MAX_GROUP_BY);

    try {
      let id = observationCompose?.editId || null;
      if (id) {
        const existing = await ApiClient.loadObservation(id);
        const existingChartStyle = (existing.widgets || []).find((w) => w.type === 'timeseries_bps')?.chartStyle;
        await ApiClient.updateObservation(id, {
          ...existing,
          name: (name || '').trim() || existing.name,
          filters: nextFilters,
          thresholds: validThresholds,
          widgets: [
            {
              id: 'w-ts',
              type: 'timeseries_bps',
              metric: metric || 'bps',
              groupBy: chartGroup,
              chartStyle: existingChartStyle === 'lines' ? 'lines' : 'stack',
              seriesLimit: 8,
              limit: null,
            },
            {
              id: 'w-top',
              type: 'top_table',
              metric: metric || 'bps',
              groupBy: chartGroup,
              limit: 15,
            },
          ],
        });
        pushToast({ kind: 'success', title: 'Фильтры наблюдения обновлены', desc: name || existing.name });
      } else {
        const payload = {
          name: (name || '').trim() || `Наблюдение · ${metricLabel}`,
          description: '',
          lookback: lookback || '1h',
          filters: nextFilters,
          thresholds: validThresholds,
          widgets: [
            {
              id: 'w-ts',
              type: 'timeseries_bps',
              metric: metric || 'bps',
              groupBy: chartGroup,
              chartStyle: 'stack',
              seriesLimit: 10,
              limit: null,
            },
            {
              id: 'w-top',
              type: 'top_table',
              metric: metric || 'bps',
              groupBy: chartGroup,
              limit: 100,
            },
          ],
          materialize: { enabled: materializeEnabled !== false },
          report: {
            enabled: !!reportEnabled,
            period: reportPeriod || 'yesterday',
            cron: '0 8 * * *',
            timezone: 'Europe/Moscow',
            formats: ['html', 'csv'],
            emailTo: [],
          },
        };
        const res = await ApiClient.createObservation(payload);
        id = res.data?.id;
        pushToast({ kind: 'success', title: 'Добавлено в наблюдения', desc: payload.name });
      }
      clearObservationCompose();
      setShowObservationSave(false);
      if (id) {
        try { sessionStorage.setItem('grapes-observation-open', id); } catch { /* ignore */ }
      }
      if (typeof onNavigate === 'function') onNavigate('observations');
      else location.hash = 'observations';
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось сохранить наблюдение', desc: err.message });
    }
  };

  const deleteSavedFilter = async (query) => {
    if (isBuiltinExplorerPreset(query)) return;
    if (!window.confirm(`Удалить сохранённый фильтр «${query.name}»?`)) return;
    try {
      await ApiClient.deleteExplorerFilter(query.id);
      const items = await ApiClient.loadExplorerSavedFilters();
      setSavedFilters(mergeExplorerSavedFilters(items));
      pushToast({ kind: 'success', title: 'Фильтр удалён', desc: query.name });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить', desc: err.message });
    }
  };

  const copyFilterShareLink = async () => {
    const { validThresholds } = resolveExplorerThresholdPayload(thresholds, schema);
    const url = buildExplorerShareUrl({
      metric,
      groupBy: normalizeExplorerGroupTokens(groupBy),
      filters: filters.map(normalizeExplorerFilter),
      thresholds: validThresholds,
      limit,
      vis,
      timeRange,
      customPeriod,
    });
    try {
      await copyTextToClipboard(url);
      pushToast({ kind: 'success', title: 'Ссылка скопирована', desc: 'URL содержит параметры фильтра.' });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось скопировать', desc: err.message });
    }
  };

  const copyResultsShareLink = async () => {
    if (!snapshotId) {
      pushToast({ kind: 'error', title: 'Нет данных для шаринга', desc: 'Сначала выполните запрос.' });
      return;
    }
    setSharing(true);
    try {
      const data = await explorerApi.shareSnapshot(snapshotId);
      const url = buildExplorerSnapshotShareUrl(data.token);
      await copyTextToClipboard(url);
      setShareMeta((prev) => ({
        ...(prev || {}),
        expiresAt: data.expiresAt,
        sharedAt: data.sharedAt,
      }));
      pushToast({
        kind: 'success',
        title: 'Ссылка скопирована',
        desc: `Сохранённые результаты доступны до ${formatSnapshotTimestamp(data.expiresAt, displayTimezone)}.`,
      });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось создать ссылку', desc: err.message });
    } finally {
      setSharing(false);
    }
  };

  const exportCsv = async () => {
    if (!hasAppliedQuery || !activeQuery) return;
    setExporting(true);
    try {
      const exportPayload = {
        metric: activeQuery.metric,
        groupBy: activeQuery.groupBy,
        filters: (activeQuery.filters || []).map(normalizeExplorerFilter),
        thresholds: resolveExplorerThresholdPayload(activeQuery.thresholds, schema).validThresholds,
      };
      if (meta?.windowFrom && meta?.windowTo) {
        exportPayload.from = meta.windowFrom;
        exportPayload.to = meta.windowTo;
        exportPayload.range = 'custom';
      } else {
        exportPayload.timeRange = activeQuery.timeRange;
        exportPayload.customPeriod = activeQuery.customPeriod;
        if (meta?.windowAnchor) exportPayload.windowAnchor = meta.windowAnchor;
      }
      const blob = await explorerApi.exportCsv(exportPayload);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `explorer-flows-${Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      const periodHint = meta?.windowFrom && meta?.windowTo
        ? `Период таблицы: ${meta.windowFrom} — ${meta.windowTo}.`
        : 'Обновите запрос для точного совпадения периода.';
      pushToast({
        kind: 'success',
        title: 'CSV экспортирован',
        desc: meta?.windowFrom && meta?.windowTo
          ? `Все столбцы, до 10 000 строк. ${periodHint}`
          : 'Все столбцы, до 10 000 строк.',
      });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Экспорт не удался', desc: err.message });
    } finally {
      setExporting(false);
    }
  };

  const addFilterFromCell = (field, value, label, groupMask = null) => {
    const meta = filterFieldMeta(schema, field);
    const op = groupMask != null && groupMask !== EXPLORER_GROUP_MASK_DEFAULT
      ? 'cidr'
      : meta?.type === 'tcp_flags' ? 'eq' : '=';
    setFilters((prev) => [...prev, {
      id: Date.now() + Math.random(),
      field,
      op,
      value,
      label: label || null,
      logic: 'and',
    }]);
    if (hasAppliedQuery) runQuery();
  };

  const applyFiltersAndRun = (nextFilters, toastTitle, toastDesc) => {
    setFilters(nextFilters);
    const snapshot = buildExplorerQuerySnapshot({
      timeRange,
      customPeriod,
      filters: nextFilters,
      metric,
      groupBy,
      limit,
      vis,
    });
    setAppliedSnapshot(snapshot);
    replaceExplorerUrl(snapshot);
    setHasAppliedQuery(true);
    setQueryVersion((v) => v + 1);
    if (toastTitle) {
      pushToast({ kind: 'success', title: toastTitle, desc: toastDesc });
    }
  };

  const focusRow = (row) => {
    const nextFilters = [
      ...filters,
      ...appliedGroupBy.map((groupToken, idx) => {
        const field = explorerGroupFieldId(groupToken);
        const mask = explorerGroupMask(groupToken);
        const filterVal = mask != null && mask !== EXPLORER_GROUP_MASK_DEFAULT
          ? { value: row.values[idx], label: null }
          : explorerRowFilterValue(row, groupToken, idx, dimensionById);
        const isTcpFlags = field === 'tcp_flags' || dimensionById[field]?.kind === 'tcp_flags';
        return {
          id: Date.now() + idx + Math.random(),
          field,
          op: mask != null && mask !== EXPLORER_GROUP_MASK_DEFAULT ? 'cidr' : isTcpFlags ? 'eq' : '=',
          value: filterVal.value,
          label: filterVal.label,
          logic: 'and',
        };
      }),
    ];
    applyFiltersAndRun(nextFilters, 'Фокус на строке', 'Значения строки добавлены в фильтры.');
  };

  const excludeRow = (row) => {
    const nextFilters = [
      ...filters,
      ...appliedGroupBy.map((groupToken, idx) => {
        const field = explorerGroupFieldId(groupToken);
        const filterVal = explorerRowFilterValue(row, groupToken, idx, dimensionById);
        const isTcpFlags = field === 'tcp_flags' || dimensionById[field]?.kind === 'tcp_flags';
        return {
          id: Date.now() + idx + Math.random(),
          field,
          op: isTcpFlags ? 'neq' : '!=',
          value: filterVal.value,
          label: filterVal.label,
          logic: 'and',
        };
      }),
    ];
    applyFiltersAndRun(nextFilters, 'Строка исключена', 'Значения строки добавлены как исключение.');
  };

  const toggleDynamicsSeries = (rowId) => {
    setVis((prev) => (isExplorerDynamicsVis(prev) ? prev : EXPLORER_VIS_DEFAULT));
    setDynamicsSeriesIds((prev) => {
      const next = new Set(prev);
      if (next.has(rowId)) next.delete(rowId);
      else next.add(rowId);
      return next;
    });
  };

  const requestFetchLimit = (nextLimit) => {
    const target = Number(nextLimit);
    if (!Number.isFinite(target) || target <= 0) return;
    if (target <= fetchLimit) {
      setVisualLimit(target);
      setLimit(target);
      return;
    }
    setFetchLimit(target);
    setLimit(target);
    setVisualLimit(target);
  };

  const applyDisplayLimit = (next) => {
    if (next === 'all') {
      setVisualLimit('all');
      setLimit(fetchLimit);
      return;
    }
    const target = Number(next);
    if (!Number.isFinite(target) || target <= 0) return;
    if (EXPLORER_ON_DEMAND_FETCH_LIMITS.includes(target)) {
      if (hasAppliedQuery && fetchLimit < target) {
        requestFetchLimit(target);
      } else {
        setVisualLimit(target);
        setLimit(target);
      }
      return;
    }
    const shown = hasAppliedQuery
      ? Math.min(target, fetchLimit, results.length || target)
      : target;
    setVisualLimit(shown);
    setLimit(shown);
  };

  const toggleOthersOnChart = () => setShowOthersOnChart((v) => !v);

  const changeExplorerVis = (nextVis) => {
    const normalized = normalizeExplorerVis(nextVis);
    setVis(normalized);
    if (isExplorerStackVis(normalized)) setShowOthersOnChart(true);
  };

  const resultTableColumns = useMemo(() => buildExplorerResultColumns({
    groupBy: appliedGroupBy,
    dimensions,
    dimensionById,
    metricLabel: appliedMetricLabel,
    metric: appliedMetric,
    meta,
    showAllMetrics: showAllResultColumns,
    onAddFilter: addFilterFromCell,
    onFocusRow: focusRow,
    onExcludeRow: excludeRow,
    chartSeriesIds: dynamicsSeriesIds,
    onToggleDynamicsSeries: toggleDynamicsSeries,
    showOthersOnChart,
    onToggleOthersOnChart: toggleOthersOnChart,
  }), [appliedGroupBy, dimensions, dimensionById, appliedMetricLabel, appliedMetric, meta, showAllResultColumns, addFilterFromCell, focusRow, excludeRow, toggleDynamicsSeries, dynamicsSeriesIds, showOthersOnChart]);

  const fitExplorerResultColumns = useCallback((columns, tableRows, pinnedRows) => (
    fitExplorerTableColumnWidths(columns, tableRows, pinnedRows, {
      meta,
      metric: appliedMetric,
      groupBy: appliedGroupBy,
    })
  ), [meta, appliedMetric, appliedGroupBy]);

  const visibleResults = useMemo(
    () => sliceExplorerVisualRows(results, visualLimit),
    [results, visualLimit],
  );
  const othersRow = useMemo(() => buildExplorerOthersRow({
    shownRows: visibleResults,
    summary,
    meta,
    metric: appliedMetric,
    groupBy: appliedGroupBy,
  }), [visibleResults, summary, meta, appliedMetric, appliedGroupBy]);
  const othersChartAvailable = Boolean(othersRow);
  const isRefreshingData = refreshing;
  const appliedThresholds = activeQuery?.thresholds || [];
  const thresholdEmptyState = hasAppliedQuery
    && source !== 'loading'
    && !isRefreshingData
    && results.length === 0
    && (meta?.rowsHidden > 0 || (meta?.thresholds?.length > 0) || appliedThresholds.length > 0);
  const clearAllThresholds = () => {
    setThresholds([]);
    if (!hasAppliedQuery || !appliedSnapshot) return;
    setAppliedSnapshot({
      ...migrateExplorerSnapshot(appliedSnapshot),
      thresholds: [],
    });
    setQueryVersion((v) => v + 1);
  };
  const clientThresholdWarning = explorerThresholdApi().shouldShowThresholdPeakWarning?.({
    thresholds: resolveExplorerThresholdPayload(thresholds, schema).validThresholds,
    groupBy,
    timeRange,
    customPeriod,
  });
  const idleState = !hasAppliedQuery && source !== 'loading';

  return (
    <div className="main__container" style={{ maxWidth: 1820, padding: 0 }}>
      <div className="page-head" style={{ padding: '0 4px' }}>
        <div>
          <h1>Разбор трафика</h1>
          <p>Historical flow explorer: фильтры по времени, направлению, коллекторам, сущностям, протоколам, VLAN, ASN, L3 и сервисам.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="link" onClick={copyFilterShareLink}>Поделиться фильтрами</Button>
          <Button
            kind="ghost"
            icon="copy"
            onClick={copyResultsShareLink}
            disabled={!snapshotId || sharing || !hasAppliedQuery}
          >
            {sharing ? 'Ссылка…' : 'Поделиться результатами'}
          </Button>
          <Button kind="ghost" icon="export" onClick={exportCsv} disabled={!hasAppliedQuery || !results.length || exporting}>
            {exporting ? 'Экспорт…' : 'Экспорт'}
          </Button>
        </div>
      </div>

      {(source === 'snapshot') && hasAppliedQuery && (
        <div
          className="row"
          style={{
            gap: 12,
            flexWrap: 'wrap',
            alignItems: 'center',
            padding: '10px 14px',
            margin: '0 4px',
            borderRadius: 10,
            border: '1px solid var(--bd-soft)',
            background: 'rgba(126, 146, 248, 0.08)',
          }}
        >
          <div style={{ flex: 1, minWidth: 220, font: 'var(--pv-text-body-3)' }}>
            Просмотр сохранённого снимка результатов
            {shareMeta?.createdAt ? ` · создан ${formatSnapshotTimestamp(shareMeta.createdAt, displayTimezone)}` : ''}
            {shareMeta?.expiresAt ? ` · доступен до ${formatSnapshotTimestamp(shareMeta.expiresAt, displayTimezone)}` : ''}
          </div>
        </div>
      )}

      <div className="col" style={{ gap: 16, minWidth: 0 }}>
        {observationCompose && (
          <div
            className="row"
            style={{
              gap: 12,
              flexWrap: 'wrap',
              alignItems: 'center',
              padding: '12px 14px',
              borderRadius: 10,
              border: '1px solid var(--bd-soft)',
              background: 'rgba(126, 146, 248, 0.12)',
            }}
          >
            <div style={{ flex: 1, minWidth: 220, font: 'var(--pv-text-body-3)' }}>
              {observationCompose.editId
                ? 'Редактируете фильтры наблюдения. Соберите условия и нажмите «Добавить в наблюдения».'
                : 'Новое наблюдение: соберите фильтр здесь, затем «Добавить в наблюдения».'}
            </div>
            {canWriteObservation && (
              <Button kind="primary" size="sm" onClick={openSaveAsObservation}>
                Добавить в наблюдения
              </Button>
            )}
            <Button kind="ghost" size="sm" onClick={clearObservationCompose}>Отмена</Button>
          </div>
        )}

        {!filterPanel && (
          <Card pad="sm">
            <div className="row" style={{ gap: 14, flexWrap: 'wrap', alignItems: 'center' }}>
              <Button kind="ghost" size="sm" icon="filter" onClick={openFilterPanel}>
                Фильтры
                {filters.length > 0 && <span className="nav-item__badge" style={{ marginLeft: 4 }}>{filters.length}</span>}
              </Button>
              <ExplorerMetricGroupControls
                metric={metric}
                setMetric={setMetric}
                availableMetrics={availableMetrics}
                groupBy={groupBy}
                setGroupBy={setGroupBy}
                dimensionById={dimensionById}
                dimensions={dimensions}
                schema={schema}
                cabinetMode={cabinetMode}
                showGroupBy={filterMode !== 'text'}
              />
            </div>
          </Card>
        )}

        {filterPanel && (
          <ExplorerFilters
            schema={schema}
            filters={filters}
            setFilters={setFilters}
            timeRange={timeRange}
            onTimeRangeChange={setTimeRange}
            customPeriod={customPeriod}
            onCustomPeriodChange={setCustomPeriod}
            displayTimezone={displayTimezone}
            chartZoomDepth={periodZoomStack.length}
            onChartZoomReset={resetExplorerChartRangeZoom}
            filterMode={filterMode}
            onFilterModeChange={changeFilterMode}
            filterText={filterText}
            onFilterTextChange={setFilterText}
            onClearFilters={clearExplorerFilters}
            filterTextError={filterTextError}
            filterRowErrors={filterRowErrors}
            savedQueries={savedFilters}
            lastApplied={lastApplied}
            onApplySaved={applySavedQuery}
            onApplyLastApplied={applyLastApplied}
            onRestoreLastApplied={restoreLastAppliedToDraft}
            onSaveLastApplied={() => {
              if (!lastApplied) return;
              applyExplorerQuerySnapshot(migrateExplorerSnapshot(lastApplied), querySetters);
              setShowSave(true);
            }}
            onCollapse={() => setFilterPanel(false)}
            onRun={runQuery}
            runDisabled={source === 'loading' || refreshing}
            canWrite={canWrite}
            onSave={() => { setEditingSaved(null); setShowSave(true); }}
            onSaveAsObservation={canWriteObservation ? openSaveAsObservation : null}
            onEditSaved={(q) => {
              const payload = migrateExplorerSnapshot(q.query || q);
              applyExplorerQuerySnapshot(payload, querySetters);
              if (payload.metric) setMetric(payload.metric);
              if (Array.isArray(payload.groupBy)) setGroupBy(normalizeExplorerGroupTokens(payload.groupBy));
              if (payload.limit) setLimit(payload.limit);
              if (payload.vis) setVis(normalizeExplorerVis(payload.vis));
              setEditingSaved(q);
              setShowSave(true);
            }}
            onDeleteSaved={deleteSavedFilter}
            thresholds={thresholds}
            setThresholds={setThresholds}
            thresholdPeakWarning={clientThresholdWarning}
            maxRangeDays={maxRangeDays}
            cabinetClientWarning={cabinetClientPeriodWarning}
            cabinetMode={cabinetMode}
            metric={metric}
            setMetric={setMetric}
            groupBy={groupBy}
            setGroupBy={setGroupBy}
            availableMetrics={availableMetrics}
            dimensions={dimensions}
            dimensionById={dimensionById}
          />
        )}

        {idleState ? (
          <Card title="Нет данных" pad="sm">
            <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--fg-secondary)' }}>
              Задайте период, направление, коллекторы и условия фильтрации, затем нажмите «Применить».
            </div>
          </Card>
        ) : (
          <>
            {appliedGroupBy.length === 0 && (
              source === 'loading' || isRefreshingData ? (
                <Card title="Базовые значения" pad="sm">
                  <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>
                    Выполняем запрос…
                  </div>
                </Card>
              ) : source === 'error' ? (
                <Card title="Базовые значения" pad="sm">
                  <div style={{ padding: 32, textAlign: 'center', color: 'var(--st-critical)' }}>
                    {error || ApiClient.LOAD_FAILED}
                  </div>
                </Card>
              ) : (
                <>
                  <ExplorerSummary summary={summary} />
                  <Card
                    title={`Динамика · ${appliedMetricLabel}`}
                    subtitle={`${timeRangeLabel(appliedTimeRange, appliedCustomPeriod)} · ${meta?.dataTable || 'flows_raw'}`}
                    loadMs={loadMs}
                    serverMs={serverMs}
                  >
                    <ExplorerTotalChart
                      points={timeseries}
                      metric={appliedMetric}
                      metricLabel={appliedMetricLabel}
                      displayTimezone={displayTimezone}
                      chartLongRange={isLongChartRange(appliedTimeRange, appliedCustomPeriod)}
                      onRangeSelect={applyExplorerChartRangeZoom}
                      bucketSeconds={explorerGranularityBucketSeconds(meta?.granularity)}
                    />
                  </Card>
                </>
              )
            )}

            {appliedGroupBy.length > 0 && (() => {
              const analysisToolbar = (
                <>
                  <div className="explorer-results-tools__cluster">
                    <ExplorerAnalysisTabs value={vis} onChange={changeExplorerVis} compact />
                    <div className="explorer-results-tools__limit-block">
                      <ExplorerVisualLimitControl
                        total={results.length}
                        fetchLimit={fetchLimit}
                        value={visualLimit}
                        loadingMore={refreshing}
                        onChange={applyDisplayLimit}
                        onRequestFetchLimit={requestFetchLimit}
                      />
                    </div>
                    <Button kind="ghost" size="sm" icon="refresh" onClick={runQuery} />
                  </div>
                  <div className="explorer-results-tools__actions">
                    <Button
                      kind={showAllResultColumns ? 'primary' : 'ghost'}
                      size="sm"
                      icon="sliders"
                      onClick={() => setShowAllResultColumns((v) => !v)}
                    >
                      {showAllResultColumns ? 'Скрыть поля' : 'Все поля'}
                    </Button>
                    {isExplorerDynamicsVis(vis) && (
                      <Button kind="ghost" size="sm" icon="download" onClick={exportCsv} disabled={!hasAppliedQuery || !results.length || exporting}>CSV</Button>
                    )}
                  </div>
                </>
              );

              const analysisBody = isRefreshingData ? (
                <ExplorerRefreshingData />
              ) : source === 'loading' && !results.length ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--fg-secondary)' }}>Выполняем запрос…</div>
              ) : source === 'error' && !results.length ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--st-critical)' }}>{error || ApiClient.LOAD_FAILED}</div>
              ) : thresholdEmptyState ? (
                <div className="explorer-threshold-empty">
                  <p>Нет строк, проходящих порог</p>
                  <Button kind="ghost" size="sm" onClick={clearAllThresholds}>Снять пороги</Button>
                </div>
              ) : results.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--fg-secondary)' }}>
                  Нет данных для выбранных фильтров. Ослабьте фильтры или расширьте период.
                </div>
              ) : null;

              return (
                  <Card
                    className="card--explorer-results"
                    title="Результаты"
                    subtitle="График динамики и таблица: серии по селектору «Показать», отдельные строки — «Показать» / «Скрыть с графика»"
                    loadMs={loadMs}
                    serverMs={serverMs}
                    pad="0"
                    tools={(
                      <div className="explorer-results-tools">
                        {analysisToolbar}
                      </div>
                    )}
                  >
                    {analysisBody || (
                      <div className="explorer-results-layout">
                        <div className="explorer-results-chart">
                          <DynamicsChartExplorer
                            active={isExplorerDynamicsVis(vis)}
                            stackMode={explorerVisToStackMode(vis)}
                            results={results}
                            metric={appliedMetric}
                            metricLabel={appliedMetricLabel}
                            resultSeries={resultSeries}
                            displayTimezone={displayTimezone}
                            chartLongRange={isLongChartRange(appliedTimeRange, appliedCustomPeriod)}
                            selectedSeriesIds={dynamicsSeriesIds}
                            onRangeSelect={applyExplorerChartRangeZoom}
                            bucketSeconds={explorerGranularityBucketSeconds(meta?.granularity)}
                            totalPoints={othersChartAvailable ? timeseries : null}
                            showOthers={showOthersOnChart}
                          />
                        </div>
                        <DataTable
                          rows={visibleResults}
                          rowKey="id"
                          resizableColumns
                          getRowClassName={(row) => {
                            if (row.isOthers) return showOthersOnChart ? 'is-dynamics-active' : '';
                            return dynamicsSeriesIds.has(row.id) ? 'is-dynamics-active' : '';
                          }}
                          pinnedRows={othersRow ? [othersRow] : null}
                          pageSize={Math.max(resolveExplorerVisualCount(visualLimit, results.length), 1)}
                          initialSort={{ key: appliedDefaultSortKey, dir: 'desc' }}
                          emptyTitle={source === 'loading' ? 'Выполняем запрос…' : 'Нет данных'}
                          footerNote={(
                            <>
                              <span>
                                Показано {visibleResults.length} из {results.length} загруженных · {meta?.granularity || 'raw'}
                                {meta?.trafficSampled ? ' · с учётом sampling' : ''}
                                {meta?.rowsHidden > 0 ? ` · Скрыто порогами: ${meta.rowsHidden}` : ''}
                              </span>
                              <span>
                                Запрос выполнен за <b style={{ color: 'var(--fg-primary)' }}>{serverMs ?? '—'} мс</b>
                                {' · ClickHouse · '}{meta?.dataTable || 'flows_raw'}
                              </span>
                            </>
                          )}
                          columns={resultTableColumns}
                          fitColumnWidths={fitExplorerResultColumns}
                        />
                      </div>
                    )}
                  </Card>
              );
            })()}
          </>
        )}
      </div>

      <SaveQueryModal
        open={showSave}
        onClose={() => { setShowSave(false); setEditingSaved(null); }}
        groupBy={groupBy}
        metric={metric}
        filters={filters}
        dimensionById={dimensionById}
        metricLabel={metricLabel}
        editing={editingSaved}
        onSave={saveCurrentQuery}
      />

      <SaveObservationModal
        open={showObservationSave}
        onClose={() => setShowObservationSave(false)}
        filters={filters}
        metricLabel={metricLabel}
        groupBy={groupBy}
        dimensionById={dimensionById}
        timeRange={timeRange}
        editingId={observationCompose?.editId || null}
        initialName={observationCompose?.name || ''}
        onSave={saveAsObservation}
      />
    </div>
  );
}

function ExplorerRefreshingData() {
  return (
    <div className="explorer-refreshing-data">Обновление данных</div>
  );
}

function ExplorerVisualLimitControl({
  total,
  fetchLimit,
  value,
  onChange,
  onRequestFetchLimit,
  loadingMore = false,
}) {
  const shown = resolveExplorerVisualCount(value, total);
  const instantOptions = [5, 10, 25].filter((n) => n <= fetchLimit);
  const canExpandInstant = total > EXPLORER_DEFAULT_VISUAL_LIMIT || fetchLimit > EXPLORER_DEFAULT_VISUAL_LIMIT;

  if (!canExpandInstant && fetchLimit < 50) return null;

  return (
    <div className="explorer-visual-limit">
      <div className="explorer-visual-limit__main row">
        <span className="explorer-visual-limit__summary">
          Загружено {total} · показано {shown}
        </span>
        <div className="seg explorer-visual-limit__seg">
          {instantOptions.map((opt) => (
            <button
              key={String(opt)}
              type="button"
              className={isExplorerDisplayLimitActive(opt, value, fetchLimit) ? 'is-active' : ''}
              disabled={loadingMore}
              onClick={() => onChange(opt)}
            >
              {opt}
            </button>
          ))}
          {EXPLORER_ON_DEMAND_FETCH_LIMITS.map((opt) => {
            const loaded = fetchLimit >= opt;
            const active = loaded && isExplorerDisplayLimitActive(opt, value, fetchLimit);
            return (
              <button
                key={String(opt)}
                type="button"
                className={active ? 'is-active' : ''}
                disabled={loadingMore}
                title={loaded ? `Показать top ${opt}` : `Загрузить top ${opt}`}
                onClick={() => {
                  if (loaded) onChange(opt);
                  else onRequestFetchLimit?.(opt);
                }}
              >
                {loaded ? opt : `+${opt}`}
              </button>
            );
          })}
          {fetchLimit > EXPLORER_DEFAULT_VISUAL_LIMIT && (
            <button
              type="button"
              className={value === 'all' ? 'is-active' : ''}
              disabled={loadingMore}
              onClick={() => onChange('all')}
            >
              Все
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function ExplorerChartToggleButton({ onChart, onClick, disabled = false }) {
  return (
    <button
      type="button"
      className={`badge explorer-row-actions__btn${onChart ? ' badge--info' : ''}`}
      title={onChart ? 'Скрыть серию с графика динамики' : 'Показать серию на графике динамики'}
      disabled={disabled}
      onClick={onClick}
    >
      <ExplorerActionLabel full={onChart ? 'Скрыть с графика' : 'Показать'} short={onChart ? 'Скрыть' : 'Показать'} />
    </button>
  );
}

function ExplorerActionLabel({ full, short }) {
  return (
    <>
      <span className="explorer-row-actions__label explorer-row-actions__label--full">{full}</span>
      <span className="explorer-row-actions__label explorer-row-actions__label--short">{short}</span>
    </>
  );
}

function ExplorerRowActions({
  row,
  onFocus,
  onExclude,
  chartSeriesIds,
  onToggleDynamicsSeries,
}) {
  const onChart = chartSeriesIds?.has(row.id);
  return (
    <div className="explorer-row-actions row" onClick={(e) => e.stopPropagation()}>
      <button type="button" className="badge explorer-row-actions__btn" title="Добавить значения строки в фильтр" onClick={() => onFocus?.(row)}>
        <ExplorerActionLabel full="В фильтр" short="Фильтр" />
      </button>
      <button
        type="button"
        className="badge explorer-row-actions__btn"
        title={onExclude ? 'Исключить значения строки из выборки' : 'Исключение недоступно для группировки по IP-сети'}
        disabled={!onExclude}
        onClick={() => onExclude?.(row)}
      >
        <ExplorerActionLabel full="Исключить" short="Искл." />
      </button>
      <button
        type="button"
        className={`badge explorer-row-actions__btn${onChart ? ' badge--info' : ''}`}
        title={onChart ? 'Скрыть серию с графика динамики' : 'Показать серию на графике динамики'}
        onClick={() => onToggleDynamicsSeries?.(row.id)}
      >
        <ExplorerActionLabel full={onChart ? 'Скрыть с графика' : 'Показать'} short={onChart ? 'Скрыть' : 'Показать'} />
      </button>
    </div>
  );
}

function ExplorerSummary({ summary, loading = false }) {
  const data = { ...EMPTY_EXPLORER_SUMMARY, ...summary };
  const cards = [
    { label: 'Объём / Volume', value: fmtBytes(data.totalBytes) },
    { label: 'Пакетов / Packets', value: fmtNum(data.totalPackets) },
    { label: 'Потоков / Flows', value: fmtNum(data.totalFlows) },
    { label: 'Средняя скорость / Average bitrate', value: fmtBits(data.avgBps) },
    { label: 'Уникальных IP источника / Unique source IPs', value: data.uniqSrc == null ? '—' : fmtNum(data.uniqSrc) },
    { label: 'Unique dst', value: data.uniqDst == null ? '—' : fmtNum(data.uniqDst) },
    { label: 'Ingress', value: fmtBytes(data.inBytes) },
    { label: 'Egress', value: fmtBytes(data.outBytes) },
  ];
  return (
    <div
      className="grid grid--auto-fit-sm grid--gap-sm"
      style={{
        opacity: loading ? 0.65 : 1,
        transition: 'opacity 0.15s ease',
      }}
    >
      {cards.map((c) => (
        <Card key={c.label} pad="sm">
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginBottom: 4 }}>{c.label}</div>
          <div className="mono" style={{ font: 'var(--pv-text-h4)' }}>{c.value}</div>
        </Card>
      ))}
      <Card pad="sm" style={{ gridColumn: 'span 2' }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginBottom: 6 }}>Top protocols</div>
        <div className="row" style={{ gap: 6, flexWrap: 'wrap', minHeight: 22 }}>
          {data.topProtocols?.length > 0 ? (
            data.topProtocols.slice(0, 5).map((p) => <span key={p} className="badge">{p}</span>)
          ) : (
            <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>—</span>
          )}
        </div>
      </Card>
    </div>
  );
}

function BuilderControl({ label, children }) {
  return (
    <div className="col" style={{ gap: 4, minWidth: 0 }}>
      <div style={{ font: 'var(--pv-text-body-3-bold)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-secondary)', fontSize: 10 }}>{label}</div>
      <div className="row" style={{ gap: 4 }}>{children}</div>
    </div>
  );
}

function ExplorerGroupChip({ token, dimension, onChange, onRemove }) {
  const { id, mask } = parseExplorerGroupToken(token);
  const defaultMask = dimension?.maskDefault || EXPLORER_GROUP_MASK_DEFAULT;
  const [draftMask, setDraftMask] = useState(String(mask ?? defaultMask));

  useEffect(() => {
    setDraftMask(String(mask ?? defaultMask));
  }, [mask, defaultMask]);

  const commitMask = (rawValue = draftMask) => {
    const nextToken = formatExplorerGroupToken(id, rawValue);
    const normalizedMask = String(explorerGroupMask(nextToken) ?? defaultMask);
    setDraftMask(normalizedMask);
    if (nextToken !== token) onChange?.(nextToken);
  };

  const handleMaskChange = (rawValue) => {
    setDraftMask(rawValue);
    const trimmed = String(rawValue ?? '').trim();
    if (!/^\d{1,2}$/.test(trimmed)) return;
    const num = Number(trimmed);
    if (num >= 1 && num <= 32) commitMask(trimmed);
  };

  return (
    <span className="explorer-query-chip explorer-group-chip">
      <span className="explorer-query-chip__label">{dimension?.label || id}</span>
      {dimension?.maskable && (
        <>
          <span className="explorer-group-chip__sep" aria-hidden="true">/</span>
          <input
            className="input mono explorer-group-mask-input"
            type="number"
            min={dimension.maskMin || 1}
            max={dimension.maskMax || 32}
            step="1"
            aria-label={`Маска для ${dimension.label || id}`}
            value={draftMask}
            onChange={(e) => handleMaskChange(e.target.value)}
            onBlur={() => commitMask()}
            onKeyDown={(e) => {
              if (e.key === 'Enter') e.currentTarget.blur();
            }}
          />
        </>
      )}
      <button
        type="button"
        className="explorer-query-chip__remove"
        onClick={onRemove}
        aria-label="Удалить измерение"
        title="Удалить измерение"
      >
        <Icon name="x" size={10} stroke={2.5} />
      </button>
    </span>
  );
}

function explorerCatalogConditionCountLabel(count) {
  const n = Number(count) || 0;
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return `${n} условие`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return `${n} условия`;
  return `${n} условий`;
}

function explorerCatalogFieldList(schema, items, { excludeIds = [] } = {}) {
  const exclude = new Set(excludeIds);
  const visible = items.filter((item) => item && !exclude.has(item.id));
  const byId = Object.fromEntries(visible.map((item) => [item.id, item]));
  const catalogs = Object.entries(schema?.dimensionGroups || {})
    .map(([catalogName, fieldIds]) => ({
      id: catalogName,
      label: catalogName,
      fields: (Array.isArray(fieldIds) ? fieldIds : [])
        .map((id) => byId[id])
        .filter(Boolean),
    }))
    .filter((catalog) => catalog.fields.length > 0);
  return { visible, byId, catalogs };
}

function ExplorerCatalogFieldPickerPanel({
  panelRef,
  menuStyle,
  schema,
  items,
  excludeIds = [],
  selectedIds = [],
  onPick,
  searchPlaceholder = 'Поиск...',
  useCatalogs = true,
}) {
  const [q, setQ] = useState('');
  const [activeCatalog, setActiveCatalog] = useState(null);
  const { visible, catalogs } = useMemo(
    () => explorerCatalogFieldList(schema, items, { excludeIds }),
    [schema, items, excludeIds],
  );
  const needle = q.trim();

  useEffect(() => {
    if (needle) setActiveCatalog(null);
  }, [needle]);

  const searchResults = useMemo(() => {
    if (!needle) return [];
    return visible.filter((item) => explorerFieldMatchesQuery(item, needle));
  }, [visible, needle]);

  const activeCatalogEntry = useMemo(
    () => catalogs.find((catalog) => catalog.id === activeCatalog) || null,
    [catalogs, activeCatalog],
  );

  const flatGroups = useMemo(() => {
    const grouped = {};
    visible.forEach((item) => {
      const key = item.group || 'Прочее';
      grouped[key] = grouped[key] || [];
      grouped[key].push(item);
    });
    return grouped;
  }, [visible]);

  if (!menuStyle) return null;

  const itemButtonStyle = {
    all: 'unset',
    display: 'block',
    width: '100%',
    boxSizing: 'border-box',
    padding: '8px 10px',
    borderRadius: 8,
    cursor: 'pointer',
  };

  const renderCatalogButton = (catalog) => (
    <button
      key={catalog.id}
      type="button"
      className="explorer-catalog-picker__catalog"
      onClick={() => setActiveCatalog(catalog.id)}
    >
      <span className="explorer-catalog-picker__catalog-main">
        <span className="explorer-catalog-picker__catalog-label">{catalog.label}</span>
        <span className="explorer-catalog-picker__catalog-meta">
          {explorerCatalogConditionCountLabel(catalog.fields.length)} · нажмите, чтобы раскрыть
        </span>
      </span>
      <Icon name="chevR" size={14} className="explorer-catalog-picker__catalog-chevron" />
    </button>
  );

  const renderFieldButton = (item, { catalogLabel = null } = {}) => {
    const disabled = selectedIds.includes(item.id);
    const hint = item.valueHint || item.hint || null;
    return (
      <button
        key={item.id}
        type="button"
        disabled={disabled}
        onClick={() => { if (!disabled) onPick(item); }}
        style={{
          ...itemButtonStyle,
          cursor: disabled ? 'default' : 'pointer',
          color: disabled ? 'var(--fg-muted)' : 'var(--fg-primary)',
        }}
      >
        <span>{item.label}</span>
        {(catalogLabel || hint) && (
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: 2 }}>
            {[catalogLabel, hint].filter(Boolean).join(' · ')}
          </div>
        )}
      </button>
    );
  };

  let body = null;
  if (needle) {
    body = searchResults.length === 0
      ? <div style={{ padding: '8px 4px', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Ничего не найдено</div>
      : searchResults.map((item) => renderFieldButton(item, { catalogLabel: item.group || null }));
  } else if (useCatalogs && catalogs.length > 0) {
    body = activeCatalogEntry ? (
      <>
        <button
          type="button"
          className="btn btn--ghost btn--sm explorer-catalog-picker__back"
          onClick={() => setActiveCatalog(null)}
        >
          ← {activeCatalogEntry.label}
        </button>
        {activeCatalogEntry.fields.map((item) => renderFieldButton(item))}
      </>
    ) : (
      <>
        <div className="explorer-catalog-picker__hint">Выберите категорию — внутри список условий</div>
        {catalogs.map((catalog) => renderCatalogButton(catalog))}
      </>
    );
  } else {
    body = Object.entries(flatGroups).map(([groupName, groupItems]) => (
      <div key={groupName} className="explorer-picker-group">
        {groupName && <div className="explorer-picker-group__heading">{groupName}</div>}
        {groupItems.map((item) => renderFieldButton(item))}
      </div>
    ));
  }

  return ReactDOM.createPortal(
    <div
      ref={panelRef}
      style={{
        ...menuStyle,
        background: 'var(--bg-surface)',
        border: '1px solid var(--bd-default)',
        borderRadius: 12,
        boxShadow: 'var(--pv-shadow-popover)',
        padding: 8,
      }}
    >
      <input
        className="input"
        placeholder={searchPlaceholder}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        autoFocus
        style={{ marginBottom: 6 }}
      />
      {body}
    </div>,
    document.body,
  );
}

function DimensionPicker({ anchorRef, dimensions, schema, selected, onPick, onClose, cabinetMode = false }) {
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);

  React.useLayoutEffect(() => {
    const anchor = anchorRef?.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      const width = 320;
      setMenuStyle({ position: 'fixed', top: rect.bottom + 6, left: Math.max(8, rect.left), width, maxHeight: 440, zIndex: 1200, overflowY: 'auto' });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => { window.removeEventListener('resize', updatePosition); window.removeEventListener('scroll', updatePosition, true); };
  }, [anchorRef]);

  useEffect(() => {
    const onPointerDown = (e) => {
      if (panelRef.current?.contains(e.target) || anchorRef?.current?.contains(e.target)) return;
      onClose();
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [onClose, anchorRef]);

  return (
    <ExplorerCatalogFieldPickerPanel
      panelRef={panelRef}
      menuStyle={menuStyle}
      schema={schema}
      items={dimensions.filter((d) => d.groupable !== false)}
      selectedIds={selected}
      onPick={(item) => onPick(item.id)}
      searchPlaceholder="Поиск измерения..."
      useCatalogs={!cabinetMode}
    />
  );
}

function EntityPicker({ entityType, value, label, onSelect, onClear, placeholder = 'Поиск сущности...', switchIp = '', fullWidth = false }) {
  const rootRef = React.useRef(null);
  const inputRef = React.useRef(null);
  const menuRef = React.useRef(null);
  const focusedRef = React.useRef(false);
  const [q, setQ] = useState('');
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState(false);
  const [menuStyle, setMenuStyle] = useState(null);

  const visibleItems = useMemo(() => dedupeExplorerEntityItems(items), [items]);

  const displayValue = label || (value != null && value !== '' ? String(value) : '');
  const showComposite = !editing && value != null && value !== '' && label && String(label) !== String(value);

  useEffect(() => {
    if (focusedRef.current || editing) return;
    setQ(displayValue);
  }, [displayValue, editing]);

  useEffect(() => {
    if (!open) {
      setMenuStyle(null);
      return undefined;
    }
    const anchor = rootRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      setMenuStyle({
        position: 'fixed',
        top: rect.bottom + 4,
        left: Math.max(8, rect.left),
        width: Math.max(rect.width, 280),
        maxHeight: 320,
        zIndex: 1400,
        overflowY: 'auto',
      });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open, showComposite, q, visibleItems.length, loading]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (menuRef.current?.contains(e.target) || rootRef.current?.contains(e.target)) return;
      focusedRef.current = false;
      setEditing(false);
      setOpen(false);
      setLoading(false);
      if (value != null && value !== '') setQ(displayValue);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open, displayValue, value]);

  useEffect(() => {
    if (!entityType || !open) return undefined;
    let cancelled = false;
    setLoading(true);
    const timer = setTimeout(() => {
      if (window.__GRAPES_CABINET_EXPLORER__) {
        setItems([]);
        setLoading(false);
        return;
      }
      ApiClient.searchExplorerEntities({ type: entityType, q, limit: 20, switchIp }).then((rows) => {
        if (!cancelled) {
          setItems(rows || []);
          setLoading(false);
        }
      }).catch(() => {
        if (!cancelled) {
          setItems([]);
          setLoading(false);
        }
      });
    }, 200);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [entityType, q, open, switchIp]);

  const handleInputChange = (next) => {
    if (value != null && value !== '' && next !== displayValue) {
      onClear?.();
    }
    setEditing(true);
    setQ(next);
    setOpen(true);
  };

  const beginEdit = () => {
    setEditing(true);
    setOpen(true);
    requestAnimationFrame(() => inputRef.current?.focus());
  };

  const selectItem = (item) => {
    onSelect(item);
    setQ(item.label);
    focusedRef.current = false;
    setEditing(false);
    setOpen(false);
  };

  const pickerMenu = open && menuStyle ? ReactDOM.createPortal(
    <div
      ref={menuRef}
      className="explorer-entity-picker__menu explorer-entity-picker__menu--portal"
      style={menuStyle}
      onMouseDown={(e) => e.preventDefault()}
    >
      {loading ? (
        <div className="explorer-entity-picker__empty">Поиск…</div>
      ) : visibleItems.length === 0 ? (
        <div className="explorer-entity-picker__empty">Ничего не найдено</div>
      ) : visibleItems.map((item) => (
        <button
          key={item.id}
          type="button"
          className={`explorer-entity-picker__item${item.disabled ? ' is-disabled' : ''}${item.hasBinding === false ? ' is-weak' : ''}`}
          disabled={Boolean(item.disabled)}
          title={item.hasBinding === false ? 'Нет CIDR/портов — фильтр сработает только по метке src_client/dst_client' : undefined}
          onMouseDown={(e) => {
            if (item.disabled) return;
            e.preventDefault();
            selectItem(item);
          }}
        >
          <span className="explorer-entity-picker__item-label">{item.label}</span>
          {item.sublabel && (
            <span className="explorer-entity-picker__item-sublabel">{item.sublabel}</span>
          )}
        </button>
      ))}
    </div>,
    document.body,
  ) : null;

  return (
    <div
      ref={rootRef}
      className="explorer-entity-picker"
      style={{ position: 'relative', ...(fullWidth ? { width: '100%', flex: 'none', minWidth: 0 } : { flex: 1, minWidth: 0 }) }}
      aria-expanded={open}
    >
      {showComposite ? (
        <button
          type="button"
          className="explorer-entity-value__display input"
          onClick={beginEdit}
          title={`${label} · ${value}`}
        >
          <span className="explorer-entity-value__label">{label}</span>
          <span className="explorer-entity-value__canonical mono">{value}</span>
        </button>
      ) : (
        <input
          ref={inputRef}
          className="input mono"
          value={q}
          placeholder={placeholder}
          title={placeholder}
          onFocus={() => {
            focusedRef.current = true;
            setEditing(true);
            setOpen(true);
          }}
          onChange={(e) => handleInputChange(e.target.value)}
        />
      )}
      {value != null && value !== '' && (
        <button
          type="button"
          className="icon-btn explorer-entity-picker__clear"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => {
            onClear?.();
            setQ('');
            setItems([]);
            setEditing(true);
            setOpen(true);
            inputRef.current?.focus();
          }}
        >
          <Icon name="x" size={10} />
        </button>
      )}
      {pickerMenu}
    </div>
  );
}

function ExplorerFilterTextEditor({ value, onChange, error, schema, filters = [] }) {
  const textareaRef = React.useRef(null);
  const itemRefs = React.useRef([]);
  const [cursor, setCursor] = useState(0);
  const [activeIndex, setActiveIndex] = useState(0);
  const [entityItems, setEntityItems] = useState([]);
  const [entityLoading, setEntityLoading] = useState(false);
  const [menuStyle, setMenuStyle] = useState(null);
  const [autocompleteOpen, setAutocompleteOpen] = useState(false);

  const switchIpScope = useMemo(
    () => explorerSwitchIpScopeFromFilters(filters) || explorerSwitchIpScopeFromText(value),
    [filters, value],
  );

  const currentLine = useMemo(() => {
    const { start, end } = explorerTextLineBounds(value, cursor);
    return String(value || '').slice(start, end);
  }, [value, cursor]);

  const currentMeta = useMemo(() => {
    const { rest } = parseLogicPrefix(currentLine.trim());
    const field = rest.match(/^([\w.]+)/)?.[1];
    return filterFieldMeta(schema, field);
  }, [schema, currentLine]);

  const entitySearchReady = useMemo(() => {
    if (!currentMeta?.entityType) return false;
    const { rest } = parseLogicPrefix(currentLine.trim());
    return /^[\w.]+\s+\S+/.test(rest);
  }, [currentMeta?.entityType, currentLine]);

  useEffect(() => {
    const entityType = currentMeta?.entityType;
    if (!entityType || !entitySearchReady) {
      setEntityItems([]);
      setEntityLoading(false);
      return undefined;
    }
    const q = explorerTextValueFragment(currentLine);
    let cancelled = false;
    setEntityLoading(true);
    const timer = setTimeout(() => {
      if (window.__GRAPES_CABINET_EXPLORER__) {
        setEntityItems([]);
        setEntityLoading(false);
        return;
      }
      ApiClient.searchExplorerEntities({
        type: entityType,
        q,
        limit: 8,
        switchIp: entityType === 'if_name' ? switchIpScope : '',
      }).then((rows) => {
        if (!cancelled) {
          setEntityItems(rows || []);
          setEntityLoading(false);
        }
      }).catch(() => {
        if (!cancelled) {
          setEntityItems([]);
          setEntityLoading(false);
        }
      });
    }, 180);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [currentMeta?.entityType, currentLine, entitySearchReady, switchIpScope]);

  const suggestions = useMemo(
    () => buildExplorerTextSuggestions({ value, cursor, schema, entityItems }),
    [value, cursor, schema, entityItems],
  );
  const visibleSuggestions = autocompleteOpen ? suggestions : [];
  const showAutocompleteMenu = autocompleteOpen && (
    visibleSuggestions.length > 0 || (entityLoading && entitySearchReady)
  );

  const safeActiveIndex = visibleSuggestions.length
    ? Math.min(activeIndex, visibleSuggestions.length - 1)
    : 0;

  useEffect(() => {
    setActiveIndex(0);
    if (suggestions.length === 0 && !entityLoading) {
      setAutocompleteOpen(false);
    }
  }, [suggestions.length, currentLine, entityLoading]);

  useEffect(() => {
    itemRefs.current[safeActiveIndex]?.scrollIntoView({ block: 'nearest' });
  }, [safeActiveIndex, menuStyle]);

  const updateCursor = () => {
    const el = textareaRef.current;
    if (el) setCursor(el.selectionStart || 0);
  };

  const applySuggestion = (suggestion) => {
    const bounds = explorerTextLineBounds(value, cursor);
    const next = `${String(value || '').slice(0, bounds.start)}${suggestion.insert}${String(value || '').slice(bounds.end)}`;
    onChange(next);
    const nextCursor = bounds.start + suggestion.insert.length;
    requestAnimationFrame(() => {
      textareaRef.current?.focus();
      textareaRef.current?.setSelectionRange(nextCursor, nextCursor);
      setCursor(nextCursor);
      setAutocompleteOpen(false);
    });
  };

  React.useLayoutEffect(() => {
    if (!showAutocompleteMenu || !textareaRef.current) {
      setMenuStyle(null);
      return undefined;
    }
    const updatePosition = () => {
      const el = textareaRef.current;
      if (!el) return;
      const coords = getTextareaCaretCoordinates(el, cursor);
      const panelWidth = visibleSuggestions.length
        ? Math.min(
          Math.max(220, ...visibleSuggestions.map((item) => (
            String(item.label || '').length * 7 + String(item.hint || '').length * 5 + 44
          ))),
          420,
        )
        : 220;
      const panelHeight = visibleSuggestions.length
        ? Math.min(visibleSuggestions.length * 28 + 8, 224)
        : 36;
      let top = coords.top + coords.height + 4;
      if (top + panelHeight > window.innerHeight - 8) {
        top = Math.max(8, coords.top - panelHeight - 4);
      }
      const maxLeft = Math.max(8, window.innerWidth - panelWidth - 8);
      setMenuStyle({
        position: 'fixed',
        top,
        left: Math.min(Math.max(8, coords.left), maxLeft),
        width: panelWidth,
        maxHeight: 224,
        zIndex: 1300,
        overflowY: 'auto',
      });
    };
    updatePosition();
    const el = textareaRef.current;
    el.addEventListener('scroll', updatePosition);
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      el.removeEventListener('scroll', updatePosition);
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [cursor, showAutocompleteMenu, visibleSuggestions, value]);

  const handleKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') return;

    if (!visibleSuggestions.length) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((idx) => (idx + 1) % visibleSuggestions.length);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((idx) => (idx - 1 + visibleSuggestions.length) % visibleSuggestions.length);
      return;
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      setActiveIndex(0);
      setAutocompleteOpen(false);
      return;
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      applySuggestion(visibleSuggestions[safeActiveIndex]);
    }
  };

  return (
    <div className="col" style={{ gap: 6, position: 'relative' }}>
      <textarea
        ref={textareaRef}
        className="input mono"
        rows={12}
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
          setCursor(e.target.selectionStart || 0);
          setAutocompleteOpen(true);
        }}
        onClick={(e) => {
          updateCursor(e);
          setAutocompleteOpen(false);
        }}
        onKeyUp={updateCursor}
        onKeyDown={handleKeyDown}
        onFocus={updateCursor}
        placeholder={'time range 1h\ngroup by src_ip, dst_ip\nproto = UDP\nthreshold avg bps > 100 mbps'}
        spellCheck={false}
        style={{ minHeight: 180, resize: 'vertical', fontSize: 12, lineHeight: 1.45 }}
      />
      {error && (
        <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }} role="alert">{error}</div>
      )}
      {showAutocompleteMenu && menuStyle && ReactDOM.createPortal(
        <div
          role="listbox"
          aria-label="Подсказки фильтра"
          style={{
            ...menuStyle,
            background: 'var(--bg-surface)',
            border: '1px solid var(--bd-default)',
            borderRadius: 10,
            boxShadow: 'var(--pv-shadow-popover)',
            padding: 4,
          }}
        >
          {entityLoading && visibleSuggestions.length === 0 ? (
            <div style={{ padding: '8px 10px', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Поиск…</div>
          ) : visibleSuggestions.map((item, index) => {
            const active = index === safeActiveIndex;
            return (
              <button
                key={`${item.label}-${item.insert}`}
                ref={(el) => { itemRefs.current[index] = el; }}
                type="button"
                role="option"
                aria-selected={active}
                title={item.hint || undefined}
                onMouseDown={(ev) => {
                  ev.preventDefault();
                  applySuggestion(item);
                }}
                onMouseEnter={() => setActiveIndex(index)}
                style={{
                  all: 'unset',
                  display: 'flex',
                  alignItems: 'center',
                  width: '100%',
                  boxSizing: 'border-box',
                  minHeight: 26,
                  padding: '4px 8px',
                  borderRadius: 6,
                  cursor: 'pointer',
                  background: active ? 'var(--surf-3)' : 'transparent',
                }}
              >
                <div className="mono" style={{ font: 'var(--pv-text-body-2-bold)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }}>
                  {item.label}
                </div>
                {item.hint && (
                  <div style={{
                    font: 'var(--pv-text-body-3)',
                    color: 'var(--fg-muted)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    marginLeft: 10,
                  }}>
                    {item.hint}
                  </div>
                )}
              </button>
            );
          })}
        </div>,
        document.body,
      )}
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        ↑↓ выбор · Tab вставка · Enter новая строка · Ctrl+Enter применить
      </div>
    </div>
  );
}

function ExplorerAddFilterMenu({
  schema,
  onPickField,
  cabinetMode = false,
}) {
  const [open, setOpen] = useState(false);
  const anchorRef = React.useRef(null);
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);

  const fieldItems = useMemo(
    () => (schema?.filterFields || [])
      .map((f) => ({
        id: f.id,
        label: f.label,
        group: f.group || 'Поля',
        hint: f.valueHint || null,
        valueHint: f.valueHint || null,
        aliases: f.aliases || [],
      })),
    [schema],
  );

  React.useLayoutEffect(() => {
    if (!open) return undefined;
    const anchor = anchorRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      const rect = anchor.getBoundingClientRect();
      setMenuStyle({
        position: 'fixed',
        top: rect.bottom + 4,
        left: Math.max(8, rect.left),
        width: Math.max(rect.width, 280),
        maxHeight: 320,
        zIndex: 1300,
        overflowY: 'auto',
      });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (panelRef.current?.contains(e.target) || anchorRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const pick = (item) => {
    onPickField(item.id);
    setOpen(false);
  };

  return (
    <>
      <div ref={anchorRef}>
        <Button kind="ghost" size="sm" icon="plus" onClick={() => setOpen((v) => !v)}>Условие</Button>
      </div>
      {open && (
        <ExplorerCatalogFieldPickerPanel
          panelRef={panelRef}
          menuStyle={menuStyle}
          schema={schema}
          items={fieldItems}
          onPick={pick}
          searchPlaceholder="Поиск фильтра..."
          useCatalogs={!cabinetMode}
        />
      )}
    </>
  );
}

function ExplorerFilterModeToggle({ filterMode, onFilterModeChange }) {
  return (
    <div className="seg explorer-filter-mode-toggle" role="group" aria-label="Режим фильтра">
      <button
        type="button"
        className={filterMode === 'graphic' ? 'is-active' : ''}
        title="Графический режим"
        aria-label="Графический режим"
        aria-pressed={filterMode === 'graphic'}
        onClick={() => onFilterModeChange('graphic')}
      >
        <Icon name="sliders" size={14} />
      </button>
      <button
        type="button"
        className={filterMode === 'text' ? 'is-active' : ''}
        title="Текстовый режим"
        aria-label="Текстовый режим"
        aria-pressed={filterMode === 'text'}
        onClick={() => onFilterModeChange('text')}
      >
        <Icon name="code" size={14} />
      </button>
    </div>
  );
}

function ExplorerAnalysisTabs({ value, onChange, compact = false }) {
  return (
    <div
      className={`seg explorer-analysis-tabs${compact ? ' explorer-analysis-tabs--compact' : ''}`}
      role="group"
      aria-label="Тип анализа"
    >
      {VIS_TYPES.map((v) => (
        <button
          key={v.id}
          type="button"
          className={value === v.id ? 'is-active' : ''}
          onClick={() => onChange(v.id)}
          title={`${v.label}: ${v.hint}`}
          aria-label={v.label}
          aria-pressed={value === v.id}
        >
          <Icon name={v.icon} size={compact ? 14 : 12} />
          <span>{v.label}</span>
        </button>
      ))}
    </div>
  );
}

function ExplorerFilterTemplatesMenu({
  lastApplied,
  savedQueries = [],
  canWrite,
  runDisabled = false,
  onApplyLastApplied,
  onRestoreLastApplied,
  onSaveLastApplied,
  onApplySaved,
  onEditSaved,
  onDeleteSaved,
  onAddQuickFilter,
}) {
  const [open, setOpen] = useState(false);
  const anchorRef = React.useRef(null);
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);

  React.useLayoutEffect(() => {
    if (!open) return undefined;
    const anchor = anchorRef.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      setMenuStyle(computeExplorerPopoverStyle(anchor, { minWidth: 300, maxHeight: 420, gap: 4 }));
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (panelRef.current?.contains(e.target) || anchorRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  const sectionTitleStyle = {
    font: 'var(--pv-text-body-3-bold)',
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    color: 'var(--fg-secondary)',
    marginBottom: 6,
  };

  return (
    <>
      <div ref={anchorRef}>
        <Button
          kind="ghost"
          size="sm"
          icon="star"
          iconRight={open ? 'chevU' : 'chevD'}
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
        >
          Шаблоны
        </Button>
      </div>
      {open && menuStyle && ReactDOM.createPortal(
        <div
          ref={panelRef}
          className="explorer-filter-templates-menu"
          style={{
            ...menuStyle,
            background: 'var(--bg-surface)',
            border: '1px solid var(--bd-default)',
            borderRadius: 10,
            boxShadow: 'var(--pv-shadow-popover)',
            padding: 10,
          }}
        >
          {lastApplied && (
            <div style={{ marginBottom: 12 }}>
              <div style={sectionTitleStyle}>Последний применённый</div>
              <div className="col" style={{ gap: 6, padding: '8px 10px', background: 'var(--surf-1)', border: '1px solid var(--bd-soft)', borderRadius: 10 }}>
                <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{summarizeExplorerQuery(lastApplied)}</div>
                <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                  <Button kind="ghost" size="xs" icon="play" onClick={() => { onApplyLastApplied?.(); setOpen(false); }} disabled={runDisabled}>Применить</Button>
                  <Button kind="ghost" size="xs" icon="filter" onClick={() => { onRestoreLastApplied?.(); setOpen(false); }}>В конструктор</Button>
                  {canWrite && (
                    <Button kind="ghost" size="xs" icon="save" onClick={() => { onSaveLastApplied?.(); setOpen(false); }}>Сохранить</Button>
                  )}
                </div>
              </div>
            </div>
          )}

          <div style={{ marginBottom: 12 }}>
            <div style={sectionTitleStyle}>Быстрые фильтры</div>
            <div className="col" style={{ gap: 2 }}>
              {EXPLORER_QUICK_FILTERS.map((q) => (
                <button
                  key={q.label}
                  type="button"
                  onClick={() => {
                    onAddQuickFilter?.({ field: q.field, op: '=', value: q.val });
                    setOpen(false);
                  }}
                  style={{
                    all: 'unset',
                    boxSizing: 'border-box',
                    width: '100%',
                    padding: '8px 10px',
                    borderRadius: 8,
                    cursor: 'pointer',
                    font: 'var(--pv-text-body-2)',
                    color: 'var(--fg-secondary)',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg-primary)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--fg-secondary)'; }}
                >
                  {q.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <div style={sectionTitleStyle}>Сохранённые</div>
            <div className="col" style={{ gap: 4 }}>
              {savedQueries.length === 0 ? (
                <div style={{ padding: '8px 4px', color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>Нет сохранённых шаблонов</div>
              ) : savedQueries.map((q) => {
                const builtin = isBuiltinExplorerPreset(q);
                return (
                  <div
                    key={q.id}
                    className="row"
                    style={{ alignItems: 'center', gap: 4, padding: '2px 0' }}
                  >
                    <button
                      type="button"
                      onClick={() => {
                        onApplySaved?.(q);
                        setOpen(false);
                      }}
                      className="row"
                      style={{
                        all: 'unset',
                        flex: 1,
                        minWidth: 0,
                        padding: '6px 10px',
                        borderRadius: 8,
                        font: 'var(--pv-text-body-2)',
                        color: 'var(--fg-secondary)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg-primary)'; }}
                      onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--fg-secondary)'; }}
                    >
                      <Icon name="star" size={11} />
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{q.name}</span>
                    </button>
                    {canWrite && !builtin && (
                      <>
                        <button
                          type="button"
                          className="icon-btn tt"
                          data-tt="Редактировать"
                          style={{ width: 28, height: 28, flexShrink: 0 }}
                          onClick={(e) => {
                            e.stopPropagation();
                            onEditSaved?.(q);
                            setOpen(false);
                          }}
                        >
                          <Icon name="edit" size={14} />
                        </button>
                        <button
                          type="button"
                          className="icon-btn tt"
                          data-tt="Удалить фильтр"
                          style={{ width: 28, height: 28, flexShrink: 0 }}
                          onClick={(e) => {
                            e.stopPropagation();
                            onDeleteSaved?.(q);
                          }}
                        >
                          <Icon name="trash" size={14} />
                        </button>
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>,
        document.body,
      )}
    </>
  );
}

function ExplorerChipRow({ label, mandatory, children, errors = [] }) {
  return (
    <div className="explorer-chip-row">
      <div className="explorer-chip-row__label">
        {label}
        {mandatory && <span className="explorer-chip-row__mandatory">*</span>}
      </div>
      <div className="explorer-chip-row__chips">{children}</div>
      {errors.length > 0 && (
        <div className="explorer-chip-row__errors">
          {errors.map((msg) => (
            <div key={msg} className="explorer-chip-row__error" role="alert">{msg}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function ExplorerQueryChip({
  label, onClick, onRemove, warn = false, className = '', title,
}) {
  return (
    <span className={`explorer-query-chip${warn ? ' explorer-query-chip--warn' : ''}${className ? ` ${className}` : ''}`} title={title}>
      <button type="button" className="explorer-query-chip__body" onClick={onClick}>
        <span className="explorer-query-chip__label">{label}</span>
      </button>
      {onRemove && (
        <button
          type="button"
          className="explorer-query-chip__remove"
          onClick={(e) => { e.stopPropagation(); onRemove(e); }}
          aria-label="Удалить"
          title="Удалить"
        >
          <Icon name="x" size={10} stroke={2.5} />
        </button>
      )}
    </span>
  );
}

function ExplorerPopoverMenu({ anchorRef, open, onClose, children, minWidth = 200, maxHeight = 320 }) {
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);

  React.useLayoutEffect(() => {
    if (!open) {
      setMenuStyle(null);
      return undefined;
    }
    const anchor = anchorRef?.current;
    if (!anchor) return undefined;
    const updatePosition = () => {
      setMenuStyle(computeExplorerPopoverStyle(anchor, { minWidth, maxHeight, gap: 4 }));
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [open, anchorRef, minWidth, maxHeight]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (e) => {
      if (panelRef.current?.contains(e.target) || anchorRef?.current?.contains(e.target)) return;
      if (isExplorerNestedMenuTarget(e.target)) return;
      onClose?.();
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open, onClose, anchorRef]);

  if (!open || !menuStyle) return null;
  return ReactDOM.createPortal(
    <div ref={panelRef} style={menuStyle}>{children}</div>,
    document.body,
  );
}

function ExplorerMetricChipPicker({ metrics, value, onChange }) {
  const [open, setOpen] = useState(false);
  const anchorRef = React.useRef(null);
  const current = metrics.find((m) => m.id === value) || metrics[0];

  return (
    <>
      <span ref={anchorRef}>
        <ExplorerQueryChip
          label={current?.label || value}
          onClick={() => setOpen((v) => !v)}
          className="explorer-query-chip--metric"
        />
      </span>
      <ExplorerPopoverMenu anchorRef={anchorRef} open={open} onClose={() => setOpen(false)} minWidth={220}>
        <div className="explorer-filter-edit-popover" style={{ boxShadow: 'none', border: 'none', padding: 4 }}>
          {metrics.map((m) => (
            <div
              key={m.id}
              className={`explorer-metric-picker-item${m.id === value ? ' is-active' : ''}`}
              role="menuitem"
              onClick={() => {
                onChange(m.id);
                setOpen(false);
              }}
            >
              {m.label}
            </div>
          ))}
        </div>
      </ExplorerPopoverMenu>
    </>
  );
}

function ExplorerLogicChip({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const anchorRef = React.useRef(null);
  const normalized = normalizeFilterLogicValue(value);
  const current = EXPLORER_FILTER_LOGIC_OPTIONS.find((o) => o.id === normalized) || EXPLORER_FILTER_LOGIC_OPTIONS[0];

  return (
    <>
      <span ref={anchorRef}>
        <button type="button" className="explorer-query-chip explorer-logic-chip" onClick={() => setOpen((v) => !v)}>
          {current.label}
          <Icon name="chevD" size={10} />
        </button>
      </span>
      <ExplorerPopoverMenu anchorRef={anchorRef} open={open} onClose={() => setOpen(false)} minWidth={140} maxHeight={200}>
        <div className="explorer-filter-edit-popover" style={{ boxShadow: 'none', border: 'none', padding: 4 }}>
          {EXPLORER_FILTER_LOGIC_OPTIONS.map((opt) => (
            <div
              key={opt.id}
              className={`explorer-logic-picker-item${opt.id === normalized ? ' is-active' : ''}`}
              role="menuitem"
              onClick={() => {
                onChange(opt.id);
                setOpen(false);
              }}
            >
              {opt.label}
            </div>
          ))}
        </div>
      </ExplorerPopoverMenu>
    </>
  );
}

function ExplorerMetricGroupControls({
  metric,
  setMetric,
  availableMetrics,
  groupBy,
  setGroupBy,
  dimensionById,
  dimensions,
  schema,
  cabinetMode,
  showGroupBy = true,
}) {
  const [addingDim, setAddingDim] = useState(false);
  const dimAnchorRef = React.useRef(null);

  return (
    <div className="explorer-metric-group-chips">
      <ExplorerMetricChipPicker metrics={availableMetrics} value={metric} onChange={setMetric} />
      {showGroupBy && (
        <>
          <span className="explorer-chip-row__sep">по</span>
          {groupBy.map((token) => {
            const id = explorerGroupFieldId(token);
            return (
              <ExplorerGroupChip
                key={id}
                token={token}
                dimension={dimensionById[id]}
                onChange={(nextToken) => setGroupBy((current) => normalizeExplorerGroupTokens(
                  current.map((item) => (explorerGroupFieldId(item) === id ? nextToken : item)),
                ))}
                onRemove={() => setGroupBy((current) => current.filter((item) => explorerGroupFieldId(item) !== id))}
              />
            );
          })}
          <span ref={dimAnchorRef}>
            <button type="button" className="explorer-chip-add" onClick={() => setAddingDim((v) => !v)}>
              <Icon name="plus" size={12} />
            </button>
            {addingDim && (
              <DimensionPicker
                anchorRef={dimAnchorRef}
                dimensions={dimensions}
                schema={schema}
                selected={groupBy.map(explorerGroupFieldId)}
                cabinetMode={cabinetMode}
                onPick={(id) => {
                  if (!groupBy.some((token) => explorerGroupFieldId(token) === id)) {
                    setGroupBy(normalizeExplorerGroupTokens([...groupBy, id]));
                  }
                  setAddingDim(false);
                }}
                onClose={() => setAddingDim(false)}
              />
            )}
          </span>
        </>
      )}
    </div>
  );
}

function ExplorerFilterEditControl({ children }) {
  return <div className="explorer-filter-edit-popover__control">{children}</div>;
}

function ExplorerFilterEditPopover({
  filter,
  schema,
  filterFields,
  switchIpScope,
  onChange,
  onClose,
  anchorRef,
  open,
}) {
  const meta = filterFieldMeta(schema, filter.field);
  const ops = filterOpsForField(schema, filter.field);
  const isSpecialField = filter.field === 'direction' || filter.field === 'collector';

  return (
    <ExplorerPopoverMenu anchorRef={anchorRef} open={open} onClose={onClose} minWidth={300} maxHeight={420}>
      <div className="explorer-filter-edit-popover">
        <div className="explorer-filter-edit-popover__row">
          <div className="explorer-filter-edit-popover__label">Поле</div>
          {isSpecialField ? (
            <ExplorerFilterEditControl>
              <div className="explorer-filter-edit-popover__static">{meta?.label || filter.field}</div>
            </ExplorerFilterEditControl>
          ) : (
            <ExplorerFilterEditControl>
              <FilterSearchPicker
                items={filterFields}
                value={filter.field}
                onChange={(fieldId) => {
                  const nextOps = filterOpsForField(schema, fieldId);
                  const defaultOp = defaultOpForField(schema, fieldId);
                  onChange({
                    field: fieldId,
                    value: '',
                    label: null,
                    op: nextOps.includes(filter.op) ? filter.op : defaultOp,
                  });
                }}
                searchPlaceholder="Поиск поля..."
                emptyLabel="Поле…"
                grouped
                fullWidth
              />
            </ExplorerFilterEditControl>
          )}
        </div>
        <div className="explorer-filter-edit-popover__row">
          <div className="explorer-filter-edit-popover__label">Оператор</div>
          <ExplorerFilterEditControl>
            <select
              className="input"
              value={filter.op}
              onChange={(e) => onChange({ op: e.target.value })}
            >
              {ops.map((op) => <option key={op} value={op}>{explorerOpLabel(op)}</option>)}
            </select>
          </ExplorerFilterEditControl>
        </div>
        <div className="explorer-filter-edit-popover__row">
          <div className="explorer-filter-edit-popover__label">Значение</div>
          <ExplorerFilterEditControl>
            {filter.field === 'direction' ? (
              <DirectionFilter
                embedded
                formatSummary={explorerDirectionSummaryLabel}
                directions={directionFilterToMap(filter.value)}
                onDirectionsChange={(dirs) => {
                  const value = directionMapToFilterValue(dirs);
                  const nextOp = !value
                    ? '='
                    : (value.includes(',')
                      ? (['=', '!='].includes(filter.op) ? filter.op : 'in')
                      : (['in', 'not_in'].includes(filter.op) ? filter.op : '='));
                  onChange({ value, op: nextOp });
                }}
              />
            ) : filter.field === 'collector' ? (
              <CollectorFilter
                embedded
                collectorFilter={collectorFilterToArray(filter.value)}
                onCollectorFilterChange={(arr) => onChange({ value: collectorArrayToFilterValue(arr) })}
              />
            ) : (meta?.type === 'tcp_flags' || filter.field === 'tcp_flags') ? (
              <TcpFlagsFilter
                value={filter.value}
                onChange={(patch) => onChange(patch)}
                onClear={() => onChange({ value: '', label: null })}
              />
            ) : (
              <FilterValueInput
                fieldId={filter.field}
                meta={meta}
                value={filter.value}
                label={filter.label}
                switchIpScope={switchIpScope}
                onChange={(patch) => onChange(patch)}
                onClear={() => onChange({ value: '', label: null })}
                fullWidth
              />
            )}
          </ExplorerFilterEditControl>
        </div>
      </div>
    </ExplorerPopoverMenu>
  );
}

function ExplorerFilterChipItem({
  filter,
  schema,
  filterFields,
  switchIpScope,
  rowError,
  isEditing,
  onToggleEdit,
  onCloseEdit,
  onChange,
  onRemove,
}) {
  const anchorRef = React.useRef(null);
  const chipLabel = formatExplorerFilterChipLabel(filter, schema);

  return (
    <span ref={anchorRef}>
      <ExplorerQueryChip
        label={chipLabel}
        warn={Boolean(rowError)}
        title={rowError || chipLabel}
        onClick={onToggleEdit}
        onRemove={onRemove}
      />
      <ExplorerFilterEditPopover
        filter={filter}
        schema={schema}
        filterFields={filterFields}
        switchIpScope={switchIpScope}
        open={isEditing}
        anchorRef={anchorRef}
        onClose={onCloseEdit}
        onChange={onChange}
      />
    </span>
  );
}

function ExplorerThresholdChipItem({
  row,
  schema,
  isEditing,
  onToggleEdit,
  onCloseEdit,
  onChange,
  onRemove,
}) {
  const anchorRef = React.useRef(null);
  const chipLabel = formatExplorerThresholdChipLabel(row, schema);

  return (
    <span ref={anchorRef}>
      <ExplorerQueryChip
        label={chipLabel}
        onClick={onToggleEdit}
        onRemove={onRemove}
      />
      <ExplorerThresholdEditPopover
        row={row}
        schema={schema}
        open={isEditing}
        anchorRef={anchorRef}
        onClose={onCloseEdit}
        onChange={onChange}
      />
    </span>
  );
}

function ExplorerConditionChipsRow({
  schema,
  filters,
  setFilters,
  filterRowErrors = {},
  cabinetMode,
  editingFilterId,
  setEditingFilterId,
  onPickField,
}) {
  const filterFields = schema?.filterFields || [];
  const switchIpScope = explorerSwitchIpScopeFromFilters(filters);
  const updateFilter = (id, patch) => setFilters(filters.map((f) => (f.id === id ? { ...f, ...patch } : f)));

  const rowErrors = filters
    .map((f) => filterRowErrors[f.id])
    .filter(Boolean);

  return (
    <ExplorerChipRow label="Условия" errors={rowErrors}>
      {filters.map((f, i) => (
        <React.Fragment key={f.id}>
          {i > 0 && (
            <ExplorerLogicChip
              value={f.logic}
              onChange={(logic) => updateFilter(f.id, { logic })}
            />
          )}
          <ExplorerFilterChipItem
            filter={f}
            schema={schema}
            filterFields={filterFields}
            switchIpScope={switchIpScope}
            rowError={filterRowErrors[f.id]}
            isEditing={editingFilterId === f.id}
            onToggleEdit={() => setEditingFilterId(editingFilterId === f.id ? null : f.id)}
            onCloseEdit={() => setEditingFilterId(null)}
            onChange={(patch) => updateFilter(f.id, patch)}
            onRemove={() => {
              setFilters(filters.filter((x) => x.id !== f.id));
              if (editingFilterId === f.id) setEditingFilterId(null);
            }}
          />
        </React.Fragment>
      ))}
      <ExplorerAddFilterMenu
        schema={schema}
        cabinetMode={cabinetMode}
        onPickField={onPickField}
      />
    </ExplorerChipRow>
  );
}

function ExplorerThresholdEditPopover({
  row,
  schema,
  onChange,
  onClose,
  anchorRef,
  open,
}) {
  return (
    <ExplorerPopoverMenu anchorRef={anchorRef} open={open} onClose={onClose} minWidth={320} maxHeight={480}>
      <div className="explorer-threshold-edit-popover">
        <ExplorerThresholdRow
          row={row}
          schema={schema}
          onChange={onChange}
          compact
        />
      </div>
    </ExplorerPopoverMenu>
  );
}

function ExplorerThresholdChipsRow({
  schema,
  thresholds,
  setThresholds,
  peakWarning,
  editingThresholdId,
  setEditingThresholdId,
  onAddThreshold,
}) {
  const updateThreshold = (id, patch) => {
    setThresholds(thresholds.map((t) => (t.id === id ? { ...t, ...patch } : t)));
  };

  return (
    <>
      {peakWarning && (
        <div className="explorer-threshold-warning" role="status" style={{ marginBottom: 4 }}>{peakWarning}</div>
      )}
      <ExplorerChipRow label="Пороги">
        {thresholds.map((row) => (
          <ExplorerThresholdChipItem
            key={row.id}
            row={row}
            schema={schema}
            isEditing={editingThresholdId === row.id}
            onToggleEdit={() => setEditingThresholdId(editingThresholdId === row.id ? null : row.id)}
            onCloseEdit={() => setEditingThresholdId(null)}
            onChange={(patch) => updateThreshold(row.id, patch)}
            onRemove={() => {
              setThresholds(thresholds.filter((t) => t.id !== row.id));
              if (editingThresholdId === row.id) setEditingThresholdId(null);
            }}
          />
        ))}
        <button type="button" className="explorer-chip-add" onClick={onAddThreshold}>
          <Icon name="plus" size={12} />
        </button>
      </ExplorerChipRow>
    </>
  );
}

function ExplorerThresholdRow({
  row, schema, onChange, onRemove, compact = false,
}) {
  const api = explorerThresholdApi();
  const metrics = api.thresholdMetricsFromSchema?.(schema) || api.EXPLORER_THRESHOLD_DEFAULT_METRICS || [];
  const metricMeta = metrics.find((m) => m.id === row.metric) || metrics[0];
  const units = api.thresholdUnitsForMetric?.(row.metric) || ['count'];
  const unitLabels = api.UNIT_LABELS?.[row.metric] || {};
  const rangeOp = row.op === 'between' || row.op === 'outside';
  const showPeak = metricMeta?.peakSupported;
  const showPeakWindow = showPeak && row.aggregate === 'peak';

  return (
    <div className="explorer-threshold-row">
      <div className="explorer-threshold-row__main">
        {showPeak && (
          <div className="seg explorer-threshold-row__agg" role="group" aria-label="Режим порога">
            <button
              type="button"
              className={(row.aggregate || 'avg') === 'avg' ? 'is-active' : ''}
              aria-pressed={(row.aggregate || 'avg') === 'avg'}
              onClick={() => onChange({ aggregate: 'avg' })}
            >
              средняя
            </button>
            <button
              type="button"
              className={row.aggregate === 'peak' ? 'is-active' : ''}
              aria-pressed={row.aggregate === 'peak'}
              onClick={() => onChange({ aggregate: 'peak' })}
            >
              пик
            </button>
          </div>
        )}
        <select className="input explorer-threshold-row__metric" value={row.metric} onChange={(e) => onChange({ metric: e.target.value, unit: api.defaultThresholdUnit?.(e.target.value, metrics) })}>
          {metrics.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
        </select>
        <select className="input explorer-threshold-row__op" value={row.op} onChange={(e) => onChange({ op: e.target.value })}>
          {(api.EXPLORER_THRESHOLD_OPS || []).map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
        </select>
        <input className="input explorer-threshold-row__value mono" type="text" inputMode="decimal" value={row.value} placeholder="0" onChange={(e) => onChange({ value: e.target.value })} />
        {rangeOp && (
          <input className="input explorer-threshold-row__value mono" type="text" inputMode="decimal" value={row.value2} placeholder="0" onChange={(e) => onChange({ value2: e.target.value })} />
        )}
        {row.metric !== 'pct' && (
          <select className="input explorer-threshold-row__unit" value={row.unit} onChange={(e) => onChange({ unit: e.target.value })}>
            {units.map((u) => <option key={u} value={u}>{unitLabels[u] || u}</option>)}
          </select>
        )}
        {showPeakWindow && (
          <select className="input explorer-threshold-row__peak" value={row.peakWindow || '5m'} onChange={(e) => onChange({ peakWindow: e.target.value })}>
            {(api.EXPLORER_THRESHOLD_PEAK_WINDOWS || []).map((w) => <option key={w.id} value={w.id}>{w.label}</option>)}
          </select>
        )}
        {!compact && onRemove && (
        <button type="button" className="icon-btn explorer-filter-row__remove" onClick={onRemove} title="Удалить порог">
          <Icon name="x" size={10} stroke={2.5} />
        </button>
        )}
      </div>
    </div>
  );
}

function ExplorerFilters({
  schema,
  filters,
  setFilters,
  timeRange,
  onTimeRangeChange,
  customPeriod,
  onCustomPeriodChange,
  displayTimezone,
  chartZoomDepth = 0,
  onChartZoomReset,
  filterMode,
  onFilterModeChange,
  filterText,
  onFilterTextChange,
  onClearFilters,
  filterTextError,
  filterRowErrors = {},
  savedQueries = [],
  lastApplied,
  onApplySaved,
  onApplyLastApplied,
  onRestoreLastApplied,
  onSaveLastApplied,
  onCollapse,
  onRun,
  runDisabled = false,
  canWrite,
  onSave,
  onSaveAsObservation,
  onEditSaved,
  onDeleteSaved,
  thresholds = [],
  setThresholds,
  thresholdPeakWarning,
  maxRangeDays: maxRangeDaysProp,
  cabinetClientWarning = null,
  cabinetMode = false,
  metric,
  setMetric,
  groupBy,
  setGroupBy,
  availableMetrics = [],
  dimensions = [],
  dimensionById = {},
}) {
  const panelRef = React.useRef(null);
  const [editingFilterId, setEditingFilterId] = useState(null);
  const [editingThresholdId, setEditingThresholdId] = useState(null);
  const maxRangeDays = Number(maxRangeDaysProp) > 0
    ? Number(maxRangeDaysProp)
    : explorerRangeLimitDays(schema?.maxRangeDays);

  useEffect(() => {
    const onKeyDown = (e) => {
      if (runDisabled) return;
      if (!(e.ctrlKey || e.metaKey) || e.key !== 'Enter') return;
      if (!panelRef.current?.contains(document.activeElement)) return;
      e.preventDefault();
      onRun?.();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onRun, runDisabled]);

  const addThreshold = () => {
    const id = Date.now() + Math.random();
    setThresholds([
      ...thresholds,
      {
        id,
        metric: 'bps',
        aggregate: 'avg',
        peakWindow: '5m',
        op: 'gt',
        value: '',
        value2: '',
        unit: 'mbps',
      },
    ]);
    setEditingThresholdId(id);
  };

  const addFilterWithField = (fieldId) => {
    const id = Date.now() + Math.random();
    setFilters([
      ...filters,
      {
        id,
        field: fieldId,
        op: defaultOpForField(schema, fieldId),
        value: '',
        logic: 'and',
      },
    ]);
    setEditingFilterId(id);
  };

  const filterActions = (
    <div className="explorer-filters-actions">
      <ExplorerFilterTemplatesMenu
        lastApplied={lastApplied}
        savedQueries={savedQueries}
        canWrite={canWrite}
        runDisabled={runDisabled}
        onApplyLastApplied={onApplyLastApplied}
        onRestoreLastApplied={onRestoreLastApplied}
        onSaveLastApplied={onSaveLastApplied}
        onApplySaved={onApplySaved}
        onEditSaved={onEditSaved}
        onDeleteSaved={onDeleteSaved}
        onAddQuickFilter={(filter) => {
          const id = Date.now() + Math.random();
          setFilters([...filters, { field: 'src_ip', op: '=', value: '', logic: 'and', ...filter, id }]);
        }}
      />
      <Button kind="ghost" size="sm" icon="x" onClick={onClearFilters}>Очистить фильтры</Button>
      <Button kind="ghost" size="sm" icon="play" onClick={onRun} disabled={runDisabled}>
        {runDisabled ? 'Загрузка…' : 'Применить'}
      </Button>
      {canWrite && (
        <Button kind="ghost" size="sm" icon="save" onClick={onSave}>Сохранить</Button>
      )}
      {canWrite && onSaveAsObservation && (
        <Button kind="primary" size="sm" onClick={onSaveAsObservation}>Добавить в наблюдения</Button>
      )}
      {filterMode === 'graphic' && (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>Ctrl+Enter — применить</span>
      )}
    </div>
  );

  return (
    <div ref={panelRef}>
    <Card pad="sm" className="explorer-filters-panel">
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          <div style={{ font: 'var(--pv-text-h4)' }}>Фильтры</div>
          <ExplorerFilterModeToggle filterMode={filterMode} onFilterModeChange={onFilterModeChange} />
        </div>
        <button className="icon-btn" onClick={onCollapse} title="Свернуть панель"><Icon name="chevL" size={14} /></button>
      </div>

      {filterMode === 'graphic' ? (
        <div className="col explorer-filters-panel__body explorer-filters-panel__body--chips" style={{ marginBottom: 12 }}>
          {cabinetClientWarning && (
            <div style={{
              padding: '8px 10px',
              borderRadius: 8,
              background: 'var(--surf-2)',
              border: '1px solid var(--bd-soft)',
              color: 'var(--fg-secondary)',
              font: 'var(--pv-text-body-3)',
            }}
            >
              {cabinetClientWarning}. Для суток и дольше удобнее кабинет клиента.
            </div>
          )}

          <ExplorerChipRow label="Период" mandatory>
            <TimeFilter
              variant="explorer"
              appearance="chip"
              timeRange={timeRange}
              onTimeRangeChange={onTimeRangeChange}
              customPeriod={customPeriod}
              onCustomPeriodChange={onCustomPeriodChange}
              maxRangeDays={maxRangeDays}
            />
            {chartZoomDepth > 0 && (
              <button
                type="button"
                className="time-pill time-pill--reset"
                title="Вернуть предыдущий период"
                onClick={onChartZoomReset}
              >
                <Icon name="zoom" size={14} />
                <span>Сброс zoom</span>
              </button>
            )}
          </ExplorerChipRow>

          <ExplorerChipRow label="Метрика">
            <ExplorerMetricGroupControls
              metric={metric}
              setMetric={setMetric}
              availableMetrics={availableMetrics}
              groupBy={groupBy}
              setGroupBy={setGroupBy}
              dimensionById={dimensionById}
              dimensions={dimensions}
              schema={schema}
              cabinetMode={cabinetMode}
            />
          </ExplorerChipRow>

          <ExplorerConditionChipsRow
            schema={schema}
            filters={filters}
            setFilters={setFilters}
            filterRowErrors={filterRowErrors}
            cabinetMode={cabinetMode}
            editingFilterId={editingFilterId}
            setEditingFilterId={setEditingFilterId}
            onPickField={addFilterWithField}
          />

          <ExplorerThresholdChipsRow
            schema={schema}
            thresholds={thresholds}
            setThresholds={setThresholds}
            peakWarning={thresholdPeakWarning}
            editingThresholdId={editingThresholdId}
            setEditingThresholdId={setEditingThresholdId}
            onAddThreshold={addThreshold}
          />

          {filterActions}
        </div>
      ) : (
        <div className="col explorer-filters-panel__body explorer-filters-panel__body--chips" style={{ marginBottom: 12 }}>
          <ExplorerChipRow label="Метрика">
            <ExplorerMetricChipPicker
              metrics={availableMetrics}
              value={metric}
              onChange={setMetric}
            />
          </ExplorerChipRow>
          <ExplorerFilterTextEditor
            value={filterText}
            onChange={onFilterTextChange}
            error={filterTextError}
            schema={schema}
            filters={filters}
          />
          {filterActions}
        </div>
      )}
    </Card>
    </div>
  );
}

function explorerPointBucketKey(pt) {
  const ms = Number(pt?.bucketMs);
  if (Number.isFinite(ms) && ms > 0) return `ms:${ms}`;
  return normalizeBucketString(pt?.bucket);
}

function ExplorerTotalChart({
  points,
  metric,
  metricLabel,
  displayTimezone,
  chartLongRange,
  onRangeSelect,
  bucketSeconds = 300,
}) {
  const normalizedPoints = (Array.isArray(points) ? points : [])
    .map((point) => {
      const next = {
        ...point,
        bucket: normalizeBucketString(point.bucket),
        value: Number(point.value) || 0,
      };
      if (point.bucketMs != null) next.bucketMs = Number(point.bucketMs);
      next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
      return next;
    })
    .sort((a, b) => (resolvePointEpochMs(a) || 0) - (resolvePointEpochMs(b) || 0));
  const chartPoints = normalizedPoints.length === 1
    ? [normalizedPoints[0], { ...normalizedPoints[0] }]
    : normalizedPoints;

  if (chartPoints.length < 2) {
    return (
      <div className="explorer-lines__empty">
        Недостаточно временных точек для динамики. Расширьте период или выберите другую метрику.
      </div>
    );
  }

  return (
    <div className="explorer-lines col" style={{ gap: 8 }}>
      <div className="explorer-time-chart explorer-dynamics-chart">
        <DualChart
          points={chartPoints}
          lines={[{ key: 'value', label: metricLabel || metric, color: '#7381f4' }]}
          height={EXPLORER_CHART_HEIGHT}
          mode="bw"
          gapAsZero
          onRangeSelect={onRangeSelect}
          bucketSeconds={bucketSeconds}
          displayTimezone={displayTimezone}
          valueFormatter={(value) => formatMetric(value, metric)}
          axisFormatter={(value) => formatMetricAxis(value, metric)}
          yAxisUnit={metricAxisUnit(metric)}
        />
      </div>
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        Ось Y — {metricLabel || metric} по всем потокам, соответствующим фильтрам, в каждом временном интервале.
      </div>
    </div>
  );
}

function DynamicsChartExplorer({
  active = true,
  stackMode,
  results,
  metric,
  metricLabel,
  resultSeries,
  displayTimezone,
  chartLongRange,
  selectedSeriesIds,
  onRangeSelect,
  bucketSeconds = 300,
  totalPoints = null,
  showOthers = false,
}) {
  const [chartKey, setChartKey] = useState(0);
  const selectedSeriesKey = [...selectedSeriesIds].sort().join('|');
  useEffect(() => {
    if (active) setChartKey((k) => k + 1);
  }, [active, selectedSeriesKey, showOthers, stackMode]);
  const seriesByRow = resultSeries?.seriesByRow || {};
  const resultIdSet = new Set(results.map((r) => r.id));
  const selectedIds = [...selectedSeriesIds].filter((id) => resultIdSet.has(id));
  const chartRowIds = selectedIds;

  const lines = results.filter((r) => chartRowIds.includes(r.id)).map((row) => ({
    key: row.id,
    label: explorerRowLabel(row),
    color: row.color,
  }));

  const pointsByBucket = new Map();
  for (const rowId of chartRowIds) {
    const rawPoints = seriesByRow[rowId] || [];
    for (const pt of rawPoints) {
      const key = explorerPointBucketKey(pt);
      if (!pointsByBucket.has(key)) {
        const next = { ...pt, bucket: normalizeBucketString(pt.bucket) };
        if (pt.bucketMs != null) next.bucketMs = Number(pt.bucketMs);
        pointsByBucket.set(key, next);
      }
      const current = Number(pointsByBucket.get(key)[rowId]) || 0;
      pointsByBucket.get(key)[rowId] = current + (Number(pt.value) || 0);
    }
  }

  // Everything not on the chart, taken from the unsliced totals of the same query.
  let hasOthers = false;
  if (Array.isArray(totalPoints) && totalPoints.length && chartRowIds.length) {
    for (const pt of totalPoints) {
      const key = explorerPointBucketKey(pt);
      const total = Number(pt.value) || 0;
      if (!total) continue;
      const target = pointsByBucket.get(key);
      if (!target) continue;
      const shown = chartRowIds.reduce((s, id) => s + (Number(target[id]) || 0), 0);
      const rest = total - shown;
      if (rest > 0 && rest / total >= 0.0001) {
        target[EXPLORER_OTHERS_ID] = rest;
        hasOthers = true;
      }
    }
  }
  if (showOthers && hasOthers) {
    lines.push({ key: EXPLORER_OTHERS_ID, label: EXPLORER_OTHERS_LABEL, color: EXPLORER_OTHERS_COLOR });
  }

  const points = [...pointsByBucket.values()]
    .sort((a, b) => (resolvePointEpochMs(a) || 0) - (resolvePointEpochMs(b) || 0))
    .map((pt) => {
      const next = { ...pt };
      for (const rowId of chartRowIds) {
        if (next[rowId] == null) next[rowId] = 0;
      }
      if (showOthers && hasOthers && next[EXPLORER_OTHERS_ID] == null) next[EXPLORER_OTHERS_ID] = 0;
      next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
      if (next.bucketMs != null) next.bucketMs = Number(next.bucketMs);
      return next;
    });
  const chartPoints = points.length === 1 ? [points[0], { ...points[0] }] : points;
  const isStack = stackMode === 'sum' || stackMode === 'share';
  const chartAxisUnit = isStack && stackMode === 'share' ? '%' : metricAxisUnit(metric);
  const chartAxisFormatter = isStack && stackMode === 'share'
    ? (v) => formatChartSharePercent(v)
    : (v) => formatMetricAxis(v, metric);
  const chartCaption = stackMode === 'sum'
    ? 'Верхняя кромка = сумма выбранных серий в каждом временном интервале.'
    : stackMode === 'share'
      ? 'Доли выбранных серий, нормализованные к 100%. Абсолютный объём виден только в подсказке.'
      : `Ось Y — ${metricLabel || metric} в каждом временном интервале, не сумма за весь период.`;

  return (
    <div className="explorer-lines col" style={{ gap: 12 }}>
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        {selectedIds.length
          ? `На графике ${selectedIds.length} серий. Управляйте сериями кнопками «Показать» / «Скрыть с графика» в таблице.`
          : 'Нет серий на графике. Включите строки кнопкой «Показать» в таблице «Результаты».'}
      </div>
      {chartPoints.length > 1 && lines.length ? (
        <>
          <div className="explorer-time-chart explorer-dynamics-chart">
            <DualChart
              key={chartKey}
              points={chartPoints}
              lines={lines}
              stackMode={stackMode}
              height={EXPLORER_CHART_HEIGHT}
              mode="bw"
              gapAsZero
              onRangeSelect={onRangeSelect}
              bucketSeconds={bucketSeconds}
              displayTimezone={displayTimezone}
              valueFormatter={(v) => formatMetric(v, metric)}
              axisFormatter={chartAxisFormatter}
              yAxisUnit={chartAxisUnit}
            />
          </div>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: -4 }}>
            {chartCaption}
            {onRangeSelect && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginLeft: 8 }}>
                <Icon name="info" size={12} /> Выделите диапазон на графике
              </span>
            )}
          </div>
        </>
      ) : (
        <div className="explorer-lines__empty">
          {selectedIds.length
            ? 'Недостаточно временных точек для динамики. Расширьте период или выберите другую метрику.'
            : 'Включите серии в таблице «Результаты», чтобы добавить их на график.'}
        </div>
      )}
    </div>
  );
}

function explorerAvgBps(row, meta) {
  const avg = Number(row?.avgBps);
  if (Number.isFinite(avg) && avg > 0) return avg;
  const bytes = Number(row?.bytes) || 0;
  const windowSeconds = Number(meta?.windowSeconds) || 0;
  return windowSeconds > 0 ? Math.round(bytes * 8 / windowSeconds) : 0;
}

function formatMetric(v, metric) {
  if (metric === 'bps') return fmtBits(v);
  if (metric === 'volume') return fmtBytes(v);
  if (metric === 'pps') return `${fmtNum(v)} п/с`;
  if (metric === 'fps') return `${fmtNum(v)} потоков/сек`;
  return fmtNum(v);
}

function formatMetricAxis(v, metric) {
  if (metric === 'bps' && typeof fmtBitsAxis === 'function') return fmtBitsAxis(v);
  const n = Number(v);
  if (!Number.isFinite(n)) return '0';
  if (metric === 'pps' || metric === 'fps') {
    if (n >= 1e6) return `${(n / 1e6).toFixed(n >= 10e6 ? 0 : 1)}M`;
    if (n >= 1e3) return `${(n / 1e3).toFixed(n >= 10e3 ? 0 : 1)}k`;
    return n < 10 && !Number.isInteger(n) ? n.toFixed(1) : String(Math.round(n));
  }
  if (typeof fmtCompact === 'function') return fmtCompact(n);
  return String(Math.round(n));
}

function metricAxisUnit(metric) {
  if (metric === 'bps') return 'бит/с';
  if (metric === 'volume') return 'байт';
  if (metric === 'pps') return 'п/с';
  if (metric === 'fps') return 'потоков/сек';
  return '';
}

function SaveObservationModal({
  open,
  onClose,
  filters,
  metricLabel,
  groupBy,
  dimensionById,
  timeRange,
  editingId,
  initialName,
  onSave,
}) {
  const defaultLookback = timeRange === '15m'
    ? '30m'
    : (['30m', '1h', '6h', '24h', '7d'].includes(timeRange) ? timeRange : '1h');
  const defaultTop = (groupBy || []).find((g) => (
    ['src_asn', 'dst_asn', 'src_ip', 'dst_ip', 'vlan', 'proto'].includes(explorerGroupFieldId(g))
  ))
    || groupBy?.[0]
    || 'src_asn';
  const [name, setName] = useState('');
  const [lookback, setLookback] = useState(defaultLookback);
  const [materializeEnabled, setMaterializeEnabled] = useState(true);
  const [reportEnabled, setReportEnabled] = useState(false);
  const [reportPeriod, setReportPeriod] = useState('yesterday');
  const [topGroup, setTopGroup] = useState(defaultTop);
  const [busy, setBusy] = useState(false);
  // Группировка из разбора трафика всегда важнее селектора: см. saveAsObservation.
  const groupSummary = (groupBy || []).map((g) => explorerGroupLabel(g, dimensionById || {})).join(' × ');

  useEffect(() => {
    if (!open) return;
    setName(initialName || `Наблюдение · ${metricLabel}`);
    setLookback(defaultLookback);
    setMaterializeEnabled(true);
    setReportEnabled(false);
    setReportPeriod('yesterday');
    setTopGroup(defaultTop);
    setBusy(false);
  }, [open, editingId, initialName, metricLabel, defaultLookback, defaultTop]);

  const submit = async () => {
    if (!onSave || busy) return;
    setBusy(true);
    try {
      await onSave({
        name,
        lookback,
        materializeEnabled,
        reportEnabled,
        reportPeriod,
        topGroup,
      });
    } finally {
      setBusy(false);
    }
  };

  const filterSummary = (filters || []).slice(0, 5).map((f) => `${f.field} ${f.op} ${f.value}`).join(' · ')
    + ((filters || []).length > 5 ? ' …' : '');

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editingId ? 'Обновить наблюдение' : 'Добавить в наблюдения'}
      subtitle="Будет график трафика по этим фильтрам и таблица топа."
      footer={(
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" disabled={busy} onClick={submit}>
            {busy ? 'Сохранение…' : (editingId ? 'Обновить' : 'Добавить')}
          </Button>
        </>
      )}
    >
      <div className="col" style={{ gap: 12 }}>
        <Card pad="sm" style={{ background: 'var(--surf-1)' }}>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            Фильтры: {filterSummary || 'нет'}
          </div>
        </Card>
        <div className="field">
          <label>Название</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
          <div className="field" style={{ flex: 1, minWidth: 140 }}>
            <label>Окно графика</label>
            <select className="input" value={lookback} onChange={(e) => setLookback(e.target.value)}>
              <option value="30m">30 минут</option>
              <option value="1h">1 час</option>
              <option value="6h">6 часов</option>
              <option value="24h">24 часа</option>
              <option value="7d">7 дней</option>
            </select>
          </div>
          <div className="field" style={{ flex: 1, minWidth: 160 }}>
            <label>{groupSummary ? 'Разрез' : 'Топ по полю'}</label>
            {groupSummary ? (
              <div
                className="input"
                style={{ display: 'flex', alignItems: 'center', color: 'var(--fg-secondary)' }}
                title={`Взято из группировки в разборе трафика: ${groupSummary}`}
              >
                {groupSummary}
              </div>
            ) : (
              <select className="input" value={topGroup} onChange={(e) => setTopGroup(e.target.value)}>
                {['src_asn', 'dst_asn', 'src_ip', 'dst_ip', 'vlan', 'proto', 'src_country', 'dst_country'].map((id) => (
                  <option key={id} value={id}>{dimensionById?.[id]?.label || id}</option>
                ))}
              </select>
            )}
          </div>
        </div>
        {(groupBy || []).length > OBSERVATION_MAX_GROUP_BY && (
          <div style={{ color: 'var(--fg-warning)', font: 'var(--pv-text-body-3)' }}>
            Наблюдение сохранит первые {OBSERVATION_MAX_GROUP_BY} измерения разреза:
            {' '}
            {(groupBy || []).slice(0, OBSERVATION_MAX_GROUP_BY)
              .map((g) => explorerGroupLabel(g, dimensionById || {}))
              .join(' × ')}
            . Остальные останутся только в разборе трафика.
          </div>
        )}
        <label className="row" style={{ gap: 8, alignItems: 'center' }}>
          <input
            type="checkbox"
            checked={materializeEnabled}
            onChange={(e) => setMaterializeEnabled(e.target.checked)}
          />
          Подготовка данных (rollup раз в 5 минут)
        </label>
        <div style={{ marginLeft: 24, color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
          Без неё плитка будет пустой: график и топ по группировке считаются из подготовленных данных.
          Счёт с момента создания, прошлые сутки не пересчитываются.
        </div>
        <label className="row" style={{ gap: 8, alignItems: 'center' }}>
          <input type="checkbox" checked={reportEnabled} onChange={(e) => setReportEnabled(e.target.checked)} />
          Ежедневный отчёт
        </label>
        {reportEnabled && (
          <label className="row" style={{ gap: 8, alignItems: 'center', marginLeft: 24 }}>
            за период
            <select className="input" style={{ width: 160 }} value={reportPeriod} onChange={(e) => setReportPeriod(e.target.value)}>
              <option value="yesterday">вчера</option>
              <option value="last_24h">последние 24 часа</option>
            </select>
          </label>
        )}
      </div>
    </Modal>
  );
}

function SaveQueryModal({ open, onClose, groupBy, metric, filters, dimensionById, metricLabel, editing, onSave }) {
  const defaultName = editing?.name || `${metricLabel} · ${groupBy.map((g) => explorerGroupLabel(g, dimensionById)).join(' × ')}`;
  const [name, setName] = useState(defaultName);
  const [description, setDescription] = useState(editing?.description || '');
  const [folder, setFolder] = useState(editing?.folder || 'Мои фильтры');
  const [isShared, setIsShared] = useState(Boolean(editing?.isShared));

  useEffect(() => {
    if (!open) return;
    setName(editing?.name || defaultName);
    setDescription(editing?.description || '');
    setFolder(editing?.folder || 'Мои фильтры');
    setIsShared(Boolean(editing?.isShared));
  }, [open, editing, defaultName]);

  const submit = () => {
    if (onSave) onSave({ name, description, folder, isShared, id: editing?.id });
    onClose();
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editing ? 'Редактировать фильтр' : 'Сохранить фильтр'}
      subtitle="Фильтр будет доступен на сервере в блоке «Сохранённые»."
      footer={(
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" icon="save" onClick={submit}>{editing ? 'Обновить' : 'Сохранить'}</Button>
        </>
      )}
    >
      <div className="grid grid--2col">
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Название</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Описание</label>
          <textarea className="input" rows="2" style={{ height: 'auto', paddingTop: 10 }} value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <div className="field">
          <label>Папка</label>
          <select className="input" value={folder} onChange={(e) => setFolder(e.target.value)}>
            <option>Мои фильтры</option>
            <option>Команда NOC</option>
            <option>Безопасность</option>
          </select>
        </div>
        <div className="field">
          <label>Доступ</label>
          <label className="row" style={{ gap: 8, marginTop: 8 }}>
            <input type="checkbox" checked={isShared} onChange={(e) => setIsShared(e.target.checked)} />
            <span>Поделиться с командой</span>
          </label>
        </div>
        <Card pad="sm" style={{ gridColumn: '1 / -1', background: 'var(--surf-1)' }}>
          <div>Метрика: <b>{metricLabel}</b></div>
          <div>Группировка: <b>{groupBy.map((g) => explorerGroupLabel(g, dimensionById)).join(', ')}</b></div>
          <div>Фильтры: <b>{filters.length || 'нет'}</b></div>
        </Card>
      </div>
    </Modal>
  );
}

Object.assign(window, { PageExplorer });
