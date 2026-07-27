/* Historical Explorer Flows — расследование flow-событий через явные фильтры */

const DEFAULT_EXPLORER_PRESETS = [
  {
    id: 'udp-talkers',
    name: 'UDP src → dst',
    metric: 'pps',
    groupBy: ['src_ip', 'dst_ip'],
    filters: [{ id: 1, field: 'proto', op: '=', value: 'UDP' }],
    limit: 10,
    vis: 'data',
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
    vis: 'data',
  },
  {
    id: 'top-dst-asn',
    name: 'Top destination ASN',
    metric: 'bps',
    groupBy: ['dst_asn'],
    filters: [],
    limit: 25,
    vis: 'data',
  },
];

const EXPLORER_DEFAULT_VISUAL_LIMIT = 5;
const EXPLORER_DEFAULT_FETCH_LIMIT = 25;
const EXPLORER_ON_DEMAND_FETCH_LIMITS = [50, 100];
const EXPLORER_DYNAMICS_MAX_SERIES = 5;
const EXPLORER_VIS_DEFAULT = 'data';

const VIS_TYPES = [
  { id: 'contribution', label: 'Вклад', icon: 'pieChart', hint: 'Кто даёт основной объём' },
  { id: 'data', label: 'Данные', icon: 'menu', hint: 'График динамики и детальная таблица' },
];

const EXPLORER_VIS_LEGACY_MAP = {
  lines: 'data',
  dynamics: 'data',
  donut: 'contribution',
  bars: 'contribution',
  sankey: 'contribution',
  relations: 'contribution',
  table: 'data',
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
  return new Set(
    sliceExplorerVisualRows(rows, visualLimit)
      .slice(0, EXPLORER_DYNAMICS_MAX_SERIES)
      .map((r) => r.id),
  );
}


function pruneDynamicsSeriesIds(seriesIds, results) {
  const resultIdSet = new Set(results.map((r) => r.id));
  return new Set([...seriesIds].filter((id) => resultIdSet.has(id)));
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

function buildExplorerAnalysisCardTitle({
  visLabel,
  metricLabel,
  groupLabels,
  visualLimit,
  loadedCount,
}) {
  const shown = resolveExplorerVisualCount(visualLimit, loadedCount);
  const groups = groupLabels.join(' × ');
  if (shown < loadedCount) {
    return `${visLabel}: ${metricLabel} · ${groups} · показано ${shown} из ${loadedCount}`;
  }
  return `${visLabel}: ${metricLabel} · топ ${loadedCount} ${groups}`;
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

function explorerRowFilterValue(row, dimId, valueIdx, dimensionById) {
  const kind = dimensionById[dimId]?.kind;
  if (kind === 'tcp_flags' || dimId === 'tcp_flags') {
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
  const raw = row.rawValues?.[valueIdx] ?? row.values[valueIdx];
  return { value: raw, label: null };
}

function explorerAsnSortKey(row, valueIdx) {
  const meta = row.asnMeta?.[valueIdx];
  if (meta?.asName) return meta.asName.toLowerCase();
  if (meta?.asn) return meta.asn;
  return row.rawValues?.[valueIdx] ?? row.values[valueIdx] ?? '';
}

const EMPTY_EXPLORER_SUMMARY = {
  totalBytes: 0,
  totalPackets: 0,
  totalFlows: 0,
  avgBps: 0,
  uniqSrc: 0,
  uniqDst: 0,
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
    title: 'Средняя бит/с',
    width: 140,
    sortAccessor: (r, meta) => explorerAvgBps(r, meta),
    render: (r, meta) => fmtBits(explorerAvgBps(r, meta)),
  },
  {
    key: 'pps',
    title: 'Пакеты/с',
    width: 120,
    sortAccessor: (r) => r.pps,
    render: (r) => formatMetric(r.pps, 'pps'),
  },
  {
    key: 'fps',
    title: 'Потоки/с',
    width: 120,
    sortAccessor: (r) => r.fps,
    render: (r) => formatMetric(r.fps, 'fps'),
  },
  {
    key: 'flows',
    title: 'Flows',
    width: 110,
    sortAccessor: (r) => r.flows,
    render: (r) => fmtNum(r.flows),
  },
  {
    key: 'packets',
    title: 'Packets',
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
    num: true,
    sortAccessor: (r) => (col.sortAccessor.length > 1 ? col.sortAccessor(r, meta) : col.sortAccessor(r)),
    render: (r) => (
      <span className="mono">{col.render.length > 1 ? col.render(r, meta) : col.render(r)}</span>
    ),
  }));
}

function isBuiltinExplorerPreset(query) {
  return DEFAULT_EXPLORER_PRESETS.some((d) => d.id === query?.id);
}

function mergeExplorerSavedFilters(items) {
  return [...DEFAULT_EXPLORER_PRESETS, ...(items || []).filter((q) => !isBuiltinExplorerPreset(q))];
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
    : 'Поиск по всем коммутаторам · уточните «IP или название»';
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

function loadLastAppliedExplorerQuery() {
  try {
    const raw = localStorage.getItem(EXPLORER_LAST_APPLIED_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function saveLastAppliedExplorerQuery(snapshot) {
  try {
    localStorage.setItem(EXPLORER_LAST_APPLIED_KEY, JSON.stringify(snapshot));
  } catch { /* ignore quota */ }
}

function resolveExplorerCacheTtlMs(timeRange) {
  return timeRange === 'custom' ? EXPLORER_CACHE_TTL_CUSTOM_MS : EXPLORER_CACHE_TTL_RELATIVE_MS;
}

function buildExplorerQueryKey(snapshot) {
  const migrated = migrateExplorerSnapshot(snapshot);
  if (!migrated) return '';
  const fetchLimit = resolveExplorerFetchLimit(migrated.fetchLimit ?? migrated.limit);
  return JSON.stringify({
    metric: migrated.metric || 'bps',
    groupBy: migrated.groupBy || [],
    filters: (migrated.filters || []).map(normalizeExplorerFilter),
    timeRange: migrated.timeRange || '1h',
    customPeriod: migrated.timeRange === 'custom' ? migrated.customPeriod : null,
    fetchLimit,
  });
}

function saveExplorerResultCache({ snapshot, payload }) {
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
    sessionStorage.setItem(EXPLORER_RESULT_CACHE_KEY, JSON.stringify(entry));
  } catch { /* ignore quota */ }
}

function loadExplorerResultCache(queryKey) {
  try {
    const raw = sessionStorage.getItem(EXPLORER_RESULT_CACHE_KEY);
    if (!raw) return null;
    const entry = JSON.parse(raw);
    if (!entry || entry.queryKey !== queryKey) return null;
    if (entry.expiresAt && Date.now() > new Date(entry.expiresAt).getTime()) return null;
    return entry;
  } catch {
    return null;
  }
}

function updateExplorerResultCacheUi(patch) {
  try {
    const raw = sessionStorage.getItem(EXPLORER_RESULT_CACHE_KEY);
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
    sessionStorage.setItem(EXPLORER_RESULT_CACHE_KEY, JSON.stringify(entry));
  } catch { /* ignore quota */ }
}

function clearExplorerResultCache() {
  try {
    sessionStorage.removeItem(EXPLORER_RESULT_CACHE_KEY);
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
  return {
    ...rest,
    filters: filters.map(normalizeExplorerFilter),
  };
}

function migrateExplorerUrlGlobals(globals = {}, urlFilters = []) {
  return migrateExplorerSnapshot({
    directions: globals.directions,
    collectorFilter: globals.collectorFilter,
    filters: urlFilters,
  }).filters;
}

const EXPLORER_ADD_FILTER_DEFS = [
  { id: '__direction__', label: 'Направление', group: 'Система', hint: 'Входящий, исходящий, транзит…' },
  { id: '__collector__', label: 'Коллекторы', group: 'Система', hint: 'Локации и экспортёры' },
];

const EXPLORER_QUICK_FILTERS = [
  { field: 'proto', label: 'TCP', val: 'TCP' },
  { field: 'proto', label: 'UDP', val: 'UDP' },
  { field: 'dst_port', label: 'DNS dst/53', val: '53' },
  { field: 'dst_port', label: 'HTTPS dst/443', val: '443' },
];

function buildExplorerQuerySnapshot({
  timeRange, customPeriod, filters, metric, groupBy, limit, vis,
  fetchLimit, visualLimit, dynamicsSeriesIds,
}) {
  return {
    timeRange,
    customPeriod: timeRange === 'custom' ? { ...(customPeriod || {}) } : null,
    filters: filters.map(normalizeExplorerFilter),
    metric,
    groupBy: [...groupBy],
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
    metric: urlState.metric || 'bps',
    groupBy: urlState.groupBy || ['src_ip', 'dst_ip'],
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
  saveLastAppliedExplorerQuery(migrated);
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
  if (migrated.metric) setters.setMetric(migrated.metric);
  if (Array.isArray(migrated.groupBy)) setters.setGroupBy(migrated.groupBy);
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

function restoreExplorerDraftFromSnapshot(snapshot, setters, { filterMode, setFilterText } = {}) {
  if (!snapshot) return null;
  const migrated = migrateExplorerSnapshot(snapshot);
  if (!migrated) return null;
  applyExplorerQuerySnapshot(migrated, setters);
  if (filterMode === 'text' && setFilterText) {
    setFilterText(serializeExplorerFilterDsl({
      timeRange: migrated.timeRange,
      customPeriod: migrated.customPeriod,
      filters: migrated.filters,
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
  timeRange, customPeriod, filters,
}) {
  const lines = [];
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    lines.push(`time between "${customPeriod.from}" and "${customPeriod.to}"`);
  } else {
    lines.push(`time range ${timeRange}`);
  }

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

  return lines.join('\n');
}

function parseExplorerFilterDsl(text, schema = null) {
  const lines = String(text || '').split('\n').map((l) => l.trim()).filter(Boolean);
  if (!lines.length) throw new Error('Фильтр пуст');

  let timeRange = '1h';
  let customPeriod = defaultCustomPeriod();
  const filters = [];
  let conditionIndex = 0;
  let pendingLogic = null;

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

  for (const rawLine of lines) {
    const lineLower = rawLine.toLowerCase();

    const logicOnly = parseLogicOnlyLine(rawLine);
    if (logicOnly) {
      pendingLogic = logicOnly;
      continue;
    }

    if (lineLower.startsWith('time ')) {
      const betweenMatch = rawLine.match(/^time\s+between\s+"([^"]+)"\s+and\s+"([^"]+)"/i);
      if (betweenMatch) {
        timeRange = 'custom';
        customPeriod = { from: betweenMatch[1], to: betweenMatch[2] };
        const err = validateExplorerCustomPeriod(customPeriod, 'custom');
        if (err) throw new Error(err);
        continue;
      }
      const rangeMatch = rawLine.match(/^time\s+range\s+(\S+)/i);
      if (rangeMatch) {
        timeRange = rangeMatch[1];
        continue;
      }
      throw new Error(`Неверный формат времени: ${rawLine}`);
    }

    const { logic: inlineLogic, rest } = parseLogicPrefix(rawLine);
    const logic = pendingLogic ?? (filters.length > 0 ? inlineLogic : 'and');
    pendingLogic = null;

    const systemInMatch = rest.match(/^(direction|collector)\s+(in|not_in|один из|ни один из)\s*\(([^)]+)\)/i);
    if (systemInMatch) {
      const field = systemInMatch[1].toLowerCase();
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
        const opRe = new RegExp(`^${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s+(.+)$`, 'i');
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

    throw new Error(`Не удалось разобрать строку: ${rawLine}`);
  }

  if (pendingLogic) {
    throw new Error('После связки условия (И, ИЛИ, И НЕ, ИЛИ НЕ) ожидается фильтр');
  }

  const periodErr = validateExplorerCustomPeriod(
    timeRange === 'custom' ? customPeriod : {},
    timeRange,
  );
  if (periodErr) throw new Error(periodErr);

  return { timeRange, customPeriod, filters };
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

  [
    lineSuggestion('time range', 'time range 1h', 'Период'),
    lineSuggestion('time between', 'time between "YYYY-MM-DDTHH:mm" and "YYYY-MM-DDTHH:mm"', 'Ручной диапазон'),
    lineSuggestion('direction', 'direction in (in, out, transit)', 'Направления'),
    lineSuggestion('collector', 'collector in ("collector-id")', 'Коллекторы'),
    ...explorerLogicAutocompleteEntries().map(({ token, hint }) => lineSuggestion(token, `${token} `, hint)),
  ]
    .filter((item) => matchesNeedle(item.label, item.hint))
    .forEach((item) => suggestions.push(item));

  if (!rest.includes(' ') && !['time', 'direction', 'collector'].some((k) => lowerRest.startsWith(k))) {
    const fieldNeedle = rest.toLowerCase();
    fields
      .filter((f) => fieldNeedle && (
        f.id.toLowerCase().includes(fieldNeedle)
        || String(f.label).toLowerCase().includes(fieldNeedle)
      ))
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

  if (lowerRest.startsWith('direction')) {
    ['total', 'in', 'out', 'transit', 'internal', 'unknown'].forEach((dir) => {
      suggestions.push(lineSuggestion(dir, `direction in (${dir})`, 'Значение direction'));
    });
    suggestions.push(lineSuggestion('total, in, out', 'direction in (total, in, out)', 'Несколько направлений'));
  }

  if (lowerRest.startsWith('collector')) {
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
      suggestions.push(lineSuggestion(
        String(item.label || v),
        `${logicPrefix}${field} ${resolvedOp} ${v}`,
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
    if (!f.op || op === '=') op = 'has_any';
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
    return {
      id: 'collector',
      label: 'Коллекторы',
      group: 'Система',
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

function normalizeFilterPickerItem(item) {
  if (item == null) return null;
  if (typeof item === 'string') return { id: item, label: item, hint: null, group: null };
  return {
    id: item.value ?? item.id,
    label: item.label ?? item.value ?? item.id,
    hint: item.hint || null,
    group: item.group || null,
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
    const needle = q.trim().toLowerCase();
    if (!needle) return normalized;
    return normalized.filter((item) => (
      String(item.label).toLowerCase().includes(needle)
      || String(item.id).toLowerCase().includes(needle)
      || String(item.hint || '').toLowerCase().includes(needle)
    ));
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
          flex: 1,
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
          style={{
            ...menuStyle,
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
            <div key={groupName || 'all'}>
              {grouped && groupName && (
                <div style={{ font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-muted)', padding: '8px 4px 4px' }}>{groupName}</div>
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
        zIndex: 1200,
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

function FilterValueInput({ fieldId, meta, value, label, onChange, onClear, switchIpScope = '' }) {
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
    />
  ) : meta?.valueOptions?.length ? (
    <FilterSearchPicker
      items={meta.valueOptions}
      value={value}
      onChange={(next) => onChange({ value: next, label: null })}
      buttonLabel={value ? String(value) : undefined}
      searchPlaceholder="Поиск значения..."
      emptyLabel="Выбрать значение…"
      inputPlaceholder={meta.valueHint}
      allowCustom
      mono
      style={{ flex: 1, minWidth: 0 }}
    />
  ) : (
    <input
      className="input mono"
      value={value ?? ''}
      placeholder={meta?.valueHint || 'value'}
      title={meta?.valueHint || undefined}
      onChange={(e) => onChange({ value: e.target.value, label: null })}
      style={{ flex: 1, minWidth: 0 }}
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

function buildExplorerResultColumns({
  groupBy,
  dimensions,
  dimensionById,
  metricLabel,
  metric,
  meta,
  showAllGroups,
  showAllMetrics,
  onAddFilter,
  onFocusRow,
  onExcludeRow,
  onDynamicsRow,
  selectedDynamicsSeriesIds,
  onToggleDynamicsSeries,
}) {
  const visibleDimensionIds = showAllGroups
    ? dimensions.map((d) => d.id)
    : groupBy;

  const groupCols = visibleDimensionIds.map((dimId, colIdx) => {
    const valueIdx = groupBy.indexOf(dimId);
    const hasValue = valueIdx >= 0;
    const isAsn = dimId.endsWith('asn');
    return {
      key: `dim-${dimId}`,
      title: dimensionById[dimId]?.label || dimId,
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
        const filterVal = explorerRowFilterValue(r, dimId, valueIdx, dimensionById);
        const monoClass = dimId.endsWith('ip') || dimId.endsWith('_mac') ? 'mono' : '';
        const isTcpFlags = dimId === 'tcp_flags';
        const rawTooltip = isTcpFlags && r.rawValues?.[valueIdx] != null
          ? ` · raw ${r.rawValues[valueIdx]}`
          : '';
        const showColorSwatch = dimId !== 'dst_ip' && (colIdx === 0 || selectedDynamicsSeriesIds?.has(r.id));
        return (
          <button
            type="button"
            className="row"
            style={{ all: 'unset', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}
            onClick={(e) => {
              e.stopPropagation();
              onAddFilter(dimId, filterVal.value, filterVal.label);
            }}
            title={`Добавить в фильтры${rawTooltip}`}
          >
            {showColorSwatch && (
              <span style={{ width: 10, height: 10, borderRadius: 3, background: r.color, flexShrink: 0 }} />
            )}
            <span className={monoClass} style={{ font: 'var(--pv-text-body-2-bold)' }}>
              {isAsn ? explorerAsnDisplayValue(r, valueIdx) : r.values[valueIdx]}
            </span>
          </button>
        );
      },
    };
  });

  const metricCol = {
    key: 'metric',
    title: metricLabel,
    align: 'right',
    width: 140,
    num: true,
    sortAccessor: (r) => r.metric,
    render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{formatMetric(r.metric, metric)}</span>,
  };

  const pctCol = {
    key: 'pct',
    title: `Доля · ${metricLabel}`,
    align: 'right',
    width: 90,
    num: true,
    sortAccessor: (r) => r.pct,
    render: (r) => <span className="mono">{r.pct.toFixed(2)}%</span>,
  };

  const actionsCol = {
    key: 'actions',
    title: 'Действия',
    sortAccessor: () => '',
    headerClassName: 'explorer-col-actions',
    cellClassName: 'explorer-col-actions',
    render: (r) => (r.isOthers ? null : (
      <ExplorerRowActions
        row={r}
        onFocus={onFocusRow}
        onExclude={onExcludeRow}
        onDynamics={onDynamicsRow}
        selectedDynamicsSeriesIds={selectedDynamicsSeriesIds}
        onToggleDynamicsSeries={onToggleDynamicsSeries}
      />
    )),
  };

  const baseCols = [...groupCols, metricCol, pctCol, actionsCol];
  if (!showAllMetrics) return baseCols;
  return [...baseCols, ...buildExplorerMetricColumnDefs(meta)];
}

function PageExplorer({ onNavigate, displayTimezone }) {
  const canWrite = AuthAccess.canWritePage('explorer');
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
  const [metric, setMetric] = useState(urlState?.metric || 'bps');
  const [groupBy, setGroupBy] = useState(
    composeGroupBy
      || urlState?.groupBy
      || ['src_ip', 'dst_ip'],
  );
  const [filters, setFilters] = useState(() => {
    // Editing an observation must load THAT observation's filters, not last Explorer query.
    if (composeFilters) return cloneExplorerFilters(composeFilters);
    if (urlState?.filters?.length) return cloneExplorerFilters(urlState.filters);
    const last = loadLastAppliedExplorerQuery();
    if (last) return cloneExplorerFilters(migrateExplorerSnapshot(last).filters);
    return cloneExplorerFilters(migrateExplorerUrlGlobals(urlGlobals, []));
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
  const [addingDim, setAddingDim] = useState(false);
  const dimAnchorRef = React.useRef(null);
  const [showSave, setShowSave] = useState(false);
  const [showObservationSave, setShowObservationSave] = useState(false);
  const [editingSaved, setEditingSaved] = useState(null);
  const canWriteObservation = AuthAccess.canWritePage('observations') || canWrite;
  const [selected, setSelected] = useState(new Set());
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
  const [savedFilters, setSavedFilters] = useState(DEFAULT_EXPLORER_PRESETS);
  const [lastApplied, setLastApplied] = useState(() => loadLastAppliedExplorerQuery());
  const [exporting, setExporting] = useState(false);
  const [showAllResultColumns, setShowAllResultColumns] = useState(true);
  const [showAllGroupColumns, setShowAllGroupColumns] = useState(false);
  const [visualLimit, setVisualLimit] = useState(EXPLORER_DEFAULT_VISUAL_LIMIT);
  const [dynamicsSeriesIds, setDynamicsSeriesIds] = useState(() => new Set());
  const [dynamicsFocusRowId, setDynamicsFocusRowId] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [periodZoomStack, setPeriodZoomStack] = useState([]);
  const periodRef = React.useRef({ timeRange, customPeriod });
  const dynamicsQueryVersionRef = React.useRef(queryVersion);
  const skipDynamicsDefaultRef = React.useRef(false);
  const mountRestoreDoneRef = React.useRef(false);

  useEffect(() => {
    periodRef.current = { timeRange, customPeriod };
  }, [timeRange, customPeriod]);

  const dimensions = schema?.dimensions || [];
  const metrics = schema?.metrics || [];
  const dimensionById = useMemo(() => Object.fromEntries(dimensions.map((d) => [d.id, d])), [dimensions]);

  const querySetters = useMemo(() => ({
    setTimeRange, setCustomPeriod, setFilters, setMetric, setGroupBy, setLimit, setVis,
  }), []);

  const draftRestoreOpts = useMemo(() => ({ filterMode, setFilterText }), [filterMode]);

  const cacheHydrateHandlers = useMemo(() => ({
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
    skipDynamicsDefaultRef,
    dynamicsQueryVersionRef,
  }), [querySetters, draftRestoreOpts]);

  useEffect(() => {
    if (mountRestoreDoneRef.current) return;
    mountRestoreDoneRef.current = true;

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
    const cached = loadExplorerResultCache(queryKey);
    if (cached) {
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
    ApiClient.loadExplorerSchema().then((data) => {
      if (!cancelled && data) setSchema(data);
    }).catch(() => {});
    ApiClient.loadExplorerSavedFilters().then((items) => {
      if (!cancelled && Array.isArray(items)) {
        setSavedFilters(mergeExplorerSavedFilters(items));
      }
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (filterMode !== 'text') return;
    setFilterText(serializeExplorerFilterDsl({
      timeRange, customPeriod, filters,
    }));
    setFilterTextError(null);
  }, [filterMode]);

  const applyParsedTextToDraft = (text) => {
    const parsed = parseExplorerFilterDsl(text, schema);
    setTimeRange(parsed.timeRange);
    if (parsed.timeRange === 'custom') setCustomPeriod(parsed.customPeriod);
    setFilters(cloneExplorerFilters(parsed.filters));
    setFilterTextError(null);
    return parsed;
  };

  const changeFilterMode = (nextMode) => {
    if (nextMode === filterMode) return;
    if (filterMode === 'text' && nextMode === 'graphic') {
      try {
        applyParsedTextToDraft(filterText);
      } catch (err) {
        setFilterTextError(err.message);
        pushToast({ kind: 'error', title: 'Ошибка фильтра', desc: err.message });
        return;
      }
    }
    if (nextMode === 'text') {
      setFilterText(serializeExplorerFilterDsl({
        timeRange, customPeriod, filters,
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
    }));
    setFilterTextError(null);
    setFilterRowErrors({});
  };

  const availableMetrics = useMemo(
    () => (metrics.length ? metrics : [{ id: 'bps', label: 'Средняя бит/с' }])
      .filter((m) => !(m.id === 'uniq_src' && groupBy.includes('src_ip'))),
    [metrics, groupBy],
  );

  useEffect(() => {
    if (metric === 'uniq_src' && groupBy.includes('src_ip')) setMetric('bps');
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
      metric: qMetric,
      groupBy: qGroupBy,
    } = migrated;
    ApiClient.loadExplorerQuery({
      metric: qMetric,
      groupBy: qGroupBy,
      filters: (qFilters || []).map(normalizeExplorerFilter),
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
          metric: qMetric,
          groupBy: qGroupBy,
          limit: fetchLimit,
          vis,
          fetchLimit,
          visualLimit,
          dynamicsSeriesIds: [...resolvedSeriesIds],
        });
        saveLastAppliedExplorerQuery(snapshot);
        setLastApplied(snapshot);
        saveExplorerResultCache({
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
    setDynamicsFocusRowId(null);
  }, [queryVersion]);

  useEffect(() => {
    if (!hasAppliedQuery || !results.length) {
      if (!results.length) {
        setDynamicsSeriesIds(new Set());
        setDynamicsFocusRowId(null);
      }
      return;
    }

    const queryChanged = dynamicsQueryVersionRef.current !== queryVersion;
    if (queryChanged) dynamicsQueryVersionRef.current = queryVersion;

    if (dynamicsFocusRowId) {
      if (results.some((r) => r.id === dynamicsFocusRowId)) {
        setDynamicsSeriesIds(new Set([dynamicsFocusRowId]));
      } else {
        setDynamicsFocusRowId(null);
        setDynamicsSeriesIds(defaultDynamicsSeriesIds(results, visualLimit));
      }
      return;
    }

    if (queryChanged) {
      setDynamicsSeriesIds(defaultDynamicsSeriesIds(results, visualLimit));
      return;
    }

    setDynamicsSeriesIds((prev) => {
      const pruned = pruneDynamicsSeriesIds(prev, results);
      if (prev.size === 0) {
        return defaultDynamicsSeriesIds(results, visualLimit);
      }
      if (pruned.size > 0) return pruned;
      return defaultDynamicsSeriesIds(results, visualLimit);
    });
  }, [queryVersion, visualLimit, rows, hasAppliedQuery, dynamicsFocusRowId, results]);

  const dynamicsSeriesKey = [...dynamicsSeriesIds].sort().join('|');
  useEffect(() => {
    if (!hasAppliedQuery || source === 'error') return;
    updateExplorerResultCacheUi({
      vis,
      visualLimit,
      dynamicsSeriesIds: [...dynamicsSeriesIds],
    });
  }, [vis, visualLimit, dynamicsSeriesKey, hasAppliedQuery, source]);

  const schemaMetrics = metrics.length ? metrics : [{ id: 'bps', label: 'Средняя бит/с' }];
  const metricLabel = availableMetrics.find((m) => m.id === metric)?.label || metric;
  const groupLabels = groupBy.map((g) => dimensionById[g]?.label || g);
  const appliedMetricLabel = schemaMetrics.find((m) => m.id === appliedMetric)?.label || appliedMetric;
  const appliedGroupLabels = appliedGroupBy.map((g) => dimensionById[g]?.label || g);
  const appliedDefaultSortKey = appliedMetric === 'volume' ? 'bytes' : appliedMetric === 'bps' ? 'avgBps' : appliedMetric === 'flows' ? 'flows' : 'metric';

  const requeryWithPeriod = (nextTimeRange, nextCustomPeriod) => {
    setTimeRange(nextTimeRange);
    setCustomPeriod(nextCustomPeriod);
    if (!hasAppliedQuery || !appliedSnapshot) return;
    const periodErr = validateExplorerCustomPeriod(
      nextTimeRange === 'custom' ? nextCustomPeriod : {},
      nextTimeRange,
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
    if (!range?.from || !range?.to || validateExplorerCustomPeriod(range, 'custom')) return;
    setPeriodZoomStack((stack) => [...stack, periodRef.current]);
    requeryWithPeriod('custom', { from: range.from, to: range.to });
  };

  const resetExplorerChartRangeZoom = () => {
    if (!periodZoomStack.length) return;
    const prev = periodZoomStack[periodZoomStack.length - 1];
    setPeriodZoomStack((stack) => stack.slice(0, -1));
    requeryWithPeriod(prev.timeRange, prev.customPeriod);
  };

  const runQuery = () => {
    let snapshot = buildExplorerQuerySnapshot({
      timeRange, customPeriod, filters, metric, groupBy, limit, vis,
    });
    let activeFilters = filters;
    if (filterMode === 'text') {
      try {
        const parsed = applyParsedTextToDraft(filterText);
        activeFilters = parsed.filters;
        snapshot = {
          ...snapshot,
          timeRange: parsed.timeRange,
          customPeriod: parsed.customPeriod,
          filters: parsed.filters,
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

    snapshot = { ...snapshot, filters: validFilters };

    const periodErr = validateExplorerCustomPeriod(
      snapshot.timeRange === 'custom' ? snapshot.customPeriod : {},
      snapshot.timeRange,
    );
    if (periodErr) {
      pushToast({ kind: 'error', title: 'Неверный период', desc: periodErr });
      return;
    }
    if (filterMode === 'graphic' && validFilters.length !== activeFilters.length) {
      setFilters(validFilters);
    }
    skipDynamicsDefaultRef.current = false;
    setDynamicsSeriesIds(new Set());
    setDynamicsFocusRowId(null);
    setAppliedSnapshot(buildExplorerQuerySnapshot({
      ...snapshot,
      limit: resolveExplorerFetchLimit(snapshot.limit ?? limit),
      fetchLimit: resolveExplorerFetchLimit(snapshot.limit ?? limit),
      visualLimit: EXPLORER_DEFAULT_VISUAL_LIMIT,
      dynamicsSeriesIds: [],
    }));
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
    setGroupBy(snapshot.groupBy);
    setFetchLimit(resolveExplorerFetchLimit(snapshot.limit));
    setVis(normalizeExplorerVis(snapshot.vis));
    setVisualLimit(EXPLORER_DEFAULT_VISUAL_LIMIT);
    setLimit(EXPLORER_DEFAULT_VISUAL_LIMIT);
    setSelected(new Set());
    skipDynamicsDefaultRef.current = false;
    setDynamicsSeriesIds(new Set());
    setDynamicsFocusRowId(null);
    setAppliedSnapshot(snapshot);
    setHasAppliedQuery(true);
    setQueryVersion((v) => v + 1);
  };

  const applyLastApplied = () => {
    if (!lastApplied) return;
    const queryKey = buildExplorerQueryKey(lastApplied);
    const cached = loadExplorerResultCache(queryKey);
    if (cached && hydrateExplorerFromCachedEntry(cached, { ...cacheHydrateHandlers, queryVersion })) {
      return;
    }
    applyExplorerQuerySnapshot(migrateExplorerSnapshot(lastApplied), querySetters);
    setMetric(lastApplied.metric || metric);
    setGroupBy(lastApplied.groupBy || groupBy);
    setFetchLimit(resolveExplorerFetchLimit(lastApplied.fetchLimit ?? lastApplied.limit));
    setVis(normalizeExplorerVis(lastApplied.vis));
    setVisualLimit(lastApplied.visualLimit ?? EXPLORER_DEFAULT_VISUAL_LIMIT);
    setLimit(lastApplied.visualLimit ?? EXPLORER_DEFAULT_VISUAL_LIMIT);
    setSelected(new Set());
    skipDynamicsDefaultRef.current = false;
    setDynamicsSeriesIds(new Set());
    setDynamicsFocusRowId(null);
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
      timeRange, customPeriod, filters, metric, groupBy, limit, vis,
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
    if (!filters?.length) {
      pushToast({ kind: 'error', title: 'Нужен фильтр', desc: 'Добавьте хотя бы одно условие, затем «Добавить в наблюдения».' });
      return;
    }
    setShowObservationSave(true);
  };

  const saveAsObservation = async ({ name, lookback, liveEnabled, refreshSec, reportEnabled, reportPeriod, topGroup }) => {
    const nextFilters = (filters || []).map((f, i) => ({
      id: f.id || `f-${i}`,
      field: f.field,
      op: f.op || '=',
      value: f.value ?? '',
      label: f.label ?? null,
      logic: f.logic || 'and',
    })).filter((f) => f.field);

    try {
      let id = observationCompose?.editId || null;
      if (id) {
        const existing = await ApiClient.loadObservation(id);
        const chartGroup = (groupBy || []).length
          ? [...groupBy]
          : [topGroup || 'src_asn'];
        await ApiClient.updateObservation(id, {
          ...existing,
          name: (name || '').trim() || existing.name,
          filters: nextFilters,
          widgets: [
            {
              id: 'w-ts',
              type: 'timeseries_bps',
              metric: metric || 'bps',
              groupBy: chartGroup,
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
        const chartGroup = (groupBy || []).length
          ? [...groupBy]
          : [topGroup || 'src_asn'];
        const payload = {
          name: (name || '').trim() || `Наблюдение · ${metricLabel}`,
          description: '',
          lookback: lookback || '1h',
          filters: nextFilters,
          widgets: [
            {
              id: 'w-ts',
              type: 'timeseries_bps',
              metric: metric || 'bps',
              groupBy: chartGroup,
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
          live: { enabled: !!liveEnabled, refreshSec: Math.max(300, Number(refreshSec) || 300) },
          materialize: { enabled: false, intervalSec: Math.max(300, Number(refreshSec) || 300) },
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

  const copyShareLink = async () => {
    const url = buildExplorerShareUrl({
      metric,
      groupBy,
      filters: filters.map(normalizeExplorerFilter),
      limit,
      vis,
      timeRange,
      customPeriod,
    });
    try {
      await copyTextToClipboard(url);
      pushToast({ kind: 'success', title: 'Ссылка скопирована', desc: 'URL содержит параметры запроса.' });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось скопировать', desc: err.message });
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
      const blob = await ApiClient.exportExplorerCsv(exportPayload);
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

  const addFilterFromCell = (field, value, label) => {
    const meta = filterFieldMeta(schema, field);
    const op = meta?.type === 'tcp_flags' ? 'eq' : '=';
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
    setHasAppliedQuery(true);
    setQueryVersion((v) => v + 1);
    if (toastTitle) {
      pushToast({ kind: 'success', title: toastTitle, desc: toastDesc });
    }
  };

  const focusRow = (row) => {
    const nextFilters = [
      ...filters,
      ...appliedGroupBy.map((field, idx) => {
        const filterVal = explorerRowFilterValue(row, field, idx, dimensionById);
        const isTcpFlags = field === 'tcp_flags' || dimensionById[field]?.kind === 'tcp_flags';
        return {
          id: Date.now() + idx + Math.random(),
          field,
          op: isTcpFlags ? 'eq' : '=',
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
      ...appliedGroupBy.map((field, idx) => {
        const filterVal = explorerRowFilterValue(row, field, idx, dimensionById);
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

  const showRowDynamics = (row) => {
    setVis('data');
    setDynamicsFocusRowId(row.id);
    setDynamicsSeriesIds(new Set([row.id]));
  };

  const clearDynamicsFocus = () => {
    setDynamicsFocusRowId(null);
    setDynamicsSeriesIds(defaultDynamicsSeriesIds(results, visualLimit));
  };

  const toggleDynamicsSeries = (rowId) => {
    if (dynamicsFocusRowId) {
      if (dynamicsFocusRowId === rowId) clearDynamicsFocus();
      return;
    }
    setDynamicsSeriesIds((prev) => {
      const next = new Set(prev);
      if (next.has(rowId)) next.delete(rowId);
      else {
        if (next.size >= EXPLORER_DYNAMICS_MAX_SERIES) {
          pushToast({
            kind: 'warning',
            title: 'Лимит серий',
            desc: `Можно сравнить не более ${EXPLORER_DYNAMICS_MAX_SERIES} серий.`,
          });
          return prev;
        }
        next.add(rowId);
      }
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

  const drillDownSelected = () => {
    const row = results.find((r) => selected.has(r.id));
    if (!row) return;
    focusRow(row);
    setSelected(new Set());
  };

  const resultTableColumns = useMemo(() => buildExplorerResultColumns({
    groupBy: appliedGroupBy,
    dimensions,
    dimensionById,
    metricLabel: appliedMetricLabel,
    metric: appliedMetric,
    meta,
    showAllGroups: showAllGroupColumns,
    showAllMetrics: showAllResultColumns,
    onAddFilter: addFilterFromCell,
    onFocusRow: focusRow,
    onExcludeRow: excludeRow,
    onDynamicsRow: showRowDynamics,
    selectedDynamicsSeriesIds: dynamicsSeriesIds,
    onToggleDynamicsSeries: toggleDynamicsSeries,
  }), [appliedGroupBy, dimensions, dimensionById, appliedMetricLabel, appliedMetric, meta, showAllGroupColumns, showAllResultColumns, addFilterFromCell, focusRow, excludeRow, showRowDynamics, dynamicsSeriesIds, toggleDynamicsSeries]);

  const visibleResults = useMemo(
    () => sliceExplorerVisualRows(results, visualLimit),
    [results, visualLimit],
  );
  const othersEligible = appliedGroupBy.length > 0
    && Boolean(EXPLORER_OTHERS_METRIC[appliedMetric])
    && (!meta?.pctScope || meta.pctScope === 'full_filtered');
  const othersRow = useMemo(() => buildExplorerOthersRow({
    shownRows: visibleResults,
    summary,
    meta,
    metric: appliedMetric,
    groupBy: appliedGroupBy,
  }), [visibleResults, summary, meta, appliedMetric, appliedGroupBy]);
  const activeVisMeta = VIS_TYPES.find((v) => v.id === vis) || VIS_TYPES[0];

  const idleState = !hasAppliedQuery && source !== 'loading';
  const isRefreshingData = refreshing;

  return (
    <div className="main__container" style={{ maxWidth: 1820, padding: 0 }}>
      <div className="page-head" style={{ padding: '0 4px' }}>
        <div>
          <h1>Разбор трафика</h1>
          <p>Historical flow explorer: фильтры по времени, направлению, коллекторам, сущностям, протоколам, VLAN, ASN, L3 и сервисам.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="copy" onClick={copyShareLink}>Поделиться</Button>
          <Button kind="ghost" icon="export" onClick={exportCsv} disabled={!hasAppliedQuery || !results.length || exporting}>
            {exporting ? 'Экспорт…' : 'Экспорт'}
          </Button>
        </div>
      </div>

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

        <Card pad="sm">
          <div className="row" style={{ gap: 14, flexWrap: 'wrap' }}>
            {!filterPanel && (
              <Button kind="ghost" size="sm" icon="filter" onClick={openFilterPanel}>
                Фильтры
                {filters.length > 0 && <span className="nav-item__badge" style={{ marginLeft: 4 }}>{filters.length}</span>}
              </Button>
            )}
            <BuilderControl label="Метрика">
              <select className="input" style={{ width: 'auto', minWidth: 140 }} value={metric} onChange={(e) => setMetric(e.target.value)}>
                {availableMetrics.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
              </select>
            </BuilderControl>
            <BuilderControl label="Группировка">
              <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                {groupBy.map((d) => (
                  <span key={d} className="badge badge--info" style={{ padding: '4px 10px 4px 8px', gap: 6, fontSize: 12 }}>
                    {dimensionById[d]?.label || d}
                    <button onClick={() => setGroupBy((g) => g.filter((x) => x !== d))} style={{ all: 'unset', cursor: 'pointer', opacity: 0.8, marginLeft: 2 }}>
                      <Icon name="x" size={10} stroke={2.5} />
                    </button>
                  </span>
                ))}
                <div ref={dimAnchorRef}>
                  <Button kind="ghost" size="xs" icon="plus" onClick={() => setAddingDim((v) => !v)}>Измерение</Button>
                  {addingDim && (
                    <DimensionPicker
                      anchorRef={dimAnchorRef}
                      dimensions={dimensions}
                      selected={groupBy}
                      onPick={(id) => { if (!groupBy.includes(id)) setGroupBy([...groupBy, id]); setAddingDim(false); }}
                      onClose={() => setAddingDim(false)}
                    />
                  )}
                </div>
              </div>
            </BuilderControl>
          </div>
        </Card>

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
            canWrite={canWrite}
            onSave={() => { setEditingSaved(null); setShowSave(true); }}
            onSaveAsObservation={canWriteObservation ? openSaveAsObservation : null}
            onEditSaved={(q) => {
              const payload = migrateExplorerSnapshot(q.query || q);
              applyExplorerQuerySnapshot(payload, querySetters);
              if (payload.metric) setMetric(payload.metric);
              if (Array.isArray(payload.groupBy)) setGroupBy(payload.groupBy);
              if (payload.limit) setLimit(payload.limit);
              if (payload.vis) setVis(normalizeExplorerVis(payload.vis));
              setEditingSaved(q);
              setShowSave(true);
            }}
            onDeleteSaved={deleteSavedFilter}
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
                <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <ExplorerAnalysisTabs value={vis} onChange={setVis} compact />
                  <ExplorerVisualLimitControl
                    total={results.length}
                    fetchLimit={fetchLimit}
                    value={visualLimit}
                    loadingMore={refreshing}
                    onChange={applyDisplayLimit}
                    onRequestFetchLimit={requestFetchLimit}
                  />
                  <Button kind="ghost" size="sm" icon="refresh" onClick={runQuery} />
                </div>
              );

              const analysisBody = isRefreshingData ? (
                <ExplorerRefreshingData />
              ) : source === 'loading' && !results.length ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--fg-secondary)' }}>Выполняем запрос…</div>
              ) : source === 'error' && !results.length ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--st-critical)' }}>{error || ApiClient.LOAD_FAILED}</div>
              ) : results.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--fg-secondary)' }}>
                  Нет данных для выбранных фильтров. Ослабьте фильтры или расширьте период.
                </div>
              ) : null;

              if (vis === 'data') {
                return (
                  <Card
                    className="card--explorer-results"
                    title="Результаты"
                    subtitle="График динамики и таблица: управляйте сериями через «На график» / «Скрыть с графика», строки — для drill-down"
                    loadMs={loadMs}
                    serverMs={serverMs}
                    pad="0"
                    tools={(
                      <div className="explorer-results-tools">
                        {analysisToolbar}
                        {selected.size > 0 && (
                          <>
                            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', whiteSpace: 'nowrap' }}>
                              Выбрано: <b style={{ color: 'var(--fg-primary)' }}>{selected.size}</b>
                            </span>
                            <Button kind="ghost" size="sm" icon="filter" onClick={drillDownSelected}>Drill-down</Button>
                            <Button kind="ghost" size="sm" icon="x" onClick={() => setSelected(new Set())}>Сброс</Button>
                          </>
                        )}
                        {dimensions.length > 1 && (
                          <Button
                            kind={showAllGroupColumns ? 'primary' : 'ghost'}
                            size="sm"
                            icon="layers"
                            onClick={() => setShowAllGroupColumns((v) => !v)}
                          >
                            {showAllGroupColumns ? 'Скрыть группировки' : 'Все группировки'}
                          </Button>
                        )}
                        <Button
                          kind={showAllResultColumns ? 'primary' : 'ghost'}
                          size="sm"
                          icon="sliders"
                          onClick={() => setShowAllResultColumns((v) => !v)}
                        >
                          {showAllResultColumns ? 'Скрыть поля' : 'Все поля'}
                        </Button>
                        <Button kind="ghost" size="sm" icon="download" onClick={exportCsv} disabled={!hasAppliedQuery || !results.length || exporting}>CSV</Button>
                      </div>
                    )}
                  >
                    {analysisBody || (
                      <div className="explorer-results-layout">
                        <div className="explorer-results-chart">
                          <DynamicsChartExplorer
                            active={vis === 'data'}
                            results={results}
                            metric={appliedMetric}
                            metricLabel={appliedMetricLabel}
                            resultSeries={resultSeries}
                            displayTimezone={displayTimezone}
                            chartLongRange={isLongChartRange(appliedTimeRange, appliedCustomPeriod)}
                            selectedSeriesIds={dynamicsSeriesIds}
                            focusRowId={dynamicsFocusRowId}
                            onClearFocus={clearDynamicsFocus}
                            onRangeSelect={applyExplorerChartRangeZoom}
                            bucketSeconds={explorerGranularityBucketSeconds(meta?.granularity)}
                            totalPoints={othersEligible ? timeseries : null}
                          />
                        </div>
                        <DataTable
                          rows={visibleResults}
                          rowKey="id"
                          selectable
                          selected={selected}
                          onSelectChange={setSelected}
                          onRowClick={(row) => {
                            setSelected((prev) => {
                              const next = new Set(prev);
                              if (next.has(row.id)) next.delete(row.id);
                              else next.add(row.id);
                              return next;
                            });
                          }}
                          getRowClassName={(row) => (dynamicsSeriesIds.has(row.id) ? 'is-dynamics-active' : '')}
                          pinnedRows={othersRow ? [othersRow] : null}
                          pageSize={Math.max(resolveExplorerVisualCount(visualLimit, results.length), 1)}
                          initialSort={{ key: appliedDefaultSortKey, dir: 'desc' }}
                          emptyTitle={source === 'loading' ? 'Выполняем запрос…' : 'Нет данных'}
                          footerNote={(
                            <>
                              <span>
                                Показано {visibleResults.length} из {results.length} загруженных · {meta?.granularity || 'raw'}
                                {meta?.trafficSampled ? ' · с учётом sampling' : ''}
                              </span>
                              <span>
                                Запрос выполнен за <b style={{ color: 'var(--fg-primary)' }}>{serverMs ?? '—'} мс</b>
                                {' · ClickHouse · '}{meta?.dataTable || 'flows_raw'}
                              </span>
                            </>
                          )}
                          columns={resultTableColumns}
                        />
                      </div>
                    )}
                  </Card>
                );
              }

              return (
                <Card
                  title={buildExplorerAnalysisCardTitle({
                    visLabel: activeVisMeta.label,
                    metricLabel: appliedMetricLabel,
                    groupLabels: appliedGroupLabels,
                    visualLimit,
                    loadedCount: results.length,
                  })}
                  subtitle={`${timeRangeLabel(appliedTimeRange, appliedCustomPeriod)} · ${meta?.dataTable || 'flows_raw'}${source === 'error' ? ` · ${error || ApiClient.LOAD_FAILED}` : ''}`}
                  loadMs={loadMs}
                  serverMs={serverMs}
                  tools={analysisToolbar}
                >
                  {analysisBody || (
                    <ContributionBarsExplorer
                      results={othersRow ? [...visibleResults, othersRow] : visibleResults}
                      metric={appliedMetric}
                      metricLabel={appliedMetricLabel}
                      onFocus={focusRow}
                      onExclude={excludeRow}
                      onDynamics={showRowDynamics}
                    />
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
    <div className="explorer-visual-limit row">
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
  onDynamics,
  selectedDynamicsSeriesIds,
  onToggleDynamicsSeries,
}) {
  const onChart = selectedDynamicsSeriesIds?.has(row.id);
  const hasDynamicsToggle = typeof onToggleDynamicsSeries === 'function';
  return (
    <div className="explorer-row-actions row" onClick={(e) => e.stopPropagation()}>
      <button type="button" className="badge explorer-row-actions__btn" title="Добавить значения строки в фильтр" onClick={() => onFocus?.(row)}>
        <ExplorerActionLabel full="В фильтр" short="Фильтр" />
      </button>
      <button type="button" className="badge explorer-row-actions__btn" title="Исключить значения строки из выборки" onClick={() => onExclude?.(row)}>
        <ExplorerActionLabel full="Исключить" short="Искл." />
      </button>
      {hasDynamicsToggle ? (
        <button
          type="button"
          className={`badge explorer-row-actions__btn${onChart ? ' badge--info' : ''}`}
          title={onChart ? 'Скрыть серию с графика динамики' : 'Показать серию на графике динамики'}
          onClick={() => onToggleDynamicsSeries(row.id)}
        >
          <ExplorerActionLabel full={onChart ? 'Скрыть с графика' : 'На график'} short={onChart ? 'Скрыть' : 'График'} />
        </button>
      ) : (
        <button type="button" className="badge explorer-row-actions__btn" title="Показать динамику для этой строки" onClick={() => onDynamics?.(row)}>
          <ExplorerActionLabel full="На график" short="График" />
        </button>
      )}
    </div>
  );
}

function ExplorerSummary({ summary, loading = false }) {
  const data = { ...EMPTY_EXPLORER_SUMMARY, ...summary };
  const cards = [
    { label: 'Объём', value: fmtBytes(data.totalBytes) },
    { label: 'Packets', value: fmtNum(data.totalPackets) },
    { label: 'Flows', value: fmtNum(data.totalFlows) },
    { label: 'Avg bps', value: fmtBits(data.avgBps) },
    { label: 'Unique src', value: fmtNum(data.uniqSrc) },
    { label: 'Unique dst', value: fmtNum(data.uniqDst) },
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

function DimensionPicker({ anchorRef, dimensions, selected, onPick, onClose }) {
  const [q, setQ] = useState('');
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);
  const groups = useMemo(() => {
    const g = {};
    dimensions.filter((d) => d.groupable !== false && (!q || d.label.toLowerCase().includes(q.toLowerCase()))).forEach((d) => {
      (g[d.group] = g[d.group] || []).push(d);
    });
    return g;
  }, [dimensions, q]);

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

  if (!menuStyle) return null;
  return ReactDOM.createPortal(
    <div ref={panelRef} style={{ ...menuStyle, background: 'var(--bg-surface)', border: '1px solid var(--bd-default)', borderRadius: 12, boxShadow: 'var(--pv-shadow-popover)', padding: 8 }}>
      <input className="input" placeholder="Поиск измерения..." value={q} onChange={(e) => setQ(e.target.value)} autoFocus />
      {Object.entries(groups).map(([gn, items]) => (
        <div key={gn}>
          <div style={{ font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-muted)', padding: '10px 8px 4px' }}>{gn}</div>
          {items.map((d) => {
            const dis = selected.includes(d.id);
            return (
              <div key={d.id} onClick={() => !dis && onPick(d.id)} style={{ padding: '8px 10px', borderRadius: 8, cursor: dis ? 'default' : 'pointer', color: dis ? 'var(--fg-muted)' : 'var(--fg-primary)' }}>
                {d.label}
              </div>
            );
          })}
        </div>
      ))}
    </div>,
    document.body,
  );
}

function EntityPicker({ entityType, value, label, onSelect, onClear, placeholder = 'Поиск сущности...', switchIp = '' }) {
  const inputRef = React.useRef(null);
  const focusedRef = React.useRef(false);
  const [q, setQ] = useState('');
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState(false);

  const visibleItems = useMemo(() => dedupeExplorerEntityItems(items), [items]);

  const displayValue = label || (value != null && value !== '' ? String(value) : '');
  const showComposite = !editing && value != null && value !== '' && label && String(label) !== String(value);

  useEffect(() => {
    if (focusedRef.current || editing) return;
    setQ(displayValue);
  }, [displayValue, editing]);

  useEffect(() => {
    if (!entityType || !open) return undefined;
    let cancelled = false;
    setLoading(true);
    const timer = setTimeout(() => {
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

  return (
    <div className="explorer-entity-picker" style={{ position: 'relative', flex: 1, minWidth: 0 }}>
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
          onBlur={() => {
            setTimeout(() => {
              focusedRef.current = false;
              setEditing(false);
              setOpen(false);
              setLoading(false);
              if (value != null && value !== '') {
                setQ(displayValue);
              }
            }, 150);
          }}
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
      {open && (
        <div
          className="explorer-entity-picker__menu"
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
              className="explorer-entity-picker__item"
              onMouseDown={(e) => {
                e.preventDefault();
                onSelect(item);
                setQ(item.label);
                focusedRef.current = false;
                setEditing(false);
                setOpen(false);
              }}
            >
              <span className="explorer-entity-picker__item-label">{item.label}</span>
              {item.sublabel && (
                <span className="explorer-entity-picker__item-sublabel">{item.sublabel}</span>
              )}
            </button>
          ))}
        </div>
      )}
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
    if (suggestions.length > 0) {
      setAutocompleteOpen(true);
    } else if (!entityLoading) {
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
        placeholder={'time range 1h\ndirection in (in, out)\nproto = UDP'}
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
  onPickSystem,
  onPickField,
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const anchorRef = React.useRef(null);
  const panelRef = React.useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);

  const fieldItems = useMemo(
    () => (schema?.filterFields || [])
      .filter((f) => f.id !== 'direction' && f.id !== 'collector')
      .map((f) => ({
        id: f.id,
        label: f.label,
        group: f.group || 'Поля',
        hint: f.valueHint || null,
      })),
    [schema],
  );

  const allItems = useMemo(
    () => [...EXPLORER_ADD_FILTER_DEFS, ...fieldItems],
    [fieldItems],
  );

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return allItems;
    return allItems.filter((item) => (
      String(item.label).toLowerCase().includes(needle)
      || String(item.id).toLowerCase().includes(needle)
      || String(item.hint || '').toLowerCase().includes(needle)
    ));
  }, [allItems, q]);

  const groups = useMemo(() => filtered.reduce((acc, item) => {
    const key = item.group || 'Прочее';
    acc[key] = acc[key] || [];
    acc[key].push(item);
    return acc;
  }, {}), [filtered]);

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
    if (item.id.startsWith('__')) {
      onPickSystem(item.id);
    } else {
      onPickField(item.id);
    }
    setOpen(false);
    setQ('');
  };

  return (
    <>
      <div ref={anchorRef}>
        <Button kind="ghost" size="sm" icon="plus" onClick={() => setOpen((v) => !v)}>Добавить</Button>
      </div>
      {open && menuStyle && ReactDOM.createPortal(
        <div
          ref={panelRef}
          style={{
            ...menuStyle,
            background: 'var(--bg-surface)',
            border: '1px solid var(--bd-default)',
            borderRadius: 10,
            boxShadow: 'var(--pv-shadow-popover)',
            padding: 8,
          }}
        >
          <input
            className="input"
            placeholder="Поиск фильтра..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
            autoFocus
            style={{ marginBottom: 6 }}
          />
          {Object.keys(groups).length === 0 ? (
            <div style={{ padding: '8px 4px', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Ничего не найдено</div>
          ) : Object.entries(groups).map(([groupName, groupItems]) => (
            <div key={groupName}>
              <div style={{ font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-muted)', padding: '8px 4px 4px' }}>{groupName}</div>
              {groupItems.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => pick(item)}
                  style={{
                    all: 'unset',
                    display: 'block',
                    width: '100%',
                    boxSizing: 'border-box',
                    padding: '8px 10px',
                    borderRadius: 8,
                    cursor: 'pointer',
                  }}
                >
                  <span>{item.label}</span>
                  {item.hint && (
                    <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: 2 }}>{item.hint}</div>
                  )}
                </button>
              ))}
            </div>
          ))}
        </div>,
        document.body,
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
          {!compact && <span>{v.label}</span>}
        </button>
      ))}
    </div>
  );
}

function ExplorerFilterTemplatesMenu({
  lastApplied,
  savedQueries = [],
  canWrite,
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
      const rect = anchor.getBoundingClientRect();
      setMenuStyle({
        position: 'fixed',
        top: rect.bottom + 4,
        left: Math.max(8, rect.left),
        width: Math.max(rect.width, 300),
        maxHeight: 420,
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
                  <Button kind="ghost" size="xs" icon="play" onClick={() => { onApplyLastApplied?.(); setOpen(false); }}>Применить</Button>
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

function ExplorerSystemFilterRow({ title, mandatory, onRemove, children }) {
  return (
    <div className="col" style={{ padding: '8px 10px', background: 'var(--surf-1)', border: '1px solid var(--bd-soft)', borderRadius: 10, gap: 6 }}>
      <div className="row" style={{ gap: 6, alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-secondary)' }}>
          {title}
          {mandatory && <span style={{ color: 'var(--st-critical)', marginLeft: 4 }}>*</span>}
        </div>
        {!mandatory && onRemove && (
          <button type="button" className="icon-btn" style={{ width: 26, height: 26 }} onClick={onRemove}>
            <Icon name="x" size={10} stroke={2.5} />
          </button>
        )}
      </div>
      {children}
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
  canWrite,
  onSave,
  onSaveAsObservation,
  onEditSaved,
  onDeleteSaved,
}) {
  const panelRef = React.useRef(null);
  const filterFields = (schema?.filterFields || []).filter((f) => f.id !== 'direction' && f.id !== 'collector');
  const switchIpScope = explorerSwitchIpScopeFromFilters(filters);

  useEffect(() => {
    const onKeyDown = (e) => {
      if (!(e.ctrlKey || e.metaKey) || e.key !== 'Enter') return;
      if (!panelRef.current?.contains(document.activeElement)) return;
      e.preventDefault();
      onRun?.();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onRun]);
  const updateFilter = (id, patch) => setFilters(filters.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  const addFilter = (filter = {}) => {
    setFilters([...filters, { id: Date.now() + Math.random(), field: 'src_ip', op: '=', value: '', logic: 'and', ...filter }]);
  };

  const pickSystemFilter = (systemId) => {
    if (systemId === '__direction__') {
      addFilter({ field: 'direction', op: 'in', value: defaultDirectionFilterValue() });
    } else if (systemId === '__collector__') {
      addFilter({ field: 'collector', op: 'in', value: '' });
    }
  };

  const hasAnyFilter = filters.length > 0;

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
        <div className="col" style={{ gap: 8, marginBottom: 12 }}>
          <ExplorerSystemFilterRow title="Период" mandatory>
            <TimeFilter
              variant="explorer"
              timeRange={timeRange}
              onTimeRangeChange={onTimeRangeChange}
              customPeriod={customPeriod}
              onCustomPeriodChange={onCustomPeriodChange}
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
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
              Макс. {EXPLORER_MAX_RANGE_DAYS} дней
            </div>
          </ExplorerSystemFilterRow>

          {!hasAnyFilter && (
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', padding: '6px 0' }}>
              Добавьте фильтры из меню «Добавить».
            </div>
          )}

          {filters.map((f, i) => {
            const meta = filterFieldMeta(schema, f.field);
            const ops = filterOpsForField(schema, f.field);
            const isSpecialField = f.field === 'direction' || f.field === 'collector';
            const rowError = filterRowErrors[f.id];
            return (
              <div
                key={f.id}
                className={`explorer-filter-row${i === 0 ? ' explorer-filter-row--first' : ''}${rowError ? ' explorer-filter-row--warn' : ''}`}
              >
                <div className="explorer-filter-row__main">
                  {i > 0 && (
                    <select
                      className="input explorer-filter-row__logic"
                      value={normalizeFilterLogicValue(f.logic)}
                      onChange={(e) => updateFilter(f.id, { logic: e.target.value })}
                      title="Связь с предыдущим условием"
                    >
                      {EXPLORER_FILTER_LOGIC_OPTIONS.map((opt) => (
                        <option key={opt.id} value={opt.id}>{opt.label}</option>
                      ))}
                    </select>
                  )}
                  {i === 0 && <span className="explorer-filter-row__logic-placeholder" aria-hidden="true" />}
                  {isSpecialField ? (
                    <div className="explorer-filter-row__field-label">
                      {meta?.label || f.field}
                    </div>
                  ) : (
                    <div className="explorer-filter-row__field">
                      <FilterSearchPicker
                        items={filterFields}
                        value={f.field}
                        onChange={(fieldId) => {
                          const nextOps = filterOpsForField(schema, fieldId);
                          updateFilter(f.id, {
                            field: fieldId,
                            value: '',
                            label: null,
                            op: nextOps.includes(f.op) ? f.op : nextOps[0],
                          });
                        }}
                        searchPlaceholder="Поиск поля..."
                        emptyLabel="Поле…"
                        grouped
                      />
                    </div>
                  )}
                  <select
                    className="input explorer-filter-row__op"
                    value={f.op}
                    onChange={(e) => updateFilter(f.id, { op: e.target.value })}
                  >
                    {ops.map((op) => <option key={op} value={op}>{explorerOpLabel(op)}</option>)}
                  </select>
                  <div className="explorer-filter-row__value">
                    {f.field === 'direction' ? (
                      <DirectionFilter
                        embedded
                        formatSummary={explorerDirectionSummaryLabel}
                        directions={directionFilterToMap(f.value)}
                        onDirectionsChange={(dirs) => {
                          const value = directionMapToFilterValue(dirs);
                          const nextOp = !value
                            ? 'in'
                            : (value.includes(',')
                              ? (['=', '!='].includes(f.op) ? f.op : 'in')
                              : (['in', 'not_in'].includes(f.op) ? f.op : '='));
                          updateFilter(f.id, { value, op: nextOp });
                        }}
                      />
                    ) : f.field === 'collector' ? (
                      <CollectorFilter
                        embedded
                        collectorFilter={collectorFilterToArray(f.value)}
                        onCollectorFilterChange={(arr) => updateFilter(f.id, { value: collectorArrayToFilterValue(arr) })}
                      />
                    ) : (meta?.type === 'tcp_flags' || f.field === 'tcp_flags') ? (
                      <TcpFlagsFilter
                        value={f.value}
                        onChange={(patch) => updateFilter(f.id, patch)}
                        onClear={() => updateFilter(f.id, { value: '', label: null })}
                      />
                    ) : (
                      <FilterValueInput
                        fieldId={f.field}
                        meta={meta}
                        value={f.value}
                        label={f.label}
                        switchIpScope={switchIpScope}
                        onChange={(patch) => updateFilter(f.id, patch)}
                        onClear={() => updateFilter(f.id, { value: '', label: null })}
                      />
                    )}
                  </div>
                  <button
                    type="button"
                    className="icon-btn explorer-filter-row__remove"
                    onClick={() => setFilters(filters.filter((x) => x.id !== f.id))}
                    title="Удалить условие"
                  >
                    <Icon name="x" size={10} stroke={2.5} />
                  </button>
                </div>
                {rowError && (
                  <div className="explorer-filter-row__warn" role="alert">{rowError}</div>
                )}
              </div>
            );
          })}

          <div className="row" style={{ gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <ExplorerAddFilterMenu
              schema={schema}
              onPickSystem={pickSystemFilter}
              onPickField={(fieldId) => {
                const nextOps = filterOpsForField(schema, fieldId);
                addFilter({ field: fieldId, op: nextOps[0], value: '' });
              }}
            />
            <ExplorerFilterTemplatesMenu
              lastApplied={lastApplied}
              savedQueries={savedQueries}
              canWrite={canWrite}
              onApplyLastApplied={onApplyLastApplied}
              onRestoreLastApplied={onRestoreLastApplied}
              onSaveLastApplied={onSaveLastApplied}
              onApplySaved={onApplySaved}
              onEditSaved={onEditSaved}
              onDeleteSaved={onDeleteSaved}
              onAddQuickFilter={addFilter}
            />
            <Button kind="ghost" size="sm" icon="x" onClick={onClearFilters}>Очистить фильтры</Button>
            <Button kind="ghost" size="sm" icon="play" onClick={onRun}>Применить</Button>
            {canWrite && (
              <Button kind="ghost" size="sm" icon="save" onClick={onSave}>Сохранить</Button>
            )}
            {canWrite && onSaveAsObservation && (
              <Button kind="primary" size="sm" onClick={onSaveAsObservation}>Добавить в наблюдения</Button>
            )}
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>Ctrl+Enter — применить</span>
          </div>
        </div>
      ) : (
        <div className="col" style={{ gap: 8, marginBottom: 12 }}>
          <ExplorerFilterTextEditor
            value={filterText}
            onChange={onFilterTextChange}
            error={filterTextError}
            schema={schema}
            filters={filters}
          />
          <div className="row" style={{ gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <ExplorerFilterTemplatesMenu
              lastApplied={lastApplied}
              savedQueries={savedQueries}
              canWrite={canWrite}
              onApplyLastApplied={onApplyLastApplied}
              onRestoreLastApplied={onRestoreLastApplied}
              onSaveLastApplied={onSaveLastApplied}
              onApplySaved={onApplySaved}
              onEditSaved={onEditSaved}
              onDeleteSaved={onDeleteSaved}
              onAddQuickFilter={addFilter}
            />
            <Button kind="ghost" size="sm" icon="x" onClick={onClearFilters}>Очистить фильтры</Button>
            <Button kind="ghost" size="sm" icon="play" onClick={onRun}>Применить</Button>
            {canWrite && (
              <Button kind="ghost" size="sm" icon="save" onClick={onSave}>Сохранить</Button>
            )}
            {canWrite && onSaveAsObservation && (
              <Button kind="primary" size="sm" onClick={onSaveAsObservation}>Добавить в наблюдения</Button>
            )}
          </div>
        </div>
      )}
    </Card>
    </div>
  );
}

function ContributionBarsExplorer({
  results,
  metric,
  metricLabel,
  onFocus,
  onExclude,
  onDynamics,
}) {
  if (!results.length) {
    return (
      <div className="explorer-lines__empty">
        Нет значений для отображения вклада. Измените фильтры или группировку.
      </div>
    );
  }

  const maxMetric = Math.max(...results.map((r) => Number(r.metric) || 0), 1);

  return (
    <div className="explorer-bars col" style={{ gap: 12 }}>
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        Кто даёт основной объём по метрике «{metricLabel}».
      </div>
      {results.map((row) => {
        const widthPct = Math.max(2, ((Number(row.metric) || 0) / maxMetric) * 100);
        return (
          <div key={row.id} className="explorer-bars__row">
            <div className="explorer-bars__head">
              <span className="explorer-bars__swatch" style={{ background: row.color }} aria-hidden="true" />
              <span className="explorer-bars__label" title={explorerRowLabel(row)}>{explorerRowLabel(row)}</span>
              <span className="explorer-bars__value mono">{formatMetric(row.metric, metric)}</span>
              <span className="explorer-bars__value mono">{Number(row.pct || 0).toFixed(2)}%</span>
            </div>
            <div className="explorer-bars__track">
              <div className="explorer-bars__fill" style={{ width: `${widthPct}%`, background: row.color }} />
            </div>
            {!row.isOthers && (
              <ExplorerRowActions
                row={row}
                onFocus={onFocus}
                onExclude={onExclude}
                onDynamics={onDynamics}
              />
            )}
          </div>
        );
      })}
    </div>
  );
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
          height={280}
          mode="bw"
          onRangeSelect={onRangeSelect}
          bucketSeconds={bucketSeconds}
          displayTimezone={displayTimezone}
          valueFormatter={(value) => formatMetric(value, metric)}
          axisFormatter={(value) => formatMetric(value, metric)}
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
  results,
  metric,
  metricLabel,
  resultSeries,
  displayTimezone,
  chartLongRange,
  selectedSeriesIds,
  focusRowId = null,
  onClearFocus,
  onRangeSelect,
  bucketSeconds = 300,
  totalPoints = null,
}) {
  const [chartKey, setChartKey] = useState(0);
  useEffect(() => {
    if (active) setChartKey((k) => k + 1);
  }, [active, focusRowId]);
  const seriesByRow = resultSeries?.seriesByRow || {};
  const resultIdSet = new Set(results.map((r) => r.id));
  const selectedIds = [...selectedSeriesIds].filter((id) => resultIdSet.has(id));
  const chartRowIds = selectedIds;
  const focusedRow = focusRowId ? results.find((r) => r.id === focusRowId) : null;

  const lines = results.filter((r) => chartRowIds.includes(r.id)).map((row) => ({
    key: row.id,
    label: explorerRowLabel(row),
    color: row.color,
  }));

  const pointsByBucket = new Map();
  for (const rowId of chartRowIds) {
    const rawPoints = seriesByRow[rowId] || [];
    for (const pt of rawPoints) {
      const bucket = normalizeBucketString(pt.bucket);
      if (!pointsByBucket.has(bucket)) {
        pointsByBucket.set(bucket, { ...pt, bucket });
      }
      const current = Number(pointsByBucket.get(bucket)[rowId]) || 0;
      pointsByBucket.get(bucket)[rowId] = current + (Number(pt.value) || 0);
    }
  }

  // Everything not on the chart, taken from the unsliced totals of the same query.
  let hasOthers = false;
  if (Array.isArray(totalPoints) && totalPoints.length && chartRowIds.length) {
    for (const pt of totalPoints) {
      const bucket = normalizeBucketString(pt.bucket);
      const total = Number(pt.value) || 0;
      if (!total) continue;
      const target = pointsByBucket.get(bucket);
      if (!target) continue;
      const shown = chartRowIds.reduce((s, id) => s + (Number(target[id]) || 0), 0);
      const rest = total - shown;
      if (rest > 0 && rest / total >= 0.0001) {
        target[EXPLORER_OTHERS_ID] = rest;
        hasOthers = true;
      }
    }
  }
  if (hasOthers) {
    lines.push({ key: EXPLORER_OTHERS_ID, label: EXPLORER_OTHERS_LABEL, color: EXPLORER_OTHERS_COLOR });
  }

  const points = [...pointsByBucket.values()]
    .sort((a, b) => (resolvePointEpochMs(a) || 0) - (resolvePointEpochMs(b) || 0))
    .map((pt) => {
      const next = { ...pt };
      next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
      if (next.bucketMs != null) next.bucketMs = Number(next.bucketMs);
      return next;
    });
  const chartPoints = points.length === 1 ? [points[0], { ...points[0] }] : points;

  return (
    <div className="explorer-lines col" style={{ gap: 12 }}>
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        {focusRowId && focusedRow
          ? `Динамика: ${explorerRowLabel(focusedRow)}.`
          : selectedIds.length
            ? `На графике ${selectedIds.length} серий по интервалам времени. Управляйте сериями в таблице «Результаты».`
            : 'Выберите строки в таблице «Результаты», чтобы посмотреть динамику по каждой серии.'}
      </div>
      {focusRowId && onClearFocus && (
        <div>
          <Button kind="ghost" size="sm" onClick={onClearFocus}>Показать top-N серий</Button>
        </div>
      )}
      {chartPoints.length > 1 && lines.length ? (
        <>
          <div className="explorer-time-chart explorer-dynamics-chart">
            <DualChart
              key={chartKey}
              points={chartPoints}
              lines={lines}
              height={280}
              mode="bw"
              onRangeSelect={onRangeSelect}
              bucketSeconds={bucketSeconds}
              displayTimezone={displayTimezone}
              valueFormatter={(v) => formatMetric(v, metric)}
              axisFormatter={(v) => formatMetric(v, metric)}
            />
          </div>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: -4 }}>
            Ось Y — {metricLabel || metric} в каждом временном интервале, не сумма за весь период.
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
  if (metric === 'fps') return `${fmtNum(v)} ф/с`;
  return fmtNum(v);
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
  const defaultLookback = ['15m', '1h', '6h', '24h', '7d'].includes(timeRange) ? timeRange : '1h';
  const defaultTop = (groupBy || []).find((g) => ['src_asn', 'dst_asn', 'src_ip', 'dst_ip', 'vlan', 'proto'].includes(g))
    || groupBy?.[0]
    || 'src_asn';
  const [name, setName] = useState('');
  const [lookback, setLookback] = useState(defaultLookback);
  const [liveEnabled, setLiveEnabled] = useState(true);
  const [refreshSec, setRefreshSec] = useState(300);
  const [reportEnabled, setReportEnabled] = useState(false);
  const [reportPeriod, setReportPeriod] = useState('yesterday');
  const [topGroup, setTopGroup] = useState(defaultTop);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(initialName || `Наблюдение · ${metricLabel}`);
    setLookback(defaultLookback);
    setLiveEnabled(true);
    setRefreshSec(60);
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
        liveEnabled,
        refreshSec,
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
              <option value="15m">15 минут</option>
              <option value="1h">1 час</option>
              <option value="6h">6 часов</option>
              <option value="24h">24 часа</option>
              <option value="7d">7 дней</option>
            </select>
          </div>
          <div className="field" style={{ flex: 1, minWidth: 160 }}>
            <label>Топ по полю</label>
            <select className="input" value={topGroup} onChange={(e) => setTopGroup(e.target.value)}>
              {['src_asn', 'dst_asn', 'src_ip', 'dst_ip', 'vlan', 'proto', 'src_country', 'dst_country'].map((id) => (
                <option key={id} value={id}>{dimensionById?.[id]?.label || id}</option>
              ))}
            </select>
          </div>
        </div>
        <label className="row" style={{ gap: 8, alignItems: 'center' }}>
          <input type="checkbox" checked={liveEnabled} onChange={(e) => setLiveEnabled(e.target.checked)} />
          Обновлять автоматически
        </label>
        {liveEnabled && (
          <label className="row" style={{ gap: 8, alignItems: 'center', marginLeft: 24 }}>
            каждые
            <select className="input" style={{ width: 120 }} value={refreshSec} onChange={(e) => setRefreshSec(Number(e.target.value))}>
              <option value={300}>5 мин</option>
              <option value={900}>15 мин</option>
            </select>
          </label>
        )}
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
  const defaultName = editing?.name || `${metricLabel} · ${groupBy.map((g) => dimensionById[g]?.label || g).join(' × ')}`;
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
          <div>Группировка: <b>{groupBy.map((g) => dimensionById[g]?.label || g).join(', ')}</b></div>
          <div>Фильтры: <b>{filters.length || 'нет'}</b></div>
        </Card>
      </div>
    </Modal>
  );
}

Object.assign(window, { PageExplorer });
