/* Observations: live tile board (2 columns). Filters collected in Explorer. */

const {
  useState, useEffect, useLayoutEffect, useCallback, useMemo, useRef,
} = React;

function obsT(key, params) {
  return GrapesI18n.t(key, params);
}

const LOOKBACK_LABELS_LEGACY = {
  '15m': '15 минут',
};

function observationLookbackLabel(v) {
  const key = `period.${v}`;
  if (GrapesI18n.has(key)) return obsT(key);
  return LOOKBACK_LABELS_LEGACY[v] || v;
}

function observationLookbackChip(v) {
  const key = `period.chip.${v}`;
  if (GrapesI18n.has(key)) return obsT(key);
  return v;
}

function parseObservationGroupToken(token) {
  const raw = String(token ?? '').trim();
  const slash = raw.indexOf('/');
  const candidateId = slash < 0 ? raw : raw.slice(0, slash);
  if (candidateId !== 'src_ip' && candidateId !== 'dst_ip') return { id: raw, mask: null };
  const value = slash < 0 ? 32 : Number(raw.slice(slash + 1).trim());
  return {
    id: candidateId,
    mask: Number.isInteger(value) && value >= 1 && value <= 32 ? value : 32,
  };
}

const LOOKBACK_OPTIONS = ['30m', '1h', '6h', '24h', '7d'];

function normalizeObservationLookback(value) {
  return value === '15m' ? '30m' : (value || '1h');
}

const OBS_CHART_STYLE_DEFS = [
  { id: 'lines', labelKey: 'observations.chart.lines', hintKey: 'observations.chart.linesHint', icon: 'lineChart' },
  { id: 'stack', labelKey: 'observations.chart.stack', hintKey: 'observations.chart.stackHint', icon: 'layers' },
];

function observationChartStyles() {
  return OBS_CHART_STYLE_DEFS.map((style) => ({
    ...style,
    label: obsT(style.labelKey),
    hint: obsT(style.hintKey),
  }));
}

const OBS_CHART_DIRECTION_LINE_KEYS = new Set([
  'incoming', 'outgoing', 'transit', 'internal', 'unclassified', 'total',
]);

function observationChartLineLabel(line) {
  if (!line) return '';
  const key = String(line.key || '').trim();
  if (key && OBS_CHART_DIRECTION_LINE_KEYS.has(key) && GrapesI18n.has(`direction.${key}`)) {
    return obsT(`direction.${key}`);
  }
  return line.label || key;
}

function localizeObservationChartLines(lines) {
  return (lines || []).map((ln) => ({
    ...ln,
    label: observationChartLineLabel(ln),
  }));
}

function normalizeObservationChartStyle(value) {
  return value === 'stack' ? 'stack' : 'lines';
}

function observationChartStyleToStackMode(chartStyle) {
  return normalizeObservationChartStyle(chartStyle) === 'stack' ? 'sum' : undefined;
}

function observationWidgetsWithChartStyle(widgets, chartStyle) {
  const nextStyle = normalizeObservationChartStyle(chartStyle);
  return (widgets || []).map((w) => (
    w.type === 'timeseries_bps' ? { ...w, chartStyle: nextStyle } : w
  ));
}

function observationChartStyleFromWidgets(widgets) {
  const chart = (widgets || []).find((w) => w.type === 'timeseries_bps');
  return normalizeObservationChartStyle(chart?.chartStyle);
}

/** Строк топа в плитке; «Прочие» показывается сверх этого числа. */
const TOP_ROWS_VIEW_LIMIT = 100;

const OBSERVATION_LOOKBACK_MS = {
  '15m': 15 * 60 * 1000,
  '30m': 30 * 60 * 1000,
  '1h': 3600 * 1000,
  '6h': 6 * 3600 * 1000,
  '24h': 86400 * 1000,
  '7d': 7 * 86400 * 1000,
};

function observationChartPeriodBounds({ customRange, lookback, window, displayTimezone }) {
  const tz = displayTimezone || (typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined);
  const range = window?.from && window?.to
    ? window
    : customRange?.from && customRange?.to
      ? customRange
      : null;
  if (range?.from && range?.to) {
    const startMs = wallPartsToMs(parseBucketWallParts(String(range.from).replace('T', ' ')), tz);
    const endMs = wallPartsToMs(parseBucketWallParts(String(range.to).replace('T', ' ')), tz);
    if (startMs != null && endMs != null && endMs > startMs) {
      return { periodStartMs: startMs, periodEndMs: endMs };
    }
  }
  const ms = OBSERVATION_LOOKBACK_MS[lookback] || OBSERVATION_LOOKBACK_MS['1h'];
  const endMs = Date.now();
  return { periodStartMs: endMs - ms, periodEndMs: endMs };
}

const MIN_REFRESH_SEC = 300;

/** Fallback, если браузер не умеет Intl.supportedValuesOf('timeZone'). */
const TIMEZONE_FALLBACK = [
  'UTC',
  'Europe/Kaliningrad', 'Europe/Moscow', 'Europe/Samara', 'Asia/Yekaterinburg',
  'Asia/Omsk', 'Asia/Novosibirsk', 'Asia/Krasnoyarsk', 'Asia/Irkutsk',
  'Asia/Yakutsk', 'Asia/Vladivostok', 'Asia/Magadan', 'Asia/Kamchatka',
  'Europe/Minsk', 'Europe/Kyiv', 'Asia/Almaty', 'Asia/Tashkent',
  'Asia/Tbilisi', 'Asia/Yerevan', 'Asia/Baku',
  'Europe/London', 'Europe/Berlin', 'Europe/Belgrade', 'Europe/Istanbul',
  'Asia/Dubai', 'Asia/Shanghai', 'Asia/Tokyo',
  'America/New_York', 'America/Chicago', 'America/Los_Angeles',
];

function timezoneOptions() {
  try {
    if (typeof Intl.supportedValuesOf === 'function') {
      const list = Intl.supportedValuesOf('timeZone');
      if (Array.isArray(list) && list.length) return list;
    }
  } catch {
    /* fall through */
  }
  return TIMEZONE_FALLBACK;
}

function timezoneOffsetLabel(tz) {
  try {
    const parts = new Intl.DateTimeFormat('ru-RU', { timeZone: tz, timeZoneName: 'shortOffset' })
      .formatToParts(new Date());
    const name = parts.find((p) => p.type === 'timeZoneName')?.value;
    return name ? ` · ${name}` : '';
  } catch {
    return '';
  }
}

function TimezonePicker({ value, onChange }) {
  const options = useMemo(timezoneOptions, []);
  const [text, setText] = useState(value || '');
  const [open, setOpen] = useState(false);

  useEffect(() => { setText(value || ''); }, [value]);

  const query = text.trim().toLowerCase();
  const matches = useMemo(() => {
    const exact = query && options.some((tz) => tz.toLowerCase() === query);
    const list = query && !exact ? options.filter((tz) => tz.toLowerCase().includes(query)) : options;
    return list.slice(0, 60);
  }, [options, query]);

  const commit = (tz) => {
    onChange(tz);
    setText(tz);
    setOpen(false);
  };

  return (
    <div style={{ position: 'relative', width: 220 }}>
      <input
        className="input"
        style={{ width: '100%' }}
        placeholder="Europe/Moscow"
        value={text}
        onChange={(e) => { setText(e.target.value); setOpen(true); }}
        onFocus={() => setOpen(true)}
        onBlur={() => {
          setOpen(false);
          const next = text.trim();
          if (options.includes(next)) onChange(next);
          else setText(value || '');
        }}
      />
      {open && matches.length > 0 && (
        <div
          style={{
            position: 'absolute',
            zIndex: 40,
            top: 'calc(100% + 2px)',
            left: 0,
            right: 0,
            maxHeight: 240,
            overflowY: 'auto',
            background: 'var(--surf-0)',
            border: '1px solid var(--bd-soft, #ddd)',
            borderRadius: 6,
            boxShadow: '0 8px 20px rgba(0,0,0,.14)',
          }}
        >
          {matches.map((tz) => (
            <div
              key={tz}
              role="option"
              aria-selected={tz === value}
              style={{
                padding: '5px 8px',
                cursor: 'pointer',
                font: 'var(--pv-text-body-3)',
                background: tz === value ? 'var(--surf-2, #eef2ff)' : 'transparent',
              }}
              onMouseDown={(e) => { e.preventDefault(); commit(tz); }}
            >
              {tz}
              <span style={{ color: 'var(--fg-muted)' }}>{timezoneOffsetLabel(tz)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function formatBps(v) {
  if (typeof fmtBits === 'function') return fmtBits(v);
  const n = Number(v) || 0;
  if (n >= 1e12) return `${(n / 1e12).toFixed(2)} Tbps`;
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} Gbps`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)} Mbps`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} Kbps`;
  return `${n.toFixed(0)} bps`;
}

function formatAxisBps(v) {
  if (typeof fmtBitsAxis === 'function') return fmtBitsAxis(v);
  return formatBps(v);
}

function normalizeObservationChartMetric(metric) {
  const key = String(metric || 'bps').trim();
  return ['bps', 'volume', 'pps', 'fps', 'flows'].includes(key) ? key : 'bps';
}

function observationMetricFromWidgets(widgets) {
  const chart = chartWidgetFrom(widgets);
  return normalizeObservationChartMetric(chart?.metric);
}

function observationTableMetricFromWidgets(widgets) {
  const top = (widgets || []).find((w) => w.type === 'top_table');
  return normalizeObservationChartMetric(top?.metric || chartWidgetFrom(widgets)?.metric);
}

function observationMetricAxisUnit(metric) {
  const m = normalizeObservationChartMetric(metric);
  if (m === 'bps') return obsT('unit.bps');
  if (m === 'volume') return obsT('unit.bytes');
  if (m === 'pps') return obsT('unit.pps');
  if (m === 'fps') return obsT('unit.flowsPerSec');
  if (m === 'flows') return obsT('unit.flows');
  return '';
}

function observationMetricValueLabel(metric) {
  switch (normalizeObservationChartMetric(metric)) {
    case 'pps': return obsT('observations.metric.pps');
    case 'fps': return obsT('observations.metric.fps');
    case 'volume': return obsT('observations.metric.volume');
    case 'flows': return obsT('observations.metric.flows');
    default: return obsT('observations.metric.avgBps');
  }
}

function formatObservationMetric(v, metric) {
  if (typeof formatMetric === 'function') return formatMetric(v, metric);
  if (metric === 'pps') return `${v} ${obsT('unit.pps')}`;
  return formatBps(v);
}

function formatObservationMetricAxis(v, metric) {
  if (typeof formatMetricAxis === 'function') return formatMetricAxis(v, metric);
  if (metric === 'bps') return formatAxisBps(v);
  return formatObservationMetric(v, metric);
}

function observationPointValue(p) {
  if (p?.value != null && Number.isFinite(Number(p.value))) return Number(p.value);
  return Number(p?.bps) || 0;
}

/** Aggregate series values for the observation chart stats strip. */
function chartSeriesStats(points, lines, mode = 'total', metric = 'bps') {
  if (!points?.length) return null;
  const values = points.map((p) => {
    if (mode === 'grouped' && lines?.length) {
      return lines.reduce((sum, ln) => sum + (Number(p[ln.key]) || 0), 0);
    }
    return observationPointValue(p);
  });
  const min = Math.min(...values);
  const max = Math.max(...values);
  const sum = values.reduce((a, b) => a + b, 0);
  const avg = sum / values.length;
  const last = values[values.length - 1];
  const pctOfMax = max > 0 ? (last / max) * 100 : null;
  return { min, max, avg, last, pctOfMax, n: values.length };
}

/**
 * Разрез наблюдения — весь список измерений, а не первое поле: наблюдение из
 * разбора трафика может группировать по четырём измерениям, и обрезка теряла остальные.
 */
function groupLabel(token, options) {
  const { id, mask } = parseObservationGroupToken(token);
  const label = (options || []).find((o) => o.id === id)?.label || id;
  return mask != null && mask !== 32 ? `${label} /${mask}` : label;
}

const COMPOSE_KEY = 'grapes-observation-compose';
const OPEN_KEY = 'grapes-observation-open';
const SECTION_STORAGE_KEY = 'grapes-observations-section';
const COMPOSE_CHANGED_EVENT = 'grapes-observation-compose';

function readObservationComposeDraft() {
  try {
    const raw = sessionStorage.getItem(COMPOSE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed?.active ? parsed : null;
  } catch {
    return null;
  }
}

function notifyObservationComposeChanged() {
  try {
    window.dispatchEvent(new CustomEvent(COMPOSE_CHANGED_EVENT));
  } catch {
    // ignore
  }
}

function groupByFromWidgets(widgets) {
  const list = Array.isArray(widgets) ? widgets : [];
  const chart = list.find((w) => w.type === 'timeseries_bps' && w.groupBy?.length);
  if (chart) return chart.groupBy.map(String);
  const top = list.find((w) => w.type === 'top_table' && w.groupBy?.length);
  return top ? top.groupBy.map(String) : ['src_asn'];
}

function chartWidgetDataSource(widgets) {
  const chart = (widgets || []).find((w) => w.type === 'timeseries_bps');
  return chart?.dataSource || 'explorer';
}

/** Содержимое widgets для синхронизации lookback/стиля без сброса фильтра серий. */
function observationWidgetsTileSyncSignature(widgets) {
  const style = observationChartStyleFromWidgets(widgets);
  const hasTop = hasTopTableWidget(widgets) ? '1' : '0';
  return `${style}\0${hasTop}`;
}

/** Смена разреза графика — фильтр чипов серий нужно обнулить. */
function observationSeriesFocusResetSignature(widgets) {
  const groupBy = groupByFromWidgets(widgets).join('|');
  const metric = observationMetricFromWidgets(widgets);
  const dataSource = chartWidgetDataSource(widgets);
  return `${groupBy}\0${metric}\0${dataSource}`;
}

function isNativeAggregateObservation(item) {
  const ds = chartWidgetDataSource(item?.widgets);
  return ds === 'traffic_direction' || ds === 'vlan_trend';
}

function hasTopTableWidget(widgets) {
  return (widgets || []).some((w) => w.type === 'top_table');
}

function chartWidgetFrom(widgets) {
  return (widgets || []).find((w) => w.type === 'timeseries_bps') || null;
}

function chartWidgetNativeScope(widgets) {
  const chart = chartWidgetFrom(widgets);
  return chart?.nativeScope || { collectorFilter: [], vlanIds: [] };
}

function widgetsWithNativeScope(widgets, nativeScope) {
  return (widgets || []).map((w) => (
    w.type === 'timeseries_bps' && isNativeAggregateObservation({ widgets: [w] })
      ? { ...w, nativeScope }
      : w
  ));
}

function nativeAggregateSummary(item, collectors = [], locations = []) {
  const ds = chartWidgetDataSource(item?.widgets);
  if (ds !== 'traffic_direction' && ds !== 'vlan_trend') return null;
  const scope = chartWidgetNativeScope(item?.widgets);
  const parts = [];
  if (typeof collectorFilterLabel === 'function') {
    parts.push(`${obsT('observations.collector')}: ${collectorFilterLabel(scope.collectorFilter, collectors, locations)}`);
  }
  if (ds === 'vlan_trend') {
    if (scope.vlanIds?.length) {
      parts.push(`VLAN: ${scope.vlanIds.join(', ')}`);
    } else {
      parts.push('VLAN не выбраны');
    }
  }
  return parts.length ? parts.join(' · ') : null;
}

function NativeScopeSettings({
  dataSource,
  nativeScope,
  onChange,
  disabled = false,
}) {
  const [vlanRows, setVlanRows] = useState([]);
  const [vlanLoading, setVlanLoading] = useState(false);
  const [vlanSearch, setVlanSearch] = useState('');
  const [manualVlan, setManualVlan] = useState('');
  const selectedVlanIds = useMemo(
    () => new Set((nativeScope?.vlanIds || []).map((v) => Number(v))),
    [nativeScope?.vlanIds],
  );

  useEffect(() => {
    if (dataSource !== 'vlan_trend') return undefined;
    let cancelled = false;
    setVlanLoading(true);
    Promise.all([
      ApiClient.loadRefVlans(),
      ApiClient.loadRefVlansSeen({ hours: 24 * 7, limit: 500 }),
    ])
      .then(([namedR, seenR]) => {
        if (cancelled) return;
        const byId = new Map();
        for (const row of [...(namedR.rows || []), ...(seenR.rows || [])]) {
          const id = Number(row.vlanId);
          if (!Number.isInteger(id) || id <= 0) continue;
          if (!byId.has(id)) {
            byId.set(id, {
              vlanId: id,
              label: row.displayName ? `${id} · ${row.displayName}` : String(id),
            });
          }
        }
        setVlanRows([...byId.values()].sort((a, b) => a.vlanId - b.vlanId));
      })
      .catch(() => {
        if (!cancelled) setVlanRows([]);
      })
      .finally(() => {
        if (!cancelled) setVlanLoading(false);
      });
    return () => { cancelled = true; };
  }, [dataSource]);

  const filteredVlanRows = useMemo(() => {
    const q = vlanSearch.trim().toLowerCase();
    if (!q) return vlanRows;
    return vlanRows.filter((row) => (
      String(row.vlanId).includes(q) || row.label.toLowerCase().includes(q)
    ));
  }, [vlanRows, vlanSearch]);

  const patchScope = (patch) => onChange({ ...nativeScope, ...patch });

  const toggleVlan = (vlanId) => {
    const id = Number(vlanId);
    if (!Number.isInteger(id) || id <= 0) return;
    const next = new Set(selectedVlanIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    patchScope({ vlanIds: [...next].sort((a, b) => a - b) });
  };

  const addManualVlan = () => {
    const id = Number(String(manualVlan || '').trim());
    if (!Number.isInteger(id) || id <= 0 || id > 4094) return;
    const next = new Set(selectedVlanIds);
    next.add(id);
    patchScope({ vlanIds: [...next].sort((a, b) => a - b) });
    setManualVlan('');
  };

  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="col" style={{ gap: 6 }}>
        <span>{obsT('observations.collector')}</span>
        {typeof CollectorFilter === 'function' ? (
          <CollectorFilter
            embedded
            collectorFilter={nativeScope?.collectorFilter || []}
            onCollectorFilterChange={(next) => patchScope({ collectorFilter: next })}
          />
        ) : (
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            Компонент фильтра коллектора недоступен
          </div>
        )}
      </div>
      {dataSource === 'vlan_trend' && (
        <div className="col" style={{ gap: 8 }}>
          <span>VLAN</span>
          <input
            className="input"
            placeholder="Поиск VLAN"
            value={vlanSearch}
            disabled={disabled}
            onChange={(e) => setVlanSearch(e.target.value)}
          />
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <input
              className="input"
              style={{ width: 120 }}
              placeholder="ID VLAN"
              value={manualVlan}
              disabled={disabled}
              onChange={(e) => setManualVlan(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addManualVlan();
                }
              }}
            />
            <button type="button" className="btn" disabled={disabled} onClick={addManualVlan}>
              {obsT('observations.settings.add')}
            </button>
          </div>
          {selectedVlanIds.size > 0 && (
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              Выбрано: {[...selectedVlanIds].sort((a, b) => a - b).join(', ')}
            </div>
          )}
          <div
            className="col"
            style={{
              gap: 2,
              maxHeight: 220,
              overflowY: 'auto',
              border: '1px solid var(--bd-soft)',
              borderRadius: 8,
              padding: 8,
            }}
          >
            {vlanLoading && (
              <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Загрузка VLAN…</div>
            )}
            {!vlanLoading && !filteredVlanRows.length && (
              <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
                VLAN не найдены — добавьте ID вручную
              </div>
            )}
            {filteredVlanRows.map((row) => (
              <label key={row.vlanId} className="row" style={{ gap: 8, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={selectedVlanIds.has(row.vlanId)}
                  disabled={disabled}
                  onChange={() => toggleVlan(row.vlanId)}
                />
                <span className="mono">{row.label}</span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

const FILTER_LOGIC_EXPR = {
  and: 'AND',
  or: 'OR',
  and_not: 'AND NOT',
  or_not: 'OR NOT',
};

function filterPredicateLabel(f, filterFields) {
  const fields = Array.isArray(filterFields) ? filterFields : [];
  const label = fields.find((ff) => ff.id === f.field)?.label || f.field;
  return `${label} ${f.op} ${f.value ?? ''}`;
}

function formatFilterNodeSummary(f, filterFields, index = 0) {
  if (f?.type === 'group' && Array.isArray(f.children)) {
    const inner = f.children.map((child, childIndex) => formatFilterNodeSummary(child, filterFields, childIndex)).join(' ');
    const wrapped = f.children.length > 1 ? `(${inner})` : inner;
    if (index === 0) return wrapped;
    const logic = FILTER_LOGIC_EXPR[f.logic] || FILTER_LOGIC_EXPR.and;
    return `· ${logic} · ${wrapped}`;
  }
  const pred = filterPredicateLabel(f, filterFields);
  if (index === 0) return pred;
  const logic = FILTER_LOGIC_EXPR[f.logic] || FILTER_LOGIC_EXPR.and;
  return `· ${logic} · ${pred}`;
}

function formatFilterSummary(filters, filterFields) {
  const list = Array.isArray(filters) ? filters : [];
  if (!list.length) return obsT('observations.filters.none');
  return list.map((f, i) => formatFilterNodeSummary(f, filterFields, i)).join(' ');
}

function renderFilterNodeSummary(f, filterFields, index = 0) {
  if (f?.type === 'group' && Array.isArray(f.children)) {
    const logic = FILTER_LOGIC_EXPR[f.logic] || FILTER_LOGIC_EXPR.and;
    return (
      <React.Fragment key={f.id || `group-${index}`}>
        {index > 0 ? (
          <>
            {' · '}
            <span className="obs-tile__filter-logic">{logic}</span>
            {' · '}
          </>
        ) : null}
        {'('}
        {f.children.map((child, childIndex) => renderFilterNodeSummary(child, filterFields, childIndex))}
        {')'}
      </React.Fragment>
    );
  }
  const logic = FILTER_LOGIC_EXPR[f.logic] || FILTER_LOGIC_EXPR.and;
  return (
    <React.Fragment key={f.id || `${f.field}-${index}`}>
      {index > 0 ? (
        <>
          {' · '}
          <span className="obs-tile__filter-logic">{logic}</span>
          {' · '}
        </>
      ) : null}
      {filterPredicateLabel(f, filterFields)}
    </React.Fragment>
  );
}

function renderFilterSummary(filters, filterFields) {
  const list = Array.isArray(filters) ? filters : [];
  if (!list.length) return obsT('observations.filters.none');
  return list.map((f, i) => renderFilterNodeSummary(f, filterFields, i));
}

function formatGroupSummary(groupBy, groupOptions) {
  const list = Array.isArray(groupBy) ? groupBy : [];
  if (!list.length) return '';
  return list.map((g) => groupLabel(g, groupOptions)).join(' × ');
}

function formatObservationScopeSummary(item, filterFields, groupOptions) {
  const parts = [];
  parts.push(item.filters?.length ? formatFilterSummary(item.filters, filterFields) : obsT('observations.filters.none'));
  const groupSummary = formatGroupSummary(groupByFromWidgets(item.widgets), groupOptions);
  if (groupSummary) parts.push(`группировка: ${groupSummary}`);
  if (item.thresholds?.length && window.ExplorerThresholds?.formatThresholdChipLabel) {
    const thr = item.thresholds.slice(0, 2).map((t) => window.ExplorerThresholds.formatThresholdChipLabel(t)).join(' · ');
    parts.push(`пороги: ${thr}${item.thresholds.length > 2 ? ' …' : ''}`);
  }
  return parts.join(' · ');
}

function reportPeriodLabel(item) {
  const tz = item.report?.schedule?.timezone || 'Europe/Moscow';
  return item.report?.period === 'last_24h'
    ? `последние 24 часа (${tz})`
    : `вчера, календарные сутки (${tz})`;
}

/** Live не настраивается: плитка и воркер всегда идут шагом 5 минут. */
function tileRefreshSec() {
  return MIN_REFRESH_SEC;
}

const ROLLUP_BUCKET_MS = 5 * 60 * 1000;
/** Тик воркера (60 с) плюс запись шота — раньше нового бакета в rollup не будет. */
const WORKER_WRITE_LAG_MS = 75 * 1000;
/** Бакет мог задержаться — перепроверяем шагом воркера, а не через все 5 минут. */
const TILE_RETRY_MS = 60 * 1000;

/**
 * Следующий запрос назначаем на момент, когда rollup должен получить очередной
 * бакет: window.to — правый край готовых данных. Слепой опрос раз в 5 минут
 * добавлял к отставанию графика ещё до 5 минут, потому что попадал в паузу
 * между записями. Ожидание само по себе не превышает бакет плюс лаг воркера.
 */
function nextTileDelayMs(windowTo) {
  const endMs = Date.parse(windowTo || '');
  if (!Number.isFinite(endMs)) return tileRefreshSec() * 1000;
  const waitMs = endMs + ROLLUP_BUCKET_MS + WORKER_WRITE_LAG_MS - Date.now();
  return Math.max(TILE_RETRY_MS, waitMs);
}

function observationVisFromChartStyle(chartStyle) {
  return normalizeObservationChartStyle(chartStyle) === 'stack' ? 'stack' : 'lines';
}

function observationExplorerQueryFallback(item) {
  const groupBy = groupByFromWidgets(item?.widgets);
  return {
    timeRange: normalizeObservationLookback(item?.lookback || '1h'),
    customPeriod: null,
    filters: Array.isArray(item?.filters) ? item.filters : [],
    thresholds: Array.isArray(item?.thresholds) ? item.thresholds : [],
    metric: observationMetricFromWidgets(item?.widgets),
    groupBy,
    vis: observationVisFromChartStyle(observationChartStyleFromWidgets(item?.widgets)),
    limit: 25,
  };
}

function observationExplorerQueryForCompose(item, { customRange } = {}) {
  const base = (item?.explorerQuery && typeof item.explorerQuery === 'object')
    ? { ...item.explorerQuery }
    : observationExplorerQueryFallback(item);
  if (customRange?.from && customRange?.to) {
    return {
      ...base,
      timeRange: 'custom',
      customPeriod: { from: customRange.from, to: customRange.to },
    };
  }
  return base;
}

function observationExplorerQueryWithLookback(explorerQuery, lookback, item = null) {
  const base = (explorerQuery && typeof explorerQuery === 'object')
    ? { ...explorerQuery }
    : (item ? observationExplorerQueryFallback(item) : {});
  return {
    ...base,
    timeRange: normalizeObservationLookback(lookback || '1h'),
    customPeriod: null,
  };
}

function startComposeInExplorer(onNavigate, {
  mode = null,
  editId = null,
  name = '',
  explorerQuery = null,
  filters = null,
  thresholds = null,
  groupBy = null,
  lookback = null,
} = {}) {
  const resolvedEditId = editId || null;
  const resolvedMode = mode || (resolvedEditId ? 'edit' : 'new');
  const resolvedQuery = explorerQuery || (
    Array.isArray(filters)
      ? {
        filters,
        thresholds: Array.isArray(thresholds) ? thresholds : [],
        groupBy: Array.isArray(groupBy) && groupBy.length ? groupBy : ['src_asn'],
        timeRange: lookback || '1h',
        customPeriod: null,
        metric: 'bps',
        vis: 'stack',
        limit: 25,
      }
      : null
  );
  try {
    sessionStorage.setItem(COMPOSE_KEY, JSON.stringify({
      active: true,
      mode: resolvedMode,
      editId: resolvedMode === 'edit' ? resolvedEditId : null,
      name: name || '',
      explorerQuery: resolvedQuery,
      autoRun: Boolean(resolvedQuery),
      startedAt: Date.now(),
    }));
  } catch {
    // ignore
  }
  notifyObservationComposeChanged();
  if (typeof onNavigate === 'function') onNavigate('explorer');
  else location.hash = 'explorer';
}

function shortBucketLabel(raw, displayTimezone) {
  // Keep raw bucket for DualChart/Spark — they format via displayTimezone.
  // Fallback only for AreaChart (no TZ-aware axis).
  if (typeof formatBucketLabel === 'function') {
    const label = formatBucketLabel(raw, false, displayTimezone);
    if (label && label !== '—') return label;
  }
  const s = String(raw || '');
  const m = s.match(/T(\d{2}:\d{2})/);
  if (m) return m[1];
  if (s.length >= 16) return s.slice(11, 16);
  return s;
}

function observationPeriodLabel(lookback, customRange) {
  if (customRange?.from && customRange?.to) {
    if (typeof formatCustomPeriodLabel === 'function') {
      return formatCustomPeriodLabel(customRange);
    }
    return obsT('observations.period.selected');
  }
  return observationLookbackLabel(lookback);
}

function ObservationChart({
  points,
  lines,
  mode = 'total',
  stackMode,
  height = 160,
  metric = 'bps',
  onRangeSelect,
  displayTimezone,
  bucketSeconds = 300,
  periodStartMs,
  periodEndMs,
  skipLeadingGaps = false,
  skipTrailingGaps = false,
  tipTranslucent = true,
}) {
  const chartMetric = normalizeObservationChartMetric(metric);
  const axisUnit = observationMetricAxisUnit(chartMetric);
  const valueFmt = (v) => formatObservationMetric(v, chartMetric);
  const axisFmt = (v) => formatObservationMetricAxis(v, chartMetric);
  if (!points?.length) {
    return (
      <div style={{
        height,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--fg-secondary)',
        font: 'var(--pv-text-body-3)',
      }}>
        Нет данных за окно
      </div>
    );
  }

  if (mode === 'grouped' && lines?.length && typeof DualChart === 'function') {
    const chartPoints = points.map((p) => ({
      ...p,
      // Do not pre-slice UTC HH:MM into t — DualChart formats via displayTimezone.
      bucket: p.bucket || p.t,
    }));
    const ready = chartPoints.length === 1
      ? [chartPoints[0], { ...chartPoints[0] }]
      : chartPoints;
    return (
      <DualChart
        points={ready}
        lines={lines}
        stackMode={stackMode}
        height={height}
        mode="bw"
        gapAsZero={stackMode === 'sum'}
        valueFormatter={valueFmt}
        axisFormatter={axisFmt}
        onRangeSelect={onRangeSelect}
        bucketSeconds={bucketSeconds}
        displayTimezone={displayTimezone}
        periodStartMs={periodStartMs}
        periodEndMs={periodEndMs}
        skipLeadingGaps={skipLeadingGaps}
        skipTrailingGaps={skipTrailingGaps}
        tipTranslucent={tipTranslucent}
        tipUnitLabel={axisUnit}
        yAxisUnit={axisUnit}
        yAxisTitlePad={36}
      />
    );
  }

  const chartPoints = points.map((p) => ({
    ...p,
    value: observationPointValue(p),
    bps: Number(p.bps) || 0,
    bucket: p.bucket || p.t,
    t: p.t || p.bucket,
  }));
  if (typeof TimeSeriesSparkChart === 'function') {
    return (
      <TimeSeriesSparkChart
        points={chartPoints}
        height={height}
        valueKey="value"
        valueLabel={observationMetricValueLabel(chartMetric)}
        formatValue={valueFmt}
        axisFormatter={axisFmt}
        onRangeSelect={onRangeSelect}
        bucketSeconds={bucketSeconds}
        displayTimezone={displayTimezone}
        periodStartMs={periodStartMs}
        periodEndMs={periodEndMs}
        skipLeadingGaps={skipLeadingGaps}
        skipTrailingGaps={skipTrailingGaps}
        tipTranslucent={tipTranslucent}
        yAxisUnit={axisUnit}
        yAxisTitlePad={36}
      />
    );
  }
  return (
    <AreaChart
      data={chartPoints.map((p) => ({
        t: shortBucketLabel(p.bucket || p.t, displayTimezone),
        v: observationPointValue(p),
      }))}
      height={height}
      units={axisUnit}
    />
  );
}

function ObservationChartStats({ points, lines, mode = 'total', metric = 'bps' }) {
  const chartMetric = normalizeObservationChartMetric(metric);
  const valueFmt = (v) => formatObservationMetric(v, chartMetric);
  const stats = chartSeriesStats(points, lines, mode, chartMetric);
  if (!stats) return null;
  return (
    <div
      className="row"
      style={{
        gap: 14,
        flexWrap: 'wrap',
        font: 'var(--pv-text-body-3)',
        color: 'var(--fg-secondary)',
        marginTop: 4,
      }}
    >
      <span title={obsT('observations.stats.avgTitle')}>
        avg <span className="mono" style={{ color: 'var(--fg-primary)' }}>{valueFmt(stats.avg)}</span>
      </span>
      <span title={obsT('observations.stats.minTitle')}>
        min <span className="mono" style={{ color: 'var(--fg-primary)' }}>{valueFmt(stats.min)}</span>
      </span>
      <span title={obsT('observations.stats.maxTitle')}>
        max <span className="mono" style={{ color: 'var(--fg-primary)' }}>{valueFmt(stats.max)}</span>
      </span>
      <span title={obsT('observations.stats.nowMaxTitle')}>
        now/max{' '}
        <span className="mono" style={{ color: 'var(--fg-primary)' }}>
          {stats.pctOfMax == null ? '—' : `${stats.pctOfMax.toFixed(1)}%`}
        </span>
      </span>
    </div>
  );
}

function observationSeriesCountLabel(count) {
  const n10 = count % 10;
  const n100 = count % 100;
  if (n10 === 1 && n100 !== 11) return 'серия';
  if (n10 >= 2 && n10 <= 4 && (n100 < 12 || n100 > 14)) return 'серии';
  return 'серий';
}

function ObservationSeriesFocus({ lines, focusKeys, onToggle, onClear }) {
  if (!lines?.length || lines.length < 2) return null;
  const selected = new Set(focusKeys || []);
  const filtering = selected.size > 0;
  return (
    <div className="obs-tile__legend" role="group" aria-label="Серии графика">
      <button
        type="button"
        className={`obs-tile__chip${!filtering ? ' is-active' : ''}`}
        aria-pressed={!filtering}
        onClick={onClear}
      >
        Все
      </button>
      {lines.map((ln) => {
        const on = selected.has(ln.key);
        const dim = filtering && !on;
        return (
          <button
            key={ln.key}
            type="button"
            className={`obs-tile__chip${on ? ' is-solo' : ''}${dim ? ' is-off' : ''}`}
            aria-pressed={on}
            title={on ? obsT('observations.series.remove') : obsT('observations.series.add')}
            onClick={() => onToggle(ln.key)}
          >
            <span className="obs-tile__chip-swatch" style={{ background: ln.color || 'var(--fg-muted)' }} />
            <span className="obs-tile__chip-label">{ln.label || ln.key}</span>
          </button>
        );
      })}
    </div>
  );
}

function formatObservationAttemptTime(iso, timeZone) {
  const at = new Date(iso);
  if (!Number.isFinite(at.getTime())) return '';
  const opts = { hour: '2-digit', minute: '2-digit' };
  if (timeZone) opts.timeZone = timeZone;
  const dayKey = (d) => d.toLocaleDateString('ru-RU', timeZone ? { timeZone } : undefined);
  const time = at.toLocaleTimeString('ru-RU', opts);
  if (dayKey(at) === dayKey(new Date())) return time;
  const date = at.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short', ...(timeZone ? { timeZone } : {}) });
  return `${date}, ${time}`;
}

function ObservationMaterializeIssue({ issue, displayTimezone, onRetry }) {
  const [busy, setBusy] = useState(false);
  const nextAt = issue.nextAttemptAt
    ? formatObservationAttemptTime(issue.nextAttemptAt, displayTimezone)
    : '';
  let status;
  if (issue.stopped) {
    status = `Остановлено после ${issue.maxFailCount} ошибок, само не продолжит.`;
  } else if (nextAt) {
    status = `Ошибок подряд: ${issue.failCount} из ${issue.maxFailCount}. Следующая попытка в ${nextAt}.`;
  } else {
    status = `Ошибок подряд: ${issue.failCount} из ${issue.maxFailCount}. Повтор на ближайшем цикле.`;
  }
  const retry = () => {
    if (!onRetry || busy) return;
    setBusy(true);
    Promise.resolve(onRetry()).finally(() => setBusy(false));
  };
  return (
    <div className="obs-tile__issue" role="alert">
      <div className="obs-tile__issue-text">
        <div className="obs-tile__issue-title">Данные не считаются: {issue.reason}</div>
        <div className="obs-tile__issue-status">{status}</div>
      </div>
      {onRetry && (
        <button type="button" className="btn btn--sm" disabled={busy} onClick={retry}>
          {busy ? 'Запуск…' : 'Повторить сейчас'}
        </button>
      )}
    </div>
  );
}

function LookbackPicker({ value, options, onChange }) {
  const list = options?.length ? options : LOOKBACK_OPTIONS;
  return (
    <div className="seg obs-tile__lookback" role="group" aria-label="Период графика">
      {list.map((v) => (
        <button
          key={v}
          type="button"
          className={v === value ? 'is-active' : ''}
          title={observationLookbackLabel(v)}
          onClick={() => onChange(v)}
        >
          {observationLookbackChip(v)}
        </button>
      ))}
    </div>
  );
}

function ObservationChartStylePicker({ value, onChange, disabled = false }) {
  return (
    <div className="seg obs-tile__chart-style" role="group" aria-label={obsT('observations.settings.chartType')}>
      {observationChartStyles().map((style) => (
        <button
          key={style.id}
          type="button"
          className={style.id === value ? 'is-active' : ''}
          title={style.hint || style.label}
          aria-pressed={style.id === value}
          disabled={disabled}
          onClick={() => onChange(style.id)}
        >
          <Icon name={style.icon} size={12} />
          <span>{style.label}</span>
        </button>
      ))}
    </div>
  );
}

function ObservationLiveTile({
  item,
  groupOptions,
  filterFields,
  lookbackOptions,
  expanded,
  onToggleExpand,
  onNavigate,
  canWrite,
  onSettings,
  onDelete,
  onCancel,
  onRetry,
  onRunReport,
  onLookbackChange,
  onChartStyleChange,
  isNativeAggregate,
  collectors,
  locations,
  editMode,
  onDragHandleMouseDown,
  onHide,
  onDuplicate,
}) {
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [lookback, setLookback] = useState(normalizeObservationLookback(item.lookback));
  const [chartStyle, setChartStyle] = useState(() => observationChartStyleFromWidgets(item.widgets));
  const [customRange, setCustomRange] = useState(null);
  const [zoomStack, setZoomStack] = useState([]);
  const [runs, setRuns] = useState([]);
  const [runsError, setRunsError] = useState('');
  const [expandedTab, setExpandedTab] = useState(() => (
    hasTopTableWidget(item.widgets) ? 'top' : 'reports'
  )); // top | reports
  const [focusKeys, setFocusKeys] = useState([]);
  const customRangeRef = useRef(null);
  const displayTimezone = typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined;
  const widgetsTileSyncSignature = observationWidgetsTileSyncSignature(item.widgets);
  const seriesFocusResetSignature = observationSeriesFocusResetSignature(item.widgets);

  useEffect(() => {
    customRangeRef.current = customRange;
  }, [customRange]);

  useEffect(() => {
    setLookback(normalizeObservationLookback(item.lookback));
    setChartStyle(observationChartStyleFromWidgets(item.widgets));
    setCustomRange(null);
    setZoomStack([]);
    if (!hasTopTableWidget(item.widgets)) setExpandedTab('reports');
  }, [item.id, item.lookback, widgetsTileSyncSignature]);

  useEffect(() => {
    setFocusKeys([]);
  }, [item.id, seriesFocusResetSignature]);

  const previewPayload = useMemo(() => (
    customRange?.from && customRange?.to
      ? { from: customRange.from, to: customRange.to }
      : { lookback: lookback || '1h' }
  ), [customRange?.from, customRange?.to, lookback]);

  const chartPeriodBounds = useMemo(
    () => observationChartPeriodBounds({
      window: preview?.window,
      customRange,
      lookback,
      displayTimezone,
    }),
    [preview?.window?.from, preview?.window?.to, customRange?.from, customRange?.to, lookback, displayTimezone],
  );

  useEffect(() => {
    let cancelled = false;
    let timer = null;
    // У фиксированного диапазона данные не меняются — подстраиваться под бакеты незачем.
    const isLive = !(previewPayload.from && previewPayload.to);
    setLoading(true);
    function scheduleNext(windowTo) {
      if (cancelled) return;
      const delay = isLive ? nextTileDelayMs(windowTo) : tileRefreshSec() * 1000;
      timer = setTimeout(() => tick({ initial: false }), delay);
    }
    function tick(opts = { initial: true }) {
      if (opts.initial) setLoading(true);
      else setRefreshing(true);
      ApiClient.previewObservation(item.id, previewPayload)
        .then((body) => {
          if (cancelled) return;
          const data = body.data || body;
          setPreview(data);
          setLoading(false);
          setRefreshing(false);
          setError('');
          setUpdatedAt(new Date());
          scheduleNext(data?.window?.to);
        })
        .catch((e) => {
          if (cancelled) return;
          setError(e.message);
          setLoading(false);
          setRefreshing(false);
          scheduleNext(null);
        });
    }
    tick({ initial: true });
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [item.id, previewPayload]);

  useEffect(() => {
    if (!expanded) return undefined;
    let cancelled = false;
    ApiClient.loadObservationRuns(item.id)
      .then((rows) => {
        if (!cancelled) {
          setRuns(Array.isArray(rows) ? rows.slice(0, 20) : []);
          setRunsError('');
        }
      })
      .catch((e) => {
        if (!cancelled) setRunsError(e.message || 'Не удалось загрузить отчёты');
      });
    return () => { cancelled = true; };
  }, [expanded, item.id, updatedAt]);

  const changeLookback = (next) => {
    if (!next || next === lookback) return;
    setCustomRange(null);
    setZoomStack([]);
    setLookback(next);
    if (canEdit && typeof onLookbackChange === 'function') onLookbackChange(item.id, next);
  };

  const changeChartStyle = (next) => {
    const normalized = normalizeObservationChartStyle(next);
    if (normalized === chartStyle) return;
    setChartStyle(normalized);
    if (canEdit && typeof onChartStyleChange === 'function') onChartStyleChange(item.id, normalized);
  };

  const handleChartRangeSelect = (range) => {
    if (!range?.from || !range?.to) return;
    if (typeof validateCustomPeriod === 'function' && validateCustomPeriod(range)) return;
    setZoomStack((stack) => [...stack, customRangeRef.current]);
    setCustomRange({ from: range.from, to: range.to });
  };

  const resetTileZoom = () => {
    if (!zoomStack.length) {
      setCustomRange(null);
      return;
    }
    const prev = zoomStack[zoomStack.length - 1];
    setCustomRange(prev);
    setZoomStack((stack) => stack.slice(0, -1));
  };

  const chartWidget = (preview?.widgets || []).find((w) => w.type === 'timeseries_bps');
  const topWidget = (preview?.widgets || []).find((w) => w.type === 'top_table');
  // "Прочие" is the remainder of the whole traffic, so it must survive the display cut.
  const topRowsWithOther = useMemo(() => {
    const all = Array.isArray(topWidget?.rows) ? topWidget.rows : [];
    const other = all.find((r) => r.isOther);
    const shown = all.filter((r) => !r.isOther).slice(0, TOP_ROWS_VIEW_LIMIT);
    return other ? [...shown, other] : shown;
  }, [topWidget]);
  const chartMode = chartWidget?.mode === 'grouped' ? 'grouped' : 'total';
  const points = chartWidget?.points || chartWidget?.series || [];
  const lines = localizeObservationChartLines(chartWidget?.lines || []);
  const lineKeys = lines.map((ln) => ln.key).join('\0');
  useEffect(() => {
    setFocusKeys((prev) => {
      if (!prev.length) return prev;
      const allowed = new Set(lines.map((ln) => ln.key));
      const next = prev.filter((key) => allowed.has(key));
      return next.length === prev.length ? prev : next;
    });
  }, [lineKeys]);
  const focusSet = useMemo(() => new Set(focusKeys), [focusKeys]);
  const visibleLines = focusSet.size ? lines.filter((ln) => focusSet.has(ln.key)) : lines;
  const chartStackMode = observationChartStyleToStackMode(chartStyle);
  const focusLabel = focusSet.size
    ? lines.filter((ln) => focusSet.has(ln.key)).map((ln) => ln.label || ln.key).join(', ')
    : null;

  const toggleFocusKey = (key) => {
    setFocusKeys((prev) => (
      prev.includes(key) ? prev.filter((item) => item !== key) : [...prev, key]
    ));
  };
  const chartMetric = observationMetricFromWidgets(item.widgets);
  const tableMetric = observationTableMetricFromWidgets(item.widgets);
  const tableMetricUnit = observationMetricAxisUnit(tableMetric);
  const topGroupBy = groupByFromWidgets(item.widgets);
  const topLabel = topGroupBy.map((g) => groupLabel(g, groupOptions)).join(' × ');
  const nativeSummary = isNativeAggregate
    ? nativeAggregateSummary(item, collectors, locations)
    : null;
  const showTopTab = hasTopTableWidget(item.widgets);
  const chartH = expanded ? 320 : 200;
  const periodLabel = observationPeriodLabel(lookback, customRange);
  const canResetZoom = Boolean(customRange || zoomStack.length);
  const canEdit = Boolean(canWrite && item.canEdit);

  const openInExplorer = () => startComposeInExplorer(onNavigate, {
    mode: canEdit ? 'edit' : 'new',
    editId: canEdit ? item.id : null,
    name: item.name || '',
    explorerQuery: observationExplorerQueryForCompose(item, { customRange }),
  });

  const verboseMeta = DashboardLog?.isVerbose?.() === true;
  let footerMeta = null;
  if (loading && !points.length) footerMeta = 'загрузка…';
  else if (refreshing) footerMeta = 'обновление…';
  else if (verboseMeta) {
    footerMeta = chartMode === 'grouped'
      ? `${focusLabel ? `${focusKeys.length} ${observationSeriesCountLabel(focusKeys.length)} · ${focusLabel}` : `${lines.length} серий`} · ${points.length} точек · ${periodLabel}${customRange ? ' · zoom' : ''}`
      : `${points.length} точек · ${periodLabel}${customRange ? ' · zoom' : ''}`;
    if (updatedAt) footerMeta += ` · ${updatedAt.toLocaleTimeString('ru-RU')}`;
  }

  return (
    <div
      className={`obs-tile-wrap${expanded ? ' obs-tile-wrap--expanded' : ''}`}
      data-obs-tile-id={item.id}
      data-obs-flip-id={item.id}
    >
    <Card pad="sm" className={`obs-tile${expanded ? ' obs-tile--expanded' : ''}${editMode ? ' obs-tile--edit' : ''}`}>
      <div className="obs-tile__head">
        {editMode && onDragHandleMouseDown ? (
          <div
            className="obs-tile__drag-handle"
            title={obsT('observations.board.dragReorder')}
            onMouseDown={onDragHandleMouseDown}
          >
            <Icon name="drag" size={14} />
          </div>
        ) : null}
        <div style={{ flex: 1, minWidth: 160 }}>
          <div className="obs-tile__title">{item.name}</div>
          {item.description ? <div className="obs-tile__desc">{item.description}</div> : null}
          {isNativeAggregate && verboseMeta && nativeSummary ? (
            <div className="obs-tile__filter-scope" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              {nativeSummary}
            </div>
          ) : !isNativeAggregate ? (
            <button
              type="button"
              className="obs-tile__filter-link"
              onClick={openInExplorer}
              title="Открыть в разборе трафика"
            >
              <span className="obs-tile__filter-scope">
                <span className="obs-tile__filter-scope-label">{obsT('observations.filters')}:</span>
                {' '}
                <span className="obs-tile__filter-link-text">
                  {renderFilterSummary(item.filters || [], filterFields)}
                </span>
              </span>
              {topLabel ? (
                <span className="obs-tile__filter-scope obs-tile__filter-scope--group">
                  <span className="obs-tile__filter-scope-label">{obsT('observations.group')}:</span>
                  {' '}
                  <span className="obs-tile__filter-link-text">{topLabel}</span>
                </span>
              ) : null}
            </button>
          ) : null}
        </div>
        <div className="obs-tile__tools">
          {editMode && onHide ? (
            <button
              type="button"
              className="obs-tile__icon tt"
              data-tt={obsT('observations.board.hide')}
              aria-label={obsT('observations.board.hide')}
              onClick={onHide}
            >
              <Icon name="eyeOff" size={15} />
            </button>
          ) : null}
          {!editMode && (
          <button
            type="button"
            className="obs-tile__expand"
            onClick={onToggleExpand}
            aria-expanded={expanded}
            title={expanded ? obsT('observations.collapseTitle') : obsT('observations.expandTitle')}
          >
            <Icon name={expanded ? 'collapse' : 'expand'} size={14} />
            <span>{expanded ? obsT('observations.collapse') : obsT('observations.expand')}</span>
          </button>
          )}
          {!editMode && canEdit && onDuplicate && (
            <button
              type="button"
              className="obs-tile__icon tt"
              data-tt={obsT('observations.section.copy')}
              aria-label={obsT('observations.section.copy')}
              onClick={onDuplicate}
            >
              <Icon name="copy" size={15} />
            </button>
          )}
          {!editMode && canEdit && (
            <button
              type="button"
              className="obs-tile__icon tt"
              data-tt={obsT('observations.settings')}
              aria-label={obsT('observations.settings')}
              onClick={onSettings}
            >
              <Icon name="sliders" size={15} />
            </button>
          )}
          {!editMode && canEdit && item.materialize?.status === 'running' && onCancel && (
            <button
              type="button"
              className="obs-tile__icon tt"
              data-tt="Отменить подготовку"
              aria-label="Отменить подготовку"
              onClick={onCancel}
            >
              <Icon name="x" size={15} />
            </button>
          )}
          {!editMode && canEdit && (
            <button
              type="button"
              className="obs-tile__icon obs-tile__icon--danger tt"
              data-tt={obsT('observations.delete')}
              aria-label={obsT('observations.delete')}
              onClick={onDelete}
            >
              <Icon name="trash" size={15} />
            </button>
          )}
        </div>
      </div>

      {error && (
        <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{error}</div>
      )}
      {item.materializeIssue && (
        <ObservationMaterializeIssue
          issue={item.materializeIssue}
          displayTimezone={displayTimezone}
          onRetry={canEdit ? onRetry : null}
        />
      )}
      {(item.warnings || []).map((w) => (
        <div key={w} style={{ color: 'var(--fg-warning)', font: 'var(--pv-text-body-3)' }}>{w}</div>
      ))}
      {chartWidget?.warning && (
        <div style={{ color: 'var(--fg-warning)', font: 'var(--pv-text-body-3)' }}>
          {chartWidget.warning}
        </div>
      )}

      <div className="obs-tile__chart" style={{ minHeight: chartH, opacity: loading && !points.length ? 0.55 : 1, transition: 'opacity .15s' }}>
        <ObservationChart
          points={points}
          lines={visibleLines}
          mode={chartMode}
          stackMode={chartMode === 'grouped' ? chartStackMode : undefined}
          height={chartH}
          metric={isNativeAggregate ? 'bps' : chartMetric}
          onRangeSelect={points.length > 1 ? handleChartRangeSelect : undefined}
          displayTimezone={displayTimezone}
          bucketSeconds={300}
          periodStartMs={chartPeriodBounds.periodStartMs}
          periodEndMs={chartPeriodBounds.periodEndMs}
          skipLeadingGaps
          skipTrailingGaps
        />
      </div>
      {chartMode === 'grouped' && (
        <ObservationSeriesFocus
          lines={lines}
          focusKeys={focusKeys}
          onToggle={toggleFocusKey}
          onClear={() => setFocusKeys([])}
        />
      )}
      {!!points.length && (
        <ObservationChartStats
          points={points}
          lines={visibleLines}
          mode={chartMode}
          metric={isNativeAggregate ? 'bps' : chartMetric}
        />
      )}

      <div className="obs-tile__footer">
        {footerMeta ? <span className="obs-tile__meta">{footerMeta}</span> : null}
        <div className="obs-tile__footer-tools">
          {canResetZoom && (
            <button
              type="button"
              className="time-pill time-pill--reset"
              title="Вернуть предыдущий период"
              onClick={resetTileZoom}
            >
              <Icon name="zoom" size={14} />
              <span>Сброс</span>
            </button>
          )}
          {chartMode === 'grouped' && lines.length > 1 && (
            <ObservationChartStylePicker
              value={chartStyle}
              onChange={changeChartStyle}
            />
          )}
          <LookbackPicker
            value={lookback}
            options={lookbackOptions}
            onChange={changeLookback}
          />
        </div>
      </div>

      {expanded && (
        <div style={{ marginTop: 4, borderTop: '1px solid var(--bd-soft)', paddingTop: 12 }}>
          <div className="seg" style={{ width: 'fit-content', marginBottom: 10 }}>
            {showTopTab && (
              <button type="button" className={expandedTab === 'top' ? 'is-active' : ''} onClick={() => setExpandedTab('top')}>
                Топ
              </button>
            )}
            <button type="button" className={expandedTab === 'reports' ? 'is-active' : ''} onClick={() => setExpandedTab('reports')}>
              Отчёты
            </button>
          </div>

          {expandedTab === 'top' && showTopTab && (
            <>
              <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 8 }}>
                Разбивка: топ по {topLabel} ({tableMetricUnit} за {periodLabel})
              </div>
              {Array.isArray(topWidget?.rows) && topWidget.rows.length > 0 ? (
                <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
                  <thead>
                    <tr>
                      {(topWidget.groupBy || []).map((g) => (
                        <th key={g} style={{ textAlign: 'left', padding: 4 }}>
                          {groupLabel(g, groupOptions)}
                        </th>
                      ))}
                      <th style={{ textAlign: 'right', padding: 4 }}>{tableMetricUnit}</th>
                      <th style={{ textAlign: 'right', padding: 4 }}>%</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topRowsWithOther.map((r) => {
                      const rowKey = r.key || r.id;
                      const onChart = lines.some((ln) => ln.key === rowKey);
                      const isFocus = focusSet.has(rowKey);
                      return (
                        <tr
                          key={rowKey}
                          className={[
                            r.isOther ? 'obs-tile__row--other' : '',
                            onChart ? 'obs-tile__row--pick' : '',
                            isFocus ? 'obs-tile__row--focus' : '',
                          ].filter(Boolean).join(' ') || undefined}
                          title={onChart ? (isFocus ? obsT('observations.series.remove') : obsT('observations.series.add')) : undefined}
                          onClick={onChart ? () => toggleFocusKey(rowKey) : undefined}
                        >
                          {(r.values || []).map((v, i) => (
                            <td key={i} style={{ padding: 4 }} className="mono">{v}</td>
                          ))}
                          <td style={{ padding: 4, textAlign: 'right' }} className="mono">
                            {formatObservationMetric(r.metric, tableMetric)}
                          </td>
                          <td style={{ padding: 4, textAlign: 'right' }} className="mono">
                            {r.pct != null && Number.isFinite(Number(r.pct))
                              ? `${Number(r.pct).toFixed(1)}%`
                              : '—'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Нет строк топа</div>
              )}
            </>
          )}

          {expandedTab === 'reports' && (
            <div className="col" style={{ gap: 8 }}>
              <div className="row" style={{ justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                <div style={{ font: 'var(--pv-text-body-2-bold)' }}>История запусков</div>
                {canEdit && (
                  <button
                    type="button"
                    className="btn"
                    onClick={() => {
                      Promise.resolve(onRunReport?.())
                        .then(() => setUpdatedAt(new Date()))
                        .catch((e) => setRunsError(e.message));
                    }}
                  >
                    Сформировать отчёт
                  </button>
                )}
              </div>
              <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
                {`Отчёт за: ${reportPeriodLabel(item)} — период берётся из настроек отчёта, а не из time range плитки.`}
              </div>
              {runsError && <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{runsError}</div>}
              {!runs.length && !runsError && (
                <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Пока нет запусков</div>
              )}
              {!!runs.length && (
                <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left', padding: 4 }}>Когда</th>
                      <th style={{ textAlign: 'left', padding: 4 }}>Период</th>
                      <th style={{ textAlign: 'left', padding: 4 }}>Статус</th>
                      <th style={{ textAlign: 'left', padding: 4 }}>Письмо</th>
                      <th style={{ textAlign: 'left', padding: 4 }}>Файлы</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run) => (
                      <tr key={run.id}>
                        <td style={{ padding: 4 }}>{fmtDiagTime(run.finishedAt || run.startedAt)}</td>
                        <td style={{ padding: 4 }}>{run.period || '—'}</td>
                        <td style={{ padding: 4 }}>{run.status || '—'}</td>
                        <td style={{ padding: 4 }}>
                          {run.emailStatus || '—'}
                          {run.emailError ? ` (${run.emailError})` : ''}
                        </td>
                        <td style={{ padding: 4 }}>
                          <a href={ApiClient.observationRunArtifactUrl(item.id, run.id, 'report.html')} target="_blank" rel="noreferrer">сводка</a>
                          {(run.tables || []).map((t) => {
                            const label = t.label
                              || (t.type === 'timeseries_bps' ? 'График' : t.type === 'top_table' ? 'Топ' : t.file);
                            return (
                              <span key={t.file}>
                                {' · '}
                                <a href={ApiClient.observationRunArtifactUrl(item.id, run.id, t.file)} target="_blank" rel="noreferrer">
                                  {label}
                                </a>
                              </span>
                            );
                          })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
    </div>
  );
}

function fmtDiagTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('ru-RU');
  } catch {
    return String(iso);
  }
}

const OBS_BOARD_DRAG_THRESHOLD_PX = 8;
const OBS_BOARD_FLIP_TRANSITION = 'transform 0.34s cubic-bezier(0.22, 1, 0.36, 1)';

function compareObservationsDefaultOrder(a, b) {
  const ao = Number(a.layout?.order) || 0;
  const bo = Number(b.layout?.order) || 0;
  if (ao !== bo) return ao - bo;
  return String(a.name || '').localeCompare(String(b.name || ''), 'ru');
}

function sortObservationsDefaultOrder(items) {
  return [...items].sort(compareObservationsDefaultOrder);
}

function mergeObservationBoardOrder(items, savedIds) {
  const byId = new Map((items || []).map((item) => [item.id, item]));
  const ordered = [];
  const seen = new Set();
  for (const rawId of savedIds || []) {
    const id = String(rawId || '').trim();
    if (!id || seen.has(id)) continue;
    const item = byId.get(id);
    if (item) {
      ordered.push(item);
      seen.add(id);
    }
  }
  const rest = sortObservationsDefaultOrder((items || []).filter((item) => !seen.has(item.id)));
  return [...ordered, ...rest];
}

function moveObservationIdToIndex(ids, sourceId, targetIndex) {
  if (!sourceId || !Number.isInteger(targetIndex)) return ids;
  const sourceIndex = ids.indexOf(sourceId);
  if (sourceIndex < 0 || sourceIndex === targetIndex) return ids;
  const next = ids.filter((id) => id !== sourceId);
  const insertIndex = Math.max(0, Math.min(targetIndex, next.length));
  next.splice(insertIndex, 0, sourceId);
  return next;
}

function sameObservationIds(a, b) {
  return a.length === b.length && a.every((id, index) => id === b[index]);
}

function readObservationBoardRect(el) {
  if (!el) return null;
  const rect = el.getBoundingClientRect();
  const transform = window.getComputedStyle(el).transform;
  if (!transform || transform === 'none') return rect;
  try {
    const matrix = new DOMMatrixReadOnly(transform);
    return new DOMRect(
      rect.left - matrix.e,
      rect.top - matrix.f,
      rect.width,
      rect.height,
    );
  } catch {
    return rect;
  }
}

function observationBoardSlots(boardEl) {
  if (!boardEl) return [];
  return [...boardEl.querySelectorAll(':scope > .obs-tile-wrap')]
    .map((el, index) => ({ el, index, rect: readObservationBoardRect(el) }))
    .filter((slot) => slot.rect);
}

function findObservationBoardDropIndex(clientX, clientY, boardEl, fallbackIndex) {
  const slots = observationBoardSlots(boardEl);
  if (!slots.length) return fallbackIndex;
  const direct = slots.find(({ rect }) => (
    clientX >= rect.left && clientX <= rect.right
      && clientY >= rect.top && clientY <= rect.bottom
  ));
  if (direct) return direct.index;

  const columnSlots = slots.filter(({ rect }) => clientX >= rect.left && clientX <= rect.right);
  const candidates = columnSlots.length ? columnSlots : slots;
  let nearest = null;
  let nearestDistance = Infinity;
  for (const slot of candidates) {
    const dx = clientX < slot.rect.left
      ? slot.rect.left - clientX
      : (clientX > slot.rect.right ? clientX - slot.rect.right : 0);
    const dy = clientY < slot.rect.top
      ? slot.rect.top - clientY
      : (clientY > slot.rect.bottom ? clientY - slot.rect.bottom : 0);
    const distance = Math.hypot(dx, dy);
    if (distance < nearestDistance) {
      nearest = slot;
      nearestDistance = distance;
    }
  }
  return nearest ? nearest.index : fallbackIndex;
}

function captureObservationBoardFlipRects(boardEl) {
  const rects = new Map();
  if (!boardEl) return rects;
  boardEl.querySelectorAll('[data-obs-flip-id]').forEach((el) => {
    const id = el.dataset.obsFlipId;
    if (id) rects.set(id, readObservationBoardRect(el));
  });
  return rects;
}

function runObservationBoardFlipAnimation(boardEl, firstRects) {
  if (!boardEl || !firstRects?.size) return;
  boardEl.querySelectorAll('[data-obs-flip-id]').forEach((el) => {
    const first = firstRects.get(el.dataset.obsFlipId);
    if (!first) return;
    const last = readObservationBoardRect(el);
    if (!last) return;
    const dx = first.left - last.left;
    const dy = first.top - last.top;
    if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) return;
    el.style.transform = `translate3d(${dx}px, ${dy}px, 0)`;
    el.style.transition = 'none';
    requestAnimationFrame(() => {
      el.style.transition = OBS_BOARD_FLIP_TRANSITION;
      el.style.transform = '';
    });
  });
}

function ObservationsHiddenMenu({ items, onRestore, editMode }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);

  useEffect(() => {
    if (!editMode) setOpen(false);
  }, [editMode]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event) => {
      if (!rootRef.current?.contains(event.target)) setOpen(false);
    };
    const onKeyDown = (event) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  if (!editMode) return null;

  return (
    <div className={`observations-hidden-menu${open ? ' is-open' : ''}`} ref={rootRef}>
      <button
        type="button"
        className="btn btn--sm"
        onClick={() => setOpen((value) => !value)}
        title={obsT('observations.board.hiddenCards')}
      >
        <Icon name="eyeOff" size={14} />
        <span>{obsT('observations.board.hidden')}</span>
        {items.length ? <span className="observations-hidden-menu__count">{items.length}</span> : null}
        <Icon name="chevD" size={12} />
      </button>
      {open ? (
        <div className="observations-hidden-menu__dropdown" role="menu">
          <div className="observations-hidden-menu__title">
            {obsT('observations.board.hiddenCards')}
          </div>
          {items.length ? items.map((item) => (
            <div key={item.id} className="observations-hidden-menu__item" role="menuitem">
              <span className="observations-hidden-menu__item-label">{item.name || item.id}</span>
              <button
                type="button"
                className="observations-hidden-menu__restore"
                onClick={() => onRestore(item.id)}
              >
                <Icon name="eye" size={14} />
                {obsT('observations.board.restore')}
              </button>
            </div>
          )) : (
            <div className="observations-hidden-menu__empty">
              {obsT('observations.board.noHidden')}
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}

function ObservationsBoardToolbar({
  editMode,
  saveState,
  hiddenItems,
  onCustomize,
  onRestore,
  onRevert,
  onCancel,
  onDone,
  className = '',
}) {
  const saveLabel = {
    idle: '',
    saving: obsT('observations.board.saving'),
    saved: obsT('observations.board.saved'),
    error: obsT('observations.board.saveError'),
  }[saveState] || '';

  return (
    <div className={`observations-board-toolbar${editMode ? ' observations-board-toolbar--edit' : ''}${className ? ` ${className}` : ''}`}>
      {saveLabel ? (
        <span className={`observations-board-toolbar__status${saveState === 'error' ? ' is-error' : ''}`}>
          {saveLabel}
        </span>
      ) : null}
      {editMode ? (
        <>
          <ObservationsHiddenMenu
            editMode={editMode}
            items={hiddenItems}
            onRestore={onRestore}
          />
          <button type="button" className="btn btn--sm" onClick={onRevert}>
            {obsT('observations.board.revert')}
          </button>
          <button type="button" className="btn btn--sm" onClick={onCancel}>
            {obsT('observations.board.cancel')}
          </button>
          <button
            type="button"
            className="btn btn--sm btn--primary"
            disabled={saveState === 'saving'}
            onClick={onDone}
          >
            {obsT('observations.board.done')}
          </button>
        </>
      ) : (
        <button type="button" className="btn btn--sm" onClick={onCustomize}>
          <Icon name="sliders" size={14} />
          <span>{obsT('observations.board.customize')}</span>
        </button>
      )}
    </div>
  );
}

function ObservationBoardTilePhantom({
  id, title, expanded, height,
}) {
  return (
    <div
      className={`obs-tile-wrap obs-tile-wrap--phantom${expanded ? ' obs-tile-wrap--expanded' : ''}`}
      data-obs-board-phantom="true"
      data-obs-flip-id={id}
      aria-hidden="true"
      style={height ? { height, minHeight: height } : undefined}
    >
      <div className="obs-tile-phantom__frame">
        <span>{title}</span>
      </div>
    </div>
  );
}

function ObservationSectionsPanel({ onChanged }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [newTitle, setNewTitle] = useState('');
  const [editSection, setEditSection] = useState(null);
  const [dragId, setDragId] = useState(null);

  const loadSections = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await ApiClient.loadObservationSectionsAdmin();
      setRows(data || []);
    } catch (err) {
      setError(err.message || obsT('observations.sections.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadSections(); }, [loadSections]);

  const notifyChanged = useCallback(async () => {
    await loadSections();
    if (onChanged) await onChanged();
  }, [loadSections, onChanged]);

  const createSection = async () => {
    const title = String(newTitle || '').trim();
    if (!title) return;
    try {
      await ApiClient.createObservationSection(title);
      setNewTitle('');
      pushToast({ kind: 'success', title: obsT('observations.sections.created') });
      await notifyChanged();
    } catch (err) {
      pushToast({ kind: 'error', title: err.message });
    }
  };

  const deleteSection = async (section) => {
    const ok = window.confirm(obsT('observations.sections.deleteConfirm', {
      title: section.title,
      count: section.count ?? 0,
    }));
    if (!ok) return;
    try {
      const res = await ApiClient.deleteObservationSection(section.id);
      pushToast({
        kind: 'success',
        title: obsT('observations.sections.deleted'),
        desc: obsT('observations.sections.moved', { n: res.moved ?? 0 }),
      });
      await notifyChanged();
    } catch (err) {
      pushToast({ kind: 'error', title: err.message });
    }
  };

  const persistOrder = async (ordered) => {
    try {
      await ApiClient.reorderObservationSections(ordered.map((s) => s.id));
      setRows(ordered);
      if (onChanged) await onChanged();
    } catch (err) {
      pushToast({ kind: 'error', title: err.message });
      await loadSections();
    }
  };

  const onDropRow = (targetId) => {
    if (!dragId || dragId === targetId) return;
    const ids = rows.map((r) => r.id);
    const from = ids.indexOf(dragId);
    const to = ids.indexOf(targetId);
    if (from < 0 || to < 0) return;
    const next = [...rows];
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    setDragId(null);
    persistOrder(next);
  };

  const openEdit = (section) => {
    setEditSection({
      id: section.id,
      title: section.title,
      system: section.system,
    });
  };

  const saveEdit = async () => {
    if (!editSection) return;
    try {
      await ApiClient.updateObservationSection(editSection.id, {
        title: editSection.title,
      });
      pushToast({ kind: 'success', title: obsT('observations.sections.saved') });
      setEditSection(null);
      await notifyChanged();
    } catch (err) {
      pushToast({ kind: 'error', title: err.message });
    }
  };

  return (
    <div className="col" style={{ gap: 16 }}>
      {error && <div className="form-error">{error}</div>}
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <input
          className="input"
          style={{ maxWidth: 320 }}
          placeholder={obsT('observations.sections.newTitle')}
          value={newTitle}
          onChange={(e) => setNewTitle(e.target.value)}
        />
        <Button kind="primary" onClick={createSection} disabled={!newTitle.trim()}>{obsT('observations.sections.create')}</Button>
      </div>
      <p style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', margin: 0 }}>
        {obsT('observations.sections.accessInRolesHint')}
      </p>
      {loading ? (
        <div style={{ color: 'var(--fg-secondary)' }}>{obsT('observations.sections.loading')}</div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <thead>
            <tr>
              <th style={{ width: 36 }} />
              <th>{obsT('observations.sections.col.title')}</th>
              <th style={{ width: 100 }}>{obsT('observations.sections.col.count')}</th>
              <th style={{ width: 120 }} />
            </tr>
          </thead>
          <tbody>
            {rows.map((section) => {
              const canEditSection = section.level === 'edit';
              return (
              <tr
                key={section.id}
                draggable={canEditSection}
                onDragStart={() => { if (canEditSection) setDragId(section.id); }}
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => onDropRow(section.id)}
              >
                <td style={{ cursor: canEditSection ? 'grab' : 'default', opacity: canEditSection ? 1 : 0.35 }}>
                  {canEditSection ? <Icon name="drag" size={14} /> : null}
                </td>
                <td>
                  {section.title}
                  {section.system ? (
                    <span style={{ marginLeft: 8, color: 'var(--fg-muted)' }}>({obsT('observations.sections.system')})</span>
                  ) : null}
                </td>
                <td>{section.count ?? 0}</td>
                <td>
                  {canEditSection ? (
                    <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
                      <button type="button" className="icon-btn" onClick={() => openEdit(section)}><Icon name="edit" size={15} /></button>
                      {!section.system && (
                        <button type="button" className="icon-btn" onClick={() => deleteSection(section)}><Icon name="trash" size={15} /></button>
                      )}
                    </div>
                  ) : null}
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <Modal
        open={!!editSection}
        onClose={() => setEditSection(null)}
        title={obsT('observations.sections.modalTitle')}
        footer={(
          <>
            <Button kind="ghost" onClick={() => setEditSection(null)}>{obsT('observations.board.cancel')}</Button>
            <Button kind="primary" onClick={saveEdit}>{obsT('observations.settings.save')}</Button>
          </>
        )}
      >
        <div className="field">
          <label htmlFor="obs-section-rename-title">{obsT('observations.sections.col.title')}</label>
          <input
            id="obs-section-rename-title"
            className="input"
            value={editSection?.title ?? ''}
            onChange={(e) => setEditSection((cur) => (cur ? { ...cur, title: e.target.value } : cur))}
            autoFocus
          />
        </div>
      </Modal>
    </div>
  );
}

function PageObservations({ onNavigate }) {
  const canWriteObservations = AuthAccess.canWritePage('observations');
  const canWrite = canWriteObservations || AuthAccess.canWritePage('explorer');
  const canManageSections = AuthAccess.can('observations.manage_sections');
  const [config, setConfig] = useState(null);
  const [sections, setSections] = useState([]);
  const [activeSectionId, setActiveSectionId] = useState(null);
  const [copyDialog, setCopyDialog] = useState(null);
  const [items, setItems] = useState([]);
  const [expandedId, setExpandedId] = useState(null);
  const [settingsItemId, setSettingsItemId] = useState(null);
  const [settings, setSettings] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [collectors, setCollectors] = useState([]);
  const [locations, setLocations] = useState([]);
  const [boardOrderIds, setBoardOrderIds] = useState([]);
  const [boardHiddenIds, setBoardHiddenIds] = useState([]);
  const [editMode, setEditMode] = useState(false);
  const [manageSections, setManageSections] = useState(false);
  const [editDraftOrderIds, setEditDraftOrderIds] = useState([]);
  const [editBaselineOrderIds, setEditBaselineOrderIds] = useState([]);
  const [editDraftHiddenIds, setEditDraftHiddenIds] = useState([]);
  const [editBaselineHiddenIds, setEditBaselineHiddenIds] = useState([]);
  const [boardSaveStatus, setBoardSaveStatus] = useState('idle');
  const [draggingTileId, setDraggingTileId] = useState(null);
  const [draggingTileHeight, setDraggingTileHeight] = useState(null);
  const [dragPreviewOrderIds, setDragPreviewOrderIds] = useState(null);
  const boardRef = useRef(null);
  const boardOrderIdsRef = useRef([]);
  const confirmedBoardOrderRef = useRef([]);
  const confirmedBoardHiddenIdsRef = useRef([]);
  const editDraftOrderIdsRef = useRef([]);
  const editBaselineOrderIdsRef = useRef([]);
  const editDraftHiddenIdsRef = useRef([]);
  const editBaselineHiddenIdsRef = useRef([]);
  const editModeRef = useRef(false);
  const dragPreviewOrderIdsRef = useRef(null);
  const dragMoveRafRef = useRef(null);
  const flipFirstRectsRef = useRef(null);

  const settingsItem = useMemo(
    () => items.find((x) => x.id === settingsItemId) || null,
    [items, settingsItemId],
  );

  const filterFields = config?.schema?.filterFields || [];
  // Все измерения схемы, а не только «топовые»: разрез приходит из разбора
  // трафика и может содержать любое поле, иначе подпись падает до сырого id.
  const groupOptions = useMemo(() => {
    const dims = config?.schema?.dimensions || [];
    return dims.map((d) => ({ id: d.id, label: d.label }));
  }, [config]);

  const reload = useCallback(async () => {
    const [cfg, list, layoutResp, sectionList] = await Promise.all([
      ApiClient.loadObservationsConfig(),
      ApiClient.loadObservations(),
      ApiClient.loadObservationsBoardLayout(),
      ApiClient.loadObservationSections(),
    ]);
    setConfig(cfg);
    setItems(list);
    setSections(sectionList || []);
    const savedIds = layoutResp?.data?.observationIds;
    const savedHiddenIds = layoutResp?.data?.hiddenObservationIds;
    const availableIds = new Set(list.map((item) => item.id));
    if (!editModeRef.current) {
      setBoardOrderIds((prev) => {
        const baseIds = Array.isArray(savedIds) ? savedIds : prev;
        const merged = mergeObservationBoardOrder(list, baseIds.length ? baseIds : prev);
        const ids = merged.map((item) => item.id);
        boardOrderIdsRef.current = ids;
        if (Array.isArray(savedIds)) confirmedBoardOrderRef.current = ids;
        else if (!prev.length) confirmedBoardOrderRef.current = ids;
        return ids;
      });
      setBoardHiddenIds((prev) => {
        const source = Array.isArray(savedHiddenIds) ? savedHiddenIds : prev;
        const ids = source.filter((id) => availableIds.has(id));
        if (Array.isArray(savedHiddenIds)) confirmedBoardHiddenIdsRef.current = ids;
        else if (!prev.length) confirmedBoardHiddenIdsRef.current = ids;
        return ids;
      });
    } else {
      setEditDraftOrderIds((prev) => {
        const merged = mergeObservationBoardOrder(list, prev);
        const ids = merged.map((item) => item.id);
        editDraftOrderIdsRef.current = ids;
        return ids;
      });
      setEditDraftHiddenIds((prev) => {
        const ids = prev.filter((id) => availableIds.has(id));
        editDraftHiddenIdsRef.current = ids;
        return ids;
      });
    }
    return list;
  }, []);

  const toggleManageSections = useCallback(() => {
    setManageSections((open) => {
      const next = !open;
      if (next) setEditMode(false);
      return next;
    });
  }, []);

  useEffect(() => {
    editModeRef.current = editMode;
  }, [editMode]);

  useEffect(() => {
    editDraftOrderIdsRef.current = editDraftOrderIds;
  }, [editDraftOrderIds]);

  useEffect(() => {
    editBaselineOrderIdsRef.current = editBaselineOrderIds;
  }, [editBaselineOrderIds]);

  useEffect(() => {
    editDraftHiddenIdsRef.current = editDraftHiddenIds;
  }, [editDraftHiddenIds]);

  useEffect(() => {
    editBaselineHiddenIdsRef.current = editBaselineHiddenIds;
  }, [editBaselineHiddenIds]);

  useLayoutEffect(() => {
    if (!flipFirstRectsRef.current || !boardRef.current) return;
    runObservationBoardFlipAnimation(boardRef.current, flipFirstRectsRef.current);
    flipFirstRectsRef.current = null;
  }, [dragPreviewOrderIds, editDraftHiddenIds]);

  const enterBoardEditMode = useCallback(() => {
    const ids = [...boardOrderIdsRef.current];
    const hiddenIds = [...confirmedBoardHiddenIdsRef.current];
    editBaselineOrderIdsRef.current = ids;
    editDraftOrderIdsRef.current = ids;
    editBaselineHiddenIdsRef.current = hiddenIds;
    editDraftHiddenIdsRef.current = hiddenIds;
    setEditBaselineOrderIds(ids);
    setEditDraftOrderIds(ids);
    setEditBaselineHiddenIds(hiddenIds);
    setEditDraftHiddenIds(hiddenIds);
    setBoardSaveStatus('idle');
    setEditMode(true);
    setExpandedId(null);
    setDragPreviewOrderIds(null);
    dragPreviewOrderIdsRef.current = null;
    setDraggingTileId(null);
    setDraggingTileHeight(null);
  }, []);

  const revertBoardEditDraft = useCallback(() => {
    const baseline = [...editBaselineOrderIdsRef.current];
    const hiddenBaseline = [...editBaselineHiddenIdsRef.current];
    editDraftOrderIdsRef.current = baseline;
    editDraftHiddenIdsRef.current = hiddenBaseline;
    setEditDraftOrderIds(baseline);
    setEditDraftHiddenIds(hiddenBaseline);
    setDragPreviewOrderIds(null);
    dragPreviewOrderIdsRef.current = null;
    setDraggingTileId(null);
    setDraggingTileHeight(null);
    setBoardSaveStatus('idle');
  }, []);

  const cancelBoardEditMode = useCallback(() => {
    const confirmed = [...confirmedBoardOrderRef.current];
    const confirmedHidden = [...confirmedBoardHiddenIdsRef.current];
    editDraftOrderIdsRef.current = confirmed;
    editDraftHiddenIdsRef.current = confirmedHidden;
    setEditDraftOrderIds(confirmed);
    setEditDraftHiddenIds(confirmedHidden);
    setEditMode(false);
    setDragPreviewOrderIds(null);
    dragPreviewOrderIdsRef.current = null;
    setDraggingTileId(null);
    setDraggingTileHeight(null);
    setBoardSaveStatus('idle');
  }, []);

  const confirmBoardEditMode = useCallback(async () => {
    const nextIds = [...editDraftOrderIdsRef.current];
    const nextHiddenIds = [...editDraftHiddenIdsRef.current];
    const confirmed = confirmedBoardOrderRef.current;
    const confirmedHidden = confirmedBoardHiddenIdsRef.current;
    if (sameObservationIds(nextIds, confirmed) && sameObservationIds(nextHiddenIds, confirmedHidden)) {
      setEditMode(false);
      setBoardSaveStatus('idle');
      return;
    }
    setBoardSaveStatus('saving');
    try {
      await ApiClient.saveObservationsBoardLayout({
        version: 1,
        observationIds: nextIds,
        hiddenObservationIds: nextHiddenIds,
      });
      confirmedBoardOrderRef.current = nextIds;
      confirmedBoardHiddenIdsRef.current = nextHiddenIds;
      boardOrderIdsRef.current = nextIds;
      setBoardOrderIds(nextIds);
      setBoardHiddenIds(nextHiddenIds);
      editBaselineOrderIdsRef.current = nextIds;
      editBaselineHiddenIdsRef.current = nextHiddenIds;
      setEditBaselineOrderIds(nextIds);
      setEditBaselineHiddenIds(nextHiddenIds);
      setBoardSaveStatus('saved');
      setEditMode(false);
      setDragPreviewOrderIds(null);
      dragPreviewOrderIdsRef.current = null;
      setDraggingTileId(null);
      setDraggingTileHeight(null);
    } catch (e) {
      setBoardSaveStatus('error');
      setError(e.message || obsT('observations.board.saveError'));
    }
  }, []);

  const commitBoardReorder = useCallback((nextIds) => {
    if (!nextIds?.length) return;
    const current = editDraftOrderIdsRef.current;
    if (sameObservationIds(nextIds, current)) return;
    editDraftOrderIdsRef.current = nextIds;
    setEditDraftOrderIds(nextIds);
    setBoardSaveStatus('idle');
  }, []);

  const hideObservationTile = useCallback((observationId) => {
    if (!observationId || editDraftHiddenIdsRef.current.includes(observationId)) return;
    flipFirstRectsRef.current = captureObservationBoardFlipRects(boardRef.current);
    const next = [...editDraftHiddenIdsRef.current, observationId];
    editDraftHiddenIdsRef.current = next;
    setEditDraftHiddenIds(next);
    setBoardSaveStatus('idle');
  }, []);

  const restoreObservationTile = useCallback((observationId) => {
    if (!observationId || !editDraftHiddenIdsRef.current.includes(observationId)) return;
    flipFirstRectsRef.current = captureObservationBoardFlipRects(boardRef.current);
    const next = editDraftHiddenIdsRef.current.filter((id) => id !== observationId);
    editDraftHiddenIdsRef.current = next;
    setEditDraftHiddenIds(next);
    setBoardSaveStatus('idle');
  }, []);

  const onBoardDragHandleMouseDown = useCallback((sourceId) => (event) => {
    if (!editModeRef.current || event.button !== 0) return;
    event.preventDefault();
    const originX = event.clientX;
    const originY = event.clientY;
    let dragStarted = false;
    const baseOrder = [...editDraftOrderIdsRef.current];
    let lastDropIndex = baseOrder.indexOf(sourceId);
    dragPreviewOrderIdsRef.current = baseOrder;
    const sourceEl = boardRef.current?.querySelector(`[data-obs-tile-id="${sourceId}"]`);
    const sourceRect = sourceEl?.getBoundingClientRect();

    const applyPreview = (ev) => {
      if (!dragStarted) {
        if (Math.hypot(ev.clientX - originX, ev.clientY - originY) < OBS_BOARD_DRAG_THRESHOLD_PX) return;
        dragStarted = true;
        setDraggingTileId(sourceId);
        setDraggingTileHeight(sourceRect?.height || null);
      }
      const dropIndex = findObservationBoardDropIndex(
        ev.clientX,
        ev.clientY,
        boardRef.current,
        lastDropIndex,
      );
      if (!Number.isInteger(dropIndex)) return;
      lastDropIndex = dropIndex;
      const preview = moveObservationIdToIndex(baseOrder, sourceId, dropIndex);
      if (preview.every((id, i) => id === baseOrder[i])) {
        if (dragPreviewOrderIdsRef.current !== baseOrder) {
          flipFirstRectsRef.current = captureObservationBoardFlipRects(boardRef.current);
        }
        setDragPreviewOrderIds(null);
        dragPreviewOrderIdsRef.current = baseOrder;
        return;
      }
      const current = dragPreviewOrderIdsRef.current;
      if (current?.length === preview.length && preview.every((id, i) => id === current[i])) return;
      flipFirstRectsRef.current = captureObservationBoardFlipRects(boardRef.current);
      dragPreviewOrderIdsRef.current = preview;
      setDragPreviewOrderIds(preview);
    };

    const onMove = (ev) => {
      if (dragMoveRafRef.current) return;
      dragMoveRafRef.current = requestAnimationFrame(() => {
        dragMoveRafRef.current = null;
        applyPreview(ev);
      });
    };

    const onUp = (ev) => {
      if (dragMoveRafRef.current) {
        cancelAnimationFrame(dragMoveRafRef.current);
        dragMoveRafRef.current = null;
        applyPreview(ev);
      }
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      setDraggingTileId(null);
      setDraggingTileHeight(null);
      setDragPreviewOrderIds(null);
      const preview = dragPreviewOrderIdsRef.current;
      dragPreviewOrderIdsRef.current = null;
      if (!dragStarted) return;
      // Фиксируем ровно тот порядок, который пользователь видел перед drop,
      // не пересчитывая цель по уже перестроенному DOM.
      commitBoardReorder(preview || baseOrder);
    };

    document.body.style.cursor = 'grabbing';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }, [commitBoardReorder]);

  const activeSection = useMemo(
    () => sections.find((s) => s.id === activeSectionId) || null,
    [sections, activeSectionId],
  );
  const sectionCanEdit = activeSection?.level === 'edit';
  const editableSections = useMemo(
    () => sections.filter((s) => s.level === 'edit'),
    [sections],
  );

  const sectionItems = useMemo(() => {
    if (!activeSectionId) return items;
    return items.filter((item) => (item.sectionId || 'general') === activeSectionId);
  }, [items, activeSectionId]);

  const displayItems = useMemo(() => {
    const orderIds = editMode
      ? (dragPreviewOrderIds || editDraftOrderIds)
      : boardOrderIds;
    const hiddenIds = new Set(editMode ? editDraftHiddenIds : boardHiddenIds);
    if (!orderIds?.length) {
      return sortObservationsDefaultOrder(sectionItems).filter((item) => !hiddenIds.has(item.id));
    }
    const byId = new Map(sectionItems.map((item) => [item.id, item]));
    return orderIds.map((id) => byId.get(id)).filter((item) => item && !hiddenIds.has(item.id));
  }, [
    sectionItems,
    boardOrderIds,
    boardHiddenIds,
    editDraftOrderIds,
    editDraftHiddenIds,
    dragPreviewOrderIds,
    editMode,
  ]);

  const hiddenItems = useMemo(() => {
    if (!editMode || !editDraftHiddenIds.length) return [];
    const hidden = new Set(editDraftHiddenIds);
    return mergeObservationBoardOrder(sectionItems, editDraftOrderIds)
      .filter((item) => hidden.has(item.id));
  }, [sectionItems, editDraftOrderIds, editDraftHiddenIds, editMode]);

  useEffect(() => {
    let cancelled = false;
    ApiClient.loadDashboardCollectors()
      .then(({ collectors: collectorRows, locations: locationRows }) => {
        if (cancelled) return;
        setCollectors(collectorRows || []);
        setLocations(locationRows || []);
      })
      .catch(() => {
        if (!cancelled) {
          setCollectors([]);
          setLocations([]);
        }
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    reload()
      .then((list) => {
        try {
          const openId = sessionStorage.getItem(OPEN_KEY);
          if (!openId) return;
          sessionStorage.removeItem(OPEN_KEY);
          if ((list || []).some((x) => x.id === openId)) setExpandedId(openId);
        } catch {
          // ignore
        }
      })
      .catch((e) => setError(e.message));
  }, [reload]);

  useEffect(() => {
    if (!sections.length) return;
    if (activeSectionId && sections.some((s) => s.id === activeSectionId)) return;
    const fromUrl = (typeof parseAppHash === 'function' ? parseAppHash() : { params: new URLSearchParams() })
      .params?.get('section');
    let stored = null;
    try {
      stored = localStorage.getItem(SECTION_STORAGE_KEY);
    } catch {
      stored = null;
    }
    let pick = fromUrl || stored || sections[0].id;
    if (!sections.some((s) => s.id === pick)) pick = sections[0].id;
    if (fromUrl && fromUrl !== pick) {
      pushToast?.({
        kind: 'info',
        title: obsT('observations.section.unavailable', { title: sections.find((s) => s.id === pick)?.title || pick }),
      });
    }
    setActiveSectionId(pick);
    try {
      localStorage.setItem(SECTION_STORAGE_KEY, pick);
    } catch {
      // ignore
    }
  }, [sections, activeSectionId]);

  const selectSection = useCallback((sectionId) => {
    setActiveSectionId(sectionId);
    try {
      localStorage.setItem(SECTION_STORAGE_KEY, sectionId);
    } catch {
      // ignore
    }
    const qs = sectionId ? `?section=${encodeURIComponent(sectionId)}` : '';
    if (typeof onNavigate === 'function') {
      location.hash = `observations${qs}`;
    } else {
      location.hash = `observations${qs}`;
    }
  }, [onNavigate]);

  const runDuplicate = useCallback(async (observationId, targetSectionId) => {
    setError('');
    try {
      await ApiClient.duplicateObservation(observationId, targetSectionId ? { sectionId: targetSectionId } : {});
      setCopyDialog(null);
      await reload();
      pushToast?.({ kind: 'success', title: obsT('observations.section.copy') });
    } catch (e) {
      setError(e.message);
    }
  }, [reload]);

  const requestDuplicate = useCallback((item) => {
    if (!item?.canEdit && !sectionCanEdit) {
      const editable = editableSections;
      if (!editable.length) return;
      setCopyDialog({ observationId: item.id, sectionId: editable[0]?.id || 'general' });
      return;
    }
    runDuplicate(item.id, null);
  }, [sectionCanEdit, editableSections, runDuplicate]);

  useEffect(() => {
    const t = setInterval(() => {
      reload().catch((e) => setError(e.message));
    }, MIN_REFRESH_SEC * 1000);
    return () => clearInterval(t);
  }, [reload]);

  const openSettings = (item) => {
    setSettingsItemId(item.id);
    setSettings({
      name: item.name,
      description: item.description || '',
      folder: item.folder || 'Мои наблюдения',
      lookback: item.lookback,
      widgets: item.widgets,
      layout: { ...(item.layout || { order: 0 }), width: 1 },
      materialize: { enabled: Boolean(item.materialize?.enabled) },
      report: {
        enabled: Boolean(item.report?.enabled),
        period: item.report?.period || 'yesterday',
        emailTo: Array.isArray(item.report?.emailTo) ? item.report.emailTo : [],
        schedule: {
          kind: 'daily',
          time: '08:00',
          timezone: 'Europe/Moscow',
          weekday: 1,
          day: 1,
          ...(item.report?.schedule || {}),
        },
      },
      filters: item.filters,
      thresholds: item.thresholds || [],
      explorerQuery: item.explorerQuery || null,
      sectionId: item.sectionId || 'general',
    });
    setError('');
  };

  const saveSettings = async () => {
    if (!settingsCanEdit || !settingsItemId || !settings) return;
    if (settingsItem?.canEdit === false) {
      setError('Нет прав на изменение этого наблюдения');
      return;
    }
    if (settingsIsNative && chartWidgetDataSource(settings.widgets) === 'vlan_trend') {
      const scope = chartWidgetNativeScope(settings.widgets);
      if (!scope.vlanIds?.length) {
        setError('Выберите хотя бы один VLAN');
        return;
      }
    }
    setBusy(true);
    setError('');
    try {
      await ApiClient.updateObservation(settingsItemId, {
        name: settings.name,
        description: settings.description,
        folder: settings.folder,
        lookback: settings.lookback,
        widgets: settings.widgets,
        layout: settings.layout,
        materialize: settings.materialize,
        report: settings.report,
        filters: settings.filters,
        thresholds: settings.thresholds || [],
        explorerQuery: settings.explorerQuery ?? settingsItem.explorerQuery ?? null,
        sectionId: settings.sectionId,
      });
      await reload();
      setSettingsItemId(null);
      setSettings(null);
    } catch (e) {
      const occupants = e.occupants || e.body?.occupants;
      if (occupants?.length) {
        setError(`${e.message} Занято: ${occupants.map((o) => o.name).join(', ')}`);
      } else {
        setError(e.message);
      }
    } finally {
      setBusy(false);
    }
  };

  const removeItem = async (id) => {
    if (!sectionCanEdit || !window.confirm(obsT('observations.deleteConfirm'))) return;
    setError('');
    try {
      await ApiClient.deleteObservation(id);
      setItems((prev) => prev.filter((row) => row.id !== id));
      if (expandedId === id) setExpandedId(null);
      if (settingsItemId === id) {
        setSettingsItemId(null);
        setSettings(null);
      }
      await reload();
    } catch (e) {
      setError(e.message || 'Не удалось удалить наблюдение');
    }
  };

  const changeTileLookback = async (id, lookback) => {
    let current = null;
    let nextExplorerQuery = observationExplorerQueryWithLookback(null, lookback);
    setItems((prev) => {
      current = prev.find((row) => row.id === id) || null;
      if (current) {
        nextExplorerQuery = observationExplorerQueryWithLookback(
          current.explorerQuery,
          lookback,
          current,
        );
      }
      return prev.map((row) => (
        row.id === id
          ? { ...row, lookback, explorerQuery: nextExplorerQuery }
          : row
      ));
    });
    if (!current?.canEdit) return;
    try {
      // Смена периода не должна выключать подготовку данных.
      await ApiClient.updateObservation(id, {
        ...current,
        lookback,
        explorerQuery: nextExplorerQuery,
        materialize: { ...(current.materialize || {}), enabled: Boolean(current.materialize?.enabled) },
      });
    } catch (e) {
      setError(e.message);
      await reload();
    }
  };

  const changeTileChartStyle = async (id, chartStyle) => {
    let current = null;
    setItems((prev) => {
      current = prev.find((row) => row.id === id) || null;
      return prev.map((row) => (
        row.id === id
          ? { ...row, widgets: observationWidgetsWithChartStyle(row.widgets, chartStyle) }
          : row
      ));
    });
    if (!current?.canEdit) return;
    try {
      await ApiClient.updateObservation(id, {
        ...current,
        widgets: observationWidgetsWithChartStyle(current.widgets, chartStyle),
        materialize: { ...(current.materialize || {}), enabled: Boolean(current.materialize?.enabled) },
      });
    } catch (e) {
      setError(e.message);
      await reload();
    }
  };

  const settingsGroupBy = groupByFromWidgets(settings?.widgets);
  const settingsChartStyle = observationChartStyleFromWidgets(settings?.widgets);
  const settingsGroupSummary = formatGroupSummary(settingsGroupBy, groupOptions);
  const settingsIsNative = settingsItem ? isNativeAggregateObservation(settingsItem) : false;
  const settingsNativeDataSource = chartWidgetDataSource(settings?.widgets || settingsItem?.widgets);
  const settingsNativeScope = chartWidgetNativeScope(settings?.widgets);
  const settingsCanEdit = Boolean(settingsItem?.canEdit);

  if (settings && settingsItem) {
    return (
      <div className="main__container">
        <div className="page-head">
          <h1>{obsT('observations.settings')}</h1>
          <button type="button" className="btn" onClick={() => { setSettings(null); setSettingsItemId(null); }}>
            {obsT('observations.settings.back')}
          </button>
        </div>
        <div className="col" style={{ gap: 16, padding: '0 0 24px' }}>
        {error && (
          <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)' }}>{error}</div>
        )}
        <Card title={settingsItem.name}>
          <div className="col" style={{ gap: 12 }}>
            <div className="col" style={{ gap: 4, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              <div>
                {obsT('observations.filters')}:{' '}
                {renderFilterSummary(settings.filters, filterFields)}
              </div>
              {settingsGroupSummary ? (
                <div>{obsT('observations.group')}: {settingsGroupSummary}</div>
              ) : null}
              {settings.thresholds?.length && window.ExplorerThresholds?.formatThresholdChipLabel ? (
                <div>
                  Пороги:{' '}
                  {settings.thresholds.slice(0, 2).map((t) => window.ExplorerThresholds.formatThresholdChipLabel(t)).join(' · ')}
                  {settings.thresholds.length > 2 ? ' …' : ''}
                </div>
              ) : null}
            </div>
            {canWrite && !settingsIsNative && (
              <button
                type="button"
                className="btn"
                style={{ alignSelf: 'flex-start' }}
                onClick={() => startComposeInExplorer(onNavigate, {
                  mode: settingsItem.canEdit ? 'edit' : 'new',
                  editId: settingsItem.canEdit ? settingsItem.id : null,
                  name: settingsItem.name || settings.name,
                  explorerQuery: observationExplorerQueryForCompose({
                    ...settingsItem,
                    filters: settings.filters || settingsItem.filters || [],
                    thresholds: settings.thresholds || settingsItem.thresholds || [],
                    lookback: settings.lookback || settingsItem.lookback || null,
                    widgets: settings.widgets || settingsItem.widgets,
                    explorerQuery: settings.explorerQuery ?? settingsItem.explorerQuery,
                  }),
                })}
              >
                {settingsItem.canEdit
                  ? obsT('observations.settings.changeFilters')
                  : 'Скопировать фильтры в разбор трафика'}
              </button>
            )}
            {settingsIsNative && (
              <NativeScopeSettings
                dataSource={settingsNativeDataSource}
                nativeScope={settingsNativeScope}
                disabled={!settingsCanEdit}
                onChange={(nextScope) => setSettings({
                  ...settings,
                  widgets: widgetsWithNativeScope(settings.widgets, nextScope),
                })}
              />
            )}
            <label className="col" style={{ gap: 4 }}>
              <span>{obsT('observations.settings.name')}</span>
              <input className="input" value={settings.name} onChange={(e) => setSettings({ ...settings, name: e.target.value })} />
            </label>
            <label className="col" style={{ gap: 4 }}>
              <span>{obsT('observations.settings.description')}</span>
              <input
                className="input"
                value={settings.description || ''}
                onChange={(e) => setSettings({ ...settings, description: e.target.value })}
              />
            </label>
            {!settingsIsNative && (
              <>
                <label className="row" style={{ gap: 8, alignItems: 'center' }}>
                  <input
                    type="checkbox"
                    checked={!!settings.materialize?.enabled}
                    onChange={(e) => setSettings({
                      ...settings,
                      materialize: { ...(settings.materialize || {}), enabled: e.target.checked },
                    })}
                  />
                  {obsT('observations.materialize.label')}
                </label>
                <div style={{ marginLeft: 24, color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
                  {obsT('observations.materialize.hint')}
                </div>
              </>
            )}
            {settingsGroupBy.length > 0 && (
              <div className="col" style={{ gap: 6 }}>
                <span>{obsT('observations.settings.chartType')}</span>
                <ObservationChartStylePicker
                  value={settingsChartStyle}
                  onChange={(next) => setSettings({
                    ...settings,
                    widgets: observationWidgetsWithChartStyle(settings.widgets, next),
                  })}
                />
              </div>
            )}
            <label className="row" style={{ gap: 8, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={!!settings.report.enabled}
                onChange={(e) => setSettings({
                  ...settings,
                  report: { ...settings.report, enabled: e.target.checked },
                })}
              />
              {obsT('observations.settings.report')}
            </label>
            {settings.report.enabled && (
              <div className="col" style={{ gap: 8, marginLeft: 24 }}>
                <label className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  за период
                  <select
                    className="input"
                    style={{ width: 160 }}
                    value={settings.report.period || 'yesterday'}
                    onChange={(e) => setSettings({
                      ...settings,
                      report: { ...settings.report, period: e.target.value },
                    })}
                  >
                    <option value="yesterday">вчера</option>
                    <option value="last_24h">последние 24 часа</option>
                  </select>
                </label>
                <label className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  расписание
                  <select
                    className="input"
                    style={{ width: 140 }}
                    value={settings.report.schedule?.kind || 'daily'}
                    onChange={(e) => setSettings({
                      ...settings,
                      report: {
                        ...settings.report,
                        schedule: { ...(settings.report.schedule || {}), kind: e.target.value },
                      },
                    })}
                  >
                    <option value="daily">ежедневно</option>
                    <option value="weekly">еженедельно</option>
                    <option value="monthly">ежемесячно</option>
                  </select>
                  в
                  <input
                    className="input"
                    style={{ width: 90 }}
                    value={settings.report.schedule?.time || '08:00'}
                    onChange={(e) => setSettings({
                      ...settings,
                      report: {
                        ...settings.report,
                        schedule: { ...(settings.report.schedule || {}), time: e.target.value },
                      },
                    })}
                  />
                  <TimezonePicker
                    value={settings.report.schedule?.timezone || 'Europe/Moscow'}
                    onChange={(tz) => setSettings({
                      ...settings,
                      report: {
                        ...settings.report,
                        schedule: { ...(settings.report.schedule || {}), timezone: tz },
                      },
                    })}
                  />
                </label>
                {(settings.report.schedule?.kind || 'daily') === 'weekly' && (
                  <label className="row" style={{ gap: 8, alignItems: 'center' }}>
                    день недели (1=пн)
                    <input
                      className="input"
                      style={{ width: 70 }}
                      type="number"
                      min={1}
                      max={7}
                      value={settings.report.schedule?.weekday || 1}
                      onChange={(e) => setSettings({
                        ...settings,
                        report: {
                          ...settings.report,
                          schedule: { ...(settings.report.schedule || {}), weekday: Number(e.target.value) },
                        },
                      })}
                    />
                  </label>
                )}
                {(settings.report.schedule?.kind || 'daily') === 'monthly' && (
                  <label className="row" style={{ gap: 8, alignItems: 'center' }}>
                    число месяца
                    <input
                      className="input"
                      style={{ width: 70 }}
                      type="number"
                      min={1}
                      max={28}
                      value={settings.report.schedule?.day || 1}
                      onChange={(e) => setSettings({
                        ...settings,
                        report: {
                          ...settings.report,
                          schedule: { ...(settings.report.schedule || {}), day: Number(e.target.value) },
                        },
                      })}
                    />
                  </label>
                )}
                <label className="col" style={{ gap: 4 }}>
                  <span>Email (через запятую, до 10)</span>
                  <input
                    className="input"
                    value={(settings.report.emailTo || []).join(', ')}
                    onChange={(e) => setSettings({
                      ...settings,
                      report: {
                        ...settings.report,
                        emailTo: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                      },
                    })}
                    placeholder="ops@example.com"
                  />
                </label>
              </div>
            )}
            <label className="col" style={{ gap: 4 }}>
              <span>{obsT('observations.section.field')}</span>
              <select
                className="input"
                value={settings.sectionId || 'general'}
                disabled={!settingsCanEdit}
                onChange={(e) => setSettings({ ...settings, sectionId: e.target.value })}
              >
                {editableSections.map((s) => (
                  <option key={s.id} value={s.id}>{s.title}</option>
                ))}
              </select>
            </label>
            <button type="button" className="btn btn--primary" disabled={busy || !settingsCanEdit} onClick={saveSettings}>
              {obsT('observations.settings.save')}
            </button>
          </div>
        </Card>
        </div>
      </div>
    );
  }

  const boardToolbar = (sticky = false) => (
    !manageSections && sectionItems.length > 0 && sectionCanEdit ? (
      <ObservationsBoardToolbar
        editMode={editMode}
        saveState={boardSaveStatus}
        hiddenItems={hiddenItems}
        onCustomize={enterBoardEditMode}
        onRestore={restoreObservationTile}
        onRevert={revertBoardEditDraft}
        onCancel={cancelBoardEditMode}
        onDone={confirmBoardEditMode}
        className={sticky ? 'observations-board-toolbar--sticky' : ''}
      />
    ) : null
  );

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{obsT('observations.title')}</h1>
          {sections.length > 1 ? (
            <div className="row observations-section-tabs" style={{ gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
              {sections.map((sec) => (
                <Button
                  key={sec.id}
                  kind={sec.id === activeSectionId ? 'primary' : 'default'}
                  size="sm"
                  onClick={() => selectSection(sec.id)}
                  title={sec.level === 'view' ? obsT('observations.section.viewOnly') : undefined}
                >
                  <span>{sec.title}</span>
                  <span className="observations-section-tab__count">{sec.count}</span>
                  {sec.level === 'view' ? (
                    <Icon name="eye" size={13} style={{ opacity: 0.55 }} />
                  ) : null}
                </Button>
              ))}
            </div>
          ) : null}
        </div>
        <div className="page-head__tools" style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {!editMode ? boardToolbar() : null}
          {canManageSections && !editMode ? (
            <Button
              kind={manageSections ? 'primary' : 'ghost'}
              icon="settings"
              onClick={toggleManageSections}
            >
              {manageSections
                ? obsT('observations.sections.backToBoard')
                : obsT('observations.sections.manage')}
            </Button>
          ) : null}
          {sectionCanEdit && !editMode && !manageSections && (
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => startComposeInExplorer(onNavigate, { mode: 'new' })}
            >
              + {obsT('observations.new')}
            </button>
          )}
        </div>
      </div>
      {editMode && !manageSections ? boardToolbar(true) : null}
      <div className="col" style={{ gap: 16, padding: '0 0 24px' }}>

      {error && (
        <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--fg-primary)' }}>
          {error}
        </div>
      )}

      {manageSections ? (
        <ObservationSectionsPanel onChanged={reload} />
      ) : (
        <>
          {sectionItems.length > 0 && (
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              {sectionItems[0]?.quotas?.maxMaterialize
                ? obsT('observations.prep.quota', {
                  n: sectionItems[0]?.quotas?.activeMaterialize ?? 0,
                  max: sectionItems[0].quotas.maxMaterialize,
                })
                : obsT('observations.prep.active', { n: sectionItems[0]?.quotas?.activeMaterialize ?? 0 })}
            </div>
          )}

          {!sectionItems.length && (
            <Card>
              <div style={{ color: 'var(--fg-secondary)' }}>
                {sections.length
                  ? obsT('observations.section.empty')
                  : 'Пока пусто. Нажмите «+ Новое» — соберите фильтр в разборе трафика и «Добавить в наблюдения».'}
              </div>
            </Card>
          )}

          {sectionItems.length > 0 && (
            <div
              ref={boardRef}
              className={[
                'observations-board',
                editMode ? 'observations-board--edit' : '',
                draggingTileId ? 'observations-board--dragging' : '',
                dragPreviewOrderIds ? 'observations-board--drag-preview' : '',
              ].filter(Boolean).join(' ')}
            >
              {displayItems.map((item) => {
                if (draggingTileId === item.id) {
                  return (
                    <ObservationBoardTilePhantom
                      key={`phantom-${item.id}`}
                      id={item.id}
                      title={item.name}
                      expanded={expandedId === item.id}
                      height={draggingTileHeight}
                    />
                  );
                }
                return (
                  <ObservationLiveTile
                    key={item.id}
                    item={item}
                    groupOptions={groupOptions}
                    filterFields={filterFields}
                    onNavigate={onNavigate}
                    lookbackOptions={config?.lookbacks || LOOKBACK_OPTIONS}
                    expanded={expandedId === item.id}
                    onToggleExpand={() => setExpandedId((cur) => (cur === item.id ? null : item.id))}
                    canWrite={sectionCanEdit}
                    editMode={editMode && sectionCanEdit}
                    onDragHandleMouseDown={onBoardDragHandleMouseDown(item.id)}
                    onHide={() => hideObservationTile(item.id)}
                    onSettings={() => openSettings(item)}
                    onDuplicate={() => requestDuplicate(item)}
                    onDelete={() => removeItem(item.id)}
                    onCancel={() => ApiClient.cancelObservationMaterialize(item.id)
                      .then(() => reload())
                      .then(() => pushToast?.({ kind: 'success', title: 'Подготовка отменена' }))
                      .catch((e) => setError(e.message))}
                    onRetry={() => ApiClient.retryObservationMaterialize(item.id)
                      .then(() => reload())
                      .then(() => pushToast?.({ kind: 'success', title: 'Перезапущено', desc: 'Воркер возьмёт наблюдение в течение минуты' }))
                      .catch((e) => setError(e.message))}
                    onLookbackChange={changeTileLookback}
                    onChartStyleChange={changeTileChartStyle}
                    onRunReport={() => ApiClient.runObservationReport(item.id)
                      .then(() => pushToast?.({ kind: 'success', title: 'Отчёт сформирован' }))
                      .catch((e) => setError(e.message))}
                    isNativeAggregate={isNativeAggregateObservation(item)}
                    collectors={collectors}
                    locations={locations}
                  />
                );
              })}
            </div>
          )}
        </>
      )}
      {copyDialog ? (
        <div className="modal-backdrop" role="presentation" onClick={() => setCopyDialog(null)}>
          <div className="modal" role="dialog" onClick={(e) => e.stopPropagation()}>
            <h2 style={{ marginTop: 0 }}>{obsT('observations.section.copyTitle')}</h2>
            <label className="col" style={{ gap: 4, marginBottom: 16 }}>
              <span>{obsT('observations.section.copyTarget')}</span>
              <select
                className="input"
                value={copyDialog.sectionId}
                onChange={(e) => setCopyDialog({ ...copyDialog, sectionId: e.target.value })}
              >
                {editableSections.map((s) => (
                  <option key={s.id} value={s.id}>{s.title}</option>
                ))}
              </select>
            </label>
            <div className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
              <button type="button" className="btn" onClick={() => setCopyDialog(null)}>{obsT('observations.board.cancel')}</button>
              <button
                type="button"
                className="btn btn--primary"
                onClick={() => runDuplicate(copyDialog.observationId, copyDialog.sectionId)}
              >
                {obsT('observations.section.copyConfirm')}
              </button>
            </div>
          </div>
        </div>
      ) : null}
      </div>
    </div>
  );
}

window.PageObservations = PageObservations;
window.startObservationCompose = startComposeInExplorer;
window.readObservationComposeDraft = readObservationComposeDraft;
