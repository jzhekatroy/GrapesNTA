/* Observations: live tile board (2 columns). Filters collected in Explorer. */

const { useState, useEffect, useCallback, useMemo, useRef } = React;

const LOOKBACK_LABELS = {
  '15m': '15 минут',
  '30m': '30 минут',
  '1h': '1 час',
  '6h': '6 часов',
  '24h': '24 часа',
  '7d': '7 дней',
};

const LOOKBACK_SHORT = {
  '15m': '15м',
  '30m': '30м',
  '1h': '1ч',
  '6h': '6ч',
  '24h': '24ч',
  '7d': '7д',
};

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

const OBS_CHART_STYLES = [
  { id: 'lines', label: 'Линии', icon: 'lineChart', hint: 'Перекрывающиеся линии по сериям' },
  { id: 'stack', label: 'Стек', icon: 'layers', hint: 'Площади друг на друге, сумма выбранных серий' },
];

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

/** Aggregate series values for the observation chart stats strip. */
function chartSeriesStats(points, lines, mode = 'total') {
  if (!points?.length) return null;
  const values = points.map((p) => {
    if (mode === 'grouped' && lines?.length) {
      return lines.reduce((sum, ln) => sum + (Number(p[ln.key]) || 0), 0);
    }
    return Number(p.bps) || 0;
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

function groupByFromWidgets(widgets) {
  const list = Array.isArray(widgets) ? widgets : [];
  const chart = list.find((w) => w.type === 'timeseries_bps' && w.groupBy?.length);
  if (chart) return chart.groupBy.map(String);
  const top = list.find((w) => w.type === 'top_table' && w.groupBy?.length);
  return top ? top.groupBy.map(String) : ['src_asn'];
}

function formatFilterSummary(filters, filterFields) {
  if (!filters?.length) return 'без фильтров';
  return filters.slice(0, 3).map((f) => {
    const label = filterFields.find((ff) => ff.id === f.field)?.label || f.field;
    return `${label} ${f.op} ${f.value ?? ''}`;
  }).join(' · ') + (filters.length > 3 ? ' …' : '');
}

function formatObservationScopeSummary(item, filterFields) {
  const parts = [];
  parts.push(item.filters?.length ? formatFilterSummary(item.filters, filterFields) : 'без фильтров');
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

function startComposeInExplorer(onNavigate, {
  editId = null,
  name = '',
  filters = null,
  thresholds = null,
  groupBy = null,
  lookback = null,
} = {}) {
  try {
    sessionStorage.setItem(COMPOSE_KEY, JSON.stringify({
      active: true,
      editId: editId || null,
      name: name || '',
      filters: Array.isArray(filters) ? filters : null,
      thresholds: Array.isArray(thresholds) ? thresholds : null,
      groupBy: Array.isArray(groupBy) ? groupBy : null,
      lookback: lookback || null,
      startedAt: Date.now(),
    }));
  } catch {
    // ignore
  }
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
    return 'выбранный период';
  }
  return LOOKBACK_LABELS[lookback] || lookback;
}

function ObservationChart({
  points,
  lines,
  mode = 'total',
  stackMode,
  height = 160,
  onRangeSelect,
  displayTimezone,
  bucketSeconds = 300,
  periodStartMs,
  periodEndMs,
  skipLeadingGaps = false,
  skipTrailingGaps = false,
  tipTranslucent = true,
}) {
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
        valueFormatter={formatBps}
        axisFormatter={formatAxisBps}
        onRangeSelect={onRangeSelect}
        bucketSeconds={bucketSeconds}
        displayTimezone={displayTimezone}
        periodStartMs={periodStartMs}
        periodEndMs={periodEndMs}
        skipLeadingGaps={skipLeadingGaps}
        skipTrailingGaps={skipTrailingGaps}
        tipTranslucent={tipTranslucent}
        tipUnitLabel="бит/с"
        yAxisUnit="бит/с"
      />
    );
  }

  const chartPoints = points.map((p) => ({
    ...p,
    bps: Number(p.bps) || 0,
    bucket: p.bucket || p.t,
    t: p.t || p.bucket,
  }));
  if (typeof TimeSeriesSparkChart === 'function') {
    return (
      <TimeSeriesSparkChart
        points={chartPoints}
        height={height}
        valueKey="bps"
        formatValue={formatBps}
        axisFormatter={formatAxisBps}
        onRangeSelect={onRangeSelect}
        bucketSeconds={bucketSeconds}
        displayTimezone={displayTimezone}
        periodStartMs={periodStartMs}
        periodEndMs={periodEndMs}
        skipLeadingGaps={skipLeadingGaps}
        skipTrailingGaps={skipTrailingGaps}
        tipTranslucent={tipTranslucent}
      />
    );
  }
  return (
    <AreaChart
      data={chartPoints.map((p) => ({
        t: shortBucketLabel(p.bucket || p.t, displayTimezone),
        v: p.bps,
      }))}
      height={height}
      units="бит/с"
    />
  );
}

function ObservationChartStats({ points, lines, mode = 'total' }) {
  const stats = chartSeriesStats(points, lines, mode);
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
      <span title="Среднее по точкам окна">
        avg <span className="mono" style={{ color: 'var(--fg-primary)' }}>{formatBps(stats.avg)}</span>
      </span>
      <span title="Минимум за окно">
        min <span className="mono" style={{ color: 'var(--fg-primary)' }}>{formatBps(stats.min)}</span>
      </span>
      <span title="Максимум за окно">
        max <span className="mono" style={{ color: 'var(--fg-primary)' }}>{formatBps(stats.max)}</span>
      </span>
      <span title="Последняя точка относительно пика окна">
        now/max{' '}
        <span className="mono" style={{ color: 'var(--fg-primary)' }}>
          {stats.pctOfMax == null ? '—' : `${stats.pctOfMax.toFixed(1)}%`}
        </span>
      </span>
    </div>
  );
}

function ObservationSeriesFocus({ lines, focusKey, onFocus }) {
  if (!lines?.length || lines.length < 2) return null;
  return (
    <div className="obs-tile__legend" role="group" aria-label="Серии графика">
      <button
        type="button"
        className={`obs-tile__chip${focusKey == null ? ' is-active' : ''}`}
        onClick={() => onFocus(null)}
      >
        Все
      </button>
      {lines.map((ln) => {
        const solo = focusKey === ln.key;
        const dim = focusKey != null && !solo;
        return (
          <button
            key={ln.key}
            type="button"
            className={`obs-tile__chip${solo ? ' is-solo' : ''}${dim ? ' is-off' : ''}`}
            title={solo ? 'Показать все серии' : `Только ${ln.label || ln.key}`}
            onClick={() => onFocus(solo ? null : ln.key)}
          >
            <span className="obs-tile__chip-swatch" style={{ background: ln.color || 'var(--fg-muted)' }} />
            <span className="obs-tile__chip-label">{ln.label || ln.key}</span>
          </button>
        );
      })}
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
          title={LOOKBACK_LABELS[v] || v}
          onClick={() => onChange(v)}
        >
          {LOOKBACK_SHORT[v] || v}
        </button>
      ))}
    </div>
  );
}

function ObservationChartStylePicker({ value, onChange, disabled = false }) {
  return (
    <div className="seg obs-tile__chart-style" role="group" aria-label="Тип графика">
      {OBS_CHART_STYLES.map((style) => (
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
  lookbackOptions,
  expanded,
  onToggleExpand,
  canWrite,
  onSettings,
  onDelete,
  onCancel,
  onRunReport,
  onLookbackChange,
  onChartStyleChange,
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
  const [expandedTab, setExpandedTab] = useState('top'); // top | reports
  const [focusKey, setFocusKey] = useState(null);
  const customRangeRef = useRef(null);
  const displayTimezone = typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined;

  useEffect(() => {
    customRangeRef.current = customRange;
  }, [customRange]);

  useEffect(() => {
    setLookback(normalizeObservationLookback(item.lookback));
    setChartStyle(observationChartStyleFromWidgets(item.widgets));
    setCustomRange(null);
    setZoomStack([]);
    setFocusKey(null);
  }, [item.id, item.lookback, item.widgets]);

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
    if (typeof onLookbackChange === 'function') onLookbackChange(item.id, next);
  };

  const changeChartStyle = (next) => {
    const normalized = normalizeObservationChartStyle(next);
    if (normalized === chartStyle) return;
    setChartStyle(normalized);
    if (typeof onChartStyleChange === 'function') onChartStyleChange(item.id, normalized);
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
  const lines = chartWidget?.lines || [];
  const lineKeys = lines.map((ln) => ln.key).join('\0');
  useEffect(() => {
    if (focusKey && !lines.some((ln) => ln.key === focusKey)) setFocusKey(null);
  }, [focusKey, lineKeys]);
  const visibleLines = focusKey ? lines.filter((ln) => ln.key === focusKey) : lines;
  const chartStackMode = observationChartStyleToStackMode(chartStyle);
  const focusLabel = focusKey
    ? (lines.find((ln) => ln.key === focusKey)?.label || focusKey)
    : null;
  const topGroupBy = groupByFromWidgets(item.widgets);
  const topLabel = topGroupBy.map((g) => groupLabel(g, groupOptions)).join(' × ');
  const chartH = expanded ? 320 : 200;
  const periodLabel = observationPeriodLabel(lookback, customRange);
  const canResetZoom = Boolean(customRange || zoomStack.length);

  return (
    <Card pad="sm" className={`obs-tile${expanded ? ' obs-tile--expanded' : ''}`}>
      <div className="obs-tile__head">
        <div style={{ flex: 1, minWidth: 160 }}>
          <div className="obs-tile__title">{item.name}</div>
          {item.description ? <div className="obs-tile__desc">{item.description}</div> : null}
          {topLabel ? (
            <div className="obs-tile__sub">
              Топ по {topLabel}
              {focusLabel ? ` · фокус: ${focusLabel}` : ''}
            </div>
          ) : null}
        </div>
        <div className="obs-tile__tools">
          <button
            type="button"
            className="obs-tile__expand"
            onClick={onToggleExpand}
            aria-expanded={expanded}
            title={expanded ? 'Свернуть график и таблицу' : 'Развернуть график и таблицу'}
          >
            <Icon name={expanded ? 'collapse' : 'expand'} size={14} />
            <span>{expanded ? 'Свернуть' : 'Развернуть'}</span>
          </button>
          {canWrite && (
            <button
              type="button"
              className="obs-tile__icon tt"
              data-tt="Настройки"
              aria-label="Настройки"
              onClick={onSettings}
            >
              <Icon name="sliders" size={15} />
            </button>
          )}
          {canWrite && item.materialize?.status === 'running' && onCancel && (
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
          {canWrite && (
            <button
              type="button"
              className="obs-tile__icon obs-tile__icon--danger tt"
              data-tt="Удалить"
              aria-label="Удалить"
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
      {(item.warnings || []).map((w) => (
        <div key={w} style={{ color: 'var(--fg-warning)', font: 'var(--pv-text-body-3)' }}>{w}</div>
      ))}
      {chartWidget?.warning && (
        <div style={{ color: 'var(--fg-warning)', font: 'var(--pv-text-body-3)' }}>
          {chartWidget.warning}
        </div>
      )}

      <div style={{ minHeight: chartH, opacity: loading && !points.length ? 0.55 : 1, transition: 'opacity .15s', overflow: 'visible' }}>
        <ObservationChart
          points={points}
          lines={visibleLines}
          mode={chartMode}
          stackMode={chartMode === 'grouped' ? chartStackMode : undefined}
          height={chartH}
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
          focusKey={focusKey}
          onFocus={setFocusKey}
        />
      )}
      {!!points.length && (
        <ObservationChartStats points={points} lines={visibleLines} mode={chartMode} />
      )}

      <div className="obs-tile__footer">
        <span className="obs-tile__meta">
          {loading && !points.length
            ? 'загрузка…'
            : refreshing
              ? 'обновление…'
              : chartMode === 'grouped'
              ? `${focusLabel ? `1 серия · ${focusLabel}` : `${lines.length} серий`} · ${points.length} точек · ${periodLabel}${customRange ? ' · zoom' : ''}`
              : `${points.length} точек · ${periodLabel}${customRange ? ' · zoom' : ''}`}
          {updatedAt ? ` · ${updatedAt.toLocaleTimeString('ru-RU')}` : ''}
        </span>
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
            <button type="button" className={expandedTab === 'top' ? 'is-active' : ''} onClick={() => setExpandedTab('top')}>
              Топ
            </button>
            <button type="button" className={expandedTab === 'reports' ? 'is-active' : ''} onClick={() => setExpandedTab('reports')}>
              Отчёты
            </button>
          </div>

          {expandedTab === 'top' && (
            <>
              <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 8 }}>
                Разбивка: топ по {topLabel} (бит/с за {periodLabel})
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
                      <th style={{ textAlign: 'right', padding: 4 }}>бит/с</th>
                      <th style={{ textAlign: 'right', padding: 4 }}>%</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topRowsWithOther.map((r) => {
                      const rowKey = r.key || r.id;
                      const onChart = lines.some((ln) => ln.key === rowKey);
                      const isFocus = focusKey != null && rowKey === focusKey;
                      return (
                        <tr
                          key={rowKey}
                          className={[
                            r.isOther ? 'obs-tile__row--other' : '',
                            onChart ? 'obs-tile__row--pick' : '',
                            isFocus ? 'obs-tile__row--focus' : '',
                          ].filter(Boolean).join(' ') || undefined}
                          title={onChart ? (isFocus ? 'Показать все серии' : 'Показать только эту серию') : undefined}
                          onClick={onChart ? () => setFocusKey(isFocus ? null : rowKey) : undefined}
                        >
                          {(r.values || []).map((v, i) => (
                            <td key={i} style={{ padding: 4 }} className="mono">{v}</td>
                          ))}
                          <td style={{ padding: 4, textAlign: 'right' }} className="mono">{formatBps(r.metric)}</td>
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
                {canWrite && (
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

function PageObservations({ onNavigate }) {
  const canWriteObservations = AuthAccess.canWritePage('observations');
  const canWrite = canWriteObservations || AuthAccess.canWritePage('explorer');
  const [config, setConfig] = useState(null);
  const [items, setItems] = useState([]);
  const [expandedId, setExpandedId] = useState(null);
  const [settingsItemId, setSettingsItemId] = useState(null);
  const [settings, setSettings] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

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
    const [cfg, list] = await Promise.all([
      ApiClient.loadObservationsConfig(),
      ApiClient.loadObservations(),
    ]);
    setConfig(cfg);
    setItems(list);
    return list;
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
    });
    setError('');
  };

  const saveSettings = async () => {
    if (!canWriteObservations || !settingsItemId || !settings) return;
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
    if (!canWriteObservations || !window.confirm('Удалить наблюдение?')) return;
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
    setItems((prev) => {
      current = prev.find((row) => row.id === id) || null;
      return prev.map((row) => (row.id === id ? { ...row, lookback } : row));
    });
    if (!canWriteObservations || !current) return;
    try {
      // Смена периода не должна выключать подготовку данных.
      await ApiClient.updateObservation(id, {
        ...current,
        lookback,
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
    if (!canWriteObservations || !current) return;
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

  if (settings && settingsItem) {
    return (
      <div className="main__container">
        <div className="page-head">
          <h1>Настройки</h1>
          <button type="button" className="btn" onClick={() => { setSettings(null); setSettingsItemId(null); }}>
            К доске
          </button>
        </div>
        <div className="col" style={{ gap: 16, padding: '0 0 24px' }}>
        {error && (
          <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)' }}>{error}</div>
        )}
        <Card title={settingsItem.name}>
          <div className="col" style={{ gap: 12 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              Фильтры: {formatObservationScopeSummary(settings, filterFields)}
            </div>
            {canWrite && (
              <button
                type="button"
                className="btn"
                style={{ alignSelf: 'flex-start' }}
                onClick={() => startComposeInExplorer(onNavigate, {
                  editId: settingsItem.id,
                  name: settingsItem.name || settings.name,
                  filters: settings.filters || settingsItem.filters || [],
                  thresholds: settings.thresholds || settingsItem.thresholds || [],
                  groupBy: settingsGroupBy.length ? settingsGroupBy : null,
                  lookback: settings.lookback || settingsItem.lookback || null,
                })}
              >
                Изменить фильтры в разборе трафика
              </button>
            )}
            <label className="col" style={{ gap: 4 }}>
              <span>Название</span>
              <input className="input" value={settings.name} onChange={(e) => setSettings({ ...settings, name: e.target.value })} />
            </label>
            <label className="col" style={{ gap: 4 }}>
              <span>Описание</span>
              <input
                className="input"
                value={settings.description || ''}
                onChange={(e) => setSettings({ ...settings, description: e.target.value })}
              />
            </label>
            <label className="row" style={{ gap: 8, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={!!settings.materialize?.enabled}
                onChange={(e) => setSettings({
                  ...settings,
                  materialize: { ...(settings.materialize || {}), enabled: e.target.checked },
                })}
              />
              Подготовка данных (rollup раз в 5 минут)
            </label>
            <div style={{ marginLeft: 24, color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
              Без неё график и таблица топа по группировке пустые. Каждая подготовка — постоянная нагрузка на ClickHouse.
              Счёт с момента включения, прошлые сутки не пересчитываются.
            </div>
            {settingsGroupBy.length > 0 && (
              <div className="col" style={{ gap: 6 }}>
                <span>Тип графика</span>
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
              Отчёт по расписанию
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
            <button type="button" className="btn btn--primary" disabled={busy || !canWriteObservations} onClick={saveSettings}>
              Сохранить
            </button>
          </div>
        </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Наблюдения</h1>
        </div>
        {canWrite && (
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => startComposeInExplorer(onNavigate)}
          >
            + Новое
          </button>
        )}
      </div>
      <div className="col" style={{ gap: 16, padding: '0 0 24px' }}>

      {error && (
        <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--fg-primary)' }}>
          {error}
        </div>
      )}

      {items.length > 0 && (
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {items[0]?.quotas?.maxMaterialize
            ? `Подготовка данных: занято ${items[0]?.quotas?.activeMaterialize ?? 0} из ${items[0].quotas.maxMaterialize}`
            : `Подготовка данных: активно ${items[0]?.quotas?.activeMaterialize ?? 0}`}
        </div>
      )}

      {!items.length && (
        <Card>
          <div style={{ color: 'var(--fg-secondary)' }}>
            Пока пусто. Нажмите «+ Новое» — соберите фильтр в разборе трафика и «Добавить в наблюдения».
          </div>
        </Card>
      )}

      {items.length > 0 && (() => {
        const sorted = [...items].sort((a, b) => {
          const ao = Number(a.layout?.order) || 0;
          const bo = Number(b.layout?.order) || 0;
          if (ao !== bo) return ao - bo;
          return String(a.name || '').localeCompare(String(b.name || ''), 'ru');
        });
        return (
          <div className="observations-board">
            {sorted.map((item) => (
              <ObservationLiveTile
                key={item.id}
                item={item}
                groupOptions={groupOptions}
                lookbackOptions={config?.lookbacks || LOOKBACK_OPTIONS}
                expanded={expandedId === item.id}
                onToggleExpand={() => setExpandedId((cur) => (cur === item.id ? null : item.id))}
                canWrite={canWriteObservations}
                onSettings={() => openSettings(item)}
                onDelete={() => removeItem(item.id)}
                onCancel={() => ApiClient.cancelObservationMaterialize(item.id)
                  .then(() => reload())
                  .then(() => pushToast?.({ kind: 'success', title: 'Подготовка отменена' }))
                  .catch((e) => setError(e.message))}
                onLookbackChange={changeTileLookback}
                onChartStyleChange={changeTileChartStyle}
                onRunReport={() => ApiClient.runObservationReport(item.id)
                  .then(() => pushToast?.({ kind: 'success', title: 'Отчёт сформирован' }))
                  .catch((e) => setError(e.message))}
              />
            ))}
          </div>
        );
      })()}
      </div>
    </div>
  );
}

window.PageObservations = PageObservations;
window.startObservationCompose = startComposeInExplorer;
