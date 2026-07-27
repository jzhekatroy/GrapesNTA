/* Observations: live tile board (2 columns). Filters collected in Explorer. */

const { useState, useEffect, useCallback, useMemo, useRef } = React;

const LOOKBACK_LABELS = {
  '15m': '15 минут',
  '1h': '1 час',
  '6h': '6 часов',
  '24h': '24 часа',
  '7d': '7 дней',
};

const LOOKBACK_OPTIONS = Object.keys(LOOKBACK_LABELS);

const OBSERVATION_LOOKBACK_MS = {
  '15m': 15 * 60 * 1000,
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

const REFRESH_LABELS = {
  15: '15 сек',
  30: '30 сек',
  60: '1 мин',
  300: '5 мин',
  900: '15 мин',
};

const TOP_GROUP_OPTIONS = [
  { id: 'src_asn', label: 'Source ASN' },
  { id: 'dst_asn', label: 'Destination ASN' },
  { id: 'src_ip', label: 'Source IP' },
  { id: 'dst_ip', label: 'Destination IP' },
  { id: 'vlan', label: 'VLAN' },
  { id: 'proto', label: 'Протокол' },
  { id: 'src_country', label: 'Страна src' },
  { id: 'dst_country', label: 'Страна dst' },
];

const COMPOSE_KEY = 'grapes-observation-compose';
const OPEN_KEY = 'grapes-observation-open';

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

function topGroupFromWidgets(widgets) {
  const top = (widgets || []).find((w) => w.type === 'top_table');
  return top?.groupBy?.[0] || 'src_asn';
}

function withTopGroup(widgets, groupId) {
  const groupBy = [groupId || 'src_asn'];
  const list = Array.isArray(widgets) ? widgets.map((w) => ({ ...w })) : [];
  if (!list.some((w) => w.type === 'timeseries_bps')) {
    list.unshift({
      id: 'w-ts',
      type: 'timeseries_bps',
      metric: 'bps',
      groupBy,
      seriesLimit: 8,
      limit: null,
    });
  } else {
    for (const w of list) {
      if (w.type === 'timeseries_bps') {
        w.groupBy = groupBy;
        w.seriesLimit = w.seriesLimit || 8;
      }
    }
  }
  const idx = list.findIndex((w) => w.type === 'top_table');
  const top = {
    id: 'w-top',
    type: 'top_table',
    metric: 'bps',
    groupBy,
    limit: 15,
  };
  if (idx >= 0) list[idx] = { ...list[idx], ...top, id: list[idx].id || 'w-top' };
  else list.push(top);
  return list;
}

function formatFilterSummary(filters, filterFields) {
  if (!filters?.length) return 'без фильтров';
  return filters.slice(0, 3).map((f) => {
    const label = filterFields.find((ff) => ff.id === f.field)?.label || f.field;
    return `${label} ${f.op} ${f.value ?? ''}`;
  }).join(' · ') + (filters.length > 3 ? ' …' : '');
}

function formatDataThrough(item) {
  const iso = item.materialize?.dataThrough || item.materialize?.cursorMinute;
  if (!iso) return null;
  try {
    const d = new Date(iso);
    if (!Number.isFinite(d.getTime())) return null;
    return d.toLocaleString('ru-RU', {
      timeZone: typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined,
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return null;
  }
}

function reportPeriodLabel(item) {
  const tz = item.report?.schedule?.timezone || 'Europe/Moscow';
  return item.report?.period === 'last_24h'
    ? `последние 24 часа (${tz})`
    : `вчера, календарные сутки (${tz})`;
}

function rollupStatusLabel(item) {
  const through = formatDataThrough(item);
  const throughPart = through ? `данные по ${through}` : null;
  if (!item.scope?.materializeRequired) return throughPart;
  if (!item.materialize?.enabled) {
    return throughPart ? `${throughPart} · нужна подготовка` : 'нужна подготовка';
  }
  const st = item.materialize.status;
  const bf = item.backfillProgress;
  const bfPart = bf && !bf.done ? `история: ${bf.hoursDone} из ${bf.hoursTotal} ч` : null;
  const parts = [throughPart];
  if (st === 'lagging') parts.push(`отставание ${item.materialize.lagSeconds || '?'}с`);
  else if (st === 'queued' || st === 'running') parts.push('готовим данные…');
  else if (st === 'error') parts.push(item.materialize.lastError ? `ошибка: ${item.materialize.lastError}` : 'ошибка подготовки');
  if (bfPart) parts.push(bfPart);
  return parts.filter(Boolean).join(' · ') || null;
}

function downloadTextFile(filename, text, mime = 'text/csv;charset=utf-8') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function csvEscapeCell(v) {
  const s = String(v ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function tileRefreshSec(item) {
  const want = item.live?.enabled
    ? Number(item.live.refreshSec) || MIN_REFRESH_SEC
    : MIN_REFRESH_SEC;
  return Math.max(MIN_REFRESH_SEC, want);
}

function startComposeInExplorer(onNavigate, {
  editId = null,
  name = '',
  filters = null,
  groupBy = null,
  lookback = null,
} = {}) {
  try {
    sessionStorage.setItem(COMPOSE_KEY, JSON.stringify({
      active: true,
      editId: editId || null,
      name: name || '',
      filters: Array.isArray(filters) ? filters : null,
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
  height = 160,
  onRangeSelect,
  displayTimezone,
  bucketSeconds = 300,
  periodStartMs,
  periodEndMs,
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
        height={height}
        mode="bw"
        valueFormatter={formatBps}
        axisFormatter={formatAxisBps}
        onRangeSelect={onRangeSelect}
        bucketSeconds={bucketSeconds}
        displayTimezone={displayTimezone}
        periodStartMs={periodStartMs}
        periodEndMs={periodEndMs}
        tipUnitLabel="бит/с"
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

function LookbackPicker({ value, options, onChange, compact = false }) {
  const list = options?.length ? options : LOOKBACK_OPTIONS;
  return (
    <div
      className="row"
      role="group"
      aria-label="Окно графика"
      style={{ gap: 4, flexWrap: 'wrap', alignItems: 'center' }}
    >
      {!compact && (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginRight: 2 }}>
          Окно
        </span>
      )}
      {list.map((v) => {
        const active = v === value;
        return (
          <button
            key={v}
            type="button"
            className="btn"
            onClick={() => onChange(v)}
            style={{
              padding: compact ? '2px 8px' : '4px 10px',
              font: 'var(--pv-text-body-3)',
              background: active ? 'var(--surf-3, var(--surf-2))' : 'transparent',
              borderColor: active ? 'var(--bd-strong, var(--bd-soft))' : 'var(--bd-soft)',
              fontWeight: active ? 600 : 400,
            }}
          >
            {v}
          </button>
        );
      })}
    </div>
  );
}

function ObservationLiveTile({
  item,
  filterFields,
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
}) {
  const [preview, setPreview] = useState(null);
  const [comparePreview, setComparePreview] = useState(null);
  const [compareOn, setCompareOn] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [lookback, setLookback] = useState(item.lookback || '1h');
  const [customRange, setCustomRange] = useState(null);
  const [zoomStack, setZoomStack] = useState([]);
  const [runs, setRuns] = useState([]);
  const [runsError, setRunsError] = useState('');
  const [expandedTab, setExpandedTab] = useState('top'); // top | reports
  const customRangeRef = useRef(null);
  const displayTimezone = typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined;

  useEffect(() => {
    customRangeRef.current = customRange;
  }, [customRange]);

  useEffect(() => {
    setLookback(item.lookback || '1h');
    setCustomRange(null);
    setZoomStack([]);
  }, [item.id, item.lookback]);

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
    setLoading(true);
    const tick = (opts = { initial: true }) => {
      if (opts.initial) setLoading(true);
      else setRefreshing(true);
      ApiClient.previewObservation(item.id, previewPayload)
        .then((body) => {
          if (cancelled) return;
          setPreview(body.data || body);
          setLoading(false);
          setRefreshing(false);
          setError('');
          setUpdatedAt(new Date());
        })
        .catch((e) => {
          if (cancelled) return;
          setError(e.message);
          setLoading(false);
          setRefreshing(false);
        });
    };
    tick({ initial: true });
    const timer = setInterval(() => tick({ initial: false }), tileRefreshSec(item) * 1000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [item.id, previewPayload, item.live?.enabled, item.live?.refreshSec]);

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

  useEffect(() => {
    if (!compareOn) {
      setComparePreview(null);
      return undefined;
    }
    let cancelled = false;
    const ms = OBSERVATION_LOOKBACK_MS[lookback] || OBSERVATION_LOOKBACK_MS['1h'];
    const shift = lookback === '7d' || lookback === '24h' ? 7 * 86400 * 1000 : ms;
    let from;
    let to;
    if (customRange?.from && customRange?.to) {
      const a = Date.parse(customRange.from);
      const b = Date.parse(customRange.to);
      if (Number.isFinite(a) && Number.isFinite(b)) {
        from = new Date(a - shift).toISOString();
        to = new Date(b - shift).toISOString();
      }
    } else {
      to = new Date(Date.now() - shift).toISOString();
      from = new Date(Date.now() - shift - ms).toISOString();
    }
    if (!from || !to) return undefined;
    ApiClient.previewObservation(item.id, { from, to })
      .then((body) => {
        if (!cancelled) setComparePreview(body.data || body);
      })
      .catch(() => {
        if (!cancelled) setComparePreview(null);
      });
    return () => { cancelled = true; };
  }, [compareOn, item.id, lookback, customRange?.from, customRange?.to]);

  const changeLookback = (next) => {
    if (!next || next === lookback) return;
    setCustomRange(null);
    setZoomStack([]);
    setLookback(next);
    if (typeof onLookbackChange === 'function') onLookbackChange(item.id, next);
  };

  const exportCsv = () => {
    const chartW = (preview?.widgets || []).find((w) => w.type === 'timeseries_bps');
    const topW = (preview?.widgets || []).find((w) => w.type === 'top_table');
    const pts = chartW?.points || chartW?.series || [];
    const linesLocal = chartW?.lines || [];
    const mode = chartW?.mode === 'grouped' ? 'grouped' : 'total';
    const grouped = mode === 'grouped' && linesLocal.length > 0;
    const headers = grouped ? ['t', 'series', 'bps'] : ['t', 'bps'];
    const rows = [];
    for (const p of pts) {
      if (!grouped) {
        rows.push([p.t, p.bps].map(csvEscapeCell).join(','));
        continue;
      }
      for (const ln of linesLocal) {
        if (p[ln.key] == null) continue;
        rows.push([p.t, ln.label || ln.key, p[ln.key]].map(csvEscapeCell).join(','));
      }
    }
    let text = `${headers.join(',')}\n${rows.join('\n')}\n`;
    if (Array.isArray(topW?.rows) && topW.rows.length) {
      text += '\n# top\n';
      const gh = [...(topW.groupBy || []), 'metric', 'pct'];
      text += `${gh.join(',')}\n`;
      for (const r of topW.rows) {
        text += [...(r.values || []), r.metric, r.pct].map(csvEscapeCell).join(',');
        text += '\n';
      }
    }
    downloadTextFile(`${item.name || item.id}.csv`, text);
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
    const shown = all.filter((r) => !r.isOther).slice(0, 25);
    return other ? [...shown, other] : shown;
  }, [topWidget]);
  const chartMode = chartWidget?.mode === 'grouped' ? 'grouped' : 'total';
  const basePoints = chartWidget?.points || chartWidget?.series || [];
  const baseLines = chartWidget?.lines || [];
  const compareWidget = (comparePreview?.widgets || []).find((w) => w.type === 'timeseries_bps');
  const compareSeries = compareWidget?.points || compareWidget?.series || [];
  const points = useMemo(() => {
    if (!compareOn || !compareSeries.length || !basePoints.length) return basePoints;
    const byIdx = compareSeries;
    return basePoints.map((p, i) => {
      const prev = byIdx[i] || byIdx[byIdx.length - 1] || {};
      return { ...p, bps_prev: Number(prev.bps) || 0 };
    });
  }, [basePoints, compareSeries, compareOn]);
  const lines = useMemo(() => {
    if (!compareOn || chartMode === 'grouped') return baseLines;
    if (!basePoints.length) return baseLines;
    return [
      { key: 'bps', label: 'сейчас', color: 'var(--accent, #3b82f6)' },
      { key: 'bps_prev', label: 'прошлый период', color: 'var(--fg-muted, #888)' },
    ];
  }, [baseLines, compareOn, chartMode, basePoints.length]);
  const lastBps = (() => {
    if (!points.length) return null;
    const last = points[points.length - 1];
    if (chartMode === 'grouped' && lines.length) {
      return lines.reduce((sum, ln) => sum + (Number(last[ln.key]) || 0), 0);
    }
    return Number(last.bps) || 0;
  })();
  const topBy = topGroupFromWidgets(item.widgets);
  const topLabel = groupOptions.find((g) => g.id === topBy)?.label || topBy;
  const rollup = rollupStatusLabel(item);
  const chartH = expanded ? 320 : 200;
  const periodLabel = observationPeriodLabel(lookback, customRange);
  const canResetZoom = Boolean(customRange || zoomStack.length);
  const tileWidth = Number(item.layout?.width) === 2 ? 2 : 1;

  return (
    <Card
      pad="sm"
      style={{
        gridColumn: expanded || tileWidth === 2 ? '1 / -1' : 'auto',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        minWidth: 0,
      }}
    >
      <div className="row" style={{ justifyContent: 'space-between', gap: 8, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 160 }}>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>
            {item.name}
            {item.isShared ? (
              <span style={{ marginLeft: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>общее</span>
            ) : null}
          </div>
          {item.description ? (
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 2 }}>
              {item.description}
            </div>
          ) : null}
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 2 }}>
            {formatFilterSummary(item.filters, filterFields)}
          </div>
          <div
            style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: 2 }}
            title="Нормальная задержка ~10 минут: бакет 5 минут + запас на late flows"
          >
            график: топ по {topLabel}
            {' · '}
            таблица: топ {topLabel}
            {item.live?.enabled
              ? ` · обновл. ${REFRESH_LABELS[tileRefreshSec(item)] || `${tileRefreshSec(item)}с`}`
              : ` · обновл. ${REFRESH_LABELS[MIN_REFRESH_SEC]}`}
            {rollup ? ` · ${rollup}` : ''}
          </div>
        </div>
        <div className="row" style={{ gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {lastBps != null && (
            <span
              className="mono"
              title={chartMode === 'grouped' ? `Сумма топ-серий по ${topLabel}` : 'Суммарный трафик по фильтру'}
              style={{ font: 'var(--pv-text-body-2-bold)', marginRight: 4 }}
            >
              {formatBps(lastBps)}
            </span>
          )}
          <button type="button" className="btn" onClick={onToggleExpand}>
            {expanded ? 'Свернуть' : `Топ · ${topLabel}`}
          </button>
          {canWrite && <button type="button" className="btn" onClick={onSettings}>Настройки</button>}
          {canWrite && item.materialize?.status === 'running' && onCancel && (
            <button type="button" className="btn" onClick={onCancel}>Отменить</button>
          )}
          {canWrite && (
            <button type="button" className="btn" onClick={onDelete}>Удалить</button>
          )}
        </div>
      </div>

      {error && (
        <div style={{ color: 'crimson', font: 'var(--pv-text-body-3)' }}>{error}</div>
      )}
      {(item.warnings || []).map((w) => (
        <div key={w} style={{ color: 'var(--fg-warning, #b78103)', font: 'var(--pv-text-body-3)' }}>{w}</div>
      ))}
      {chartWidget?.warning && (
        <div style={{ color: 'var(--fg-warning, #b78103)', font: 'var(--pv-text-body-3)' }}>
          {chartWidget.warning}
        </div>
      )}

      <div className="row" style={{ justifyContent: 'space-between', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {chartMode === 'grouped'
            ? `Динамика топ-${lines.length || 8} по ${topLabel} (из rollup)`
            : 'Суммарный трафик по фильтру (из rollup)'}
          {points.length > 1 && (
            <span style={{ color: 'var(--fg-muted)', marginLeft: 8 }}>
              · выделите диапазон на графике
            </span>
          )}
        </div>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          {canResetZoom && (
            <button
              type="button"
              className="time-pill time-pill--reset"
              title="Вернуть предыдущий период"
              onClick={resetTileZoom}
            >
              <Icon name="zoom" size={14} />
              <span>Сброс zoom</span>
            </button>
          )}
          <label className="row" style={{ gap: 4, alignItems: 'center', font: 'var(--pv-text-body-3)' }}>
            <input type="checkbox" checked={compareOn} onChange={(e) => setCompareOn(e.target.checked)} />
            сравнить
          </label>
          <button type="button" className="btn" onClick={exportCsv} disabled={!points.length}>CSV</button>
          <LookbackPicker
            value={lookback}
            options={lookbackOptions}
            onChange={changeLookback}
            compact={!expanded}
          />
        </div>
      </div>
      <div style={{ minHeight: chartH, opacity: loading && !points.length ? 0.55 : 1, transition: 'opacity .15s', overflow: 'visible' }}>
        <ObservationChart
          points={points}
          lines={lines}
          mode={compareOn && chartMode !== 'grouped' ? 'grouped' : chartMode}
          height={chartH}
          onRangeSelect={points.length > 1 ? handleChartRangeSelect : undefined}
          displayTimezone={displayTimezone}
          bucketSeconds={300}
          periodStartMs={chartPeriodBounds.periodStartMs}
          periodEndMs={chartPeriodBounds.periodEndMs}
        />
      </div>
      {!!points.length && (
        <ObservationChartStats points={points} lines={lines} mode={chartMode} />
      )}

      <div className="row" style={{ justifyContent: 'space-between', color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
        <span>
          {loading && !points.length
            ? 'загрузка…'
            : refreshing
              ? 'обновление…'
              : chartMode === 'grouped'
              ? `${lines.length} серий · ${points.length} точек · ${periodLabel}${customRange ? ' · zoom' : ''}`
              : `${points.length} точек · ${periodLabel}${customRange ? ' · zoom' : ''}`}
          {updatedAt ? ` · ${updatedAt.toLocaleTimeString('ru-RU')}` : ''}
          {compareOn ? ' · + прошлый период' : ''}
        </span>
        <span>бит/с</span>
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
                          {groupOptions.find((o) => o.id === g)?.label || g}
                        </th>
                      ))}
                      <th style={{ textAlign: 'right', padding: 4 }}>бит/с</th>
                      <th style={{ textAlign: 'right', padding: 4 }}>%</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topRowsWithOther.map((r) => (
                      <tr key={r.id || r.key} style={r.isOther ? { color: 'var(--fg-secondary)' } : undefined}>
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
                    ))}
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
              {runsError && <div style={{ color: 'crimson', font: 'var(--pv-text-body-3)' }}>{runsError}</div>}
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

function workerStatusMeta(worker) {
  if (!worker) return { label: 'неизвестно', color: 'var(--fg-muted)' };
  if (worker.alive) return { label: 'работает', color: '#1a7f37' };
  if (worker.status === 'stale') return { label: 'нет heartbeat', color: '#b78103' };
  return { label: 'остановлен', color: 'crimson' };
}

function ObservationDiagnosticsPanel() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState(null);

  const reload = useCallback((opts = { initial: false }) => {
    if (opts.initial) setLoading(true);
    ApiClient.loadObservationAnalyticsDiagnostics()
      .then((body) => {
        setData(body);
        setError('');
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    reload({ initial: true });
    // Diagnostics should refresh often — worker health is the point of this tab.
    const t = setInterval(() => reload({ initial: false }), 15000);
    return () => clearInterval(t);
  }, [reload]);

  const worker = data?.worker;
  const status = workerStatusMeta(worker);

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          Состояние analytics loop в `grapes-worker` и запросы к ClickHouse.
          Полная диагностика (rollups + проблемы): Администрирование → Диагностика.
        </div>
        <button type="button" className="btn" onClick={() => reload({ initial: false })} disabled={loading}>
          {loading && !data ? 'загрузка…' : 'Обновить'}
        </button>
      </div>

      {error && (
        <div style={{ padding: 10, borderRadius: 8, background: 'rgba(220,50,50,.12)', color: 'crimson' }}>
          {error}
        </div>
      )}

      {worker && !worker.alive && (
        <div style={{
          padding: 12,
          borderRadius: 8,
          background: 'rgba(183,129,3,.12)',
          color: 'var(--fg-primary)',
          font: 'var(--pv-text-body-3)',
        }}>
          Воркер analytics сейчас не работает ({status.label}
          {worker.heartbeatAgeSec != null ? `, последний heartbeat ${worker.heartbeatAgeSec}с назад` : ''}
          ). Запуск: <span className="mono">GRAPES_ANALYTICS_WORKER=1 node server/analytics.js loop</span>
        </div>
      )}

      <Card title="Воркер">
        <div className="grid grid--auto-fit-md grid--gap-sm" style={{ font: 'var(--pv-text-body-3)' }}>
          <div>
            <div style={{ color: 'var(--fg-muted)' }}>Статус</div>
            <div style={{ font: 'var(--pv-text-body-2-bold)', color: status.color }}>{status.label}</div>
            {worker?.statusReason && (
              <div style={{ color: 'var(--fg-secondary)', marginTop: 2 }}>{worker.statusReason}</div>
            )}
          </div>
          <div>
            <div style={{ color: 'var(--fg-muted)' }}>Источник</div>
            <div className="mono">
              {worker?.source === 'clickhouse' ? 'ClickHouse' : worker?.source === 'file' ? 'локальный файл' : (worker?.source || '—')}
            </div>
            {data?.storePath && (
              <div style={{ color: 'var(--fg-secondary)', marginTop: 2, wordBreak: 'break-all' }}>{data.storePath}</div>
            )}
          </div>
          <div>
            <div style={{ color: 'var(--fg-muted)' }}>Host</div>
            <div className="mono">{worker?.host || '—'}</div>
          </div>
          <div>
            <div style={{ color: 'var(--fg-muted)' }}>PID</div>
            <div className="mono">{worker?.pid ?? '—'}</div>
          </div>
          <div>
            <div style={{ color: 'var(--fg-muted)' }}>Последний heartbeat</div>
            <div>{fmtDiagTime(worker?.lastHeartbeatAt)}</div>
            {worker?.heartbeatAgeSec != null && (
              <div style={{ color: 'var(--fg-secondary)' }}>{worker.heartbeatAgeSec}с назад</div>
            )}
          </div>
          <div>
            <div style={{ color: 'var(--fg-muted)' }}>Последний tick</div>
            <div>{fmtDiagTime(worker?.lastTickAt)}</div>
            {worker?.lastTickMs != null && (
              <div style={{ color: 'var(--fg-secondary)' }}>{worker.lastTickMs} мс</div>
            )}
          </div>
          <div>
            <div style={{ color: 'var(--fg-muted)' }}>Запущен</div>
            <div>{fmtDiagTime(worker?.startedAt)}</div>
          </div>
          <div>
            <div style={{ color: 'var(--fg-muted)' }}>Ошибка tick</div>
            <div style={{ color: worker?.lastError ? 'crimson' : 'inherit' }}>{worker?.lastError || '—'}</div>
          </div>
        </div>
        {data?.lastTick && (
          <pre style={{
            marginTop: 12,
            padding: 10,
            borderRadius: 8,
            background: 'var(--surf-2)',
            font: 'var(--pv-text-body-3)',
            overflow: 'auto',
            maxHeight: 180,
          }}>
            {JSON.stringify(data.lastTick, null, 2)}
          </pre>
        )}
      </Card>

      <Card title="Наблюдения (rollup)">
        <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: 6 }}>Наблюдение</th>
              <th style={{ textAlign: 'left', padding: 6 }}>materialize</th>
              <th style={{ textAlign: 'left', padding: 6 }}>cursor</th>
              <th style={{ textAlign: 'right', padding: 6 }}>lag</th>
              <th style={{ textAlign: 'left', padding: 6 }}>max minute CH (`observation_rollups_5m`)</th>
            </tr>
          </thead>
          <tbody>
            {(data?.jobs || []).map((j) => (
              <tr key={j.id}>
                <td style={{ padding: 6 }}>{j.name}</td>
                <td style={{ padding: 6 }} className="mono">{j.materialize?.status || '—'}</td>
                <td style={{ padding: 6 }} className="mono">{fmtDiagTime(j.materialize?.cursorMinute)}</td>
                <td style={{ padding: 6, textAlign: 'right' }} className="mono">{j.materialize?.lagSeconds ?? '—'}</td>
                <td style={{ padding: 6 }} className="mono">{j.rollup?.maxMinute || '—'}</td>
              </tr>
            ))}
            {!loading && !(data?.jobs || []).length && (
              <tr><td colSpan={5} style={{ padding: 8, color: 'var(--fg-secondary)' }}>Нет materialize job’ов</td></tr>
            )}
          </tbody>
        </table>
        {data?.rollupStatsError && (
          <div style={{ marginTop: 8, color: 'var(--fg-warning, #b78103)', font: 'var(--pv-text-body-3)' }}>
            CH stats: {data.rollupStatsError}
          </div>
        )}
      </Card>

      <Card title="Последние запросы">
        <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: 6 }}>время</th>
              <th style={{ textAlign: 'left', padding: 6 }}>имя</th>
              <th style={{ textAlign: 'right', padding: 6 }}>мс</th>
              <th style={{ textAlign: 'right', padding: 6 }}>строк</th>
              <th style={{ textAlign: 'left', padding: 6 }}>ошибка</th>
            </tr>
          </thead>
          <tbody>
            {(data?.queries || []).map((q) => (
              <React.Fragment key={q.id}>
                <tr
                  onClick={() => setExpandedId((cur) => (cur === q.id ? null : q.id))}
                  style={{ cursor: 'pointer', background: expandedId === q.id ? 'var(--surf-2)' : 'transparent' }}
                >
                  <td style={{ padding: 6 }} className="mono">{fmtDiagTime(q.at)}</td>
                  <td style={{ padding: 6 }} className="mono">{q.name}</td>
                  <td style={{ padding: 6, textAlign: 'right' }} className="mono">{q.elapsedMs}</td>
                  <td style={{ padding: 6, textAlign: 'right' }} className="mono">{q.rows}</td>
                  <td style={{ padding: 6, color: q.error ? 'crimson' : 'var(--fg-secondary)' }}>
                    {q.error || '—'}
                  </td>
                </tr>
                {expandedId === q.id && (
                  <tr>
                    <td colSpan={5} style={{ padding: '8px 6px 12px' }}>
                      <pre style={{
                        margin: 0,
                        padding: 10,
                        borderRadius: 8,
                        background: 'var(--surf-1)',
                        border: '1px solid var(--bd-soft)',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        font: 'var(--pv-text-body-3)',
                        maxHeight: 360,
                        overflow: 'auto',
                      }}>
                        {q.sql}
                        {'\n\n-- params\n'}
                        {JSON.stringify(q.params || {}, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
            {!loading && !(data?.queries || []).length && (
              <tr><td colSpan={5} style={{ padding: 8, color: 'var(--fg-secondary)' }}>Запросов пока нет — воркер не писал диагностику</td></tr>
            )}
          </tbody>
        </table>
      </Card>

      <ObservationSmtpPanel />
    </div>
  );
}

function ObservationSmtpPanel() {
  const [smtp, setSmtp] = useState(null);
  const [error, setError] = useState('');
  const [forbidden, setForbidden] = useState(false);
  const [busy, setBusy] = useState(false);
  const [testTo, setTestTo] = useState('');

  useEffect(() => {
    ApiClient.loadSmtpSettings()
      .then((data) => {
        setSmtp(data);
        setForbidden(false);
        setError('');
      })
      .catch((e) => {
        if (e.status === 403) setForbidden(true);
        setError(e.message);
      });
  }, []);

  if (forbidden) {
    return (
      <Card title="SMTP (отчёты)">
        <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          Настройки почты доступны только администратору.
        </div>
      </Card>
    );
  }

  if (!smtp) {
    return (
      <Card title="SMTP (отчёты)">
        <div style={{ color: 'var(--fg-secondary)' }}>{error || 'загрузка…'}</div>
      </Card>
    );
  }

  const save = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await ApiClient.saveSmtpSettings(smtp);
      setSmtp(res.data || smtp);
      pushToast?.({ kind: 'success', title: 'SMTP сохранён' });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    setError('');
    try {
      await ApiClient.testSmtpSettings(testTo);
      pushToast?.({ kind: 'success', title: 'Тестовое письмо отправлено' });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="SMTP (отчёты по наблюдениям)">
      <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
        {error && <div style={{ color: 'crimson' }}>{error}</div>}
        <label className="row" style={{ gap: 8, alignItems: 'center' }}>
          <input
            type="checkbox"
            checked={!!smtp.enabled}
            onChange={(e) => setSmtp({ ...smtp, enabled: e.target.checked })}
          />
          Включить отправку
        </label>
        <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
          <label className="col" style={{ gap: 4, minWidth: 180 }}>
            <span>Host</span>
            <input className="input" value={smtp.host || ''} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })} />
          </label>
          <label className="col" style={{ gap: 4, minWidth: 90 }}>
            <span>Port</span>
            <input className="input" type="number" value={smtp.port || 587} onChange={(e) => setSmtp({ ...smtp, port: Number(e.target.value) })} />
          </label>
          <label className="row" style={{ gap: 6, alignItems: 'center', marginTop: 18 }}>
            <input type="checkbox" checked={!!smtp.secure} onChange={(e) => setSmtp({ ...smtp, secure: e.target.checked })} />
            TLS (465)
          </label>
        </div>
        <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
          <label className="col" style={{ gap: 4, minWidth: 160 }}>
            <span>Username</span>
            <input className="input" value={smtp.username || ''} onChange={(e) => setSmtp({ ...smtp, username: e.target.value })} />
          </label>
          <label className="col" style={{ gap: 4, minWidth: 160 }}>
            <span>Password {smtp.passwordSet ? '(задан)' : ''}</span>
            <input
              className="input"
              type="password"
              placeholder={smtp.passwordSet ? 'оставьте пустым, чтобы не менять' : ''}
              value={smtp.password || ''}
              onChange={(e) => setSmtp({ ...smtp, password: e.target.value })}
            />
          </label>
          <label className="col" style={{ gap: 4, minWidth: 180 }}>
            <span>From email</span>
            <input className="input" value={smtp.fromEmail || ''} onChange={(e) => setSmtp({ ...smtp, fromEmail: e.target.value })} />
          </label>
          <label className="col" style={{ gap: 4, minWidth: 140 }}>
            <span>From name</span>
            <input className="input" value={smtp.fromName || ''} onChange={(e) => setSmtp({ ...smtp, fromName: e.target.value })} />
          </label>
        </div>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <button type="button" className="btn btn--primary" disabled={busy} onClick={save}>Сохранить SMTP</button>
          <input
            className="input"
            style={{ width: 220 }}
            placeholder="email для теста"
            value={testTo}
            onChange={(e) => setTestTo(e.target.value)}
          />
          <button type="button" className="btn" disabled={busy || !testTo} onClick={test}>Проверить отправку</button>
        </div>
      </div>
    </Card>
  );
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
  const [pageTab, setPageTab] = useState('board');

  const settingsItem = useMemo(
    () => items.find((x) => x.id === settingsItemId) || null,
    [items, settingsItemId],
  );

  const filterFields = config?.schema?.filterFields || [];
  const groupOptions = useMemo(() => {
    const dims = config?.schema?.dimensions || [];
    if (!dims.length) return TOP_GROUP_OPTIONS;
    const mapped = TOP_GROUP_OPTIONS
      .map((o) => dims.find((d) => d.id === o.id))
      .filter(Boolean)
      .map((d) => ({ id: d.id, label: d.label }));
    return mapped.length ? mapped : TOP_GROUP_OPTIONS;
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
    if (pageTab !== 'board') return undefined;
    const t = setInterval(() => {
      reload().catch((e) => setError(e.message));
    }, MIN_REFRESH_SEC * 1000);
    return () => clearInterval(t);
  }, [pageTab, reload]);

  const openSettings = (item) => {
    setSettingsItemId(item.id);
    setSettings({
      name: item.name,
      description: item.description || '',
      folder: item.folder || 'Мои наблюдения',
      isShared: Boolean(item.isShared),
      lookback: item.lookback,
      widgets: item.widgets,
      layout: item.layout || { order: 0, width: 1 },
      live: { ...(item.live || { enabled: true, refreshSec: MIN_REFRESH_SEC }) },
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
        isShared: settings.isShared,
        lookback: settings.lookback,
        widgets: withTopGroup(settings.widgets, topGroupFromWidgets(settings.widgets)),
        layout: settings.layout,
        live: settings.live,
        report: settings.report,
        filters: settings.filters,
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
      // Keep live/materialize — period switch must not disable rollup.
      await ApiClient.updateObservation(id, {
        ...current,
        lookback,
        live: { ...(current.live || {}), enabled: current.live?.enabled !== false },
        materialize: {
          ...(current.materialize || {}),
          enabled: current.live?.enabled !== false
            ? true
            : Boolean(current.materialize?.enabled),
        },
      });
    } catch (e) {
      setError(e.message);
      await reload();
    }
  };

  const settingsTop = topGroupFromWidgets(settings?.widgets);

  if (settings && settingsItem) {
    return (
      <div className="col" style={{ gap: 16, padding: '0 0 24px' }}>
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
          <h1 style={{ margin: 0, font: 'var(--pv-text-headline)' }}>Настройки</h1>
          <button type="button" className="btn" onClick={() => { setSettings(null); setSettingsItemId(null); }}>
            К доске
          </button>
        </div>
        {error && (
          <div style={{ padding: 10, borderRadius: 8, background: 'rgba(220,50,50,.12)' }}>{error}</div>
        )}
        <Card title={settingsItem.name}>
          <div className="col" style={{ gap: 12 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              Фильтры: {formatFilterSummary(settings.filters, filterFields)}
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
                  groupBy: settingsTop ? [settingsTop] : null,
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
            <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
              <label className="col" style={{ gap: 4, minWidth: 160 }}>
                <span>Папка</span>
                <input
                  className="input"
                  value={settings.folder || 'Мои наблюдения'}
                  onChange={(e) => setSettings({ ...settings, folder: e.target.value })}
                />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 160 }}>
                <span>Окно графика</span>
                <select className="input" value={settings.lookback} onChange={(e) => setSettings({ ...settings, lookback: e.target.value })}>
                  {(config?.lookbacks || Object.keys(LOOKBACK_LABELS)).map((v) => (
                    <option key={v} value={v}>{LOOKBACK_LABELS[v] || v}</option>
                  ))}
                </select>
              </label>
              <label className="col" style={{ gap: 4, minWidth: 180 }}>
                <span>Топ по полю</span>
                <select
                  className="input"
                  value={settingsTop}
                  onChange={(e) => setSettings({ ...settings, widgets: withTopGroup(settings.widgets, e.target.value) })}
                >
                  {groupOptions.map((g) => <option key={g.id} value={g.id}>{g.label}</option>)}
                </select>
              </label>
              <label className="col" style={{ gap: 4, minWidth: 140 }}>
                <span>Ширина плитки</span>
                <select
                  className="input"
                  value={Number(settings.layout?.width) === 2 ? 2 : 1}
                  onChange={(e) => setSettings({
                    ...settings,
                    layout: { ...(settings.layout || {}), width: Number(e.target.value), order: settings.layout?.order || 0 },
                  })}
                >
                  <option value={1}>1 колонка</option>
                  <option value={2}>на всю ширину</option>
                </select>
              </label>
            </div>
            <label className="row" style={{ gap: 8, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={!!settings.isShared}
                onChange={(e) => setSettings({ ...settings, isShared: e.target.checked })}
              />
              Доступно всем
            </label>
            <label className="row" style={{ gap: 8, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={!!settings.live.enabled}
                onChange={(e) => setSettings({
                  ...settings,
                  live: {
                    ...settings.live,
                    enabled: e.target.checked,
                    refreshSec: Math.max(MIN_REFRESH_SEC, settings.live.refreshSec || MIN_REFRESH_SEC),
                  },
                })}
              />
              Live на доске
            </label>
            {settings.live.enabled && (
              <label className="row" style={{ gap: 8, alignItems: 'center', marginLeft: 24 }}>
                каждые
                <select
                  className="input"
                  style={{ width: 120 }}
                  value={Math.max(MIN_REFRESH_SEC, Number(settings.live.refreshSec) || MIN_REFRESH_SEC)}
                  onChange={(e) => setSettings({
                    ...settings,
                    live: { ...settings.live, refreshSec: Number(e.target.value) },
                  })}
                >
                  {(config?.refreshSecs || [300, 900]).map((v) => (
                    <option key={v} value={v}>{REFRESH_LABELS[v] || `${v}с`}</option>
                  ))}
                </select>
                <span style={{ color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
                  (и UI, и воркер; запас 5 мин на late flows)
                </span>
              </label>
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
                  <input
                    className="input"
                    style={{ width: 160 }}
                    value={settings.report.schedule?.timezone || 'Europe/Moscow'}
                    onChange={(e) => setSettings({
                      ...settings,
                      report: {
                        ...settings.report,
                        schedule: { ...(settings.report.schedule || {}), timezone: e.target.value },
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
    );
  }

  return (
    <div className="col" style={{ gap: 16, padding: '0 0 24px' }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <div>
          <h1 style={{ margin: 0, font: 'var(--pv-text-headline)' }}>Наблюдения</h1>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 4 }}>
            {pageTab === 'board'
              ? 'Live-доска: обновление по настройке наблюдения (минимум раз в 5 минут).'
              : 'Диагностика воркера analytics — обновление раз в 5 минут.'}
          </div>
        </div>
        {pageTab === 'board' && canWrite && (
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => startComposeInExplorer(onNavigate)}
          >
            + Новое
          </button>
        )}
      </div>

      <div className="seg" style={{ width: 'fit-content' }}>
        <button
          type="button"
          className={pageTab === 'board' ? 'is-active' : ''}
          onClick={() => setPageTab('board')}
        >
          Доска
        </button>
        <button
          type="button"
          className={pageTab === 'diagnostics' ? 'is-active' : ''}
          onClick={() => setPageTab('diagnostics')}
        >
          Диагностика воркера
        </button>
      </div>

      {pageTab === 'diagnostics' && <ObservationDiagnosticsPanel />}

      {pageTab === 'board' && (
        <>
      {error && (
        <div style={{ padding: 10, borderRadius: 8, background: 'rgba(220,50,50,.12)', color: 'var(--fg-primary)' }}>
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
        const folders = [];
        const byFolder = new Map();
        for (const item of sorted) {
          const folder = item.folder || 'Мои наблюдения';
          if (!byFolder.has(folder)) {
            byFolder.set(folder, []);
            folders.push(folder);
          }
          byFolder.get(folder).push(item);
        }
        return folders.map((folder) => (
          <div key={folder} className="col" style={{ gap: 10 }}>
            <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{folder}</div>
            <div className="observations-board">
              {byFolder.get(folder).map((item) => (
                <ObservationLiveTile
                  key={item.id}
                  item={item}
                  filterFields={filterFields}
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
                  onRunReport={() => ApiClient.runObservationReport(item.id)
                    .then(() => pushToast?.({ kind: 'success', title: 'Отчёт сформирован' }))
                    .catch((e) => setError(e.message))}
                />
              ))}
            </div>
          </div>
        ));
      })()}

        </>
      )}
    </div>
  );
}

window.PageObservations = PageObservations;
window.startObservationCompose = startComposeInExplorer;
