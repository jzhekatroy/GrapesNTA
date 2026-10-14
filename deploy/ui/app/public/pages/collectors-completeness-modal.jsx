/* global React, ApiClient, Button, Modal, TimeSeriesSparkChart, fmtCompact, GrapesI18n,
   getDisplayTimezone, msToDatetimeLocalValue, displayDatetimeLocalToData, parseChartBucketMs */

const { useState, useEffect, useCallback } = React;

function collectorsT(key, params) {
  return GrapesI18n.t(key, params);
}

const HOUR_MS = 3600000;
const DAY_MS = 24 * HOUR_MS;
const MIN_ZOOM_MS = HOUR_MS;

const PERIOD_PRESETS = [
  { id: '6h', labelKey: 'collectorsPage.tl.preset.6h', ms: 6 * HOUR_MS },
  { id: '24h', labelKey: 'collectorsPage.tl.preset.24h', ms: DAY_MS },
  { id: '7d', labelKey: 'collectorsPage.tl.preset.7d', ms: 7 * DAY_MS },
  { id: '30d', labelKey: 'collectorsPage.tl.preset.30d', ms: 30 * DAY_MS },
  { id: '90d', labelKey: 'collectorsPage.tl.preset.90d', ms: 90 * DAY_MS },
];

const CHARTS = [
  { key: 'completenessPct', labelKey: 'collectorsPage.tl.chart.completenessPct', color: '#3FB68B', pct: true, xdp: true },
  { key: 'phy', labelKey: 'collectorsPage.tl.chart.phy', unitKey: 'collectorsPage.tl.unit.packets', color: '#8B93A7', xdp: true, stage: 'interface' },
  { key: 'seen', labelKey: 'collectorsPage.tl.chart.seen', unitKey: 'collectorsPage.tl.unit.packets', color: '#7E92F8', xdp: true },
  { key: 'input', labelKey: 'collectorsPage.tl.chart.input', unitKey: 'collectorsPage.tl.unit.datagrams', color: '#7E92F8', sflow: true },
  { key: 'nfRecords', labelKey: 'collectorsPage.tl.chart.nfRecords', unitKey: 'collectorsPage.tl.unit.flows', color: '#C084FC', stage: 'netflow' },
  { key: 'acked', labelKey: 'collectorsPage.tl.chart.acked', unitKey: 'collectorsPage.tl.unit.packets', color: '#3FB68B', xdp: true },
  { key: 'written', labelKey: 'collectorsPage.tl.chart.written', unitKey: 'collectorsPage.tl.unit.records', color: '#3FB68B', sflow: true },
  { key: 'lag', labelKey: 'collectorsPage.tl.chart.lag', unitKey: 'collectorsPage.tl.unit.segments', color: '#F0B400', lag: true },
];

function resolveChart(chart) {
  return {
    ...chart,
    label: collectorsT(chart.labelKey),
    unit: chart.unitKey ? collectorsT(chart.unitKey) : undefined,
  };
}

function incidentText(inc, field) {
  const code = inc?.code;
  const key = code ? `collectorsPage.tl.${code}${field === 'hint' ? '.hint' : ''}` : '';
  if (key && GrapesI18n.has(key)) return collectorsT(key);
  return field === 'hint' ? (inc?.hint || '') : (inc?.title || '');
}

function fmtPct(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return `${Number(value).toFixed(2)}%`;
}

function fmtSmallPct(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  if (n === 0) return '0%';
  if (n < 0.001) return '<0.001%';
  if (n < 1) return `${n.toFixed(3)}%`;
  return `${n.toFixed(2)}%`;
}

function fmtCompactCount(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)} ${collectorsT('unit.billion')}`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} ${collectorsT('unit.million')}`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)} ${collectorsT('unit.thousand')}`;
  return String(Math.round(n));
}

function fmtWhen(ms, withYear = false) {
  if (ms == null) return '—';
  return new Date(ms).toLocaleString(GrapesI18n.intlLocale(), {
    timeZone: getDisplayTimezone(),
    day: '2-digit',
    month: '2-digit',
    ...(withYear ? { year: 'numeric' } : {}),
    hour: '2-digit',
    minute: '2-digit',
  });
}

function fmtDuration(sec) {
  const s = Math.max(0, Math.round(Number(sec) || 0));
  if (s < 60) return collectorsT('collectorsPage.duration.lessThanMinute');
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (days > 0) return hours > 0
    ? collectorsT('collectorsPage.duration.daysHours', { days, hours })
    : collectorsT('collectorsPage.duration.days', { days });
  if (hours > 0) return minutes > 0
    ? collectorsT('collectorsPage.duration.hoursMinutes', { hours, minutes })
    : collectorsT('collectorsPage.duration.hours', { hours });
  return collectorsT('collectorsPage.duration.minutes', { minutes });
}

function completenessTone(pct) {
  if (pct == null) return '';
  if (pct >= 99) return 'completeness-tone-green';
  if (pct >= 90) return 'completeness-tone-yellow';
  return 'completeness-tone-red';
}

function localInputToMs(value) {
  if (!value) return null;
  return parseChartBucketMs(displayDatetimeLocalToData(value));
}

function msToLocalInput(ms) {
  return msToDatetimeLocalValue(ms, getDisplayTimezone());
}

function presetRange(presetId) {
  const preset = PERIOD_PRESETS.find((p) => p.id === presetId) || PERIOD_PRESETS[1];
  const toMs = Date.now();
  return { fromMs: toMs - preset.ms, toMs };
}

function zoomRange(startMs, endMs) {
  const now = Date.now();
  let from = startMs;
  let to = endMs;
  const span = to - from;
  const pad = Math.max(span * 0.25, 15 * 60000);
  from -= pad;
  to += pad;
  if (to - from < MIN_ZOOM_MS) {
    const mid = (startMs + endMs) / 2;
    from = mid - MIN_ZOOM_MS / 2;
    to = mid + MIN_ZOOM_MS / 2;
  }
  if (to > now) {
    from -= to - now;
    to = now;
  }
  return { fromMs: Math.round(from), toMs: Math.round(to) };
}

function visibleCharts(timeline) {
  const stages = new Set(timeline?.stages || []);
  const xdp = timeline?.inputUnit === 'packets';
  const summary = timeline?.summary || {};
  return CHARTS.filter((chart) => {
    if (chart.xdp && !xdp) return false;
    if (chart.sflow && xdp) return false;
    if (chart.stage && !stages.has(chart.stage) && !(Number(summary[chart.key]) > 0)) return false;
    if (chart.lag) return true;
    return true;
  }).map(resolveChart);
}

function PeriodBar({ preset, range, canGoBack, onPreset, onCustom, onBack, busy }) {
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');

  useEffect(() => {
    if (!range) return;
    setFrom(msToLocalInput(range.fromMs));
    setTo(msToLocalInput(range.toMs));
  }, [range?.fromMs, range?.toMs]);

  const apply = () => {
    const fromMs = localInputToMs(from);
    const toMs = localInputToMs(to);
    if (fromMs == null || toMs == null || toMs <= fromMs) return;
    onCustom({ fromMs, toMs: Math.min(toMs, Date.now()) });
  };

  return (
    <div className="collector-tl-period">
      <div className="seg">
        {PERIOD_PRESETS.map((p) => (
          <button
            key={p.id}
            type="button"
            className={preset === p.id ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => onPreset(p.id)}
            disabled={busy}
          >
            {collectorsT(p.labelKey)}
          </button>
        ))}
      </div>
      <label className="collector-tl-period__field">
        <span>{collectorsT('collectorsPage.tl.periodFrom')}</span>
        <input className="input" type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
      </label>
      <label className="collector-tl-period__field">
        <span>{collectorsT('collectorsPage.tl.periodTo')}</span>
        <input className="input" type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
      </label>
      <Button size="sm" onClick={apply} disabled={busy}>{collectorsT('collectorsPage.tl.show')}</Button>
      {canGoBack && (
        <Button size="sm" kind="ghost" icon="arrowL" onClick={onBack} disabled={busy}>{collectorsT('collectorsPage.tl.back')}</Button>
      )}
    </div>
  );
}

function PeriodStats({ timeline }) {
  const summary = timeline?.summary;
  if (!summary) return null;
  const stats = visibleCharts(timeline).filter((c) => !c.lag && !c.pct);
  return (
    <div className="collector-tl-stats">
      {stats.map((stat) => {
        const sub = statSubline(stat.key, summary);
        return (
          <div key={stat.key} className="collector-tl-stat">
            <div className="collector-tl-stat__label">{stat.label}</div>
            <div className="collector-tl-stat__value">
              {fmtCompactCount(summary[stat.key])}
              {stat.unit && <span className="collector-tl-stat__unit">{stat.unit}</span>}
            </div>
            {sub && <div className={`collector-tl-stat__sub ${sub.tone || ''}`}>{sub.text}</div>}
          </div>
        );
      })}
    </div>
  );
}

function statSubline(key, s) {
  if (key === 'phy' && s.phyDiscardPct != null) {
    return {
      text: collectorsT('collectorsPage.tl.stat.phyDiscard', {
        count: fmtCompactCount(s.phyDiscards),
        pct: fmtSmallPct(s.phyDiscardPct),
      }),
      tone: s.phyDiscards > 0 ? 'completeness-tone-yellow' : '',
    };
  }
  if (key === 'seen' && s.seenPctOfPhy != null) {
    return { text: collectorsT('collectorsPage.tl.stat.seenOfPhy', { pct: fmtPct(s.seenPctOfPhy) }) };
  }
  if (key === 'nfRecords' && s.nfPctOfFlows != null) {
    return {
      text: collectorsT('collectorsPage.tl.stat.nfOfFlows', {
        pct: fmtPct(s.nfPctOfFlows),
        count: fmtCompactCount(s.flowRecords),
      }),
      tone: completenessTone(s.nfPctOfFlows),
    };
  }
  if (key === 'acked' && s.completenessPct != null) {
    return {
      text: collectorsT('collectorsPage.tl.stat.completenessOfSeen', { pct: fmtPct(s.completenessPct) }),
      tone: completenessTone(s.completenessPct),
    };
  }
  return null;
}

function IncidentRow({ inc, onZoom }) {
  const also = inc.alsoCauses || [];
  const title = incidentText(inc, 'title');
  const hint = incidentText(inc, 'hint');
  return (
    <button type="button" className={`collector-tl-incident collector-tl-incident--${inc.severity}`} onClick={() => onZoom(inc.startMs, inc.endMs)}>
      <div className="collector-tl-incident__head">
        <b>{title}</b>
        <span className="collector-tl-incident__when">{fmtWhen(inc.startMs)} — {inc.ongoing ? collectorsT('collectorsPage.tl.now') : fmtWhen(inc.endMs)}</span>
        <span className="collector-tl-incident__dur">{fmtDuration(inc.durationSec)}</span>
      </div>
      {hint && <div className="collector-tl-incident__note">{hint}</div>}
      {also.length > 0 && (
        <div className="collector-tl-incident__note">
          {collectorsT('collectorsPage.tl.also', {
            list: also.map((c) => collectorsT('collectorsPage.tl.alsoItem', {
              title: incidentText(c, 'title').toLowerCase(),
              duration: fmtDuration(c.durationSec),
            })).join(', '),
          })}
        </div>
      )}
    </button>
  );
}

function IncidentList({ timeline, onZoom }) {
  const incidents = timeline?.incidents || [];
  if (!incidents.length) {
    return <div className="collector-tl-fold">{collectorsT('collectorsPage.tl.noIncidents')}</div>;
  }
  return (
    <details className="collector-tl-fold">
      <summary>{collectorsT('collectorsPage.tl.incidentCount', { n: incidents.length })}</summary>
      <div className="collector-tl-incidents">
        {incidents.map((inc) => (
          <IncidentRow key={inc.startMs} inc={inc} onZoom={onZoom} />
        ))}
      </div>
      {timeline?.truncated && (
        <div className="collector-tl-muted">{collectorsT('collectorsPage.tl.truncated')}</div>
      )}
    </details>
  );
}

function MetricCharts({ timeline, onRange }) {
  const cells = (timeline?.buckets || []).filter((c) => c.state !== 'none');
  if (!cells.length) return null;
  const bucketSec = timeline.bucketSeconds || 1;
  const points = cells.map((c) => ({
    bucketMs: c.startMs,
    completenessPct: c.completenessPct,
    phy: c.phy == null ? null : c.phy / bucketSec,
    seen: c.seen == null ? null : c.seen / bucketSec,
    input: c.input == null ? null : c.input / bucketSec,
    nfRecords: c.nfRecords == null ? null : c.nfRecords / bucketSec,
    acked: c.acked == null ? null : c.acked / bucketSec,
    written: c.written == null ? null : c.written / bucketSec,
    lag: c.lagSegmentsMax,
  }));
  const onRangeSelect = (range) => {
    const fromMs = localInputToMs(range.from);
    const toMs = localInputToMs(range.to);
    if (fromMs != null && toMs != null && toMs > fromMs) onRange({ fromMs, toMs });
  };
  return (
    <div className="collector-tl-charts">
      {visibleCharts(timeline).map((chart) => (
        <div key={chart.key}>
          <div className="collector-tl-chart-title">
            {chart.label}
            {chart.pct
              ? collectorsT('collectorsPage.tl.chartSmoothing', { duration: fmtDuration(timeline.completenessSmoothSec || 3600) })
              : chart.lag
                ? collectorsT('collectorsPage.tl.chartLagSuffix', { unit: chart.unit })
                : collectorsT('collectorsPage.tl.chartRateSuffix', { unit: chart.unit })}
          </div>
          <TimeSeriesSparkChart
            points={points}
            height={140}
            valueKey={chart.key}
            valueLabel={chart.label}
            color={chart.color}
            bucketSeconds={timeline.bucketSeconds}
            fillGaps={false}
            onRangeSelect={onRangeSelect}
            axisFormatter={chart.pct ? (v) => `${Math.round(Number(v) || 0)}%` : fmtCompact}
            formatValue={chart.pct ? fmtPct : (v) => fmtCompactCount(v)}
          />
        </div>
      ))}
    </div>
  );
}

function CollectorsCompletenessModal({ open, source, onClose }) {
  const [preset, setPreset] = useState('24h');
  const [range, setRange] = useState(null);
  const [stack, setStack] = useState([]);
  const [timeline, setTimeline] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!open || !source?.sourceId) {
      setTimeline(null);
      setError(null);
      setRange(null);
      setStack([]);
      return;
    }
    setPreset('24h');
    setStack([]);
    setRange(presetRange('24h'));
  }, [open, source?.sourceId]);

  useEffect(() => {
    if (!open || !source?.sourceId || !range) return undefined;
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      const res = await ApiClient.loadCollectorTimeline(source.sourceId, range.fromMs, range.toMs);
      if (cancelled) return;
      if (res.source === 'error') {
        setError(res.error || collectorsT('collectorsPage.tl.loadFailed'));
      } else {
        setTimeline(res.data);
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [open, source?.sourceId, range?.fromMs, range?.toMs]);

  const goTo = useCallback((next, nextPreset = 'custom') => {
    setStack((s) => (range ? [...s, { range, preset }] : s));
    setPreset(nextPreset);
    setRange(next);
  }, [range, preset]);

  const onZoom = useCallback((startMs, endMs) => goTo(zoomRange(startMs, endMs)), [goTo]);

  const onBack = () => {
    if (!stack.length) return;
    const prev = stack[stack.length - 1];
    setStack(stack.slice(0, -1));
    setPreset(prev.preset);
    setRange(prev.range);
  };

  if (!open || !source) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={collectorsT('collectorsPage.tl.modalTitle')}
      subtitle={range ? `${source.sourceId} · ${fmtWhen(range.fromMs, true)} — ${fmtWhen(range.toMs, true)}` : source.sourceId}
      size="xl"
      footer={<Button kind="ghost" onClick={onClose}>{collectorsT('modal.close')}</Button>}
    >
      <div className="completeness-modal-body">
        <PeriodBar
          preset={preset}
          range={range}
          canGoBack={stack.length > 0}
          busy={loading}
          onPreset={(id) => goTo(presetRange(id), id)}
          onCustom={(r) => goTo(r)}
          onBack={onBack}
        />

        {error && <div className="form-error">{error}</div>}
        {loading && !timeline && <div className="collector-tl-muted">{collectorsT('dashboard.loading')}</div>}

        {timeline && (
          <div className={loading ? 'collector-tl-body collector-tl-body--loading' : 'collector-tl-body'}>
            <IncidentList timeline={timeline} onZoom={onZoom} />
            <PeriodStats timeline={timeline} />
            <MetricCharts timeline={timeline} onRange={(r) => goTo(r)} />
          </div>
        )}
      </div>
    </Modal>
  );
}

Object.assign(window, { CollectorsCompletenessModal });
