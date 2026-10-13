/* DNS-запросы — анализ DNS-трафика из dns_log */

function dnsT(key, params) {
  return GrapesI18n.t(key, params);
}

const DNS_REFRESH_MS = 60_000;
const DNS_SHORT_RANGES = new Set(['30m', '1h', '3h', '6h']);
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

const DNS_CHART_LINES = [
  { key: 'qps', labelKey: 'dns.chart.line.requests', color: '#7E92F8' },
  { key: 'responses_per_sec', labelKey: 'dns.chart.line.allAnswers', tipKey: 'dns.chart.line.allAnswersTip', color: '#51D16D' },
  { key: 'nxdomain_per_sec', labelKey: 'dns.chart.line.domainNotFound', tipKey: 'dns.chart.line.domainNotFoundTip', color: '#F0B400' },
  { key: 'servfail_per_sec', labelKey: 'dns.chart.line.dnsServerError', tipKey: 'dns.chart.line.dnsServerErrorTip', color: '#F06B6B' },
];

function resolveDnsChartLine(ln) {
  return {
    ...ln,
    label: dnsT(ln.labelKey),
    tip: ln.tipKey ? dnsT(ln.tipKey) : undefined,
  };
}
const DNS_CHART_HEIGHT = 320;

const DNS_TOPS_SPLIT_KEY = 'grapes-dns-tops-split';
const DEFAULT_DNS_LEFT_SPLIT = 1 / 3;
const DEFAULT_DNS_MID_SPLIT = 1 / 3;
const DNS_TOPS_SPLIT_MIN = 0.15;
const DNS_TOPS_SPLITTER_WIDTH = 10;

function loadDnsTopsSplit() {
  try {
    const raw = localStorage.getItem(DNS_TOPS_SPLIT_KEY);
    if (!raw) return { left: DEFAULT_DNS_LEFT_SPLIT, mid: DEFAULT_DNS_MID_SPLIT };
    const parsed = JSON.parse(raw);
    const left = Number(parsed?.left);
    const mid = Number(parsed?.mid);
    if (!Number.isFinite(left) || !Number.isFinite(mid)) {
      return { left: DEFAULT_DNS_LEFT_SPLIT, mid: DEFAULT_DNS_MID_SPLIT };
    }
    return normalizeDnsTopsSplit(left, mid);
  } catch {
    return { left: DEFAULT_DNS_LEFT_SPLIT, mid: DEFAULT_DNS_MID_SPLIT };
  }
}

function saveDnsTopsSplit(left, mid) {
  try {
    localStorage.setItem(DNS_TOPS_SPLIT_KEY, JSON.stringify({ left, mid }));
  } catch { /* ignore */ }
}

function normalizeDnsTopsSplit(left, mid) {
  const min = DNS_TOPS_SPLIT_MIN;
  let l = Math.min(1 - min * 2, Math.max(min, left));
  let m = Math.min(1 - l - min, Math.max(min, mid));
  if (1 - l - m < min) m = Math.max(min, 1 - l - min);
  return { left: l, mid: m };
}

function clampDnsLeftSplit(left, mid) {
  const min = DNS_TOPS_SPLIT_MIN;
  return Math.min(1 - mid - min, Math.max(min, left));
}

function clampDnsMidSplit(left, mid) {
  const min = DNS_TOPS_SPLIT_MIN;
  return Math.min(1 - left - min, Math.max(min, mid));
}

function fmtDnsTipValue(n) {
  if (n == null || Number.isNaN(n)) return '—';
  const v = Number(n);
  if (v >= 1e9) return `${(v / 1e9).toFixed(1)} ${dnsT('unit.billion')}`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)} ${dnsT('unit.million')}`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)} ${dnsT('unit.thousand')}`;
  if (v >= 100) return String(Math.round(v));
  if (v >= 1) return v % 1 === 0 ? String(Math.round(v)) : v.toFixed(1);
  return v.toFixed(2);
}

function dnsErrorSeverity(errorPercent) {
  const v = Number(errorPercent) || 0;
  if (v >= 75) return 'critical';
  if (v >= 16) return 'warning';
  return null;
}

function dnsErrorRowClass(errorPercent) {
  const severity = dnsErrorSeverity(errorPercent);
  if (severity === 'critical') return 'dns-row--critical';
  if (severity === 'warning') return 'dns-row--warning';
  return '';
}

function dnsErrorPercentClass(errorPercent) {
  const severity = dnsErrorSeverity(errorPercent);
  if (severity === 'critical') return 'dns-error-pct--critical';
  if (severity === 'warning') return 'dns-error-pct--warning';
  return '';
}

function DnsErrorPercent({ value }) {
  const cls = dnsErrorPercentClass(value);
  return (
    <span className={cls ? `dns-error-pct ${cls}` : 'dns-error-pct'}>
      {value}%
    </span>
  );
}

function dnsEventTypeLabel(eventType) {
  if (eventType === 'response') return dnsT('dns.eventType.response');
  if (eventType === 'query') return dnsT('dns.eventType.query');
  return eventType || '—';
}

function dnsEventTypeTone(eventType) {
  if (eventType === 'response') return 'success';
  if (eventType === 'query') return 'info';
  return 'neutral';
}

const DNS_RCODE_TECH = {
  0: 'NOERROR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
};

function dnsRcodeTechLabel(rcode) {
  const n = Number(rcode);
  return DNS_RCODE_TECH[n] ?? String(rcode ?? '');
}

function dnsRcodeHumanLabel(rcode) {
  const n = Number(rcode);
  if (n === 0) return dnsT('dns.rcode.success');
  if (n === 2) return dnsT('dns.rcode.dnsServerError');
  if (n === 3) return dnsT('dns.rcode.domainNotFound');
  return dnsT('dns.rcode.other');
}

function dnsRcodeHumanTitle(rcode) {
  return dnsT('dns.rcode.titleWithTech', {
    label: dnsRcodeHumanLabel(rcode),
    tech: dnsRcodeTechLabel(rcode),
  });
}

function dnsRcodeTone(label, rcode) {
  const n = Number(rcode);
  const upper = String(label || '').toUpperCase();
  if (n === 0 || upper === 'NOERROR') return 'success';
  if (n === 3 || upper === 'NXDOMAIN') return 'warning';
  if (n === 2 || upper === 'SERVFAIL') return 'critical';
  return 'neutral';
}

function DnsEventTypeBadge({ eventType }) {
  return (
    <span className="dns-recent-badge">
      <Badge tone={dnsEventTypeTone(eventType)}>{dnsEventTypeLabel(eventType)}</Badge>
    </span>
  );
}

function DnsRcodeBadge({ rcode }) {
  const text = dnsRcodeHumanLabel(rcode);
  const title = dnsRcodeHumanTitle(rcode);
  return (
    <span className="dns-recent-badge" title={title}>
      <Badge tone={dnsRcodeTone(text, rcode)}>{text}</Badge>
    </span>
  );
}

function DnsIpCell({ ip, resolverLabel, isExternal, onClick, className }) {
  return (
    <span className={`dns-ip-cell${className ? ` ${className}` : ''}`}>
      {onClick ? (
        <button
          type="button"
          className="link-btn mono dns-recent-ip"
          onClick={onClick}
          title={dnsT('dns.openInExplorer')}
        >
          {ip}
        </button>
      ) : (
        <span className="mono dns-recent-ip">{ip}</span>
      )}
      {resolverLabel ? (
        <span className="dns-ip-cell__badge">
          <Badge tone="neutral">{resolverLabel}</Badge>
        </span>
      ) : null}
      {isExternal ? (
        <span className="dns-ip-cell__badge">
          <Badge tone="info">{dnsT('dns.badge.external')}</Badge>
        </span>
      ) : null}
    </span>
  );
}

function DnsHideResolversToggle({ checked, onChange }) {
  return (
    <label className="dns-hide-resolvers" title={dnsT('dns.hideResolversTitle')}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>{dnsT('dns.hideResolvers')}</span>
    </label>
  );
}

function openDnsExplorerDraft({ field, value, timeRange, customPeriod }) {
  location.hash = buildDnsExplorerDraftUrl({
    filters: [{ field, op: 'eq', value }],
    timeRange,
    customPeriod,
  });
}

function DnsLoadState({ children, style, className }) {
  return (
    <div className={`other-ports-table__state${className ? ` ${className}` : ''}`} style={style}>
      {children || dnsT('dashboard.loadFailed')}
    </div>
  );
}

function DnsEmptyState({ children, style, className }) {
  return (
    <div className={`other-ports-table__state${className ? ` ${className}` : ''}`} style={style}>
      {children || dnsT('dashboard.noDataPeriod')}
    </div>
  );
}

function dnsIsLongPeriod(timeRange, customPeriod) {
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    const span = customPeriodSpanMs(customPeriod);
    return span != null && span > SIX_HOURS_MS;
  }
  return !DNS_SHORT_RANGES.has(timeRange);
}

function dnsAggregateEmptyMessage() {
  return dnsT('dns.emptyAggregate');
}

function DnsTopsRow({ leftSplit, midSplit, onSplitChange, children }) {
  const rowRef = useRef(null);
  const clientsPaneRef = useRef(null);
  const domainsPaneRef = useRef(null);
  const serversPaneRef = useRef(null);
  const splitRef = useRef({ left: leftSplit, mid: midSplit });
  const isDraggingRef = useRef(false);
  const skipTransitionRef = useRef(true);
  const pendingDragRef = useRef(null);
  const rafRef = useRef(null);
  const childArray = React.Children.toArray(children);
  const clientsPane = childArray[0];
  const domainsPane = childArray[1];
  const serversPane = childArray[2];

  splitRef.current = { left: leftSplit, mid: midSplit };

  const paneRefs = [clientsPaneRef, domainsPaneRef, serversPaneRef];

  const clearPaneFlex = () => {
    paneRefs.forEach((ref) => ref.current?.style.removeProperty('flex'));
  };

  const applySplit = (left, mid, { live = false } = {}) => {
    const right = 1 - left - mid;
    rowRef.current?.style.setProperty('--dns-left-split', String(left));
    rowRef.current?.style.setProperty('--dns-mid-split', String(mid));
    rowRef.current?.style.setProperty('--dns-right-split', String(right));
    if (!live) {
      clearPaneFlex();
      return;
    }
    clientsPaneRef.current?.style.setProperty('flex', `${left} 1 0`);
    domainsPaneRef.current?.style.setProperty('flex', `${mid} 1 0`);
    serversPaneRef.current?.style.setProperty('flex', `${right} 1 0`);
  };

  useEffect(() => {
    if (isDraggingRef.current) return;
    const row = rowRef.current;
    if (!row) return;
    const normalized = normalizeDnsTopsSplit(leftSplit, midSplit);
    if (skipTransitionRef.current) {
      skipTransitionRef.current = false;
      row.classList.add('is-snapping');
      applySplit(normalized.left, normalized.mid);
      requestAnimationFrame(() => row.classList.remove('is-snapping'));
      return;
    }
    applySplit(normalized.left, normalized.mid);
  }, [leftSplit, midSplit]);

  const flexWidth = () => {
    const el = rowRef.current;
    if (!el) return 1;
    const rect = el.getBoundingClientRect();
    return Math.max(rect.width - 2 * DNS_TOPS_SPLITTER_WIDTH, 1);
  };

  const splitFromClientX = (which, clientX, dragStart) => {
    const el = rowRef.current;
    if (!el) return splitRef.current;
    const rect = el.getBoundingClientRect();
    const boundaryX = clientX - rect.left;
    const fraction = boundaryX / flexWidth();
    if (which === 1) {
      const left = clampDnsLeftSplit(fraction, dragStart.mid);
      return { left, mid: dragStart.mid };
    }
    const mid = clampDnsMidSplit(dragStart.left, fraction - dragStart.left);
    return { left: dragStart.left, mid };
  };

  const flushSplitUpdate = () => {
    rafRef.current = null;
    const pending = pendingDragRef.current;
    if (!pending) return;
    const next = splitFromClientX(pending.which, pending.clientX, pending.dragStart);
    const prev = splitRef.current;
    if (Math.abs(next.left - prev.left) < 0.001 && Math.abs(next.mid - prev.mid) < 0.001) return;
    splitRef.current = next;
    applySplit(next.left, next.mid, { live: true });
  };

  const scheduleSplitUpdate = (which, clientX, dragStart) => {
    pendingDragRef.current = { which, clientX, dragStart };
    if (rafRef.current != null) return;
    rafRef.current = requestAnimationFrame(flushSplitUpdate);
  };

  const stopDrag = (onMove, onUp) => {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    if (rafRef.current != null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    pendingDragRef.current = null;
    isDraggingRef.current = false;
    rowRef.current?.classList.remove('is-dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  };

  const onSplitterMouseDown = (which, e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    isDraggingRef.current = true;
    const dragStart = { ...splitRef.current };
    applySplit(dragStart.left, dragStart.mid, { live: true });

    const onMove = (ev) => scheduleSplitUpdate(which, ev.clientX, dragStart);

    const onUp = () => {
      flushSplitUpdate();
      stopDrag(onMove, onUp);
      applySplit(splitRef.current.left, splitRef.current.mid);
      if (
        Math.abs(splitRef.current.left - dragStart.left) >= 0.005
        || Math.abs(splitRef.current.mid - dragStart.mid) >= 0.005
      ) {
        onSplitChange(splitRef.current);
        saveDnsTopsSplit(splitRef.current.left, splitRef.current.mid);
      }
    };

    rowRef.current?.classList.add('is-dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  return (
    <div ref={rowRef} className="dns-tops-row">
      <div ref={clientsPaneRef} className="dns-tops-row__pane dns-tops-row__pane--clients">
        {clientsPane}
      </div>
      <div
        className="dns-tops-row__splitter"
        role="separator"
        aria-orientation="vertical"
        aria-valuenow={Math.round(leftSplit * 100)}
        aria-valuemin={Math.round(DNS_TOPS_SPLIT_MIN * 100)}
        aria-valuemax={Math.round((1 - midSplit - DNS_TOPS_SPLIT_MIN) * 100)}
        aria-label={dnsT('dns.splitter.clientsWidth')}
        tabIndex={0}
        onMouseDown={(e) => onSplitterMouseDown(1, e)}
      />
      <div ref={domainsPaneRef} className="dns-tops-row__pane dns-tops-row__pane--domains">
        {domainsPane}
      </div>
      <div
        className="dns-tops-row__splitter"
        role="separator"
        aria-orientation="vertical"
        aria-valuenow={Math.round((leftSplit + midSplit) * 100)}
        aria-valuemin={Math.round((leftSplit + DNS_TOPS_SPLIT_MIN) * 100)}
        aria-valuemax={Math.round((1 - DNS_TOPS_SPLIT_MIN) * 100)}
        aria-label={dnsT('dns.splitter.domainsWidth')}
        tabIndex={0}
        onMouseDown={(e) => onSplitterMouseDown(2, e)}
      />
      <div ref={serversPaneRef} className="dns-tops-row__pane dns-tops-row__pane--servers">
        {serversPane}
      </div>
    </div>
  );
}

function formatDnsBucketLabel(bucket) {
  if (!bucket) return '—';
  const d = new Date(bucket);
  if (Number.isNaN(d.getTime())) {
    const m = String(bucket).match(/(\d{2}):(\d{2})/);
    return m ? `${m[1]}:${m[2]}` : String(bucket);
  }
  return d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}

function formatDnsAnswers(row) {
  const parts = [];
  if (row.answersA?.length) parts.push(...row.answersA);
  if (row.answersAaaa?.length) parts.push(...row.answersAaaa);
  if (row.answersCname?.length) parts.push(...row.answersCname.map((c) => `CNAME ${c}`));
  return parts.length ? parts.join(', ') : '—';
}

function formatDnsTs(ts, displayTimezone = getDisplayTimezone()) {
  if (!ts) return '—';
  const text = String(ts).replace('T', ' ').trim().slice(0, 19);
  const ms = typeof parseChartBucketMs === 'function'
    ? parseChartBucketMs(text)
    : Date.parse(`${text.replace(' ', 'T')}Z`);
  if (ms == null || !Number.isFinite(ms)) return String(ts);
  return new Date(ms).toLocaleString(GrapesI18n.intlLocale(), {
    timeZone: displayTimezone || getDisplayTimezone(),
    day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function PageDnsQueries({ onNavigate, timeRange, customPeriod, collectorFilter, displayTimezone, onChartRangeSelect }) {
  const [hideResolvers, setHideResolvers] = useState(true);
  const [topsSplit, setTopsSplit] = useState(() => loadDnsTopsSplit());

  const [activityRows, setActivityRows] = useState([]);
  const [activitySource, setActivitySource] = useState('loading');
  const [activityMeta, setActivityMeta] = useState(null);
  const [activityLoadMs, setActivityLoadMs] = useState(null);
  const [activityServerMs, setActivityServerMs] = useState(null);
  const [chartHidden, setChartHidden] = useState(() => new Set());

  const [topDomains, setTopDomains] = useState([]);
  const [topDomainsSource, setTopDomainsSource] = useState('loading');
  const [topDomainsMeta, setTopDomainsMeta] = useState(null);
  const [topDomainsLoadMs, setTopDomainsLoadMs] = useState(null);
  const [topDomainsServerMs, setTopDomainsServerMs] = useState(null);

  const [topClients, setTopClients] = useState([]);
  const [topClientsSource, setTopClientsSource] = useState('loading');
  const [topClientsMeta, setTopClientsMeta] = useState(null);
  const [topClientsLoadMs, setTopClientsLoadMs] = useState(null);
  const [topClientsServerMs, setTopClientsServerMs] = useState(null);

  const [topServers, setTopServers] = useState([]);
  const [topServersSource, setTopServersSource] = useState('loading');
  const [topServersMeta, setTopServersMeta] = useState(null);
  const [topServersLoadMs, setTopServersLoadMs] = useState(null);
  const [topServersServerMs, setTopServersServerMs] = useState(null);

  const [recentRows, setRecentRows] = useState([]);
  const [recentSource, setRecentSource] = useState('loading');
  const [recentMeta, setRecentMeta] = useState(null);
  const [recentLoadMs, setRecentLoadMs] = useState(null);
  const [recentServerMs, setRecentServerMs] = useState(null);

  const periodLabel = timeRangeLabel(timeRange, customPeriod);
  const chartLongRange = isLongChartRange(timeRange, customPeriod);
  const collectorFilterKey = (collectorFilter || []).join(',');
  const overviewFilters = useMemo(() => ({
    timeRange,
    customPeriod,
    collectorFilter: collectorFilterKey ? collectorFilter : undefined,
  }), [timeRange, customPeriod?.from, customPeriod?.to, collectorFilterKey, collectorFilter]);

  const topClientsFilters = useMemo(() => ({
    ...overviewFilters,
    hideResolvers,
  }), [overviewFilters, hideResolvers]);

  const recentFilters = useMemo(() => ({
    ...overviewFilters,
    limit: 50,
  }), [overviewFilters]);

  useEffect(() => {
    let cancelled = false;
    const load = (initial) => {
      if (initial) setActivitySource('loading');
      ApiClient.loadDnsActivity(overviewFilters).then((r) => {
        if (!cancelled) {
          setActivityRows(Array.isArray(r.rows) ? r.rows : []);
          setActivityMeta(r.meta ?? null);
          setActivitySource(r.source || 'error');
          setActivityLoadMs(r.loadMs ?? null);
          setActivityServerMs(r.serverMs ?? null);
        }
      });
    };
    load(true);
    const timer = setInterval(() => load(false), DNS_REFRESH_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, [overviewFilters]);

  useEffect(() => {
    let cancelled = false;
    setTopDomainsSource('loading');
    ApiClient.loadDnsTopDomains(overviewFilters).then((r) => {
      if (!cancelled) {
        setTopDomains((Array.isArray(r.rows) ? r.rows : []).map((row, i) => ({
          ...row,
          _id: `${row.queryName}|${row.qtype}|${i}`,
        })));
        setTopDomainsMeta(r.meta ?? null);
        setTopDomainsSource(r.source || 'error');
        setTopDomainsLoadMs(r.loadMs ?? null);
        setTopDomainsServerMs(r.serverMs ?? null);
      }
    });
    return () => { cancelled = true; };
  }, [overviewFilters]);

  useEffect(() => {
    let cancelled = false;
    setTopClientsSource('loading');
    ApiClient.loadDnsTopClients(topClientsFilters).then((r) => {
      if (!cancelled) {
        setTopClients(Array.isArray(r.rows) ? r.rows : []);
        setTopClientsMeta(r.meta ?? null);
        setTopClientsSource(r.source || 'error');
        setTopClientsLoadMs(r.loadMs ?? null);
        setTopClientsServerMs(r.serverMs ?? null);
      }
    });
    return () => { cancelled = true; };
  }, [topClientsFilters]);

  useEffect(() => {
    let cancelled = false;
    setTopServersSource('loading');
    ApiClient.loadDnsTopServers(overviewFilters).then((r) => {
      if (!cancelled) {
        setTopServers(Array.isArray(r.rows) ? r.rows : []);
        setTopServersMeta(r.meta ?? null);
        setTopServersSource(r.source || 'error');
        setTopServersLoadMs(r.loadMs ?? null);
        setTopServersServerMs(r.serverMs ?? null);
      }
    });
    return () => { cancelled = true; };
  }, [overviewFilters]);

  useEffect(() => {
    let cancelled = false;
    const load = (initial) => {
      if (initial) setRecentSource('loading');
      ApiClient.loadDnsRecent(recentFilters).then((r) => {
        if (!cancelled) {
          setRecentRows((Array.isArray(r.rows) ? r.rows : []).map((row, i) => ({
            ...row,
            _id: `${row.eventTime}|${row.client}|${i}`,
          })));
          setRecentMeta(r.meta ?? null);
          setRecentSource(r.source || 'error');
          setRecentLoadMs(r.loadMs ?? null);
          setRecentServerMs(r.serverMs ?? null);
        }
      });
    };
    load(true);
    const timer = setInterval(() => load(false), DNS_REFRESH_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, [recentFilters]);

  const chartPoints = useMemo(() => activityRows.map((row) => {
    const bucket = normalizeBucketString(row.bucket);
    return {
      bucket,
      bucketMs: row.bucketMs != null ? Number(row.bucketMs) : null,
      t: formatPointTimeLabel({ bucket, bucketMs: row.bucketMs != null ? Number(row.bucketMs) : null }, chartLongRange, displayTimezone),
      qps: row.qps,
      responses_per_sec: row.responsesPerSec,
      nxdomain_per_sec: row.nxdomainPerSec,
      servfail_per_sec: row.servfailPerSec,
      _raw: row,
    };
  }), [activityRows, chartLongRange, displayTimezone]);

  const dnsChartBucketSeconds = dnsBucketSecondsFromMode(activityMeta?.bucketMode);

  const chartLines = DNS_CHART_LINES.map(resolveDnsChartLine);
  const visibleChartLines = chartLines.filter((ln) => !chartHidden.has(ln.key));

  const toggleChartSeries = (key) => {
    setChartHidden((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const recentSub = dnsT('dns.recentSub', { period: periodLabel });

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{dnsT('nav.item.dns')}</h1>
          <p>{dnsT('dns.subtitle')} · {periodLabel}</p>
        </div>
      </div>

      <Card className="dns-chart-card">
        <div className="dns-chart-card__head">
          <div className="dns-chart-card__titles">
            <div className="dns-chart-card__title">{dnsT('dns.chart.title')}</div>
            <div className="dns-chart-card__sub">{periodLabel} · {dnsT('dns.chart.rateUnit')}</div>
          </div>
          <WidgetLoadBadge loadMs={activityLoadMs} serverMs={activityServerMs} />
        </div>
        <div className="dns-chart-card__legend chart-legend">
          {chartLines.map((ln) => {
            const off = chartHidden.has(ln.key);
            return (
              <button
                key={ln.key}
                type="button"
                className={`chart-legend__item${off ? ' is-off' : ''}`}
                aria-pressed={!off}
                title={ln.tip || (off ? dnsT('dashboard.chart.legend.show') : dnsT('dashboard.chart.legend.hide'))}
                onClick={() => toggleChartSeries(ln.key)}
              >
                <span
                  className="chart-legend__swatch dns-chart-card__swatch"
                  style={{ background: ln.color, opacity: off ? 0.35 : 1 }}
                />
                {ln.label}
              </button>
            );
          })}
        </div>
        <div className="dns-chart-card__hint">
          <Icon name="info" size={12} />
          {dnsT('dns.chart.hint')}
          {onChartRangeSelect ? dnsT('dashboard.chart.selectRangeSuffix') : ''}
          {dnsT('dashboard.chart.autoRefreshWithHint')}
        </div>
        {activitySource === 'error' ? (
          <DnsLoadState className="dns-chart-card__state" />
        ) : activitySource === 'loading' ? (
          <div className="skeleton dns-chart-card__state" />
        ) : activityRows.length === 0 && activityMeta?.dataTier === 'aggregate' ? (
          <DnsEmptyState className="dns-chart-card__state">{dnsAggregateEmptyMessage()}</DnsEmptyState>
        ) : (
          <div className="dns-chart-card__plot">
            <DualChart
              points={chartPoints}
              lines={visibleChartLines}
              height={DNS_CHART_HEIGHT}
              mode="bw"
              onRangeSelect={onChartRangeSelect}
              bucketSeconds={dnsChartBucketSeconds}
              displayTimezone={displayTimezone}
              valueFormatter={fmtDnsTipValue}
              axisFormatter={fmtCompact}
              tipUnitLabel={dnsT('dns.chart.rateUnit')}
            />
          </div>
        )}
      </Card>

      <DnsTopsRow
        leftSplit={topsSplit.left}
        midSplit={topsSplit.mid}
        onSplitChange={setTopsSplit}
      >
        <Card className="dns-top-card">
          <div className="dns-card-head">
            <div>
              <div className="dns-card-head__title">{dnsT('dns.table.querySources')}</div>
              <div className="dns-card-head__sub">{periodLabel}</div>
            </div>
            <WidgetLoadBadge loadMs={topClientsLoadMs} serverMs={topClientsServerMs} />
          </div>
          <div className="dns-top-card__toolbar">
            <DnsHideResolversToggle checked={hideResolvers} onChange={setHideResolvers} />
            <Button kind="ghost" size="sm" onClick={() => onNavigate?.('dns-resolvers')}>{dnsT('dns.configureList')}</Button>
          </div>
          {topClientsSource === 'error' ? (
            <DnsLoadState />
          ) : topClientsSource === 'loading' ? (
            <div className="skeleton" style={{ height: 200 }} />
          ) : topClients.length === 0 && topClientsMeta?.dataTier === 'aggregate' ? (
            <DnsEmptyState>{dnsAggregateEmptyMessage()}</DnsEmptyState>
          ) : (
            <div className="dns-top-card__body">
            <DataTable
              rows={topClients}
              rowKey="client"
              dense
              pageSize={10}
              resizableColumns={false}
              columns={[
                {
                  key: 'client',
                  title: dnsT('dns.col.ipAddress'),
                  render: (row) => (
                    <DnsIpCell
                      ip={row.client}
                      resolverLabel={row.resolverLabel}
                      isExternal={row.isExternal}
                      onClick={() => openDnsExplorerDraft({
                        field: 'client_ip',
                        value: row.client,
                        timeRange,
                        customPeriod,
                      })}
                    />
                  ),
                },
                { key: 'queries', title: dnsT('dns.col.queries'), align: 'right', num: true, render: (r) => fmtNum(r.queries) },
                { key: 'uniqueDomains', title: dnsT('dns.col.uniqueDomains'), align: 'right', num: true, render: (r) => fmtNum(r.uniqueDomains) },
                { key: 'nxdomain', title: dnsT('dns.col.notFound'), align: 'right', num: true, render: (r) => fmtNum(r.nxdomain) },
                { key: 'servfail', title: dnsT('dns.col.dnsFailures'), align: 'right', num: true, render: (r) => fmtNum(r.servfail) },
                {
                  key: 'errorPercent',
                  title: dnsT('dns.col.dnsFailuresPct'),
                  align: 'right',
                  render: (r) => <DnsErrorPercent value={r.errorPercent} />,
                },
              ]}
              getRowClassName={(row) => dnsErrorRowClass(row.errorPercent)}
            />
            </div>
          )}
        </Card>

        <Card className="dns-top-card">
          <div className="dns-card-head">
            <div>
              <div className="dns-card-head__title">{dnsT('dns.table.domains')}</div>
              <div className="dns-card-head__sub">{periodLabel}</div>
            </div>
            <WidgetLoadBadge loadMs={topDomainsLoadMs} serverMs={topDomainsServerMs} />
          </div>
          {topDomainsSource === 'error' ? (
            <DnsLoadState />
          ) : topDomainsSource === 'loading' ? (
            <div className="skeleton" style={{ height: 200 }} />
          ) : topDomains.length === 0 && topDomainsMeta?.dataTier === 'aggregate' ? (
            <DnsEmptyState>{dnsAggregateEmptyMessage()}</DnsEmptyState>
          ) : (
            <div className="dns-top-card__body">
            <DataTable
              rows={topDomains}
              rowKey="_id"
              dense
              pageSize={10}
              resizableColumns={false}
              columns={[
                {
                  key: 'queryName',
                  title: dnsT('dns.col.domain'),
                  render: (row) => (
                    <button
                      type="button"
                      className="link-btn dns-table-domain"
                      onClick={() => openDnsExplorerDraft({
                        field: 'query_name',
                        value: row.queryName,
                        timeRange,
                        customPeriod,
                      })}
                      title={dnsT('dns.openInExplorer')}
                    >
                      {row.queryName}
                    </button>
                  ),
                },
                { key: 'qtype', title: 'QTYPE' },
                { key: 'queries', title: dnsT('dns.col.queries'), align: 'right', num: true, render: (r) => fmtNum(r.queries) },
                { key: 'responses', title: dnsT('dns.col.responses'), align: 'right', num: true, render: (r) => fmtNum(r.responses) },
                { key: 'nxdomain', title: dnsT('dns.col.notFound'), align: 'right', num: true, render: (r) => fmtNum(r.nxdomain) },
                { key: 'servfail', title: dnsT('dns.col.dnsFailures'), align: 'right', num: true, render: (r) => fmtNum(r.servfail) },
                {
                  key: 'errorPercent',
                  title: dnsT('dns.col.dnsFailuresPct'),
                  align: 'right',
                  render: (r) => <DnsErrorPercent value={r.errorPercent} />,
                },
              ]}
              getRowClassName={(row) => dnsErrorRowClass(row.errorPercent)}
            />
            </div>
          )}
        </Card>

        <Card className="dns-top-card">
          <div className="dns-card-head">
            <div>
              <div className="dns-card-head__title">{dnsT('dns.table.dnsServers')}</div>
              <div className="dns-card-head__sub">{periodLabel}</div>
            </div>
            <WidgetLoadBadge loadMs={topServersLoadMs} serverMs={topServersServerMs} />
          </div>
          {topServersSource === 'error' ? (
            <DnsLoadState />
          ) : topServersSource === 'loading' ? (
            <div className="skeleton" style={{ height: 200 }} />
          ) : topServers.length === 0 && topServersMeta?.dataTier === 'aggregate' ? (
            <DnsEmptyState>{dnsAggregateEmptyMessage()}</DnsEmptyState>
          ) : (
            <div className="dns-top-card__body">
            <DataTable
              rows={topServers}
              rowKey="server"
              dense
              pageSize={10}
              resizableColumns={false}
              columns={[
                {
                  key: 'server',
                  title: dnsT('dns.col.ipAddress'),
                  render: (row) => (
                    <DnsIpCell
                      ip={row.server}
                      resolverLabel={row.resolverLabel}
                      isExternal={row.isExternal}
                      onClick={() => openDnsExplorerDraft({
                        field: 'server_ip',
                        value: row.server,
                        timeRange,
                        customPeriod,
                      })}
                    />
                  ),
                },
                { key: 'queries', title: dnsT('dns.col.queries'), align: 'right', num: true, render: (r) => fmtNum(r.queries) },
                { key: 'responses', title: dnsT('dns.col.responses'), align: 'right', num: true, render: (r) => fmtNum(r.responses) },
                { key: 'nxdomain', title: dnsT('dns.col.notFound'), align: 'right', num: true, render: (r) => fmtNum(r.nxdomain) },
                { key: 'servfail', title: dnsT('dns.col.dnsFailures'), align: 'right', num: true, render: (r) => fmtNum(r.servfail) },
                {
                  key: 'errorPercent',
                  title: dnsT('dns.col.dnsFailuresPct'),
                  align: 'right',
                  render: (r) => <DnsErrorPercent value={r.errorPercent} />,
                },
              ]}
              getRowClassName={(row) => dnsErrorRowClass(row.errorPercent)}
            />
            </div>
          )}
        </Card>
      </DnsTopsRow>

      <Card className="dns-recent-card">
        <div className="dns-card-head">
          <div>
            <div className="dns-card-head__title">{dnsT('dns.table.recentEvents')}</div>
            <div className="dns-card-head__sub">{recentSub}</div>
          </div>
          <WidgetLoadBadge loadMs={recentLoadMs} serverMs={recentServerMs} />
        </div>
        {recentSource === 'error' ? (
          <DnsLoadState />
        ) : (
          <div className="dns-recent-card__body">
            <DataTable
              rows={recentRows}
              rowKey="_id"
              dense
              pageSize={15}
              resizableColumns={false}
              columns={[
                {
                  key: 'eventTime',
                  title: dnsT('dns.col.time'),
                  width: 150,
                  render: (r) => <span className="mono dns-recent-time">{formatDnsTs(r.eventTime, displayTimezone)}</span>,
                },
                {
                  key: 'eventType',
                  title: dnsT('dns.col.type'),
                  width: 88,
                  sortable: false,
                  render: (r) => <DnsEventTypeBadge eventType={r.eventType} />,
                },
                {
                  key: 'client',
                  title: dnsT('dns.col.client'),
                  width: 180,
                  render: (r) => (
                    <DnsIpCell
                      ip={r.client}
                      resolverLabel={r.clientBadges?.resolverLabel}
                      isExternal={r.clientBadges?.isExternal}
                    />
                  ),
                },
                {
                  key: 'server',
                  title: dnsT('dns.col.dnsServer'),
                  width: 180,
                  render: (r) => (
                    <DnsIpCell
                      ip={r.server}
                      resolverLabel={r.serverBadges?.resolverLabel}
                      isExternal={r.serverBadges?.isExternal}
                    />
                  ),
                },
                {
                  key: 'queryName',
                  title: dnsT('dns.col.domain'),
                  render: (r) => (
                    <span className="dns-table-domain dns-recent-domain" title={r.queryName || '—'}>
                      {r.queryName || '—'}
                    </span>
                  ),
                },
                { key: 'qtype', title: dnsT('dns.col.queryType'), width: 88 },
                {
                  key: 'rcodeLabel',
                  title: dnsT('dns.col.responseResult'),
                  width: 140,
                  sortable: false,
                  render: (r) => <DnsRcodeBadge rcode={r.rcode} />,
                },
                {
                  key: 'answers',
                  title: dnsT('dns.col.answers'),
                  render: (r) => {
                    const text = formatDnsAnswers(r);
                    return (
                      <span className="dns-table-domain dns-recent-answers" title={text}>
                        {text}
                      </span>
                    );
                  },
                },
              ]}
            />
          </div>
        )}
      </Card>
    </div>
  );
}

Object.assign(window, { PageDnsQueries });
