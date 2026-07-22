/* DNS-запросы — анализ DNS-трафика из dns_log */

const DNS_REFRESH_MS = 60_000;
const LOAD_FAILED = 'Не удалось загрузить';
const DNS_SHORT_RANGES = new Set(['30m', '1h', '3h', '6h']);
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

const DNS_CHART_LINES = [
  { key: 'qps', label: 'Запросы', color: '#7E92F8' },
  { key: 'responses_per_sec', label: 'Ответы', color: '#51D16D' },
  { key: 'nxdomain_per_sec', label: 'NXDOMAIN', color: '#F0B400' },
  { key: 'servfail_per_sec', label: 'SERVFAIL', color: '#F06B6B' },
];
const DNS_CHART_HEIGHT = 320;

function fmtDnsTipValue(n) {
  if (n == null || Number.isNaN(n)) return '—';
  const v = Number(n);
  if (v >= 1e9) return `${(v / 1e9).toFixed(1)} млрд`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)} млн`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)} тыс`;
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
  if (eventType === 'response') return 'Ответ';
  if (eventType === 'query') return 'Запрос';
  return eventType || '—';
}

function dnsEventTypeTone(eventType) {
  if (eventType === 'response') return 'success';
  if (eventType === 'query') return 'info';
  return 'neutral';
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

function DnsRcodeBadge({ label, rcode }) {
  const text = label || '—';
  return (
    <span className="dns-recent-badge">
      <Badge tone={dnsRcodeTone(label, rcode)}>{text}</Badge>
    </span>
  );
}

const RCODE_FILTER_OPTS = [
  { value: '', label: 'Все RCODE' },
  { value: '0', label: 'NOERROR' },
  { value: '2', label: 'SERVFAIL' },
  { value: '3', label: 'NXDOMAIN' },
];

function DnsLoadState({ children, style, className }) {
  return (
    <div className={`other-ports-table__state${className ? ` ${className}` : ''}`} style={style}>
      {children || LOAD_FAILED}
    </div>
  );
}

function DnsEmptyState({ children, style, className }) {
  return (
    <div className={`other-ports-table__state${className ? ` ${className}` : ''}`} style={style}>
      {children || 'Нет данных за выбранный период'}
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
  return 'Нет данных в агрегатах за выбранный период. Возможно, агрегация ещё не выполнена.';
}

function useDebouncedValue(value, delay = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
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

function formatDnsTs(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString('ru-RU', {
    day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function PageDnsQueries({ onNavigate, timeRange, customPeriod, collectorFilter, displayTimezone, onChartRangeSelect }) {
  const [qtype, setQtype] = useState('');
  const [rcode, setRcode] = useState('');
  const [domainSearch, setDomainSearch] = useState('');
  const [clientIp, setClientIp] = useState('');
  const [domainDraft, setDomainDraft] = useState('');
  const [clientIpDraft, setClientIpDraft] = useState('');

  const [qtypeOpts, setQtypeOpts] = useState([]);

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

  const [recentRows, setRecentRows] = useState([]);
  const [recentSource, setRecentSource] = useState('loading');
  const [recentMeta, setRecentMeta] = useState(null);
  const [recentLoadMs, setRecentLoadMs] = useState(null);
  const [recentServerMs, setRecentServerMs] = useState(null);

  const debouncedDomain = useDebouncedValue(domainDraft, 300);
  const debouncedClientIp = useDebouncedValue(clientIpDraft, 300);

  useEffect(() => { setDomainSearch(debouncedDomain.trim()); }, [debouncedDomain]);
  useEffect(() => { setClientIp(debouncedClientIp.trim()); }, [debouncedClientIp]);

  const periodLabel = timeRangeLabel(timeRange, customPeriod);
  const chartLongRange = isLongChartRange(timeRange, customPeriod);
  const collectorFilterKey = (collectorFilter || []).join(',');
  const apiFilters = useMemo(() => ({
    timeRange,
    customPeriod,
    collectorFilter: collectorFilterKey ? collectorFilter : undefined,
    qtype: qtype || undefined,
    rcode: rcode !== '' ? Number(rcode) : undefined,
    domainSearch: domainSearch || undefined,
    clientIp: clientIp || undefined,
  }), [timeRange, customPeriod?.from, customPeriod?.to, collectorFilterKey, collectorFilter, qtype, rcode, domainSearch, clientIp]);

  useEffect(() => {
    let cancelled = false;
    ApiClient.loadDnsQtypes(apiFilters).then((r) => {
      if (!cancelled) {
        setQtypeOpts(Array.isArray(r.rows) ? r.rows : []);
      }
    });
    return () => { cancelled = true; };
  }, [apiFilters]);

  useEffect(() => {
    let cancelled = false;
    const load = (initial) => {
      if (initial) setActivitySource('loading');
      ApiClient.loadDnsActivity(apiFilters).then((r) => {
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
  }, [apiFilters]);

  useEffect(() => {
    let cancelled = false;
    setTopDomainsSource('loading');
    ApiClient.loadDnsTopDomains(apiFilters).then((r) => {
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
  }, [apiFilters]);

  useEffect(() => {
    let cancelled = false;
    setTopClientsSource('loading');
    ApiClient.loadDnsTopClients(apiFilters).then((r) => {
      if (!cancelled) {
        setTopClients(Array.isArray(r.rows) ? r.rows : []);
        setTopClientsMeta(r.meta ?? null);
        setTopClientsSource(r.source || 'error');
        setTopClientsLoadMs(r.loadMs ?? null);
        setTopClientsServerMs(r.serverMs ?? null);
      }
    });
    return () => { cancelled = true; };
  }, [apiFilters]);

  useEffect(() => {
    let cancelled = false;
    const load = (initial) => {
      if (initial) setRecentSource('loading');
      ApiClient.loadDnsRecent(apiFilters).then((r) => {
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
  }, [apiFilters]);

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

  const visibleChartLines = DNS_CHART_LINES.filter((ln) => !chartHidden.has(ln.key));

  const toggleChartSeries = (key) => {
    setChartHidden((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const clearFilters = () => {
    setQtype('');
    setRcode('');
    setDomainDraft('');
    setClientIpDraft('');
  };

  const hasActiveFilters = qtype || rcode !== '' || domainDraft || clientIpDraft;

  const recentForced30m = recentMeta?.recentWindow === '30m' && dnsIsLongPeriod(timeRange, customPeriod);
  const recentSub = recentForced30m
    ? 'Показаны последние 30 минут (ограничение для производительности). Укажите IP клиента или домен для поиска за весь период'
    : `Последние события · ${periodLabel}`;

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>DNS-запросы</h1>
          <p>Анализ DNS-активности, топ доменов и клиентов · {periodLabel}</p>
        </div>
      </div>

      <Card style={{ marginBottom: 16 }}>
        <div className="dns-filters">
          <div className="dns-filters__group">
            <label className="dns-filters__label" htmlFor="dns-qtype">QTYPE</label>
            <select id="dns-qtype" className="input" value={qtype} onChange={(e) => setQtype(e.target.value)}>
              <option value="">Все типы</option>
              {qtypeOpts.map((o) => (
                <option key={o.qtype} value={o.qtype}>{o.qtype} ({fmtNum(o.rows)})</option>
              ))}
            </select>
          </div>

          <div className="dns-filters__group">
            <label className="dns-filters__label" htmlFor="dns-rcode">RCODE</label>
            <select id="dns-rcode" className="input" value={rcode} onChange={(e) => setRcode(e.target.value)}>
              {RCODE_FILTER_OPTS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>

          <div className="dns-filters__group">
            <label className="dns-filters__label" htmlFor="dns-domain">Поиск домена</label>
            <div className="input-wrap">
              <Icon name="search" size={14} />
              <input
                id="dns-domain"
                className="input input--with-icon"
                placeholder="cisco.com"
                value={domainDraft}
                onChange={(e) => setDomainDraft(e.target.value)}
              />
            </div>
          </div>

          <div className="dns-filters__group">
            <label className="dns-filters__label" htmlFor="dns-client">Client IP</label>
            <input
              id="dns-client"
              className="input"
              placeholder="188.143.128.3"
              value={clientIpDraft}
              onChange={(e) => setClientIpDraft(e.target.value)}
            />
          </div>

          {hasActiveFilters && (
            <div className="dns-filters__group dns-filters__group--actions">
              <Button kind="ghost" size="sm" onClick={clearFilters}>Сбросить фильтры</Button>
            </div>
          )}
        </div>
      </Card>

      <Card className="dns-chart-card">
        <div className="dns-chart-card__head">
          <div className="dns-chart-card__titles">
            <div className="dns-chart-card__title">Активность DNS</div>
            <div className="dns-chart-card__sub">{periodLabel} · запр./с</div>
          </div>
          <WidgetLoadBadge loadMs={activityLoadMs} serverMs={activityServerMs} />
        </div>
        <div className="dns-chart-card__legend chart-legend">
          {DNS_CHART_LINES.map((ln) => {
            const off = chartHidden.has(ln.key);
            return (
              <button
                key={ln.key}
                type="button"
                className={`chart-legend__item${off ? ' is-off' : ''}`}
                aria-pressed={!off}
                title={off ? 'Показать на графике' : 'Скрыть с графика'}
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
          {onChartRangeSelect ? 'Выделите диапазон на графике · авто-обновление каждую минуту' : 'Авто-обновление каждую минуту'}
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
              tipUnitLabel="запр./с"
            />
          </div>
        )}
      </Card>

      <div className="dns-tops-grid">
        <Card className="dns-top-card">
          <div className="dns-card-head">
            <div>
              <div className="dns-card-head__title">Топ доменов</div>
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
              columns={[
                {
                  key: 'queryName',
                  title: 'Домен',
                  render: (row) => (
                    <button
                      type="button"
                      className="link-btn dns-table-domain"
                      onClick={() => setDomainDraft(row.queryName)}
                      title="Фильтровать по этому домену"
                    >
                      {row.queryName}
                    </button>
                  ),
                },
                { key: 'qtype', title: 'QTYPE' },
                { key: 'queries', title: 'Запросы', align: 'right', num: true, render: (r) => fmtNum(r.queries) },
                { key: 'responses', title: 'Ответы', align: 'right', num: true, render: (r) => fmtNum(r.responses) },
                { key: 'nxdomain', title: 'NXDOMAIN', align: 'right', num: true, render: (r) => fmtNum(r.nxdomain) },
                { key: 'servfail', title: 'SERVFAIL', align: 'right', num: true, render: (r) => fmtNum(r.servfail) },
                {
                  key: 'errorPercent',
                  title: 'Ошибки, %',
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
              <div className="dns-card-head__title">Топ клиентов</div>
              <div className="dns-card-head__sub">{periodLabel}</div>
            </div>
            <WidgetLoadBadge loadMs={topClientsLoadMs} serverMs={topClientsServerMs} />
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
              columns={[
                {
                  key: 'client',
                  title: 'IP клиента',
                  render: (row) => (
                    <button
                      type="button"
                      className="link-btn mono"
                      onClick={() => setClientIpDraft(row.client)}
                      title="Фильтровать по этому IP"
                    >
                      {row.client}
                    </button>
                  ),
                },
                { key: 'queries', title: 'Запросы', align: 'right', num: true, render: (r) => fmtNum(r.queries) },
                { key: 'uniqueDomains', title: 'Уникальные домены', align: 'right', num: true, render: (r) => fmtNum(r.uniqueDomains) },
                { key: 'nxdomain', title: 'NXDOMAIN', align: 'right', num: true, render: (r) => fmtNum(r.nxdomain) },
                { key: 'servfail', title: 'SERVFAIL', align: 'right', num: true, render: (r) => fmtNum(r.servfail) },
                {
                  key: 'errorPercent',
                  title: 'Ошибки, %',
                  align: 'right',
                  render: (r) => <DnsErrorPercent value={r.errorPercent} />,
                },
              ]}
              getRowClassName={(row) => dnsErrorRowClass(row.errorPercent)}
            />
            </div>
          )}
        </Card>
      </div>

      <Card className="dns-recent-card">
        <div className="dns-card-head">
          <div>
            <div className="dns-card-head__title">Последние запросы DNS</div>
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
              columns={[
                {
                  key: 'eventTime',
                  title: 'Время',
                  width: 150,
                  render: (r) => <span className="mono dns-recent-time">{formatDnsTs(r.eventTime)}</span>,
                },
                {
                  key: 'eventType',
                  title: 'Тип',
                  width: 88,
                  sortable: false,
                  render: (r) => <DnsEventTypeBadge eventType={r.eventType} />,
                },
                {
                  key: 'client',
                  title: 'Клиент',
                  width: 130,
                  render: (r) => (
                    <button
                      type="button"
                      className="link-btn mono dns-recent-ip"
                      onClick={() => setClientIpDraft(r.client)}
                      title="Фильтровать по этому IP"
                    >
                      {r.client}
                    </button>
                  ),
                },
                {
                  key: 'server',
                  title: 'DNS-сервер',
                  width: 130,
                  render: (r) => <span className="mono dns-recent-ip">{r.server}</span>,
                },
                {
                  key: 'queryName',
                  title: 'Домен',
                  render: (r) => (
                    <button
                      type="button"
                      className="link-btn dns-table-domain dns-recent-domain"
                      onClick={() => setDomainDraft(r.queryName)}
                      title={r.queryName ? `Фильтровать по домену ${r.queryName}` : 'Фильтровать по этому домену'}
                    >
                      {r.queryName || '—'}
                    </button>
                  ),
                },
                { key: 'qtype', title: 'QTYPE', width: 72 },
                {
                  key: 'rcodeLabel',
                  title: 'RCODE',
                  width: 110,
                  sortable: false,
                  render: (r) => <DnsRcodeBadge label={r.rcodeLabel} rcode={r.rcode} />,
                },
                {
                  key: 'answers',
                  title: 'Ответы',
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
