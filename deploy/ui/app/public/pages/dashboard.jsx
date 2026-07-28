/* Обзор */

const CHART_REFRESH_MS = 60_000;
const DASHBOARD_TALKERS_LIMIT = 7;
const LOAD_FAILED = 'Не удалось загрузить';
const DASHBOARD_CHART_SPLIT_KEY = 'grapes-dashboard-chart-split';
const DEFAULT_TREND_SPLIT = 0.5;
const TREND_SPLIT_MIN = 0.35;
const TREND_SPLIT_MAX = 0.65;
const SHARE_RIGHT_SPLIT = 1 / 3;
const DASHBOARD_SPLITTER_WIDTH = 10;

function loadTrendSplit() {
  try {
    const raw = localStorage.getItem(DASHBOARD_CHART_SPLIT_KEY);
    if (raw == null) return DEFAULT_TREND_SPLIT;
    const n = Number(raw);
    if (!Number.isFinite(n)) return DEFAULT_TREND_SPLIT;
    const split = Math.min(TREND_SPLIT_MAX, Math.max(TREND_SPLIT_MIN, n));
    // Ignore stale share-mode ratio accidentally persisted as trend split.
    if (Math.abs(split - SHARE_RIGHT_SPLIT) < 0.005) return DEFAULT_TREND_SPLIT;
    return split;
  } catch {
    return DEFAULT_TREND_SPLIT;
  }
}

function saveTrendSplit(value) {
  try {
    localStorage.setItem(DASHBOARD_CHART_SPLIT_KEY, String(value));
  } catch { /* ignore */ }
}

function clampTrendSplit(value) {
  return Math.min(TREND_SPLIT_MAX, Math.max(TREND_SPLIT_MIN, value));
}

function DataLoadState({ children, style }) {
  return (
    <div className="other-ports-table__state" style={style}>
      {children || LOAD_FAILED}
    </div>
  );
}

const COUNTRY_BASIS_LABELS = {
  ip: 'Страна IP',
  asn: 'Страна ASN (реестр)',
};

const MAP_SIDE_LABELS = {
  remote: 'Удалённая',
  src: 'Источник',
  dst: 'Назначение',
};

const TRAFFIC_STAT_TILES = [
  { id: 'max', label: 'Максимально', mode: 'rate' },
  { id: 'avg', label: 'Среднее', mode: 'rate' },
  { id: 'volume', label: 'Объём', mode: 'volume' },
];

function PageDashboard({ onNavigate, directions, timeRange, customPeriod, collectorFilter, displayTimezone, onChartRangeSelect }) {
  const [data, setData] = useState({
    source: 'loading',
    series: { points: [], lines: [] },
    protocols: [],
    services: [],
    failedWidgets: {},
  });
  const [trafficStats, setTrafficStats] = useState(null);
  const [statsSource, setStatsSource] = useState('loading');
  const [statsLoadMs, setStatsLoadMs] = useState(null);
  const [statsServerMs, setStatsServerMs] = useState(null);
  const [chartMode, setChartMode] = useState('bw');
  const [chartHidden, setChartHidden] = useState(() => new Set());
  const [distributionMode, setDistributionMode] = useState('share');
  const [trendSplit, setTrendSplit] = useState(loadTrendSplit);
  const [protocolTrend, setProtocolTrend] = useState({ source: 'idle', series: { points: [], lines: [] }, loadMs: null, serverMs: null });
  const [serviceTrend, setServiceTrend] = useState({ source: 'idle', series: { points: [], lines: [] }, loadMs: null, serverMs: null });
  const [otherPortsOpen, setOtherPortsOpen] = useState(false);
  const periodLabel = timeRangeLabel(timeRange, customPeriod);
  const chartLongRange = isLongChartRange(timeRange, customPeriod);
  const chartPeriodBounds = useMemo(
    () => computeChartPeriodBounds(timeRange, customPeriod),
    [timeRange, customPeriod?.from, customPeriod?.to],
  );
  const directionsKey = TRAFFIC_DIRECTIONS.map((d) => (directions?.[d.id] ? '1' : '0')).join('');
  const collectorFilterKey = (collectorFilter || []).join('|');
  const chartLinesKey = (data.series?.lines || []).map((ln) => ln.key).join(',');

  const toggleChartSeries = (key) => {
    setChartHidden((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  useEffect(() => {
    setChartHidden(new Set());
  }, [directionsKey, chartLinesKey]);

  useEffect(() => {
    setOtherPortsOpen(false);
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey]);

  useEffect(() => {
    let cancelled = false;

    const loadChart = (initial) => {
      if (initial) setData((d) => ({ ...d, source: 'loading' }));
      ApiClient.loadDashboardData({ timeRange, customPeriod, directions, collectorFilter }).then((d) => {
        if (!cancelled) setData(d);
      });
    };

    loadChart(true);
    const timer = setInterval(() => loadChart(false), CHART_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey]);

  useEffect(() => {
    if (distributionMode !== 'trend') return undefined;
    let cancelled = false;

    const loadTrends = (initial) => {
      if (initial) {
        setProtocolTrend((s) => ({ ...s, source: 'loading' }));
        setServiceTrend((s) => ({ ...s, source: 'loading' }));
      }
      Promise.all([
        ApiClient.loadProtocolTrend({ timeRange, customPeriod, directions, collectorFilter }),
        ApiClient.loadServiceTrend({ timeRange, customPeriod, directions, collectorFilter }),
      ]).then(([protocolsR, servicesR]) => {
        if (cancelled) return;
        setProtocolTrend({
          source: protocolsR.ok ? 'clickhouse' : 'error',
          series: protocolsR.ok ? (protocolsR.data || { points: [], lines: [] }) : { points: [], lines: [] },
          loadMs: protocolsR.loadMs ?? null,
          serverMs: protocolsR.serverMs ?? null,
        });
        setServiceTrend({
          source: servicesR.ok ? 'clickhouse' : 'error',
          series: servicesR.ok ? (servicesR.data || { points: [], lines: [] }) : { points: [], lines: [] },
          loadMs: servicesR.loadMs ?? null,
          serverMs: servicesR.serverMs ?? null,
        });
      });
    };

    loadTrends(true);
    const timer = setInterval(() => loadTrends(false), CHART_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [distributionMode, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey]);

  useEffect(() => {
    let cancelled = false;
    setStatsSource('loading');
    ApiClient.loadTrafficStats({ timeRange, customPeriod, collectorFilter }).then((r) => {
      if (!cancelled) {
        setTrafficStats(r.trafficStats);
        setStatsSource(r.source);
        setStatsLoadMs(r.loadMs ?? null);
        setStatsServerMs(r.serverMs ?? null);
      }
    });
    return () => { cancelled = true; };
  }, [timeRange, customPeriod?.from, customPeriod?.to, collectorFilterKey]);

  const { series, protocols, services, source, failedWidgets = {}, loadTimings = {}, loadServerMs = {} } = data;
  const chartLines = (series?.lines || []).filter((ln) => directions?.[ln.key]);
  const chartPoints = (series?.points || []).map((pt) => {
    const next = { ...pt };
    if (next.bucket) next.bucket = normalizeBucketString(next.bucket);
    next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
    if (next.bucketMs != null) next.bucketMs = Number(next.bucketMs);
    for (const ln of chartLines) {
      const f = `${ln.key}_pps`;
      if (next[f] == null && ln.key === 'total' && next.pps != null) {
        next[f] = Number(next.pps) || 0;
      }
    }
    return next;
  });
  const visibleChartLines = chartLines.filter((ln) => !chartHidden.has(ln.key));
  const visiblePpsLines = chartLines.filter((ln) => !chartHidden.has(`${ln.key}_pps`));
  const chartPpsHiddenKey = (key) => `${key}_pps`;
  const dataSource = statsSource === 'clickhouse' || source === 'clickhouse'
    ? 'clickhouse'
    : statsSource === 'loading' || source === 'loading'
      ? 'loading'
      : 'error';
  const dataSubtitleSuffix = dataSource === 'clickhouse'
    ? 'ClickHouse'
    : dataSource === 'loading'
      ? '…'
      : LOAD_FAILED;
  const trendRangeHint = onChartRangeSelect ? ' · выделите диапазон на графике' : '';
  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Сводка по сети</h1>
          <p>Живой обзор трафика, потоков и состояния инфраструктуры.</p>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid traffic-stat-grid grid--mb">
        {statsSource === 'error' ? (
          <Card style={{ gridColumn: '1 / -1' }}>
            <DataLoadState />
          </Card>
        ) : TRAFFIC_STAT_TILES.map((tile) => (
          <TrafficStatTile
            key={tile.id}
            label={tile.label}
            mode={tile.mode}
            stats={trafficStats?.[tile.id] || {}}
            directions={directions}
            loadMs={statsLoadMs}
            serverMs={statsServerMs}
          />
        ))}
      </div>

      {/* Main chart row */}
      <DashboardChartRow
        distributionMode={distributionMode}
        trendSplit={trendSplit}
        onTrendSplitChange={setTrendSplit}
      >
        <Card
          title="Полоса пропускания и pps"
          subtitle={`${periodLabel} · NetFlow v9 + IPFIX · ${dataSubtitleSuffix}`}
          loadMs={loadTimings.series}
          serverMs={loadServerMs.series}
          tools={
            <>
              <div className="seg">
                <button className={chartMode === 'bw' ? 'is-active' : ''} onClick={() => setChartMode('bw')}>Полоса</button>
                <button className={chartMode === 'pps' ? 'is-active' : ''} onClick={() => setChartMode('pps')}>pps</button>
              </div>
              <Button kind="ghost" size="sm" icon="zoom" />
              <Button kind="ghost" size="sm" icon="more" />
            </>
          }
        >
          <div className="chart-legend row" style={{gap: 14, marginBottom: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', flexWrap: 'wrap'}}>
            {chartMode === 'bw' && chartLines.map((ln) => {
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
                    className="chart-legend__swatch"
                    style={{
                      width: 12,
                      height: ln.key === 'total' ? 3 : 2,
                      background: ln.color,
                      opacity: off ? 0.35 : 1,
                    }}
                  />
                  {ln.label}, бит/с
                </button>
              );
            })}
            {chartMode === 'pps' && chartLines.map((ln) => {
              const ppsKey = chartPpsHiddenKey(ln.key);
              const off = chartHidden.has(ppsKey);
              return (
                <button
                  key={ppsKey}
                  type="button"
                  className={`chart-legend__item${off ? ' is-off' : ''}`}
                  aria-pressed={!off}
                  title={off ? 'Показать на графике' : 'Скрыть с графика'}
                  onClick={() => toggleChartSeries(ppsKey)}
                >
                  <span
                    className="chart-legend__swatch"
                    style={{
                      width: 12,
                      height: ln.key === 'total' ? 3 : 2,
                      background: ln.color,
                      opacity: off ? 0.35 : 1,
                    }}
                  />
                  {ln.label}, пакеты/с
                </button>
              );
            })}
            <span className="chart-legend__meta" style={{display: 'inline-flex', alignItems: 'center', gap: 6}}>
              <Icon name="info" size={12} /> {onChartRangeSelect ? 'Выделите диапазон на графике · авто-обновление каждую минуту' : 'Авто-обновление каждую минуту'}
            </span>
          </div>
          {(source === 'error' || failedWidgets.series) && source !== 'loading' ? (
            <DataLoadState style={{ minHeight: 280 }} />
          ) : (
            <DualChart
              points={chartPoints}
              lines={visibleChartLines}
              ppsLines={visiblePpsLines}
              height={280}
              mode={chartMode}
              onRangeSelect={onChartRangeSelect}
              bucketSeconds={300}
              displayTimezone={displayTimezone}
              periodStartMs={chartPeriodBounds.startMs}
              periodEndMs={chartPeriodBounds.endMs}
            />
          )}
        </Card>

        <Card pad="sm">
          <div className="distribution-card__head">
            <div className="distribution-card__title">Распределение</div>
            <div className="seg distribution-card__switch">
              <button
                type="button"
                className={distributionMode === 'share' ? 'is-active' : ''}
                onClick={() => setDistributionMode('share')}
              >
                Доля
              </button>
              <button
                type="button"
                className={distributionMode === 'trend' ? 'is-active' : ''}
                onClick={() => setDistributionMode('trend')}
              >
                Динамика
              </button>
            </div>
          </div>
          <div className="distribution-split">
            <DistributionPane
              title="Протоколы"
              subtitle={distributionMode === 'share'
                ? `L4 по объёму · ${periodLabel}`
                : `Top 5 L4 · ${periodLabel}${trendRangeHint}`}
              mode={distributionMode}
              items={protocols}
              trend={protocolTrend}
              chartLongRange={chartLongRange}
              displayTimezone={displayTimezone}
              onRangeSelect={distributionMode === 'trend' ? onChartRangeSelect : undefined}
              periodStartMs={chartPeriodBounds.startMs}
              periodEndMs={chartPeriodBounds.endMs}
              failed={source === 'error' || failedWidgets.protocols}
              trendFailed={protocolTrend.source === 'error'}
              loadMs={distributionMode === 'trend' ? protocolTrend.loadMs : loadTimings.protocols}
              serverMs={distributionMode === 'trend' ? protocolTrend.serverMs : loadServerMs.protocols}
            />
            <div className="distribution-split__divider" aria-hidden="true" />
            <DistributionPane
              title="Сервисы"
              subtitle={distributionMode === 'share'
                ? `L7 по объёму · ${periodLabel}`
                : `Top 5 L7 · ${periodLabel}${trendRangeHint}`}
              mode={distributionMode}
              items={services}
              trend={serviceTrend}
              chartLongRange={chartLongRange}
              displayTimezone={displayTimezone}
              onOtherClick={() => setOtherPortsOpen(true)}
              onRangeSelect={distributionMode === 'trend' ? onChartRangeSelect : undefined}
              periodStartMs={chartPeriodBounds.startMs}
              periodEndMs={chartPeriodBounds.endMs}
              failed={source === 'error' || failedWidgets.services}
              trendFailed={serviceTrend.source === 'error'}
              loadMs={distributionMode === 'trend' ? serviceTrend.loadMs : loadTimings.services}
              serverMs={distributionMode === 'trend' ? serviceTrend.serverMs : loadServerMs.services}
            />
          </div>
        </Card>
      </DashboardChartRow>

      <div className="grid grid--1col grid--mb">
        <VlanDistributionCard
          timeRange={timeRange}
          customPeriod={customPeriod}
          directions={directions}
          directionsKey={directionsKey}
          collectorFilter={collectorFilter}
          periodLabel={periodLabel}
          chartLongRange={chartLongRange}
          displayTimezone={displayTimezone}
          onNavigate={onNavigate}
          onChartRangeSelect={onChartRangeSelect}
        />
      </div>

      <OtherPortsModal
        open={otherPortsOpen}
        onClose={() => setOtherPortsOpen(false)}
        timeRange={timeRange}
        customPeriod={customPeriod}
        directions={directions}
        collectorFilter={collectorFilter}
        periodLabel={periodLabel}
      />

      {/* Talkers + Map row */}
      <div className="grid grid--12-1 grid--stretch grid--mb">
        <TopTalkersCard
          onNavigate={onNavigate}
          timeRange={timeRange}
          customPeriod={customPeriod}
          directions={directions}
          directionsKey={directionsKey}
          collectorFilter={collectorFilter}
          periodLabel={periodLabel}
        />

        <CountryHeatmapCard
          timeRange={timeRange}
          customPeriod={customPeriod}
          directions={directions}
          directionsKey={directionsKey}
          collectorFilter={collectorFilter}
          periodLabel={periodLabel}
        />
      </div>

      <RecentFlowsCard
        directions={directions}
        directionsKey={directionsKey}
        collectorFilter={collectorFilter}
      />
    </div>
  );
}

function RecentFlowsCard({ directions, directionsKey, collectorFilter }) {
  const collectorFilterKey = (collectorFilter || []).join('|');
  const [rows, setRows] = useState([]);
  const [flowsSource, setFlowsSource] = useState('loading');
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);

  const directionFilterLabel = directionSummaryLabel(directions);

  useEffect(() => {
    let cancelled = false;

    const load = (initial) => {
      if (initial) setFlowsSource('loading');
      ApiClient.loadRecentFlows({ directions, limit: 20, collectorFilter }).then((r) => {
        if (!cancelled) {
          setRows(Array.isArray(r.rows) ? r.rows : []);
          setFlowsSource(r.source || 'error');
          setLoadMs(r.loadMs ?? null);
          setServerMs(r.serverMs ?? null);
        }
      });
    };

    load(true);
    return () => { cancelled = true; };
  }, [directionsKey, collectorFilterKey]);

  const hasData = flowsSource === 'clickhouse';

  return (
    <Card
      className="card--recent-flows"
      title="Последние потоки"
      subtitle={`Последние потоки из flows_raw · ${directionFilterLabel}`}
      loadMs={loadMs}
      serverMs={serverMs}
      pad="0"
    >
      <table className="table table--recent-flows" style={{ borderRadius: 0 }}>
        <thead>
          <tr>
            <th className="recent-flows__time-col">Время</th>
            <th>Поток</th>
            <th className="recent-flows__meta-col">VLAN / GEO</th>
            <th className="recent-flows__proto-col">Proto</th>
            <th className="recent-flows__bytes-col">Объём</th>
            <th className="recent-flows__asn-col">ASN</th>
          </tr>
        </thead>
        <tbody>
          {flowsSource === 'loading' && (
            <tr>
              <td colSpan={6} className="talker-table-state">Загрузка…</td>
            </tr>
          )}
          {flowsSource === 'error' && (
            <tr>
              <td colSpan={6} className="talker-table-state">{LOAD_FAILED}</td>
            </tr>
          )}
          {hasData && rows.length === 0 && (
            <tr>
              <td colSpan={6} className="talker-table-state">Нет потоков для выбранного направления</td>
            </tr>
          )}
          {hasData && rows.map((f, i) => (
            <tr key={`${f.ts}-${f.src}-${f.dst}-${i}`}>
              <td className="recent-flows__time mono">{f.ts}</td>
              <td>
                <RecentFlowEndpointCell flow={f} />
              </td>
              <td>
                <RecentFlowMetaCell flow={f} />
              </td>
              <td><RecentFlowProtoBadge proto={f.proto} /></td>
              <td className="recent-flows__bytes num">
                <div>{fmtBytes(f.bytes)}</div>
                <small>{fmtNum(f.pkts)} пак.</small>
              </td>
              <td className="recent-flows__asn-cell">
                <RecentFlowAsnCell
                  srcAsn={f.srcAsn}
                  dstAsn={f.dstAsn}
                  srcAsName={f.srcAsName}
                  dstAsName={f.dstAsName}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function RecentFlowProtoBadge({ proto }) {
  return (
    <Badge tone={proto === 'TCP' ? 'info' : proto === 'UDP' ? 'neutral' : proto === 'QUIC' ? 'success' : 'warning'}>
      {proto}
    </Badge>
  );
}

function recentPortLabel(port) {
  const n = Number(port);
  return Number.isFinite(n) && n > 0 ? String(n) : '';
}

function recentVlanLabel(flow) {
  for (const value of [flow.srcVlan, flow.vlanId, flow.dstVlan]) {
    const n = Number(value);
    if (Number.isFinite(n) && n > 0) return String(n);
  }
  return '—';
}

function countryShort(code, ip) {
  const c = String(code || '').trim();
  if (c && c !== '??') return countryFlagEmoji(c);
  return specialIpLabel(ip) || '—';
}

function RecentFlowEndpointCell({ flow }) {
  const srcLabel = flow.srcLabel && flow.srcLabel !== flow.srcIp ? flow.srcLabel : '';
  const dstLabel = flow.dstLabel && flow.dstLabel !== flow.dstIp ? flow.dstLabel : '';
  const srcPort = recentPortLabel(flow.srcPort);
  const dstPort = recentPortLabel(flow.dstPort);
  return (
    <div className="recent-flow-endpoints">
      <div className="recent-flow-endpoint">
        <span className="recent-flow-endpoint__ip mono">{flow.srcIp}</span>
        {srcPort && <span className="recent-flow-endpoint__port mono">:{srcPort}</span>}
        {srcLabel && <span className="recent-flow-endpoint__label">{srcLabel}</span>}
      </div>
      <div className="recent-flow-arrow" aria-hidden="true">→</div>
      <div className="recent-flow-endpoint">
        <span className="recent-flow-endpoint__ip mono">{flow.dstIp}</span>
        {dstPort && <span className="recent-flow-endpoint__port mono">:{dstPort}</span>}
        {dstLabel && <span className="recent-flow-endpoint__label">{dstLabel}</span>}
      </div>
    </div>
  );
}

function RecentFlowMetaCell({ flow }) {
  const srcGeo = countryShort(flow.srcCountry, flow.srcIp);
  const dstGeo = countryShort(flow.dstCountry, flow.dstIp);
  return (
    <div className="recent-flow-meta">
      <span className="recent-flow-meta__vlan mono">{recentVlanLabel(flow)}</span>
      <span className="recent-flow-meta__geo" title={`${flow.srcCountry || '??'} → ${flow.dstCountry || '??'}`}>
        {srcGeo}<span className="recent-flow-meta__arrow">→</span>{dstGeo}
      </span>
    </div>
  );
}

function recentFlowAsnLabel(asn, asName) {
  const n = Number(asn);
  if (!Number.isFinite(n) || n <= 0) return '—';
  const name = String(asName || '').trim();
  if (name && !/^AS?\d+$/i.test(name)) return `${name} · AS${n}`;
  return `AS${n}`;
}

function RecentFlowAsnCell({ srcAsn, dstAsn, srcAsName, dstAsName }) {
  const src = recentFlowAsnLabel(srcAsn, srcAsName);
  const dst = recentFlowAsnLabel(dstAsn, dstAsName);
  if (src === '—' && dst === '—') {
    return <span className="recent-flows__asn mono">—</span>;
  }
  if (src !== '—' && dst !== '—') {
    return (
      <div className="recent-flows__asn-stack">
        <span className="recent-flows__asn-line mono" title={src}>{src}</span>
        <span className="recent-flows__asn-line mono" title={dst}>{dst}</span>
      </div>
    );
  }
  return <span className="recent-flows__asn mono">{dst !== '—' ? dst : src}</span>;
}

function TopTalkersCard({ onNavigate, timeRange, customPeriod, directions, directionsKey, collectorFilter, periodLabel }) {
  const collectorFilterKey = (collectorFilter || []).join('|');
  const [group, setGroup] = useState('src');
  const [rows, setRows] = useState([]);
  const [talkersMeta, setTalkersMeta] = useState(null);
  const [talkersSource, setTalkersSource] = useState('loading');
  const [expandedKey, setExpandedKey] = useState(null);
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);

  const subtitle = `${periodLabel} · ${directionSummaryLabel(directions)}`;
  const directionFilterLabel = directionSummaryLabel(directions);
  const hasData = talkersSource === 'clickhouse';

  useEffect(() => {
    setExpandedKey(null);
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, group, collectorFilterKey]);

  useEffect(() => {
    let cancelled = false;

    const load = (initial) => {
      if (initial) setTalkersSource('loading');
      ApiClient.loadTopTalkers({
        timeRange,
        customPeriod,
        directions,
        group,
        limit: DASHBOARD_TALKERS_LIMIT,
        collectorFilter,
      }).then((r) => {
        if (!cancelled) {
          setRows(Array.isArray(r.rows) ? r.rows : []);
          setTalkersMeta(r.meta || null);
          setTalkersSource(r.source || 'error');
          setLoadMs(r.loadMs ?? null);
          setServerMs(r.serverMs ?? null);
        }
      });
    };

    load(true);
    return () => { cancelled = true; };
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, group, collectorFilterKey]);

  const isPair = group === 'pair';
  const colSpan = 4;

  const toggleRow = (key) => {
    setExpandedKey((prev) => (prev === key ? null : key));
  };

  return (
    <Card
      className="card--top-talkers"
      title="Топ ASN"
      subtitle={subtitle}
      loadMs={loadMs}
      serverMs={serverMs}
      tools={
        <div className="top-talkers-tools">
          <div className="seg seg--compact" role="tablist" aria-label="Группировка топ ASN">
            {TOP_TALKERS_TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={group === tab.id}
                className={group === tab.id ? 'is-active' : ''}
                onClick={() => setGroup(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <Button kind="ghost" size="sm" iconRight="arrowURight" onClick={() => onNavigate('top')}>Все</Button>
        </div>
      }
      pad="0"
    >
      <table className="table table--top-talkers" style={{ borderRadius: 0 }}>
        <thead>
          <tr>
            <th className="talker-col-rank">#</th>
            <th className="talker-col-endpoint">{isPair ? 'Пара ASN' : 'ASN'}</th>
            <th className={`talker-row__geo talker-col-geo${isPair ? ' talker-row__geo--pair' : ''}`}>Страна</th>
            <th className="num talker-col-volume">Объём</th>
          </tr>
        </thead>
        <tbody>
          {talkersSource === 'loading' && (
            <tr>
              <td colSpan={colSpan} className="talker-table-state">Загрузка…</td>
            </tr>
          )}
          {talkersSource === 'error' && (
            <tr>
              <td colSpan={colSpan} className="talker-table-state">{LOAD_FAILED}</td>
            </tr>
          )}
          {hasData && rows.length === 0 && (
            <tr>
              <td colSpan={colSpan} className="talker-table-state">Нет данных за выбранный период</td>
            </tr>
          )}
          {hasData && rows.map((t, i) => {
            const key = talkerRowKey(t, isPair);
            const expanded = expandedKey === key;

            if (isPair) {
              return (
                <React.Fragment key={key}>
                  <tr
                    className={`talker-row${expanded ? ' talker-row--expanded' : ''}`}
                    onClick={() => toggleRow(key)}
                    aria-expanded={expanded}
                  >
                    <td className="num talker-row__rank">{i + 1}</td>
                    <td className="talker-col-endpoint"><TalkerMainPairIpCell row={t} /></td>
                    <td className="talker-row__geo talker-row__geo--pair">
                      <TalkerMainPairGeoCell row={t} />
                    </td>
                    <td className="num talker-row__volume">{fmtVolumeSize(t.trafficGb, t.trafficTb)}</td>
                  </tr>
                  {expanded && (
                    <tr className="talker-row-detail">
                      <td colSpan={colSpan}>
                        <TalkerRowDetail
                          row={t}
                          isPair
                          periodLabel={periodLabel}
                          directionFilterLabel={directionFilterLabel}
                          meta={talkersMeta}
                        />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            }

            return (
              <React.Fragment key={key}>
                <tr
                  className={`talker-row${expanded ? ' talker-row--expanded' : ''}`}
                  onClick={() => toggleRow(key)}
                  aria-expanded={expanded}
                >
                  <td className="num talker-row__rank">{i + 1}</td>
                  <td className="talker-col-endpoint">
                    <TalkerMainAsnCell asName={t.asName} asn={t.asn} />
                  </td>
                  <td className="talker-row__geo">{talkerGeoDisplay(t.asCountry || t.countryCode)}</td>
                  <td className="num talker-row__volume">{fmtVolumeSize(t.trafficGb, t.trafficTb)}</td>
                </tr>
                {expanded && (
                  <tr className="talker-row-detail">
                    <td colSpan={colSpan}>
                      <TalkerRowDetail
                        row={t}
                        isPair={false}
                        periodLabel={periodLabel}
                        directionFilterLabel={directionFilterLabel}
                        meta={talkersMeta}
                      />
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </Card>
  );
}

function CountryHeatmapCard({ timeRange, customPeriod, directions, directionsKey, collectorFilter, periodLabel }) {
  const collectorFilterKey = (collectorFilter || []).join('|');
  const [countryBasis, setCountryBasis] = useState('ip');
  const [mapSide, setMapSide] = useState('remote');
  const [colorMetric, setColorMetric] = useState('share');
  const [countryRows, setCountryRows] = useState([]);
  const [countrySource, setCountrySource] = useState('loading');
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);
  const [mapModalOpen, setMapModalOpen] = useState(false);

  const flowDirections = TRAFFIC_DIRECTIONS.filter((d) => d.id !== 'total');
  const enabledFlow = flowDirections.filter((d) => directions?.[d.id]);
  const onlyInternal = enabledFlow.length === 1 && enabledFlow[0].id === 'internal';
  const showInternalHint = onlyInternal && mapSide === 'remote';

  const basisLabel = COUNTRY_BASIS_LABELS[countryBasis] || countryBasis;
  const mapSideLabel = MAP_SIDE_LABELS[mapSide] || mapSide;
  const sourceNote = countrySource === 'clickhouse'
    ? 'ClickHouse'
    : countrySource === 'loading'
      ? '…'
      : LOAD_FAILED;

  useEffect(() => {
    let cancelled = false;

    const loadCountries = (initial) => {
      if (initial) setCountrySource('loading');
      ApiClient.loadCountries({
        timeRange,
        customPeriod,
        directions,
        basis: countryBasis,
        mapSide,
        collectorFilter,
      }).then((r) => {
        if (!cancelled) {
          setCountryRows(Array.isArray(r.rows) ? r.rows : []);
          setCountrySource(r.source || 'error');
          setLoadMs(r.loadMs ?? null);
          setServerMs(r.serverMs ?? null);
        }
      });
    };

    loadCountries(true);
    return () => { cancelled = true; };
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, countryBasis, mapSide, collectorFilterKey]);

  const countryListKey = `${directionsKey}|${countryBasis}|${mapSide}|${timeRange}|${customPeriod?.from}|${customPeriod?.to}|${collectorFilterKey || ''}`;
  const mapSubtitle = `${periodLabel} · ${basisLabel} · ${mapSideLabel} · ${sourceNote}`;

  return (
    <>
    <Card
      title="География источников"
      subtitle={`${periodLabel} · ${basisLabel} · ${mapSideLabel} · ${sourceNote}`}
      loadMs={loadMs}
      serverMs={serverMs}
      tools={
        <div className="country-heatmap-tools row">
          <div className="seg seg--compact" title="Метод определения страны">
            <button
              type="button"
              className={countryBasis === 'ip' ? 'is-active' : ''}
              onClick={() => setCountryBasis('ip')}
            >
              IP
            </button>
            <button
              type="button"
              className={countryBasis === 'asn' ? 'is-active' : ''}
              onClick={() => setCountryBasis('asn')}
            >
              ASN
            </button>
          </div>
          <div className="seg seg--compact" title="Сторона flow на карте">
            <button
              type="button"
              className={mapSide === 'remote' ? 'is-active' : ''}
              onClick={() => setMapSide('remote')}
            >
              Remote
            </button>
            <button
              type="button"
              className={mapSide === 'src' ? 'is-active' : ''}
              onClick={() => setMapSide('src')}
            >
              Src
            </button>
            <button
              type="button"
              className={mapSide === 'dst' ? 'is-active' : ''}
              onClick={() => setMapSide('dst')}
            >
              Dst
            </button>
          </div>
          <div className="seg seg--compact" title="Метрика заливки карты">
            <button
              type="button"
              className={colorMetric === 'share' ? 'is-active' : ''}
              onClick={() => setColorMetric('share')}
            >
              %
            </button>
            <button
              type="button"
              className={colorMetric === 'volume' ? 'is-active' : ''}
              onClick={() => setColorMetric('volume')}
            >
              Gb
            </button>
          </div>
        </div>
      }
    >
      {showInternalHint && (
        <div className="country-heatmap-hint">
          Для internal используйте src или dst
        </div>
      )}
      <CountryChoropleth
        rows={countryRows}
        colorMetric={colorMetric}
        loading={countrySource === 'loading'}
        failed={countrySource === 'error'}
        showExpand
        onExpand={() => setMapModalOpen(true)}
      />
      {countryRows.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <CountryRankList rows={countryRows} listKey={countryListKey} colorMetric={colorMetric} />
        </div>
      )}
    </Card>

    <CountryMapModal
      open={mapModalOpen}
      onClose={() => setMapModalOpen(false)}
      rows={countryRows}
      colorMetric={colorMetric}
      loading={countrySource === 'loading'}
      failed={countrySource === 'error'}
      subtitle={mapSubtitle}
    />
    </>
  );
}

function CountryMapModal({ open, onClose, rows, colorMetric, loading, failed, subtitle }) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      size="map"
      title="География источников"
      subtitle={subtitle}
    >
      <div className="country-map-modal__body">
        <CountryChoropleth
          rows={rows}
          colorMetric={colorMetric}
          loading={loading}
          failed={failed}
          large
        />
      </div>
    </Modal>
  );
}

function DashboardChartRow({ distributionMode, trendSplit, onTrendSplitChange, children }) {
  const rowRef = useRef(null);
  const mainPaneRef = useRef(null);
  const distributionPaneRef = useRef(null);
  const trendSplitRef = useRef(trendSplit);
  const isDraggingRef = useRef(false);
  const skipTransitionRef = useRef(true);
  const pendingClientXRef = useRef(null);
  const rafRef = useRef(null);
  const childArray = React.Children.toArray(children);
  const mainPane = childArray[0];
  const distributionPane = childArray[1];
  const isTrend = distributionMode === 'trend';
  const rowModeClass = isTrend ? ' dashboard-chart-row--trend' : ' dashboard-chart-row--share';

  trendSplitRef.current = trendSplit;

  const targetSplit = isTrend ? trendSplit : SHARE_RIGHT_SPLIT;

  const splitFromClientX = (clientX) => {
    const el = rowRef.current;
    if (!el) return trendSplitRef.current;
    const rect = el.getBoundingClientRect();
    if (!rect.width) return trendSplitRef.current;
    const flexWidth = Math.max(rect.width - (isTrend ? DASHBOARD_SPLITTER_WIDTH : 0), 1);
    const boundaryX = clientX - rect.left;
    return clampTrendSplit(1 - boundaryX / flexWidth);
  };

  const clearPaneFlex = () => {
    mainPaneRef.current?.style.removeProperty('flex');
    distributionPaneRef.current?.style.removeProperty('flex');
  };

  const applySplit = (split, { live = false } = {}) => {
    rowRef.current?.style.setProperty('--dash-right-split', String(split));
    if (!live) {
      clearPaneFlex();
      return;
    }
    const left = 1 - split;
    mainPaneRef.current?.style.setProperty('flex', `${left} 1 0`);
    distributionPaneRef.current?.style.setProperty('flex', `${split} 1 0`);
  };

  useEffect(() => {
    if (isDraggingRef.current) return;
    const row = rowRef.current;
    if (!row) return;
    if (skipTransitionRef.current) {
      skipTransitionRef.current = false;
      row.classList.add('is-snapping');
      applySplit(targetSplit);
      requestAnimationFrame(() => row.classList.remove('is-snapping'));
      return;
    }
    applySplit(targetSplit);
  }, [targetSplit, isTrend]);

  const flushSplitUpdate = () => {
    rafRef.current = null;
    const clientX = pendingClientXRef.current;
    if (clientX == null) return;
    const next = splitFromClientX(clientX);
    if (Math.abs(next - trendSplitRef.current) < 0.001) return;
    trendSplitRef.current = next;
    applySplit(next, { live: true });
  };

  const scheduleSplitUpdate = (clientX) => {
    pendingClientXRef.current = clientX;
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
    pendingClientXRef.current = null;
    isDraggingRef.current = false;
    rowRef.current?.classList.remove('is-dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  };

  const onSplitterMouseDown = (e) => {
    if (!isTrend || e.button !== 0) return;
    e.preventDefault();
    isDraggingRef.current = true;
    const dragStartSplit = trendSplitRef.current;
    applySplit(dragStartSplit, { live: true });

    const onMove = (ev) => scheduleSplitUpdate(ev.clientX);

    const onUp = () => {
      flushSplitUpdate();
      stopDrag(onMove, onUp);
      applySplit(trendSplitRef.current);
      if (Math.abs(trendSplitRef.current - dragStartSplit) >= 0.005) {
        onTrendSplitChange(trendSplitRef.current);
        saveTrendSplit(trendSplitRef.current);
      }
    };

    rowRef.current?.classList.add('is-dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  return (
    <div
      ref={rowRef}
      className={`dashboard-chart-row${rowModeClass}`}
    >
      <div ref={mainPaneRef} className="dashboard-chart-row__pane dashboard-chart-row__pane--main">
        {mainPane}
      </div>
      <div
        className="dashboard-chart-row__splitter"
        role="separator"
        aria-orientation="vertical"
        aria-hidden={!isTrend}
        aria-valuenow={Math.round(trendSplit * 100)}
        aria-valuemin={Math.round(TREND_SPLIT_MIN * 100)}
        aria-valuemax={Math.round(TREND_SPLIT_MAX * 100)}
        aria-label="Изменить ширину карточек"
        tabIndex={isTrend ? 0 : -1}
        onMouseDown={onSplitterMouseDown}
      />
      <div ref={distributionPaneRef} className="dashboard-chart-row__pane dashboard-chart-row__pane--distribution">
        {distributionPane}
      </div>
    </div>
  );
}

function DistributionPane({
  title,
  subtitle,
  mode = 'share',
  items,
  trend,
  chartLongRange,
  displayTimezone,
  onOtherClick,
  onRangeSelect,
  bucketSeconds = 300,
  periodStartMs,
  periodEndMs,
  failed,
  trendFailed,
  loadMs,
  serverMs,
  centered = false,
}) {
  const center = donutCenterTraffic(filterNonZeroDonutSegments(items));
  const trendSeries = trend?.series || { points: [], lines: [] };
  const trendPoints = (trendSeries.points || []).map((pt) => {
    const next = { ...pt };
    if (next.bucket) next.bucket = normalizeBucketString(next.bucket);
    next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
    if (next.bucketMs != null) next.bucketMs = Number(next.bucketMs);
    return next;
  });
  const trendLoading = mode === 'trend' && (trend?.source === 'loading' || trend?.source === 'idle');
  const showTrendError = mode === 'trend' && (trendFailed || trend?.source === 'error');
  const showShareError = mode === 'share' && failed;

  let content;
  if (mode === 'share' && showShareError) {
    content = <DataLoadState style={{ flex: 1, minHeight: 150 }} />;
  } else if (mode === 'share') {
    content = (
      <Donut
        data={items}
        centerLabel={center.label}
        centerSub={center.sub}
        size={150}
        thickness={20}
        onOtherClick={onOtherClick}
      />
    );
  } else if (trendLoading) {
    content = <div className="distribution-pane__loading">Загрузка…</div>;
  } else if (showTrendError) {
    content = <DataLoadState style={{ flex: 1, minHeight: 150 }} />;
  } else {
    content = (
      <CategoryTrendChart
        points={trendPoints}
        lines={trendSeries.lines || []}
        height={190}
        bucketSeconds={bucketSeconds}
        displayTimezone={displayTimezone}
        onRangeSelect={onRangeSelect}
        periodStartMs={periodStartMs}
        periodEndMs={periodEndMs}
      />
    );
  }

  return (
    <div className={`distribution-pane${centered ? ' distribution-pane--centered' : ''}`}>
      <WidgetLoadBadge loadMs={loadMs} serverMs={serverMs} />
      <div className="distribution-pane__head">
        <div className="distribution-pane__title">{title}</div>
        {subtitle && <div className="distribution-pane__sub">{subtitle}</div>}
      </div>
      <div className="distribution-pane__content">{content}</div>
    </div>
  );
}

function VlanDistributionCard({
  timeRange,
  customPeriod,
  directions,
  directionsKey,
  collectorFilter,
  periodLabel,
  chartLongRange,
  displayTimezone,
  onNavigate,
  onChartRangeSelect,
}) {
  const collectorFilterKey = (collectorFilter || []).join('|');
  const [mode, setMode] = useState('trend');
  const [share, setShare] = useState({ source: 'idle', items: [], loadMs: null, serverMs: null });
  const [trend, setTrend] = useState({ source: 'idle', series: { points: [], lines: [] }, loadMs: null, serverMs: null });

  useEffect(() => {
    let cancelled = false;
    setShare((s) => ({ ...s, source: 'loading' }));
    ApiClient.dashboardVlans({ timeRange, customPeriod, directions, collectorFilter })
      .then((data) => {
        if (cancelled) return;
        setShare({ source: 'clickhouse', items: Array.isArray(data) ? data : [] });
      })
      .catch(() => { if (!cancelled) setShare({ source: 'error', items: [] }); });
    return () => { cancelled = true; };
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey]);

  useEffect(() => {
    if (mode !== 'trend') return undefined;
    let cancelled = false;
    setTrend((s) => ({ ...s, source: 'loading' }));
    ApiClient.loadVlanTrend({ timeRange, customPeriod, directions, collectorFilter })
      .then((r) => {
        if (cancelled) return;
        setTrend({
          source: r.ok ? 'clickhouse' : 'error',
          series: r.ok ? (r.data || { points: [], lines: [] }) : { points: [], lines: [] },
          loadMs: r.loadMs ?? null,
          serverMs: r.serverMs ?? null,
        });
      });
    return () => { cancelled = true; };
  }, [mode, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey]);

  const chartPeriodBounds = useMemo(
    () => computeChartPeriodBounds(timeRange, customPeriod),
    [timeRange, customPeriod?.from, customPeriod?.to],
  );

  return (
    <Card pad="sm">
      <div className="distribution-card__head">
        <div className="distribution-card__title">VLAN</div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {onNavigate && (
            <Button kind="ghost" size="sm" onClick={() => onNavigate('vlan')}>Справочник VLAN</Button>
          )}
          <div className="seg distribution-card__switch">
            <button type="button" className={mode === 'share' ? 'is-active' : ''} onClick={() => setMode('share')}>Доля</button>
            <button type="button" className={mode === 'trend' ? 'is-active' : ''} onClick={() => setMode('trend')}>Динамика</button>
          </div>
        </div>
      </div>
      <div className={`distribution-split distribution-split--solo${mode === 'trend' ? ' distribution-split--solo-trend' : ''}`}>
        <DistributionPane
          title="Top VLAN по объёму"
          subtitle={mode === 'share'
            ? `По объёму · ${periodLabel}`
            : `Top 5 VLAN · ${periodLabel}${onChartRangeSelect ? ' · выделите диапазон на графике' : ''}`}
          mode={mode}
          items={share.items}
          trend={trend}
          chartLongRange={chartLongRange}
          displayTimezone={displayTimezone}
          onRangeSelect={mode === 'trend' ? onChartRangeSelect : undefined}
          periodStartMs={chartPeriodBounds.startMs}
          periodEndMs={chartPeriodBounds.endMs}
          failed={share.source === 'error'}
          trendFailed={trend.source === 'error'}
          loadMs={mode === 'trend' ? trend.loadMs : share.loadMs}
          serverMs={mode === 'trend' ? trend.serverMs : share.serverMs}
          centered={mode === 'share'}
        />
      </div>
    </Card>
  );
}

const PORT_SIDE_LABELS = {
  src: 'Источник',
  dst: 'Назначение',
  source: 'Источник',
  destination: 'Назначение',
};

function formatPortSide(side) {
  if (!side) return '—';
  const key = String(side).toLowerCase();
  return PORT_SIDE_LABELS[key] || side;
}

function OtherPortsModal({ open, onClose, timeRange, customPeriod, directions, collectorFilter, periodLabel }) {
  const collectorFilterKey = (collectorFilter || []).join('|');
  const [rows, setRows] = useState([]);
  const [status, setStatus] = useState('idle');
  const directionsKey = TRAFFIC_DIRECTIONS.map((d) => (directions?.[d.id] ? '1' : '0')).join('');

  useEffect(() => {
    if (!open) return undefined;
    let cancelled = false;
    setStatus('loading');
    setRows([]);
    ApiClient.dashboardOtherPorts({ timeRange, customPeriod, directions, collectorFilter })
      .then((data) => {
        if (!cancelled) {
          setRows(Array.isArray(data) ? data : []);
          setStatus('ready');
        }
      })
      .catch(() => {
        if (!cancelled) {
          setRows([]);
          setStatus('error');
        }
      });
    return () => { cancelled = true; };
  }, [open, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title="ТОП 20 остальных портов"
      subtitle={`Внутри Other · ${periodLabel}${status === 'error' ? ` · ${LOAD_FAILED}` : ''}`}
    >
      <div className="other-ports-modal__body">
        {status === 'loading' ? (
          <div className="other-ports-table__state">Загрузка…</div>
        ) : status === 'error' ? (
          <div className="other-ports-table__state">{LOAD_FAILED}</div>
        ) : rows.length === 0 ? (
          <div className="other-ports-table__state">Нет данных за выбранный период</div>
        ) : (
          <table className="other-ports-table other-ports-table--compact">
            <thead>
              <tr>
                <th>Транспорт</th>
                <th className="num">Порт</th>
                <th>Сторона</th>
                <th className="num">% в Other</th>
                <th className="num">Гбит/с</th>
                <th className="num">ГБ</th>
                <th className="num">Пакеты</th>
                <th className="num">Потоки</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={`${r.transport}-${r.port}-${r.portSide}-${i}`}>
                  <td>{r.transport}</td>
                  <td className="num mono">{r.port}</td>
                  <td>{formatPortSide(r.portSide)}</td>
                  <td className="num mono">{r.percent.toFixed(2)}%</td>
                  <td className="num mono">{r.avgGbps.toFixed(3)}</td>
                  <td className="num mono">{r.trafficGb.toFixed(3)}</td>
                  <td className="num mono">{fmtNum(r.packets)}</td>
                  <td className="num mono">{fmtNum(r.flows)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Modal>
  );
}

function TrafficStatTile({ label, mode, stats, directions, loadMs, serverMs }) {
  const rows = TRAFFIC_DIRECTIONS.filter((d) => directions?.[d.id]);

  return (
    <Card loadMs={loadMs} serverMs={serverMs}>
      <div className="traffic-stat-tile">
        <div className="traffic-stat-tile__title">{label}</div>
        <div className="traffic-stat-tile__rows">
          {rows.map((d) => {
            const s = stats[d.id] || {};
            const vals = mode === 'volume'
              ? `${fmtVolumeSize(s.gb, s.tb)}, ${fmtMpTotal(s.packets || 0)}`
              : `${fmtGbps(s.bps || 0)}, ${fmtMpps(s.pps || 0)}`;
            return (
              <div key={d.id} className="traffic-stat-tile__row">
                <span className="traffic-stat-tile__dir">
                  <span className="traffic-stat-tile__swatch" style={{ background: d.color }} />
                  {d.label}
                </span>
                <span className="traffic-stat-tile__vals mono">{vals}</span>
              </div>
            );
          })}
        </div>
      </div>
    </Card>
  );
}

Object.assign(window, { PageDashboard, DistributionPane, OtherPortsModal, TrafficStatTile, CountryHeatmapCard, CountryMapModal, RecentFlowsCard });
