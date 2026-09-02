/* Обзор */

const CHART_REFRESH_MS = 60_000;
const DASHBOARD_TALKERS_LIMIT = 7;
const LOAD_FAILED = 'Не удалось загрузить';
const DEFAULT_TREND_SPLIT = 0.5;
const TREND_SPLIT_MIN = 0.35;
const TREND_SPLIT_MAX = 0.65;
const SHARE_RIGHT_SPLIT = 1 / 3;
const DASHBOARD_SPLITTER_WIDTH = 10;

function clampTrendSplit(value) {
  return Math.min(TREND_SPLIT_MAX, Math.max(TREND_SPLIT_MIN, Number(value) || DEFAULT_TREND_SPLIT));
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

const TRAFFIC_STAT_TILES = [
  { id: 'max', label: 'Максимально', mode: 'rate' },
  { id: 'avg', label: 'Среднее', mode: 'rate' },
  { id: 'volume', label: 'Объём', mode: 'volume' },
];

const STAT_WIDGET_DEFS = {
  'stat-max': { tileId: 'max', label: 'Максимально', mode: 'rate' },
  'stat-avg': { tileId: 'avg', label: 'Среднее', mode: 'rate' },
  'stat-volume': { tileId: 'volume', label: 'Объём', mode: 'volume' },
};

const CHART_BUNDLE_WIDGET_IDS = ['traffic-chart', 'distribution-protocols', 'distribution-services'];
const STAT_WIDGET_IDS = ['stat-max', 'stat-avg', 'stat-volume'];

function PageDashboard(props) {
  return props.cabinetMode
    ? <CabinetDashboard {...props} />
    : <OperatorDashboard {...props} />;
}

function OperatorDashboard({
  onNavigate,
  directions,
  timeRange,
  customPeriod,
  collectorFilter,
  displayTimezone,
  onChartRangeSelect,
  readOnly,
}) {
  const canEditLayout = !readOnly;
  const beginHiddenDragRef = useRef(null);
  const {
    layout,
    editMode,
    setEditMode,
    setDistributionSettings,
    resetLayout,
    saveState,
    moveWidget,
    resizeWidget,
    resizeWidgetHeight,
    setWidgetVisible,
    addStack,
    extractFromStack,
  } = useDashboardLayout({ enabled: true, canEdit: canEditLayout });

  const visibleIds = useMemo(() => {
    const widgets = layout.widgets || [];
    const ids = new Set();
    for (const widget of widgets) {
      if (widget.visible === false) continue;
      if (widget.parentStack) {
        const stack = widgets.find((item) => item.id === widget.parentStack);
        if (stack?.visible !== false) ids.add(widget.id);
        continue;
      }
      ids.add(widget.id);
    }
    return ids;
  }, [layout.widgets]);
  const needsStats = useMemo(
    () => STAT_WIDGET_IDS.some((id) => visibleIds.has(id)),
    [visibleIds],
  );
  const needsChartBundle = useMemo(
    () => CHART_BUNDLE_WIDGET_IDS.some((id) => visibleIds.has(id)),
    [visibleIds],
  );
  const layoutDistribution = layout.settings?.distribution || DEFAULT_OPERATOR_LAYOUT.settings.distribution;
  const [protocolsMode, setProtocolsMode] = useState(() => layoutDistribution.protocolsMode || 'share');
  const [servicesMode, setServicesMode] = useState(() => layoutDistribution.servicesMode || 'share');

  useEffect(() => {
    const distribution = layout.settings?.distribution || DEFAULT_OPERATOR_LAYOUT.settings.distribution;
    const nextProtocols = distribution.protocolsMode || 'share';
    const nextServices = distribution.servicesMode || 'share';
    setProtocolsMode((prev) => (prev === nextProtocols ? prev : nextProtocols));
    setServicesMode((prev) => (prev === nextServices ? prev : nextServices));
  }, [
    layout.settings?.distribution?.protocolsMode,
    layout.settings?.distribution?.servicesMode,
  ]);

  const stopDistributionControlEvent = (event) => {
    event.preventDefault();
    event.stopPropagation();
  };
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
    if (!needsChartBundle) return undefined;
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
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey, needsChartBundle]);

  useEffect(() => {
    if (!needsChartBundle || protocolsMode !== 'trend') return undefined;
    if (!visibleIds.has('distribution-protocols')) return undefined;
    let cancelled = false;

    const loadTrend = (initial) => {
      if (initial) setProtocolTrend((s) => ({ ...s, source: 'loading' }));
      ApiClient.loadProtocolTrend({ timeRange, customPeriod, directions, collectorFilter })
        .then((protocolsR) => {
          if (cancelled) return;
          setProtocolTrend({
            source: protocolsR.ok ? 'clickhouse' : 'error',
            series: protocolsR.ok ? (protocolsR.data || { points: [], lines: [] }) : { points: [], lines: [] },
            loadMs: protocolsR.loadMs ?? null,
            serverMs: protocolsR.serverMs ?? null,
          });
        });
    };

    loadTrend(true);
    const timer = setInterval(() => loadTrend(false), CHART_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [protocolsMode, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey, needsChartBundle, visibleIds]);

  useEffect(() => {
    if (!needsChartBundle || servicesMode !== 'trend') return undefined;
    if (!visibleIds.has('distribution-services')) return undefined;
    let cancelled = false;

    const loadTrend = (initial) => {
      if (initial) setServiceTrend((s) => ({ ...s, source: 'loading' }));
      ApiClient.loadServiceTrend({ timeRange, customPeriod, directions, collectorFilter })
        .then((servicesR) => {
          if (cancelled) return;
          setServiceTrend({
            source: servicesR.ok ? 'clickhouse' : 'error',
            series: servicesR.ok ? (servicesR.data || { points: [], lines: [] }) : { points: [], lines: [] },
            loadMs: servicesR.loadMs ?? null,
            serverMs: servicesR.serverMs ?? null,
          });
        });
    };

    loadTrend(true);
    const timer = setInterval(() => loadTrend(false), CHART_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [servicesMode, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey, needsChartBundle, visibleIds]);

  useEffect(() => {
    if (!needsStats) return undefined;
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
  }, [timeRange, customPeriod?.from, customPeriod?.to, collectorFilterKey, needsStats]);

  const onProtocolsModeChange = (mode) => {
    setProtocolsMode(mode);
    setDistributionSettings({ protocolsMode: mode });
  };

  const onServicesModeChange = (mode) => {
    setServicesMode(mode);
    setDistributionSettings({ servicesMode: mode });
  };

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
  const trendRangeHint = onChartRangeSelect ? ' · выделите диапазон на графике' : '';
  const statDirectionDefs = TRAFFIC_DIRECTIONS
    .filter((direction) => directions?.[direction.id])
    .map((direction) => ({ ...direction, enabled: true }));

  const distributionModeToggle = (mode, onChange) => (
    <div
      className="seg distribution-card__switch"
      onMouseDown={stopDistributionControlEvent}
    >
      <button
        type="button"
        className={mode === 'share' ? 'is-active' : ''}
        onMouseDown={stopDistributionControlEvent}
        onClick={(event) => {
          stopDistributionControlEvent(event);
          onChange('share');
        }}
      >
        Доля
      </button>
      <button
        type="button"
        className={mode === 'trend' ? 'is-active' : ''}
        onMouseDown={stopDistributionControlEvent}
        onClick={(event) => {
          stopDistributionControlEvent(event);
          onChange('trend');
        }}
      >
        Динамика
      </button>
    </div>
  );

  const widgetRenderers = {
    'stat-max': () => (
      statsSource === 'error' ? (
        <Card><DataLoadState /></Card>
      ) : (
        <OverviewTrafficStatTile
          label={STAT_WIDGET_DEFS['stat-max'].label}
          mode={STAT_WIDGET_DEFS['stat-max'].mode}
          stats={trafficStats?.[STAT_WIDGET_DEFS['stat-max'].tileId] || {}}
          directionDefs={statDirectionDefs}
          loadMs={statsLoadMs}
          serverMs={statsServerMs}
        />
      )
    ),
    'stat-avg': () => (
      statsSource === 'error' ? (
        <Card><DataLoadState /></Card>
      ) : (
        <OverviewTrafficStatTile
          label={STAT_WIDGET_DEFS['stat-avg'].label}
          mode={STAT_WIDGET_DEFS['stat-avg'].mode}
          stats={trafficStats?.[STAT_WIDGET_DEFS['stat-avg'].tileId] || {}}
          directionDefs={statDirectionDefs}
          loadMs={statsLoadMs}
          serverMs={statsServerMs}
        />
      )
    ),
    'stat-volume': () => (
      statsSource === 'error' ? (
        <Card><DataLoadState /></Card>
      ) : (
        <OverviewTrafficStatTile
          label={STAT_WIDGET_DEFS['stat-volume'].label}
          mode={STAT_WIDGET_DEFS['stat-volume'].mode}
          stats={trafficStats?.[STAT_WIDGET_DEFS['stat-volume'].tileId] || {}}
          directionDefs={statDirectionDefs}
          loadMs={statsLoadMs}
          serverMs={statsServerMs}
        />
      )
    ),
    'traffic-chart': () => (
      <OverviewTrafficChartCard
        title="Полоса пропускания и pps"
        points={chartPoints}
        lines={chartLines}
        ppsLines={chartLines}
        mode={chartMode}
        onModeChange={setChartMode}
        hiddenKeys={chartHidden}
        onToggleLine={toggleChartSeries}
        loading={false}
        failed={(source === 'error' || failedWidgets.series) && source !== 'loading'}
        loadMs={loadTimings.series}
        serverMs={loadServerMs.series}
        displayTimezone={displayTimezone}
        periodStartMs={chartPeriodBounds.startMs}
        periodEndMs={chartPeriodBounds.endMs}
        bucketSeconds={300}
        onRangeSelect={onChartRangeSelect}
        showEmptyState={false}
      />
    ),
    'distribution-protocols': () => (
      <Card pad="sm">
        <div className="distribution-card__head">
          <div className="distribution-card__title">Протоколы</div>
          {distributionModeToggle(protocolsMode, onProtocolsModeChange)}
        </div>
        <OverviewDistributionPane
          title="Протоколы"
          subtitle={protocolsMode === 'share'
            ? `L4 по объёму · ${periodLabel}`
            : `Top 5 L4 · ${periodLabel}${trendRangeHint}`}
          mode={protocolsMode}
          items={protocols}
          trend={protocolTrend}
          chartLongRange={chartLongRange}
          displayTimezone={displayTimezone}
          onRangeSelect={protocolsMode === 'trend' ? onChartRangeSelect : undefined}
          periodStartMs={chartPeriodBounds.startMs}
          periodEndMs={chartPeriodBounds.endMs}
          failed={source === 'error' || failedWidgets.protocols}
          trendFailed={protocolTrend.source === 'error'}
          loadMs={protocolsMode === 'trend' ? protocolTrend.loadMs : loadTimings.protocols}
          serverMs={protocolsMode === 'trend' ? protocolTrend.serverMs : loadServerMs.protocols}
        />
      </Card>
    ),
    'distribution-services': () => (
      <Card pad="sm">
        <div className="distribution-card__head">
          <div className="distribution-card__title">Сервисы</div>
          {distributionModeToggle(servicesMode, onServicesModeChange)}
        </div>
        <OverviewDistributionPane
          title="Сервисы"
          subtitle={servicesMode === 'share'
            ? `L7 по объёму · ${periodLabel}`
            : `Top 5 L7 · ${periodLabel}${trendRangeHint}`}
          mode={servicesMode}
          items={services}
          trend={serviceTrend}
          chartLongRange={chartLongRange}
          displayTimezone={displayTimezone}
          onOtherClick={() => setOtherPortsOpen(true)}
          onRangeSelect={servicesMode === 'trend' ? onChartRangeSelect : undefined}
          periodStartMs={chartPeriodBounds.startMs}
          periodEndMs={chartPeriodBounds.endMs}
          failed={source === 'error' || failedWidgets.services}
          trendFailed={serviceTrend.source === 'error'}
          loadMs={servicesMode === 'trend' ? serviceTrend.loadMs : loadTimings.services}
          serverMs={servicesMode === 'trend' ? serviceTrend.serverMs : loadServerMs.services}
        />
      </Card>
    ),
    vlan: () => (
      <VlanDistributionCard
        enabled={visibleIds.has('vlan')}
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
    ),
    'top-talkers': () => (
      <TopTalkersCard
        enabled={visibleIds.has('top-talkers')}
        onNavigate={onNavigate}
        timeRange={timeRange}
        customPeriod={customPeriod}
        directions={directions}
        directionsKey={directionsKey}
        collectorFilter={collectorFilter}
        periodLabel={periodLabel}
      />
    ),
    countries: () => (
      <CountryHeatmapCard
        enabled={visibleIds.has('countries')}
        timeRange={timeRange}
        customPeriod={customPeriod}
        directions={directions}
        directionsKey={directionsKey}
        collectorFilter={collectorFilter}
        periodLabel={periodLabel}
      />
    ),
    'recent-flows': () => (
      <RecentFlowsCard
        enabled={visibleIds.has('recent-flows')}
        directions={directions}
        directionsKey={directionsKey}
        collectorFilter={collectorFilter}
        displayTimezone={displayTimezone}
      />
    ),
  };

  const layoutToolbar = (sticky = false) => (
    <DashboardLayoutToolbar
      editMode={editMode}
      onToggleEdit={setEditMode}
      onReset={resetLayout}
      onAddVerticalStack={() => addStack('vertical')}
      onAddHorizontalStack={() => addStack('horizontal')}
      saveState={saveState}
      canEdit={canEditLayout}
      widgets={layout.widgets}
      onRestoreWidget={(widgetId) => setWidgetVisible(widgetId, true)}
      onHiddenWidgetDragStart={(widgetId, event) => beginHiddenDragRef.current?.(widgetId, event)}
      className={sticky ? 'dashboard-layout-toolbar--sticky' : ''}
    />
  );

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Сводка по сети</h1>
          <p>Живой обзор трафика, потоков и состояния инфраструктуры.</p>
        </div>
        {editMode ? null : layoutToolbar()}
      </div>
      {editMode ? layoutToolbar(true) : null}

      <DashboardGrid
        layout={layout}
        distributionModes={{ protocols: protocolsMode, services: servicesMode }}
        editMode={editMode}
        renderers={widgetRenderers}
        onMoveWidget={moveWidget}
        onResizeWidget={resizeWidget}
        onResizeWidgetHeight={resizeWidgetHeight}
        onToggleWidgetVisible={setWidgetVisible}
        onExtractFromStack={extractFromStack}
        beginDragRef={beginHiddenDragRef}
      />

      <OtherPortsModal
        open={otherPortsOpen}
        onClose={() => setOtherPortsOpen(false)}
        timeRange={timeRange}
        customPeriod={customPeriod}
        directions={directions}
        collectorFilter={collectorFilter}
        periodLabel={periodLabel}
      />
    </div>
  );
}

const CABINET_OVERVIEW_DIRECTIONS = [
  { id: 'in', label: 'К вам', color: '#51D16D' },
  { id: 'out', label: 'От вас', color: '#6972F0' },
];

function cabinetOverviewState(result, emptyData) {
  return {
    source: result?.source || 'error',
    data: result?.data ?? emptyData,
    meta: result?.meta || null,
    error: result?.error || '',
    status: result?.status || 0,
    loadMs: result?.loadMs ?? null,
    serverMs: result?.serverMs ?? null,
  };
}

function cabinetStatsForTile(data, tile) {
  const output = {};
  for (const direction of ['in', 'out']) {
    const raw = data?.[tile]?.[direction];
    if (raw && typeof raw === 'object') {
      output[direction] = raw;
    } else if (tile === 'volume') {
      const bytes = Number(raw) || 0;
      output[direction] = { gb: (bytes * 8) / 1e9, packets: 0 };
    } else {
      output[direction] = { bps: Number(raw) || 0, pps: 0 };
    }
  }
  return output;
}

function cabinetCountryRows(rows, totalBytes, bounds) {
  const windowSeconds = bounds?.startMs != null && bounds?.endMs != null
    ? Math.max((Number(bounds.endMs) - Number(bounds.startMs)) / 1000, 1)
    : 0;
  return cabinetShareItems(rows, totalBytes).map((row) => {
    const bytes = Number(row.bytes) || 0;
    return {
      ...row,
      countryCode: row.synthetic ? '??' : row.countryCode,
      trafficGb: (bytes * 8) / 1e9,
      avgGbps: windowSeconds > 0 ? (bytes * 8 / windowSeconds) / 1e9 : 0,
      packetCount: Number(row.packets) || 0,
      flowCount: Number(row.flowsCount) || 0,
    };
  });
}

function cabinetServiceDonutItems(rows, totalBytes) {
  const colors = ['#6972F0', '#51D16D', '#F0B400', '#22B8CF', '#A4ADFF', '#D16BA5', '#7F7F9D'];
  return cabinetShareItems(rows, totalBytes).map((row, index) => ({
    ...row,
    label: row.synthetic ? 'Прочее' : formatCabinetServiceLabel(row),
    value: Number(row.sharePercent) || 0,
    percent: Number(row.sharePercent) || 0,
    trafficGb: ((Number(row.bytes) || 0) * 8) / 1e9,
    color: colors[index % colors.length],
    ...(row.synthetic ? { key: 'other' } : {}),
  }));
}

function CabinetDashboard({ onNavigate, timeRange, customPeriod, displayTimezone, onChartRangeSelect }) {
  const periodLabel = timeRangeLabel(timeRange, customPeriod);
  const periodKey = `${timeRange}|${customPeriod?.from || ''}|${customPeriod?.to || ''}`;
  const chartLongRange = isLongChartRange(timeRange, customPeriod);
  const bounds = useMemo(
    () => computeChartPeriodBounds(timeRange, customPeriod),
    [timeRange, customPeriod?.from, customPeriod?.to],
  );
  const [series, setSeries] = useState({ source: 'loading', data: [], meta: null });
  const [stats, setStats] = useState({ source: 'loading', data: null, meta: null });
  const [countries, setCountries] = useState({ source: 'loading', data: [], meta: null });
  const [services, setServices] = useState({ source: 'loading', data: [], meta: null });
  const [recent, setRecent] = useState({ source: 'loading', data: [], meta: null });
  const [countryDirection, setCountryDirection] = useState('in');
  const [serviceDirection, setServiceDirection] = useState('in');
  const [countryMetric, setCountryMetric] = useState('share');
  const [chartMode, setChartMode] = useState('bw');
  const [chartHidden, setChartHidden] = useState(() => new Set());

  useEffect(() => {
    let cancelled = false;
    setSeries({ source: 'loading', data: [], meta: null });
    setStats({ source: 'loading', data: null, meta: null });
    Promise.all([
      ApiClient.loadCabinetOverviewSeries({ timeRange, customPeriod, granularity: 'auto' }),
      ApiClient.loadCabinetOverviewStats({ timeRange, customPeriod }),
    ]).then(([seriesResult, statsResult]) => {
      if (cancelled) return;
      setSeries(cabinetOverviewState(seriesResult, []));
      setStats(cabinetOverviewState(statsResult, null));
    });
    return () => { cancelled = true; };
  }, [periodKey]);

  useEffect(() => {
    let cancelled = false;
    setCountries({ source: 'loading', data: [], meta: null });
    ApiClient.loadCabinetOverviewCountries({
      timeRange, customPeriod, direction: countryDirection, limit: 20,
    }).then((result) => {
      if (!cancelled) setCountries(cabinetOverviewState(result, []));
    });
    return () => { cancelled = true; };
  }, [periodKey, countryDirection]);

  useEffect(() => {
    let cancelled = false;
    setServices({ source: 'loading', data: [], meta: null });
    ApiClient.loadCabinetOverviewServices({
      timeRange, customPeriod, direction: serviceDirection, limit: 20,
    }).then((result) => {
      if (!cancelled) setServices(cabinetOverviewState(result, []));
    });
    return () => { cancelled = true; };
  }, [periodKey, serviceDirection]);

  useEffect(() => {
    let cancelled = false;
    setRecent({ source: 'loading', data: [], meta: null });
    ApiClient.loadCabinetOverviewRecentFlows({ limit: 20 }).then((result) => {
      if (!cancelled) setRecent(cabinetOverviewState(result, []));
    });
    return () => { cancelled = true; };
  }, []);

  const chart = useMemo(
    () => cabinetSeriesToChart(series.data, series.meta),
    [series.data, series.meta?.granularity],
  );
  const chartPoints = useMemo(
    () => (chart.points || []).map((point) => ({
      ...point,
      t: formatPointTimeLabel(point, chartLongRange, displayTimezone),
    })),
    [chart.points, chartLongRange, displayTimezone],
  );
  const countryRows = useMemo(
    () => cabinetCountryRows(countries.data, countries.meta?.totalBytes, bounds),
    [countries.data, countries.meta?.totalBytes, bounds],
  );
  const serviceItems = useMemo(
    () => cabinetServiceDonutItems(services.data, services.meta?.totalBytes),
    [services.data, services.meta?.totalBytes],
  );
  const toggleChartLine = (key) => setChartHidden((previous) => {
    const next = new Set(previous);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Сводка по сети</h1>
          <p>Обзор входящего и исходящего трафика вашей сети.</p>
        </div>
        {onNavigate && (
          <Button
            kind="ghost"
            size="sm"
            iconRight="arrowURight"
            onClick={() => openCabinetExplorer(onNavigate, { timeRange, customPeriod })}
          >
            Разбор трафика
          </Button>
        )}
      </div>

      <div className="grid traffic-stat-grid grid--mb">
        {stats.source === 'error' ? (
          <Card style={{ gridColumn: '1 / -1' }}>
            <OverviewDataState error={stats.error} status={stats.status} />
          </Card>
        ) : ['max', 'avg', 'volume'].map((id) => (
          <OverviewTrafficStatTile
            key={id}
            label={id === 'max' ? 'Максимально' : id === 'avg' ? 'Среднее' : 'Объём'}
            mode={id === 'volume' ? 'volume' : 'rate'}
            stats={cabinetStatsForTile(stats.data, id)}
            directionDefs={CABINET_OVERVIEW_DIRECTIONS}
            loadMs={stats.loadMs}
            serverMs={stats.serverMs}
          />
        ))}
      </div>

      <DashboardChartRow distributionMode="share" trendSplit={SHARE_RIGHT_SPLIT} onTrendSplitChange={() => {}}>
        <OverviewTrafficChartCard
          title="Полоса пропускания и pps"
          subtitle={periodLabel}
          points={chartPoints}
          lines={chart.lines}
          ppsLines={chart.lines}
          mode={chartMode}
          onModeChange={setChartMode}
          hiddenKeys={chartHidden}
          onToggleLine={toggleChartLine}
          loading={series.source === 'loading'}
          failed={series.source === 'error'}
          error={series.error}
          status={series.status}
          loadMs={series.loadMs}
          serverMs={series.serverMs}
          displayTimezone={displayTimezone}
          periodStartMs={bounds.startMs}
          periodEndMs={bounds.endMs}
          bucketSeconds={chart.bucketSeconds}
          onRangeSelect={onChartRangeSelect}
        />
        <Card pad="sm">
          <div className="distribution-card__head">
            <div className="distribution-card__title">Сервисы</div>
            <OverviewDirectionToggle value={serviceDirection} onChange={setServiceDirection} />
          </div>
          <div className="distribution-split distribution-split--solo">
            <OverviewDistributionPane
              title="Сервисы по объёму"
              subtitle={`${periodLabel} · ${serviceDirection === 'in' ? 'к вам' : 'от вас'}`}
              items={serviceItems}
              failed={services.source === 'error'}
              error={services.error}
              status={services.status}
              loadMs={services.loadMs}
              serverMs={services.serverMs}
              centered
            />
          </div>
        </Card>
      </DashboardChartRow>

      <div className="grid grid--1col grid--mb">
        <OverviewCountryCard
          subtitle={`${periodLabel} · ${countryDirection === 'in' ? 'к вам' : 'от вас'}`}
          rows={countryRows}
          colorMetric={countryMetric}
          onColorMetricChange={setCountryMetric}
          extraTools={<OverviewDirectionToggle value={countryDirection} onChange={setCountryDirection} />}
          loading={countries.source === 'loading'}
          failed={countries.source === 'error'}
          error={countries.error}
          status={countries.status}
          loadMs={countries.loadMs}
          serverMs={countries.serverMs}
          listKey={`${periodKey}|${countryDirection}`}
        />
      </div>

      <OverviewRecentFlowsCard
        rows={recent.data}
        source={recent.source}
        error={recent.error}
        status={recent.status}
        subtitle="Последние минуты, независимо от выбранного периода"
        loadMs={recent.loadMs}
        serverMs={recent.serverMs}
        displayTimezone={displayTimezone}
        cabinetMode
      />
    </div>
  );
}

function RecentFlowsCard({ enabled = true, directions, directionsKey, collectorFilter, displayTimezone }) {
  const collectorFilterKey = (collectorFilter || []).join('|');
  const [rows, setRows] = useState([]);
  const [flowsSource, setFlowsSource] = useState('loading');
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);

  const directionFilterLabel = directionSummaryLabel(directions);

  useEffect(() => {
    if (!enabled) return undefined;
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
  }, [enabled, directionsKey, collectorFilterKey]);

  return (
    <OverviewRecentFlowsCard
      rows={rows}
      source={flowsSource}
      subtitle={directionFilterLabel}
      loadMs={loadMs}
      serverMs={serverMs}
      displayTimezone={displayTimezone}
      emptyLabel="Нет потоков для выбранного направления"
    />
  );
}

function TopTalkersCard({
  enabled = true,
  onNavigate,
  timeRange,
  customPeriod,
  directions,
  directionsKey,
  collectorFilter,
  periodLabel,
}) {
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
    if (!enabled) return undefined;
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
  }, [enabled, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, group, collectorFilterKey]);

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

function CountryHeatmapCard({
  enabled = true,
  timeRange,
  customPeriod,
  directions,
  directionsKey,
  collectorFilter,
  periodLabel,
}) {
  const collectorFilterKey = (collectorFilter || []).join('|');
  const [countryBasis, setCountryBasis] = useState('ip');
  const [mapSide, setMapSide] = useState('remote');
  const [colorMetric, setColorMetric] = useState('share');
  const [countryRows, setCountryRows] = useState([]);
  const [countrySource, setCountrySource] = useState('loading');
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);

  const flowDirections = TRAFFIC_DIRECTIONS.filter((d) => d.id !== 'total');
  const enabledFlow = flowDirections.filter((d) => directions?.[d.id]);
  const onlyInternal = enabledFlow.length === 1 && enabledFlow[0].id === 'internal';
  const showInternalHint = onlyInternal && mapSide === 'remote';

  const basisLabel = COUNTRY_BASIS_LABELS[countryBasis] || countryBasis;

  useEffect(() => {
    if (!enabled) return undefined;
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
  }, [enabled, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, countryBasis, mapSide, collectorFilterKey]);

  const countryListKey = `${directionsKey}|${countryBasis}|${mapSide}|${timeRange}|${customPeriod?.from}|${customPeriod?.to}|${collectorFilterKey || ''}`;
  return (
    <OverviewCountryCard
      title="География источников"
      subtitle={`${periodLabel} · ${basisLabel}`}
      rows={countryRows}
      colorMetric={colorMetric}
      onColorMetricChange={setColorMetric}
      loading={countrySource === 'loading'}
      failed={countrySource === 'error'}
      loadMs={loadMs}
      serverMs={serverMs}
      listKey={countryListKey}
      extraTools={
        <>
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
        </>
      }
      notice={showInternalHint ? (
        <div className="country-heatmap-hint">
          Для internal используйте src или dst
        </div>
      ) : null}
    />
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

function VlanDistributionCard({
  enabled = true,
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
    if (!enabled) return undefined;
    let cancelled = false;
    setShare((s) => ({ ...s, source: 'loading' }));
    ApiClient.dashboardVlans({ timeRange, customPeriod, directions, collectorFilter })
      .then((data) => {
        if (cancelled) return;
        setShare({ source: 'clickhouse', items: Array.isArray(data) ? data : [] });
      })
      .catch(() => { if (!cancelled) setShare({ source: 'error', items: [] }); });
    return () => { cancelled = true; };
  }, [enabled, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey]);

  useEffect(() => {
    if (!enabled || mode !== 'trend') return undefined;
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
  }, [enabled, mode, timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey]);

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
            <Button kind="ghost" size="sm" onClick={() => onNavigate('vlan')}>Моя сеть · VLAN</Button>
          )}
          <div className="seg distribution-card__switch">
            <button type="button" className={mode === 'share' ? 'is-active' : ''} onClick={() => setMode('share')}>Доля</button>
            <button type="button" className={mode === 'trend' ? 'is-active' : ''} onClick={() => setMode('trend')}>Динамика</button>
          </div>
        </div>
      </div>
      <div className={`distribution-split distribution-split--solo${mode === 'trend' ? ' distribution-split--solo-trend' : ''}`}>
        <OverviewDistributionPane
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

Object.assign(window, { PageDashboard, OtherPortsModal, CountryHeatmapCard, RecentFlowsCard });
