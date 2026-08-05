/* Разбор DNS — исследование dns_log по образцу Explorer */

const DNS_EXPLORER_DEFAULT_METRIC = 'queries_per_sec';
const DNS_EXPLORER_DEFAULT_LIMIT = 50;
const DNS_EXPLORER_DEFAULT_VISUAL_LIMIT = 5;
const DNS_EXPLORER_CHART_HEIGHT = 196;

const DNS_RCODE_OPTIONS = [
  { value: '0', label: 'Успешно' },
  { value: '2', label: 'Ошибка DNS-сервера' },
  { value: '3', label: 'Домен не найден' },
  { value: 'other', label: 'Другой код' },
];

const DNS_FIELD_OPS = {
  client_ip: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in_cidr', label: 'входит в CIDR' },
  ],
  query_name: [
    { id: 'eq', label: 'равно' },
    { id: 'contains', label: 'содержит' },
    { id: 'not_contains', label: 'не содержит' },
  ],
  server_ip: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in_cidr', label: 'входит в CIDR' },
  ],
  qtype: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in', label: 'один из' },
  ],
  rcode: [
    { id: 'eq', label: 'равно' },
    { id: 'ne', label: 'не равно' },
    { id: 'in', label: 'один из' },
  ],
  source_id: [{ id: 'in', label: 'один из' }],
};

function cloneDnsExplorerFilters(filters) {
  return (filters || []).map((f) => ({ ...f, values: f.values ? [...f.values] : undefined }));
}

function dnsExplorerFilterLabel(fieldId, schema) {
  return schema?.fields?.find((f) => f.id === fieldId)?.label || fieldId;
}

function dnsExplorerMetricLabel(metricId, schema) {
  return schema?.metrics?.find((m) => m.id === metricId)?.label || metricId;
}

function dnsExplorerGroupLabel(groupId, schema) {
  return schema?.groupBy?.find((g) => g.id === groupId)?.label || groupId;
}

function buildDnsExplorerPayload({
  metric,
  groupBy,
  filters,
  timeRange,
  customPeriod,
  collectorFilter,
  limit,
}) {
  const body = {
    metric,
    groupBy,
    filters,
    limit,
    range: timeRange,
  };
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    body.from = customPeriod.from;
    body.to = customPeriod.to;
  }
  if (collectorFilter?.length) {
    body.collectorId = collectorFilter.join(',');
  }
  return body;
}

function defaultDnsChartSeriesIds(rows, limit = DNS_EXPLORER_DEFAULT_VISUAL_LIMIT) {
  return new Set(sliceDnsVisualRows(rows, limit).map((r) => r.id));
}

function resolveDnsVisualCount(visualLimit, total) {
  if (visualLimit === 'all') return total;
  const n = Number(visualLimit);
  if (!Number.isFinite(n) || n <= 0) return Math.min(DNS_EXPLORER_DEFAULT_VISUAL_LIMIT, total);
  return Math.min(n, total);
}

function sliceDnsVisualRows(rows, visualLimit) {
  return (rows || []).slice(0, resolveDnsVisualCount(visualLimit, rows?.length || 0));
}

function isDnsDisplayLimitActive(buttonLimit, visualLimit, fetchLimit) {
  if (visualLimit === 'all') return buttonLimit === fetchLimit;
  return Number(visualLimit) === buttonLimit;
}

function DnsExplorerVisualLimitControl({ total, fetchLimit, value, onChange }) {
  const shown = resolveDnsVisualCount(value, total);
  const instantOptions = [5, 10, 25, 50].filter((n) => n <= fetchLimit);
  if (total <= DNS_EXPLORER_DEFAULT_VISUAL_LIMIT && fetchLimit <= DNS_EXPLORER_DEFAULT_VISUAL_LIMIT) return null;

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
              className={isDnsDisplayLimitActive(opt, value, fetchLimit) ? 'is-active' : ''}
              onClick={() => onChange(opt)}
            >
              {opt}
            </button>
          ))}
          {fetchLimit > DNS_EXPLORER_DEFAULT_VISUAL_LIMIT && (
            <button
              type="button"
              className={value === 'all' ? 'is-active' : ''}
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

function dnsExplorerDimDisplayValue(value, fieldId) {
  if (fieldId === 'rcode') {
    const n = Number(value);
    if (n === 0) return 'Успешно';
    if (n === 2) return 'Ошибка DNS-сервера';
    if (n === 3) return 'Домен не найден';
    if (Number.isFinite(n)) return 'Другой код';
  }
  return value ?? '—';
}

function dnsExplorerRowLabel(row, groupBy) {
  return (row?.values || []).map((val, idx) => dnsExplorerDimDisplayValue(val, groupBy[idx])).join(' · ');
}

function dnsExplorerMetricKind(metricId, schema) {
  return schema?.metrics?.find((m) => m.id === metricId)?.kind
    || (String(metricId || '').endsWith('_per_sec') ? 'rate' : 'total');
}

function formatDnsMetric(value, metric, schema) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  if (dnsExplorerMetricKind(metric, schema) === 'rate') {
    if (n >= 1e6) return `${(n / 1e6).toFixed(n >= 10e6 ? 0 : 1)} млн/с`;
    if (n >= 1e3) return `${(n / 1e3).toFixed(n >= 10e3 ? 0 : 1)} тыс/с`;
    if (n > 0 && n < 10 && !Number.isInteger(n)) return `${n.toFixed(1)}/с`;
    return `${fmtNum(n)}/с`;
  }
  return fmtNum(n);
}

function formatDnsMetricAxis(value, metric, schema) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '0';
  if (dnsExplorerMetricKind(metric, schema) === 'rate') {
    if (n >= 1e6) return `${(n / 1e6).toFixed(n >= 10e6 ? 0 : 1)}M`;
    if (n >= 1e3) return `${(n / 1e3).toFixed(n >= 10e3 ? 0 : 1)}k`;
    return n < 10 && !Number.isInteger(n) ? n.toFixed(1) : String(Math.round(n));
  }
  return fmtCompact(n);
}

function dnsMetricAxisUnit(metric, schema) {
  return dnsExplorerMetricLabel(metric, schema) || '';
}

function dnsExplorerTableMetricTitle(metricId, schema) {
  const label = dnsExplorerMetricLabel(metricId, schema);
  if (dnsExplorerMetricKind(metricId, schema) === 'rate') {
    return `${label} (ср.)`;
  }
  return label;
}

function DnsExplorerChartToggleButton({ onChart, onClick }) {
  return (
    <button
      type="button"
      className={`badge explorer-row-actions__btn${onChart ? ' badge--info' : ''}`}
      title={onChart ? 'Скрыть серию с графика динамики' : 'Показать серию на графике динамики'}
      onClick={onClick}
    >
      <span className="explorer-row-actions__label explorer-row-actions__label--full">{onChart ? 'Скрыть с графика' : 'Показать'}</span>
      <span className="explorer-row-actions__label explorer-row-actions__label--short">{onChart ? 'Скрыть' : 'Показать'}</span>
    </button>
  );
}

function DnsExplorerTotalChart({
  points,
  metric,
  metricLabel,
  schema,
  displayTimezone,
  chartLongRange,
  bucketSeconds,
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
          height={DNS_EXPLORER_CHART_HEIGHT}
          mode="bw"
          gapAsZero
          bucketSeconds={bucketSeconds}
          displayTimezone={displayTimezone}
          valueFormatter={(value) => formatDnsMetric(value, metric, schema)}
          axisFormatter={(value) => formatDnsMetricAxis(value, metric, schema)}
          yAxisUnit={dnsMetricAxisUnit(metric, schema)}
        />
      </div>
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
        Ось Y — {metricLabel || metric} по всем DNS-событиям, соответствующим условиям, в каждом временном интервале.
      </div>
    </div>
  );
}

function DnsExplorerDynamicsChart({
  results,
  resultSeries,
  metric,
  metricLabel,
  schema,
  displayTimezone,
  chartLongRange,
  selectedSeriesIds,
  groupBy,
  bucketSeconds,
}) {
  const [chartKey, setChartKey] = useState(0);
  const selectedSeriesKey = [...selectedSeriesIds].sort().join('|');
  useEffect(() => {
    setChartKey((k) => k + 1);
  }, [selectedSeriesKey]);

  const seriesByRow = resultSeries?.seriesByRow || {};
  const resultIdSet = new Set(results.map((r) => r.id));
  const selectedIds = [...selectedSeriesIds].filter((id) => resultIdSet.has(id));
  const lines = results
    .filter((r) => selectedIds.includes(r.id))
    .map((row) => ({
      key: row.id,
      label: dnsExplorerRowLabel(row, groupBy),
      color: row.color,
    }));

  const pointsByBucket = new Map();
  for (const rowId of selectedIds) {
    for (const pt of seriesByRow[rowId] || []) {
      const bucket = normalizeBucketString(pt.bucket);
      if (!pointsByBucket.has(bucket)) {
        pointsByBucket.set(bucket, { ...pt, bucket });
      }
      const current = Number(pointsByBucket.get(bucket)[rowId]) || 0;
      pointsByBucket.get(bucket)[rowId] = current + (Number(pt.value) || 0);
    }
  }

  const points = [...pointsByBucket.values()]
    .sort((a, b) => (resolvePointEpochMs(a) || 0) - (resolvePointEpochMs(b) || 0))
    .map((pt) => {
      const next = { ...pt };
      for (const rowId of selectedIds) {
        if (next[rowId] == null) next[rowId] = 0;
      }
      next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
      if (next.bucketMs != null) next.bucketMs = Number(next.bucketMs);
      return next;
    });
  const chartPoints = points.length === 1 ? [points[0], { ...points[0] }] : points;

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
              height={DNS_EXPLORER_CHART_HEIGHT}
              mode="bw"
              gapAsZero
              bucketSeconds={bucketSeconds}
              displayTimezone={displayTimezone}
              valueFormatter={(v) => formatDnsMetric(v, metric, schema)}
              axisFormatter={(v) => formatDnsMetricAxis(v, metric, schema)}
              yAxisUnit={dnsMetricAxisUnit(metric, schema)}
            />
          </div>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginTop: -4 }}>
            Ось Y — {metricLabel || metric} в каждом временном интервале. В таблице — среднее за период.
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

function DnsExplorerFilterRow({
  row,
  index,
  schema,
  suggestCtx,
  onChange,
  onRemove,
  dnsSources,
}) {
  const ops = DNS_FIELD_OPS[row.field] || [{ id: 'eq', label: 'равно' }];
  const [suggestions, setSuggestions] = useState([]);
  const [qtypes, setQtypes] = useState([]);

  useEffect(() => {
    if (row.field === 'qtype') {
      ApiClient.suggestDnsExplorerQtypes(suggestCtx).then(setQtypes).catch(() => setQtypes([]));
    }
  }, [row.field, suggestCtx]);

  useEffect(() => {
    if (!row.value || row.field === 'rcode' || row.field === 'source_id' || row.field === 'qtype') {
      setSuggestions([]);
      return undefined;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      const loader = row.field === 'query_name'
        ? ApiClient.suggestDnsExplorerDomains
        : row.field === 'client_ip'
          ? ApiClient.suggestDnsExplorerClientIps
          : row.field === 'server_ip'
            ? ApiClient.suggestDnsExplorerServerIps
            : null;
      if (!loader) return;
      loader(suggestCtx, row.value).then((items) => {
        if (!cancelled) setSuggestions(items);
      }).catch(() => { if (!cancelled) setSuggestions([]); });
    }, 300);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [row.field, row.value, suggestCtx]);

  const renderValueInput = () => {
    if (row.field === 'rcode') {
      if (row.op === 'in') {
        return (
          <select
            className="input"
            multiple
            value={row.values || []}
            onChange={(e) => onChange(index, {
              ...row,
              values: [...e.target.selectedOptions].map((o) => o.value),
            })}
          >
            {DNS_RCODE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        );
      }
      return (
        <select className="input" value={row.value || ''} onChange={(e) => onChange(index, { ...row, value: e.target.value })}>
          <option value="">Выберите…</option>
          {DNS_RCODE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      );
    }
    if (row.field === 'source_id') {
      return (
        <select
          className="input"
          multiple
          value={row.values || []}
          onChange={(e) => onChange(index, {
            ...row,
            values: [...e.target.selectedOptions].map((o) => o.value),
          })}
        >
          {(dnsSources || []).map((s) => (
            <option key={s.sourceId} value={s.sourceId}>{s.displayName || s.sourceId}</option>
          ))}
        </select>
      );
    }
    if (row.field === 'qtype' && row.op === 'in') {
      return (
        <select
          className="input"
          multiple
          value={row.values || []}
          onChange={(e) => onChange(index, {
            ...row,
            values: [...e.target.selectedOptions].map((o) => o.value),
          })}
        >
          {qtypes.map((o) => (
            <option key={o.value} value={o.value}>{o.value} ({fmtNum(o.count)})</option>
          ))}
        </select>
      );
    }
    return (
      <div className="dns-explorer-suggest">
        <input
          className="input"
          value={row.value || ''}
          onChange={(e) => onChange(index, { ...row, value: e.target.value })}
          placeholder="Значение"
          list={`dns-explorer-suggest-${index}`}
        />
        {suggestions.length > 0 && (
          <datalist id={`dns-explorer-suggest-${index}`}>
            {suggestions.map((s) => (
              <option key={s.value} value={s.value}>{s.resolverLabel ? `${s.value} · ${s.resolverLabel}` : s.value}</option>
            ))}
          </datalist>
        )}
      </div>
    );
  };

  return (
    <div className="dns-explorer-filter-row">
      <select
        className="input"
        value={row.field}
        onChange={(e) => onChange(index, { field: e.target.value, op: DNS_FIELD_OPS[e.target.value]?.[0]?.id || 'eq', value: '' })}
      >
        {(schema?.fields || []).map((f) => (
          <option key={f.id} value={f.id}>{f.label}</option>
        ))}
      </select>
      <select className="input" value={row.op} onChange={(e) => onChange(index, { ...row, op: e.target.value })}>
        {ops.map((o) => (
          <option key={o.id} value={o.id}>{o.label}</option>
        ))}
      </select>
      {renderValueInput()}
      <button type="button" className="icon-btn" title="Удалить условие" onClick={() => onRemove(index)}>
        <Icon name="x" size={14} />
      </button>
    </div>
  );
}

function PageDnsExplorer({ onNavigate, displayTimezone }) {
  const urlGlobals = useMemo(() => applyDnsExplorerUrlGlobals(parseAppHash().params), []);
  const urlState = useMemo(() => readDnsExplorerPageParamsFromHash?.() || null, []);

  const [schema, setSchema] = useState(null);
  const [dnsSources, setDnsSources] = useState([]);
  const [timeRange, setTimeRange] = useState(urlGlobals.timeRange || '24h');
  const [customPeriod, setCustomPeriod] = useState(urlGlobals.customPeriod || defaultCustomPeriod());
  const [collectorFilter, setCollectorFilter] = useState(urlGlobals.collectorFilter || []);
  const [metric, setMetric] = useState(urlState?.metric || DNS_EXPLORER_DEFAULT_METRIC);
  const [groupBy, setGroupBy] = useState(urlState?.groupBy || []);
  const [filters, setFilters] = useState(() => cloneDnsExplorerFilters(urlState?.filters?.length ? urlState.filters : []));
  const initialDraftRef = useRef({
    metric: urlState?.metric || DNS_EXPLORER_DEFAULT_METRIC,
    groupBy: urlState?.groupBy || [],
    filters: cloneDnsExplorerFilters(urlState?.filters?.length ? urlState.filters : []),
    timeRange: urlGlobals.timeRange || '24h',
    customPeriod: urlGlobals.customPeriod || defaultCustomPeriod(),
    collectorFilter: urlGlobals.collectorFilter || [],
  });
  const [appliedSnapshot, setAppliedSnapshot] = useState(null);
  const [hasAppliedQuery, setHasAppliedQuery] = useState(false);
  const [source, setSource] = useState('idle');
  const [error, setError] = useState(null);
  const [meta, setMeta] = useState(null);
  const [timeseries, setTimeseries] = useState([]);
  const [resultSeries, setResultSeries] = useState(null);
  const [rows, setRows] = useState([]);
  const [visualLimit, setVisualLimit] = useState(DNS_EXPLORER_DEFAULT_VISUAL_LIMIT);
  const [chartSeriesIds, setChartSeriesIds] = useState(() => new Set());
  const prevVisualLimitRef = useRef(null);
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);

  useEffect(() => {
    ApiClient.loadDnsExplorerSchema().then(setSchema).catch(() => setSchema(null));
    ApiClient.loadDnsSources().then((r) => setDnsSources(r.rows || [])).catch(() => setDnsSources([]));
  }, []);

  const suggestCtx = useMemo(() => ({
    timeRange,
    customPeriod,
    collectorFilter,
    filters,
  }), [timeRange, customPeriod?.from, customPeriod?.to, collectorFilter, filters]);

  const draftDirty = appliedSnapshot
    ? (
      appliedSnapshot.metric !== metric
      || JSON.stringify(appliedSnapshot.groupBy) !== JSON.stringify(groupBy)
      || JSON.stringify(appliedSnapshot.filters) !== JSON.stringify(filters)
      || appliedSnapshot.timeRange !== timeRange
      || appliedSnapshot.customPeriod?.from !== customPeriod?.from
      || appliedSnapshot.customPeriod?.to !== customPeriod?.to
      || (appliedSnapshot.collectorFilter || []).join(',') !== (collectorFilter || []).join(',')
    )
    : hasAppliedQuery
      ? false
      : (
        initialDraftRef.current.metric !== metric
        || JSON.stringify(initialDraftRef.current.groupBy) !== JSON.stringify(groupBy)
        || JSON.stringify(initialDraftRef.current.filters) !== JSON.stringify(filters)
        || initialDraftRef.current.timeRange !== timeRange
        || initialDraftRef.current.customPeriod?.from !== customPeriod?.from
        || initialDraftRef.current.customPeriod?.to !== customPeriod?.to
        || (initialDraftRef.current.collectorFilter || []).join(',') !== (collectorFilter || []).join(',')
      );

  const runQuery = async () => {
    setSource('loading');
    setError(null);
    const snapshot = {
      metric,
      groupBy: [...groupBy],
      filters: cloneDnsExplorerFilters(filters),
      timeRange,
      customPeriod: { ...customPeriod },
      collectorFilter: [...(collectorFilter || [])],
    };
    const payload = buildDnsExplorerPayload({ ...snapshot, limit: DNS_EXPLORER_DEFAULT_LIMIT });
    const result = await ApiClient.runDnsExplorerQuery(payload);
    if (!result.ok) {
      setSource('error');
      setError(result.message || ApiClient.LOAD_FAILED);
      setRows([]);
      setTimeseries([]);
      setResultSeries(null);
      setChartSeriesIds(new Set());
      setMeta(null);
      return;
    }
    const apiRows = result.data?.rows || [];
    setAppliedSnapshot(snapshot);
    setHasAppliedQuery(true);
    setSource('clickhouse');
    setMeta(result.meta);
    setLoadMs(result.loadMs);
    setServerMs(result.serverMs);
    setRows(apiRows);
    setTimeseries(result.data?.timeseries || []);
    setResultSeries(result.data?.resultSeries || null);
    setChartSeriesIds(snapshot.groupBy?.length
      ? defaultDnsChartSeriesIds(apiRows, visualLimit)
      : new Set());
  };

  useEffect(() => {
    if (prevVisualLimitRef.current === null) {
      prevVisualLimitRef.current = visualLimit;
      return;
    }
    if (prevVisualLimitRef.current === visualLimit) return;
    prevVisualLimitRef.current = visualLimit;
    if (!hasAppliedQuery || !(appliedSnapshot?.groupBy || []).length || !rows.length) return;
    setChartSeriesIds(defaultDnsChartSeriesIds(rows, visualLimit));
  }, [visualLimit, hasAppliedQuery, appliedSnapshot?.groupBy, rows]);

  const toggleChartSeries = (rowId) => {
    setChartSeriesIds((prev) => {
      const next = new Set(prev);
      if (next.has(rowId)) next.delete(rowId);
      else next.add(rowId);
      return next;
    });
  };

  const addFilter = () => {
    setFilters((prev) => [...prev, { field: 'query_name', op: 'contains', value: '' }]);
  };

  const updateFilter = (index, next) => {
    setFilters((prev) => prev.map((row, i) => (i === index ? next : row)));
  };

  const removeFilter = (index) => {
    setFilters((prev) => prev.filter((_, i) => i !== index));
  };

  const tableColumns = useMemo(() => {
    const appliedGroup = appliedSnapshot?.groupBy || [];
    if (!appliedGroup.length) return [];
    const cols = appliedGroup.map((id, idx) => ({
      key: `dim_${idx}`,
      title: dnsExplorerGroupLabel(id, schema),
      headerClassName: 'explorer-col-dim',
      cellClassName: 'explorer-col-dim',
      render: (row) => (
        idx === 0 ? (
          <div className="explorer-dim-cell">
            <span className="explorer-dim-cell__swatch" style={{ background: row.color }} aria-hidden="true" />
            <span className="mono">{dnsExplorerDimDisplayValue(row.values?.[idx], id)}</span>
          </div>
        ) : (
          <span className="mono">{dnsExplorerDimDisplayValue(row.values?.[idx], id)}</span>
        )
      ),
    }));
    cols.push({
      key: 'value',
      title: dnsExplorerTableMetricTitle(appliedSnapshot?.metric, schema),
      align: 'right',
      num: true,
      headerClassName: 'explorer-col-metric',
      cellClassName: 'explorer-col-metric',
      render: (r) => formatDnsMetric(r.value, appliedSnapshot?.metric, schema),
    });
    cols.push({
      key: 'actions',
      title: '',
      sortable: false,
      headerClassName: 'explorer-col-actions',
      cellClassName: 'explorer-col-actions',
      render: (row) => (
        <div className="explorer-row-actions">
          <DnsExplorerChartToggleButton
            onChart={chartSeriesIds.has(row.id)}
            onClick={() => toggleChartSeries(row.id)}
          />
        </div>
      ),
    });
    return cols;
  }, [appliedSnapshot, schema, chartSeriesIds]);

  const appliedGroupBy = appliedSnapshot?.groupBy || [];
  const chartLongRange = isLongChartRange(appliedSnapshot?.timeRange || timeRange, appliedSnapshot?.customPeriod || customPeriod);
  const chartBucketSeconds = dnsBucketSecondsFromMode(meta?.bucketMode);
  const appliedMetricLabel = dnsExplorerMetricLabel(appliedSnapshot?.metric, schema);
  const visibleResults = useMemo(
    () => sliceDnsVisualRows(rows, visualLimit),
    [rows, visualLimit],
  );
  const visiblePageSize = Math.max(resolveDnsVisualCount(visualLimit, visibleResults.length), 1);

  const copyShareUrl = () => {
    if (!appliedSnapshot) return;
    const url = buildDnsExplorerShareUrl({
      ...appliedSnapshot,
    });
    navigator.clipboard?.writeText(url);
  };

  return (
    <div className="main__container dns-explorer-page">
      <div className="page-head">
        <div>
          <h1>Разбор DNS</h1>
          <p>Исследование DNS-запросов по условиям · {timeRangeLabel(timeRange, customPeriod)}</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" size="sm" onClick={() => onNavigate?.('dns')}>Вернуться в обзор DNS</Button>
          {hasAppliedQuery && (
            <Button kind="ghost" size="sm" icon="link" onClick={copyShareUrl}>Копировать ссылку</Button>
          )}
        </div>
      </div>

      <Card pad="sm" className="dns-explorer-builder">
        <div className="dns-explorer-builder__row">
          <label className="dns-explorer-builder__field">
            <span>Период</span>
            <TimeFilter
              variant="explorer"
              timeRange={timeRange}
              onTimeRangeChange={setTimeRange}
              customPeriod={customPeriod}
              onCustomPeriodChange={setCustomPeriod}
              displayTimezone={displayTimezone}
            />
          </label>
          <label className="dns-explorer-builder__field">
            <span>Метрика</span>
            <select className="input" value={metric} onChange={(e) => setMetric(e.target.value)}>
              {(schema?.metrics || []).map((m) => (
                <option key={m.id} value={m.id}>{m.label}</option>
              ))}
            </select>
          </label>
          <label className="dns-explorer-builder__field dns-explorer-builder__field--grow">
            <span>Группировка</span>
            <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
              {groupBy.map((id) => (
                <span key={id} className="badge badge--info" style={{ padding: '4px 10px', gap: 6 }}>
                  {dnsExplorerGroupLabel(id, schema)}
                  <button type="button" className="icon-btn" style={{ width: 18, height: 18 }} onClick={() => setGroupBy((g) => g.filter((x) => x !== id))}>
                    <Icon name="x" size={10} />
                  </button>
                </span>
              ))}
              <select
                className="input"
                value=""
                onChange={(e) => {
                  const id = e.target.value;
                  if (id && !groupBy.includes(id)) setGroupBy((g) => [...g, id]);
                  e.target.value = '';
                }}
              >
                <option value="">+ Измерение</option>
                {(schema?.groupBy || []).filter((g) => !groupBy.includes(g.id)).map((g) => (
                  <option key={g.id} value={g.id}>{g.label}</option>
                ))}
              </select>
            </div>
          </label>
        </div>

        <div className="dns-explorer-builder__filters">
          <div className="dns-explorer-builder__filters-head">
            <strong>Условия</strong>
            <Button kind="ghost" size="sm" icon="plus" onClick={addFilter}>Добавить</Button>
          </div>
          {filters.length === 0 ? (
            <div className="dns-explorer-builder__empty">Условия не заданы — будет показана суммарная динамика.</div>
          ) : (
            filters.map((row, index) => (
              <DnsExplorerFilterRow
                key={`${row.field}-${index}`}
                row={row}
                index={index}
                schema={schema}
                suggestCtx={suggestCtx}
                onChange={updateFilter}
                onRemove={removeFilter}
                dnsSources={dnsSources}
              />
            ))
          )}
        </div>

        <div className="dns-explorer-builder__actions">
          {draftDirty && <span className="dns-explorer-builder__dirty">Есть неприменённые изменения</span>}
          <Button kind="primary" icon="play" onClick={runQuery} disabled={source === 'loading'}>Построить</Button>
        </div>
      </Card>

      {source === 'loading' ? (
        <Card pad="sm">
          <div className="explorer-refreshing-data">Получение данных</div>
        </Card>
      ) : !hasAppliedQuery ? (
        <Card pad="sm">
          <div className="other-ports-table__state">Задайте условия и нажмите «Построить».</div>
        </Card>
      ) : source === 'error' ? (
        <Card pad="sm"><div className="other-ports-table__state" style={{ color: 'var(--st-critical)' }}>{error}</div></Card>
      ) : (
        appliedGroupBy.length === 0 ? (
          <Card
            title={`Динамика · ${appliedMetricLabel}`}
            subtitle={`${timeRangeLabel(appliedSnapshot?.timeRange, appliedSnapshot?.customPeriod)} · ${meta?.dataTable || 'dns_log'}`}
            loadMs={loadMs}
            serverMs={serverMs}
          >
            <DnsExplorerTotalChart
              points={timeseries}
              metric={appliedSnapshot?.metric}
              metricLabel={appliedMetricLabel}
              schema={schema}
              displayTimezone={displayTimezone}
              chartLongRange={chartLongRange}
              bucketSeconds={chartBucketSeconds}
            />
          </Card>
        ) : (
          <Card
            className="card--explorer-results dns-explorer-results"
            title="Результаты"
            subtitle="График динамики и таблица: серии по селектору «Показать», отдельные строки — «Показать» / «Скрыть с графика»"
            loadMs={loadMs}
            serverMs={serverMs}
            pad="0"
            tools={(
              <div className="explorer-results-tools">
                <div className="explorer-results-tools__cluster">
                  <div className="explorer-results-tools__limit-block">
                    <DnsExplorerVisualLimitControl
                      total={rows.length}
                      fetchLimit={DNS_EXPLORER_DEFAULT_LIMIT}
                      value={visualLimit}
                      onChange={setVisualLimit}
                    />
                  </div>
                </div>
              </div>
            )}
          >
            <div className="explorer-results-layout">
              <div className="explorer-results-chart">
                <DnsExplorerDynamicsChart
                  results={rows}
                  resultSeries={resultSeries}
                  metric={appliedSnapshot?.metric}
                  metricLabel={appliedMetricLabel}
                  schema={schema}
                  displayTimezone={displayTimezone}
                  chartLongRange={chartLongRange}
                  selectedSeriesIds={chartSeriesIds}
                  groupBy={appliedGroupBy}
                  bucketSeconds={chartBucketSeconds}
                />
              </div>
              <DataTable
                rows={visibleResults}
                rowKey="id"
                dense
                resizableColumns={false}
                pageSize={visiblePageSize}
                getRowClassName={(row) => (chartSeriesIds.has(row.id) ? 'is-dynamics-active' : '')}
                columns={tableColumns}
                footerNote={(
                  <span>
                    Показано {visibleResults.length} из {rows.length} загруженных · {meta?.dataTable || 'dns_log'}
                  </span>
                )}
              />
            </div>
          </Card>
        )
      )}
    </div>
  );
}

Object.assign(window, { PageDnsExplorer });
