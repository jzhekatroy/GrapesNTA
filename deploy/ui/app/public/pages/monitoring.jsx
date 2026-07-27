/* Мониторинг контролируемых показателей */

const MONITORING_REFRESH_MS = 60_000;
const MONITORING_CHART_HEIGHT = 320;
const MONITORING_DEVIATIONS_LIMIT = 10;
const LOAD_FAILED = 'Не удалось загрузить';

const MONITORING_CHART_LINES = [
  { key: 'value', label: 'Значение', color: '#7E92F8' },
  { key: 'ciLow', label: 'Нижняя граница', color: '#51D16D' },
  { key: 'ciHigh', label: 'Верхняя граница', color: '#F06B6B' },
];

function defaultMonitoringPeriod(displayTimezone) {
  const tz = displayTimezone || getDisplayTimezone();
  const parts = intlPartsMs(Date.now(), tz);
  const fromMs = wallPartsToMs({
    y: Number(pickIntlPart(parts, 'year')),
    mo: Number(pickIntlPart(parts, 'month')),
    d: Number(pickIntlPart(parts, 'day')),
    h: 0,
    mi: 0,
    s: 0,
  }, tz);
  const safeFromMs = Number.isFinite(fromMs) ? fromMs : Date.now();
  const toMs = Date.now();
  return {
    from: msToDatetimeLocalValue(safeFromMs, tz),
    to: msToDatetimeLocalValue(toMs, tz),
  };
}

function yesterdayMonitoringPeriod(displayTimezone) {
  const tz = displayTimezone || getDisplayTimezone();
  const todayParts = intlPartsMs(Date.now(), tz);
  const todayWall = {
    y: Number(pickIntlPart(todayParts, 'year')),
    mo: Number(pickIntlPart(todayParts, 'month')),
    d: Number(pickIntlPart(todayParts, 'day')),
  };
  const todayStartMs = wallPartsToMs({ ...todayWall, h: 0, mi: 0, s: 0 }, tz);
  if (!Number.isFinite(todayStartMs)) {
    return defaultMonitoringPeriod(displayTimezone);
  }
  const todayNoonMs = wallPartsToMs({ ...todayWall, h: 12, mi: 0, s: 0 }, tz);
  const yesterdayParts = intlPartsMs(
    Number.isFinite(todayNoonMs) ? todayNoonMs - 86400000 : todayStartMs - 12 * 3600000,
    tz,
  );
  const yesterdayWall = {
    y: Number(pickIntlPart(yesterdayParts, 'year')),
    mo: Number(pickIntlPart(yesterdayParts, 'month')),
    d: Number(pickIntlPart(yesterdayParts, 'day')),
  };
  const fromMs = wallPartsToMs({ ...yesterdayWall, h: 0, mi: 0, s: 0 }, tz);
  const safeFromMs = Number.isFinite(fromMs) ? fromMs : todayStartMs - 86400000;
  return {
    from: msToDatetimeLocalValue(safeFromMs, tz),
    to: msToDatetimeLocalValue(todayStartMs, tz),
  };
}

function fmtGbitMin(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  const v = Number(value);
  if (v >= 100) return String(Math.round(v));
  if (v >= 10) return v.toFixed(1);
  if (v >= 1) return v.toFixed(2);
  return v.toFixed(3);
}

function monitoringPeriodLabel({ from, to }) {
  if (!from || !to) return '—';
  return formatCustomPeriodLabel({ from, to });
}

const MONITORING_DATA_TIMEZONE = 'Europe/Moscow';

function fmtMonitoringDt(value, displayTimezone, dtMs = null) {
  if (dtMs != null && Number.isFinite(Number(dtMs))) {
    return formatTipPointTime({ bucketMs: Number(dtMs) }, displayTimezone);
  }
  if (!value) return '—';
  const ms = bucketWallToMs(normalizeBucketString(value), MONITORING_DATA_TIMEZONE);
  if (ms == null) return String(value);
  return formatTipPointTime({ bucketMs: ms }, displayTimezone);
}

function PageMonitoring({ displayTimezone }) {
  const [parameters, setParameters] = useState([]);
  const [parametersSource, setParametersSource] = useState('loading');
  const [parametersLoadMs, setParametersLoadMs] = useState(null);
  const [parametersServerMs, setParametersServerMs] = useState(null);

  const [selectedId, setSelectedId] = useState(null);
  const [period, setPeriod] = useState(() => defaultMonitoringPeriod(displayTimezone));
  const [periodDraft, setPeriodDraft] = useState(() => defaultMonitoringPeriod(displayTimezone));
  const [periodError, setPeriodError] = useState('');
  const [periodZoomStack, setPeriodZoomStack] = useState([]);
  const [chartHidden, setChartHidden] = useState(() => new Set());

  const [seriesRows, setSeriesRows] = useState([]);
  const [seriesMeta, setSeriesMeta] = useState(null);
  const [seriesSource, setSeriesSource] = useState('idle');
  const [seriesLoadMs, setSeriesLoadMs] = useState(null);
  const [seriesServerMs, setSeriesServerMs] = useState(null);

  const [bounds, setBounds] = useState(null);
  const [boundsSource, setBoundsSource] = useState('idle');
  const [boundsError, setBoundsError] = useState('');
  const [boundsDraft, setBoundsDraft] = useState({ ciLow: '', ciHigh: '', ciMinimum: '' });
  const [boundsSaving, setBoundsSaving] = useState(false);
  const [boundsSaveError, setBoundsSaveError] = useState('');

  const canWrite = AuthAccess.canWritePage('monitoring');

  const [deviations, setDeviations] = useState([]);
  const [deviationsSource, setDeviationsSource] = useState('loading');
  const [deviationsLoadMs, setDeviationsLoadMs] = useState(null);
  const [deviationsServerMs, setDeviationsServerMs] = useState(null);

  const selectedParam = useMemo(
    () => parameters.find((item) => item.id === selectedId) || null,
    [parameters, selectedId],
  );

  const visibleChartLines = useMemo(
    () => MONITORING_CHART_LINES.filter((line) => !chartHidden.has(line.key)),
    [chartHidden],
  );

  const toggleChartSeries = (key) => {
    setChartHidden((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const applyMonitoringChartRangeZoom = (range) => {
    if (!range?.from || !range?.to || validateCustomPeriod(range)) return;
    setPeriodZoomStack((stack) => [...stack, period]);
    setPeriodDraft({ from: range.from, to: range.to });
    setPeriod({ from: range.from, to: range.to });
    setPeriodError('');
  };

  const resetMonitoringChartRangeZoom = () => {
    setPeriodZoomStack((stack) => {
      if (!stack.length) return stack;
      const prev = stack[stack.length - 1];
      setPeriodDraft(prev);
      setPeriod(prev);
      setPeriodError('');
      return stack.slice(0, -1);
    });
  };

  useEffect(() => {
    setChartHidden(new Set());
  }, [selectedId]);

  useEffect(() => {
    setPeriod(defaultMonitoringPeriod(displayTimezone));
    setPeriodDraft(defaultMonitoringPeriod(displayTimezone));
    setPeriodZoomStack([]);
  }, [displayTimezone]);

  useEffect(() => {
    let cancelled = false;
    const load = (initial) => {
      if (initial) setParametersSource('loading');
      ApiClient.loadMonitoringParameters().then((result) => {
        if (cancelled) return;
        const rows = Array.isArray(result.rows) ? result.rows : [];
        setParameters(rows);
        setParametersSource(result.source || 'error');
        setParametersLoadMs(result.loadMs ?? null);
        setParametersServerMs(result.serverMs ?? null);
        setSelectedId((prev) => {
          if (prev && rows.some((item) => item.id === prev)) return prev;
          return rows[0]?.id || null;
        });
      });
    };
    load(true);
    const timer = setInterval(() => load(false), MONITORING_REFRESH_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const load = (initial) => {
      if (initial) setDeviationsSource('loading');
      ApiClient.loadMonitoringDeviations({ limit: MONITORING_DEVIATIONS_LIMIT }).then((result) => {
        if (cancelled) return;
        setDeviations(Array.isArray(result.rows) ? result.rows : []);
        setDeviationsSource(result.source || 'error');
        setDeviationsLoadMs(result.loadMs ?? null);
        setDeviationsServerMs(result.serverMs ?? null);
      });
    };
    load(true);
    const timer = setInterval(() => load(false), MONITORING_REFRESH_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  useEffect(() => {
    if (!selectedId || !period.from || !period.to) {
      setSeriesRows([]);
      setSeriesMeta(null);
      setSeriesSource('idle');
      return undefined;
    }

    let cancelled = false;
    let requestId = 0;
    const load = (initial) => {
      const currentRequest = ++requestId;
      if (initial) setSeriesSource('loading');
      ApiClient.loadMonitoringSeries({
        parameter: selectedId,
        from: period.from,
        to: period.to,
      }).then((result) => {
        if (cancelled || currentRequest !== requestId) return;
        setSeriesRows(Array.isArray(result.rows) ? result.rows : []);
        setSeriesMeta(result.meta ?? null);
        setSeriesSource(result.source || 'error');
        setSeriesLoadMs(result.loadMs ?? null);
        setSeriesServerMs(result.serverMs ?? null);
      });
    };

    load(true);
    const timer = setInterval(() => load(false), MONITORING_REFRESH_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, [selectedId, period.from, period.to]);

  useEffect(() => {
    if (!selectedId) {
      setBounds(null);
      setBoundsSource('idle');
      setBoundsError('');
      return undefined;
    }

    let cancelled = false;
    setBoundsSource('loading');
    setBoundsError('');
    ApiClient.loadMonitoringBounds(selectedId).then((result) => {
      if (cancelled) return;
      if (result.source === 'error') {
        setBounds(null);
        setBoundsSource('error');
        setBoundsError(result.error || LOAD_FAILED);
        return;
      }
      setBounds(result.data || null);
      setBoundsSource('clickhouse');
      setBoundsError('');
    });
    return () => { cancelled = true; };
  }, [selectedId]);

  useEffect(() => {
    if (!bounds) {
      setBoundsDraft({ ciLow: '', ciHigh: '', ciMinimum: '' });
      setBoundsSaveError('');
      return;
    }
    setBoundsDraft({
      ciLow: bounds.ciLow != null ? String(bounds.ciLow) : '',
      ciHigh: bounds.ciHigh != null ? String(bounds.ciHigh) : '',
      ciMinimum: bounds.ciMinimum != null ? String(bounds.ciMinimum) : '',
    });
    setBoundsSaveError('');
  }, [bounds]);

  const validateBoundsDraft = (draft) => {
    const low = Number(draft.ciLow);
    const high = Number(draft.ciHigh);
    const minimum = Number(draft.ciMinimum);
    if (!Number.isFinite(low) || !Number.isFinite(high) || !Number.isFinite(minimum)) {
      return 'Все границы должны быть числами';
    }
    return '';
  };

  const saveBounds = async () => {
    if (!selectedId || !canWrite) return;
    const validationError = validateBoundsDraft(boundsDraft);
    if (validationError) {
      setBoundsSaveError(validationError);
      return;
    }
    setBoundsSaving(true);
    setBoundsSaveError('');
    const result = await ApiClient.saveMonitoringBounds(selectedId, {
      ciLow: Number(boundsDraft.ciLow),
      ciHigh: Number(boundsDraft.ciHigh),
      ciMinimum: Number(boundsDraft.ciMinimum),
    });
    setBoundsSaving(false);
    if (result.source === 'error') {
      const message = result.error || LOAD_FAILED;
      setBoundsSaveError(message);
      pushToast({ kind: 'error', title: 'Не удалось сохранить границы', desc: message });
      return;
    }
    setBounds(result.data || null);
    pushToast({ kind: 'success', title: 'Границы сохранены' });
  };

  const chartLongRange = useMemo(
    () => isLongChartRange('custom', period),
    [period.from, period.to],
  );

  const chartPoints = useMemo(() => seriesRows.map((row) => {
    const bucket = normalizeBucketString(row.bucket);
    const bucketMs = row.bucketMs != null ? Number(row.bucketMs) : null;
    return {
      bucket,
      bucketMs,
      t: formatPointTimeLabel({ bucket, bucketMs }, chartLongRange, displayTimezone),
      value: row.value,
      ciLow: row.ciLow,
      ciHigh: row.ciHigh,
      _raw: row,
    };
  }), [seriesRows, chartLongRange, displayTimezone]);

  const applyPeriod = () => {
    const err = validateCustomPeriod(periodDraft);
    setPeriodError(err || '');
    if (err) return;
    setPeriodZoomStack([]);
    setPeriod({ ...periodDraft });
  };

  const resetPeriod = () => {
    const next = defaultMonitoringPeriod(displayTimezone);
    setPeriodDraft(next);
    setPeriod(next);
    setPeriodError('');
    setPeriodZoomStack([]);
  };

  const resetYesterdayPeriod = () => {
    const next = yesterdayMonitoringPeriod(displayTimezone);
    setPeriodDraft(next);
    setPeriod(next);
    setPeriodError('');
    setPeriodZoomStack([]);
  };

  return (
    <div className="main__container monitoring-page">
      <div className="page-head">
        <div>
          <h1>Мониторинг</h1>
          <p>Контролируемые показатели и отклонения от границ интервалов</p>
        </div>
        <div className="row monitoring-page__head-actions">
          <WidgetLoadBadge loadMs={parametersLoadMs} serverMs={parametersServerMs} />
        </div>
      </div>

      <div className="monitoring-page__layout">
        <Card className="monitoring-page__params" title="Показатели и аномалии">
          {parametersSource === 'loading' ? (
            <div className="skeleton monitoring-page__params-skeleton" />
          ) : parametersSource === 'error' ? (
            <Empty title={LOAD_FAILED} />
          ) : parameters.length === 0 ? (
            <Empty title="Нет показателей" />
          ) : (
            <div className="monitoring-param-list">
              {parameters.map((item) => {
                const active = item.id === selectedId;
                const deviationTone = item.deviations24h > 0 ? 'warning' : 'neutral';
                return (
                  <button
                    key={item.id}
                    type="button"
                    className={`monitoring-param-list__item${active ? ' is-active' : ''}`}
                    onClick={() => setSelectedId(item.id)}
                  >
                    <div className="monitoring-param-list__main">
                      <div className="monitoring-param-list__label">{item.label}</div>
                    </div>
                    <Badge tone={deviationTone} title="Отклонения за последние 24 часа">
                      {item.deviations24h}
                    </Badge>
                  </button>
                );
              })}
            </div>
          )}
        </Card>

        <div className="monitoring-page__main">
          <Card className="monitoring-page__period">
            <div className="monitoring-page__period-head">
              <div>
                <div className="monitoring-page__period-title">Период графика</div>
                <div className="monitoring-page__period-sub">
                  {selectedParam
                    ? `${selectedParam.label}, ${selectedParam.unit} · ${monitoringPeriodLabel(period)}`
                    : monitoringPeriodLabel(period)}
                </div>
              </div>
              <WidgetLoadBadge loadMs={seriesLoadMs} serverMs={seriesServerMs} />
            </div>
            <div className="monitoring-page__period-fields row">
              <div className="field">
                <label htmlFor="monitoring-from">Начало</label>
                <input
                  id="monitoring-from"
                  className="input"
                  type="datetime-local"
                  value={periodDraft.from}
                  onChange={(e) => setPeriodDraft((prev) => ({ ...prev, from: e.target.value }))}
                />
              </div>
              <div className="field">
                <label htmlFor="monitoring-to">Конец</label>
                <input
                  id="monitoring-to"
                  className="input"
                  type="datetime-local"
                  value={periodDraft.to}
                  onChange={(e) => setPeriodDraft((prev) => ({ ...prev, to: e.target.value }))}
                />
              </div>
              <div className="row monitoring-page__period-actions">
                <Button kind="primary" onClick={applyPeriod}>Применить</Button>
                <Button kind="ghost" onClick={resetYesterdayPeriod}>Вчера</Button>
                <Button kind="ghost" onClick={resetPeriod}>Сегодня</Button>
                {periodZoomStack.length > 0 && (
                  <button
                    type="button"
                    className="time-pill time-pill--reset"
                    title="Вернуть предыдущий период"
                    onClick={resetMonitoringChartRangeZoom}
                  >
                    <Icon name="zoom" size={14} />
                    <span>Сброс zoom</span>
                  </button>
                )}
              </div>
            </div>
            {periodError && <div className="form-error">{periodError}</div>}
          </Card>

          <div className="monitoring-page__chart-layout">
            <Card className="monitoring-page__chart" title={selectedParam ? selectedParam.label : 'График'}>
              <div
                className="chart-legend row monitoring-page__chart-legend"
                style={{
                  gap: 14,
                  marginBottom: 8,
                  font: 'var(--pv-text-body-3)',
                  color: 'var(--fg-secondary)',
                  flexWrap: 'wrap',
                }}
              >
                {MONITORING_CHART_LINES.map((line) => {
                  const off = chartHidden.has(line.key);
                  return (
                    <button
                      key={line.key}
                      type="button"
                      className={`chart-legend__item${off ? ' is-off' : ''}`}
                      aria-pressed={!off}
                      title={off ? 'Показать на графике' : 'Скрыть с графика'}
                      onClick={() => toggleChartSeries(line.key)}
                    >
                      <span
                        className="chart-legend__swatch"
                        style={{
                          width: 12,
                          height: line.key === 'value' ? 3 : 2,
                          background: line.color,
                          opacity: off ? 0.35 : 1,
                        }}
                      />
                      {line.label}
                    </button>
                  );
                })}
                <span
                  className="chart-legend__meta"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  <Icon name="info" size={12} />
                  Выделите диапазон на графике · агрегация 1 мин · авто-обновление каждую минуту
                </span>
              </div>
              {!selectedParam ? (
                <Empty title="Выберите показатель" />
              ) : seriesSource === 'error' ? (
                <Empty title={LOAD_FAILED} />
              ) : seriesSource === 'loading' ? (
                <div className="skeleton monitoring-page__chart-skeleton" />
              ) : chartPoints.length === 0 ? (
                <Empty title="Нет данных за выбранный период" />
              ) : (
                <div className="monitoring-page__chart-plot">
                  <DualChart
                    points={chartPoints}
                    lines={visibleChartLines}
                    height={MONITORING_CHART_HEIGHT}
                    mode="bw"
                    bucketSeconds={60}
                    displayTimezone={displayTimezone}
                    onRangeSelect={applyMonitoringChartRangeZoom}
                    valueFormatter={fmtGbitMin}
                    axisFormatter={fmtCompact}
                    tipUnitLabel={selectedParam.unit}
                    yAxisLabel={selectedParam.label}
                    yAxisUnit={selectedParam.unit}
                  />
                </div>
              )}
            </Card>

            <Card className="monitoring-page__bounds" title="Границы интервала">
              {!selectedParam ? (
                <Empty title="Выберите показатель" />
              ) : boundsSource === 'loading' ? (
                <div className="skeleton monitoring-page__bounds-skeleton" />
              ) : boundsSource === 'error' ? (
                <div className="monitoring-page__bounds-error">{boundsError}</div>
              ) : (
                <div className="monitoring-page__bounds-fields">
                  <div className="field">
                    <label htmlFor="monitoring-ci-low">Нижняя граница (ci_low)</label>
                    <input
                      id="monitoring-ci-low"
                      className="input"
                      type="number"
                      step="any"
                      readOnly={!canWrite}
                      value={boundsDraft.ciLow}
                      onChange={(e) => setBoundsDraft((prev) => ({ ...prev, ciLow: e.target.value }))}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="monitoring-ci-high">Верхняя граница (ci_high)</label>
                    <input
                      id="monitoring-ci-high"
                      className="input"
                      type="number"
                      step="any"
                      readOnly={!canWrite}
                      value={boundsDraft.ciHigh}
                      onChange={(e) => setBoundsDraft((prev) => ({ ...prev, ciHigh: e.target.value }))}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="monitoring-ci-minimum">Минимальная граница (ci_minimum)</label>
                    <input
                      id="monitoring-ci-minimum"
                      className="input"
                      type="number"
                      step="any"
                      readOnly={!canWrite}
                      value={boundsDraft.ciMinimum}
                      onChange={(e) => setBoundsDraft((prev) => ({ ...prev, ciMinimum: e.target.value }))}
                    />
                  </div>
                  {canWrite && (
                    <div className="monitoring-page__bounds-actions">
                      <Button kind="primary" onClick={saveBounds} disabled={boundsSaving}>
                        {boundsSaving ? 'Сохранение…' : 'Сохранить'}
                      </Button>
                    </div>
                  )}
                  {boundsSaveError && <div className="form-error">{boundsSaveError}</div>}
                  <div className="monitoring-page__bounds-meta">
                    {bounds?.configKey ? `${bounds.configKey} · ` : ''}
                    config.yaml
                    {bounds?.mode ? ` · ${bounds.mode}` : ''}
                    {bounds?.host ? ` · ${bounds.host}` : ''}
                    {bounds?.configPath ? ` · ${bounds.configPath}` : ''}
                  </div>
                </div>
              )}
            </Card>
          </div>

          <Card className="monitoring-page__deviations" title="Отклонения за последние 24 часа">
            <div className="monitoring-page__deviations-head">
              <div className="monitoring-page__period-sub">Последние {MONITORING_DEVIATIONS_LIMIT} событий</div>
              <WidgetLoadBadge loadMs={deviationsLoadMs} serverMs={deviationsServerMs} />
            </div>
            {deviationsSource === 'loading' ? (
              <div className="skeleton monitoring-page__deviations-skeleton" />
            ) : deviationsSource === 'error' ? (
              <Empty title={LOAD_FAILED} />
            ) : deviations.length === 0 ? (
              <Empty title="Отклонений за последние 24 часа нет" />
            ) : (
              <DataTable
                rows={deviations}
                rowKey={(row, index) => `${row.dt}|${row.featureName}|${index}`}
                dense
                columns={[
                  {
                    key: 'dt',
                    title: 'Дата и время',
                    render: (row) => fmtMonitoringDt(row.dt, displayTimezone, row.dtMs),
                  },
                  {
                    key: 'featureLabel',
                    title: 'Параметр',
                  },
                  {
                    key: 'value',
                    title: 'Значение',
                    render: (row) => fmtGbitMin(row.value),
                  },
                  {
                    key: 'ciLow',
                    title: 'ci_low',
                    render: (row) => fmtGbitMin(row.ciLow),
                  },
                  {
                    key: 'ciHigh',
                    title: 'ci_high',
                    render: (row) => fmtGbitMin(row.ciHigh),
                  },
                ]}
              />
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { PageMonitoring });
