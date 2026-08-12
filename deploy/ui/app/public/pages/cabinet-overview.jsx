/* Обзор личного кабинета клиента */

const CABINET_OVERVIEW_TOP_LIMIT = 20;

function PageCabinetOverview({ timeRange, customPeriod, displayTimezone, onNavigate, readOnly }) {
  const [seriesState, setSeriesState] = useState({ source: 'loading', data: [], meta: null, error: '' });
  const [countriesState, setCountriesState] = useState({ source: 'loading', data: [], meta: null, error: '' });
  const [servicesState, setServicesState] = useState({ source: 'loading', data: [], meta: null, error: '' });
  const [countryDirection, setCountryDirection] = useState('in');
  const [serviceDirection, setServiceDirection] = useState('in');

  const periodLabel = timeRangeLabel(timeRange, customPeriod);
  const chartLongRange = isLongChartRange(timeRange, customPeriod);
  const periodKey = `${timeRange}|${customPeriod?.from || ''}|${customPeriod?.to || ''}`;
  const chartPeriodBounds = useMemo(
    () => computeChartPeriodBounds(timeRange, customPeriod),
    [timeRange, customPeriod?.from, customPeriod?.to],
  );

  useEffect(() => {
    let cancelled = false;
    setSeriesState({ source: 'loading', data: [], meta: null, error: '' });
    ApiClient.loadCabinetOverviewSeries({ timeRange, customPeriod, granularity: 'auto' })
      .then((result) => {
        if (cancelled) return;
        setSeriesState({
          source: result.source || 'error',
          data: Array.isArray(result.data) ? result.data : [],
          meta: result.meta || null,
          error: result.error || '',
          loadMs: result.loadMs ?? null,
          serverMs: result.serverMs ?? null,
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setSeriesState({
            source: 'error',
            data: [],
            meta: null,
            error: err.message || ApiClient.LOAD_FAILED,
          });
        }
      });
    return () => { cancelled = true; };
  }, [periodKey]);

  useEffect(() => {
    let cancelled = false;
    setCountriesState({ source: 'loading', data: [], meta: null, error: '' });
    ApiClient.loadCabinetOverviewCountries({
      timeRange,
      customPeriod,
      direction: countryDirection,
      limit: CABINET_OVERVIEW_TOP_LIMIT,
    })
      .then((result) => {
        if (cancelled) return;
        setCountriesState({
          source: result.source || 'error',
          data: Array.isArray(result.data) ? result.data : [],
          meta: result.meta || null,
          error: result.error || '',
          loadMs: result.loadMs ?? null,
          serverMs: result.serverMs ?? null,
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setCountriesState({
            source: 'error',
            data: [],
            meta: null,
            error: err.message || ApiClient.LOAD_FAILED,
          });
        }
      });
    return () => { cancelled = true; };
  }, [periodKey, countryDirection]);

  useEffect(() => {
    let cancelled = false;
    setServicesState({ source: 'loading', data: [], meta: null, error: '' });
    ApiClient.loadCabinetOverviewServices({
      timeRange,
      customPeriod,
      direction: serviceDirection,
      limit: CABINET_OVERVIEW_TOP_LIMIT,
    })
      .then((result) => {
        if (cancelled) return;
        setServicesState({
          source: result.source || 'error',
          data: Array.isArray(result.data) ? result.data : [],
          meta: result.meta || null,
          error: result.error || '',
          loadMs: result.loadMs ?? null,
          serverMs: result.serverMs ?? null,
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setServicesState({
            source: 'error',
            data: [],
            meta: null,
            error: err.message || ApiClient.LOAD_FAILED,
          });
        }
      });
    return () => { cancelled = true; };
  }, [periodKey, serviceDirection]);

  const chartBundle = useMemo(
    () => cabinetSeriesToChart(seriesState.data, seriesState.meta),
    [seriesState.data, seriesState.meta?.granularity],
  );
  const chartPoints = useMemo(
    () => (chartBundle.points || []).map((pt) => ({
      ...pt,
      t: formatPointTimeLabel(pt, chartLongRange, displayTimezone),
    })),
    [chartBundle.points, chartLongRange, displayTimezone],
  );

  const totals = seriesState.meta?.totals || { in: 0, out: 0 };
  const countryShares = useMemo(() => {
    if (!countriesState.data?.length) return [];
    return cabinetShareItems(countriesState.data, countriesState.meta?.totalBytes);
  }, [countriesState.data, countriesState.meta?.totalBytes]);
  const serviceShares = useMemo(() => {
    if (!servicesState.data?.length) return [];
    return cabinetShareItems(servicesState.data, servicesState.meta?.totalBytes);
  }, [servicesState.data, servicesState.meta?.totalBytes]);

  const renderDirectionToggle = (direction, setDirection) => (
    <div className="seg seg--compact" title="Направление трафика">
      <button type="button" className={direction === 'in' ? 'is-active' : ''} onClick={() => setDirection('in')}>
        Входящий
      </button>
      <button type="button" className={direction === 'out' ? 'is-active' : ''} onClick={() => setDirection('out')}>
        Исходящий
      </button>
    </div>
  );

  const renderShareTable = (items, labelForRow) => (
    <table className="table table--dense cabinet-share-table">
      <thead>
        <tr>
          <th>Разрез</th>
          <th style={{ textAlign: 'right' }}>Доля</th>
          <th style={{ textAlign: 'right' }}>Объём</th>
        </tr>
      </thead>
      <tbody>
        {items.map((row, idx) => (
          <tr key={row.key || row.countryCode || row.serviceCode || row.synthetic || idx}>
            <td>{labelForRow(row)}</td>
            <td className="mono num" style={{ textAlign: 'right' }}>{row.sharePercent.toFixed(2)}%</td>
            <td className="mono num" style={{ textAlign: 'right' }}>{fmtGbTotal(row.bytes)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <div className="main__container">
      <CabinetDnsWarningBanner style={{ marginBottom: 16 }} />

      <div className="page-head">
        <div>
          <h1>Обзор</h1>
          <p>Входящий и исходящий трафик вашей сети · {periodLabel}</p>
        </div>
        {onNavigate && (
          <div className="row" style={{ gap: 8 }}>
            <Button
              kind="ghost"
              size="sm"
              onClick={() => openCabinetExplorer(onNavigate, {
                groupBy: ['asn'],
                timeRange,
                customPeriod,
              })}
            >
              ASN в разборе
            </Button>
          </div>
        )}
      </div>

      <Card
        title="Трафик"
        subtitle={periodLabel}
        loadMs={seriesState.loadMs}
        serverMs={seriesState.serverMs}
      >
        {seriesState.source === 'loading' ? (
          <div className="skeleton" style={{ height: 220 }} />
        ) : seriesState.source === 'error' ? (
          <CabinetErrorState error={seriesState.error} />
        ) : !chartPoints.length ? (
          <CabinetEmptyState />
        ) : (
          <>
            <div className="cabinet-overview-totals row" style={{ gap: 24, marginBottom: 16, flexWrap: 'wrap' }}>
              <div>
                <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-caption-1)' }}>Входящий</div>
                <div className="mono" style={{ font: 'var(--pv-text-title-3)' }}>{fmtGbTotal(totals.in)}</div>
              </div>
              <div>
                <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-caption-1)' }}>Исходящий</div>
                <div className="mono" style={{ font: 'var(--pv-text-title-3)' }}>{fmtGbTotal(totals.out)}</div>
              </div>
            </div>
            <CategoryTrendChart
              points={chartPoints}
              lines={chartBundle.lines}
              height={220}
              bucketSeconds={chartBundle.bucketSeconds}
              displayTimezone={displayTimezone}
              periodStartMs={chartPeriodBounds.startMs}
              periodEndMs={chartPeriodBounds.endMs}
            />
            <CabinetDataMeta
              granularity={seriesState.meta?.granularity}
              dataUntil={seriesState.meta?.dataUntil}
              readOnly={readOnly}
              displayTimezone={displayTimezone}
              style={{ marginTop: 10 }}
            />
          </>
        )}
      </Card>

      <div className="cabinet-overview-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16, marginTop: 16 }}>
        <Card
          title="Топ стран"
          tools={renderDirectionToggle(countryDirection, setCountryDirection)}
          loadMs={countriesState.loadMs}
          serverMs={countriesState.serverMs}
        >
          {countriesState.source === 'loading' ? (
            <div className="skeleton" style={{ height: 180 }} />
          ) : countriesState.source === 'error' ? (
            <CabinetErrorState error={countriesState.error} />
          ) : !countryShares.length ? (
            <CabinetEmptyState />
          ) : (
            <>
              {renderShareTable(countryShares, (row) => (
                row.synthetic ? 'Прочее' : (
                  <span className="row" style={{ gap: 8, alignItems: 'center' }}>
                    <span>{countryFlagEmoji(row.countryCode)}</span>
                    <span>{countryDisplayName(row.countryCode)}</span>
                  </span>
                )
              ))}
              <CabinetDataMeta
                granularity={countriesState.meta?.breakdownGranularity || 'hour'}
                dataUntil={countriesState.meta?.dataUntil}
                readOnly={readOnly}
                displayTimezone={displayTimezone}
                style={{ marginTop: 10 }}
              />
              {onNavigate && (
                <div style={{ marginTop: 12 }}>
                  <Button
                    kind="ghost"
                    size="sm"
                    onClick={() => openCabinetExplorer(onNavigate, {
                      groupBy: cabinetExplorerGroupByForDirection('country', countryDirection),
                      direction: countryDirection,
                      timeRange,
                      customPeriod,
                    })}
                  >
                    Посмотреть в разборе
                  </Button>
                </div>
              )}
            </>
          )}
        </Card>

        <Card
          title="Топ сервисов"
          tools={renderDirectionToggle(serviceDirection, setServiceDirection)}
          loadMs={servicesState.loadMs}
          serverMs={servicesState.serverMs}
        >
          {servicesState.source === 'loading' ? (
            <div className="skeleton" style={{ height: 180 }} />
          ) : servicesState.source === 'error' ? (
            <CabinetErrorState error={servicesState.error} />
          ) : !serviceShares.length ? (
            <CabinetEmptyState />
          ) : (
            <>
              {renderShareTable(serviceShares, (row) => (
                row.synthetic ? 'Прочее' : formatCabinetServiceLabel(row)
              ))}
              <CabinetDataMeta
                granularity={servicesState.meta?.breakdownGranularity || 'hour'}
                dataUntil={servicesState.meta?.dataUntil}
                readOnly={readOnly}
                displayTimezone={displayTimezone}
                style={{ marginTop: 10 }}
              />
              {onNavigate && (
                <div style={{ marginTop: 12 }}>
                  <Button
                    kind="ghost"
                    size="sm"
                    onClick={() => openCabinetExplorer(onNavigate, {
                      groupBy: cabinetExplorerGroupByForDirection('service', serviceDirection),
                      direction: serviceDirection,
                      timeRange,
                      customPeriod,
                    })}
                  >
                    Посмотреть в разборе
                  </Button>
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </div>
  );
}

Object.assign(window, { PageCabinetOverview });
