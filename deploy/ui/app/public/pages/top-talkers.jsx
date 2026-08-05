/* Топ ASN — анализ src / dst / pair по автономным системам */

const TOP_DIRECTIONS = [
  { id: 'src', label: 'Источники', icon: 'arrowU' },
  { id: 'dst', label: 'Назначения', icon: 'arrowD' },
  { id: 'pair', label: 'Пары src → dst', icon: 'flow' },
];

const TOP_LOAD_FAILED = 'Не удалось загрузить';
const TOP_TALKERS_PAGE_SIZE = 25;

function PageTop({ onNavigate, timeRange, customPeriod, directions, collectorFilter }) {
  const initialParams = readTopTalkersPageParamsFromHash();
  const [direction, setDirection] = useState(initialParams?.direction || 'src');
  const [metric, setMetric] = useState(initialParams?.metric || 'bps');
  const [search, setSearch] = useState(initialParams?.search || '');
  const [rows, setRows] = useState([]);
  const [meta, setMeta] = useState(null);
  const [source, setSource] = useState('loading');
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [expandedKey, setExpandedKey] = useState(null);
  const [loadMs, setLoadMs] = useState(null);
  const [serverMs, setServerMs] = useState(null);
  const loadMoreSentinelRef = useRef(null);
  const loadSeqRef = useRef(0);
  const nextOffsetRef = useRef(0);
  const loadInFlightRef = useRef(false);
  const loadMoreFnRef = useRef(() => {});

  const periodLabel = timeRangeLabel(timeRange, customPeriod);
  const directionFilterLabel = directionSummaryLabel(directions);
  const directionsKey = TRAFFIC_DIRECTIONS.map((d) => (directions?.[d.id] ? '1' : '0')).join('');
  const collectorFilterKey = (collectorFilter || []).join('|');
  const isPair = direction === 'pair';
  const hasData = source === 'clickhouse';
  const metricLabel = METRICS.find((m) => m.id === metric)?.label || metric;
  const directionLabel = TOP_DIRECTIONS.find((d) => d.id === direction)?.label || direction;

  useEffect(() => {
    setExpandedKey(null);
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, direction, collectorFilterKey]);

  useEffect(() => {
    const applyPageParamsFromHash = () => {
      const params = readTopTalkersPageParamsFromHash();
      if (!params) return;
      setDirection(params.direction);
      setMetric(params.metric);
      setSearch(params.search);
    };
    applyPageParamsFromHash();
    addEventListener('hashchange', applyPageParamsFromHash);
    return () => removeEventListener('hashchange', applyPageParamsFromHash);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const seq = ++loadSeqRef.current;
    nextOffsetRef.current = 0;
    loadInFlightRef.current = false;
    setSource('loading');
    setRows([]);
    setHasMore(true);
    setLoadingMore(false);
    ApiClient.loadTopTalkers({
      timeRange,
      customPeriod,
      directions,
      group: direction,
      limit: TOP_TALKERS_PAGE_SIZE,
      offset: 0,
      collectorFilter,
    }).then((r) => {
      if (cancelled || seq !== loadSeqRef.current) return;
      const batch = Array.isArray(r.rows) ? r.rows : [];
      nextOffsetRef.current = batch.length;
      setRows(batch);
      setMeta(r.meta || null);
      setSource(r.source || 'error');
      setHasMore(r.hasMore ?? batch.length >= TOP_TALKERS_PAGE_SIZE);
      setLoadMs(r.loadMs ?? null);
      setServerMs(r.serverMs ?? null);
    });
    return () => { cancelled = true; };
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, direction, collectorFilterKey]);

  const loadMore = useCallback(() => {
    if (loadInFlightRef.current || !hasMore || source !== 'clickhouse') return;
    loadInFlightRef.current = true;
    setLoadingMore(true);
    const offset = nextOffsetRef.current;
    const seq = loadSeqRef.current;
    ApiClient.loadTopTalkers({
      timeRange,
      customPeriod,
      directions,
      group: direction,
      limit: TOP_TALKERS_PAGE_SIZE,
      offset,
      collectorFilter,
    }).then((r) => {
      if (seq !== loadSeqRef.current) return;
      loadInFlightRef.current = false;
      setLoadingMore(false);
      if (r.source !== 'clickhouse') return;
      const batch = Array.isArray(r.rows) ? r.rows : [];
      nextOffsetRef.current = offset + batch.length;
      if (!batch.length) {
        setHasMore(false);
        return;
      }
      const isPairMode = direction === 'pair';
      setRows((prev) => {
        const seen = new Set(prev.map((row) => talkerRowKey(row, isPairMode)));
        return [...prev, ...batch.filter((row) => !seen.has(talkerRowKey(row, isPairMode)))];
      });
      setHasMore(r.hasMore ?? batch.length >= TOP_TALKERS_PAGE_SIZE);
    }).catch(() => {
      if (seq !== loadSeqRef.current) return;
      loadInFlightRef.current = false;
      setLoadingMore(false);
    });
  }, [
    hasMore, source, timeRange, customPeriod?.from, customPeriod?.to,
    directionsKey, direction, collectorFilterKey,
  ]);

  loadMoreFnRef.current = loadMore;

  useEffect(() => {
    const node = loadMoreSentinelRef.current;
    if (!node || !hasMore || source !== 'clickhouse') return undefined;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) loadMoreFnRef.current();
      },
      { rootMargin: '120px', threshold: 0 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [hasMore, source]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((row) => talkerSearchText(row, isPair).includes(s));
  }, [rows, search, isPair]);

  const totalMetric = useMemo(
    () => rows.reduce((sum, row) => sum + talkerMetricValue(row, metric), 0),
    [rows, metric],
  );

  const totalVolume = useMemo(
    () => rows.reduce((sum, row) => sum + (Number(row.totalBytes) || 0), 0),
    [rows],
  );

  const maxMetric = useMemo(() => {
    if (!filtered.length) return 1;
    return Math.max(...filtered.map((row) => talkerMetricValue(row, metric)), 1);
  }, [filtered, metric]);

  const colSpan = 5;

  const toggleRow = (key) => {
    setExpandedKey((prev) => (prev === key ? null : key));
  };

  const copyShareLink = async () => {
    const url = buildTopTalkersShareUrl({
      direction,
      metric,
      search,
      timeRange,
      customPeriod,
      directions,
      collectorFilter,
    });
    try {
      await copyTextToClipboard(url);
      history.replaceState(null, '', url);
      pushToast({ kind: 'success', title: 'Ссылка скопирована', desc: 'URL содержит текущие параметры страницы.' });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось скопировать', desc: err.message });
    }
  };

  const exportCsv = () => {
    if (!filtered.length) return;
    exportTopTalkersCsv({
      rows: filtered,
      isPair,
      metric,
      metricLabel,
      totalMetric,
    });
    pushToast({ kind: 'success', title: 'CSV экспортирован', desc: `${filtered.length} строк.` });
  };

  return (
    <div className="main__container page-top-talkers">
      <div className="page-head">
        <div>
          <h1>Топ ASN</h1>
          <p>{periodLabel} · {directionFilterLabel}</p>
        </div>
        <div className="row page-head__actions">
          <Button kind="ghost" icon="copy" onClick={copyShareLink}>Поделиться</Button>
          <Button kind="ghost" icon="export" onClick={exportCsv} disabled={!filtered.length || source === 'loading'}>Экспорт</Button>
          <Button kind="primary" icon="explorer" onClick={() => onNavigate('explorer')}>Открыть в разборе трафика</Button>
        </div>
      </div>

      <Card pad="sm" className="top-talkers-filters-card" style={{ marginBottom: 16 }}>
        <div className="row top-talkers-filters">
          <BuilderControl label="Направление">
            <div className="seg">
              {TOP_DIRECTIONS.map((d) => (
                <button key={d.id} className={direction === d.id ? 'is-active' : ''} onClick={() => setDirection(d.id)}>
                  <Icon name={d.icon} size={11} /> {d.label}
                </button>
              ))}
            </div>
          </BuilderControl>
          <BuilderControl label="Метрика">
            <div className="seg">
              {METRICS.slice(0, 4).map((m) => (
                <button key={m.id} className={metric === m.id ? 'is-active' : ''} onClick={() => setMetric(m.id)}>{m.label}</button>
              ))}
            </div>
          </BuilderControl>
        </div>
      </Card>

      <div className="top-talkers-panels">
        <Card
          title={`${directionLabel} — ${metricLabel}`}
          subtitle={`Топ ${TOP_TALKERS_PAGE_SIZE}+ · ${periodLabel}`}
          loadMs={loadMs}
          serverMs={serverMs}
        >
          {source === 'loading' && (
            <div className="talker-table-state">Загрузка…</div>
          )}
          {source === 'error' && (
            <div className="talker-table-state">{TOP_LOAD_FAILED}</div>
          )}
          {hasData && filtered.length === 0 && (
            <div className="talker-table-state">Нет данных за выбранный период</div>
          )}
          {hasData && filtered.length > 0 && (
            <div className="col" style={{ gap: 10, maxHeight: 540, overflowY: 'auto', paddingRight: 4 }}>
              {filtered.slice(0, 12).map((row, i) => (
                <TopBarRow
                  key={talkerRowKey(row, isPair)}
                  row={row}
                  i={i}
                  max={maxMetric}
                  metric={metric}
                  isPair={isPair}
                />
              ))}
            </div>
          )}
        </Card>

        <Card title="Период и источник" subtitle={periodLabel}>
          <div className="col" style={{ gap: 12 }}>
            <TopInfoRow label="Период" value={periodLabel} />
            <TopInfoRow label="Фильтр направлений" value={directionFilterLabel} />
            <TopInfoRow label="Группировка" value={directionLabel} />
            <TopInfoRow label="Гранулярность" value={meta?.granularity || '—'} />
            <TopInfoRow label="Источник данных" value={talkerSourceLabel(source)} />
            <TopInfoRow label="Запрос" value={fmtTalkerLoadMs(loadMs, serverMs)} />
          </div>
        </Card>
      </div>

      <Card
        className="card--top-talkers card--top-talkers-full"
        title="Полная таблица"
        subtitle={`${directionLabel} · Объём`}
        pad="0"
        loadMs={loadMs}
        serverMs={serverMs}
        tools={
          <div className="input-wrap" style={{ maxWidth: 240 }}>
            <Icon name="search" size={14} />
            <input
              className="input input--with-icon"
              placeholder="Найти в топе..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        }
      >
        <div className="top-talkers-table-wrap">
        <table className="table table--top-talkers" style={{ borderRadius: 0 }}>
          <thead>
            <tr>
              <th className="talker-col-rank">#</th>
              <th className="talker-col-endpoint">{isPair ? 'Пара ASN' : 'ASN'}</th>
              <th className={`talker-row__geo talker-col-geo${isPair ? ' talker-row__geo--pair' : ''}`}>Страна</th>
              <th className="num talker-col-volume">Объём</th>
              <th className="num talker-col-share">Доля</th>
            </tr>
          </thead>
          <tbody>
            {source === 'loading' && (
              <tr>
                <td colSpan={colSpan} className="talker-table-state">Загрузка…</td>
              </tr>
            )}
            {source === 'error' && (
              <tr>
                <td colSpan={colSpan} className="talker-table-state">{TOP_LOAD_FAILED}</td>
              </tr>
            )}
            {hasData && filtered.length === 0 && (
              <tr>
                <td colSpan={colSpan} className="talker-table-state">Нет данных за выбранный период</td>
              </tr>
            )}
            {hasData && filtered.map((row, i) => {
              const key = talkerRowKey(row, isPair);
              const expanded = expandedKey === key;
              const rowBytes = Number(row.totalBytes) || 0;
              const share = totalVolume > 0 ? (rowBytes / totalVolume) * 100 : 0;

              if (isPair) {
                return (
                  <React.Fragment key={key}>
                    <tr
                      className={`talker-row${expanded ? ' talker-row--expanded' : ''}`}
                      onClick={() => toggleRow(key)}
                      aria-expanded={expanded}
                    >
                      <td className="num talker-row__rank">{i + 1}</td>
                      <td className="talker-col-endpoint"><TalkerMainPairIpCell row={row} /></td>
                      <td className="talker-row__geo talker-row__geo--pair">
                        <TalkerMainPairGeoCell row={row} />
                      </td>
                      <td className="num talker-row__volume">{fmtVolumeSize(row.trafficGb, row.trafficTb)}</td>
                      <td className="num" style={{ textAlign: 'right', color: 'var(--fg-secondary)' }}>
                        {share.toFixed(1)}%
                      </td>
                    </tr>
                    {expanded && (
                      <tr className="talker-row-detail">
                        <td colSpan={colSpan}>
                          <TalkerRowDetail
                            row={row}
                            isPair
                            periodLabel={periodLabel}
                            directionFilterLabel={directionFilterLabel}
                            meta={meta}
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
                      <TalkerMainAsnCell asName={row.asName} asn={row.asn} />
                    </td>
                    <td className="talker-row__geo">{talkerGeoDisplay(row.asCountry || row.countryCode)}</td>
                    <td className="num talker-row__volume">{fmtVolumeSize(row.trafficGb, row.trafficTb)}</td>
                    <td className="num" style={{ textAlign: 'right', color: 'var(--fg-secondary)' }}>
                      {share.toFixed(1)}%
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="talker-row-detail">
                      <td colSpan={colSpan}>
                        <TalkerRowDetail
                          row={row}
                          isPair={false}
                          periodLabel={periodLabel}
                          directionFilterLabel={directionFilterLabel}
                          meta={meta}
                        />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
        </div>
        {hasMore && hasData && (
          <div ref={loadMoreSentinelRef} className="talker-table-state" style={{ padding: '12px 16px' }}>
            {loadingMore ? 'Загрузка…' : 'Прокрутите для подгрузки'}
          </div>
        )}
        <div className="table-foot">
          <div className="table-foot__row">
            <span>
              {search
                ? `Найдено ${filtered.length} из ${rows.length} загруженных`
                : `Загружено ${rows.length}${hasMore ? '+' : ''}`}
            </span>
            <span>Запрос выполнен за <b style={{ color: 'var(--fg-primary)' }}>{fmtTalkerLoadMs(loadMs, serverMs)}</b></span>
          </div>
        </div>
      </Card>
    </div>
  );
}

function TopBarRow({ row, i, max, metric, isPair }) {
  const value = talkerMetricValue(row, metric);
  const pct = (value / max) * 100;
  const color = PROTOCOL_CHART_COLORS[i % PROTOCOL_CHART_COLORS.length];
  return (
    <div className="top-bar-row">
      <div className="row top-bar-row__head">
        <span className="top-bar-row__rank">{i + 1}</span>
        <span className="top-bar-row__label">
          {talkerBarLabel(row, isPair)}
        </span>
        <span className="mono top-bar-row__metric">
          {talkerMetricDisplay(row, metric)}
        </span>
      </div>
      <div className="top-bar-row__track">
        <div className="top-bar-row__fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

function TopInfoRow({ label, value }) {
  return (
    <div className="row" style={{ justifyContent: 'space-between', gap: 12 }}>
      <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{label}</span>
      <span style={{ font: 'var(--pv-text-body-2-bold)', textAlign: 'right' }}>{value}</span>
    </div>
  );
}

Object.assign(window, { PageTop });
