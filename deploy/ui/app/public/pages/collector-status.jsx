/* Мониторинг коллекторов — read-only operational view */

const AUTO_REFRESH_MS = 30000;
const COLLECTORS_TAB_KEY = 'grapes-collectors-tab';

const COLLECTOR_STATE_LABELS = {
  online: 'Работает',
  offline: 'Нет данных',
  empty: 'Без экспортёров',
};

const COLLECTOR_STATE_TONE = {
  online: 'healthy',
  offline: 'critical',
  empty: 'idle',
};

function fmtAgeSeconds(sec) {
  const n = Number(sec) || 0;
  if (n < 60) return `${n} с`;
  if (n < 3600) return `${Math.floor(n / 60)} мин`;
  return `${Math.floor(n / 3600)} ч ${Math.floor((n % 3600) / 60)} мин`;
}

function fmtLastSeen(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function CollectorStateBadge({ state }) {
  return (
    <StatusIndicator
      status={COLLECTOR_STATE_TONE[state] || 'idle'}
      label={COLLECTOR_STATE_LABELS[state] || state}
    />
  );
}

function PageCollectorStatus({ onNavigate }) {
  const [overview, setOverview] = useState(null);
  const [meta, setMeta] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [stateFilter, setStateFilter] = useState('all');
  const [openLocations, setOpenLocations] = useState(() => new Set());
  const [openCollectors, setOpenCollectors] = useState(() => new Set());

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const res = await ApiClient.loadCollectorOverview();
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setOverview(null);
        setMeta(null);
      } else {
        setOverview(res.data || null);
        setMeta(res.meta || null);
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const id = setInterval(reload, AUTO_REFRESH_MS);
    return () => clearInterval(id);
  }, [autoRefresh, reload]);

  const locations = overview?.locations || [];

  useEffect(() => {
    setOpenLocations(new Set(locations.map((loc) => loc.locationId || loc.locationName || '__unknown__')));
    const colKeys = locations.flatMap((loc) => {
      const locKey = loc.locationId || loc.locationName || '__unknown__';
      return (loc.collectors || []).map((c) => `${locKey}::${c.collectorId}`);
    });
    setOpenCollectors(new Set(colKeys));
  }, [locations.length, refreshKey]);

  const counts = useMemo(() => {
    const collectors = overview?.collectors || [];
    return {
      online: collectors.filter((c) => c.state === 'online').length,
      offline: collectors.filter((c) => c.state === 'offline').length,
      empty: collectors.filter((c) => c.state === 'empty').length,
    };
  }, [overview]);

  const filteredTree = useMemo(() => {
    if (stateFilter === 'all') return locations;
    return locations.map((loc) => ({
      ...loc,
      collectors: (loc.collectors || []).filter((c) => c.state === stateFilter),
    })).filter((loc) => loc.collectors.length > 0);
  }, [locations, stateFilter]);

  const toggleLocation = (key) => {
    setOpenLocations((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const toggleCollector = (key) => {
    setOpenCollectors((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const goFixBinding = () => {
    sessionStorage.setItem(COLLECTORS_TAB_KEY, 'unassigned');
    if (onNavigate) onNavigate('collectors');
    else location.hash = 'collectors';
  };

  const goConfigure = () => {
    if (onNavigate) onNavigate('collectors');
    else location.hash = 'collectors';
  };

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Мониторинг коллекторов</h1>
          <p>
            Оперативная картина по каталогу и live-данным за 5 минут.
            Состояние считается по привязанным экспортёрам потоков, а не по имени хоста.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="settings" onClick={goConfigure}>Настроить</Button>
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
          <Button
            kind={autoRefresh ? 'primary' : 'ghost'}
            icon="clock"
            onClick={() => setAutoRefresh((v) => !v)}
          >
            Auto 30 с
          </Button>
        </div>
      </div>

      <div className="grid grid--3col grid--mb">
        <SumCard label="Работает" value={counts.online} icon="check" tone="success" />
        <SumCard label="Нет данных" value={counts.offline} icon="x" tone="critical" />
        <SumCard label="Без экспортёров" value={counts.empty} icon="alert" tone="warning" />
      </div>

      <Card pad="sm" style={{ marginBottom: 16 }}>
        <div className="row" style={{ gap: 16, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="seg" style={{ marginBottom: 2 }}>
            {[
              ['all', 'Все'],
              ['online', 'Работают'],
              ['offline', 'Нет данных'],
              ['empty', 'Без экспортёров'],
            ].map(([id, label]) => (
              <button key={id} className={stateFilter === id ? 'is-active' : ''} onClick={() => setStateFilter(id)}>
                {label}
              </button>
            ))}
          </div>
          <Button kind="ghost" size="sm" onClick={goFixBinding}>Исправить привязку</Button>
          {meta && (
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginLeft: 'auto' }}>
              Коллекторов: {meta.collectorCount ?? '—'} · активных экспортёров: {meta.liveSourceCount ?? '—'} · окно {meta.windowMinutes ?? 5} мин
            </span>
          )}
        </div>
      </Card>

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : loadError ? (
        <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={reload}>Повторить</Button>} />
      ) : filteredTree.length === 0 ? (
        <Empty
          icon="collectors"
          title="Нет коллекторов"
          desc="Добавьте коллекторы и привяжите экспортёры потоков в каталоге."
          action={<Button kind="primary" onClick={goConfigure}>Настроить</Button>}
        />
      ) : (
        <div className="status-tree">
          {filteredTree.map((loc) => {
            const locKey = loc.locationId || loc.locationName || '__unknown__';
            const locOpen = openLocations.has(locKey);
            const locFlows = (loc.collectors || []).reduce((sum, c) => sum + (Number(c.flowsPerMin) || 0), 0);
            const locLive = (loc.collectors || []).reduce((sum, c) => sum + (Number(c.liveSourceCount) || 0), 0);
            const locTotal = (loc.collectors || []).reduce((sum, c) => sum + (Number(c.sourceCount) || 0), 0);
            return (
              <Card key={locKey} pad="sm" className="status-tree__block">
                <button type="button" className="status-tree__head" onClick={() => toggleLocation(locKey)}>
                  <Icon name={locOpen ? 'chevD' : 'chevR'} size={14} />
                  <div className="status-tree__head-main">
                    <span className="status-tree__title">{loc.locationName || 'Без локации'}</span>
                    <span className="status-tree__meta">
                      {loc.collectors.length} коллекторов · {locLive}/{locTotal} активных · {fmtNum(locFlows)} потоков/мин
                    </span>
                  </div>
                </button>

                {locOpen && (loc.collectors || []).map((col) => {
                  const colKey = `${locKey}::${col.collectorId}`;
                  const colOpen = openCollectors.has(colKey);
                  return (
                    <div key={colKey} className="status-tree__section">
                      <button type="button" className="status-tree__head status-tree__head--collector" onClick={() => toggleCollector(colKey)}>
                        <Icon name={colOpen ? 'chevD' : 'chevR'} size={14} />
                        <div className="status-tree__head-main">
                          <span className="status-tree__title">{col.displayName || col.collectorId}</span>
                          <span className="status-tree__meta">
                            {col.liveSourceCount}/{col.sourceCount} экспортёров · {fmtNum(col.flowsPerMin)} потоков/мин · {fmtBytes(col.bytesPerSec)}/с
                            {col.lastSeen ? ` · последний поток ${fmtLastSeen(col.lastSeen)}` : ''}
                          </span>
                        </div>
                        <CollectorStateBadge state={col.state} />
                      </button>

                      {colOpen && (
                        <div className="status-tree__table-wrap">
                          <table className="table status-tree__table">
                            <thead>
                              <tr>
                                <th>Экспортёр</th>
                                <th>Тип</th>
                                <th>Каталог</th>
                                <th>Активность</th>
                                <th className="num">Потоков/мин</th>
                                <th className="num">Байт/с</th>
                                <th>Давность</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(col.sources || []).map((src) => (
                                <tr key={src.sourceId}>
                                  <td>
                                    <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{src.sourceName || src.sourceId}</div>
                                    <div className="mono" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{src.sourceId}</div>
                                  </td>
                                  <td><Badge tone="neutral">{src.sourceType || '—'}</Badge></td>
                                  <td>
                                    <Badge tone={src.catalogState === 'assigned' ? 'success' : src.catalogState === 'broken_collector_link' ? 'critical' : 'warning'}>
                                      {src.catalogState || '—'}
                                    </Badge>
                                  </td>
                                  <td>
                                    <StatusIndicator
                                      status={src.isLive ? 'healthy' : 'idle'}
                                      label={src.isLive ? 'Активен' : '—'}
                                    />
                                  </td>
                                  <td className="num mono">{fmtNum(src.flowsPerMin)}</td>
                                  <td className="num mono">{fmtBytes(src.bytesPerSec)}/с</td>
                                  <td>{src.ageSec != null ? fmtAgeSeconds(src.ageSec) : '—'}</td>
                                </tr>
                              ))}
                              {!col.sources?.length && (
                                <tr>
                                  <td colSpan={7} style={{ color: 'var(--fg-secondary)', textAlign: 'center' }}>
                                    Нет привязанных экспортёров
                                  </td>
                                </tr>
                              )}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  );
                })}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

Object.assign(window, { PageCollectorStatus, CollectorStateBadge });
