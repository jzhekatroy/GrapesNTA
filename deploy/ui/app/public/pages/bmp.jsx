/* BMP / BGP — сессии, таблица маршрутов, события и churn */

const { useState, useEffect, useCallback, useMemo } = React;

const AUTO_REFRESH_MS = 30000;
const RANGE_OPTIONS = [
  { id: '15m', label: '15 мин' },
  { id: '1h', label: '1 час' },
  { id: '6h', label: '6 часов' },
  { id: '24h', label: '24 часа' },
];
const PAGE_SIZES = [25, 50, 100, 200];

function fmtBmpTime(value) {
  if (!value) return '—';
  const s = String(value).includes('T') ? value : `${String(value).replace(' ', 'T')}Z`;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function BmpErrorBanner({ error }) {
  if (!error) return null;
  return (
    <div style={{
      marginBottom: 12,
      padding: '10px 12px',
      borderRadius: 8,
      background: 'var(--st-critical-bg)',
      color: 'var(--st-critical)',
      font: 'var(--pv-text-body-3)',
    }}>
      {error}
    </div>
  );
}

function BmpPager({ offset, limit, total, onChange, loading }) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil((total || 0) / limit));
  const from = total ? offset + 1 : 0;
  const to = Math.min(offset + limit, total || 0);
  return (
    <div className="row" style={{ gap: 10, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
      <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
        {total ? `${from}–${to} из ${fmtNum(total)}` : 'нет строк'}
      </span>
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <select
          className="input"
          value={limit}
          disabled={loading}
          onChange={(e) => onChange({ offset: 0, limit: Number(e.target.value) })}
          style={{ width: 90 }}
          title="Строк на странице"
        >
          {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
        </select>
        <Button
          kind="ghost"
          size="sm"
          disabled={loading || page <= 1}
          onClick={() => onChange({ offset: Math.max(0, offset - limit), limit })}
        >
          Назад
        </Button>
        <span style={{ font: 'var(--pv-text-body-3)', minWidth: 70, textAlign: 'center' }}>
          {page} / {pages}
        </span>
        <Button
          kind="ghost"
          size="sm"
          disabled={loading || page >= pages}
          onClick={() => onChange({ offset: offset + limit, limit })}
        >
          Далее
        </Button>
      </div>
    </div>
  );
}

function BmpHealthTab({ summary, peers, routers, loading }) {
  return (
    <div className="col" style={{ gap: 14 }}>
      <Card title="Роутеры BMP" pad="sm">
        <table className="table">
          <thead>
            <tr>
              <th>Роутер</th>
              <th className="num">Пиры</th>
              <th className="num">События / 1 ч</th>
              <th>Последнее событие</th>
              <th>Статус</th>
            </tr>
          </thead>
          <tbody>
            {(routers || []).map((r) => (
              <tr key={r.router_addr}>
                <td className="mono">{r.router_addr}</td>
                <td className="num mono">{r.peers_up} / {r.peers_down}</td>
                <td className="num mono">{fmtNum(r.events_1h)}</td>
                <td>{fmtBmpTime(r.last_route_event_at)}</td>
                <td>
                  <StatusIndicator
                    status={r.stale ? 'critical' : 'healthy'}
                    label={r.stale ? 'нет событий' : 'активен'}
                  />
                </td>
              </tr>
            ))}
            {!loading && !(routers || []).length && (
              <tr><td colSpan={5} style={{ color: 'var(--fg-secondary)' }}>Нет данных</td></tr>
            )}
          </tbody>
        </table>
      </Card>

      <Card title="BGP-пиры" pad="sm">
        <table className="table">
          <thead>
            <tr>
              <th>Роутер</th>
              <th>Пир</th>
              <th>ASN</th>
              <th>Состояние</th>
              <th>Обновлено</th>
            </tr>
          </thead>
          <tbody>
            {(peers || []).map((p, i) => (
              <tr key={`${p.router_addr}-${p.peer_addr}-${i}`}>
                <td className="mono">{p.router_addr}</td>
                <td className="mono">{p.peer_addr === '0.0.0.0' ? 'local-RIB' : p.peer_addr}</td>
                <td>{p.peer_asn_label || (p.peer_asn ? `AS${p.peer_asn}` : '—')}</td>
                <td>
                  <StatusIndicator
                    status={p.state === 'up' ? 'healthy' : 'critical'}
                    label={p.state === 'up' ? 'up' : 'down'}
                  />
                </td>
                <td>{fmtBmpTime(p.ts)}</td>
              </tr>
            ))}
            {!loading && !(peers || []).length && (
              <tr><td colSpan={5} style={{ color: 'var(--fg-secondary)' }}>Нет peer-событий</td></tr>
            )}
          </tbody>
        </table>
        {summary?.routesCurrent != null && (
          <div style={{ marginTop: 10, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            Префиксов в снимке: {fmtNum(summary.routesCurrent)}
            {summary.routesSnapshotAt ? ` · обновлён ${fmtBmpTime(summary.routesSnapshotAt)}` : ''}
          </div>
        )}
      </Card>
    </div>
  );
}

function BmpRoutesTab({
  routes, total, offset, limit, q, family, loading, note,
  onQChange, onFamilyChange, onSearch, onPageChange, onOpenEvents,
}) {
  const cols = useMemo(() => [
    {
      key: 'prefix',
      title: 'Префикс',
      width: 180,
      render: (r) => (
        <button
          type="button"
          className="btn btn--link mono"
          style={{ padding: 0 }}
          onClick={() => onOpenEvents(r.prefix)}
          title="Показать события по префиксу"
        >
          {r.prefix}
        </button>
      ),
    },
    {
      key: 'family',
      title: 'Семейство',
      width: 90,
      render: (r) => (Number(r.family) === 6 ? 'IPv6' : 'IPv4'),
    },
    {
      key: 'origin_asn',
      title: 'Origin ASN',
      render: (r) => r.origin_asn_label || (r.origin_asn ? `AS${r.origin_asn}` : '—'),
      sortAccessor: (r) => Number(r.origin_asn) || 0,
    },
    {
      key: 'peer_asn',
      title: 'Peer ASN',
      render: (r) => r.peer_asn_label || (r.peer_asn ? `AS${r.peer_asn}` : '—'),
      sortAccessor: (r) => Number(r.peer_asn) || 0,
    },
    {
      key: 'active_paths',
      title: 'Paths',
      width: 80,
      align: 'right',
      num: true,
      sortAccessor: (r) => Number(r.active_paths) || 0,
    },
    {
      key: 'last_ts',
      title: 'Обновлён',
      width: 150,
      render: (r) => fmtBmpTime(r.last_ts),
      sortAccessor: (r) => String(r.last_ts || ''),
    },
  ], [onOpenEvents]);

  return (
    <div className="col" style={{ gap: 12 }}>
      <Card pad="sm">
        <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>Поиск</div>
            <div className="input-wrap">
              <Icon name="search" size={14} />
              <input
                className="input input--with-icon"
                placeholder="Префикс, AS12389 или имя ASN"
                value={q}
                onChange={(e) => onQChange(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') onSearch(); }}
              />
            </div>
          </div>
          <div>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>Семейство</div>
            <select className="input" value={family} onChange={(e) => onFamilyChange(e.target.value)} style={{ width: 120 }}>
              <option value="">Все</option>
              <option value="4">IPv4</option>
              <option value="6">IPv6</option>
            </select>
          </div>
          <Button kind="primary" icon="search" onClick={onSearch} disabled={loading}>Найти</Button>
        </div>
        {note && (
          <div style={{ marginTop: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{note}</div>
        )}
      </Card>

      {loading && !routes.length ? (
        <Card pad="sm"><div style={{ padding: 28, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div></Card>
      ) : (
        <>
          <DataTable
            rows={(routes || []).map((r, i) => ({
              ...r,
              id: `${r.prefix}|${r.origin_asn}|${r.peer_asn}|${i}`,
            }))}
            columns={cols}
            rowKey="id"
            pageSize={Math.max(routes.length, 1)}
            initialSort={{ key: 'last_ts', dir: 'desc' }}
            emptyTitle="Маршруты не найдены"
            emptyDesc="Измените запрос или семейство адресов."
            dense
          />
          <BmpPager
            offset={offset}
            limit={limit}
            total={total}
            loading={loading}
            onChange={onPageChange}
          />
        </>
      )}
    </div>
  );
}

function BmpEventsTab({
  events, filters, onFilterChange, onSearch, onClear, loading, range, onRangeChange,
}) {
  const hasFilters = Boolean(
    filters.prefix || filters.peer_asn || filters.origin_asn || filters.event_type || filters.family,
  );
  const rangeLabel = RANGE_OPTIONS.find((o) => o.id === range)?.label || range;

  return (
    <div className="col" style={{ gap: 12 }}>
      <Card pad="sm">
        <div className="row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>Период</div>
            <div className="seg">
              {RANGE_OPTIONS.map((o) => (
                <button
                  key={o.id}
                  type="button"
                  className={range === o.id ? 'is-active' : ''}
                  onClick={() => onRangeChange(o.id)}
                >
                  {o.label}
                </button>
              ))}
            </div>
          </div>
          <div style={{ minWidth: 170, flex: 1 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>Префикс</div>
            <input
              className="input"
              placeholder="1.2.3.0/24"
              value={filters.prefix || ''}
              onChange={(e) => onFilterChange({ ...filters, prefix: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') onSearch(); }}
            />
          </div>
          <div style={{ width: 110 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>Origin ASN</div>
            <input
              className="input"
              placeholder="13335"
              value={filters.origin_asn || ''}
              onChange={(e) => onFilterChange({ ...filters, origin_asn: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') onSearch(); }}
            />
          </div>
          <div style={{ width: 110 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>Peer ASN</div>
            <input
              className="input"
              placeholder="44050"
              value={filters.peer_asn || ''}
              onChange={(e) => onFilterChange({ ...filters, peer_asn: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') onSearch(); }}
            />
          </div>
          <div style={{ width: 130 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>Тип</div>
            <select
              className="input"
              value={filters.event_type || ''}
              onChange={(e) => onFilterChange({ ...filters, event_type: e.target.value })}
            >
              <option value="">Все</option>
              <option value="announce">announce</option>
              <option value="withdraw">withdraw</option>
            </select>
          </div>
          <div style={{ width: 110 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>Семейство</div>
            <select
              className="input"
              value={filters.family || ''}
              onChange={(e) => onFilterChange({ ...filters, family: e.target.value })}
            >
              <option value="">Все</option>
              <option value="4">IPv4</option>
              <option value="6">IPv6</option>
            </select>
          </div>
          <Button kind="primary" icon="search" onClick={onSearch} disabled={loading}>Найти</Button>
          {hasFilters && (
            <Button kind="ghost" onClick={onClear} disabled={loading}>Сбросить</Button>
          )}
        </div>
      </Card>

      <Card pad="sm">
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
          <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            Показано {fmtNum((events || []).length)} · период {rangeLabel}
          </span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>Время</th>
              <th>Тип</th>
              <th>Роутер</th>
              <th>Префикс</th>
              <th>Next-hop</th>
              <th>Origin</th>
              <th>AS_PATH</th>
            </tr>
          </thead>
          <tbody>
            {(events || []).map((ev, i) => (
              <tr key={`${ev.ts}-${ev.prefix}-${i}`}>
                <td className="mono">{fmtBmpTime(ev.ts)}</td>
                <td>
                  <Badge tone={ev.event_type === 'withdraw' ? 'critical' : 'success'}>
                    {ev.event_type}
                  </Badge>
                </td>
                <td className="mono">{ev.router_addr}</td>
                <td className="mono">{ev.prefix}</td>
                <td className="mono">{ev.next_hop || '—'}</td>
                <td>{ev.origin_asn_label || (ev.origin_asn ? `AS${ev.origin_asn}` : '—')}</td>
                <td className="mono" title={Array.isArray(ev.as_path) ? ev.as_path.join(' ') : ''}>
                  {Array.isArray(ev.as_path) && ev.as_path.length
                    ? ev.as_path.map((a) => String(a)).join(' → ')
                    : '—'}
                </td>
              </tr>
            ))}
            {!loading && !(events || []).length && (
              <tr><td colSpan={7} style={{ color: 'var(--fg-secondary)' }}>Нет событий за выбранный период</td></tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function bmpChartLabel(bucket, longRange) {
  const s = String(bucket || '');
  if (!s) return '—';
  const time = s.length >= 16 ? s.slice(11, 16) : s;
  if (!longRange) return time;
  if (s.length >= 10) return `${s.slice(8, 10)}.${s.slice(5, 7)} ${time}`;
  return time;
}

function BmpChurnTab({ counts, churn, flap, range, onRangeChange, loading, onOpenEvents }) {
  const series = churn?.series || [];
  const longRange = range === '6h' || range === '24h';
  const bucketSeconds = range === '24h' ? 300 : 60;
  const chartPoints = series.map((p) => {
    const bucket = String(p.minute || '');
    return {
      t: bmpChartLabel(bucket, longRange),
      bucket,
      announces: Number(p.announces) || 0,
      withdraws: Number(p.withdraws) || 0,
    };
  });
  const lines = [
    { key: 'announces', label: 'Announce', color: 'var(--st-success)' },
    { key: 'withdraws', label: 'Withdraw', color: 'var(--st-critical, #c0392b)' },
  ];
  const peak = series.reduce((acc, p) => {
    const n = (Number(p.announces) || 0) + (Number(p.withdraws) || 0);
    return n > acc ? n : acc;
  }, 0);

  return (
    <div className="col" style={{ gap: 14 }}>
      <Card pad="sm">
        <div className="row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
          <div className="seg">
            {RANGE_OPTIONS.map((o) => (
              <button
                key={o.id}
                type="button"
                className={range === o.id ? 'is-active' : ''}
                onClick={() => onRangeChange(o.id)}
              >
                {o.label}
              </button>
            ))}
          </div>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            {loading ? 'загрузка…' : `пик ${fmtNum(peak)} соб./интервал · bucket ${bucketSeconds === 300 ? '5 мин' : '1 мин'}`}
          </div>
        </div>
      </Card>

      <Card title="Динамика announce / withdraw" pad="sm">
        {churn?.seriesNote && (
          <div style={{ marginBottom: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            {churn.seriesNote}
          </div>
        )}
        {chartPoints.length > 1 && typeof DualChart === 'function' ? (
          <>
            <DualChart
              points={chartPoints}
              lines={lines}
              height={260}
              mode="bw"
              bucketSeconds={bucketSeconds}
              tipUnitLabel="событий"
              valueFormatter={(v) => fmtNum(v)}
              axisFormatter={(v) => (typeof fmtCompact === 'function' ? fmtCompact(v) : fmtNum(v))}
            />
            <div className="row" style={{ gap: 16, marginTop: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              <span><span style={{ color: lines[0].color }}>●</span> announce</span>
              <span><span style={{ color: lines[1].color }}>●</span> withdraw</span>
            </div>
          </>
        ) : (
          <div style={{ padding: 24, color: 'var(--fg-secondary)', textAlign: 'center' }}>
            {loading ? 'Загрузка…' : 'Недостаточно точек для графика'}
          </div>
        )}
      </Card>

      <div className="grid grid--2col grid--gap-sm">
        <Card title="Топ префиксов по изменениям" pad="sm">
          <table className="table">
            <thead>
              <tr>
                <th>Префикс</th>
                <th className="num">События</th>
                <th className="num">Ann / Wd</th>
              </tr>
            </thead>
            <tbody>
              {(churn?.topPrefixes || []).slice(0, 15).map((r) => (
                <tr key={r.prefix}>
                  <td>
                    <button type="button" className="btn btn--link mono" style={{ padding: 0 }} onClick={() => onOpenEvents(r.prefix)}>
                      {r.prefix}
                    </button>
                  </td>
                  <td className="num mono">{fmtNum(r.events)}</td>
                  <td className="num mono">{fmtNum(r.announces)} / {fmtNum(r.withdraws)}</td>
                </tr>
              ))}
              {!loading && !(churn?.topPrefixes || []).length && (
                <tr><td colSpan={3} style={{ color: 'var(--fg-secondary)' }}>Нет данных</td></tr>
              )}
            </tbody>
          </table>
        </Card>

        <Card
          title="Кандидаты на flap"
          pad="sm"
          subtitle={flap?.minToggles ? `≥ ${flap.minToggles} событий, ann и wd ≥ 2` : null}
        >
          <table className="table">
            <thead>
              <tr>
                <th>Префикс</th>
                <th className="num">Toggles</th>
                <th className="num">Ann / Wd</th>
                <th>Окно</th>
              </tr>
            </thead>
            <tbody>
              {(flap?.flapCandidates || []).slice(0, 15).map((r) => (
                <tr key={r.prefix}>
                  <td>
                    <button type="button" className="btn btn--link mono" style={{ padding: 0 }} onClick={() => onOpenEvents(r.prefix)}>
                      {r.prefix}
                    </button>
                  </td>
                  <td className="num mono">{fmtNum(r.toggle_count)}</td>
                  <td className="num mono">{fmtNum(r.announces)} / {fmtNum(r.withdraws)}</td>
                  <td style={{ font: 'var(--pv-text-body-3)', whiteSpace: 'nowrap' }}>
                    {fmtBmpTime(r.first_ts)} → {fmtBmpTime(r.last_ts)}
                  </td>
                </tr>
              ))}
              {!loading && !(flap?.flapCandidates || []).length && (
                <tr><td colSpan={4} style={{ color: 'var(--fg-secondary)' }}>Нет кандидатов за период</td></tr>
              )}
            </tbody>
          </table>
        </Card>
      </div>

      <Card title="Топ peer ASN по обновлениям" pad="sm">
        <table className="table">
          <thead>
            <tr>
              <th>ASN</th>
              <th className="num">Announce</th>
              <th className="num">Withdraw</th>
              <th className="num">Всего</th>
            </tr>
          </thead>
          <tbody>
            {(counts?.byPeerAsn || []).slice(0, 12).map((r) => {
              const sum = (Number(r.announces) || 0) + (Number(r.withdraws) || 0);
              return (
                <tr key={r.peer_asn}>
                  <td>{r.peer_asn_label || (r.peer_asn ? `AS${r.peer_asn}` : '—')}</td>
                  <td className="num mono">{fmtNum(r.announces)}</td>
                  <td className="num mono">{fmtNum(r.withdraws)}</td>
                  <td className="num mono">{fmtNum(sum)}</td>
                </tr>
              );
            })}
            {!loading && !(counts?.byPeerAsn || []).length && (
              <tr><td colSpan={4} style={{ color: 'var(--fg-secondary)' }}>Нет данных</td></tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function PageBmp() {
  const [tab, setTab] = useState('health');
  const [range, setRange] = useState('1h');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const [summary, setSummary] = useState(null);
  const [peers, setPeers] = useState([]);
  const [routers, setRouters] = useState([]);

  const [routes, setRoutes] = useState([]);
  const [routesTotal, setRoutesTotal] = useState(0);
  const [routesNote, setRoutesNote] = useState('');
  const [routeQ, setRouteQ] = useState('');
  const [routeFamily, setRouteFamily] = useState('');
  const [routeLimit, setRouteLimit] = useState(50);
  const [routeOffset, setRouteOffset] = useState(0);

  const [events, setEvents] = useState([]);
  const [eventFilters, setEventFilters] = useState({});

  const [counts, setCounts] = useState(null);
  const [churn, setChurn] = useState(null);
  const [flap, setFlap] = useState(null);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  const loadHealth = useCallback(async () => {
    const [s, p, r] = await Promise.all([
      ApiClient.loadBmpSummary(),
      ApiClient.loadBmpPeers(),
      ApiClient.loadBmpRouters(),
    ]);
    setSummary(s);
    setPeers(p.peers || []);
    setRouters(r.routers || []);
  }, []);

  const loadRoutes = useCallback(async ({
    q = routeQ,
    family = routeFamily,
    limit = routeLimit,
    offset = routeOffset,
  } = {}) => {
    const body = await ApiClient.loadBmpRoutes({
      q: q || undefined,
      family: family || undefined,
      limit,
      offset,
    });
    setRoutes(body.routes || []);
    setRoutesTotal(Number(body.total) || 0);
    setRoutesNote(body.note || '');
    setRouteLimit(Number(body.limit) || limit);
    setRouteOffset(Number(body.offset) || 0);
  }, [routeQ, routeFamily, routeLimit, routeOffset]);

  const loadEvents = useCallback(async (filters = eventFilters, r = range) => {
    const body = await ApiClient.loadBmpEvents({
      ...filters,
      range: r,
      limit: 150,
    });
    setEvents(body.events || []);
  }, [eventFilters, range]);

  const loadChurn = useCallback(async (r = range) => {
    const [c, ch, f] = await Promise.all([
      ApiClient.loadBmpCounts({ range: r }),
      ApiClient.loadBmpChurn({ range: r }),
      ApiClient.loadBmpFlap({ range: r }),
    ]);
    setCounts(c);
    setChurn(ch);
    setFlap(f);
  }, [range]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError('');
      try {
        if (tab === 'health') await loadHealth();
        else if (tab === 'routes') await loadRoutes();
        else if (tab === 'events') await loadEvents();
        else if (tab === 'churn') await loadChurn();
      } catch (e) {
        if (!cancelled) setError(e.message || String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [tab, range, refreshKey, loadHealth, loadRoutes, loadEvents, loadChurn]);

  useEffect(() => {
    if (!autoRefresh || tab !== 'health') return undefined;
    const id = setInterval(reload, AUTO_REFRESH_MS);
    return () => clearInterval(id);
  }, [autoRefresh, tab, reload]);

  const runSearch = async (fn) => {
    setLoading(true);
    setError('');
    try {
      await fn();
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setLoading(false);
    }
  };

  const openEventsForPrefix = (prefix) => {
    setEventFilters({ prefix: prefix || '' });
    setTab('events');
  };

  const tabs = [
    { id: 'health', label: 'Обзор' },
    { id: 'routes', label: 'Маршруты' },
    { id: 'events', label: 'События' },
    { id: 'churn', label: 'Изменения' },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>BMP / BGP</h1>
          <p>Состояние BMP-сессий, текущая таблица префиксов и журнал announce/withdraw.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          {tab === 'health' && (
            <Button
              kind={autoRefresh ? 'primary' : 'ghost'}
              icon="clock"
              onClick={() => setAutoRefresh((v) => !v)}
            >
              Auto 30 с
            </Button>
          )}
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>
            Обновить
          </Button>
        </div>
      </div>

      <Card pad="sm" style={{ marginBottom: 14 }}>
        <div className="seg">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              className={tab === t.id ? 'is-active' : ''}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>
      </Card>

      <BmpErrorBanner error={error} />

      {tab === 'health' && (
        <BmpHealthTab summary={summary} peers={peers} routers={routers} loading={loading} />
      )}
      {tab === 'routes' && (
        <BmpRoutesTab
          routes={routes}
          total={routesTotal}
          offset={routeOffset}
          limit={routeLimit}
          q={routeQ}
          family={routeFamily}
          loading={loading}
          note={routesNote}
          onQChange={setRouteQ}
          onFamilyChange={(v) => {
            setRouteFamily(v);
            setRouteOffset(0);
            runSearch(() => loadRoutes({ q: routeQ, family: v, limit: routeLimit, offset: 0 }));
          }}
          onSearch={() => runSearch(() => {
            setRouteOffset(0);
            return loadRoutes({ q: routeQ, family: routeFamily, limit: routeLimit, offset: 0 });
          })}
          onPageChange={({ offset, limit }) => runSearch(() => loadRoutes({
            q: routeQ,
            family: routeFamily,
            limit,
            offset,
          }))}
          onOpenEvents={openEventsForPrefix}
        />
      )}
      {tab === 'events' && (
        <BmpEventsTab
          events={events}
          filters={eventFilters}
          onFilterChange={setEventFilters}
          onSearch={() => runSearch(() => loadEvents())}
          onClear={() => {
            const cleared = {};
            setEventFilters(cleared);
            runSearch(() => loadEvents(cleared, range));
          }}
          loading={loading}
          range={range}
          onRangeChange={(r) => { setRange(r); }}
        />
      )}
      {tab === 'churn' && (
        <BmpChurnTab
          counts={counts}
          churn={churn}
          flap={flap}
          range={range}
          onRangeChange={setRange}
          loading={loading}
          onOpenEvents={openEventsForPrefix}
        />
      )}
    </div>
  );
}

Object.assign(window, { PageBmp });
