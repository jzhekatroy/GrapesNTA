/* BMP / BGP — sessions, route table, events and churn */

const { useState, useEffect, useCallback, useMemo } = React;

const AUTO_REFRESH_MS = 30000;
const RANGE_IDS = ['15m', '1h', '6h', '24h'];
const PAGE_SIZES = [25, 50, 100, 200];

function bmpT(key, params) {
  return GrapesI18n.t(key, params);
}

function bmpRangeLabel(id) {
  const key = `period.${id}`;
  return GrapesI18n.has(key) ? bmpT(key) : id;
}

function formatBmpError(message) {
  const text = String(message || '');
  const ruMatch = text.match(/^Недопустимый range:\s*(.+)$/);
  if (ruMatch) return bmpT('bmpPage.err.invalidRange', { key: ruMatch[1].trim() });
  const enMatch = text.match(/^Invalid range:\s*(.+)$/i);
  if (enMatch) return bmpT('bmpPage.err.invalidRange', { key: enMatch[1].trim() });
  return text;
}

function fmtBmpTime(value) {
  if (!value) return '—';
  const s = String(value).includes('T') ? value : `${String(value).replace(' ', 'T')}Z`;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(GrapesI18n.intlLocale(), {
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
      {formatBmpError(error)}
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
        {total
          ? bmpT('bmpPage.pager.range', { from, to, total: fmtNum(total) })
          : bmpT('bmpPage.pager.empty')}
      </span>
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <select
          className="input"
          value={limit}
          disabled={loading}
          onChange={(e) => onChange({ offset: 0, limit: Number(e.target.value) })}
          style={{ width: 90 }}
          title={bmpT('table.rowsPerPage')}
        >
          {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
        </select>
        <Button
          kind="ghost"
          size="sm"
          disabled={loading || page <= 1}
          onClick={() => onChange({ offset: Math.max(0, offset - limit), limit })}
        >
          {bmpT('bmpPage.pager.prev')}
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
          {bmpT('bmpPage.pager.next')}
        </Button>
      </div>
    </div>
  );
}

function BmpHealthTab({ summary, peers, routers, loading }) {
  return (
    <div className="col" style={{ gap: 14 }}>
      <Card title={bmpT('bmpPage.health.routersTitle')} pad="sm">
        <table className="table">
          <thead>
            <tr>
              <th>{bmpT('bmpPage.col.router')}</th>
              <th className="num">{bmpT('bmpPage.col.peers')}</th>
              <th className="num">{bmpT('bmpPage.col.events1h')}</th>
              <th>{bmpT('bmpPage.col.lastEvent')}</th>
              <th>{bmpT('bmpPage.col.status')}</th>
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
                    label={r.stale ? bmpT('bmpPage.router.stale') : bmpT('bmpPage.router.active')}
                  />
                </td>
              </tr>
            ))}
            {!loading && !(routers || []).length && (
              <tr><td colSpan={5} style={{ color: 'var(--fg-secondary)' }}>{bmpT('table.empty')}</td></tr>
            )}
          </tbody>
        </table>
      </Card>

      <Card title={bmpT('bmpPage.health.peersTitle')} pad="sm">
        <table className="table">
          <thead>
            <tr>
              <th>{bmpT('bmpPage.col.router')}</th>
              <th>{bmpT('bmpPage.col.peer')}</th>
              <th>{bmpT('bmpPage.col.asn')}</th>
              <th>{bmpT('bmpPage.col.state')}</th>
              <th>{bmpT('bmpPage.col.updated')}</th>
            </tr>
          </thead>
          <tbody>
            {(peers || []).map((p, i) => (
              <tr key={`${p.router_addr}-${p.peer_addr}-${i}`}>
                <td className="mono">{p.router_addr}</td>
                <td className="mono">{p.peer_addr === '0.0.0.0' ? bmpT('bmpPage.peer.localRib') : p.peer_addr}</td>
                <td>{p.peer_asn_label || (p.peer_asn ? `AS${p.peer_asn}` : '—')}</td>
                <td>
                  <StatusIndicator
                    status={p.state === 'up' ? 'healthy' : 'critical'}
                    label={p.state === 'up' ? bmpT('bmpPage.peer.up') : bmpT('bmpPage.peer.down')}
                  />
                </td>
                <td>{fmtBmpTime(p.ts)}</td>
              </tr>
            ))}
            {!loading && !(peers || []).length && (
              <tr><td colSpan={5} style={{ color: 'var(--fg-secondary)' }}>{bmpT('bmpPage.empty.noPeers')}</td></tr>
            )}
          </tbody>
        </table>
        {summary?.routesCurrent != null && (
          <div style={{ marginTop: 10, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            {bmpT('bmpPage.snapshot.prefixes', { n: fmtNum(summary.routesCurrent) })}
            {summary.routesSnapshotAt
              ? bmpT('bmpPage.snapshot.updated', { time: fmtBmpTime(summary.routesSnapshotAt) })
              : ''}
          </div>
        )}
      </Card>
    </div>
  );
}

function BmpRoutesTab({
  routes, total, offset, limit, q, family, loading, hasNextHop, routesLoaded,
  onQChange, onFamilyChange, onSearch, onPageChange, onOpenEvents,
}) {
  const cols = useMemo(() => [
    {
      key: 'prefix',
      title: bmpT('bmpPage.col.prefix'),
      width: 180,
      render: (r) => (
        <button
          type="button"
          className="btn btn--link mono"
          style={{ padding: 0 }}
          onClick={() => onOpenEvents(r.prefix)}
          title={bmpT('bmpPage.routes.openEventsPrefix')}
        >
          {r.prefix}
        </button>
      ),
    },
    {
      key: 'family',
      title: bmpT('bmpPage.col.family'),
      width: 90,
      render: (r) => (Number(r.family) === 6 ? bmpT('bmpPage.family.ipv6') : bmpT('bmpPage.family.ipv4')),
    },
    {
      key: 'origin_asn',
      title: bmpT('bmpPage.col.originAsn'),
      render: (r) => r.origin_asn_label || (r.origin_asn ? `AS${r.origin_asn}` : '—'),
      sortAccessor: (r) => Number(r.origin_asn) || 0,
    },
    {
      key: 'peer_asn',
      title: bmpT('bmpPage.col.peerAsn'),
      render: (r) => r.peer_asn_label || (r.peer_asn ? `AS${r.peer_asn}` : '—'),
      sortAccessor: (r) => Number(r.peer_asn) || 0,
    },
    ...(hasNextHop ? [{
      key: 'next_hop',
      title: bmpT('bmpPage.col.nextHop'),
      width: 160,
      render: (r) => <span className="mono">{r.next_hop || '—'}</span>,
      sortAccessor: (r) => String(r.next_hop || ''),
    }] : []),
    {
      key: 'active_paths',
      title: hasNextHop ? bmpT('bmpPage.col.peersCount') : bmpT('bmpPage.col.paths'),
      width: 80,
      align: 'right',
      num: true,
      sortAccessor: (r) => Number(r.active_paths) || 0,
    },
    ...(hasNextHop ? [{
      key: 'prefix_paths',
      title: bmpT('bmpPage.col.prefixTotal'),
      width: 140,
      align: 'right',
      num: true,
      render: (r) => bmpT('bmpPage.routes.pathsHop', {
        paths: Number(r.prefix_paths) || 0,
        hops: Number(r.prefix_next_hops) || 1,
      }),
      sortAccessor: (r) => Number(r.prefix_paths) || 0,
    }] : []),
    {
      key: 'last_ts',
      title: bmpT('bmpPage.col.updated'),
      width: 150,
      render: (r) => fmtBmpTime(r.last_ts),
      sortAccessor: (r) => String(r.last_ts || ''),
    },
  ], [onOpenEvents, hasNextHop]);

  const routesNote = routesLoaded
    ? bmpT(hasNextHop ? 'bmpPage.routes.note.nextHop' : 'bmpPage.routes.note.legacy')
    : '';

  return (
    <div className="col" style={{ gap: 12 }}>
      <Card pad="sm">
        <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>{bmpT('bmpPage.filter.search')}</div>
            <div className="input-wrap">
              <Icon name="search" size={14} />
              <input
                className="input input--with-icon"
                placeholder={bmpT('bmpPage.routes.searchPlaceholder')}
                value={q}
                onChange={(e) => onQChange(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') onSearch(); }}
              />
            </div>
          </div>
          <div>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>{bmpT('bmpPage.filter.family')}</div>
            <select className="input" value={family} onChange={(e) => onFamilyChange(e.target.value)} style={{ width: 120 }}>
              <option value="">{bmpT('bmpPage.filter.all')}</option>
              <option value="4">{bmpT('bmpPage.family.ipv4')}</option>
              <option value="6">{bmpT('bmpPage.family.ipv6')}</option>
            </select>
          </div>
          <Button kind="primary" icon="search" onClick={onSearch} disabled={loading}>{bmpT('bmpPage.action.search')}</Button>
        </div>
        {routesNote && (
          <div style={{ marginTop: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{routesNote}</div>
        )}
      </Card>

      {loading && !routes.length ? (
        <Card pad="sm"><div style={{ padding: 28, textAlign: 'center', color: 'var(--fg-secondary)' }}>{bmpT('bmpPage.loading')}</div></Card>
      ) : (
        <>
          <DataTable
            rows={(routes || []).map((r, i) => ({
              ...r,
              id: `${r.prefix}|${r.next_hop || ''}|${r.origin_asn}|${r.peer_asn}|${i}`,
            }))}
            columns={cols}
            rowKey="id"
            pageSize={Math.max(routes.length, 1)}
            initialSort={{ key: 'last_ts', dir: 'desc' }}
            emptyTitle={bmpT('bmpPage.routes.emptyTitle')}
            emptyDesc={bmpT('bmpPage.routes.emptyDesc')}
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
  const rangeLabel = bmpRangeLabel(range);

  return (
    <div className="col" style={{ gap: 12 }}>
      <Card pad="sm">
        <div className="row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>{bmpT('bmpPage.filter.period')}</div>
            <div className="seg">
              {RANGE_IDS.map((id) => (
                <button
                  key={id}
                  type="button"
                  className={range === id ? 'is-active' : ''}
                  onClick={() => onRangeChange(id)}
                >
                  {bmpRangeLabel(id)}
                </button>
              ))}
            </div>
          </div>
          <div style={{ minWidth: 170, flex: 1 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>{bmpT('bmpPage.col.prefix')}</div>
            <input
              className="input"
              placeholder="1.2.3.0/24"
              value={filters.prefix || ''}
              onChange={(e) => onFilterChange({ ...filters, prefix: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') onSearch(); }}
            />
          </div>
          <div style={{ width: 110 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>{bmpT('bmpPage.col.originAsn')}</div>
            <input
              className="input"
              placeholder="13335"
              value={filters.origin_asn || ''}
              onChange={(e) => onFilterChange({ ...filters, origin_asn: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') onSearch(); }}
            />
          </div>
          <div style={{ width: 110 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>{bmpT('bmpPage.col.peerAsn')}</div>
            <input
              className="input"
              placeholder="44050"
              value={filters.peer_asn || ''}
              onChange={(e) => onFilterChange({ ...filters, peer_asn: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') onSearch(); }}
            />
          </div>
          <div style={{ width: 130 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>{bmpT('bmpPage.filter.type')}</div>
            <select
              className="input"
              value={filters.event_type || ''}
              onChange={(e) => onFilterChange({ ...filters, event_type: e.target.value })}
            >
              <option value="">{bmpT('bmpPage.filter.all')}</option>
              <option value="announce">{bmpT('bmpPage.event.announce')}</option>
              <option value="withdraw">{bmpT('bmpPage.event.withdraw')}</option>
            </select>
          </div>
          <div style={{ width: 110 }}>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)', marginBottom: 4 }}>{bmpT('bmpPage.filter.family')}</div>
            <select
              className="input"
              value={filters.family || ''}
              onChange={(e) => onFilterChange({ ...filters, family: e.target.value })}
            >
              <option value="">{bmpT('bmpPage.filter.all')}</option>
              <option value="4">{bmpT('bmpPage.family.ipv4')}</option>
              <option value="6">{bmpT('bmpPage.family.ipv6')}</option>
            </select>
          </div>
          <Button kind="primary" icon="search" onClick={onSearch} disabled={loading}>{bmpT('bmpPage.action.search')}</Button>
          {hasFilters && (
            <Button kind="ghost" onClick={onClear} disabled={loading}>{bmpT('bmpPage.action.reset')}</Button>
          )}
        </div>
      </Card>

      <Card pad="sm">
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
          <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            {bmpT('bmpPage.events.summary', { n: fmtNum((events || []).length), range: rangeLabel })}
          </span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{bmpT('bmpPage.col.time')}</th>
              <th>{bmpT('bmpPage.col.type')}</th>
              <th>{bmpT('bmpPage.col.router')}</th>
              <th>{bmpT('bmpPage.col.prefix')}</th>
              <th>{bmpT('bmpPage.col.nextHopDash')}</th>
              <th>{bmpT('bmpPage.col.origin')}</th>
              <th>{bmpT('bmpPage.col.asPath')}</th>
            </tr>
          </thead>
          <tbody>
            {(events || []).map((ev, i) => (
              <tr key={`${ev.ts}-${ev.prefix}-${i}`}>
                <td className="mono">{fmtBmpTime(ev.ts)}</td>
                <td>
                  <Badge tone={ev.event_type === 'withdraw' ? 'critical' : 'success'}>
                    {ev.event_type === 'withdraw'
                      ? bmpT('bmpPage.event.withdraw')
                      : ev.event_type === 'announce'
                        ? bmpT('bmpPage.event.announce')
                        : ev.event_type}
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
              <tr><td colSpan={7} style={{ color: 'var(--fg-secondary)' }}>{bmpT('bmpPage.events.empty')}</td></tr>
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
  const bucketLabel = bucketSeconds === 300
    ? bmpT('chart.tip.bucket.5min')
    : bmpT('chart.tip.bucket.1min');
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
    { key: 'announces', label: bmpT('bmpPage.chart.announce'), color: 'var(--st-success)' },
    { key: 'withdraws', label: bmpT('bmpPage.chart.withdraw'), color: 'var(--st-critical, #c0392b)' },
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
            {RANGE_IDS.map((id) => (
              <button
                key={id}
                type="button"
                className={range === id ? 'is-active' : ''}
                onClick={() => onRangeChange(id)}
              >
                {bmpRangeLabel(id)}
              </button>
            ))}
          </div>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            {loading
              ? bmpT('bmpPage.loadingShort')
              : bmpT('bmpPage.churn.peakLine', { peak: fmtNum(peak), bucket: bucketLabel })}
          </div>
        </div>
      </Card>

      <Card title={bmpT('bmpPage.churn.chartTitle')} pad="sm">
        {churn?.seriesNote && (
          <div style={{ marginBottom: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            {bmpT('bmpPage.churn.seriesNote')}
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
              tipUnitLabel={bmpT('bmpPage.churn.tipUnit')}
              valueFormatter={(v) => fmtNum(v)}
              axisFormatter={(v) => (typeof fmtCompact === 'function' ? fmtCompact(v) : fmtNum(v))}
            />
            <div className="row" style={{ gap: 16, marginTop: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              <span><span style={{ color: lines[0].color }}>●</span> {bmpT('bmpPage.event.announce')}</span>
              <span><span style={{ color: lines[1].color }}>●</span> {bmpT('bmpPage.event.withdraw')}</span>
            </div>
          </>
        ) : (
          <div style={{ padding: 24, color: 'var(--fg-secondary)', textAlign: 'center' }}>
            {loading ? bmpT('bmpPage.loading') : bmpT('bmpPage.churn.insufficientPoints')}
          </div>
        )}
      </Card>

      <div className="grid grid--2col grid--gap-sm">
        <Card title={bmpT('bmpPage.churn.topPrefixes')} pad="sm">
          <table className="table">
            <thead>
              <tr>
                <th>{bmpT('bmpPage.col.prefix')}</th>
                <th className="num">{bmpT('bmpPage.col.events')}</th>
                <th className="num">{bmpT('bmpPage.col.annWd')}</th>
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
                <tr><td colSpan={3} style={{ color: 'var(--fg-secondary)' }}>{bmpT('table.empty')}</td></tr>
              )}
            </tbody>
          </table>
        </Card>

        <Card
          title={bmpT('bmpPage.churn.flapTitle')}
          pad="sm"
          subtitle={flap?.minToggles ? bmpT('bmpPage.churn.flapSubtitle', { n: flap.minToggles }) : null}
        >
          <table className="table">
            <thead>
              <tr>
                <th>{bmpT('bmpPage.col.prefix')}</th>
                <th className="num">{bmpT('bmpPage.col.toggles')}</th>
                <th className="num">{bmpT('bmpPage.col.annWd')}</th>
                <th>{bmpT('bmpPage.col.window')}</th>
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
                <tr><td colSpan={4} style={{ color: 'var(--fg-secondary)' }}>{bmpT('bmpPage.churn.emptyFlap')}</td></tr>
              )}
            </tbody>
          </table>
        </Card>
      </div>

      <Card title={bmpT('bmpPage.churn.topPeerAsn')} pad="sm">
        <table className="table">
          <thead>
            <tr>
              <th>{bmpT('bmpPage.col.asn')}</th>
              <th className="num">{bmpT('bmpPage.chart.announce')}</th>
              <th className="num">{bmpT('bmpPage.chart.withdraw')}</th>
              <th className="num">{bmpT('bmpPage.col.total')}</th>
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
              <tr><td colSpan={4} style={{ color: 'var(--fg-secondary)' }}>{bmpT('table.empty')}</td></tr>
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
  const [routesLoaded, setRoutesLoaded] = useState(false);
  const [routesHasNextHop, setRoutesHasNextHop] = useState(false);
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
    setRoutesLoaded(true);
    setRoutesHasNextHop(Boolean(body.hasNextHop));
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
    { id: 'health', label: bmpT('bmpPage.tab.health') },
    { id: 'routes', label: bmpT('bmpPage.tab.routes') },
    { id: 'events', label: bmpT('bmpPage.tab.events') },
    { id: 'churn', label: bmpT('bmpPage.tab.churn') },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{bmpT('bmpPage.title')}</h1>
          <p>{bmpT('bmpPage.subtitle')}</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          {tab === 'health' && (
            <Button
              kind={autoRefresh ? 'primary' : 'ghost'}
              icon="clock"
              onClick={() => setAutoRefresh((v) => !v)}
            >
              {bmpT('bmpPage.autoRefresh')}
            </Button>
          )}
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>
            {bmpT('chrome.refresh')}
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
          routesLoaded={routesLoaded}
          hasNextHop={routesHasNextHop}
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
