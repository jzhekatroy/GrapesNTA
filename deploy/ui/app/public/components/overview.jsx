/* Shared, data-only overview widgets for operator and client dashboards. */

const OVERVIEW_LOAD_FAILED = 'Не удалось загрузить';

function OverviewDataState({ children, style, error, status }) {
  const message = status === 403
    ? 'Недостаточно прав'
    : (children || error || OVERVIEW_LOAD_FAILED);
  return (
    <div className="other-ports-table__state" style={style}>
      {message}
    </div>
  );
}

function OverviewEmptyState({ children }) {
  return (
    <Empty
      icon="info"
      title="Нет данных"
      desc={children || 'За выбранный период данных пока нет. Для нового клиента история начинается с момента подключения.'}
    />
  );
}

function OverviewTrafficStatTile({ label, mode, stats, directionDefs, loadMs, serverMs, footer }) {
  const rows = (directionDefs || []).filter((d) => d.enabled !== false);
  return (
    <Card loadMs={loadMs} serverMs={serverMs}>
      <div className="traffic-stat-tile">
        <div className="traffic-stat-tile__title">{label}</div>
        <div className="traffic-stat-tile__rows">
          {rows.map((d) => {
            const value = stats?.[d.id] || {};
            const vals = mode === 'volume'
              ? `${fmtVolumeSize(value.gb, value.tb)}, ${fmtMpTotal(value.packets || 0)}`
              : `${fmtGbps(value.bps || 0)}, ${fmtMpps(value.pps || 0)}`;
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
        {footer}
      </div>
    </Card>
  );
}

function OverviewTrafficChartCard({
  title,
  subtitle,
  points,
  lines,
  ppsLines,
  mode,
  onModeChange,
  hiddenKeys,
  onToggleLine,
  loading,
  failed,
  error,
  status,
  loadMs,
  serverMs,
  displayTimezone,
  periodStartMs,
  periodEndMs,
  bucketSeconds,
  onRangeSelect,
  footer,
  allowPps = true,
  showEmptyState = true,
}) {
  const hidden = hiddenKeys || new Set();
  const visibleLines = (lines || []).filter((line) => !hidden.has(line.key));
  const visiblePps = (ppsLines || lines || []).filter((line) => !hidden.has(`${line.key}_pps`));
  const showRefreshHint = DashboardLog?.isVerbose?.() === true;
  return (
    <Card
      title={title}
      subtitle={subtitle}
      loadMs={loadMs}
      serverMs={serverMs}
      tools={allowPps ? (
        <>
          <div className="seg">
            <button className={mode === 'bw' ? 'is-active' : ''} onClick={() => onModeChange?.('bw')}>Полоса</button>
            <button className={mode === 'pps' ? 'is-active' : ''} onClick={() => onModeChange?.('pps')}>pps</button>
          </div>
          <Button kind="ghost" size="sm" icon="zoom" />
          <Button kind="ghost" size="sm" icon="more" />
        </>
      ) : null}
    >
      {(onRangeSelect || showRefreshHint) ? (
        <div className="chart-range-hint">
          {onRangeSelect ? (
            <>
              <Icon name="info" size={12} /> Выделите диапазон на графике
            </>
          ) : null}
          {showRefreshHint ? (
            <span>
              {onRangeSelect ? ' · авто-обновление каждую минуту' : 'Авто-обновление каждую минуту'}
            </span>
          ) : null}
        </div>
      ) : null}
      {loading ? (
        <div className="skeleton" style={{ height: 280 }} />
      ) : failed ? (
        <OverviewDataState style={{ minHeight: 280 }} error={error} status={status} />
      ) : showEmptyState && !(points || []).length ? (
        <OverviewEmptyState />
      ) : (
        <DualChart
          points={points || []}
          lines={visibleLines}
          ppsLines={visiblePps}
          height={280}
          mode={mode}
          onRangeSelect={onRangeSelect}
          bucketSeconds={bucketSeconds}
          displayTimezone={displayTimezone}
          periodStartMs={periodStartMs}
          periodEndMs={periodEndMs}
          skipTrailingGaps
        />
      )}
      <div className="chart-legend chart-legend--below">
        {(lines || []).map((line) => {
          const key = mode === 'pps' ? `${line.key}_pps` : line.key;
          const off = hidden.has(key);
          return (
            <button
              key={key}
              type="button"
              className={`chart-legend__item${off ? ' is-off' : ''}`}
              aria-pressed={!off}
              title={off ? 'Показать на графике' : 'Скрыть с графика'}
              onClick={() => onToggleLine?.(key)}
            >
              <span
                className="chart-legend__swatch"
                style={{ width: 12, height: line.key === 'total' ? 3 : 2, background: line.color, opacity: off ? 0.35 : 1 }}
              />
              {line.label}, {mode === 'pps' ? 'пакеты/с' : 'бит/с'}
            </button>
          );
        })}
      </div>
      {footer}
    </Card>
  );
}

function OverviewDirectionToggle({ value, onChange }) {
  return (
    <div className="seg seg--compact" title="Направление трафика">
      <button type="button" className={value === 'in' ? 'is-active' : ''} onClick={() => onChange?.('in')}>К вам</button>
      <button type="button" className={value === 'out' ? 'is-active' : ''} onClick={() => onChange?.('out')}>От вас</button>
    </div>
  );
}

function OverviewDistributionPane({
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
  error,
  status,
  trendFailed,
  loadMs,
  serverMs,
  centered = false,
}) {
  const center = donutCenterTraffic(filterNonZeroDonutSegments(items || []));
  const trendSeries = trend?.series || { points: [], lines: [] };
  const trendPoints = (trendSeries.points || []).map((pt) => {
    const next = { ...pt };
    if (next.bucket) next.bucket = normalizeBucketString(next.bucket);
    next.t = formatPointTimeLabel(next, chartLongRange, displayTimezone);
    if (next.bucketMs != null) next.bucketMs = Number(next.bucketMs);
    return next;
  });
  const loading = mode === 'trend' && (trend?.source === 'loading' || trend?.source === 'idle');
  let content;
  if ((mode === 'share' && failed) || (mode === 'trend' && (trendFailed || trend?.source === 'error'))) {
    content = <OverviewDataState style={{ flex: 1, minHeight: 150 }} error={error} status={status} />;
  } else if (mode === 'share') {
    content = <Donut data={items || []} centerLabel={center.label} centerSub={center.sub} size={150} thickness={20} onOtherClick={onOtherClick} />;
  } else if (loading) {
    content = <div className="distribution-pane__loading">Загрузка…</div>;
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
        skipTrailingGaps
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

function OverviewCountryCard({
  title = 'География источников',
  subtitle,
  rows,
  colorMetric,
  onColorMetricChange,
  extraTools,
  loading,
  failed,
  error,
  status,
  loadMs,
  serverMs,
  listKey,
  notice,
  footer,
}) {
  const [modalOpen, setModalOpen] = useState(false);
  const visibleRows = (rows || []).filter((row) => !row.synthetic);
  const otherRow = (rows || []).find((row) => row.synthetic);
  return (
    <>
      <Card
        title={title}
        subtitle={subtitle}
        loadMs={loadMs}
        serverMs={serverMs}
        tools={
          <div className="country-heatmap-tools row">
            {extraTools}
            <div className="seg seg--compact" title="Метрика заливки карты">
              <button type="button" className={colorMetric === 'share' ? 'is-active' : ''} onClick={() => onColorMetricChange?.('share')}>%</button>
              <button type="button" className={colorMetric === 'volume' ? 'is-active' : ''} onClick={() => onColorMetricChange?.('volume')}>Gb</button>
            </div>
          </div>
        }
      >
        {notice}
        {failed && status === 403 ? (
          <OverviewDataState style={{ minHeight: 220 }} error={error} status={status} />
        ) : (
          <CountryChoropleth
            rows={visibleRows}
            colorMetric={colorMetric}
            loading={loading}
            failed={failed}
            showExpand
            onExpand={() => setModalOpen(true)}
          />
        )}
        {visibleRows.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <CountryRankList rows={visibleRows} listKey={listKey} colorMetric={colorMetric} />
          </div>
        )}
        {otherRow && (
          <div className="chart-data-until">
            Прочее · {Number(otherRow.sharePercent || 0).toFixed(2)}% · {fmtVolumeSize(otherRow.trafficGb || 0)}
          </div>
        )}
        {footer}
      </Card>
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} size="map" title={title} subtitle={subtitle}>
        <div className="country-map-modal__body">
          <CountryChoropleth rows={visibleRows} colorMetric={colorMetric} loading={loading} failed={failed} large />
        </div>
      </Modal>
    </>
  );
}

function formatRecentFlowTs(ts) {
  if (!ts) return '—';
  const text = String(ts).replace('T', ' ').trim();
  const match = text.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  if (match) return `${match[3]}.${match[2]} ${match[4]}`;
  return text.slice(0, 14);
}

function OverviewFlowEndpoint({ flow }) {
  const srcPort = Number(flow.srcPort) > 0 ? `:${flow.srcPort}` : '';
  const dstPort = Number(flow.dstPort) > 0 ? `:${flow.dstPort}` : '';
  const srcLabel = flow.srcLabel && flow.srcLabel !== flow.srcIp ? flow.srcLabel : '';
  const dstLabel = flow.dstLabel && flow.dstLabel !== flow.dstIp ? flow.dstLabel : '';
  return (
    <div className="recent-flow-endpoints">
      <div className="recent-flow-endpoint">
        <span className="recent-flow-endpoint__ip mono">{flow.srcIp}</span>
        {srcPort && <span className="recent-flow-endpoint__port mono">{srcPort}</span>}
        {srcLabel && <span className="recent-flow-endpoint__label">{srcLabel}</span>}
      </div>
      <div className="recent-flow-arrow" aria-hidden="true">→</div>
      <div className="recent-flow-endpoint">
        <span className="recent-flow-endpoint__ip mono">{flow.dstIp}</span>
        {dstPort && <span className="recent-flow-endpoint__port mono">{dstPort}</span>}
        {dstLabel && <span className="recent-flow-endpoint__label">{dstLabel}</span>}
      </div>
    </div>
  );
}

function RecentFlowProtoBadge({ proto }) {
  return (
    <Badge tone={proto === 'TCP' ? 'info' : proto === 'UDP' ? 'neutral' : proto === 'QUIC' ? 'success' : 'warning'}>
      {proto}
    </Badge>
  );
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

function OverviewRecentFlowsCard({
  rows,
  source,
  error,
  status,
  subtitle,
  loadMs,
  serverMs,
  cabinetMode = false,
  emptyLabel = 'Нет последних потоков',
}) {
  const colSpan = cabinetMode ? 7 : 6;
  return (
    <Card className="card--recent-flows" title="Последние потоки" subtitle={subtitle} loadMs={loadMs} serverMs={serverMs} pad="0">
      <table className={`table table--recent-flows${cabinetMode ? ' table--recent-flows--cabinet' : ''}`} style={{ borderRadius: 0 }}>
        <thead>
          <tr>
            <th className="recent-flows__time-col">Время</th>
            {cabinetMode && <th className="recent-flows__direction-col">Направление</th>}
            <th className="recent-flows__flow-col">Поток</th>
            <th className="recent-flows__meta-col">{cabinetMode ? 'Страны' : 'VLAN / GEO'}</th>
            <th className="recent-flows__proto-col">Proto</th>
            <th className="recent-flows__bytes-col">Объём</th>
            <th className="recent-flows__asn-col">ASN</th>
          </tr>
        </thead>
        <tbody>
          {source === 'loading' && <tr><td colSpan={colSpan} className="talker-table-state">Загрузка…</td></tr>}
          {source === 'error' && (
            <tr>
              <td colSpan={colSpan} className="talker-table-state">
                {status === 403 ? 'Недостаточно прав' : (error || OVERVIEW_LOAD_FAILED)}
              </td>
            </tr>
          )}
          {source === 'clickhouse' && !(rows || []).length && <tr><td colSpan={colSpan} className="talker-table-state">{emptyLabel}</td></tr>}
          {source === 'clickhouse' && (rows || []).map((flow, index) => (
            <tr key={`${flow.ts}-${flow.srcIp}-${flow.dstIp}-${index}`}>
              <td className="recent-flows__time mono" title={flow.ts}>{formatRecentFlowTs(flow.ts)}</td>
              {cabinetMode && (
                <td className="recent-flows__direction-col">
                  <Badge tone="info">{flow.clientSide === 'dst' ? 'К вам' : flow.clientSide === 'both' ? 'Внутри' : 'От вас'}</Badge>
                </td>
              )}
              <td className="recent-flows__flow-col"><OverviewFlowEndpoint flow={flow} /></td>
              <td>
                {cabinetMode ? (
                  <span className="recent-flow-meta__geo">{countryShort(flow.srcCountry, flow.srcIp)} → {countryShort(flow.dstCountry, flow.dstIp)}</span>
                ) : (
                  <RecentFlowMetaCell flow={flow} />
                )}
              </td>
              <td><RecentFlowProtoBadge proto={flow.proto} /></td>
              <td className="recent-flows__bytes num"><div>{fmtBytes(flow.bytes)}</div><small>{fmtNum(flow.pkts)} пак.</small></td>
              <td className="recent-flows__asn-cell">
                <RecentFlowAsnCell srcAsn={flow.srcAsn} dstAsn={flow.dstAsn} srcAsName={flow.srcAsName} dstAsName={flow.dstAsName} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

Object.assign(window, {
  OverviewDataState,
  OverviewEmptyState,
  OverviewTrafficStatTile,
  OverviewTrafficChartCard,
  OverviewDirectionToggle,
  OverviewDistributionPane,
  OverviewCountryCard,
  OverviewRecentFlowsCard,
});
