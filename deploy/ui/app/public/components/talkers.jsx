/* Shared top-talkers helpers and table cells (dashboard + full page) */

const TOP_TALKERS_TABS = [
  { id: 'src', label: 'Источники' },
  { id: 'dst', label: 'Назначения' },
  { id: 'pair', label: 'Пары' },
];

const TALKER_PAIR_ARROW = ' → ';

function talkerGeoDisplay(code) {
  const c = String(code || '').trim();
  if (!c || c === '??') return 'Неизвестно';
  return countryFlagEmoji(c);
}

function formatTalkerAsn(row) {
  if (row?.asnLabel) return row.asnLabel;
  const n = Number(row?.asn);
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n === 0) return 'AS0';
  return `AS${n}`;
}

function isPseudoAsName(name) {
  return /^AS?\d+$/i.test(String(name || '').trim());
}

function talkerAsNameDisplay(asName, asn, fallback) {
  const name = String(asName || '').trim();
  if (name && !isPseudoAsName(name)) return name;
  const n = Number(asn);
  if (Number.isFinite(n) && n === 0) return 'Без ASN';
  if (Number.isFinite(n) && n > 0) return `AS${n}`;
  const fb = String(fallback || '').trim();
  return fb || '—';
}

function ipv4ToNumber(ip) {
  const parts = String(ip || '').trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n * 256) + v;
  }
  return n >>> 0;
}

function specialIpLabel(ip) {
  const n = ipv4ToNumber(ip);
  if (n == null) return '';
  const inRange = (start, end) => n >= ipv4ToNumber(start) && n <= ipv4ToNumber(end);
  if (inRange('10.0.0.0', '10.255.255.255')) return 'RFC1918 private';
  if (inRange('172.16.0.0', '172.31.255.255')) return 'RFC1918 private';
  if (inRange('192.168.0.0', '192.168.255.255')) return 'RFC1918 private';
  if (inRange('224.0.0.0', '239.255.255.255')) return 'Multicast';
  if (inRange('240.0.0.0', '255.255.255.255')) return 'Reserved';
  if (inRange('169.254.0.0', '169.254.255.255')) return 'Link-local';
  if (inRange('127.0.0.0', '127.255.255.255')) return 'Loopback';
  return '';
}

function talkerRowKey(row, isPair) {
  return isPair
    ? `pair:${row.srcAsn}-${row.dstAsn}`
    : `endpoint:${row.asn}`;
}

function talkerListLabel(val) {
  const s = val == null ? '' : String(val).trim();
  return s || '—';
}

function talkerListJoin(arr) {
  if (!arr?.length) return '—';
  return arr.join(', ');
}

function fmtTalkerBandwidth(gbps) {
  const v = Number(gbps) || 0;
  if (v >= 1) return { value: v.toFixed(3), unit: 'Gbps' };
  if (v >= 0.001) return { value: (v * 1000).toFixed(1), unit: 'Mbps' };
  if (v > 0) return { value: (v * 1e6).toFixed(0), unit: 'Kbps' };
  return { value: '0', unit: 'Gbps' };
}

function TalkerBandwidthText({ gbps }) {
  const { value, unit } = fmtTalkerBandwidth(gbps);
  return <>{value} {unit}</>;
}

function TalkerMainIpCell({ ip, label }) {
  const showLabel = label && label !== ip;
  return (
    <div className="talker-main-cell">
      <div className="mono talker-main-cell__primary">{ip}</div>
      {showLabel && <div className="mono talker-main-cell__sub">{label}</div>}
    </div>
  );
}

function TalkerMainAsnCell({ asName, asn, fallback }) {
  const primary = talkerAsNameDisplay(asName, asn, fallback);
  const secondary = formatTalkerAsn({ asn });
  const fullTitle = secondary !== '—' && secondary !== primary
    ? `${primary} (${secondary})`
    : primary;
  return (
    <div className="talker-main-cell" title={fullTitle}>
      <div className="talker-main-cell__primary talker-main-cell__primary--wrap">{primary}</div>
      {secondary !== '—' && secondary !== primary && (
        <div className="mono talker-main-cell__sub">{secondary}</div>
      )}
    </div>
  );
}

function TalkerMainPairIpCell({ row }) {
  // Stacked pair: each side gets full width for the ASN name.
  const src = talkerAsNameDisplay(row.srcAsName, row.srcAsn);
  const dst = talkerAsNameDisplay(row.dstAsName, row.dstAsn);
  const srcAsn = formatTalkerAsn({ asn: row.srcAsn });
  const dstAsn = formatTalkerAsn({ asn: row.dstAsn });
  const fullTitle = `${src} (${srcAsn}) → ${dst} (${dstAsn})`;
  return (
    <div className="talker-main-cell talker-main-cell--pair-stack" title={fullTitle}>
      <div className="talker-pair-side">
        <div className="talker-main-cell__primary talker-main-cell__primary--wrap">{src}</div>
        <div className="mono talker-main-cell__sub">{srcAsn}</div>
      </div>
      <div className="talker-pair-arrow-row" aria-hidden="true">{TALKER_PAIR_ARROW.trim()}</div>
      <div className="talker-pair-side">
        <div className="talker-main-cell__primary talker-main-cell__primary--wrap">{dst}</div>
        <div className="mono talker-main-cell__sub">{dstAsn}</div>
      </div>
    </div>
  );
}

function TalkerMainPairAsnCell({ row }) {
  return (
    <div className="talker-main-cell">
      <div className="mono talker-main-cell__primary">
        {formatTalkerAsn({ asn: row.srcAsn })}{TALKER_PAIR_ARROW}{formatTalkerAsn({ asn: row.dstAsn })}
      </div>
    </div>
  );
}

function pairGeoPart(country) {
  const c = String(country || '').trim();
  if (c && c !== '??') return { label: countryFlagEmoji(c), title: c };
  return { label: '?', title: '??' };
}

function TalkerMainPairGeoCell({ row }) {
  const src = pairGeoPart(row.srcAsCountry || row.srcCountry);
  const dst = pairGeoPart(row.dstAsCountry || row.dstCountry);
  if (src.label === '?' && dst.label === '?') {
    return <span className="talker-main-cell__geo">Неизвестно</span>;
  }
  return (
    <span className="talker-main-cell__geo talker-main-cell__geo--pair" title={`${src.title} → ${dst.title}`}>
      {src.label}<span className="talker-pair-arrow" aria-hidden="true">{TALKER_PAIR_ARROW}</span>{dst.label}
    </span>
  );
}

function TalkerDetailItem({ label, value }) {
  return (
    <div className="talker-detail-item">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function TalkerDetailSection({ title, children }) {
  return (
    <section className="talker-detail-section">
      <h4 className="talker-detail-section__title">{title}</h4>
      <dl className="talker-detail-grid">{children}</dl>
    </section>
  );
}

function TalkerRowDetail({ row, isPair, periodLabel, directionFilterLabel, meta }) {
  const periodNote = meta?.granularity
    ? `${periodLabel} · ${meta.granularity}`
    : periodLabel;

  if (isPair) {
    return (
      <div className="talker-detail-pair">
        <TalkerDetailSection title="Источник">
          <TalkerDetailItem label="ASN" value={`${talkerAsNameDisplay(row.srcAsName, row.srcAsn)} / ${formatTalkerAsn({ asn: row.srcAsn })}`} />
          <TalkerDetailItem label="Страна ASN" value={row.srcAsCountry ? talkerGeoDisplay(row.srcAsCountry) : 'Неизвестно'} />
        </TalkerDetailSection>
        <TalkerDetailSection title="Назначение">
          <TalkerDetailItem label="ASN" value={`${talkerAsNameDisplay(row.dstAsName, row.dstAsn)} / ${formatTalkerAsn({ asn: row.dstAsn })}`} />
          <TalkerDetailItem label="Страна ASN" value={row.dstAsCountry ? talkerGeoDisplay(row.dstAsCountry) : 'Неизвестно'} />
        </TalkerDetailSection>
        <TalkerDetailSection title="Трафик">
          <TalkerDetailItem label="Объём" value={fmtVolumeSize(row.trafficGb, row.trafficTb)} />
          <TalkerDetailItem label="Байты" value={fmtNum(row.totalBytes)} />
          <TalkerDetailItem label="Средняя скорость" value={<TalkerBandwidthText gbps={row.avgGbps} />} />
          <TalkerDetailItem label="Средний PPS" value={fmtNum(row.avgPps)} />
          <TalkerDetailItem label="Flows" value={fmtNum(row.flowCount)} />
          <TalkerDetailItem label="Source IDs" value={talkerListJoin(row.sourceIds)} />
          <TalkerDetailItem label="Directions" value={talkerListJoin(row.directions)} />
          <TalkerDetailItem label="Фильтр направления" value={directionFilterLabel} />
          <TalkerDetailItem label="Период" value={periodNote} />
        </TalkerDetailSection>
      </div>
    );
  }

  return (
    <dl className="talker-detail-grid">
      <TalkerDetailItem label="ASN" value={talkerAsNameDisplay(row.asName, row.asn)} />
      <TalkerDetailItem label="Номер ASN" value={formatTalkerAsn(row)} />
      <TalkerDetailItem label="Страна ASN" value={talkerGeoDisplay(row.asCountry || row.countryCode)} />
      <TalkerDetailItem label="Объём" value={fmtVolumeSize(row.trafficGb, row.trafficTb)} />
      <TalkerDetailItem label="Байты" value={fmtNum(row.totalBytes)} />
      <TalkerDetailItem label="Средняя скорость" value={<TalkerBandwidthText gbps={row.avgGbps} />} />
      <TalkerDetailItem label="Средний PPS" value={fmtNum(row.avgPps)} />
      <TalkerDetailItem label="Flows" value={fmtNum(row.flowCount)} />
      <TalkerDetailItem label="Source IDs" value={talkerListJoin(row.sourceIds)} />
      <TalkerDetailItem label="Directions" value={talkerListJoin(row.directions)} />
      <TalkerDetailItem label="Фильтр направления" value={directionFilterLabel} />
      <TalkerDetailItem label="Сторона" value={row.endpointSide || row.group} />
      <TalkerDetailItem label="Период" value={periodNote} />
    </dl>
  );
}

function talkerMetricValue(row, metric) {
  if (metric === 'bps') return (Number(row.avgGbps) || 0) * 1e9;
  if (metric === 'volume') return Number(row.totalBytes) || 0;
  if (metric === 'pps') return Number(row.avgPps) || 0;
  if (metric === 'fps') return Number(row.flowCount) || 0;
  return 0;
}

function talkerMetricDisplay(row, metric) {
  if (metric === 'volume') return fmtVolumeSize(row.trafficGb, row.trafficTb);
  const v = talkerMetricValue(row, metric);
  return formatMetric(v, metric);
}

function talkerRowsVolumeTotalDisplay(rows) {
  const totalGb = rows.reduce((sum, row) => sum + (Number(row.trafficGb) || 0), 0);
  return fmtVolumeSize(totalGb, 0);
}

function talkerBarLabel(row, isPair) {
  if (isPair) {
    return `${formatTalkerAsn({ asn: row.srcAsn })} → ${formatTalkerAsn({ asn: row.dstAsn })}`;
  }
  return talkerAsNameDisplay(row.asName, row.asn);
}

function talkerSearchText(row, isPair) {
  if (isPair) {
    return [
      row.srcAsName, row.dstAsName, row.srcAsn, row.dstAsn,
      row.srcAsCountry, row.dstAsCountry, row.srcCountry, row.dstCountry,
    ].filter(Boolean).join(' ').toLowerCase();
  }
  return [
    row.asName, row.asn, row.asnLabel, row.countryCode, row.asCountry,
  ].filter(Boolean).join(' ').toLowerCase();
}

function talkerSourceLabel(source) {
  if (source === 'clickhouse') return 'ClickHouse';
  if (source === 'loading') return 'Загрузка…';
  if (source === 'error') return 'Ошибка';
  return '—';
}

function fmtTalkerLoadMs(loadMs, serverMs) {
  if (loadMs == null) return '—';
  if (serverMs != null) return `${loadMs} мс (SQL ${serverMs} мс)`;
  return `${loadMs} мс`;
}

function csvEscape(value) {
  const s = String(value ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadCsv(filename, lines) {
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportTopTalkersCsv({
  rows,
  isPair,
  metric,
  metricLabel,
  totalMetric,
}) {
  const sharePct = (row) => {
    const value = talkerMetricValue(row, metric);
    return totalMetric > 0 ? ((value / totalMetric) * 100).toFixed(1) : '0.0';
  };

  const headers = isPair
    ? [
      '#', 'Src ASN name', 'Dst ASN name', 'Src ASN', 'Dst ASN',
      'Src country', 'Dst country',
      metricLabel, 'Доля %', 'Объём', 'Traffic bytes', 'Avg Gbps', 'Avg PPS', 'Flows',
    ]
    : [
      '#', 'ASN name', 'ASN number', 'Country',
      metricLabel, 'Доля %', 'Объём', 'Traffic bytes', 'Avg Gbps', 'Avg PPS', 'Flows',
    ];

  const lines = [
    headers.map(csvEscape).join(','),
    ...rows.map((row, i) => {
      if (isPair) {
        return [
          i + 1,
          talkerAsNameDisplay(row.srcAsName, row.srcAsn),
          talkerAsNameDisplay(row.dstAsName, row.dstAsn),
          formatTalkerAsn({ asn: row.srcAsn }),
          formatTalkerAsn({ asn: row.dstAsn }),
          row.srcAsCountry || row.srcCountry || '',
          row.dstAsCountry || row.dstCountry || '',
          talkerMetricDisplay(row, metric),
          sharePct(row),
          fmtVolumeSize(row.trafficGb, row.trafficTb),
          row.totalBytes,
          row.avgGbps,
          row.avgPps,
          row.flowCount,
        ].map(csvEscape).join(',');
      }
      return [
        i + 1,
        talkerAsNameDisplay(row.asName, row.asn),
        formatTalkerAsn(row),
        row.asCountry || row.countryCode || '',
        talkerMetricDisplay(row, metric),
        sharePct(row),
        fmtVolumeSize(row.trafficGb, row.trafficTb),
        row.totalBytes,
        row.avgGbps,
        row.avgPps,
        row.flowCount,
      ].map(csvEscape).join(',');
    }),
  ];

  const stamp = new Date().toISOString().slice(0, 10);
  downloadCsv(`top-asn-${isPair ? 'pair' : 'endpoint'}-${stamp}.csv`, lines);
}

Object.assign(window, {
  TOP_TALKERS_TABS,
  talkerGeoDisplay,
  formatTalkerAsn,
  talkerAsNameDisplay,
  specialIpLabel,
  talkerRowKey,
  talkerListLabel,
  talkerListJoin,
  fmtTalkerBandwidth,
  TalkerBandwidthText,
  TalkerMainIpCell,
  TalkerMainAsnCell,
  TalkerMainPairIpCell,
  TalkerMainPairAsnCell,
  TalkerMainPairGeoCell,
  TalkerRowDetail,
  talkerMetricValue,
  talkerMetricDisplay,
  talkerRowsVolumeTotalDisplay,
  talkerBarLabel,
  talkerSearchText,
  talkerSourceLabel,
  fmtTalkerLoadMs,
  csvEscape,
  exportTopTalkersCsv,
});
