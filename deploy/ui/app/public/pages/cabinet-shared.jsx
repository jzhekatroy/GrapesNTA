/* Общие компоненты и утилиты личного кабинета клиента */

const CABINET_DNS_EMPTY_HINT = 'DNS-данные могут быть неполными: при перегрузке коллектора часть запросов не попадает в журнал. Нулевая активность не всегда означает, что запросов не было — признак потерь будет добавлен позже.';

const CABINET_DIRECTION_LABELS = {
  in: 'Входящий',
  out: 'Исходящий',
};

function cabinetGranularityBucketSeconds(granularity) {
  const map = { minute: 60, hour: 3600, day: 86400 };
  return map[String(granularity || '').toLowerCase()] || 3600;
}

function cabinetSeriesToChart(data, meta) {
  const granularity = meta?.granularity || 'hour';
  const bucketSeconds = cabinetGranularityBucketSeconds(granularity);
  const byBucket = new Map();

  for (const row of data || []) {
    const key = String(row.bucket || row.hour || '').trim();
    if (!key) continue;
    if (!byBucket.has(key)) {
      const fromApiMs = Number(row.bucketMs);
      const fromApiTs = Number(row.bucket_ts);
      const bucketMs = Number.isFinite(fromApiMs) && fromApiMs > 0
        ? fromApiMs
        : (Number.isFinite(fromApiTs) && fromApiTs > 0
          ? fromApiTs * 1000
          : (typeof parseChartBucketMs === 'function' ? parseChartBucketMs(key) : null));
      byBucket.set(key, { bucket: key, bucketMs });
    }
    const pt = byBucket.get(key);
    const dir = String(row.direction || '');
    if (dir !== 'in' && dir !== 'out') continue;
    const bytes = Number(row.bytes) || 0;
    const packets = Number(row.packets) || 0;
    pt[dir] = bucketSeconds > 0 ? (bytes * 8) / bucketSeconds : 0;
    pt[`${dir}_pps`] = bucketSeconds > 0 ? packets / bucketSeconds : 0;
  }

  const points = Array.from(byBucket.values()).sort((a, b) => {
    const am = typeof resolvePointEpochMs === 'function' ? (resolvePointEpochMs(a) ?? 0) : 0;
    const bm = typeof resolvePointEpochMs === 'function' ? (resolvePointEpochMs(b) ?? 0) : 0;
    return am - bm;
  });

  return {
    points,
    lines: [
      { key: 'in', label: 'К вам', color: '#51D16D' },
      { key: 'out', label: 'От вас', color: '#6972F0' },
    ],
    bucketSeconds,
  };
}

function groupImpersonationSessions(events) {
  const bySession = new Map();
  for (const ev of events || []) {
    const sessionAuditId = String(ev.sessionAuditId || ev.id || '');
    if (!sessionAuditId) continue;
    if (!bySession.has(sessionAuditId)) {
      bySession.set(sessionAuditId, {
        sessionAuditId,
        start: null,
        end: null,
        events: [],
      });
    }
    const session = bySession.get(sessionAuditId);
    session.events.push(ev);
    if (ev.event === 'start') session.start = ev;
    if (ev.event === 'end') session.end = ev;
  }

  return Array.from(bySession.values())
    .map((session) => {
      const startMs = session.start?.eventAt ? Date.parse(session.start.eventAt) : NaN;
      const endMs = session.end?.eventAt ? Date.parse(session.end.eventAt) : NaN;
      const durationMs = Number.isFinite(startMs) && Number.isFinite(endMs) ? Math.max(endMs - startMs, 0) : null;
      const orphaned = !!session.start?.orphaned
        || (session.start && !session.end && String(session.start.reason || '') === 'orphaned');
      return {
        ...session,
        durationMs,
        active: !!session.start && !session.end && !orphaned,
        orphaned,
      };
    })
    .sort((a, b) => {
      const am = a.start?.eventAt ? Date.parse(a.start.eventAt) : 0;
      const bm = b.start?.eventAt ? Date.parse(b.start.eventAt) : 0;
      return bm - am;
    });
}

function cabinetShareItems(rows, totalBytes) {
  const list = Array.isArray(rows) ? rows : [];
  const sumRows = list.reduce((acc, row) => acc + (Number(row.bytes) || 0), 0);
  const explicitTotal = Number(totalBytes);
  const hasExplicitTotal = Number.isFinite(explicitTotal) && explicitTotal > 0;
  if (!sumRows && !hasExplicitTotal) return [];

  const total = hasExplicitTotal ? explicitTotal : sumRows;
  if (!total) return [];

  const items = list.map((row) => ({
    ...row,
    sharePercent: ((Number(row.bytes) || 0) / total) * 100,
  }));
  const remainder = hasExplicitTotal ? Math.max(total - sumRows, 0) : 0;
  if (remainder > 0) {
    items.push({
      key: '__other__',
      synthetic: true,
      bytes: remainder,
      sharePercent: (remainder / total) * 100,
    });
  }
  return items;
}

function formatCabinetServiceLabel(row) {
  if (row?.serviceName) return row.serviceName;
  const port = Number(row?.servicePort) || 0;
  const transport = row?.transport || 'tcp';
  if (!port) return row?.serviceCode || '—';
  if (row?.portOwner === 'local') return `${transport}/${port}, ваш порт`;
  if (row?.portOwner === 'remote') return `${transport}/${port}, порт удалённой стороны`;
  return `${transport}/${port}`;
}

function formatCabinetDomainLabel(row) {
  const domain = String(row?.domain || '');
  if (row?.folded || domain === 'other') return 'Прочие домены (свёрнутый хвост)';
  if (domain === 'unknown') return 'Неразобранные имена';
  return domain || '—';
}

function cabinetExplorerGroupByForDirection(breakdown, direction) {
  const dir = String(direction || 'in').trim().toLowerCase();
  if (breakdown === 'country') {
    return dir === 'out' ? ['dst_country'] : ['src_country'];
  }
  if (breakdown === 'service') {
    return dir === 'out' ? ['dst_service'] : ['src_service'];
  }
  return Array.isArray(breakdown) ? breakdown : [];
}

function openCabinetExplorer(onNavigate, {
  groupBy,
  timeRange,
  customPeriod,
  direction,
} = {}) {
  const params = new URLSearchParams();
  params.set('metric', 'volume');
  params.set('vis', 'table');
  const resolvedGroupBy = Array.isArray(groupBy) && groupBy.length
    ? groupBy
    : [];
  if (resolvedGroupBy.length) params.set('groupBy', resolvedGroupBy.join(','));
  params.set('range', timeRange || '24h');
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    params.set('from', customPeriod.from);
    params.set('to', customPeriod.to);
  }
  const dir = String(direction || '').trim().toLowerCase();
  if (dir === 'in' || dir === 'out' || dir === 'internal') {
    params.set('filters', JSON.stringify([
      { id: 1, field: 'client_direction', op: '=', value: dir, logic: 'and' },
    ]));
  }
  if (typeof onNavigate === 'function') onNavigate('explorer');
  location.hash = `explorer?${params.toString()}`;
}

function CabinetLoadState({ children, style }) {
  return (
    <div className="other-ports-table__state" style={style}>
      {children || (typeof ApiClient !== 'undefined' ? ApiClient.LOAD_FAILED : 'Не удалось загрузить')}
    </div>
  );
}

function CabinetEmptyState({ children, style, titleHint }) {
  const defaultDesc = 'За выбранный период данных пока нет. Для нового клиента агрегаты начинают заполняться с момента подключения.';
  return (
    <Empty
      icon="info"
      title="Нет данных"
      titleHint={titleHint}
      desc={children ?? (titleHint ? null : defaultDesc)}
    />
  );
}

function CabinetErrorState({ error, style }) {
  return (
    <div className="other-ports-table__state" style={{ color: 'var(--st-critical)', ...style }}>
      {error || (typeof ApiClient !== 'undefined' ? ApiClient.LOAD_FAILED : 'Не удалось загрузить')}
    </div>
  );
}

Object.assign(window, {
  CABINET_DNS_EMPTY_HINT,
  CABINET_DIRECTION_LABELS,
  CabinetLoadState,
  CabinetEmptyState,
  CabinetErrorState,
  cabinetSeriesToChart,
  cabinetGranularityBucketSeconds,
  groupImpersonationSessions,
  cabinetShareItems,
  formatCabinetServiceLabel,
  formatCabinetDomainLabel,
  cabinetExplorerGroupByForDirection,
  openCabinetExplorer,
});
