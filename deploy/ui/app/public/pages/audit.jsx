/* Журнал аудита — Администрирование (только Administrator). */

const PERIOD_PRESETS = [
  { id: '24h', hours: 24 },
  { id: '7d', hours: 24 * 7 },
  { id: '30d', hours: 24 * 30 },
];

const KIND_OPTIONS = ['all', 'login', 'login_fail', 'logout', 'page', 'query', 'chart', 'write'];

const AUDIT_PAGE_SIZE = 25;

const RESULT_OPTIONS = ['all', 'ok', 'timeout', 'oom', 'fail', 'denied'];

function auditT(key, params) {
  return GrapesI18n.t(key, params);
}

function auditClientError(key) {
  return `i18n:${key}`;
}

function auditErrorText(error) {
  if (typeof error === 'string' && error.startsWith('i18n:')) return auditT(error.slice(5));
  return error || '';
}

function auditRoleLabel(roleId) {
  const id = String(roleId || '').trim();
  if (!id) return '';
  return GrapesI18n.localizedRoleDisplay(id, id);
}

function auditPageTitle(page) {
  return GrapesI18n.localizedPageMeta(page.id, page).title || page.title || page.id;
}

function parseAuditEventMs(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  const text = String(value).trim();
  if (!text) return null;

  // Сервер пишет event_at как UTC (toISOString без суффикса Z).
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(text) && !/(?:[zZ]|[+-]\d{2}:?\d{2})$/.test(text)) {
    const isoLike = text.replace(' ', 'T');
    const ms = Date.parse(isoLike.endsWith('Z') ? isoLike : `${isoLike}Z`);
    return Number.isNaN(ms) ? null : ms;
  }

  const ms = Date.parse(text);
  return Number.isNaN(ms) ? null : ms;
}

function fmtAuditDateTime(value, displayTimezone) {
  const ms = parseAuditEventMs(value);
  if (ms == null) return value ? String(value) : '—';
  if (typeof formatTipPointTime === 'function') {
    return formatTipPointTime({ bucketMs: ms }, displayTimezone);
  }
  return new Date(ms).toLocaleString(GrapesI18n.intlLocale(), {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    ...(displayTimezone ? { timeZone: displayTimezone } : {}),
  });
}

function periodRange(presetId) {
  const preset = PERIOD_PRESETS.find((p) => p.id === presetId) || PERIOD_PRESETS[1];
  const to = new Date();
  const from = new Date(to.getTime() - preset.hours * 60 * 60 * 1000);
  return { from: from.toISOString(), to: to.toISOString() };
}

function auditActionLabel(row) {
  const actionKey = row.action ? `auditPage.action.${row.action}` : '';
  if (actionKey && GrapesI18n.has(actionKey)) return auditT(actionKey);
  if (row.action === 'api_write' || row.method) {
    if (row.resource) return auditT('auditPage.action.writeResource', { resource: row.resource });
    return auditT('auditPage.action.api_write');
  }
  if (row.method && row.path) {
    return auditT('auditPage.action.writeMethod', { method: row.method, path: row.path });
  }
  return row.action || '—';
}

const AUDIT_PAGE_TITLE_TO_ID = {
  'Мониторинг': 'monitoring',
  'Обзор': 'dashboard',
  'Настройки': 'cabinet-settings',
  'Наблюдения': 'observations',
  'DNS': 'dns',
  'Разбор трафика': 'explorer',
  'Разбор DNS': 'dns-explorer',
  'Топ ASN': 'top',
  'Коллекторы': 'collectors',
  'Исключения из статистики': 'flow-exclusions',
  'SNMP': 'snmp',
  'BMP / BGP': 'bmp',
  'Классификация трафика': 'traffic-classification',
  'Моя сеть': 'cidr',
  'Владельцы L3': 'entities',
  'VLAN': 'vlan',
  'DNS-резолверы': 'dns-resolvers',
  'Порты оборудования': 'interface-roles',
  'Сервисы и порты приложений': 'port-services',
  'Роутеры и экспортёры': 'routers',
  'Внешние базы данных': 'databases',
  'Другие справочники': 'other',
  'Пользователи и права': 'users',
  'Журнал аудита': 'audit',
  'Клиенты': 'clients',
  'Почта (SMTP)': 'smtp',
  'Диагностика': 'diagnostics',
  'Хранение данных': 'ttl',
};

const AUDIT_OBJECT_LABEL_KEYS = {
  'DNS-резолвер': 'auditPage.object.dnsResolver',
  'Порт оборудования': 'auditPage.object.interfacePort',
  'Пересчёт портов': 'auditPage.object.portsRebuild',
  'Коммутатор (порты оборудования)': 'auditPage.object.switchPorts',
  'График': 'auditPage.kind.chart',
  'Разбор трафика': 'nav.item.explorer',
  'net-entities': 'auditPage.object.page.entities',
  'vlans': 'auditPage.object.page.vlan',
  'port-services': 'nav.item.port-services',
  'locations': 'auditPage.object.locations',
  'collectors': 'nav.item.collectors',
  'flow-sources': 'auditPage.object.flowSources',
  'snmp-settings': 'auditPage.object.snmpSettings',
  'snmp-agents': 'auditPage.object.snmpAgents',
  'direction-settings': 'nav.item.traffic-classification',
  'interface-role-rules': 'auditPage.object.interfaceRoleRules',
  'l3-prefixes': 'nav.item.cidr',
  'flow-exclusions': 'collectorsPage.exclusion.title',
  'dns-resolvers': 'nav.item.dns-resolvers',
};

function auditPageObjectTitle(pageId) {
  if (!pageId) return '';
  const navKey = `nav.item.${pageId}`;
  if (GrapesI18n.has(navKey)) return auditT(navKey);
  const pageKey = `auditPage.object.page.${pageId}`;
  if (GrapesI18n.has(pageKey)) return auditT(pageKey);
  return '';
}

function auditStoredObjectLabel(stored) {
  const labelKey = AUDIT_OBJECT_LABEL_KEYS[stored];
  if (labelKey && GrapesI18n.has(labelKey)) return auditT(labelKey);
  return '';
}

function auditObjectLabel(row) {
  if (row.action === 'page_view') {
    const byId = auditPageObjectTitle(row.objectId || row.resource);
    if (byId) return byId;
    const byTitle = auditPageObjectTitle(AUDIT_PAGE_TITLE_TO_ID[String(row.objectLabel || '').trim()]);
    if (byTitle) return byTitle;
  }
  if (row.action === 'explorer_query') {
    const byId = auditPageObjectTitle(row.resource || 'explorer');
    if (byId) return byId;
  }
  const stored = String(row.objectLabel || '').trim();
  if (stored) {
    const known = auditStoredObjectLabel(stored);
    if (known) return known;
    return stored;
  }
  if (row.objectId) return row.objectId;
  return '—';
}

function parseAuditDetail(detail) {
  if (detail == null || detail === '') return null;
  const text = String(detail).trim();
  if (!text) return null;
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      return JSON.parse(text);
    } catch {
      return { legacyText: text };
    }
  }
  return { legacyText: text };
}

function auditRequestForRow(row) {
  const parsed = parseAuditDetail(row.detail);
  if (parsed?.request) return parsed.request;
  if (row.method && row.path) {
    return { method: row.method, path: row.path };
  }
  return null;
}

function auditBodyFallbackSummary(body) {
  if (!body || typeof body !== 'object') return '';
  const parts = [];
  if (body.resolverId || body.resolver_id) {
    parts.push(auditT('auditPage.body.resolver', { id: body.resolverId || body.resolver_id }));
  }
  if (body.enabled !== undefined) {
    const state = body.enabled === 1 || body.enabled === true
      ? auditT('auditPage.enabled.on')
      : auditT('auditPage.enabled.off');
    parts.push(auditT('auditPage.body.state', { state }));
  }
  if (body.switchIp || body.switch_ip) {
    const ip = body.switchIp || body.switch_ip;
    const idx = body.ifIndex ?? body.if_index;
    const endpoint = idx != null ? `${ip}:${idx}` : String(ip);
    parts.push(auditT('auditPage.body.port', { endpoint }));
  }
  if (body.boundary) parts.push(auditT('auditPage.body.side', { boundary: body.boundary }));
  if (Array.isArray(body.interfaces) && body.interfaces.length) {
    parts.push(auditT('auditPage.body.ports', { count: body.interfaces.length }));
  }
  return parts.join('; ');
}

function auditExplorerDetail(parsed) {
  return parsed?.explorer && typeof parsed.explorer === 'object' ? parsed.explorer : null;
}

function auditChangesSummary(row, { maxItems = 3 } = {}) {
  const parsed = parseAuditDetail(row.detail);
  const explorer = auditExplorerDetail(parsed);
  if (explorer || row.action === 'explorer_query') {
    const parts = [];
    if (explorer?.elapsedMs != null) parts.push(auditT('auditPage.unit.ms', { ms: explorer.elapsedMs }));
    const firstLine = String(explorer?.filtersText || '').split('\n').find((line) => line.trim());
    if (firstLine) parts.push(firstLine.trim());
    return parts.join(' · ');
  }
  if (parsed?.changes?.length) {
    const parts = parsed.changes.slice(0, maxItems).map(
      (c) => `${c.label}: ${c.from} → ${c.to}`,
    );
    if (parsed.changes.length > maxItems) {
      parts.push(auditT('auditPage.changes.more', { count: parsed.changes.length - maxItems }));
    }
    return parts.join('; ');
  }
  const request = auditRequestForRow(row);
  const bodySummary = auditBodyFallbackSummary(request?.body);
  if (bodySummary) return bodySummary;
  if (parsed?.legacyText) return parsed.legacyText;
  return '';
}

function formatAuditRequestBlock(request) {
  if (!request) return '';
  const lines = [`${request.method || 'GET'} ${request.path || ''}`.trim()];
  if (request.body && Object.keys(request.body).length) {
    lines.push(JSON.stringify(request.body, null, 2));
  }
  return lines.join('\n\n');
}

function AuditChangesList({ changes }) {
  if (!changes?.length) return null;
  return (
    <div className="col" style={{ gap: 6 }}>
      <strong>{auditT('auditPage.detail.changes')}</strong>
      <ul style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 4 }}>
        {changes.map((c) => (
          <li key={`${c.field}-${c.label}-${c.from}-${c.to}`}>
            <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{c.label}</span>
            {': '}
            <span className="mono">{c.from}</span>
            {' → '}
            <span className="mono">{c.to}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function auditDetailPreStyle() {
  return {
    margin: 0,
    padding: 10,
    borderRadius: 8,
    background: 'var(--bg-surface-3)',
    border: '1px solid var(--bd-default)',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    font: 'var(--pv-text-body-3)',
    maxHeight: 280,
    overflow: 'auto',
  };
}

function AuditExplorerDetailBlock({ detail }) {
  if (!detail) return null;
  const queries = Array.isArray(detail.queries) ? detail.queries : [];
  const sqlBlocks = queries.map((q, index) => {
    const header = [
      q.name || auditT('auditPage.detail.queryName', { n: index + 1 }),
      q.elapsedMs != null ? auditT('auditPage.unit.ms', { ms: q.elapsedMs }) : null,
      q.error ? auditT('auditPage.detail.queryError') : null,
    ].filter(Boolean).join(' · ');
    const body = q.sql || q.error || '—';
    return `${header}\n${body}`;
  }).join('\n\n—\n\n');

  return (
    <div className="col" style={{ gap: 10 }}>
      {detail.elapsedMs != null && (
        <div><strong>{auditT('auditPage.detail.elapsed')}</strong> {auditT('auditPage.unit.ms', { ms: detail.elapsedMs })}</div>
      )}
      {detail.filtersText && (
        <div className="col" style={{ gap: 6 }}>
          <strong>{auditT('auditPage.detail.filters')}</strong>
          <pre className="mono" style={auditDetailPreStyle()}>{detail.filtersText}</pre>
        </div>
      )}
      {sqlBlocks && (
        <div className="col" style={{ gap: 6 }}>
          <strong>{auditT('auditPage.detail.sql')}</strong>
          <pre className="mono" style={auditDetailPreStyle()}>{sqlBlocks}</pre>
        </div>
      )}
      {detail.error && (
        <div className="col" style={{ gap: 6 }}>
          <strong>{auditT('auditPage.detail.error')}</strong>
          <pre
            className="mono"
            style={{ ...auditDetailPreStyle(), color: 'var(--st-critical)' }}
          >
            {detail.error}
          </pre>
        </div>
      )}
    </div>
  );
}

function AuditRequestBlock({ request }) {
  if (!request) return null;
  const text = formatAuditRequestBlock(request);
  return (
    <div className="col" style={{ gap: 6 }}>
      <strong>{auditT('auditPage.detail.http')}</strong>
      <pre className="mono" style={auditDetailPreStyle()}>
        {text}
      </pre>
    </div>
  );
}

function auditResultLabel(result) {
  const key = result ? `auditPage.result.${result}` : '';
  if (key && GrapesI18n.has(key)) return auditT(key);
  return result || '—';
}

function auditResultStyle(result) {
  if (result === 'fail' || result === 'denied' || result === 'timeout' || result === 'oom') {
    return { color: 'var(--st-critical)', font: 'var(--pv-text-body-2-bold)' };
  }
  return { color: 'var(--fg-primary)' };
}

function normalizeClientIp(ip) {
  const s = String(ip || '').trim();
  if (!s) return '';
  if (s.toLowerCase().startsWith('::ffff:')) return s.slice(7);
  return s;
}

function auditFilterIp(raw) {
  const s = String(raw || '').trim();
  return s || undefined;
}

function auditExportFields(row, displayTimezone) {
  return {
    time: fmtAuditDateTime(row.eventAt, displayTimezone),
    actor: row.actorUsername || '',
    role: auditRoleLabel(row.actorRole),
    ip: normalizeClientIp(row.ip),
    action: auditActionLabel(row),
    object: auditObjectLabel(row),
    changes: auditChangesSummary(row, { maxItems: 20 }),
    result: auditResultLabel(row.result),
    method: row.method || '',
    path: row.path || '',
    detail: row.detail || '',
    userAgent: row.userAgent || '',
  };
}

function csvEscape(value) {
  const s = String(value ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadBlob(filename, parts, mimeType) {
  const blob = new Blob(parts, { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function buildAuditCsv(rows, displayTimezone) {
  const headers = [
    'time', 'actor', 'role', 'ip', 'action', 'object', 'changes', 'result',
    'method', 'path', 'request', 'userAgent',
  ].map((id) => auditT(`auditPage.col.${id}`));
  const lines = [
    headers.map(csvEscape).join(','),
    ...rows.map((row) => {
      const f = auditExportFields(row, displayTimezone);
      const reqText = formatAuditRequestBlock(auditRequestForRow(row));
      return [
        f.time, f.actor, f.role, f.ip, f.action, f.object, f.changes, f.result,
        f.method, f.path, reqText, f.userAgent,
      ].map(csvEscape).join(',');
    }),
  ];
  return `\uFEFF${lines.join('\n')}`;
}

function buildAuditTxt(rows, displayTimezone, { periodLabel, total }) {
  const header = [
    auditT('auditPage.export.docTitle'),
    auditT('auditPage.export.exportedAt', { time: new Date().toLocaleString(GrapesI18n.intlLocale()) }),
    auditT('auditPage.export.period', { period: periodLabel }),
    total > rows.length
      ? auditT('auditPage.export.recordsOf', { count: rows.length, total })
      : auditT('auditPage.export.records', { count: rows.length }),
    '',
  ];
  const blocks = rows.map((row, index) => {
    const f = auditExportFields(row, displayTimezone);
    const actor = f.actor || '—';
    const requestText = formatAuditRequestBlock(auditRequestForRow(row));
    return [
      `[${index + 1}] ${f.time}`,
      `  ${f.role
        ? auditT('auditPage.export.whoRole', { actor, role: f.role })
        : auditT('auditPage.export.who', { actor })}`,
      `  ${auditT('auditPage.export.ip', { ip: f.ip || '—' })}`,
      `  ${auditT('auditPage.export.action', { action: f.action })}`,
      `  ${auditT('auditPage.export.object', { object: f.object })}`,
      ...(f.changes ? [`  ${auditT('auditPage.export.changes', { changes: f.changes })}`] : []),
      `  ${auditT('auditPage.export.result', { result: f.result })}`,
      ...(requestText
        ? [`  ${auditT('auditPage.export.request')}\n${requestText.split('\n').map((line) => `    ${line}`).join('\n')}`]
        : []),
      ...(f.userAgent ? [`  ${auditT('auditPage.export.userAgent', { userAgent: f.userAgent })}`] : []),
    ].join('\n');
  });
  return [...header, ...blocks].join('\n');
}

async function fetchAllAuditRows(filters) {
  const limit = 500;
  let offset = 0;
  let total = Infinity;
  const all = [];
  while (offset < total) {
    const res = await ApiClient.loadAudit({ ...filters, limit, offset });
    const batch = res.data || [];
    total = Number(res.meta?.total);
    if (!Number.isFinite(total)) total = batch.length;
    all.push(...batch);
    if (!batch.length || batch.length < limit || all.length >= total) break;
    offset += batch.length;
  }
  return { rows: all, total };
}

function PageAudit({ currentUser, displayTimezone }) {
  const canAccess = !!currentUser?.effectivePermissions?.audit;
  const [period, setPeriod] = useState('7d');
  const [userId, setUserId] = useState('');
  const [pageId, setPageId] = useState('');
  const [ipQuery, setIpQuery] = useState('');
  const [kind, setKind] = useState('all');
  const [resultFilter, setResultFilter] = useState('all');
  const [users, setUsers] = useState([]);
  const [appPages, setAppPages] = useState([]);
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [exporting, setExporting] = useState(false);

  const locale = GrapesI18n.getLocale();
  const sortLocale = locale === 'en' ? 'en' : 'ru';

  const pageOptions = useMemo(() => {
    return [...appPages].sort((a, b) => {
      const aMeta = GrapesI18n.localizedPageMeta(a.id, a);
      const bMeta = GrapesI18n.localizedPageMeta(b.id, b);
      const sec = String(aMeta.section || '').localeCompare(String(bMeta.section || ''), sortLocale);
      if (sec !== 0) return sec;
      return String(aMeta.title || '').localeCompare(String(bMeta.title || ''), sortLocale);
    });
  }, [appPages, sortLocale]);

  const userOptions = useMemo(() => {
    return [...users].sort((a, b) => String(a.fullName || '').localeCompare(String(b.fullName || ''), sortLocale));
  }, [users, sortLocale]);

  useEffect(() => {
    if (!canAccess) return undefined;
    let cancelled = false;
    Promise.all([ApiClient.loadUsers(), AppPages.load()])
      .then(([userList, pages]) => {
        if (cancelled) return;
        setUsers(userList || []);
        setAppPages(pages || []);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [canAccess]);

  const currentFilters = useCallback(() => {
    const range = periodRange(period);
    return {
      from: range.from,
      to: range.to,
      userId: userId || undefined,
      pageId: pageId || undefined,
      ip: auditFilterIp(ipQuery),
      kind: kind === 'all' ? undefined : kind,
      result: resultFilter === 'all' ? undefined : resultFilter,
    };
  }, [period, userId, pageId, ipQuery, kind, resultFilter]);

  const periodPreset = PERIOD_PRESETS.find((p) => p.id === period) || PERIOD_PRESETS[1];
  const periodLabel = auditT(`auditPage.period.${periodPreset.id}`);

  const loadAll = useCallback(async () => {
    if (!canAccess) {
      setLoading(false);
      setError(auditClientError('auditPage.adminOnly'));
      setRows([]);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const range = periodRange(period);
      const res = await ApiClient.loadAudit({
        from: range.from,
        to: range.to,
        userId: userId || undefined,
        pageId: pageId || undefined,
        ip: auditFilterIp(ipQuery),
        kind: kind === 'all' ? undefined : kind,
        result: resultFilter === 'all' ? undefined : resultFilter,
        limit: AUDIT_PAGE_SIZE,
        offset: (page - 1) * AUDIT_PAGE_SIZE,
      });
      setRows(res.data || []);
      setTotal(res.meta?.total ?? (res.data || []).length);
    } catch (err) {
      setError(err.message || auditClientError('auditPage.loadFailed'));
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [canAccess, period, userId, pageId, ipQuery, kind, resultFilter, page, refreshKey]);

  const applyFilters = () => {
    setPage(1);
    setRefreshKey((k) => k + 1);
  };

  useEffect(() => { loadAll(); }, [loadAll]);

  const exportLogs = async (format) => {
    if (!canAccess || exporting) return;
    setExporting(true);
    try {
      const { rows: exportRows, total: exportTotal } = await fetchAllAuditRows(currentFilters());
      if (!exportRows.length) {
        pushToast?.({
          kind: 'warning',
          title: auditT('auditPage.export.nothingTitle'),
          desc: auditT('auditPage.export.nothingDesc'),
        });
        return;
      }
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      if (format === 'csv') {
        downloadBlob(
          `audit-log-${stamp}.csv`,
          [buildAuditCsv(exportRows, displayTimezone)],
          'text/csv;charset=utf-8',
        );
      } else {
        downloadBlob(
          `audit-log-${stamp}.txt`,
          [buildAuditTxt(exportRows, displayTimezone, { periodLabel, total: exportTotal })],
          'text/plain;charset=utf-8',
        );
      }
      pushToast?.({
        kind: 'success',
        title: auditT(format === 'csv' ? 'auditPage.export.csvDone' : 'auditPage.export.txtDone'),
        desc: auditT('auditPage.export.count', { count: exportRows.length }),
      });
    } catch (err) {
      pushToast?.({
        kind: 'error',
        title: auditT('auditPage.export.failed'),
        desc: err.message || auditT('auditPage.loadFailed'),
      });
    } finally {
      setExporting(false);
    }
  };

  const cols = [
    {
      key: 'eventAt',
      title: auditT('auditPage.col.time'),
      width: 150,
      sortAccessor: (r) => r.eventAt,
      render: (r) => fmtAuditDateTime(r.eventAt, displayTimezone),
    },
    {
      key: 'actorUsername',
      title: auditT('auditPage.col.actor'),
      width: 140,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-2-bold)' }}>
          {r.actorUsername || '—'}
        </span>
      ),
    },
    {
      key: 'ip',
      title: auditT('auditPage.col.ip'),
      width: 130,
      render: (r) => <span className="mono">{normalizeClientIp(r.ip) || '—'}</span>,
    },
    {
      key: 'action',
      title: auditT('auditPage.col.action'),
      width: 180,
      render: (r) => auditActionLabel(r),
    },
    {
      key: 'object',
      title: auditT('auditPage.col.object'),
      width: 180,
      render: (r) => auditObjectLabel(r),
    },
    {
      key: 'changes',
      title: auditT('auditPage.col.changes'),
      width: 280,
      render: (r) => {
        const summary = auditChangesSummary(r);
        if (!summary) return '—';
        return (
          <span className="overflow-text" title={summary} style={{ font: 'var(--pv-text-body-3)' }}>
            {summary}
          </span>
        );
      },
    },
    {
      key: 'result',
      title: auditT('auditPage.col.result'),
      width: 90,
      render: (r) => (
        <span style={auditResultStyle(r.result)}>{auditResultLabel(r.result)}</span>
      ),
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{auditT('auditPage.title')}</h1>
          <p>{auditT('auditPage.subtitle')}</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button
            kind="ghost"
            icon="export"
            onClick={() => exportLogs('csv')}
            disabled={loading || exporting || !canAccess}
          >
            {auditT('auditPage.export.csv')}
          </Button>
          <Button
            kind="ghost"
            icon="export"
            onClick={() => exportLogs('txt')}
            disabled={loading || exporting || !canAccess}
          >
            {auditT('auditPage.export.txt')}
          </Button>
          <Button kind="ghost" icon="refresh" onClick={() => setRefreshKey((k) => k + 1)} disabled={loading || exporting}>
            {auditT('chrome.refresh')}
          </Button>
        </div>
      </div>

      <Card pad="sm" style={{ marginBottom: 16 }}>
        <div className="row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <label className="col" style={{ gap: 4 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{auditT('auditPage.filter.period')}</span>
            <select className="input" value={period} onChange={(e) => { setPeriod(e.target.value); setPage(1); }}>
              {PERIOD_PRESETS.map((p) => (
                <option key={p.id} value={p.id}>{auditT(`auditPage.period.${p.id}`)}</option>
              ))}
            </select>
          </label>
          <label className="col" style={{ gap: 4, minWidth: 200 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{auditT('auditPage.filter.user')}</span>
            <select className="input" value={userId} onChange={(e) => { setUserId(e.target.value); setPage(1); }}>
              <option value="">{auditT('auditPage.filter.allUsers')}</option>
              {userOptions.map((u) => (
                <option key={u.id} value={u.id}>{u.fullName} ({u.username})</option>
              ))}
            </select>
          </label>
          <label className="col" style={{ gap: 4, minWidth: 200 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{auditT('auditPage.filter.page')}</span>
            <select className="input" value={pageId} onChange={(e) => { setPageId(e.target.value); setPage(1); }}>
              <option value="">{auditT('auditPage.filter.allPages')}</option>
              {pageOptions.map((p) => (
                <option key={p.id} value={p.id}>{auditPageTitle(p)}</option>
              ))}
            </select>
          </label>
          <label className="col" style={{ gap: 4, minWidth: 140 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{auditT('auditPage.filter.ip')}</span>
            <input
              className="input"
              placeholder={auditT('auditPage.filter.ipPlaceholder')}
              value={ipQuery}
              onChange={(e) => { setIpQuery(e.target.value); setPage(1); }}
            />
          </label>
          <label className="col" style={{ gap: 4 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{auditT('auditPage.filter.kind')}</span>
            <select className="input" value={kind} onChange={(e) => { setKind(e.target.value); setPage(1); }}>
              {KIND_OPTIONS.map((id) => (
                <option key={id} value={id}>{auditT(`auditPage.kind.${id}`)}</option>
              ))}
            </select>
          </label>
          <label className="col" style={{ gap: 4 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{auditT('auditPage.filter.result')}</span>
            <select className="input" value={resultFilter} onChange={(e) => { setResultFilter(e.target.value); setPage(1); }}>
              {RESULT_OPTIONS.map((id) => (
                <option key={id} value={id}>{auditT(`auditPage.result.${id}`)}</option>
              ))}
            </select>
          </label>
          <Button kind="primary" onClick={applyFilters} disabled={loading || !canAccess}>
            {auditT('auditPage.apply')}
          </Button>
        </div>
      </Card>

      {!canAccess ? (
        <Card>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {auditT('auditPage.adminOnly')}
          </div>
        </Card>
      ) : error ? (
        <Card>
          <div style={{ color: 'var(--st-critical)' }}>{auditErrorText(error)}</div>
        </Card>
      ) : loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>{auditT('auditPage.loading')}</div>
        </Card>
      ) : (
        <>
          <DataTable
            rows={rows}
            columns={cols}
            rowKey="id"
            pageSize={AUDIT_PAGE_SIZE}
            page={page}
            totalRows={total}
            onPageChange={setPage}
            onRowClick={(r) => setSelected(r)}
            emptyTitle={auditT('auditPage.emptyTitle')}
            emptyDesc={auditT('auditPage.emptyDesc')}
          />
        </>
      )}

      <SidePanel
        open={!!selected}
        onClose={() => setSelected(null)}
        title={auditT('auditPage.detail.title')}
        subtitle={selected ? fmtAuditDateTime(selected.eventAt, displayTimezone) : ''}
      >
        {selected && (() => {
          const parsed = parseAuditDetail(selected.detail);
          const explorerDetail = auditExplorerDetail(parsed);
          const request = selected.action === 'explorer_query' || explorerDetail
            ? null
            : auditRequestForRow(selected);
          return (
            <div className="col" style={{ gap: 12, font: 'var(--pv-text-body-3)' }}>
              <div><strong>{auditT('auditPage.detail.action')}</strong> {auditActionLabel(selected)}</div>
              <div><strong>{auditT('auditPage.detail.actor')}</strong> {selected.actorUsername || '—'}{selected.actorRole ? ` (${auditRoleLabel(selected.actorRole)})` : ''}</div>
              <div><strong>{auditT('auditPage.detail.ip')}</strong> <span className="mono">{normalizeClientIp(selected.ip) || '—'}</span></div>
              <div><strong>{auditT('auditPage.detail.object')}</strong> {auditObjectLabel(selected)}</div>
              <div><strong>{auditT('auditPage.detail.result')}</strong> <span style={auditResultStyle(selected.result)}>{auditResultLabel(selected.result)}</span></div>
              <AuditChangesList changes={parsed?.changes} />
              {parsed?.legacyText && !parsed?.changes?.length && !explorerDetail && (
                <div><strong>{auditT('auditPage.detail.legacy')}</strong> {parsed.legacyText}</div>
              )}
              <AuditExplorerDetailBlock detail={explorerDetail} />
              <AuditRequestBlock request={request} />
              {selected.userAgent && (
                <div><strong>{auditT('auditPage.detail.userAgent')}</strong> <span style={{ wordBreak: 'break-word' }}>{selected.userAgent}</span></div>
              )}
            </div>
          );
        })()}
      </SidePanel>
    </div>
  );
}

Object.assign(window, { PageAudit });
