/* Журнал аудита — Администрирование (только Administrator). */

const PERIOD_PRESETS = [
  { id: '24h', label: '24 ч', hours: 24 },
  { id: '7d', label: '7 дн', hours: 24 * 7 },
  { id: '30d', label: '30 дн', hours: 24 * 30 },
];

const KIND_OPTIONS = [
  { id: 'all', label: 'Все типы' },
  { id: 'login', label: 'Вход' },
  { id: 'login_fail', label: 'Отказ входа' },
  { id: 'logout', label: 'Выход' },
  { id: 'page', label: 'Страница' },
  { id: 'write', label: 'Изменение' },
];

const RESULT_OPTIONS = [
  { id: 'all', label: 'Все результаты' },
  { id: 'ok', label: 'ok' },
  { id: 'fail', label: 'fail' },
  { id: 'denied', label: 'denied' },
];

const ACTION_LABELS = {
  login: 'Вход',
  login_fail: 'Отказ входа',
  logout: 'Выход',
  password_change: 'Смена пароля',
  user_create: 'Пользователь: создан',
  user_update: 'Пользователь: изменён',
  user_delete: 'Пользователь: удалён',
  role_change: 'Смена роли',
  permissions_change: 'Смена прав',
  impersonate_start: 'Вход в кабинет',
  impersonate_end: 'Выход из кабинета',
  page_view: 'Страница',
  api_write: 'Изменение',
};

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
  return new Date(ms).toLocaleString('ru-RU', {
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
  const mapped = ACTION_LABELS[row.action];
  if (mapped) return mapped;
  if (row.action === 'api_write' || row.method) {
    const resource = row.resource ? ` (${row.resource})` : '';
    return `Изменение${resource}`;
  }
  if (row.method && row.path) return `Изменение · ${row.method} ${row.path}`;
  return row.action || '—';
}

function auditObjectLabel(row) {
  if (row.objectLabel) return row.objectLabel;
  if (row.objectId) return row.objectId;
  return '—';
}

function auditResultLabel(result) {
  if (result === 'ok') return 'ок';
  if (result === 'fail') return 'ошибка';
  if (result === 'denied') return 'отказ';
  return result || '—';
}

function auditResultStyle(result) {
  if (result === 'fail' || result === 'denied') {
    return { color: 'var(--st-critical)', font: 'var(--pv-text-body-2-bold)' };
  }
  return { color: 'var(--fg-primary)' };
}

function auditExportFields(row, displayTimezone) {
  return {
    time: fmtAuditDateTime(row.eventAt, displayTimezone),
    actor: row.actorUsername || '',
    role: row.actorRole || '',
    ip: row.ip || '',
    action: auditActionLabel(row),
    object: auditObjectLabel(row),
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
    'Время', 'Кто', 'Роль', 'IP', 'Действие', 'Объект', 'Результат',
    'Метод', 'Путь', 'Детали', 'User-Agent',
  ];
  const lines = [
    headers.map(csvEscape).join(','),
    ...rows.map((row) => {
      const f = auditExportFields(row, displayTimezone);
      return [
        f.time, f.actor, f.role, f.ip, f.action, f.object, f.result,
        f.method, f.path, f.detail, f.userAgent,
      ].map(csvEscape).join(',');
    }),
  ];
  return `\uFEFF${lines.join('\n')}`;
}

function buildAuditTxt(rows, displayTimezone, { periodLabel, total }) {
  const header = [
    'Журнал аудита Grapes NTA',
    `Экспорт: ${new Date().toLocaleString('ru-RU')}`,
    `Период: ${periodLabel}`,
    `Записей: ${rows.length}${total > rows.length ? ` (в выборке ${total})` : ''}`,
    '',
  ];
  const blocks = rows.map((row, index) => {
    const f = auditExportFields(row, displayTimezone);
    return [
      `[${index + 1}] ${f.time}`,
      `  Кто: ${f.actor || '—'}${f.role ? ` (${f.role})` : ''}`,
      `  IP: ${f.ip || '—'}`,
      `  Действие: ${f.action}`,
      `  Объект: ${f.object}`,
      `  Результат: ${f.result}`,
      ...(f.method ? [`  Метод: ${f.method}`] : []),
      ...(f.path ? [`  Путь: ${f.path}`] : []),
      ...(f.detail ? [`  Детали: ${f.detail}`] : []),
      ...(f.userAgent ? [`  User-Agent: ${f.userAgent}`] : []),
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
  const [userQuery, setUserQuery] = useState('');
  const [ipQuery, setIpQuery] = useState('');
  const [kind, setKind] = useState('all');
  const [resultFilter, setResultFilter] = useState('all');
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [exporting, setExporting] = useState(false);

  const currentFilters = useCallback(() => {
    const range = periodRange(period);
    return {
      from: range.from,
      to: range.to,
      q: userQuery.trim() || undefined,
      ip: ipQuery.trim() || undefined,
      kind: kind === 'all' ? undefined : kind,
      result: resultFilter === 'all' ? undefined : resultFilter,
    };
  }, [period, userQuery, ipQuery, kind, resultFilter]);

  const periodLabel = useMemo(
    () => (PERIOD_PRESETS.find((p) => p.id === period) || PERIOD_PRESETS[1]).label,
    [period],
  );

  const loadAll = useCallback(async () => {
    if (!canAccess) {
      setLoading(false);
      setError('Журнал аудита доступен только администратору.');
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
        q: userQuery.trim() || undefined,
        ip: ipQuery.trim() || undefined,
        kind: kind === 'all' ? undefined : kind,
        result: resultFilter === 'all' ? undefined : resultFilter,
        limit: 100,
        offset: 0,
      });
      setRows(res.data || []);
      setTotal(res.meta?.total ?? (res.data || []).length);
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [canAccess, period, userQuery, ipQuery, kind, resultFilter, refreshKey]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const exportLogs = async (format) => {
    if (!canAccess || exporting) return;
    setExporting(true);
    try {
      const { rows: exportRows, total: exportTotal } = await fetchAllAuditRows(currentFilters());
      if (!exportRows.length) {
        pushToast?.({ kind: 'warning', title: 'Нечего экспортировать', desc: 'За выбранный период записей нет.' });
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
        title: format === 'csv' ? 'CSV экспортирован' : 'TXT экспортирован',
        desc: `${exportRows.length} записей.`,
      });
    } catch (err) {
      pushToast?.({ kind: 'error', title: 'Не удалось экспортировать', desc: err.message || ApiClient.LOAD_FAILED });
    } finally {
      setExporting(false);
    }
  };

  const cols = [
    {
      key: 'eventAt',
      title: 'Время',
      width: 150,
      sortAccessor: (r) => r.eventAt,
      render: (r) => fmtAuditDateTime(r.eventAt, displayTimezone),
    },
    {
      key: 'actorUsername',
      title: 'Кто',
      width: 140,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-2-bold)' }}>
          {r.actorUsername || '—'}
        </span>
      ),
    },
    {
      key: 'ip',
      title: 'IP',
      width: 130,
      render: (r) => <span className="mono">{r.ip || '—'}</span>,
    },
    {
      key: 'action',
      title: 'Действие',
      width: 180,
      render: (r) => auditActionLabel(r),
    },
    {
      key: 'object',
      title: 'Объект',
      width: 200,
      render: (r) => auditObjectLabel(r),
    },
    {
      key: 'result',
      title: 'Результат',
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
          <h1>Журнал аудита</h1>
          <p>Входы, переходы по разделам и изменения в системе. Доступно только администратору.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button
            kind="ghost"
            icon="export"
            onClick={() => exportLogs('csv')}
            disabled={loading || exporting || !canAccess}
          >
            CSV
          </Button>
          <Button
            kind="ghost"
            icon="export"
            onClick={() => exportLogs('txt')}
            disabled={loading || exporting || !canAccess}
          >
            TXT
          </Button>
          <Button kind="ghost" icon="refresh" onClick={() => setRefreshKey((k) => k + 1)} disabled={loading || exporting}>
            Обновить
          </Button>
        </div>
      </div>

      <Card pad="sm" style={{ marginBottom: 16 }}>
        <div className="row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <label className="col" style={{ gap: 4 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>Период</span>
            <select className="input" value={period} onChange={(e) => setPeriod(e.target.value)}>
              {PERIOD_PRESETS.map((p) => (
                <option key={p.id} value={p.id}>{p.label}</option>
              ))}
            </select>
          </label>
          <label className="col" style={{ gap: 4, minWidth: 160 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>Пользователь</span>
            <input
              className="input"
              placeholder="логин или ФИО"
              value={userQuery}
              onChange={(e) => setUserQuery(e.target.value)}
            />
          </label>
          <label className="col" style={{ gap: 4, minWidth: 140 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>IP</span>
            <input
              className="input"
              placeholder="185.x.x.x"
              value={ipQuery}
              onChange={(e) => setIpQuery(e.target.value)}
            />
          </label>
          <label className="col" style={{ gap: 4 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>Тип</span>
            <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
              {KIND_OPTIONS.map((o) => (
                <option key={o.id} value={o.id}>{o.label}</option>
              ))}
            </select>
          </label>
          <label className="col" style={{ gap: 4 }}>
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>Результат</span>
            <select className="input" value={resultFilter} onChange={(e) => setResultFilter(e.target.value)}>
              {RESULT_OPTIONS.map((o) => (
                <option key={o.id} value={o.id}>{o.label}</option>
              ))}
            </select>
          </label>
          <Button kind="primary" onClick={() => setRefreshKey((k) => k + 1)} disabled={loading || !canAccess}>
            Применить
          </Button>
        </div>
      </Card>

      {!canAccess ? (
        <Card>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            Журнал аудита доступен только администратору.
          </div>
        </Card>
      ) : error ? (
        <Card>
          <div style={{ color: 'var(--st-critical)' }}>{error}</div>
        </Card>
      ) : loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : (
        <>
          <DataTable
            rows={rows}
            columns={cols}
            rowKey="id"
            pageSize={25}
            onRowClick={(r) => setSelected(r)}
            emptyTitle="За период записей нет"
            emptyDesc="Измените фильтры или период."
          />
          {total > rows.length && (
            <div style={{ marginTop: 8, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              Показано {rows.length} из {total} записей
            </div>
          )}
        </>
      )}

      <SidePanel
        open={!!selected}
        onClose={() => setSelected(null)}
        title="Событие аудита"
        subtitle={selected ? fmtAuditDateTime(selected.eventAt, displayTimezone) : ''}
      >
        {selected && (
          <div className="col" style={{ gap: 12, font: 'var(--pv-text-body-3)' }}>
            <div><strong>Действие:</strong> {auditActionLabel(selected)}</div>
            <div><strong>Кто:</strong> {selected.actorUsername || '—'}{selected.actorRole ? ` (${selected.actorRole})` : ''}</div>
            <div><strong>IP:</strong> <span className="mono">{selected.ip || '—'}</span></div>
            <div><strong>Объект:</strong> {auditObjectLabel(selected)}</div>
            <div><strong>Результат:</strong> <span style={auditResultStyle(selected.result)}>{auditResultLabel(selected.result)}</span></div>
            {selected.path && (
              <div><strong>Путь:</strong> <span className="mono">{selected.path}</span></div>
            )}
            {selected.method && (
              <div><strong>Метод:</strong> <span className="mono">{selected.method}</span></div>
            )}
            {selected.detail && (
              <div><strong>Детали:</strong> {selected.detail}</div>
            )}
            {selected.userAgent && (
              <div><strong>User-Agent:</strong> <span style={{ wordBreak: 'break-word' }}>{selected.userAgent}</span></div>
            )}
          </div>
        )}
      </SidePanel>
    </div>
  );
}

Object.assign(window, { PageAudit });
