/* Клиенты — администрирование личных кабинетов */

const CLIENT_BIND_MODES = [
  { value: 'prefixes', label: 'По сетям (CIDR)' },
  { value: 'ports', label: 'По портам интерфейсов' },
];

const BIND_MODE_LABELS = Object.fromEntries(CLIENT_BIND_MODES.map((m) => [m.value, m.label]));
const MAX_CLIENT_USERS = 5;
const SAVE_SUCCESS_TITLE = 'Настройки сохранены';
const SAVE_SUCCESS_DESC = 'Изменения будут автоматически применены в течение 60 секунд.';

const IMPERSONATION_REASON_LABELS = {
  impersonate: 'Вход в кабинет',
  stop: 'Ручной выход',
  timeout: 'Истёк сеанс (30 мин)',
  logout: 'Выход из системы',
  orphaned: 'Сеанс прерван перезапуском',
};

const CYRILLIC_TO_LATIN = {
  а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z',
  и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r',
  с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'ts', ч: 'ch', ш: 'sh',
  щ: 'sch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya',
};

function transliterateChar(ch) {
  const lower = ch.toLowerCase();
  if (CYRILLIC_TO_LATIN[lower] !== undefined) return CYRILLIC_TO_LATIN[lower];
  return lower;
}

function buildClientSlug(displayName) {
  const raw = String(displayName ?? '').trim();
  if (!raw) return '';

  let out = '';
  for (const ch of raw) {
    if (/\s/.test(ch)) {
      out += '-';
      continue;
    }
    const mapped = transliterateChar(ch);
    if (/[a-z0-9]/.test(mapped)) out += mapped;
    else if (mapped === '-') out += '-';
  }

  return out
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function previewClientId(displayName) {
  const slug = buildClientSlug(displayName);
  if (!slug) return '';
  return `client:${slug}`;
}

function fmtDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function fmtDuration(ms) {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return '—';
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h} ч ${m} мин`;
  if (m > 0) return `${m} мин ${s} с`;
  return `${s} с`;
}

function randomChar(chars) {
  const bytes = new Uint32Array(1);
  crypto.getRandomValues(bytes);
  return chars[bytes[0] % chars.length];
}

function generatePassword() {
  const groups = [
    'abcdefghijklmnopqrstuvwxyz',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '0123456789',
    '!@#$%^&*()-_=+[]{}',
  ];
  const chars = groups.join('');
  const seed = groups.map(randomChar);
  while (seed.length < 14) seed.push(randomChar(chars));
  return seed
    .map((ch) => ({ ch, sort: Math.random() }))
    .sort((a, b) => a.sort - b.sort)
    .map((x) => x.ch)
    .join('');
}

function bindCountLabel(row) {
  if (row.bindMode === 'ports') return row.portCount ?? 0;
  return row.prefixCount ?? 0;
}

function bindCountTitle(row) {
  return row.bindMode === 'ports' ? 'Портов' : 'Сетей';
}

function parseIpv4SearchTerm(raw) {
  const q = String(raw ?? '').trim();
  const m = q.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  if (m.slice(1).some((octet) => Number(octet) > 255)) return null;
  return q;
}

function ipv4ToInt(ip) {
  const parsed = parseIpv4SearchTerm(ip);
  if (!parsed) return null;
  return parsed.split('.').reduce((acc, octet) => ((acc << 8) + Number(octet)) >>> 0, 0);
}

function ipv4InCidr(ip, cidr) {
  const raw = String(cidr ?? '').trim();
  const slash = raw.indexOf('/');
  const net = slash >= 0 ? raw.slice(0, slash) : raw;
  const bitsRaw = slash >= 0 ? Number(raw.slice(slash + 1)) : 32;
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(net);
  if (ipInt == null || netInt == null) return false;
  if (!Number.isInteger(bitsRaw) || bitsRaw < 0 || bitsRaw > 32) return false;
  const mask = bitsRaw === 0 ? 0 : (0xFFFFFFFF << (32 - bitsRaw)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function asBindingList(value) {
  if (Array.isArray(value)) return value.map((item) => String(item || '').trim()).filter(Boolean);
  if (!value) return [];
  return String(value).split(/\s*,\s*/).map((item) => item.trim()).filter(Boolean);
}

function clientRowMatchesSearch(row, raw) {
  const tokens = String(raw || '').trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) return true;
  const prefixes = asBindingList(row.bindingPrefixes);
  const hay = [
    row.displayName,
    row.clientId,
    row.comment,
    BIND_MODE_LABELS[row.bindMode],
    row.bindMode,
    ...(asBindingList(row.bindingPreview)),
    row.bindingSearch || '',
    ...prefixes,
  ].join('\n').toLowerCase();
  return tokens.every((token) => {
    if (hay.includes(token.toLowerCase())) return true;
    const ip = parseIpv4SearchTerm(token);
    return !!(ip && prefixes.some((prefix) => ipv4InCidr(ip, prefix)));
  });
}

function formatBindingPreview(row) {
  const items = asBindingList(row.bindingPreview);
  const total = bindCountLabel(row);
  const extra = Math.max(0, total - items.length);
  return { items, extra };
}

function groupImpersonationSessions(events) {
  const bySession = new Map();
  for (const ev of events || []) {
    const sid = ev.sessionAuditId || ev.id;
    if (!bySession.has(sid)) {
      bySession.set(sid, { sessionAuditId: sid, starts: [], ends: [] });
    }
    const group = bySession.get(sid);
    if (ev.event === 'start') group.starts.push(ev);
    else if (ev.event === 'end') group.ends.push(ev);
  }

  return [...bySession.values()].map((group) => {
    const start = group.starts.sort((a, b) => new Date(a.eventAt) - new Date(b.eventAt))[0] || null;
    const end = group.ends.sort((a, b) => new Date(b.eventAt) - new Date(a.eventAt))[0] || null;
    const orphaned = !!(start?.orphaned || start?.reason === 'orphaned');
    let status = 'completed';
    if (orphaned && !end) status = 'orphaned';
    else if (!end) status = 'active';

    const startMs = start ? new Date(start.eventAt).getTime() : null;
    const endMs = end ? new Date(end.eventAt).getTime() : null;
    const durationMs = startMs != null && endMs != null ? endMs - startMs : null;

    return {
      sessionAuditId: group.sessionAuditId,
      start,
      end,
      status,
      orphaned,
      durationMs,
      actorUsername: start?.actorUsername || end?.actorUsername || '—',
      actorUserId: start?.actorUserId || end?.actorUserId || '',
      clientId: start?.clientId || end?.clientId || '',
      clientDisplayName: start?.clientDisplayName || end?.clientDisplayName || '',
      endReason: end?.reason || '',
    };
  }).sort((a, b) => {
    const ta = new Date(a.start?.eventAt || a.end?.eventAt || 0).getTime();
    const tb = new Date(b.start?.eventAt || b.end?.eventAt || 0).getTime();
    return tb - ta;
  });
}

function sessionStatusBadge(session) {
  if (session.status === 'active') {
    return <Badge tone="success" dot>Активен</Badge>;
  }
  if (session.status === 'orphaned') {
    return <Badge tone="warning" dot>Незакрытый</Badge>;
  }
  return <Badge tone="neutral">Завершён</Badge>;
}

function PageClients({ onAuthRefresh, onNavigate }) {
  const canWrite = AuthAccess.canWritePage('clients');
  const [pageTab, setPageTab] = useState('clients');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [showCreate, setShowCreate] = useState(false);
  const [drawerClient, setDrawerClient] = useState(null);
  const [togglingId, setTogglingId] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    if (!canWrite) {
      setLoading(false);
      setLoadError('Недостаточно прав для просмотра клиентов');
      setRows([]);
      return undefined;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      try {
        const res = await ApiClient.loadClients();
        if (cancelled) return;
        const data = (res.data || []).map((r) => {
          const clientId = r.clientId || r.client_id || '';
          return { ...r, clientId, id: clientId };
        });
        setRows(data);
      } catch (err) {
        if (cancelled) return;
        setLoadError(err.message || ApiClient.LOAD_FAILED);
        setRows([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [refreshKey, canWrite]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    return rows.filter((r) => clientRowMatchesSearch(r, search));
  }, [rows, search]);

  const patchRow = useCallback((clientId, patch) => {
    const resolvedId = clientId || patch?.clientId || patch?.client_id || '';
    setRows((prev) => prev.map((r) => (
      r.clientId === resolvedId
        ? { ...r, ...patch, clientId: patch.clientId || patch.client_id || r.clientId || resolvedId, id: resolvedId }
        : r
    )));
    setDrawerClient((prev) => (
      prev && prev.clientId === resolvedId
        ? { ...prev, ...patch, clientId: patch.clientId || patch.client_id || prev.clientId || resolvedId, id: resolvedId }
        : prev
    ));
  }, []);

  const handleToggleEnabled = async (row) => {
    if (!canWrite) return;
    const next = !row.enabled;
    const label = next ? 'включить' : 'выключить';
    if (!window.confirm(`${label.charAt(0).toUpperCase() + label.slice(1)} клиента «${row.displayName}»?`)) return;
    setTogglingId(row.clientId);
    try {
      const res = await ApiClient.updateClient(row.clientId, {
        displayName: row.displayName,
        comment: row.comment,
        bindMode: row.bindMode,
        enabled: next,
      });
      const updated = res.data || { ...row, enabled: next };
      patchRow(row.clientId, updated);
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось изменить состояние', desc: err.message });
    } finally {
      setTogglingId(null);
    }
  };

  const handleImpersonate = async (row) => {
    if (!canWrite || !row.enabled) return;
    try {
      await ApiClient.impersonateClient(row.clientId);
      pushToast({ kind: 'success', title: 'Вход в кабинет', desc: `Открыт кабинет «${row.displayName}» (только просмотр).` });
      if (onAuthRefresh) await onAuthRefresh();
      if (onNavigate) onNavigate('dashboard');
      else location.hash = 'dashboard';
    } catch (err) {
      const title = err.status === 409
        ? 'Вход уже выполнен'
        : err.status === 404
          ? 'Клиент недоступен'
          : err.status === 403
            ? 'Вход запрещён'
            : 'Не удалось войти в кабинет';
      pushToast({ kind: 'error', title, desc: err.message });
    }
  };

  const handleClientSaved = (client) => {
    const clientId = client?.clientId || client?.client_id || '';
    if (!clientId) {
      reload();
      return;
    }
    const normalized = { ...client, clientId, id: clientId };
    setRows((prev) => {
      const idx = prev.findIndex((r) => r.clientId === clientId);
      if (idx < 0) return [...prev, normalized].sort((a, b) => String(a.displayName).localeCompare(String(b.displayName), 'ru'));
      const copy = [...prev];
      copy[idx] = { ...copy[idx], ...normalized };
      return copy;
    });
    setDrawerClient((prev) => (
      prev && prev.clientId === clientId ? { ...prev, ...normalized } : prev
    ));
  };

  const cols = [
    {
      key: 'displayName',
      title: 'Название',
      width: 220,
      sortAccessor: (r) => r.displayName,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-2-bold)', opacity: r.enabled ? 1 : 0.55 }}>
          {r.displayName || '—'}
        </span>
      ),
    },
    {
      key: 'clientId',
      title: 'Идентификатор',
      width: 200,
      sortAccessor: (r) => r.clientId,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)', opacity: r.enabled ? 1 : 0.55 }}>
          {r.clientId}
        </span>
      ),
    },
    {
      key: 'bindMode',
      title: 'Способ привязки',
      width: 180,
      sortAccessor: (r) => BIND_MODE_LABELS[r.bindMode] || r.bindMode,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', opacity: r.enabled ? 1 : 0.55 }}>
          {BIND_MODE_LABELS[r.bindMode] || r.bindMode || '—'}
        </span>
      ),
    },
    {
      key: 'bindings',
      title: 'Привязки',
      width: 280,
      sortAccessor: (r) => (asBindingList(r.bindingPreview)[0] || bindCountLabel(r)),
      render: (r) => {
        const { items, extra } = formatBindingPreview(r);
        if (!items.length && !bindCountLabel(r)) {
          return <span style={{ color: 'var(--fg-secondary)', opacity: r.enabled ? 1 : 0.55 }}>—</span>;
        }
        return (
          <div style={{ opacity: r.enabled ? 1 : 0.55 }} title={bindCountTitle(r)}>
            {items.map((item) => (
              <div key={item} className="mono" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
                {item}
              </div>
            ))}
            {extra > 0 && (
              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-tertiary, var(--fg-secondary))' }}>
                +{extra}
              </div>
            )}
          </div>
        );
      },
    },
    {
      key: 'bindCount',
      title: 'Сетей / портов',
      width: 120,
      num: true,
      align: 'right',
      sortAccessor: (r) => bindCountLabel(r),
      render: (r) => (
        <span className="mono" style={{ opacity: r.enabled ? 1 : 0.55 }} title={bindCountTitle(r)}>
          {bindCountLabel(r)}
        </span>
      ),
    },
    {
      key: 'userCount',
      title: 'Учёток',
      width: 90,
      num: true,
      align: 'right',
      sortAccessor: (r) => r.userCount,
      render: (r) => (
        <span className="mono" style={{ opacity: r.enabled ? 1 : 0.55 }}>{r.userCount ?? 0}</span>
      ),
    },
    {
      key: 'enabled',
      title: 'Состояние',
      width: 110,
      sortAccessor: (r) => (r.enabled ? 1 : 0),
      render: (r) => (
        r.enabled
          ? <Badge tone="success" dot>Включён</Badge>
          : <Badge tone="neutral">Выключен</Badge>
      ),
    },
    {
      key: 'updatedAt',
      title: 'Изменён',
      width: 150,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', opacity: r.enabled ? 1 : 0.55 }}>
          {fmtDateTime(r.updatedAt)}
        </span>
      ),
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Клиенты</h1>
          <p>Справочник клиентских кабинетов: привязка по сетям или портам. В поиске — название, IP/CIDR, свитч и ifName, несколько слов через пробел.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading || !canWrite}>Обновить</Button>
          {pageTab === 'clients' && (
            <Button kind="primary" icon="plus" onClick={() => setShowCreate(true)} disabled={!!loadError || !canWrite}>
              Добавить клиента
            </Button>
          )}
        </div>
      </div>

      <div className="row" style={{ gap: 8, marginBottom: 16 }}>
        <Button kind={pageTab === 'clients' ? 'primary' : 'ghost'} onClick={() => setPageTab('clients')}>Клиенты</Button>
        <Button kind={pageTab === 'audit' ? 'primary' : 'ghost'} onClick={() => setPageTab('audit')}>Журнал входов</Button>
      </div>

      {pageTab === 'audit' ? (
        <ImpersonationAuditPanel canWrite={canWrite} />
      ) : loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : loadError ? (
        <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={canWrite ? <Button kind="primary" icon="refresh" onClick={reload}>Повторить</Button> : null} />
      ) : (
        <DataTable
          rows={filtered}
          columns={cols}
          rowKey="id"
          selectable
          selected={selected}
          onSelectChange={setSelected}
          pageSize={15}
          onRowClick={canWrite ? (r) => setDrawerClient({ ...r }) : undefined}
          getRowClassName={(r) => (r.enabled ? '' : 'is-disabled')}
          emptyTitle="Клиенты не найдены"
          emptyDesc="Создайте клиента или уточните поиск."
          toolbar={{
            search,
            onSearch: setSearch,
            searchPlaceholder: 'Название, IP, CIDR, свитч, PortChannel32…',
            searchMaxWidth: 420,
          }}
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              {r.enabled && (
                <button className="icon-btn tt" data-tt="Войти в кабинет" onClick={(e) => { e.stopPropagation(); handleImpersonate(r); }}>
                  <Icon name="eye" size={15} />
                </button>
              )}
              <button className="icon-btn tt" data-tt="Карточка клиента" onClick={(e) => { e.stopPropagation(); setDrawerClient({ ...r }); }}>
                <Icon name="edit" size={15} />
              </button>
              <button
                className="icon-btn tt"
                data-tt={r.enabled ? 'Выключить' : 'Включить'}
                disabled={togglingId === r.clientId}
                onClick={(e) => { e.stopPropagation(); handleToggleEnabled(r); }}
              >
                <Icon name={r.enabled ? 'pause' : 'play'} size={15} />
              </button>
            </div>
          ) : null}
        />
      )}

      <ClientCreateModal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(client) => {
          setShowCreate(false);
          handleClientSaved(client);
          pushToast({ kind: 'success', title: 'Клиент создан', desc: SAVE_SUCCESS_DESC });
        }}
      />

      <ClientDrawer
        client={drawerClient}
        canWrite={canWrite}
        onClose={() => setDrawerClient(null)}
        onSaved={handleClientSaved}
        onImpersonate={handleImpersonate}
        onUsersChanged={reload}
      />
    </div>
  );
}

function ClientCreateModal({ open, onClose, onCreated }) {
  const [displayName, setDisplayName] = useState('');
  const [bindMode, setBindMode] = useState(CLIENT_BIND_MODES[0].value);
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const clientIdPreview = previewClientId(displayName);

  useEffect(() => {
    if (!open) return;
    setDisplayName('');
    setBindMode(CLIENT_BIND_MODES[0].value);
    setComment('');
    setFormError('');
  }, [open]);

  const handleSave = async () => {
    const name = displayName.trim();
    if (!name) {
      setFormError('Укажите название клиента');
      return;
    }
    if (!clientIdPreview) {
      setFormError('Не удалось сформировать идентификатор из названия');
      return;
    }
    setSaving(true);
    setFormError('');
    try {
      const res = await ApiClient.createClient({
        clientId: clientIdPreview,
        displayName: name,
        bindMode,
        comment: comment.trim(),
      });
      const payload = res?.data && typeof res.data === 'object' ? res.data : {};
      onCreated({
        ...payload,
        clientId: payload.clientId || payload.client_id || clientIdPreview,
        displayName: payload.displayName || payload.display_name || name,
        bindMode: payload.bindMode || payload.bind_mode || bindMode,
        comment: payload.comment ?? comment.trim(),
        enabled: payload.enabled !== undefined ? payload.enabled : true,
      });
    } catch (err) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Добавить клиента"
      subtitle="Новая запись справочника клиентов"
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
          <Button kind="primary" icon="plus" onClick={handleSave} disabled={saving}>
            {saving ? 'Создание…' : 'Создать'}
          </Button>
        </>
      }
    >
      {formError && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
          {formError}
        </div>
      )}
      <div className="grid grid--1col">
        <div className="field">
          <label>Название</label>
          <input
            className="input"
            placeholder="ООО Ромашка, Филиал №3…"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </div>
        {clientIdPreview && (
          <div className="field">
            <label>Будет создан ID</label>
            <input className="input mono" value={clientIdPreview} readOnly disabled />
          </div>
        )}
        <div className="field">
          <label>Способ привязки</label>
          <select className="input" value={bindMode} onChange={(e) => setBindMode(e.target.value)}>
            {CLIENT_BIND_MODES.map((m) => (
              <option key={m.value} value={m.value}>{m.label}</option>
            ))}
          </select>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 6 }}>
            Выбирается один раз: либо сети, либо порты. Сменить способ можно только когда список другого типа пуст.
          </div>
        </div>
        <div className="field">
          <label>Комментарий</label>
          <input
            className="input"
            placeholder="Необязательно"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </div>
      </div>
    </Modal>
  );
}

function ClientDrawer({ client, canWrite, onClose, onSaved, onImpersonate, onUsersChanged }) {
  const [tab, setTab] = useState('general');
  const [displayName, setDisplayName] = useState('');
  const [comment, setComment] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!client) return;
    setTab('general');
    setDisplayName(client.displayName || '');
    setComment(client.comment || '');
    setEnabled(!!client.enabled);
    setError('');
  }, [client?.clientId]);

  const saveGeneral = async () => {
    if (!client || !canWrite) return;
    const name = displayName.trim();
    if (!name) {
      setError('Укажите название клиента');
      return;
    }
    setSaving(true);
    setError('');
    try {
      const res = await ApiClient.updateClient(client.clientId, {
        displayName: name,
        comment: comment.trim(),
        bindMode: client.bindMode,
        enabled,
      });
      onSaved(res.data || { ...client, displayName: name, comment, enabled });
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const tabs = [
    { id: 'general', label: 'Общие', icon: 'info' },
    { id: 'bindings', label: 'Привязка', icon: 'link' },
    { id: 'users', label: 'Учётные записи', icon: 'users' },
    { id: 'audit', label: 'Журнал входов', icon: 'clock' },
  ];

  return (
    <SidePanel
      open={!!client}
      onClose={onClose}
      title={client?.displayName || 'Клиент'}
      subtitle={client ? `${client.clientId} · ${BIND_MODE_LABELS[client.bindMode] || client.bindMode}` : ''}
      footer={
        tab === 'general' ? (
          <>
            <Button kind="ghost" onClick={onClose}>Закрыть</Button>
            {canWrite && (
              <Button kind="primary" icon="save" onClick={saveGeneral} disabled={saving}>
                {saving ? 'Сохранение…' : 'Сохранить'}
              </Button>
            )}
          </>
        ) : (
          <Button kind="ghost" onClick={onClose}>Закрыть</Button>
        )
      }
    >
      {client && (
        <div className="col" style={{ gap: 16 }}>
          <div className="row" style={{ gap: 4, borderBottom: '1px solid var(--bd-soft)', marginBottom: 4, flexWrap: 'wrap' }}>
            {tabs.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                style={{
                  all: 'unset',
                  cursor: 'pointer',
                  padding: '10px 12px',
                  font: 'var(--pv-text-body-2-bold)',
                  color: tab === t.id ? 'var(--fg-primary)' : 'var(--fg-secondary)',
                  borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
                  marginBottom: -1,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <Icon name={t.icon} size={14} />
                {t.label}
              </button>
            ))}
          </div>

          {tab === 'general' && (
            <ClientGeneralTab
              client={client}
              canWrite={canWrite}
              displayName={displayName}
              comment={comment}
              enabled={enabled}
              onDisplayNameChange={setDisplayName}
              onCommentChange={setComment}
              onEnabledChange={setEnabled}
              onImpersonate={() => onImpersonate(client)}
              error={error}
            />
          )}

          {tab === 'bindings' && (
            <ClientBindingsTab client={client} canWrite={canWrite} onSaved={onSaved} />
          )}

          {tab === 'users' && (
            <ClientUsersTab client={client} canWrite={canWrite} onChanged={onUsersChanged} />
          )}

          {tab === 'audit' && (
            <ImpersonationAuditPanel canWrite={canWrite} clientId={client.clientId} compact />
          )}
        </div>
      )}
    </SidePanel>
  );
}

function ClientGeneralTab({
  client,
  canWrite,
  displayName,
  comment,
  enabled,
  onDisplayNameChange,
  onCommentChange,
  onEnabledChange,
  onImpersonate,
  error,
}) {
  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="field">
        <label>Идентификатор</label>
        <input className="input mono" value={client.clientId} readOnly disabled />
      </div>
      <div className="field">
        <label>Название</label>
        <input
          className="input"
          value={displayName}
          onChange={(e) => onDisplayNameChange(e.target.value)}
          disabled={!canWrite}
        />
      </div>
      <div className="field">
        <label>Комментарий</label>
        <input
          className="input"
          value={comment}
          onChange={(e) => onCommentChange(e.target.value)}
          disabled={!canWrite}
        />
      </div>
      <div className="field">
        <label>Способ привязки</label>
        <input className="input" value={BIND_MODE_LABELS[client.bindMode] || client.bindMode} readOnly disabled />
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 6 }}>
          Задаётся при создании. Для смены способа сначала удалите все записи другого типа.
        </div>
      </div>
      <SwitchField
        label="Клиент включён"
        hint="Выключенный клиент не может войти в кабинет и скрывается из списков входа."
        checked={enabled}
        onChange={onEnabledChange}
        disabled={!canWrite}
      />
      {canWrite && enabled && (
        <div>
          <Button kind="primary" icon="eye" onClick={onImpersonate}>Войти в кабинет</Button>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 8 }}>
            Просмотр кабинета глазами клиента без пароля. Сеанс только для чтения, до 30 минут.
          </div>
        </div>
      )}
      {error && <div className="form-error">{error}</div>}
    </div>
  );
}

const BINDING_ADDED_TITLE = 'Привязка сохранена';
const BINDING_REMOVED_TITLE = 'Привязка снята';

function bindingOptionKey(opt, isPrefixes) {
  return isPrefixes
    ? `${opt.family}:${opt.prefix}`
    : `${opt.switchIp}:${opt.ifIndex}`;
}

function bindingItemKey(item, isPrefixes) {
  return isPrefixes
    ? `${item.family}:${item.prefix}`
    : `${item.switchIp}:${item.ifIndex}`;
}

function resolveBindingOptionStatus(opt, items, client, isPrefixes) {
  const key = bindingOptionKey(opt, isPrefixes);
  const assignedHere = items.some((it) => bindingItemKey(it, isPrefixes) === key);
  if (assignedHere) {
    return {
      conflict: false,
      assignedHere: true,
      selectable: false,
      label: 'У этого клиента',
    };
  }
  if (opt.ownerClientId && opt.ownerClientId !== client.clientId && !opt.available) {
    return {
      conflict: true,
      assignedHere: false,
      selectable: false,
      label: `Занято: ${opt.ownerDisplayName || opt.ownerClientId}`,
    };
  }
  return {
    conflict: false,
    assignedHere: false,
    selectable: true,
    label: 'Свободно',
  };
}

function patchBindingOptions(options, { key, client, isPrefixes, action }) {
  return (options || []).map((opt) => {
    if (bindingOptionKey(opt, isPrefixes) !== key) return opt;
    if (action === 'assign') {
      return {
        ...opt,
        ownerClientId: client.clientId,
        ownerDisplayName: client.displayName || client.clientId,
        available: false,
      };
    }
    return {
      ...opt,
      ownerClientId: '',
      ownerDisplayName: '',
      available: true,
    };
  });
}

function ClientBindingsTab({ client, canWrite, onSaved }) {
  const isPrefixes = client.bindMode === 'prefixes';
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [selectorQ, setSelectorQ] = useState('');
  const [options, setOptions] = useState([]);
  const [optionsLoading, setOptionsLoading] = useState(false);
  const [optionsRefreshKey, setOptionsRefreshKey] = useState(0);

  const loadBindings = useCallback(async () => {
    if (!canWrite || !client?.clientId) return;
    setLoading(true);
    setError('');
    try {
      const res = isPrefixes
        ? await ApiClient.loadClientPrefixes(client.clientId)
        : await ApiClient.loadClientPorts(client.clientId);
      setItems(res.data || []);
    } catch (err) {
      setError(err.message);
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [canWrite, client?.clientId, isPrefixes]);

  useEffect(() => { loadBindings(); }, [loadBindings]);

  const refreshOptions = useCallback(async (q) => {
    if (!canWrite) return;
    setOptionsLoading(true);
    try {
      const res = isPrefixes
        ? await ApiClient.loadClientPrefixOptions({ q, limit: 30 })
        : await ApiClient.loadClientPortOptions({ q, limit: 30 });
      setOptions(res.data || []);
    } catch (err) {
      setOptions([]);
    } finally {
      setOptionsLoading(false);
    }
  }, [canWrite, isPrefixes]);

  useEffect(() => {
    if (!canWrite) return undefined;
    let cancelled = false;
    const timer = setTimeout(() => {
      if (cancelled) return;
      refreshOptions(selectorQ);
    }, 250);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [selectorQ, canWrite, refreshOptions, optionsRefreshKey]);

  const itemKey = (item) => bindingItemKey(item, isPrefixes);

  const buildPayload = useCallback((nextItems) => (
    isPrefixes
      ? { items: nextItems.map((it) => ({ prefix: it.prefix })) }
      : {
        items: nextItems.map((it) => ({
          switchIp: it.switchIp,
          ifIndex: it.ifIndex,
          comment: it.comment || '',
        })),
      }
  ), [isPrefixes]);

  const persistBindings = useCallback(async (nextItems, { successToast } = {}) => {
    setSaving(true);
    setError('');
    try {
      const payload = buildPayload(nextItems);
      const res = isPrefixes
        ? await ApiClient.saveClientPrefixes(client.clientId, payload)
        : await ApiClient.saveClientPorts(client.clientId, payload);
      const saved = res.data || [];
      setItems(saved);
      onSaved({
        ...client,
        prefixCount: isPrefixes ? saved.length : client.prefixCount,
        portCount: !isPrefixes ? saved.length : client.portCount,
      });
      setOptionsRefreshKey((k) => k + 1);
      if (successToast) {
        pushToast({
          kind: 'success',
          title: successToast.title,
          desc: successToast.desc || SAVE_SUCCESS_DESC,
        });
      }
      return saved;
    } catch (err) {
      setError(err.message);
      pushToast({ kind: 'error', title: 'Не удалось сохранить привязку', desc: err.message });
      throw err;
    } finally {
      setSaving(false);
    }
  }, [buildPayload, client, isPrefixes, onSaved]);

  const addItem = async (option) => {
    if (!canWrite || saving) return;
    const key = bindingOptionKey(option, isPrefixes);
    if (items.some((it) => itemKey(it) === key)) return;
    if (!option.available && option.ownerClientId && option.ownerClientId !== client.clientId) {
      pushToast({
        kind: 'error',
        title: 'Конфликт закрепления',
        desc: isPrefixes
          ? `Сеть ${option.prefix} закреплена за клиентом ${option.ownerDisplayName || option.ownerClientId}`
          : `Порт закреплён за клиентом ${option.ownerDisplayName || option.ownerClientId}`,
      });
      return;
    }

    const nextItem = isPrefixes
      ? { prefix: option.prefix, family: option.family, enabled: true }
      : {
        switchIp: option.switchIp,
        ifIndex: option.ifIndex,
        comment: option.ifName || option.ifAlias || '',
        enabled: true,
      };
    const nextItems = [...items, nextItem];
    setItems(nextItems);
    setOptions((prev) => patchBindingOptions(prev, {
      key,
      client,
      isPrefixes,
      action: 'assign',
    }));

    setSelectorQ('');
    try {
      await persistBindings(nextItems, {
        successToast: {
          title: BINDING_ADDED_TITLE,
          desc: isPrefixes
            ? `Сеть ${option.prefix} закреплена за «${client.displayName}».`
            : `Порт ${option.switchIp} · ifIndex ${option.ifIndex} закреплён за «${client.displayName}».`,
        },
      });
    } catch {
      await loadBindings();
      setOptionsRefreshKey((k) => k + 1);
    }
  };

  const removeItem = async (key) => {
    if (!canWrite || saving) return;
    const removed = items.find((it) => itemKey(it) === key);
    if (!removed) return;
    const nextItems = items.filter((it) => itemKey(it) !== key);
    setItems(nextItems);
    setOptions((prev) => patchBindingOptions(prev, {
      key,
      client,
      isPrefixes,
      action: 'release',
    }));
    try {
      await persistBindings(nextItems, {
        successToast: {
          title: BINDING_REMOVED_TITLE,
          desc: isPrefixes
            ? `Сеть ${removed.prefix} отвязана от «${client.displayName}».`
            : `Порт ${removed.switchIp} · ifIndex ${removed.ifIndex} отвязан от «${client.displayName}».`,
        },
      });
    } catch {
      await loadBindings();
      setOptionsRefreshKey((k) => k + 1);
    }
  };

  const filteredOptions = useMemo(() => options || [], [options]);

  return (
    <div className="col" style={{ gap: 14 }}>
      {!isPrefixes && (
        <Card pad="sm" style={{ background: 'var(--st-warning-bg)', border: '1px solid var(--st-warning)' }}>
          <div style={{ font: 'var(--pv-text-body-2-bold)', color: 'var(--st-warning)', marginBottom: 4 }}>Ограничение DNS</div>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            Клиент, заданный только портами, не увидит своих DNS-запросов: в DNS-логе нет ни портов, ни VLAN, привязка возможна только по адресам.
          </div>
        </Card>
      )}

      {loading ? (
        <div style={{ color: 'var(--fg-secondary)' }}>Загрузка…</div>
      ) : (
        <>
          <div>
            <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 8 }}>
              {isPrefixes ? 'Сети клиента' : 'Порты клиента'}
            </div>
            {items.length === 0 ? (
              <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
                {isPrefixes ? 'Сети не назначены.' : 'Порты не назначены.'}
              </div>
            ) : (
              <div className="col" style={{ gap: 8 }}>
                {items.map((it) => {
                  const key = itemKey(it);
                  return (
                    <div key={key} className="row" style={{ justifyContent: 'space-between', gap: 12, alignItems: 'center' }}>
                      <div>
                        {isPrefixes ? (
                          <>
                            <div className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{it.prefix}</div>
                            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>IPv{it.family}</div>
                          </>
                        ) : (
                          <>
                            <div className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{it.switchIp} · ifIndex {it.ifIndex}</div>
                            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{it.comment || '—'}</div>
                          </>
                        )}
                      </div>
                      {canWrite && (
                        <button type="button" className="icon-btn tt" data-tt="Убрать" onClick={() => removeItem(key)} disabled={saving}>
                          <Icon name="trash" size={15} />
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {canWrite && (
            <div className="field">
              <label>{isPrefixes ? 'Добавить сеть из справочника' : 'Добавить порт из инвентаря'}</label>
              <input
                className="input"
                placeholder={isPrefixes ? 'Поиск по префиксу…' : 'IP коммутатора, имя или описание…'}
                value={selectorQ}
                onChange={(e) => setSelectorQ(e.target.value)}
              />
              {optionsLoading && (
                <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 6 }}>
                  {saving ? 'Сохранение…' : 'Поиск…'}
                </div>
              )}
              {!optionsLoading && selectorQ.trim() && filteredOptions.length === 0 && (
                <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 6 }}>
                  {isPrefixes ? 'Сети не найдены.' : 'Порты не найдены.'}
                </div>
              )}
              {!optionsLoading && filteredOptions.length > 0 && (
                <div className="col" style={{ gap: 4, marginTop: 8, maxHeight: 220, overflow: 'auto' }}>
                  {filteredOptions.slice(0, 20).map((opt) => {
                    const key = bindingOptionKey(opt, isPrefixes);
                    const status = resolveBindingOptionStatus(opt, items, client, isPrefixes);
                    return (
                      <button
                        key={key}
                        type="button"
                        className="row"
                        style={{
                          all: 'unset',
                          cursor: status.selectable && !saving ? 'pointer' : 'not-allowed',
                          display: 'flex',
                          justifyContent: 'space-between',
                          gap: 12,
                          padding: '8px 10px',
                          borderRadius: 8,
                          background: 'var(--surf-3)',
                          opacity: status.selectable ? 1 : 0.65,
                        }}
                        disabled={!status.selectable || saving}
                        onClick={() => addItem(opt)}
                      >
                        <div>
                          {isPrefixes ? (
                            <div className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{opt.prefix}</div>
                          ) : (
                            <>
                              <div className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{opt.switchIp} · {opt.ifIndex}</div>
                              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
                                {[opt.ifName, opt.ifAlias, opt.ifDescr].filter(Boolean).join(' · ') || '—'}
                              </div>
                            </>
                          )}
                        </div>
                        <div style={{
                          font: 'var(--pv-text-body-3)',
                          color: status.conflict ? 'var(--st-critical)' : status.assignedHere ? 'var(--st-success)' : 'var(--fg-secondary)',
                          textAlign: 'right',
                        }}
                        >
                          {status.label}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {canWrite && saving && (
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              Сохранение привязки…
            </div>
          )}
        </>
      )}
      {error && <div className="form-error">{error}</div>}
    </div>
  );
}

function ClientUsersTab({ client, canWrite, onChanged }) {
  const [users, setUsers] = useState([]);
  const [meta, setMeta] = useState({ used: 0, limit: MAX_CLIENT_USERS, remaining: MAX_CLIENT_USERS });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const [createdPassword, setCreatedPassword] = useState(null);
  const [passwordFor, setPasswordFor] = useState(null);
  const [togglingId, setTogglingId] = useState(null);

  const loadUsers = useCallback(async () => {
    if (!canWrite || !client?.clientId) return;
    setLoading(true);
    setError('');
    try {
      const res = await ApiClient.loadUsersForClient(client.clientId);
      setUsers(res.data || []);
      setMeta({
        used: res.meta?.used ?? (res.data || []).length,
        limit: res.meta?.limit ?? MAX_CLIENT_USERS,
        remaining: res.meta?.remaining ?? Math.max(MAX_CLIENT_USERS - (res.data || []).length, 0),
      });
    } catch (err) {
      setError(err.message);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  }, [canWrite, client?.clientId]);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  const toggleActive = async (user) => {
    if (!canWrite) return;
    setTogglingId(user.id);
    try {
      await ApiClient.updateUser(user.id, {
        fullName: user.fullName,
        username: user.username,
        active: !user.active,
      });
      pushToast({ kind: 'success', title: user.active ? 'Учётная запись отключена' : 'Учётная запись включена' });
      await loadUsers();
      if (onChanged) onChanged();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось изменить состояние', desc: err.message });
    } finally {
      setTogglingId(null);
    }
  };

  const atLimit = (meta.used ?? users.length) >= (meta.limit ?? MAX_CLIENT_USERS);

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
        <div style={{ font: 'var(--pv-text-body-2-bold)' }}>
          Использовано {meta.used ?? users.length} из {meta.limit ?? MAX_CLIENT_USERS}
        </div>
        {canWrite && (
          <Button
            kind="primary"
            icon="users"
            disabled={atLimit}
            onClick={() => { setCreateOpen(true); setCreatedPassword(null); }}
          >
            Создать учётную запись
          </Button>
        )}
      </div>
      {atLimit && (
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--st-warning)' }}>
          Достигнут лимит учётных записей для клиента (не более {meta.limit ?? MAX_CLIENT_USERS}).
        </div>
      )}

      {loading ? (
        <div style={{ color: 'var(--fg-secondary)' }}>Загрузка…</div>
      ) : users.length === 0 ? (
        <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Учётные записи не созданы.</div>
      ) : (
        <div className="col" style={{ gap: 10 }}>
          {users.map((u) => (
            <Card key={u.id} pad="sm">
              <div className="row" style={{ justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
                <div>
                  <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{u.fullName}</div>
                  <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{u.username}</div>
                  <div className="row" style={{ gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
                    {u.active
                      ? <Badge tone="success" dot>Активна</Badge>
                      : <Badge tone="neutral">Отключена</Badge>}
                    {u.forcePasswordChange && <Badge tone="warning" dot>Требуется смена пароля</Badge>}
                  </div>
                  <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 8 }}>
                    Изменена: {fmtDateTime(u.updatedAt)}
                    {u.passwordChangedAt ? ` · пароль: ${fmtDateTime(u.passwordChangedAt)}` : ''}
                  </div>
                </div>
                {canWrite && (
                  <div className="row" style={{ gap: 4 }}>
                    <button className="icon-btn tt" data-tt="Сменить пароль" onClick={() => setPasswordFor(u)}>
                      <Icon name="key" size={15} />
                    </button>
                    <button
                      className="icon-btn tt"
                      data-tt={u.active ? 'Отключить' : 'Включить'}
                      disabled={togglingId === u.id}
                      onClick={() => toggleActive(u)}
                    >
                      <Icon name={u.active ? 'pause' : 'play'} size={15} />
                    </button>
                  </div>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      {error && <div className="form-error">{error}</div>}

      <ClientUserCreateModal
        open={createOpen}
        client={client}
        onClose={() => setCreateOpen(false)}
        onCreated={async (result) => {
          setCreateOpen(false);
          setCreatedPassword(result);
          await loadUsers();
          if (onChanged) onChanged();
        }}
      />

      <ClientUserPasswordModal
        user={passwordFor}
        onClose={() => setPasswordFor(null)}
        onSaved={loadUsers}
      />

      <ClientUserPasswordRevealModal
        result={createdPassword}
        onClose={() => setCreatedPassword(null)}
      />
    </div>
  );
}

function ClientUserCreateModal({ open, client, onClose, onCreated }) {
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [forcePasswordChange, setForcePasswordChange] = useState(true);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setFullName('');
    setUsername('');
    setForcePasswordChange(true);
    setPassword(generatePassword());
    setShowPassword(false);
    setError('');
  }, [open]);

  const submit = async () => {
    setError('');
    if (!fullName.trim()) { setError('Укажите ФИО'); return; }
    if (!username.trim()) { setError('Укажите username'); return; }
    if (password.length < 12) { setError('Пароль должен быть не короче 12 символов'); return; }
    setSaving(true);
    try {
      const user = await ApiClient.createUser({
        fullName: fullName.trim(),
        username: username.trim(),
        password,
        roleId: 'Client',
        clientId: client.clientId,
        forcePasswordChange,
      });
      pushToast({ kind: 'success', title: 'Учётная запись создана' });
      onCreated({ user, password, username: username.trim(), fullName: fullName.trim() });
    } catch (err) {
      setError(err.message || 'Не удалось создать учётную запись');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Создать учётную запись"
      subtitle={`Клиент: ${client?.displayName || client?.clientId}`}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" icon="users" onClick={submit} disabled={saving}>
            {saving ? 'Создание…' : 'Создать'}
          </Button>
        </>
      }
    >
      <div className="col" style={{ gap: 14 }}>
        <div className="field">
          <label>ФИО</label>
          <input className="input" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Иван Иванов" />
        </div>
        <div className="field">
          <label>Username</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="ivanov" />
        </div>
        <div className="field">
          <label>Пароль</label>
          <div className="row" style={{ gap: 8 }}>
            <input
              className="input"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <Button kind="ghost" onClick={() => setPassword(generatePassword())}>Сгенерировать</Button>
            <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>{showPassword ? 'Скрыть' : 'Показать'}</Button>
          </div>
        </div>
        <SwitchField
          label="Требовать смену пароля при входе"
          hint="Пользователь сменит пароль сразу после первого входа с выданным паролем."
          checked={forcePasswordChange}
          onChange={setForcePasswordChange}
        />
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          Роль <b>Client</b> и клиент <span className="mono">{client?.clientId}</span> назначаются автоматически.
        </div>
        {error && <div className="form-error">{error}</div>}
      </div>
    </Modal>
  );
}

function ClientUserPasswordModal({ user, onClose, onSaved }) {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!user) return;
    setPassword(generatePassword());
    setShowPassword(false);
    setError('');
  }, [user?.id]);

  const submit = async () => {
    setError('');
    if (password.length < 12) { setError('Пароль должен быть не короче 12 символов'); return; }
    setSaving(true);
    try {
      await ApiClient.changeUserPassword(user.id, { password });
      pushToast({ kind: 'success', title: 'Пароль изменён' });
      onClose();
      if (onSaved) await onSaved();
    } catch (err) {
      setError(err.message || 'Не удалось изменить пароль');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={!!user}
      onClose={onClose}
      title="Сменить пароль"
      subtitle={user ? `${user.fullName} · ${user.username}` : ''}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" icon="key" onClick={submit} disabled={saving}>{saving ? 'Сохранение…' : 'Сменить пароль'}</Button>
        </>
      }
    >
      <div className="field">
        <label>Новый пароль</label>
        <div className="row" style={{ gap: 8 }}>
          <input className="input" type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} />
          <Button kind="ghost" onClick={() => setPassword(generatePassword())}>Сгенерировать</Button>
          <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>{showPassword ? 'Скрыть' : 'Показать'}</Button>
        </div>
      </div>
      {error && <div className="form-error" style={{ marginTop: 12 }}>{error}</div>}
    </Modal>
  );
}

function ClientUserPasswordRevealModal({ result, onClose }) {
  if (!result) return null;
  return (
    <Modal
      open
      onClose={onClose}
      title="Пароль создан"
      subtitle={`${result.fullName} · ${result.username}`}
      footer={<Button kind="primary" onClick={onClose}>Понятно</Button>}
    >
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginBottom: 12 }}>
        Сохраните пароль сейчас — он больше не будет показан.
      </div>
      <div className="field">
        <label>Пароль</label>
        <input className="input mono" value={result.password} readOnly onFocus={(e) => e.target.select()} />
      </div>
    </Modal>
  );
}

function ImpersonationAuditPanel({ canWrite, clientId, compact = false }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    if (!canWrite) {
      setEvents([]);
      setError('Недостаточно прав');
      return undefined;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError('');
      try {
        const res = await ApiClient.loadImpersonationAudit({ limit: compact ? 100 : 200 });
        if (cancelled) return;
        setEvents(res.data || []);
      } catch (err) {
        if (cancelled) return;
        setError(err.message || ApiClient.LOAD_FAILED);
        setEvents([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [canWrite, refreshKey, compact]);

  const sessions = useMemo(() => {
    const filtered = clientId
      ? (events || []).filter((ev) => ev.clientId === clientId)
      : (events || []);
    return groupImpersonationSessions(filtered);
  }, [events, clientId]);

  const cols = [
    {
      key: 'actor',
      title: 'Оператор',
      width: 160,
      render: (s) => (
        <div>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{s.actorUsername}</div>
        </div>
      ),
    },
    ...(!clientId ? [{
      key: 'client',
      title: 'Клиент',
      width: 200,
      render: (s) => (
        <div>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{s.clientDisplayName || '—'}</div>
          <div className="mono" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{s.clientId}</div>
        </div>
      ),
    }] : []),
    {
      key: 'started',
      title: 'Вход',
      width: 150,
      sortAccessor: (s) => s.start?.eventAt,
      render: (s) => fmtDateTime(s.start?.eventAt),
    },
    {
      key: 'ended',
      title: 'Выход',
      width: 150,
      sortAccessor: (s) => s.end?.eventAt,
      render: (s) => fmtDateTime(s.end?.eventAt),
    },
    {
      key: 'duration',
      title: 'Длительность',
      width: 120,
      sortAccessor: (s) => s.durationMs,
      render: (s) => fmtDuration(s.durationMs),
    },
    {
      key: 'status',
      title: 'Состояние',
      width: 130,
      render: (s) => sessionStatusBadge(s),
    },
    {
      key: 'reason',
      title: 'Причина завершения',
      width: 180,
      render: (s) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {s.end
            ? (IMPERSONATION_REASON_LABELS[s.endReason] || s.endReason || '—')
            : s.orphaned
              ? IMPERSONATION_REASON_LABELS.orphaned
              : '—'}
        </span>
      ),
    },
  ];

  if (loading) {
    return <div style={{ color: 'var(--fg-secondary)' }}>Загрузка журнала…</div>;
  }

  if (error) {
    return (
      <Empty
        icon="db"
        title="Не удалось загрузить журнал"
        desc={error}
        action={canWrite ? <Button kind="primary" icon="refresh" onClick={() => setRefreshKey((k) => k + 1)}>Повторить</Button> : null}
      />
    );
  }

  return (
    <div className="col" style={{ gap: 12 }}>
      {!compact && (
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            История входов администратора в кабинеты клиентов. Сеансы собираются по идентификатору сессии.
          </div>
          <Button kind="ghost" icon="refresh" onClick={() => setRefreshKey((k) => k + 1)}>Обновить</Button>
        </div>
      )}
      <DataTable
        rows={sessions}
        columns={cols}
        rowKey="sessionAuditId"
        pageSize={compact ? 8 : 15}
        emptyTitle="Записей нет"
        emptyDesc={clientId ? 'Для этого клиента входов администратора пока не было.' : 'Входы администратора в кабинеты клиентов пока не выполнялись.'}
        dense={compact}
      />
    </div>
  );
}

function SwitchField({ label, hint, checked, onChange, disabled }) {
  return (
    <label className="switch-field" style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: disabled ? 'default' : 'pointer' }}>
      <button
        type="button"
        className="ui-switch"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        style={{
          width: 40,
          height: 22,
          borderRadius: 999,
          border: 'none',
          padding: 0,
          flexShrink: 0,
          cursor: disabled ? 'not-allowed' : 'pointer',
          background: checked ? 'var(--grad-primary)' : 'var(--surf-4)',
          position: 'relative',
          transition: 'background var(--pv-dur-fast)',
          opacity: disabled ? 0.6 : 1,
        }}
      >
        <span style={{
          position: 'absolute',
          top: 2,
          left: checked ? 20 : 2,
          width: 18,
          height: 18,
          borderRadius: '50%',
          background: 'var(--pv-white-main)',
          transition: 'left var(--pv-dur-fast)',
          boxShadow: '0 1px 3px rgba(0,0,0,0.25)',
        }} />
      </button>
      <span>
        <div style={{ font: 'var(--pv-text-body-2-bold)', color: 'var(--fg-primary)' }}>{label}</div>
        {hint && <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 2 }}>{hint}</div>}
      </span>
    </label>
  );
}

Object.assign(window, { PageClients });
