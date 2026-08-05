/* DNS-резолверы — справочник для классификации адресов на странице DNS-запросов */

const DNS_RESOLVER_ROLES = [
  { value: 'resolver', label: 'Резолвер оператора' },
  { value: 'client', label: 'Резолвер абонента' },
  { value: 'public', label: 'Публичный резолвер' },
];

const DNS_RESOLVER_ROLE_LABELS = Object.fromEntries(DNS_RESOLVER_ROLES.map((r) => [r.value, r.label]));

const SAVE_SUCCESS_TITLE = 'Настройки сохранены';
const SAVE_SUCCESS_DESC = 'Изменения будут автоматически применены в течение 60 секунд.';

function dnsResolverRowKey(row) {
  return row.resolverId;
}

function parseCidrClient(prefix) {
  const trimmed = String(prefix ?? '').trim();
  if (!trimmed) return { ok: false, error: 'Укажите префикс (CIDR)' };
  const slash = trimmed.indexOf('/');
  if (slash < 0) return { ok: false, error: 'Префикс должен быть в формате CIDR' };
  const ipPart = trimmed.slice(0, slash);
  const mask = Number(trimmed.slice(slash + 1));
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ipPart);
  const v6 = ipPart.includes(':');
  if (v4 && mask >= 0 && mask <= 32) return { ok: true, prefix: `${ipPart}/${mask}`, family: 4 };
  if (v6 && mask >= 0 && mask <= 128) return { ok: true, prefix: trimmed, family: 6 };
  return { ok: false, error: 'Некорректный CIDR или маска' };
}

function fmtDnsResolverUpdatedAt(value) {
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

function PageDnsResolvers() {
  const canWrite = AuthAccess.canWritePage('dns-resolvers');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [togglingId, setTogglingId] = useState(null);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const res = await ApiClient.loadDnsResolvers();
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
      } else {
        setRows((res.rows || []).map((r) => ({ ...r, id: dnsResolverRowKey(r) })));
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => {
      const roleLabel = DNS_RESOLVER_ROLE_LABELS[r.role] || r.role;
      return (
        r.prefix.toLowerCase().includes(s)
        || (r.displayName || '').toLowerCase().includes(s)
        || (r.comment || '').toLowerCase().includes(s)
        || roleLabel.toLowerCase().includes(s)
      );
    });
  }, [rows, search]);

  const handleToggle = async (row) => {
    const next = row.enabled === 1 ? 0 : 1;
    const label = next === 1 ? 'включить' : 'отключить';
    if (!window.confirm(`${label.charAt(0).toUpperCase() + label.slice(1)} резолвер ${row.prefix}?`)) return;
    setTogglingId(row.id);
    try {
      await ApiClient.toggleDnsResolver({ resolverId: row.resolverId, enabled: next });
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось изменить статус', desc: err.message });
    } finally {
      setTogglingId(null);
    }
  };

  const handleDelete = async (row) => {
    if (!window.confirm(`Удалить резолвер ${row.prefix} безвозвратно?`)) return;
    try {
      await ApiClient.deleteDnsResolver({ resolverId: row.resolverId });
      pushToast({ kind: 'success', title: 'Резолвер удалён', desc: 'Запись удалена из справочника.' });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить', desc: err.message });
    }
  };

  const cols = [
    {
      key: 'prefix',
      title: 'Префикс',
      width: 220,
      sortAccessor: (r) => r.prefix,
      render: (r) => (
        <div className="row" style={{ gap: 8, opacity: r.enabled === 1 ? 1 : 0.55 }}>
          <Icon name="globe" size={14} style={{ color: r.enabled === 1 ? '#A4ADFF' : 'var(--fg-secondary)' }} />
          <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.prefix}</span>
        </div>
      ),
    },
    {
      key: 'enabled',
      title: 'Активен',
      width: 88,
      sortAccessor: (r) => r.enabled,
      render: (r) => (
        <DnsResolverEnabledToggle
          enabled={r.enabled === 1}
          disabled={!canWrite || togglingId === r.id}
          onChange={() => handleToggle(r)}
        />
      ),
    },
    {
      key: 'family',
      title: 'IP',
      width: 72,
      render: (r) => <span className="tag">IPv{r.family}</span>,
    },
    {
      key: 'role',
      title: 'Роль',
      width: 180,
      sortAccessor: (r) => DNS_RESOLVER_ROLE_LABELS[r.role] || r.role,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)' }}>
          {DNS_RESOLVER_ROLE_LABELS[r.role] || r.role}
        </span>
      ),
    },
    {
      key: 'displayName',
      title: 'Отображаемое имя',
      width: 180,
      render: (r) => r.displayName || <span style={{ color: 'var(--fg-secondary)' }}>—</span>,
    },
    {
      key: 'comment',
      title: 'Комментарий',
      width: 180,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.comment || '—'}
        </span>
      ),
    },
    {
      key: 'source',
      title: 'Источник',
      width: 90,
      render: (r) => <span className="tag">{r.source || '—'}</span>,
    },
    {
      key: 'updatedAt',
      title: 'Обновлено',
      width: 140,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {fmtDnsResolverUpdatedAt(r.updatedAt)}
        </span>
      ),
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>DNS-резолверы</h1>
          <p>Справочник для бейджей на странице DNS-запросов: резолверы оператора, абонентов и публичные DNS.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>Добавить резолвер</Button>
        </div>
      </div>

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : loadError ? (
        <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={reload}>Повторить</Button>} />
      ) : (
        <DataTable
          rows={filtered}
          columns={cols}
          rowKey="id"
          selectable
          selected={selected}
          onSelectChange={setSelected}
          pageSize={15}
          onRowClick={canWrite ? (r) => setEditing({ ...r, isNew: false }) : undefined}
          emptyTitle="Нет резолверов"
          emptyDesc="Добавьте префикс или уточните поиск."
          toolbar={{
            search,
            onSearch: setSearch,
          }}
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: false }); }}>
                <Icon name="edit" size={15} />
              </button>
              <button className="icon-btn tt" data-tt="Удалить" onClick={(e) => { e.stopPropagation(); handleDelete(r); }}>
                <Icon name="trash" size={15} />
              </button>
            </div>
          ) : null}
        />
      )}

      <DnsResolverFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd || (editing && editing.isNew)}
        onClose={() => { setShowAdd(false); setEditing(null); }}
        onSaved={() => {
          setShowAdd(false);
          setEditing(null);
          reload();
          pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
        }}
      />
    </div>
  );
}

function DnsResolverEnabledToggle({ enabled, disabled, onChange }) {
  return (
    <button
      type="button"
      className="l3-enabled-toggle"
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onChange(); }}
      title={enabled ? 'Отключить' : 'Включить'}
      aria-pressed={enabled}
      style={{
        width: 36,
        height: 20,
        borderRadius: 999,
        border: 'none',
        padding: 0,
        cursor: disabled ? 'wait' : 'pointer',
        background: enabled ? 'var(--grad-primary)' : 'var(--surf-4)',
        position: 'relative',
        transition: 'background var(--pv-dur-fast)',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      <span style={{
        position: 'absolute',
        top: 2,
        left: enabled ? 18 : 2,
        width: 16,
        height: 16,
        borderRadius: 999,
        background: '#fff',
        transition: 'left var(--pv-dur-fast) var(--pv-ease-out)',
      }} />
    </button>
  );
}

function DnsResolverFormModal({ open, row, isNew, onClose, onSaved }) {
  const [prefix, setPrefix] = useState('');
  const [family, setFamily] = useState(4);
  const [role, setRole] = useState(DNS_RESOLVER_ROLES[0].value);
  const [displayName, setDisplayName] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    if (isNew) {
      setPrefix('');
      setFamily(4);
      setRole(DNS_RESOLVER_ROLES[0].value);
      setDisplayName('');
      setComment('');
    } else if (row) {
      setPrefix(row.prefix);
      setFamily(row.family);
      setRole(DNS_RESOLVER_ROLE_LABELS[row.role] ? row.role : DNS_RESOLVER_ROLES[0].value);
      setDisplayName(row.displayName || '');
      setComment(row.comment || '');
    }
    setFormError('');
  }, [open, isNew, row]);

  const onPrefixChange = (value) => {
    setPrefix(value);
    if (isNew) {
      const parsed = parseCidrClient(value);
      if (parsed.ok) setFamily(parsed.family);
    }
  };

  const validate = () => {
    const parsed = parseCidrClient(prefix);
    if (!parsed.ok) return parsed.error;
    if (isNew && parsed.family !== family) return 'Версия IP не соответствует адресу';
    if (!isNew && parsed.prefix !== row.prefix) return 'Префикс нельзя изменить';
    if (!DNS_RESOLVER_ROLE_LABELS[role]) return 'Выберите роль';
    return '';
  };

  const handleSave = async () => {
    const err = validate();
    if (err) {
      setFormError(err);
      return;
    }
    const parsed = parseCidrClient(prefix);
    setSaving(true);
    setFormError('');
    try {
      await ApiClient.saveDnsResolver({
        resolverId: isNew ? crypto.randomUUID() : row.resolverId,
        prefix: isNew ? parsed.prefix : row.prefix,
        family: isNew ? parsed.family : row.family,
        role,
        displayName,
        comment,
        enabled: 1,
      });
      onSaved();
    } catch (e) {
      setFormError(e.message || 'Ошибка сохранения');
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? 'Добавить резолвер' : 'Редактировать резолвер'}
      subtitle={isNew ? 'Новая запись справочника' : row?.prefix}
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
          <Button kind="primary" icon="save" onClick={handleSave} disabled={saving}>
            {saving ? 'Сохранение…' : 'Сохранить'}
          </Button>
        </>
      }
    >
      {formError && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
          {formError}
        </div>
      )}
      <div className="grid grid--2col">
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Префикс (CIDR)</label>
          <input
            className="input mono"
            placeholder="8.8.8.8/32"
            value={prefix}
            onChange={(e) => onPrefixChange(e.target.value)}
            readOnly={!isNew}
            disabled={!isNew}
          />
        </div>
        <div className="field">
          <label>Версия IP</label>
          <input className="input" value={`IPv${family}`} readOnly disabled />
        </div>
        <div className="field">
          <label>Роль</label>
          <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            {DNS_RESOLVER_ROLES.map((r) => (
              <option key={r.value} value={r.value}>{r.label}</option>
            ))}
          </select>
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Отображаемое имя</label>
          <input className="input" placeholder="Необязательно" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Комментарий</label>
          <input className="input" placeholder="Необязательно" value={comment} onChange={(e) => setComment(e.target.value)} />
        </div>
      </div>
    </Modal>
  );
}

Object.assign(window, { PageDnsResolvers, DNS_RESOLVER_ROLES });
