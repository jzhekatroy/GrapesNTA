/* Собственные сети (CIDR) — L3-префиксы из ClickHouse */

const L3_ROLES = [
  { value: 'provider_public', label: 'Публичная сеть провайдера' },
  { value: 'internal', label: 'Внутренняя сеть провайдера' },
  { value: 'customer_allocated', label: 'Сеть клиента из нашего пула' },
  { value: 'customer_transit', label: 'Транзитная сеть клиента' },
  { value: 'remote', label: 'Чужая / внешняя сеть' },
];

const L3_ROLE_LABELS = Object.fromEntries(L3_ROLES.map((r) => [r.value, r.label]));

const SAVE_SUCCESS_TITLE = 'Настройки сохранены';
const SAVE_SUCCESS_DESC = 'Изменения будут автоматически применены в течение 60 секунд.';

function l3RowKey(row) {
  return `${row.family}:${row.prefix}`;
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

function fmtL3UpdatedAt(value) {
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

function PageCIDR({ embedded = false, refreshKey: parentRefreshKey = 0, onReload } = {}) {
  const canWrite = AuthAccess.canWritePage('cidr');
  const [rows, setRows] = useState([]);
  const [entities, setEntities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [localRefreshKey, setLocalRefreshKey] = useState(0);
  const [togglingId, setTogglingId] = useState(null);

  const refreshKey = onReload ? parentRefreshKey : localRefreshKey;
  const reload = useCallback(() => {
    if (onReload) onReload();
    else setLocalRefreshKey((k) => k + 1);
  }, [onReload]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const [prefixRes, entityRes] = await Promise.all([
        ApiClient.loadL3Prefixes(),
        ApiClient.loadNetEntities(),
      ]);
      if (cancelled) return;
      if (prefixRes.source === 'error' || entityRes.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
        setEntities([]);
      } else {
        setRows((prefixRes.rows || []).map((r) => ({ ...r, id: l3RowKey(r) })));
        setEntities(entityRes.rows || []);
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => {
      const roleLabel = L3_ROLE_LABELS[r.role] || r.role;
      return (
        r.prefix.toLowerCase().includes(s)
        || (r.entityName || '').toLowerCase().includes(s)
        || (r.entityId || '').toLowerCase().includes(s)
        || (r.displayName || '').toLowerCase().includes(s)
        || (r.comment || '').toLowerCase().includes(s)
        || roleLabel.toLowerCase().includes(s)
      );
    });
  }, [rows, search]);

  const handleToggle = async (row) => {
    const next = row.enabled === 1 ? 0 : 1;
    const label = next === 1 ? 'включить' : 'отключить';
    if (!window.confirm(`${label.charAt(0).toUpperCase() + label.slice(1)} сеть ${row.prefix}?`)) return;
    setTogglingId(row.id);
    try {
      await ApiClient.toggleL3Prefix({ prefix: row.prefix, family: row.family, enabled: next });
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось изменить статус', desc: err.message });
    } finally {
      setTogglingId(null);
    }
  };

  const handleDelete = async (row) => {
    if (!window.confirm(`Удалить сеть ${row.prefix} безвозвратно? Все версии записи будут удалены из ClickHouse.`)) return;
    try {
      await ApiClient.deleteL3Prefix({ prefix: row.prefix, family: row.family });
      pushToast({ kind: 'success', title: 'Сеть удалена', desc: 'Префикс удалён из справочника.' });
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
          <Icon name="cidr" size={14} style={{ color: r.enabled === 1 ? '#A4ADFF' : 'var(--fg-secondary)' }} />
          <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.prefix}</span>
        </div>
      ),
    },
    {
      key: 'enabled',
      title: 'Активна',
      width: 88,
      sortAccessor: (r) => r.enabled,
      render: (r) => (
        <L3EnabledToggle
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
      key: 'entity',
      title: 'Владелец',
      width: 220,
      sortAccessor: (r) => r.entityName || r.entityId,
      render: (r) => (
        <div>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.entityName || '—'}</div>
          {r.entityId && (
            <div className="mono" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 2 }}>
              {r.entityId}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'role',
      title: 'Роль',
      width: 200,
      sortAccessor: (r) => L3_ROLE_LABELS[r.role] || r.role,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)' }}>
          {L3_ROLE_LABELS[r.role] || r.role}
        </span>
      ),
    },
    {
      key: 'displayName',
      title: 'Отображаемое имя',
      width: 160,
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
          {fmtL3UpdatedAt(r.updatedAt)}
        </span>
      ),
    },
  ];

  const body = (
    <>
      {!embedded && (
        <div className="page-head">
          <div>
            <h1>Собственные сети (CIDR)</h1>
            <p>L3-префиксы для классификации трафика: владелец сети и роль адресов. Изменения применяются автоматически (~60 с).</p>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Button kind="ghost" icon="upload" disabled title="В разработке" onClick={() => pushToast({ kind: 'info', title: 'Импорт CSV', desc: 'Функция в разработке.' })}>Импорт из CSV</Button>
            <Button kind="ghost" icon="export" disabled title="В разработке" onClick={() => pushToast({ kind: 'info', title: 'Экспорт', desc: 'Функция в разработке.' })}>Экспорт</Button>
            <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
            <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>Добавить сеть</Button>
          </div>
        </div>
      )}

      {embedded && (
        <div className="row" style={{ justifyContent: 'flex-end', marginBottom: 12, gap: 8 }}>
          <Button kind="ghost" icon="upload" disabled title="В разработке" onClick={() => pushToast({ kind: 'info', title: 'Импорт CSV', desc: 'Функция в разработке.' })}>Импорт из CSV</Button>
          <Button kind="ghost" icon="export" disabled title="В разработке" onClick={() => pushToast({ kind: 'info', title: 'Экспорт', desc: 'Функция в разработке.' })}>Экспорт</Button>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>Добавить сеть</Button>
        </div>
      )}

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
          emptyTitle="Нет сетей"
          emptyDesc="Добавьте L3-префикс или уточните поиск."
          toolbar={{
            search,
            onSearch: setSearch,
            left: selected.size > 0 ? (
              <div className="row" style={{ gap: 8 }}>
                <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
                  Выбрано: <b style={{ color: 'var(--fg-primary)' }}>{selected.size}</b>
                </span>
                <Button size="sm" kind="ghost" disabled onClick={() => pushToast({ kind: 'info', title: 'Bulk edit', desc: 'Функция в разработке.' })}>Bulk edit</Button>
              </div>
            ) : null,
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

      <L3PrefixFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd || (editing && editing.isNew)}
        entities={entities}
        onClose={() => { setShowAdd(false); setEditing(null); }}
        onSaved={() => {
          setShowAdd(false);
          setEditing(null);
          reload();
          pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
        }}
      />
    </>
  );

  if (embedded) return body;
  return <div className="main__container">{body}</div>;
}

function L3EnabledToggle({ enabled, disabled, onChange }) {
  return (
    <button
      type="button"
      className="l3-enabled-toggle"
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onChange(); }}
      title={enabled ? 'Отключить сеть' : 'Включить сеть'}
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
        background: 'var(--pv-white-main)',
        transition: 'left var(--pv-dur-fast) var(--pv-ease-out)',
      }} />
    </button>
  );
}

function L3PrefixFormModal({ open, row, isNew, entities, onClose, onSaved }) {
  const [prefix, setPrefix] = useState('');
  const [family, setFamily] = useState(4);
  const [entityId, setEntityId] = useState('');
  const [role, setRole] = useState(L3_ROLES[0].value);
  const [displayName, setDisplayName] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    if (isNew) {
      setPrefix('');
      setFamily(4);
      setEntityId(entities[0]?.entityId || '');
      setRole(L3_ROLES[0].value);
      setDisplayName('');
      setComment('');
    } else if (row) {
      setPrefix(row.prefix);
      setFamily(row.family);
      setEntityId(row.entityId || '');
      setRole(L3_ROLE_LABELS[row.role] ? row.role : L3_ROLES[0].value);
      setDisplayName(row.displayName || '');
      setComment(row.comment || '');
    }
    setFormError('');
  }, [open, isNew, row, entities]);

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
    if (!isNew && (parsed.prefix !== row.prefix || parsed.family !== row.family)) {
      return 'Префикс нельзя изменить';
    }
    if (!entityId) return 'Выберите владельца сети';
    if (!L3_ROLE_LABELS[role]) return 'Выберите роль сети';
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
      await ApiClient.saveL3Prefix({
        prefix: isNew ? parsed.prefix : row.prefix,
        family: isNew ? parsed.family : row.family,
        entityId,
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
      title={isNew ? 'Добавить сеть' : 'Редактировать сеть'}
      subtitle={isNew ? 'Новый L3-префикс' : row?.prefix}
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
            placeholder="188.143.128.0/17"
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
          <label>Роль сети</label>
          <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            {L3_ROLES.map((r) => (
              <option key={r.value} value={r.value}>{r.label}</option>
            ))}
          </select>
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Владелец сети</label>
          <select className="input" value={entityId} onChange={(e) => setEntityId(e.target.value)}>
            <option value="">— выберите —</option>
            {entities.map((e) => (
              <option key={e.entityId} value={e.entityId}>
                {e.displayName} ({e.entityId})
              </option>
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

Object.assign(window, { PageCIDR, L3_ROLES });
