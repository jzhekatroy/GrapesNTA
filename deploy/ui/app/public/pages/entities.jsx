/* Владельцы L3 — справочник net_entities (ClickHouse) */

const ENTITY_TYPES = [
  { value: 'isp', label: 'Провайдер' },
  { value: 'customer', label: 'Клиент' },
  { value: 'internal', label: 'Внутренний объект' },
];

const ENTITY_TYPE_LABELS = Object.fromEntries(ENTITY_TYPES.map((t) => [t.value, t.label]));

const SAVE_SUCCESS_TITLE = 'Настройки сохранены';
const SAVE_SUCCESS_DESC = 'Изменения будут автоматически применены в течение 60 секунд.';

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

function buildEntitySlug(displayName) {
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

function previewEntityId(ownerType, displayName) {
  const prefix = String(ownerType ?? '').trim();
  if (!ENTITY_TYPE_LABELS[prefix]) return '';
  const slug = buildEntitySlug(displayName);
  if (!slug) return '';
  return `${prefix}:${slug}`;
}

function ownerTypeFromEntityId(entityId) {
  const idx = String(entityId).indexOf(':');
  if (idx < 0) return null;
  const prefix = entityId.slice(0, idx);
  return ENTITY_TYPE_LABELS[prefix] ? prefix : null;
}

function fmtEntityUpdatedAt(value) {
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

function PageEntities({ embedded = false, refreshKey: parentRefreshKey = 0, onReload } = {}) {
  const canWrite = AuthAccess.canWritePage('entities');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [localRefreshKey, setLocalRefreshKey] = useState(0);

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
      const res = await ApiClient.loadNetEntitiesAdmin();
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
      } else {
        setRows((res.rows || []).map((r) => ({ ...r, id: r.entityId })));
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => (
      (r.displayName || '').toLowerCase().includes(s)
      || (r.entityId || '').toLowerCase().includes(s)
      || (r.comment || '').toLowerCase().includes(s)
      || (r.source || '').toLowerCase().includes(s)
    ));
  }, [rows, search]);

  const handleDisable = async (row) => {
    if (!window.confirm(`Отключить владельца «${row.displayName}»?`)) return;
    try {
      await ApiClient.saveNetEntity({
        entityId: row.entityId,
        displayName: row.displayName,
        comment: row.comment,
        enabled: 0,
      });
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось отключить', desc: err.message });
    }
  };

  const cols = [
    {
      key: 'displayName',
      title: 'Название',
      width: 220,
      sortAccessor: (r) => r.displayName,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName || '—'}</span>
      ),
    },
    {
      key: 'entityId',
      title: 'Entity ID',
      width: 200,
      sortAccessor: (r) => r.entityId,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.entityId}</span>
      ),
    },
    {
      key: 'comment',
      title: 'Комментарий',
      width: 220,
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
      title: 'Дата изменения',
      width: 150,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {fmtEntityUpdatedAt(r.updatedAt)}
        </span>
      ),
    },
  ];

  const body = (
    <>
      {!embedded && (
        <div className="page-head">
          <div>
            <h1>Владельцы L3</h1>
            <p>Справочник владельцев сетей для L3-префиксов и классификации. Идентификатор entity_id задаётся один раз при создании.</p>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
            <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>Добавить владельца</Button>
          </div>
        </div>
      )}

      {embedded && (
        <div className="row" style={{ justifyContent: 'flex-end', marginBottom: 12 }}>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>Добавить владельца</Button>
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
          emptyTitle="Нет активных владельцев"
          emptyDesc="Добавьте владельца или уточните поиск."
          toolbar={{
            search,
            onSearch: setSearch,
          }}
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: false }); }}>
                <Icon name="edit" size={15} />
              </button>
              <button className="icon-btn tt" data-tt="Отключить" onClick={(e) => { e.stopPropagation(); handleDisable(r); }}>
                <Icon name="trash" size={15} />
              </button>
            </div>
          ) : null}
        />
      )}

      <EntityFormModal
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
    </>
  );

  if (embedded) return body;
  return <div className="main__container">{body}</div>;
}

function EntityFormModal({ open, row, isNew, onClose, onSaved }) {
  const [displayName, setDisplayName] = useState('');
  const [ownerType, setOwnerType] = useState(ENTITY_TYPES[0].value);
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const entityIdPreview = isNew ? previewEntityId(ownerType, displayName) : (row?.entityId || '');
  const ownerTypeReadonly = !isNew ? ownerTypeFromEntityId(row?.entityId) : null;

  useEffect(() => {
    if (!open) return;
    setFormError('');
    if (isNew) {
      setDisplayName('');
      setOwnerType(ENTITY_TYPES[0].value);
      setComment('');
    } else {
      setDisplayName(row?.displayName || '');
      setComment(row?.comment || '');
      setOwnerType(ownerTypeFromEntityId(row?.entityId) || ENTITY_TYPES[0].value);
    }
  }, [open, isNew, row]);

  const handleSave = async () => {
    const name = displayName.trim();
    if (!name) {
      setFormError('Укажите название владельца');
      return;
    }
    if (isNew && !ENTITY_TYPE_LABELS[ownerType]) {
      setFormError('Выберите тип владельца');
      return;
    }
    if (isNew && !entityIdPreview) {
      setFormError('Не удалось сформировать идентификатор из названия');
      return;
    }

    setSaving(true);
    setFormError('');
    try {
      await ApiClient.saveNetEntity({
        entityId: isNew ? undefined : row.entityId,
        displayName: name,
        ownerType: isNew ? ownerType : undefined,
        comment,
        enabled: 1,
      });
      onSaved();
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
      title={isNew ? 'Добавить владельца' : 'Редактировать владельца'}
      subtitle={isNew ? 'Новая запись справочника' : row?.entityId}
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
      <div className="grid grid--1col">
        {!isNew && (
          <div className="field">
            <label>Entity ID</label>
            <input className="input mono" value={row?.entityId || ''} readOnly disabled />
          </div>
        )}
        <div className="field">
          <label>Название</label>
          <input
            className="input"
            placeholder="ПИН, Клиент А, Офис…"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </div>
        <div className="field">
          <label>Тип владельца</label>
          {isNew ? (
            <select className="input" value={ownerType} onChange={(e) => setOwnerType(e.target.value)}>
              {ENTITY_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          ) : (
            <input
              className="input"
              value={ENTITY_TYPE_LABELS[ownerTypeReadonly] || '—'}
              readOnly
              disabled
            />
          )}
        </div>
        {isNew && entityIdPreview && (
          <div className="field">
            <label>Будет создан ID</label>
            <input className="input mono" value={entityIdPreview} readOnly disabled />
          </div>
        )}
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

Object.assign(window, { PageEntities, ENTITY_TYPES });
