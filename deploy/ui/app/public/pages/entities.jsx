/* Владельцы L3 — справочник net_entities (ClickHouse) */

const ENTITY_TYPES = [
  { value: 'isp', labelKey: 'network.entities.type.isp' },
  { value: 'customer', labelKey: 'network.entities.type.customer' },
  { value: 'internal', labelKey: 'network.entities.type.internal' },
];

const ENTITY_TYPE_VALUES = new Set(ENTITY_TYPES.map((t) => t.value));

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
  if (!ENTITY_TYPE_VALUES.has(ownerType)) return '';
  const slug = buildEntitySlug(displayName);
  if (!slug) return '';
  return `${ownerType}:${slug}`;
}

function ownerTypeFromEntityId(entityId) {
  const idx = String(entityId).indexOf(':');
  if (idx < 0) return null;
  const prefix = entityId.slice(0, idx);
  return ENTITY_TYPE_VALUES.has(prefix) ? prefix : null;
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
    if (!window.confirm(networkT('network.entities.disableConfirm', { name: row.displayName }))) return;
    try {
      await ApiClient.saveNetEntity({
        entityId: row.entityId,
        displayName: row.displayName,
        comment: row.comment,
        enabled: 0,
      });
      pushToast({
        kind: 'success',
        title: networkT('network.saveSuccess.title'),
        desc: networkT('network.saveSuccess.desc'),
      });
      reload();
    } catch (err) {
      pushToast({
        kind: 'error',
        title: networkT('network.entities.disableFailed'),
        desc: formatNetworkApiError(err),
      });
    }
  };

  const cols = [
    {
      key: 'displayName',
      title: networkT('network.col.name'),
      width: 220,
      sortAccessor: (r) => r.displayName,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName || networkEmDash()}</span>
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
      title: networkT('network.col.comment'),
      width: 220,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.comment || networkEmDash()}
        </span>
      ),
    },
    {
      key: 'source',
      title: networkT('network.col.source'),
      width: 90,
      render: (r) => <span className="tag">{networkSourceLabel(r.source)}</span>,
    },
    {
      key: 'updatedAt',
      title: networkT('network.col.changedAt'),
      width: 150,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {fmtNetworkDateTime(r.updatedAt)}
        </span>
      ),
    },
  ];

  const body = (
    <>
      {!embedded && (
        <div className="page-head">
          <div>
            <h1>{networkT('network.entities.title')}</h1>
            <p>{networkT('network.entities.subtitle')}</p>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>{networkT('chrome.refresh')}</Button>
            <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>
              {networkT('network.entities.add')}
            </Button>
          </div>
        </div>
      )}

      {embedded && (
        <div className="row" style={{ justifyContent: 'flex-end', marginBottom: 12 }}>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>
            {networkT('network.entities.add')}
          </Button>
        </div>
      )}

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>{networkT('dashboard.loading')}</div>
        </Card>
      ) : loadError ? (
        <Empty
          icon="db"
          title={networkT('dashboard.loadFailed')}
          desc={resolveNetworkLoadError(loadError)}
          action={<Button kind="primary" icon="refresh" onClick={reload}>{networkT('network.retry')}</Button>}
        />
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
          emptyTitle={networkT('network.entities.empty.title')}
          emptyDesc={networkT('network.entities.empty.desc')}
          toolbar={{
            search,
            onSearch: setSearch,
          }}
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              <button className="icon-btn tt" data-tt={networkT('network.editTip')} onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: false }); }}>
                <Icon name="edit" size={15} />
              </button>
              <button className="icon-btn tt" data-tt={networkT('network.disableTip')} onClick={(e) => { e.stopPropagation(); handleDisable(r); }}>
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
          pushToast({
            kind: 'success',
            title: networkT('network.saveSuccess.title'),
            desc: networkT('network.saveSuccess.desc'),
          });
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
      setFormError(networkT('network.err.displayNameRequired'));
      return;
    }
    if (isNew && !ENTITY_TYPE_VALUES.has(ownerType)) {
      setFormError(networkT('network.err.ownerTypeRequired'));
      return;
    }
    if (isNew && !entityIdPreview) {
      setFormError(networkT('network.err.slugFromNameFailed'));
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
      setFormError(formatNetworkApiError(err));
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? networkT('network.entities.modal.add') : networkT('network.entities.modal.edit')}
      subtitle={isNew ? networkT('network.entities.modal.subtitleNew') : row?.entityId}
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>{networkT('network.cancel')}</Button>
          <Button kind="primary" icon="save" onClick={handleSave} disabled={saving}>
            {saving ? networkT('network.saving') : networkT('network.save')}
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
          <label>{networkT('network.entities.field.name')}</label>
          <input
            className="input"
            placeholder={networkT('network.entities.placeholder.name')}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </div>
        <div className="field">
          <label>{networkT('network.entities.field.ownerType')}</label>
          {isNew ? (
            <select className="input" value={ownerType} onChange={(e) => setOwnerType(e.target.value)}>
              {ENTITY_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{networkT(t.labelKey)}</option>
              ))}
            </select>
          ) : (
            <input
              className="input"
              value={entityTypeLabel(ownerTypeReadonly)}
              readOnly
              disabled
            />
          )}
        </div>
        {isNew && entityIdPreview && (
          <div className="field">
            <label>{networkT('network.entities.field.idPreview')}</label>
            <input className="input mono" value={entityIdPreview} readOnly disabled />
          </div>
        )}
        <div className="field">
          <label>{networkT('network.col.comment')}</label>
          <input
            className="input"
            placeholder={networkT('network.optional')}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </div>
      </div>
    </Modal>
  );
}

Object.assign(window, { PageEntities, ENTITY_TYPES });
