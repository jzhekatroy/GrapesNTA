/* Собственные сети (CIDR) — L3-префиксы из ClickHouse */

const L3_ROLES = [
  { value: 'provider_public', labelKey: 'network.cidr.role.provider_public' },
  { value: 'internal', labelKey: 'network.cidr.role.internal' },
  { value: 'customer_allocated', labelKey: 'network.cidr.role.customer_allocated' },
  { value: 'customer_transit', labelKey: 'network.cidr.role.customer_transit' },
  { value: 'remote', labelKey: 'network.cidr.role.remote' },
];

const L3_ROLE_VALUES = new Set(L3_ROLES.map((r) => r.value));

function l3RowKey(row) {
  return `${row.family}:${row.prefix}`;
}

function networkErrMessage(code) {
  return networkT(`network.err.${code}`);
}

function parseCidrClient(prefix) {
  const trimmed = String(prefix ?? '').trim();
  if (!trimmed) return { ok: false, code: 'prefixRequired' };
  const slash = trimmed.indexOf('/');
  if (slash < 0) return { ok: false, code: 'prefixCidrFormatShort' };
  const ipPart = trimmed.slice(0, slash);
  const mask = Number(trimmed.slice(slash + 1));
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ipPart);
  const v6 = ipPart.includes(':');
  if (v4 && mask >= 0 && mask <= 32) return { ok: true, prefix: `${ipPart}/${mask}`, family: 4 };
  if (v6 && mask >= 0 && mask <= 128) return { ok: true, prefix: trimmed, family: 6 };
  return { ok: false, code: 'invalidCidrMask' };
}

function comingSoonToast(titleKey) {
  pushToast({
    kind: 'info',
    title: networkT(titleKey),
    desc: networkT('network.comingSoon.desc'),
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
      const roleLabel = l3RoleLabel(r.role);
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
    const confirmKey = next === 1 ? 'network.cidr.confirmEnable' : 'network.cidr.confirmDisable';
    if (!window.confirm(networkT(confirmKey, { prefix: row.prefix }))) return;
    setTogglingId(row.id);
    try {
      await ApiClient.toggleL3Prefix({ prefix: row.prefix, family: row.family, enabled: next });
      pushToast({
        kind: 'success',
        title: networkT('network.saveSuccess.title'),
        desc: networkT('network.saveSuccess.desc'),
      });
      reload();
    } catch (err) {
      pushToast({
        kind: 'error',
        title: networkT('network.cidr.toggleFailed'),
        desc: formatNetworkApiError(err),
      });
    } finally {
      setTogglingId(null);
    }
  };

  const handleDelete = async (row) => {
    if (!window.confirm(networkT('network.cidr.confirmDelete', { prefix: row.prefix }))) return;
    try {
      await ApiClient.deleteL3Prefix({ prefix: row.prefix, family: row.family });
      pushToast({
        kind: 'success',
        title: networkT('network.cidr.deleted.title'),
        desc: networkT('network.cidr.deleted.desc'),
      });
      reload();
    } catch (err) {
      pushToast({
        kind: 'error',
        title: networkT('network.cidr.deleteFailed'),
        desc: formatNetworkApiError(err),
      });
    }
  };

  const cols = [
    {
      key: 'prefix',
      title: networkT('network.cidr.col.prefix'),
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
      title: networkT('network.cidr.col.active'),
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
      title: networkT('network.cidr.col.ip'),
      width: 72,
      render: (r) => <span className="tag">IPv{r.family}</span>,
    },
    {
      key: 'entity',
      title: networkT('network.cidr.col.owner'),
      width: 220,
      sortAccessor: (r) => r.entityName || r.entityId,
      render: (r) => (
        <div>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.entityName || r.entityId || networkEmDash()}</div>
        </div>
      ),
    },
    {
      key: 'role',
      title: networkT('network.cidr.col.role'),
      width: 200,
      sortAccessor: (r) => l3RoleLabel(r.role),
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)' }}>
          {l3RoleLabel(r.role)}
        </span>
      ),
    },
    {
      key: 'displayName',
      title: networkT('network.cidr.col.displayName'),
      width: 160,
      render: (r) => r.displayName || <span style={{ color: 'var(--fg-secondary)' }}>{networkEmDash()}</span>,
    },
    {
      key: 'comment',
      title: networkT('network.col.comment'),
      width: 180,
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
      title: networkT('network.col.updated'),
      width: 140,
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
            <h1>{networkT('network.cidr.title')}</h1>
            <p>{networkT('network.cidr.subtitle')}</p>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Button
              kind="ghost"
              icon="upload"
              disabled
              title={networkT('network.comingSoon')}
              onClick={() => comingSoonToast('network.cidr.importToast.title')}
            >
              {networkT('network.cidr.importCsv')}
            </Button>
            <Button
              kind="ghost"
              icon="export"
              disabled
              title={networkT('network.comingSoon')}
              onClick={() => comingSoonToast('network.cidr.exportToast.title')}
            >
              {networkT('network.cidr.export')}
            </Button>
            <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>{networkT('chrome.refresh')}</Button>
            <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>
              {networkT('network.cidr.add')}
            </Button>
          </div>
        </div>
      )}

      {embedded && (
        <div className="row" style={{ justifyContent: 'flex-end', marginBottom: 12, gap: 8 }}>
          <Button
            kind="ghost"
            icon="upload"
            disabled
            title={networkT('network.comingSoon')}
            onClick={() => comingSoonToast('network.cidr.importToast.title')}
          >
            {networkT('network.cidr.importCsv')}
          </Button>
          <Button
            kind="ghost"
            icon="export"
            disabled
            title={networkT('network.comingSoon')}
            onClick={() => comingSoonToast('network.cidr.exportToast.title')}
          >
            {networkT('network.cidr.export')}
          </Button>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>
            {networkT('network.cidr.add')}
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
          emptyTitle={networkT('network.cidr.empty.title')}
          emptyDesc={networkT('network.cidr.empty.desc')}
          toolbar={{
            search,
            onSearch: setSearch,
            left: selected.size > 0 ? (
              <div className="row" style={{ gap: 8 }}>
                <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
                  {networkT('network.cidr.selectedCount', { n: selected.size })}
                </span>
                <Button
                  size="sm"
                  kind="ghost"
                  disabled
                  onClick={() => pushToast({ kind: 'info', title: networkT('network.cidr.bulkEdit'), desc: networkT('network.comingSoon.desc') })}
                >
                  {networkT('network.cidr.bulkEdit')}
                </Button>
              </div>
            ) : null,
          }}
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              <button className="icon-btn tt" data-tt={networkT('network.editTip')} onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: false }); }}>
                <Icon name="edit" size={15} />
              </button>
              <button className="icon-btn tt" data-tt={networkT('network.deleteTip')} onClick={(e) => { e.stopPropagation(); handleDelete(r); }}>
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

function L3EnabledToggle({ enabled, disabled, onChange }) {
  return (
    <button
      type="button"
      className="l3-enabled-toggle"
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onChange(); }}
      title={enabled ? networkT('network.cidr.toggleDisable') : networkT('network.cidr.toggleEnable')}
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
      setRole(L3_ROLE_VALUES.has(row.role) ? row.role : L3_ROLES[0].value);
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
    if (!parsed.ok) return networkErrMessage(parsed.code);
    if (isNew && parsed.family !== family) return networkErrMessage('familyMismatch');
    if (!isNew && (parsed.prefix !== row.prefix || parsed.family !== row.family)) {
      return networkErrMessage('prefixImmutable');
    }
    if (!entityId) return networkErrMessage('entityRequired');
    if (!L3_ROLE_VALUES.has(role)) return networkErrMessage('roleRequired');
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
      setFormError(formatNetworkApiError(e));
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? networkT('network.cidr.modal.add') : networkT('network.cidr.modal.edit')}
      subtitle={isNew ? networkT('network.cidr.modal.subtitleNew') : row?.prefix}
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
      <div className="grid grid--2col">
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>{networkT('network.cidr.field.prefix')}</label>
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
          <label>{networkT('network.cidr.field.ipVersion')}</label>
          <input className="input" value={`IPv${family}`} readOnly disabled />
        </div>
        <div className="field">
          <label>{networkT('network.cidr.field.role')}</label>
          <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            {L3_ROLES.map((r) => (
              <option key={r.value} value={r.value}>{networkT(r.labelKey)}</option>
            ))}
          </select>
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>{networkT('network.cidr.field.owner')}</label>
          <select className="input" value={entityId} onChange={(e) => setEntityId(e.target.value)}>
            <option value="">{networkT('network.cidr.selectOwner')}</option>
            {entities.map((e) => (
              <option key={e.entityId} value={e.entityId}>
                {e.displayName || e.entityId}
              </option>
            ))}
          </select>
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>{networkT('network.cidr.col.displayName')}</label>
          <input className="input" placeholder={networkT('network.optional')} value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>{networkT('network.col.comment')}</label>
          <input className="input" placeholder={networkT('network.optional')} value={comment} onChange={(e) => setComment(e.target.value)} />
        </div>
      </div>
    </Modal>
  );
}

Object.assign(window, { PageCIDR, L3_ROLES });
