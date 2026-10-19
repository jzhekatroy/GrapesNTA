/* DNS-резолверы — справочник для классификации адресов на странице DNS-запросов */

function dnsResolversT(key, params) {
  return GrapesI18n.t(key, params);
}

const DNS_RESOLVER_ROLE_VALUES = ['resolver', 'client', 'public'];

const DNS_RESOLVER_API_ERROR_KEYS = {
  'Укажите префикс (CIDR)': 'dnsResolvers.err.prefixRequired',
  'Префикс должен быть в формате CIDR': 'dnsResolvers.err.prefixCidrFormat',
  'Префикс должен быть в формате CIDR (например 8.8.8.8/32)': 'dnsResolvers.err.prefixCidrFormatExample',
  'Некорректная длина маски в CIDR': 'dnsResolvers.err.maskLengthInvalid',
  'Для IPv4 маска должна быть от 0 до 32': 'dnsResolvers.err.ipv4MaskRange',
  'Для IPv6 маска должна быть от 0 до 128': 'dnsResolvers.err.ipv6MaskRange',
  'Некорректный IP-адрес в префиксе': 'dnsResolvers.err.ipInvalid',
  'Некорректный CIDR или маска': 'dnsResolvers.err.cidrInvalid',
  'Не указан идентификатор резолвера': 'dnsResolvers.err.resolverIdRequired',
  'Версия IP не соответствует адресу': 'dnsResolvers.err.ipFamilyMismatch',
  'Версия IP не соответствует адресу в префиксе': 'dnsResolvers.err.ipFamilyMismatchPrefix',
  'Префикс нельзя изменить': 'dnsResolvers.err.prefixImmutable',
  'Выберите роль': 'dnsResolvers.err.roleRequired',
  'Недопустимая роль резолвера': 'dnsResolvers.err.roleInvalid',
  'Резолвер не найден': 'dnsResolvers.err.notFound',
  'Сначала отредактируйте резолвер и выберите допустимую роль': 'dnsResolvers.err.fixRoleBeforeEnable',
  'Ошибка сохранения': 'dnsResolvers.err.saveFailed',
};

function localizeDnsResolverApiError(message) {
  const trimmed = String(message ?? '').trim();
  const key = DNS_RESOLVER_API_ERROR_KEYS[trimmed];
  return key ? dnsResolversT(key) : trimmed;
}

function dnsResolverRoleLabel(role) {
  const key = `dnsResolvers.role.${role}`;
  return GrapesI18n.has(key) ? dnsResolversT(key) : role;
}

function dnsResolverRolesForSelect() {
  return DNS_RESOLVER_ROLE_VALUES.map((value) => ({
    value,
    label: dnsResolverRoleLabel(value),
  }));
}

function isKnownDnsResolverRole(role) {
  return DNS_RESOLVER_ROLE_VALUES.includes(role);
}

function dnsResolverRowKey(row) {
  return row.resolverId;
}

function parseCidrClient(prefix) {
  const trimmed = String(prefix ?? '').trim();
  if (!trimmed) return { ok: false, errorKey: 'dnsResolvers.err.prefixRequired' };
  const slash = trimmed.indexOf('/');
  if (slash < 0) return { ok: false, errorKey: 'dnsResolvers.err.prefixCidrFormat' };
  const ipPart = trimmed.slice(0, slash);
  const mask = Number(trimmed.slice(slash + 1));
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ipPart);
  const v6 = ipPart.includes(':');
  if (v4 && mask >= 0 && mask <= 32) return { ok: true, prefix: `${ipPart}/${mask}`, family: 4 };
  if (v6 && mask >= 0 && mask <= 128) return { ok: true, prefix: trimmed, family: 6 };
  return { ok: false, errorKey: 'dnsResolvers.err.cidrInvalid' };
}

function fmtDnsResolverUpdatedAt(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(GrapesI18n.intlLocale(), {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function PageDnsResolvers() {
  const canWrite = AuthAccess.canWritePage('dns-resolvers');
  const i18nLocale = GrapesI18n.getLocale();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
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
      setLoadError(false);
      const res = await ApiClient.loadDnsResolvers();
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(true);
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
      const roleLabel = dnsResolverRoleLabel(r.role);
      return (
        r.prefix.toLowerCase().includes(s)
        || (r.displayName || '').toLowerCase().includes(s)
        || (r.comment || '').toLowerCase().includes(s)
        || roleLabel.toLowerCase().includes(s)
      );
    });
  }, [rows, search, i18nLocale]);

  const handleToggle = async (row) => {
    const next = row.enabled === 1 ? 0 : 1;
    const confirmKey = next === 1 ? 'dnsResolvers.confirm.enable' : 'dnsResolvers.confirm.disable';
    if (!window.confirm(dnsResolversT(confirmKey, { prefix: row.prefix }))) return;
    setTogglingId(row.id);
    try {
      await ApiClient.toggleDnsResolver({ resolverId: row.resolverId, enabled: next });
      pushToast({
        kind: 'success',
        title: dnsResolversT('dnsResolvers.saveSuccessTitle'),
        desc: dnsResolversT('dnsResolvers.saveSuccessDesc'),
      });
      reload();
    } catch (err) {
      pushToast({
        kind: 'error',
        title: dnsResolversT('dnsResolvers.toast.toggleFailed'),
        desc: localizeDnsResolverApiError(err.message),
      });
    } finally {
      setTogglingId(null);
    }
  };

  const handleDelete = async (row) => {
    if (!window.confirm(dnsResolversT('dnsResolvers.confirm.delete', { prefix: row.prefix }))) return;
    try {
      await ApiClient.deleteDnsResolver({ resolverId: row.resolverId });
      pushToast({
        kind: 'success',
        title: dnsResolversT('dnsResolvers.toast.deletedTitle'),
        desc: dnsResolversT('dnsResolvers.toast.deletedDesc'),
      });
      reload();
    } catch (err) {
      pushToast({
        kind: 'error',
        title: dnsResolversT('dnsResolvers.toast.deleteFailed'),
        desc: localizeDnsResolverApiError(err.message),
      });
    }
  };

  const cols = useMemo(() => [
    {
      key: 'prefix',
      title: dnsResolversT('dnsResolvers.col.prefix'),
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
      title: dnsResolversT('dnsResolvers.col.enabled'),
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
      title: dnsResolversT('dnsResolvers.col.role'),
      width: 180,
      sortAccessor: (r) => dnsResolverRoleLabel(r.role),
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)' }}>
          {dnsResolverRoleLabel(r.role)}
        </span>
      ),
    },
    {
      key: 'displayName',
      title: dnsResolversT('dnsResolvers.col.displayName'),
      width: 180,
      render: (r) => r.displayName || <span style={{ color: 'var(--fg-secondary)' }}>—</span>,
    },
    {
      key: 'comment',
      title: dnsResolversT('dnsResolvers.col.comment'),
      width: 180,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.comment || '—'}
        </span>
      ),
    },
    {
      key: 'source',
      title: dnsResolversT('dnsResolvers.col.source'),
      width: 90,
      render: (r) => <span className="tag">{r.source || '—'}</span>,
    },
    {
      key: 'updatedAt',
      title: dnsResolversT('dnsResolvers.col.updatedAt'),
      width: 140,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {fmtDnsResolverUpdatedAt(r.updatedAt)}
        </span>
      ),
    },
  ], [canWrite, togglingId, i18nLocale]);

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{dnsResolversT('nav.item.dns-resolvers')}</h1>
          <p>{dnsResolversT('dnsResolvers.subtitle')}</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>{dnsResolversT('chrome.refresh')}</Button>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>{dnsResolversT('dnsResolvers.addResolver')}</Button>
        </div>
      </div>

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>{dnsResolversT('dnsResolvers.loading')}</div>
        </Card>
      ) : loadError ? (
        <Empty
          icon="db"
          title={dnsResolversT('dnsResolvers.loadFailed')}
          desc={dnsResolversT('dnsResolvers.loadFailed')}
          action={<Button kind="primary" icon="refresh" onClick={reload}>{dnsResolversT('dnsResolvers.retry')}</Button>}
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
          emptyTitle={dnsResolversT('dnsResolvers.emptyTitle')}
          emptyDesc={dnsResolversT('dnsResolvers.emptyDesc')}
          toolbar={{
            search,
            onSearch: setSearch,
          }}
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              <button className="icon-btn tt" data-tt={dnsResolversT('dnsResolvers.action.edit')} onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: false }); }}>
                <Icon name="edit" size={15} />
              </button>
              <button className="icon-btn tt" data-tt={dnsResolversT('dnsResolvers.action.delete')} onClick={(e) => { e.stopPropagation(); handleDelete(r); }}>
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
          pushToast({
            kind: 'success',
            title: dnsResolversT('dnsResolvers.saveSuccessTitle'),
            desc: dnsResolversT('dnsResolvers.saveSuccessDesc'),
          });
        }}
      />
    </div>
  );
}

function DnsResolverEnabledToggle({ enabled, disabled, onChange }) {
  const title = enabled
    ? dnsResolversT('dnsResolvers.toggle.disable')
    : dnsResolversT('dnsResolvers.toggle.enable');
  return (
    <button
      type="button"
      className="l3-enabled-toggle"
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onChange(); }}
      title={title}
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

function DnsResolverFormModal({ open, row, isNew, onClose, onSaved }) {
  const i18nLocale = GrapesI18n.getLocale();
  const roleOptions = useMemo(() => dnsResolverRolesForSelect(), [i18nLocale]);
  const [prefix, setPrefix] = useState('');
  const [family, setFamily] = useState(4);
  const [role, setRole] = useState(DNS_RESOLVER_ROLE_VALUES[0]);
  const [displayName, setDisplayName] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    if (isNew) {
      setPrefix('');
      setFamily(4);
      setRole(DNS_RESOLVER_ROLE_VALUES[0]);
      setDisplayName('');
      setComment('');
    } else if (row) {
      setPrefix(row.prefix);
      setFamily(row.family);
      setRole(isKnownDnsResolverRole(row.role) ? row.role : DNS_RESOLVER_ROLE_VALUES[0]);
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
    if (!parsed.ok) return dnsResolversT(parsed.errorKey);
    if (isNew && parsed.family !== family) return dnsResolversT('dnsResolvers.err.ipFamilyMismatch');
    if (!isNew && parsed.prefix !== row.prefix) return dnsResolversT('dnsResolvers.err.prefixImmutable');
    if (!isKnownDnsResolverRole(role)) return dnsResolversT('dnsResolvers.err.roleRequired');
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
      setFormError(localizeDnsResolverApiError(e.message) || dnsResolversT('dnsResolvers.err.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? dnsResolversT('dnsResolvers.modal.addTitle') : dnsResolversT('dnsResolvers.modal.editTitle')}
      subtitle={isNew ? dnsResolversT('dnsResolvers.modal.newSubtitle') : row?.prefix}
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>{dnsResolversT('dnsResolvers.cancel')}</Button>
          <Button kind="primary" icon="save" onClick={handleSave} disabled={saving}>
            {saving ? dnsResolversT('dnsResolvers.saving') : dnsResolversT('dnsResolvers.save')}
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
          <label>{dnsResolversT('dnsResolvers.modal.prefixLabel')}</label>
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
          <label>{dnsResolversT('dnsResolvers.modal.ipVersion')}</label>
          <input className="input" value={`IPv${family}`} readOnly disabled />
        </div>
        <div className="field">
          <label>{dnsResolversT('dnsResolvers.col.role')}</label>
          <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            {roleOptions.map((r) => (
              <option key={r.value} value={r.value}>{r.label}</option>
            ))}
          </select>
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>{dnsResolversT('dnsResolvers.col.displayName')}</label>
          <input className="input" placeholder={dnsResolversT('dnsResolvers.modal.optional')} value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>{dnsResolversT('dnsResolvers.col.comment')}</label>
          <input className="input" placeholder={dnsResolversT('dnsResolvers.modal.optional')} value={comment} onChange={(e) => setComment(e.target.value)} />
        </div>
      </div>
    </Modal>
  );
}

Object.assign(window, { PageDnsResolvers, DNS_RESOLVER_ROLES: DNS_RESOLVER_ROLE_VALUES });
