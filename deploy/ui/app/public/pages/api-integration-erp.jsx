/* Раздел «API интеграция ERP»: управление подключениями (API-клиентами).
   Контракт и решения — docs/API_INTEGRATION_ERP_UI.md (раздел 8 — редизайн
   по референсу страницы «Клиенты»: шапка page-head, DataTable, модалки). */

const API_ERP_CLIENT_ID_MIN = 12;
const API_ERP_CLIENT_ID_MAX = 64;
const API_ERP_CLIENT_SECRET_MIN = 12;
const API_ERP_CLIENT_SECRET_MAX = 512;
const API_ERP_MANUAL_ID_RE = /^[A-Za-z0-9._:-]+$/;

function apiErpT(key, params) {
  return GrapesI18n.t(key, params);
}

function apiErpFormatDate(value) {
  if (!value) return '—';
  const iso = String(value).includes('T') ? String(value) : `${String(value).replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString(GrapesI18n.intlLocale(), { timeZone: 'Europe/Moscow' });
}

function apiErpFormatWhen(value) {
  if (!value) return '—';
  const iso = String(value).includes('T') ? String(value) : `${String(value).replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(value);
  return `${date.toLocaleString(GrapesI18n.intlLocale(), { timeZone: 'Europe/Moscow' })} ${apiErpT('apiErpPage.tzSuffix')}`;
}

function apiErpFormatAgo(ms) {
  if (!ms) return apiErpT('apiErpPage.ago.never');
  const diff = Date.now() - Number(ms);
  if (diff < 0) return apiErpFormatWhen(new Date(Number(ms)).toISOString());
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return apiErpT('apiErpPage.ago.justNow');
  if (minutes < 60) return apiErpT('apiErpPage.ago.min', { n: minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return apiErpT('apiErpPage.ago.hour', { n: hours });
  return apiErpT('apiErpPage.ago.day', { n: Math.floor(hours / 24) });
}

function apiErpActionLabel(action) {
  const key = `auditPage.action.${action}`;
  return GrapesI18n.has(key) ? GrapesI18n.t(key) : (action || '—');
}

async function apiErpCopy(label, value) {
  try {
    await copyTextToClipboard(value);
    pushToast?.({ kind: 'success', title: apiErpT('apiErpPage.toast.copied', { label }) });
  } catch (err) {
    pushToast?.({ kind: 'error', title: apiErpT('apiErpPage.toast.copyFailed'), desc: err.message });
  }
}

function ApiErpCopyRow({ label, value }) {
  return (
    <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      <span style={{ minWidth: 110, color: 'var(--fg-secondary)' }}>{label}</span>
      <span className="mono" style={{ wordBreak: 'break-all' }}>{value}</span>
      <Button kind="ghost" size="sm" icon="copy" onClick={() => apiErpCopy(label, value)}>{apiErpT('apiErpPage.copy')}</Button>
    </div>
  );
}

// Креды после создания/пересоздания. Секрет показывается один раз.
function ApiErpIssuedModal({ issued, onClose }) {
  if (!issued) return null;
  const hasSecret = Boolean(issued.clientSecret);
  const copyAll = () => {
    const lines = [
      apiErpT('apiErpPage.issued.copyConnection', { name: issued.clientName }),
      `client_id: ${issued.clientId}`,
    ];
    if (hasSecret) lines.push(`client_secret: ${issued.clientSecret}`);
    apiErpCopy(apiErpT('apiErpPage.issued.copyAllLabel'), lines.join('\n'));
  };
  return (
    <Modal
      open
      onClose={onClose}
      title={issued.previousClientId ? apiErpT('apiErpPage.issued.titleRecreate') : apiErpT('apiErpPage.issued.titleNew')}
      subtitle={issued.clientName}
      footer={
        <>
          <Button kind="ghost" icon="copy" onClick={copyAll}>{apiErpT('apiErpPage.issued.copyAll')}</Button>
          <Button kind="primary" onClick={onClose}>{apiErpT('apiErpPage.issued.ok')}</Button>
        </>
      }
    >
      <div className="col" style={{ gap: 12, font: 'var(--pv-text-body-3)' }}>
        {hasSecret
          ? (
            <div style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--st-warning-bg)', color: 'var(--st-warning)' }}>
              {apiErpT('apiErpPage.issued.secretOnce')}
            </div>
          )
          : (
            <div style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--st-warning-bg)', color: 'var(--st-warning)' }}>
              {apiErpT('apiErpPage.issued.secretManual')}
            </div>
          )}
        <ApiErpCopyRow label="client_id" value={issued.clientId} />
        {hasSecret
          ? <ApiErpCopyRow label="client_secret" value={issued.clientSecret} />
          : null}
        {issued.previousClientId
          ? (
            <div style={{ color: 'var(--fg-secondary)' }}>
              {apiErpT('apiErpPage.issued.previousDisabled.before')}
              <span className="mono">{issued.previousClientId}</span>
              {apiErpT('apiErpPage.issued.previousDisabled.after')}
            </div>
          )
          : null}
      </div>
    </Modal>
  );
}

// Создание: сгенерировать автоматически или указать свои креды.
function ApiErpCreateModal({ open, onClose, onCreated }) {
  const [mode, setMode] = useState('generate');
  const [name, setName] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    setMode('generate');
    setName('');
    setClientId('');
    setClientSecret('');
    setFormError('');
  }, [open]);

  const trimmedId = clientId.trim();
  const valid = Boolean(name.trim())
    && (mode === 'generate'
      || (trimmedId.length >= API_ERP_CLIENT_ID_MIN
        && trimmedId.length <= API_ERP_CLIENT_ID_MAX
        && API_ERP_MANUAL_ID_RE.test(trimmedId)
        && clientSecret.length >= API_ERP_CLIENT_SECRET_MIN
        && clientSecret.length <= API_ERP_CLIENT_SECRET_MAX));

  const submit = async () => {
    setSaving(true);
    setFormError('');
    try {
      if (mode === 'manual') {
        const res = await ApiClient.registerApiClientManual({
          name: name.trim(),
          clientId: trimmedId,
          clientSecret,
        });
        onCreated({ clientName: res.data.clientName, clientId: res.data.clientId });
      } else {
        const res = await ApiClient.createApiClient({ name: name.trim() });
        onCreated(res.data);
      }
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
      title={apiErpT('apiErpPage.create.title')}
      subtitle={apiErpT('apiErpPage.create.subtitle')}
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>{apiErpT('apiErpPage.create.cancel')}</Button>
          <Button kind="primary" icon="plus" onClick={submit} disabled={saving || !valid}>
            {saving ? apiErpT('apiErpPage.create.saving') : apiErpT('apiErpPage.create.submit')}
          </Button>
        </>
      }
    >
      {formError
        ? (
          <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
            {formError}
          </div>
        )
        : null}
      <div className="grid grid--1col">
        <div className="row" style={{ gap: 8, marginBottom: 12 }}>
          <Button kind={mode === 'generate' ? 'primary' : 'ghost'} onClick={() => setMode('generate')} disabled={saving}>{apiErpT('apiErpPage.create.modeGenerate')}</Button>
          <Button kind={mode === 'manual' ? 'primary' : 'ghost'} onClick={() => setMode('manual')} disabled={saving}>{apiErpT('apiErpPage.create.modeManual')}</Button>
        </div>
        <div className="field">
          <label>{apiErpT('apiErpPage.create.name')}</label>
          <input
            className="input"
            placeholder={apiErpT('apiErpPage.create.namePlaceholder')}
            value={name}
            disabled={saving}
            onChange={(e) => setName(e.target.value)}
          />
          <div className="hint">{apiErpT('apiErpPage.create.nameHint')}</div>
        </div>
        {mode === 'manual'
          ? (
            <>
              <div className="field">
                <label>client_id</label>
                <input
                  className="input mono"
                  placeholder={apiErpT('apiErpPage.create.idPlaceholder', { min: API_ERP_CLIENT_ID_MIN, max: API_ERP_CLIENT_ID_MAX })}
                  value={clientId}
                  disabled={saving}
                  onChange={(e) => setClientId(e.target.value)}
                />
                <div className="hint">{apiErpT('apiErpPage.create.idHint')}</div>
              </div>
              <div className="field">
                <label>client_secret</label>
                <input
                  className="input mono"
                  type="password"
                  placeholder={apiErpT('apiErpPage.create.secretPlaceholder', { min: API_ERP_CLIENT_SECRET_MIN })}
                  value={clientSecret}
                  disabled={saving}
                  autoComplete="off"
                  onChange={(e) => setClientSecret(e.target.value)}
                />
                <div className="hint">{apiErpT('apiErpPage.create.secretHint')}</div>
              </div>
            </>
          )
          : (
            <div className="hint" style={{ color: 'var(--fg-secondary)' }}>
              {apiErpT('apiErpPage.create.generateHint')}
            </div>
          )}
      </div>
    </Modal>
  );
}

// Карточка подключения: дублирует данные строки и действия, плюс монитор,
// полный журнал и проверка пары.
function ApiErpClientModal({
  row,
  canWrite,
  busy,
  detailsTick,
  onClose,
  onRecreate,
  onToggle,
  onRevokeTokens,
  onDelete,
}) {
  const [monitor, setMonitor] = useState(null);
  const [journal, setJournal] = useState(null);
  const [pairSecret, setPairSecret] = useState('');
  const [pairResult, setPairResult] = useState(null);
  const [detailsError, setDetailsError] = useState('');

  const loadDetails = useCallback(() => {
    setDetailsError('');
    return Promise.all([
      ApiClient.monitorApiClient(row.clientId),
      ApiClient.loadApiClientsJournal(row.clientId),
    ]).then(([mon, log]) => {
      setMonitor(mon.data);
      setJournal(log.data || []);
    }).catch((e) => setDetailsError(e.message));
  }, [row.clientId]);

  useEffect(() => { loadDetails(); }, [loadDetails, detailsTick]);

  const verifyPair = async () => {
    try {
      const res = await ApiClient.verifyApiClientPair({ clientId: row.clientId, clientSecret: pairSecret });
      setPairResult(res.data);
    } catch (e) {
      setDetailsError(e.message);
    }
  };

  const nta = monitor?.nta || {};
  const erp = monitor?.erp || {};
  const busyAll = busy !== '';

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={row.clientName}
      subtitle={<span className="mono">{row.clientId}</span>}
      footer={
        <>
          {canWrite
            ? (
              <>
                <Button
                  kind="ghost"
                  icon="refresh"
                  disabled={busyAll || !row.active}
                  title={row.active ? apiErpT('apiErpPage.card.recreateTitle') : apiErpT('apiErpPage.card.onlyActive')}
                  onClick={() => onRecreate(row)}
                >
                  {apiErpT('apiErpPage.card.recreate')}
                </Button>
                <Button
                  kind="ghost"
                  icon="x"
                  disabled={busyAll || row.activeTokens === 0}
                  title={row.activeTokens === 0 ? apiErpT('apiErpPage.card.noTokens') : apiErpT('apiErpPage.card.revokeTitle')}
                  onClick={() => onRevokeTokens(row)}
                >
                  {apiErpT('apiErpPage.card.revokeTokens')}
                </Button>
                <Button
                  kind="ghost"
                  icon={row.active ? 'pause' : 'play'}
                  disabled={busyAll}
                  title={row.active ? apiErpT('apiErpPage.card.disableTitle') : apiErpT('apiErpPage.card.enableTitle')}
                  onClick={() => onToggle(row)}
                >
                  {row.active ? apiErpT('apiErpPage.card.disable') : apiErpT('apiErpPage.card.enable')}
                </Button>
                <Button
                  kind="ghost"
                  icon="trash"
                  disabled={busyAll}
                  title={apiErpT('apiErpPage.card.deleteTitle')}
                  onClick={() => onDelete(row)}
                >
                  {apiErpT('apiErpPage.card.delete')}
                </Button>
              </>
            )
            : null}
          <Button kind="primary" onClick={onClose}>{apiErpT('apiErpPage.card.close')}</Button>
        </>
      }
    >
      <div className="col" style={{ gap: 16 }}>
        {detailsError
          ? <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{detailsError}</div>
          : null}

        <div className="row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          {row.active
            ? <Badge tone="success" dot>{apiErpT('apiErpPage.status.active')}</Badge>
            : <Badge tone="neutral">{apiErpT('apiErpPage.status.inactive')}</Badge>}
          {row.manual ? <Tag>{apiErpT('apiErpPage.tag.manual')}</Tag> : null}
          <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {apiErpT('apiErpPage.card.meta', {
              created: apiErpFormatDate(row.createdAt),
              updated: apiErpFormatDate(row.updatedAt),
              ttl: nta.tokenTtlSec || '—',
            })}
          </span>
          <Button kind="ghost" size="sm" icon="copy" onClick={() => apiErpCopy('client_id', row.clientId)}>client_id</Button>
        </div>

        <Card title={apiErpT('apiErpPage.monitor.title')} pad="sm">
          {!monitor
            ? <div style={{ color: 'var(--fg-secondary)', padding: 8 }}>{apiErpT('apiErpPage.loading')}</div>
            : (
              <div className="row" style={{ gap: 24, flexWrap: 'wrap', alignItems: 'flex-start', padding: 8 }}>
                <div className="col" style={{ gap: 6, font: 'var(--pv-text-body-3)', minWidth: 260 }}>
                  <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{apiErpT('apiErpPage.monitor.ntaSide')}</div>
                  <div style={{ color: row.active ? 'var(--st-success)' : 'var(--st-critical)' }}>
                    {row.active ? apiErpT('apiErpPage.monitor.activeOk') : apiErpT('apiErpPage.monitor.inactiveFail')}
                  </div>
                  {row.active
                    ? (
                      <div style={{ color: nta.tokenIssued ? 'var(--st-success)' : 'var(--st-critical)' }}>
                        {nta.tokenIssued
                          ? apiErpT('apiErpPage.monitor.tokenOk')
                          : apiErpT('apiErpPage.monitor.tokenFail', { error: nta.tokenError || apiErpT('apiErpPage.monitor.unknownError') })}
                      </div>
                    )
                    : null}
                  <div>{apiErpT('apiErpPage.monitor.activeTokens', { n: nta.activeTokens ?? 0 })}
                    {nta.tokenExpiresSoonestAt
                      ? ` ${apiErpT('apiErpPage.monitor.expiresSoon', { when: apiErpFormatWhen(new Date(nta.tokenExpiresSoonestAt).toISOString()) })}`
                      : ''}
                  </div>
                </div>
                <div className="col" style={{ gap: 6, font: 'var(--pv-text-body-3)', minWidth: 260 }}>
                  <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{apiErpT('apiErpPage.monitor.consumerSide')}</div>
                  <div>{apiErpT('apiErpPage.monitor.lastUsed', { value: apiErpFormatAgo(erp.lastUsedAt) })}</div>
                  <div>{apiErpT('apiErpPage.monitor.exchangesToday', { n: erp.tokensIssuedToday ?? 0 })}</div>
                  <div>{apiErpT('apiErpPage.monitor.requestsToday', { n: erp.requestsToday ?? 0 })}</div>
                </div>
              </div>
            )}
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', padding: '0 8px 8px' }}>
            {apiErpT('apiErpPage.monitor.note')}
          </div>
        </Card>

        <Card title={apiErpT('apiErpPage.journal.connectionTitle')} pad="sm">
          {!journal
            ? <div style={{ color: 'var(--fg-secondary)', padding: 8 }}>{apiErpT('apiErpPage.loading')}</div>
            : (
              <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.when')}</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.who')}</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.action')}</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.object')}</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.result')}</th>
                  </tr>
                </thead>
                <tbody>
                  {journal.length === 0
                    ? <tr><td colSpan="5" style={{ padding: 8, color: 'var(--fg-secondary)' }}>{apiErpT('apiErpPage.journal.empty')}</td></tr>
                    : journal.map((item) => (
                      <tr key={item.id}>
                        <td className="mono" style={{ padding: '6px 8px' }}>{apiErpFormatWhen(item.eventAt)}</td>
                        <td style={{ padding: '6px 8px' }}>{item.actorUsername || '—'}</td>
                        <td style={{ padding: '6px 8px' }}>{apiErpActionLabel(item.action)}</td>
                        <td style={{ padding: '6px 8px' }}>{item.objectLabel || item.objectId || '—'}</td>
                        <td style={{ padding: '6px 8px', color: item.result === 'ok' ? 'var(--st-success)' : 'var(--st-critical)' }}>
                          {item.result === 'ok' ? apiErpT('apiErpPage.journal.ok') : item.result}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
        </Card>

        <Card title={apiErpT('apiErpPage.pair.title')} pad="sm">
          <div className="col" style={{ gap: 10, padding: 8, font: 'var(--pv-text-body-3)' }}>
            <div style={{ color: 'var(--fg-secondary)' }}>
              {apiErpT('apiErpPage.pair.desc')}
            </div>
            <div className="field">
              <label>client_secret</label>
              <input
                className="input mono"
                type="password"
                placeholder={apiErpT('apiErpPage.pair.secretPlaceholder')}
                value={pairSecret}
                autoComplete="off"
                onChange={(e) => { setPairSecret(e.target.value); setPairResult(null); }}
              />
            </div>
            <div>
              <Button kind="primary" disabled={!pairSecret} onClick={verifyPair}>{apiErpT('apiErpPage.pair.submit')}</Button>
            </div>
            {pairResult
              ? (
                <div className="col" style={{ gap: 4, font: 'var(--pv-text-body-2-bold)' }}>
                  <div style={{ color: pairResult.match ? 'var(--st-success)' : 'var(--st-critical)' }}>
                    {pairResult.match ? apiErpT('apiErpPage.pair.match') : apiErpT('apiErpPage.pair.noMatch')}
                  </div>
                  {!pairResult.active
                    ? <div style={{ color: 'var(--st-warning)' }}>{apiErpT('apiErpPage.pair.inactiveWarning')}</div>
                    : null}
                </div>
              )
              : null}
          </div>
        </Card>
      </div>
    </Modal>
  );
}

// Кнопка-меню «ещё» для действий строки: карточка вынесена отдельно,
// остальное — здесь, чтобы не расползаться иконками.
function ApiErpRowMenu({ row, busy, onRecreate, onToggle, onRevokeTokens, onDelete }) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onDoc = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const item = ({ icon, label, danger, disabled, reason, onClick }) => (
    <button
      key={label}
      type="button"
      disabled={disabled}
      title={disabled ? reason : undefined}
      className={`api-erp-menu__item${danger ? ' api-erp-menu__item--danger' : ''}`}
      onClick={(e) => {
        e.stopPropagation();
        if (!disabled) {
          setOpen(false);
          onClick();
        }
      }}
    >
      <Icon name={icon} size={14} />
      {label}
    </button>
  );

  return (
    <div ref={wrapRef} style={{ position: 'relative' }}>
      <button
        className="icon-btn tt"
        data-tt={apiErpT('apiErpPage.card.actionsTooltip')}
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
      >
        <Icon name="more" size={15} />
      </button>
      {open
        ? (
          <div className="api-erp-menu" onClick={(e) => e.stopPropagation()}>
            {item({
              icon: 'refresh',
              label: apiErpT('apiErpPage.menu.recreate'),
              disabled: busy !== '' || !row.active,
              reason: apiErpT('apiErpPage.card.onlyActive'),
              onClick: () => onRecreate(row),
            })}
            {item({
              icon: 'x',
              label: apiErpT('apiErpPage.card.revokeTokens'),
              disabled: busy !== '' || row.activeTokens === 0,
              reason: apiErpT('apiErpPage.card.noTokens'),
              onClick: () => onRevokeTokens(row),
            })}
            {item({
              icon: row.active ? 'pause' : 'play',
              label: row.active ? apiErpT('apiErpPage.card.disable') : apiErpT('apiErpPage.card.enable'),
              disabled: busy !== '',
              onClick: () => onToggle(row),
            })}
            {item({
              icon: 'trash',
              label: apiErpT('apiErpPage.card.delete'),
              danger: true,
              disabled: busy !== '',
              onClick: () => onDelete(row),
            })}
          </div>
        )
        : null}
    </div>
  );
}

function PageApiIntegrationErp({ currentUser }) {
  const canWrite = currentUser?.roleId === 'Administrator'
    || !!currentUser?.effectiveWritePermissions?.['api-integration-erp'];

  const [payload, setPayload] = useState(null);
  const [journal, setJournal] = useState([]);
  const [error, setError] = useState('');
  const [forbidden, setForbidden] = useState(false);
  const [busy, setBusy] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [issued, setIssued] = useState(null);
  const [cardId, setCardId] = useState(null);
  const [detailsTick, setDetailsTick] = useState(0);

  const load = useCallback(() => {
    return Promise.all([
      ApiClient.loadApiClients(),
      ApiClient.loadApiClientsJournal(),
    ]).then(([list, log]) => {
      setPayload(list.data);
      setJournal(log.data || []);
      setForbidden(false);
      setError('');
    }).catch((e) => {
      if (e.status === 403) setForbidden(true);
      setError(e.message);
    });
  }, []);

  useEffect(() => { load(); }, [load]);

  const refresh = async () => {
    setRefreshing(true);
    try {
      await load();
    } finally {
      setRefreshing(false);
    }
  };

  const run = async (key, fn) => {
    setBusy(key);
    setError('');
    try {
      return await fn();
    } catch (e) {
      setError(e.message);
      pushToast?.({ kind: 'error', title: apiErpT('apiErpPage.error'), desc: e.message });
      return null;
    } finally {
      setBusy('');
    }
  };

  const reloadAll = async () => {
    await load();
    setDetailsTick((t) => t + 1);
  };

  const recreate = (row) => {
    if (!window.confirm(apiErpT('apiErpPage.confirm.recreate', { name: row.clientName }))) return;
    return run(`recreate:${row.clientId}`, async () => {
      const res = await ApiClient.recreateApiClient(row.clientId);
      setCardId(null);
      setIssued(res.data);
      pushToast?.({ kind: 'success', title: apiErpT('apiErpPage.toast.recreated') });
      await reloadAll();
    });
  };

  const toggle = (row) => run(`toggle:${row.clientId}`, async () => {
    if (row.active) {
      await ApiClient.deactivateApiClient(row.clientId);
      pushToast?.({ kind: 'success', title: apiErpT('apiErpPage.toast.disabled') });
    } else {
      await ApiClient.activateApiClient(row.clientId);
      pushToast?.({ kind: 'success', title: apiErpT('apiErpPage.toast.enabled') });
    }
    await reloadAll();
  });

  const revokeTokens = (row) => {
    if (!window.confirm(apiErpT('apiErpPage.confirm.revoke', { name: row.clientName }))) return;
    return run(`revoke:${row.clientId}`, async () => {
      const res = await ApiClient.revokeApiClientTokens(row.clientId);
      pushToast?.({ kind: 'success', title: apiErpT('apiErpPage.toast.revokedCount', { n: res.data.revokedTokens }) });
      await reloadAll();
    });
  };

  const removeClient = (row) => {
    if (!window.confirm(apiErpT('apiErpPage.confirm.delete', { name: row.clientName, id: row.clientId }))) return;
    return run(`delete:${row.clientId}`, async () => {
      await ApiClient.deleteApiClient(row.clientId);
      setCardId(null);
      pushToast?.({ kind: 'success', title: apiErpT('apiErpPage.toast.deleted') });
      await reloadAll();
    });
  };

  if (forbidden) {
    return (
      <div className="main__container">
        <Card>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {apiErpT('apiErpPage.forbidden')}
          </div>
        </Card>
      </div>
    );
  }

  const clients = payload?.clients || [];
  const ttlSec = payload?.tokenTtlSec;
  const cardRow = cardId ? clients.find((c) => c.clientId === cardId) : null;
  if (cardId && !cardRow) setCardId(null);

  const needle = search.trim().toLowerCase();
  const filtered = needle
    ? clients.filter((c) => (
      c.clientName.toLowerCase().includes(needle)
      || c.clientId.toLowerCase().includes(needle)
    ))
    : clients;

  const cols = [
    {
      key: 'clientName',
      title: apiErpT('apiErpPage.col.name'),
      render: (r) => (
        <span className="row" style={{ gap: 8, alignItems: 'center' }}>
          <span>{r.clientName}</span>
          {r.manual ? <Tag>{apiErpT('apiErpPage.tag.manual')}</Tag> : null}
        </span>
      ),
      sortAccessor: (r) => r.clientName.toLowerCase(),
    },
    {
      key: 'clientId',
      title: 'client_id',
      width: 240,
      render: (r) => (
        <span style={{ display: 'block', maxWidth: '100%', overflow: 'hidden' }}>
          <OverflowText value={r.clientId} className="mono" />
        </span>
      ),
      sortAccessor: (r) => r.clientId,
    },
    {
      key: 'active',
      title: apiErpT('apiErpPage.col.status'),
      width: 110,
      sortAccessor: (r) => (r.active ? 1 : 0),
      render: (r) => (
        r.active
          ? <Badge tone="success" dot>{apiErpT('apiErpPage.status.active')}</Badge>
          : <Badge tone="neutral">{apiErpT('apiErpPage.status.inactive')}</Badge>
      ),
    },
    {
      key: 'activeTokens',
      title: apiErpT('apiErpPage.col.tokens'),
      width: 90,
      num: true,
      sortAccessor: (r) => r.activeTokens,
      render: (r) => r.activeTokens,
    },
    {
      key: 'lastUsedAt',
      title: apiErpT('apiErpPage.col.lastUsed'),
      width: 170,
      sortAccessor: (r) => r.lastUsedAt || 0,
      render: (r) => <span style={{ color: 'var(--fg-secondary)' }}>{apiErpFormatAgo(r.lastUsedAt)}</span>,
    },
    {
      key: 'today',
      title: apiErpT('apiErpPage.col.today'),
      width: 190,
      sortAccessor: (r) => r.tokensIssuedToday,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)' }}>
          {apiErpT('apiErpPage.col.todayValue', { exchanges: r.tokensIssuedToday, requests: r.requestsToday })}
        </span>
      ),
    },
    {
      key: 'createdAt',
      title: apiErpT('apiErpPage.col.createdAt'),
      width: 110,
      sortAccessor: (r) => String(r.createdAt || ''),
      render: (r) => <span style={{ color: 'var(--fg-secondary)' }}>{apiErpFormatDate(r.createdAt)}</span>,
    },
    {
      key: 'updatedAt',
      title: apiErpT('apiErpPage.col.updatedAt'),
      width: 110,
      sortAccessor: (r) => String(r.updatedAt || ''),
      render: (r) => <span style={{ color: 'var(--fg-secondary)', opacity: r.active ? 1 : 0.55 }}>{apiErpFormatDate(r.updatedAt)}</span>,
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{apiErpT('apiErpPage.title')}</h1>
          <p>{apiErpT('apiErpPage.subtitle')}</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button
            kind="ghost"
            icon="refresh"
            onClick={refresh}
            disabled={refreshing || !payload}
            title={apiErpT('apiErpPage.refreshTitle')}
          >
            {refreshing ? apiErpT('apiErpPage.refreshing') : apiErpT('apiErpPage.refresh')}
          </Button>
          {canWrite
            ? <Button kind="primary" icon="plus" onClick={() => setShowCreate(true)}>{apiErpT('apiErpPage.create.submit')}</Button>
            : null}
        </div>
      </div>

      {error
        ? <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)', marginBottom: 12 }}>{error}</div>
        : null}

      {!payload
        ? (
          <Card pad="sm">
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>{apiErpT('apiErpPage.loading')}</div>
          </Card>
        )
        : (
          <DataTable
            rows={filtered}
            columns={cols}
            rowKey="clientId"
            pageSize={15}
            onRowClick={(r) => setCardId(r.clientId)}
            getRowClassName={(r) => (r.active ? '' : 'is-disabled')}
            emptyTitle={apiErpT('apiErpPage.emptyTitle')}
            emptyDesc={canWrite ? apiErpT('apiErpPage.emptyDescCan') : apiErpT('apiErpPage.emptyDesc')}
            toolbar={{
              search,
              onSearch: setSearch,
              searchPlaceholder: apiErpT('apiErpPage.searchPlaceholder'),
              searchMaxWidth: 420,
            }}
            footerNote={ttlSec ? apiErpT('apiErpPage.footerNote', { ttl: ttlSec }) : null}
            rowActions={(r) => (
              <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
                <button className="icon-btn tt" data-tt={apiErpT('apiErpPage.card.cardTooltip')} onClick={(e) => { e.stopPropagation(); setCardId(r.clientId); }}>
                  <Icon name="edit" size={15} />
                </button>
                {canWrite
                  ? (
                    <ApiErpRowMenu
                      row={r}
                      busy={busy}
                      onRecreate={recreate}
                      onToggle={toggle}
                      onRevokeTokens={revokeTokens}
                      onDelete={removeClient}
                    />
                  )
                  : null}
              </div>
            )}
          />
        )}

      <div style={{ marginTop: 16 }}>
        <Card title={apiErpT('apiErpPage.journal.title')} pad="sm">
          <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.when')}</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.who')}</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.action')}</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.connection')}</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>{apiErpT('apiErpPage.col.result')}</th>
              </tr>
            </thead>
            <tbody>
              {journal.length === 0
                ? <tr><td colSpan="5" style={{ padding: 8, color: 'var(--fg-secondary)' }}>{apiErpT('apiErpPage.journal.empty')}</td></tr>
                : journal.map((row) => (
                  <tr key={row.id}>
                    <td className="mono" style={{ padding: '6px 8px' }}>{apiErpFormatWhen(row.eventAt)}</td>
                    <td style={{ padding: '6px 8px' }}>{row.actorUsername || '—'}</td>
                    <td style={{ padding: '6px 8px' }}>{apiErpActionLabel(row.action)}</td>
                    <td style={{ padding: '6px 8px' }}>{row.objectLabel || row.objectId || '—'}</td>
                    <td style={{ padding: '6px 8px', color: row.result === 'ok' ? 'var(--st-success)' : 'var(--st-critical)' }}>
                      {row.result === 'ok' ? apiErpT('apiErpPage.journal.ok') : row.result}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </Card>
      </div>

      <ApiErpCreateModal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(data) => {
          setShowCreate(false);
          setIssued(data);
          pushToast?.({ kind: 'success', title: apiErpT('apiErpPage.toast.created') });
          reloadAll();
        }}
      />

      <ApiErpIssuedModal issued={issued} onClose={() => setIssued(null)} />

      {cardRow
        ? (
          <ApiErpClientModal
            row={cardRow}
            canWrite={canWrite}
            busy={busy}
            detailsTick={detailsTick}
            onClose={() => setCardId(null)}
            onRecreate={recreate}
            onToggle={toggle}
            onRevokeTokens={revokeTokens}
            onDelete={removeClient}
          />
        )
        : null}
    </div>
  );
}

window.PageApiIntegrationErp = PageApiIntegrationErp;
