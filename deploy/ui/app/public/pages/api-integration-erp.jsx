/* Раздел «API интеграция ERP»: управление подключениями (API-клиентами).
   Контракт и решения — docs/API_INTEGRATION_ERP_UI.md (раздел 8 — редизайн
   по референсу страницы «Клиенты»: шапка page-head, DataTable, модалки). */

const API_ERP_CLIENT_ID_MIN = 12;
const API_ERP_CLIENT_ID_MAX = 64;
const API_ERP_CLIENT_SECRET_MIN = 12;
const API_ERP_CLIENT_SECRET_MAX = 512;
const API_ERP_MANUAL_ID_RE = /^[A-Za-z0-9._:-]+$/;

function apiErpFormatDate(value) {
  if (!value) return '—';
  const iso = String(value).includes('T') ? String(value) : `${String(value).replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString('ru-RU', { timeZone: 'Europe/Moscow' });
}

function apiErpFormatWhen(value) {
  if (!value) return '—';
  const iso = String(value).includes('T') ? String(value) : `${String(value).replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(value);
  return `${date.toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })} МСК`;
}

function apiErpFormatAgo(ms) {
  if (!ms) return 'никогда';
  const diff = Date.now() - Number(ms);
  if (diff < 0) return apiErpFormatWhen(new Date(Number(ms)).toISOString());
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'только что';
  if (minutes < 60) return `${minutes} мин назад`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} ч назад`;
  return `${Math.floor(hours / 24)} дн назад`;
}

function apiErpActionLabel(action) {
  const key = `auditPage.action.${action}`;
  return GrapesI18n.has(key) ? GrapesI18n.t(key) : (action || '—');
}

async function apiErpCopy(label, value) {
  try {
    await copyTextToClipboard(value);
    pushToast?.({ kind: 'success', title: `${label} скопирован` });
  } catch (err) {
    pushToast?.({ kind: 'error', title: 'Не удалось скопировать', desc: err.message });
  }
}

function ApiErpCopyRow({ label, value }) {
  return (
    <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      <span style={{ minWidth: 110, color: 'var(--fg-secondary)' }}>{label}</span>
      <span className="mono" style={{ wordBreak: 'break-all' }}>{value}</span>
      <Button kind="ghost" size="sm" icon="copy" onClick={() => apiErpCopy(label, value)}>копировать</Button>
    </div>
  );
}

// Креды после создания/пересоздания. Секрет показывается один раз.
function ApiErpIssuedModal({ issued, onClose }) {
  if (!issued) return null;
  const hasSecret = Boolean(issued.clientSecret);
  const copyAll = () => {
    const lines = [
      `Подключение: ${issued.clientName}`,
      `client_id: ${issued.clientId}`,
    ];
    if (hasSecret) lines.push(`client_secret: ${issued.clientSecret}`);
    apiErpCopy('Всё', lines.join('\n'));
  };
  return (
    <Modal
      open
      onClose={onClose}
      title={issued.previousClientId ? 'Выпущены новые креды' : 'Подключение создано'}
      subtitle={issued.clientName}
      footer={
        <>
          <Button kind="ghost" icon="copy" onClick={copyAll}>Скопировать всё</Button>
          <Button kind="primary" onClick={onClose}>Понятно, секрет сохранил</Button>
        </>
      }
    >
      <div className="col" style={{ gap: 12, font: 'var(--pv-text-body-3)' }}>
        {hasSecret
          ? (
            <div style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--st-warning-bg)', color: 'var(--st-warning)' }}>
              Секрет показывается только один раз и нигде не хранится. Скопируйте сейчас
              и передайте в ERP по защищённому каналу.
            </div>
          )
          : (
            <div style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--st-warning-bg)', color: 'var(--st-warning)' }}>
              Секрет вы задали сами — в базе только хэш, мы его не показываем и не храним.
            </div>
          )}
        <ApiErpCopyRow label="client_id" value={issued.clientId} />
        {hasSecret
          ? <ApiErpCopyRow label="client_secret" value={issued.clientSecret} />
          : null}
        {issued.previousClientId
          ? (
            <div style={{ color: 'var(--fg-secondary)' }}>
              Прежний client_id <span className="mono">{issued.previousClientId}</span> отключён,
              его токены отозваны.
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
      title="Новое подключение"
      subtitle="Потребитель будет обменивать client_id и client_secret на токен через /api/v1/oauth/token"
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
          <Button kind="primary" icon="plus" onClick={submit} disabled={saving || !valid}>
            {saving ? 'создаю…' : 'Создать'}
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
          <Button kind={mode === 'generate' ? 'primary' : 'ghost'} onClick={() => setMode('generate')} disabled={saving}>Сгенерировать автоматически</Button>
          <Button kind={mode === 'manual' ? 'primary' : 'ghost'} onClick={() => setMode('manual')} disabled={saving}>Указать свои</Button>
        </div>
        <div className="field">
          <label>Название</label>
          <input
            className="input"
            placeholder="например: Piter-ix прод"
            value={name}
            disabled={saving}
            onChange={(e) => setName(e.target.value)}
          />
          <div className="hint">Отображается в таблице и журнале. Должно быть уникальным среди активных.</div>
        </div>
        {mode === 'manual'
          ? (
            <>
              <div className="field">
                <label>client_id</label>
                <input
                  className="input mono"
                  placeholder={`от ${API_ERP_CLIENT_ID_MIN} до ${API_ERP_CLIENT_ID_MAX} символов`}
                  value={clientId}
                  disabled={saving}
                  onChange={(e) => setClientId(e.target.value)}
                />
                <div className="hint">Латиница, цифры и символы . _ : -</div>
              </div>
              <div className="field">
                <label>client_secret</label>
                <input
                  className="input mono"
                  type="password"
                  placeholder={`от ${API_ERP_CLIENT_SECRET_MIN} символов`}
                  value={clientSecret}
                  disabled={saving}
                  autoComplete="off"
                  onChange={(e) => setClientSecret(e.target.value)}
                />
                <div className="hint">Сохраняется хэшем и больше не показывается. Передайте точную строку в ERP.</div>
              </div>
            </>
          )
          : (
            <div className="hint" style={{ color: 'var(--fg-secondary)' }}>
              client_id (префикс nta-) и секрет сгенерируем сами и покажем один раз после создания.
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
                  title={row.active ? 'Выпустить новые client_id и секрет' : 'Доступно только активным подключениям'}
                  onClick={() => onRecreate(row)}
                >
                  Пересоздать
                </Button>
                <Button
                  kind="ghost"
                  icon="x"
                  disabled={busyAll || row.activeTokens === 0}
                  title={row.activeTokens === 0 ? 'Нет живых токенов — отзывать нечего' : 'Отозвать все живые токены'}
                  onClick={() => onRevokeTokens(row)}
                >
                  Отозвать токены
                </Button>
                <Button
                  kind="ghost"
                  icon={row.active ? 'pause' : 'play'}
                  disabled={busyAll}
                  title={row.active ? 'Отключить: токены будут отозваны' : 'Включить с прежними кредами'}
                  onClick={() => onToggle(row)}
                >
                  {row.active ? 'Отключить' : 'Включить'}
                </Button>
                <Button
                  kind="ghost"
                  icon="trash"
                  disabled={busyAll}
                  title="Удалить подключение безвозвратно; история останется в журнале аудита"
                  onClick={() => onDelete(row)}
                >
                  Удалить
                </Button>
              </>
            )
            : null}
          <Button kind="primary" onClick={onClose}>Закрыть</Button>
        </>
      }
    >
      <div className="col" style={{ gap: 16 }}>
        {detailsError
          ? <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{detailsError}</div>
          : null}

        <div className="row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          {row.active
            ? <Badge tone="success" dot>активно</Badge>
            : <Badge tone="neutral">отключено</Badge>}
          {row.manual ? <Tag>свои креды</Tag> : null}
          <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            создан {apiErpFormatDate(row.createdAt)} · обновлён {apiErpFormatDate(row.updatedAt)} · TTL токена {nta.tokenTtlSec || '—'} с
          </span>
          <Button kind="ghost" size="sm" icon="copy" onClick={() => apiErpCopy('client_id', row.clientId)}>client_id</Button>
        </div>

        <Card title="Монитор" pad="sm">
          {!monitor
            ? <div style={{ color: 'var(--fg-secondary)', padding: 8 }}>загрузка…</div>
            : (
              <div className="row" style={{ gap: 24, flexWrap: 'wrap', alignItems: 'flex-start', padding: 8 }}>
                <div className="col" style={{ gap: 6, font: 'var(--pv-text-body-3)', minWidth: 260 }}>
                  <div style={{ font: 'var(--pv-text-body-2-bold)' }}>Сторона NTA</div>
                  <div style={{ color: row.active ? 'var(--st-success)' : 'var(--st-critical)' }}>
                    {row.active ? '✓ Подключение активно' : '✗ Отключено — /oauth/token не выдаст токен'}
                  </div>
                  {row.active
                    ? (
                      <div style={{ color: nta.tokenIssued ? 'var(--st-success)' : 'var(--st-critical)' }}>
                        {nta.tokenIssued
                          ? '✓ Токен выпускается (тестовый получен и отозван)'
                          : `✗ Ошибка выпуска токена: ${nta.tokenError || 'неизвестно'}`}
                      </div>
                    )
                    : null}
                  <div>Живых токенов: {nta.activeTokens ?? 0}
                    {nta.tokenExpiresSoonestAt
                      ? ` (ближайший истекает ${apiErpFormatWhen(new Date(nta.tokenExpiresSoonestAt).toISOString())})`
                      : ''}
                  </div>
                </div>
                <div className="col" style={{ gap: 6, font: 'var(--pv-text-body-3)', minWidth: 260 }}>
                  <div style={{ font: 'var(--pv-text-body-2-bold)' }}>Сторона потребителя</div>
                  <div>Последний приход: {apiErpFormatAgo(erp.lastUsedAt)}</div>
                  <div>Обменов токеном за сутки: {erp.tokensIssuedToday ?? 0}</div>
                  <div>API-запросов за сутки: {erp.requestsToday ?? 0}</div>
                </div>
              </div>
            )}
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', padding: '0 8px 8px' }}>
            Проверяем только свою сторону: соединение всегда инициирует потребитель. Обмены есть,
            а операций нет — потребитель подключён, но бездействует; «никогда» — кредами ещё не пользовались.
          </div>
        </Card>

        <Card title="Журнал подключения" pad="sm">
          {!journal
            ? <div style={{ color: 'var(--fg-secondary)', padding: 8 }}>загрузка…</div>
            : (
              <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Когда</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Кто</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Действие</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Объект</th>
                    <th style={{ textAlign: 'left', padding: '6px 8px' }}>Результат</th>
                  </tr>
                </thead>
                <tbody>
                  {journal.length === 0
                    ? <tr><td colSpan="5" style={{ padding: 8, color: 'var(--fg-secondary)' }}>Записей нет</td></tr>
                    : journal.map((item) => (
                      <tr key={item.id}>
                        <td className="mono" style={{ padding: '6px 8px' }}>{apiErpFormatWhen(item.eventAt)}</td>
                        <td style={{ padding: '6px 8px' }}>{item.actorUsername || '—'}</td>
                        <td style={{ padding: '6px 8px' }}>{apiErpActionLabel(item.action)}</td>
                        <td style={{ padding: '6px 8px' }}>{item.objectLabel || item.objectId || '—'}</td>
                        <td style={{ padding: '6px 8px', color: item.result === 'ok' ? 'var(--st-success)' : 'var(--st-critical)' }}>
                          {item.result === 'ok' ? 'ок' : item.result}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
        </Card>

        <Card title="Проверить пару id+секрет" pad="sm">
          <div className="col" style={{ gap: 10, padding: 8, font: 'var(--pv-text-body-3)' }}>
            <div style={{ color: 'var(--fg-secondary)' }}>
              Сравним секрет с хэшем так же, как /oauth/token. Вставьте секрет, который передали потребителю.
            </div>
            <div className="field">
              <label>client_secret</label>
              <input
                className="input mono"
                type="password"
                placeholder="секрет из ERP"
                value={pairSecret}
                autoComplete="off"
                onChange={(e) => { setPairSecret(e.target.value); setPairResult(null); }}
              />
            </div>
            <div>
              <Button kind="primary" disabled={!pairSecret} onClick={verifyPair}>Проверить</Button>
            </div>
            {pairResult
              ? (
                <div className="col" style={{ gap: 4, font: 'var(--pv-text-body-2-bold)' }}>
                  <div style={{ color: pairResult.match ? 'var(--st-success)' : 'var(--st-critical)' }}>
                    {pairResult.match ? '✓ Секрет совпадает' : '✗ Секрет не совпадает'}
                  </div>
                  {!pairResult.active
                    ? <div style={{ color: 'var(--st-warning)' }}>Подключение сейчас отключено — обмен всё равно не пройдёт</div>
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
        data-tt="Действия"
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
      >
        <Icon name="more" size={15} />
      </button>
      {open
        ? (
          <div className="api-erp-menu" onClick={(e) => e.stopPropagation()}>
            {item({
              icon: 'refresh',
              label: 'Пересоздать креды',
              disabled: busy !== '' || !row.active,
              reason: 'Доступно только активным подключениям',
              onClick: () => onRecreate(row),
            })}
            {item({
              icon: 'x',
              label: 'Отозвать токены',
              disabled: busy !== '' || row.activeTokens === 0,
              reason: 'Нет живых токенов — отзывать нечего',
              onClick: () => onRevokeTokens(row),
            })}
            {item({
              icon: row.active ? 'pause' : 'play',
              label: row.active ? 'Отключить' : 'Включить',
              disabled: busy !== '',
              onClick: () => onToggle(row),
            })}
            {item({
              icon: 'trash',
              label: 'Удалить',
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
      pushToast?.({ kind: 'error', title: 'Ошибка', desc: e.message });
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
    if (!window.confirm(
      `Пересоздать «${row.clientName}»?\n\nВыпустим новые client_id и секрет. Прежний client_id будет отключён, его токены отозваны.`,
    )) return;
    return run(`recreate:${row.clientId}`, async () => {
      const res = await ApiClient.recreateApiClient(row.clientId);
      setCardId(null);
      setIssued(res.data);
      pushToast?.({ kind: 'success', title: 'Креды пересозданы, старые отозваны' });
      await reloadAll();
    });
  };

  const toggle = (row) => run(`toggle:${row.clientId}`, async () => {
    if (row.active) {
      await ApiClient.deactivateApiClient(row.clientId);
      pushToast?.({ kind: 'success', title: 'Подключение отключено, токены отозваны' });
    } else {
      await ApiClient.activateApiClient(row.clientId);
      pushToast?.({ kind: 'success', title: 'Подключение включено' });
    }
    await reloadAll();
  });

  const revokeTokens = (row) => {
    if (!window.confirm(
      `Отозвать все токены «${row.clientName}»?\nERP переподключится при следующем обмене. Сами креды не меняются.`,
    )) return;
    return run(`revoke:${row.clientId}`, async () => {
      const res = await ApiClient.revokeApiClientTokens(row.clientId);
      pushToast?.({ kind: 'success', title: `Отозвано токенов: ${res.data.revokedTokens}` });
      await reloadAll();
    });
  };

  const removeClient = (row) => {
    if (!window.confirm(
      `Удалить «${row.clientName}» (${row.clientId})?\n\nСтрока будет удалена из базы безвозвратно, токены отозваны. История действий останется в журнале аудита.`,
    )) return;
    return run(`delete:${row.clientId}`, async () => {
      await ApiClient.deleteApiClient(row.clientId);
      setCardId(null);
      pushToast?.({ kind: 'success', title: 'Подключение удалено' });
      await reloadAll();
    });
  };

  if (forbidden) {
    return (
      <div className="main__container">
        <Card>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            Раздел только для ролей с доступом «API интеграция ERP».
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
      title: 'Название',
      render: (r) => (
        <span className="row" style={{ gap: 8, alignItems: 'center' }}>
          <span>{r.clientName}</span>
          {r.manual ? <Tag>свои креды</Tag> : null}
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
      title: 'Статус',
      width: 110,
      sortAccessor: (r) => (r.active ? 1 : 0),
      render: (r) => (
        r.active
          ? <Badge tone="success" dot>активно</Badge>
          : <Badge tone="neutral">отключено</Badge>
      ),
    },
    {
      key: 'activeTokens',
      title: 'Токены',
      width: 90,
      num: true,
      sortAccessor: (r) => r.activeTokens,
      render: (r) => r.activeTokens,
    },
    {
      key: 'lastUsedAt',
      title: 'Последний приход',
      width: 170,
      sortAccessor: (r) => r.lastUsedAt || 0,
      render: (r) => <span style={{ color: 'var(--fg-secondary)' }}>{apiErpFormatAgo(r.lastUsedAt)}</span>,
    },
    {
      key: 'today',
      title: 'За сутки',
      width: 190,
      sortAccessor: (r) => r.tokensIssuedToday,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)' }}>
          обменов {r.tokensIssuedToday} · запросов {r.requestsToday}
        </span>
      ),
    },
    {
      key: 'createdAt',
      title: 'Создан',
      width: 110,
      sortAccessor: (r) => String(r.createdAt || ''),
      render: (r) => <span style={{ color: 'var(--fg-secondary)' }}>{apiErpFormatDate(r.createdAt)}</span>,
    },
    {
      key: 'updatedAt',
      title: 'Обновлён',
      width: 110,
      sortAccessor: (r) => String(r.updatedAt || ''),
      render: (r) => <span style={{ color: 'var(--fg-secondary)', opacity: r.active ? 1 : 0.55 }}>{apiErpFormatDate(r.updatedAt)}</span>,
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>API интеграции</h1>
          <p>Управление API подключениями: выдача кредов, пересоздание, токены, журнал.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button
            kind="ghost"
            icon="refresh"
            onClick={refresh}
            disabled={refreshing || !payload}
            title="Перечитать список подключений и журнал с сервера"
          >
            {refreshing ? 'Обновляю…' : 'Обновить'}
          </Button>
          {canWrite
            ? <Button kind="primary" icon="plus" onClick={() => setShowCreate(true)}>Создать</Button>
            : null}
        </div>
      </div>

      {error
        ? <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)', marginBottom: 12 }}>{error}</div>
        : null}

      {!payload
        ? (
          <Card pad="sm">
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>загрузка…</div>
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
            emptyTitle="Подключений ещё нет"
            emptyDesc={canWrite ? 'Нажмите «Создать», чтобы выпустить креды.' : 'Нет ни одного подключения.'}
            toolbar={{
              search,
              onSearch: setSearch,
              searchPlaceholder: 'Поиск по названию или client_id',
              searchMaxWidth: 420,
            }}
            footerNote={ttlSec ? `TTL токена: ${ttlSec} с. Отключённые подключения остаются в списке для истории.` : null}
            rowActions={(r) => (
              <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
                <button className="icon-btn tt" data-tt="Карточка" onClick={(e) => { e.stopPropagation(); setCardId(r.clientId); }}>
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
        <Card title="Журнал" pad="sm">
          <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>Когда</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>Кто</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>Действие</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>Подключение</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>Результат</th>
              </tr>
            </thead>
            <tbody>
              {journal.length === 0
                ? <tr><td colSpan="5" style={{ padding: 8, color: 'var(--fg-secondary)' }}>Записей нет</td></tr>
                : journal.map((row) => (
                  <tr key={row.id}>
                    <td className="mono" style={{ padding: '6px 8px' }}>{apiErpFormatWhen(row.eventAt)}</td>
                    <td style={{ padding: '6px 8px' }}>{row.actorUsername || '—'}</td>
                    <td style={{ padding: '6px 8px' }}>{apiErpActionLabel(row.action)}</td>
                    <td style={{ padding: '6px 8px' }}>{row.objectLabel || row.objectId || '—'}</td>
                    <td style={{ padding: '6px 8px', color: row.result === 'ok' ? 'var(--st-success)' : 'var(--st-critical)' }}>
                      {row.result === 'ok' ? 'ок' : row.result}
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
          pushToast?.({ kind: 'success', title: 'Подключение создано' });
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
