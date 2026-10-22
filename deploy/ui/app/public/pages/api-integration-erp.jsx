/* Раздел «API интеграция ERP»: выдача и управление кредами подключений.
   Контракт и решения — docs/API_INTEGRATION_ERP_UI.md. Стиль как у вкладки
   ERP в «Диагностике» (erp-piterix.jsx). */

function apiErpFormatWhen(value) {
  if (!value) return '—';
  const raw = String(value);
  const iso = raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return raw;
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
  const days = Math.floor(hours / 24);
  return `${days} дн назад (${apiErpFormatWhen(new Date(Number(ms)).toISOString())})`;
}

function apiErpActionLabel(action) {
  const key = `auditPage.action.${action}`;
  return GrapesI18n.has(key) ? GrapesI18n.t(key) : (action || '—');
}

function ApiErpCopyValue({ label, value }) {
  const copy = async () => {
    try {
      await copyTextToClipboard(value);
      pushToast?.({ kind: 'success', title: `${label} скопирован` });
    } catch (err) {
      pushToast?.({ kind: 'error', title: 'Не удалось скопировать', desc: err.message });
    }
  };
  return (
    <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      <span style={{ minWidth: 90, color: 'var(--fg-secondary)' }}>{label}</span>
      <span className="mono" style={{ wordBreak: 'break-all' }}>{value}</span>
      <Button kind="ghost" size="sm" onClick={copy}>копировать</Button>
    </div>
  );
}

// Креды после выпуска: секрет показывается один раз, закрыть блок — потерять.
function ApiErpIssued({ issued, onClose }) {
  if (!issued) return null;
  return (
    <Card
      title={issued.previousClientId ? 'Выпущены новые креды' : 'Креды созданы'}
      style={{ border: '1px solid var(--st-warning)' }}
    >
      <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
        <div style={{ color: 'var(--st-warning)', font: 'var(--pv-text-body-2-bold)' }}>
          Секрет показывается только один раз и нигде не хранится. Скопируйте сейчас
          и передайте в ERP по защищённому каналу.
        </div>
        <ApiErpCopyValue label="Подключение" value={issued.clientName} />
        <ApiErpCopyValue label="client_id" value={issued.clientId} />
        {issued.clientSecret
          ? <ApiErpCopyValue label="client_secret" value={issued.clientSecret} />
          : <div style={{ color: 'var(--fg-secondary)' }}>секрет задаёте вы сами (ручной ввод)</div>}
        {issued.previousClientId
          ? (
            <div style={{ color: 'var(--fg-secondary)' }}>
              Прежний client_id <span className="mono">{issued.previousClientId}</span> отключён,
              его токены отозваны.
            </div>
          )
          : null}
        <div>
          <Button kind="ghost" onClick={onClose}>закрыть (секрет больше не показать)</Button>
        </div>
      </div>
    </Card>
  );
}

function ApiErpMonitorPanel({ monitor }) {
  if (!monitor) return null;
  const nta = monitor.nta || {};
  const erp = monitor.erp || {};
  return (
    <Card title={`Монитор: ${monitor.clientName}`}>
      <div className="row" style={{ gap: 24, flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <div className="col" style={{ gap: 6, font: 'var(--pv-text-body-3)', minWidth: 260 }}>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>Сторона NTA</div>
          <div style={{ color: monitor.active ? 'var(--st-success)' : 'var(--st-critical)' }}>
            {monitor.active ? '✓ Подключение активно' : '✗ Отключено — /oauth/token не выдаст токен'}
          </div>
          {monitor.active
            ? (
              <div style={{ color: nta.tokenIssued ? 'var(--st-success)' : 'var(--st-critical)' }}>
                {nta.tokenIssued
                  ? '✓ Токен выпускается (тестовый получен и отозван)'
                  : `✗ Ошибка выпуска токена: ${nta.tokenError || 'неизвестно'}`}
              </div>
            )
            : null}
          <div>TTL токена: {nta.tokenTtlSec || '—'} с</div>
          <div>Живых токенов: {nta.activeTokens ?? 0}
            {nta.tokenExpiresSoonestAt
              ? ` (ближайший истекает ${apiErpFormatWhen(new Date(nta.tokenExpiresSoonestAt).toISOString())})`
              : ''}
          </div>
        </div>
        <div className="col" style={{ gap: 6, font: 'var(--pv-text-body-3)', minWidth: 260 }}>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>Сторона ERP</div>
          <div>Последний приход: {apiErpFormatAgo(erp.lastUsedAt)}</div>
          <div>Обменов токеном за сутки: {erp.tokensIssuedToday ?? 0}</div>
          <div>API-запросов за сутки: {erp.requestsToday ?? 0}</div>
          {(erp.recentOperations || []).length > 0
            ? (
              <div className="col" style={{ gap: 4, marginTop: 4 }}>
                <div style={{ color: 'var(--fg-secondary)' }}>Последние операции:</div>
                {(erp.recentOperations || []).map((op, i) => (
                  <div key={i} className="row" style={{ gap: 8 }}>
                    <span className="mono">{apiErpFormatWhen(op.eventAt)}</span>
                    <span>{apiErpActionLabel(op.action)}</span>
                    <span style={{ color: 'var(--fg-secondary)' }}>{op.objectLabel}</span>
                  </div>
                ))}
              </div>
            )
            : <div style={{ color: 'var(--fg-secondary)' }}>Операций через Bearer-API пока нет</div>}
        </div>
      </div>
      <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 10 }}>
        NTA не может опросить ERP: соединение всегда инициирует ERP. Если обмены есть, а операций
        нет — ERP подключён, но ничего не делает. Если «никогда» — креды ещё не дошли до ERP.
      </div>
    </Card>
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
  const [issued, setIssued] = useState(null);
  const [monitor, setMonitor] = useState(null);
  const [pairResult, setPairResult] = useState(null);

  const [newName, setNewName] = useState('');
  const [manualName, setManualName] = useState('');
  const [manualId, setManualId] = useState('');
  const [manualSecret, setManualSecret] = useState('');
  const [pairId, setPairId] = useState('');
  const [pairSecret, setPairSecret] = useState('');

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

  const run = async (key, fn) => {
    setBusy(key);
    setError('');
    try {
      return await fn();
    } catch (e) {
      setError(e.message);
      return null;
    } finally {
      setBusy('');
    }
  };

  const createClient = () => run('create', async () => {
    const res = await ApiClient.createApiClient({ name: newName });
    setIssued(res.data);
    setNewName('');
    pushToast?.({ kind: 'success', title: 'Подключение создано' });
    await load();
  });

  const recreate = (row) => {
    if (!window.confirm(
      `Пересоздать «${row.clientName}»?\n\nВыпустим новые client_id и секрет. Прежний client_id будет отключён, его токены отозваны.`,
    )) return;
    run(`recreate:${row.clientId}`, async () => {
      const res = await ApiClient.recreateApiClient(row.clientId);
      setIssued(res.data);
      setMonitor(null);
      pushToast?.({ kind: 'success', title: 'Креды пересозданы, старые отозваны' });
      await load();
    });
  };

  const registerManual = () => run('manual', async () => {
    await ApiClient.registerApiClientManual({
      name: manualName,
      clientId: manualId.trim(),
      clientSecret,
    });
    setManualName('');
    setManualId('');
    setManualSecret('');
    pushToast?.({ kind: 'success', title: 'Свои креды сохранены' });
    await load();
  });

  const toggle = (row) => run(`toggle:${row.clientId}`, async () => {
    if (row.active) {
      await ApiClient.deactivateApiClient(row.clientId);
      pushToast?.({ kind: 'success', title: 'Подключение отключено, токены отозваны' });
    } else {
      await ApiClient.activateApiClient(row.clientId);
      pushToast?.({ kind: 'success', title: 'Подключение включено' });
    }
    setMonitor(null);
    await load();
  });

  const revokeTokens = (row) => {
    if (!window.confirm(
      `Отозвать все токены «${row.clientName}»?\nERP переподключится при следующем обмене. Сами креды не меняются.`,
    )) return;
    run(`revoke:${row.clientId}`, async () => {
      const res = await ApiClient.revokeApiClientTokens(row.clientId);
      pushToast?.({ kind: 'success', title: `Отозвано токенов: ${res.data.revokedTokens}` });
      await load();
    });
  };

  const openMonitor = (row) => run(`monitor:${row.clientId}`, async () => {
    const res = await ApiClient.monitorApiClient(row.clientId);
    setMonitor(res.data);
  });

  const verifyPair = () => run('pair', async () => {
    const res = await ApiClient.verifyApiClientPair({ clientId: pairId.trim(), clientSecret: pairSecret });
    setPairResult(res.data);
  });

  if (forbidden) {
    return (
      <Card>
        <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          Раздел только для ролей с доступом «API интеграция ERP».
        </div>
      </Card>
    );
  }
  if (!payload) {
    return (
      <Card>
        <div style={{ color: 'var(--fg-secondary)' }}>{error || 'загрузка…'}</div>
      </Card>
    );
  }

  const clients = payload.clients || [];
  const ttlSec = payload.tokenTtlSec;

  return (
    <div className="col" style={{ gap: 16 }}>
      {error && <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{error}</div>}

      <ApiErpIssued issued={issued} onClose={() => setIssued(null)} />
      <ApiErpMonitorPanel monitor={monitor} />

      {canWrite ? (
        <div className="row" style={{ gap: 16, flexWrap: 'wrap', alignItems: 'stretch' }}>
          <Card title="Создать подключение">
            <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
              <div>Сгенерируем client_id и секрет под вашим названием. Секрет показывается один раз.</div>
              <label className="col" style={{ gap: 4 }}>
                Название
                <input
                  value={newName}
                  disabled={busy === 'create'}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Piter-ix"
                  className="mono"
                />
              </label>
              <div>
                <button
                  type="button"
                  className="btn btn--primary"
                  disabled={busy === 'create' || !newName.trim()}
                  onClick={createClient}
                >
                  {busy === 'create' ? 'создаю…' : 'Создать'}
                </button>
              </div>
            </div>
          </Card>

          <Card title="Свои креды">
            <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
              <div>Зададим свои client_id и секрет (минимум 12 символов). Секрет хранится хэшем и больше не показывается.</div>
              <label className="col" style={{ gap: 4 }}>
                Название
                <input
                  value={manualName}
                  disabled={busy === 'manual'}
                  onChange={(e) => setManualName(e.target.value)}
                  placeholder="Трансроут"
                  className="mono"
                />
              </label>
              <label className="col" style={{ gap: 4 }}>
                client_id
                <input
                  value={manualId}
                  disabled={busy === 'manual'}
                  onChange={(e) => setManualId(e.target.value)}
                  placeholder="erp-piterix-prod"
                  className="mono"
                />
              </label>
              <label className="col" style={{ gap: 4 }}>
                client_secret
                <input
                  type="password"
                  value={manualSecret}
                  disabled={busy === 'manual'}
                  onChange={(e) => setManualSecret(e.target.value)}
                  placeholder="минимум 12 символов"
                  autoComplete="off"
                  className="mono"
                />
              </label>
              <div>
                <button
                  type="button"
                  className="btn btn--primary"
                  disabled={busy === 'manual' || !manualName.trim() || !manualId.trim() || !manualSecret}
                  onClick={registerManual}
                >
                  {busy === 'manual' ? 'сохраняю…' : 'Сохранить'}
                </button>
              </div>
            </div>
          </Card>

          <Card title="Проверить пару id+секрет">
            <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
              <div>
                Сравним секрет с хэшем так же, как /oauth/token. Проверяйте те же данные, что передали в ERP.
              </div>
              <label className="col" style={{ gap: 4 }}>
                client_id
                <input
                  value={pairId}
                  disabled={busy === 'pair'}
                  onChange={(e) => setPairId(e.target.value)}
                  className="mono"
                />
              </label>
              <label className="col" style={{ gap: 4 }}>
                client_secret
                <input
                  type="password"
                  value={pairSecret}
                  disabled={busy === 'pair'}
                  onChange={(e) => setPairSecret(e.target.value)}
                  autoComplete="off"
                  className="mono"
                />
              </label>
              <div>
                <button
                  type="button"
                  className="btn btn--primary"
                  disabled={busy === 'pair' || !pairId.trim() || !pairSecret}
                  onClick={verifyPair}
                >
                  {busy === 'pair' ? 'проверяю…' : 'Проверить'}
                </button>
              </div>
              {pairResult
                ? (
                  <div
                    className="col"
                    style={{
                      gap: 4,
                      color: pairResult.match ? 'var(--st-success)' : 'var(--st-critical)',
                      font: 'var(--pv-text-body-2-bold)',
                    }}
                  >
                    <div>{pairResult.match ? '✓ Секрет совпадает' : '✗ Секрет не совпадает'}</div>
                    {!pairResult.active
                      ? <div style={{ color: 'var(--st-warning)' }}>Подключение сейчас отключено — обмен всё равно не пройдёт</div>
                      : null}
                  </div>
                )
                : null}
            </div>
          </Card>
        </div>
      ) : null}

      <Card title="Подключения">
        <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Название</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>client_id</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Статус</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Токены</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Последний приход ERP</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>За сутки</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Действия</th>
            </tr>
          </thead>
          <tbody>
            {clients.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ padding: 8, color: 'var(--fg-secondary)' }}>
                  Подключений ещё нет{ttlSec ? ` · TTL токена ${ttlSec} с` : ''}
                </td>
              </tr>
            ) : clients.map((row) => (
              <tr key={row.clientId} style={{ opacity: row.active ? 1 : 0.6 }}>
                <td style={{ padding: '6px 8px' }}>
                  {row.clientName}
                  {row.manual ? <span style={{ color: 'var(--fg-secondary)' }}> · свои креды</span> : null}
                </td>
                <td className="mono" style={{ padding: '6px 8px' }}>{row.clientId}</td>
                <td style={{ padding: '6px 8px', color: row.active ? 'var(--st-success)' : 'var(--st-critical)' }}>
                  {row.active ? 'активно' : 'отключено'}
                </td>
                <td style={{ padding: '6px 8px' }}>{row.activeTokens}</td>
                <td style={{ padding: '6px 8px' }}>{apiErpFormatAgo(row.lastUsedAt)}</td>
                <td style={{ padding: '6px 8px' }}>
                  обменов {row.tokensIssuedToday}, запросов {row.requestsToday}
                </td>
                <td style={{ padding: '6px 8px' }}>
                  <span className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="btn"
                      disabled={busy.startsWith('monitor:') || busy === `monitor:${row.clientId}`}
                      onClick={() => openMonitor(row)}
                    >
                      {busy === `monitor:${row.clientId}` ? '…' : 'Монитор'}
                    </button>
                    {canWrite ? (
                      <>
                        <button
                          type="button"
                          className="btn"
                          disabled={busy !== '' || !row.active}
                          onClick={() => recreate(row)}
                        >
                          Пересоздать
                        </button>
                        <button
                          type="button"
                          className="btn"
                          disabled={busy !== '' || row.activeTokens === 0}
                          onClick={() => revokeTokens(row)}
                        >
                          Отозвать токены
                        </button>
                        <button
                          type="button"
                          className="btn"
                          disabled={busy !== ''}
                          onClick={() => toggle(row)}
                        >
                          {row.active ? 'Отключить' : 'Включить'}
                        </button>
                      </>
                    ) : null}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {clients.length > 0 && ttlSec
          ? (
            <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 8 }}>
              TTL токена: {ttlSec} с. Отключённые подключения и их предыстория остаются в списке для журнала.
            </div>
          )
          : null}
      </Card>

      <Card title="Журнал">
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
            {journal.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ padding: 8, color: 'var(--fg-secondary)' }}>Записей нет</td>
              </tr>
            ) : journal.map((row) => (
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
  );
}

window.PageApiIntegrationErp = PageApiIntegrationErp;
