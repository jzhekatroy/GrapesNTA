/* Синхронизация клиентов из ERP — вкладка диагностики. */

function formatWhen(value) {
  if (!value) return '—';
  const raw = String(value);
  const iso = raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return raw;
  return `${date.toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })} МСК`;
}

function triggerLabel(row) {
  if (!row) return '—';
  if (row.trigger === 'cron') return 'ночной cron';
  if (row.trigger === 'ui') return 'кнопка на этой вкладке';
  if (row.trigger === 'cli') return 'запуск с сервера';
  return row.trigger || '—';
}

function modeLabel(row) {
  if (!row) return '—';
  return Number(row.full) ? 'полный (все ЛС, снять пропавших)' : `порция, лимит ${row.limit_n}`;
}

function isTodayMsk(value) {
  if (!value) return false;
  const iso = String(value).includes('T') ? String(value) : `${String(value).replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return false;
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Moscow', year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(date);
  const now = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Moscow', year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(new Date());
  return parts === now;
}

function PageErpPiterix() {
  const [status, setStatus] = useState(null);
  const [journal, setJournal] = useState([]);
  const [error, setError] = useState('');
  const [forbidden, setForbidden] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saving, setSaving] = useState(false);
  const [limit, setLimit] = useState(50);
  const [full, setFull] = useState(false);
  const [cronEnabled, setCronEnabled] = useState(false);
  const [categories, setCategories] = useState({ piter_ix: true, dc: false, bb: false });
  const [apiBase, setApiBase] = useState('https://erp.bth.su');
  const [apiHost, setApiHost] = useState('erp.bth.su');
  const [apiToken, setApiToken] = useState('');
  const [apiInsecure, setApiInsecure] = useState(true);
  const [bindMode, setBindMode] = useState('ports');

  const load = useCallback(() => {
    return Promise.all([
      ApiClient.loadErpPiterixStatus(),
      ApiClient.loadErpPiterixJournal(),
    ]).then(([st, log]) => {
      setStatus(st);
      setJournal(log);
      if (st?.settings) {
        setCronEnabled(!!st.settings.cronEnabled);
        setCategories({ piter_ix: true, dc: false, bb: false, ...st.settings.categories });
        setApiBase(st.settings.apiBase || 'https://erp.bth.su');
        setApiHost(st.settings.apiHost || 'erp.bth.su');
        setApiInsecure(st.settings.apiInsecure !== false);
        setBindMode(st.settings.bindMode === 'prefixes' ? 'prefixes' : 'ports');
        setApiToken('');
      }
      setForbidden(false);
      setError('');
    }).catch((e) => {
      if (e.status === 403) setForbidden(true);
      setError(e.message);
    });
  }, []);

  useEffect(() => { load(); }, [load]);

  const saveSettings = async () => {
    setSaving(true);
    setError('');
    try {
      const next = await ApiClient.saveErpPiterixSettings({
        cronEnabled,
        categories,
        apiBase,
        apiHost,
        apiToken,
        apiInsecure,
        bindMode,
      });
      setCronEnabled(!!next.cronEnabled);
      setCategories({ piter_ix: true, dc: false, bb: false, ...next.categories });
      setApiBase(next.apiBase || apiBase);
      setApiHost(next.apiHost || apiHost);
      setApiInsecure(next.apiInsecure !== false);
      setBindMode(next.bindMode === 'prefixes' ? 'prefixes' : 'ports');
      setApiToken('');
      pushToast?.({ kind: 'success', title: 'Настройки ERP сохранены' });
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const run = async () => {
    setBusy(true);
    setError('');
    try {
      const data = await ApiClient.runErpPiterixSync({ limit, full });
      pushToast?.({
        kind: 'success',
        title: full ? 'Полный прогон завершён' : `Заведено или обновлено: ${data.upserted}`,
      });
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const last = status?.lastRun;
  const reasons = last?.skippedSummary?.byReason || {};
  const lastFailed = Boolean(last?.error);
  const nightRecorded = last && last.trigger === 'cron' && isTodayMsk(last.started_at);
  const catalog = status?.settings?.catalog || [];

  if (forbidden) {
    return (
      <Card>
        <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          Вкладка только для администратора.
        </div>
      </Card>
    );
  }
  if (!status) {
    return (
      <Card>
        <div style={{ color: 'var(--fg-secondary)' }}>{error || 'загрузка…'}</div>
      </Card>
    );
  }

  return (
    <div className="col" style={{ gap: 16 }}>
      {error && <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{error}</div>}

      <Card title="Настройки">
        <div className="col" style={{ gap: 12, font: 'var(--pv-text-body-3)' }}>
          <label className="col" style={{ gap: 4 }}>
            URL API
            <input
              value={apiBase}
              disabled={saving}
              onChange={(e) => setApiBase(e.target.value)}
              placeholder="https://erp.bth.su"
              className="mono"
            />
          </label>
          <label className="col" style={{ gap: 4 }}>
            Host
            <input
              value={apiHost}
              disabled={saving}
              onChange={(e) => setApiHost(e.target.value)}
              placeholder="erp.bth.su"
              className="mono"
            />
          </label>
          <label className="col" style={{ gap: 4 }}>
            Токен
            <input
              type="password"
              value={apiToken}
              disabled={saving}
              onChange={(e) => setApiToken(e.target.value)}
              placeholder={status.settings?.tokenSet ? 'задан, введите чтобы сменить' : 'Bearer token'}
              autoComplete="off"
            />
          </label>
          <label className="row" style={{ gap: 8, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={apiInsecure}
              disabled={saving}
              onChange={(e) => setApiInsecure(e.target.checked)}
            />
            Не проверять TLS-сертификат (--insecure)
          </label>
          <div>
            Как размечать клиента
            <div className="col" style={{ gap: 6, marginTop: 6 }}>
              <label className="row" style={{ gap: 8, alignItems: 'center' }}>
                <input
                  type="radio"
                  name="erp-bind-mode"
                  checked={bindMode === 'prefixes'}
                  disabled={saving}
                  onChange={() => setBindMode('prefixes')}
                />
                По IP — текущие ips[].ip, если cidr пустой то /32
              </label>
              <label className="row" style={{ gap: 8, alignItems: 'center' }}>
                <input
                  type="radio"
                  name="erp-bind-mode"
                  checked={bindMode === 'ports'}
                  disabled={saving}
                  onChange={() => setBindMode('ports')}
                />
                По портам коммутатора — ips[].switch.host + port
              </label>
            </div>
          </div>
          <label className="row" style={{ gap: 8, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={cronEnabled}
              disabled={saving}
              onChange={(e) => setCronEnabled(e.target.checked)}
            />
            Включить ночной cron (03:15 МСК, полный прогон)
          </label>
          <div>
            Какие категории забирать из ERP. Критерий задаёт биллинг, мы только включаем выгрузку.
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}></th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>Категория</th>
                <th style={{ textAlign: 'left', padding: '6px 8px' }}>Критерий</th>
                <th style={{ textAlign: 'right', padding: '6px 8px' }}>Сейчас у нас</th>
              </tr>
            </thead>
            <tbody>
              {catalog.map((cat) => (
                <tr key={cat.id}>
                  <td style={{ padding: '6px 8px' }}>
                    <input
                      type="checkbox"
                      checked={!!categories[cat.id]}
                      disabled={saving}
                      onChange={(e) => setCategories((prev) => ({ ...prev, [cat.id]: e.target.checked }))}
                    />
                  </td>
                  <td className="mono" style={{ padding: '6px 8px' }}>{cat.id}</td>
                  <td style={{ padding: '6px 8px', color: 'var(--fg-secondary)' }}>{cat.rule}</td>
                  <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                    {status.clientsByCategory?.[cat.id] ?? 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div>
            <button type="button" className="btn btn--primary" disabled={saving} onClick={saveSettings}>
              {saving ? 'сохраняю…' : 'Сохранить настройки'}
            </button>
          </div>
          <div style={{ color: 'var(--fg-secondary)' }}>
            {status.erpConfigured ? 'Токен ERP задан.' : 'Нет ERP_API_TOKEN — ни cron, ни кнопка в API не сходят.'}
            {' '}Портов сейчас: {status.ports}.
          </div>
        </div>
      </Card>

      <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
        <Card title="Ночной cron 03:15 МСК">
          {!cronEnabled ? (
            <div style={{ color: 'var(--st-warning)', font: 'var(--pv-text-body-2-bold)' }}>Выключен в настройках</div>
          ) : nightRecorded && !lastFailed ? (
            <div style={{ color: 'var(--st-success)', font: 'var(--pv-text-body-2-bold)' }}>Сегодня отработал</div>
          ) : lastFailed && last.trigger === 'cron' && isTodayMsk(last.started_at) ? (
            <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-2-bold)' }}>Сегодня упал</div>
          ) : (
            <div style={{ color: 'var(--st-warning)', font: 'var(--pv-text-body-2-bold)' }}>За сегодня записи нет</div>
          )}
        </Card>
        <Card title="Последняя запись">
          {!last ? (
            <div style={{ color: 'var(--fg-secondary)' }}>Ещё ни одного прогона не записали</div>
          ) : (
            <div className="col" style={{ gap: 6, font: 'var(--pv-text-body-3)' }}>
              <div style={{ font: 'var(--pv-text-body-2-bold)', color: lastFailed ? 'var(--st-critical)' : undefined }}>
                {lastFailed ? 'Ошибка' : 'Ок'} · {formatWhen(last.started_at)}
              </div>
              <div>{triggerLabel(last)} · {modeLabel(last)}</div>
              {lastFailed ? (
                <div style={{ color: 'var(--st-critical)' }}>{last.error}</div>
              ) : (
                <div>
                  из ERP {last.fetched}, активных {last.active},
                  обновлено {last.upserted}, снято {last.disabled}, пропущено {last.skipped}
                </div>
              )}
              {journal[0]?.reportRows > 0 && (
                <div>
                  <a href={ApiClient.erpPiterixReportUrl(journal[0].run_id)} download>
                    Скачать отчёт (CSV, {journal[0].reportRows} строк)
                  </a>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card title="Запустить сейчас">
        <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
          <div>
            Берёт включённые категории и выбранный способ разметки. Порция — только новые. Полный прогон обновляет имена и снимает пропавших внутри этих категорий.
          </div>
          <label className="row" style={{ gap: 8, alignItems: 'center' }}>
            Лимит порции
            <input
              type="number"
              min="1"
              max="500"
              value={limit}
              disabled={full || busy}
              onChange={(e) => setLimit(Number(e.target.value) || 50)}
              style={{ width: 80 }}
            />
          </label>
          <label className="row" style={{ gap: 8, alignItems: 'center' }}>
            <input type="checkbox" checked={full} disabled={busy} onChange={(e) => setFull(e.target.checked)} />
            Полный прогон
          </label>
          <div>
            <button type="button" className="btn btn--primary" disabled={busy || !status.erpConfigured || status.running} onClick={run}>
              {busy || status.running ? 'выполняется…' : 'Запустить'}
            </button>
          </div>
          {(busy || status.running) && (
            <div style={{ color: 'var(--st-warning)' }}>
              Идёт запрос в ERP. Если крутится дольше минуты — перезапустите UI, предыдущий прогон завис.
            </div>
          )}
        </div>
      </Card>

      {Object.keys(reasons).length > 0 && (
        <Card title="Почему не разметили в последнем прогоне">
          <div className="col" style={{ gap: 4, font: 'var(--pv-text-body-3)' }}>
            {Object.entries(reasons).map(([reason, n]) => (
              <div key={reason}>{reason}: {n}</div>
            ))}
          </div>
        </Card>
      )}

      <Card title="Что в отчёте">
        <div className="col" style={{ gap: 4, font: 'var(--pv-text-body-3)' }}>
          <div>
            Отчёт пишется при каждом прогоне, включая ночной, и хранится 90 дней. Он всегда по текущему
            способу разметки — сейчас {bindMode === 'prefixes' ? 'по IP-префиксам' : 'по портам коммутаторов'}.
          </div>
          <div>«Можно разметить»: да — привязка создана; нет — не создана, причина в соседней колонке. «Замечания» разметке не мешают, но требуют решения.</div>
          {bindMode === 'prefixes' ? (
            <>
              <div>Строка — клиент и один его префикс. Нельзя разметить: в ERP нет ни одного адреса; тот же префикс указан у другого ЛС.</div>
              <div>Замечания: префикс вне наших CIDR; непригодный адрес с указанием диапазона (0.0.0.0/8 — обычно опечатка, loopback, link-local, multicast, зарезервированный IANA 240.0.0.0/4); приватный диапазон; вложенность в чужой префикс; подозрительно широкая маска; наш CIDR заведён с ролью remote.</div>
            </>
          ) : (
            <>
              <div>Строка — клиент и один его порт. Нельзя разметить: в ERP нет порта коммутатора; коммутатора из ERP нет в нашем SNMP-каталоге; коммутатор есть, но такого ifIndex у нас нет; порт указан у другого ЛС — тогда он не размечается никому.</div>
              <div>Замечание: у ЛС нет ни одного адреса в ERP. Разметке по портам это не мешает, но помешает, если переключить стенд на разметку по IP.</div>
            </>
          )}
          <div>Раздел «пропал из ERP» — клиенты, которых полный прогон отключил.</div>
        </div>
      </Card>

      <Card title="Журнал прогонов">
        <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Когда</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Кто</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Режим</th>
              <th style={{ textAlign: 'right', padding: '6px 8px' }}>Из ERP</th>
              <th style={{ textAlign: 'right', padding: '6px 8px' }}>Обновлено</th>
              <th style={{ textAlign: 'right', padding: '6px 8px' }}>Снято</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Итог</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Отчёт</th>
            </tr>
          </thead>
          <tbody>
            {journal.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ padding: 8, color: 'var(--fg-secondary)' }}>Записей нет</td>
              </tr>
            ) : journal.map((row) => (
              <tr key={row.run_id}>
                <td className="mono" style={{ padding: '6px 8px' }}>{formatWhen(row.started_at)}</td>
                <td style={{ padding: '6px 8px' }}>{triggerLabel(row)}</td>
                <td style={{ padding: '6px 8px' }}>{modeLabel(row)}</td>
                <td style={{ padding: '6px 8px', textAlign: 'right' }}>{row.fetched}</td>
                <td style={{ padding: '6px 8px', textAlign: 'right' }}>{row.upserted}</td>
                <td style={{ padding: '6px 8px', textAlign: 'right' }}>{row.disabled}</td>
                <td style={{ padding: '6px 8px', color: row.error ? 'var(--st-critical)' : undefined }}>
                  {row.error || 'ок'}
                </td>
                <td style={{ padding: '6px 8px' }}>
                  {row.reportRows > 0 ? (
                    <a href={ApiClient.erpPiterixReportUrl(row.run_id)} download>
                      CSV, {row.reportRows} строк
                    </a>
                  ) : (
                    <span style={{ color: 'var(--fg-secondary)' }}>—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

window.PageErpPiterix = PageErpPiterix;
