/* SMTP — настройки почты для отчётов по наблюдениям (Администрирование). */

function smtpT(key, params) {
  return GrapesI18n.t(key, params);
}

const SMTP_API_ERROR_MAP = {
  'Только администратор': 'smtpPage.err.adminOnly',
  'Укажите host и from_email перед включением SMTP': 'smtpPage.err.hostFromRequired',
  'SMTP отключён или не настроен': 'smtpPage.err.disabledOrUnset',
  'SMTP host не задан': 'smtpPage.err.hostUnset',
  'SMTP from_email не задан': 'smtpPage.err.fromEmailUnset',
  'Не указаны получатели': 'smtpPage.err.noRecipients',
  'Укажите адрес получателя': 'smtpPage.err.recipientRequired',
};

const SMTP_PORT_ERROR_RE = /^Порт: ожидается целое число от (\d+) до (\d+)$/;

function smtpApiErrorMessage(raw) {
  const message = String(raw || '').trim();
  if (!message) return '';
  const key = SMTP_API_ERROR_MAP[message];
  if (key) return smtpT(key);
  const portMatch = message.match(SMTP_PORT_ERROR_RE);
  if (portMatch) {
    return smtpT('smtpPage.err.portRange', { min: portMatch[1], max: portMatch[2] });
  }
  return message;
}

function PageSmtp() {
  const [smtp, setSmtp] = useState(null);
  const [error, setError] = useState('');
  const [forbidden, setForbidden] = useState(false);
  const [busy, setBusy] = useState(false);
  const [testTo, setTestTo] = useState('');

  useEffect(() => {
    ApiClient.loadSmtpSettings()
      .then((data) => {
        setSmtp(data);
        setForbidden(false);
        setError('');
      })
      .catch((e) => {
        if (e.status === 403) setForbidden(true);
        setError(e.message);
      });
  }, []);

  const save = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await ApiClient.saveSmtpSettings(smtp);
      setSmtp(res.data || smtp);
      pushToast?.({ kind: 'success', title: smtpT('smtpPage.toast.saved') });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    setError('');
    try {
      await ApiClient.testSmtpSettings(testTo);
      pushToast?.({ kind: 'success', title: smtpT('smtpPage.toast.testSent') });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const displayError = smtpApiErrorMessage(error);

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{smtpT('smtpPage.title')}</h1>
          <p>{smtpT('smtpPage.subtitle')}</p>
        </div>
      </div>

      {forbidden ? (
        <Card>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {smtpT('smtpPage.forbidden')}
          </div>
        </Card>
      ) : !smtp ? (
        <Card>
          <div style={{ color: 'var(--fg-secondary)' }}>{displayError || smtpT('smtpPage.loading')}</div>
        </Card>
      ) : (
        <Card title={smtpT('smtpPage.settings.title')}>
          <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
            {error && <div style={{ color: 'var(--st-critical)' }}>{displayError}</div>}
            <label className="row" style={{ gap: 8, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={!!smtp.enabled}
                onChange={(e) => setSmtp({ ...smtp, enabled: e.target.checked })}
              />
              {smtpT('smtpPage.enabled')}
            </label>
            <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
              <label className="col" style={{ gap: 4, minWidth: 180 }}>
                <span>{smtpT('smtpPage.field.host')}</span>
                <input className="input" value={smtp.host || ''} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })} />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 90 }}>
                <span>{smtpT('smtpPage.field.port')}</span>
                <input className="input" type="number" value={smtp.port || 587} onChange={(e) => setSmtp({ ...smtp, port: Number(e.target.value) })} />
              </label>
              <label className="row" style={{ gap: 6, alignItems: 'center', marginTop: 18 }}>
                <input type="checkbox" checked={!!smtp.secure} onChange={(e) => setSmtp({ ...smtp, secure: e.target.checked })} />
                {smtpT('smtpPage.field.tls465')}
              </label>
            </div>
            <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
              <label className="col" style={{ gap: 4, minWidth: 160 }}>
                <span>{smtpT('smtpPage.field.username')}</span>
                <input className="input" value={smtp.username || ''} onChange={(e) => setSmtp({ ...smtp, username: e.target.value })} />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 160 }}>
                <span>
                  {smtpT('smtpPage.field.password')}
                  {smtp.passwordSet ? ` ${smtpT('smtpPage.field.passwordSet')}` : ''}
                </span>
                <input
                  className="input"
                  type="password"
                  placeholder={smtp.passwordSet ? smtpT('smtpPage.field.passwordPlaceholder') : ''}
                  value={smtp.password || ''}
                  onChange={(e) => setSmtp({ ...smtp, password: e.target.value })}
                />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 180 }}>
                <span>{smtpT('smtpPage.field.fromEmail')}</span>
                <input className="input" value={smtp.fromEmail || ''} onChange={(e) => setSmtp({ ...smtp, fromEmail: e.target.value })} />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 140 }}>
                <span>{smtpT('smtpPage.field.fromName')}</span>
                <input className="input" value={smtp.fromName || ''} onChange={(e) => setSmtp({ ...smtp, fromName: e.target.value })} />
              </label>
            </div>
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <button type="button" className="btn btn--primary" disabled={busy} onClick={save}>{smtpT('smtpPage.save')}</button>
              <input
                className="input"
                style={{ width: 220 }}
                placeholder={smtpT('smtpPage.testPlaceholder')}
                value={testTo}
                onChange={(e) => setTestTo(e.target.value)}
              />
              <button type="button" className="btn" disabled={busy || !testTo} onClick={test}>{smtpT('smtpPage.testSend')}</button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

Object.assign(window, { PageSmtp });
