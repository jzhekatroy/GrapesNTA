/* SMTP — настройки почты для отчётов по наблюдениям (Администрирование). */

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
      pushToast?.({ kind: 'success', title: 'SMTP сохранён' });
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
      pushToast?.({ kind: 'success', title: 'Тестовое письмо отправлено' });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Почта (SMTP)</h1>
          <p>Отправка отчётов по наблюдениям. Доступно только администратору.</p>
        </div>
      </div>

      {forbidden ? (
        <Card>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            Настройки почты доступны только администратору.
          </div>
        </Card>
      ) : !smtp ? (
        <Card>
          <div style={{ color: 'var(--fg-secondary)' }}>{error || 'загрузка…'}</div>
        </Card>
      ) : (
        <Card title="Параметры SMTP">
          <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
            {error && <div style={{ color: 'crimson' }}>{error}</div>}
            <label className="row" style={{ gap: 8, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={!!smtp.enabled}
                onChange={(e) => setSmtp({ ...smtp, enabled: e.target.checked })}
              />
              Включить отправку
            </label>
            <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
              <label className="col" style={{ gap: 4, minWidth: 180 }}>
                <span>Host</span>
                <input className="input" value={smtp.host || ''} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })} />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 90 }}>
                <span>Port</span>
                <input className="input" type="number" value={smtp.port || 587} onChange={(e) => setSmtp({ ...smtp, port: Number(e.target.value) })} />
              </label>
              <label className="row" style={{ gap: 6, alignItems: 'center', marginTop: 18 }}>
                <input type="checkbox" checked={!!smtp.secure} onChange={(e) => setSmtp({ ...smtp, secure: e.target.checked })} />
                TLS (465)
              </label>
            </div>
            <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
              <label className="col" style={{ gap: 4, minWidth: 160 }}>
                <span>Username</span>
                <input className="input" value={smtp.username || ''} onChange={(e) => setSmtp({ ...smtp, username: e.target.value })} />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 160 }}>
                <span>Password {smtp.passwordSet ? '(задан)' : ''}</span>
                <input
                  className="input"
                  type="password"
                  placeholder={smtp.passwordSet ? 'оставьте пустым, чтобы не менять' : ''}
                  value={smtp.password || ''}
                  onChange={(e) => setSmtp({ ...smtp, password: e.target.value })}
                />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 180 }}>
                <span>From email</span>
                <input className="input" value={smtp.fromEmail || ''} onChange={(e) => setSmtp({ ...smtp, fromEmail: e.target.value })} />
              </label>
              <label className="col" style={{ gap: 4, minWidth: 140 }}>
                <span>From name</span>
                <input className="input" value={smtp.fromName || ''} onChange={(e) => setSmtp({ ...smtp, fromName: e.target.value })} />
              </label>
            </div>
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <button type="button" className="btn btn--primary" disabled={busy} onClick={save}>Сохранить SMTP</button>
              <input
                className="input"
                style={{ width: 220 }}
                placeholder="email для теста"
                value={testTo}
                onChange={(e) => setTestTo(e.target.value)}
              />
              <button type="button" className="btn" disabled={busy || !testTo} onClick={test}>Проверить отправку</button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

Object.assign(window, { PageSmtp });
