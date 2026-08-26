/* Настройки личного кабинета клиента */

const CABINET_BIND_MODE_LABELS = {
  prefixes: 'По IP-сетям',
  ports: 'По портам коммутатора',
};

const CABINET_SOURCE_LABELS = {
  erp: 'ERP PiterIX',
  manual: 'Создан вручную',
};

function generatePassword() {
  const groups = [
    'abcdefghijklmnopqrstuvwxyz',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '0123456789',
    '!@#$%^&*()-_=+[]{}',
  ];
  const pick = (chars) => chars[Math.floor(Math.random() * chars.length)];
  const parts = groups.map((group) => pick(group));
  const all = groups.join('');
  while (parts.length < 14) parts.push(pick(all));
  return parts.sort(() => Math.random() - 0.5).join('');
}

function PageCabinetSettings({ readOnly, onAuthRefresh }) {
  const [profile, setProfile] = useState(null);
  const [company, setCompany] = useState(null);
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [profileError, setProfileError] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);

  const loadProfile = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const body = await ApiClient.loadCabinetProfile();
      setProfile(body.data || null);
      setCompany(body.company || null);
      setFullName(body.data?.fullName || '');
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
      setProfile(null);
      setCompany(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProfile();
  }, [loadProfile]);

  const saveProfile = async () => {
    if (readOnly) return;
    setProfileError('');
    const name = fullName.trim();
    if (!name) {
      setProfileError('Укажите ФИО');
      return;
    }
    setSavingProfile(true);
    try {
      const data = await ApiClient.patchCabinetProfile({ fullName: name });
      setProfile(data);
      setFullName(data.fullName || name);
      pushToast({ kind: 'success', title: 'Профиль сохранён' });
      if (onAuthRefresh) await onAuthRefresh();
    } catch (err) {
      setProfileError(err.message || 'Не удалось сохранить профиль');
    } finally {
      setSavingProfile(false);
    }
  };

  if (loading) {
    return (
      <div className="page">
        <Card title="Настройки">
          <div style={{ color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page">
        <Card title="Настройки">
          <div className="form-error">{error}</div>
        </Card>
      </div>
    );
  }

  return (
    <div className="page col" style={{ gap: 16 }}>
      {readOnly && (
        <Card>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            Режим просмотра администратора
          </div>
        </Card>
      )}

      <Card title="Мой профиль" subtitle="Логин и пароль учётной записи">
        <div className="col" style={{ gap: 14, maxWidth: 520 }}>
          <div className="field">
            <label>Логин</label>
            <input className="input mono" value={profile?.username || ''} readOnly disabled />
          </div>
          <div className="field">
            <label>ФИО</label>
            <input
              className="input"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              disabled={readOnly}
              readOnly={readOnly}
            />
          </div>
          {!readOnly && (
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <Button kind="primary" icon="save" onClick={saveProfile} disabled={savingProfile}>
                {savingProfile ? 'Сохранение…' : 'Сохранить'}
              </Button>
              <Button kind="ghost" icon="key" onClick={() => setPasswordOpen(true)}>
                Сменить пароль
              </Button>
            </div>
          )}
          {profileError && <div className="form-error">{profileError}</div>}
        </div>
      </Card>

      <Card title="Компания" subtitle="Сведения о вашей организации">
        <div className="col" style={{ gap: 14, maxWidth: 520 }}>
          <div className="field">
            <label>Название</label>
            <input className="input" value={company?.displayName || ''} readOnly disabled />
            {company?.source === 'erp' && (
              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 6 }}>
                Название компании обновляется из ERP. Для изменения обратитесь к оператору.
              </div>
            )}
          </div>
          <div className="field">
            <label>Идентификатор</label>
            <input className="input mono" value={company?.clientId || ''} readOnly disabled />
          </div>
          <div className="field">
            <label>Способ учёта трафика</label>
            <input
              className="input"
              value={CABINET_BIND_MODE_LABELS[company?.bindMode] || company?.bindMode || '—'}
              readOnly
              disabled
            />
          </div>
          <div className="field">
            <label>Источник данных</label>
            <input
              className="input"
              value={CABINET_SOURCE_LABELS[company?.source] || company?.source || '—'}
              readOnly
              disabled
            />
          </div>
        </div>
      </Card>

      <CabinetSettingsPasswordModal
        open={passwordOpen && !readOnly}
        onClose={() => setPasswordOpen(false)}
        onSaved={async () => {
          setPasswordOpen(false);
          pushToast({ kind: 'success', title: 'Пароль изменён' });
          await loadProfile();
          if (onAuthRefresh) await onAuthRefresh();
        }}
      />
    </div>
  );
}

function CabinetSettingsPasswordModal({ open, onClose, onSaved }) {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPassword(generatePassword());
    setShowPassword(false);
    setError('');
  }, [open]);

  const submit = async () => {
    setError('');
    if (password.length < 12) {
      setError('Пароль должен быть не короче 12 символов');
      return;
    }
    setSaving(true);
    try {
      await ApiClient.changeCabinetProfilePassword({ password });
      if (onSaved) await onSaved();
    } catch (err) {
      setError(err.message || 'Не удалось сменить пароль');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Сменить пароль"
      footer={(
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" icon="key" onClick={submit} disabled={saving}>
            {saving ? 'Сохранение…' : 'Сменить пароль'}
          </Button>
        </>
      )}
    >
      <div className="field">
        <label>Новый пароль</label>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <input
            className="input"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <Button kind="ghost" onClick={() => setPassword(generatePassword())}>Сгенерировать</Button>
          <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>{showPassword ? 'Скрыть' : 'Показать'}</Button>
        </div>
      </div>
      {error && <div className="form-error" style={{ marginTop: 12 }}>{error}</div>}
    </Modal>
  );
}

Object.assign(window, { PageCabinetSettings });
