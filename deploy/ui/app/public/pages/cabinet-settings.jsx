/* Настройки личного кабинета клиента */

function cabinetSettingsT(key, params) {
  return GrapesI18n.t(key, params);
}

function cabinetBindModeLabel(bindMode) {
  if (bindMode === 'prefixes') return cabinetSettingsT('cabinet.settings.bindMode.prefixes');
  if (bindMode === 'ports') return cabinetSettingsT('cabinet.settings.bindMode.ports');
  return bindMode || '—';
}

function cabinetSourceLabel(source) {
  if (source === 'erp') return cabinetSettingsT('cabinet.settings.source.erp');
  if (source === 'manual') return cabinetSettingsT('cabinet.settings.source.manual');
  return source || '—';
}

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
      setProfileError(cabinetSettingsT('cabinet.settings.fullNameRequired'));
      return;
    }
    setSavingProfile(true);
    try {
      const data = await ApiClient.patchCabinetProfile({ fullName: name });
      setProfile(data);
      setFullName(data.fullName || name);
      pushToast({ kind: 'success', title: cabinetSettingsT('cabinet.settings.profileSaved') });
      if (onAuthRefresh) await onAuthRefresh();
    } catch (err) {
      setProfileError(err.message || cabinetSettingsT('cabinet.settings.saveProfileFailed'));
    } finally {
      setSavingProfile(false);
    }
  };

  if (loading) {
    return (
      <div className="page">
        <Card title={cabinetSettingsT('cabinet.settings.title')}>
          <div style={{ color: 'var(--fg-secondary)' }}>{cabinetSettingsT('dashboard.loading')}</div>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page">
        <Card title={cabinetSettingsT('cabinet.settings.title')}>
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
            {cabinetSettingsT('cabinet.settings.readOnlyMode')}
          </div>
        </Card>
      )}

      <Card title={cabinetSettingsT('cabinet.settings.myProfile')} subtitle={cabinetSettingsT('cabinet.settings.myProfileSub')}>
        <div className="col" style={{ gap: 14, maxWidth: 520 }}>
          <div className="field">
            <label>{cabinetSettingsT('cabinet.settings.login')}</label>
            <input className="input mono" value={profile?.username || ''} readOnly disabled />
          </div>
          <div className="field">
            <label>{cabinetSettingsT('cabinet.settings.fullName')}</label>
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
                {savingProfile ? cabinetSettingsT('cabinet.settings.saving') : cabinetSettingsT('cabinet.settings.save')}
              </Button>
              <Button kind="ghost" icon="key" onClick={() => setPasswordOpen(true)}>
                {cabinetSettingsT('cabinet.settings.changePassword')}
              </Button>
            </div>
          )}
          {profileError && <div className="form-error">{profileError}</div>}
        </div>
      </Card>

      <Card title={cabinetSettingsT('cabinet.settings.company')} subtitle={cabinetSettingsT('cabinet.settings.companySub')}>
        <div className="col" style={{ gap: 14, maxWidth: 520 }}>
          <div className="field">
            <label>{cabinetSettingsT('cabinet.settings.companyName')}</label>
            <input className="input" value={company?.displayName || ''} readOnly disabled />
            {company?.source === 'erp' && (
              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 6 }}>
                {cabinetSettingsT('cabinet.settings.companyErpHint')}
              </div>
            )}
          </div>
          <div className="field">
            <label>{cabinetSettingsT('cabinet.settings.clientId')}</label>
            <input className="input mono" value={company?.clientId || ''} readOnly disabled />
          </div>
          <div className="field">
            <label>{cabinetSettingsT('cabinet.settings.bindMode')}</label>
            <input
              className="input"
              value={cabinetBindModeLabel(company?.bindMode)}
              readOnly
              disabled
            />
          </div>
          <div className="field">
            <label>{cabinetSettingsT('cabinet.settings.dataSource')}</label>
            <input
              className="input"
              value={cabinetSourceLabel(company?.source)}
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
          pushToast({ kind: 'success', title: cabinetSettingsT('cabinet.settings.passwordChanged') });
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
      setError(cabinetSettingsT('cabinet.settings.passwordMinLength'));
      return;
    }
    setSaving(true);
    try {
      await ApiClient.changeCabinetProfilePassword({ password });
      if (onSaved) await onSaved();
    } catch (err) {
      setError(err.message || cabinetSettingsT('cabinet.settings.passwordChangeFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={cabinetSettingsT('cabinet.settings.passwordModal.title')}
      footer={(
        <>
          <Button kind="ghost" onClick={onClose}>{cabinetSettingsT('period.cancel')}</Button>
          <Button kind="primary" icon="key" onClick={submit} disabled={saving}>
            {saving ? cabinetSettingsT('cabinet.settings.saving') : cabinetSettingsT('cabinet.settings.changePassword')}
          </Button>
        </>
      )}
    >
      <div className="field">
        <label>{cabinetSettingsT('cabinet.settings.newPassword')}</label>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <input
            className="input"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <Button kind="ghost" onClick={() => setPassword(generatePassword())}>{cabinetSettingsT('cabinet.settings.generate')}</Button>
          <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>
            {showPassword ? cabinetSettingsT('cabinet.settings.hide') : cabinetSettingsT('cabinet.settings.show')}
          </Button>
        </div>
      </div>
      {error && <div className="form-error" style={{ marginTop: 12 }}>{error}</div>}
    </Modal>
  );
}

Object.assign(window, { PageCabinetSettings });
