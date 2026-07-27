/* Пользователи и права доступа */

const OVERRIDE_OPTIONS = [
  { id: 'INHERIT', label: 'Наследовать' },
  { id: 'ALLOW', label: 'Разрешить' },
  { id: 'DENY', label: 'Запретить' },
];

function PageUsers({ currentUser, onAuthRefresh }) {
  const [tab, setTab] = useState('users');
  const [rows, setRows] = useState([]);
  const [roles, setRoles] = useState([]);
  const [resources, setResources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [formState, setFormState] = useState(null);
  const [passwordFor, setPasswordFor] = useState(null);
  const [drawerUser, setDrawerUser] = useState(null);
  const [drawerRole, setDrawerRole] = useState(null);
  const [roleFormOpen, setRoleFormOpen] = useState(false);
  const canChangePassword = currentUser?.permissions?.includes('users.change_password');
  const canWrite = !!currentUser?.effectiveWritePermissions?.users;

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [users, roleList, pageList] = await Promise.all([
        ApiClient.loadUsers(),
        ApiClient.loadRoles(),
        ApiClient.loadRbacResources(),
      ]);
      setRows(users);
      setRoles(roleList);
      setResources(pageList);
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, []);

  const visibleResources = useMemo(
    () => resources.filter((p) => !p.hidden),
    [resources],
  );

  const roleMap = useMemo(() => Object.fromEntries(roles.map((r) => [r.id, r])), [roles]);

  const filtered = useMemo(() => rows.filter((u) => {
    if (roleFilter !== 'all' && u.roleId !== roleFilter) return false;
    if (!search) return true;
    const s = search.toLowerCase();
    return u.fullName.toLowerCase().includes(s) || u.username.toLowerCase().includes(s);
  }), [rows, search, roleFilter]);

  const saveUser = async (payload) => {
    if (formState?.mode === 'edit') {
      await ApiClient.updateUser(formState.user.id, payload);
      pushToast({ kind: 'success', title: 'Пользователь обновлён' });
    } else {
      await ApiClient.createUser(payload);
      pushToast({ kind: 'success', title: 'Пользователь создан' });
    }
    setFormState(null);
    await loadAll();
  };

  const deleteBlockedReason = (user) => {
    if (user.roleId === 'Administrator') return 'Нельзя удалить учётную запись администратора';
    if (rows.length <= 1) return 'Нельзя удалить последнего пользователя в системе';
    return null;
  };

  const deleteUser = async (user) => {
    const blocked = deleteBlockedReason(user);
    if (blocked) {
      pushToast({ kind: 'error', title: 'Удаление недоступно', desc: blocked });
      return;
    }
    const ok = window.confirm(`Удалить пользователя ${user.username}?`);
    if (!ok) return;
    try {
      await ApiClient.deleteUser(user.id);
      pushToast({ kind: 'success', title: 'Пользователь удалён' });
      if (drawerUser?.id === user.id) setDrawerUser(null);
      await loadAll();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить', desc: err.message });
    }
  };

  const changePassword = async (user, password) => {
    await ApiClient.changeUserPassword(user.id, { password });
    pushToast({ kind: 'success', title: 'Пароль изменён' });
    setPasswordFor(null);
    await loadAll();
  };

  const userCols = [
    { key: 'fullName', title: 'Пользователь', width: 300, render: (u) => (
      <div className="row" style={{gap: 10}}>
        <div style={{
          width: 36, height: 36, borderRadius: 999,
          background: avatarBg(u.id),
          display: 'grid', placeItems: 'center',
          color: '#fff', font: 'var(--pv-text-body-2-bold)',
          flexShrink: 0,
        }}>{userInitial(u)}</div>
        <div>
          <div style={{font: 'var(--pv-text-body-2-bold)', color: 'var(--fg-primary)'}}>{u.fullName}</div>
          <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>{u.username}</div>
        </div>
      </div>
    )},
    { key: 'roleId', title: 'Роль', width: 170, render: (u) => (
      <Badge tone={u.roleId === 'Administrator' ? 'critical' : 'neutral'}>
        {roleMap[u.roleId]?.displayName || roleLabel(u.roleId)}
      </Badge>
    )},
    { key: 'forcePasswordChange', title: 'Смена пароля', width: 170, render: (u) => (
      u.forcePasswordChange
        ? <Badge tone="warning" dot>Требуется</Badge>
        : <Badge tone="success" dot>Не требуется</Badge>
    )},
    { key: 'createdAt', title: 'Создан', width: 180, render: (u) => formatDateTime(u.createdAt) },
    { key: 'updatedAt', title: 'Изменён', width: 180, render: (u) => formatDateTime(u.updatedAt) },
  ];

  const roleCols = [
    { key: 'name', title: 'Системное имя', width: 200, render: (r) => <code>{r.name}</code> },
    { key: 'displayName', title: 'Отображаемое имя', width: 220, render: (r) => r.displayName },
    { key: 'updatedAt', title: 'Изменена', width: 180, render: (r) => formatDateTime(r.updatedAt) },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Пользователи и права доступа</h1>
          <p>Локальные учётные записи, роли и индивидуальные переопределения доступа к страницам.</p>
        </div>
        <div className="row" style={{gap: 8}}>
          <Button kind="ghost" icon="refresh" onClick={loadAll} disabled={loading}>Обновить</Button>
          {tab === 'users' && canWrite && (
            <Button kind="primary" icon="users" onClick={() => setFormState({ mode: 'create' })}>Добавить пользователя</Button>
          )}
          {tab === 'roles' && canWrite && (
            <Button kind="primary" icon="key" onClick={() => setRoleFormOpen(true)}>Создать роль</Button>
          )}
        </div>
      </div>

      <div className="row" style={{gap: 8, marginBottom: 16}}>
        <Button kind={tab === 'users' ? 'primary' : 'ghost'} onClick={() => setTab('users')}>Пользователи</Button>
        <Button kind={tab === 'roles' ? 'primary' : 'ghost'} onClick={() => setTab('roles')}>Роли</Button>
      </div>

      {tab === 'users' && (
        <div className="grid grid--4col grid--mb">
          <SumCard label="Всего пользователей" value={rows.length} icon="users" />
          <SumCard label="Ролей" value={roles.length} icon="key" />
          <SumCard label="Требуют смену пароля" value={rows.filter(u => u.forcePasswordChange).length} icon="clock" tone="warning" />
          <SumCard label="Страниц в реестре" value={visibleResources.length} icon="check" tone="success" />
        </div>
      )}

      {error && (
        <Card pad="sm" style={{marginBottom: 16}}>
          <div className="form-error">{error}</div>
        </Card>
      )}

      {tab === 'users' ? (
        <DataTable
          key="users-table"
          rows={filtered}
          columns={userCols}
          rowKey="id"
          pageSize={10}
          onRowClick={canWrite ? (u) => setDrawerUser(u) : undefined}
          emptyTitle={loading ? 'Загрузка...' : 'Пользователи не найдены'}
          emptyDesc={loading ? 'Получаем список пользователей.' : 'Создайте пользователя через форму.'}
          toolbar={{
            search,
            onSearch: setSearch,
            left: (
              <select className="input" style={{maxWidth: 220}} value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
                <option value="all">Все роли</option>
                {roles.map((r) => <option key={r.id} value={r.id}>{r.displayName}</option>)}
              </select>
            ),
          }}
          rowActions={(u) => canWrite ? (
            <div className="row" style={{gap: 4, justifyContent: 'flex-end'}}>
              {canChangePassword && (
                <button className="icon-btn tt" data-tt="Сменить пароль" onClick={(e) => { e.stopPropagation(); setPasswordFor(u); }}><Icon name="key" size={15} /></button>
              )}
              <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setFormState({ mode: 'edit', user: u }); }}><Icon name="edit" size={15} /></button>
              {!deleteBlockedReason(u) && (
                <button className="icon-btn tt" data-tt="Удалить" onClick={(e) => { e.stopPropagation(); deleteUser(u); }}><Icon name="trash" size={15} /></button>
              )}
            </div>
          ) : null}
        />
      ) : (
        <DataTable
          key="roles-table"
          rows={roles}
          columns={roleCols}
          rowKey="id"
          pageSize={10}
          onRowClick={canWrite ? (r) => setDrawerRole(r) : undefined}
          emptyTitle={loading ? 'Загрузка...' : 'Роли не найдены'}
          emptyDesc="Создайте роль для настройки доступа к страницам."
        />
      )}

      <UserFormModal
        state={formState}
        roles={roles}
        onClose={() => setFormState(null)}
        onSubmit={saveUser}
      />
      <ChangePasswordModal
        user={passwordFor}
        onClose={() => setPasswordFor(null)}
        onSubmit={changePassword}
      />
      <UserDrawer
        user={drawerUser}
        roles={roles}
        resources={visibleResources}
        onClose={() => setDrawerUser(null)}
        onSaved={async () => {
          await loadAll();
          if (drawerUser?.id === currentUser?.id && onAuthRefresh) await onAuthRefresh();
        }}
      />
      <RoleDrawer
        role={drawerRole}
        resources={visibleResources}
        onClose={() => setDrawerRole(null)}
        onSaved={loadAll}
        onDeleted={() => { setDrawerRole(null); loadAll(); }}
      />
      <RoleFormModal
        open={roleFormOpen}
        onClose={() => setRoleFormOpen(false)}
        onCreated={(role) => { setRoleFormOpen(false); loadAll(); setDrawerRole(role); }}
      />
    </div>
  );
}

function UserDrawer({ user, roles, resources, onClose, onSaved }) {
  const [roleId, setRoleId] = useState('');
  const [forcePasswordChange, setForcePasswordChange] = useState(false);
  const [overrides, setOverrides] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!user) return;
    setRoleId(user.roleId || '');
    setForcePasswordChange(!!user.forcePasswordChange);
    setError('');
    setLoading(true);
    ApiClient.loadUserPermissions(user.id)
      .then((data) => setOverrides(data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [user?.id]);

  const save = async () => {
    if (!user) return;
    setSaving(true);
    setError('');
    try {
      if (roleId !== user.roleId) await ApiClient.updateUserRole(user.id, roleId);
      if (forcePasswordChange !== !!user.forcePasswordChange) {
        await ApiClient.updateUser(user.id, {
          fullName: user.fullName,
          username: user.username,
          forcePasswordChange,
        });
      }
      await ApiClient.saveUserPermissions(user.id, overrides);
      pushToast({ kind: 'success', title: 'Права пользователя сохранены' });
      await onSaved();
      onClose();
    } catch (err) {
      setError(err.message || 'Не удалось сохранить');
    } finally {
      setSaving(false);
    }
  };

  return (
    <SidePanel
      open={!!user}
      onClose={onClose}
      title={user?.fullName || 'Пользователь'}
      subtitle={user ? `${user.username} · создан ${formatDateTime(user.createdAt)}` : ''}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" icon="save" onClick={save} disabled={saving || loading}>
            {saving ? 'Сохранение...' : 'Сохранить'}
          </Button>
        </>
      }
    >
      {user && (
        <div className="col" style={{gap: 16}}>
          <div className="field">
            <label>Роль</label>
            <select className="input" value={roleId} onChange={(e) => setRoleId(e.target.value)}>
              {roles.map((r) => <option key={r.id} value={r.id}>{r.displayName}</option>)}
            </select>
          </div>
          <SwitchField
            label="Требовать смену пароля при входе"
            hint="При следующем входе пользователь увидит только экран смены пароля."
            checked={forcePasswordChange}
            onChange={setForcePasswordChange}
          />
          <div>
            <div style={{font: 'var(--pv-text-body-2-bold)', marginBottom: 8}}>Доступ к страницам</div>
            {loading ? (
              <div style={{color: 'var(--fg-secondary)'}}>Загрузка...</div>
            ) : (
              <div className="col" style={{gap: 8}}>
                {resources.map((page) => (
                  <div key={page.id} className="row" style={{justifyContent: 'space-between', gap: 12}}>
                    <div>
                      <div style={{font: 'var(--pv-text-body-2-bold)'}}>{page.title}</div>
                      <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>{page.section}</div>
                    </div>
                    <select
                      className="input"
                      style={{maxWidth: 160}}
                      value={overrides[page.id] || 'INHERIT'}
                      onChange={(e) => setOverrides((s) => ({ ...s, [page.id]: e.target.value }))}
                    >
                      {OVERRIDE_OPTIONS.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
                    </select>
                  </div>
                ))}
              </div>
            )}
          </div>
          {error && <div className="form-error">{error}</div>}
        </div>
      )}
    </SidePanel>
  );
}

function RoleDrawer({ role, resources, onClose, onSaved, onDeleted }) {
  const [displayName, setDisplayName] = useState('');
  const [permissions, setPermissions] = useState({});
  const [writePermissions, setWritePermissions] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const isStandard = role && ['Administrator', 'Operator', 'ReadOnly'].includes(role.id);

  useEffect(() => {
    if (!role) return;
    setDisplayName(role.displayName || '');
    setError('');
    setLoading(true);
    ApiClient.loadRole(role.id)
      .then((data) => {
        setDisplayName(data.displayName || role.displayName);
        setPermissions(data.permissions || {});
        setWritePermissions(data.writePermissions || {});
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [role?.id]);

  const setAccess = (pageId, access) => {
    setPermissions((s) => ({ ...s, [pageId]: access }));
    if (!access) {
      setWritePermissions((s) => ({ ...s, [pageId]: false }));
    }
  };

  const save = async () => {
    if (!role) return;
    setSaving(true);
    setError('');
    try {
      await ApiClient.updateRole(role.id, { displayName, permissions, writePermissions });
      pushToast({ kind: 'success', title: 'Роль сохранена' });
      await onSaved();
      onClose();
    } catch (err) {
      setError(err.message || 'Не удалось сохранить');
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!role || isStandard) return;
    const ok = window.confirm(`Удалить роль ${role.displayName}?`);
    if (!ok) return;
    try {
      await ApiClient.deleteRole(role.id);
      pushToast({ kind: 'success', title: 'Роль удалена' });
      onDeleted();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить роль', desc: err.message });
    }
  };

  return (
    <SidePanel
      open={!!role}
      onClose={onClose}
      title={role?.displayName || 'Роль'}
      subtitle={role ? `Системное имя: ${role.name}` : ''}
      footer={
        <>
          {!isStandard && (
            <Button kind="ghost" onClick={remove}>Удалить</Button>
          )}
          <span style={{flex: 1}} />
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" icon="save" onClick={save} disabled={saving || loading}>
            {saving ? 'Сохранение...' : 'Сохранить'}
          </Button>
        </>
      }
    >
      {role && (
        <div className="col" style={{gap: 16}}>
          <div className="field">
            <label>Системное имя</label>
            <input className="input" value={role.name} disabled />
          </div>
          <div className="field">
            <label>Отображаемое имя</label>
            <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </div>
          <div>
            <div style={{font: 'var(--pv-text-body-2-bold)', marginBottom: 8}}>Доступ к страницам</div>
            {loading ? (
              <div style={{color: 'var(--fg-secondary)'}}>Загрузка...</div>
            ) : (
              <div className="col" style={{gap: 8}}>
                {resources.map((page) => {
                  const hasAccess = !!permissions[page.id];
                  const canWrite = !!writePermissions[page.id];
                  return (
                    <div key={page.id} className="row" style={{justifyContent: 'space-between', gap: 12, alignItems: 'center'}}>
                      <div>
                        <div style={{font: 'var(--pv-text-body-2-bold)'}}>{page.title}</div>
                        <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>{page.section}</div>
                      </div>
                      <div className="row" style={{gap: 16, flexShrink: 0}}>
                        <label className="row" style={{gap: 6, cursor: 'pointer', font: 'var(--pv-text-body-3)'}}>
                          <Checkbox
                            checked={hasAccess}
                            onChange={(v) => setAccess(page.id, v)}
                          />
                          <span>Просмотр</span>
                        </label>
                        <label className="row" style={{gap: 6, cursor: hasAccess ? 'pointer' : 'not-allowed', font: 'var(--pv-text-body-3)', opacity: hasAccess ? 1 : 0.45}}>
                          <Checkbox
                            checked={canWrite}
                            disabled={!hasAccess}
                            onChange={(v) => setWritePermissions((s) => ({ ...s, [page.id]: v }))}
                          />
                          <span>Изменение</span>
                        </label>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          {error && <div className="form-error">{error}</div>}
        </div>
      )}
    </SidePanel>
  );
}

function RoleFormModal({ open, onClose, onCreated }) {
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName('');
    setDisplayName('');
    setError('');
  }, [open]);

  const submit = async () => {
    setError('');
    if (!name.trim()) { setError('Укажите системное имя'); return; }
    if (!displayName.trim()) { setError('Укажите отображаемое имя'); return; }
    setSaving(true);
    try {
      const role = await ApiClient.createRole({ name: name.trim(), displayName: displayName.trim() });
      pushToast({ kind: 'success', title: 'Роль создана' });
      onCreated(role);
    } catch (err) {
      setError(err.message || 'Не удалось создать роль');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Создать роль"
      subtitle="Новой роли по умолчанию разрешён доступ ко всем страницам"
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" onClick={submit} disabled={saving}>{saving ? 'Создание...' : 'Создать'}</Button>
        </>
      }
    >
      <div className="col" style={{gap: 14}}>
        <div className="field">
          <label>Системное имя</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Analyst" />
        </div>
        <div className="field">
          <label>Отображаемое имя</label>
          <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Аналитик" />
        </div>
        {error && <div className="form-error">{error}</div>}
      </div>
    </Modal>
  );
}

function SwitchField({ label, hint, checked, onChange, disabled }) {
  return (
    <label className="switch-field" style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: disabled ? 'default' : 'pointer' }}>
      <button
        type="button"
        className="ui-switch"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        style={{
          width: 40,
          height: 22,
          borderRadius: 999,
          border: 'none',
          padding: 0,
          flexShrink: 0,
          cursor: disabled ? 'not-allowed' : 'pointer',
          background: checked ? 'var(--grad-primary)' : 'var(--surf-4)',
          position: 'relative',
          transition: 'background var(--pv-dur-fast)',
          opacity: disabled ? 0.6 : 1,
        }}
      >
        <span style={{
          position: 'absolute',
          top: 2,
          left: checked ? 20 : 2,
          width: 18,
          height: 18,
          borderRadius: '50%',
          background: '#fff',
          transition: 'left var(--pv-dur-fast)',
          boxShadow: '0 1px 3px rgba(0,0,0,0.25)',
        }} />
      </button>
      <span>
        <div style={{ font: 'var(--pv-text-body-2-bold)', color: 'var(--fg-primary)' }}>{label}</div>
        {hint && <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 2 }}>{hint}</div>}
      </span>
    </label>
  );
}

function avatarBg(id) {
  const palettes = [
    'linear-gradient(135deg, #7E92F8, #6972F0)',
    'linear-gradient(135deg, #51D16D, #3FA857)',
    'linear-gradient(135deg, #F0B400, #D47F00)',
    'linear-gradient(135deg, #F04138, #C2322B)',
    'linear-gradient(135deg, #A4ADFF, #7E92F8)',
  ];
  const h = String(id || '').split('').reduce((a, c) => a + c.charCodeAt(0), 0);
  return palettes[h % palettes.length];
}

function userInitial(user) {
  return (user.fullName || user.username || '?').trim().slice(0, 1).toUpperCase();
}

function roleLabel(roleId) {
  return roleId === 'Administrator' ? 'Администратор' : roleId;
}

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
}

function randomChar(chars) {
  const bytes = new Uint32Array(1);
  crypto.getRandomValues(bytes);
  return chars[bytes[0] % chars.length];
}

function generatePassword() {
  const groups = [
    'abcdefghijklmnopqrstuvwxyz',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '0123456789',
    '!@#$%^&*()-_=+[]{}',
  ];
  const chars = groups.join('');
  const seed = groups.map(randomChar);
  while (seed.length < 14) seed.push(randomChar(chars));
  return seed
    .map((ch) => ({ ch, sort: Math.random() }))
    .sort((a, b) => a.sort - b.sort)
    .map((x) => x.ch)
    .join('');
}

function UserFormModal({ state, roles, onClose, onSubmit }) {
  const open = !!state;
  const isEdit = state?.mode === 'edit';
  const user = state?.user;
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [roleId, setRoleId] = useState('Operator');
  const [forcePasswordChange, setForcePasswordChange] = useState(false);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setFullName(user?.fullName || '');
    setUsername(user?.username || '');
    setRoleId(user?.roleId || roles[0]?.id || 'Operator');
    setForcePasswordChange(!!user?.forcePasswordChange);
    setPassword('');
    setShowPassword(false);
    setError('');
  }, [open, user?.id, roles]);

  const submit = async () => {
    setError('');
    if (!fullName.trim()) { setError('Укажите ФИО'); return; }
    if (!username.trim()) { setError('Укажите username'); return; }
    if (!isEdit && password.length < 12) { setError('Пароль должен быть не короче 12 символов'); return; }
    setSaving(true);
    try {
      await onSubmit({
        fullName: fullName.trim(),
        username: username.trim(),
        ...(isEdit ? {} : { password, roleId, forcePasswordChange }),
      });
    } catch (err) {
      setError(err.message || 'Не удалось сохранить пользователя');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEdit ? 'Редактировать пользователя' : 'Пригласить пользователя'}
      subtitle={isEdit ? 'ФИО и username. Роль и права — в карточке пользователя.' : 'Создание локальной учётной записи'}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" icon={isEdit ? 'save' : 'users'} onClick={submit} disabled={saving}>
            {saving ? 'Сохранение...' : isEdit ? 'Сохранить' : 'Создать'}
          </Button>
        </>
      }
    >
      <div className="grid grid--2col">
        <div className="field" style={{gridColumn: '1 / -1'}}>
          <label>ФИО</label>
          <input className="input" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Иван Иванов" />
        </div>
        <div className="field" style={{gridColumn: '1 / -1'}}>
          <label>Username</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="ivanov" />
        </div>
        {!isEdit && (
          <>
            <div className="field" style={{gridColumn: '1 / -1'}}>
              <label>Пароль</label>
              <div className="row" style={{gap: 8}}>
                <input
                  className="input"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Минимум 12 символов"
                />
                <Button kind="ghost" onClick={() => setPassword(generatePassword())}>Сгенерировать пароль</Button>
                <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>{showPassword ? 'Скрыть' : 'Показать'}</Button>
              </div>
            </div>
            <div className="field" style={{gridColumn: '1 / -1'}}>
              <label>Роль</label>
              <select className="input" value={roleId} onChange={(e) => setRoleId(e.target.value)}>
                {roles.map((r) => <option key={r.id} value={r.id}>{r.displayName}</option>)}
              </select>
            </div>
            <div style={{gridColumn: '1 / -1'}}>
              <SwitchField
                label="Требовать смену пароля при входе"
                hint="Пользователь сменит пароль сразу после первого входа с выданным паролем."
                checked={forcePasswordChange}
                onChange={setForcePasswordChange}
              />
            </div>
          </>
        )}
        {error && <div className="form-error" style={{gridColumn: '1 / -1'}}>{error}</div>}
      </div>
    </Modal>
  );
}

function ChangePasswordModal({ user, onClose, onSubmit }) {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!user) return;
    setPassword('');
    setShowPassword(false);
    setError('');
  }, [user?.id]);

  const submit = async () => {
    setError('');
    if (password.length < 12) { setError('Пароль должен быть не короче 12 символов'); return; }
    setSaving(true);
    try {
      await onSubmit(user, password);
    } catch (err) {
      setError(err.message || 'Не удалось изменить пароль');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={!!user}
      onClose={onClose}
      title="Сменить пароль"
      subtitle={user ? `${user.fullName} · ${user.username}` : ''}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          <Button kind="primary" icon="key" onClick={submit} disabled={saving}>{saving ? 'Сохранение...' : 'Сменить пароль'}</Button>
        </>
      }
    >
      <div className="field">
        <label>Новый пароль</label>
        <div className="row" style={{gap: 8}}>
          <input
            className="input"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Минимум 12 символов"
          />
          <Button kind="ghost" onClick={() => setPassword(generatePassword())}>Сгенерировать пароль</Button>
          <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>{showPassword ? 'Скрыть' : 'Показать'}</Button>
        </div>
      </div>
      {error && <div className="form-error" style={{marginTop: 12}}>{error}</div>}
    </Modal>
  );
}

Object.assign(window, { PageUsers });
