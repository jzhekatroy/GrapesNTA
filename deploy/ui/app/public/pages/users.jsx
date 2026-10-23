/* Users and access rights */

function usersT(key, params) {
  return GrapesI18n.t(key, params);
}

function usersOverrideOptions() {
  return [
    { id: 'INHERIT', label: usersT('usersPage.override.inherit') },
    { id: 'ALLOW', label: usersT('usersPage.override.allow') },
    { id: 'DENY', label: usersT('usersPage.override.deny') },
  ];
}

function usersRbacPageMeta(page) {
  return GrapesI18n.localizedPageMeta(page.id, page);
}

function PageUsers({ currentUser, onAuthRefresh, onNavigate, displayTimezone }) {
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
  const canDiagnostics = !!currentUser?.effectivePermissions?.diagnostics;

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
      setError(err.message || usersT('usersPage.loadFailed'));
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
      pushToast({ kind: 'success', title: usersT('usersPage.toast.userUpdated') });
    } else {
      await ApiClient.createUser(payload);
      pushToast({ kind: 'success', title: usersT('usersPage.toast.userCreated') });
    }
    setFormState(null);
    await loadAll();
  };

  const deleteBlockedReason = (user) => {
    if (user.roleId === 'Administrator') return usersT('usersPage.err.deleteAdmin');
    if (rows.length <= 1) return usersT('usersPage.err.deleteLastUser');
    return null;
  };

  const deleteUser = async (user) => {
    const blocked = deleteBlockedReason(user);
    if (blocked) {
      pushToast({ kind: 'error', title: usersT('usersPage.toast.deleteBlocked'), desc: blocked });
      return;
    }
    const ok = window.confirm(usersT('usersPage.confirm.deleteUser', { username: user.username }));
    if (!ok) return;
    try {
      await ApiClient.deleteUser(user.id);
      pushToast({ kind: 'success', title: usersT('usersPage.toast.userDeleted') });
      if (drawerUser?.id === user.id) setDrawerUser(null);
      await loadAll();
    } catch (err) {
      pushToast({ kind: 'error', title: usersT('usersPage.toast.deleteFailed'), desc: err.message });
    }
  };

  const changePassword = async (user, password) => {
    await ApiClient.changeUserPassword(user.id, { password });
    pushToast({ kind: 'success', title: usersT('usersPage.toast.passwordChanged') });
    setPasswordFor(null);
    await loadAll();
  };

  const userCols = [
    { key: 'fullName', title: usersT('usersPage.col.user'), width: 300, render: (u) => (
      <div className="row" style={{gap: 10}}>
        <div style={{
          width: 36, height: 36, borderRadius: 999,
          background: avatarBg(u.id),
          display: 'grid', placeItems: 'center',
          color: 'var(--fg-on-grad)', font: 'var(--pv-text-body-2-bold)',
          flexShrink: 0,
        }}>{userInitial(u)}</div>
        <div>
          <div style={{font: 'var(--pv-text-body-2-bold)', color: 'var(--fg-primary)'}}>{u.fullName}</div>
          <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>{u.username}</div>
        </div>
      </div>
    )},
    { key: 'roleId', title: usersT('usersPage.col.role'), width: 170, render: (u) => (
      <Badge tone={u.roleId === 'Administrator' ? 'critical' : 'neutral'}>
        {GrapesI18n.localizedRoleDisplay(u.roleId, roleMap[u.roleId]?.displayName)}
      </Badge>
    )},
    { key: 'forcePasswordChange', title: usersT('usersPage.col.forcePasswordChange'), width: 170, render: (u) => (
      u.forcePasswordChange
        ? <Badge tone="warning" dot>{usersT('usersPage.badge.required')}</Badge>
        : <Badge tone="success" dot>{usersT('usersPage.badge.notRequired')}</Badge>
    )},
    { key: 'createdAt', title: usersT('usersPage.col.createdAt'), width: 180, render: (u) => formatDateTime(u.createdAt, displayTimezone) },
    { key: 'passwordChangedAt', title: usersT('usersPage.col.passwordChangedAt'), width: 180, render: (u) => formatDateTime(u.passwordChangedAt, displayTimezone) },
  ];

  const roleCols = [
    { key: 'name', title: usersT('usersPage.col.roleName'), width: 200, render: (r) => <code>{r.name}</code> },
    { key: 'displayName', title: usersT('usersPage.col.roleDisplayName'), width: 220, render: (r) => r.displayName },
    { key: 'updatedAt', title: usersT('usersPage.col.roleUpdatedAt'), width: 180, render: (r) => formatDateTime(r.updatedAt, displayTimezone) },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{usersT('usersPage.title')}</h1>
          <p>
            {usersT('usersPage.subtitle')}
            {canDiagnostics && (
              <>
                {usersT('usersPage.subtitleDiagnosticsPrefix')}
                <button
                  type="button"
                  className="link-btn"
                  style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}
                  onClick={() => (onNavigate ? onNavigate('diagnostics') : (location.hash = 'diagnostics'))}
                >
                  {usersT('usersPage.diagnostics')}
                </button>
                .
              </>
            )}
          </p>
        </div>
        <div className="row" style={{gap: 8}}>
          <Button kind="ghost" icon="refresh" onClick={loadAll} disabled={loading}>{usersT('chrome.refresh')}</Button>
          {tab === 'users' && canWrite && (
            <Button kind="primary" icon="users" onClick={() => setFormState({ mode: 'create' })}>{usersT('usersPage.addUser')}</Button>
          )}
          {tab === 'roles' && canWrite && (
            <Button kind="primary" icon="key" onClick={() => setRoleFormOpen(true)}>{usersT('usersPage.createRole')}</Button>
          )}
        </div>
      </div>

      <div className="row" style={{gap: 8, marginBottom: 16}}>
        <Button kind={tab === 'users' ? 'primary' : 'ghost'} onClick={() => setTab('users')}>{usersT('usersPage.tab.users')}</Button>
        <Button kind={tab === 'roles' ? 'primary' : 'ghost'} onClick={() => setTab('roles')}>{usersT('usersPage.tab.roles')}</Button>
        {canWrite && (
          <Button kind={tab === 'sections' ? 'primary' : 'ghost'} onClick={() => setTab('sections')}>{usersT('usersPage.tab.sections')}</Button>
        )}
      </div>

      {error && (
        <Card pad="sm" style={{marginBottom: 16}}>
          <div className="form-error">{error}</div>
        </Card>
      )}

      {tab === 'sections' && canWrite ? (
        <ObservationSectionsPanel roles={roles} />
      ) : tab === 'users' ? (
        <DataTable
          key="users-table"
          rows={filtered}
          columns={userCols}
          rowKey="id"
          pageSize={10}
          onRowClick={canWrite ? (u) => setDrawerUser(u) : undefined}
          emptyTitle={loading ? usersT('usersPage.empty.loadingTitle') : usersT('usersPage.empty.usersTitle')}
          emptyDesc={loading ? usersT('usersPage.empty.usersLoadingDesc') : usersT('usersPage.empty.usersDesc')}
          toolbar={{
            search,
            onSearch: setSearch,
            left: (
              <select className="input" style={{maxWidth: 220}} value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
                <option value="all">{usersT('usersPage.filter.allRoles')}</option>
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>{GrapesI18n.localizedRoleDisplay(r.id, r.displayName)}</option>
                ))}
              </select>
            ),
          }}
          rowActions={(u) => canWrite ? (
            <div className="row" style={{gap: 4, justifyContent: 'flex-end'}}>
              {canChangePassword && (
                <button className="icon-btn tt" data-tt={usersT('usersPage.tt.changePassword')} onClick={(e) => { e.stopPropagation(); setPasswordFor(u); }}><Icon name="key" size={15} /></button>
              )}
              <button className="icon-btn tt" data-tt={usersT('usersPage.tt.edit')} onClick={(e) => { e.stopPropagation(); setFormState({ mode: 'edit', user: u }); }}><Icon name="edit" size={15} /></button>
              {!deleteBlockedReason(u) && (
                <button className="icon-btn tt" data-tt={usersT('usersPage.tt.delete')} onClick={(e) => { e.stopPropagation(); deleteUser(u); }}><Icon name="trash" size={15} /></button>
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
          emptyTitle={loading ? usersT('usersPage.empty.loadingTitle') : usersT('usersPage.empty.rolesTitle')}
          emptyDesc={usersT('usersPage.empty.rolesDesc')}
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
        displayTimezone={displayTimezone}
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

const OBS_SECTION_EXCLUDED_ROLES = new Set(['Administrator', 'Client']);

function observationSectionRoleLevelLabel(level) {
  if (level === 'edit') return usersT('users.sections.roleLevel.edit');
  if (level === 'view') return usersT('users.sections.roleLevel.view');
  return usersT('users.sections.roleLevel.none');
}

function ObservationSectionsPanel({ roles }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [newTitle, setNewTitle] = useState('');
  const [editSection, setEditSection] = useState(null);
  const [dragId, setDragId] = useState(null);

  const manageableRoles = useMemo(
    () => roles.filter((r) => !OBS_SECTION_EXCLUDED_ROLES.has(r.id)),
    [roles],
  );

  const loadSections = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await ApiClient.loadObservationSectionsAdmin();
      setRows(data || []);
    } catch (err) {
      setError(err.message || usersT('usersPage.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadSections(); }, [loadSections]);

  const createSection = async () => {
    const title = String(newTitle || '').trim();
    if (!title) return;
    try {
      await ApiClient.createObservationSection(title);
      setNewTitle('');
      pushToast({ kind: 'success', title: usersT('users.sections.created') });
      await loadSections();
    } catch (err) {
      pushToast({ kind: 'error', title: err.message });
    }
  };

  const deleteSection = async (section) => {
    const ok = window.confirm(usersT('users.sections.deleteConfirm', {
      title: section.title,
      count: section.count ?? 0,
    }));
    if (!ok) return;
    try {
      const res = await ApiClient.deleteObservationSection(section.id);
      pushToast({
        kind: 'success',
        title: usersT('users.sections.deleted'),
        desc: usersT('users.sections.moved', { n: res.moved ?? 0 }),
      });
      await loadSections();
    } catch (err) {
      pushToast({ kind: 'error', title: err.message });
    }
  };

  const persistOrder = async (ordered) => {
    try {
      await ApiClient.reorderObservationSections(ordered.map((s) => s.id));
      setRows(ordered);
    } catch (err) {
      pushToast({ kind: 'error', title: err.message });
      await loadSections();
    }
  };

  const onDropRow = (targetId) => {
    if (!dragId || dragId === targetId) return;
    const ids = rows.map((r) => r.id);
    const from = ids.indexOf(dragId);
    const to = ids.indexOf(targetId);
    if (from < 0 || to < 0) return;
    const next = [...rows];
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    setDragId(null);
    persistOrder(next);
  };

  const openEdit = (section) => {
    const roleLevels = {};
    manageableRoles.forEach((r) => {
      roleLevels[r.id] = section.roles?.[r.id] || 'none';
    });
    setEditSection({
      id: section.id,
      title: section.title,
      system: section.system,
      roles: roleLevels,
    });
  };

  const saveEdit = async () => {
    if (!editSection) return;
    try {
      await ApiClient.updateObservationSection(editSection.id, {
        title: editSection.title,
        roles: editSection.roles,
      });
      pushToast({ kind: 'success', title: usersT('users.sections.saved') });
      setEditSection(null);
      await loadSections();
    } catch (err) {
      pushToast({ kind: 'error', title: err.message });
    }
  };

  return (
    <div className="col" style={{ gap: 16 }}>
      {error && <div className="form-error">{error}</div>}
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <input
          className="input"
          style={{ maxWidth: 320 }}
          placeholder={usersT('users.sections.newTitle')}
          value={newTitle}
          onChange={(e) => setNewTitle(e.target.value)}
        />
        <Button kind="primary" onClick={createSection} disabled={!newTitle.trim()}>{usersT('users.sections.create')}</Button>
      </div>
      {loading ? (
        <div style={{ color: 'var(--fg-secondary)' }}>{usersT('usersPage.empty.loadingTitle')}</div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <thead>
            <tr>
              <th style={{ width: 36 }} />
              <th>{usersT('users.sections.col.title')}</th>
              <th style={{ width: 100 }}>{usersT('users.sections.col.count')}</th>
              <th>{usersT('users.sections.col.roles')}</th>
              <th style={{ width: 120 }} />
            </tr>
          </thead>
          <tbody>
            {rows.map((section) => (
              <tr
                key={section.id}
                draggable
                onDragStart={() => setDragId(section.id)}
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => onDropRow(section.id)}
              >
                <td style={{ cursor: 'grab' }}><Icon name="drag" size={14} /></td>
                <td>
                  {section.title}
                  {section.system ? (
                    <span style={{ marginLeft: 8, color: 'var(--fg-muted)' }}>({usersT('users.sections.system')})</span>
                  ) : null}
                </td>
                <td>{section.count ?? 0}</td>
                <td>
                  <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                    {Object.entries(section.roles || {}).map(([roleId, level]) => (
                      <Badge key={roleId} tone="neutral">
                        {usersT('users.sections.roleChip', {
                          role: GrapesI18n.localizedRoleDisplay(roleId, roleId),
                          level: level === 'edit' ? usersT('users.sections.roleLevel.edit') : usersT('users.sections.roleLevel.view'),
                        })}
                      </Badge>
                    ))}
                  </div>
                </td>
                <td>
                  <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
                    <button type="button" className="icon-btn" onClick={() => openEdit(section)}><Icon name="edit" size={15} /></button>
                    {!section.system && (
                      <button type="button" className="icon-btn" onClick={() => deleteSection(section)}><Icon name="trash" size={15} /></button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {editSection ? (
        <div className="modal-backdrop" role="presentation" onClick={() => setEditSection(null)}>
          <div className="modal" role="dialog" style={{ maxWidth: 560 }} onClick={(e) => e.stopPropagation()}>
            <h2 style={{ marginTop: 0 }}>{usersT('users.sections.modalTitle')}</h2>
            <label className="col" style={{ gap: 4, marginBottom: 12 }}>
              <span>{usersT('users.sections.col.title')}</span>
              <input
                className="input"
                value={editSection.title}
                onChange={(e) => setEditSection({ ...editSection, title: e.target.value })}
              />
            </label>
            <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)', marginBottom: 12 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left' }}>{usersT('usersPage.col.role')}</th>
                  <th style={{ textAlign: 'left' }}>{usersT('users.sections.col.roles')}</th>
                </tr>
              </thead>
              <tbody>
                {manageableRoles.map((role) => (
                  <tr key={role.id}>
                    <td>{GrapesI18n.localizedRoleDisplay(role.id, role.displayName)}</td>
                    <td>
                      <select
                        className="input"
                        value={editSection.roles[role.id] || 'none'}
                        onChange={(e) => setEditSection({
                          ...editSection,
                          roles: { ...editSection.roles, [role.id]: e.target.value },
                        })}
                      >
                        <option value="none">{usersT('users.sections.roleLevel.none')}</option>
                        <option value="view">{usersT('users.sections.roleLevel.view')}</option>
                        <option value="edit">{usersT('users.sections.roleLevel.edit')}</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p style={{ color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>{usersT('users.sections.adminHint')}</p>
            <div className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
              <Button kind="ghost" onClick={() => setEditSection(null)}>{usersT('usersPage.cancel')}</Button>
              <Button kind="primary" onClick={saveEdit}>{usersT('usersPage.save')}</Button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function UserDrawer({ user, roles, resources, displayTimezone, onClose, onSaved }) {
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
      pushToast({ kind: 'success', title: usersT('usersPage.toast.permissionsSaved') });
      await onSaved();
      onClose();
    } catch (err) {
      setError(err.message || usersT('usersPage.err.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const overrideOptions = usersOverrideOptions();

  return (
    <SidePanel
      open={!!user}
      onClose={onClose}
      title={user?.fullName || usersT('user.fallbackName')}
      subtitle={user ? usersT('usersPage.drawer.userSubtitle', {
        username: user.username,
        time: formatDateTime(user.createdAt, displayTimezone),
      }) : ''}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>{usersT('usersPage.cancel')}</Button>
          <Button kind="primary" icon="save" onClick={save} disabled={saving || loading}>
            {saving ? usersT('usersPage.saving') : usersT('usersPage.save')}
          </Button>
        </>
      }
    >
      {user && (
        <div className="col" style={{gap: 16}}>
          <div className="field">
            <label>{usersT('usersPage.label.role')}</label>
            <select className="input" value={roleId} onChange={(e) => setRoleId(e.target.value)}>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>{GrapesI18n.localizedRoleDisplay(r.id, r.displayName)}</option>
              ))}
            </select>
          </div>
          <SwitchField
            label={usersT('usersPage.forcePasswordChange.label')}
            hint={usersT('usersPage.forcePasswordChange.hintDrawer')}
            checked={forcePasswordChange}
            onChange={setForcePasswordChange}
          />
          <div>
            <div style={{font: 'var(--pv-text-body-2-bold)', marginBottom: 8}}>{usersT('usersPage.pageAccess')}</div>
            {loading ? (
              <div style={{color: 'var(--fg-secondary)'}}>{usersT('usersPage.loading')}</div>
            ) : (
              <div className="col" style={{gap: 8}}>
                {resources.map((page) => {
                  const meta = usersRbacPageMeta(page);
                  return (
                    <div key={page.id} className="row" style={{justifyContent: 'space-between', gap: 12}}>
                      <div>
                        <div style={{font: 'var(--pv-text-body-2-bold)'}}>{meta.title}</div>
                        <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>{meta.section}</div>
                      </div>
                      <select
                        className="input"
                        style={{maxWidth: 160}}
                        value={overrides[page.id] || 'INHERIT'}
                        onChange={(e) => setOverrides((s) => ({ ...s, [page.id]: e.target.value }))}
                      >
                        {overrideOptions.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
                      </select>
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

function RoleDrawer({ role, resources, onClose, onSaved, onDeleted }) {
  const [displayName, setDisplayName] = useState('');
  const [startPage, setStartPage] = useState('dashboard');
  const [attackAlert, setAttackAlert] = useState(false);
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
        setStartPage(data.startPage || 'dashboard');
        setAttackAlert(!!data.attackAlert);
        setPermissions(data.permissions || {});
        setWritePermissions(data.writePermissions || {});
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [role?.id]);

  const allowedStartPages = useMemo(
    () => resources.filter((page) => permissions[page.id]),
    [resources, permissions],
  );

  useEffect(() => {
    if (startPage === 'dashboard') return;
    if (!permissions[startPage]) setStartPage('dashboard');
  }, [permissions, startPage]);

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
      await ApiClient.updateRole(role.id, {
        displayName,
        startPage,
        attackAlert,
        permissions,
        writePermissions,
      });
      pushToast({ kind: 'success', title: usersT('usersPage.toast.roleSaved') });
      await onSaved();
      onClose();
    } catch (err) {
      setError(err.message || usersT('usersPage.err.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!role || isStandard) return;
    const ok = window.confirm(usersT('usersPage.confirm.deleteRole', { name: role.displayName }));
    if (!ok) return;
    try {
      await ApiClient.deleteRole(role.id);
      pushToast({ kind: 'success', title: usersT('usersPage.toast.roleDeleted') });
      onDeleted();
    } catch (err) {
      pushToast({ kind: 'error', title: usersT('usersPage.toast.roleDeleteFailed'), desc: err.message });
    }
  };

  return (
    <SidePanel
      open={!!role}
      onClose={onClose}
      title={role?.displayName || usersT('usersPage.drawer.roleTitleFallback')}
      subtitle={role ? usersT('usersPage.drawer.roleSubtitle', { name: role.name }) : ''}
      footer={
        <>
          {!isStandard && (
            <Button kind="ghost" onClick={remove}>{usersT('usersPage.delete')}</Button>
          )}
          <span style={{flex: 1}} />
          <Button kind="ghost" onClick={onClose}>{usersT('usersPage.cancel')}</Button>
          <Button kind="primary" icon="save" onClick={save} disabled={saving || loading}>
            {saving ? usersT('usersPage.saving') : usersT('usersPage.save')}
          </Button>
        </>
      }
    >
      {role && (
        <div className="col" style={{gap: 16}}>
          <div className="field">
            <label>{usersT('usersPage.label.systemName')}</label>
            <input className="input" value={role.name} disabled />
          </div>
          <div className="field">
            <label>{usersT('usersPage.label.displayName')}</label>
            <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </div>
          <div className="field">
            <label>{usersT('usersPage.label.startPage')}</label>
            <select
              className="input"
              value={startPage}
              onChange={(e) => setStartPage(e.target.value)}
              disabled={loading || allowedStartPages.length === 0}
            >
              {allowedStartPages.map((page) => {
                const meta = usersRbacPageMeta(page);
                return (
                  <option key={page.id} value={page.id}>
                    {meta.title}
                  </option>
                );
              })}
            </select>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 6 }}>
              {usersT('usersPage.label.startPageHint')}
            </div>
          </div>
          <label className="row" style={{ gap: 8, cursor: 'pointer', alignItems: 'flex-start' }}>
            <Checkbox checked={attackAlert} onChange={setAttackAlert} />
            <div>
              <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{usersT('usersPage.label.attackAlert')}</div>
              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 4 }}>
                {usersT('usersPage.label.attackAlertHint')}
              </div>
            </div>
          </label>
          <div>
            <div style={{font: 'var(--pv-text-body-2-bold)', marginBottom: 8}}>{usersT('usersPage.pageAccess')}</div>
            {loading ? (
              <div style={{color: 'var(--fg-secondary)'}}>{usersT('usersPage.loading')}</div>
            ) : (
              <div className="col" style={{gap: 8}}>
                {resources.map((page) => {
                  const hasAccess = !!permissions[page.id];
                  const canWrite = !!writePermissions[page.id];
                  const meta = usersRbacPageMeta(page);
                  return (
                    <div key={page.id} className="row" style={{justifyContent: 'space-between', gap: 12, alignItems: 'center'}}>
                      <div>
                        <div style={{font: 'var(--pv-text-body-2-bold)'}}>{meta.title}</div>
                        <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>{meta.section}</div>
                      </div>
                      <div className="row" style={{gap: 16, flexShrink: 0}}>
                        <label className="row" style={{gap: 6, cursor: 'pointer', font: 'var(--pv-text-body-3)'}}>
                          <Checkbox
                            checked={hasAccess}
                            onChange={(v) => setAccess(page.id, v)}
                          />
                          <span>{usersT('usersPage.access.view')}</span>
                        </label>
                        <label className="row" style={{gap: 6, cursor: hasAccess ? 'pointer' : 'not-allowed', font: 'var(--pv-text-body-3)', opacity: hasAccess ? 1 : 0.45}}>
                          <Checkbox
                            checked={canWrite}
                            disabled={!hasAccess}
                            onChange={(v) => setWritePermissions((s) => ({ ...s, [page.id]: v }))}
                          />
                          <span>{usersT('usersPage.access.write')}</span>
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
    if (!name.trim()) { setError(usersT('usersPage.err.roleNameRequired')); return; }
    if (!displayName.trim()) { setError(usersT('usersPage.err.roleDisplayNameRequired')); return; }
    setSaving(true);
    try {
      const role = await ApiClient.createRole({ name: name.trim(), displayName: displayName.trim() });
      pushToast({ kind: 'success', title: usersT('usersPage.toast.roleCreated') });
      onCreated(role);
    } catch (err) {
      setError(err.message || usersT('usersPage.err.roleCreateFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={usersT('usersPage.roleModal.title')}
      subtitle={usersT('usersPage.roleModal.subtitle')}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>{usersT('usersPage.cancel')}</Button>
          <Button kind="primary" onClick={submit} disabled={saving}>{saving ? usersT('usersPage.creating') : usersT('usersPage.create')}</Button>
        </>
      }
    >
      <div className="col" style={{gap: 14}}>
        <div className="field">
          <label>{usersT('usersPage.label.systemName')}</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={usersT('usersPage.roleModal.placeholder.name')} />
        </div>
        <div className="field">
          <label>{usersT('usersPage.label.displayName')}</label>
          <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder={usersT('usersPage.roleModal.placeholder.displayName')} />
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
          background: 'var(--pv-white-main)',
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

function parseUserTimestampMs(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  const text = String(value).trim();
  if (!text) return null;
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(text) && !/(?:[zZ]|[+-]\d{2}:?\d{2})$/.test(text)) {
    const isoLike = text.replace(' ', 'T');
    const ms = Date.parse(isoLike.endsWith('Z') ? isoLike : `${isoLike}Z`);
    return Number.isNaN(ms) ? null : ms;
  }
  const ms = Date.parse(text);
  return Number.isNaN(ms) ? null : ms;
}

function formatDateTime(value, displayTimezone) {
  const ms = parseUserTimestampMs(value);
  if (ms == null) return value ? String(value) : '—';
  const tz = displayTimezone || (typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined);
  const intlLoc = (typeof GrapesI18n !== 'undefined' && GrapesI18n.intlLocale)
    ? GrapesI18n.intlLocale()
    : 'ru-RU';
  return new Date(ms).toLocaleString(intlLoc, {
    dateStyle: 'short',
    timeStyle: 'short',
    ...(tz ? { timeZone: tz } : {}),
  });
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
    if (!fullName.trim()) { setError(usersT('usersPage.err.fullNameRequired')); return; }
    if (!username.trim()) { setError(usersT('usersPage.err.usernameRequired')); return; }
    if (!isEdit && password.length < 12) { setError(usersT('usersPage.err.passwordMinLength')); return; }
    setSaving(true);
    try {
      await onSubmit({
        fullName: fullName.trim(),
        username: username.trim(),
        ...(isEdit ? {} : { password, roleId, forcePasswordChange }),
      });
    } catch (err) {
      setError(err.message || usersT('usersPage.err.userSaveFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEdit ? usersT('usersPage.userModal.editTitle') : usersT('usersPage.userModal.inviteTitle')}
      subtitle={isEdit ? usersT('usersPage.userModal.editSubtitle') : usersT('usersPage.userModal.createSubtitle')}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>{usersT('usersPage.cancel')}</Button>
          <Button kind="primary" icon={isEdit ? 'save' : 'users'} onClick={submit} disabled={saving}>
            {saving ? usersT('usersPage.saving') : (isEdit ? usersT('usersPage.save') : usersT('usersPage.create'))}
          </Button>
        </>
      }
    >
      <div className="grid grid--2col">
        <div className="field" style={{gridColumn: '1 / -1'}}>
          <label>{usersT('usersPage.label.fullName')}</label>
          <input className="input" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder={usersT('usersPage.userModal.placeholder.fullName')} />
        </div>
        <div className="field" style={{gridColumn: '1 / -1'}}>
          <label>{usersT('usersPage.label.username')}</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} placeholder={usersT('usersPage.userModal.placeholder.username')} />
        </div>
        {!isEdit && (
          <>
            <div className="field" style={{gridColumn: '1 / -1'}}>
              <label>{usersT('usersPage.label.password')}</label>
              <div className="row" style={{gap: 8}}>
                <input
                  className="input"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={usersT('usersPage.passwordPlaceholder')}
                />
                <Button kind="ghost" onClick={() => setPassword(generatePassword())}>{usersT('usersPage.generatePassword')}</Button>
                <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>{showPassword ? usersT('usersPage.hidePassword') : usersT('usersPage.showPassword')}</Button>
              </div>
            </div>
            <div className="field" style={{gridColumn: '1 / -1'}}>
              <label>{usersT('usersPage.label.role')}</label>
              <select className="input" value={roleId} onChange={(e) => setRoleId(e.target.value)}>
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>{GrapesI18n.localizedRoleDisplay(r.id, r.displayName)}</option>
                ))}
              </select>
            </div>
            <div style={{gridColumn: '1 / -1'}}>
              <SwitchField
                label={usersT('usersPage.forcePasswordChange.label')}
                hint={usersT('usersPage.forcePasswordChange.hintCreate')}
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
    if (password.length < 12) { setError(usersT('usersPage.err.passwordMinLength')); return; }
    setSaving(true);
    try {
      await onSubmit(user, password);
    } catch (err) {
      setError(err.message || usersT('usersPage.err.changePwdFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={!!user}
      onClose={onClose}
      title={usersT('usersPage.changePwd.title')}
      subtitle={user ? `${user.fullName} · ${user.username}` : ''}
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>{usersT('usersPage.cancel')}</Button>
          <Button kind="primary" icon="key" onClick={submit} disabled={saving}>{saving ? usersT('usersPage.saving') : usersT('usersPage.changePwd.submit')}</Button>
        </>
      }
    >
      <div className="field">
        <label>{usersT('usersPage.changePwd.newPassword')}</label>
        <div className="row" style={{gap: 8}}>
          <input
            className="input"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={usersT('usersPage.passwordPlaceholder')}
          />
          <Button kind="ghost" onClick={() => setPassword(generatePassword())}>{usersT('usersPage.generatePassword')}</Button>
          <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>{showPassword ? usersT('usersPage.hidePassword') : usersT('usersPage.showPassword')}</Button>
        </div>
      </div>
      {error && <div className="form-error" style={{marginTop: 12}}>{error}</div>}
    </Modal>
  );
}

Object.assign(window, { PageUsers });
