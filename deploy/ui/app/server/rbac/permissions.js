const {
  config,
  query,
  insertRows,
  usersTableRef,
  rolesTableRef,
  rolePermissionsTableRef,
  userPermissionsTableRef,
} = require('../clickhouse');
const { pageIds } = require('./resources');
const { latestRolesCte, latestRolePermissionsCte } = require('./bootstrap');

const OVERRIDE_MODES = new Set(['INHERIT', 'ALLOW', 'DENY']);
const DEFAULT_ROLE_ID = 'Administrator';
const DEFAULT_NEW_USER_ROLE_ID = 'Operator';

function latestUserPermissionsCte() {
  return `
    latest AS (
      SELECT
        user_id,
        resource,
        mode,
        updated_at,
        row_number() OVER (PARTITION BY user_id, resource ORDER BY updated_at DESC) AS rn
      FROM ${userPermissionsTableRef()}
    )
  `;
}

function resolvePageAccess({ rolePermissions, userOverrides, resource }) {
  const override = userOverrides[resource];
  if (override === 'DENY') return false;
  if (override === 'ALLOW') return true;
  const perm = rolePermissions[resource];
  if (perm && typeof perm === 'object') return !!perm.access;
  return !!perm;
}

function resolvePageWrite({ rolePermissions, userOverrides, resource }) {
  if (!resolvePageAccess({ rolePermissions, userOverrides, resource })) return false;
  const perm = rolePermissions[resource];
  if (perm && typeof perm === 'object') return !!perm.write;
  return !!perm;
}

async function loadRolePermissions(roleId) {
  const { rows } = await query(
    `
      WITH ${latestRolePermissionsCte()}
      SELECT resource, allowed, can_write
      FROM latest
      WHERE rn = 1 AND role_id = {roleId:String}
    `,
    { roleId: String(roleId ?? '') },
    { name: 'rbac/load-role-permissions' },
  );
  const map = {};
  for (const row of rows) {
    const access = Number(row.allowed) === 1;
    map[String(row.resource)] = {
      access,
      write: access && Number(row.can_write ?? 1) === 1,
    };
  }
  return map;
}

async function loadUserOverrides(userId) {
  const { rows } = await query(
    `
      WITH ${latestUserPermissionsCte()}
      SELECT resource, mode
      FROM latest
      WHERE rn = 1 AND user_id = {userId:String}
    `,
    { userId: String(userId ?? '') },
    { name: 'rbac/load-user-overrides' },
  );
  const map = {};
  for (const row of rows) {
    const mode = String(row.mode ?? 'INHERIT').toUpperCase();
    if (OVERRIDE_MODES.has(mode)) map[String(row.resource)] = mode;
  }
  return map;
}

async function loadRole(roleId) {
  const { rows } = await query(
    `
      WITH ${latestRolesCte()}
      SELECT id, name, display_name, created_at, updated_at
      FROM latest
      WHERE rn = 1 AND id = {roleId:String}
      LIMIT 1
    `,
    { roleId: String(roleId ?? '') },
    { name: 'rbac/load-role' },
  );
  if (!rows[0]) return null;
  const row = rows[0];
  return {
    id: String(row.id),
    name: String(row.name),
    displayName: String(row.display_name ?? row.name),
    createdAt: row.created_at ?? null,
    updatedAt: row.updated_at ?? null,
  };
}

async function buildEffectivePermissions(user) {
  const roleId = user?.roleId || DEFAULT_ROLE_ID;
  const [rolePermissions, userOverrides] = await Promise.all([
    loadRolePermissions(roleId),
    loadUserOverrides(user?.id),
  ]);
  const effective = {};
  for (const resource of pageIds()) {
    effective[resource] = resolvePageAccess({ rolePermissions, userOverrides, resource });
  }
  return effective;
}

async function buildEffectiveWritePermissions(user) {
  const roleId = user?.roleId || DEFAULT_ROLE_ID;
  const [rolePermissions, userOverrides] = await Promise.all([
    loadRolePermissions(roleId),
    loadUserOverrides(user?.id),
  ]);
  const effective = {};
  for (const resource of pageIds()) {
    effective[resource] = resolvePageWrite({ rolePermissions, userOverrides, resource });
  }
  return effective;
}

async function canAccess(user, resource) {
  const effective = await buildEffectivePermissions(user);
  return !!effective[resource];
}

async function canWrite(user, resource) {
  const effective = await buildEffectiveWritePermissions(user);
  return !!effective[resource];
}

function canPerformAction(user, action, effectivePermissions, effectiveWritePermissions) {
  if (action === 'users.change_password') {
    return !!(effectivePermissions?.users || user?.roleId === DEFAULT_ROLE_ID);
  }
  return false;
}

async function userPermissions(user) {
  const effective = await buildEffectivePermissions(user);
  const actions = [];
  if (canPerformAction(user, 'users.change_password', effective)) {
    actions.push('users.change_password');
  }
  return actions;
}

async function hasPermission(user, permission) {
  const effective = await buildEffectivePermissions(user);
  return canPerformAction(user, permission, effective);
}

async function countUsersByRole(roleId) {
  const { rows } = await query(
    `
      WITH
        latest AS (
          SELECT
            id,
            role_id,
            row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
          FROM ${usersTableRef()}
        )
      SELECT count() AS count
      FROM latest
      WHERE rn = 1 AND role_id = {roleId:String}
    `,
    { roleId: String(roleId) },
    { name: 'rbac/count-users-by-role' },
  );
  return Number(rows[0]?.count) || 0;
}

function clickhouseDateTime(date = new Date()) {
  return date.toISOString().replace('T', ' ').replace('Z', '');
}

async function listRoles() {
  const { rows, elapsedMs } = await query(
    `
      WITH ${latestRolesCte()}
      SELECT id, name, display_name, created_at, updated_at
      FROM latest
      WHERE rn = 1
      ORDER BY name
    `,
    {},
    { name: 'rbac/list-roles' },
  );
  return {
    data: rows.map((row) => ({
      id: String(row.id),
      name: String(row.name),
      displayName: String(row.display_name ?? row.name),
      createdAt: row.created_at ?? null,
      updatedAt: row.updated_at ?? null,
    })),
    meta: { elapsedMs, rows: rows.length },
  };
}

async function getRoleWithPermissions(roleId) {
  const role = await loadRole(roleId);
  if (!role) return null;
  const rolePermissions = await loadRolePermissions(roleId);
  const permissions = {};
  const writePermissions = {};
  for (const resource of pageIds()) {
    const perm = rolePermissions[resource] || { access: false, write: false };
    permissions[resource] = !!perm.access;
    writePermissions[resource] = !!perm.write;
  }
  return { ...role, permissions, writePermissions };
}

async function createRole({ name, displayName }) {
  const roleName = String(name ?? '').trim();
  const roleDisplayName = String(displayName ?? roleName).trim();
  if (!roleName) {
    const err = new Error('Укажите системное имя роли');
    err.statusCode = 400;
    throw err;
  }
  if (!roleDisplayName) {
    const err = new Error('Укажите отображаемое имя роли');
    err.statusCode = 400;
    throw err;
  }

  const { rows } = await query(
    `
      WITH ${latestRolesCte()}
      SELECT count() AS count
      FROM latest
      WHERE rn = 1 AND (id = {id:String} OR name = {name:String})
    `,
    { id: roleName, name: roleName },
    { name: 'rbac/role-exists' },
  );
  if (Number(rows[0]?.count) > 0) {
    const err = new Error('Роль с таким именем уже существует');
    err.statusCode = 409;
    throw err;
  }

  const now = clickhouseDateTime();
  const role = {
    id: roleName,
    name: roleName,
    display_name: roleDisplayName,
    created_at: now,
    updated_at: now,
  };
  await insertRows(config.rolesTable, [role], { name: 'rbac/create-role' });

  const permRows = pageIds().map((resource) => ({
    role_id: roleName,
    resource,
    allowed: 1,
    can_write: 1,
    updated_at: now,
  }));
  await insertRows(config.rolePermissionsTable, permRows, { name: 'rbac/create-role-permissions' });

  return getRoleWithPermissions(roleName);
}

async function updateRole(roleId, { displayName, permissions, writePermissions }) {
  const existing = await loadRole(roleId);
  if (!existing) {
    const err = new Error('Роль не найдена');
    err.statusCode = 404;
    throw err;
  }

  const now = clickhouseDateTime();
  if (displayName !== undefined) {
    const nextDisplayName = String(displayName).trim();
    if (!nextDisplayName) {
      const err = new Error('Укажите отображаемое имя роли');
      err.statusCode = 400;
      throw err;
    }
    await insertRows(config.rolesTable, [{
      id: existing.id,
      name: existing.name,
      display_name: nextDisplayName,
      created_at: existing.createdAt,
      updated_at: now,
    }], { name: 'rbac/update-role' });
  }

  const hasAccessUpdates = permissions && typeof permissions === 'object';
  const hasWriteUpdates = writePermissions && typeof writePermissions === 'object';
  if (hasAccessUpdates || hasWriteUpdates) {
    const current = await loadRolePermissions(existing.id);
    const permRows = pageIds().map((resource) => {
      const prev = current[resource] || { access: false, write: false };
      const access = hasAccessUpdates && permissions[resource] !== undefined
        ? !!permissions[resource]
        : prev.access;
      const write = hasWriteUpdates && writePermissions[resource] !== undefined
        ? !!writePermissions[resource]
        : prev.write;
      return {
        role_id: existing.id,
        resource,
        allowed: access ? 1 : 0,
        can_write: access && write ? 1 : 0,
        updated_at: now,
      };
    });
    await insertRows(config.rolePermissionsTable, permRows, { name: 'rbac/update-role-permissions' });
  }

  return getRoleWithPermissions(existing.id);
}

async function deleteRole(roleId) {
  const existing = await loadRole(roleId);
  if (!existing) {
    const err = new Error('Роль не найдена');
    err.statusCode = 404;
    throw err;
  }

  const standardIds = new Set(['Administrator', 'Operator', 'ReadOnly']);
  if (standardIds.has(existing.id)) {
    const err = new Error('Нельзя удалить стандартную роль');
    err.statusCode = 400;
    throw err;
  }

  const userCount = await countUsersByRole(existing.id);
  if (userCount > 0) {
    const err = new Error('Нельзя удалить роль: есть связанные пользователи');
    err.statusCode = 409;
    throw err;
  }

  const { executeCommand } = require('../clickhouse');
  await executeCommand(
    `ALTER TABLE ${rolesTableRef()} DELETE WHERE id = {id:String}`,
    { id: existing.id },
    { name: 'rbac/delete-role' },
  );

  return { ok: true };
}

async function getUserPermissionOverrides(userId) {
  const overrides = await loadUserOverrides(userId);
  const result = {};
  for (const resource of pageIds()) {
    result[resource] = overrides[resource] || 'INHERIT';
  }
  return result;
}

async function saveUserPermissionOverrides(userId, overrides) {
  const now = clickhouseDateTime();
  const rows = [];
  for (const resource of pageIds()) {
    const mode = String(overrides?.[resource] ?? 'INHERIT').toUpperCase();
    if (!OVERRIDE_MODES.has(mode)) continue;
    rows.push({
      user_id: String(userId),
      resource,
      mode,
      updated_at: now,
    });
  }
  if (rows.length) {
    await insertRows(config.userPermissionsTable, rows, { name: 'rbac/save-user-overrides' });
  }
  return getUserPermissionOverrides(userId);
}

async function assignUserRole(userId, roleId) {
  const role = await loadRole(roleId);
  if (!role) {
    const err = new Error('Роль не найдена');
    err.statusCode = 404;
    throw err;
  }

  const { getUserById } = require('../users');
  const existing = await getUserById(userId);
  if (!existing) {
    const err = new Error('Пользователь не найден');
    err.statusCode = 404;
    throw err;
  }

  const now = clickhouseDateTime();
  await insertRows(config.usersTable, [{
    id: existing.id,
    username: existing.username,
    full_name: existing.fullName,
    password_hash: existing.passwordHash,
    role_id: role.id,
    force_password_change: existing.forcePasswordChange ? 1 : 0,
    created_at: existing.createdAt,
    updated_at: now,
    password_changed_at: existing.passwordChangedAt ?? null,
  }], { name: 'rbac/assign-user-role' });

  return { roleId: role.id, role };
}

module.exports = {
  DEFAULT_ROLE_ID,
  DEFAULT_NEW_USER_ROLE_ID,
  OVERRIDE_MODES,
  resolvePageAccess,
  resolvePageWrite,
  loadRolePermissions,
  loadUserOverrides,
  loadRole,
  buildEffectivePermissions,
  buildEffectiveWritePermissions,
  canAccess,
  canWrite,
  canPerformAction,
  userPermissions,
  hasPermission,
  listRoles,
  getRoleWithPermissions,
  createRole,
  updateRole,
  deleteRole,
  getUserPermissionOverrides,
  saveUserPermissionOverrides,
  assignUserRole,
  countUsersByRole,
};
