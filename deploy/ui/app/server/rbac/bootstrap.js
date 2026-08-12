const crypto = require('crypto');
const {
  config,
  query,
  insertRows,
  executeCommand,
  rolesTableRef,
  rolePermissionsTableRef,
  userPermissionsTableRef,
  usersTableRef,
} = require('../clickhouse');
const { pageIds } = require('./resources');
const {
  CLIENT_ROLE_ID,
  CLIENTS_RESOURCE,
  CLIENT_PAGE_RESOURCES,
} = require('../cabinet/constants');

const STANDARD_ROLES = [
  { id: 'Administrator', name: 'Administrator', displayName: 'Администратор' },
  { id: 'Operator', name: 'Operator', displayName: 'Оператор' },
  { id: 'ReadOnly', name: 'ReadOnly', displayName: 'Только чтение' },
  { id: CLIENT_ROLE_ID, name: CLIENT_ROLE_ID, displayName: 'Клиент' },
];

const ADMIN_ONLY_RESOURCES = new Set(['ttl', 'diagnostics', 'smtp']);
const OPERATOR_MANAGED_RESOURCES = new Set([CLIENTS_RESOURCE]);

function clickhouseDateTime(date = new Date()) {
  return date.toISOString().replace('T', ' ').replace('Z', '');
}

function latestRolesCte() {
  return `
    latest AS (
      SELECT
        id,
        name,
        display_name,
        created_at,
        updated_at,
        row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
      FROM ${rolesTableRef()}
    )
  `;
}

function latestRolePermissionsCte() {
  return `
    latest AS (
      SELECT
        role_id,
        resource,
        allowed,
        can_write,
        updated_at,
        row_number() OVER (PARTITION BY role_id, resource ORDER BY updated_at DESC) AS rn
      FROM ${rolePermissionsTableRef()}
    )
  `;
}

function defaultAllowed(roleId, resource) {
  if (roleId === CLIENT_ROLE_ID) {
    return CLIENT_PAGE_RESOURCES.has(resource) ? 1 : 0;
  }
  if (OPERATOR_MANAGED_RESOURCES.has(resource)) {
    return (roleId === 'Administrator' || roleId === 'Operator') ? 1 : 0;
  }
  if (ADMIN_ONLY_RESOURCES.has(resource)) {
    return roleId === 'Administrator' ? 1 : 0;
  }
  return 1;
}

function defaultCanWrite(roleId, resource, allowed) {
  if (!allowed) return 0;
  if (roleId === 'ReadOnly' || roleId === CLIENT_ROLE_ID) return 0;
  return 1;
}

async function ensureRbacTables() {
  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${rolesTableRef()}
      (
        id String,
        name String,
        display_name String,
        created_at DateTime64(3) DEFAULT now64(3),
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = MergeTree
      ORDER BY id
    `,
    {},
    { name: 'rbac/create-roles' },
  );

  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${rolePermissionsTableRef()}
      (
        role_id String,
        resource String,
        allowed UInt8,
        can_write UInt8 DEFAULT 1,
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = MergeTree
      ORDER BY (role_id, resource)
    `,
    {},
    { name: 'rbac/create-role-permissions' },
  );

  await executeCommand(
    `
      ALTER TABLE ${rolePermissionsTableRef()}
      ADD COLUMN IF NOT EXISTS can_write UInt8 DEFAULT 1
    `,
    {},
    { name: 'rbac/add-role-permissions-can-write' },
  );

  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${userPermissionsTableRef()}
      (
        user_id String,
        resource String,
        mode String,
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = MergeTree
      ORDER BY (user_id, resource)
    `,
    {},
    { name: 'rbac/create-user-permissions' },
  );
}

async function listRoleNames() {
  const { rows } = await query(
    `
      WITH ${latestRolesCte()}
      SELECT name FROM latest WHERE rn = 1
    `,
    {},
    { name: 'rbac/list-role-names' },
  );
  return new Set(rows.map((r) => String(r.name)));
}

async function listRoleIds() {
  const { rows } = await query(
    `
      WITH ${latestRolesCte()}
      SELECT id FROM latest WHERE rn = 1
    `,
    {},
    { name: 'rbac/list-role-ids' },
  );
  return rows.map((r) => String(r.id));
}

async function bootstrapStandardRoles() {
  const existingNames = await listRoleNames();
  const now = clickhouseDateTime();
  const toInsert = STANDARD_ROLES
    .filter((role) => !existingNames.has(role.name))
    .map((role) => ({
      id: role.id,
      name: role.name,
      display_name: role.displayName,
      created_at: now,
      updated_at: now,
    }));

  if (toInsert.length) {
    await insertRows(config.rolesTable, toInsert, { name: 'rbac/bootstrap-roles' });
  }
  return toInsert.length;
}

async function listRolePermissionKeys(roleId) {
  const { rows } = await query(
    `
      WITH ${latestRolePermissionsCte()}
      SELECT resource FROM latest
      WHERE rn = 1 AND role_id = {roleId:String}
    `,
    { roleId: String(roleId) },
    { name: 'rbac/list-role-permission-keys' },
  );
  return new Set(rows.map((r) => String(r.resource)));
}

async function syncRolePermissions() {
  const resources = pageIds();
  const roleIds = await listRoleIds();
  const now = clickhouseDateTime();
  const rows = [];

  for (const roleId of roleIds) {
    const existing = await listRolePermissionKeys(roleId);
    for (const resource of resources) {
      if (!existing.has(resource)) {
        const allowed = defaultAllowed(roleId, resource);
        rows.push({
          role_id: roleId,
          resource,
          allowed,
          can_write: defaultCanWrite(roleId, resource, allowed),
          updated_at: now,
        });
      }
    }
  }

  if (rows.length) {
    await insertRows(config.rolePermissionsTable, rows, { name: 'rbac/sync-role-permissions' });
  }
  return rows.length;
}

async function syncReadOnlyWritePermissions() {
  const roleIds = await listRoleIds();
  if (!roleIds.includes('ReadOnly')) return 0;

  const { rows } = await query(
    `
      WITH ${latestRolePermissionsCte()}
      SELECT resource, allowed, can_write
      FROM latest
      WHERE rn = 1 AND role_id = 'ReadOnly'
    `,
    {},
    { name: 'rbac/list-readonly-permissions' },
  );

  const now = clickhouseDateTime();
  const patchRows = rows
    .filter((row) => Number(row.allowed) === 1 && Number(row.can_write ?? 1) !== 0)
    .map((row) => ({
      role_id: 'ReadOnly',
      resource: String(row.resource),
      allowed: 1,
      can_write: 0,
      updated_at: now,
    }));

  if (patchRows.length) {
    await insertRows(config.rolePermissionsTable, patchRows, { name: 'rbac/sync-readonly-write' });
  }
  return patchRows.length;
}

async function migrateUserRoles() {
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
      SELECT id, role_id FROM latest WHERE rn = 1
    `,
    {},
    { name: 'rbac/migrate-user-roles-read' },
  );

  const updates = rows.filter((r) => {
    const roleId = String(r.role_id ?? '');
    return !roleId || roleId === 'Administrator' || roleId === 'admin';
  });

  if (!updates.length) return 0;

  const now = clickhouseDateTime();
  const { rows: fullRows } = await query(
    `
      WITH
        latest AS (
          SELECT
            id,
            username,
            full_name,
            password_hash,
            role_id,
            force_password_change,
            is_active,
            client_id,
            created_at,
            updated_at,
            password_changed_at,
            row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
          FROM ${usersTableRef()}
        )
      SELECT * FROM latest WHERE rn = 1
    `,
    {},
    { name: 'rbac/migrate-user-roles-full' },
  );

  const patchRows = fullRows
    .filter((r) => {
      const roleId = String(r.role_id ?? '');
      return !roleId || roleId === 'admin';
    })
    .map((r) => ({
      id: r.id,
      username: r.username,
      full_name: r.full_name,
      password_hash: r.password_hash,
      role_id: 'Administrator',
      force_password_change: Number(r.force_password_change),
      is_active: r.is_active === undefined ? 1 : Number(r.is_active),
      client_id: String(r.client_id ?? ''),
      created_at: r.created_at,
      updated_at: now,
      password_changed_at: r.password_changed_at ?? null,
    }));

  if (patchRows.length) {
    await insertRows(config.usersTable, patchRows, { name: 'rbac/migrate-user-roles' });
  }
  return patchRows.length;
}

async function syncClientRolePermissions() {
  const roleIds = await listRoleIds();
  if (!roleIds.includes(CLIENT_ROLE_ID)) return 0;

  const resources = pageIds();
  const now = clickhouseDateTime();
  const rows = resources.map((resource) => {
    const allowed = defaultAllowed(CLIENT_ROLE_ID, resource);
    return {
      role_id: CLIENT_ROLE_ID,
      resource,
      allowed,
      can_write: 0,
      updated_at: now,
    };
  });

  if (rows.length) {
    await insertRows(config.rolePermissionsTable, rows, { name: 'rbac/sync-client-permissions' });
  }
  return rows.length;
}

async function ensureRbac() {
  await ensureRbacTables();
  const rolesCreated = await bootstrapStandardRoles();
  await migrateUserRoles();
  const permissionsAdded = await syncRolePermissions();
  const writePermissionsPatched = await syncReadOnlyWritePermissions();
  const clientPermissionsSynced = await syncClientRolePermissions();
  return { rolesCreated, permissionsAdded, writePermissionsPatched, clientPermissionsSynced };
}

module.exports = {
  STANDARD_ROLES,
  ensureRbac,
  latestRolesCte,
  latestRolePermissionsCte,
};
