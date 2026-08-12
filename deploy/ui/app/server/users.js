const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const {
  config,
  query,
  insertRows,
  executeCommand,
  usersTableRef,
} = require('./clickhouse');

const { DEFAULT_ROLE_ID, DEFAULT_NEW_USER_ROLE_ID, userPermissions, hasPermission } = require('./rbac/permissions');
const { CLIENT_ROLE_ID, MAX_USERS_PER_CLIENT } = require('./cabinet/constants');

const LEGACY_DEFAULT_ROLE_ID = DEFAULT_ROLE_ID;
const DEFAULT_ADMIN = {
  username: 'admin',
  fullName: 'Administrator',
  password: 'adminadmin',
};
const PASSWORD_MIN_LENGTH = 12;
const BCRYPT_ROUNDS = 12;

function clickhouseDateTime(date = new Date()) {
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

function publicUser(row) {
  return {
    id: String(row.id ?? ''),
    username: String(row.username ?? ''),
    fullName: String(row.full_name ?? ''),
    roleId: String(row.role_id ?? LEGACY_DEFAULT_ROLE_ID),
    forcePasswordChange: Number(row.force_password_change) === 1,
    active: row.is_active === undefined ? true : Number(row.is_active) === 1,
    clientId: String(row.client_id ?? row.clientId ?? ''),
    createdAt: row.created_at ?? null,
    updatedAt: row.updated_at ?? null,
    passwordChangedAt: row.password_changed_at ?? null,
  };
}

function privateUser(row) {
  return {
    ...publicUser(row),
    passwordHash: String(row.password_hash ?? ''),
  };
}

function normalizeUsername(username) {
  return String(username ?? '').trim();
}

function normalizeFullName(fullName) {
  return String(fullName ?? '').trim();
}

function validatePassword(password) {
  const value = String(password ?? '');
  if (!value) return 'Укажите пароль';
  if (value.length < PASSWORD_MIN_LENGTH) {
    return `Пароль должен быть не короче ${PASSWORD_MIN_LENGTH} символов`;
  }
  return null;
}

function parseForcePasswordChange(body) {
  if (body?.forcePasswordChange === undefined && body?.force_password_change === undefined) {
    return undefined;
  }
  const value = body?.forcePasswordChange ?? body?.force_password_change;
  return value === true || value === 1 || value === '1';
}

function latestUsersCte() {
  return `
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
        row_number() OVER (
          PARTITION BY id
          ORDER BY updated_at DESC
        ) AS rn
      FROM ${usersTableRef()}
    )
  `;
}

function baseUserSelect(where = '') {
  return `
    WITH
      ${latestUsersCte()}
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
      password_changed_at
    FROM latest
    WHERE rn = 1
    ${where}
  `;
}

function parseActive(body) {
  if (body?.active === undefined && body?.is_active === undefined && body?.isActive === undefined) {
    return undefined;
  }
  const value = body?.active ?? body?.is_active ?? body?.isActive;
  return value === true || value === 1 || value === '1';
}

function parseClientId(body) {
  if (body?.clientId === undefined && body?.client_id === undefined) return undefined;
  return String(body?.clientId ?? body?.client_id ?? '').trim();
}

async function countUsersForClient(clientId, { exceptId } = {}) {
  const params = { clientId: String(clientId || '') };
  let except = '';
  if (exceptId) {
    params.exceptId = String(exceptId);
    except = 'AND id != {exceptId:String}';
  }
  const { rows } = await query(
    `
      WITH ${latestUsersCte()}
      SELECT count() AS count
      FROM latest
      WHERE rn = 1
        AND client_id = {clientId:String}
        AND client_id != ''
        ${except}
    `,
    params,
    { name: 'users/count-for-client' },
  );
  return Number(rows[0]?.count) || 0;
}

async function ensureUsersTable() {
  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${usersTableRef()}
      (
        id String,
        username String,
        full_name String,
        password_hash String,
        role_id String DEFAULT '${LEGACY_DEFAULT_ROLE_ID}',
        force_password_change UInt8 DEFAULT 0,
        is_active UInt8 DEFAULT 1,
        client_id String DEFAULT '',
        created_at DateTime64(3) DEFAULT now64(3),
        updated_at DateTime64(3) DEFAULT now64(3),
        password_changed_at Nullable(DateTime64(3)) DEFAULT NULL
      )
      ENGINE = MergeTree
      ORDER BY id
    `,
    {},
    { name: 'users/create-table' },
  );

  await executeCommand(
    `ALTER TABLE ${usersTableRef()} ADD COLUMN IF NOT EXISTS password_changed_at Nullable(DateTime64(3)) DEFAULT NULL`,
    {},
    { name: 'users/add-password-changed-at' },
  );
  await executeCommand(
    `ALTER TABLE ${usersTableRef()} ADD COLUMN IF NOT EXISTS is_active UInt8 DEFAULT 1`,
    {},
    { name: 'users/add-is-active' },
  );
  await executeCommand(
    `ALTER TABLE ${usersTableRef()} ADD COLUMN IF NOT EXISTS client_id String DEFAULT ''`,
    {},
    { name: 'users/add-client-id' },
  );

  const { rows } = await query(
    `SELECT count() AS count FROM ${usersTableRef()}`,
    {},
    { name: 'users/count' },
  );
  if (Number(rows[0]?.count) > 0) return { bootstrapped: false };

  const passwordHash = await bcrypt.hash(DEFAULT_ADMIN.password, BCRYPT_ROUNDS);
  const now = clickhouseDateTime();
  await insertRows(config.usersTable, [{
    id: crypto.randomUUID(),
    username: DEFAULT_ADMIN.username,
    full_name: DEFAULT_ADMIN.fullName,
    password_hash: passwordHash,
    role_id: LEGACY_DEFAULT_ROLE_ID,
    force_password_change: 1,
    is_active: 1,
    client_id: '',
    created_at: now,
    updated_at: now,
    password_changed_at: now,
  }], { name: 'users/bootstrap-admin' });

  return { bootstrapped: true };
}

async function listUsers({ clientId } = {}) {
  const params = {};
  const where = clientId ? 'AND client_id = {clientId:String}' : '';
  if (clientId) params.clientId = String(clientId).trim();
  const { rows, elapsedMs } = await query(
    `${baseUserSelect(where)} ORDER BY username`,
    params,
    { name: 'users/list' },
  );
  const data = rows.map(publicUser);
  const meta = { elapsedMs, rows: rows.length };
  if (clientId) {
    const used = data.length;
    meta.clientId = String(clientId);
    meta.limit = MAX_USERS_PER_CLIENT;
    meta.used = used;
    meta.remaining = Math.max(MAX_USERS_PER_CLIENT - used, 0);
  }
  return { data, meta };
}

async function getUserById(id) {
  const { rows } = await query(
    `${baseUserSelect('AND id = {id:String}')} LIMIT 1`,
    { id: String(id ?? '') },
    { name: 'users/get-by-id' },
  );
  return rows[0] ? privateUser(rows[0]) : null;
}

async function getUserByUsername(username) {
  const { rows } = await query(
    `${baseUserSelect('AND lowerUTF8(username) = lowerUTF8({username:String})')} LIMIT 1`,
    { username: normalizeUsername(username) },
    { name: 'users/get-by-username' },
  );
  return rows[0] ? privateUser(rows[0]) : null;
}

async function usernameExists(username, { exceptId } = {}) {
  const params = { username: normalizeUsername(username) };
  let except = '';
  if (exceptId) {
    params.exceptId = String(exceptId);
    except = 'AND id != {exceptId:String}';
  }
  const { rows } = await query(
    `
      WITH
        ${latestUsersCte()}
      SELECT count() AS count
      FROM latest
      WHERE rn = 1
        AND lowerUTF8(username) = lowerUTF8({username:String})
        ${except}
    `,
    params,
    { name: 'users/username-exists' },
  );
  return Number(rows[0]?.count) > 0;
}

async function validateUserPayload(body, { isNew, existingId, existing } = {}) {
  const username = normalizeUsername(body?.username);
  const fullName = normalizeFullName(body?.fullName ?? body?.full_name);

  if (!fullName) return { ok: false, statusCode: 400, error: 'Укажите ФИО пользователя' };
  if (!username) return { ok: false, statusCode: 400, error: 'Укажите username пользователя' };

  if (await usernameExists(username, { exceptId: existingId })) {
    return { ok: false, statusCode: 409, error: 'Пользователь с таким username уже существует' };
  }

  if (isNew) {
    const passwordError = validatePassword(body?.password);
    if (passwordError) return { ok: false, statusCode: 400, error: passwordError };
  }

  const payload = { ok: true, username, fullName };
  const forcePasswordChange = parseForcePasswordChange(body);
  if (forcePasswordChange !== undefined) payload.forcePasswordChange = forcePasswordChange;

  const active = parseActive(body);
  if (active !== undefined) payload.active = active;

  let roleId = existing?.roleId || LEGACY_DEFAULT_ROLE_ID;
  if (isNew) {
    roleId = String(body?.roleId ?? body?.role_id ?? '').trim() || DEFAULT_NEW_USER_ROLE_ID;
    payload.roleId = roleId;
  } else if (body?.roleId !== undefined || body?.role_id !== undefined) {
    roleId = String(body?.roleId ?? body?.role_id ?? '').trim() || existing.roleId;
    payload.roleId = roleId;
  }

  const clientIdRaw = parseClientId(body);
  let clientId = existing?.clientId || '';
  if (clientIdRaw !== undefined) clientId = clientIdRaw;
  if (roleId === CLIENT_ROLE_ID) {
    if (!clientId) {
      return { ok: false, statusCode: 400, error: 'Для роли Client укажите clientId' };
    }
    const count = await countUsersForClient(clientId, { exceptId: existingId });
    if (count >= MAX_USERS_PER_CLIENT) {
      return {
        ok: false,
        statusCode: 400,
        error: `У клиента уже ${MAX_USERS_PER_CLIENT} учётных записей`,
      };
    }
  } else {
    clientId = '';
  }
  payload.clientId = clientId;

  return payload;
}

function validationError(result) {
  const err = new Error(result.error);
  err.statusCode = result.statusCode || 400;
  return err;
}

async function createUser(body) {
  const validation = await validateUserPayload(body, { isNew: true });
  if (!validation.ok) throw validationError(validation);

  const passwordHash = await bcrypt.hash(String(body.password), BCRYPT_ROUNDS);
  const now = clickhouseDateTime();
  const record = {
    id: crypto.randomUUID(),
    username: validation.username,
    full_name: validation.fullName,
    password_hash: passwordHash,
    role_id: validation.roleId,
    force_password_change: validation.forcePasswordChange ? 1 : 0,
    is_active: validation.active === undefined ? 1 : (validation.active ? 1 : 0),
    client_id: validation.clientId || '',
    created_at: now,
    updated_at: now,
    password_changed_at: now,
  };

  const { elapsedMs } = await insertRows(config.usersTable, [record], {
    name: 'users/create',
  });
  return { data: publicUser(record), meta: { elapsedMs } };
}

async function updateUser(id, body) {
  const existing = await getUserById(id);
  if (!existing) {
    const err = new Error('Пользователь не найден');
    err.statusCode = 404;
    throw err;
  }

  const validation = await validateUserPayload(body, {
    isNew: false,
    existingId: id,
    existing,
  });
  if (!validation.ok) throw validationError(validation);

  const clientIdRaw = parseClientId(body);
  const record = {
    id: existing.id,
    username: validation.username,
    full_name: validation.fullName,
    password_hash: existing.passwordHash,
    role_id: validation.roleId || existing.roleId || LEGACY_DEFAULT_ROLE_ID,
    force_password_change: validation.forcePasswordChange !== undefined
      ? (validation.forcePasswordChange ? 1 : 0)
      : (existing.forcePasswordChange ? 1 : 0),
    is_active: validation.active !== undefined
      ? (validation.active ? 1 : 0)
      : (existing.active ? 1 : 0),
    client_id: clientIdRaw !== undefined ? validation.clientId : (existing.clientId || ''),
    created_at: existing.createdAt,
    updated_at: clickhouseDateTime(),
    password_changed_at: existing.passwordChangedAt ?? null,
  };

  const { elapsedMs } = await insertRows(config.usersTable, [record], {
    name: 'users/update',
  });
  return { data: publicUser(record), meta: { elapsedMs } };
}

async function countUsers() {
  const { rows } = await query(
    `
      WITH
        ${latestUsersCte()}
      SELECT count() AS count
      FROM latest
      WHERE rn = 1
    `,
    {},
    { name: 'users/count-all' },
  );
  return Number(rows[0]?.count) || 0;
}

function deleteUserBlockedReason(user, totalUsers) {
  if (user?.roleId === LEGACY_DEFAULT_ROLE_ID) {
    return 'Нельзя удалить учётную запись администратора';
  }
  if (totalUsers <= 1) {
    return 'Нельзя удалить последнего пользователя в системе';
  }
  return null;
}

async function deleteUser(id) {
  const existing = await getUserById(id);
  if (!existing) {
    const err = new Error('Пользователь не найден');
    err.statusCode = 404;
    throw err;
  }

  const blockReason = deleteUserBlockedReason(existing, await countUsers());
  if (blockReason) {
    const err = new Error(blockReason);
    err.statusCode = 400;
    throw err;
  }

  const { elapsedMs } = await executeCommand(
    `DELETE FROM ${usersTableRef()} WHERE id = {id:String}`,
    { id: existing.id },
    { name: 'users/delete' },
  );
  return { meta: { elapsedMs } };
}

async function changeUserPassword(id, password, { clearForce = false } = {}) {
  const existing = await getUserById(id);
  if (!existing) {
    const err = new Error('Пользователь не найден');
    err.statusCode = 404;
    throw err;
  }

  const passwordError = validatePassword(password);
  if (passwordError) {
    const err = new Error(passwordError);
    err.statusCode = 400;
    throw err;
  }

  const passwordHash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
  const now = clickhouseDateTime();
  const record = {
    id: existing.id,
    username: existing.username,
    full_name: existing.fullName,
    password_hash: passwordHash,
    role_id: existing.roleId || LEGACY_DEFAULT_ROLE_ID,
    force_password_change: clearForce ? 0 : existing.forcePasswordChange ? 1 : 0,
    is_active: existing.active ? 1 : 0,
    client_id: existing.clientId || '',
    created_at: existing.createdAt,
    updated_at: now,
    password_changed_at: now,
  };

  const { elapsedMs } = await insertRows(config.usersTable, [record], {
    name: 'users/change-password',
  });
  return { data: publicUser(record), meta: { elapsedMs } };
}

async function verifyCredentials(username, password) {
  const user = await getUserByUsername(username);
  if (!user?.passwordHash) return null;
  if (!user.active) {
    const err = new Error('Учётная запись отключена');
    err.statusCode = 403;
    throw err;
  }
  if (user.roleId === CLIENT_ROLE_ID && !user.clientId) {
    const err = new Error('Учётная запись клиента не привязана к клиенту');
    err.statusCode = 403;
    throw err;
  }
  const ok = await bcrypt.compare(String(password ?? ''), user.passwordHash);
  return ok ? user : null;
}

module.exports = {
  DEFAULT_ROLE_ID: LEGACY_DEFAULT_ROLE_ID,
  PASSWORD_MIN_LENGTH,
  ensureUsersTable,
  listUsers,
  getUserById,
  getUserByUsername,
  createUser,
  updateUser,
  deleteUser,
  changeUserPassword,
  verifyCredentials,
  userPermissions,
  hasPermission,
};
