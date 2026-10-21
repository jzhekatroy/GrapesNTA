'use strict';

const express = require('express');
const {
  listUsers,
  getUserByUsername,
  createUser,
  deleteUser,
  resetUserPassword,
  generatePassword,
} = require('./users');
const { getEnabledClient } = require('./cabinet/clients-lookup');
const { CLIENT_ROLE_ID } = require('./cabinet/constants');
const { getActiveClientById, verifyApiClient } = require('./api-clients');
const { writeAuditEvent, resolveClientIpFromReq } = require('./audit-log');

const API_ACTOR_ROLE = 'ApiClient';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function apiError(statusCode, code, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  err.code = code;
  return err;
}

function sendApiError(res, err, fallbackStatus = 502) {
  const status = err.statusCode || fallbackStatus;
  const body = { error: err.message };
  if (err.code) body.code = err.code;
  res.status(status).json(body);
}

function toContractUser(user) {
  return {
    login: String(user?.username ?? ''),
    fullName: String(user?.fullName ?? ''),
    createdAt: user?.createdAt ?? null,
    active: user?.active !== false,
  };
}

function requireAccount(account) {
  const value = String(account ?? '').trim();
  if (!value) throw apiError(400, 'validation_failed', 'Укажите account (номер ЛС)');
  return value;
}

function requireLogin(login) {
  const value = String(login ?? '').trim();
  if (!value) throw apiError(400, 'validation_failed', 'Укажите login (email)');
  if (!EMAIL_RE.test(value)) {
    throw apiError(400, 'validation_failed', 'login должен быть email-адресом');
  }
  return value;
}

/** DELETE принимает те же поля в JSON-теле или, если тела нет, в query. */
function parseDeleteFields(body = {}, query = {}) {
  return {
    account: String(body.account ?? query.account ?? '').trim(),
    login: String(body.login ?? query.login ?? '').trim(),
  };
}

async function requireEnabledAccount(account) {
  const client = await getEnabledClient(account);
  if (!client) {
    throw apiError(
      404,
      'account_not_found',
      'ЛС не найден в NTA (возможно, ещё не синхронизирован). Запустите синхронизацию и повторите.',
    );
  }
  return client;
}

async function findAccountUser(account, login) {
  const user = await getUserByUsername(login);
  if (!user || String(user.clientId || '') !== String(account)) {
    throw apiError(404, 'user_not_found', `Пользователь ${login} у ЛС ${account} не найден`);
  }
  return user;
}

function auditContext(req) {
  const client = req.apiClient || {};
  return {
    actorUserId: '',
    actorUsername: `api:${client.clientName || client.clientId || 'unknown'}`,
    actorRole: API_ACTOR_ROLE,
    ip: resolveClientIpFromReq(req),
    userAgent: String(req.headers?.['user-agent'] || ''),
  };
}

function createApiV1Router({ sessions, apiTokens }) {
  const router = express.Router();

  router.post('/oauth/token', express.urlencoded({ extended: false }), async (req, res) => {
    try {
      const body = req.body || {};
      const grantType = String(body.grant_type ?? body.grantType ?? '').trim();
      const clientId = String(body.client_id ?? body.clientId ?? '').trim();
      const clientSecret = String(body.client_secret ?? body.clientSecret ?? '').trim();

      if (grantType !== 'client_credentials') {
        throw apiError(400, 'validation_failed', 'Поддерживается только grant_type=client_credentials');
      }
      if (!clientId || !clientSecret) {
        throw apiError(400, 'validation_failed', 'Укажите client_id и client_secret');
      }

      const client = await verifyApiClient(clientId, clientSecret);
      if (!client) {
        throw apiError(401, 'invalid_client', 'Неверные учётные данные клиента');
      }

      const issued = apiTokens.issue(client.clientId);
      res.json({
        token_type: 'Bearer',
        expires_in: apiTokens.ttlSec,
        access_token: issued.token,
      });
    } catch (err) {
      sendApiError(res, err);
    }
  });

  router.use(async (req, res, next) => {
    try {
      const header = String(req.headers?.authorization || '');
      const match = /^Bearer\s+(.+)$/i.exec(header);
      if (!match) {
        throw apiError(401, 'unauthorized', 'Требуется Authorization: Bearer <токен>');
      }
      const record = apiTokens.verify(match[1].trim());
      if (!record) {
        throw apiError(401, 'unauthorized', 'Токен недействителен или истёк');
      }
      const client = await getActiveClientById(record.clientId);
      if (!client) {
        throw apiError(401, 'unauthorized', 'API-клиент деактивирован');
      }
      req.apiClient = { clientId: client.clientId, clientName: client.clientName };
      next();
    } catch (err) {
      sendApiError(res, err);
    }
  });

  router.get('/clients/users', async (req, res) => {
    try {
      const account = requireAccount(req.query.account);
      await requireEnabledAccount(account);
      const { data, meta } = await listUsers({ clientId: account });
      res.json({ data: data.map(toContractUser), meta });
    } catch (err) {
      sendApiError(res, err);
    }
  });

  router.post('/clients/users', async (req, res) => {
    try {
      const body = req.body || {};
      const account = requireAccount(body.account);
      const login = requireLogin(body.login);
      const fullName = String(body.fullName ?? body.full_name ?? '').trim();

      await requireEnabledAccount(account);

      if (await getUserByUsername(login)) {
        throw apiError(409, 'login_taken', `Логин ${login} уже занят`);
      }

      const { meta } = await listUsers({ clientId: account });
      if (Number(meta?.used) >= Number(meta?.limit)) {
        throw apiError(
          409,
          'client_users_limit_reached',
          `Все ${meta.limit} учётных записей созданы, удалите старую, чтобы добавить новую`,
        );
      }

      const password = generatePassword();
      await createUser({
        username: login,
        fullName: fullName || login,
        password,
        roleId: CLIENT_ROLE_ID,
        clientId: account,
        forcePasswordChange: true,
      });

      await writeAuditEvent({
        ...auditContext(req),
        action: 'user_create',
        resource: 'users',
        method: 'POST',
        path: '/api/v1/clients/users',
        objectLabel: login,
        detail: `accountId=${account}`,
      }).catch(() => {});

      res.status(201).json({ account, login, password });
    } catch (err) {
      sendApiError(res, err);
    }
  });

  router.post('/clients/users/password-reset', async (req, res) => {
    try {
      const body = req.body || {};
      const account = requireAccount(body.account);
      const login = requireLogin(body.login);

      await requireEnabledAccount(account);
      const user = await findAccountUser(account, login);

      const result = await resetUserPassword(user.id);
      sessions?.revokeClientSessions?.({ userIds: [user.id] });

      await writeAuditEvent({
        ...auditContext(req),
        action: 'password_reset',
        resource: 'users',
        method: 'POST',
        path: '/api/v1/clients/users/password-reset',
        objectLabel: login,
        detail: `accountId=${account}`,
      }).catch(() => {});

      res.json({ account, login, password: result.password });
    } catch (err) {
      sendApiError(res, err);
    }
  });

  router.delete('/clients/users', async (req, res) => {
    try {
      const { account, login } = parseDeleteFields(req.body || {}, req.query || {});
      requireAccount(account);
      requireLogin(login);

      await requireEnabledAccount(account);
      const user = await findAccountUser(account, login);

      await deleteUser(user.id);
      sessions?.revokeClientSessions?.({ userIds: [user.id] });

      await writeAuditEvent({
        ...auditContext(req),
        action: 'user_delete',
        resource: 'users',
        method: 'DELETE',
        path: '/api/v1/clients/users',
        objectLabel: login,
        detail: `accountId=${account}`,
      }).catch(() => {});

      res.json({ ok: true });
    } catch (err) {
      sendApiError(res, err);
    }
  });

  return router;
}

module.exports = {
  createApiV1Router,
  apiError,
  toContractUser,
  parseDeleteFields,
  requireAccount,
  requireLogin,
  EMAIL_RE,
};
