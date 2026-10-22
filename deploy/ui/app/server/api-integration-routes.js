'use strict';

// Раздел «API интеграция ERP»: управление API-клиентами из UI.
//  Монтируется в index.js под /api/admin/api-clients
//  после requireSession — доступ через ресурс
// api-integration-erp (rbac/api-map.js), мутации пишет общий аудит-мидлварь
// (action'ы api_client_* в audit-log.js).

const express = require('express');
const bcrypt = require('bcryptjs');
const {
  createApiClient,
  recreateApiClient,
  registerApiClient,
  activateApiClient,
  deactivateApiClient,
  getClientById,
  listApiClients,
} = require('./api-clients');
const { listAuditEvents } = require('./audit-log');

// События, из которых складывается журнал раздела.
const JOURNAL_ACTIONS = [
  'api_client_create',
  'api_client_recreate',
  'api_client_manual_register',
  'api_client_activate',
  'api_client_deactivate',
  'api_client_tokens_revoke',
];

const MONITOR_RECENT_OPS_LIMIT = 5;
const MONITOR_TEST_TOKEN_TTL_SEC = 60;

function sendError(res, err) {
  const status = Number(err.statusCode) || 500;
  res.status(status).json({ error: err.message || String(err) });
}

function requireClientId(body = {}) {
  const clientId = String(body.clientId ?? '').trim();
  if (!clientId) {
    const err = new Error('Укажите client_id');
    err.statusCode = 400;
    throw err;
  }
  return clientId;
}

// Чистая сборка полезной нагрузки списка: связывает клиентов, живые токены
// и статистику «Монитора». Ручные client_id не имеют префикса nta-.
function buildClientsPayload(clients, activeTokens, stats, tokenTtlSec) {
  const tokensByClient = new Map((activeTokens ?? []).map((row) => [row.clientId, row]));
  return {
    tokenTtlSec,
    clients: (clients ?? []).map((client) => {
      const tokens = tokensByClient.get(client.clientId);
      const stat = (stats ?? {})[client.clientId] || {};
      return {
        clientId: client.clientId,
        clientName: client.clientName,
        active: client.active,
        manual: !String(client.clientId).startsWith('nta-'),
        createdAt: client.createdAt ?? null,
        updatedAt: client.updatedAt ?? null,
        activeTokens: tokens?.count ?? 0,
        tokenExpiresSoonestAt: tokens?.expiresSoonestAt ?? null,
        lastUsedAt: stat.lastUsedAt ?? null,
        tokensIssuedToday: stat.tokensIssuedToday ?? 0,
        requestsToday: stat.requestsToday ?? 0,
      };
    }),
  };
}

function createApiIntegrationRouter({ apiTokens } = {}) {
  const router = express.Router();

  router.get('/', async (_req, res) => {
    try {
      const clients = await listApiClients();
      const stats = apiTokens.getClientStats(clients.map((client) => client.clientId));
      res.json({
        data: buildClientsPayload(
          clients,
          apiTokens.listActiveTokens(),
          stats,
          apiTokens.ttlSec,
        ),
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  // Креды возвращаются один раз — в ClickHouse остаётся только bcrypt-хэш.
  router.post('/', async (req, res) => {
    try {
      const created = await createApiClient({ name: req.body?.name });
      res.status(201).json({ data: created });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post('/recreate', async (req, res) => {
    try {
      const clientId = requireClientId(req.body);
      const result = await recreateApiClient(clientId);
      const revokedTokens = apiTokens.revokeByClientId(result.previousClientId);
      res.status(201).json({ data: { ...result, revokedTokens } });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post('/manual', async (req, res) => {
    try {
      const registered = await registerApiClient({
        name: req.body?.name,
        clientId: req.body?.clientId,
        clientSecret: req.body?.clientSecret,
      });
      res.status(201).json({ data: registered });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post('/activate', async (req, res) => {
    try {
      const clientId = requireClientId(req.body);
      res.json({ data: await activateApiClient(clientId) });
    } catch (err) {
      sendError(res, err);
    }
  });

  // Отключение гасит и живые токены: ERP не должен продолжать на старых.
  router.post('/deactivate', async (req, res) => {
    try {
      const clientId = requireClientId(req.body);
      const result = await deactivateApiClient(clientId);
      const revokedTokens = apiTokens.revokeByClientId(clientId);
      res.json({ data: { ...result, revokedTokens } });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post('/revoke-tokens', async (req, res) => {
    try {
      const clientId = requireClientId(req.body);
      const client = await getClientById(clientId);
      if (!client) {
        const err = new Error('API-клиент не найден');
        err.statusCode = 404;
        throw err;
      }
      const revokedTokens = apiTokens.revokeByClientId(clientId);
      res.json({ data: { clientId, revokedTokens } });
    } catch (err) {
      sendError(res, err);
    }
  });

  // Самотест «Монитора»: сторона NTA + сторона ERP. Опрашивать ERP не может
  // никто — соединение всегда инициирует ERP; его приходы видны в статистике.
  router.post('/monitor', async (req, res) => {
    try {
      const clientId = requireClientId(req.body);
      const client = await getClientById(clientId);
      if (!client) {
        const err = new Error('API-клиент не найден');
        err.statusCode = 404;
        throw err;
      }
      const stats = apiTokens.getClientStats([clientId])[clientId] || {};
      const tokens = apiTokens.listActiveTokens().find((row) => row.clientId === clientId);

      let tokenIssued = false;
      let tokenError = null;
      if (client.active) {
        try {
          // Тот же механизм, что /oauth/token; skipStats — чтобы самотест не
          // накручивал счётчик «обменов токеном».
          const test = apiTokens.issue(clientId, {
            ttlSec: MONITOR_TEST_TOKEN_TTL_SEC,
            skipStats: true,
          });
          apiTokens.revoke(test.token);
          tokenIssued = true;
        } catch (err) {
          tokenError = err.message || String(err);
        }
      }

      let recentOperations = [];
      try {
        // Операции Bearer-API от имени этого подключения: актёр api:<имя>.
        const log = await listAuditEvents({
          actorUsername: `api:${client.clientName}`,
          limit: MONITOR_RECENT_OPS_LIMIT,
        });
        recentOperations = log.data.map((row) => ({
          eventAt: row.eventAt,
          action: row.action,
          objectLabel: row.objectLabel,
          result: row.result,
        }));
      } catch {
        // Журнал не критичен для самотеста — панель живёт и без него.
      }

      res.json({
        data: {
          clientId: client.clientId,
          clientName: client.clientName,
          active: client.active,
          nta: {
            active: client.active,
            tokenIssued,
            tokenError,
            tokenTtlSec: apiTokens.ttlSec,
            activeTokens: tokens?.count ?? 0,
            tokenExpiresSoonestAt: tokens?.expiresSoonestAt ?? null,
          },
          erp: {
            lastUsedAt: stats.lastUsedAt ?? null,
            tokensIssuedToday: stats.tokensIssuedToday ?? 0,
            requestsToday: stats.requestsToday ?? 0,
            recentOperations,
          },
        },
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  // Проверка пары id+секрет: тот же bcrypt.compare, что в /oauth/token, но
  // без выдачи токена. Работает и для отключённых подключений.
  router.post('/verify-pair', async (req, res) => {
    try {
      const clientId = requireClientId(req.body);
      const client = await getClientById(clientId);
      if (!client) {
        const err = new Error('API-клиент не найден');
        err.statusCode = 404;
        throw err;
      }
      const clientSecret = String(req.body?.clientSecret ?? '');
      const match = client.secretHash
        ? await bcrypt.compare(clientSecret, client.secretHash)
        : false;
      res.json({ data: { clientId, match, active: client.active } });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/journal', async (req, res) => {
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
      const result = await listAuditEvents({ actions: JOURNAL_ACTIONS, limit });
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  return router;
}

module.exports = {
  createApiIntegrationRouter,
  buildClientsPayload,
  requireClientId,
  JOURNAL_ACTIONS,
};
