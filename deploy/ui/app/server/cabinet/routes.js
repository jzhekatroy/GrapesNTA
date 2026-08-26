const express = require('express');
const { query } = require('../clickhouse');
const { canWrite } = require('../rbac/permissions');
const {
  executeExplorerQueryBundle,
} = require('../explorer');
const { CLIENTS_RESOURCE } = require('./constants');
const { getEnabledClient, fillClientDisplayName } = require('./clients-lookup');
const {
  isClientRole,
  isCabinetScoped,
  clearImpersonation,
  buildImpersonationSession,
  requireScopedClientId,
  cabinetPayload,
} = require('./context');
const { listUsers } = require('../users');
const {
  getCabinetProfile,
  patchCabinetProfile,
  changeCabinetProfilePassword,
} = require('./profile');
const {
  writeImpersonationEvent,
  listRecentImpersonationEvents,
} = require('./impersonation-audit');
const { writeImpersonateAuditEvent } = require('../audit-log');
const {
  listClients,
  getClientAdmin,
  createClient,
  updateClient,
  listClientPrefixes,
  listClientPorts,
  syncClientPrefixes,
  syncClientPorts,
  listPrefixOptions,
  listPortOptions,
} = require('./client-admin');
const {
  overviewSeries,
  overviewStats,
  overviewRecentFlows,
  overviewCountries,
  overviewServices,
  dnsDomains,
  dnsQueries,
} = require('./data');
const {
  cabinetExplorerSchema,
  cabinetExplorerQuery,
  cabinetExplorerFlows,
  cabinetExplorerExportCsv,
} = require('./explorer');
const {
  tryCreateSnapshot,
  shareSnapshot,
  revokeShare,
  getSharedSnapshot,
  buildExplorerStoredQuery,
  buildExplorerStoredPayload,
} = require('../analysis-snapshots');

async function runNamed(builder, { name } = {}) {
  const spec = await builder();
  const { rows, elapsedMs } = await query(spec.sql, spec.params || {}, {
    name,
    clickhouse_settings: spec.clickhouse_settings,
    requestTimeoutMs: spec.requestTimeoutMs,
  });
  return {
    data: await spec.map(rows),
    meta: { elapsedMs, rows: rows.length, ...(spec.meta || {}) },
  };
}

function sendError(res, err, fallback = 502) {
  res.status(err.statusCode || fallback).json({ error: err.message });
}

function createCabinetRouter({ sessions }) {
  const router = express.Router();

  router.get('/me', async (req, res) => {
    try {
      res.json({
        cabinet: await fillClientDisplayName(req.cabinetPayload || cabinetPayload(req.cabinet)),
        actor: {
          id: req.user.id,
          username: req.user.username,
          fullName: req.user.fullName,
          roleId: req.user.roleId,
        },
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/profile', async (req, res) => {
    try {
      res.json(await getCabinetProfile(req.user, req.cabinet));
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.patch('/profile', async (req, res) => {
    try {
      res.json(await patchCabinetProfile(req.user.id, req.body || {}));
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.post('/profile/password', async (req, res) => {
    try {
      const result = await changeCabinetProfilePassword(req.user.id, req.body?.password);
      if (req.user.forcePasswordChange) req.user.forcePasswordChange = false;
      res.json({ ok: true, ...result });
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.get('/overview/series', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await overviewSeries(clientId, req.query);
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/overview/stats', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await overviewStats(clientId, req.query);
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/overview/recent-flows', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await overviewRecentFlows(clientId, req.query);
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/overview/countries', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await overviewCountries(clientId, req.query);
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/overview/services', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await overviewServices(clientId, req.query);
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/dns/domains', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await dnsDomains(clientId, req.query);
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/dns/queries', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await dnsQueries(clientId, req.query);
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/explorer/schema', async (req, res) => {
    try {
      requireScopedClientId(req.cabinet);
      res.json({ data: cabinetExplorerSchema() });
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.post('/explorer/query', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const body = req.body || {};
      const started = Date.now();
      const bundle = await cabinetExplorerQuery(clientId, body);
      const queryBody = bundle.queryBody || body;
      const {
        flowsResult,
        resultSeriesResult,
        summaryData,
        timeseriesResult,
        flowRows,
      } = await executeExplorerQueryBundle(bundle, queryBody, runNamed, 'cabinet/explorer');
      const elapsedMs = Date.now() - started;
      const responseMeta = {
        ...(flowsResult?.meta || {
          dataTable: 'flows_raw',
          groupBy: [],
          grouped: false,
          granularity: timeseriesResult?.meta?.granularity,
        }),
        elapsedMs,
      };
      const responseBody = {
        data: {
          rows: flowRows,
          summary: summaryData,
          timeseries: timeseriesResult?.data || null,
          resultSeries: resultSeriesResult?.data || null,
          breakdowns: {},
        },
        meta: responseMeta,
      };
      const stored = tryCreateSnapshot({
        kind: 'explorer',
        ownerId: req.user.id,
        clientId,
        query: buildExplorerStoredQuery(queryBody, responseMeta),
        payload: buildExplorerStoredPayload(responseBody.data, responseMeta, elapsedMs),
      });
      if (stored) {
        responseBody.meta.snapshotId = stored.id;
        responseBody.meta.snapshotExpiresAt = stored.expiresAt;
      }
      res.json(responseBody);
    } catch (err) {
      sendError(res, err, err.statusCode || 400);
    }
  });

  router.post('/explorer/flows', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await runNamed(
        () => cabinetExplorerFlows(clientId, req.body || {}),
        { name: 'cabinet/explorer/flows-only' },
      );
      res.json(result);
    } catch (err) {
      sendError(res, err, err.statusCode || 400);
    }
  });

  router.post('/explorer/export', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const csv = await cabinetExplorerExportCsv(clientId, req.body || {});
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="cabinet-explorer-${Date.now()}.csv"`);
      res.send(`\uFEFF${csv}`);
    } catch (err) {
      sendError(res, err, err.statusCode || 400);
    }
  });

  router.post('/explorer/snapshots/:id/share', async (req, res) => {
    try {
      const data = shareSnapshot(req.params.id, req.user.id, { kind: 'explorer' });
      res.json({ ok: true, data });
    } catch (err) {
      sendError(res, err, err.statusCode || 400);
    }
  });

  router.get('/explorer/snapshots/shared/:token', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const data = getSharedSnapshot(req.params.token, {
        kind: 'explorer',
        readerClientId: clientId,
        readerUserId: req.user.id,
      });
      res.json({ ok: true, data });
    } catch (err) {
      sendError(res, err, err.statusCode || 400);
    }
  });

  router.delete('/explorer/snapshots/:id/share', async (req, res) => {
    try {
      revokeShare(req.params.id, req.user.id, { kind: 'explorer' });
      res.json({ ok: true });
    } catch (err) {
      sendError(res, err, err.statusCode || 400);
    }
  });

  return router;
}

function createClientsRouter({ sessions }) {
  const router = express.Router();

  router.get('/impersonation/audit', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      const result = await listRecentImpersonationEvents({
        limit: Number(req.query.limit) || 50,
      });
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/options/prefixes', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      const result = await listPrefixOptions({
        q: req.query.q,
        limit: req.query.limit,
      });
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/options/ports', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      const result = await listPortOptions({
        q: req.query.q,
        limit: req.query.limit,
      });
      res.json(result);
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      res.json(await listClients());
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post('/', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      const result = await createClient(req.body || {});
      res.status(201).json({ ok: true, ...result });
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.get('/:clientId/prefixes', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      res.json(await listClientPrefixes(req.params.clientId));
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.put('/:clientId/prefixes', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      res.json(await syncClientPrefixes(req.params.clientId, req.body || {}));
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.get('/:clientId/ports', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      res.json(await listClientPorts(req.params.clientId));
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.put('/:clientId/ports', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      res.json(await syncClientPorts(req.params.clientId, req.body || {}));
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.put('/:clientId', async (req, res) => {
    try {
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }
      const result = await updateClient(req.params.clientId, req.body || {});
      if (result.clientDisabled && sessions?.revokeClientSessions) {
        const usersResult = await listUsers({ clientId: req.params.clientId });
        const userIds = (usersResult.data || []).map((u) => u.id);
        sessions.revokeClientSessions({ userIds, clientId: req.params.clientId });
      }
      res.json({ ok: true, data: result.data, meta: result.meta });
    } catch (err) {
      sendError(res, err, err.statusCode || 502);
    }
  });

  router.get('/:clientId', async (req, res) => {
    try {
      const client = await getEnabledClient(req.params.clientId);
      if (!client) {
        res.status(404).json({ error: 'Клиент не найден или выключен' });
        return;
      }
      res.json({ data: client });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.post('/:clientId/impersonate', async (req, res) => {
    try {
      if (isClientRole(req.user) || isCabinetScoped(req.cabinet)) {
        res.status(403).json({ error: 'Вложенный вход в кабинет запрещён' });
        return;
      }
      if (!(await canWrite(req.user, CLIENTS_RESOURCE))) {
        res.status(403).json({ error: 'Недостаточно прав для входа в кабинет клиента' });
        return;
      }

      const client = await getEnabledClient(req.params.clientId);
      if (!client) {
        res.status(404).json({ error: 'Клиент не найден или выключен' });
        return;
      }

      const sessionRecord = sessions.get(req.sessionId);
      if (!sessionRecord) {
        res.status(401).json({ error: 'Требуется авторизация' });
        return;
      }
      if (sessionRecord.impersonation) {
        res.status(409).json({ error: 'Уже выполнен вход в кабинет клиента' });
        return;
      }

      const start = await writeImpersonationEvent({
        event: 'start',
        actorUserId: req.user.id,
        actorUsername: req.user.username,
        clientId: client.clientId,
        clientDisplayName: client.displayName,
        reason: 'impersonate',
      });

      sessionRecord.impersonation = buildImpersonationSession({
        clientId: client.clientId,
        clientDisplayName: client.displayName,
        auditId: start.auditId,
      });
      sessions.set(req.sessionId, sessionRecord);

      await writeImpersonateAuditEvent(req, {
        kind: 'start',
        clientId: client.clientId,
        clientDisplayName: client.displayName,
        sessionId: req.sessionId,
      }).catch(() => {});

      res.json({
        ok: true,
        cabinet: cabinetPayload({
          mode: 'impersonation',
          clientId: client.clientId,
          clientDisplayName: client.displayName,
          readOnly: true,
          impersonation: sessionRecord.impersonation,
        }),
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  return router;
}

async function stopImpersonationHandler(req, res, { sessions, reason = 'stop' } = {}) {
  try {
    const sessionRecord = sessions.get(req.sessionId);
    if (!sessionRecord?.impersonation) {
      res.status(400).json({ error: 'Сейчас нет активного входа в кабинет клиента' });
      return;
    }
    const ended = clearImpersonation(sessionRecord, reason);
    sessions.set(req.sessionId, sessionRecord);
    await writeImpersonationEvent({
      auditId: ended.auditId,
      sessionAuditId: ended.auditId,
      event: 'end',
      actorUserId: req.user.id,
      actorUsername: req.user.username,
      clientId: ended.clientId,
      clientDisplayName: ended.clientDisplayName,
      reason,
    });
    await writeImpersonateAuditEvent(req, {
      kind: 'end',
      clientId: ended.clientId,
      clientDisplayName: ended.clientDisplayName,
      sessionId: req.sessionId,
    }).catch(() => {});
    res.json({ ok: true, cabinet: cabinetPayload({
      mode: 'operator',
      clientId: null,
      clientDisplayName: null,
      readOnly: false,
      impersonation: null,
    }) });
  } catch (err) {
    sendError(res, err);
  }
}

module.exports = {
  createCabinetRouter,
  createClientsRouter,
  stopImpersonationHandler,
};
