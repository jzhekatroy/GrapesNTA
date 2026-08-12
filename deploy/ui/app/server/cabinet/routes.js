const express = require('express');
const { query } = require('../clickhouse');
const { canWrite } = require('../rbac/permissions');
const {
  explorerResultSeries,
  summaryFromExplorerFlowRows,
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
const {
  writeImpersonationEvent,
  listRecentImpersonationEvents,
} = require('./impersonation-audit');
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

  router.get('/overview/series', async (req, res) => {
    try {
      const clientId = requireScopedClientId(req.cabinet);
      const result = await overviewSeries(clientId, req.query);
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
      const flowsResult = bundle.flowsSpec
        ? await runNamed(() => Promise.resolve(bundle.flowsSpec), { name: 'cabinet/explorer/flows' })
        : null;
      const resultSeriesResult = flowsResult?.data?.length
        ? await runNamed(
          () => explorerResultSeries(queryBody, flowsResult.data),
          { name: 'cabinet/explorer/result-series' },
        )
        : null;
      const summaryResult = bundle.summarySpec
        ? await runNamed(() => Promise.resolve(bundle.summarySpec), { name: 'cabinet/explorer/summary' })
        : null;
      const timeseriesResult = bundle.timeseriesSpec
        ? await runNamed(() => Promise.resolve(bundle.timeseriesSpec), { name: 'cabinet/explorer/timeseries' })
        : null;
      const flowRows = flowsResult?.data || [];
      const hasThresholds = Array.isArray(flowsResult?.meta?.thresholds) && flowsResult.meta.thresholds.length > 0;
      let summaryData = summaryResult?.data || null;
      if (hasThresholds && bundle.flowsSpec && flowRows.length) {
        summaryData = summaryFromExplorerFlowRows(flowRows, flowsResult.meta?.windowSeconds);
      } else if (hasThresholds && bundle.flowsSpec && !flowRows.length) {
        summaryData = summaryFromExplorerFlowRows([], flowsResult?.meta?.windowSeconds);
      }
      res.json({
        data: {
          rows: flowRows,
          summary: summaryData,
          timeseries: timeseriesResult?.data || null,
          resultSeries: resultSeriesResult?.data || null,
          breakdowns: {},
        },
        meta: {
          ...(flowsResult?.meta || {
            dataTable: 'flows_raw',
            groupBy: [],
            grouped: false,
            granularity: timeseriesResult?.meta?.granularity,
          }),
          elapsedMs: Date.now() - started,
        },
      });
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
      res.json({ ok: true, ...result });
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
