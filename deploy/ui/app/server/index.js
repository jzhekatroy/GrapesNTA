require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const { ping, query, getConfig } = require('./clickhouse');
const { logApiIncoming, logApiDone, logApiError, getLogConfig } = require('./logger');
const { runWithRequestContext, getRequestContext } = require('./request-context');
const { recordFailedRequest, listFailedRequests } = require('./failed-requests');
const {
  trafficBandwidthSeries,
  trafficDirectionStats,
  protocolDistribution,
  protocolDistributionTimeseries,
  serviceDistribution,
  serviceDistributionTimeseries,
  vlanDistribution,
  vlanDistributionTimeseries,
  vlanTopTable,
  normalizeVlanDirections,
  otherPortsTop20,
  countryHeatmap,
  dashboardCollectors,
  normalizeProtocolDirections,
  normalizeChartDirections,
  parseChartDirectionsQuery,
  topTalkersDashboard,
  normalizeTopTalkersGroup,
  fetchRecentFlows,
} = require('./queries');
const {
  explorerFlows,
  explorerSchema,
  explorerQuery,
  executeExplorerQueryBundle,
  searchExplorerEntities,
  listSavedExplorerFilters,
  createSavedExplorerFilter,
  updateSavedExplorerFilter,
  deleteSavedExplorerFilter,
  explorerExportCsv,
} = require('./explorer');
const {
  ensureObservationsStore,
  listObservations,
  getObservation,
  createObservation,
  updateObservation,
  deleteObservation,
  duplicateObservation,
  cancelMaterialize,
  queueMaterialize,
  previewObservation,
  runObservationReport,
  listRuns,
  getRunArtifact,
  observationsConfig,
  getObservationAnalyticsDiagnostics,
} = require('./observations');
const {
  ensureSmtpSettingsTables,
  getSmtpSettings,
  saveSmtpSettings,
  sendTestMail,
} = require('./smtp-settings');
const { getWorkerDiagnostics } = require('./diagnostics-worker');
const {
  scanGaps,
  enqueueBackfill,
  listBackfillQueue,
  cancelBackfill,
} = require('./diagnostics-worker-gaps');
const { getEnrichmentDiagnostics } = require('./diagnostics-enrichment');
const { getSnmpDiagnostics } = require('./diagnostics-snmp');
const { getBoundsDiagnostics } = require('./diagnostics-bounds');
const { getBuildInfo, formatBuildInfoLogLine } = require('./build-info');
const { createSessionStore } = require('./sessions');
const {
  dnsSources,
  dnsActivityChart,
  dnsTopDomains,
  dnsTopClients,
  dnsTopServers,
  dnsRecent,
  dnsQtypes,
  parseDnsFiltersQuery,
  parseDnsOverviewQuery,
} = require('./dns-queries');
const {
  dnsExplorerSchema,
  dnsExplorerQuery,
  dnsExplorerExportCsv,
  dnsExplorerSuggestDomains,
  dnsExplorerSuggestClientIps,
  dnsExplorerSuggestServerIps,
  dnsExplorerSuggestQtypes,
  dnsExplorerSuggestAnswers,
  parseDnsExplorerBody,
  parseDnsExplorerSuggestQuery,
} = require('./dns-explorer');
const {
  tryCreateSnapshot,
  shareSnapshot,
  revokeShare,
  getSharedSnapshot,
  getActiveShareLinkStats,
  buildExplorerStoredQuery,
  buildExplorerStoredPayload,
  buildDnsExplorerStoredQuery,
  buildDnsExplorerStoredPayload,
  ensureStore: ensureAnalysisSnapshotsStore,
} = require('./analysis-snapshots');
const {
  getLayout: getDashboardLayout,
  putLayout: putDashboardLayout,
  resetLayout: resetDashboardLayout,
} = require('./dashboard-layout');
const { isCabinetScoped } = require('./cabinet/context');
const {
  listL3Prefixes,
  listNetEntities,
  saveL3Prefix,
  setL3PrefixEnabled,
  deleteL3Prefix,
} = require('./l3-prefixes');
const {
  listDnsResolvers,
  saveDnsResolver,
  setDnsResolverEnabled,
  deleteDnsResolver,
} = require('./dns-resolvers');
const {
  listFlowExclusions,
  flowExclusionsExcludedStats,
  saveFlowExclusion,
  setFlowExclusionEnabled,
  deleteFlowExclusion,
} = require('./flow-exclusions');
const { listNetEntitiesAdmin, saveNetEntity } = require('./net-entities');
const {
  listVlansAdmin,
  listUnnamedVlansSeen,
  saveVlan,
  setVlanEnabled,
  deleteVlan,
} = require('./net-l2-vlans');
const { listLocations, saveLocation } = require('./net-locations');
const { listCollectorsAdmin, listCollectorsForSelect, saveCollector, deleteCollector } = require('./net-collectors');
const { listFlowSources, bindFlowSource, registerFlowSource, deleteFlowSource } = require('./net-flow-sources');
const {
  listSnmpSettings,
  saveSnmpSettings,
  listSnmpAgents,
  saveSnmpAgent,
  listSnmpInterfaces,
  requestSnmpProbe,
  requestSnmpProbeAll,
  deleteSnmpAgent,
} = require('./net-snmp');
const {
  getDirectionSettings,
  saveDirectionSettings,
  listInterfaceRoleRules,
  saveInterfaceRoleRule,
  deleteInterfaceRoleRule,
  previewInterfaceRoleRule,
  listInterfaceRoles,
  listInterfaceRoleSwitches,
  saveInterfaceRole,
  deleteInterfaceRole,
  materializeEffectiveRoles,
  getInterfaceRoleSummary,
} = require('./net-interface-roles');
const {
  getInterfaceFieldCoverage,
  compareDirectionModels,
  listInterfacesByTraffic,
} = require('./direction-audit');
const {
  listPortServices,
  savePortService,
  disablePortService,
  previewSeedDefaults,
  seedDefaults,
} = require('./port-services');
const { fetchCollectorStatus } = require('./collector-status');
const { fetchCollectorOverview, fetchDiscoveredSources } = require('./collector-overview');
const { fetchCollectorCompleteness, settings: completenessSettings } = require('./collector-completeness');
const { fetchCompletenessDetail, fetchCompletenessHistory } = require('./collector-pipeline');
const {
  getBmpSummary,
  getBmpPeers,
  getBmpRouters,
  getBmpRoutes,
  getBmpEvents,
  getBmpCounts,
  getBmpChurn,
  getBmpFlap,
} = require('./bmp');
const { listTtlTables, updateTtlTable } = require('./ttl-management');
const {
  ensureUsersTable,
  listUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUser,
  changeUserPassword,
  resetUserPassword,
  verifyCredentials,
  hasPermission,
} = require('./users');
const { ensureRbac } = require('./rbac/bootstrap');
const {
  buildEffectivePermissions,
  buildEffectiveWritePermissions,
  loadRole,
  userPermissions,
} = require('./rbac/permissions');
const { apiResourceGuard } = require('./rbac/middleware');
const { createRbacRouter } = require('./rbac/routes');
const { createCabinetGuard } = require('./cabinet/guard');
const {
  createCabinetRouter,
  createClientsRouter,
  stopImpersonationHandler,
} = require('./cabinet/routes');
const { createErpPiterixRouter } = require('./erp-piterix-routes');
const { createDetectionRouter } = require('./detection-routes');
const {
  resolveCabinetContext,
  cabinetPayload,
  clearImpersonation,
  getSessionRecord,
} = require('./cabinet/context');
const { ensureImpersonationAuditTable, writeImpersonationEvent } = require('./cabinet/impersonation-audit');
const {
  writeAuditEvent,
  writePageViewEvent,
  writeImpersonateAuditEvent,
  createAuditMiddleware,
  listAuditEvents,
  auditContextFromReq,
} = require('./audit-log');
const { fillClientDisplayName, rejectDisabledClientSession } = require('./cabinet/clients-lookup');

const PORT = Number(process.env.PORT) || 3000;
const app = express();
const SESSION_COOKIE = 'grapes_session';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const sessions = createSessionStore();
const cabinetIsolationGuard = createCabinetGuard({ sessions });

function envBool(name, fallback = false) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

const SESSION_COOKIE_SECURE = envBool('SESSION_COOKIE_SECURE', false);
const TRUST_PROXY = envBool('TRUST_PROXY', false);

if (TRUST_PROXY) app.set('trust proxy', 1);

app.use(express.json({ limit: '256kb' }));

app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();

  runWithRequestContext({ failedSql: null }, () => {
    const started = Date.now();
    const route = req.originalUrl || req.url;
    logApiIncoming(req);

    const sendJson = res.json.bind(res);
    res.json = (body) => {
      if (body?.meta) res.locals.apiMeta = body.meta;
      if (body?.error) res.locals.apiError = body.error;
      return sendJson(body);
    };

    res.on('finish', () => {
      const elapsedMs = Date.now() - started;
      if (res.statusCode >= 400) {
        logApiError(route, res.locals.apiError || `HTTP ${res.statusCode}`, elapsedMs);
        recordFailedRequest({
          method: req.method,
          route,
          query: req.query,
          body: req.body,
          statusCode: res.statusCode,
          error: res.locals.apiError || `HTTP ${res.statusCode}`,
          userId: req.user?.id,
          elapsedMs,
          failedSql: getRequestContext()?.failedSql,
        });
        return;
      }
      logApiDone(route, res.statusCode, elapsedMs, res.locals.apiMeta);
    });

    next();
  });
});

function parseCookies(header = '') {
  return Object.fromEntries(
    String(header)
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const idx = part.indexOf('=');
        if (idx < 0) return [part, ''];
        return [
          decodeURIComponent(part.slice(0, idx)),
          decodeURIComponent(part.slice(idx + 1)),
        ];
      }),
  );
}

function setSessionCookie(res, sessionId) {
  res.cookie(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: 'lax',
    secure: SESSION_COOKIE_SECURE,
    path: '/',
    maxAge: SESSION_TTL_MS,
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    sameSite: 'lax',
    secure: SESSION_COOKIE_SECURE,
    path: '/',
  });
}

function createSession(user) {
  const sessionId = crypto.randomUUID();
  sessions.set(sessionId, {
    userId: user.id,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return sessionId;
}

async function sessionUserPayload(user, sessionRecord = null) {
  const [effectivePermissions, effectiveWritePermissions, permissions, role] = await Promise.all([
    buildEffectivePermissions(user),
    buildEffectiveWritePermissions(user),
    userPermissions(user),
    loadRole(user.roleId),
  ]);

  const cabinet = await fillClientDisplayName(
    cabinetPayload(resolveCabinetContext(user, sessionRecord)),
  );

  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName,
    roleId: user.roleId,
    forcePasswordChange: user.forcePasswordChange,
    active: user.active !== false,
    clientId: user.clientId || '',
    updatedAt: user.updatedAt ?? null,
    permissions,
    effectivePermissions,
    effectiveWritePermissions,
    role: role ? {
      id: role.id,
      name: role.name,
      displayName: role.displayName,
    } : null,
    cabinet,
  };
}

async function getSessionUser(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[SESSION_COOKIE];
  if (!sessionId) return null;

  const session = sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  session.expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(sessionId, session);
  const user = await getUserById(session.userId);
  if (!user) {
    sessions.delete(sessionId);
    return null;
  }
  return { user, sessionId, session };
}

function sendApiError(res, err, fallbackStatus = 502) {
  const status = err.statusCode || fallbackStatus;
  const body = { error: err.message };
  if (err.code) body.code = err.code;
  res.status(status).json(body);
}

function forcedPasswordRouteAllowed(req) {
  if (req.method !== 'POST') return false;
  const userPassword = req.path.match(/^\/users\/([^/]+)\/password$/);
  if (userPassword) {
    return decodeURIComponent(userPassword[1]) === req.user?.id;
  }
  if (req.path === '/cabinet/profile/password') {
    return true;
  }
  return false;
}

async function requireSession(req, res, next) {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      res.status(401).json({ error: 'Требуется авторизация' });
      return;
    }
    req.user = session.user;
    req.sessionId = session.sessionId;

    if (!req.user.active) {
      sessions.delete(req.sessionId);
      res.status(403).json({ error: 'Учётная запись отключена' });
      return;
    }

    if (await rejectDisabledClientSession(req.user, req.sessionId, sessions, res)) {
      return;
    }

    if (req.user.forcePasswordChange && !forcedPasswordRouteAllowed(req)) {
      res.status(403).json({ error: 'Необходимо сменить пароль' });
      return;
    }

    next();
  } catch (err) {
    sendApiError(res, err);
  }
}

async function runNamed(builder, { label = 'other', name } = {}) {
  const spec = await builder();
  const { rows, elapsedMs } = await query(spec.sql, spec.params || {}, {
    label,
    name,
    clickhouse_settings: spec.clickhouse_settings,
    requestTimeoutMs: spec.requestTimeoutMs,
  });
  return {
    data: await spec.map(rows),
    meta: { elapsedMs, rows: rows.length, ...(spec.meta || {}) },
  };
}

function snapshotReaderClientId(req) {
  if (!isCabinetScoped(req.cabinet)) return null;
  return req.cabinet?.clientId || req.user?.clientId || null;
}

function attachExplorerSnapshotMeta(responseBody, {
  ownerId,
  clientId = null,
  body,
  data,
  meta,
  elapsedMs,
}) {
  const stored = tryCreateSnapshot({
    kind: 'explorer',
    ownerId,
    clientId,
    query: buildExplorerStoredQuery(body, meta),
    payload: buildExplorerStoredPayload(data, meta, elapsedMs),
  });
  if (stored) {
    responseBody.meta.snapshotId = stored.id;
    responseBody.meta.snapshotExpiresAt = stored.expiresAt;
  }
  return responseBody;
}

function attachDnsExplorerSnapshotMeta(responseBody, {
  ownerId,
  body,
  data,
  meta,
  elapsedMs,
}) {
  const stored = tryCreateSnapshot({
    kind: 'dns-explorer',
    ownerId,
    query: buildDnsExplorerStoredQuery(body, meta),
    payload: buildDnsExplorerStoredPayload(data, meta, elapsedMs),
  });
  if (stored) {
    responseBody.meta.snapshotId = stored.id;
    responseBody.meta.snapshotExpiresAt = stored.expiresAt;
  }
  return responseBody;
}

function parseCollectorIdQuery(query) {
  const raw = query.collector_id;
  if (raw == null || raw === '') return undefined;
  if (Array.isArray(raw)) {
    const parts = raw.map((v) => String(v).trim()).filter(Boolean);
    return parts.length ? parts.join(',') : undefined;
  }
  const v = String(raw).trim();
  return v || undefined;
}

app.get('/api/health', async (_req, res) => {
  const status = await ping(true);
  res.json({
    ok: status.ok,
    clickhouse: {
      connected: status.ok,
      version: status.version,
      error: status.error,
      ...getConfig(),
    },
  });
});

app.get('/api/build-info', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ data: getBuildInfo() });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const user = await verifyCredentials(req.body?.username, req.body?.password);
    if (!user) {
      await writeAuditEvent({
        ...auditContextFromReq(req),
        action: 'login_fail',
        resource: 'auth',
        method: 'POST',
        path: '/api/auth/login',
        objectLabel: username,
        result: 'fail',
      }).catch(() => {});
      res.status(401).json({ error: 'Вход с паролем не сработал. Попробуйте еще раз, пожалуйста' });
      return;
    }
    const sessionId = createSession(user);
    setSessionCookie(res, sessionId);
    await writeAuditEvent({
      ...auditContextFromReq(req, sessionId),
      actorUserId: user.id,
      actorUsername: user.username,
      actorRole: user.roleId,
      action: 'login',
      resource: 'auth',
      method: 'POST',
      path: '/api/auth/login',
      result: 'ok',
    }).catch(() => {});
    res.json({ ok: true, user: await sessionUserPayload(user, sessions.get(sessionId)) });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const cookies = parseCookies(req.headers.cookie);
    const sessionId = cookies[SESSION_COOKIE];
    let logoutUser = null;
    if (sessionId) {
      const sessionRecord = getSessionRecord(sessions, sessionId);
      if (sessionRecord?.impersonation) {
        const ended = clearImpersonation(sessionRecord, 'logout');
        const user = await getUserById(sessionRecord.userId).catch(() => null);
        logoutUser = user;
        if (ended && user) {
          await writeImpersonationEvent({
            auditId: ended.auditId,
            sessionAuditId: ended.auditId,
            event: 'end',
            actorUserId: user.id,
            actorUsername: user.username,
            clientId: ended.clientId,
            clientDisplayName: ended.clientDisplayName,
            reason: 'logout',
          }).catch(() => {});
          req.user = user;
          await writeImpersonateAuditEvent(req, {
            kind: 'end',
            clientId: ended.clientId,
            clientDisplayName: ended.clientDisplayName,
            sessionId,
            path: '/api/auth/logout',
          }).catch(() => {});
        }
      } else if (sessionRecord?.userId) {
        logoutUser = await getUserById(sessionRecord.userId).catch(() => null);
      }
      sessions.delete(sessionId);
    }
    if (logoutUser) {
      await writeAuditEvent({
        ...auditContextFromReq(req, sessionId),
        actorUserId: logoutUser.id,
        actorUsername: logoutUser.username,
        actorRole: logoutUser.roleId,
        action: 'logout',
        resource: 'auth',
        method: 'POST',
        path: '/api/auth/logout',
        result: 'ok',
      }).catch(() => {});
    }
    clearSessionCookie(res);
    res.json({ ok: true });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      res.status(401).json({ error: 'Требуется авторизация' });
      return;
    }
    if (!session.user.active) {
      sessions.delete(session.sessionId);
      res.status(403).json({ error: 'Учётная запись отключена' });
      return;
    }
    if (await rejectDisabledClientSession(session.user, session.sessionId, sessions, res)) {
      return;
    }
    res.json({ user: await sessionUserPayload(session.user, session.session) });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/auth/stop-impersonation', async (req, res) => {
  try {
    const session = await getSessionUser(req);
    if (!session) {
      res.status(401).json({ error: 'Требуется авторизация' });
      return;
    }
    req.user = session.user;
    req.sessionId = session.sessionId;
    await stopImpersonationHandler(req, res, { sessions, reason: 'stop' });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.use('/api', requireSession);
app.use('/api', apiResourceGuard);
app.use('/api', cabinetIsolationGuard);
app.use('/api', createAuditMiddleware());

app.post('/api/audit/page', async (req, res) => {
  try {
    const pageId = String(req.body?.pageId || '').trim();
    if (!pageId) {
      res.status(400).json({ error: 'pageId обязателен' });
      return;
    }
    await writePageViewEvent(req, pageId, req.sessionId);
    res.json({ ok: true });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/audit', async (req, res) => {
  try {
    const result = await listAuditEvents({
      from: req.query.from,
      to: req.query.to,
      q: req.query.q,
      ip: req.query.ip,
      kind: req.query.kind,
      result: req.query.result,
      limit: req.query.limit,
      offset: req.query.offset,
    });
    res.json(result);
  } catch (err) {
    sendApiError(res, err);
  }
});

app.use('/api/rbac', createRbacRouter());
app.use('/api/cabinet', createCabinetRouter({ sessions }));
app.use('/api/clients', createClientsRouter({ sessions }));
app.use('/api/erp-piterix', createErpPiterixRouter());
app.use('/api/detection', createDetectionRouter());

app.get('/api/dashboard/collectors', async (_req, res) => {
  try {
    const [collectorsResult, locationsResult] = await Promise.all([
      runNamed(() => dashboardCollectors(), { name: 'dashboard/collectors' }),
      runNamed(() => listLocations(), { name: 'dashboard/locations' }),
    ]);
    res.json({
      data: {
        collectors: collectorsResult.data,
        locations: locationsResult.data,
      },
      meta: {
        elapsedMs: Math.max(collectorsResult.meta?.elapsedMs || 0, locationsResult.meta?.elapsedMs || 0),
        rows: (collectorsResult.meta?.rows || 0) + (locationsResult.meta?.rows || 0),
      },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/traffic-stats', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => trafficDirectionStats({ range, from, to, collectorId }),
      { name: 'dashboard/traffic-stats' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/traffic', async (req, res) => {
  try {
    const range = String(req.query.range || '1h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = parseChartDirectionsQuery(req.query.directions);
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => trafficBandwidthSeries({ range, from, to, directions, collectorId }),
      { label: 'chart', name: 'dashboard/traffic' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/protocols', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeProtocolDirections(String(req.query.directions).split(','))
      : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => protocolDistribution({ range, from, to, directions, collectorId }),
      { name: 'dashboard/protocols' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/services', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeProtocolDirections(String(req.query.directions).split(','))
      : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => serviceDistribution({ range, from, to, directions, collectorId }),
      { name: 'dashboard/services' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/protocols/timeseries', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeProtocolDirections(String(req.query.directions).split(','))
      : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => protocolDistributionTimeseries({ range, from, to, directions, collectorId }),
      { name: 'dashboard/protocols/timeseries' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/services/timeseries', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeProtocolDirections(String(req.query.directions).split(','))
      : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => serviceDistributionTimeseries({ range, from, to, directions, collectorId }),
      { name: 'dashboard/services/timeseries' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/vlans', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeVlanDirections(String(req.query.directions).split(','))
      : undefined;
    const attachmentType = req.query.attachment_type ? String(req.query.attachment_type) : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => vlanDistribution({ range, from, to, directions, collectorId, attachmentType }),
      { name: 'dashboard/vlans' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, attachmentType, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/vlans/timeseries', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeVlanDirections(String(req.query.directions).split(','))
      : undefined;
    const attachmentType = req.query.attachment_type ? String(req.query.attachment_type) : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => vlanDistributionTimeseries({ range, from, to, directions, collectorId, attachmentType }),
      { name: 'dashboard/vlans/timeseries' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, attachmentType, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/vlan/top', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeVlanDirections(String(req.query.directions).split(','))
      : undefined;
    const attachmentType = req.query.attachment_type ? String(req.query.attachment_type) : undefined;
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => vlanTopTable({ range, from, to, directions, collectorId, attachmentType, limit }),
      { name: 'vlan/top' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, attachmentType, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/other-ports', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeProtocolDirections(String(req.query.directions).split(','))
      : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => otherPortsTop20({ range, from, to, directions, collectorId }),
      { name: 'dashboard/other-ports' },
    );
    res.json({
      ...result,
      meta: { ...result.meta, range, from, to, directions, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/countries', async (req, res) => {
  try {
    const range = String(req.query.range || '24h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeProtocolDirections(String(req.query.directions).split(','))
      : undefined;
    const countryBasis = req.query.basis ? String(req.query.basis) : 'ip';
    const mapSide = req.query.map_side ? String(req.query.map_side) : 'remote';
    const sourceIds = req.query.source_ids
      ? String(req.query.source_ids).split(',').map((s) => s.trim()).filter(Boolean)
      : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => countryHeatmap({ range, from, to, directions, countryBasis, mapSide, sourceIds, collectorId }),
      { name: 'dashboard/countries' },
    );
    res.json({
      ...result,
      meta: {
        ...result.meta,
        range,
        from,
        to,
        directions,
        countryBasis,
        mapSide,
        sourceIds,
        collectorId,
      },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/top-talkers', async (req, res) => {
  try {
    const range = String(req.query.range || '1h');
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;
    const directions = req.query.directions
      ? normalizeProtocolDirections(String(req.query.directions).split(','))
      : undefined;
    const group = normalizeTopTalkersGroup(req.query.group);
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const offset = Math.min(Math.max(Number(req.query.offset) || 0, 0), 10000);
    const sourceIds = req.query.source_ids
      ? String(req.query.source_ids).split(',').map((s) => s.trim()).filter(Boolean)
      : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await runNamed(
      () => topTalkersDashboard({ range, from, to, directions, group, limit, offset, sourceIds, collectorId }),
      { name: 'dashboard/top-talkers' },
    );
    res.json({
      ...result,
      meta: {
        ...(result.meta || {}),
        range,
        from,
        to,
        directions,
        group,
        limit,
        offset,
        hasMore: (result.data?.length ?? 0) >= limit,
        sourceIds,
        collectorId,
      },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dashboard/recent-flows', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 200);
    const directions = req.query.directions
      ? normalizeProtocolDirections(String(req.query.directions).split(','))
      : req.query.direction
        ? normalizeProtocolDirections([String(req.query.direction)])
        : undefined;
    const collectorId = parseCollectorIdQuery(req.query);
    const result = await fetchRecentFlows(limit, directions, collectorId, {
      name: 'dashboard/recent-flows',
    });
    res.json({
      ...result,
      meta: { ...result.meta, directions, collectorId },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

function rejectCabinetDashboardLayout(req, res) {
  if (isCabinetScoped(req.cabinet)) {
    res.status(403).json({ error: 'Layout недоступен в клиентском кабинете' });
    return true;
  }
  return false;
}

app.get('/api/dashboard/layout', async (req, res) => {
  try {
    if (rejectCabinetDashboardLayout(req, res)) return;
    const stored = getDashboardLayout(req.user.id);
    res.json({
      data: stored?.layout || null,
      updatedAt: stored?.updatedAt || null,
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.put('/api/dashboard/layout', async (req, res) => {
  try {
    if (rejectCabinetDashboardLayout(req, res)) return;
    const saved = putDashboardLayout(req.user.id, req.body || {});
    res.json({ ok: true, data: saved.layout, updatedAt: saved.updatedAt });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

app.post('/api/dashboard/layout/reset', async (req, res) => {
  try {
    if (rejectCabinetDashboardLayout(req, res)) return;
    const result = resetDashboardLayout(req.user.id);
    res.json({ ok: true, data: result.layout, updatedAt: result.updatedAt });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

app.get('/api/explorer/schema', async (_req, res) => {
  try {
    res.json({ data: explorerSchema() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/explorer/entities', async (req, res) => {
  try {
    const data = await searchExplorerEntities({
      type: req.query.type,
      q: req.query.q,
      limit: req.query.limit,
      switchIp: req.query.switch_ip || req.query.switchIp || '',
    });
    res.json({ data });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/explorer/query', async (req, res) => {
  try {
    const body = req.body || {};
    const started = Date.now();
    const bundle = await explorerQuery(body);
    const queryBody = bundle.queryBody || body;
    const {
      flowsResult,
      resultSeriesResult,
      summaryData,
      timeseriesResult,
      breakdownResults,
      flowRows,
    } = await executeExplorerQueryBundle(bundle, queryBody, runNamed, 'explorer');
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
        breakdowns: breakdownResults,
      },
      meta: responseMeta,
    };
    attachExplorerSnapshotMeta(responseBody, {
      ownerId: req.user.id,
      body: queryBody,
      data: responseBody.data,
      meta: responseMeta,
      elapsedMs,
    });
    res.json(responseBody);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/explorer/flows', async (req, res) => {
  try {
    const body = req.body || {};
    const result = await runNamed(
      () => explorerFlows(body),
      { name: 'explorer/flows' },
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/explorer/export', async (req, res) => {
  try {
    const csv = await explorerExportCsv(req.body || {});
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="explorer-flows-${Date.now()}.csv"`);
    res.send(`\uFEFF${csv}`);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/explorer/saved-filters', async (req, res) => {
  try {
    const data = listSavedExplorerFilters(req.user.id);
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/explorer/saved-filters', async (req, res) => {
  try {
    const data = createSavedExplorerFilter(req.user.id, req.body || {});
    res.json({ ok: true, data });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/explorer/saved-filters/:id', async (req, res) => {
  try {
    const data = updateSavedExplorerFilter(req.params.id, req.user.id, req.body || {});
    if (!data) {
      res.status(404).json({ error: 'Фильтр не найден' });
      return;
    }
    res.json({ ok: true, data });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/explorer/saved-filters/:id', async (req, res) => {
  try {
    const ok = deleteSavedExplorerFilter(req.params.id, req.user.id);
    if (!ok) {
      res.status(404).json({ error: 'Фильтр не найден' });
      return;
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/explorer/snapshots/:id/share', async (req, res) => {
  try {
    const data = shareSnapshot(req.params.id, req.user.id, { kind: 'explorer' });
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

app.get('/api/explorer/snapshots/shared/:token', async (req, res) => {
  try {
    const data = getSharedSnapshot(req.params.token, {
      kind: 'explorer',
      readerClientId: snapshotReaderClientId(req),
      readerUserId: req.user.id,
    });
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

app.delete('/api/explorer/snapshots/:id/share', async (req, res) => {
  try {
    revokeShare(req.params.id, req.user.id, { kind: 'explorer' });
    res.json({ ok: true });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

app.get('/api/observations/config', async (_req, res) => {
  try {
    res.json({ data: observationsConfig() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/observations', async (req, res) => {
  try {
    res.json({ data: await listObservations(req.user.id) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/observations', async (req, res) => {
  try {
    const data = await createObservation(req.user.id, req.body || {});
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.status || 400).json({
      error: err.message,
      occupants: err.occupants || undefined,
      quotas: err.quotas || undefined,
    });
  }
});

app.get('/api/settings/smtp', async (req, res) => {
  try {
    if (String(req.user?.roleId || '') !== 'Administrator') {
      res.status(403).json({ error: 'Только администратор' });
      return;
    }
    await ensureSmtpSettingsTables();
    res.json({ data: await getSmtpSettings() });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.put('/api/settings/smtp', async (req, res) => {
  try {
    if (String(req.user?.roleId || '') !== 'Administrator') {
      res.status(403).json({ error: 'Только администратор' });
      return;
    }
    await saveSmtpSettings(req.body || {});
    res.json({ ok: true, data: await getSmtpSettings() });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

app.post('/api/settings/smtp/test', async (req, res) => {
  try {
    if (String(req.user?.roleId || '') !== 'Administrator') {
      res.status(403).json({ error: 'Только администратор' });
      return;
    }
    const to = String(req.body?.to || req.user?.email || req.user?.username || '').trim();
    await sendTestMail(to);
    res.json({ ok: true });
  } catch (err) {
    res.status(err.statusCode || 502).json({ error: err.message });
  }
});

app.get('/api/observations/analytics/diagnostics', async (_req, res) => {
  try {
    const data = await getObservationAnalyticsDiagnostics();
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/diagnostics/worker', async (_req, res) => {
  try {
    const data = await getWorkerDiagnostics();
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/diagnostics/worker/gaps', async (req, res) => {
  try {
    const opts = (req.query.from && req.query.to)
      ? { from: req.query.from, to: req.query.to }
      : { days: req.query.days };
    const data = await scanGaps(opts);
    res.json({ data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.get('/api/diagnostics/worker/backfill', async (req, res) => {
  try {
    const data = await listBackfillQueue(req.query.limit);
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/diagnostics/worker/backfill', async (req, res) => {
  try {
    const body = req.body || {};
    const data = await enqueueBackfill({
      ranges: Array.isArray(body.ranges) ? body.ranges : null,
      from: body.from,
      to: body.to,
      includeObservations: body.includeObservations !== false,
      jobs: body.jobs,
    });
    res.status(201).json({ data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.post('/api/diagnostics/worker/backfill/cancel', async (_req, res) => {
  try {
    const data = await cancelBackfill();
    res.json({ data });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.get('/api/diagnostics/enrichment', async (_req, res) => {
  try {
    const data = await getEnrichmentDiagnostics();
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/diagnostics/snmp', async (_req, res) => {
  try {
    const data = await getSnmpDiagnostics();
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/diagnostics/bounds', async (_req, res) => {
  try {
    const data = await getBoundsDiagnostics();
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/diagnostics/analysis-snapshots', async (_req, res) => {
  try {
    res.json({ data: getActiveShareLinkStats() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/diagnostics/build-info', (_req, res) => {
  res.json({ data: getBuildInfo() });
});

app.get('/api/diagnostics/failed-requests', async (req, res) => {
  try {
    const limit = req.query.limit;
    const offset = req.query.offset;
    const data = listFailedRequests({ limit, offset });
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/observations/:id', async (req, res) => {
  try {
    const data = await getObservation(req.params.id, req.user.id);
    if (!data) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/observations/:id', async (req, res) => {
  try {
    const data = await updateObservation(req.params.id, req.user.id, req.body || {});
    if (!data) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.status || 400).json({
      error: err.message,
      occupants: err.occupants || undefined,
      quotas: err.quotas || undefined,
    });
  }
});

app.delete('/api/observations/:id', async (req, res) => {
  try {
    const ok = await deleteObservation(req.params.id, req.user.id);
    if (!ok) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

app.post('/api/observations/:id/duplicate', async (req, res) => {
  try {
    const data = await duplicateObservation(req.params.id, req.user.id);
    if (!data) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

app.post('/api/observations/:id/cancel', async (req, res) => {
  try {
    const data = await cancelMaterialize(req.params.id, req.user.id);
    if (!data) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message });
  }
});

app.post('/api/observations/:id/materialize', async (req, res) => {
  try {
    const data = await queueMaterialize(req.params.id, req.user.id);
    if (!data) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.status || 400).json({
      error: err.message,
      occupants: err.occupants || undefined,
      quotas: err.quotas || undefined,
    });
  }
});

app.post('/api/observations/:id/preview', async (req, res) => {
  try {
    const data = await previewObservation(req.params.id, req.user.id, req.body || {});
    if (!data) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ data });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/observations/:id/run', async (req, res) => {
  try {
    const data = await runObservationReport(req.params.id, req.user.id);
    if (!data) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ ok: true, data });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/observations/:id/runs', async (req, res) => {
  try {
    const data = await listRuns(req.params.id, req.user.id);
    if (!data) {
      res.status(404).json({ error: 'Наблюдение не найдено' });
      return;
    }
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/observations/:id/runs/:runId/artifact', async (req, res) => {
  try {
    const file = req.query.file || 'report.html';
    const artifact = await getRunArtifact(req.params.id, req.params.runId, req.user.id, file);
    if (!artifact) {
      res.status(404).json({ error: 'Артефакт не найден' });
      return;
    }
    res.setHeader('Content-Type', artifact.contentType);
    res.setHeader('Content-Disposition', `inline; filename="${artifact.fileName}"`);
    fs.createReadStream(artifact.path).pipe(res);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

function dnsRouteMeta(filters, extra = {}) {
  return {
    range: filters.range,
    from: filters.from,
    to: filters.to,
    sourceIds: filters.sourceIds,
    collectorId: filters.collectorId,
    hideResolvers: filters.hideResolvers,
    ...extra,
  };
}

app.get('/api/dns/sources', async (_req, res) => {
  try {
    const result = await runNamed(() => dnsSources(), { name: 'dns/sources' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dns/activity', async (req, res) => {
  try {
    const filters = parseDnsOverviewQuery(req.query);
    const result = await runNamed(() => dnsActivityChart(filters), { name: 'dns/activity' });
    res.json({
      ...result,
      meta: { ...result.meta, ...dnsRouteMeta(filters) },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dns/top-domains', async (req, res) => {
  try {
    const filters = parseDnsOverviewQuery(req.query);
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const result = await runNamed(() => dnsTopDomains(filters, limit), { name: 'dns/top-domains' });
    res.json({
      ...result,
      meta: { ...result.meta, ...dnsRouteMeta(filters, { limit }) },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dns/top-clients', async (req, res) => {
  try {
    const filters = parseDnsOverviewQuery(req.query);
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const result = await runNamed(() => dnsTopClients(filters, limit), { name: 'dns/top-clients' });
    res.json({
      ...result,
      meta: { ...result.meta, ...dnsRouteMeta(filters, { limit }) },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dns/top-servers', async (req, res) => {
  try {
    const filters = parseDnsOverviewQuery(req.query);
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const result = await runNamed(() => dnsTopServers(filters, limit), { name: 'dns/top-servers' });
    res.json({
      ...result,
      meta: { ...result.meta, ...dnsRouteMeta(filters, { limit }) },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dns/recent', async (req, res) => {
  try {
    const filters = parseDnsOverviewQuery(req.query);
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 500);
    const result = await runNamed(() => dnsRecent(filters, limit), { name: 'dns/recent' });
    res.json({
      ...result,
      meta: { ...result.meta, ...dnsRouteMeta(filters, { limit }) },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dns/qtypes', async (req, res) => {
  try {
    const filters = parseDnsFiltersQuery(req.query);
    const result = await runNamed(() => dnsQtypes(filters), { name: 'dns/qtypes' });
    res.json({
      ...result,
      meta: { ...result.meta, ...dnsRouteMeta(filters) },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/dns-explorer/schema', async (_req, res) => {
  try {
    res.json({ data: dnsExplorerSchema() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/dns-explorer/query', async (req, res) => {
  try {
    const body = parseDnsExplorerBody(req.body || {});
    const started = Date.now();
    const spec = dnsExplorerQuery(body);
    const groupBy = spec.meta.groupBy || [];
    const runTimeseries = (querySpec, name) => runNamed(
      () => ({ sql: querySpec.timeseriesSql, params: querySpec.params, map: querySpec.mapTimeseries }),
      { name },
    );
    const queries = [
      runTimeseries(spec, 'dns-explorer/timeseries'),
      runNamed(() => ({ sql: spec.tableSql, params: spec.params, map: spec.mapTable }), { name: 'dns-explorer/table' }),
    ];
    if (groupBy.length) {
      queries.push(runTimeseries(dnsExplorerQuery({ ...body, groupBy: [] }), 'dns-explorer/timeseries-total'));
    }
    const [tsResult, tableResult, totalTsResult] = await Promise.all(queries);
    const tsRows = tsResult.data || [];
    const tableRows = tableResult.data || [];
    const timeseries = normalizeDnsExplorerTimeseries(
      groupBy.length ? (totalTsResult?.data || []) : tsRows,
    );
    const elapsedMs = Date.now() - started;
    const responseMeta = {
      ...spec.meta,
      range: body.range,
      from: body.from,
      to: body.to,
      elapsedMs,
    };
    const responseBody = {
      data: {
        rows: tableRows,
        timeseries,
        resultSeries: groupBy.length ? buildDnsExplorerResultSeries(tsRows, tableRows) : null,
      },
      meta: responseMeta,
    };
    attachDnsExplorerSnapshotMeta(responseBody, {
      ownerId: req.user.id,
      body,
      data: responseBody.data,
      meta: responseMeta,
      elapsedMs,
    });
    res.json(responseBody);
  } catch (err) {
    const status = /Неизвестн|укажите|Некоррект|недоступ|retention|должен|период/i.test(err.message) ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/dns-explorer/export', async (req, res) => {
  try {
    const csv = await dnsExplorerExportCsv(req.body || {});
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="dns-explorer-${Date.now()}.csv"`);
    res.send(`\uFEFF${csv}`);
  } catch (err) {
    const status = /Неизвестн|укажите|Некоррект|недоступ|retention|должен|период/i.test(err.message) ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/dns-explorer/snapshots/:id/share', async (req, res) => {
  try {
    const data = shareSnapshot(req.params.id, req.user.id, { kind: 'dns-explorer' });
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

app.get('/api/dns-explorer/snapshots/shared/:token', async (req, res) => {
  try {
    const data = getSharedSnapshot(req.params.token, {
      kind: 'dns-explorer',
      readerClientId: snapshotReaderClientId(req),
      readerUserId: req.user.id,
    });
    res.json({ ok: true, data });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

app.delete('/api/dns-explorer/snapshots/:id/share', async (req, res) => {
  try {
    revokeShare(req.params.id, req.user.id, { kind: 'dns-explorer' });
    res.json({ ok: true });
  } catch (err) {
    res.status(err.statusCode || 400).json({ error: err.message });
  }
});

function normalizeDnsExplorerTimeseries(rows) {
  return (rows || []).map((r) => ({
    bucket: String(r.bucket || ''),
    bucketMs: Number(r.bucketMs) || 0,
    value: Number(r.value) || 0,
  }));
}

function buildDnsExplorerResultSeries(tsRows, tableRows) {
  const seriesByRow = Object.fromEntries((tableRows || []).map((row) => [row.id, []]));
  const keyToId = new Map((tableRows || []).map((row) => [row.seriesKey, row.id]));
  for (const pt of tsRows || []) {
    const rowId = keyToId.get(pt.seriesKey);
    if (!rowId) continue;
    seriesByRow[rowId].push({
      bucket: String(pt.bucket || ''),
      bucketMs: Number(pt.bucketMs) || 0,
      value: Number(pt.value) || 0,
    });
  }
  return { seriesByRow };
}

app.get('/api/dns-explorer/suggest/domains', async (req, res) => {
  try {
    const ctx = parseDnsExplorerSuggestQuery(req.query);
    const spec = dnsExplorerSuggestDomains(ctx, ctx.q, 20);
    const result = await runNamed(() => spec, { name: 'dns-explorer/suggest/domains' });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/dns-explorer/suggest/client-ips', async (req, res) => {
  try {
    const ctx = parseDnsExplorerSuggestQuery(req.query);
    const spec = dnsExplorerSuggestClientIps(ctx, ctx.q, 20);
    const result = await runNamed(() => spec, { name: 'dns-explorer/suggest/client-ips' });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/dns-explorer/suggest/server-ips', async (req, res) => {
  try {
    const ctx = parseDnsExplorerSuggestQuery(req.query);
    const spec = dnsExplorerSuggestServerIps(ctx, ctx.q, 20);
    const result = await runNamed(() => spec, { name: 'dns-explorer/suggest/server-ips' });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/dns-explorer/suggest/qtypes', async (req, res) => {
  try {
    const ctx = parseDnsExplorerSuggestQuery(req.query);
    const spec = dnsExplorerSuggestQtypes(ctx);
    const result = await runNamed(() => spec, { name: 'dns-explorer/suggest/qtypes' });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/dns-explorer/suggest/answers', async (req, res) => {
  try {
    const ctx = parseDnsExplorerSuggestQuery(req.query);
    const spec = dnsExplorerSuggestAnswers(ctx, ctx.q, 50);
    const result = await runNamed(() => spec, { name: 'dns-explorer/suggest/answers' });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const clientId = String(req.query.clientId ?? req.query.client_id ?? '').trim() || undefined;
    res.json(await listUsers({ clientId }));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/users', async (req, res) => {
  try {
    const result = await createUser(req.body || {});
    res.status(201).json({ ok: true, ...result });
  } catch (err) {
    sendApiError(res, err, err.statusCode || 502);
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const result = await updateUser(req.params.id, req.body || {});
    res.json({ ok: true, ...result });
  } catch (err) {
    sendApiError(res, err, err.statusCode || 502);
  }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    const result = await deleteUser(req.params.id);
    res.json({ ok: true, ...result });
  } catch (err) {
    sendApiError(res, err, err.statusCode || 502);
  }
});

app.post('/api/users/:id/password-reset', async (req, res) => {
  try {
    const targetId = String(req.params.id);
    if (!(await hasPermission(req.user, 'users.change_password'))) {
      res.status(403).json({ error: 'Недостаточно прав для смены пароля' });
      return;
    }
    const result = await resetUserPassword(targetId, req.body?.password);
    const targetUser = await getUserById(targetId).catch(() => null);
    await writeAuditEvent({
      ...auditContextFromReq(req, req.sessionId),
      action: 'password_reset',
      resource: 'users',
      method: 'POST',
      path: `/api/users/${encodeURIComponent(targetId)}/password-reset`,
      objectId: targetId,
      objectLabel: targetUser?.username || targetId,
      result: 'ok',
    }).catch(() => {});
    res.json({
      ok: true,
      data: result.data,
      password: result.password,
    });
  } catch (err) {
    sendApiError(res, err, err.statusCode || 502);
  }
});

app.post('/api/users/:id/password', async (req, res) => {
  try {
    const targetId = String(req.params.id);
    const isSelf = targetId === req.user.id;
    if (!isSelf && !(await hasPermission(req.user, 'users.change_password'))) {
      res.status(403).json({ error: 'Недостаточно прав для смены пароля' });
      return;
    }
    const result = await changeUserPassword(targetId, req.body?.password, {
      clearForce: isSelf && req.user.forcePasswordChange,
    });
    if (isSelf && req.user.forcePasswordChange) req.user.forcePasswordChange = false;
    const targetUser = isSelf ? req.user : await getUserById(targetId).catch(() => null);
    await writeAuditEvent({
      ...auditContextFromReq(req, req.sessionId),
      action: 'password_change',
      resource: 'users',
      method: 'POST',
      path: `/api/users/${encodeURIComponent(targetId)}/password`,
      objectId: targetId,
      objectLabel: targetUser?.username || targetId,
      result: 'ok',
    }).catch(() => {});
    res.json({ ok: true, ...result });
  } catch (err) {
    sendApiError(res, err, err.statusCode || 502);
  }
});

app.get('/api/admin/ttl', async (_req, res) => {
  try {
    const result = await listTtlTables();
    res.json(result);
  } catch (err) {
    sendApiError(res, err, err.statusCode || 502);
  }
});

app.put('/api/admin/ttl/:id', async (req, res) => {
  try {
    const result = await updateTtlTable(req.params.id, req.body?.days, {
      roleId: req.user?.roleId,
    });
    res.json(result);
  } catch (err) {
    sendApiError(res, err, err.statusCode || 502);
  }
});

app.get('/api/refs/l3-prefixes', async (_req, res) => {
  try {
    const result = await runNamed(() => listL3Prefixes(), { name: 'refs/l3-prefixes' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/refs/dns-resolvers', async (_req, res) => {
  try {
    const result = await runNamed(() => listDnsResolvers(), { name: 'refs/dns-resolvers' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/refs/flow-exclusions', async (_req, res) => {
  try {
    const [result, stats] = await Promise.all([
      runNamed(() => listFlowExclusions(), { name: 'refs/flow-exclusions' }),
      flowExclusionsExcludedStats(),
    ]);
    const rules = Array.isArray(result.data) ? result.data : [];
    res.json({
      ...result,
      meta: {
        ...result.meta,
        rulesTotal: rules.length,
        rulesEnabled: rules.filter((r) => r.enabled === 1).length,
        ...stats,
      },
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/refs/entities', async (_req, res) => {
  try {
    const result = await runNamed(() => listNetEntities(), { name: 'refs/entities' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/refs/net-entities', async (_req, res) => {
  try {
    const result = await runNamed(() => listNetEntitiesAdmin(), { name: 'refs/net-entities' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/refs/net-entities', async (req, res) => {
  try {
    const { elapsedMs, entityId } = await saveNetEntity(req.body || {});
    res.json({ ok: true, meta: { elapsedMs, entityId } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.get('/api/refs/vlans', async (_req, res) => {
  try {
    const result = await runNamed(() => listVlansAdmin(), { name: 'refs/vlans' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/refs/vlans/seen', async (req, res) => {
  try {
    const lookbackHours = req.query.hours ? Number(req.query.hours) : undefined;
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    const result = await runNamed(
      () => listUnnamedVlansSeen({ lookbackHours, limit }),
      { name: 'refs/vlans-seen' },
    );
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/refs/vlans', async (req, res) => {
  try {
    const { elapsedMs, vlanId } = await saveVlan(req.body || {});
    res.json({ ok: true, meta: { elapsedMs, vlanId } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/vlans/enabled', async (req, res) => {
  try {
    const meta = await setVlanEnabled(req.body || {});
    res.json({ ok: true, meta });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/vlans/delete', async (req, res) => {
  try {
    const meta = await deleteVlan(req.body || {});
    res.json({ ok: true, meta });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.get('/api/refs/port-services', async (req, res) => {
  try {
    const filters = {
      search: req.query.search,
      transport: req.query.transport,
      category: req.query.category,
    };
    const result = await runNamed(() => listPortServices(filters), { name: 'refs/port-services' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/refs/port-services', async (req, res) => {
  try {
    const meta = await savePortService(req.body || {});
    res.json({ ok: true, meta });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/port-services/disable', async (req, res) => {
  try {
    const meta = await disablePortService(req.body || {});
    res.json({ ok: true, meta });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.get('/api/refs/port-services/seed-defaults', async (_req, res) => {
  try {
    const preview = await previewSeedDefaults();
    res.json(preview);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/refs/port-services/seed-defaults', async (_req, res) => {
  try {
    const meta = await seedDefaults();
    res.json({ ok: true, meta });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/refs/locations', async (_req, res) => {
  try {
    const result = await runNamed(() => listLocations(), { name: 'refs/locations' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/refs/locations', async (req, res) => {
  try {
    const { elapsedMs, locationId } = await saveLocation(req.body || {});
    res.json({ ok: true, meta: { elapsedMs, locationId } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.get('/api/refs/collectors', async (_req, res) => {
  try {
    const result = await runNamed(() => listCollectorsAdmin(), { name: 'refs/collectors' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/refs/collectors', async (req, res) => {
  try {
    const { elapsedMs, collectorId, boundSources, bindErrors } = await saveCollector(req.body || {});
    res.json({
      ok: true,
      meta: { elapsedMs, collectorId, boundSources, bindErrors },
    });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/collectors/delete', async (req, res) => {
  try {
    const { elapsedMs, collectorId, unboundSources } = await deleteCollector(req.body || {});
    res.json({
      ok: true,
      meta: { elapsedMs, collectorId, unboundSources },
    });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : 502;
    res.status(status).json({
      error: err.message,
      unbindErrors: err.unbindErrors,
    });
  }
});

app.get('/api/refs/collectors/options', async (_req, res) => {
  try {
    const result = await runNamed(() => listCollectorsForSelect(), { name: 'refs/collectors-options' });
    res.json({
      ...result,
      data: result.data.map((row) => ({
        value: row.collectorId,
        label: row.label,
        collectorId: row.collectorId,
        collectorName: row.collectorName,
        hostname: row.hostname,
        locationId: row.locationId,
        locationName: row.locationName,
      })),
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/refs/flow-sources', async (_req, res) => {
  try {
    const result = await runNamed(() => listFlowSources(), { name: 'refs/flow-sources' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/refs/flow-sources/bind', async (req, res) => {
  try {
    const { elapsedMs, sourceId, collectorId } = await bindFlowSource(req.body || {});
    res.json({ ok: true, meta: { elapsedMs, sourceId, collectorId } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/flow-sources', async (req, res) => {
  try {
    const result = await registerFlowSource(req.body || {});
    res.json({ ok: true, meta: result });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/flow-sources/delete', async (req, res) => {
  try {
    const result = await deleteFlowSource(req.body || {});
    res.json({ ok: true, meta: result });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.get('/api/refs/snmp-settings', async (_req, res) => {
  try {
    const spec = await listSnmpSettings();
    res.json({ data: spec.map(), meta: spec.meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/snmp-settings', async (req, res) => {
  try {
    const meta = await saveSnmpSettings(req.body || {});
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/refs/snmp-agents', async (_req, res) => {
  try {
    res.json(await runNamed(() => listSnmpAgents(), { name: 'refs/snmp-agents' }));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/snmp-agents', async (req, res) => {
  try {
    const meta = await saveSnmpAgent(req.body?.switchIp ?? req.body?.switch_ip, req.body || {});
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/refs/snmp-agents/:ip/interfaces', async (req, res) => {
  try {
    res.json(await runNamed(
      () => listSnmpInterfaces(req.params.ip),
      { name: 'refs/snmp-agent-interfaces' },
    ));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/snmp-agents/probe-all', async (_req, res) => {
  try {
    const meta = await requestSnmpProbeAll({ enable: true });
    res.status(202).json({ ok: true, accepted: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/snmp-agents/:ip/probe', async (req, res) => {
  try {
    const meta = await requestSnmpProbe(req.params.ip);
    res.status(202).json({ ok: true, accepted: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.delete('/api/refs/snmp-agents/:ip', async (req, res) => {
  try {
    const meta = await deleteSnmpAgent(req.params.ip);
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/refs/direction-settings', async (_req, res) => {
  try {
    res.json({ data: await getDirectionSettings() });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/direction-settings', async (req, res) => {
  try {
    const meta = await saveDirectionSettings(req.body || {}, { updatedBy: req.user?.id || '' });
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/refs/interface-role-rules', async (_req, res) => {
  try {
    res.json(await runNamed(() => listInterfaceRoleRules(), { name: 'refs/interface-role-rules' }));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/interface-role-rules', async (req, res) => {
  try {
    const meta = await saveInterfaceRoleRule(req.body || {});
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/interface-role-rules/delete', async (req, res) => {
  try {
    const meta = await deleteInterfaceRoleRule(req.body || {});
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/interface-role-rules/preview', async (req, res) => {
  try {
    res.json(await runNamed(
      () => previewInterfaceRoleRule(req.body || {}),
      { name: 'refs/interface-role-rule-preview' },
    ));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/refs/interface-roles/summary', async (_req, res) => {
  try {
    res.json(await runNamed(() => getInterfaceRoleSummary(), { name: 'refs/interface-roles-summary' }));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/refs/interface-roles/switches', async (_req, res) => {
  try {
    res.json(await runNamed(() => listInterfaceRoleSwitches(), { name: 'refs/interface-roles-switches' }));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/refs/interface-roles/:ip', async (req, res) => {
  try {
    res.json(await runNamed(
      () => listInterfaceRoles(req.params.ip),
      { name: 'refs/interface-roles' },
    ));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/interface-roles', async (req, res) => {
  try {
    const meta = await saveInterfaceRole(req.body || {}, { updatedBy: req.user?.id || '' });
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/interface-roles/delete', async (req, res) => {
  try {
    const meta = await deleteInterfaceRole(req.body || {}, { updatedBy: req.user?.id || '' });
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.post('/api/refs/interface-roles/rebuild', async (_req, res) => {
  try {
    const meta = await materializeEffectiveRoles();
    res.json({ ok: true, meta });
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/diagnostics/direction/coverage', async (req, res) => {
  try {
    res.json(await runNamed(
      () => getInterfaceFieldCoverage({ hours: req.query.hours }),
      { name: 'diagnostics/direction-coverage' },
    ));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/diagnostics/direction/compare', async (req, res) => {
  try {
    res.json(await runNamed(
      () => compareDirectionModels({ hours: req.query.hours }),
      { name: 'diagnostics/direction-compare' },
    ));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/diagnostics/direction/interfaces', async (req, res) => {
  try {
    res.json(await runNamed(
      () => listInterfacesByTraffic({
        hours: req.query.hours,
        limit: req.query.limit,
        onlyUnmarked: req.query.only_unmarked === '1' || req.query.onlyUnmarked === '1',
        asnThreshold: req.query.asn_threshold,
        switchIp: req.query.switch_ip || req.query.switchIp,
      }),
      { name: 'diagnostics/direction-interfaces' },
    ));
  } catch (err) {
    sendApiError(res, err);
  }
});

app.get('/api/collectors/discovered', async (_req, res) => {
  try {
    const result = await fetchDiscoveredSources();
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/collectors/overview', async (_req, res) => {
  try {
    const result = await fetchCollectorOverview();
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/collectors/status', async (_req, res) => {
  try {
    const result = await fetchCollectorStatus();
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/collectors/completeness', async (_req, res) => {
  try {
    const result = await fetchCollectorCompleteness();
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/api/collectors/completeness/detail', async (req, res) => {
  try {
    const result = await fetchCompletenessDetail(req.query?.sourceId, completenessSettings.windowMinutes);
    res.json(result);
  } catch (err) {
    res.status(err.statusCode === 400 ? 400 : 502).json({ error: err.message });
  }
});

app.get('/api/collectors/completeness/history', async (req, res) => {
  try {
    const result = await fetchCompletenessHistory(req.query?.sourceId);
    res.json(result);
  } catch (err) {
    res.status(err.statusCode === 400 ? 400 : 502).json({ error: err.message });
  }
});

function bmpStatus(err) {
  return err.statusCode === 400 ? 400 : 502;
}

app.get('/api/bmp/summary', async (_req, res) => {
  try {
    res.json(await getBmpSummary());
  } catch (err) {
    res.status(bmpStatus(err)).json({ error: err.message });
  }
});

app.get('/api/bmp/peers', async (req, res) => {
  try {
    res.json(await getBmpPeers(req.query || {}));
  } catch (err) {
    res.status(bmpStatus(err)).json({ error: err.message });
  }
});

app.get('/api/bmp/routers', async (_req, res) => {
  try {
    res.json(await getBmpRouters());
  } catch (err) {
    res.status(bmpStatus(err)).json({ error: err.message });
  }
});

app.get('/api/bmp/routes', async (req, res) => {
  try {
    res.json(await getBmpRoutes(req.query || {}));
  } catch (err) {
    res.status(bmpStatus(err)).json({ error: err.message });
  }
});

app.get('/api/bmp/events', async (req, res) => {
  try {
    res.json(await getBmpEvents(req.query || {}));
  } catch (err) {
    res.status(bmpStatus(err)).json({ error: err.message });
  }
});

app.get('/api/bmp/counts', async (req, res) => {
  try {
    res.json(await getBmpCounts(req.query || {}));
  } catch (err) {
    res.status(bmpStatus(err)).json({ error: err.message });
  }
});

app.get('/api/bmp/churn', async (req, res) => {
  try {
    res.json(await getBmpChurn(req.query || {}));
  } catch (err) {
    res.status(bmpStatus(err)).json({ error: err.message });
  }
});

app.get('/api/bmp/flap', async (req, res) => {
  try {
    res.json(await getBmpFlap(req.query || {}));
  } catch (err) {
    res.status(bmpStatus(err)).json({ error: err.message });
  }
});

app.post('/api/refs/l3-prefixes', async (req, res) => {
  try {
    const { elapsedMs } = await saveL3Prefix(req.body || {});
    res.json({ ok: true, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/dns-resolvers', async (req, res) => {
  try {
    const { elapsedMs } = await saveDnsResolver(req.body || {});
    res.json({ ok: true, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/l3-prefixes/toggle', async (req, res) => {
  try {
    const { elapsedMs, enabled } = await setL3PrefixEnabled(req.body || {});
    res.json({ ok: true, enabled, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/dns-resolvers/toggle', async (req, res) => {
  try {
    const { elapsedMs, enabled } = await setDnsResolverEnabled(req.body || {});
    res.json({ ok: true, enabled, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.delete('/api/refs/l3-prefixes', async (req, res) => {
  try {
    const { elapsedMs } = await deleteL3Prefix(req.body || {});
    res.json({ ok: true, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.delete('/api/refs/dns-resolvers', async (req, res) => {
  try {
    const { elapsedMs } = await deleteDnsResolver(req.body || {});
    res.json({ ok: true, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/flow-exclusions', async (req, res) => {
  try {
    const { elapsedMs, ruleId } = await saveFlowExclusion(req.body || {});
    res.json({ ok: true, ruleId, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.post('/api/refs/flow-exclusions/toggle', async (req, res) => {
  try {
    const { elapsedMs, enabled } = await setFlowExclusionEnabled(req.body || {});
    res.json({ ok: true, enabled, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.delete('/api/refs/flow-exclusions', async (req, res) => {
  try {
    const { elapsedMs } = await deleteFlowExclusion(req.body || {});
    res.json({ ok: true, meta: { elapsedMs } });
  } catch (err) {
    const status = err.statusCode === 400 ? 400 : err.statusCode === 404 ? 404 : 502;
    res.status(status).json({ error: err.message });
  }
});

app.get('/runtime-config.js', (_req, res) => {
  const { verbose } = getLogConfig();
  const frontendMode = process.env.FRONTEND_MODE === 'bundled' ? 'bundled' : 'babel';
  res.type('application/javascript');
  res.set('Cache-Control', 'no-store');
  res.send(`window.__GRAPES_RUNTIME__=${JSON.stringify({
    verbose,
    dataTimezone: getConfig().dataTimezone || 'UTC',
    frontendMode,
  })};`);
});

app.use(express.static(path.join(__dirname, '..', 'public'), {
  setHeaders(res, filePath) {
    if (/\/dist\/[^/]+\.[a-f0-9]{8,}\./i.test(filePath)) {
      res.set('Cache-Control', 'max-age=31536000, immutable');
      return;
    }
    if (/\.(?:jsx?|css|html?)$/i.test(filePath)) {
      res.set('Cache-Control', 'no-cache');
    }
  },
}));

app.listen(PORT, () => {
  const buildInfoLine = formatBuildInfoLogLine(getBuildInfo());
  if (buildInfoLine) console.log(buildInfoLine);
  console.log(`Grapes NTA → http://localhost:${PORT}`);
  const { logSql } = getConfig();
  const { verbose } = getLogConfig();
  console.log(`ClickHouse SQL logging: ${logSql ? 'on' : 'off'} (CLICKHOUSE_LOG_SQL)`);
  console.log(`Verbose logging: ${verbose ? 'on' : 'off'} (LOG_VERBOSE)`);
  console.log(`Session cookie secure: ${SESSION_COOKIE_SECURE ? 'on' : 'off'} (SESSION_COOKIE_SECURE)`);
  ping(true).then((s) => {
    if (s.ok) {
      console.log(`ClickHouse ${s.version} @ ${getConfig().url}`);
      ensureUsersTable()
        .then(async (result) => {
          if (result.bootstrapped) {
            console.log('Users table initialized; default admin created.');
          } else {
            console.log('Users table ready.');
          }
          const rbac = await ensureRbac();
          if (rbac.rolesCreated) {
            console.log(`RBAC: created ${rbac.rolesCreated} standard role(s).`);
          }
          if (rbac.permissionsAdded) {
            console.log(`RBAC: synced ${rbac.permissionsAdded} permission row(s).`);
          }
          if (rbac.writePermissionsPatched) {
            console.log(`RBAC: patched ${rbac.writePermissionsPatched} write permission row(s).`);
          }
          if (rbac.clientPermissionsSynced) {
            console.log(`RBAC: synced ${rbac.clientPermissionsSynced} Client permission row(s).`);
          }
          console.log('RBAC ready.');
          await ensureImpersonationAuditTable();
          console.log('Cabinet impersonation audit ready.');
          await ensureObservationsStore();
          console.log('Observations store ready (ClickHouse).');
          ensureAnalysisSnapshotsStore();
          console.log('Analysis snapshots store ready (SQLite).');
        })
        .catch((err) => {
          console.error(`Users/RBAC/observations/cabinet initialization failed: ${err.message}`);
        });
    } else {
      console.warn(`ClickHouse недоступен: ${s.error}`);
      console.warn('UI покажет «Не удалось загрузить» до восстановления соединения.');
    }
  });
});
