const { CLIENT_API_ALLOWLIST } = require('./constants');
const {
  isCabinetScoped,
  resolveCabinetContext,
  clearImpersonation,
  cabinetPayload,
} = require('./context');
const { writeImpersonationEvent } = require('./impersonation-audit');
const { writeImpersonateAuditEvent } = require('../audit-log');

function requestApiPath(req) {
  // Middleware is mounted at /api, so Express strips that prefix from req.path.
  // Rebuild the full API path for allowlist matching.
  const base = String(req.baseUrl || '');
  const path = String(req.path || '');
  if (base || path) return `${base}${path}`;
  return String(req.originalUrl || '').split('?')[0];
}

/** POST endpoints that only read data (allowed in impersonation read-only mode). */
const CABINET_READONLY_POST_ALLOWLIST = [
  /^\/api\/cabinet\/explorer\/query$/,
  /^\/api\/cabinet\/explorer\/flows$/,
  /^\/api\/cabinet\/explorer\/export$/,
];

function pathAllowedForClient(path) {
  const p = String(path || '');
  return CLIENT_API_ALLOWLIST.some((re) => re.test(p));
}

function isReadOnlyCabinetPost(path) {
  const p = String(path || '');
  return CABINET_READONLY_POST_ALLOWLIST.some((re) => re.test(p));
}

function isMutatingMethod(method) {
  const m = String(method || 'GET').toUpperCase();
  return !(m === 'GET' || m === 'HEAD' || m === 'OPTIONS');
}

/**
 * Attach req.cabinet and enforce the client allowlist / impersonation read-only.
 * Must run after requireSession.
 */
function createCabinetGuard({ sessions }) {
  return async function cabinetIsolationGuard(req, res, next) {
    try {
      const sessionRecord = sessions.get(req.sessionId);
      let context = resolveCabinetContext(req.user, sessionRecord);

      if (context.impersonationExpired && sessionRecord) {
        const ended = clearImpersonation(sessionRecord, 'timeout');
        if (ended) {
          sessions.set(req.sessionId, sessionRecord);
          await writeImpersonationEvent({
            auditId: ended.auditId,
            event: 'end',
            actorUserId: req.user.id,
            actorUsername: req.user.username,
            clientId: ended.clientId,
            clientDisplayName: ended.clientDisplayName,
            reason: 'timeout',
          }).catch(() => {});
          req.sessionId = req.sessionId || '';
          await writeImpersonateAuditEvent(req, {
            kind: 'end',
            clientId: ended.clientId,
            clientDisplayName: ended.clientDisplayName,
            sessionId: req.sessionId,
            path: req.originalUrl?.split('?')[0] || '',
          }).catch(() => {});
        }
        context = resolveCabinetContext(req.user, sessionRecord);
      }

      req.cabinet = context;
      req.cabinetPayload = cabinetPayload(context);

      if (!isCabinetScoped(context)) {
        next();
        return;
      }

      if (!context.clientId) {
        res.status(403).json({ error: 'Кабинет недоступен: клиент не привязан к учётной записи' });
        return;
      }

      const apiPath = requestApiPath(req);
      if (!pathAllowedForClient(apiPath)) {
        res.status(403).json({ error: 'Недостаточно прав' });
        return;
      }

      if (context.mode === 'client'
        && req.method === 'POST'
        && /^\/api\/users\/[^/]+\/password$/.test(apiPath)) {
        const match = apiPath.match(/^\/api\/users\/([^/]+)\/password$/);
        const targetId = match ? decodeURIComponent(match[1]) : '';
        if (targetId !== req.user.id) {
          res.status(403).json({ error: 'Недостаточно прав' });
          return;
        }
      }

      if (context.readOnly && isMutatingMethod(req.method)) {
        const allowedWrite = apiPath === '/api/auth/stop-impersonation'
          || apiPath === '/api/auth/logout'
          || apiPath === '/api/audit/page'
          || isReadOnlyCabinetPost(apiPath);
        if (!allowedWrite) {
          res.status(403).json({ error: 'Режим просмотра кабинета: только чтение' });
          return;
        }
      }

      // Defense in depth: never trust a client_id coming from the request.
      if (req.query && Object.prototype.hasOwnProperty.call(req.query, 'client_id')) {
        delete req.query.client_id;
      }
      if (req.query && Object.prototype.hasOwnProperty.call(req.query, 'clientId')) {
        delete req.query.clientId;
      }
      if (req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
        if (Object.prototype.hasOwnProperty.call(req.body, 'client_id')) {
          delete req.body.client_id;
        }
        if (Object.prototype.hasOwnProperty.call(req.body, 'clientId')) {
          delete req.body.clientId;
        }
      }

      next();
    } catch (err) {
      res.status(502).json({ error: err.message });
    }
  };
}

module.exports = {
  requestApiPath,
  pathAllowedForClient,
  isReadOnlyCabinetPost,
  isMutatingMethod,
  createCabinetGuard,
};
