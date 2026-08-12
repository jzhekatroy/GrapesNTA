const {
  CLIENT_ROLE_ID,
  IMPERSONATION_TTL_MS,
} = require('./constants');

function isClientRole(user) {
  return String(user?.roleId || '') === CLIENT_ROLE_ID;
}

function clearImpersonation(session, reason = 'stop') {
  if (!session?.impersonation) return null;
  const ended = { ...session.impersonation, endReason: reason };
  delete session.impersonation;
  return ended;
}

function getSessionRecord(sessions, sessionId) {
  if (!sessionId || !sessions) return null;
  return sessions.get(sessionId) || null;
}

/**
 * Resolve the effective cabinet context for a request.
 * Operator stays operator unless impersonating; Client always scopes to own clientId.
 */
function resolveCabinetContext(user, sessionRecord) {
  const now = Date.now();
  const impersonation = sessionRecord?.impersonation || null;

  if (impersonation) {
    if (Number(impersonation.expiresAt) > 0 && Number(impersonation.expiresAt) <= now) {
      return {
        mode: 'operator',
        clientId: null,
        clientDisplayName: null,
        readOnly: false,
        impersonation: null,
        impersonationExpired: impersonation,
      };
    }
    return {
      mode: 'impersonation',
      clientId: String(impersonation.clientId || ''),
      clientDisplayName: String(impersonation.clientDisplayName || impersonation.clientId || ''),
      readOnly: true,
      impersonation: {
        clientId: String(impersonation.clientId || ''),
        clientDisplayName: String(impersonation.clientDisplayName || ''),
        startedAt: impersonation.startedAt || null,
        expiresAt: impersonation.expiresAt || null,
        auditId: impersonation.auditId || null,
      },
      impersonationExpired: null,
    };
  }

  if (isClientRole(user)) {
    const clientId = String(user.clientId || '').trim();
    return {
      mode: 'client',
      clientId: clientId || null,
      // Left empty on purpose: the session only knows the id, and the readable
      // name lives in the catalog. Falling back to the id here would look like
      // a resolved name and stop anyone from looking it up.
      clientDisplayName: String(user.clientDisplayName || ''),
      readOnly: false,
      impersonation: null,
      impersonationExpired: null,
    };
  }

  return {
    mode: 'operator',
    clientId: null,
    clientDisplayName: null,
    readOnly: false,
    impersonation: null,
    impersonationExpired: null,
  };
}

function isCabinetScoped(context) {
  return context?.mode === 'client' || context?.mode === 'impersonation';
}

function buildImpersonationSession({ clientId, clientDisplayName, auditId, now = Date.now() }) {
  return {
    clientId: String(clientId),
    clientDisplayName: String(clientDisplayName || clientId),
    auditId: String(auditId || ''),
    startedAt: now,
    expiresAt: now + IMPERSONATION_TTL_MS,
  };
}

function cabinetPayload(context) {
  return {
    mode: context.mode,
    clientId: context.clientId,
    clientDisplayName: context.clientDisplayName,
    readOnly: !!context.readOnly,
    impersonation: context.impersonation
      ? {
          clientId: context.impersonation.clientId,
          clientDisplayName: context.impersonation.clientDisplayName,
          startedAt: context.impersonation.startedAt,
          expiresAt: context.impersonation.expiresAt,
        }
      : null,
  };
}

/** Always take client id from context; ignore request params. */
function requireScopedClientId(context) {
  const clientId = String(context?.clientId || '').trim();
  if (!clientId) {
    const err = new Error('Кабинет недоступен: клиент не привязан к учётной записи');
    err.statusCode = 403;
    throw err;
  }
  return clientId;
}

module.exports = {
  isClientRole,
  clearImpersonation,
  getSessionRecord,
  resolveCabinetContext,
  isCabinetScoped,
  buildImpersonationSession,
  cabinetPayload,
  requireScopedClientId,
};
