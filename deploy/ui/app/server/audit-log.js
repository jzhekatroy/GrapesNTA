const crypto = require('crypto');
const {
  config,
  query,
  insertRows,
  executeCommand,
} = require('./clickhouse');
const { getResourceForPath } = require('./rbac/api-map');
const { titlesMap } = require('./rbac/resources');

const TABLE = process.env.CLICKHOUSE_AUDIT_LOG_TABLE || 'app_audit_log';
const PAGE_VIEW_DEDUP_MS = 2000;

const WRITE_ACTIONS = new Set([
  'user_create',
  'user_update',
  'user_delete',
  'role_change',
  'permissions_change',
  'password_change',
  'impersonate_start',
  'impersonate_end',
  'api_write',
]);

const KIND_ACTIONS = {
  login: ['login'],
  login_fail: ['login_fail'],
  logout: ['logout'],
  page: ['page_view'],
  write: [...WRITE_ACTIONS],
};

const recentPageViews = new Map();

function tableRef() {
  return `${config.database}.${TABLE}`;
}

function clickhouseDateTime(date = new Date()) {
  return date.toISOString().replace('T', ' ').replace('Z', '');
}

function parseClickHouseDateTime(value) {
  if (value == null || value === '') return null;
  const text = String(value).trim();
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(text)) return text;
  const d = value instanceof Date ? value : new Date(text);
  if (Number.isNaN(d.getTime())) return null;
  return clickhouseDateTime(d);
}

function sanitizeDetail(value) {
  if (value == null || value === '') return '';
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (/password|authorization|cookie|token/i.test(text)) return '';
  return text.slice(0, 2000);
}

function auditContextFromReq(req, sessionId = '') {
  return {
    ip: String(req.ip || ''),
    userAgent: String(req.headers?.['user-agent'] || ''),
    sessionId: String(sessionId || ''),
    actorUserId: String(req.user?.id || ''),
    actorUsername: String(req.user?.username || ''),
    actorRole: String(req.user?.roleId || ''),
  };
}

function shouldSkipPageView(sessionId, pageId) {
  const key = `${sessionId || ''}:${pageId || ''}`;
  const now = Date.now();
  const prev = recentPageViews.get(key);
  if (prev && now - prev < PAGE_VIEW_DEDUP_MS) return true;
  recentPageViews.set(key, now);
  if (recentPageViews.size > 5000) {
    for (const [k, ts] of recentPageViews) {
      if (now - ts > PAGE_VIEW_DEDUP_MS * 2) recentPageViews.delete(k);
    }
  }
  return false;
}

async function ensureAuditLogTable() {
  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${tableRef()}
      (
        id String,
        event_at DateTime64(3) DEFAULT now64(3),
        actor_user_id String DEFAULT '',
        actor_username String DEFAULT '',
        actor_role String DEFAULT '',
        ip String DEFAULT '',
        user_agent String DEFAULT '',
        action LowCardinality(String) DEFAULT '',
        resource String DEFAULT '',
        method String DEFAULT '',
        path String DEFAULT '',
        object_id String DEFAULT '',
        object_label String DEFAULT '',
        result LowCardinality(String) DEFAULT 'ok',
        detail String DEFAULT '',
        session_id String DEFAULT ''
      )
      ENGINE = MergeTree
      ORDER BY (event_at, id)
      TTL toDateTime(event_at) + INTERVAL 180 DAY
    `,
    {},
    { name: 'audit/create-audit-log' },
  );
}

async function writeAuditEvent({
  actorUserId = '',
  actorUsername = '',
  actorRole = '',
  ip = '',
  userAgent = '',
  action = '',
  resource = '',
  method = '',
  path = '',
  objectId = '',
  objectLabel = '',
  result = 'ok',
  detail = '',
  sessionId = '',
  eventAt,
} = {}) {
  const row = {
    id: crypto.randomUUID(),
    event_at: eventAt ? clickhouseDateTime(new Date(eventAt)) : clickhouseDateTime(),
    actor_user_id: String(actorUserId || ''),
    actor_username: String(actorUsername || ''),
    actor_role: String(actorRole || ''),
    ip: String(ip || ''),
    user_agent: String(userAgent || ''),
    action: String(action || ''),
    resource: String(resource || ''),
    method: String(method || ''),
    path: String(path || ''),
    object_id: String(objectId || ''),
    object_label: String(objectLabel || ''),
    result: String(result || 'ok'),
    detail: sanitizeDetail(detail),
    session_id: String(sessionId || ''),
  };
  await insertRows(TABLE, [row], { name: 'audit/write' });
  return { id: row.id, eventAt: row.event_at };
}

function resolveWriteAction(method, apiPath) {
  const m = String(method || 'GET').toUpperCase();
  const p = String(apiPath || '');

  if (p === '/api/users' && m === 'POST') return 'user_create';
  if (/^\/api\/users\/[^/]+$/.test(p) && m === 'PUT') return 'user_update';
  if (/^\/api\/users\/[^/]+$/.test(p) && m === 'DELETE') return 'user_delete';
  if (/^\/api\/users\/[^/]+\/password$/.test(p) && m === 'POST') return 'password_change';
  if (/^\/api\/rbac\/users\/[^/]+\/role$/.test(p) && m === 'PUT') return 'role_change';
  if (/^\/api\/rbac\/users\/[^/]+\/permissions$/.test(p) && m === 'PUT') return 'permissions_change';
  if (/^\/api\/rbac\/roles$/.test(p) && m === 'POST') return 'role_change';
  if (/^\/api\/rbac\/roles\/[^/]+$/.test(p) && (m === 'PUT' || m === 'DELETE')) return 'role_change';

  return 'api_write';
}

function resolveObjectFromPath(apiPath, method) {
  const p = String(apiPath || '');
  const m = String(method || 'GET').toUpperCase();

  let match = p.match(/^\/api\/users\/([^/]+)/);
  if (match) return { objectId: decodeURIComponent(match[1]), objectLabel: '' };

  match = p.match(/^\/api\/clients\/([^/]+)/);
  if (match) return { objectId: decodeURIComponent(match[1]), objectLabel: '' };

  match = p.match(/^\/api\/rbac\/roles\/([^/]+)/);
  if (match) return { objectId: decodeURIComponent(match[1]), objectLabel: '' };

  match = p.match(/^\/api\/refs\/([^/?]+)/);
  if (match) return { objectId: '', objectLabel: match[1] };

  if (p.startsWith('/api/observations')) {
    match = p.match(/^\/api\/observations\/([^/]+)/);
    return { objectId: match ? decodeURIComponent(match[1]) : '', objectLabel: 'Наблюдение' };
  }

  return { objectId: '', objectLabel: m === 'POST' ? p : '' };
}

function auditResultFromStatus(statusCode) {
  const code = Number(statusCode) || 0;
  if (code >= 200 && code < 300) return 'ok';
  if (code === 403) return 'denied';
  return 'fail';
}

function isAuditWriteExempt(apiPath) {
  const p = String(apiPath || '');
  if (p === '/api/health') return true;
  if (p.startsWith('/api/auth/')) return true;
  if (p === '/api/audit/page') return true;
  if (/^\/api\/users\/[^/]+\/password$/.test(p)) return true;
  if (/^\/api\/clients\/[^/]+\/impersonate$/.test(p)) return true;
  return false;
}

function shouldAuditMutatingRequest(method, apiPath) {
  const m = String(method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return false;
  if (isAuditWriteExempt(apiPath)) return false;
  return true;
}

async function writePageViewEvent(req, pageId, sessionId) {
  const pid = String(pageId || '').trim();
  if (!pid) return null;
  if (shouldSkipPageView(sessionId, pid)) return null;

  const titles = titlesMap();
  const label = titles[pid]?.title || pid;
  const ctx = auditContextFromReq(req, sessionId);

  return writeAuditEvent({
    ...ctx,
    action: 'page_view',
    resource: pid,
    method: 'POST',
    path: '/api/audit/page',
    objectId: pid,
    objectLabel: label,
    result: 'ok',
  });
}

async function writeImpersonateAuditEvent(req, {
  kind,
  clientId,
  clientDisplayName,
  sessionId,
  path = '',
} = {}) {
  const ctx = auditContextFromReq(req, sessionId);
  const action = kind === 'start' ? 'impersonate_start' : 'impersonate_end';
  return writeAuditEvent({
    ...ctx,
    action,
    resource: 'clients',
    method: 'POST',
    path: path || (kind === 'start'
      ? `/api/clients/${encodeURIComponent(clientId)}/impersonate`
      : '/api/auth/stop-impersonation'),
    objectId: String(clientId || ''),
    objectLabel: String(clientDisplayName || clientId || ''),
    result: 'ok',
  });
}

function createAuditMiddleware() {
  return (req, res, next) => {
    const apiPath = `/api${req.path || ''}`;
    if (!shouldAuditMutatingRequest(req.method, apiPath)) return next();

    res.on('finish', () => {
      writeMutatingAuditEvent(req, res, req.sessionId).catch(() => {});
    });
    next();
  };
}

async function writeMutatingAuditEvent(req, res, sessionId) {
  const apiPath = `/api${req.path || ''}`;
  if (!shouldAuditMutatingRequest(req.method, apiPath)) return null;

  const action = resolveWriteAction(req.method, apiPath);
  const resource = getResourceForPath(apiPath, req.method) || '';
  const { objectId, objectLabel } = resolveObjectFromPath(apiPath, req.method);
  const ctx = auditContextFromReq(req, sessionId);
  const result = auditResultFromStatus(res.statusCode);

  return writeAuditEvent({
    ...ctx,
    action,
    resource,
    method: String(req.method || '').toUpperCase(),
    path: apiPath,
    objectId,
    objectLabel,
    result,
  });
}

function buildKindFilter(kind) {
  const k = String(kind || '').trim();
  if (!k || k === 'all') return null;
  const actions = KIND_ACTIONS[k];
  if (!actions) return null;
  return actions;
}

function buildListSql(filters) {
  const conditions = ['1 = 1'];
  const params = {};

  if (filters.from) {
    const from = parseClickHouseDateTime(filters.from);
    if (from) {
      conditions.push('event_at >= {from:DateTime64(3)}');
      params.from = from;
    }
  }
  if (filters.to) {
    const to = parseClickHouseDateTime(filters.to);
    if (to) {
      conditions.push('event_at <= {to:DateTime64(3)}');
      params.to = to;
    }
  }
  if (filters.q) {
    conditions.push('(positionCaseInsensitive(actor_username, {q:String}) > 0 OR positionCaseInsensitive(object_label, {q:String}) > 0)');
    params.q = filters.q;
  }
  if (filters.ip) {
    conditions.push('startsWith(ip, {ip:String})');
    params.ip = filters.ip;
  }
  const kindActions = buildKindFilter(filters.kind);
  if (kindActions?.length) {
    conditions.push('action IN {actions:Array(String)}');
    params.actions = kindActions;
  }
  if (filters.result && filters.result !== 'all') {
    conditions.push('result = {result:String}');
    params.result = filters.result;
  }

  const where = conditions.join(' AND ');
  return { where, params };
}

function mapAuditRow(r) {
  return {
    id: String(r.id),
    eventAt: r.event_at,
    actorUserId: String(r.actor_user_id || ''),
    actorUsername: String(r.actor_username || ''),
    actorRole: String(r.actor_role || ''),
    ip: String(r.ip || ''),
    userAgent: String(r.user_agent || ''),
    action: String(r.action || ''),
    resource: String(r.resource || ''),
    method: String(r.method || ''),
    path: String(r.path || ''),
    objectId: String(r.object_id || ''),
    objectLabel: String(r.object_label || ''),
    result: String(r.result || ''),
    detail: String(r.detail || ''),
  };
}

async function listAuditEvents({
  from,
  to,
  q,
  ip,
  kind,
  result,
  limit = 100,
  offset = 0,
} = {}) {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const safeOffset = Math.max(Number(offset) || 0, 0);
  const { where, params } = buildListSql({ from, to, q, ip, kind, result });

  const countResult = await query(
    `
      SELECT count() AS total
      FROM ${tableRef()}
      WHERE ${where}
    `,
    params,
    { name: 'audit/list-count' },
  );
  const total = Number(countResult.rows[0]?.total) || 0;

  const listParams = { ...params, limit: safeLimit, offset: safeOffset };
  const { rows, elapsedMs } = await query(
    `
      SELECT
        id,
        event_at,
        actor_user_id,
        actor_username,
        actor_role,
        ip,
        user_agent,
        action,
        resource,
        method,
        path,
        object_id,
        object_label,
        result,
        detail
      FROM ${tableRef()}
      WHERE ${where}
      ORDER BY event_at DESC
      LIMIT {limit:UInt32}
      OFFSET {offset:UInt32}
    `,
    listParams,
    { name: 'audit/list' },
  );

  return {
    data: rows.map(mapAuditRow),
    meta: { total, limit: safeLimit, offset: safeOffset, elapsedMs },
  };
}

module.exports = {
  ensureAuditLogTable,
  writeAuditEvent,
  writePageViewEvent,
  writeImpersonateAuditEvent,
  writeMutatingAuditEvent,
  createAuditMiddleware,
  listAuditEvents,
  auditContextFromReq,
  auditResultFromStatus,
  shouldSkipPageView,
  sanitizeDetail,
  shouldAuditMutatingRequest,
  isAuditWriteExempt,
  resolveWriteAction,
  parseClickHouseDateTime,
};
