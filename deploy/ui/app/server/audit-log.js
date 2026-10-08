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
  'password_reset',
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

const AUDIT_DETAIL_MAX_LEN = 8000;
const SENSITIVE_DETAIL_KEY = /^(password|passwordHash|password_hash|token|authorization|cookie|secret)$/i;

function sanitizeDetail(value) {
  if (value == null || value === '') return '';
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (text.startsWith('{') || text.startsWith('[')) {
    return text.slice(0, AUDIT_DETAIL_MAX_LEN);
  }
  if (/password|authorization|cookie|token/i.test(text)) return '';
  return text.slice(0, 2000);
}

function redactAuditPayload(value, depth = 0) {
  if (depth > 10) return '[…]';
  if (value == null || typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    return value.map((item) => redactAuditPayload(item, depth + 1));
  }
  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (SENSITIVE_DETAIL_KEY.test(key)) {
      out[key] = '[скрыто]';
    } else {
      out[key] = redactAuditPayload(val, depth + 1);
    }
  }
  return out;
}

function formatAuditDisplayValue(value) {
  if (value === true) return 'да';
  if (value === false) return 'нет';
  if (value == null || value === '') return '—';
  return String(value);
}

function pickBodyField(body, ...keys) {
  if (!body || typeof body !== 'object') return undefined;
  for (const key of keys) {
    if (body[key] !== undefined) return body[key];
  }
  return undefined;
}

function pushChange(changes, { field, label, from, to }) {
  const fromText = formatAuditDisplayValue(from);
  const toText = formatAuditDisplayValue(to);
  if (fromText === toText) return;
  changes.push({ field, label, from: fromText, to: toText });
}

function diffUserSnapshot(snapshot, body, changes) {
  if (!snapshot || !body) return;
  const pairs = [
    ['fullName', ['fullName', 'full_name'], 'ФИО'],
    ['roleId', ['roleId', 'role_id'], 'Роль'],
    ['active', ['active', 'is_active'], 'Активен'],
    ['clientId', ['clientId', 'client_id'], 'Клиент'],
  ];
  for (const [snapKey, bodyKeys, label] of pairs) {
    const next = pickBodyField(body, ...bodyKeys);
    if (next === undefined) continue;
    pushChange(changes, {
      field: snapKey,
      label,
      from: snapshot[snapKey],
      to: next,
    });
  }
}

function diffOverrideMaps(beforeMap, body, changes, limit = 40) {
  const overrides = body?.overrides && typeof body.overrides === 'object'
    ? body.overrides
    : (body && typeof body === 'object' ? body : {});
  const keys = new Set([
    ...Object.keys(beforeMap || {}),
    ...Object.keys(overrides),
  ]);
  let added = 0;
  for (const resource of keys) {
    if (added >= limit) break;
    const from = beforeMap?.[resource] || 'INHERIT';
    const to = overrides[resource] !== undefined ? overrides[resource] : from;
    if (String(from) === String(to)) continue;
    pushChange(changes, {
      field: resource,
      label: `Право: ${resource}`,
      from,
      to,
    });
    added += 1;
  }
}

function diffRolePermissionsSnapshot(snapshot, body, changes, limit = 40) {
  if (!snapshot || !body) return;
  let added = 0;
  if (body.displayName !== undefined) {
    pushChange(changes, {
      field: 'displayName',
      label: 'Отображаемое имя роли',
      from: snapshot.displayName,
      to: body.displayName,
    });
  }
  const permSources = [
    { key: 'permissions', label: 'Доступ', map: snapshot.permissions },
    { key: 'writePermissions', label: 'Запись', map: snapshot.writePermissions },
  ];
  for (const { key, label, map } of permSources) {
    const patch = body[key];
    if (!patch || typeof patch !== 'object') continue;
    for (const [resource, nextVal] of Object.entries(patch)) {
      if (added >= limit) return;
      const prevVal = map?.[resource];
      if (prevVal === undefined && nextVal === undefined) continue;
      pushChange(changes, {
        field: `${key}.${resource}`,
        label: `${label}: ${resource}`,
        from: prevVal,
        to: nextVal,
      });
      added += 1;
    }
  }
}

function normalizeAuditApiPath(req) {
  const rawPath = String(req.path || '').trim();
  if (!rawPath) return '/api';
  if (rawPath === '/api' || rawPath.startsWith('/api/')) return rawPath;
  return rawPath.startsWith('/') ? `/api${rawPath}` : `/api/${rawPath}`;
}

function auditBoundaryLabel(value) {
  const map = {
    internal: 'Наша сторона',
    external: 'Внешняя',
    unknown: 'Не задана',
    '': '—',
  };
  return map[value] ?? formatAuditDisplayValue(value);
}

function auditEnabledLabel(value) {
  if (value === 1 || value === true || value === '1') return 'вкл';
  if (value === 0 || value === false || value === '0') return 'выкл';
  return formatAuditDisplayValue(value);
}

function auditPortTitle(switchIp, ifIndex, port) {
  const name = port?.ifName ? ` (${port.ifName})` : '';
  return `${switchIp}:${ifIndex}${name}`;
}

function diffDnsResolverSnapshot(snapshot, body, changes, { toggle = false } = {}) {
  if (!snapshot) return;
  const title = snapshot.displayName || snapshot.prefix || snapshot.resolverId || 'резолвер';
  if (toggle) {
    let nextEnabled = pickBodyField(body, 'enabled');
    if (nextEnabled !== 0 && nextEnabled !== 1) {
      nextEnabled = snapshot.enabled ? 0 : 1;
    }
    pushChange(changes, {
      field: 'enabled',
      label: `Резолвер ${title}`,
      from: auditEnabledLabel(snapshot.enabled),
      to: auditEnabledLabel(nextEnabled),
    });
    return;
  }

  const prefix = pickBodyField(body, 'prefix');
  if (prefix !== undefined) {
    pushChange(changes, {
      field: 'prefix',
      label: `${title}: префикс`,
      from: snapshot.prefix,
      to: prefix,
    });
  }
  const role = pickBodyField(body, 'role');
  if (role !== undefined) {
    pushChange(changes, {
      field: 'role',
      label: `${title}: роль`,
      from: snapshot.role,
      to: role,
    });
  }
  const displayName = pickBodyField(body, 'displayName', 'display_name');
  if (displayName !== undefined) {
    pushChange(changes, {
      field: 'displayName',
      label: `${title}: имя`,
      from: snapshot.displayName,
      to: displayName,
    });
  }
  const nextEnabled = pickBodyField(body, 'enabled');
  if (nextEnabled !== undefined) {
    pushChange(changes, {
      field: 'enabled',
      label: `${title}: состояние`,
      from: auditEnabledLabel(snapshot.enabled),
      to: auditEnabledLabel(nextEnabled),
    });
  }
}

function auditSwitchTitle(switchIp, displayName) {
  const ip = String(switchIp || '').trim();
  const name = String(displayName || '').trim();
  return name ? `${ip} (${name})` : ip;
}

function diffInterfaceRoleSwitchVisibility(beforeState, changes, limit = 25) {
  const isHide = !!beforeState.isHide;
  const entries = beforeState.entries || [];
  let added = 0;
  for (const snap of entries) {
    if (added >= limit) break;
    const title = auditSwitchTitle(snap.switchIp, snap.displayName);
    pushChange(changes, {
      field: String(snap.switchIp || ''),
      label: `Коммутатор ${title}`,
      from: snap.hidden === 1 ? 'скрыт из списка' : 'в списке',
      to: isHide ? 'скрыт из списка' : 'в списке',
    });
    added += 1;
  }
}

function diffInterfaceRoleEntries(beforeState, body, changes, limit = 30) {
  const { parseInterfaceRoleEntries } = require('./net-interface-roles');
  const entries = parseInterfaceRoleEntries(body);
  const beforeMap = new Map(
    (beforeState.entries || []).map((entry) => [`${entry.switchIp}:${entry.ifIndex}`, entry]),
  );
  let added = 0;
  for (const entry of entries) {
    if (added >= limit) break;
    const switchIp = String(entry?.switchIp ?? entry?.switch_ip ?? '').trim();
    const ifIndex = Number(entry?.ifIndex ?? entry?.if_index);
    if (!switchIp || !Number.isInteger(ifIndex)) continue;
    const key = `${switchIp}:${ifIndex}`;
    const prev = beforeMap.get(key);
    const port = prev?.port;
    const title = auditPortTitle(switchIp, ifIndex, port);

    if (beforeState.isDelete) {
      pushChange(changes, {
        field: key,
        label: `Порт ${title}`,
        from: auditBoundaryLabel(port?.boundary),
        to: 'по правилу',
      });
      added += 1;
      continue;
    }

    const nextBoundary = entry?.boundary ?? body?.boundary;
    if (nextBoundary !== undefined && nextBoundary !== '') {
      pushChange(changes, {
        field: `${key}.boundary`,
        label: `Порт ${title}: сторона`,
        from: auditBoundaryLabel(port?.boundary),
        to: auditBoundaryLabel(nextBoundary),
      });
      added += 1;
    }

    const nextConnectivity = entry?.connectivity ?? body?.connectivity;
    if (nextConnectivity !== undefined && String(nextConnectivity) !== '') {
      pushChange(changes, {
        field: `${key}.connectivity`,
        label: `Порт ${title}: стык`,
        from: port?.connectivity || '—',
        to: nextConnectivity,
      });
      added += 1;
    }
  }
}

function recordDnsResolverCreate(body, changes) {
  const prefix = pickBodyField(body, 'prefix');
  const role = pickBodyField(body, 'role');
  const displayName = pickBodyField(body, 'displayName', 'display_name');
  if (prefix) pushChange(changes, { field: 'prefix', label: 'Резолвер: префикс', from: '—', to: prefix });
  if (role) pushChange(changes, { field: 'role', label: 'Резолвер: роль', from: '—', to: role });
  if (displayName) pushChange(changes, { field: 'displayName', label: 'Резолвер: имя', from: '—', to: displayName });
  const enabled = pickBodyField(body, 'enabled');
  if (enabled !== undefined) {
    pushChange(changes, { field: 'enabled', label: 'Резолвер: состояние', from: '—', to: auditEnabledLabel(enabled) });
  }
}

function shouldCaptureAuditBeforeState(method, apiPath) {
  const m = String(method || 'GET').toUpperCase();
  const p = String(apiPath || '');
  if (['PUT', 'PATCH', 'DELETE'].includes(m)) return true;
  if (m !== 'POST') return false;
  return p === '/api/refs/dns-resolvers/toggle'
    || p === '/api/refs/dns-resolvers'
    || p === '/api/refs/interface-roles'
    || p === '/api/refs/interface-roles/delete'
    || p === '/api/refs/interface-roles/switches/delete'
    || p === '/api/refs/interface-roles/switches/restore';
}

function recordUserCreateFields(body, changes) {
  const fields = [
    ['username', 'Логин'],
    ['fullName', 'ФИО'],
    ['roleId', 'Роль'],
    ['clientId', 'Клиент'],
  ];
  for (const [key, label] of fields) {
    const val = key === 'fullName'
      ? pickBodyField(body, 'fullName', 'full_name')
      : key === 'roleId'
        ? pickBodyField(body, 'roleId', 'role_id')
        : key === 'clientId'
          ? pickBodyField(body, 'clientId', 'client_id')
          : pickBodyField(body, key);
    if (val === undefined || val === '') continue;
    pushChange(changes, { field: key, label, from: '—', to: val });
  }
  const active = pickBodyField(body, 'active', 'is_active');
  if (active !== undefined) {
    pushChange(changes, { field: 'active', label: 'Активен', from: '—', to: active });
  }
}

async function captureAuditBeforeState(req, apiPath) {
  const method = String(req.method || 'GET').toUpperCase();
  if (!shouldCaptureAuditBeforeState(method, apiPath)) return null;

  try {
    if (apiPath === '/api/refs/dns-resolvers/toggle' && method === 'POST') {
      const { fetchLatestDnsResolver, parseResolverKey } = require('./dns-resolvers');
      const key = parseResolverKey(req.body || {});
      if (!key.ok) return null;
      const snapshot = await fetchLatestDnsResolver(key.resolverId);
      return snapshot ? { kind: 'dnsResolver', toggle: true, snapshot } : null;
    }

    if (apiPath === '/api/refs/dns-resolvers' && method === 'POST') {
      const { fetchLatestDnsResolver, parseResolverKey } = require('./dns-resolvers');
      const key = parseResolverKey(req.body || {});
      if (!key.ok) return null;
      const snapshot = await fetchLatestDnsResolver(key.resolverId);
      return snapshot ? { kind: 'dnsResolver', snapshot } : null;
    }

    if ((apiPath === '/api/refs/interface-roles' || apiPath === '/api/refs/interface-roles/delete')
      && method === 'POST') {
      const { parseInterfaceRoleEntries, fetchInterfacePortForAudit } = require('./net-interface-roles');
      const entries = parseInterfaceRoleEntries(req.body || {});
      const snapshots = [];
      for (const entry of entries.slice(0, 25)) {
        const switchIp = String(entry?.switchIp ?? entry?.switch_ip ?? '').trim();
        const ifIndex = Number(entry?.ifIndex ?? entry?.if_index);
        if (!switchIp || !Number.isInteger(ifIndex)) continue;
        const port = await fetchInterfacePortForAudit(switchIp, ifIndex);
        snapshots.push({ switchIp, ifIndex, port });
      }
      return {
        kind: 'interfaceRoles',
        isDelete: apiPath.endsWith('/delete'),
        entries: snapshots,
      };
    }

    if ((apiPath === '/api/refs/interface-roles/switches/delete'
      || apiPath === '/api/refs/interface-roles/switches/restore')
      && method === 'POST') {
      const { parseSwitchEntries, fetchInterfaceRoleSwitchForAudit } = require('./net-interface-roles');
      const entries = parseSwitchEntries(req.body || {});
      const snapshots = [];
      for (const entry of entries.slice(0, 25)) {
        const snap = await fetchInterfaceRoleSwitchForAudit(entry.switchIp);
        if (snap) snapshots.push(snap);
      }
      return {
        kind: 'interfaceRoleSwitchVisibility',
        isHide: apiPath.endsWith('/delete'),
        entries: snapshots,
      };
    }

    let match = apiPath.match(/^\/api\/users\/([^/]+)$/);
    if (match) {
      const { getUserById } = require('./users');
      const user = await getUserById(decodeURIComponent(match[1]));
      if (!user) return null;
      return {
        kind: 'user',
        snapshot: {
          fullName: user.fullName,
          roleId: user.roleId,
          active: user.active,
          clientId: user.clientId || '',
          username: user.username,
        },
      };
    }

    match = apiPath.match(/^\/api\/rbac\/users\/([^/]+)\/role$/);
    if (match) {
      const { getUserById } = require('./users');
      const user = await getUserById(decodeURIComponent(match[1]));
      if (!user) return null;
      return { kind: 'userRole', snapshot: { roleId: user.roleId } };
    }

    match = apiPath.match(/^\/api\/rbac\/users\/([^/]+)\/permissions$/);
    if (match) {
      const { loadUserOverrides } = require('./rbac/permissions');
      const overrides = await loadUserOverrides(decodeURIComponent(match[1]));
      return { kind: 'userPermissions', snapshot: { overrides } };
    }

    match = apiPath.match(/^\/api\/rbac\/roles\/([^/]+)$/);
    if (match) {
      const { getRoleWithPermissions } = require('./rbac/permissions');
      const role = await getRoleWithPermissions(decodeURIComponent(match[1]));
      if (!role) return null;
      return {
        kind: 'role',
        snapshot: {
          displayName: role.displayName,
          permissions: role.permissions,
          writePermissions: role.writePermissions,
        },
      };
    }
  } catch {
    return null;
  }
  return null;
}

function buildMutatingAuditDetail(req, apiPath, action, beforeState) {
  const method = String(req.method || 'GET').toUpperCase();
  const body = redactAuditPayload(req.body && typeof req.body === 'object' ? req.body : {});
  const request = {
    method,
    path: apiPath,
  };
  if (body && Object.keys(body).length) {
    request.body = body;
  }

  const changes = [];
  if (action === 'user_create' && method === 'POST') {
    recordUserCreateFields(body, changes);
  } else if (beforeState?.kind === 'user') {
    diffUserSnapshot(beforeState.snapshot, body, changes);
  } else if (beforeState?.kind === 'userRole') {
    const nextRole = pickBodyField(body, 'roleId', 'role_id');
    if (nextRole !== undefined) {
      pushChange(changes, {
        field: 'roleId',
        label: 'Роль',
        from: beforeState.snapshot.roleId,
        to: nextRole,
      });
    }
  } else if (beforeState?.kind === 'userPermissions') {
    diffOverrideMaps(beforeState.snapshot.overrides, body, changes);
  } else if (beforeState?.kind === 'role') {
    diffRolePermissionsSnapshot(beforeState.snapshot, body, changes);
  } else if (beforeState?.kind === 'dnsResolver') {
    diffDnsResolverSnapshot(beforeState.snapshot, body, changes, { toggle: !!beforeState.toggle });
  } else if (beforeState?.kind === 'interfaceRoles') {
    diffInterfaceRoleEntries(beforeState, body, changes);
  } else if (beforeState?.kind === 'interfaceRoleSwitchVisibility') {
    diffInterfaceRoleSwitchVisibility(beforeState, changes);
  } else if (apiPath === '/api/refs/dns-resolvers' && method === 'POST') {
    recordDnsResolverCreate(body, changes);
  }

  const payload = { request };
  if (changes.length) payload.changes = changes;
  return sanitizeDetail(payload);
}

function normalizeStoredIp(ip) {
  const s = String(ip || '').trim();
  if (!s) return '';
  if (s.toLowerCase().startsWith('::ffff:')) return s.slice(7);
  return s;
}

function isLoopbackIp(ip) {
  const s = String(ip || '').trim().toLowerCase();
  if (!s) return false;
  const bare = s.startsWith('::ffff:') ? s.slice(7) : s;
  return bare === '127.0.0.1' || s === '::1' || bare === 'localhost';
}

function firstForwardedClientIp(header) {
  if (header == null || header === '') return '';
  const parts = String(header).split(',').map((p) => p.trim()).filter(Boolean);
  for (const part of parts) {
    const normalized = normalizeStoredIp(part);
    if (normalized && !isLoopbackIp(part)) return normalized;
  }
  return '';
}

function resolveClientIpFromReq(req) {
  const peerIp = String(req.ip || req.socket?.remoteAddress || '').trim();
  if (isLoopbackIp(peerIp)) {
    const xReal = req.headers?.['x-real-ip'];
    if (xReal) {
      const fromReal = normalizeStoredIp(String(xReal).trim());
      if (fromReal) return fromReal;
    }
    const fromForwarded = firstForwardedClientIp(req.headers?.['x-forwarded-for']);
    if (fromForwarded) return fromForwarded;
  }
  return normalizeStoredIp(peerIp);
}

function auditIpFilterVariants(raw) {
  const s = String(raw || '').trim();
  if (!s) return [];
  const variants = new Set([s]);
  if (s.toLowerCase().startsWith('::ffff:')) {
    variants.add(s.slice(7));
  } else if (!s.includes(':')) {
    variants.add(`::ffff:${s}`);
  }
  return [...variants];
}

function auditContextFromReq(req, sessionId = '') {
  return {
    ip: resolveClientIpFromReq(req),
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
  if (/^\/api\/users\/[^/]+\/password-reset$/.test(p) && m === 'POST') return 'password_reset';
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

  if (p === '/api/refs/dns-resolvers/toggle') {
    return { objectId: '', objectLabel: 'DNS-резолвер' };
  }
  if (p === '/api/refs/dns-resolvers') {
    return { objectId: '', objectLabel: 'DNS-резолвер' };
  }
  if (p === '/api/refs/interface-roles/delete') {
    return { objectId: '', objectLabel: 'Порт оборудования' };
  }
  if (p === '/api/refs/interface-roles') {
    return { objectId: '', objectLabel: 'Порт оборудования' };
  }
  if (p === '/api/refs/interface-roles/rebuild') {
    return { objectId: '', objectLabel: 'Пересчёт портов' };
  }
  if (p === '/api/refs/interface-roles/switches/delete' || p === '/api/refs/interface-roles/switches/restore') {
    return { objectId: '', objectLabel: 'Коммутатор (порты оборудования)' };
  }

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
  if (/^\/api\/users\/[^/]+\/password-reset$/.test(p)) return true;
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
    const apiPath = normalizeAuditApiPath(req);
    if (!shouldAuditMutatingRequest(req.method, apiPath)) return next();

    const beforePromise = captureAuditBeforeState(req, apiPath);

    res.on('finish', () => {
      beforePromise
        .then((beforeState) => writeMutatingAuditEvent(req, res, req.sessionId, { beforeState }))
        .catch(() => writeMutatingAuditEvent(req, res, req.sessionId).catch(() => {}));
    });
    next();
  };
}

async function writeMutatingAuditEvent(req, res, sessionId, { beforeState } = {}) {
  const apiPath = normalizeAuditApiPath(req);
  if (!shouldAuditMutatingRequest(req.method, apiPath)) return null;

  const action = resolveWriteAction(req.method, apiPath);
  const resource = getResourceForPath(apiPath, req.method) || '';
  const { objectId, objectLabel } = resolveObjectFromPath(apiPath, req.method);
  const ctx = auditContextFromReq(req, sessionId);
  const result = auditResultFromStatus(res.statusCode);
  const detail = buildMutatingAuditDetail(req, apiPath, action, beforeState);

  return writeAuditEvent({
    ...ctx,
    action,
    resource,
    method: String(req.method || '').toUpperCase(),
    path: apiPath,
    objectId,
    objectLabel,
    result,
    detail,
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
  if (filters.pageId) {
    conditions.push('resource = {pageId:String}');
    params.pageId = String(filters.pageId);
  }
  if (filters.userId) {
    conditions.push('actor_user_id = {userId:String}');
    params.userId = String(filters.userId);
  }
  if (filters.ip) {
    const variants = auditIpFilterVariants(filters.ip);
    if (variants.length === 1) {
      conditions.push('startsWith(ip, {ip:String})');
      params.ip = variants[0];
    } else {
      conditions.push('(startsWith(ip, {ipA:String}) OR startsWith(ip, {ipB:String}))');
      params.ipA = variants[0];
      params.ipB = variants[1];
    }
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
  pageId,
  userId,
  kind,
  result,
  limit = 100,
  offset = 0,
} = {}) {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const safeOffset = Math.max(Number(offset) || 0, 0);
  const { where, params } = buildListSql({
    from, to, q, ip, pageId, userId, kind, result,
  });

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
  resolveClientIpFromReq,
  isLoopbackIp,
  normalizeStoredIp,
  auditIpFilterVariants,
  buildListSql,
  buildMutatingAuditDetail,
  redactAuditPayload,
  normalizeAuditApiPath,
  diffDnsResolverSnapshot,
  diffInterfaceRoleEntries,
};
