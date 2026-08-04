const net = require('net');
const {
  config,
  query,
  insertRows,
  executeCommand,
  dnsResolversTableRef,
} = require('./clickhouse');

const ALLOWED_ROLES = new Set(['resolver', 'client', 'public']);

const ROLE_LABELS = {
  resolver: 'Резолвер',
  client: 'Клиент',
  public: 'Публичный',
};

function mapResolverRow(r) {
  const enabled = Number(r.enabled);
  return {
    resolverId: String(r.resolver_id ?? ''),
    prefix: String(r.prefix ?? ''),
    family: Number(r.family),
    role: String(r.role ?? ''),
    displayName: String(r.display_name ?? ''),
    comment: String(r.comment ?? ''),
    source: String(r.source ?? ''),
    enabled: enabled === 1 ? 1 : 0,
    updatedAt: r.updated_at ?? null,
  };
}

function parseCidr(prefix) {
  const trimmed = String(prefix ?? '').trim();
  if (!trimmed) return { ok: false, error: 'Укажите префикс (CIDR)' };

  const slash = trimmed.indexOf('/');
  if (slash < 0) return { ok: false, error: 'Префикс должен быть в формате CIDR (например 8.8.8.8/32)' };

  const ipPart = trimmed.slice(0, slash);
  const maskPart = trimmed.slice(slash + 1);
  const mask = Number(maskPart);

  if (!/^\d+$/.test(maskPart) || !Number.isInteger(mask)) {
    return { ok: false, error: 'Некорректная длина маски в CIDR' };
  }

  const isV4 = net.isIPv4(ipPart);
  const isV6 = net.isIPv6(ipPart);

  if (isV4 && !isV6) {
    if (mask < 0 || mask > 32) return { ok: false, error: 'Для IPv4 маска должна быть от 0 до 32' };
    return { ok: true, prefix: `${ipPart}/${mask}`, family: 4 };
  }

  if (isV6) {
    if (mask < 0 || mask > 128) return { ok: false, error: 'Для IPv6 маска должна быть от 0 до 128' };
    return { ok: true, prefix: `${ipPart}/${mask}`, family: 6 };
  }

  return { ok: false, error: 'Некорректный IP-адрес в префиксе' };
}

function parseResolverKey(body) {
  const resolverId = String(body?.resolverId ?? body?.resolver_id ?? '').trim();
  if (!resolverId) return { ok: false, error: 'Не указан идентификатор резолвера' };
  return { ok: true, resolverId };
}

function latestResolversCte(resolversTable) {
  return `
    ranked AS (
      SELECT
        resolver_id,
        prefix,
        family,
        role,
        display_name,
        comment,
        source,
        enabled,
        updated_at,
        row_number() OVER (
          PARTITION BY resolver_id
          ORDER BY updated_at DESC
        ) AS rn
      FROM ${resolversTable}
    )
  `;
}

async function fetchLatestDnsResolver(resolverId) {
  const resolversTable = dnsResolversTableRef();
  const { rows } = await query(
    `
      SELECT
        resolver_id,
        prefix,
        family,
        role,
        display_name,
        comment,
        source,
        enabled,
        updated_at
      FROM ${resolversTable}
      WHERE resolver_id = {resolver_id:String}
      ORDER BY updated_at DESC
      LIMIT 1
    `,
    { resolver_id: resolverId },
    { name: 'refs/dns-resolvers-latest' },
  );
  return rows[0] ? mapResolverRow(rows[0]) : null;
}

function listDnsResolvers() {
  const resolversTable = dnsResolversTableRef();

  return {
    sql: `
      WITH
        ${latestResolversCte(resolversTable)}
      SELECT
        resolver_id,
        prefix,
        family,
        role,
        display_name,
        comment,
        source,
        enabled,
        updated_at
      FROM ranked
      WHERE rn = 1
      ORDER BY
        role,
        prefix
    `,
    params: {},
    map(rows) {
      return rows.map(mapResolverRow);
    },
  };
}

async function validateDnsResolverPayload(body, { requireActiveFields = true } = {}) {
  const parsed = parseCidr(body?.prefix);
  if (!parsed.ok) return parsed;

  let family = Number(body?.family);
  if (!Number.isInteger(family) || (family !== 4 && family !== 6)) {
    family = parsed.family;
  }

  if (family !== parsed.family) {
    return { ok: false, error: 'Версия IP не соответствует адресу в префиксе' };
  }

  let enabled = Number(body?.enabled);
  if (enabled !== 0 && enabled !== 1) enabled = 1;

  const role = String(body?.role ?? '').trim();
  const resolverId = String(body?.resolverId ?? body?.resolver_id ?? '').trim();

  if (!resolverId) {
    return { ok: false, error: 'Не указан идентификатор резолвера' };
  }

  if (requireActiveFields && enabled === 1) {
    if (!ALLOWED_ROLES.has(role)) {
      return { ok: false, error: 'Недопустимая роль резолвера' };
    }
  }

  return {
    ok: true,
    record: {
      resolver_id: resolverId,
      prefix: parsed.prefix,
      family,
      role,
      display_name: String(body?.displayName ?? body?.display_name ?? '').trim(),
      comment: String(body?.comment ?? '').trim(),
      enabled,
      source: 'webui',
    },
  };
}

async function saveDnsResolver(body) {
  const validation = await validateDnsResolverPayload(body, { requireActiveFields: true });
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  const { record } = validation;
  const { elapsedMs } = await insertRows(config.dnsResolversTable, [record], {
    name: 'refs/dns-resolvers-insert',
  });

  return { elapsedMs };
}

async function setDnsResolverEnabled(body) {
  const key = parseResolverKey(body);
  if (!key.ok) {
    const err = new Error(key.error);
    err.statusCode = 400;
    throw err;
  }

  const latest = await fetchLatestDnsResolver(key.resolverId);
  if (!latest) {
    const err = new Error('Резолвер не найден');
    err.statusCode = 404;
    throw err;
  }

  let nextEnabled = Number(body?.enabled);
  if (nextEnabled !== 0 && nextEnabled !== 1) {
    nextEnabled = latest.enabled ? 0 : 1;
  }

  if (nextEnabled === 1 && !ALLOWED_ROLES.has(latest.role)) {
    const err = new Error('Сначала отредактируйте резолвер и выберите допустимую роль');
    err.statusCode = 400;
    throw err;
  }

  const record = {
    resolver_id: latest.resolverId,
    prefix: latest.prefix,
    family: latest.family,
    role: latest.role,
    display_name: latest.displayName,
    comment: latest.comment,
    enabled: nextEnabled,
    source: 'webui',
  };

  const { elapsedMs } = await insertRows(config.dnsResolversTable, [record], {
    name: 'refs/dns-resolvers-toggle',
  });

  return { elapsedMs, enabled: nextEnabled };
}

async function deleteDnsResolver(body) {
  const key = parseResolverKey(body);
  if (!key.ok) {
    const err = new Error(key.error);
    err.statusCode = 400;
    throw err;
  }

  const latest = await fetchLatestDnsResolver(key.resolverId);
  if (!latest) {
    const err = new Error('Резолвер не найден');
    err.statusCode = 404;
    throw err;
  }

  const table = dnsResolversTableRef();
  const { elapsedMs } = await executeCommand(
    `DELETE FROM ${table} WHERE resolver_id = {resolver_id:String}`,
    { resolver_id: key.resolverId },
    { name: 'refs/dns-resolvers-delete' },
  );

  return { elapsedMs };
}

module.exports = {
  ALLOWED_ROLES,
  ROLE_LABELS,
  listDnsResolvers,
  saveDnsResolver,
  setDnsResolverEnabled,
  deleteDnsResolver,
  parseCidr,
  validateDnsResolverPayload,
};
