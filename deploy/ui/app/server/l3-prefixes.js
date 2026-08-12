const net = require('net');
const {
  config,
  query,
  insertRows,
  executeCommand,
  l3PrefixesTableRef,
  entitiesViewRef,
} = require('./clickhouse');

const ALLOWED_ROLES = new Set([
  'provider_public',
  'internal',
  'customer_allocated',
  'customer_transit',
  'remote',
]);

function mapPrefixRow(r) {
  const enabled = Number(r.enabled);
  return {
    prefix: String(r.prefix ?? ''),
    family: Number(r.family),
    entityId: String(r.entity_id ?? ''),
    entityName: String(r.entity_name ?? ''),
    role: String(r.role ?? ''),
    displayName: String(r.display_name ?? ''),
    comment: String(r.comment ?? ''),
    source: String(r.source ?? ''),
    enabled: enabled === 1 ? 1 : 0,
    updatedAt: r.updated_at ?? null,
  };
}

function mapEntityRow(r) {
  return {
    entityId: String(r.entity_id ?? ''),
    displayName: String(r.display_name ?? ''),
  };
}

function parseCidr(prefix) {
  const trimmed = String(prefix ?? '').trim();
  if (!trimmed) return { ok: false, error: 'Укажите префикс (CIDR)' };

  const slash = trimmed.indexOf('/');
  if (slash < 0) return { ok: false, error: 'Префикс должен быть в формате CIDR (например 10.0.0.0/8)' };

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

function parsePrefixKey(body) {
  const parsed = parseCidr(body?.prefix);
  if (!parsed.ok) return parsed;

  let family = Number(body?.family);
  if (!Number.isInteger(family) || (family !== 4 && family !== 6)) {
    family = parsed.family;
  }
  if (family !== parsed.family) {
    return { ok: false, error: 'Версия IP не соответствует адресу в префиксе' };
  }

  return { ok: true, prefix: parsed.prefix, family };
}

function latestPrefixesCte(prefixesTable, entitiesTable) {
  return `
    ranked AS (
      SELECT
        p.prefix,
        p.family,
        p.entity_id,
        e.display_name AS entity_name,
        p.role,
        p.display_name,
        p.comment,
        p.source,
        p.enabled,
        p.updated_at,
        row_number() OVER (
          PARTITION BY p.family, p.prefix
          ORDER BY p.updated_at DESC
        ) AS rn
      FROM ${prefixesTable} AS p
      LEFT JOIN ${entitiesTable} AS e
        ON p.entity_id = e.entity_id
    )
  `;
}

async function fetchEntityIds() {
  const entitiesTable = entitiesViewRef();
  const { rows } = await query(
    `
      SELECT entity_id
      FROM ${entitiesTable}
    `,
    {},
    { name: 'refs/entities-ids' },
  );
  return new Set(rows.map((r) => String(r.entity_id)));
}

async function fetchLatestL3Prefix(family, prefix) {
  const prefixesTable = l3PrefixesTableRef();
  const { rows } = await query(
    `
      SELECT
        prefix,
        family,
        entity_id,
        role,
        display_name,
        comment,
        source,
        enabled,
        updated_at
      FROM ${prefixesTable}
      WHERE family = {family:UInt8} AND prefix = {prefix:String}
      ORDER BY updated_at DESC
      LIMIT 1
    `,
    { family, prefix },
    { name: 'refs/l3-prefixes-latest' },
  );
  return rows[0] ? mapPrefixRow(rows[0]) : null;
}

function listL3Prefixes() {
  const prefixesTable = l3PrefixesTableRef();
  const entitiesTable = entitiesViewRef();

  return {
    sql: `
      WITH
        ${latestPrefixesCte(prefixesTable, entitiesTable)}
      SELECT
        prefix,
        family,
        entity_id,
        entity_name,
        role,
        display_name,
        comment,
        source,
        enabled,
        updated_at
      FROM ranked
      WHERE rn = 1
      ORDER BY
        family,
        prefix
    `,
    params: {},
    map(rows) {
      return rows.map(mapPrefixRow);
    },
  };
}

function listNetEntities() {
  const entitiesTable = entitiesViewRef();

  return {
    sql: `
      SELECT
        entity_id,
        display_name
      FROM ${entitiesTable}
      ORDER BY display_name
    `,
    params: {},
    map(rows) {
      return rows.map(mapEntityRow);
    },
  };
}

async function validateL3PrefixPayload(body, { requireActiveFields = true } = {}) {
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

  const entityId = String(body?.entityId ?? body?.entity_id ?? '').trim();
  const role = String(body?.role ?? '').trim();

  if (requireActiveFields && enabled === 1) {
    if (!entityId) return { ok: false, error: 'Выберите владельца сети' };
    if (!ALLOWED_ROLES.has(role)) {
      return { ok: false, error: 'Недопустимая роль сети' };
    }
    const entityIds = await fetchEntityIds();
    if (!entityIds.has(entityId)) {
      return { ok: false, error: 'Выбранный владелец не найден в справочнике объектов' };
    }
  }

  return {
    ok: true,
    record: {
      prefix: parsed.prefix,
      family,
      entity_id: entityId,
      role,
      display_name: String(body?.displayName ?? body?.display_name ?? '').trim(),
      comment: String(body?.comment ?? '').trim(),
      enabled,
      source: 'webui',
    },
  };
}

async function saveL3Prefix(body) {
  const validation = await validateL3PrefixPayload(body, { requireActiveFields: true });
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  const { record } = validation;
  const { elapsedMs } = await insertRows(config.l3PrefixesTable, [record], {
    name: 'refs/l3-prefixes-insert',
  });

  return { elapsedMs };
}

async function setL3PrefixEnabled(body) {
  const key = parsePrefixKey(body);
  if (!key.ok) {
    const err = new Error(key.error);
    err.statusCode = 400;
    throw err;
  }

  const latest = await fetchLatestL3Prefix(key.family, key.prefix);
  if (!latest) {
    const err = new Error('Префикс не найден');
    err.statusCode = 404;
    throw err;
  }

  let nextEnabled = Number(body?.enabled);
  if (nextEnabled !== 0 && nextEnabled !== 1) {
    nextEnabled = latest.enabled ? 0 : 1;
  }

  if (nextEnabled === 1) {
    if (!ALLOWED_ROLES.has(latest.role)) {
      const err = new Error('Сначала отредактируйте сеть и выберите допустимую роль');
      err.statusCode = 400;
      throw err;
    }
    const entityIds = await fetchEntityIds();
    if (!latest.entityId || !entityIds.has(latest.entityId)) {
      const err = new Error('Выберите действующего владельца сети перед включением');
      err.statusCode = 400;
      throw err;
    }
  }

  const record = {
    prefix: latest.prefix,
    family: latest.family,
    entity_id: latest.entityId,
    role: latest.role,
    display_name: latest.displayName,
    comment: latest.comment,
    enabled: nextEnabled,
    source: 'webui',
  };

  const { elapsedMs } = await insertRows(config.l3PrefixesTable, [record], {
    name: 'refs/l3-prefixes-toggle',
  });

  return { elapsedMs, enabled: nextEnabled };
}

async function deleteL3Prefix(body) {
  const key = parsePrefixKey(body);
  if (!key.ok) {
    const err = new Error(key.error);
    err.statusCode = 400;
    throw err;
  }

  const latest = await fetchLatestL3Prefix(key.family, key.prefix);
  if (!latest) {
    const err = new Error('Префикс не найден');
    err.statusCode = 404;
    throw err;
  }

  const table = l3PrefixesTableRef();
  const { elapsedMs } = await executeCommand(
    `DELETE FROM ${table} WHERE family = {family:UInt8} AND prefix = {prefix:String}`,
    { family: key.family, prefix: key.prefix },
    { name: 'refs/l3-prefixes-delete' },
  );

  return { elapsedMs };
}

module.exports = {
  ALLOWED_ROLES,
  listL3Prefixes,
  listNetEntities,
  saveL3Prefix,
  setL3PrefixEnabled,
  deleteL3Prefix,
  parseCidr,
  validateL3PrefixPayload,
};
