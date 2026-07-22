const {
  config,
  query,
  insertRows,
  portServicesTableRef,
  portServicesViewRef,
} = require('./clickhouse');
const { DEFAULT_PORT_SERVICES } = require('./port-services-defaults');

const TRANSPORTS = new Set(['tcp', 'udp', 'sctp', 'icmp', 'icmpv6']);
const SERVICE_CODE_RE = /^[a-z0-9_]+$/;
const MIN_PORT = 0;
const MAX_PORT = 65535;

function formatPortLabel(portFrom, portTo) {
  if (portFrom === portTo) return String(portFrom);
  return `${portFrom}-${portTo}`;
}

function chNowDateTime() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} `
    + `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function mapPortServiceRow(r) {
  const portFrom = Number(r.port_from);
  const portTo = Number(r.port_to);
  return {
    transport: String(r.transport ?? ''),
    portFrom,
    portTo,
    portLabel: String(r.port_label ?? formatPortLabel(portFrom, portTo)),
    serviceCode: String(r.service_code ?? ''),
    serviceName: String(r.service_name ?? ''),
    category: String(r.category ?? ''),
    description: String(r.description ?? ''),
    updatedAt: r.updated_at ?? null,
  };
}

function parsePortRange(body) {
  const portMode = String(body?.portMode ?? body?.port_mode ?? 'single').trim().toLowerCase();

  if (portMode === 'range') {
    const rawFrom = body?.portFrom ?? body?.port_from;
    const rawTo = body?.portTo ?? body?.port_to;
    if (rawFrom === undefined || rawFrom === null || String(rawFrom).trim() === ''
        || rawTo === undefined || rawTo === null || String(rawTo).trim() === '') {
      return { ok: false, error: 'Укажите начало и конец диапазона' };
    }
    const portFrom = Number(rawFrom);
    const portTo = Number(rawTo);
    if (!Number.isInteger(portFrom) || portFrom < MIN_PORT || portFrom > MAX_PORT) {
      return { ok: false, error: 'Укажите начало диапазона в пределах 0–65535' };
    }
    if (!Number.isInteger(portTo) || portTo < MIN_PORT || portTo > MAX_PORT) {
      return { ok: false, error: 'Укажите конец диапазона в пределах 0–65535' };
    }
    if (portFrom > portTo) {
      return { ok: false, error: 'Начало диапазона не может быть больше конца' };
    }
    return { ok: true, portFrom, portTo };
  }

  const rawPort = body?.port ?? body?.portFrom ?? body?.port_from;
  if (rawPort === undefined || rawPort === null || String(rawPort).trim() === '') {
    return { ok: false, error: 'Укажите порт в диапазоне 0–65535' };
  }
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
    return { ok: false, error: 'Укажите порт в диапазоне 0–65535' };
  }
  return { ok: true, portFrom: port, portTo: port };
}

function parseOriginalKey(body) {
  const transport = String(body?.originalTransport ?? body?.original_transport ?? '').trim();
  const portFrom = body?.originalPortFrom ?? body?.original_port_from;
  const portTo = body?.originalPortTo ?? body?.original_port_to;
  if (!transport || portFrom === undefined || portTo === undefined) return null;
  return {
    transport,
    portFrom: Number(portFrom),
    portTo: Number(portTo),
  };
}

function keysEqual(a, b) {
  return a.transport === b.transport
    && a.portFrom === b.portFrom
    && a.portTo === b.portTo;
}

function validatePortServicePayload(body) {
  const transport = String(body?.transport ?? '').trim().toLowerCase();
  if (!TRANSPORTS.has(transport)) {
    return { ok: false, error: 'Выберите транспортный протокол' };
  }

  const ports = parsePortRange(body);
  if (!ports.ok) return ports;

  const serviceCode = String(body?.serviceCode ?? body?.service_code ?? '').trim().toLowerCase();
  if (!serviceCode) return { ok: false, error: 'Укажите код сервиса' };
  if (!SERVICE_CODE_RE.test(serviceCode)) {
    return { ok: false, error: 'Код сервиса: только латиница нижнего регистра, цифры и _' };
  }

  const serviceName = String(body?.serviceName ?? body?.service_name ?? '').trim();
  if (!serviceName) return { ok: false, error: 'Укажите название сервиса' };

  const category = String(body?.category ?? '').trim();
  if (!category) return { ok: false, error: 'Укажите категорию' };

  return {
    ok: true,
    record: {
      transport,
      port_from: ports.portFrom,
      port_to: ports.portTo,
      service_code: serviceCode,
      service_name: serviceName,
      category,
      description: String(body?.description ?? '').trim(),
    },
    portFrom: ports.portFrom,
    portTo: ports.portTo,
  };
}

async function findOverlappingRules(transport, portFrom, portTo, exclude = null) {
  const view = portServicesViewRef();
  const { rows } = await query(
    `
      SELECT
        transport,
        port_from,
        port_to,
        service_code,
        service_name,
        category
      FROM ${view}
      WHERE transport = {transport:String}
        AND port_from <= {port_to:UInt16}
        AND port_to >= {port_from:UInt16}
      ORDER BY port_from, port_to
    `,
    { transport, port_from: portFrom, port_to: portTo },
    { name: 'refs/port-services-overlap' },
  );

  if (!exclude) return rows;

  return rows.filter((r) => !(
    String(r.transport) === exclude.transport
    && Number(r.port_from) === exclude.portFrom
    && Number(r.port_to) === exclude.portTo
  ));
}

function formatOverlapError(row) {
  const portFrom = Number(row.port_from);
  const portTo = Number(row.port_to);
  const label = formatPortLabel(portFrom, portTo);
  const name = String(row.service_name ?? row.service_code ?? '');
  return `Диапазон пересекается с существующим правилом: ${row.transport}/${label} ${name}. Измените диапазон или отключите старое правило.`;
}

async function fetchActivePortService(key) {
  const view = portServicesViewRef();
  const { rows } = await query(
    `
      SELECT
        transport,
        port_from,
        port_to,
        service_code,
        service_name,
        category,
        description
      FROM ${view}
      WHERE transport = {transport:String}
        AND port_from = {port_from:UInt16}
        AND port_to = {port_to:UInt16}
      LIMIT 1
    `,
    {
      transport: key.transport,
      port_from: key.portFrom,
      port_to: key.portTo,
    },
    { name: 'refs/port-services-get' },
  );
  return rows[0] ?? null;
}

function listPortServices(filters = {}) {
  const view = portServicesViewRef();
  const conditions = [];
  const params = {};

  const search = String(filters.search ?? '').trim();
  if (search) {
    conditions.push(`(
      positionCaseInsensitive(service_code, {search:String}) > 0
      OR positionCaseInsensitive(service_name, {search:String}) > 0
      OR positionCaseInsensitive(category, {search:String}) > 0
      OR toString(port_from) = {search:String}
      OR toString(port_to) = {search:String}
    )`);
    params.search = search;
  }

  const transport = String(filters.transport ?? '').trim().toLowerCase();
  if (transport && TRANSPORTS.has(transport)) {
    conditions.push('transport = {transportFilter:String}');
    params.transportFilter = transport;
  }

  const category = String(filters.category ?? '').trim();
  if (category) {
    conditions.push('category = {categoryFilter:String}');
    params.categoryFilter = category;
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = search ? 'LIMIT 200' : '';

  return {
    sql: `
      SELECT
        transport,
        port_from,
        port_to,
        if(port_from = port_to, toString(port_from), concat(toString(port_from), '-', toString(port_to))) AS port_label,
        service_code,
        service_name,
        category,
        description,
        updated_at
      FROM ${view}
      ${where}
      ORDER BY transport, port_from, port_to
      ${limit}
    `,
    params,
    map(rows) {
      return rows.map(mapPortServiceRow);
    },
  };
}

async function insertPortServiceRecord(record, isEnabled) {
  const row = {
    ...record,
    is_enabled: isEnabled ? 1 : 0,
    updated_at: chNowDateTime(),
  };
  return insertRows(config.portServicesTable, [row], {
    name: isEnabled ? 'refs/port-services-insert' : 'refs/port-services-disable',
  });
}

function recordFromExisting(existing) {
  return {
    transport: String(existing.transport),
    port_from: Number(existing.port_from),
    port_to: Number(existing.port_to),
    service_code: String(existing.service_code),
    service_name: String(existing.service_name),
    category: String(existing.category),
    description: String(existing.description ?? ''),
  };
}

async function savePortService(body) {
  const original = parseOriginalKey(body);
  const isNew = !original;

  const validation = validatePortServicePayload(body);
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  const { record, portFrom, portTo } = validation;
  const keyChanged = original && !keysEqual(original, { transport: record.transport, portFrom, portTo });

  if (!isNew && keyChanged) {
    const existing = await fetchActivePortService(original);
    if (!existing) {
      const err = new Error('Запись не найдена или уже отключена');
      err.statusCode = 404;
      throw err;
    }
    await insertPortServiceRecord(recordFromExisting(existing), false);
  } else if (!isNew && !keyChanged) {
    const existing = await fetchActivePortService(original);
    if (!existing) {
      const err = new Error('Запись не найдена или уже отключена');
      err.statusCode = 404;
      throw err;
    }
  }

  const overlaps = await findOverlappingRules(
    record.transport,
    portFrom,
    portTo,
    isNew || keyChanged ? null : original,
  );
  if (overlaps.length > 0) {
    const err = new Error(formatOverlapError(overlaps[0]));
    err.statusCode = 400;
    throw err;
  }

  const { elapsedMs } = await insertPortServiceRecord(record, true);

  return { elapsedMs, transport: record.transport, portFrom, portTo };
}

async function disablePortService(body) {
  const transport = String(body?.transport ?? '').trim().toLowerCase();
  const portFrom = Number(body?.portFrom ?? body?.port_from);
  const portTo = Number(body?.portTo ?? body?.port_to);

  if (!TRANSPORTS.has(transport)) {
    const err = new Error('Не указан транспорт');
    err.statusCode = 400;
    throw err;
  }
  if (!Number.isInteger(portFrom) || !Number.isInteger(portTo)) {
    const err = new Error('Не указан диапазон портов');
    err.statusCode = 400;
    throw err;
  }

  const existing = await fetchActivePortService({ transport, portFrom, portTo });
  if (!existing) {
    const err = new Error('Запись не найдена или уже отключена');
    err.statusCode = 404;
    throw err;
  }

  const { elapsedMs } = await insertPortServiceRecord(recordFromExisting(existing), false);

  return { elapsedMs, transport, portFrom, portTo };
}

function defaultKey(record) {
  return `${record.transport}:${record.port_from}:${record.port_to}`;
}

/** All known keys (enabled + disabled) — never re-insert these. */
async function fetchKnownPortServiceKeys() {
  const table = portServicesTableRef();
  const { rows } = await query(
    `
      SELECT
        transport,
        port_from,
        port_to,
        argMax(is_enabled, updated_at) AS enabled_latest
      FROM ${table}
      GROUP BY transport, port_from, port_to
    `,
    {},
    { name: 'refs/port-services-known-keys' },
  );
  const keys = new Map();
  for (const r of rows) {
    const key = `${r.transport}:${Number(r.port_from)}:${Number(r.port_to)}`;
    keys.set(key, Number(r.enabled_latest) === 1 ? 'enabled' : 'disabled');
  }
  return keys;
}

function summarizeDefault(record) {
  return {
    transport: record.transport,
    portFrom: record.port_from,
    portTo: record.port_to,
    portLabel: formatPortLabel(record.port_from, record.port_to),
    serviceCode: record.service_code,
    serviceName: record.service_name,
    category: record.category,
  };
}

async function fetchActivePortServiceRules() {
  const view = portServicesViewRef();
  const { rows } = await query(
    `
      SELECT transport, port_from, port_to, service_code, service_name
      FROM ${view}
      ORDER BY transport, port_from, port_to
    `,
    {},
    { name: 'refs/port-services-active-all' },
  );
  return rows.map((r) => ({
    transport: String(r.transport),
    portFrom: Number(r.port_from),
    portTo: Number(r.port_to),
    serviceCode: String(r.service_code ?? ''),
    serviceName: String(r.service_name ?? ''),
  }));
}

function findLocalOverlap(activeRules, transport, portFrom, portTo) {
  return activeRules.find((r) => (
    r.transport === transport
    && r.portFrom <= portTo
    && r.portTo >= portFrom
  )) || null;
}

/**
 * Preview which standard services can be added without touching user rules.
 * Skips exact keys (incl. disabled) and anything overlapping an active rule.
 */
async function previewSeedDefaults() {
  const [known, activeRules] = await Promise.all([
    fetchKnownPortServiceKeys(),
    fetchActivePortServiceRules(),
  ]);
  const toAdd = [];
  const skippedExisting = [];
  const skippedDisabled = [];
  const skippedOverlap = [];

  for (const record of DEFAULT_PORT_SERVICES) {
    const key = defaultKey(record);
    const status = known.get(key);
    if (status === 'enabled') {
      skippedExisting.push(summarizeDefault(record));
      continue;
    }
    if (status === 'disabled') {
      skippedDisabled.push(summarizeDefault(record));
      continue;
    }

    const overlap = findLocalOverlap(
      activeRules,
      record.transport,
      record.port_from,
      record.port_to,
    );
    if (overlap) {
      skippedOverlap.push({
        ...summarizeDefault(record),
        overlapsWith: formatPortLabel(overlap.portFrom, overlap.portTo),
        overlapsService: overlap.serviceName || overlap.serviceCode,
      });
      continue;
    }

    toAdd.push(summarizeDefault(record));
  }

  return {
    totalDefaults: DEFAULT_PORT_SERVICES.length,
    toAdd,
    skippedExisting,
    skippedDisabled,
    skippedOverlap,
    counts: {
      toAdd: toAdd.length,
      skippedExisting: skippedExisting.length,
      skippedDisabled: skippedDisabled.length,
      skippedOverlap: skippedOverlap.length,
    },
  };
}

async function seedDefaults() {
  const preview = await previewSeedDefaults();
  if (preview.toAdd.length === 0) {
    return {
      elapsedMs: 0,
      inserted: 0,
      ...preview.counts,
      message: 'Нечего добавлять: все стандартные сервисы уже есть или конфликтуют с вашими правилами.',
    };
  }

  const byKey = new Map(DEFAULT_PORT_SERVICES.map((r) => [defaultKey(r), r]));
  const rows = preview.toAdd.map((item) => {
    const record = byKey.get(`${item.transport}:${item.portFrom}:${item.portTo}`);
    return {
      ...record,
      is_enabled: 1,
      updated_at: chNowDateTime(),
    };
  });

  const { elapsedMs } = await insertRows(config.portServicesTable, rows, {
    name: 'refs/port-services-seed-defaults',
  });

  return {
    elapsedMs,
    inserted: rows.length,
    ...preview.counts,
    message: `Добавлено ${rows.length} стандартных сервисов. Существующие правила не изменены.`,
  };
}

module.exports = {
  TRANSPORTS,
  listPortServices,
  validatePortServicePayload,
  savePortService,
  disablePortService,
  previewSeedDefaults,
  seedDefaults,
  formatPortLabel,
};
