const {
  config,
  query,
  executeCommand,
} = require('./clickhouse');

const MIN_TTL_DAYS = 1;
const MAX_TTL_DAYS = 3650;
const ADMIN_ROLE_ID = 'Administrator';

function qIdent(name) {
  return `\`${String(name).replace(/`/g, '``')}\``;
}

function tableRef(tableName) {
  return `${qIdent(config.database)}.${qIdent(tableName)}`;
}

const TTL_CATALOG = [
  {
    id: 'flows_raw',
    label: 'Сырые потоки',
    table: () => config.flowsRawTable,
    ttlColumn: 'time_received_ns',
    defaultDays: 5,
    heavy: true,
  },
  {
    id: 'traffic_asn_1m',
    label: 'Топ ASN (минутные)',
    table: () => config.talkerTable,
    ttlColumn: 'minute',
    defaultDays: 2,
    heavy: false,
  },
  {
    id: 'traffic_asn_pair_1m',
    label: 'Топ ASN-пары (минутные)',
    table: () => config.pairTable,
    ttlColumn: 'minute',
    defaultDays: 2,
    heavy: false,
  },
  {
    id: 'traffic_asn_1h',
    label: 'Топ ASN (часовые)',
    table: () => config.talkerHourTable,
    ttlColumn: 'hour',
    defaultDays: 90,
    heavy: false,
  },
  {
    id: 'traffic_asn_pair_1h',
    label: 'Топ ASN-пары (часовые)',
    table: () => config.pairHourTable,
    ttlColumn: 'hour',
    defaultDays: 90,
    heavy: true,
  },
  {
    id: 'dns_log',
    label: 'DNS-запросы',
    table: () => config.dnsLogTable,
    ttlColumn: 'ts',
    defaultDays: 30,
    heavy: true,
  },
  {
    id: 'dns_answers',
    label: 'DNS-ответы',
    table: () => config.dnsAnswersTable,
    ttlColumn: 'ts',
    defaultDays: 30,
    heavy: false,
  },
  {
    id: 'bmp_route_events',
    label: 'BMP-события',
    table: () => config.bmpRouteEventsTable,
    ttlColumn: 'ts',
    defaultDays: 365,
    heavy: false,
  },
  {
    id: 'app_audit_log',
    label: 'Журнал аудита',
    table: () => 'app_audit_log',
    ttlColumn: 'event_at',
    defaultDays: 180,
    heavy: false,
  },
];

const catalogById = Object.fromEntries(TTL_CATALOG.map((entry) => [entry.id, entry]));

function parseTtlSpec(ddlText) {
  const text = String(ddlText ?? '');

  const patterns = [
    /TTL\s+(.+?)\s*\+\s*INTERVAL\s+(\d+)\s+DAY/i,
    /TTL\s+(.+?)\s*\+\s*toIntervalDay\((\d+)\)/i,
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (!match) continue;
    const exprBase = match[1].trim();
    const days = Number(match[2]);
    if (!exprBase || !Number.isFinite(days)) continue;
    return { exprBase, days };
  }

  return null;
}

function isWrappedExpr(exprBase) {
  return /^to(?:DateTime|Date|DateTime64)\(/i.test(String(exprBase ?? '').trim());
}

function extractBareColumn(exprBase) {
  const trimmed = String(exprBase ?? '').trim();
  if (!trimmed) return null;

  const wrapped = trimmed.match(/^to(?:DateTime|Date|DateTime64)\((.+)\)$/i);
  if (wrapped) return extractBareColumn(wrapped[1]);

  const backtick = trimmed.match(/^`([^`]+)`$/);
  if (backtick) return backtick[1];

  if (/^[\w.]+$/.test(trimmed)) return trimmed;
  return null;
}

function needsDateTimeWrap(columnType) {
  return /^DateTime64/i.test(String(columnType ?? ''));
}

function buildExprBaseForColumn(column, columnType) {
  const ident = qIdent(column);
  if (needsDateTimeWrap(columnType)) {
    return `toDateTime(${ident})`;
  }
  return ident;
}

function normalizeExprBase(exprBase, tableName, columnTypes) {
  if (isWrappedExpr(exprBase)) {
    return exprBase;
  }

  const bareCol = extractBareColumn(exprBase);
  if (!bareCol) return exprBase;

  const columnType = columnTypes[`${tableName}.${bareCol}`];
  if (needsDateTimeWrap(columnType)) {
    return buildExprBaseForColumn(bareCol, columnType);
  }

  return exprBase.includes('`') ? exprBase : qIdent(bareCol);
}

function resolveTtlExpr(meta, catalogColumn, defaultDays, tableName, columnTypes) {
  const parsed = parseTtlSpec(meta?.engine_full) || parseTtlSpec(meta?.create_table_query);

  if (parsed) {
    const exprBase = normalizeExprBase(parsed.exprBase, tableName, columnTypes);
    const column = extractBareColumn(parsed.exprBase) || catalogColumn;
    return {
      exprBase,
      column,
      days: parsed.days,
      fromDdl: true,
    };
  }

  const columnType = columnTypes[`${tableName}.${catalogColumn}`];
  return {
    exprBase: buildExprBaseForColumn(catalogColumn, columnType),
    column: catalogColumn,
    days: defaultDays,
    fromDdl: false,
  };
}

function buildTtlExpression(exprBase, days) {
  return `${exprBase} + INTERVAL ${days} DAY`;
}

function getCatalogEntry(id) {
  const entry = catalogById[String(id ?? '')];
  if (!entry) {
    const err = new Error('Неизвестная таблица TTL');
    err.statusCode = 404;
    throw err;
  }
  return entry;
}

function validateDays(days) {
  const value = Number(days);
  if (!Number.isInteger(value) || value < MIN_TTL_DAYS || value > MAX_TTL_DAYS) {
    const err = new Error(`Срок хранения должен быть целым числом от ${MIN_TTL_DAYS} до ${MAX_TTL_DAYS} дней`);
    err.statusCode = 400;
    throw err;
  }
  return value;
}

function assertAdministrator(roleId) {
  if (String(roleId ?? '') !== ADMIN_ROLE_ID) {
    const err = new Error('Изменение TTL доступно только администратору');
    err.statusCode = 403;
    throw err;
  }
}

async function fetchTableMeta(tableName) {
  const { rows } = await query(
    `
      SELECT name, engine_full, create_table_query, total_bytes, total_rows
      FROM system.tables
      WHERE database = {db:String} AND name = {table:String}
      LIMIT 1
    `,
    { db: config.database, table: tableName },
    { name: 'admin/ttl-table-meta' },
  );
  return rows[0] || null;
}

async function fetchColumnTypes(tableNames) {
  const uniqueTables = [...new Set(tableNames)];
  if (!uniqueTables.length) return {};

  const { rows } = await query(
    `
      SELECT table, name, type
      FROM system.columns
      WHERE database = {db:String}
        AND table IN {tables:Array(String)}
    `,
    { db: config.database, tables: uniqueTables },
    { name: 'admin/ttl-column-types' },
  );

  const map = {};
  for (const row of rows) {
    map[`${row.table}.${row.name}`] = String(row.type ?? '');
  }
  return map;
}

async function listTtlTables() {
  const tableNames = TTL_CATALOG.map((entry) => entry.table());
  const [tablesResult, columnTypes] = await Promise.all([
    query(
      `
        SELECT name, engine_full, create_table_query, total_bytes, total_rows
        FROM system.tables
        WHERE database = {db:String}
          AND name IN {tables:Array(String)}
      `,
      { db: config.database, tables: tableNames },
      { name: 'admin/ttl-list' },
    ),
    fetchColumnTypes(tableNames),
  ]);

  const { rows, elapsedMs } = tablesResult;
  const metaByName = Object.fromEntries(rows.map((row) => [String(row.name), row]));

  const data = TTL_CATALOG.map((entry) => {
    const table = entry.table();
    const meta = metaByName[table] || {};
    const resolved = resolveTtlExpr(meta, entry.ttlColumn, entry.defaultDays, table, columnTypes);
    const ttlExpression = buildTtlExpression(resolved.exprBase, resolved.days);

    return {
      id: entry.id,
      label: entry.label,
      table,
      ttlColumn: resolved.column,
      ttlDays: resolved.days,
      ttlExpression,
      defaultDays: entry.defaultDays,
      heavy: entry.heavy,
      totalBytes: Number(meta.total_bytes) || 0,
      totalRows: Number(meta.total_rows) || 0,
      found: Boolean(meta.name),
      ttlFromDdl: resolved.fromDdl,
    };
  });

  return { data, meta: { elapsedMs, rows: data.length } };
}

async function updateTtlTable(id, days, { roleId } = {}) {
  assertAdministrator(roleId);
  const entry = getCatalogEntry(id);
  const ttlDays = validateDays(days);
  const table = entry.table();

  const [meta, columnTypes] = await Promise.all([
    fetchTableMeta(table),
    fetchColumnTypes([table]),
  ]);

  if (!meta) {
    const err = new Error(`Таблица ${table} не найдена в ClickHouse`);
    err.statusCode = 404;
    throw err;
  }

  const resolved = resolveTtlExpr(meta, entry.ttlColumn, entry.defaultDays, table, columnTypes);
  const ttlExpr = buildTtlExpression(resolved.exprBase, ttlDays);

  const { elapsedMs } = await executeCommand(
    `ALTER TABLE ${tableRef(table)} MODIFY TTL ${ttlExpr}`,
    {},
    { name: 'admin/ttl-update' },
  );

  return {
    ok: true,
    id: entry.id,
    table,
    ttlColumn: resolved.column,
    ttlDays,
    ttlExpression: ttlExpr,
    meta: { elapsedMs },
  };
}

module.exports = {
  ADMIN_ROLE_ID,
  TTL_CATALOG,
  listTtlTables,
  updateTtlTable,
  parseTtlSpec,
  normalizeExprBase,
  buildExprBaseForColumn,
};
