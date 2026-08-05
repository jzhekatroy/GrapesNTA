const {
  config,
  dnsLogTableRef,
  dnsResolversViewRef,
  l3PrefixesViewRef,
  sourcesTableRef,
} = require('./clickhouse');
const {
  buildRawDnsFilters,
  dnsIpExpr,
  clientIpFilterSql,
  serverIpFilterSql,
  appendSourceFilter,
  resolveDnsWindow,
  dnsBucketExpr,
  dnsBucketSeconds,
  dnsMeta,
  mapIpBadgeFields,
  dnsResolverLabelSql,
  formatRcodeHumanLabel,
  dnsSources,
} = require('./dns-queries');
const { parseCollectorScopes, mergeCollectorParams } = require('./queries');

const DNS_EXPLORER_MAX_RANGE_DAYS = 7;
const DNS_EXPLORER_DEFAULT_LIMIT = 50;
const DNS_EXPLORER_MAX_LIMIT = 200;

const METRICS = [
  { id: 'queries_per_sec', label: 'Запросы/с', kind: 'rate', event: 'queries' },
  { id: 'responses_per_sec', label: 'Все ответы/с', kind: 'rate', event: 'responses' },
  { id: 'nxdomain_per_sec', label: 'Домен не найден/с', kind: 'rate', event: 'nxdomain' },
  { id: 'servfail_per_sec', label: 'Ошибки DNS-сервера/с', kind: 'rate', event: 'servfail' },
  { id: 'queries_total', label: 'Всего запросов', kind: 'total', event: 'queries' },
  { id: 'responses_total', label: 'Всего ответов', kind: 'total', event: 'responses' },
];

const GROUP_BY = [
  { id: 'client_ip', label: 'IP источника', column: 'client_ip' },
  { id: 'query_name', label: 'Домен', column: 'query_name' },
  { id: 'server_ip', label: 'IP DNS-сервера', column: 'server_ip' },
  { id: 'qtype', label: 'Тип запроса', column: 'qtype' },
  { id: 'rcode', label: 'Результат ответа', column: 'rcode' },
];

const FIELDS = [
  { id: 'client_ip', label: 'IP источника', ops: ['eq', 'ne', 'in_cidr'] },
  { id: 'query_name', label: 'Домен', ops: ['eq', 'contains', 'not_contains'] },
  { id: 'server_ip', label: 'IP DNS-сервера', ops: ['eq', 'ne', 'in_cidr'] },
  { id: 'qtype', label: 'Тип запроса', ops: ['eq', 'ne', 'in'] },
  { id: 'rcode', label: 'Результат ответа', ops: ['eq', 'ne', 'in'] },
  { id: 'source_id', label: 'Источник/коллектор', ops: ['in'] },
];

const RCODE_VALUES = [
  { id: '0', label: 'Успешно', code: 0 },
  { id: '2', label: 'Ошибка DNS-сервера', code: 2 },
  { id: '3', label: 'Домен не найден', code: 3 },
  { id: 'other', label: 'Другой код', code: 'other' },
];

const METRIC_BY_ID = Object.fromEntries(METRICS.map((m) => [m.id, m]));
const GROUP_BY_ID = Object.fromEntries(GROUP_BY.map((g) => [g.id, g]));
const FIELD_BY_ID = Object.fromEntries(FIELDS.map((f) => [f.id, f]));

function dnsExplorerSchema() {
  return {
    metrics: METRICS,
    groupBy: GROUP_BY,
    fields: FIELDS,
    rcodeValues: RCODE_VALUES,
  };
}

function validateDnsExplorerWindow({ range = '24h', from, to } = {}) {
  if (range === 'custom') {
    if (!from || !to) throw new Error('Для своего периода нужны параметры from и to');
    const start = new Date(from).getTime();
    const end = new Date(to).getTime();
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
      throw new Error('Некорректный пользовательский период');
    }
    const days = (end - start) / (24 * 60 * 60 * 1000);
    if (days > DNS_EXPLORER_MAX_RANGE_DAYS) {
      throw new Error(`Период не может превышать ${DNS_EXPLORER_MAX_RANGE_DAYS} дней (retention dns_log)`);
    }
    return;
  }
  const blocked = new Set(['30d', '60d', '90d']);
  if (blocked.has(range)) {
    throw new Error(`Период «${range}» недоступен для разбора DNS. Выберите период до ${DNS_EXPLORER_MAX_RANGE_DAYS} дней.`);
  }
}

function normalizeRcodeFilterValue(value) {
  if (value === '0' || value === 0 || value === 'NOERROR') return 0;
  if (value === '2' || value === 2 || value === 'SERVFAIL') return 2;
  if (value === '3' || value === 3 || value === 'NXDOMAIN') return 3;
  if (value === 'other') return 'other';
  const n = Number(value);
  if (Number.isFinite(n)) return n;
  throw new Error(`Неизвестный результат ответа: ${value}`);
}

function rcodeSqlForValue(value, alias = '') {
  const col = alias ? `${alias}.rcode` : 'rcode';
  const n = normalizeRcodeFilterValue(value);
  if (n === 'other') return `${col} NOT IN (0, 2, 3)`;
  return `${col} = {rcode_${String(value).replace(/[^a-zA-Z0-9]/g, '_')}:UInt8}`;
}

function groupExpr(fieldId, alias = '') {
  const g = GROUP_BY_ID[fieldId];
  if (!g) throw new Error(`Неизвестная группировка: ${fieldId}`);
  if (fieldId === 'client_ip') return `${dnsIpExpr(`${alias ? `${alias}.` : ''}client_ip`)}`;
  if (fieldId === 'server_ip') return `${dnsIpExpr(`${alias ? `${alias}.` : ''}server_ip`)}`;
  if (fieldId === 'rcode') return `toString(${alias ? `${alias}.` : ''}rcode)`;
  return `${alias ? `${alias}.` : ''}${g.column}`;
}

function metricEventCountSql(metricId, alias = '') {
  const metric = METRIC_BY_ID[metricId];
  if (!metric) throw new Error(`Неизвестная метрика: ${metricId}`);
  const p = alias ? `${alias}.` : '';
  if (metric.event === 'queries') return `countIf(${p}is_response = 0)`;
  if (metric.event === 'responses') return `countIf(${p}is_response = 1)`;
  if (metric.event === 'nxdomain') return `countIf(${p}is_response = 1 AND ${p}rcode = 3)`;
  if (metric.event === 'servfail') return `countIf(${p}is_response = 1 AND ${p}rcode = 2)`;
  throw new Error(`Метрика не поддерживается: ${metricId}`);
}

function metricSelectSql(metricId, bucketSec, alias = '') {
  const metric = METRIC_BY_ID[metricId];
  if (!metric) throw new Error(`Неизвестная метрика: ${metricId}`);
  const expr = metricEventCountSql(metricId, alias);
  return metric.kind === 'rate' ? `round((${expr}) / ${bucketSec}, 2)` : expr;
}

function metricPeriodValueSql(metricId, windowSeconds, alias = '') {
  const metric = METRIC_BY_ID[metricId];
  if (!metric) throw new Error(`Неизвестная метрика: ${metricId}`);
  const expr = metricEventCountSql(metricId, alias);
  if (metric.kind === 'rate') {
    const sec = Math.max(Number(windowSeconds) || 1, 1);
    return `round((${expr}) / ${sec}, 2)`;
  }
  return expr;
}

function validateDnsExplorerFilters(filters = []) {
  if (!Array.isArray(filters)) throw new Error('filters должен быть массивом');
  return filters.map((raw, idx) => {
    const field = String(raw?.field || '');
    const op = String(raw?.op || '');
    const def = FIELD_BY_ID[field];
    if (!def) throw new Error(`Строка ${idx + 1}: неизвестное поле «${field}»`);
    if (!def.ops.includes(op)) {
      throw new Error(`Строка ${idx + 1}: оператор «${op}» недоступен для поля «${def.label}»`);
    }
    if (op === 'in') {
      const values = Array.isArray(raw.values) ? raw.values.map(String).filter(Boolean) : [];
      if (!values.length) throw new Error(`Строка ${idx + 1}: укажите значения для «один из»`);
      return { field, op, values };
    }
    const value = raw.value != null ? String(raw.value).trim() : '';
    if (!value) throw new Error(`Строка ${idx + 1}: укажите значение`);
    return { field, op, value };
  });
}

function buildExplorerWhereClauses(filters, alias = 'd') {
  const clauses = [];
  const params = {};
  const col = (name) => `${alias}.${name}`;

  for (let i = 0; i < filters.length; i += 1) {
    const f = filters[i];
    const key = `f${i}`;
    if (f.field === 'client_ip') {
      if (f.op === 'eq') {
        clauses.push(clientIpFilterSql(alias));
        params.client_ip = f.value;
      } else if (f.op === 'ne') {
        clauses.push(`NOT (${clientIpFilterSql(alias)})`);
        params.client_ip = f.value;
      } else if (f.op === 'in_cidr') {
        clauses.push(`isIPAddressInRange(${dnsIpExpr(col('client_ip'))}, {${key}:String})`);
        params[key] = f.value;
      }
    } else if (f.field === 'server_ip') {
      if (f.op === 'eq') {
        clauses.push(serverIpFilterSql(alias));
        params.server_ip = f.value;
      } else if (f.op === 'ne') {
        clauses.push(`NOT (${serverIpFilterSql(alias)})`);
        params.server_ip = f.value;
      } else if (f.op === 'in_cidr') {
        clauses.push(`isIPAddressInRange(${dnsIpExpr(col('server_ip'))}, {${key}:String})`);
        params[key] = f.value;
      }
    } else if (f.field === 'query_name') {
      if (f.op === 'eq') {
        clauses.push(`${col('query_name')} = {${key}:String}`);
        params[key] = f.value;
      } else if (f.op === 'contains') {
        clauses.push(`positionCaseInsensitive(${col('query_name')}, {${key}:String}) > 0`);
        params[key] = f.value;
      } else if (f.op === 'not_contains') {
        clauses.push(`positionCaseInsensitive(${col('query_name')}, {${key}:String}) = 0`);
        params[key] = f.value;
      }
    } else if (f.field === 'qtype') {
      if (f.op === 'eq') {
        clauses.push(`${col('qtype')} = {${key}:String}`);
        params[key] = f.value;
      } else if (f.op === 'ne') {
        clauses.push(`${col('qtype')} != {${key}:String}`);
        params[key] = f.value;
      } else if (f.op === 'in') {
        clauses.push(`${col('qtype')} IN {${key}:Array(String)}`);
        params[key] = f.values;
      }
    } else if (f.field === 'rcode') {
      if (f.op === 'eq') {
        const n = normalizeRcodeFilterValue(f.value);
        if (n === 'other') clauses.push(`${col('rcode')} NOT IN (0, 2, 3)`);
        else {
          clauses.push(`${col('rcode')} = {${key}:UInt8}`);
          params[key] = n;
        }
      } else if (f.op === 'ne') {
        const n = normalizeRcodeFilterValue(f.value);
        if (n === 'other') clauses.push(`${col('rcode')} IN (0, 2, 3)`);
        else {
          clauses.push(`${col('rcode')} != {${key}:UInt8}`);
          params[key] = n;
        }
      } else if (f.op === 'in') {
        const codes = [];
        let hasOther = false;
        for (const v of f.values) {
          const n = normalizeRcodeFilterValue(v);
          if (n === 'other') hasOther = true;
          else codes.push(n);
        }
        const parts = [];
        if (codes.length) {
          parts.push(`${col('rcode')} IN {${key}:Array(UInt8)}`);
          params[key] = codes;
        }
        if (hasOther) parts.push(`${col('rcode')} NOT IN (0, 2, 3)`);
        if (!parts.length) throw new Error('Укажите значения результата ответа');
        clauses.push(parts.length > 1 ? `(${parts.join(' OR ')})` : parts[0]);
      }
    } else if (f.field === 'source_id') {
      clauses.push(`${col('source_id')} IN {${key}:Array(String)}`);
      params[key] = f.values;
    }
  }

  return { clauses, params };
}

function buildDnsExplorerBaseWhere(body = {}) {
  const range = String(body.range || '24h');
  const from = body.from ? String(body.from) : undefined;
  const to = body.to ? String(body.to) : undefined;
  validateDnsExplorerWindow({ range, from, to });

  const filters = validateDnsExplorerFilters(body.filters || []);
  const window = resolveDnsWindow({ range, from, to });
  const clauses = [window.whereTs.replace(/\bts\b/g, 'd.ts')];
  const params = { ...window.params };

  appendSourceFilter(clauses, params, {
    sourceIds: body.sourceIds,
    collectorId: body.collectorId,
    collectorScopes: body.collectorScopes,
  }, 'd');

  const explorer = buildExplorerWhereClauses(filters, 'd');
  clauses.push(...explorer.clauses);
  Object.assign(params, explorer.params);

  return {
    whereSql: clauses.join('\n  AND '),
    params,
    window,
    filters,
    range,
    from,
    to,
  };
}

function dnsExplorerQuery(body = {}) {
  const metricId = String(body.metric || 'queries_per_sec');
  if (!METRIC_BY_ID[metricId]) throw new Error(`Неизвестная метрика: ${metricId}`);

  const groupBy = Array.isArray(body.groupBy)
    ? body.groupBy.map(String).filter((id) => GROUP_BY_ID[id])
    : [];
  if (body.groupBy?.length && groupBy.length !== body.groupBy.length) {
    throw new Error('Указана неизвестная группировка');
  }

  const limit = Math.min(
    Math.max(Number(body.limit) || DNS_EXPLORER_DEFAULT_LIMIT, 1),
    DNS_EXPLORER_MAX_LIMIT,
  );

  const base = buildDnsExplorerBaseWhere(body);
  const bucketMode = base.window.bucketMode;
  const bucketSec = dnsBucketSeconds(bucketMode);
  const windowSeconds = base.window.windowSeconds;
  const bucket = dnsBucketExpr(bucketMode).replace(/\bts\b/g, 'd.ts');
  const metricSql = metricSelectSql(metricId, bucketSec, 'd');
  const tableMetricSql = metricPeriodValueSql(metricId, windowSeconds, 'd');
  const rankMetricSql = metricEventCountSql(metricId, 'd');

  if (!groupBy.length) {
    const sql = `
      SELECT
        ${bucket} AS bucket,
        toUnixTimestamp(${bucket}) AS bucket_ts,
        ${metricSql} AS value
      FROM ${dnsLogTableRef()} AS d
      WHERE ${base.whereSql}
      GROUP BY bucket
      ORDER BY bucket
    `;
    return {
      timeseriesSql: sql,
      tableSql: `
        SELECT 'Всего' AS label, ${tableMetricSql} AS value
        FROM ${dnsLogTableRef()} AS d
        WHERE ${base.whereSql}
      `,
      params: base.params,
      meta: {
        metric: metricId,
        groupBy: [],
        dataTable: config.dnsLogTable,
        dataTier: 'raw',
        bucketMode,
        windowSeconds,
        truncated: false,
        limit: 1,
      },
      mapTimeseries(rows) {
        return rows.map((r) => ({
          bucket: String(r.bucket || ''),
          bucketMs: Number(r.bucket_ts) * 1000,
          value: Number(r.value) || 0,
        }));
      },
      mapTable(rows) {
        return rows.map((r) => ({
          id: 'dns-total',
          seriesKey: 'total',
          label: String(r.label || 'Всего'),
          values: [String(r.label || 'Всего')],
          value: Number(r.value) || 0,
          color: CHART_COLORS[0],
        }));
      },
    };
  }

  const groupSelects = groupBy.map((id, idx) => `${groupExpr(id, 'd')} AS dim_${idx}`);
  const groupCols = groupBy.map((_, idx) => `dim_${idx}`);
  const groupList = groupCols.join(', ');

  return {
    timeseriesSql: `
      WITH bucketed AS (
        SELECT
          ${bucket} AS bucket,
          ${groupSelects.join(',\n          ')},
          ${metricSql} AS value
        FROM ${dnsLogTableRef()} AS d
        WHERE ${base.whereSql}
        GROUP BY bucket, ${groupList}
      ),
      ranked AS (
        SELECT
          ${groupSelects.join(',\n          ')},
          ${rankMetricSql} AS total
        FROM ${dnsLogTableRef()} AS d
        WHERE ${base.whereSql}
        GROUP BY ${groupList}
        ORDER BY total DESC
        LIMIT {limit:UInt32}
      )
      SELECT
        b.bucket,
        toUnixTimestamp(b.bucket) AS bucket_ts,
        ${groupCols.map((c) => `b.${c}`).join(', ')},
        b.value
      FROM bucketed AS b
      INNER JOIN ranked AS r ON ${groupCols.map((c) => `b.${c} = r.${c}`).join(' AND ')}
      ORDER BY b.bucket
    `,
    tableSql: `
      WITH grouped AS (
        SELECT
          ${groupSelects.join(',\n          ')},
          ${tableMetricSql} AS value
        FROM ${dnsLogTableRef()} AS d
        WHERE ${base.whereSql}
        GROUP BY ${groupList}
      )
      SELECT ${groupList}, value
      FROM grouped
      ORDER BY value DESC
      LIMIT {limit:UInt32}
    `,
    params: { ...base.params, limit },
    meta: {
      metric: metricId,
      groupBy,
      dataTable: config.dnsLogTable,
      dataTier: 'raw',
      bucketMode,
      windowSeconds,
      truncated: true,
      limit,
    },
    mapTimeseries(rows) {
      return rows.map((r) => {
        const dims = groupCols.map((c, idx) => r[c]);
        const key = dims.join('|');
        return {
          bucket: String(r.bucket || ''),
          bucketMs: Number(r.bucket_ts) * 1000,
          seriesKey: key,
          value: Number(r.value) || 0,
          dims,
        };
      });
    },
    mapTable(rows) {
      return rows.map((r, i) => {
        const values = groupCols.map((c) => String(r[c] ?? ''));
        const seriesKey = values.join('|');
        return {
          id: `dns-row-${i}`,
          seriesKey,
          values,
          value: Number(r.value) || 0,
          color: CHART_COLORS[i % CHART_COLORS.length],
        };
      });
    },
  };
}

const CHART_COLORS = ['#7E92F8', '#51D16D', '#F0B400', '#F06B6B', '#C084FC', '#38BDF8', '#FB923C'];

function dnsExplorerSuggestDomains(body = {}, q = '', lim = 20) {
  const base = buildDnsExplorerBaseWhere(body);
  const needle = String(q || '').trim();
  const clauses = [...base.whereSql.split('\n  AND ')];
  const params = { ...base.params, limit: lim };
  if (needle) {
    clauses.push('positionCaseInsensitive(d.query_name, {q:String}) > 0');
    params.q = needle;
  }
  return {
    sql: `
      SELECT
        d.query_name AS value,
        count() AS cnt
      FROM ${dnsLogTableRef()} AS d
      WHERE ${clauses.join('\n  AND ')}
      GROUP BY value
      ORDER BY cnt DESC
      LIMIT {limit:UInt32}
    `,
    params,
    map(rows) {
      return rows.map((r) => ({
        value: String(r.value || ''),
        count: Number(r.cnt) || 0,
      }));
    },
  };
}

function dnsExplorerSuggestClientIps(body = {}, q = '', lim = 20) {
  const base = buildDnsExplorerBaseWhere(body);
  const needle = String(q || '').trim();
  const clientExpr = dnsIpExpr('d.client_ip');
  const clauses = [...base.whereSql.split('\n  AND ')];
  const params = { ...base.params, limit: lim };
  if (needle) {
    clauses.push(`positionCaseInsensitive(${clientExpr}, {q:String}) > 0`);
    params.q = needle;
  }
  return {
    sql: `
      WITH ips AS (
        SELECT ${clientExpr} AS ip, count() AS cnt
        FROM ${dnsLogTableRef()} AS d
        WHERE ${clauses.join('\n  AND ')}
        GROUP BY ip
        ORDER BY cnt DESC
        LIMIT {limit:UInt32}
      ),
      ${badgeCtes('ips', 'ip')}
      SELECT
        i.ip AS value,
        i.cnt AS count,
        rb.resolver_label AS resolver_label,
        ii.ip IS NULL AS is_external
      FROM ips AS i
      LEFT JOIN resolver_badges AS rb ON i.ip = rb.ip
      LEFT JOIN internal_ips AS ii ON i.ip = ii.ip
      ORDER BY i.cnt DESC
    `,
    params,
    map(rows) {
      return rows.map((r) => ({
        value: String(r.value || ''),
        count: Number(r.count) || 0,
        ...mapIpBadgeFields(r),
      }));
    },
  };
}

function dnsExplorerSuggestServerIps(body = {}, q = '', lim = 20) {
  const base = buildDnsExplorerBaseWhere(body);
  const needle = String(q || '').trim();
  const serverExpr = dnsIpExpr('d.server_ip');
  const clauses = [...base.whereSql.split('\n  AND ')];
  const params = { ...base.params, limit: lim };
  if (needle) {
    clauses.push(`positionCaseInsensitive(${serverExpr}, {q:String}) > 0`);
    params.q = needle;
  }
  return {
    sql: `
      WITH ips AS (
        SELECT ${serverExpr} AS ip, count() AS cnt
        FROM ${dnsLogTableRef()} AS d
        WHERE ${clauses.join('\n  AND ')}
        GROUP BY ip
        ORDER BY cnt DESC
        LIMIT {limit:UInt32}
      ),
      ${badgeCtes('ips', 'ip')}
      SELECT
        i.ip AS value,
        i.cnt AS count,
        rb.resolver_label AS resolver_label,
        ii.ip IS NULL AS is_external
      FROM ips AS i
      LEFT JOIN resolver_badges AS rb ON i.ip = rb.ip
      LEFT JOIN internal_ips AS ii ON i.ip = ii.ip
      ORDER BY i.cnt DESC
    `,
    params,
    map(rows) {
      return rows.map((r) => ({
        value: String(r.value || ''),
        count: Number(r.count) || 0,
        ...mapIpBadgeFields(r),
      }));
    },
  };
}

function badgeCtes(tableName, ipColumn) {
  const resolversView = dnsResolversViewRef();
  const l3View = l3PrefixesViewRef();
  const label = dnsResolverLabelSql('res');
  return `
    resolver_badges AS (
      SELECT
        a.${ipColumn} AS ip,
        argMax(res.role, length(res.prefix)) AS resolver_role,
        argMax(${label}, length(res.prefix)) AS resolver_label
      FROM ${tableName} AS a
      CROSS JOIN ${resolversView} AS res
      WHERE isIPAddressInRange(a.${ipColumn}, res.prefix)
      GROUP BY a.${ipColumn}
    ),
    internal_ips AS (
      SELECT DISTINCT a.${ipColumn} AS ip
      FROM ${tableName} AS a
      CROSS JOIN ${l3View} AS p
      WHERE isIPAddressInRange(a.${ipColumn}, p.prefix)
    )`;
}

function dnsExplorerSuggestQtypes(body = {}) {
  const base = buildDnsExplorerBaseWhere(body);
  return {
    sql: `
      SELECT
        d.qtype AS value,
        count() AS count
      FROM ${dnsLogTableRef()} AS d
      WHERE ${base.whereSql}
      GROUP BY value
      ORDER BY count DESC
      LIMIT 50
    `,
    params: base.params,
    map(rows) {
      return rows.map((r) => ({
        value: String(r.value || ''),
        count: Number(r.count) || 0,
      }));
    },
  };
}

function parseDnsExplorerBody(body = {}) {
  const range = String(body.range || '24h');
  const from = body.from ? String(body.from) : undefined;
  const to = body.to ? String(body.to) : undefined;
  const sourceIds = Array.isArray(body.sourceIds)
    ? body.sourceIds.map(String).filter(Boolean)
    : undefined;
  const collectorId = body.collectorId != null ? String(body.collectorId) : undefined;
  const collectorScopes = body.collectorScopes || (collectorId ? parseCollectorScopes(collectorId) : undefined);
  return {
    range,
    from,
    to,
    sourceIds,
    collectorId,
    collectorScopes,
    metric: body.metric,
    groupBy: body.groupBy,
    filters: body.filters,
    limit: body.limit,
  };
}

function parseDnsExplorerSuggestQuery(query = {}) {
  const range = String(query.range || '24h');
  const from = query.from ? String(query.from) : undefined;
  const to = query.to ? String(query.to) : undefined;
  const sourceIds = query.source_ids
    ? String(query.source_ids).split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;
  const collectorId = query.collector_id ? String(query.collector_id) : undefined;
  const collectorScopes = collectorId ? parseCollectorScopes(collectorId) : undefined;
  let filters = [];
  if (query.filters) {
    try { filters = JSON.parse(decodeURIComponent(String(query.filters))); } catch { filters = []; }
  }
  return {
    range,
    from,
    to,
    sourceIds,
    collectorId,
    collectorScopes,
    filters: Array.isArray(filters) ? filters : [],
    q: query.q ? String(query.q) : '',
  };
}

module.exports = {
  dnsExplorerSchema,
  dnsExplorerQuery,
  dnsExplorerSuggestDomains,
  dnsExplorerSuggestClientIps,
  dnsExplorerSuggestServerIps,
  dnsExplorerSuggestQtypes,
  parseDnsExplorerBody,
  parseDnsExplorerSuggestQuery,
  dnsSources,
};
