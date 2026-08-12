const {
  config,
  dnsLogTableRef,
  dnsResolversViewRef,
  l3PrefixesViewRef,
  sourcesTableRef,
  query,
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
const DNS_EXPLORER_MAX_EXPORT_ROWS = 10000;

const DNS_FILTER_LOGIC = new Set(['and', 'or', 'and_not', 'or_not']);

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
  { id: 'answer', label: 'Ответ', column: 'answer' },
  { id: 'answer_type', label: 'Тип ответа', column: 'answer_type' },
];

const FIELDS = [
  { id: 'client_ip', label: 'IP источника', ops: ['eq', 'ne', 'in_cidr'] },
  { id: 'query_name', label: 'Домен', ops: ['eq', 'contains', 'not_contains'] },
  { id: 'server_ip', label: 'IP DNS-сервера', ops: ['eq', 'ne', 'in_cidr'] },
  { id: 'qtype', label: 'Тип запроса', ops: ['eq', 'ne', 'in'] },
  { id: 'rcode', label: 'Результат ответа', ops: ['eq', 'ne', 'in'] },
  { id: 'answer', label: 'Ответ', ops: ['eq', 'ne', 'in_cidr', 'contains'] },
  { id: 'source_id', label: 'Источник/коллектор', ops: ['in'] },
];

const ANSWER_GROUP_IDS = new Set(['answer', 'answer_type']);

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

function needsAnswerExpand(groupBy = []) {
  return groupBy.some((id) => ANSWER_GROUP_IDS.has(id));
}

function dnsDomainNormalizeExpr(colExpr) {
  return `replaceRegexpOne(${colExpr}, '\\\\.$', '')`;
}

function dnsDomainEqSql(colExpr, paramKey) {
  return `${dnsDomainNormalizeExpr(colExpr)} = ${dnsDomainNormalizeExpr(`{${paramKey}:String}`)}`;
}

function dnsAnswerPairJoinExpr(alias = 'inner_d') {
  const p = alias ? `${alias}.` : '';
  return `arrayJoin(
    if(
      empty(${p}answers_a) AND empty(${p}answers_aaaa) AND empty(${p}answers_cname),
      [tuple('none', '')],
      arrayConcat(
        arrayMap(x -> tuple('A', toString(toIPv4(reinterpretAsUInt32(reverse(substring(x, 1, 4)))))), ${p}answers_a),
        arrayMap(x -> tuple('AAAA', IPv6NumToString(x)), ${p}answers_aaaa),
        arrayMap(x -> tuple('CNAME', x), ${p}answers_cname)
      )
    )
  )`;
}

function dnsExplorerInnerWhereSql(whereSql, innerAlias = 'inner_d') {
  return String(whereSql || '').replace(/\bd\./g, `${innerAlias}.`);
}

function dnsExplorerDataSource(base, groupBy = []) {
  if (!needsAnswerExpand(groupBy)) {
    return {
      fromSql: `${dnsLogTableRef()} AS d`,
      whereSql: base.whereSql,
    };
  }
  const answerJoin = dnsAnswerPairJoinExpr('inner_d');
  const innerWhere = dnsExplorerInnerWhereSql(base.whereSql, 'inner_d');
  return {
    fromSql: `(
      SELECT
        inner_d.ts,
        inner_d.source_id,
        inner_d.client_ip,
        inner_d.server_ip,
        inner_d.query_name,
        inner_d.qtype,
        inner_d.rcode,
        inner_d.is_response,
        ${answerJoin} AS answer_pair,
        answer_pair.1 AS answer_type,
        answer_pair.2 AS answer
      FROM ${dnsLogTableRef()} AS inner_d
      WHERE ${innerWhere}
        AND inner_d.is_response = 1
    ) AS d`,
    whereSql: '1',
  };
}

function answerEqFilterSql(alias, paramKey) {
  const col = (name) => `${alias}.${name}`;
  return `(
    arrayExists(x ->
      positionCaseInsensitive({${paramKey}:String}, ':') = 0
      AND substring(x, 1, 4) = reverse(reinterpretAsString(toIPv4({${paramKey}:String})))
      AND substring(x, 5) = unhex('000000000000000000000000'),
      ${col('answers_a')}
    )
    OR arrayExists(x ->
      positionCaseInsensitive({${paramKey}:String}, ':') > 0
      AND x = IPv6StringToNum({${paramKey}:String}),
      ${col('answers_aaaa')}
    )
    OR has(${col('answers_cname')}, {${paramKey}:String})
  )`;
}

function answerInCidrFilterSql(alias, paramKey) {
  const col = (name) => `${alias}.${name}`;
  return `(
    arrayExists(x -> isIPAddressInRange(
      toString(toIPv4(reinterpretAsUInt32(reverse(substring(x, 1, 4))))),
      {${paramKey}:String}
    ), ${col('answers_a')})
    OR arrayExists(x -> isIPAddressInRange(IPv6NumToString(x), {${paramKey}:String}), ${col('answers_aaaa')})
  )`;
}

function answerContainsFilterSql(alias, paramKey) {
  const col = (name) => `${alias}.${name}`;
  return `arrayExists(x -> positionCaseInsensitive(x, {${paramKey}:String}) > 0, ${col('answers_cname')})`;
}

function groupExpr(fieldId, alias = '') {
  const g = GROUP_BY_ID[fieldId];
  if (!g) throw new Error(`Неизвестная группировка: ${fieldId}`);
  if (fieldId === 'client_ip') return `${dnsIpExpr(`${alias ? `${alias}.` : ''}client_ip`)}`;
  if (fieldId === 'server_ip') return `${dnsIpExpr(`${alias ? `${alias}.` : ''}server_ip`)}`;
  if (fieldId === 'rcode') return `toString(${alias ? `${alias}.` : ''}rcode)`;
  if (fieldId === 'answer_type') return `${alias ? `${alias}.` : ''}answer_type`;
  if (fieldId === 'answer') return `${alias ? `${alias}.` : ''}answer`;
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

function normalizeFilterLogic(logic) {
  const key = String(logic || 'and').trim().toLowerCase();
  return DNS_FILTER_LOGIC.has(key) ? key : 'and';
}

function combineDnsExplorerFilterSql(clauses) {
  if (!clauses.length) return null;
  let sql = clauses[0].clause;
  for (let i = 1; i < clauses.length; i += 1) {
    const { logic, clause } = clauses[i];
    const op = (logic === 'or' || logic === 'or_not') ? 'OR' : 'AND';
    const part = (logic === 'and_not' || logic === 'or_not') ? `NOT (${clause})` : clause;
    sql = `(${sql} ${op} ${part})`;
  }
  return sql;
}

function pushDnsExplorerFilterClause(clauses, clause, logic) {
  if (!clause) return;
  clauses.push({ clause, logic: normalizeFilterLogic(logic) });
}

function validateDnsExplorerFilters(filters = []) {
  if (!Array.isArray(filters)) throw new Error('filters должен быть массивом');
  return filters.map((raw, idx) => {
    const field = String(raw?.field || '');
    const op = String(raw?.op || '');
    const logic = normalizeFilterLogic(raw?.logic);
    const def = FIELD_BY_ID[field];
    if (!def) throw new Error(`Строка ${idx + 1}: неизвестное поле «${field}»`);
    if (!def.ops.includes(op)) {
      throw new Error(`Строка ${idx + 1}: оператор «${op}» недоступен для поля «${def.label}»`);
    }
    if (op === 'in') {
      const values = Array.isArray(raw.values) ? raw.values.map(String).filter(Boolean) : [];
      if (!values.length) throw new Error(`Строка ${idx + 1}: укажите значения для «один из»`);
      return { field, op, values, logic };
    }
    const value = raw.value != null ? String(raw.value).trim() : '';
    if (!value) throw new Error(`Строка ${idx + 1}: укажите значение`);
    return { field, op, value, logic };
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
        pushDnsExplorerFilterClause(clauses, clientIpFilterSql(alias), f.logic);
        params.client_ip = f.value;
      } else if (f.op === 'ne') {
        pushDnsExplorerFilterClause(clauses, `NOT (${clientIpFilterSql(alias)})`, f.logic);
        params.client_ip = f.value;
      } else if (f.op === 'in_cidr') {
        pushDnsExplorerFilterClause(clauses, `isIPAddressInRange(${dnsIpExpr(col('client_ip'))}, {${key}:String})`, f.logic);
        params[key] = f.value;
      }
    } else if (f.field === 'server_ip') {
      if (f.op === 'eq') {
        pushDnsExplorerFilterClause(clauses, serverIpFilterSql(alias), f.logic);
        params.server_ip = f.value;
      } else if (f.op === 'ne') {
        pushDnsExplorerFilterClause(clauses, `NOT (${serverIpFilterSql(alias)})`, f.logic);
        params.server_ip = f.value;
      } else if (f.op === 'in_cidr') {
        pushDnsExplorerFilterClause(clauses, `isIPAddressInRange(${dnsIpExpr(col('server_ip'))}, {${key}:String})`, f.logic);
        params[key] = f.value;
      }
    } else if (f.field === 'query_name') {
      if (f.op === 'eq') {
        pushDnsExplorerFilterClause(clauses, dnsDomainEqSql(col('query_name'), key), f.logic);
        params[key] = f.value;
      } else if (f.op === 'contains') {
        pushDnsExplorerFilterClause(clauses, `positionCaseInsensitive(${col('query_name')}, {${key}:String}) > 0`, f.logic);
        params[key] = f.value;
      } else if (f.op === 'not_contains') {
        pushDnsExplorerFilterClause(clauses, `positionCaseInsensitive(${col('query_name')}, {${key}:String}) = 0`, f.logic);
        params[key] = f.value;
      }
    } else if (f.field === 'qtype') {
      if (f.op === 'eq') {
        pushDnsExplorerFilterClause(clauses, `${col('qtype')} = {${key}:String}`, f.logic);
        params[key] = f.value;
      } else if (f.op === 'ne') {
        pushDnsExplorerFilterClause(clauses, `${col('qtype')} != {${key}:String}`, f.logic);
        params[key] = f.value;
      } else if (f.op === 'in') {
        pushDnsExplorerFilterClause(clauses, `${col('qtype')} IN {${key}:Array(String)}`, f.logic);
        params[key] = f.values;
      }
    } else if (f.field === 'rcode') {
      if (f.op === 'eq') {
        const n = normalizeRcodeFilterValue(f.value);
        if (n === 'other') pushDnsExplorerFilterClause(clauses, `${col('rcode')} NOT IN (0, 2, 3)`, f.logic);
        else {
          pushDnsExplorerFilterClause(clauses, `${col('rcode')} = {${key}:UInt8}`, f.logic);
          params[key] = n;
        }
      } else if (f.op === 'ne') {
        const n = normalizeRcodeFilterValue(f.value);
        if (n === 'other') pushDnsExplorerFilterClause(clauses, `${col('rcode')} IN (0, 2, 3)`, f.logic);
        else {
          pushDnsExplorerFilterClause(clauses, `${col('rcode')} != {${key}:UInt8}`, f.logic);
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
        pushDnsExplorerFilterClause(
          clauses,
          parts.length > 1 ? `(${parts.join(' OR ')})` : parts[0],
          f.logic,
        );
      }
    } else if (f.field === 'answer') {
      if (f.op === 'eq') {
        pushDnsExplorerFilterClause(clauses, answerEqFilterSql(alias, key), f.logic);
        params[key] = f.value;
      } else if (f.op === 'ne') {
        pushDnsExplorerFilterClause(clauses, `NOT (${answerEqFilterSql(alias, key)})`, f.logic);
        params[key] = f.value;
      } else if (f.op === 'in_cidr') {
        pushDnsExplorerFilterClause(clauses, answerInCidrFilterSql(alias, key), f.logic);
        params[key] = f.value;
      } else if (f.op === 'contains') {
        pushDnsExplorerFilterClause(clauses, answerContainsFilterSql(alias, key), f.logic);
        params[key] = f.value;
      }
    } else if (f.field === 'source_id') {
      pushDnsExplorerFilterClause(clauses, `${col('source_id')} IN {${key}:Array(String)}`, f.logic);
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
  const filterSql = combineDnsExplorerFilterSql(explorer.clauses);
  if (filterSql) clauses.push(filterSql);
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

function dnsExplorerQuery(body = {}, options = {}) {
  const metricId = String(body.metric || 'queries_per_sec');
  if (!METRIC_BY_ID[metricId]) throw new Error(`Неизвестная метрика: ${metricId}`);

  const groupBy = Array.isArray(body.groupBy)
    ? body.groupBy.map(String).filter((id) => GROUP_BY_ID[id])
    : [];
  if (body.groupBy?.length && groupBy.length !== body.groupBy.length) {
    throw new Error('Указана неизвестная группировка');
  }

  const hardMax = options.maxLimit || DNS_EXPLORER_MAX_LIMIT;
  const limit = Math.min(
    Math.max(Number(body.limit) || DNS_EXPLORER_DEFAULT_LIMIT, 1),
    hardMax,
  );

  const base = buildDnsExplorerBaseWhere(body);
  const dataSource = dnsExplorerDataSource(base, groupBy);
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
      FROM ${dataSource.fromSql}
      WHERE ${dataSource.whereSql}
      GROUP BY bucket
      ORDER BY bucket
    `;
    return {
      timeseriesSql: sql,
      tableSql: `
        SELECT 'Всего' AS label, ${tableMetricSql} AS value
        FROM ${dataSource.fromSql}
        WHERE ${dataSource.whereSql}
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
        FROM ${dataSource.fromSql}
        WHERE ${dataSource.whereSql}
        GROUP BY bucket, ${groupList}
      ),
      ranked AS (
        SELECT
          ${groupSelects.join(',\n          ')},
          ${rankMetricSql} AS total
        FROM ${dataSource.fromSql}
        WHERE ${dataSource.whereSql}
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
        FROM ${dataSource.fromSql}
        WHERE ${dataSource.whereSql}
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
  const domainValueExpr = dnsDomainNormalizeExpr('d.query_name');
  return {
    sql: `
      SELECT
        ${domainValueExpr} AS value,
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

function dnsExplorerSuggestAnswers(body = {}, q = '', lim = 50) {
  const base = buildDnsExplorerBaseWhere(body);
  const needle = String(q || '').trim();
  const answerJoin = dnsAnswerPairJoinExpr('inner_d');
  const innerWhere = dnsExplorerInnerWhereSql(base.whereSql, 'inner_d');
  const params = { ...base.params, limit: lim };
  const answerFilter = needle
    ? 'AND positionCaseInsensitive(answer_pair.2, {q:String}) > 0'
    : '';
  if (needle) params.q = needle;
  return {
    sql: `
      SELECT
        answer_pair.2 AS value,
        count() AS cnt
      FROM (
        SELECT
          ${answerJoin} AS answer_pair
        FROM ${dnsLogTableRef()} AS inner_d
        WHERE ${innerWhere}
          AND inner_d.is_response = 1
      )
      WHERE answer_pair.1 != 'none'
        AND answer_pair.2 != ''
        ${answerFilter}
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
    try {
      const parsed = JSON.parse(decodeURIComponent(String(query.filters)));
      filters = Array.isArray(parsed) ? parsed : [];
    } catch {
      filters = [];
    }
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

function dnsRowsToCsv(rows, groupByIds, metricLabel) {
  const headers = [
    ...groupByIds.map((id) => GROUP_BY_ID[id]?.label || id),
    metricLabel,
  ];
  const escape = (value) => {
    const s = String(value ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.map(escape).join(',')];
  for (const row of rows) {
    const values = row.values?.length ? row.values : [row.label || ''];
    lines.push([
      ...values,
      row.value,
    ].map(escape).join(','));
  }
  return lines.join('\n');
}

async function dnsExplorerExportCsv(body = {}) {
  const exportBody = {
    ...parseDnsExplorerBody(body),
    limit: DNS_EXPLORER_MAX_EXPORT_ROWS,
  };
  if (body.from && body.to) {
    exportBody.from = String(body.from);
    exportBody.to = String(body.to);
    exportBody.range = 'custom';
  }
  const spec = dnsExplorerQuery(exportBody, { maxLimit: DNS_EXPLORER_MAX_EXPORT_ROWS });
  const { rows } = await query(spec.tableSql, spec.params || {}, { name: 'dns-explorer/export' });
  const mapped = spec.mapTable(rows);
  const metricLabel = METRIC_BY_ID[spec.meta?.metric]?.label || spec.meta?.metric || 'metric';
  return dnsRowsToCsv(mapped, spec.meta?.groupBy || [], metricLabel);
}

module.exports = {
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
  dnsSources,
  needsAnswerExpand,
  dnsExplorerDataSource,
  dnsExplorerInnerWhereSql,
  dnsDomainEqSql,
  answerEqFilterSql,
  answerInCidrFilterSql,
  answerContainsFilterSql,
  GROUP_BY,
  FIELDS,
};
