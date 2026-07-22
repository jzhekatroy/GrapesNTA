const {
  config,
  dashboardTableRef,
  countryTableRef,
  intervalsControlTableRef,
  intervalsTableRef,
  monitoringCol,
  parseDataDatetimeSql,
} = require('./clickhouse');

const MONITORING_TIMEZONE = 'Europe/Moscow';
const DEFAULT_SOURCE_ID = 'netflow';

const PARAMETERS = {
  broadband_total: {
    id: 'broadband_total',
    label: 'суммарный трафик ШПД',
    unit: 'Гбит/мин',
    featureName: 'total_bytes',
    boundsConfigKey: 'intervals',
  },
  broadband_in_ru: {
    id: 'broadband_in_ru',
    label: 'Входящий трафик ШПД из России',
    unit: 'Гбит/мин',
    featureName: 'country_ru',
    boundsConfigKey: 'intervals_country_ru',
  },
  broadband_in_foreign: {
    id: 'broadband_in_foreign',
    label: 'Входящий трафик ШПД из-за рубежа',
    unit: 'Гбит/мин',
    featureName: 'country_F',
    boundsConfigKey: 'intervals_country_ru',
  },
};

const FEATURE_LABELS = Object.fromEntries(
  Object.values(PARAMETERS).map((item) => [item.featureName, item.label]),
);

function getParameter(id) {
  return PARAMETERS[id] || null;
}

function getParameterLabel(featureName) {
  return FEATURE_LABELS[String(featureName || '')] || String(featureName || '—');
}

function listParameterIds() {
  return Object.keys(PARAMETERS);
}

function normalizeChBucketString(bucket) {
  if (bucket == null || bucket === '') return '';
  const s = String(bucket).trim();
  const m = s.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  if (m) return `${m[1]} ${m[2]}`;
  return s.slice(0, 19).replace('T', ' ');
}

function bucketKey(bucket) {
  return normalizeChBucketString(bucket);
}

function seriesNumber(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function validateDatetimeParam(value, label) {
  const s = String(value || '').trim();
  if (!s) throw new Error(`Укажите ${label}`);
  const ms = new Date(s).getTime();
  if (!Number.isFinite(ms)) throw new Error(`Некорректная дата: ${label}`);
  return s;
}

function parseMonitoringSeriesQuery(query = {}) {
  const parameter = String(query.parameter || '').trim();
  if (!parameter) throw new Error('Укажите parameter');
  if (!getParameter(parameter)) throw new Error(`Неизвестный показатель: ${parameter}`);

  const from = validateDatetimeParam(query.from, 'from');
  const to = validateDatetimeParam(query.to, 'to');
  if (new Date(from).getTime() >= new Date(to).getTime()) {
    throw new Error('Начало периода должно быть раньше конца');
  }

  return { parameter, from, to };
}

function parseMonitoringDeviationsQuery(query = {}) {
  const limit = Math.min(Math.max(Number(query.limit) || 10, 1), 100);
  return { limit };
}

function monitoringParameters() {
  const dtCol = monitoringCol('dt');
  const featureCol = monitoringCol('featureName');
  const outsideCol = monitoringCol('outsideCi');

  return {
    sql: `
      SELECT
        ${featureCol} AS feature_name,
        sum(${outsideCol}) AS deviations
      FROM ${intervalsControlTableRef()}
      WHERE ${outsideCol} = 1
        AND ${dtCol} > now() - INTERVAL 1 DAY
      GROUP BY feature_name
    `,
    params: {},
    meta: {
      period: '24h',
      controlTable: config.intervalsControlTable,
    },
    map(rows) {
      const deviationMap = new Map(
        rows.map((row) => [String(row.feature_name), Number(row.deviations) || 0]),
      );
      const totalDeviations24h = rows.reduce(
        (sum, row) => sum + (Number(row.deviations) || 0),
        0,
      );

      const parameters = listParameterIds().map((id) => {
        const param = PARAMETERS[id];
        return {
          id: param.id,
          label: param.label,
          unit: param.unit,
          featureName: param.featureName,
          deviations24h: deviationMap.get(param.featureName) || 0,
        };
      });

      return {
        parameters,
        totalDeviations24h,
      };
    },
  };
}

function monitoringSeriesValues({ parameter, from, to }) {
  const param = getParameter(parameter);
  if (!param) throw new Error(`Неизвестный показатель: ${parameter}`);

  if (param.id === 'broadband_total') {
    return {
      sql: `
        SELECT
          toTimeZone(minute, '${MONITORING_TIMEZONE}') AS dt,
          toUnixTimestamp(toTimeZone(minute, '${MONITORING_TIMEZONE}')) AS bucket_ts,
          round(total_bytes / 8 * 1e-9, 3) AS value
        FROM ${dashboardTableRef()}
        WHERE toTimeZone(minute, '${MONITORING_TIMEZONE}') >= ${parseDataDatetimeSql('from')}
          AND toTimeZone(minute, '${MONITORING_TIMEZONE}') < ${parseDataDatetimeSql('to')}
          AND source_id = {source_id:String}
        ORDER BY dt
      `,
      params: { from, to, source_id: DEFAULT_SOURCE_ID },
    };
  }

  const countryFilter = param.id === 'broadband_in_ru'
    ? "country_code = 'RU'"
    : "country_code != 'RU'";

  return {
    sql: `
      SELECT
        dt,
        toUnixTimestamp(dt) AS bucket_ts,
        Gbit AS value
      FROM (
        SELECT
          toTimeZone(minute, '${MONITORING_TIMEZONE}') AS dt,
          round(sum(bytes) / 8 * 1e-9, 3) AS Gbit
        FROM ${countryTableRef()}
        WHERE country_side = 'src'
          AND source_id = {source_id:String}
          AND country_basis = 'asn'
          AND ${countryFilter}
          AND direction = 'in'
          AND toTimeZone(minute, '${MONITORING_TIMEZONE}') >= ${parseDataDatetimeSql('from')}
          AND toTimeZone(minute, '${MONITORING_TIMEZONE}') < ${parseDataDatetimeSql('to')}
        GROUP BY dt
      )
      ORDER BY dt
    `,
    params: { from, to, source_id: DEFAULT_SOURCE_ID },
  };
}

function monitoringSeriesCi({ parameter, from, to }) {
  const param = getParameter(parameter);
  if (!param) throw new Error(`Неизвестный показатель: ${parameter}`);

  const dtCol = monitoringCol('dt');
  const featureCol = monitoringCol('featureName');
  const dtExpr = `toTimeZone(${dtCol}, '${MONITORING_TIMEZONE}')`;

  return {
    sql: `
      SELECT
        ${dtExpr} AS dt,
        toUnixTimestamp(toStartOfMinute(${dtExpr})) AS bucket_ts,
        ci_low,
        ci_high
      FROM ${intervalsTableRef()}
      WHERE ${dtCol} >= ${parseDataDatetimeSql('from')}
        AND ${dtCol} < ${parseDataDatetimeSql('to')}
        AND ${featureCol} = {feature_name:String}
      ORDER BY dt
    `,
    params: {
      from,
      to,
      feature_name: param.featureName,
    },
  };
}

function mergeMonitoringSeries(valueRows, ciRows) {
  const ciMap = new Map(
    ciRows.map((row) => [bucketKey(row.dt), row]),
  );

  return valueRows.map((valueRow) => {
    const key = bucketKey(valueRow.dt);
    const ciRow = ciMap.get(key);
    const bucketTs = valueRow?.bucket_ts;
    return {
      bucket: key,
      bucketMs: bucketTs != null ? Number(bucketTs) * 1000 : null,
      value: seriesNumber(valueRow.value),
      ciLow: ciRow != null ? seriesNumber(ciRow.ci_low) : null,
      ciHigh: ciRow != null ? seriesNumber(ciRow.ci_high) : null,
    };
  });
}

function monitoringSeriesMeta({ parameter, from, to }) {
  const param = getParameter(parameter);
  return {
    parameter: param.id,
    label: param.label,
    unit: param.unit,
    featureName: param.featureName,
    from,
    to,
    bucketSeconds: 60,
    timezone: MONITORING_TIMEZONE,
  };
}

function monitoringDeviations({ limit = 10 } = {}) {
  const dtCol = monitoringCol('dt');
  const featureCol = monitoringCol('featureName');
  const outsideCol = monitoringCol('outsideCi');
  const parameterCol = monitoringCol('parameter');
  const dtExpr = `toTimeZone(${dtCol}, '${MONITORING_TIMEZONE}')`;

  return {
    sql: `
      SELECT
        ${dtExpr} AS dt,
        toUnixTimestamp(toStartOfMinute(${dtExpr})) AS bucket_ts,
        ${featureCol} AS feature_name,
        ${parameterCol} AS value,
        ci_low,
        ci_high
      FROM ${intervalsControlTableRef()}
      WHERE ${outsideCol} = 1
        AND ${dtCol} > now() - INTERVAL 1 DAY
      ORDER BY dt DESC, feature_name
      LIMIT {limit:UInt32}
    `,
    params: { limit },
    meta: {
      period: '24h',
      limit,
      controlTable: config.intervalsControlTable,
    },
    map(rows) {
      return rows.map((row) => ({
        dt: normalizeChBucketString(row.dt),
        dtMs: row.bucket_ts != null ? Number(row.bucket_ts) * 1000 : null,
        featureName: String(row.feature_name || ''),
        featureLabel: getParameterLabel(row.feature_name),
        value: Number(row.value) || 0,
        ciLow: Number(row.ci_low),
        ciHigh: Number(row.ci_high),
      }));
    },
  };
}

module.exports = {
  PARAMETERS,
  FEATURE_LABELS,
  getParameter,
  getParameterLabel,
  listParameterIds,
  parseMonitoringSeriesQuery,
  parseMonitoringDeviationsQuery,
  monitoringParameters,
  monitoringSeriesValues,
  monitoringSeriesCi,
  mergeMonitoringSeries,
  monitoringSeriesMeta,
  monitoringDeviations,
};
