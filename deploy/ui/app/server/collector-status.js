const {
  query,
  col,
  flowCol,
  flowsRawTableRef,
  sourcesTableRef,
  collectorsViewRef,
  locationsViewRef,
  collectorHealthViewRef,
  healthCol,
} = require('./clickhouse');

function mapStatusRow(r) {
  const catalogSourceId = String(r.catalog_source_id ?? '').trim();
  const sourceId = String(r.source_id ?? '');
  return {
    sourceId,
    sourceName: String(r.source_name ?? '').trim() || sourceId,
    locationId: String(r.location_id ?? ''),
    locationName: String(r.location_name ?? ''),
    collectorId: String(r.collector_id ?? ''),
    collectorName: String(r.collector_name ?? ''),
    protocol: String(r.protocol ?? ''),
    lastSeen: r.last_seen ?? null,
    ageSeconds: Number(r.age_seconds) || 0,
    flowsPerMin: Number(r.flows_per_min) || 0,
    bytesPerSec: Number(r.bytes_per_sec) || 0,
    pktsPerSec: Number(r.pkts_per_sec) || 0,
    samplingRate: r.sampling_rate != null ? Number(r.sampling_rate) : null,
    inCatalog: Boolean(catalogSourceId),
    writerLagSec: null,
    spoolLagSec: null,
    queueDrops: null,
  };
}

function collectorStatusSpec() {
  const timeCol = col('time');
  const bytesCol = col('bytes');
  const packetsCol = col('packets');
  const sourceIdCol = flowCol('sourceId');
  const samplingCol = flowCol('samplingRate');

  if (!sourceIdCol) {
    const err = new Error('Колонка source_id не настроена (CH_COL_SOURCE_ID)');
    err.statusCode = 502;
    throw err;
  }

  const flowsRaw = flowsRawTableRef();
  const sources = sourcesTableRef();
  const collectors = collectorsViewRef();
  const locations = locationsViewRef();

  const liveSelect = [
    `${sourceIdCol} AS source_id`,
    `max(${timeCol}) AS last_seen`,
    `dateDiff('second', max(${timeCol}), now()) AS age_seconds`,
    'count() AS flows_5m',
    `sum(${bytesCol}) AS bytes_5m`,
    `sum(${packetsCol}) AS pkts_5m`,
  ];
  if (samplingCol) {
    liveSelect.push(`anyLast(${samplingCol}) AS sampling_rate`);
  }

  const outerSelect = [
    'l.location_id AS location_id',
    'l.display_name AS location_name',
    'c.collector_id AS collector_id',
    'c.display_name AS collector_name',
    's.display_name AS source_name',
    's.source_id AS catalog_source_id',
    'live.source_id AS source_id',
    "coalesce(s.source_type, '') AS protocol",
    'live.last_seen AS last_seen',
    'live.age_seconds AS age_seconds',
    'round(live.flows_5m / 5) AS flows_per_min',
    'round(live.bytes_5m / 300) AS bytes_per_sec',
    'round(live.pkts_5m / 300) AS pkts_per_sec',
  ];
  if (samplingCol) {
    outerSelect.push('live.sampling_rate AS sampling_rate');
  }

  return {
    sql: `
      WITH live AS (
        SELECT
          ${liveSelect.join(',\n          ')}
        FROM ${flowsRaw}
        WHERE ${sourceIdCol} != ''
          AND ${timeCol} >= now() - INTERVAL 5 MINUTE
        GROUP BY source_id
      )
      SELECT
        ${outerSelect.join(',\n        ')}
      FROM live
      LEFT JOIN ${sources} AS s ON live.source_id = s.source_id
      LEFT JOIN ${collectors} AS c ON s.collector_id = c.collector_id
      LEFT JOIN ${locations} AS l ON c.location_id = l.location_id
      ORDER BY location_name, collector_name, source_name, live.source_id
    `,
    params: {},
    mapRows(rows) {
      return rows.map(mapStatusRow);
    },
  };
}

async function enrichCollectorStatusHealth(rows) {
  const viewRef = collectorHealthViewRef();
  const sourceCol = healthCol('sourceId');
  if (!viewRef || !sourceCol || !rows.length) return rows;

  const writerCol = healthCol('writerLag');
  const spoolCol = healthCol('spoolLag');
  const dropsCol = healthCol('queueDrops');

  const selectParts = [`${sourceCol} AS source_id`];
  if (writerCol) selectParts.push(`${writerCol} AS writer_lag_sec`);
  if (spoolCol) selectParts.push(`${spoolCol} AS spool_lag_sec`);
  if (dropsCol) selectParts.push(`${dropsCol} AS queue_drops`);

  const sourceIds = [...new Set(rows.map((r) => r.sourceId).filter(Boolean))];
  if (!sourceIds.length) return rows;

  try {
    const { rows: healthRows } = await query(
      `
        SELECT ${selectParts.join(', ')}
        FROM ${viewRef}
        WHERE ${sourceCol} IN {source_ids:Array(String)}
      `,
      { source_ids: sourceIds },
      { name: 'collectors/status-health' },
    );

    const bySource = new Map(
      healthRows.map((h) => [String(h.source_id ?? ''), h]),
    );

    return rows.map((row) => {
      const h = bySource.get(row.sourceId);
      if (!h) return row;
      return {
        ...row,
        writerLagSec: writerCol && h.writer_lag_sec != null ? Number(h.writer_lag_sec) : null,
        spoolLagSec: spoolCol && h.spool_lag_sec != null ? Number(h.spool_lag_sec) : null,
        queueDrops: dropsCol && h.queue_drops != null ? Number(h.queue_drops) : null,
      };
    });
  } catch {
    return rows;
  }
}

async function fetchCollectorStatus() {
  const spec = collectorStatusSpec();
  const { rows, elapsedMs } = await query(spec.sql, spec.params, { name: 'collectors/status' });
  let data = spec.mapRows(rows);
  const healthEnabled = Boolean(collectorHealthViewRef());
  data = await enrichCollectorStatusHealth(data);
  return {
    data,
    meta: {
      elapsedMs,
      rows: data.length,
      healthEnabled,
      windowMinutes: 5,
    },
  };
}

module.exports = {
  collectorStatusSpec,
  enrichCollectorStatusHealth,
  fetchCollectorStatus,
};
