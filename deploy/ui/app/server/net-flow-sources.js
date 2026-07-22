const {
  config,
  query,
  insertRows,
  sourcesTableRef,
  collectorsViewRef,
  locationsViewRef,
} = require('./clickhouse');

function mapFlowSourceRow(r) {
  return {
    sourceId: String(r.source_id ?? ''),
    sourceName: String(r.source_name ?? r.display_name ?? ''),
    sourceType: String(r.source_type ?? ''),
    currentCollectorId: String(r.current_collector_id ?? r.collector_id ?? ''),
    currentCollectorName: String(r.current_collector_name ?? ''),
    currentLocationName: String(r.current_location_name ?? ''),
    state: String(r.state ?? 'assigned'),
    displayName: String(r.display_name ?? ''),
    description: String(r.description ?? ''),
    includeInTotal: Number(r.include_in_total) === 1,
    location: String(r.location ?? ''),
  };
}

function listFlowSources() {
  const sources = sourcesTableRef();
  const collectors = collectorsViewRef();
  const locations = locationsViewRef();

  return {
    sql: `
      SELECT
        s.source_id,
        s.display_name AS source_name,
        s.display_name,
        s.source_type,
        s.collector_id AS current_collector_id,
        c.display_name AS current_collector_name,
        l.display_name AS current_location_name,
        s.description,
        s.include_in_total,
        s.location,
        multiIf(
          s.collector_id = '', 'unassigned',
          c.collector_id = '', 'broken_collector_link',
          'assigned'
        ) AS state
      FROM ${sources} AS s
      LEFT JOIN ${collectors} AS c ON s.collector_id = c.collector_id
      LEFT JOIN ${locations} AS l ON c.location_id = l.location_id
      ORDER BY state, s.source_id
    `,
    params: {},
    map(rows) {
      return rows.map(mapFlowSourceRow);
    },
  };
}

async function getFlowSource(sourceId) {
  const sources = sourcesTableRef();
  const { rows } = await query(
    `
      SELECT
        source_id,
        display_name,
        source_type,
        collector_id,
        location,
        description,
        include_in_total
      FROM ${sources}
      WHERE source_id = {source_id:String}
      LIMIT 1
    `,
    { source_id: String(sourceId) },
    { name: 'refs/flow-sources-get' },
  );
  if (!rows.length) return null;
  const r = rows[0];
  return {
    source_id: String(r.source_id ?? ''),
    display_name: String(r.display_name ?? ''),
    source_type: String(r.source_type ?? ''),
    collector_id: String(r.collector_id ?? ''),
    location: String(r.location ?? ''),
    description: String(r.description ?? ''),
    include_in_total: Number(r.include_in_total) === 1 ? 1 : 0,
  };
}

async function assertCollectorExists(collectorId) {
  const id = String(collectorId ?? '').trim();
  if (!id) return;
  const collectors = collectorsViewRef();
  const { rows } = await query(
    `
      SELECT collector_id
      FROM ${collectors}
      WHERE collector_id = {collector_id:String}
      LIMIT 1
    `,
    { collector_id: id },
    { name: 'refs/flow-sources-collector-check' },
  );
  if (!rows.length) {
    const err = new Error(`Коллектор «${id}» не найден или отключён`);
    err.statusCode = 400;
    throw err;
  }
}

async function bindFlowSource(body, options = {}) {
  const sourceId = String(body?.sourceId ?? body?.source_id ?? '').trim();
  const collectorId = String(body?.collectorId ?? body?.collector_id ?? '').trim();
  if (!sourceId) {
    const err = new Error('Не указан source_id');
    err.statusCode = 400;
    throw err;
  }
  const knownCollectorIds = options.knownCollectorIds || new Set();
  if (collectorId && !knownCollectorIds.has(collectorId)) {
    await assertCollectorExists(collectorId);
  }

  const existing = await getFlowSource(sourceId);
  if (!existing) {
    const err = new Error(`Источник «${sourceId}» не найден в каталоге. Сначала зарегистрируйте его.`);
    err.statusCode = 404;
    throw err;
  }

  const record = {
    source_id: existing.source_id,
    display_name: existing.display_name,
    source_type: existing.source_type,
    collector_id: collectorId,
    location: existing.location,
    description: existing.description,
    include_in_total: existing.include_in_total,
    enabled: 1,
  };

  const { elapsedMs } = await insertRows(config.flowSourcesTable, [record], {
    name: 'refs/flow-sources-bind',
  });

  return { elapsedMs, sourceId, collectorId };
}

async function registerFlowSource(body) {
  const sourceId = String(body?.sourceId ?? body?.source_id ?? '').trim();
  if (!sourceId) {
    const err = new Error('Не указан source_id');
    err.statusCode = 400;
    throw err;
  }

  const collectorId = String(body?.collectorId ?? body?.collector_id ?? '').trim();
  if (collectorId) await assertCollectorExists(collectorId);

  const existing = await getFlowSource(sourceId);
  if (existing) {
    return bindFlowSource({ sourceId, collectorId: collectorId || existing.collector_id });
  }

  const displayName = String(body?.displayName ?? body?.display_name ?? sourceId).trim();
  const sourceType = String(body?.sourceType ?? body?.source_type ?? 'manual').trim();
  let includeInTotal = Number(body?.includeInTotal ?? body?.include_in_total);
  if (includeInTotal !== 0 && includeInTotal !== 1) includeInTotal = 1;

  const record = {
    source_id: sourceId,
    display_name: displayName,
    source_type: sourceType,
    collector_id: collectorId,
    location: String(body?.location ?? '').trim(),
    description: String(body?.description ?? '').trim(),
    include_in_total: includeInTotal,
    enabled: 1,
  };

  const { elapsedMs } = await insertRows(config.flowSourcesTable, [record], {
    name: 'refs/flow-sources-register',
  });

  return { elapsedMs, sourceId, collectorId, created: true };
}

async function deleteFlowSource(body) {
  const sourceId = String(body?.sourceId ?? body?.source_id ?? '').trim();
  if (!sourceId) {
    const err = new Error('Не указан source_id');
    err.statusCode = 400;
    throw err;
  }

  const existing = await getFlowSource(sourceId);
  if (!existing) {
    const err = new Error(`Экспортёр «${sourceId}» не найден в каталоге`);
    err.statusCode = 404;
    throw err;
  }

  const record = {
    source_id: existing.source_id,
    display_name: existing.display_name,
    source_type: existing.source_type,
    collector_id: existing.collector_id,
    location: existing.location,
    description: existing.description,
    include_in_total: existing.include_in_total,
    enabled: 0,
  };

  const { elapsedMs } = await insertRows(config.flowSourcesTable, [record], {
    name: 'refs/flow-sources-delete',
  });

  return { elapsedMs, sourceId };
}

module.exports = {
  listFlowSources,
  getFlowSource,
  bindFlowSource,
  registerFlowSource,
  deleteFlowSource,
};
