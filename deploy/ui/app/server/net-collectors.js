const {
  config,
  query,
  insertRows,
  collectorsViewRef,
  locationsViewRef,
  sourcesTableRef,
} = require('./clickhouse');
const { bindFlowSource } = require('./net-flow-sources');

const ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function mapCollectorRow(r) {
  return {
    collectorId: String(r.collector_id ?? ''),
    displayName: String(r.display_name ?? r.collector_name ?? ''),
    hostname: String(r.hostname ?? ''),
    comment: String(r.comment ?? ''),
    locationId: String(r.location_id ?? ''),
    locationName: String(r.location_name ?? ''),
    updatedAt: r.updated_at ?? null,
  };
}

async function fetchActiveCollectorIds() {
  const collectorsView = collectorsViewRef();
  const { rows } = await query(
    `
      SELECT collector_id
      FROM ${collectorsView}
    `,
    {},
    { name: 'refs/collectors-ids' },
  );
  return new Set(rows.map((r) => String(r.collector_id)));
}

async function fetchActiveLocationIds() {
  const locationsView = locationsViewRef();
  const { rows } = await query(
    `
      SELECT location_id
      FROM ${locationsView}
    `,
    {},
    { name: 'refs/collectors-location-ids' },
  );
  return new Set(rows.map((r) => String(r.location_id)));
}

async function countSourcesForCollector(collectorId) {
  const sourcesTable = sourcesTableRef();
  const { rows } = await query(
    `
      SELECT count() AS cnt
      FROM ${sourcesTable}
      WHERE collector_id = {collector_id:String}
    `,
    { collector_id: collectorId },
    { name: 'refs/collectors-source-count' },
  );
  return Number(rows[0]?.cnt ?? 0);
}

async function fetchSourceIdsForCollector(collectorId) {
  const sourcesTable = sourcesTableRef();
  const { rows } = await query(
    `
      SELECT source_id
      FROM ${sourcesTable}
      WHERE collector_id = {collector_id:String}
      ORDER BY source_id
    `,
    { collector_id: collectorId },
    { name: 'refs/collectors-source-ids' },
  );
  return rows.map((r) => String(r.source_id ?? ''));
}

async function fetchActiveCollector(collectorId) {
  const collectorsView = collectorsViewRef();
  const { rows } = await query(
    `
      SELECT
        collector_id,
        display_name,
        hostname,
        comment,
        location_id
      FROM ${collectorsView}
      WHERE collector_id = {collector_id:String}
      LIMIT 1
    `,
    { collector_id: collectorId },
    { name: 'refs/collectors-get' },
  );
  if (!rows.length) return null;
  const r = rows[0];
  return {
    collector_id: String(r.collector_id ?? ''),
    display_name: String(r.display_name ?? ''),
    hostname: String(r.hostname ?? ''),
    comment: String(r.comment ?? ''),
    location_id: String(r.location_id ?? ''),
  };
}

function listCollectorsAdmin() {
  const collectorsView = collectorsViewRef();
  const locationsView = locationsViewRef();

  return {
    sql: `
      SELECT
        c.collector_id,
        c.display_name,
        c.hostname,
        c.comment,
        c.location_id,
        l.display_name AS location_name,
        c.updated_at
      FROM ${collectorsView} AS c
      LEFT JOIN ${locationsView} AS l ON c.location_id = l.location_id
      ORDER BY location_name, c.display_name
    `,
    params: {},
    map(rows) {
      return rows.map(mapCollectorRow);
    },
  };
}

async function validateCollectorPayload(body, { isNew } = {}) {
  const displayName = String(body?.displayName ?? body?.display_name ?? '').trim();
  if (!displayName) return { ok: false, error: 'Укажите название коллектора' };

  let enabled = Number(body?.enabled);
  if (enabled !== 0 && enabled !== 1) enabled = 1;

  const hostname = String(body?.hostname ?? '').trim();
  const comment = String(body?.comment ?? '').trim();
  const locationId = String(body?.locationId ?? body?.location_id ?? '').trim();

  if (isNew) {
    const collectorId = String(body?.collectorId ?? body?.collector_id ?? '').trim().toLowerCase();
    if (!collectorId) return { ok: false, error: 'Укажите collector_id' };
    if (!ID_PATTERN.test(collectorId)) {
      return { ok: false, error: 'collector_id: только строчные латинские буквы, цифры и дефис (напр. col-msk-1)' };
    }
    if (!locationId) return { ok: false, error: 'Выберите локацию' };

    const activeLocationIds = await fetchActiveLocationIds();
    if (!activeLocationIds.has(locationId)) {
      return { ok: false, error: 'Локация не найдена или отключена' };
    }

    const activeIds = await fetchActiveCollectorIds();
    if (activeIds.has(collectorId)) {
      return { ok: false, error: `Коллектор с идентификатором ${collectorId} уже существует` };
    }

    return {
      ok: true,
      record: {
        collector_id: collectorId,
        location_id: locationId,
        display_name: displayName,
        hostname,
        comment,
        enabled: 1,
      },
    };
  }

  const collectorId = String(body?.collectorId ?? body?.collector_id ?? '').trim();
  if (!collectorId) return { ok: false, error: 'Не указан collector_id' };
  if (!ID_PATTERN.test(collectorId)) {
    return { ok: false, error: 'Некорректный collector_id' };
  }
  if (!locationId) return { ok: false, error: 'Выберите локацию' };

  const activeLocationIds = await fetchActiveLocationIds();
  if (!activeLocationIds.has(locationId)) {
    return { ok: false, error: 'Локация не найдена или отключена' };
  }

  const activeIds = await fetchActiveCollectorIds();
  if (!activeIds.has(collectorId)) {
    return { ok: false, error: 'Коллектор не найден или уже отключён' };
  }

  if (enabled === 0) {
    const sourceCount = await countSourcesForCollector(collectorId);
    if (sourceCount > 0) {
      return {
        ok: false,
        error: `Нельзя отключить коллектор: к нему привязано экспортёров: ${sourceCount}`,
      };
    }
  }

  return {
    ok: true,
    record: {
      collector_id: collectorId,
      location_id: locationId,
      display_name: displayName,
      hostname,
      comment,
      enabled,
    },
  };
}

function listCollectorsForSelect() {
  const collectorsView = collectorsViewRef();
  const locationsView = locationsViewRef();

  return {
    sql: `
      SELECT
        c.collector_id,
        c.display_name AS collector_name,
        c.hostname,
        c.location_id,
        l.display_name AS location_name,
        concat(
          if(l.display_name = '', 'Без локации', l.display_name),
          ' / ',
          c.display_name,
          if(c.hostname = '', '', concat(' (', c.hostname, ')'))
        ) AS label
      FROM ${collectorsView} AS c
      LEFT JOIN ${locationsView} AS l ON c.location_id = l.location_id
      ORDER BY location_name, collector_name
    `,
    params: {},
    map(rows) {
      return rows.map((r) => ({
        collectorId: String(r.collector_id ?? ''),
        collectorName: String(r.collector_name ?? ''),
        hostname: String(r.hostname ?? ''),
        locationId: String(r.location_id ?? ''),
        locationName: String(r.location_name ?? ''),
        label: String(r.label ?? r.collector_name ?? r.collector_id ?? ''),
      }));
    },
  };
}

async function saveCollector(body) {
  const collectorId = String(body?.collectorId ?? body?.collector_id ?? '').trim().toLowerCase();
  if (!collectorId) {
    const err = new Error('Не указан collector_id');
    err.statusCode = 400;
    throw err;
  }

  const activeIds = await fetchActiveCollectorIds();
  const isNew = !activeIds.has(collectorId);

  const validation = await validateCollectorPayload({ ...body, collectorId }, { isNew });
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  const { record } = validation;
  const { elapsedMs } = await insertRows(config.collectorsTable, [record], {
    name: 'refs/collectors-insert',
  });

  const sourceIds = Array.isArray(body?.sourceIds)
    ? body.sourceIds.map((id) => String(id).trim()).filter(Boolean)
    : [];
  const bindResults = [];
  const bindErrors = [];

  const knownCollectorIds = new Set([record.collector_id]);
  for (const sourceId of sourceIds) {
    try {
      const r = await bindFlowSource(
        { sourceId, collectorId: record.collector_id },
        { knownCollectorIds },
      );
      bindResults.push({ sourceId, ok: true, ...r });
    } catch (err) {
      bindErrors.push({ sourceId, error: err.message });
    }
  }

  return {
    elapsedMs,
    collectorId: record.collector_id,
    boundSources: bindResults.length,
    bindErrors,
  };
}

async function deleteCollector(body) {
  const collectorId = String(body?.collectorId ?? body?.collector_id ?? '').trim();
  const confirmName = String(body?.confirmName ?? body?.confirm_name ?? '').trim();

  if (!collectorId) {
    const err = new Error('Не указан collector_id');
    err.statusCode = 400;
    throw err;
  }
  if (!confirmName) {
    const err = new Error('Введите название коллектора для подтверждения');
    err.statusCode = 400;
    throw err;
  }

  const collector = await fetchActiveCollector(collectorId);
  if (!collector) {
    const err = new Error('Коллектор не найден или уже отключён');
    err.statusCode = 400;
    throw err;
  }

  if (confirmName !== collector.display_name.trim()) {
    const err = new Error('Название не совпадает. Введите точное название коллектора.');
    err.statusCode = 400;
    throw err;
  }

  const sourceIds = await fetchSourceIdsForCollector(collectorId);
  const unbindErrors = [];

  for (const sourceId of sourceIds) {
    try {
      await bindFlowSource({ sourceId, collectorId: '' });
    } catch (err) {
      unbindErrors.push({ sourceId, error: err.message });
    }
  }

  if (unbindErrors.length) {
    const err = new Error(
      `Не удалось отвязать экспортёры: ${unbindErrors.map((e) => e.sourceId).join(', ')}`,
    );
    err.statusCode = 502;
    err.unbindErrors = unbindErrors;
    throw err;
  }

  const { elapsedMs } = await insertRows(config.collectorsTable, [{
    collector_id: collector.collector_id,
    location_id: collector.location_id,
    display_name: collector.display_name,
    hostname: collector.hostname,
    comment: collector.comment,
    enabled: 0,
  }], { name: 'refs/collectors-delete' });

  return {
    elapsedMs,
    collectorId: collector.collector_id,
    unboundSources: sourceIds.length,
  };
}

module.exports = {
  listCollectorsAdmin,
  listCollectorsForSelect,
  validateCollectorPayload,
  saveCollector,
  deleteCollector,
};
