const {
  config,
  query,
  insertRows,
  locationsViewRef,
  collectorsViewRef,
} = require('./clickhouse');

const ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function mapLocationRow(r) {
  return {
    locationId: String(r.location_id ?? ''),
    displayName: String(r.display_name ?? ''),
    city: String(r.city ?? ''),
    country: String(r.country ?? ''),
    comment: String(r.comment ?? ''),
    updatedAt: r.updated_at ?? null,
  };
}

async function fetchActiveLocationIds() {
  const locationsView = locationsViewRef();
  const { rows } = await query(
    `
      SELECT location_id
      FROM ${locationsView}
    `,
    {},
    { name: 'refs/locations-ids' },
  );
  return new Set(rows.map((r) => String(r.location_id)));
}

async function countCollectorsForLocation(locationId) {
  const collectorsView = collectorsViewRef();
  const { rows } = await query(
    `
      SELECT count() AS cnt
      FROM ${collectorsView}
      WHERE location_id = {location_id:String}
    `,
    { location_id: locationId },
    { name: 'refs/locations-collector-count' },
  );
  return Number(rows[0]?.cnt ?? 0);
}

function listLocations() {
  const locationsView = locationsViewRef();

  return {
    sql: `
      SELECT
        location_id,
        display_name,
        city,
        country,
        comment,
        updated_at
      FROM ${locationsView}
      ORDER BY display_name
    `,
    params: {},
    map(rows) {
      return rows.map(mapLocationRow);
    },
  };
}

async function validateLocationPayload(body, { isNew } = {}) {
  const displayName = String(body?.displayName ?? body?.display_name ?? '').trim();
  if (!displayName) return { ok: false, error: 'Укажите название локации' };

  let enabled = Number(body?.enabled);
  if (enabled !== 0 && enabled !== 1) enabled = 1;

  const city = String(body?.city ?? '').trim();
  const country = String(body?.country ?? '').trim();
  const comment = String(body?.comment ?? '').trim();

  if (isNew) {
    const locationId = String(body?.locationId ?? body?.location_id ?? '').trim().toLowerCase();
    if (!locationId) return { ok: false, error: 'Укажите location_id' };
    if (!ID_PATTERN.test(locationId)) {
      return { ok: false, error: 'location_id: только строчные латинские буквы, цифры и дефис (напр. msk-m9)' };
    }

    const activeIds = await fetchActiveLocationIds();
    if (activeIds.has(locationId)) {
      return { ok: false, error: `Локация с идентификатором ${locationId} уже существует` };
    }

    return {
      ok: true,
      record: {
        location_id: locationId,
        display_name: displayName,
        city,
        country,
        comment,
        enabled: 1,
      },
    };
  }

  const locationId = String(body?.locationId ?? body?.location_id ?? '').trim();
  if (!locationId) return { ok: false, error: 'Не указан location_id' };
  if (!ID_PATTERN.test(locationId)) {
    return { ok: false, error: 'Некорректный location_id' };
  }

  const activeIds = await fetchActiveLocationIds();
  if (!activeIds.has(locationId)) {
    return { ok: false, error: 'Локация не найдена или уже отключена' };
  }

  if (enabled === 0) {
    const collectorCount = await countCollectorsForLocation(locationId);
    if (collectorCount > 0) {
      return {
        ok: false,
        error: `Нельзя отключить локацию: к ней привязано коллекторов: ${collectorCount}`,
      };
    }
  }

  return {
    ok: true,
    record: {
      location_id: locationId,
      display_name: displayName,
      city,
      country,
      comment,
      enabled,
    },
  };
}

async function saveLocation(body) {
  const locationId = String(body?.locationId ?? body?.location_id ?? '').trim().toLowerCase();
  if (!locationId) {
    const err = new Error('Не указан location_id');
    err.statusCode = 400;
    throw err;
  }

  const activeIds = await fetchActiveLocationIds();
  const isNew = !activeIds.has(locationId);

  const validation = await validateLocationPayload({ ...body, locationId }, { isNew });
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  const { record } = validation;
  const { elapsedMs } = await insertRows(config.locationsTable, [record], {
    name: 'refs/locations-insert',
  });

  return { elapsedMs, locationId: record.location_id };
}

module.exports = {
  listLocations,
  validateLocationPayload,
  saveLocation,
};
