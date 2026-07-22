const {
  config,
  query,
  insertRows,
  entitiesViewRef,
} = require('./clickhouse');

const ENTITY_TYPES = new Set(['isp', 'customer', 'internal']);

const ENTITY_TYPE_LABELS = {
  isp: 'Провайдер',
  customer: 'Клиент',
  internal: 'Внутренний объект',
};

const CYRILLIC_TO_LATIN = {
  а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'e', ж: 'zh', з: 'z',
  и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r',
  с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'ts', ч: 'ch', ш: 'sh',
  щ: 'sch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya',
};

function transliterateChar(ch) {
  const lower = ch.toLowerCase();
  if (CYRILLIC_TO_LATIN[lower] !== undefined) return CYRILLIC_TO_LATIN[lower];
  return lower;
}

function buildEntitySlug(displayName) {
  const raw = String(displayName ?? '').trim();
  if (!raw) return '';

  let out = '';
  for (const ch of raw) {
    if (/\s/.test(ch)) {
      out += '-';
      continue;
    }
    const mapped = transliterateChar(ch);
    if (/[a-z0-9]/.test(mapped)) out += mapped;
    else if (mapped === '-') out += '-';
  }

  return out
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function buildEntityId(ownerType, displayName) {
  const prefix = String(ownerType ?? '').trim();
  if (!ENTITY_TYPES.has(prefix)) {
    return { ok: false, error: 'Выберите тип владельца' };
  }

  const slug = buildEntitySlug(displayName);
  if (!slug) {
    return { ok: false, error: 'Не удалось сформировать идентификатор из названия' };
  }

  const entityId = `${prefix}:${slug}`;
  if (!/^(isp|customer|internal):[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entityId)) {
    return { ok: false, error: 'Сформированный entity_id не соответствует формату prefix:slug' };
  }

  return { ok: true, entityId };
}

function mapEntityAdminRow(r) {
  return {
    entityId: String(r.entity_id ?? ''),
    displayName: String(r.display_name ?? ''),
    comment: String(r.comment ?? ''),
    source: String(r.source ?? ''),
    updatedAt: r.updated_at ?? null,
  };
}

function ownerTypeFromEntityId(entityId) {
  const idx = String(entityId).indexOf(':');
  if (idx < 0) return null;
  const prefix = entityId.slice(0, idx);
  return ENTITY_TYPES.has(prefix) ? prefix : null;
}

async function fetchActiveEntityIds() {
  const entitiesView = entitiesViewRef();
  const { rows } = await query(
    `
      SELECT entity_id
      FROM ${entitiesView}
    `,
    {},
    { name: 'refs/net-entities-ids' },
  );
  return new Set(rows.map((r) => String(r.entity_id)));
}

function listNetEntitiesAdmin() {
  const entitiesView = entitiesViewRef();

  return {
    sql: `
      SELECT
        entity_id,
        display_name,
        comment,
        source,
        updated_at
      FROM ${entitiesView}
      ORDER BY display_name
    `,
    params: {},
    map(rows) {
      return rows.map(mapEntityAdminRow);
    },
  };
}

async function validateNetEntityPayload(body, { isNew } = {}) {
  const displayName = String(body?.displayName ?? body?.display_name ?? '').trim();
  if (!displayName) return { ok: false, error: 'Укажите название владельца' };

  let enabled = Number(body?.enabled);
  if (enabled !== 0 && enabled !== 1) enabled = 1;

  if (isNew) {
    const ownerType = String(body?.ownerType ?? body?.owner_type ?? '').trim();
    const built = buildEntityId(ownerType, displayName);
    if (!built.ok) return built;

    const activeIds = await fetchActiveEntityIds();
    if (activeIds.has(built.entityId)) {
      return { ok: false, error: `Владелец с идентификатором ${built.entityId} уже существует` };
    }

    return {
      ok: true,
      record: {
        entity_id: built.entityId,
        display_name: displayName,
        comment: String(body?.comment ?? '').trim(),
        enabled: 1,
        source: 'webui',
      },
    };
  }

  const entityId = String(body?.entityId ?? body?.entity_id ?? '').trim();
  if (!entityId) return { ok: false, error: 'Не указан entity_id' };

  const ownerType = ownerTypeFromEntityId(entityId);
  if (!ownerType) {
    return { ok: false, error: 'Некорректный entity_id' };
  }

  const activeIds = await fetchActiveEntityIds();
  if (enabled === 1 && !activeIds.has(entityId)) {
    return { ok: false, error: 'Владелец не найден или уже отключён' };
  }

  if (enabled === 0) {
    if (!activeIds.has(entityId)) {
      return { ok: false, error: 'Владелец не найден или уже отключён' };
    }
  }

  return {
    ok: true,
    record: {
      entity_id: entityId,
      display_name: displayName,
      comment: String(body?.comment ?? '').trim(),
      enabled,
      source: 'webui',
    },
  };
}

async function saveNetEntity(body) {
  const entityId = String(body?.entityId ?? body?.entity_id ?? '').trim();
  const isNew = !entityId;

  const validation = await validateNetEntityPayload(body, { isNew });
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  const { record } = validation;
  const { elapsedMs } = await insertRows(config.entitiesTable, [record], {
    name: 'refs/net-entities-insert',
  });

  return { elapsedMs, entityId: record.entity_id };
}

module.exports = {
  ENTITY_TYPES,
  ENTITY_TYPE_LABELS,
  buildEntitySlug,
  buildEntityId,
  ownerTypeFromEntityId,
  listNetEntitiesAdmin,
  validateNetEntityPayload,
  saveNetEntity,
};
