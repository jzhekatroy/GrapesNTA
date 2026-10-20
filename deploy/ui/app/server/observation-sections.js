const {
  config,
  query,
  insertRows,
  executeCommand,
  observationSectionsTableRef,
  observationSectionRolesTableRef,
  observationSectionMapTableRef,
  rolesTableRef,
  formatDateTime64,
} = require('./clickhouse');
const { canAccess } = require('./rbac/permissions');
const { CLIENT_ROLE_ID } = require('./cabinet/constants');

const GENERAL_SECTION_ID = 'general';
const ADMIN_ROLE_ID = 'Administrator';
const SECTION_LEVELS = new Set(['view', 'edit', 'none']);

function newSectionId() {
  return `sec-${Math.random().toString(36).slice(2, 10)}`;
}

function latestSectionsCte() {
  return `
    latest AS (
      SELECT
        id,
        title,
        sort,
        deleted,
        created_at,
        updated_at,
        row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
      FROM ${observationSectionsTableRef()}
    )
  `;
}

function latestSectionRolesCte() {
  return `
    latest AS (
      SELECT
        section_id,
        role_id,
        level,
        updated_at,
        row_number() OVER (PARTITION BY section_id, role_id ORDER BY updated_at DESC) AS rn
      FROM ${observationSectionRolesTableRef()}
    )
  `;
}

function latestSectionMapCte(whereClause = '') {
  return `
    latest AS (
      SELECT
        observation_id,
        section_id,
        updated_at,
        row_number() OVER (PARTITION BY observation_id ORDER BY updated_at DESC) AS rn
      FROM ${observationSectionMapTableRef()}
      ${whereClause}
    )
  `;
}

/** Map row missing or section deleted → general. */
function resolveObservationSectionId(sectionId, deletedSectionIds) {
  const id = String(sectionId || '').trim();
  if (!id) return GENERAL_SECTION_ID;
  if (deletedSectionIds && deletedSectionIds.has(id)) return GENERAL_SECTION_ID;
  return id;
}

/**
 * @param {object} opts
 * @param {string} opts.roleId
 * @param {boolean} opts.hasObservationsAccess
 * @param {string[]} opts.activeSectionIds - non-deleted section ids
 * @param {Record<string, Record<string, string>>} opts.rolesBySection - sectionId → roleId → level
 */
function buildSectionAccess({
  roleId,
  hasObservationsAccess,
  activeSectionIds,
  rolesBySection,
}) {
  if (!hasObservationsAccess) return {};
  const rid = String(roleId || '').trim();
  if (rid === ADMIN_ROLE_ID) {
    return Object.fromEntries(
      (activeSectionIds || []).map((id) => [id, 'edit']),
    );
  }
  const access = {};
  for (const sectionId of activeSectionIds || []) {
    const level = rolesBySection?.[sectionId]?.[rid];
    if (level === 'view' || level === 'edit') access[sectionId] = level;
  }
  return access;
}

function canViewInSection(access, sectionId) {
  const level = access?.[sectionId];
  return level === 'view' || level === 'edit';
}

function canEditInSection(access, sectionId) {
  return access?.[sectionId] === 'edit';
}

function canTransferSection(access, fromSectionId, toSectionId) {
  return canEditInSection(access, fromSectionId) && canEditInSection(access, toSectionId);
}

async function ensureObservationSectionTables() {
  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${observationSectionsTableRef()}
      (
        id String,
        title String,
        sort UInt16,
        deleted UInt8,
        created_at DateTime64(3) DEFAULT now64(3),
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = MergeTree
      ORDER BY id
    `,
    {},
    { name: 'obs-sections/create-sections' },
  );

  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${observationSectionRolesTableRef()}
      (
        section_id String,
        role_id String,
        level LowCardinality(String),
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = MergeTree
      ORDER BY (section_id, role_id)
    `,
    {},
    { name: 'obs-sections/create-section-roles' },
  );

  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${observationSectionMapTableRef()}
      (
        observation_id String,
        section_id String,
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = MergeTree
      ORDER BY observation_id
    `,
    {},
    { name: 'obs-sections/create-section-map' },
  );
}

async function listActiveSections() {
  const { rows } = await query(
    `
      WITH ${latestSectionsCte()}
      SELECT id, title, sort, deleted, created_at, updated_at
      FROM latest
      WHERE rn = 1 AND deleted = 0
      ORDER BY sort ASC, id ASC
    `,
    {},
    { name: 'obs-sections/list-active' },
  );
  return rows.map((r) => ({
    id: String(r.id),
    title: String(r.title),
    sort: Number(r.sort) || 0,
    system: String(r.id) === GENERAL_SECTION_ID,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

async function getSectionById(id) {
  const { rows } = await query(
    `
      WITH ${latestSectionsCte()}
      SELECT id, title, sort, deleted, created_at, updated_at
      FROM latest
      WHERE rn = 1 AND id = {id:String}
      LIMIT 1
    `,
    { id: String(id) },
    { name: 'obs-sections/get-by-id' },
  );
  if (!rows[0]) return null;
  const r = rows[0];
  if (Number(r.deleted) === 1) return null;
  return {
    id: String(r.id),
    title: String(r.title),
    sort: Number(r.sort) || 0,
    system: String(r.id) === GENERAL_SECTION_ID,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function listAllSectionsIncludingDeleted() {
  const { rows } = await query(
    `
      WITH ${latestSectionsCte()}
      SELECT id, title, sort, deleted, created_at, updated_at
      FROM latest
      WHERE rn = 1
      ORDER BY sort ASC, id ASC
    `,
    {},
    { name: 'obs-sections/list-all' },
  );
  return rows.map((r) => ({
    id: String(r.id),
    title: String(r.title),
    sort: Number(r.sort) || 0,
    deleted: Number(r.deleted) === 1,
    system: String(r.id) === GENERAL_SECTION_ID,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

async function deletedSectionIdSet() {
  const all = await listAllSectionsIncludingDeleted();
  return new Set(all.filter((s) => s.deleted).map((s) => s.id));
}

async function loadRolesBySection() {
  const { rows } = await query(
    `
      WITH ${latestSectionRolesCte()}
      SELECT section_id, role_id, level
      FROM latest
      WHERE rn = 1 AND level IN ('view', 'edit')
    `,
    {},
    { name: 'obs-sections/load-section-roles' },
  );
  const out = {};
  for (const r of rows) {
    const sid = String(r.section_id);
    const roleId = String(r.role_id);
    if (!out[sid]) out[sid] = {};
    out[sid][roleId] = String(r.level);
  }
  return out;
}

async function loadSectionRolesForSection(sectionId) {
  const { rows } = await query(
    `
      WITH ${latestSectionRolesCte()}
      SELECT role_id, level
      FROM latest
      WHERE rn = 1 AND section_id = {sectionId:String} AND level IN ('view', 'edit')
    `,
    { sectionId: String(sectionId) },
    { name: 'obs-sections/load-section-roles-one' },
  );
  const roles = {};
  for (const r of rows) {
    roles[String(r.role_id)] = String(r.level);
  }
  return roles;
}

async function listRoleIdsForBootstrap() {
  const { rows } = await query(
    `
      WITH latest AS (
        SELECT id, row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
        FROM ${rolesTableRef()}
      )
      SELECT id FROM latest WHERE rn = 1
    `,
    {},
    { name: 'obs-sections/list-role-ids' },
  );
  return rows.map((r) => String(r.id));
}

async function bootstrapGeneralSection() {
  const { rows } = await query(
    `
      WITH ${latestSectionsCte()}
      SELECT id FROM latest WHERE rn = 1 AND id = {id:String} LIMIT 1
    `,
    { id: GENERAL_SECTION_ID },
    { name: 'obs-sections/has-general' },
  );
  if (rows.length) return false;

  const now = formatDateTime64();
  await insertRows(config.observationSectionsTable, [{
    id: GENERAL_SECTION_ID,
    title: 'Общие',
    sort: 0,
    deleted: 0,
    created_at: now,
    updated_at: now,
  }], { name: 'obs-sections/bootstrap-general' });

  const roleIds = await listRoleIdsForBootstrap();
  const roleRows = roleIds
    .filter((id) => id !== CLIENT_ROLE_ID)
    .map((role_id) => ({
      section_id: GENERAL_SECTION_ID,
      role_id,
      level: 'edit',
      updated_at: now,
    }));
  if (roleRows.length) {
    await insertRows(config.observationSectionRolesTable, roleRows, {
      name: 'obs-sections/bootstrap-general-roles',
    });
  }
  return true;
}

async function loadObservationSectionMap() {
  const deleted = await deletedSectionIdSet();
  const { rows } = await query(
    `
      WITH ${latestSectionMapCte()}
      SELECT observation_id, section_id
      FROM latest
      WHERE rn = 1
    `,
    {},
    { name: 'obs-sections/load-map' },
  );
  const map = {};
  for (const r of rows) {
    const obsId = String(r.observation_id);
    map[obsId] = resolveObservationSectionId(String(r.section_id), deleted);
  }
  return map;
}

async function observationSectionId(observationId, mapCache = null) {
  const map = mapCache || await loadObservationSectionMap();
  return map[String(observationId)] || GENERAL_SECTION_ID;
}

async function countObservationsBySection() {
  const map = await loadObservationSectionMap();
  const counts = {};
  for (const sectionId of Object.values(map)) {
    counts[sectionId] = (counts[sectionId] || 0) + 1;
  }
  return counts;
}

async function countObservationsInSection(sectionId, observationIds = null) {
  const map = await loadObservationSectionMap();
  const target = String(sectionId);
  if (observationIds) {
    return observationIds.filter((id) => (map[id] || GENERAL_SECTION_ID) === target).length;
  }
  return Object.values(map).filter((sid) => sid === target).length;
}

async function sectionAccess(user) {
  const hasObservationsAccess = await canAccess(user, 'observations');
  const sections = await listActiveSections();
  const rolesBySection = await loadRolesBySection();
  return buildSectionAccess({
    roleId: user?.roleId,
    hasObservationsAccess,
    activeSectionIds: sections.map((s) => s.id),
    rolesBySection,
  });
}

async function setObservationSection(observationId, sectionId) {
  const now = formatDateTime64();
  await insertRows(config.observationSectionMapTable, [{
    observation_id: String(observationId),
    section_id: String(sectionId),
    updated_at: now,
  }], { name: 'obs-sections/map-set' });
}

async function moveObservationsToGeneral(fromSectionId) {
  const map = await loadObservationSectionMap();
  const now = formatDateTime64();
  const rows = Object.entries(map)
    .filter(([, sid]) => sid === fromSectionId)
    .map(([observation_id]) => ({
      observation_id,
      section_id: GENERAL_SECTION_ID,
      updated_at: now,
    }));
  if (rows.length) {
    await insertRows(config.observationSectionMapTable, rows, {
      name: 'obs-sections/map-move-general',
    });
  }
  return rows.length;
}

async function listSectionsForUser(user) {
  const access = await sectionAccess(user);
  const sections = await listActiveSections();
  const counts = await countObservationsBySection();
  return sections
    .filter((s) => canViewInSection(access, s.id))
    .map((s) => ({
      id: s.id,
      title: s.title,
      system: s.system,
      level: access[s.id],
      count: counts[s.id] || 0,
    }));
}

async function listSectionsAdmin() {
  const sections = await listActiveSections();
  const counts = await countObservationsBySection();
  const rolesBySection = await loadRolesBySection();
  return sections.map((s) => ({
    id: s.id,
    title: s.title,
    system: s.system,
    sort: s.sort,
    count: counts[s.id] || 0,
    roles: { ...(rolesBySection[s.id] || {}) },
  }));
}

function normalizeTitle(title) {
  return String(title || '').trim();
}

async function titleTaken(title, excludeId = null) {
  const t = normalizeTitle(title);
  if (!t) return false;
  const sections = await listActiveSections();
  return sections.some((s) => s.title.toLowerCase() === t.toLowerCase()
    && String(s.id) !== String(excludeId || ''));
}

async function createSection(title) {
  const t = normalizeTitle(title);
  if (!t) {
    const err = new Error('Укажите название раздела');
    err.status = 400;
    throw err;
  }
  if (await titleTaken(t)) {
    const err = new Error('Раздел с таким названием уже есть');
    err.status = 400;
    throw err;
  }
  const sections = await listActiveSections();
  const maxSort = sections.reduce((m, s) => Math.max(m, s.sort), -1);
  const now = formatDateTime64();
  const id = newSectionId();
  await insertRows(config.observationSectionsTable, [{
    id,
    title: t,
    sort: maxSort + 1,
    deleted: 0,
    created_at: now,
    updated_at: now,
  }], { name: 'obs-sections/create' });
  return getSectionById(id);
}

async function updateSection(id, payload = {}) {
  const existing = await getSectionById(id);
  if (!existing) {
    const err = new Error('Раздел не найден');
    err.status = 404;
    throw err;
  }
  const now = formatDateTime64();
  let title = existing.title;
  if (payload.title !== undefined) {
    const t = normalizeTitle(payload.title);
    if (!t) {
      const err = new Error('Укажите название раздела');
      err.status = 400;
      throw err;
    }
    if (await titleTaken(t, id)) {
      const err = new Error('Раздел с таким названием уже есть');
      err.status = 400;
      throw err;
    }
    title = t;
  }
  let sort = existing.sort;
  if (payload.sort !== undefined) {
    sort = Number(payload.sort);
    if (!Number.isFinite(sort) || sort < 0) sort = existing.sort;
  }
  await insertRows(config.observationSectionsTable, [{
    id: String(id),
    title,
    sort,
    deleted: 0,
    created_at: existing.createdAt,
    updated_at: now,
  }], { name: 'obs-sections/update' });

  if (payload.roles && typeof payload.roles === 'object') {
    await syncSectionRoles(id, payload.roles);
  }
  return getSectionById(id);
}

async function syncSectionRoles(sectionId, rolesPayload) {
  const roleIds = await listRoleIdsForBootstrap();
  const validRoleIds = new Set(roleIds.filter((r) => r !== ADMIN_ROLE_ID));
  const now = formatDateTime64();
  const rows = [];
  for (const roleId of validRoleIds) {
    let level = 'none';
    if (Object.prototype.hasOwnProperty.call(rolesPayload, roleId)) {
      level = String(rolesPayload[roleId] || 'none').toLowerCase();
    }
    if (!SECTION_LEVELS.has(level)) {
      const err = new Error(`Некорректный уровень для роли ${roleId}`);
      err.status = 400;
      throw err;
    }
    rows.push({
      section_id: String(sectionId),
      role_id: roleId,
      level,
      updated_at: now,
    });
  }
  for (const key of Object.keys(rolesPayload)) {
    if (key === ADMIN_ROLE_ID) continue;
    if (!validRoleIds.has(key)) {
      const err = new Error(`Неизвестная роль: ${key}`);
      err.status = 400;
      throw err;
    }
  }
  if (rows.length) {
    await insertRows(config.observationSectionRolesTable, rows, {
      name: 'obs-sections/sync-roles',
    });
  }
}

async function reorderSections(ids) {
  if (!Array.isArray(ids) || !ids.length) {
    const err = new Error('Укажите порядок разделов');
    err.status = 400;
    throw err;
  }
  const active = await listActiveSections();
  const activeIds = new Set(active.map((s) => s.id));
  for (const id of ids) {
    if (!activeIds.has(String(id))) {
      const err = new Error(`Неизвестный раздел: ${id}`);
      err.status = 400;
      throw err;
    }
  }
  if (ids.length !== active.length) {
    const err = new Error('Список разделов должен содержать все разделы');
    err.status = 400;
    throw err;
  }
  const now = formatDateTime64();
  const byId = Object.fromEntries(active.map((s) => [s.id, s]));
  const rows = ids.map((id, index) => ({
    id: String(id),
    title: byId[id].title,
    sort: index,
    deleted: 0,
    created_at: byId[id].createdAt,
    updated_at: now,
  }));
  await insertRows(config.observationSectionsTable, rows, { name: 'obs-sections/reorder' });
  return listSectionsAdmin();
}

async function deleteSection(id) {
  if (String(id) === GENERAL_SECTION_ID) {
    const err = new Error('Системный раздел удалить нельзя');
    err.status = 400;
    throw err;
  }
  const existing = await getSectionById(id);
  if (!existing) {
    const err = new Error('Раздел не найден');
    err.status = 404;
    throw err;
  }
  const moved = await moveObservationsToGeneral(String(id));
  const now = formatDateTime64();
  await insertRows(config.observationSectionsTable, [{
    id: String(id),
    title: existing.title,
    sort: existing.sort,
    deleted: 1,
    created_at: existing.createdAt,
    updated_at: now,
  }], { name: 'obs-sections/delete' });
  return { moved };
}

async function ensureObservationSections() {
  await ensureObservationSectionTables();
  const generalCreated = await bootstrapGeneralSection();
  return { generalCreated };
}

/** Per-request context: access + map + deleted set */
async function createObservationSectionContext(user) {
  const [access, sectionMap, deletedIds] = await Promise.all([
    sectionAccess(user),
    loadObservationSectionMap(),
    deletedSectionIdSet(),
  ]);
  return { access, sectionMap, deletedIds };
}

function sectionIdForObservation(observationId, ctx) {
  const raw = ctx.sectionMap[String(observationId)];
  if (!raw) return GENERAL_SECTION_ID;
  return resolveObservationSectionId(raw, ctx.deletedIds);
}

module.exports = {
  GENERAL_SECTION_ID,
  ADMIN_ROLE_ID,
  resolveObservationSectionId,
  buildSectionAccess,
  canViewInSection,
  canEditInSection,
  canTransferSection,
  ensureObservationSections,
  sectionAccess,
  createObservationSectionContext,
  sectionIdForObservation,
  loadObservationSectionMap,
  observationSectionId,
  setObservationSection,
  listSectionsForUser,
  listSectionsAdmin,
  createSection,
  updateSection,
  reorderSections,
  deleteSection,
  getSectionById,
  loadSectionRolesForSection,
  listActiveSections,
  countObservationsInSection,
};
