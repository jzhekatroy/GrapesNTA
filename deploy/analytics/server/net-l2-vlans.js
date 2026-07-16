const {
  config,
  query,
  insertRows,
  executeCommand,
  l2VlansTableRef,
  l2VlansViewRef,
  vlanTableRef,
  entitiesViewRef,
} = require('./clickhouse');

const VLAN_MIN = 1;
const VLAN_MAX = 4094;

const ATTACHMENT_TYPES = new Set([
  'unknown',
  'customer',
  'uplink',
  'core',
  'peering',
  'ix',
  'internal',
  'transit',
  'management',
]);

const BOUNDARY_TYPES = new Set(['unknown', 'internal', 'external']);

const ATTACHMENT_TYPE_LABELS = {
  unknown: 'Не задано',
  customer: 'Клиент',
  uplink: 'Аплинк',
  core: 'Ядро',
  peering: 'Пиринг',
  ix: 'IX',
  internal: 'Внутренний',
  transit: 'Транзит',
  management: 'Управление',
};

let vlanNameCache = { at: 0, byId: new Map() };
const VLAN_NAME_CACHE_TTL_MS = 60 * 1000;

function mapVlanAdminRow(r) {
  const enabled = Number(r.enabled);
  return {
    vlanId: Number(r.vlan_id) || 0,
    displayName: String(r.display_name ?? ''),
    entityId: String(r.entity_id ?? ''),
    entityName: String(r.entity_name ?? ''),
    attachmentType: String(r.attachment_type ?? 'unknown'),
    boundary: String(r.boundary ?? 'unknown'),
    comment: String(r.comment ?? ''),
    source: String(r.source ?? ''),
    enabled: enabled === 1 ? 1 : 0,
    updatedAt: r.updated_at ?? null,
  };
}

function parseVlanId(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < VLAN_MIN || n > VLAN_MAX) {
    return { ok: false, error: `VLAN ID должен быть числом от ${VLAN_MIN} до ${VLAN_MAX}` };
  }
  return { ok: true, vlanId: n };
}

async function fetchEntityIds() {
  const entitiesTable = entitiesViewRef();
  const { rows } = await query(
    `SELECT entity_id FROM ${entitiesTable}`,
    {},
    { name: 'refs/vlan-entity-ids' },
  );
  return new Set(rows.map((r) => String(r.entity_id)));
}

async function fetchLatestVlan(vlanId) {
  const table = l2VlansTableRef();
  const { rows } = await query(
    `
      SELECT
        vlan_id,
        entity_id,
        attachment_type,
        boundary,
        display_name,
        comment,
        source,
        enabled,
        updated_at
      FROM ${table}
      WHERE vlan_id = {vlan_id:UInt16}
      ORDER BY updated_at DESC
      LIMIT 1
    `,
    { vlan_id: vlanId },
    { name: 'refs/vlan-latest' },
  );
  return rows[0] ? mapVlanAdminRow(rows[0]) : null;
}

/** Admin list: named VLANs joined with entity display names. */
function listVlansAdmin() {
  const vlansView = l2VlansViewRef();
  const entitiesTable = entitiesViewRef();

  return {
    sql: `
      SELECT
        v.vlan_id AS vlan_id,
        v.entity_id AS entity_id,
        e.display_name AS entity_name,
        v.attachment_type AS attachment_type,
        v.boundary AS boundary,
        v.display_name AS display_name,
        v.comment AS comment,
        v.source AS source,
        1 AS enabled,
        v.updated_at AS updated_at
      FROM ${vlansView} AS v
      LEFT JOIN ${entitiesTable} AS e
        ON v.entity_id = e.entity_id
      ORDER BY v.vlan_id
    `,
    params: {},
    map(rows) {
      return rows.map(mapVlanAdminRow);
    },
  };
}

/**
 * VLANs seen in traffic over the recent window that are not yet named.
 * Helps operators quickly fill the reference table.
 */
function listUnnamedVlansSeen({ lookbackHours = 24, limit = 200 } = {}) {
  const vlanTable = vlanTableRef();
  const vlansView = l2VlansViewRef();
  const lim = Math.min(Math.max(Number(limit) || 200, 1), 1000);
  const hours = Math.min(Math.max(Number(lookbackHours) || 24, 1), 24 * 30);

  return {
    sql: `
      SELECT
        t.vlan_id AS vlan_id,
        sum(t.bytes) AS bytes,
        sum(t.flows_count) AS flows
      FROM ${vlanTable} AS t
      LEFT JOIN ${vlansView} AS v ON t.vlan_id = v.vlan_id
      WHERE t.minute >= now() - INTERVAL {hours:UInt32} HOUR
        AND t.vlan_id != 0
        AND v.vlan_id = 0
      GROUP BY t.vlan_id
      ORDER BY bytes DESC
      LIMIT {limit:UInt32}
    `,
    params: { hours, limit: lim },
    map(rows) {
      return rows.map((r) => ({
        vlanId: Number(r.vlan_id) || 0,
        bytes: Number(r.bytes) || 0,
        flows: Number(r.flows) || 0,
      }));
    },
  };
}

async function validateVlanPayload(body, { requireActiveFields = true } = {}) {
  const parsed = parseVlanId(body?.vlanId ?? body?.vlan_id);
  if (!parsed.ok) return parsed;

  let enabled = Number(body?.enabled);
  if (enabled !== 0 && enabled !== 1) enabled = 1;

  const displayName = String(body?.displayName ?? body?.display_name ?? '').trim();
  const entityId = String(body?.entityId ?? body?.entity_id ?? '').trim();

  let attachmentType = String(body?.attachmentType ?? body?.attachment_type ?? 'unknown').trim();
  if (!ATTACHMENT_TYPES.has(attachmentType)) attachmentType = 'unknown';

  let boundary = String(body?.boundary ?? 'unknown').trim();
  if (!BOUNDARY_TYPES.has(boundary)) boundary = 'unknown';

  if (requireActiveFields && enabled === 1) {
    if (!displayName) return { ok: false, error: 'Укажите название VLAN' };
    if (entityId) {
      const entityIds = await fetchEntityIds();
      if (!entityIds.has(entityId)) {
        return { ok: false, error: 'Выбранный владелец не найден в справочнике объектов' };
      }
    }
  }

  return {
    ok: true,
    record: {
      vlan_id: parsed.vlanId,
      entity_id: entityId,
      attachment_type: attachmentType,
      boundary,
      display_name: displayName,
      comment: String(body?.comment ?? '').trim(),
      enabled,
      source: 'webui',
    },
  };
}

async function saveVlan(body) {
  const validation = await validateVlanPayload(body, { requireActiveFields: true });
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  const { record } = validation;
  const { elapsedMs } = await insertRows(config.l2VlansTable, [record], {
    name: 'refs/vlan-insert',
  });
  vlanNameCache = { at: 0, byId: new Map() };

  return { elapsedMs, vlanId: record.vlan_id };
}

async function setVlanEnabled(body) {
  const parsed = parseVlanId(body?.vlanId ?? body?.vlan_id);
  if (!parsed.ok) {
    const err = new Error(parsed.error);
    err.statusCode = 400;
    throw err;
  }

  const latest = await fetchLatestVlan(parsed.vlanId);
  if (!latest) {
    const err = new Error('VLAN не найден');
    err.statusCode = 404;
    throw err;
  }

  let nextEnabled = Number(body?.enabled);
  if (nextEnabled !== 0 && nextEnabled !== 1) {
    nextEnabled = latest.enabled ? 0 : 1;
  }

  const record = {
    vlan_id: latest.vlanId,
    entity_id: latest.entityId,
    attachment_type: latest.attachmentType,
    boundary: latest.boundary,
    display_name: latest.displayName,
    comment: latest.comment,
    enabled: nextEnabled,
    source: 'webui',
  };

  const { elapsedMs } = await insertRows(config.l2VlansTable, [record], {
    name: 'refs/vlan-toggle',
  });
  vlanNameCache = { at: 0, byId: new Map() };

  return { elapsedMs, enabled: nextEnabled };
}

async function deleteVlan(body) {
  const parsed = parseVlanId(body?.vlanId ?? body?.vlan_id);
  if (!parsed.ok) {
    const err = new Error(parsed.error);
    err.statusCode = 400;
    throw err;
  }

  const table = l2VlansTableRef();
  const { elapsedMs } = await executeCommand(
    `DELETE FROM ${table} WHERE vlan_id = {vlan_id:UInt16}`,
    { vlan_id: parsed.vlanId },
    { name: 'refs/vlan-delete' },
  );
  vlanNameCache = { at: 0, byId: new Map() };

  return { elapsedMs };
}

/** Cached vlan_id -> {displayName, attachmentType, boundary, entityId} for enrichment. */
async function getVlanNameMap() {
  const now = Date.now();
  if (now - vlanNameCache.at < VLAN_NAME_CACHE_TTL_MS && vlanNameCache.byId.size >= 0) {
    if (vlanNameCache.at !== 0) return vlanNameCache.byId;
  }
  const vlansView = l2VlansViewRef();
  try {
    const { rows } = await query(
      `
        SELECT vlan_id, display_name, attachment_type, boundary, entity_id
        FROM ${vlansView}
      `,
      {},
      { name: 'refs/vlan-name-map' },
    );
    const byId = new Map();
    for (const r of rows) {
      byId.set(Number(r.vlan_id) || 0, {
        displayName: String(r.display_name ?? ''),
        attachmentType: String(r.attachment_type ?? 'unknown'),
        boundary: String(r.boundary ?? 'unknown'),
        entityId: String(r.entity_id ?? ''),
      });
    }
    vlanNameCache = { at: now, byId };
    return byId;
  } catch {
    return vlanNameCache.byId;
  }
}

function vlanLabel(vlanId, nameMap) {
  const id = Number(vlanId) || 0;
  if (!id) return 'VLAN —';
  const info = nameMap && nameMap.get(id);
  return info && info.displayName ? `VLAN ${id} · ${info.displayName}` : `VLAN ${id}`;
}

module.exports = {
  VLAN_MIN,
  VLAN_MAX,
  ATTACHMENT_TYPES,
  ATTACHMENT_TYPE_LABELS,
  BOUNDARY_TYPES,
  listVlansAdmin,
  listUnnamedVlansSeen,
  validateVlanPayload,
  saveVlan,
  setVlanEnabled,
  deleteVlan,
  getVlanNameMap,
  vlanLabel,
};
