'use strict';

const { CATEGORIES, PITER_IX_GROUPS, normalizeBindMode } = require('./erp-piterix-sync');

const SETTINGS_TABLE = 'app_erp_sync_settings';

const DEFAULTS = {
  cronEnabled: 0,
  cat_piter_ix: 1,
  cat_dc: 0,
  cat_bb: 0,
  piter_ix_g710: 1,
  piter_ix_g726: 1,
  apiBase: 'https://erp.bth.su',
  apiHost: 'erp.bth.su',
  apiToken: 'aBZFW5bH1tG80pxqon5S0noQXBX1wni0',
  apiInsecure: 1,
  bindMode: 'ports',
  ixEnabled: 0,
  ixMacOnPort: 0,
};

function tableRef(dbName = 'default') {
  return `${dbName}.${SETTINGS_TABLE}`;
}

const ENSURE_SETTINGS_SQL = `
CREATE TABLE IF NOT EXISTS default.${SETTINGS_TABLE}
(
  settings_id String DEFAULT 'global',
  cron_enabled UInt8 DEFAULT 0,
  cat_piter_ix UInt8 DEFAULT 1,
  cat_dc UInt8 DEFAULT 0,
  cat_bb UInt8 DEFAULT 0,
  piter_ix_g710 UInt8 DEFAULT 1,
  piter_ix_g726 UInt8 DEFAULT 1,
  api_base String DEFAULT '${DEFAULTS.apiBase}',
  api_host String DEFAULT '${DEFAULTS.apiHost}',
  api_token String DEFAULT '${DEFAULTS.apiToken}',
  api_insecure UInt8 DEFAULT 1,
  bind_mode LowCardinality(String) DEFAULT 'ports',
  ix_enabled UInt8 DEFAULT 0,
  ix_mac_on_port UInt8 DEFAULT 0,
  updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
`;

const ENSURE_SETTINGS_COLUMNS = [
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS api_base String DEFAULT '${DEFAULTS.apiBase}'`,
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS api_host String DEFAULT '${DEFAULTS.apiHost}'`,
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS api_token String DEFAULT '${DEFAULTS.apiToken}'`,
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS api_insecure UInt8 DEFAULT 1`,
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS bind_mode LowCardinality(String) DEFAULT 'ports'`,
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS piter_ix_g710 UInt8 DEFAULT 1`,
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS piter_ix_g726 UInt8 DEFAULT 1`,
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS ix_enabled UInt8 DEFAULT 0`,
  `ALTER TABLE default.${SETTINGS_TABLE} ADD COLUMN IF NOT EXISTS ix_mac_on_port UInt8 DEFAULT 0`,
];

function boolInt(value, fallback) {
  if (value === undefined || value === null) return fallback;
  return value === true || value === 1 || value === '1' ? 1 : 0;
}

function firstNonEmpty(...values) {
  for (const value of values) {
    const text = value == null ? '' : String(value).trim();
    if (text) return text;
  }
  return '';
}

function piterIxGroupsFromRow(row = {}) {
  const catOn = Number(row.cat_piter_ix ?? DEFAULTS.cat_piter_ix) === 1;
  const stored = row.piter_ix_g710 != null || row.piter_ix_g726 != null;
  if (!stored) return { 710: catOn, 726: catOn };
  return {
    710: Number(row.piter_ix_g710 ?? (catOn ? 1 : 0)) === 1,
    726: Number(row.piter_ix_g726 ?? (catOn ? 1 : 0)) === 1,
  };
}

function mapSettings(row = {}, { includeToken = false } = {}) {
  const categories = {};
  for (const cat of CATEGORIES) {
    const key = `cat_${cat.id}`;
    categories[cat.id] = Number(row[key] ?? DEFAULTS[key]) === 1;
  }
  const piterIxGroups = piterIxGroupsFromRow(row);
  const apiToken = firstNonEmpty(row.api_token, process.env.ERP_API_TOKEN, DEFAULTS.apiToken);
  const mapped = {
    cronEnabled: Number(row.cron_enabled ?? DEFAULTS.cronEnabled) === 1,
    categories,
    piterIxGroups,
    catalog: CATEGORIES,
    apiBase: firstNonEmpty(row.api_base, process.env.ERP_API_BASE, DEFAULTS.apiBase).replace(/\/$/, ''),
    apiHost: firstNonEmpty(row.api_host, process.env.ERP_API_HOST, DEFAULTS.apiHost),
    apiInsecure: Number(row.api_insecure ?? DEFAULTS.apiInsecure) === 1,
    bindMode: normalizeBindMode(row.bind_mode || process.env.ERP_BIND_MODE, DEFAULTS.bindMode),
    ixEnabled: Number(row.ix_enabled ?? DEFAULTS.ixEnabled) === 1,
    ixMacOnPort: Number(row.ix_mac_on_port ?? DEFAULTS.ixMacOnPort) === 1,
    tokenSet: Boolean(apiToken),
    updatedAt: row.updated_at || null,
  };
  if (includeToken) mapped.apiToken = apiToken;
  return mapped;
}

function enabledCategoryIds(settings) {
  return CATEGORIES
    .map((c) => c.id)
    .filter((id) => settings?.categories?.[id]);
}

function resolveErpConfig(settings) {
  const mapped = settings?.apiBase
    ? settings
    : mapSettings({}, { includeToken: true });
  return {
    base: String(mapped.apiBase || DEFAULTS.apiBase).replace(/\/$/, ''),
    host: String(mapped.apiHost || DEFAULTS.apiHost),
    token: String(mapped.apiToken || '').trim(),
    insecure: mapped.apiInsecure !== false,
    pageLimit: Math.min(Math.max(Number(process.env.ERP_API_PAGE_LIMIT) || 20, 1), 500),
  };
}

async function ensureSettings(db) {
  await db.command(ENSURE_SETTINGS_SQL);
  for (const sql of ENSURE_SETTINGS_COLUMNS) {
    await db.command(sql);
  }
}

async function getSettingsRaw(db) {
  await ensureSettings(db);
  const rows = await db.query(`
    SELECT cron_enabled, cat_piter_ix, cat_dc, cat_bb,
           piter_ix_g710, piter_ix_g726,
           api_base, api_host, api_token, api_insecure, bind_mode,
           ix_enabled, ix_mac_on_port, updated_at
    FROM default.${SETTINGS_TABLE}
    WHERE settings_id = 'global'
    ORDER BY updated_at DESC
    LIMIT 1
  `);
  return rows[0] || null;
}

async function getSettings(db, { includeToken = false } = {}) {
  return mapSettings(await getSettingsRaw(db) || {}, { includeToken });
}

async function saveSettings(db, body = {}) {
  const currentRaw = await getSettingsRaw(db);
  const current = mapSettings(currentRaw || {}, { includeToken: true });
  const nextToken = firstNonEmpty(body.apiToken, current.apiToken, DEFAULTS.apiToken);
  const groupsIn = body.piterIxGroups && typeof body.piterIxGroups === 'object'
    ? body.piterIxGroups
    : current.piterIxGroups;
  const next = {
    cron_enabled: boolInt(body.cronEnabled, current.cronEnabled ? 1 : 0),
    cat_piter_ix: boolInt(body.categories?.piter_ix, current.categories.piter_ix ? 1 : 0),
    cat_dc: boolInt(body.categories?.dc, current.categories.dc ? 1 : 0),
    cat_bb: boolInt(body.categories?.bb, current.categories.bb ? 1 : 0),
    piter_ix_g710: boolInt(groupsIn?.[710] ?? groupsIn?.['710'], current.piterIxGroups[710] ? 1 : 0),
    piter_ix_g726: boolInt(groupsIn?.[726] ?? groupsIn?.['726'], current.piterIxGroups[726] ? 1 : 0),
    api_base: firstNonEmpty(body.apiBase, current.apiBase, DEFAULTS.apiBase).replace(/\/$/, ''),
    api_host: firstNonEmpty(body.apiHost, current.apiHost, DEFAULTS.apiHost),
    api_token: nextToken,
    api_insecure: boolInt(body.apiInsecure, current.apiInsecure ? 1 : 0),
    bind_mode: normalizeBindMode(body.bindMode, current.bindMode || DEFAULTS.bindMode),
    ix_enabled: boolInt(body.ixEnabled, current.ixEnabled ? 1 : 0),
    ix_mac_on_port: boolInt(body.ixMacOnPort, current.ixMacOnPort ? 1 : 0),
  };
  if (!next.cat_piter_ix) {
    next.ix_enabled = 0;
    next.ix_mac_on_port = 0;
  }
  if (!next.ix_enabled) next.ix_mac_on_port = 0;
  if (!next.cat_piter_ix && !next.cat_dc && !next.cat_bb) {
    const err = new Error('Включите хотя бы одну категорию');
    err.statusCode = 400;
    throw err;
  }
  if (next.cat_piter_ix && !next.piter_ix_g710 && !next.piter_ix_g726) {
    const err = new Error('Для piter_ix выберите группу 710, 726 или обе');
    err.statusCode = 400;
    throw err;
  }
  if (!next.api_base || !next.api_host || !next.api_token) {
    const err = new Error('Укажите URL, Host и токен ERP');
    err.statusCode = 400;
    throw err;
  }
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  await db.insert(SETTINGS_TABLE, [{
    settings_id: 'global',
    ...next,
    updated_at: now,
  }]);
  return getSettings(db);
}

module.exports = {
  SETTINGS_TABLE,
  ENSURE_SETTINGS_SQL,
  DEFAULTS,
  CATEGORIES,
  PITER_IX_GROUPS,
  piterIxGroupsFromRow,
  mapSettings,
  enabledCategoryIds,
  resolveErpConfig,
  ensureSettings,
  getSettings,
  saveSettings,
};
