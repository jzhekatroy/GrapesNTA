'use strict';

const { CATEGORIES } = require('./erp-piterix-sync');

const SETTINGS_TABLE = 'app_erp_sync_settings';

const DEFAULTS = {
  cronEnabled: 0,
  cat_piter_ix: 1,
  cat_dc: 0,
  cat_bb: 0,
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
  updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
`;

function boolInt(value, fallback) {
  if (value === undefined || value === null) return fallback;
  return value === true || value === 1 || value === '1' ? 1 : 0;
}

function mapSettings(row = {}) {
  const categories = {};
  for (const cat of CATEGORIES) {
    const key = `cat_${cat.id}`;
    categories[cat.id] = Number(row[key] ?? DEFAULTS[key]) === 1;
  }
  return {
    cronEnabled: Number(row.cron_enabled ?? DEFAULTS.cronEnabled) === 1,
    categories,
    catalog: CATEGORIES,
    updatedAt: row.updated_at || null,
  };
}

function enabledCategoryIds(settings) {
  return CATEGORIES
    .map((c) => c.id)
    .filter((id) => settings?.categories?.[id]);
}

async function ensureSettings(db) {
  await db.command(ENSURE_SETTINGS_SQL);
}

async function getSettings(db) {
  await ensureSettings(db);
  const rows = await db.query(`
    SELECT cron_enabled, cat_piter_ix, cat_dc, cat_bb, updated_at
    FROM default.${SETTINGS_TABLE}
    WHERE settings_id = 'global'
    ORDER BY updated_at DESC
    LIMIT 1
  `);
  return mapSettings(rows[0] || {});
}

async function saveSettings(db, body = {}) {
  await ensureSettings(db);
  const current = await getSettings(db);
  const next = {
    cron_enabled: boolInt(body.cronEnabled, current.cronEnabled ? 1 : 0),
    cat_piter_ix: boolInt(body.categories?.piter_ix, current.categories.piter_ix ? 1 : 0),
    cat_dc: boolInt(body.categories?.dc, current.categories.dc ? 1 : 0),
    cat_bb: boolInt(body.categories?.bb, current.categories.bb ? 1 : 0),
  };
  if (!next.cat_piter_ix && !next.cat_dc && !next.cat_bb) {
    const err = new Error('Включите хотя бы одну категорию');
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
  CATEGORIES,
  mapSettings,
  enabledCategoryIds,
  ensureSettings,
  getSettings,
  saveSettings,
};
