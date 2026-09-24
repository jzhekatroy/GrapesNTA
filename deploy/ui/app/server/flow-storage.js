'use strict';

const {
  config,
  query,
  executeCommand,
} = require('./clickhouse');
const { summarizeDisks } = require('./ttl-management');

const SETTINGS_TABLE = 'app_flow_storage_settings';
const LOG_TABLE = 'flow_thinning_log';
const ADMIN_ROLE_ID = 'Administrator';
const RATES = [4, 16, 64, 256];
const MODES = ['off', 'on'];
const MIN_THRESHOLD_BYTES = 1000;
const MAX_DAYS = 3650;

// Единственный замер: xdpflowd, 1:64, порог 100 КБ, копия суток m61 23 сентября.
// 151 ГиБ стали 4.5 ГиБ, суммы за сутки разошлись на 0.002%.
const MEASURED_SHRINK = { '64:100000': 34 };
const MEASURED_NOTE = {
  '64:100000': 'суммы за сутки ±0,002%, за 5 минут у крупных абонентов до 0,5% (замер 24.09.2026)',
};

const DEFAULTS = {
  mode: 'off',
  hotDays: 1,
  xdpRate: 64,
  xdpThresholdBytes: 100000,
  runAt: '04:30',
};

function measuredNote(rate, thresholdBytes) {
  return MEASURED_NOTE[`${Number(rate)}:${Number(thresholdBytes)}`] || 'не замерено';
}

function forecastStorage({ exactBytes = 0, ttlDays = 0, hotDays = 1, rate, thresholdBytes, averagedBytes = 0 } = {}) {
  const kept = Math.max(0, Number(ttlDays) || 0);
  const exactDays = Math.min(kept, Math.max(0, Number(hotDays) || 0) + 1);
  const warmDays = Math.max(0, kept - exactDays);
  const exact = Math.max(0, Number(exactBytes) || 0);
  let thinnedBytes = Number(averagedBytes) > 0 ? Math.round(Number(averagedBytes)) : null;
  if (thinnedBytes == null) {
    const shrink = MEASURED_SHRINK[`${Number(rate)}:${Number(thresholdBytes)}`];
    if (shrink && exact > 0) thinnedBytes = Math.round(exact / shrink);
  }
  const totalBytes = thinnedBytes == null ? null : exact * exactDays + thinnedBytes * warmDays;
  return {
    exactDays,
    warmDays,
    exactBytes: exact,
    thinnedBytes,
    totalBytes,
    measured: Boolean(MEASURED_NOTE[`${Number(rate)}:${Number(thresholdBytes)}`]),
    note: measuredNote(rate, thresholdBytes),
  };
}

function validateSettings(body = {}) {
  const mode = String(body.mode ?? DEFAULTS.mode);
  const hotDays = Number(body.hotDays);
  const xdpRate = Number(body.xdpRate);
  const xdpThresholdBytes = Number(body.xdpThresholdBytes);
  const runAt = String(body.runAt ?? '').trim();
  if (!MODES.includes(mode)) {
    return { error: 'Режим: выключено или включено' };
  }
  if (!Number.isInteger(hotDays) || hotDays < 1 || hotDays > MAX_DAYS) {
    return { error: `Точный срок — целое число дней от 1 до ${MAX_DAYS}` };
  }
  if (!RATES.includes(xdpRate)) {
    return { error: 'Частота xdpflowd: 1:4, 1:16, 1:64 или 1:256' };
  }
  if (!Number.isInteger(xdpThresholdBytes) || xdpThresholdBytes < MIN_THRESHOLD_BYTES) {
    return { error: 'Порог xdpflowd — не меньше 1 КБ' };
  }
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(runAt)) {
    return { error: 'Время запуска — ЧЧ:ММ' };
  }
  return { value: { mode, hotDays, xdpRate, xdpThresholdBytes, runAt } };
}

function assertAdministrator(roleId) {
  if (String(roleId ?? '') !== ADMIN_ROLE_ID) {
    const err = new Error('Изменение хранения доступно только администратору');
    err.statusCode = 403;
    throw err;
  }
}

function mapSettings(row) {
  if (!row) return { ...DEFAULTS, updatedAt: null, updatedBy: '' };
  return {
    mode: row.mode === 'dry_run' || !MODES.includes(row.mode) ? DEFAULTS.mode : row.mode,
    hotDays: Number(row.hot_days) || DEFAULTS.hotDays,
    xdpRate: Number(row.xdp_rate) || DEFAULTS.xdpRate,
    xdpThresholdBytes: Number(row.xdp_threshold_bytes) || DEFAULTS.xdpThresholdBytes,
    runAt: row.run_at || DEFAULTS.runAt,
    updatedAt: row.updated_at || null,
    updatedBy: row.updated_by || '',
  };
}

async function tableExists(name) {
  const { rows } = await query(
    `
      SELECT count() AS n
      FROM system.tables
      WHERE database = {db:String} AND name = {table:String}
    `,
    { db: config.database, table: name },
    { name: 'admin/flow-storage-exists', useWrite: true },
  );
  return Number(rows[0]?.n) > 0;
}

async function loadSettingsRow() {
  const { rows } = await query(
    `
      SELECT mode, hot_days, xdp_rate, xdp_threshold_bytes, run_at, updated_by, updated_at
      FROM ${config.database}.${SETTINGS_TABLE} FINAL
      WHERE settings_id = 'global'
      LIMIT 1
    `,
    {},
    { name: 'admin/flow-storage-settings', useWrite: true },
  );
  return rows[0] || null;
}

async function loadLog() {
  const { rows } = await query(
    `
      SELECT day, status, mode, rate, threshold_bytes,
             rows_before, bytes_before, rows_after, bytes_after, eligible_rows,
             message, toString(started_at) AS started_at, toString(finished_at) AS finished_at
      FROM
      (
        SELECT *
        FROM ${config.database}.${LOG_TABLE}
        ORDER BY day, updated_at DESC
        LIMIT 1 BY day
      )
      ORDER BY day DESC
      LIMIT 10
    `,
    {},
    { name: 'admin/flow-storage-log', useWrite: true },
  );
  return rows.map((row) => ({
    day: row.day,
    status: row.status,
    mode: row.mode,
    rate: Number(row.rate) || 0,
    thresholdBytes: Number(row.threshold_bytes) || 0,
    rowsBefore: Number(row.rows_before) || 0,
    bytesBefore: Number(row.bytes_before) || 0,
    rowsAfter: Number(row.rows_after) || 0,
    bytesAfter: Number(row.bytes_after) || 0,
    eligibleRows: Number(row.eligible_rows) || 0,
    message: row.message || '',
    startedAt: row.started_at || null,
    finishedAt: row.finished_at && row.finished_at !== '1970-01-01 00:00:00' ? row.finished_at : null,
  }));
}

async function loadDisk() {
  try {
    const { rows } = await query(
      `SELECT name, type, total_space, free_space FROM system.disks`,
      {},
      { name: 'admin/flow-storage-disks', useWrite: true },
    );
    return summarizeDisks(rows);
  } catch {
    try {
      const { rows } = await query(
        `SELECT name, total_space, free_space FROM system.disks`,
        {},
        { name: 'admin/flow-storage-disks-compat', useWrite: true },
      );
      return summarizeDisks(rows);
    } catch {
      return null;
    }
  }
}

async function loadFlows() {
  const table = config.flowsRawWriteTable;
  const [meta, parts, disk] = await Promise.all([
    query(
      `
        SELECT engine_full, total_bytes
        FROM system.tables
        WHERE database = {db:String} AND name = {table:String}
        LIMIT 1
      `,
      { db: config.database, table },
      { name: 'admin/flow-storage-ttl', useWrite: true },
    ),
    query(
      `
        SELECT partition, sum(bytes_on_disk) AS bytes
        FROM system.parts
        WHERE active AND database = {db:String} AND table = {table:String}
          AND partition < toString(today())
        GROUP BY partition
        ORDER BY partition DESC
        LIMIT 1
      `,
      { db: config.database, table },
      { name: 'admin/flow-storage-day', useWrite: true },
    ),
    loadDisk(),
  ]);
  const engine = String(meta.rows[0]?.engine_full || '');
  const ttlMatch = engine.match(/toIntervalDay\((\d+)\)/i) || engine.match(/INTERVAL\s+(\d+)\s+DAY/i);
  return {
    table,
    ttlDays: ttlMatch ? Number(ttlMatch[1]) : null,
    totalBytes: Number(meta.rows[0]?.total_bytes) || 0,
    exactBytes: Number(parts.rows[0]?.bytes) || 0,
    exactDay: parts.rows[0]?.partition || null,
    disk,
  };
}

async function averagedThinnedBytes() {
  const { rows } = await query(
    `
      SELECT avg(bytes_after) AS bytes
      FROM
      (
        SELECT bytes_after
        FROM ${config.database}.${LOG_TABLE}
        WHERE status = 'done' AND bytes_after > 0
        ORDER BY day, updated_at DESC
        LIMIT 1 BY day
        LIMIT 14
      )
    `,
    {},
    { name: 'admin/flow-storage-avg', useWrite: true },
  );
  return Number(rows[0]?.bytes) || 0;
}

function withForecast(settings, flows, averagedBytes) {
  const forecast = forecastStorage({
    exactBytes: flows.exactBytes,
    ttlDays: flows.ttlDays || 0,
    hotDays: settings.hotDays,
    rate: settings.xdpRate,
    thresholdBytes: settings.xdpThresholdBytes,
    averagedBytes,
  });
  const room = flows.disk ? flows.disk.freeBytes + flows.totalBytes : null;
  return {
    ...forecast,
    roomBytes: room,
    fits: forecast.totalBytes == null || room == null ? null : forecast.totalBytes <= room,
  };
}

async function getFlowStorage() {
  const ready = await tableExists(SETTINGS_TABLE);
  const [settingsRow, flows] = await Promise.all([
    ready ? loadSettingsRow() : null,
    loadFlows(),
  ]);
  const settings = mapSettings(settingsRow);
  const logReady = await tableExists(LOG_TABLE);
  const [log, averagedBytes] = logReady
    ? await Promise.all([loadLog(), averagedThinnedBytes()])
    : [[], 0];
  return {
    schemaReady: ready && logReady,
    settings,
    rates: RATES,
    flows,
    forecast: withForecast(settings, flows, averagedBytes),
    log,
    untouched: 'NetFlow и sFlow не прореживаются и хранятся точно весь срок',
  };
}

async function saveFlowStorage(body, { roleId, actor } = {}) {
  assertAdministrator(roleId);
  if (!await tableExists(SETTINGS_TABLE)) {
    const err = new Error('Таблица настроек ещё не создана. Сначала выложите схему.');
    err.statusCode = 409;
    throw err;
  }
  const parsed = validateSettings(body);
  if (parsed.error) {
    const err = new Error(parsed.error);
    err.statusCode = 400;
    throw err;
  }
  const next = parsed.value;
  await executeCommand(
    `
      INSERT INTO ${config.database}.${SETTINGS_TABLE}
        (settings_id, mode, hot_days, xdp_rate, xdp_threshold_bytes, run_at, updated_by, updated_at)
      VALUES
        ('global', {mode:String}, {hotDays:UInt16}, {xdpRate:UInt16}, {threshold:UInt64},
         {runAt:String}, {actor:String}, now())
    `,
    {
      mode: next.mode,
      hotDays: next.hotDays,
      xdpRate: next.xdpRate,
      threshold: next.xdpThresholdBytes,
      runAt: next.runAt,
      actor: String(actor || '').slice(0, 200),
    },
    { name: 'admin/flow-storage-save' },
  );
  return { ok: true, settings: next };
}

module.exports = {
  RATES,
  MODES,
  DEFAULTS,
  measuredNote,
  forecastStorage,
  validateSettings,
  getFlowStorage,
  saveFlowStorage,
};
