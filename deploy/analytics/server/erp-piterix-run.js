'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const net = require('net');
const { URL } = require('url');
const crypto = require('crypto');

try {
  const extraEnv = path.join(__dirname, 'data', 'erp-piterix.env');
  if (fs.existsSync(extraEnv)) {
    require('dotenv').config({ path: extraEnv, override: false });
  }
} catch {
  // optional
}
const {
  SOURCE_TAG,
  CATEGORY,
  CATEGORIES,
  sourceTagFor,
  classifyClients,
  clickhouseDateTime,
  portComment,
  clientsToDisable,
  portsToDisable,
  prefixesToDisable,
  normalizeBindMode,
  summarizeSkipped,
} = require('./erp-piterix-sync');
const {
  ENSURE_SETTINGS_SQL,
  getSettings,
  saveSettings,
  enabledCategoryIds,
  resolveErpConfig,
} = require('./erp-piterix-settings');

const LOG_TABLE = 'erp_piterix_sync_log';
const ENSURE_SQL = [
  `CREATE TABLE IF NOT EXISTS default.net_clients
  (
    client_id LowCardinality(String),
    display_name String,
    comment String DEFAULT '',
    bind_mode LowCardinality(String) DEFAULT 'prefixes',
    enabled UInt8,
    updated_at DateTime DEFAULT now()
  )
  ENGINE = ReplacingMergeTree(updated_at)
  ORDER BY client_id`,
  `CREATE TABLE IF NOT EXISTS default.net_client_ports
  (
    client_id LowCardinality(String),
    switch_ip String,
    if_index UInt32,
    comment String DEFAULT '',
    enabled UInt8,
    updated_at DateTime DEFAULT now()
  )
  ENGINE = ReplacingMergeTree(updated_at)
  ORDER BY (switch_ip, if_index)`,
  `CREATE TABLE IF NOT EXISTS default.net_client_prefixes
  (
    client_id LowCardinality(String),
    prefix String,
    family UInt8,
    enabled UInt8,
    updated_at DateTime DEFAULT now()
  )
  ENGINE = ReplacingMergeTree(updated_at)
  ORDER BY (family, prefix)`,
  `CREATE TABLE IF NOT EXISTS default.${LOG_TABLE}
  (
    run_id String,
    started_at DateTime,
    finished_at DateTime,
    trigger LowCardinality(String),
    full UInt8,
    limit_n UInt32,
    fetched UInt32,
    active UInt32,
    labelable UInt32,
    upserted UInt32,
    ports UInt32,
    disabled UInt32,
    skipped UInt32,
    skipped_json String,
    error String,
    actor String
  )
  ENGINE = MergeTree
  ORDER BY (started_at, run_id)
  TTL started_at + toIntervalDay(180)`,
];

const FIELD_MAP = [
  { erp: 'basic_account', ours: 'net_clients.client_id', note: 'номер ЛС как в биллинге' },
  { erp: 'name', ours: 'net_clients.display_name', note: 'каждую ночь перезаписываем' },
  { erp: 'int_status + block.is_blocked', ours: 'только активные', note: 'int_status=1 и не заблокирован' },
  { erp: 'ips[].ip / ips[].cidr', ours: 'net_client_prefixes.prefix', note: 'режим IP: cidr или адрес как /32' },
  { erp: 'ips[].switch.host', ours: 'net_client_ports.switch_ip', note: 'режим портов: IPv4 коммутатора' },
  { erp: 'ips[].switch.port', ours: 'net_client_ports.if_index', note: 'Huawei ifIndex, не номер на панели' },
  { erp: 'ips[].switch.inven_number + SNMP if_name/if_alias', ours: 'net_client_ports.comment', note: '' },
  { erp: 'category piter_ix|dc|bb', ours: 'net_clients.comment', note: 'erp:<категория>' },
];

let running = null;

function erpConfig(settings) {
  return resolveErpConfig(settings);
}

function httpsGetJson(urlString, { headers = {}, insecure = false } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const req = https.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || 443,
      path: `${url.pathname}${url.search}`,
      method: 'GET',
      headers,
      rejectUnauthorized: !insecure,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`ERP HTTP ${res.statusCode} ${urlString}: ${body.slice(0, 200) || 'пустое тело'}`));
          return;
        }
        try {
          resolve(JSON.parse(body));
        } catch (err) {
          reject(new Error(`ERP: ответ не JSON (${err.message})`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(120000, () => req.destroy(new Error('ERP: timeout')));
    req.end();
  });
}

function erpRequestHeaders(cfg, urlString) {
  const headers = {
    Accept: 'application/json',
    Authorization: `Bearer ${cfg.token}`,
  };
  const hostname = new URL(urlString).hostname;
  if (net.isIP(hostname) && cfg.host) headers.Host = cfg.host;
  return headers;
}

async function fetchErpClients(db, { category = CATEGORY, full = false, fetchCap = 0 } = {}) {
  const cfg = resolveErpConfig(await getSettings(db, { includeToken: true }));
  if (!cfg.token) throw new Error('Нет токена ERP');
  const clients = [];
  let after = '';
  let pageLimit = full ? cfg.pageLimit : Math.min(cfg.pageLimit, 20);
  const maxPages = full
    ? Math.max(80, Math.ceil(15000 / Math.min(pageLimit, 20)))
    : Math.max(8, Math.ceil((fetchCap || 40) / pageLimit) + 2);
  for (let page = 0; page < maxPages; page += 1) {
    const qs = new URLSearchParams({ limit: String(pageLimit) });
    if (after) qs.set('after', after);
    const url = `${cfg.base}/api/v1/clients/by-category/${encodeURIComponent(category)}?${qs}`;
    let payload;
    try {
      payload = await httpsGetJson(url, {
        insecure: cfg.insecure,
        headers: erpRequestHeaders(cfg, url),
      });
    } catch (err) {
      if (/ERP HTTP 500/.test(String(err.message || '')) && pageLimit > 20) {
        pageLimit = 20;
        page -= 1;
        continue;
      }
      throw err;
    }
    const rows = Array.isArray(payload?.data) ? payload.data : [];
    clients.push(...rows);
    const next = payload?.next_after ?? payload?.meta?.next_after ?? '';
    if (!next || !rows.length) break;
    if (fetchCap && clients.length >= fetchCap) break;
    after = String(next);
  }
  return clients;
}

function createModuleAdapter(clickhouse) {
  return {
    async query(sql, params) {
      const { rows } = await clickhouse.query(sql, params, { name: 'erp-piterix' });
      return rows;
    },
    async insert(table, rows) {
      if (!rows.length) return;
      await clickhouse.insertRows(table, rows, { name: 'erp-piterix' });
    },
    async command(sql) {
      await clickhouse.executeCommand(sql, {}, { name: 'erp-piterix' });
    },
  };
}

function createClientAdapter(ch) {
  return {
    async query(sql, params) {
      return (await (await ch.query({
        query: sql,
        query_params: params,
        format: 'JSONEachRow',
      })).json());
    },
    async insert(table, rows) {
      if (!rows.length) return;
      await ch.insert({ table: `default.${table}`, values: rows, format: 'JSONEachRow' });
    },
    async command(sql) {
      await ch.command({ query: sql });
    },
  };
}

async function ensureSchema(db) {
  for (const sql of [...ENSURE_SQL, ENSURE_SETTINGS_SQL]) {
    await db.command(sql);
  }
}

async function loadCatalog(db) {
  const agentRows = await db.query(`
    SELECT switch_ip, display_name, last_poll_status
    FROM default.net_snmp_agents_current
  `);
  const ifaceRowsRaw = await db.query(`
    SELECT switch_ip, if_index, if_name, if_alias
    FROM default.net_interfaces_current
  `);
  return {
    agents: new Map(agentRows.map((r) => [String(r.switch_ip), r])),
    ifaces: new Set(ifaceRowsRaw.map((r) => `${r.switch_ip}:${Number(r.if_index)}`)),
    ifaceRows: new Map(ifaceRowsRaw.map((r) => [`${r.switch_ip}:${Number(r.if_index)}`, r])),
  };
}

async function applySync(db, {
  clients,
  full = false,
  limit = 50,
  trigger = 'cli',
  actor = '',
  category = CATEGORY,
  bindMode = 'ports',
} = {}) {
  await ensureSchema(db);
  const sourceTag = sourceTagFor(category);
  const mode = normalizeBindMode(bindMode);
  const catalog = mode === 'ports' ? await loadCatalog(db) : { agents: new Map(), ifaces: new Set(), ifaceRows: new Map() };
  const classified = classifyClients(clients, catalog, { sourceTag, bindMode: mode });
  const existingRows = await db.query(`
    SELECT client_id
    FROM default.net_clients_enabled
    WHERE comment = {tag:String}
  `, { tag: sourceTag });
  const existing = new Set(existingRows.map((r) => String(r.client_id)));
  const pending = classified.labelable.filter((c) => !existing.has(c.clientId));
  const take = full ? classified.labelable : pending.slice(0, Math.max(0, Number(limit) || 0));
  const now = clickhouseDateTime();

  const clientRows = take.map((c) => ({
    client_id: c.clientId,
    display_name: c.displayName,
    comment: c.comment,
    bind_mode: mode,
    enabled: 1,
    updated_at: now,
  }));
  const portRows = [];
  const prefixRows = [];
  for (const c of take) {
    if (mode === 'prefixes') {
      for (const p of c.prefixes || []) {
        prefixRows.push({
          client_id: c.clientId,
          prefix: p.prefix,
          family: p.family,
          enabled: 1,
          updated_at: now,
        });
      }
    } else {
      for (const p of c.ports) {
        portRows.push({
          client_id: c.clientId,
          switch_ip: p.switchIp,
          if_index: p.ifIndex,
          comment: portComment(p),
          enabled: 1,
          updated_at: now,
        });
      }
    }
  }

  let disabled = 0;
  if (full) {
    const gone = clientsToDisable([...existing], take.map((c) => c.clientId));
    const names = new Map((await db.query(`
      SELECT client_id, display_name
      FROM default.net_clients_enabled
      WHERE comment = {tag:String}
    `, { tag: sourceTag })).map((r) => [String(r.client_id), String(r.display_name || '')]));
    for (const id of gone) {
      clientRows.push({
        client_id: id,
        display_name: names.get(id) || id,
        comment: sourceTag,
        bind_mode: mode,
        enabled: 0,
        updated_at: now,
      });
    }
    if (mode === 'prefixes') {
      const currentPrefixes = await db.query(`
        SELECT p.client_id, p.prefix, p.family
        FROM default.net_client_prefixes_enabled AS p
        INNER JOIN default.net_clients_enabled AS c ON c.client_id = p.client_id
        WHERE c.comment = {tag:String}
      `, { tag: sourceTag });
      const dropPrefixes = prefixesToDisable(currentPrefixes, prefixRows, gone);
      for (const p of dropPrefixes) {
        prefixRows.push({
          ...p,
          enabled: 0,
          updated_at: now,
        });
      }
    } else {
      const currentPorts = await db.query(`
        SELECT p.client_id, p.switch_ip, p.if_index, p.comment
        FROM default.net_client_ports_enabled AS p
        INNER JOIN default.net_clients_enabled AS c ON c.client_id = p.client_id
        WHERE c.comment = {tag:String}
      `, { tag: sourceTag });
      const dropPorts = portsToDisable(currentPorts, portRows, gone);
      for (const p of dropPorts) {
        portRows.push({
          ...p,
          enabled: 0,
          updated_at: now,
        });
      }
    }
    disabled = gone.length;
  }

  if (clientRows.length) await db.insert('net_clients', clientRows);
  if (portRows.length) await db.insert('net_client_ports', portRows);
  if (prefixRows.length) await db.insert('net_client_prefixes', prefixRows);

  return {
    source: sourceTag,
    category,
    full,
    limit: full ? null : Number(limit) || 0,
    fetched: clients.length,
    active: classified.activeCount,
    labelableTotal: classified.labelable.length,
    already: existing.size,
    pending: full ? 0 : Math.max(0, pending.length - take.length),
    upserted: take.length,
    bindMode: mode,
    ports: mode === 'prefixes'
      ? prefixRows.filter((p) => p.enabled !== 0).length
      : portRows.filter((p) => p.enabled !== 0).length,
    skipped: classified.skipped.length,
    skippedSummary: summarizeSkipped(classified.skipped),
    disableOthers: full,
    disabled,
    trigger,
    actor,
  };
}

async function writeLog(db, startedAt, summary, error = '') {
  const finished = new Date();
  await db.insert(LOG_TABLE, [{
    run_id: crypto.randomUUID(),
    started_at: clickhouseDateTime(startedAt),
    finished_at: clickhouseDateTime(finished),
    trigger: summary.trigger || 'cli',
    full: summary.full ? 1 : 0,
    limit_n: Number(summary.limit) || 0,
    fetched: Number(summary.fetched) || 0,
    active: Number(summary.active) || 0,
    labelable: Number(summary.labelableTotal) || 0,
    upserted: Number(summary.upserted) || 0,
    ports: Number(summary.ports) || 0,
    disabled: Number(summary.disabled) || 0,
    skipped: Number(summary.skipped) || 0,
    skipped_json: JSON.stringify(summary.skippedSummary || {}),
    error: error || '',
    actor: String(summary.actor || ''),
  }]);
}

async function runSync(db, options = {}) {
  if (running) {
    const err = new Error('Синхронизация уже выполняется');
    err.statusCode = 409;
    throw err;
  }
  running = true;
  const startedAt = new Date();
  let summary = {
    trigger: options.trigger || 'cli',
    actor: options.actor || '',
    full: !!options.full,
    limit: options.limit,
  };
  try {
    const settings = await getSettings(db);
    const bindMode = normalizeBindMode(options.bindMode || settings.bindMode);
    if ((options.trigger || 'cli') === 'cron' && !settings.cronEnabled) {
      summary = {
        ...summary,
        fetched: 0,
        active: 0,
        labelableTotal: 0,
        upserted: 0,
        ports: 0,
        skipped: 0,
        disabled: 0,
        skippedSummary: { byReason: { 'cron выключен в настройках': 1 } },
      };
      await writeLog(db, startedAt, summary);
      return summary;
    }
    const categories = options.category
      ? [options.category]
      : enabledCategoryIds(settings);
    if (!categories.length) {
      const err = new Error('Нет включённых категорий ERP');
      err.statusCode = 400;
      throw err;
    }
    const parts = [];
    for (const category of categories) {
      const clients = options.clients && categories.length === 1
        ? options.clients
        : await fetchErpClients(db, {
          category,
          full: !!options.full,
          fetchCap: options.full ? 0 : Math.max(Number(options.limit) || 50, 2) * 20,
        });
      parts.push(await applySync(db, { ...options, clients, category, bindMode }));
    }
    summary = {
      trigger: options.trigger || 'cli',
      actor: options.actor || '',
      full: !!options.full,
      limit: options.full ? null : Number(options.limit) || 0,
      source: parts.map((p) => p.source).join(','),
      category: categories.join(','),
      fetched: parts.reduce((n, p) => n + p.fetched, 0),
      active: parts.reduce((n, p) => n + p.active, 0),
      labelableTotal: parts.reduce((n, p) => n + p.labelableTotal, 0),
      already: parts.reduce((n, p) => n + p.already, 0),
      pending: parts.reduce((n, p) => n + p.pending, 0),
      upserted: parts.reduce((n, p) => n + p.upserted, 0),
      ports: parts.reduce((n, p) => n + p.ports, 0),
      skipped: parts.reduce((n, p) => n + p.skipped, 0),
      disabled: parts.reduce((n, p) => n + p.disabled, 0),
      skippedSummary: mergeSkipped(parts.map((p) => p.skippedSummary)),
      disableOthers: !!options.full,
      bindMode,
      parts,
    };
    await writeLog(db, startedAt, summary);
    return summary;
  } catch (err) {
    try {
      await ensureSchema(db);
      await writeLog(db, startedAt, summary, err.message || String(err));
    } catch {
      // journal is secondary to the original error
    }
    throw err;
  } finally {
    running = null;
  }
}

function mergeSkipped(items) {
  const byReason = {};
  const sample = [];
  for (const item of items || []) {
    for (const [reason, n] of Object.entries(item?.byReason || {})) {
      byReason[reason] = (byReason[reason] || 0) + Number(n) || 0;
    }
    sample.push(...(item?.sample || []));
  }
  return { byReason, sample: sample.slice(0, 40) };
}

async function getStatus(db) {
  await ensureSchema(db);
  const [byTag, ports, last, settings] = await Promise.all([
    db.query(`
      SELECT comment, count() AS n
      FROM default.net_clients_enabled
      WHERE comment LIKE 'erp:%'
      GROUP BY comment
    `),
    db.query(`
      SELECT count() AS n
      FROM default.net_client_ports_enabled AS p
      INNER JOIN default.net_clients_enabled AS c ON c.client_id = p.client_id
      WHERE c.comment LIKE 'erp:%'
    `),
    db.query(`
      SELECT run_id, started_at, finished_at, trigger, full, limit_n, fetched, active,
             labelable, upserted, ports, disabled, skipped, skipped_json, error, actor
      FROM default.${LOG_TABLE}
      ORDER BY started_at DESC
      LIMIT 1
    `),
    getSettings(db),
  ]);
  const lastRun = last[0] || null;
  if (lastRun?.skipped_json) {
    try { lastRun.skippedSummary = JSON.parse(lastRun.skipped_json); } catch { lastRun.skippedSummary = {}; }
  }
  const clientsByCategory = {};
  let clients = 0;
  for (const row of byTag) {
    const id = String(row.comment || '').replace(/^erp:/, '');
    const n = Number(row.n) || 0;
    clientsByCategory[id] = n;
    clients += n;
  }
  return {
    source: SOURCE_TAG,
    category: enabledCategoryIds(settings).join(',') || CATEGORY,
    running: !!running,
    erpConfigured: !!settings.tokenSet,
    clients,
    clientsByCategory,
    ports: Number(ports[0]?.n) || 0,
    lastRun,
    settings,
    fieldMap: FIELD_MAP,
    night: { hour: 3, minute: 15, tz: 'Europe/Moscow', mode: 'full' },
  };
}

async function listJournal(db, limit = 30) {
  await ensureSchema(db);
  const rows = await db.query(`
    SELECT run_id, started_at, finished_at, trigger, full, limit_n, fetched, active,
           labelable, upserted, ports, disabled, skipped, skipped_json, error, actor
    FROM default.${LOG_TABLE}
    ORDER BY started_at DESC
    LIMIT {limit:UInt32}
  `, { limit: Math.min(Math.max(Number(limit) || 30, 1), 100) });
  return rows.map((row) => {
    let skippedSummary = {};
    try { skippedSummary = JSON.parse(row.skipped_json || '{}'); } catch { /* ignore */ }
    return { ...row, skippedSummary };
  });
}

module.exports = {
  LOG_TABLE,
  FIELD_MAP,
  ENSURE_SQL,
  erpConfig,
  erpRequestHeaders,
  fetchErpClients,
  getSettings,
  saveSettings,
  createModuleAdapter,
  createClientAdapter,
  ensureSchema,
  applySync,
  runSync,
  getStatus,
  listJournal,
  isRunning: () => !!running,
};
