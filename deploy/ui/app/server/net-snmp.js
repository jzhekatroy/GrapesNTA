const net = require('net');
const {
  config,
  executeCommand,
  insertRows,
  netInterfacesCurrentRef,
  query,
  snmpAgentsCurrentRef,
  snmpAgentsTableRef,
  snmpSettingsCurrentRef,
} = require('./clickhouse');

const DEFAULT_SETTINGS = {
  community: '',
  port: 161,
  timeout_ms: 2000,
  retries: 1,
  discover_lookback_hours: 24,
  refresh_interval_sec: 1800,
  full_walk_interval_sec: 21600,
  enabled: 1,
  auto_enable_new_agents: 0,
};

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function boolInt(value, fallback) {
  if (value === undefined) return fallback;
  return value === true || value === 1 || value === '1' ? 1 : 0;
}

function boundedInt(value, fallback, min, max, label) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw apiError(`${label}: ожидается целое число от ${min} до ${max}`);
  }
  return n;
}

function nullableBoundedInt(value, min, max, label) {
  if (value === undefined || value === null || value === '') return null;
  return boundedInt(value, null, min, max, label);
}

// The poller stores "never happened" as the epoch, which would render as a
// 1970 timestamp in the UI.
function epochToNull(value) {
  const text = value == null ? '' : String(value);
  if (!text || text.startsWith('1970-01-01')) return null;
  return value;
}

function mapSettings(r = {}) {
  return {
    port: Number(r.port) || DEFAULT_SETTINGS.port,
    timeoutMs: Number(r.timeout_ms) || DEFAULT_SETTINGS.timeout_ms,
    retries: Number(r.retries) || 0,
    discoverLookbackHours: Number(r.discover_lookback_hours) || DEFAULT_SETTINGS.discover_lookback_hours,
    refreshIntervalSec: Number(r.refresh_interval_sec) || DEFAULT_SETTINGS.refresh_interval_sec,
    fullWalkIntervalSec: Number(r.full_walk_interval_sec) || DEFAULT_SETTINGS.full_walk_interval_sec,
    enabled: Number(r.enabled) === 1,
    autoEnableNewAgents: Number(r.auto_enable_new_agents) === 1,
    hasCommunity: Boolean(String(r.community ?? '')),
    updatedAt: r.updated_at ?? null,
  };
}

async function getCurrentSettingsRaw() {
  const { rows } = await query(`
    SELECT
      community, port, timeout_ms, retries, discover_lookback_hours,
      refresh_interval_sec, full_walk_interval_sec, enabled,
      auto_enable_new_agents, updated_at
    FROM ${snmpSettingsCurrentRef()}
    LIMIT 1
  `, {}, { name: 'refs/snmp-settings-current' });
  return rows[0] || null;
}

async function listSnmpSettings() {
  const current = await getCurrentSettingsRaw();
  return {
    params: {},
    meta: { rows: current ? 1 : 0 },
    map() {
      return mapSettings(current || DEFAULT_SETTINGS);
    },
  };
}

async function saveSnmpSettings(body = {}) {
  const existing = await getCurrentSettingsRaw();
  const base = existing || DEFAULT_SETTINGS;
  const replacement = String(body.community ?? '').trim();
  const community = replacement || String(base.community ?? '');
  const enabled = boolInt(body.enabled, Number(base.enabled) === 1 ? 1 : 0);
  if (enabled && !community) throw apiError('Укажите community перед включением SNMP');

  const record = {
    settings_id: 'global',
    community,
    port: boundedInt(body.port, Number(base.port), 1, 65535, 'Порт'),
    timeout_ms: boundedInt(body.timeoutMs ?? body.timeout_ms, Number(base.timeout_ms), 100, 120000, 'Timeout'),
    retries: boundedInt(body.retries, Number(base.retries), 0, 10, 'Повторы'),
    discover_lookback_hours: boundedInt(
      body.discoverLookbackHours ?? body.discover_lookback_hours,
      Number(base.discover_lookback_hours),
      1,
      720,
      'Окно обнаружения',
    ),
    refresh_interval_sec: boundedInt(
      body.refreshIntervalSec ?? body.refresh_interval_sec,
      Number(base.refresh_interval_sec),
      10,
      86400,
      'Интервал обновления',
    ),
    full_walk_interval_sec: boundedInt(
      body.fullWalkIntervalSec ?? body.full_walk_interval_sec,
      Number(base.full_walk_interval_sec),
      60,
      2592000,
      'Интервал полного обхода',
    ),
    enabled,
    auto_enable_new_agents: boolInt(
      body.autoEnableNewAgents ?? body.auto_enable_new_agents,
      Number(base.auto_enable_new_agents) === 1 ? 1 : 0,
    ),
  };
  const { elapsedMs } = await insertRows(config.snmpSettingsTable, [record], {
    name: 'refs/snmp-settings-save',
  });
  return { elapsedMs };
}

function mapAgent(r) {
  const interfaceCount = Number(r.interface_count) || 0;
  return {
    switchIp: String(r.switch_ip ?? ''),
    displayName: String(r.display_name ?? ''),
    snmpEnabled: Number(r.snmp_enabled) === 1,
    hasCommunityOverride: Boolean(String(r.community_override ?? '')),
    portOverride: Number(r.port_override) || null,
    timeoutMsOverride: Number(r.timeout_ms_override) || null,
    retriesOverride: Number(r.retries_override) || null,
    firstSeenAt: r.first_seen_at ?? null,
    lastSeenAt: r.last_seen_at ?? null,
    lastPollAt: r.last_poll_at ?? null,
    // Attempts move lastPollAt; only this advances when the switch answered.
    lastOkAt: epochToNull(r.last_ok_at),
    lastFullWalkAt: r.last_full_walk_at ?? null,
    lastPollStatus: String(r.last_poll_status ?? 'never'),
    lastPollError: String(r.last_poll_error ?? ''),
    isNew: Number(r.is_new) === 1,
    updatedAt: r.updated_at ?? null,
    sourceIds: Array.isArray(r.source_ids) ? r.source_ids.map(String) : [],
    interfaceCount,
    interfacesUpdatedAt: r.interfaces_updated_at ?? null,
    hasCachedInterfaces: interfaceCount > 0,
  };
}

function listSnmpAgents() {
  // source_ids are maintained by snmp_iface_sync from flows_raw.
  // Do not join live flows here — a 24h scan of flows_raw makes the page hang.
  // Interface counts come from the catalog so UI can keep showing last-known data
  // when a re-poll is queued or the switch is temporarily unreachable.
  return {
    sql: `
      SELECT
        a.switch_ip, a.display_name, a.snmp_enabled, a.community_override,
        a.port_override, a.timeout_ms_override, a.retries_override,
        a.first_seen_at, a.last_seen_at, a.last_poll_at, a.last_ok_at,
        a.last_full_walk_at,
        a.last_poll_status, a.last_poll_error, a.is_new, a.updated_at,
        a.source_ids,
        ifNull(i.interface_count, 0) AS interface_count,
        i.interfaces_updated_at
      FROM ${snmpAgentsCurrentRef()} AS a
      LEFT JOIN
      (
        SELECT
          switch_ip,
          count() AS interface_count,
          max(updated_at) AS interfaces_updated_at
        FROM ${netInterfacesCurrentRef()}
        GROUP BY switch_ip
      ) AS i ON a.switch_ip = i.switch_ip
      ORDER BY a.is_new DESC, a.display_name, a.switch_ip
    `,
    params: {},
    map(rows) {
      return rows.map(mapAgent);
    },
  };
}

async function getAgentRaw(switchIp) {
  const { rows } = await query(`
    SELECT *
    FROM ${snmpAgentsCurrentRef()}
    WHERE switch_ip = {switch_ip:String}
    LIMIT 1
  `, { switch_ip: switchIp }, { name: 'refs/snmp-agent-current' });
  return rows[0] || null;
}

function agentWriteRecord(existing, patch = {}) {
  const replacement = String(patch.communityOverride ?? patch.community_override ?? '').trim();
  const clearCommunity = patch.useGlobalCommunity === true || patch.clearCommunityOverride === true;
  return {
    switch_ip: existing.switch_ip,
    display_name: patch.displayName !== undefined
      ? String(patch.displayName).trim()
      : String(existing.display_name ?? ''),
    source_ids: Array.isArray(existing.source_ids) ? existing.source_ids.map(String) : [],
    snmp_enabled: boolInt(patch.snmpEnabled ?? patch.snmp_enabled, Number(existing.snmp_enabled) === 1 ? 1 : 0),
    community_override: clearCommunity
      ? ''
      : (replacement || existing.community_override || ''),
    port_override: patch.portOverride !== undefined
      ? (nullableBoundedInt(patch.portOverride, 1, 65535, 'Порт') || 0)
      : (Number(existing.port_override) || 0),
    timeout_ms_override: patch.timeoutMsOverride !== undefined
      ? (nullableBoundedInt(patch.timeoutMsOverride, 100, 120000, 'Timeout') || 0)
      : (Number(existing.timeout_ms_override) || 0),
    retries_override: patch.retriesOverride !== undefined
      ? (nullableBoundedInt(patch.retriesOverride, 0, 10, 'Повторы') ?? 0)
      : (Number(existing.retries_override) || 0),
    first_seen_at: existing.first_seen_at,
    last_seen_at: existing.last_seen_at,
    last_poll_at: existing.last_poll_at,
    // Carried over explicitly: a missing key would reset the column to its
    // epoch default and erase when the switch last answered.
    last_ok_at: existing.last_ok_at ?? '1970-01-01 00:00:00',
    last_full_walk_at: existing.last_full_walk_at,
    last_poll_status: existing.last_poll_status,
    last_poll_error: existing.last_poll_error,
    is_new: patch.isNew !== undefined ? boolInt(patch.isNew, 0) : existing.is_new,
  };
}

async function saveSnmpAgent(switchIp, body = {}) {
  const ip = String(switchIp || body.switchIp || body.switch_ip || '').trim();
  if (!net.isIP(ip)) throw apiError('Некорректный IP коммутатора');
  const existing = await getAgentRaw(ip);
  if (!existing) throw apiError(`Коммутатор «${ip}» не найден`, 404);
  const record = agentWriteRecord(existing, body);
  const { elapsedMs } = await insertRows(config.snmpAgentsTable, [record], {
    name: 'refs/snmp-agent-save',
  });
  return { elapsedMs, switchIp: ip };
}

function listSnmpInterfaces(switchIp) {
  const ip = String(switchIp || '').trim();
  if (!net.isIP(ip)) throw apiError('Некорректный IP коммутатора');
  return {
    sql: `
      SELECT if_index, if_name, if_alias, if_descr, if_speed_bps, updated_at
      FROM ${netInterfacesCurrentRef()}
      WHERE switch_ip = {switch_ip:String}
      ORDER BY if_index
    `,
    params: { switch_ip: ip },
    map(rows) {
      return rows.map((r) => ({
        ifIndex: Number(r.if_index),
        ifName: String(r.if_name ?? ''),
        ifAlias: String(r.if_alias ?? ''),
        ifDescr: String(r.if_descr ?? ''),
        ifSpeedBps: Number(r.if_speed_bps) || 0,
        updatedAt: r.updated_at ?? null,
      }));
    },
  };
}

async function requestSnmpProbe(switchIp, { enable = false } = {}) {
  const ip = String(switchIp || '').trim();
  if (!net.isIP(ip)) throw apiError('Некорректный IP коммутатора');
  const existing = await getAgentRaw(ip);
  if (!existing) throw apiError(`Коммутатор «${ip}» не найден`, 404);
  const record = agentWriteRecord(existing, enable ? { snmpEnabled: true } : {});
  // Queue a fresh poll without pretending we never had catalog data.
  record.last_poll_at = '1970-01-01 00:00:00';
  record.last_poll_status = 'queued';
  record.last_poll_error = '';
  const { elapsedMs } = await insertRows(config.snmpAgentsTable, [record], {
    name: 'refs/snmp-agent-probe',
  });
  return { elapsedMs, switchIp: ip, accepted: true };
}

async function requestSnmpProbeAll({ enable = true } = {}) {
  const { rows } = await query(`
    SELECT *
    FROM ${snmpAgentsCurrentRef()}
  `, {}, { name: 'refs/snmp-agents-probe-all-load' });
  if (!rows.length) {
    return { elapsedMs: 0, accepted: 0, total: 0 };
  }
  const records = rows.map((existing) => {
    const record = agentWriteRecord(existing, enable ? { snmpEnabled: true } : {});
    record.last_poll_at = '1970-01-01 00:00:00';
    record.last_poll_status = 'queued';
    record.last_poll_error = '';
    return record;
  });
  const { elapsedMs } = await insertRows(config.snmpAgentsTable, records, {
    name: 'refs/snmp-agents-probe-all',
  });
  return { elapsedMs, accepted: records.length, total: records.length };
}

/**
 * Drop decommissioned hardware from the inventory.
 *
 * Physical delete, not a flag: the poller rebuilds the agent list from
 * flows_raw.sampler_address on every tick, so a switch that no longer exports
 * sFlow stays gone. One that still sends samples is rediscovered within the
 * discovery window and comes back as new with polling off.
 *
 * The interface catalog is deliberately left in place — Explorer joins it to
 * name ports on historical flows.
 */
async function deleteSnmpAgent(switchIp) {
  const ip = String(switchIp || '').trim();
  if (!net.isIP(ip)) throw apiError('Некорректный IP коммутатора');
  const existing = await getAgentRaw(ip);
  if (!existing) throw apiError(`Коммутатор «${ip}» не найден`, 404);
  // Mutations are asynchronous in ClickHouse; the row disappears from the
  // ReplacingMergeTree once the mutation is applied.
  const { elapsedMs } = await executeCommand(`
    ALTER TABLE ${snmpAgentsTableRef()}
    DELETE WHERE switch_ip = {switch_ip:String}
  `, { switch_ip: ip }, { name: 'refs/snmp-agent-delete' });
  return { elapsedMs, switchIp: ip, deleted: true };
}

module.exports = {
  listSnmpSettings,
  saveSnmpSettings,
  listSnmpAgents,
  saveSnmpAgent,
  listSnmpInterfaces,
  requestSnmpProbe,
  requestSnmpProbeAll,
  deleteSnmpAgent,
};
