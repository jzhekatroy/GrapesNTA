const net = require('net');
const { randomUUID } = require('crypto');
const {
  config,
  query,
  insertRows,
  executeCommand,
  flowExclusionsTableRef,
  collectorHealthSnapshotsTableRef,
} = require('./clickhouse');
const { parseCidr } = require('./l3-prefixes');

const MATCH_SIDES = new Set(['any', 'src', 'dst']);
const PORT_SIDES = new Set(['any', 'src', 'dst']);
const MIN_PORT = 0;
const MAX_PORT = 65535;

function mapRuleRow(r) {
  return {
    ruleId: String(r.rule_id ?? ''),
    prefix: String(r.prefix ?? ''),
    family: Number(r.family),
    matchSide: String(r.match_side ?? 'any'),
    proto: Number(r.proto),
    portFrom: Number(r.port_from),
    portTo: Number(r.port_to),
    portSide: String(r.port_side ?? 'any'),
    vlanId: Number(r.vlan_id),
    switchIp: String(r.switch_ip ?? ''),
    ifIndex: Number(r.if_index),
    sourceId: String(r.source_id ?? ''),
    displayName: String(r.display_name ?? ''),
    comment: String(r.comment ?? ''),
    enabled: Number(r.enabled) === 1 ? 1 : 0,
    source: String(r.source ?? ''),
    updatedAt: r.updated_at ?? null,
  };
}

function parseSide(value, allowed, fallback) {
  const side = String(value ?? fallback).trim().toLowerCase();
  return allowed.has(side) ? side : fallback;
}

function hasPortCondition(portFrom, portTo) {
  return portFrom > 0 || portTo > 0;
}

function hasRuleCondition(record) {
  if (record.prefix) return true;
  if (hasPortCondition(record.port_from, record.port_to)) return true;
  if (record.proto > 0) return true;
  if (record.vlan_id > 0) return true;
  if (record.switch_ip) return true;
  if (record.source_id) return true;
  return false;
}

function parseSwitchIp(value) {
  const switchIp = String(value ?? '').trim();
  if (!switchIp) return { ok: true, switchIp: '' };
  if (!net.isIPv4(switchIp) && !net.isIPv6(switchIp)) {
    return { ok: false, error: 'Некорректный IP коммутатора' };
  }
  return { ok: true, switchIp };
}

function parsePortRange(body) {
  const portFrom = Number(body?.portFrom ?? body?.port_from ?? 0);
  const portTo = Number(body?.portTo ?? body?.port_to ?? 0);

  if (!Number.isInteger(portFrom) || portFrom < MIN_PORT || portFrom > MAX_PORT) {
    return { ok: false, error: 'Укажите начало диапазона портов в пределах 0–65535' };
  }
  if (!Number.isInteger(portTo) || portTo < MIN_PORT || portTo > MAX_PORT) {
    return { ok: false, error: 'Укажите конец диапазона портов в пределах 0–65535' };
  }
  if (portFrom > 0 && portTo > 0 && portFrom > portTo) {
    return { ok: false, error: 'Начало диапазона больше конца' };
  }

  return { ok: true, portFrom, portTo };
}

function parseProto(body) {
  const raw = body?.proto;
  if (raw === undefined || raw === null || String(raw).trim() === '') return { ok: true, proto: 0 };
  const proto = Number(raw);
  if (!Number.isInteger(proto) || proto < 0 || proto > 255) {
    return { ok: false, error: 'Некорректный номер протокола (0–255)' };
  }
  return { ok: true, proto };
}

function parsePrefixField(body) {
  const raw = String(body?.prefix ?? '').trim();
  if (!raw) return { ok: true, prefix: '', family: 0 };

  const parsed = parseCidr(raw);
  if (!parsed.ok) return parsed;

  let family = Number(body?.family);
  if (!Number.isInteger(family) || (family !== 4 && family !== 6)) {
    family = parsed.family;
  }
  if (family !== parsed.family) {
    return { ok: false, error: 'Версия IP не соответствует адресу в префиксе' };
  }

  return { ok: true, prefix: parsed.prefix, family };
}

async function validateFlowExclusionPayload(body, { isUpdate = false } = {}) {
  const prefixParsed = parsePrefixField(body);
  if (!prefixParsed.ok) return prefixParsed;

  const portParsed = parsePortRange(body);
  if (!portParsed.ok) return portParsed;

  const protoParsed = parseProto(body);
  if (!protoParsed.ok) return protoParsed;

  const switchParsed = parseSwitchIp(body?.switchIp ?? body?.switch_ip);
  if (!switchParsed.ok) return switchParsed;

  const vlanId = Number(body?.vlanId ?? body?.vlan_id ?? 0);
  if (!Number.isInteger(vlanId) || vlanId < 0 || vlanId > 65535) {
    return { ok: false, error: 'VLAN ID должен быть в пределах 0–65535' };
  }

  const ifIndex = Number(body?.ifIndex ?? body?.if_index ?? 0);
  if (!Number.isInteger(ifIndex) || ifIndex < 0) {
    return { ok: false, error: 'Некорректный ifIndex' };
  }
  if (ifIndex > 0 && !switchParsed.switchIp) {
    return { ok: false, error: 'Укажите IP коммутатора для номера порта' };
  }

  let enabled = Number(body?.enabled);
  if (enabled !== 0 && enabled !== 1) enabled = 1;

  const record = {
    prefix: prefixParsed.prefix,
    family: prefixParsed.prefix ? prefixParsed.family : 0,
    match_side: parseSide(body?.matchSide ?? body?.match_side, MATCH_SIDES, 'any'),
    proto: protoParsed.proto,
    port_from: portParsed.portFrom,
    port_to: portParsed.portTo,
    port_side: parseSide(body?.portSide ?? body?.port_side, PORT_SIDES, 'any'),
    vlan_id: vlanId,
    switch_ip: switchParsed.switchIp,
    if_index: ifIndex,
    source_id: String(body?.sourceId ?? body?.source_id ?? '').trim(),
    display_name: String(body?.displayName ?? body?.display_name ?? '').trim(),
    comment: String(body?.comment ?? '').trim(),
    enabled,
    source: 'webui',
  };

  if (!hasRuleCondition(record)) {
    return {
      ok: false,
      error: 'Правило без условий выбросит весь трафик — укажите хотя бы одно условие',
    };
  }

  const ruleId = String(body?.ruleId ?? body?.rule_id ?? '').trim();
  if (isUpdate && !ruleId) {
    return { ok: false, error: 'Не указан идентификатор правила' };
  }

  return { ok: true, record, ruleId: ruleId || null };
}

function latestRulesCte(table) {
  return `
    ranked AS (
      SELECT
        rule_id,
        prefix,
        family,
        match_side,
        proto,
        port_from,
        port_to,
        port_side,
        vlan_id,
        switch_ip,
        if_index,
        source_id,
        display_name,
        comment,
        enabled,
        source,
        updated_at,
        row_number() OVER (
          PARTITION BY rule_id
          ORDER BY updated_at DESC
        ) AS rn
      FROM ${table}
    )
  `;
}

function listFlowExclusions() {
  const table = flowExclusionsTableRef();

  return {
    sql: `
      WITH
        ${latestRulesCte(table)}
      SELECT
        rule_id,
        prefix,
        family,
        match_side,
        proto,
        port_from,
        port_to,
        port_side,
        vlan_id,
        switch_ip,
        if_index,
        source_id,
        display_name,
        comment,
        enabled,
        source,
        updated_at
      FROM ranked
      WHERE rn = 1
      ORDER BY display_name, rule_id
    `,
    params: {},
    map(rows) {
      return rows.map(mapRuleRow);
    },
  };
}

async function flowExclusionsExcludedStats() {
  const table = collectorHealthSnapshotsTableRef();
  const { rows } = await query(
    `
      SELECT
        sum(packets) AS packets,
        sum(bytes) AS bytes
      FROM (
        SELECT
          max(flow_packets_excluded) - min(flow_packets_excluded) AS packets,
          max(flow_bytes_excluded) - min(flow_bytes_excluded) AS bytes
        FROM ${table}
        WHERE ts >= now64(3) - INTERVAL 24 HOUR
        GROUP BY source_id
      )
    `,
    {},
    { name: 'refs/flow-exclusions-stats' },
  );

  const row = rows[0] || {};
  return {
    excludedPackets24h: Number(row.packets) || 0,
    excludedBytes24h: Number(row.bytes) || 0,
  };
}

async function fetchLatestFlowExclusion(ruleId) {
  const table = flowExclusionsTableRef();
  const { rows } = await query(
    `
      SELECT
        rule_id,
        prefix,
        family,
        match_side,
        proto,
        port_from,
        port_to,
        port_side,
        vlan_id,
        switch_ip,
        if_index,
        source_id,
        display_name,
        comment,
        enabled,
        source,
        updated_at
      FROM ${table}
      WHERE rule_id = {rule_id:String}
      ORDER BY updated_at DESC
      LIMIT 1
    `,
    { rule_id: String(ruleId) },
    { name: 'refs/flow-exclusions-latest' },
  );
  return rows[0] ? mapRuleRow(rows[0]) : null;
}

async function saveFlowExclusion(body) {
  const isUpdate = !!(body?.ruleId ?? body?.rule_id);
  const validation = await validateFlowExclusionPayload(body, { isUpdate });
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.statusCode = 400;
    throw err;
  }

  const ruleId = validation.ruleId || randomUUID();
  const record = {
    rule_id: ruleId,
    ...validation.record,
  };

  const { elapsedMs } = await insertRows(config.flowExclusionsTable, [record], {
    name: 'refs/flow-exclusions-insert',
  });

  return { elapsedMs, ruleId };
}

async function setFlowExclusionEnabled(body) {
  const ruleId = String(body?.ruleId ?? body?.rule_id ?? '').trim();
  if (!ruleId) {
    const err = new Error('Не указан идентификатор правила');
    err.statusCode = 400;
    throw err;
  }

  const latest = await fetchLatestFlowExclusion(ruleId);
  if (!latest) {
    const err = new Error('Правило не найдено');
    err.statusCode = 404;
    throw err;
  }

  let nextEnabled = Number(body?.enabled);
  if (nextEnabled !== 0 && nextEnabled !== 1) {
    nextEnabled = latest.enabled ? 0 : 1;
  }

  const record = {
    rule_id: latest.ruleId,
    prefix: latest.prefix,
    family: latest.family,
    match_side: latest.matchSide,
    proto: latest.proto,
    port_from: latest.portFrom,
    port_to: latest.portTo,
    port_side: latest.portSide,
    vlan_id: latest.vlanId,
    switch_ip: latest.switchIp,
    if_index: latest.ifIndex,
    source_id: latest.sourceId,
    display_name: latest.displayName,
    comment: latest.comment,
    enabled: nextEnabled,
    source: 'webui',
  };

  const { elapsedMs } = await insertRows(config.flowExclusionsTable, [record], {
    name: 'refs/flow-exclusions-toggle',
  });

  return { elapsedMs, enabled: nextEnabled };
}

async function deleteFlowExclusion(body) {
  const ruleId = String(body?.ruleId ?? body?.rule_id ?? '').trim();
  if (!ruleId) {
    const err = new Error('Не указан идентификатор правила');
    err.statusCode = 400;
    throw err;
  }

  const latest = await fetchLatestFlowExclusion(ruleId);
  if (!latest) {
    const err = new Error('Правило не найдено');
    err.statusCode = 404;
    throw err;
  }

  const table = flowExclusionsTableRef();
  const { elapsedMs } = await executeCommand(
    `DELETE FROM ${table} WHERE rule_id = {rule_id:String}`,
    { rule_id: ruleId },
    { name: 'refs/flow-exclusions-delete' },
  );

  return { elapsedMs };
}

module.exports = {
  listFlowExclusions,
  flowExclusionsExcludedStats,
  saveFlowExclusion,
  setFlowExclusionEnabled,
  deleteFlowExclusion,
  validateFlowExclusionPayload,
  mapRuleRow,
  hasRuleCondition,
};
