'use strict';

const net = require('net');

const SOURCE_TAG = 'erp:piter_ix';
const CATEGORY = 'piter_ix';

const CATEGORIES = [
  {
    id: 'piter_ix',
    label: 'PiterIX / Transroute',
    rule: 'группа биллинга 710 (PiterIX) или 726 (Transroute)',
  },
  {
    id: 'dc',
    label: 'Data Center',
    rule: 'группа 500 (Data Center Users)',
  },
  {
    id: 'bb',
    label: 'Broadband',
    rule: 'группа 700 (Local Users) и хотя бы одна услуга service_type = 3',
  },
];

function sourceTagFor(categoryId) {
  return `erp:${String(categoryId || CATEGORY)}`;
}

// Binding by ports only ever looks at switch.host + switch.port, so whether the
// client also has an address changes nothing: one cause, not two.
const REASON = {
  inactive: 'неактивный',
  no_port: 'в ERP нет порта коммутатора',
  no_ip: 'в ERP нет текущего IP',
  switch_unknown: 'порт есть, этого коммутатора нет у нас',
  ifindex_unknown: 'коммутатор есть, такого ifIndex нет',
  conflict: 'конфликт: порт указан у другого ЛС',
  conflict_prefix: 'конфликт: этот IP указан у другого ЛС',
};

function normalizeBindMode(value, fallback = 'ports') {
  return value === 'prefixes' || value === 'ports' ? value : fallback;
}

function normalizePrefix(text) {
  const trimmed = String(text || '').trim();
  const slash = trimmed.indexOf('/');
  if (slash < 0) return null;
  const ipPart = trimmed.slice(0, slash);
  const mask = Number(trimmed.slice(slash + 1));
  const family = net.isIP(ipPart);
  if (family === 4 && Number.isInteger(mask) && mask >= 0 && mask <= 32) {
    return { prefix: `${ipPart}/${mask}`, family: 4, key: `4:${ipPart}/${mask}` };
  }
  if (family === 6 && Number.isInteger(mask) && mask >= 0 && mask <= 128) {
    return { prefix: `${ipPart}/${mask}`, family: 6, key: `6:${ipPart}/${mask}` };
  }
  return null;
}

function prefixFromIpRow(row) {
  if (!row || typeof row !== 'object') return null;
  const cidr = row.cidr != null && row.cidr !== '' ? String(row.cidr).trim() : '';
  const ip = row.ip != null ? String(row.ip).trim() : '';
  if (cidr && cidr.includes('/')) return normalizePrefix(cidr);
  if (cidr && net.isIP(cidr)) {
    return prefixFromIpRow({ ip: cidr, cidr: null });
  }
  if (ip.includes('/')) return normalizePrefix(ip);
  if (net.isIP(ip) === 4) return { prefix: `${ip}/32`, family: 4, key: `4:${ip}/32` };
  if (net.isIP(ip) === 6) return { prefix: `${ip}/128`, family: 6, key: `6:${ip}/128` };
  return null;
}

function uniquePrefixes(client) {
  const seen = [];
  for (const row of client.ips || []) {
    const prefix = prefixFromIpRow(row);
    if (!prefix) continue;
    if (seen.some((p) => p.key === prefix.key)) continue;
    seen.push(prefix);
  }
  return seen;
}

function isActive(client) {
  if (!client || (client.error && client.name == null)) return false;
  if (Number(client.int_status) !== 1) return false;
  if (client.block && client.block.is_blocked) return false;
  return true;
}

function uniquePorts(client) {
  const seen = [];
  for (const ip of client.ips || []) {
    const sw = ip.switch && typeof ip.switch === 'object' ? ip.switch : null;
    if (!sw) continue;
    const host = String(sw.host || '').trim();
    const port = sw.port;
    if (!host || port == null || port === '') continue;
    const ifIndex = Number(port);
    if (!Number.isInteger(ifIndex) || ifIndex <= 0) continue;
    const key = `${host}:${ifIndex}`;
    if (seen.some((p) => p.key === key)) continue;
    seen.push({
      key,
      switchIp: host,
      ifIndex,
      inven: String(sw.inven_number || '').trim(),
    });
  }
  return seen;
}

function classifyClients(clients, catalog, { sourceTag = SOURCE_TAG, bindMode = 'ports' } = {}) {
  const mode = normalizeBindMode(bindMode);
  const agents = catalog.agents || new Map();
  const ifaces = catalog.ifaces || new Set();

  const active = [];
  const skipped = [];
  for (const client of clients) {
    if (!isActive(client)) {
      skipped.push({ account: client.basic_account, reason: REASON.inactive });
      continue;
    }
    active.push(client);
  }

  if (mode === 'prefixes') {
    const owners = new Map();
    for (const client of active) {
      for (const prefix of uniquePrefixes(client)) {
        if (!owners.has(prefix.key)) owners.set(prefix.key, new Set());
        owners.get(prefix.key).add(String(client.basic_account));
      }
    }
    const labelable = [];
    for (const client of active) {
      const account = String(client.basic_account);
      const prefixes = uniquePrefixes(client);
      if (!prefixes.length) {
        skipped.push({ account, name: client.name || '', reason: REASON.no_ip });
        continue;
      }
      const good = prefixes.filter((prefix) => owners.get(prefix.key).size === 1);
      if (!good.length) {
        skipped.push({ account, name: client.name || '', reason: REASON.conflict_prefix });
        continue;
      }
      labelable.push({
        clientId: account,
        displayName: String(client.name || '').trim() || `ЛС ${account}`,
        comment: sourceTag,
        bindMode: 'prefixes',
        ports: [],
        prefixes: good,
      });
    }
    return { activeCount: active.length, labelable, skipped, bindMode: mode };
  }

  const owners = new Map();
  for (const client of active) {
    for (const port of uniquePorts(client)) {
      if (!owners.has(port.key)) owners.set(port.key, new Set());
      owners.get(port.key).add(String(client.basic_account));
    }
  }

  const labelable = [];
  for (const client of active) {
    const account = String(client.basic_account);
    const ports = uniquePorts(client);
    if (!ports.length) {
      skipped.push({ account, name: client.name || '', reason: REASON.no_port });
      continue;
    }

    const good = [];
    const portReasons = [];
    for (const port of ports) {
      if (owners.get(port.key).size > 1) {
        portReasons.push({ ...port, reason: REASON.conflict });
        continue;
      }
      if (!agents.has(port.switchIp)) {
        portReasons.push({ ...port, reason: REASON.switch_unknown });
        continue;
      }
      if (!ifaces.has(port.key)) {
        portReasons.push({ ...port, reason: REASON.ifindex_unknown });
        continue;
      }
      const ag = agents.get(port.switchIp) || {};
      const iface = catalog.ifaceRows?.get(port.key) || {};
      good.push({
        ...port,
        swName: ag.display_name || '',
        ifName: iface.if_name || '',
        ifAlias: iface.if_alias || '',
      });
    }

    if (!good.length) {
      skipped.push({
        account,
        name: client.name || '',
        reason: portReasons[0]?.reason || REASON.no_port,
      });
      continue;
    }

    labelable.push({
      clientId: account,
      displayName: String(client.name || '').trim() || `ЛС ${account}`,
      comment: sourceTag,
      bindMode: 'ports',
      ports: good,
      prefixes: [],
    });
  }

  return { activeCount: active.length, labelable, skipped, bindMode: mode };
}

function clickhouseDateTime(date = new Date()) {
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

function portComment(port) {
  return [port.inven, port.ifName, port.ifAlias].filter(Boolean).join(' · ');
}

function clientsToDisable(existingIds, labelableIds) {
  const keep = new Set((labelableIds || []).map(String));
  return [...new Set((existingIds || []).map(String))].filter((id) => id && !keep.has(id));
}

function prefixesToDisable(currentPrefixes, desiredPrefixes, disabledClientIds = []) {
  const desired = new Set(
    (desiredPrefixes || []).map((p) => `${p.client_id}|${p.family}|${p.prefix}`),
  );
  const disabled = new Set((disabledClientIds || []).map(String));
  const out = [];
  const seen = new Set();
  for (const p of currentPrefixes || []) {
    const clientId = String(p.client_id || '');
    const key = `${clientId}|${Number(p.family) || 0}|${p.prefix}`;
    if (seen.has(key)) continue;
    const drop = disabled.has(clientId) || (clientId && !desired.has(key));
    if (!drop) continue;
    seen.add(key);
    out.push({
      client_id: clientId,
      prefix: String(p.prefix || ''),
      family: Number(p.family) || 0,
    });
  }
  return out;
}

function portsToDisable(currentPorts, desiredPorts, disabledClientIds = []) {
  const desired = new Set(
    (desiredPorts || []).map((p) => `${p.client_id}|${p.switch_ip}|${p.if_index}`),
  );
  const disabled = new Set((disabledClientIds || []).map(String));
  const out = [];
  const seen = new Set();
  for (const p of currentPorts || []) {
    const clientId = String(p.client_id || '');
    const key = `${clientId}|${p.switch_ip}|${p.if_index}`;
    if (seen.has(key)) continue;
    const drop = disabled.has(clientId) || (clientId && !desired.has(key));
    if (!drop) continue;
    seen.add(key);
    out.push({
      client_id: clientId,
      switch_ip: String(p.switch_ip || ''),
      if_index: Number(p.if_index) || 0,
      comment: String(p.comment || ''),
    });
  }
  return out;
}

function summarizeSkipped(skipped = []) {
  const byReason = {};
  for (const row of skipped) {
    const reason = String(row.reason || 'другое');
    byReason[reason] = (byReason[reason] || 0) + 1;
  }
  return {
    byReason,
    sample: skipped.slice(0, 40).map((row) => ({
      account: String(row.account || ''),
      name: String(row.name || ''),
      reason: String(row.reason || ''),
    })),
  };
}

module.exports = {
  SOURCE_TAG,
  CATEGORY,
  CATEGORIES,
  sourceTagFor,
  REASON,
  normalizeBindMode,
  isActive,
  uniquePorts,
  uniquePrefixes,
  prefixFromIpRow,
  classifyClients,
  clickhouseDateTime,
  portComment,
  clientsToDisable,
  portsToDisable,
  prefixesToDisable,
  summarizeSkipped,
};
