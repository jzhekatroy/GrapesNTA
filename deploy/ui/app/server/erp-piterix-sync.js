'use strict';

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

const REASON = {
  inactive: 'неактивный',
  no_port: 'есть адреса, но в ERP нет ни одного порта',
  no_ip_no_port: 'нет ни адреса, ни порта в ERP',
  switch_unknown: 'порт есть, этого коммутатора нет у нас',
  ifindex_unknown: 'коммутатор есть, такого ifIndex нет',
  conflict: 'конфликт: порт указан у другого ЛС',
};

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

function classifyClients(clients, catalog, { sourceTag = SOURCE_TAG } = {}) {
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
    const ips = client.ips || [];
    const ports = uniquePorts(client);
    if (!ports.length) {
      skipped.push({
        account,
        reason: ips.length ? REASON.no_port : REASON.no_ip_no_port,
      });
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
      ports: good,
    });
  }

  return { activeCount: active.length, labelable, skipped };
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
  isActive,
  uniquePorts,
  classifyClients,
  clickhouseDateTime,
  portComment,
  clientsToDisable,
  portsToDisable,
  summarizeSkipped,
};
