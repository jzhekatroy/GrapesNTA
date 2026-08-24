'use strict';

/**
 * Per-run ERP report: one row per client×port or client×prefix, with the
 * verdict the sync itself reached plus the data-quality findings an operator
 * needs to act on. runSync only keeps counters, so without this the detail that
 * classifyClients already computes is thrown away.
 *
 * The report follows the active bindMode. Building both sections made the sheet
 * lie: on a ports stand a client with addresses but no port came out as "нет" in
 * one section and "да" in the other, and picked up CIDR notes that mean nothing
 * where binding never looks at addresses.
 */

const net = require('net');

const {
  REASON,
  normalizeBindMode,
  isActive,
  uniquePorts,
  uniquePrefixes,
} = require('./erp-piterix-sync');

const SECTION = {
  ports: 'порты',
  prefixes: 'IP',
  gone: 'пропал из ERP',
};

// Only two outcomes: either the sync created the binding or it did not. A port
// claimed by two accounts is dropped for both, so it belongs under "нет".
const VERDICT = {
  yes: 'да',
  no: 'нет',
};

// Wider than this and one client's prefix would swallow traffic that is very
// unlikely to be his. Not an error on its own, hence a note and not a verdict.
const WIDE_MASK = { 4: 24, 6: 48 };

// Addresses that cannot belong to a client. The PiterIX export carries dozens
// of 0.0.0.x rows where an operator typed a VLAN or a port number into the IP
// field, and those look like ordinary /32 until you check the range.
// Each label names the range it came from: "зарезервированный диапазон" on its
// own tells the operator nothing about which range or why it is a problem.
const UNUSABLE_RANGES = [
  ['0.0.0.0/8', 'адрес из 0.0.0.0/8, похоже на опечатку в ERP'],
  ['127.0.0.0/8', 'loopback 127.0.0.0/8, не адрес клиента'],
  ['169.254.0.0/16', 'link-local 169.254.0.0/16, не адрес клиента'],
  ['224.0.0.0/4', 'multicast 224.0.0.0/4, не адрес клиента'],
  ['240.0.0.0/4', 'диапазон 240.0.0.0/4 зарезервирован IANA и не маршрутизируется'],
  ['::1/128', 'loopback ::1, не адрес клиента'],
  ['fe80::/10', 'link-local fe80::/10, не адрес клиента'],
  ['ff00::/8', 'multicast ff00::/8, не адрес клиента'],
];

const PRIVATE_RANGES = [
  ['10.0.0.0/8', 'приватный диапазон RFC1918 10.0.0.0/8'],
  ['172.16.0.0/12', 'приватный диапазон RFC1918 172.16.0.0/12'],
  ['192.168.0.0/16', 'приватный диапазон RFC1918 192.168.0.0/16'],
  ['100.64.0.0/10', 'CGNAT RFC6598 100.64.0.0/10'],
  ['fc00::/7', 'приватный диапазон ULA fc00::/7'],
];

const COLUMNS_HEAD = [
  ['section', 'Раздел'],
  ['category', 'Категория'],
  ['account', 'ЛС'],
  ['client_name', 'Клиент'],
  ['services', 'Услуги'],
];

const COLUMNS_PORTS = [
  ['switch_host', 'Коммутатор (ERP host)'],
  ['inven', 'Инв. номер'],
  ['if_index', 'ifIndex'],
  ['switch_name', 'Коммутатор у нас'],
  ['if_name', 'if_name'],
  ['if_alias', 'if_alias'],
  ['speed_mbps', 'Скорость, Мбит/с'],
];

const COLUMNS_PREFIXES = [
  ['prefix', 'Префикс'],
  ['l3_prefix', 'Наш CIDR'],
  ['l3_role', 'Роль CIDR'],
];

const COLUMNS_TAIL = [
  ['verdict', 'Можно разметить'],
  ['reason', 'Причина'],
  ['notes', 'Замечания'],
];

const REPORT_COLUMNS = [
  ...COLUMNS_HEAD,
  ...COLUMNS_PORTS,
  ...COLUMNS_PREFIXES,
  ...COLUMNS_TAIL,
];

function ipv4ToBigInt(ip) {
  const parts = String(ip).split('.');
  let out = 0n;
  for (const part of parts) out = (out << 8n) | BigInt(Number(part) & 0xff);
  return out;
}

function ipv6ToBigInt(ip) {
  let text = String(ip);
  const embedded = text.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (embedded) {
    const v4 = ipv4ToBigInt(embedded[1]);
    const hi = (v4 >> 16n) & 0xffffn;
    const lo = v4 & 0xffffn;
    text = `${text.slice(0, embedded.index)}${hi.toString(16)}:${lo.toString(16)}`;
  }
  let parts;
  if (text.includes('::')) {
    const [head, tail] = text.split('::');
    const headParts = head ? head.split(':').filter(Boolean) : [];
    const tailParts = tail ? tail.split(':').filter(Boolean) : [];
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;
    parts = [...headParts, ...Array(missing).fill('0'), ...tailParts];
  } else {
    parts = text.split(':');
  }
  if (parts.length !== 8) return null;
  let out = 0n;
  for (const part of parts) {
    const n = parseInt(part, 16);
    if (!Number.isFinite(n)) return null;
    out = (out << 16n) | BigInt(n & 0xffff);
  }
  return out;
}

function parseCidr(text) {
  const raw = String(text || '').trim();
  const slash = raw.indexOf('/');
  if (slash < 0) return null;
  const ip = raw.slice(0, slash);
  const bits = Number(raw.slice(slash + 1));
  const family = net.isIP(ip);
  const width = family === 4 ? 32 : family === 6 ? 128 : 0;
  if (!width || !Number.isInteger(bits) || bits < 0 || bits > width) return null;
  const addr = family === 4 ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);
  if (addr == null) return null;
  const size = 1n << BigInt(width - bits);
  const start = (addr / size) * size;
  return { family, bits, start, end: start + size - 1n, text: raw };
}

function compileRanges(list) {
  return list
    .map(([cidr, label]) => {
      const parsed = parseCidr(cidr);
      return parsed ? { ...parsed, label } : null;
    })
    .filter(Boolean);
}

const UNUSABLE = compileRanges(UNUSABLE_RANGES);
const PRIVATE = compileRanges(PRIVATE_RANGES);

function matchRange(entry, ranges) {
  for (const range of ranges) {
    if (range.family !== entry.family) continue;
    if (range.start <= entry.start && range.end >= entry.end) return range;
  }
  return null;
}

/** Most specific of our prefixes that covers `entry`, or null. */
function coveringPrefix(entry, l3Index) {
  let best = null;
  for (const own of l3Index) {
    if (own.family !== entry.family) continue;
    if (own.start > entry.start || own.end < entry.end) continue;
    if (!best || own.bits > best.bits) best = own;
  }
  return best;
}

/**
 * CIDRs either nest or are disjoint, so a sweep by (family, start, bits) puts
 * every enclosing prefix before the ones it contains and lets a stack find the
 * nearest enclosing prefix owned by a different account.
 */
function findNesting(entries) {
  const sorted = [...entries].sort((a, b) => (
    a.family - b.family
    || (a.start < b.start ? -1 : a.start > b.start ? 1 : 0)
    || a.bits - b.bits
  ));
  const out = new Map();
  const stack = [];
  for (const entry of sorted) {
    while (stack.length) {
      const top = stack[stack.length - 1];
      if (top.family === entry.family && top.end >= entry.end) break;
      stack.pop();
    }
    for (let i = stack.length - 1; i >= 0; i -= 1) {
      // Strictly broader only: an identical prefix on two accounts is the
      // duplicate case and is reported there, not as nesting.
      if (stack[i].bits < entry.bits && stack[i].account !== entry.account) {
        out.set(entry.key, stack[i]);
        break;
      }
    }
    stack.push(entry);
  }
  return out;
}

function formatServices(client) {
  const list = Array.isArray(client?.services) ? client.services : [];
  const seen = new Set();
  const out = [];
  for (const service of list) {
    if (!service) continue;
    const text = `${service.id}: ${service.name}${service.type_name ? ` [${service.type_name}]` : ''}`;
    if (seen.has(text)) continue;
    seen.add(text);
    out.push(text);
  }
  return out.join('; ');
}

function clientName(client) {
  return String(client?.name || '').trim();
}

function emptyRow(section, category) {
  return {
    section,
    category: String(category || ''),
    account: '',
    client_name: '',
    services: '',
    switch_host: '',
    inven: '',
    if_index: 0,
    switch_name: '',
    if_name: '',
    if_alias: '',
    speed_mbps: 0,
    prefix: '',
    l3_prefix: '',
    l3_role: '',
    verdict: '',
    reason: '',
    notes: '',
  };
}

function joinNotes(...parts) {
  return parts.filter(Boolean).join('; ');
}

function ownersOf(active, pick) {
  const owners = new Map();
  for (const client of active) {
    const account = String(client.basic_account);
    for (const item of pick(client)) {
      if (!owners.has(item.key)) owners.set(item.key, new Set());
      owners.get(item.key).add(account);
    }
  }
  return owners;
}

function buildPortRows(active, catalog, category) {
  const agents = catalog.agents || new Map();
  const ifaces = catalog.ifaces || new Set();
  const ifaceRows = catalog.ifaceRows || new Map();
  const owners = ownersOf(active, uniquePorts);
  const rows = [];

  for (const client of active) {
    const account = String(client.basic_account);
    // Binding by ports never looks at addresses, so an empty address list is a
    // note and not a cause. It still matters: it is what would block this client
    // if the stand were switched to IP binding.
    const noAddress = uniquePrefixes(client).length ? '' : 'в ERP нет ни одного адреса';
    const base = {
      account,
      client_name: clientName(client),
      services: formatServices(client),
      notes: noAddress,
    };
    const ports = uniquePorts(client);
    if (!ports.length) {
      rows.push({
        ...emptyRow(SECTION.ports, category),
        ...base,
        verdict: VERDICT.no,
        reason: REASON.no_port,
      });
      continue;
    }
    for (const port of ports) {
      const iface = ifaceRows.get(port.key) || {};
      const agent = agents.get(port.switchIp) || {};
      const row = {
        ...emptyRow(SECTION.ports, category),
        ...base,
        switch_host: port.switchIp,
        inven: port.inven,
        if_index: port.ifIndex,
      };
      const known = {
        switch_name: agent.display_name || '',
        if_name: iface.if_name || '',
        if_alias: iface.if_alias || '',
        speed_mbps: Math.round(Number(iface.if_speed_bps || 0) / 1e6),
      };
      const shared = owners.get(port.key);
      if (shared.size > 1) {
        const others = [...shared].filter((id) => id !== account);
        rows.push({
          ...row,
          ...known,
          verdict: VERDICT.no,
          reason: REASON.conflict,
          notes: joinNotes(noAddress, `тот же порт у ЛС ${others.join(', ')}`),
        });
        continue;
      }
      if (!agents.has(port.switchIp)) {
        rows.push({ ...row, verdict: VERDICT.no, reason: REASON.switch_unknown });
        continue;
      }
      if (!ifaces.has(port.key)) {
        rows.push({
          ...row,
          switch_name: known.switch_name,
          verdict: VERDICT.no,
          reason: REASON.ifindex_unknown,
        });
        continue;
      }
      rows.push({ ...row, ...known, verdict: VERDICT.yes });
    }
  }
  return rows;
}

function buildPrefixRows(active, l3Index, category, { l3Known = true } = {}) {
  const owners = ownersOf(active, uniquePrefixes);
  const entries = [];
  for (const client of active) {
    const account = String(client.basic_account);
    for (const prefix of uniquePrefixes(client)) {
      const parsed = parseCidr(prefix.prefix);
      if (!parsed) continue;
      entries.push({ ...parsed, account, key: `${account}|${prefix.key}` });
    }
  }
  const nesting = findNesting(entries);
  const rows = [];

  for (const client of active) {
    const account = String(client.basic_account);
    const base = {
      account,
      client_name: clientName(client),
      services: formatServices(client),
    };
    const prefixes = uniquePrefixes(client);
    if (!prefixes.length) {
      rows.push({
        ...emptyRow(SECTION.prefixes, category),
        ...base,
        verdict: VERDICT.no,
        reason: REASON.no_ip,
        notes: 'клиента всё равно нужно завести, но привязать не к чему',
      });
      continue;
    }
    for (const prefix of prefixes) {
      const parsed = parseCidr(prefix.prefix);
      const notes = [];
      if (!parsed) notes.push('не разобрали адрес');
      const unusable = parsed ? matchRange(parsed, UNUSABLE) : null;
      const priv = parsed && !unusable ? matchRange(parsed, PRIVATE) : null;
      if (unusable) notes.push(unusable.label);
      if (priv) notes.push(priv.label);
      const covering = parsed && l3Known ? coveringPrefix(parsed, l3Index) : null;
      // A junk address is never in our CIDRs either; saying so twice is noise.
      if (l3Known && parsed && !covering && !unusable && !priv) notes.push('префикс вне наших CIDR');
      if (covering && covering.role === 'remote') notes.push('наш CIDR заведён с ролью remote');
      if (parsed && parsed.bits < (WIDE_MASK[parsed.family] || 0)) {
        notes.push(`широкая маска /${parsed.bits}`);
      }
      const enclosing = nesting.get(`${account}|${prefix.key}`);
      if (enclosing) notes.push(`вложен в ${enclosing.text} (ЛС ${enclosing.account})`);

      const shared = owners.get(prefix.key);
      const isDuplicate = shared && shared.size > 1;
      if (isDuplicate) {
        notes.push(`тот же префикс у ЛС ${[...shared].filter((id) => id !== account).join(', ')}`);
      }
      rows.push({
        ...emptyRow(SECTION.prefixes, category),
        ...base,
        prefix: prefix.prefix,
        l3_prefix: covering ? covering.text : '',
        l3_role: covering ? String(covering.role || '') : '',
        verdict: isDuplicate ? VERDICT.no : VERDICT.yes,
        reason: isDuplicate ? REASON.conflict_prefix : '',
        notes: notes.join('; '),
      });
    }
  }
  return rows;
}

function buildGoneRows(gone, goneNames, category) {
  return (gone || []).map((id) => ({
    ...emptyRow(SECTION.gone, category),
    account: String(id),
    client_name: String(goneNames?.get?.(String(id)) || ''),
    verdict: VERDICT.no,
    reason: 'клиента больше нет в выгрузке ERP',
    notes: 'этим прогоном он и его привязки отключены',
  }));
}

function buildReportRows({
  clients = [],
  catalog = {},
  l3 = [],
  gone = [],
  goneNames = new Map(),
  category = '',
  bindMode = 'ports',
} = {}) {
  const active = clients.filter(isActive);
  const mode = normalizeBindMode(bindMode);
  const main = [];
  if (mode === 'ports') {
    main.push(...buildPortRows(active, catalog, category));
  } else {
    const l3Known = Array.isArray(l3);
    const l3Index = [];
    for (const row of l3Known ? l3 : []) {
      const parsed = parseCidr(row.prefix);
      if (parsed) l3Index.push({ ...parsed, role: String(row.role || '') });
    }
    main.push(...buildPrefixRows(active, l3Index, category, { l3Known }));
  }
  return [...main, ...buildGoneRows(gone, goneNames, category)];
}

function summarizeReport(rows = []) {
  const bySection = {};
  const problems = {};
  for (const row of rows) {
    const section = row.section || '';
    if (!bySection[section]) bySection[section] = { total: 0, да: 0, нет: 0 };
    bySection[section].total += 1;
    if (row.verdict) bySection[section][row.verdict] += 1;
    for (const note of String(row.notes || '').split('; ')) {
      if (!note) continue;
      const key = note.replace(/ЛС .*/, 'ЛС …').replace(/\/\d+$/, '/…');
      problems[key] = (problems[key] || 0) + 1;
    }
    if (row.reason) problems[row.reason] = (problems[row.reason] || 0) + 1;
  }
  return { rows: rows.length, bySection, problems };
}

function csvEscape(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

// ifIndex and speed are UInt32 in ClickHouse, so a row the sync could not
// resolve carries 0 rather than null. Print those cells empty, as the sheet did.
const BLANK_WHEN_ZERO = new Set(['if_index', 'speed_mbps']);

/** Columns of the mode the run used, read back from the rows themselves so the
 *  CSV route does not have to know how the run was configured. Runs stored
 *  before the report became mode-specific carry both sections and keep the
 *  full set. */
function reportColumns(rows = []) {
  const ports = rows.some((row) => row.section === SECTION.ports);
  const prefixes = rows.some((row) => row.section === SECTION.prefixes);
  if (ports && prefixes) return REPORT_COLUMNS;
  return [
    ...COLUMNS_HEAD,
    ...(prefixes ? COLUMNS_PREFIXES : COLUMNS_PORTS),
    ...COLUMNS_TAIL,
  ];
}

function reportToCsv(rows = []) {
  const columns = reportColumns(rows);
  const lines = [columns.map(([, label]) => csvEscape(label)).join(',')];
  for (const row of rows) {
    lines.push(columns.map(([key]) => {
      const value = row[key];
      if (BLANK_WHEN_ZERO.has(key) && !Number(value)) return '';
      return csvEscape(value);
    }).join(','));
  }
  return lines.join('\n');
}

module.exports = {
  SECTION,
  VERDICT,
  REPORT_COLUMNS,
  reportColumns,
  parseCidr,
  coveringPrefix,
  findNesting,
  formatServices,
  buildReportRows,
  summarizeReport,
  reportToCsv,
};
