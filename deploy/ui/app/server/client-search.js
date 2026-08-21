'use strict';

const DEFAULT_REFS = {
  clientAlias: 'c',
  prefixesFrom: 'default.net_client_prefixes_enabled',
  prefixesExtraWhere: '',
  portsFrom: 'default.net_client_ports_enabled',
  portsExtraWhere: '',
  interfacesFrom: 'default.net_interfaces_current',
};

function splitClientSearchTokens(raw) {
  return String(raw ?? '').trim().split(/\s+/).filter(Boolean);
}

function parseIpv4SearchTerm(raw) {
  const q = String(raw ?? '').trim();
  const m = q.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  if (m.slice(1).some((octet) => Number(octet) > 255)) return null;
  return q;
}

function ipv4ToInt(ip) {
  const parsed = parseIpv4SearchTerm(ip);
  if (!parsed) return null;
  return parsed.split('.').reduce((acc, octet) => ((acc << 8) + Number(octet)) >>> 0, 0);
}

function ipv4InCidr(ip, cidr) {
  const raw = String(cidr ?? '').trim();
  const slash = raw.indexOf('/');
  const net = slash >= 0 ? raw.slice(0, slash) : raw;
  const bitsRaw = slash >= 0 ? Number(raw.slice(slash + 1)) : 32;
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(net);
  if (ipInt == null || netInt == null) return false;
  if (!Number.isInteger(bitsRaw) || bitsRaw < 0 || bitsRaw > 32) return false;
  const mask = bitsRaw === 0 ? 0 : (0xFFFFFFFF << (32 - bitsRaw)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function asStringArray(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item ?? '').trim()).filter(Boolean);
  }
  if (value == null) return [];
  const raw = String(value).trim();
  if (!raw) return [];
  if (raw.startsWith('[')) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed.map((item) => String(item ?? '').trim()).filter(Boolean);
      }
    } catch {
      // fall through to comma-split
    }
  }
  return raw.split(/\s*,\s*/).map((item) => item.trim()).filter(Boolean);
}

function clientRowMatchesSearch(row, raw, extraHay = []) {
  const tokens = splitClientSearchTokens(raw);
  if (!tokens.length) return true;
  const prefixes = asStringArray(row.bindingPrefixes ?? row.binding_prefixes);
  const hay = [
    row.displayName,
    row.display_name,
    row.clientId,
    row.client_id,
    row.comment,
    row.bindMode,
    row.bind_mode,
    row.bindingSearch,
    row.binding_search,
    ...asStringArray(row.bindingPreview ?? row.binding_preview),
    ...prefixes,
    ...extraHay,
  ].join('\n').toLowerCase();

  return tokens.every((token) => {
    if (hay.includes(token.toLowerCase())) return true;
    const ip = parseIpv4SearchTerm(token);
    return !!(ip && prefixes.some((prefix) => ipv4InCidr(ip, prefix)));
  });
}

function buildTokenMatchSql(token, params, index, refs) {
  const key = `q${index}`;
  params[key] = token;
  const client = refs.clientAlias || DEFAULT_REFS.clientAlias;
  const prefixesExtra = refs.prefixesExtraWhere || '';
  const portsExtra = refs.portsExtraWhere || '';
  const parts = [
    `positionCaseInsensitive(${client}.display_name, {${key}:String}) > 0`,
    `positionCaseInsensitive(${client}.client_id, {${key}:String}) > 0`,
    `positionCaseInsensitive(${client}.comment, {${key}:String}) > 0`,
    `${client}.client_id = {${key}:String}`,
    `startsWith(${client}.client_id, {${key}:String})`,
    `${client}.client_id IN (
      SELECT p.client_id
      FROM ${refs.prefixesFrom} AS p
      WHERE 1 = 1
        ${prefixesExtra}
        AND (
          positionCaseInsensitive(p.prefix, {${key}:String}) > 0
          OR (isIPv4String({${key}:String}) AND isIPAddressInRange({${key}:String}, p.prefix))
        )
    )`,
    `${client}.client_id IN (
      SELECT p.client_id
      FROM ${refs.portsFrom} AS p
      LEFT JOIN ${refs.interfacesFrom} AS ni
        ON ni.switch_ip = p.switch_ip AND ni.if_index = p.if_index
      WHERE 1 = 1
        ${portsExtra}
        AND (
          positionCaseInsensitive(p.switch_ip, {${key}:String}) > 0
          OR positionCaseInsensitive(p.comment, {${key}:String}) > 0
          OR positionCaseInsensitive(ifNull(ni.if_name, ''), {${key}:String}) > 0
          OR positionCaseInsensitive(ifNull(ni.if_alias, ''), {${key}:String}) > 0
          OR positionCaseInsensitive(ifNull(ni.if_descr, ''), {${key}:String}) > 0
          OR toString(p.if_index) = {${key}:String}
        )
    )`,
  ];
  return `(${parts.join('\n      OR ')})`;
}

function buildClientSearchWhere(search, params, refs = {}) {
  const tokens = splitClientSearchTokens(search);
  const resolved = { ...DEFAULT_REFS, ...refs };
  if (!tokens.length) return '1';
  return tokens
    .map((token, index) => buildTokenMatchSql(token, params, index, resolved))
    .join('\n    AND ');
}

module.exports = {
  DEFAULT_REFS,
  splitClientSearchTokens,
  parseIpv4SearchTerm,
  ipv4InCidr,
  asStringArray,
  clientRowMatchesSearch,
  buildClientSearchWhere,
};
