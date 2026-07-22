const fs = require('fs');
const path = require('path');
const {
  col,
  colOpt,
  config,
  flowCol,
  flowsRawTableRef,
  portServicesExpandedViewRef,
  asnNamesTableRef,
  asnRegistryEnrichedTableRef,
  l3PrefixesTableRef,
  entitiesViewRef,
  l2VlansViewRef,
  sourcesTableRef,
  netInterfacesCurrentRef,
  snmpAgentsCurrentRef,
  escapeSqlString,
  query,
} = require('./clickhouse');
const { protocolChartColor } = require('./protocol-colors');
const { getVlanNameMap, vlanLabel } = require('./net-l2-vlans');
const {
  resolveTrafficWindow,
  flowIpExpr,
  flowSamplerIpExpr,
  flowMacExpr,
  protoLabelSql,
  flowTransportSql,
  customRangeDurationMs,
  protoLabel,
  appendFlowsRawCollectorFilter,
  parseCollectorScopes,
  sourcesScopeSql,
  mergeCollectorParams,
} = require('./queries');
const {
  EXPLORER_TCP_FLAG_OPTIONS,
  parseTcpFlagsFilterValue,
  tcpFlagsLabelSql,
  tcpFlagsMaskToLabel,
  tcpFlagsNamesToMask,
  parseTcpFlagNames,
} = require('./tcp-flags');

const EXPLORER_MAX_LIMIT = 100;
const EXPLORER_MAX_EXPORT_ROWS = 10000;
const EXPLORER_MAX_RANGE_DAYS = 365;
const EXPLORER_MAX_RANGE_MS = EXPLORER_MAX_RANGE_DAYS * 86400000;
const EXPLORER_FILTER_LOGIC = new Set(['and', 'or', 'and_not', 'or_not']);
const EXPLORER_METRIC_KEYS = new Set(['bps', 'volume', 'pps', 'fps', 'flows', 'uniq_src']);
const SAVED_FILTERS_FILE = path.join(__dirname, 'data', 'explorer-saved-filters.json');

const FILTER_OPS_BY_TYPE = {
  string: ['=', '!=', 'contains', 'not_contains', 'in', 'not_in'],
  number: ['=', '!=', '>', '>=', '<', '<=', 'between', 'in'],
  ip: ['=', '!=', 'cidr', 'in'],
  switch_ip: ['=', '!=', 'cidr', 'in'],
  if_name: ['=', '!=', 'contains', 'not_contains', 'in', 'not_in'],
  mac: ['=', '!=', 'in', 'not_in', 'contains'],
  enum: ['=', '!=', 'in', 'not_in'],
  tcp_flags: ['has_any', 'has_all', 'eq', 'neq'],
  country: ['=', '!=', 'contains', 'not_contains', 'in', 'not_in'],
  entity: ['=', 'in'],
};

const DIMENSION_GROUPS = {
  IP: ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'tcp_flags', 'src_service', 'dst_service'],
  'AS / GEO': ['src_asn', 'dst_asn', 'src_country', 'dst_country'],
  'L2 / MAC': ['src_mac', 'dst_mac'],
  'L3 / Сети': ['l3_owner', 'own_network', 'src_network', 'dst_network'],
  'Инфраструктура': [
    'direction', 'source_id', 'switch_ip', 'in_if_name', 'out_if_name',
    'src_label', 'dst_label', 'src_scope', 'dst_scope',
  ],
  VLAN: ['vlan', 'vlan_attachment', 'src_vlan'],
};

const EXPLORER_FILTER_HINTS = {
  ip: 'IPv4, IPv6 или CIDR — напр. 10.0.0.0/24',
  switch_ip: 'IP или название коммутатора из SNMP-инвентаря',
  if_name: 'ifName, alias или ifIndex — напр. Ethernet1/1',
  number: 'Число; для in — через запятую: 443,80',
  string: 'Строка; для in — через запятую',
  mac: 'MAC — aa:bb:cc:dd:ee:ff или aabbccddeeff; для in — через запятую',
  enum: 'Выберите из списка или введите значение',
  tcp_flags: 'Выберите один или несколько TCP-флагов',
  asn: 'Номер ASN или название — напр. 12389',
  vlan: 'ID VLAN или имя',
  service: 'Код или название сервиса',
  l3_owner: 'Поиск L3-сущности',
  own_network: 'Префикс CIDR — напр. 10.0.0.0/24',
};

const EXPLORER_PROTO_OPTIONS = [
  { value: 'ICMP', hint: 'proto 1' },
  { value: 'TCP', hint: 'proto 6' },
  { value: 'UDP', hint: 'proto 17' },
  { value: 'GRE', hint: 'proto 47' },
  { value: 'ESP', hint: 'proto 50' },
  { value: 'AH', hint: 'proto 51' },
  { value: 'ICMPv6', hint: 'proto 58' },
  { value: 'SCTP', hint: 'proto 132' },
];

const EXPLORER_DIRECTION_OPTIONS = [
  { value: 'total', hint: 'всего' },
  { value: 'in', hint: 'входящий' },
  { value: 'out', hint: 'исходящий' },
  { value: 'transit', hint: 'транзит' },
  { value: 'internal', hint: 'внутренний' },
  { value: 'unknown', hint: 'неизвестный' },
];

const EXPLORER_FIELD_HINTS = {
  src_port: 'Порт 1–65535',
  dst_port: 'Порт 1–65535',
  src_asn: 'Номер ASN — напр. 12389',
  dst_asn: 'Номер ASN — напр. 12389',
  src_country: 'Код ISO-2 — напр. RU',
  dst_country: 'Код ISO-2 — напр. RU',
  source_id: 'ID экспортёра / source_id',
  switch_ip: 'IP или название из SNMP-инвентаря',
  in_if_name: 'ifName, alias или ifIndex входного порта',
  out_if_name: 'ifName, alias или ifIndex выходного порта',
};

function explorerSnmpPollStatusLabel(status, snmpEnabled, hasCache = false) {
  if (!Number(snmpEnabled)) return 'Отключён';
  const poll = String(status || '');
  if (poll === 'ok') return 'SNMP работает';
  if (poll === 'queued' || poll === 'never') {
    return hasCache ? 'Идёт опрос' : 'Ожидает опроса';
  }
  if (hasCache) return 'Недоступен · есть кэш';
  return poll ? 'Ошибка SNMP' : '';
}

function explorerFilterEntityType(filterType) {
  if (filterType === 'l3_owner') return 'l3_owner';
  if (filterType === 'own_network') return 'own_network';
  if (filterType === 'vlan') return 'vlan';
  if (filterType === 'asn') return 'asn';
  if (filterType === 'service') return 'service';
  if (filterType === 'switch_ip') return 'switch_ip';
  if (filterType === 'if_name') return 'if_name';
  return null;
}

function explorerFilterFieldMeta(id, d) {
  const type = d.filterType || d.kind;
  const valueOptions = d.valueOptions
    || (id === 'proto' ? EXPLORER_PROTO_OPTIONS : null)
    || (id === 'direction' ? EXPLORER_DIRECTION_OPTIONS : null)
    || (id === 'tcp_flags' ? EXPLORER_TCP_FLAG_OPTIONS : null);
  return {
    id,
    label: d.label,
    group: d.group || 'Прочее',
    type,
    ops: FILTER_OPS_BY_TYPE[type] || FILTER_OPS_BY_TYPE.string,
    entityType: explorerFilterEntityType(type),
    valueHint: d.valueHint || EXPLORER_FIELD_HINTS[id] || EXPLORER_FILTER_HINTS[type] || EXPLORER_FILTER_HINTS.string,
    valueOptions,
  };
}

const EXPLORER_RESULT_EXPORT_COLUMNS = [
  { key: 'bytes', label: 'Объём' },
  { key: 'avgBps', label: 'Средняя бит/с' },
  { key: 'pps', label: 'Пакеты/с' },
  { key: 'fps', label: 'Потоки/с' },
  { key: 'flows', label: 'Flows' },
  { key: 'packets', label: 'Packets' },
];

function enrichExplorerFlowRow(row, windowSeconds) {
  const bytes = Number(row.bytes) || 0;
  const packets = Number(row.packets) || 0;
  const flows = Number(row.flows) || 0;
  const avgFromSql = Number(row.avgBps);
  const avgBps = Number.isFinite(avgFromSql) && avgFromSql > 0
    ? avgFromSql
    : (windowSeconds > 0 ? Math.round(bytes * 8 / windowSeconds) : 0);
  const ws = windowSeconds > 0 ? windowSeconds : 0;
  return {
    ...row,
    bytes,
    packets,
    flows,
    avgBps,
    pps: ws > 0 ? Math.round(packets / ws) : 0,
    fps: ws > 0 ? Math.round((flows / ws) * 100) / 100 : 0,
  };
}

function parseExplorerAsnNumber(value) {
  const s = String(value ?? '').trim();
  if (!s || s === '—') return null;
  const prefixed = s.match(/^AS(\d+)$/i);
  if (prefixed) return Number(prefixed[1]);
  if (/^\d+$/.test(s)) return Number(s);
  return null;
}

function isPseudoAsnName(name) {
  return /^AS?\d+$/i.test(String(name || '').trim());
}

function normalizeAsnLookupName(rawName, asn) {
  const name = String(rawName || '').trim();
  if (!name || isPseudoAsnName(name)) return '';
  if (name.toUpperCase() === `AS${asn}`) return '';
  return name;
}

function asnTableNameExpr(tableAlias = '') {
  const p = tableAlias ? `${tableAlias}.` : '';
  return `nullIf(${p}name, '')`;
}

function asnExplorerDisplayLabel(asn, asName) {
  const n = Number(asn);
  if (!Number.isFinite(n) || n <= 0) return '—';
  const name = String(asName || '').trim();
  if (name && !isPseudoAsnName(name)) return `${name} (AS${n})`;
  return `AS${n}`;
}

async function loadAsnNamesFromTable(tableRef, asns, source, byAsn, { overwrite = false } = {}) {
  if (!asns.length) return;
  const nameExpr = asnTableNameExpr();
  const { rows } = await query(`
    SELECT asn, ${nameExpr} AS display_name
    FROM ${tableRef}
    WHERE asn IN ({asns:Array(UInt32)})
  `, { asns }, { name: `explorer/asn-name-${source}` });
  for (const r of rows) {
    const asn = Number(r.asn);
    if (!Number.isFinite(asn) || asn <= 0) continue;
    const asName = normalizeAsnLookupName(r.display_name, asn);
    if (overwrite || !byAsn.get(asn)) byAsn.set(asn, asName);
  }
}

async function lookupAsnDisplayNames(asnList) {
  const unique = [...new Set(asnList.filter((n) => Number.isFinite(n) && n > 0))];
  if (!unique.length) return new Map();
  const byAsn = new Map();
  try {
    await loadAsnNamesFromTable(asnNamesTableRef(), unique, 'names', byAsn, { overwrite: true });
  } catch {
    // keep partial results
  }
  const missing = unique.filter((asn) => !byAsn.get(asn));
  if (missing.length) {
    try {
      await loadAsnNamesFromTable(asnRegistryEnrichedTableRef(), missing, 'registry', byAsn);
    } catch {
      // registry is optional fallback
    }
  }
  return byAsn;
}

function dedupeExplorerAsnEntities(rows) {
  const byAsn = new Map();
  for (const r of rows) {
    const asn = Number(r.asn);
    if (!Number.isFinite(asn) || asn <= 0) continue;
    const priority = Number(r.priority) || 9;
    const name = normalizeAsnLookupName(r.name, asn);
    const prev = byAsn.get(asn);
    if (!prev) {
      byAsn.set(asn, { asn, name, priority });
      continue;
    }
    if (priority < prev.priority) {
      byAsn.set(asn, { asn, name: name || prev.name, priority });
    } else if (!prev.name && name) {
      byAsn.set(asn, { asn, name, priority: prev.priority });
    }
  }
  return [...byAsn.values()].sort((a, b) => a.asn - b.asn);
}

function ensureSavedFiltersDir() {
  const dir = path.dirname(SAVED_FILTERS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readSavedFiltersStore() {
  ensureSavedFiltersDir();
  if (!fs.existsSync(SAVED_FILTERS_FILE)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(SAVED_FILTERS_FILE, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeSavedFiltersStore(items) {
  ensureSavedFiltersDir();
  fs.writeFileSync(SAVED_FILTERS_FILE, JSON.stringify(items, null, 2));
}

function explorerWindowSeconds({ range = '24h', from, to } = {}) {
  if (range === 'custom') {
    return Math.max(1, Math.floor(customRangeDurationMs(from, to) / 1000));
  }
  const secondsByRange = {
    '30m': 30 * 60, '1h': 3600, '3h': 3 * 3600, '6h': 6 * 3600,
    '12h': 12 * 3600, '24h': 86400, '2d': 2 * 86400, '7d': 7 * 86400,
    '14d': 14 * 86400, '30d': 30 * 86400, '60d': 60 * 86400, '90d': 90 * 86400,
  };
  return secondsByRange[range] || 3600;
}

function resolveExplorerGranularity({ range, from, to, granularity = 'auto' } = {}) {
  if (granularity && granularity !== 'auto') {
    const map = { '1m': 60, '5m': 300, '1h': 3600, '1d': 86400 };
    if (map[granularity]) return { key: granularity, seconds: map[granularity] };
  }
  const windowSec = explorerWindowSeconds({ range, from, to });
  if (windowSec <= 30 * 60) return { key: '1m', seconds: 60 };
  if (windowSec <= 2 * 86400) return { key: '5m', seconds: 300 };
  if (windowSec <= 14 * 86400) return { key: '1h', seconds: 3600 };
  return { key: '1d', seconds: 86400 };
}

function explorerScaledFlowExprs(prefix = 'f') {
  const bytesCol = col('bytes');
  const packetsCol = col('packets');
  const samplingCol = flowCol('samplingRate');
  if (!samplingCol) {
    return {
      bytes: `${prefix}.${bytesCol}`,
      packets: `${prefix}.${packetsCol}`,
      flowWeight: '1',
      sampled: false,
    };
  }
  const scale = `coalesce(${prefix}.${samplingCol}, 1)`;
  return {
    bytes: `${prefix}.${bytesCol}`,
    packets: `${prefix}.${packetsCol}`,
    flowWeight: scale,
    sampled: true,
  };
}

function buildExplorerMetricSpecs(scaled) {
  const srcIp = col('srcIp');
  return {
    bps: {
      label: 'Средняя бит/с',
      expr: `round(sum(${scaled.bytes}) * 8 / window_seconds, 0)`,
      pctBase: `sum(${scaled.bytes})`,
      sortField: 'bytes',
    },
    volume: {
      label: 'Объём',
      expr: `sum(${scaled.bytes})`,
      pctBase: `sum(${scaled.bytes})`,
      sortField: 'bytes',
    },
    pps: {
      label: 'Пакеты/с',
      expr: `round(sum(${scaled.packets}) / window_seconds, 0)`,
      pctBase: `sum(${scaled.packets})`,
      sortField: 'packets',
    },
    fps: {
      label: 'Потоки/с',
      expr: `round(sum(${scaled.flowWeight}) / window_seconds, 2)`,
      pctBase: `sum(${scaled.flowWeight})`,
      sortField: 'flows',
    },
    flows: {
      label: 'Всего потоков',
      expr: `sum(${scaled.flowWeight})`,
      pctBase: `sum(${scaled.flowWeight})`,
      sortField: 'flows',
    },
    uniq_src: {
      label: 'Уникальных source IP',
      expr: `uniqCombined(f.${srcIp})`,
      pctBase: `uniqCombined(f.${srcIp})`,
      sortField: 'metric_value',
    },
  };
}

function effectiveVlanExpr(prefix = 'f') {
  const directionCol = flowCol('direction');
  const srcVlanCol = flowCol('srcVlan');
  const dstVlanCol = flowCol('dstVlan');
  if (!directionCol || !srcVlanCol || !dstVlanCol) return null;
  return `multiIf(`
    + `${prefix}.${directionCol} = 'out', ${prefix}.${srcVlanCol}, `
    + `${prefix}.${directionCol} = 'in', ${prefix}.${dstVlanCol}, `
    + `${prefix}.${srcVlanCol} != 0, ${prefix}.${srcVlanCol}, `
    + `${prefix}.${dstVlanCol})`;
}

function geoCountryExpr(ipExpr, etypeExpr = null) {
  const dict = escapeSqlString(config.geoCountryDict);
  const lookup = (keyExpr) => `dictGetString('${dict}', 'cc', tuple(${keyExpr}))`;
  const ipv4Expr = `toIPv4(reinterpretAsUInt32(reverse(substring(${ipExpr}, 1, 4))))`;
  const isIpv4 = etypeExpr
    ? `${etypeExpr} = 2048`
    : `length(${ipExpr}) = 16 AND substring(${ipExpr}, 5) = unhex('000000000000000000000000')`;
  const country = `upper(if(${isIpv4}, ${lookup(ipv4Expr)}, ${lookup(ipExpr)}))`;
  return `nullIf(nullIf(${country}, ''), '??')`;
}

function explorerDimensions() {
  const t = {
    srcIp: col('srcIp'),
    dstIp: col('dstIp'),
    srcPort: col('srcPort'),
    dstPort: col('dstPort'),
    proto: col('proto'),
    srcAsn: col('srcAsn'),
    dstAsn: col('dstAsn'),
  };
  const srcIpExpr = flowIpExpr(`f.${t.srcIp}`);
  const dstIpExpr = flowIpExpr(`f.${t.dstIp}`);
  const etypeCol = flowCol('etype');
  const etypeExpr = etypeCol ? `f.${etypeCol}` : null;
  const srcCountryExpr = geoCountryExpr(`f.${t.srcIp}`, etypeExpr);
  const dstCountryExpr = geoCountryExpr(`f.${t.dstIp}`, etypeExpr);
  // Label FixedString(16) keys without row-level etype (outer phase after LIMIT).
  const ipLabelFromKey = (k) => `if(
        length(${k}) = 16
          AND substring(${k}, 5) = unhex('000000000000000000000000'),
        toString(toIPv4(reinterpretAsUInt32(reverse(substring(${k}, 1, 4))))),
        IPv6NumToString(${k})
      )`;
  const dims = {
    src_ip: {
      label: 'Source IP', group: 'IP', kind: 'ip', expr: srcIpExpr, filterType: 'ip', filterExpr: srcIpExpr,
      groupKeyExpr: `f.${t.srcIp}`,
      labelFromKey: ipLabelFromKey,
    },
    dst_ip: {
      label: 'Destination IP', group: 'IP', kind: 'ip', expr: dstIpExpr, filterType: 'ip', filterExpr: dstIpExpr,
      groupKeyExpr: `f.${t.dstIp}`,
      labelFromKey: ipLabelFromKey,
    },
    src_port: {
      label: 'Source Port', group: 'IP', kind: 'number', expr: `toString(f.${t.srcPort})`, filterType: 'number', filterExpr: `f.${t.srcPort}`,
      groupKeyExpr: `f.${t.srcPort}`,
      labelFromKey: (k) => `toString(${k})`,
    },
    dst_port: {
      label: 'Destination Port', group: 'IP', kind: 'number', expr: `toString(f.${t.dstPort})`, filterType: 'number', filterExpr: `f.${t.dstPort}`,
      groupKeyExpr: `f.${t.dstPort}`,
      labelFromKey: (k) => `toString(${k})`,
    },
    proto: {
      label: 'Протокол', group: 'IP', kind: 'enum', expr: protoLabelSql(`f.${t.proto}`), filterType: 'enum', filterExpr: protoLabelSql(`f.${t.proto}`), rawExpr: `f.${t.proto}`,
      groupKeyExpr: `f.${t.proto}`,
      labelFromKey: (k) => protoLabelSql(k),
    },
    src_asn: {
      label: 'Source ASN', group: 'AS / GEO', kind: 'asn',
      expr: `if(f.${t.srcAsn} > 0, concat('AS', toString(f.${t.srcAsn})), '—')`,
      filterType: 'asn', filterExpr: `f.${t.srcAsn}`, side: 'src',
      groupKeyExpr: `f.${t.srcAsn}`,
      labelFromKey: (k) => `if(${k} > 0, concat('AS', toString(${k})), '—')`,
    },
    dst_asn: {
      label: 'Destination ASN', group: 'AS / GEO', kind: 'asn',
      expr: `if(f.${t.dstAsn} > 0, concat('AS', toString(f.${t.dstAsn})), '—')`,
      filterType: 'asn', filterExpr: `f.${t.dstAsn}`, side: 'dst',
      groupKeyExpr: `f.${t.dstAsn}`,
      labelFromKey: (k) => `if(${k} > 0, concat('AS', toString(${k})), '—')`,
    },
    src_country: {
      label: 'Source country', group: 'AS / GEO', kind: 'string',
      expr: srcCountryExpr, filterType: 'country', filterExpr: srcCountryExpr,
      groupKeyExpr: srcCountryExpr,
      labelFromKey: (k) => `toString(${k})`,
    },
    dst_country: {
      label: 'Destination country', group: 'AS / GEO', kind: 'string',
      expr: dstCountryExpr, filterType: 'country', filterExpr: dstCountryExpr,
      groupKeyExpr: dstCountryExpr,
      labelFromKey: (k) => `toString(${k})`,
    },
  };

  const optional = {
    direction: ['direction', 'Direction', 'Инфраструктура', 'enum'],
    source_id: ['sourceId', 'Source ID', 'Инфраструктура', 'string'],
    src_label: ['srcLabel', 'Source label', 'Инфраструктура', 'string'],
    dst_label: ['dstLabel', 'Destination label', 'Инфраструктура', 'string'],
    src_scope: ['srcEndpointScope', 'Source scope', 'Инфраструктура', 'string'],
    dst_scope: ['dstEndpointScope', 'Destination scope', 'Инфраструктура', 'string'],
    src_network: ['srcNetworkName', 'Source network', 'L3 / Сети', 'string'],
    dst_network: ['dstNetworkName', 'Destination network', 'L3 / Сети', 'string'],
    src_vlan: ['srcVlan', 'Source VLAN (raw)', 'VLAN', 'number'],
  };
  for (const [id, [key, label, group, filterType]] of Object.entries(optional)) {
    const c = flowCol(key);
    if (c) {
      dims[id] = {
        label, group, kind: filterType, filterType,
        expr: `toString(f.${c})`,
        filterExpr: filterType === 'number' ? `f.${c}` : `toString(f.${c})`,
        groupKeyExpr: `f.${c}`,
        labelFromKey: (k) => `toString(${k})`,
      };
    }
  }

  const samplerCol = flowCol('samplerAddress');
  const inIfCol = flowCol('inIf');
  const outIfCol = flowCol('outIf');
  if (samplerCol) {
    const switchIpExpr = flowSamplerIpExpr(`f.${samplerCol}`);
    dims.switch_ip = {
      label: 'IP или название',
      group: 'Инфраструктура',
      kind: 'ip',
      expr: switchIpExpr,
      filterType: 'switch_ip',
      filterExpr: switchIpExpr,
      valueHint: 'IP или название из SNMP-инвентаря',
      groupKeyExpr: `f.${samplerCol}`,
      labelFromKey: (k) => flowSamplerIpExpr(k),
    };

    // Join the SNMP interface catalog directly. A ClickHouse dictionary is
    // optional for other consumers, but Explorer runs as ui_read and must not
    // depend on dictGet grants / dictionary SOURCE credentials.
    const ifacesRef = netInterfacesCurrentRef();
    const sflowIfIndexExpr = (ifColRef) => {
      const rawExpr = `toUInt32OrZero(toString(${ifColRef}))`;
      return `if(${rawExpr} > 0 AND bitShiftRight(${rawExpr}, 30) = 0, bitAnd(${rawExpr}, 1073741823), toUInt32(0))`;
    };
    if (inIfCol) {
      dims.in_if_name = {
        label: 'Входной: имя / alias',
        group: 'Инфраструктура',
        kind: 'string',
        expr: `ifNull(nullIf(snmp_in.if_name, ''), '')`,
        filterType: 'if_name',
        filterExpr: `ifNull(nullIf(snmp_in.if_name, ''), '')`,
        valueHint: 'ifName, alias или ifIndex',
        joinSql: `
        LEFT JOIN ${ifacesRef} AS snmp_in
          ON snmp_in.switch_ip = ${switchIpExpr}
          AND snmp_in.if_index = ${sflowIfIndexExpr(`f.${inIfCol}`)}`,
        groupKeyExpr: `f.${inIfCol}`,
        labelJoin: {
          needsSampler: true,
          joinSql: (samplerKey, ifKey) => `
        LEFT JOIN ${ifacesRef} AS snmp_in
          ON snmp_in.switch_ip = ${flowSamplerIpExpr(samplerKey)}
          AND snmp_in.if_index = ${sflowIfIndexExpr(ifKey)}`,
          labelExpr: `ifNull(nullIf(snmp_in.if_name, ''), '')`,
        },
      };
    }
    if (outIfCol) {
      dims.out_if_name = {
        label: 'Выходной: имя / alias',
        group: 'Инфраструктура',
        kind: 'string',
        expr: `ifNull(nullIf(snmp_out.if_name, ''), '')`,
        filterType: 'if_name',
        filterExpr: `ifNull(nullIf(snmp_out.if_name, ''), '')`,
        valueHint: 'ifName, alias или ifIndex',
        joinSql: `
        LEFT JOIN ${ifacesRef} AS snmp_out
          ON snmp_out.switch_ip = ${switchIpExpr}
          AND snmp_out.if_index = ${sflowIfIndexExpr(`f.${outIfCol}`)}`,
        groupKeyExpr: `f.${outIfCol}`,
        labelJoin: {
          needsSampler: true,
          joinSql: (samplerKey, ifKey) => `
        LEFT JOIN ${ifacesRef} AS snmp_out
          ON snmp_out.switch_ip = ${flowSamplerIpExpr(samplerKey)}
          AND snmp_out.if_index = ${sflowIfIndexExpr(ifKey)}`,
          labelExpr: `ifNull(nullIf(snmp_out.if_name, ''), '')`,
        },
      };
    }
  }

  const srcMacCol = flowCol('srcMac');
  if (srcMacCol) {
    dims.src_mac = {
      label: 'Source MAC',
      group: 'L2 / MAC',
      kind: 'mac',
      expr: flowMacExpr(`f.${srcMacCol}`),
      filterType: 'mac',
      filterExpr: `f.${srcMacCol}`,
      groupKeyExpr: `f.${srcMacCol}`,
      labelFromKey: (k) => flowMacExpr(k),
    };
  }
  const dstMacCol = flowCol('dstMac');
  if (dstMacCol) {
    dims.dst_mac = {
      label: 'Destination MAC',
      group: 'L2 / MAC',
      kind: 'mac',
      expr: flowMacExpr(`f.${dstMacCol}`),
      filterType: 'mac',
      filterExpr: `f.${dstMacCol}`,
      groupKeyExpr: `f.${dstMacCol}`,
      labelFromKey: (k) => flowMacExpr(k),
    };
  }

  const effVlan = effectiveVlanExpr('f');
  if (effVlan) {
    dims.vlan = {
      label: 'VLAN', group: 'VLAN', kind: 'vlan',
      expr: `toString(${effVlan})`, filterType: 'vlan', filterExpr: effVlan,
      groupKeyExpr: effVlan,
      labelFromKey: (k) => `toString(${k})`,
    };
  }

  const directionCol = flowCol('direction');
  const srcAkCol = flowCol('srcAttachmentKind');
  const dstAkCol = flowCol('dstAttachmentKind');
  if (directionCol && srcAkCol && dstAkCol) {
    const effAk = `multiIf(`
      + `f.${directionCol} = 'out', f.${srcAkCol}, `
      + `f.${directionCol} = 'in', f.${dstAkCol}, `
      + `f.${srcAkCol} != 'unknown', f.${srcAkCol}, `
      + `f.${dstAkCol})`;
    dims.vlan_attachment = {
      label: 'Attachment type', group: 'VLAN', kind: 'string',
      expr: `toString(${effAk})`, filterType: 'enum', filterExpr: effAk,
    };
  }

  const psView = portServicesExpandedViewRef();
  const protoCol = col('proto');
  if (psView) {
    const srcServiceExpr = `coalesce(nullIf(ps_src.service_name, ''), ps_src.service_code, '—')`;
    const dstServiceExpr = `coalesce(nullIf(ps_dst.service_name, ''), ps_dst.service_code, '—')`;
    dims.src_service = {
      label: 'Source service', group: 'IP', kind: 'service',
      expr: srcServiceExpr, filterType: 'service', side: 'src',
      joinSql: `
        LEFT JOIN ${psView} AS ps_src
          ON ps_src.transport = ${flowTransportSql(`f.${protoCol}`)}
          AND ps_src.port = f.${col('srcPort')}`,
    };
    dims.dst_service = {
      label: 'Destination service', group: 'IP', kind: 'service',
      expr: dstServiceExpr, filterType: 'service', side: 'dst',
      joinSql: `
        LEFT JOIN ${psView} AS ps_dst
          ON ps_dst.transport = ${flowTransportSql(`f.${protoCol}`)}
          AND ps_dst.port = f.${col('dstPort')}`,
    };
  }

  dims.l3_owner = {
    label: 'L3 владелец', group: 'L3 / Сети', kind: 'entity',
    expr: `'—'`, filterType: 'l3_owner', virtual: true,
  };
  dims.own_network = {
    label: 'Собственная сеть', group: 'L3 / Сети', kind: 'entity',
    expr: `'—'`, filterType: 'own_network', virtual: true,
  };

  const tcpFlagsCol = flowCol('tcpFlags');
  if (tcpFlagsCol) {
    dims.tcp_flags = {
      label: 'TCP flags',
      group: 'IP',
      kind: 'tcp_flags',
      filterType: 'tcp_flags',
      filterExpr: `f.${tcpFlagsCol}`,
      expr: tcpFlagsLabelSql(`f.${tcpFlagsCol}`),
      groupKeyExpr: `f.${tcpFlagsCol}`,
      labelFromKey: (k) => tcpFlagsLabelSql(k),
      valueOptions: EXPLORER_TCP_FLAG_OPTIONS,
      valueHint: 'FIN, SYN, RST, PSH, ACK, URG, ECE, CWR',
    };
  }

  return dims;
}

function explorerSchema() {
  const dims = explorerDimensions();
  const metrics = buildExplorerMetricSpecs(explorerScaledFlowExprs('f'));
  const collectorField = {
    id: 'collector',
    label: 'Коллекторы',
    group: 'Система',
    filterType: 'collector',
    ops: ['in', 'not_in', '=', '!='],
    valueHint: 'ID коллектора или loc:location-id',
    entityType: null,
  };
  return {
    dimensions: Object.entries(dims)
      .filter(([, d]) => !d.virtual)
      .map(([id, d]) => ({
        id,
        label: d.label,
        group: d.group || 'Прочее',
        kind: d.kind,
        filterType: d.filterType || d.kind,
        filterOps: FILTER_OPS_BY_TYPE[d.filterType] || FILTER_OPS_BY_TYPE.string,
        groupable: !d.virtual,
      })),
    filterFields: [
      collectorField,
      ...Object.entries(dims).map(([id, d]) => explorerFilterFieldMeta(id, d)),
    ],
    metrics: Object.entries(metrics).map(([id, m]) => ({ id, label: m.label })),
    metricKeys: [...EXPLORER_METRIC_KEYS],
    maxLimit: EXPLORER_MAX_LIMIT,
    maxExportRows: EXPLORER_MAX_EXPORT_ROWS,
    dimensionGroups: DIMENSION_GROUPS,
    granularities: ['auto', '1m', '5m', '1h', '1d'],
  };
}

function normalizeExplorerLimit(limit) {
  return Math.min(Math.max(Number(limit) || 10, 1), EXPLORER_MAX_LIMIT);
}

function normalizeExplorerGroupBy(groupBy, dims) {
  const raw = Array.isArray(groupBy) ? groupBy : [];
  const list = raw.map((d) => String(d || '').trim()).filter((d) => dims[d] && !dims[d].virtual);
  return [...new Set(list)];
}

function normalizeExplorerMetric(metric) {
  const key = String(metric || 'bps').trim();
  return EXPLORER_METRIC_KEYS.has(key) ? key : 'bps';
}

function normalizeFilterLogic(logic) {
  const key = String(logic || 'and').trim().toLowerCase();
  return EXPLORER_FILTER_LOGIC.has(key) ? key : 'and';
}

function normalizeFilterList(filters) {
  return (Array.isArray(filters) ? filters : []).map((f) => ({
    field: String(f?.field || f?.dim || '').trim(),
    op: String(f?.op || '=').trim().toLowerCase(),
    value: f?.value,
    label: f?.label || null,
    logic: normalizeFilterLogic(f?.logic),
  })).filter((f) => f.field);
}

function protoNameToNumber(name) {
  const map = {
    icmp: 1, tcp: 6, udp: 17, gre: 47, esp: 50, ah: 51, icmpv6: 58, sctp: 132,
  };
  const key = String(name || '').trim().toLowerCase();
  return map[key] ?? null;
}

function parseFilterValues(value) {
  if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
  const s = String(value ?? '').trim();
  if (!s) return [];
  if (s.includes(',')) return s.split(',').map((v) => v.trim()).filter(Boolean);
  return [s];
}

async function fetchPrefixesForEntity(entityId) {
  const prefixesTable = l3PrefixesTableRef();
  const { rows } = await query(`
    SELECT prefix
    FROM ${prefixesTable}
    WHERE entity_id = {entityId:String} AND enabled = 1
    ORDER BY updated_at DESC
    LIMIT 1 BY family, prefix
  `, { entityId }, { name: 'explorer/l3-prefixes' });
  return rows.map((r) => String(r.prefix)).filter(Boolean);
}

function buildPrefixRangeClause(prefixes, params, idxRef) {
  if (!prefixes.length) return '0';
  const srcIpExpr = flowIpExpr(`f.${col('srcIp')}`);
  const dstIpExpr = flowIpExpr(`f.${col('dstIp')}`);
  const parts = prefixes.map((prefix) => {
    const paramName = `prefix_${idxRef.i++}`;
    params[paramName] = prefix;
    return `(isIPAddressInRange(${srcIpExpr}, {${paramName}:String}) OR isIPAddressInRange(${dstIpExpr}, {${paramName}:String}))`;
  });
  return parts.length === 1 ? parts[0] : `(${parts.join(' OR ')})`;
}

async function buildEntityPrefixFilter(field, value, params, idxRef) {
  if (field === 'l3_owner') {
    const entityId = String(value ?? '').trim();
    if (!entityId) return null;
    const prefixes = await fetchPrefixesForEntity(entityId);
    return buildPrefixRangeClause(prefixes, params, idxRef);
  }
  if (field === 'own_network') {
    const prefix = String(value ?? '').trim();
    if (!prefix) return null;
    return buildPrefixRangeClause([prefix], params, idxRef);
  }
  return null;
}

function pushExplorerFilterClause(clauses, clause, logic) {
  if (!clause) return;
  clauses.push({ clause, logic: normalizeFilterLogic(logic) });
}

function hasCollectorFilterInList(filters) {
  return normalizeFilterList(filters).some((f) => f.field === 'collector');
}

function buildCollectorScopeClause(scopes, op, flowAlias = 'f') {
  const sourceIdCol = flowCol('sourceId');
  if (!scopes.length || !sourceIdCol) return null;
  const sourceScope = sourcesScopeSql(scopes, 's');
  const inner = `${flowAlias}.${sourceIdCol} IN (
    SELECT source_id FROM ${sourcesTableRef()} AS s
    WHERE ${sourceScope}
  )`;
  const negOps = new Set(['!=', 'not_in']);
  return negOps.has(String(op || '').toLowerCase()) ? `NOT (${inner})` : inner;
}

function applyLegacyCollectorFilter(filters, collectorId, params, whereClauses, flowAlias = 'f') {
  if (hasCollectorFilterInList(filters) || !collectorId) return params;
  return appendFlowsRawCollectorFilter(collectorId, params, whereClauses, flowAlias);
}

function combineExplorerFilterSql(clauses) {
  if (!clauses.length) return null;
  let sql = clauses[0].clause;
  for (let i = 1; i < clauses.length; i++) {
    const { logic, clause } = clauses[i];
    const op = (logic === 'or' || logic === 'or_not') ? 'OR' : 'AND';
    const part = (logic === 'and_not' || logic === 'or_not') ? `NOT (${clause})` : clause;
    sql = `(${sql} ${op} ${part})`;
  }
  return sql;
}

function validateExplorerWindow({ range = '1h', from, to } = {}) {
  if (range === 'custom') {
    if (!from || !to) throw new Error('Для своего периода нужны параметры from и to');
    const durationMs = customRangeDurationMs(from, to);
    if (durationMs > EXPLORER_MAX_RANGE_MS) {
      throw new Error(`Период не может превышать ${EXPLORER_MAX_RANGE_DAYS} дней`);
    }
    return;
  }
  const windowMs = explorerWindowSeconds({ range }) * 1000;
  if (windowMs > EXPLORER_MAX_RANGE_MS) {
    throw new Error(`Период не может превышать ${EXPLORER_MAX_RANGE_DAYS} дней`);
  }
}

function normalizeMacValue(raw) {
  const hex = String(raw ?? '').replace(/[:\-\s.]/g, '').toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex)) return null;
  return hex.match(/.{2}/g).join(':');
}

function normalizeMacValues(values) {
  return (values || []).map(normalizeMacValue).filter(Boolean);
}

function macHexValue(normalizedColonMac) {
  return String(normalizedColonMac || '').replace(/:/g, '');
}

function macContainsNeedle(raw) {
  return String(raw ?? '').replace(/[:\-\s.]/g, '').toLowerCase();
}

function buildMacFilterClause(macCol, op, paramName, { normalized, hexValues, containsNeedle }) {
  const storage = config.macStorage === 'uint64' ? 'uint64' : 'fixedstring';
  if (storage === 'uint64') {
    if (op === 'contains') {
      return `positionCaseInsensitive(${flowMacExpr(macCol)}, {${paramName}:String}) > 0`;
    }
    if (op === 'in') {
      return `${macCol} IN arrayMap(x -> MACStringToNum(x), {${paramName}:Array(String)})`;
    }
    if (op === 'not_in') {
      return `${macCol} NOT IN arrayMap(x -> MACStringToNum(x), {${paramName}:Array(String)})`;
    }
    if (op === '!=') {
      return `${macCol} != MACStringToNum({${paramName}:String})`;
    }
    return `${macCol} = MACStringToNum({${paramName}:String})`;
  }

  if (op === 'contains') {
    return `positionCaseInsensitive(hex(${macCol}), {${paramName}:String}) > 0`;
  }
  if (op === 'in') {
    return `${macCol} IN arrayMap(x -> unhex(x), {${paramName}:Array(String)})`;
  }
  if (op === 'not_in') {
    return `${macCol} NOT IN arrayMap(x -> unhex(x), {${paramName}:Array(String)})`;
  }
  if (op === '!=') {
    return `${macCol} != unhex({${paramName}:String})`;
  }
  return `${macCol} = unhex({${paramName}:String})`;
}

async function buildExplorerFilterClauses(filters, dims, params) {
  const clauses = [];
  const joins = new Set();
  let idx = 0;
  const idxRef = { i: 0 };
  const asnNames = asnNamesTableRef();
  const asnRegistry = asnRegistryEnrichedTableRef();

  for (const f of normalizeFilterList(filters)) {
    const op = f.op;
    const values = parseFilterValues(f.value);
    if (!values.length && op !== 'between') continue;
    const addClause = (clause) => pushExplorerFilterClause(clauses, clause, f.logic);

    if (f.field === 'collector') {
      const scopes = parseCollectorScopes(values.join(','));
      if (!scopes.length) continue;
      const clause = buildCollectorScopeClause(scopes, op);
      if (clause) {
        addClause(clause);
        Object.assign(params, mergeCollectorParams(params, scopes));
      }
      continue;
    }

    const dim = dims[f.field];
    if (!dim) continue;
    // Filters that reference joined aliases (snmp_in / ps_src / …) must pull joinSql in.
    if (dim.joinSql) joins.add(dim.joinSql);

    if (dim.filterType === 'l3_owner' || dim.filterType === 'own_network') {
      addClause(await buildEntityPrefixFilter(f.field, f.value, params, idxRef));
      continue;
    }

    if (dim.filterType === 'service') {
      const psView = portServicesExpandedViewRef();
      if (!psView) continue;
      const side = dim.side === 'src' ? 'src' : 'dst';
      const portCol = side === 'src' ? col('srcPort') : col('dstPort');
      const alias = side === 'src' ? 'ps_src' : 'ps_dst';
      const paramName = `filter_${idx++}`;
      if (op === 'in' || op === 'not_in') {
        params[paramName] = values;
        const inOp = op === 'not_in' ? 'NOT IN' : 'IN';
        addClause(`(${alias}.service_code ${inOp} {${paramName}:Array(String)} OR ${alias}.service_name ${inOp} {${paramName}:Array(String)})`);
      } else {
        params[paramName] = String(f.value ?? '').trim();
        addClause(`(${alias}.service_code = {${paramName}:String} OR ${alias}.service_name = {${paramName}:String})`);
      }
      continue;
    }

    if (dim.filterType === 'vlan') {
      const eff = effectiveVlanExpr('f');
      if (!eff) continue;
      if (String(f.label || '').trim() && !/^\d+$/.test(String(f.value))) {
        const nameMap = await getVlanNameMap();
        const needle = String(f.label || f.value).trim().toLowerCase();
        const ids = [...nameMap.entries()]
          .filter(([, name]) => String(name).toLowerCase().includes(needle))
          .map(([id]) => id);
        if (!ids.length) addClause('0');
        else {
          const paramName = `filter_${idx++}`;
          params[paramName] = ids;
          addClause(`${eff} IN {${paramName}:Array(UInt16)}`);
        }
        continue;
      }
      const paramName = `filter_${idx++}`;
      params[paramName] = Number(values[0]);
      if (op === '=') addClause(`${eff} = {${paramName}:UInt16}`);
      else if (op === '!=') addClause(`${eff} != {${paramName}:UInt16}`);
      else if (op === 'in') {
        params[paramName] = values.map(Number);
        addClause(`${eff} IN {${paramName}:Array(UInt16)}`);
      }
      continue;
    }

    if (dim.filterType === 'asn') {
      const asnCol = dim.side === 'dst' ? col('dstAsn') : col('srcAsn');
      const asnNums = values.map(parseExplorerAsnNumber);
      if (asnNums.length && asnNums.every((n) => n != null)) {
        const paramName = `filter_${idx++}`;
        if (op === 'in' || op === 'not_in') {
          params[paramName] = asnNums;
          const inOp = op === 'not_in' ? 'NOT IN' : 'IN';
          addClause(`f.${asnCol} ${inOp} {${paramName}:Array(UInt32)}`);
        } else {
          params[paramName] = asnNums[0];
          if (op === '=') addClause(`f.${asnCol} = {${paramName}:UInt32}`);
          else if (op === '!=') addClause(`f.${asnCol} != {${paramName}:UInt32}`);
        }
        continue;
      }
      const paramName = `filter_${idx++}`;
      params[paramName] = `%${String(f.value ?? '').trim()}%`;
      addClause(`f.${asnCol} IN (
        SELECT asn FROM ${asnNames}
        WHERE positionCaseInsensitive(name, trim(BOTH '%' FROM {${paramName}:String})) > 0
        UNION ALL
        SELECT asn FROM ${asnRegistry}
        WHERE positionCaseInsensitive(name, trim(BOTH '%' FROM {${paramName}:String})) > 0
      )`);
      continue;
    }

    if (dim.filterType === 'tcp_flags') {
      const flagCol = dim.filterExpr || dim.expr;
      const { mask, names } = parseTcpFlagsFilterValue(f.value);
      if (!names.length && mask === 0 && op !== 'eq' && op !== 'neq' && op !== '=' && op !== '!=') {
        addClause('0');
        continue;
      }
      const paramName = `filter_${idx++}`;
      params[paramName] = mask;
      if (op === 'has_any') {
        addClause(`bitAnd(${flagCol}, {${paramName}:UInt8}) != 0`);
      } else if (op === 'has_all') {
        addClause(`bitAnd(${flagCol}, {${paramName}:UInt8}) = {${paramName}:UInt8}`);
      } else if (op === 'eq' || op === '=') {
        addClause(`${flagCol} = {${paramName}:UInt8}`);
      } else if (op === 'neq' || op === '!=' || op === '<>') {
        addClause(`${flagCol} != {${paramName}:UInt8}`);
      } else {
        addClause('0');
      }
      continue;
    }

    const expr = dim.filterExpr || dim.expr;
    const paramName = `filter_${idx++}`;

    if (dim.filterType === 'country') {
      const normalizedValues = values.map((value) => String(value).trim().toUpperCase());
      if (op === 'in' || op === 'not_in') {
        params[paramName] = normalizedValues;
        addClause(`${expr} ${op === 'not_in' ? 'NOT IN' : 'IN'} {${paramName}:Array(String)}`);
      } else {
        params[paramName] = normalizedValues[0];
        if (op === '!=' || op === '<>') addClause(`${expr} != {${paramName}:String}`);
        else if (op === 'contains') addClause(`position(toString(${expr}), {${paramName}:String}) > 0`);
        else if (op === 'not_contains') addClause(`position(toString(${expr}), {${paramName}:String}) = 0`);
        else addClause(`${expr} = {${paramName}:String}`);
      }
      continue;
    }

    if (dim.filterType === 'ip' || dim.filterType === 'switch_ip') {
      if (op === 'cidr') {
        params[paramName] = String(f.value ?? '').trim();
        addClause(`isIPAddressInRange(${expr}, {${paramName}:String})`);
        continue;
      }
      if (op === 'in') {
        params[paramName] = values;
        addClause(`${expr} IN {${paramName}:Array(String)}`);
        continue;
      }
    }

    if (dim.filterType === 'mac') {
      const macCol = dim.filterExpr || expr;
      if (op === 'contains') {
        const needle = macContainsNeedle(f.value);
        if (!needle) continue;
        params[paramName] = needle;
        addClause(buildMacFilterClause(macCol, op, paramName, { containsNeedle: needle }));
        continue;
      }
      if (op === 'in' || op === 'not_in') {
        const macs = normalizeMacValues(values);
        if (!macs.length) {
          addClause('0');
          continue;
        }
        params[paramName] = config.macStorage === 'uint64'
          ? macs
          : macs.map(macHexValue);
        addClause(buildMacFilterClause(macCol, op, paramName, { hexValues: params[paramName] }));
        continue;
      }
      const normalized = normalizeMacValue(f.value);
      if (!normalized) {
        addClause('0');
        continue;
      }
      params[paramName] = config.macStorage === 'uint64' ? normalized : macHexValue(normalized);
      addClause(buildMacFilterClause(macCol, op, paramName, { normalized }));
      continue;
    }

    if (dim.filterType === 'number') {
      if (op === 'between') {
        const parts = parseFilterValues(f.value);
        if (parts.length < 2) continue;
        params[`${paramName}_from`] = Number(parts[0]);
        params[`${paramName}_to`] = Number(parts[1]);
        addClause(`${expr} >= {${paramName}_from:UInt32} AND ${expr} <= {${paramName}_to:UInt32}`);
        continue;
      }
      if (['>', '>=', '<', '<='].includes(op)) {
        params[paramName] = Number(values[0]);
        addClause(`${expr} ${op} {${paramName}:UInt32}`);
        continue;
      }
      if (op === 'in') {
        params[paramName] = values.map(Number);
        addClause(`${expr} IN {${paramName}:Array(UInt32)}`);
        continue;
      }
    }

    if (dim.filterType === 'enum' && dim.rawExpr) {
      const protoNum = protoNameToNumber(values[0]);
      if (protoNum != null) {
        params[paramName] = protoNum;
        if (op === '!=') addClause(`${dim.rawExpr} != {${paramName}:UInt8}`);
        else addClause(`${dim.rawExpr} = {${paramName}:UInt8}`);
        continue;
      }
    }

    params[paramName] = String(f.value ?? '').trim();
    if (op === '!=' || op === '<>') addClause(`${expr} != {${paramName}:String}`);
    else if (op === 'contains') addClause(`positionCaseInsensitive(toString(${expr}), {${paramName}:String}) > 0`);
    else if (op === 'not_contains') addClause(`positionCaseInsensitive(toString(${expr}), {${paramName}:String}) = 0`);
    else if (op === 'in') {
      params[paramName] = values;
      addClause(`toString(${expr}) IN {${paramName}:Array(String)}`);
    } else if (op === 'not_in') {
      params[paramName] = values;
      addClause(`toString(${expr}) NOT IN {${paramName}:Array(String)}`);
    } else addClause(`toString(${expr}) = {${paramName}:String}`);
  }

  return { filterSql: combineExplorerFilterSql(clauses), joins: [...joins] };
}

function collectExplorerJoins(groupBy, dims, filterJoins = []) {
  const joins = new Set(filterJoins);
  for (const g of groupBy) {
    const dim = dims[g];
    if (dim?.joinSql) joins.add(dim.joinSql);
  }
  return [...joins].join('\n      ');
}

function normalizeExplorerQuery(body = {}) {
  const range = body.range || body.timeRange || '1h';
  const from = body.from;
  const to = body.to;
  validateExplorerWindow({ range, from, to });

  const collectorRaw = body.collectorId ?? body.collectorFilter;
  let collectorId;
  if (collectorRaw != null && collectorRaw !== '') {
    if (Array.isArray(collectorRaw)) {
      const parts = collectorRaw.map((v) => String(v).trim()).filter(Boolean);
      collectorId = parts.length ? parts.join(',') : undefined;
    } else {
      const v = String(collectorRaw).trim();
      collectorId = v || undefined;
    }
  }
  return {
    metric: normalizeExplorerMetric(body.metric),
    groupBy: body.groupBy,
    filters: normalizeFilterList(body.filters),
    limit: normalizeExplorerLimit(body.limit),
    offset: Math.min(Math.max(Number(body.offset) || 0, 0), 10000),
    range,
    from,
    to,
    granularity: body.granularity || 'auto',
    includeSummary: body.includeSummary !== false,
    includeTimeseries: body.includeTimeseries !== false,
    includeBreakdowns: body.includeBreakdowns !== false,
    collectorId,
  };
}

const EXPLORER_CH_SETTINGS = {
  max_bytes_before_external_group_by: '2000000000',
  max_bytes_before_external_sort: '2000000000',
  max_execution_time: '180',
  send_progress_in_http_headers: 1,
  http_headers_progress_interval_ms: 10000,
};

function explorerHeavyRequestTimeoutMs(windowSeconds, useCandidatePrefetch) {
  const hours = Math.max(1, windowSeconds / 3600);
  // Recent-slice candidate ≈ 30–90s to 24h; plain two-phase ≈ 25s/h.
  const base = useCandidatePrefetch ? 50 + hours * 8 : hours * 40;
  return Math.min(300000, Math.max(120000, Math.ceil(base) * 1000));
}

function explorerHeavyMaxExecutionSec(requestTimeoutMs) {
  return Math.max(120, Math.floor(requestTimeoutMs / 1000) - 15);
}

/** Two-phase plan: cheap GROUP BY on raw keys, then labels/JOINs after LIMIT. */
function buildExplorerGroupPlan(groups, dims) {
  if (!groups.length || groups.some((g) => !dims[g]?.groupKeyExpr)) {
    return { useTwoPhase: false };
  }
  const keys = groups.map((id, i) => ({
    dimId: id,
    dim: dims[id],
    keyExpr: dims[id].groupKeyExpr,
    keyAlias: `k${i}`,
    groupIdx: i,
  }));
  const needsSampler = groups.some((g) => dims[g]?.labelJoin?.needsSampler);
  const switchKey = keys.find((k) => k.dimId === 'switch_ip');
  const helpers = [];
  let samplerAlias = switchKey?.keyAlias || null;
  if (needsSampler && !samplerAlias) {
    const samplerCol = flowCol('samplerAddress');
    if (!samplerCol) return { useTwoPhase: false };
    samplerAlias = 'k_sampler';
    helpers.push({ keyExpr: `f.${samplerCol}`, keyAlias: samplerAlias });
  }
  const mayCollapse = groups.some((g) => (
    (g === 'in_if_name' || g === 'out_if_name') && !groups.includes('switch_ip')
  ));
  return { useTwoPhase: true, keys, helpers, samplerAlias, mayCollapse };
}

function mapExplorerFlowRows(groups, rows, windowSeconds, vlanGroupIndexes, asnGroupIndexes, tcpGroupIndexes = []) {
  return (async () => {
    const nameMap = vlanGroupIndexes.length ? await getVlanNameMap() : null;
    const asnNums = new Set();
    if (asnGroupIndexes.length) {
      for (const r of rows) {
        for (const idx of asnGroupIndexes) {
          const n = parseExplorerAsnNumber(String(r[`g${idx}`] ?? ''));
          if (n != null) asnNums.add(n);
        }
      }
    }
    const asnNameMap = asnGroupIndexes.length
      ? await lookupAsnDisplayNames([...asnNums])
      : null;
    return rows.map((r, i) => {
      const rawValues = groups.map((_, idx) => String(r[`g${idx}`] ?? '—') || '—');
      const values = [...rawValues];
      const asnMeta = groups.map(() => null);
      if (nameMap) {
        for (const idx of vlanGroupIndexes) {
          const vid = Number(values[idx]);
          values[idx] = vlanLabel(Number.isFinite(vid) ? vid : 0, nameMap);
        }
      }
      if (asnNameMap) {
        for (const idx of asnGroupIndexes) {
          const asn = parseExplorerAsnNumber(rawValues[idx]);
          if (asn == null) continue;
          const asName = asnNameMap.get(asn) || '';
          asnMeta[idx] = { asn, asName: asName || null };
          values[idx] = asnExplorerDisplayLabel(asn, asName);
        }
      }
      for (const idx of tcpGroupIndexes) {
        const raw = rawValues[idx];
        const numeric = Number(raw);
        if (Number.isFinite(numeric) && /^\d+$/.test(String(raw).trim())) {
          rawValues[idx] = String(numeric);
          values[idx] = tcpFlagsMaskToLabel(numeric);
        } else {
          const label = String(raw || '—');
          values[idx] = label === '' ? '—' : label;
          if (label === '—') {
            rawValues[idx] = '0';
          } else {
            rawValues[idx] = String(tcpFlagsNamesToMask(parseTcpFlagNames(label.replace(/\s+/g, ','))));
          }
        }
      }
      return enrichExplorerFlowRow({
        id: `row-${i}-${rawValues.join('|')}`,
        key: `row-${i}`,
        values,
        rawValues,
        asnMeta,
        metric: Number(r.metric_value) || 0,
        pct: Number(r.pct) || 0,
        bytes: Number(r.bytes) || 0,
        avgBps: Number(r.avg_bps),
        packets: Number(r.packets) || 0,
        flows: Number(r.flows) || 0,
        color: protocolChartColor(i),
      }, windowSeconds);
    });
  })();
}

async function explorerFlows(body = {}) {
  const q = normalizeExplorerQuery(body);
  const dims = explorerDimensions();
  const groups = normalizeExplorerGroupBy(q.groupBy, dims);
  if (!groups.length) throw new Error('Выберите хотя бы одну группировку');

  const metricKey = q.metric;
  const scaled = explorerScaledFlowExprs('f');
  const metricSpecs = buildExplorerMetricSpecs(scaled);
  const metricSpec = metricSpecs[metricKey];
  const pctExpr = `round(${metricSpec.pctBase} * 100 / nullIf(sum(${metricSpec.pctBase}) OVER (), 0), 2)`;
  const windowSpec = resolveTrafficWindow({ range: q.range, from: q.from, to: q.to });
  const gran = resolveExplorerGranularity(q);
  const windowSeconds = explorerWindowSeconds({ range: q.range, from: q.from, to: q.to });
  const params = { ...windowSpec.params, limit: q.limit, offset: q.offset };
  const { filterSql, joins: filterJoins } = await buildExplorerFilterClauses(q.filters, dims, params);
  const t = col('time');
  const groupRows = groups.map((g, i) => ({ id: g, label: dims[g].label, alias: `g${i}` }));
  const vlanGroupIndexes = groups.map((g, i) => (dims[g].kind === 'vlan' ? i : -1)).filter((i) => i >= 0);
  const asnGroupIndexes = groups.map((g, i) => (dims[g].kind === 'asn' ? i : -1)).filter((i) => i >= 0);
  const tcpGroupIndexes = groups.map((g, i) => (dims[g].kind === 'tcp_flags' ? i : -1)).filter((i) => i >= 0);

  const whereClauses = [`f.${t} >= ts_from`, `f.${t} < ts_to`];
  if (filterSql) whereClauses.push(filterSql);
  const scopedParams = applyLegacyCollectorFilter(q.filters, q.collectorId, params, whereClauses);
  // uniq_src needs per-row uniqueness — keep single-pass path.
  const plan = metricKey === 'uniq_src'
    ? { useTwoPhase: false }
    : buildExplorerGroupPlan(groups, dims);

  const meta = {
    metric: metricKey,
    metricLabel: metricSpec.label,
    groupBy: groupRows,
    range: q.range,
    from: q.from,
    to: q.to,
    limit: q.limit,
    offset: q.offset,
    dataTable: 'flows_raw',
    granularity: gran.key,
    windowSeconds,
    trafficSampled: scaled.sampled,
    twoPhase: !!plan.useTwoPhase,
  };

  if (!plan.useTwoPhase) {
    const joinSql = collectExplorerJoins(groups, dims, filterJoins);
    const groupSelect = groups.map((g, i) => `${dims[g].expr} AS g${i}`);
    const groupAliases = groups.map((_, i) => `g${i}`);
    return {
      sql: `
      WITH
        ${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        ${groupSelect.join(',\n        ')},
        ${metricSpec.expr} AS metric_value,
        ${pctExpr} AS pct,
        sum(${scaled.bytes}) AS bytes,
        round(sum(${scaled.bytes}) * 8 / window_seconds, 0) AS avg_bps,
        sum(${scaled.packets}) AS packets,
        sum(${scaled.flowWeight}) AS flows
      FROM ${flowsRawTableRef()} AS f
      ${joinSql}
      PREWHERE f.date >= toDate(ts_from) - 1
        AND f.date <= toDate(ts_to)
      WHERE ${whereClauses.join('\n        AND ')}
      GROUP BY ${groupAliases.join(', ')}
      ORDER BY metric_value DESC
      LIMIT {limit:UInt32} OFFSET {offset:UInt32}
    `,
      params: scopedParams,
      clickhouse_settings: EXPLORER_CH_SETTINGS,
      meta,
      async map(rows) {
        return mapExplorerFlowRows(groups, rows, windowSeconds, vlanGroupIndexes, asnGroupIndexes, tcpGroupIndexes);
      },
    };
  }

  const innerJoinSql = [...filterJoins].join('\n      ');
  const allKeys = [...plan.keys, ...plan.helpers];
  const keySelect = allKeys.map((k) => `${k.keyExpr} AS ${k.keyAlias}`).join(',\n          ');
  const keyGroupBy = allKeys.map((k) => k.keyAlias).join(', ');
  const labelJoins = [];
  const labelSelectParts = plan.keys.map((k) => {
    if (k.dim.labelJoin) {
      labelJoins.push(k.dim.labelJoin.joinSql(`a.${plan.samplerAlias}`, `a.${k.keyAlias}`));
      return `${k.dim.labelJoin.labelExpr} AS g${k.groupIdx}`;
    }
    if (typeof k.dim.labelFromKey === 'function') {
      return `${k.dim.labelFromKey(`a.${k.keyAlias}`)} AS g${k.groupIdx}`;
    }
    return `toString(a.${k.keyAlias}) AS g${k.groupIdx}`;
  });
  const groupAliases = groups.map((_, i) => `g${i}`);
  const uniqueLabelJoins = [...new Set(labelJoins)];

  const metricFromAgg = (prefix) => {
    switch (metricKey) {
      case 'volume': return `${prefix}.bytes`;
      case 'pps': return `round(${prefix}.packets / window_seconds, 0)`;
      case 'fps': return `round(${prefix}.flows / window_seconds, 2)`;
      case 'flows': return `${prefix}.flows`;
      default: return `round(${prefix}.bytes * 8 / window_seconds, 0)`;
    }
  };
  const metricFromSum = () => {
    switch (metricKey) {
      case 'volume': return 'sum(a.bytes)';
      case 'pps': return 'round(sum(a.packets) / window_seconds, 0)';
      case 'fps': return 'round(sum(a.flows) / window_seconds, 2)';
      case 'flows': return 'sum(a.flows)';
      default: return 'round(sum(a.bytes) * 8 / window_seconds, 0)';
    }
  };

  // High-card IP×IP (+ ifs) on long windows: discover top (src,dst) on a recent
  // slice of the window (cheap), then full multi-key agg over the full range only
  // for those pairs. Avoids OOM from SNMP JOINs and full-window pair GROUP BY.
  const srcKey = plan.keys.find((k) => k.dimId === 'src_ip');
  const dstKey = plan.keys.find((k) => k.dimId === 'dst_ip');
  const hasIfKeys = plan.keys.some((k) => k.dimId === 'in_if_name' || k.dimId === 'out_if_name');
  const useCandidatePrefetch = Boolean(!plan.mayCollapse
    && srcKey
    && dstKey
    && (hasIfKeys || groups.length >= 4)
    && windowSeconds >= 3 * 3600);
  const candidateLookbackHours = windowSeconds >= 12 * 3600 ? 2 : 1;

  const plainInnerAgg = `
        SELECT
          ${keySelect},
          sum(${scaled.bytes}) AS bytes,
          sum(${scaled.packets}) AS packets,
          sum(${scaled.flowWeight}) AS flows
        FROM ${flowsRawTableRef()} AS f
        ${innerJoinSql}
        PREWHERE f.date >= toDate(ts_from) - 1
          AND f.date <= toDate(ts_to)
        WHERE ${whereClauses.join('\n          AND ')}
        GROUP BY ${keyGroupBy}`;

  let innerAggSql = plainInnerAgg;
  if (useCandidatePrefetch) {
    scopedParams.candidate_limit = Math.min(300, Math.max(80, q.limit * 15));
    const coarseKeys = [srcKey, dstKey];
    const coarseSelect = coarseKeys.map((k) => `${k.keyExpr} AS ${k.keyAlias}`).join(',\n            ');
    const coarseGroupBy = coarseKeys.map((k) => k.keyAlias).join(', ');
    const scaledFull = explorerScaledFlowExprs('f_full');
    const keySelectFull = allKeys.map((k) => `${k.keyExpr.replace(/\bf\./g, 'f_full.')} AS ${k.keyAlias}`).join(',\n          ');
    const whereFull = whereClauses.map((c) => c.replace(/\bf\./g, 'f_full.')).join('\n          AND ');
    const innerJoinFull = innerJoinSql.replace(/\bf\./g, 'f_full.');
    const candidateWhere = whereClauses
      .map((c) => c.replace(`f.${t} >= ts_from`, `f.${t} >= cand_from`))
      .join('\n              AND ');
    const candidateInTuple = `(${coarseKeys.map((k) => (
      `${k.keyExpr.replace(/\bf\./g, 'f_full.')}`
    )).join(', ')}) IN (
          SELECT ${coarseGroupBy}
          FROM (
            SELECT
              ${coarseSelect},
              sum(${scaled.bytes}) AS candidate_bytes
            FROM ${flowsRawTableRef()} AS f
            ${innerJoinSql}
            PREWHERE f.date >= toDate(cand_from) - 1
              AND f.date <= toDate(ts_to)
            WHERE ${candidateWhere}
            GROUP BY ${coarseGroupBy}
            ORDER BY candidate_bytes DESC
            LIMIT {candidate_limit:UInt32}
          )
        )`;

    innerAggSql = `
        SELECT
          ${keySelectFull},
          sum(${scaledFull.bytes}) AS bytes,
          sum(${scaledFull.packets}) AS packets,
          sum(${scaledFull.flowWeight}) AS flows
        FROM ${flowsRawTableRef()} AS f_full
        ${innerJoinFull}
        PREWHERE f_full.date >= toDate(ts_from) - 1
          AND f_full.date <= toDate(ts_to)
        WHERE ${whereFull}
          AND ${candidateInTuple}
        GROUP BY ${keyGroupBy}`;
  }
  meta.candidatePrefetch = useCandidatePrefetch;
  meta.candidateLookbackHours = useCandidatePrefetch ? candidateLookbackHours : null;
  const heavyTimeoutMs = explorerHeavyRequestTimeoutMs(windowSeconds, useCandidatePrefetch);
  const heavySettings = {
    ...EXPLORER_CH_SETTINGS,
    max_execution_time: String(explorerHeavyMaxExecutionSec(heavyTimeoutMs)),
  };
  const withHead = useCandidatePrefetch
    ? `${windowSpec.cteHead}
        greatest(ts_from, ts_to - INTERVAL ${candidateLookbackHours} HOUR) AS cand_from,
        dateDiff('second', ts_from, ts_to) AS window_seconds`
    : `${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds`;

  const sql = plan.mayCollapse
    ? `
      WITH
        ${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        ${labelSelectParts.join(',\n        ')},
        ${metricFromSum()} AS metric_value,
        round(sum(a.bytes) * 100 / nullIf(sum(sum(a.bytes)) OVER (), 0), 2) AS pct,
        sum(a.bytes) AS bytes,
        round(sum(a.bytes) * 8 / window_seconds, 0) AS avg_bps,
        sum(a.packets) AS packets,
        sum(a.flows) AS flows
      FROM (
        ${plainInnerAgg}
      ) AS a
      ${uniqueLabelJoins.join('\n      ')}
      GROUP BY ${groupAliases.join(', ')}
      ORDER BY metric_value DESC
      LIMIT {limit:UInt32} OFFSET {offset:UInt32}
    `
    : `
      WITH
        ${withHead}
      SELECT
        ${labelSelectParts.join(',\n        ')},
        ${metricFromAgg('a')} AS metric_value,
        round(a.bytes * 100 / nullIf(sum(a.bytes) OVER (), 0), 2) AS pct,
        a.bytes AS bytes,
        round(a.bytes * 8 / window_seconds, 0) AS avg_bps,
        a.packets AS packets,
        a.flows AS flows
      FROM (
        ${innerAggSql}
        ORDER BY bytes DESC
        LIMIT {limit:UInt32} OFFSET {offset:UInt32}
      ) AS a
      ${uniqueLabelJoins.join('\n      ')}
      ORDER BY bytes DESC
    `;

  return {
    sql,
    params: scopedParams,
    clickhouse_settings: heavySettings,
    requestTimeoutMs: heavyTimeoutMs,
    meta,
    async map(rows) {
      return mapExplorerFlowRows(groups, rows, windowSeconds, vlanGroupIndexes, asnGroupIndexes, tcpGroupIndexes);
    },
  };
}

async function explorerSummary(body = {}) {
  const q = normalizeExplorerQuery(body);
  const dims = explorerDimensions();
  const scaled = explorerScaledFlowExprs('f');
  const windowSpec = resolveTrafficWindow({ range: q.range, from: q.from, to: q.to });
  const params = { ...windowSpec.params };
  const { filterSql, joins: filterJoins } = await buildExplorerFilterClauses(q.filters, dims, params);
  const joinSql = collectExplorerJoins([], dims, filterJoins);
  const t = col('time');
  const directionCol = flowCol('direction');
  const whereClauses = [`f.${t} >= ts_from`, `f.${t} < ts_to`];
  if (filterSql) whereClauses.push(filterSql);
  const scopedParams = applyLegacyCollectorFilter(q.filters, q.collectorId, params, whereClauses);
  const directionSelect = directionCol
    ? `sumIf(${scaled.bytes}, f.${directionCol} = 'in') AS in_bytes,
        sumIf(${scaled.bytes}, f.${directionCol} = 'out') AS out_bytes,`
    : '';
  const protoCol = col('proto');

  return {
    sql: `
      WITH
        ${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        sum(${scaled.bytes}) AS total_bytes,
        sum(${scaled.packets}) AS total_packets,
        sum(${scaled.flowWeight}) AS total_flows,
        round(sum(${scaled.bytes}) * 8 / window_seconds, 0) AS avg_bps,
        uniqCombined(f.${col('srcIp')}) AS uniq_src,
        uniqCombined(f.${col('dstIp')}) AS uniq_dst,
        ${directionSelect}
        topK(5)(f.${protoCol}) AS top_protocol_ids
      FROM ${flowsRawTableRef()} AS f
      ${joinSql}
      PREWHERE f.date >= toDate(ts_from) - 1
        AND f.date <= toDate(ts_to)
      WHERE ${whereClauses.join('\n        AND ')}
    `,
    params: scopedParams,
    meta: { kind: 'summary' },
    async map(rows) {
      const r = rows[0] || {};
      const windowSeconds = explorerWindowSeconds({ range: q.range, from: q.from, to: q.to });
      const totalBytes = Number(r.total_bytes) || 0;
      return {
        totalBytes,
        totalPackets: Number(r.total_packets) || 0,
        totalFlows: Number(r.total_flows) || 0,
        avgBps: Number(r.avg_bps) || (windowSeconds > 0 ? Math.round(totalBytes * 8 / windowSeconds) : 0),
        uniqSrc: Number(r.uniq_src) || 0,
        uniqDst: Number(r.uniq_dst) || 0,
        inBytes: Number(r.in_bytes) || null,
        outBytes: Number(r.out_bytes) || null,
        topProtocols: (Array.isArray(r.top_protocol_ids) ? r.top_protocol_ids : []).map((id) => protoLabel(id)),
      };
    },
  };
}

async function explorerResultSeries(body = {}, flowRows = []) {
  const q = normalizeExplorerQuery(body);
  if (!flowRows.length) {
    return {
      params: {},
      meta: { kind: 'result-series' },
      async map() { return { seriesByRow: {} }; },
    };
  }

  const dims = explorerDimensions();
  const groups = normalizeExplorerGroupBy(q.groupBy, dims);
  if (!groups.length) {
    return {
      params: {},
      meta: { kind: 'result-series' },
      async map() { return { seriesByRow: {} }; },
    };
  }

  const metricKey = q.metric;
  const scaled = explorerScaledFlowExprs('f');
  const gran = resolveExplorerGranularity(q);
  const windowSpec = resolveTrafficWindow({ range: q.range, from: q.from, to: q.to });
  const params = { ...windowSpec.params };
  const idxRef = { i: 0 };
  const { filterSql, joins: filterJoins } = await buildExplorerFilterClauses(q.filters, dims, params);
  const joinSql = collectExplorerJoins(groups, dims, filterJoins);
  const t = col('time');
  const whereClauses = [`f.${t} >= ts_from`, `f.${t} < ts_to`];
  if (filterSql) whereClauses.push(filterSql);
  const scopedParams = applyLegacyCollectorFilter(q.filters, q.collectorId, params, whereClauses);

  const groupMatchParts = flowRows.map((row) => {
    const conds = groups.map((g, gi) => {
      const paramName = `series_g_${idxRef.i++}`;
      const dim = dims[g];
      const raw = String(row.rawValues?.[gi] ?? row.values?.[gi] ?? '');
      if (dim.filterType === 'tcp_flags') {
        const { mask } = parseTcpFlagsFilterValue(raw);
        scopedParams[paramName] = mask;
        return `${dim.filterExpr} = {${paramName}:UInt8}`;
      }
      scopedParams[paramName] = raw;
      return `toString(${dim.expr}) = {${paramName}:String}`;
    });
    return `(${conds.join(' AND ')})`;
  });
  whereClauses.push(`(${groupMatchParts.join(' OR ')})`);

  const groupSelect = groups.map((g, i) => `${dims[g].expr} AS g${i}`);
  const groupAliases = groups.map((_, i) => `g${i}`);
  const groupBySql = ['bucket', ...groupAliases].join(', ');
  const bucketExpr = gran.key === '1d'
    ? `toStartOfDay(f.${t})`
    : `toStartOfInterval(f.${t}, INTERVAL ${gran.seconds} SECOND)`;

  return {
    sql: `
      WITH
        ${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        ${bucketExpr} AS bucket,
        ${groupSelect.join(',\n        ')},
        sum(${scaled.bytes}) AS bytes,
        sum(${scaled.packets}) AS packets,
        sum(${scaled.flowWeight}) AS flows,
        round(sum(${scaled.bytes}) * 8 / ${gran.seconds}, 0) AS bps,
        round(sum(${scaled.packets}) / ${gran.seconds}, 0) AS pps,
        round(sum(${scaled.flowWeight}) / ${gran.seconds}, 2) AS fps
      FROM ${flowsRawTableRef()} AS f
      ${joinSql}
      PREWHERE f.date >= toDate(ts_from) - 1
        AND f.date <= toDate(ts_to)
      WHERE ${whereClauses.join('\n        AND ')}
      GROUP BY ${groupBySql}
      ORDER BY bucket
    `,
    params: scopedParams,
    meta: { kind: 'result-series', metric: metricKey, granularity: gran.key },
    async map(rows) {
      const seriesByRow = Object.fromEntries(flowRows.map((row) => [row.id, []]));
      for (const r of rows) {
        const groupKey = groups.map((_, idx) => String(r[`g${idx}`] ?? '—') || '—').join('|');
        const row = flowRows.find((item) => explorerFlowRowMatchesGroupKey(item, groupKey));
        if (!row) continue;
        seriesByRow[row.id].push({
          bucket: r.bucket,
          bytes: Number(r.bytes) || 0,
          packets: Number(r.packets) || 0,
          flows: Number(r.flows) || 0,
          bps: Number(r.bps) || 0,
          pps: Number(r.pps) || 0,
          fps: Number(r.fps) || 0,
          value: explorerSeriesMetricValue(r, metricKey),
        });
      }
      return { seriesByRow };
    },
  };
}

function explorerFlowRowGroupKey(values) {
  return (values || []).map((v) => String(v ?? '—') || '—').join('|');
}

function explorerFlowRowMatchesGroupKey(row, groupKey) {
  if (explorerFlowRowGroupKey(row.values) === groupKey) return true;
  return explorerFlowRowGroupKey(row.rawValues) === groupKey;
}

function explorerFlowRowIdByGroupKey(flowRows) {
  const idByKey = new Map();
  for (const row of flowRows) {
    const labelKey = explorerFlowRowGroupKey(row.values);
    const rawKey = explorerFlowRowGroupKey(row.rawValues);
    idByKey.set(labelKey, row.id);
    if (rawKey !== labelKey) idByKey.set(rawKey, row.id);
  }
  return idByKey;
}

function explorerSeriesMetricValue(row, metricKey) {
  switch (metricKey) {
    case 'volume': return Number(row.bytes) || 0;
    case 'pps': return Number(row.pps) || 0;
    case 'fps': return Number(row.fps) || 0;
    case 'flows': return Number(row.flows) || 0;
    default: return Number(row.bps) || 0;
  }
}

/**
 * Top-N groupBy + per-bucket series in one flows_raw scan (for observation rollup).
 * Prefers raw group keys when available (same two-phase idea as explorerFlows).
 */
async function explorerGroupedTimeseries(body = {}) {
  const q = normalizeExplorerQuery(body);
  const dims = explorerDimensions();
  const groups = normalizeExplorerGroupBy(q.groupBy, dims);
  if (!groups.length) throw new Error('Выберите хотя бы одну группировку');

  const metricKey = q.metric;
  const scaled = explorerScaledFlowExprs('f');
  const gran = resolveExplorerGranularity(q);
  const windowSpec = resolveTrafficWindow({
    range: q.range, from: q.from, to: q.to, bucketSeconds: gran.seconds,
  });
  const windowSeconds = explorerWindowSeconds({ range: q.range, from: q.from, to: q.to });
  const params = { ...windowSpec.params, limit: q.limit };
  const { filterSql, joins: filterJoins } = await buildExplorerFilterClauses(q.filters, dims, params);
  const t = col('time');
  const whereClauses = [`f.${t} >= ts_from`, `f.${t} < ts_to`];
  if (filterSql) whereClauses.push(filterSql);
  const scopedParams = applyLegacyCollectorFilter(q.filters, q.collectorId, params, whereClauses);
  const plan = buildExplorerGroupPlan(groups, dims);
  const bucketExpr = gran.key === '1d'
    ? `toStartOfDay(f.${t})`
    : `toStartOfInterval(f.${t}, INTERVAL ${gran.seconds} SECOND)`;
  const vlanGroupIndexes = groups.map((g, i) => (dims[g].kind === 'vlan' ? i : -1)).filter((i) => i >= 0);
  const asnGroupIndexes = groups.map((g, i) => (dims[g].kind === 'asn' ? i : -1)).filter((i) => i >= 0);
  const tcpGroupIndexes = groups.map((g, i) => (dims[g].kind === 'tcp_flags' ? i : -1)).filter((i) => i >= 0);

  let sql;
  if (plan.useTwoPhase && !plan.mayCollapse) {
    const innerJoinSql = [...filterJoins].join('\n      ');
    const allKeys = [...plan.keys, ...plan.helpers];
    const keySelect = allKeys.map((k) => `${k.keyExpr} AS ${k.keyAlias}`).join(',\n              ');
    const keyGroupBy = ['bucket', ...allKeys.map((k) => k.keyAlias)].join(', ');
    const labelJoins = [];
    const labelSelectParts = plan.keys.map((k) => {
      if (k.dim.labelJoin) {
        labelJoins.push(k.dim.labelJoin.joinSql(`b.${plan.samplerAlias}`, `b.${k.keyAlias}`));
        return `${k.dim.labelJoin.labelExpr} AS g${k.groupIdx}`;
      }
      return `${k.dim.labelFromKey(`b.${k.keyAlias}`)} AS g${k.groupIdx}`;
    });
    const keyPassThrough = allKeys.map((k) => `b.${k.keyAlias} AS ${k.keyAlias}`).join(',\n            ');
    const keyAliases = allKeys.map((k) => k.keyAlias);
    sql = `
      WITH
        ${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        bucket,
        ${plan.keys.map((k) => `g${k.groupIdx}`).join(',\n        ')},
        bytes,
        packets,
        flows,
        round(bytes * 8 / ${gran.seconds}, 0) AS bps,
        round(packets / ${gran.seconds}, 0) AS pps,
        round(flows / ${gran.seconds}, 2) AS fps,
        series_bytes,
        series_packets,
        series_flows
      FROM (
        SELECT
          bucket,
          ${plan.keys.map((k) => `g${k.groupIdx}`).join(',\n          ')},
          bytes,
          packets,
          flows,
          series_bytes,
          series_packets,
          series_flows,
          dense_rank() OVER (ORDER BY series_bytes DESC, ${plan.keys.map((k) => `g${k.groupIdx}`).join(', ')}) AS series_rank
        FROM (
          SELECT
            b.bucket AS bucket,
            ${keyPassThrough},
            ${labelSelectParts.join(',\n            ')},
            b.bytes AS bytes,
            b.packets AS packets,
            b.flows AS flows,
            sum(b.bytes) OVER (PARTITION BY ${keyAliases.join(', ')}) AS series_bytes,
            sum(b.packets) OVER (PARTITION BY ${keyAliases.join(', ')}) AS series_packets,
            sum(b.flows) OVER (PARTITION BY ${keyAliases.join(', ')}) AS series_flows
          FROM (
            SELECT
              ${bucketExpr} AS bucket,
              ${keySelect},
              sum(${scaled.bytes}) AS bytes,
              sum(${scaled.packets}) AS packets,
              sum(${scaled.flowWeight}) AS flows
            FROM ${flowsRawTableRef()} AS f
            ${innerJoinSql}
            PREWHERE f.date >= toDate(ts_from) - 1
              AND f.date <= toDate(ts_to)
            WHERE ${whereClauses.join('\n              AND ')}
            GROUP BY ${keyGroupBy}
          ) AS b
          ${[...new Set(labelJoins)].join('\n          ')}
        )
      )
      WHERE series_rank <= {limit:UInt32}
      ORDER BY bucket, series_bytes DESC
    `;
  } else {
    const joinSql = collectExplorerJoins(groups, dims, filterJoins);
    const groupSelect = groups.map((g, i) => `${dims[g].expr} AS g${i}`);
    const groupAliases = groups.map((_, i) => `g${i}`);
    const groupByBucketSql = ['bucket', ...groupAliases].join(', ');
    const rankOrderSql = ['series_bytes DESC', ...groupAliases].join(', ');
    sql = `
      WITH
        ${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        bucket,
        ${groupAliases.join(',\n        ')},
        bytes,
        packets,
        flows,
        round(bytes * 8 / ${gran.seconds}, 0) AS bps,
        round(packets / ${gran.seconds}, 0) AS pps,
        round(flows / ${gran.seconds}, 2) AS fps,
        series_bytes,
        series_packets,
        series_flows
      FROM (
        SELECT
          *,
          dense_rank() OVER (ORDER BY ${rankOrderSql}) AS series_rank
        FROM (
          SELECT
            bucket,
            ${groupAliases.join(',\n            ')},
            bytes,
            packets,
            flows,
            sum(bytes) OVER (PARTITION BY ${groupAliases.join(', ')}) AS series_bytes,
            sum(packets) OVER (PARTITION BY ${groupAliases.join(', ')}) AS series_packets,
            sum(flows) OVER (PARTITION BY ${groupAliases.join(', ')}) AS series_flows
          FROM (
            SELECT
              ${bucketExpr} AS bucket,
              ${groupSelect.join(',\n              ')},
              sum(${scaled.bytes}) AS bytes,
              sum(${scaled.packets}) AS packets,
              sum(${scaled.flowWeight}) AS flows
            FROM ${flowsRawTableRef()} AS f
            ${joinSql}
            PREWHERE f.date >= toDate(ts_from) - 1
              AND f.date <= toDate(ts_to)
            WHERE ${whereClauses.join('\n              AND ')}
            GROUP BY ${groupByBucketSql}
          )
        )
      )
      WHERE series_rank <= {limit:UInt32}
      ORDER BY bucket, series_bytes DESC
    `;
  }

  return {
    sql,
    params: scopedParams,
    clickhouse_settings: EXPLORER_CH_SETTINGS,
    meta: {
      kind: 'grouped-timeseries',
      metric: metricKey,
      granularity: gran.key,
      groupBy: groups.map((g, i) => ({ id: g, label: dims[g].label, alias: `g${i}` })),
      windowSeconds,
    },
    async map(rows) {
      const totalsByKey = new Map();
      for (const r of rows) {
        const key = groups.map((_, idx) => String(r[`g${idx}`] ?? '—') || '—').join('|');
        if (!totalsByKey.has(key)) {
          totalsByKey.set(key, {
            rawValues: groups.map((_, idx) => String(r[`g${idx}`] ?? '—') || '—'),
            bytes: Number(r.series_bytes) || 0,
            packets: Number(r.series_packets) || 0,
            flows: Number(r.series_flows) || 0,
          });
        }
      }
      const ranked = [...totalsByKey.entries()]
        .sort((a, b) => (b[1].bytes - a[1].bytes) || a[0].localeCompare(b[0]));
      const flowRows = await mapExplorerFlowRows(
        groups,
        ranked.map(([, item], i) => ({
          ...Object.fromEntries(item.rawValues.map((v, idx) => [`g${idx}`, v])),
          metric_value: item.bytes,
          pct: 0,
          bytes: item.bytes,
          avg_bps: windowSeconds > 0 ? Math.round(item.bytes * 8 / windowSeconds) : 0,
          packets: item.packets,
          flows: item.flows,
        })),
        windowSeconds,
        vlanGroupIndexes,
        asnGroupIndexes,
        tcpGroupIndexes,
      );
      const seriesByRow = Object.fromEntries(flowRows.map((row) => [row.id, []]));
      const idByKey = explorerFlowRowIdByGroupKey(flowRows);
      for (const r of rows) {
        const groupKey = groups.map((_, idx) => String(r[`g${idx}`] ?? '—') || '—').join('|');
        const rowId = idByKey.get(groupKey);
        if (!rowId) continue;
        seriesByRow[rowId].push({
          bucket: r.bucket,
          bytes: Number(r.bytes) || 0,
          packets: Number(r.packets) || 0,
          flows: Number(r.flows) || 0,
          bps: Number(r.bps) || 0,
          pps: Number(r.pps) || 0,
          fps: Number(r.fps) || 0,
          value: explorerSeriesMetricValue(r, metricKey),
        });
      }
      return { flowRows, seriesByRow };
    },
  };
}

async function explorerTimeseries(body = {}) {
  const q = normalizeExplorerQuery(body);
  const dims = explorerDimensions();
  const scaled = explorerScaledFlowExprs('f');
  const gran = resolveExplorerGranularity(q);
  const windowSpec = resolveTrafficWindow({ range: q.range, from: q.from, to: q.to });
  const params = { ...windowSpec.params };
  const { filterSql, joins: filterJoins } = await buildExplorerFilterClauses(q.filters, dims, params);
  const joinSql = collectExplorerJoins([], dims, filterJoins);
  const t = col('time');
  const whereClauses = [`f.${t} >= ts_from`, `f.${t} < ts_to`];
  if (filterSql) whereClauses.push(filterSql);
  const scopedParams = applyLegacyCollectorFilter(q.filters, q.collectorId, params, whereClauses);
  const bucketExpr = gran.key === '1d'
    ? `toStartOfDay(f.${t})`
    : `toStartOfInterval(f.${t}, INTERVAL ${gran.seconds} SECOND)`;
  const metricExpr = {
    bps: `round(sum(${scaled.bytes}) * 8 / ${gran.seconds}, 0)`,
    volume: `sum(${scaled.bytes})`,
    pps: `round(sum(${scaled.packets}) / ${gran.seconds}, 0)`,
    fps: `round(sum(${scaled.flowWeight}) / ${gran.seconds}, 2)`,
    flows: `sum(${scaled.flowWeight})`,
    uniq_src: `uniqCombined(f.${col('srcIp')})`,
  }[q.metric] || `round(sum(${scaled.bytes}) * 8 / ${gran.seconds}, 0)`;

  return {
    sql: `
      WITH
        ${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        ${bucketExpr} AS bucket,
        sum(${scaled.bytes}) AS bytes,
        sum(${scaled.packets}) AS packets,
        sum(${scaled.flowWeight}) AS flows,
        round(sum(${scaled.bytes}) * 8 / ${gran.seconds}, 0) AS bps,
        ${metricExpr} AS metric_value
      FROM ${flowsRawTableRef()} AS f
      ${joinSql}
      PREWHERE f.date >= toDate(ts_from) - 1
        AND f.date <= toDate(ts_to)
      WHERE ${whereClauses.join('\n        AND ')}
      GROUP BY bucket
      ORDER BY bucket
    `,
    params: scopedParams,
    meta: { kind: 'timeseries', granularity: gran.key },
    async map(rows) {
      return rows.map((r) => ({
        bucket: r.bucket,
        bytes: Number(r.bytes) || 0,
        packets: Number(r.packets) || 0,
        flows: Number(r.flows) || 0,
        bps: Number(r.bps) || 0,
        value: Number(r.metric_value) || 0,
      }));
    },
  };
}

async function explorerBreakdown(body = {}, dimension = 'proto', limit = 5) {
  const q = normalizeExplorerQuery(body);
  const dims = explorerDimensions();
  const dim = dims[dimension];
  if (!dim || dim.virtual) throw new Error(`Недоступное измерение: ${dimension}`);
  const scaled = explorerScaledFlowExprs('f');
  const windowSpec = resolveTrafficWindow({ range: q.range, from: q.from, to: q.to });
  const params = { ...windowSpec.params, limit: Math.min(Math.max(Number(limit) || 5, 1), 20) };
  const { filterSql, joins: filterJoins } = await buildExplorerFilterClauses(q.filters, dims, params);
  const joinSql = collectExplorerJoins([dimension], dims, filterJoins);
  const t = col('time');
  const whereClauses = [`f.${t} >= ts_from`, `f.${t} < ts_to`];
  if (filterSql) whereClauses.push(filterSql);
  const scopedParams = applyLegacyCollectorFilter(q.filters, q.collectorId, params, whereClauses);
  const labelSelect = dimension === 'proto'
    ? `f.${col('proto')} AS proto_id`
    : `${dim.expr} AS label`;
  const groupBySql = dimension === 'proto' ? 'proto_id' : 'label';

  return {
    sql: `
      WITH
        ${windowSpec.cteHead}
        dateDiff('second', ts_from, ts_to) AS window_seconds
      SELECT
        ${labelSelect},
        sum(${scaled.bytes}) AS bytes
      FROM ${flowsRawTableRef()} AS f
      ${joinSql}
      PREWHERE f.date >= toDate(ts_from) - 1
        AND f.date <= toDate(ts_to)
      WHERE ${whereClauses.join('\n        AND ')}
      GROUP BY ${groupBySql}
      ORDER BY bytes DESC
      LIMIT {limit:UInt32}
    `,
    params: scopedParams,
    meta: { kind: 'breakdown', dimension },
    async map(rows) {
      return rows.map((r, i) => ({
        label: dimension === 'proto' ? protoLabel(r.proto_id) : String(r.label ?? '—'),
        bytes: Number(r.bytes) || 0,
        color: protocolChartColor(i),
      }));
    },
  };
}

async function explorerQuery(body = {}) {
  const q = normalizeExplorerQuery(body);
  const dims = explorerDimensions();
  const groups = normalizeExplorerGroupBy(q.groupBy, dims);
  const flowsSpec = groups.length ? await explorerFlows(body) : null;
  let summarySpec = null;
  let timeseriesSpec = null;
  const breakdownSpecs = [];

  if (q.includeSummary) summarySpec = await explorerSummary(body);
  if (q.includeTimeseries) timeseriesSpec = await explorerTimeseries(body);
  if (q.includeBreakdowns) {
    for (const dim of []) {
      if (explorerDimensions()[dim]) breakdownSpecs.push({ dim, spec: await explorerBreakdown(body, dim, 5) });
    }
  }

  return { flowsSpec, summarySpec, timeseriesSpec, breakdownSpecs, q };
}

function normalizeExplorerSwitchIpFilter(raw) {
  const values = String(raw || '')
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
  return [...new Set(values)].slice(0, 32);
}

async function searchExplorerEntities({ type, q = '', limit = 20, switchIp = '' } = {}) {
  const search = String(q || '').trim();
  const lim = Math.min(Math.max(Number(limit) || 20, 1), 50);
  const needle = search.toLowerCase();
  const switchIps = normalizeExplorerSwitchIpFilter(switchIp);

  if (type === 'asn') {
    const asnNames = asnNamesTableRef();
    const asnRegistry = asnRegistryEnrichedTableRef();
    const fetchLimit = Math.min(lim * 4, 100);
    const params = { limit: fetchLimit };
    let where = 'asn > 0';
    if (search) {
      params.search = `%${search}%`;
      where += ` AND (
        positionCaseInsensitive(name, trim(BOTH '%' FROM {search:String})) > 0
        OR toString(asn) LIKE {search:String}
        OR concat('AS', toString(asn)) LIKE {search:String}
      )`;
    }
    const { rows } = await query(`
      SELECT asn, name, priority FROM (
        SELECT asn, name, 1 AS priority
        FROM ${asnNames}
        UNION ALL
        SELECT asn, name, 2 AS priority
        FROM ${asnRegistry}
      )
      WHERE ${where}
      ORDER BY priority, asn
      LIMIT {limit:UInt32}
    `, params, { name: 'explorer/entities-asn' });
    return dedupeExplorerAsnEntities(rows).slice(0, lim).map((r) => ({
      id: String(r.asn),
      label: `${r.name || `AS${r.asn}`}`,
      sublabel: `AS${r.asn}`,
      value: Number(r.asn),
    }));
  }

  if (type === 'vlan') {
    const view = l2VlansViewRef();
    const params = { limit: lim };
    let where = 'vlan_id > 0';
    if (search) {
      params.search = `%${search}%`;
      where += ` AND (
        positionCaseInsensitive(display_name, trim(BOTH '%' FROM {search:String})) > 0
        OR toString(vlan_id) LIKE {search:String}
      )`;
    }
    const { rows } = await query(`
      SELECT vlan_id, display_name
      FROM ${view}
      WHERE ${where}
      ORDER BY vlan_id
      LIMIT {limit:UInt32}
    `, params, { name: 'explorer/entities-vlan' });
    return rows.map((r) => ({
      id: String(r.vlan_id),
      label: String(r.display_name || `VLAN ${r.vlan_id}`),
      sublabel: `VLAN ${r.vlan_id}`,
      value: Number(r.vlan_id),
    }));
  }

  if (type === 'service') {
    const view = portServicesExpandedViewRef();
    const params = { limit: lim };
    let where = '1';
    if (search) {
      params.search = `%${search}%`;
      where = `positionCaseInsensitive(service_name, trim(BOTH '%' FROM {search:String})) > 0
        OR positionCaseInsensitive(service_code, trim(BOTH '%' FROM {search:String})) > 0
        OR toString(port) LIKE {search:String}`;
    }
    const { rows } = await query(`
      SELECT transport, port, service_code, service_name
      FROM ${view}
      WHERE ${where}
      ORDER BY service_name, port
      LIMIT {limit:UInt32}
    `, params, { name: 'explorer/entities-service' });
    return rows.map((r) => ({
      id: `${r.transport}/${r.port}`,
      label: String(r.service_name || r.service_code),
      sublabel: `${String(r.transport).toUpperCase()}/${r.port}`,
      value: String(r.service_code || r.service_name),
    }));
  }

  if (type === 'l3_owner') {
    const view = entitiesViewRef();
    const params = { limit: lim };
    let where = '1';
    if (search) {
      params.search = `%${search}%`;
      where = `positionCaseInsensitive(display_name, trim(BOTH '%' FROM {search:String})) > 0
        OR positionCaseInsensitive(entity_id, trim(BOTH '%' FROM {search:String})) > 0`;
    }
    const { rows } = await query(`
      SELECT entity_id, display_name
      FROM ${view}
      WHERE ${where}
      ORDER BY display_name
      LIMIT {limit:UInt32}
    `, params, { name: 'explorer/entities-l3-owner' });
    return rows.map((r) => ({
      id: String(r.entity_id),
      label: String(r.display_name || r.entity_id),
      sublabel: String(r.entity_id),
      value: String(r.entity_id),
    }));
  }

  if (type === 'own_network') {
    const prefixesTable = l3PrefixesTableRef();
    const entitiesTable = entitiesViewRef();
    const params = { limit: lim };
    let where = 'enabled = 1';
    if (search) {
      params.search = `%${search}%`;
      where += ` AND (
        positionCaseInsensitive(prefix, trim(BOTH '%' FROM {search:String})) > 0
        OR positionCaseInsensitive(display_name, trim(BOTH '%' FROM {search:String})) > 0
        OR positionCaseInsensitive(entity_name, trim(BOTH '%' FROM {search:String})) > 0
      )`;
    }
    const { rows } = await query(`
      WITH ranked AS (
        SELECT
          p.prefix,
          p.display_name,
          e.display_name AS entity_name,
          p.role,
          row_number() OVER (PARTITION BY p.family, p.prefix ORDER BY p.updated_at DESC) AS rn
        FROM ${prefixesTable} AS p
        LEFT JOIN ${entitiesTable} AS e ON p.entity_id = e.entity_id
        WHERE ${where}
      )
      SELECT prefix, display_name, entity_name, role
      FROM ranked
      WHERE rn = 1
      ORDER BY prefix
      LIMIT {limit:UInt32}
    `, params, { name: 'explorer/entities-own-network' });
    return rows.filter((r) => !needle || String(r.prefix).toLowerCase().includes(needle)
      || String(r.display_name || '').toLowerCase().includes(needle))
      .map((r) => ({
        id: String(r.prefix),
        label: String(r.display_name || r.prefix),
        sublabel: [r.entity_name, r.role].filter(Boolean).join(' · '),
        value: String(r.prefix),
      }));
  }

  if (type === 'switch_ip') {
    const agents = snmpAgentsCurrentRef();
    const ifaces = netInterfacesCurrentRef();
    const params = { limit: lim };
    let where = '1';
    if (search) {
      params.search = `%${search}%`;
      where = `positionCaseInsensitive(a.switch_ip, trim(BOTH '%' FROM {search:String})) > 0
        OR positionCaseInsensitive(a.display_name, trim(BOTH '%' FROM {search:String})) > 0`;
    }
    const { rows } = await query(`
      SELECT
        a.switch_ip,
        a.display_name,
        a.snmp_enabled,
        a.last_poll_status,
        ifNull(i.interface_count, 0) AS interface_count
      FROM ${agents} AS a
      LEFT JOIN (
        SELECT switch_ip, count() AS interface_count
        FROM ${ifaces}
        GROUP BY switch_ip
      ) AS i ON a.switch_ip = i.switch_ip
      WHERE ${where}
      ORDER BY a.display_name, a.switch_ip
      LIMIT {limit:UInt32}
    `, params, { name: 'explorer/entities-switch-ip' });
    return rows.map((r) => {
      const ip = String(r.switch_ip);
      const name = String(r.display_name || '').trim();
      const label = name && name !== ip ? name : ip;
      const hasCache = Number(r.interface_count) > 0;
      const status = explorerSnmpPollStatusLabel(r.last_poll_status, r.snmp_enabled, hasCache);
      return {
        id: ip,
        label,
        sublabel: [name && name !== ip ? ip : null, status].filter(Boolean).join(' · '),
        value: ip,
      };
    });
  }

  if (type === 'if_name') {
    const ifaces = netInterfacesCurrentRef();
    const params = { limit: lim };
    let where = "if_name != ''";
    if (switchIps.length) {
      params.switch_ips = switchIps;
      where += ' AND switch_ip IN {switch_ips:Array(String)}';
    }
    if (search) {
      params.search = `%${search}%`;
      where += ` AND (
        positionCaseInsensitive(if_name, trim(BOTH '%' FROM {search:String})) > 0
        OR positionCaseInsensitive(if_alias, trim(BOTH '%' FROM {search:String})) > 0
        OR toString(if_index) LIKE {search:String}
        ${switchIps.length ? '' : `OR positionCaseInsensitive(switch_ip, trim(BOTH '%' FROM {search:String})) > 0`}
      )`;
    }
    // Subquery avoids CH inlining argMax/any from the *_current view into WHERE.
    const { rows } = await query(`
      SELECT
        if_name,
        any(if_alias) AS if_alias,
        any(switch_ip) AS switch_ip,
        any(if_index) AS if_index,
        count() AS switches
      FROM (
        SELECT switch_ip, if_index, if_name, if_alias
        FROM ${ifaces}
        WHERE ${where}
      ) AS i
      GROUP BY if_name
      ORDER BY switches DESC, if_name
      LIMIT {limit:UInt32}
    `, params, { name: 'explorer/entities-if-name' });
    return rows.map((r) => ({
      id: String(r.if_name),
      label: String(r.if_name),
      sublabel: [
        r.if_alias || null,
        r.if_index != null ? `ifIndex ${r.if_index}` : null,
        Number(r.switches) > 1 ? `${r.switches} свитчей` : r.switch_ip,
      ].filter(Boolean).join(' · '),
      value: String(r.if_name),
    }));
  }

  return [];
}

function listSavedExplorerFilters(userId) {
  const items = readSavedFiltersStore();
  return items.filter((item) => item.isShared || item.ownerId === userId);
}

function getSavedExplorerFilter(id, userId) {
  const item = readSavedFiltersStore().find((row) => row.id === id);
  if (!item) return null;
  if (!item.isShared && item.ownerId !== userId) return null;
  return item;
}

function createSavedExplorerFilter(userId, payload = {}) {
  const items = readSavedFiltersStore();
  const item = {
    id: `sf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: String(payload.name || 'Без названия').trim() || 'Без названия',
    description: String(payload.description || '').trim(),
    folder: String(payload.folder || 'Мои фильтры').trim() || 'Мои фильтры',
    query: payload.query || {},
    isShared: Boolean(payload.isShared),
    ownerId: userId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  items.push(item);
  writeSavedFiltersStore(items);
  return item;
}

function updateSavedExplorerFilter(id, userId, payload = {}) {
  const items = readSavedFiltersStore();
  const idx = items.findIndex((row) => row.id === id);
  if (idx < 0) return null;
  if (items[idx].ownerId !== userId) return null;
  items[idx] = {
    ...items[idx],
    name: payload.name != null ? String(payload.name).trim() || items[idx].name : items[idx].name,
    description: payload.description != null ? String(payload.description).trim() : items[idx].description,
    folder: payload.folder != null ? String(payload.folder).trim() || items[idx].folder : items[idx].folder,
    query: payload.query != null ? payload.query : items[idx].query,
    isShared: payload.isShared != null ? Boolean(payload.isShared) : items[idx].isShared,
    updatedAt: new Date().toISOString(),
  };
  writeSavedFiltersStore(items);
  return items[idx];
}

function deleteSavedExplorerFilter(id, userId) {
  const items = readSavedFiltersStore();
  const item = items.find((row) => row.id === id);
  if (!item || item.ownerId !== userId) return false;
  writeSavedFiltersStore(items.filter((row) => row.id !== id));
  return true;
}

function rowsToCsv(rows, groupBy, metricLabel) {
  const headers = [
    ...groupBy.map((g) => g.label),
    metricLabel,
    'Доля',
    ...EXPLORER_RESULT_EXPORT_COLUMNS.map((c) => c.label),
  ];
  const escape = (value) => {
    const s = String(value ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.map(escape).join(',')];
  for (const row of rows) {
    lines.push([
      ...row.values,
      row.metric,
      `${Number(row.pct || 0).toFixed(2)}%`,
      ...EXPLORER_RESULT_EXPORT_COLUMNS.map((c) => row[c.key]),
    ].map(escape).join(','));
  }
  return lines.join('\n');
}

async function explorerExportCsv(body = {}) {
  const exportBody = {
    ...body,
    limit: EXPLORER_MAX_EXPORT_ROWS,
    offset: 0,
  };
  const spec = await explorerFlows(exportBody);
  const { rows } = await query(spec.sql, spec.params || {}, { name: 'explorer/export' });
  const windowSeconds = spec.meta?.windowSeconds || explorerWindowSeconds({ range: exportBody.range, from: exportBody.from, to: exportBody.to });
  const mapped = (await spec.map(rows)).map((row) => enrichExplorerFlowRow(row, windowSeconds));
  const metricLabel = spec.meta?.metricLabel || 'metric';
  return rowsToCsv(mapped, spec.meta?.groupBy || [], metricLabel);
}

module.exports = {
  explorerSchema,
  explorerFlows,
  explorerSummary,
  explorerTimeseries,
  explorerResultSeries,
  explorerGroupedTimeseries,
  explorerBreakdown,
  explorerQuery,
  searchExplorerEntities,
  listSavedExplorerFilters,
  getSavedExplorerFilter,
  createSavedExplorerFilter,
  updateSavedExplorerFilter,
  deleteSavedExplorerFilter,
  explorerExportCsv,
  normalizeExplorerQuery,
  parseExplorerAsnNumber,
  asnExplorerDisplayLabel,
  lookupAsnDisplayNames,
  EXPLORER_MAX_LIMIT,
};
