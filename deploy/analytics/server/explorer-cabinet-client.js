const {
  col, flowCol, query, netInterfacesCurrentRef, config, escapeSqlString,
} = require('./clickhouse');
const { flowSamplerIpExpr, sflowIfIndexExpr } = require('./queries');
const { asStringArray, buildClientSearchWhere } = require('./client-search');
const { explorerFilterUsesField } = require('./explorer-filter-tree.js');

const CLIENTS_ENABLED = 'default.net_clients_enabled';
const CLIENTS_TABLE = 'default.net_clients';
const PREFIXES_ENABLED = 'default.net_client_prefixes_enabled';
const PORTS_ENABLED = 'default.net_client_ports_enabled';

const CABINET_CLIENT_MAX_RANGE_MS = 6 * 3600000;
const CABINET_CLIENT_MAX_RANGE_HOURS = 6;

function cabinetClientHttpError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function bindModeLabel(bindMode) {
  return bindMode === 'ports' ? 'по портам' : 'по сетям';
}

function bindingCountLabel(bindMode, prefixCount, portCount) {
  if (bindMode === 'ports') {
    const n = Number(portCount) || 0;
    return `${n} ${n === 1 ? 'порт' : n >= 2 && n <= 4 ? 'порта' : 'портов'}`;
  }
  const n = Number(prefixCount) || 0;
  return `${n} CIDR`;
}

function buildCabinetClientSearchWhere(search, params) {
  return buildClientSearchWhere(search, params, {
    clientAlias: 'c',
    prefixesFrom: PREFIXES_ENABLED,
    portsFrom: PORTS_ENABLED,
    interfacesFrom: netInterfacesCurrentRef(),
  });
}

function flowIpRangeExpr(flowAlias, ipColName) {
  const ipRef = `${flowAlias}.${ipColName}`;
  // FixedString(16) IPv4 layout — no etype column inside scalar subqueries.
  return `if(
    length(${ipRef}) = 16
      AND substring(${ipRef}, 5) = unhex('000000000000000000000000'),
    toString(toIPv4(reinterpretAsUInt32(reverse(substring(${ipRef}, 1, 4))))),
    IPv6NumToString(${ipRef})
  )`;
}

function explorerFlowRefs(flowAlias = 'f') {
  const srcIpCol = col('srcIp');
  const dstIpCol = col('dstIp');
  const samplerCol = flowCol('samplerAddress');
  const inIfCol = flowCol('inIf');
  const outIfCol = flowCol('outIf');
  return {
    srcIpExpr: flowIpRangeExpr(flowAlias, srcIpCol),
    dstIpExpr: flowIpRangeExpr(flowAlias, dstIpCol),
    // Словарю нужен адрес как он лежит в журнале, без превращения в строку.
    srcIpRawExpr: `${flowAlias}.${srcIpCol}`,
    dstIpRawExpr: `${flowAlias}.${dstIpCol}`,
    samplerIpExpr: samplerCol ? flowSamplerIpExpr(`${flowAlias}.${samplerCol}`) : null,
    inIfExpr: inIfCol ? sflowIfIndexExpr(`${flowAlias}.${inIfCol}`) : null,
    outIfExpr: outIfCol ? sflowIfIndexExpr(`${flowAlias}.${outIfCol}`) : null,
    srcClientExpr: `${flowAlias}.src_client`,
    dstClientExpr: `${flowAlias}.dst_client`,
  };
}

function buildPrefixMatchClause(prefixes, refs, params, idxRef) {
  if (!prefixes.length) return null;
  const parts = prefixes.map((prefix) => {
    const paramName = `cabinet_client_prefix_${idxRef.i++}`;
    params[paramName] = prefix;
    return `(isIPAddressInRange(${refs.srcIpExpr}, {${paramName}:String}) OR isIPAddressInRange(${refs.dstIpExpr}, {${paramName}:String}))`;
  });
  return parts.length === 1 ? parts[0] : `(${parts.join(' OR ')})`;
}

function buildPortMatchClause(ports, refs, params, idxRef) {
  if (!ports.length || !refs.samplerIpExpr) return null;
  const parts = ports.map((port) => {
    const switchParam = `cabinet_client_switch_${idxRef.i++}`;
    const ifParam = `cabinet_client_if_${idxRef.i++}`;
    params[switchParam] = port.switchIp;
    params[ifParam] = Number(port.ifIndex) || 0;
    const inMatch = refs.inIfExpr
      ? `(${refs.samplerIpExpr} = {${switchParam}:String} AND ${refs.inIfExpr} = {${ifParam}:UInt32})`
      : null;
    const outMatch = refs.outIfExpr
      ? `(${refs.samplerIpExpr} = {${switchParam}:String} AND ${refs.outIfExpr} = {${ifParam}:UInt32})`
      : null;
    if (inMatch && outMatch) return `(${inMatch} OR ${outMatch})`;
    return inMatch || outMatch;
  }).filter(Boolean);
  if (!parts.length) return null;
  return parts.length === 1 ? parts[0] : `(${parts.join(' OR ')})`;
}

function buildTaggedClientClause(clientId, refs, params, idxRef) {
  const srcParam = `cabinet_client_src_${idxRef.i++}`;
  const dstParam = `cabinet_client_dst_${idxRef.i++}`;
  params[srcParam] = clientId;
  params[dstParam] = clientId;
  return `(${refs.srcClientExpr} = {${srcParam}:String} OR ${refs.dstClientExpr} = {${dstParam}:String})`;
}

async function fetchLatestClientRow(clientId) {
  const { rows } = await query(
    `
      SELECT client_id, display_name, bind_mode, enabled
      FROM (
        SELECT
          client_id,
          display_name,
          bind_mode,
          enabled,
          row_number() OVER (
            PARTITION BY client_id
            ORDER BY updated_at DESC
          ) AS rn
        FROM ${CLIENTS_TABLE}
        WHERE client_id = {clientId:String}
      )
      WHERE rn = 1
      LIMIT 1
    `,
    { clientId: String(clientId ?? '').trim() },
    { name: 'explorer/cabinet-client-latest' },
  );
  return rows[0] || null;
}

async function getCabinetClientBinding(clientId, { requireEnabled = true } = {}) {
  const id = String(clientId ?? '').trim();
  if (!id) throw cabinetClientHttpError('Укажите client_id');

  let row = null;
  const { rows } = await query(
    `
      SELECT client_id, display_name, bind_mode
      FROM ${CLIENTS_ENABLED}
      WHERE client_id = {clientId:String}
      LIMIT 1
    `,
    { clientId: id },
    { name: 'explorer/cabinet-client-binding' },
  );
  row = rows[0] || null;

  if (!row && !requireEnabled) {
    row = await fetchLatestClientRow(id);
  }
  if (!row) throw cabinetClientHttpError('Клиент недоступен');
  if (requireEnabled && !rows[0]) {
    throw cabinetClientHttpError('Клиент недоступен');
  }

  const bindMode = String(row.bind_mode || '');
  let prefixes = [];
  let ports = [];

  if (bindMode === 'prefixes') {
    const prefixRes = await query(
      `
        SELECT prefix
        FROM ${PREFIXES_ENABLED}
        WHERE client_id = {clientId:String}
      `,
      { clientId: id },
      { name: 'explorer/cabinet-client-prefixes' },
    );
    prefixes = prefixRes.rows.map((r) => String(r.prefix)).filter(Boolean);
  } else if (bindMode === 'ports') {
    const portRes = await query(
      `
        SELECT switch_ip, if_index
        FROM ${PORTS_ENABLED}
        WHERE client_id = {clientId:String}
      `,
      { clientId: id },
      { name: 'explorer/cabinet-client-ports' },
    );
    ports = portRes.rows.map((r) => ({
      switchIp: String(r.switch_ip || ''),
      ifIndex: Number(r.if_index) || 0,
    })).filter((p) => p.switchIp && p.ifIndex > 0);
  }

  return {
    clientId: id,
    displayName: String(row.display_name || id),
    bindMode,
    enabled: Boolean(rows[0]),
    prefixes,
    ports,
  };
}

async function buildCabinetClientMatchSql(clientId, params, idxRef, flowAlias = 'f') {
  const binding = await getCabinetClientBinding(clientId);
  const refs = explorerFlowRefs(flowAlias);
  const parts = [buildTaggedClientClause(binding.clientId, refs, params, idxRef)];

  if (binding.bindMode === 'prefixes') {
    const prefixClause = buildPrefixMatchClause(binding.prefixes, refs, params, idxRef);
    if (prefixClause) parts.push(prefixClause);
  } else if (binding.bindMode === 'ports') {
    const portClause = buildPortMatchClause(binding.ports, refs, params, idxRef);
    if (portClause) parts.push(portClause);
  }

  return parts.length === 1 ? parts[0] : `(${parts.join(' OR ')})`;
}

async function buildCabinetClientFilterSql(ids, op, params, flowAlias = 'f') {
  const clientIds = [...new Set(
    (Array.isArray(ids) ? ids : [ids])
      .map((v) => String(v ?? '').trim())
      .filter(Boolean),
  )];
  if (!clientIds.length) return null;

  const idxRef = { i: 0 };
  const matchParts = [];
  for (const clientId of clientIds) {
    matchParts.push(await buildCabinetClientMatchSql(clientId, params, idxRef, flowAlias));
  }
  const inner = matchParts.length === 1 ? matchParts[0] : `(${matchParts.join(' OR ')})`;
  const negOps = new Set(['!=', 'not_in']);
  return negOps.has(String(op || '').toLowerCase()) ? `NOT (${inner})` : inner;
}

const CABINET_CLIENT_PORT_KEYS = 'cabinet_client_port_keys';
const CABINET_CLIENT_PORT_VALUES = 'cabinet_client_port_values';

// Привязки по портам отдаются двумя согласованными массивами, чтобы поиск
// клиента шёл через transform, то есть по хешу. Массив кортежей пришлось бы
// перебирать целиком на каждой строке потока, а это десятки секунд на окно.
// Ключи сгруппированы и упорядочены одинаково в обеих выборках, поэтому
// массивы совпадают позиция в позицию.
function cabinetClientPortCatalogSelect(column) {
  return `(SELECT groupArray(${column}) FROM (
         SELECT
           concat(p.switch_ip, '|', toString(p.if_index)) AS port_key,
           min(p.client_id) AS client_id
         FROM ${PORTS_ENABLED} AS p
         INNER JOIN ${CLIENTS_ENABLED} AS c
           ON c.client_id = p.client_id AND c.bind_mode = 'ports'
         GROUP BY port_key
         ORDER BY port_key
      ))`;
}

// Привязки по сетям в каталог не попадают: их ищет словарь net_client_prefix_dict.
function cabinetClientCatalogCteLines() {
  return `
      ${cabinetClientPortCatalogSelect('port_key')} AS ${CABINET_CLIENT_PORT_KEYS},
      ${cabinetClientPortCatalogSelect('client_id')} AS ${CABINET_CLIENT_PORT_VALUES}`;
}

function appendCabinetClientCatalogToCteHead(cteHead, groups = []) {
  if (!groups.includes('cabinet_client')) return cteHead;
  return `${cteHead}\n        ${cabinetClientCatalogCteLines().trim()},`;
}

function explorerWindowSpecWithCabinetClientCatalog(windowSpec, groups = []) {
  if (!groups.includes('cabinet_client')) return windowSpec;
  return {
    ...windowSpec,
    cteHead: appendCabinetClientCatalogToCteHead(windowSpec.cteHead, groups),
  };
}

// Привязки по сетям коллектор проставляет ещё при приёме, в src_client и
// dst_client, поэтому поиск по сетям нужен как подстраховка для данных,
// записанных до появления привязки. Подстраховка всё равно считается на каждой
// строке окна, поэтому её цена важна: перебор каталога через arrayFirst на
// 19 тысячах привязок запрашивал 54 ГиБ памяти и запрос не выполнялся вовсе,
// а словарь отдаёт то же окно на 36 миллионов строк за 3.4 секунды.
//
// Адрес в журнале лежит как 16 байт, и у IPv4 значимы только первые четыре,
// остальные нули. Ключи двух семейств различаются, поэтому и обращений два —
// так же, как в поиске страны по адресу.
function cabinetClientPrefixLookupFromDict(rawIpExpr) {
  if (!rawIpExpr) return `''`;
  const dict = escapeSqlString(config.clientPrefixDict);
  const lookup = (keyExpr) => `dictGetOrDefault('${dict}', 'client_id', tuple(${keyExpr}), '')`;
  const isIpv4 = `length(${rawIpExpr}) = 16`
    + ` AND substring(${rawIpExpr}, 5) = unhex('000000000000000000000000')`;
  const ipv4Key = `toIPv4(reinterpretAsUInt32(reverse(substring(${rawIpExpr}, 1, 4))))`;
  return `if(${isIpv4}, ${lookup(ipv4Key)}, ${lookup(rawIpExpr)})`;
}

function cabinetClientPortLookupFromRules(samplerIpExpr, ifExpr) {
  if (!samplerIpExpr || !ifExpr) return `''`;
  return `transform(
        concat(${samplerIpExpr}, '|', toString(${ifExpr})),
        ${CABINET_CLIENT_PORT_KEYS},
        ${CABINET_CLIENT_PORT_VALUES},
        ''
      )`;
}

function cabinetClientGroupKeyExpr(flowAlias = 'f') {
  const refs = explorerFlowRefs(flowAlias);
  const prefixSrc = cabinetClientPrefixLookupFromDict(refs.srcIpRawExpr);
  const prefixDst = cabinetClientPrefixLookupFromDict(refs.dstIpRawExpr);
  const portIn = cabinetClientPortLookupFromRules(refs.samplerIpExpr, refs.inIfExpr);
  const portOut = cabinetClientPortLookupFromRules(refs.samplerIpExpr, refs.outIfExpr);

  return `multiIf(
    ${refs.srcClientExpr} != '', ${refs.srcClientExpr},
    ${refs.dstClientExpr} != '', ${refs.dstClientExpr},
    ${prefixSrc} != '', ${prefixSrc},
    ${prefixDst} != '', ${prefixDst},
    ${portIn} != '', ${portIn},
    ${portOut} != '', ${portOut},
    '—'
  )`;
}

function cabinetClientLabelFromKey(keyExpr) {
  return `if(toString(${keyExpr}) = '' OR toString(${keyExpr}) = '—', '—', toString(${keyExpr}))`;
}

async function lookupCabinetClientDisplayNames(clientIds = []) {
  const ids = [...new Set(
    (Array.isArray(clientIds) ? clientIds : [])
      .map((v) => String(v || '').trim())
      .filter((v) => v && v !== '—'),
  )];
  const byId = new Map();
  if (!ids.length) return byId;

  const { rows } = await query(
    `
      SELECT client_id, display_name
      FROM ${CLIENTS_ENABLED}
      WHERE client_id IN {ids:Array(String)}
    `,
    { ids },
    { name: 'explorer/cabinet-client-names' },
  );
  for (const row of rows) {
    byId.set(String(row.client_id), String(row.display_name || row.client_id));
  }
  return byId;
}

function readCabinetClientSearchField(row, names, fallback = '') {
  for (const name of names) {
    const value = row?.[name];
    if (value != null && String(value).trim() !== '') return String(value);
  }
  return String(fallback ?? '');
}

function mapCabinetClientSearchRow(row) {
  const clientId = readCabinetClientSearchField(row, [
    'client_id',
    'clientId',
    'c.client_id',
  ]);
  const displayName = readCabinetClientSearchField(row, [
    'display_name',
    'displayName',
    'c.display_name',
  ], clientId);
  const bindMode = readCabinetClientSearchField(row, [
    'bind_mode',
    'bindMode',
    'c.bind_mode',
  ]);
  const prefixCount = Number(row.prefix_count ?? row.prefixCount ?? row['pc.prefix_count']) || 0;
  const portCount = Number(row.port_count ?? row.portCount ?? row['pt.port_count']) || 0;
  const bindingCount = bindMode === 'ports' ? portCount : prefixCount;
  const hasBinding = bindingCount > 0;
  const bindLabel = bindModeLabel(bindMode);
  const countLabel = bindingCountLabel(bindMode, prefixCount, portCount);
  const preview = asStringArray(row.binding_preview ?? row.bindingPreview).slice(0, 3);
  const extra = Math.max(0, bindingCount - preview.length);
  const previewLabel = preview.length
    ? `${preview.join(', ')}${extra > 0 ? ` +${extra}` : ''}`
    : countLabel;

  return {
    id: clientId,
    label: displayName,
    sublabel: hasBinding
      ? `${clientId} · ${bindLabel} · ${previewLabel}`
      : `${clientId} · нет привязки · только потоки с меткой`,
    value: clientId,
    disabled: false,
    hasBinding,
    bindingPreview: preview,
  };
}

async function searchCabinetClients({ q = '', limit = 20 } = {}) {
  const search = String(q || '').trim();
  const lim = Math.min(Math.max(Number(limit) || 20, 1), 50);
  const params = { limit: lim };
  const where = search ? buildCabinetClientSearchWhere(search, params) : '1';

  const { rows } = await query(
    `
      SELECT
        c.client_id AS client_id,
        c.display_name AS display_name,
        c.bind_mode AS bind_mode,
        coalesce(pc.prefix_count, 0) AS prefix_count,
        coalesce(pt.port_count, 0) AS port_count,
        if(c.bind_mode = 'ports', coalesce(pp.items, []), coalesce(px.items, [])) AS binding_preview
      FROM ${CLIENTS_ENABLED} AS c
      LEFT JOIN (
        SELECT client_id, count() AS prefix_count
        FROM ${PREFIXES_ENABLED}
        GROUP BY client_id
      ) AS pc ON pc.client_id = c.client_id
      LEFT JOIN (
        SELECT client_id, count() AS port_count
        FROM ${PORTS_ENABLED}
        GROUP BY client_id
      ) AS pt ON pt.client_id = c.client_id
      LEFT JOIN (
        SELECT
          client_id,
          arraySlice(arraySort(groupArray(prefix)), 1, 3) AS items
        FROM ${PREFIXES_ENABLED}
        GROUP BY client_id
      ) AS px ON px.client_id = c.client_id
      LEFT JOIN (
        SELECT
          p.client_id AS client_id,
          arraySlice(arraySort(groupArray(
            concat(
              p.switch_ip,
              ' · ',
              if(ni.if_name != '', ni.if_name, concat('ifIndex ', toString(p.if_index)))
            )
          )), 1, 3) AS items
        FROM ${PORTS_ENABLED} AS p
        LEFT JOIN ${netInterfacesCurrentRef()} AS ni
          ON ni.switch_ip = p.switch_ip AND ni.if_index = p.if_index
        GROUP BY p.client_id
      ) AS pp ON pp.client_id = c.client_id
      WHERE ${where}
      ORDER BY c.display_name, c.client_id
      LIMIT {limit:UInt32}
    `,
    params,
    { name: 'explorer/entities-cabinet-client' },
  );

  const mapped = rows.map(mapCabinetClientSearchRow);
  if (!search || mapped.some((row) => row.id === search)) return mapped;

  if (!/^client:/i.test(search)) return mapped;

  const latest = await fetchLatestClientRow(search);
  if (!latest || Number(latest.enabled) === 1) return mapped;

  const [prefixRes, portRes] = await Promise.all([
    query(
      `SELECT count() AS prefix_count FROM ${PREFIXES_ENABLED} WHERE client_id = {clientId:String}`,
      { clientId: search },
      { name: 'explorer/cabinet-client-prefix-count' },
    ),
    query(
      `SELECT count() AS port_count FROM ${PORTS_ENABLED} WHERE client_id = {clientId:String}`,
      { clientId: search },
      { name: 'explorer/cabinet-client-port-count' },
    ),
  ]);

  return [
    ...mapped,
    mapCabinetClientSearchRow({
      client_id: latest.client_id,
      display_name: latest.display_name,
      bind_mode: latest.bind_mode,
      prefix_count: Number(prefixRes.rows[0]?.prefix_count) || 0,
      port_count: Number(portRes.rows[0]?.port_count) || 0,
    }),
  ].slice(0, lim);
}

function queryUsesCabinetClient(q = {}) {
  if (explorerFilterUsesField(q.filters, 'cabinet_client')) return true;
  const groupBy = Array.isArray(q.groupBy) ? q.groupBy : [];
  return groupBy.some((token) => {
    const raw = String(token ?? '').trim();
    return raw === 'cabinet_client' || raw.startsWith('cabinet_client/');
  });
}

function explorerCabinetClientDisplayLabel(clientId, displayName) {
  const id = String(clientId || '').trim();
  if (!id || id === '—') return '—';
  const name = String(displayName || '').trim();
  return name && name !== id ? name : id;
}

module.exports = {
  CABINET_CLIENT_MAX_RANGE_MS,
  CABINET_CLIENT_MAX_RANGE_HOURS,
  searchCabinetClients,
  getCabinetClientBinding,
  buildCabinetClientMatchSql,
  buildCabinetClientFilterSql,
  cabinetClientGroupKeyExpr,
  cabinetClientLabelFromKey,
  lookupCabinetClientDisplayNames,
  queryUsesCabinetClient,
  explorerCabinetClientDisplayLabel,
  mapCabinetClientSearchRow,
  appendCabinetClientCatalogToCteHead,
  buildCabinetClientSearchWhere,
  explorerWindowSpecWithCabinetClientCatalog,
  CABINET_CLIENT_PORT_KEYS,
  CABINET_CLIENT_PORT_VALUES,
};
