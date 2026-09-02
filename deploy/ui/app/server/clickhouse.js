const { createClient } = require('@clickhouse/client');
const { logVerbose, logSqlStart, logSqlDone, logSqlError } = require('./logger');
const { setFailedSql } = require('./request-context');
const { inlineClickHouseParams } = require('./clickhouse-sql-inline');

function env(name, fallback = '') {
  return process.env[name] ?? fallback;
}

function envInt(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function envBool(name, fallback = false) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

/** Empty or "-" disables optional column mapping. */
function envOpt(name, fallback) {
  const v = process.env[name];
  if (v === undefined) return fallback;
  if (v === '' || v === '-') return null;
  return v;
}

function envCredential(name, fallbackName, fallback = '') {
  if (process.env[name] !== undefined && process.env[name] !== '') {
    return process.env[name];
  }
  if (fallbackName && process.env[fallbackName] !== undefined) {
    return process.env[fallbackName];
  }
  return fallback;
}

const config = {
  url: env('CLICKHOUSE_URL', 'http://localhost:8123'),
  username: env('CLICKHOUSE_USER', 'default'),
  password: env('CLICKHOUSE_PASSWORD', ''),
  readUsername: envCredential('CLICKHOUSE_READ_USER', 'CLICKHOUSE_USER', 'default'),
  readPassword: envCredential('CLICKHOUSE_READ_PASSWORD', 'CLICKHOUSE_PASSWORD', ''),
  writeUsername: envCredential('CLICKHOUSE_WRITE_USER', 'CLICKHOUSE_USER', 'default'),
  writePassword: envCredential('CLICKHOUSE_WRITE_PASSWORD', 'CLICKHOUSE_PASSWORD', ''),
  database: env('CLICKHOUSE_DATABASE', 'default'),
  table: env('CLICKHOUSE_FLOWS_TABLE', 'flows'),
  flowsRawTable: env('CLICKHOUSE_FLOWS_RAW_TABLE', 'flows_raw'),
  dashboardTable: env('CLICKHOUSE_DASHBOARD_TABLE', 'traffic_dashboard_1m'),
  dashboardHourTable: env('CLICKHOUSE_DASHBOARD_HOUR_TABLE', 'traffic_dashboard_1h'),
  dashboardDayTable: env('CLICKHOUSE_DASHBOARD_DAY_TABLE', 'traffic_dashboard_1d'),
  protocolTable: env('CLICKHOUSE_PROTOCOL_TABLE', 'traffic_protocol_1m'),
  serviceTable: env('CLICKHOUSE_SERVICE_TABLE', 'traffic_service_1m'),
  unknownPortTable: env('CLICKHOUSE_UNKNOWN_PORT_TABLE', 'traffic_unknown_port_1m'),
  countryTable: env('CLICKHOUSE_COUNTRY_TABLE', 'traffic_country_1m'),
  talkerTable: env('CLICKHOUSE_TALKER_TABLE', 'traffic_asn_1m'),
  talkerHourTable: env('CLICKHOUSE_TALKER_TABLE_HOUR', 'traffic_asn_1h'),
  pairTable: env('CLICKHOUSE_PAIR_TABLE', 'traffic_asn_pair_1m'),
  pairHourTable: env('CLICKHOUSE_PAIR_TABLE_HOUR', 'traffic_asn_pair_1h'),
  sourcesTable: env('CLICKHOUSE_SOURCES_TABLE', 'net_flow_sources_enabled'),
  flowSourcesTable: env('CLICKHOUSE_FLOW_SOURCES_TABLE', 'net_flow_sources'),
  collectorsView: env('CLICKHOUSE_COLLECTORS_VIEW', 'net_collectors_enabled'),
  asnNamesTable: env('CLICKHOUSE_ASN_NAMES_TABLE', 'asn_names'),
  ipAsnPrefixesTable: env('CLICKHOUSE_IP_ASN_PREFIXES_TABLE', 'ip_asn_prefixes_current'),
  asnRegistryEnrichedTable: env('CLICKHOUSE_ASN_REGISTRY_TABLE', 'asn_registry_enriched'),
  collectorsTable: env('CLICKHOUSE_COLLECTORS_TABLE', 'net_collectors'),
  snmpSettingsCurrent: env('CLICKHOUSE_SNMP_SETTINGS_CURRENT', 'net_snmp_settings_current'),
  snmpSettingsTable: env('CLICKHOUSE_SNMP_SETTINGS_TABLE', 'net_snmp_settings'),
  snmpAgentsCurrent: env('CLICKHOUSE_SNMP_AGENTS_CURRENT', 'net_snmp_agents_current'),
  snmpAgentsTable: env('CLICKHOUSE_SNMP_AGENTS_TABLE', 'net_snmp_agents'),
  netInterfacesCurrent: env('CLICKHOUSE_NET_INTERFACES_CURRENT', 'net_interfaces_current'),
  netInterfacesDict: env('CLICKHOUSE_NET_INTERFACES_DICT', 'default.net_interfaces_dict'),
  directionSettingsTable: env('CLICKHOUSE_DIRECTION_SETTINGS_TABLE', 'net_direction_settings'),
  directionSettingsView: env('CLICKHOUSE_DIRECTION_SETTINGS_VIEW', 'net_direction_settings_current'),
  interfaceRoleRulesTable: env('CLICKHOUSE_INTERFACE_ROLE_RULES_TABLE', 'net_interface_role_rules'),
  interfaceRoleRulesView: env('CLICKHOUSE_INTERFACE_ROLE_RULES_VIEW', 'net_interface_role_rules_current'),
  interfaceRolesTable: env('CLICKHOUSE_INTERFACE_ROLES_TABLE', 'net_interface_roles'),
  interfaceRolesView: env('CLICKHOUSE_INTERFACE_ROLES_VIEW', 'net_interface_roles_current'),
  interfaceRolesEffectiveTable: env('CLICKHOUSE_INTERFACE_ROLES_EFFECTIVE_TABLE', 'net_interface_roles_effective'),
  interfaceRolesEffectiveView: env('CLICKHOUSE_INTERFACE_ROLES_EFFECTIVE_VIEW', 'net_interface_roles_effective_current'),
  geoCountryDict: env('CLICKHOUSE_GEO_COUNTRY_DICT', 'default.geo_country_dict'),
  locationsView: env('CLICKHOUSE_LOCATIONS_VIEW', 'net_locations_enabled'),
  locationsTable: env('CLICKHOUSE_LOCATIONS_TABLE', 'net_locations'),
  dnsLogTable: env('CLICKHOUSE_DNS_LOG_TABLE', 'dns_log'),
  dnsAnswersTable: env('CLICKHOUSE_DNS_ANSWERS_TABLE', 'dns_answers'),
  dnsActivity5mTable: env('CLICKHOUSE_DNS_ACTIVITY_5M_TABLE', 'dns_activity_5m'),
  dnsDomains1hTable: env('CLICKHOUSE_DNS_DOMAINS_1H_TABLE', 'dns_domains_1h'),
  dnsClients1hTable: env('CLICKHOUSE_DNS_CLIENTS_1H_TABLE', 'dns_clients_1h'),
  dnsServers1hTable: env('CLICKHOUSE_DNS_SERVERS_1H_TABLE', 'dns_servers_1h'),
  dnsResolversTable: env('CLICKHOUSE_DNS_RESOLVERS_TABLE', 'net_dns_resolvers'),
  dnsResolversView: env('CLICKHOUSE_DNS_RESOLVERS_VIEW', 'net_dns_resolvers_enabled'),
  bmpRouteEventsTable: env('CLICKHOUSE_BMP_ROUTE_EVENTS_TABLE', 'bmp_route_events'),
  l3PrefixesTable: env('CLICKHOUSE_L3_PREFIXES_TABLE', 'net_l3_prefixes'),
  l3PrefixesView: env('CLICKHOUSE_L3_PREFIXES_VIEW', 'net_l3_prefixes_enabled'),
  clientsView: env('CLICKHOUSE_CLIENTS_VIEW', 'net_clients_enabled'),
  clientPortsView: env('CLICKHOUSE_CLIENT_PORTS_VIEW', 'net_client_ports_enabled'),
  flowExclusionsTable: env('CLICKHOUSE_FLOW_EXCLUSIONS_TABLE', 'net_flow_exclusions'),
  flowExclusionsView: env('CLICKHOUSE_FLOW_EXCLUSIONS_VIEW', 'net_flow_exclusions_enabled'),
  l2VlansTable: env('CLICKHOUSE_L2_VLANS_TABLE', 'net_l2_vlans'),
  l2VlansView: env('CLICKHOUSE_L2_VLANS_VIEW', 'net_l2_vlans_enabled'),
  vlanTable: env('CLICKHOUSE_VLAN_TABLE', 'traffic_vlan_1m'),
  entitiesTable: env('CLICKHOUSE_ENTITIES_TABLE', 'net_entities'),
  entitiesView: env('CLICKHOUSE_ENTITIES_VIEW', 'net_entities_enabled'),
  portServicesTable: env('CLICKHOUSE_PORT_SERVICES_TABLE', 'port_services'),
  portServicesView: env('CLICKHOUSE_PORT_SERVICES_VIEW', 'port_services_enabled'),
  portServicesExpandedView: env('CLICKHOUSE_PORT_SERVICES_EXPANDED_VIEW', 'port_services_expanded_enabled'),
  usersTable: env('CLICKHOUSE_USERS_TABLE', 'users'),
  rolesTable: env('CLICKHOUSE_ROLES_TABLE', 'roles'),
  rolePermissionsTable: env('CLICKHOUSE_ROLE_PERMISSIONS_TABLE', 'role_permissions'),
  userPermissionsTable: env('CLICKHOUSE_USER_PERMISSIONS_TABLE', 'user_permissions'),
  collectorHealthView: envOpt('CLICKHOUSE_COLLECTOR_HEALTH_VIEW', null),
  collectorHealthSnapshotsTable: env('CLICKHOUSE_COLLECTOR_HEALTH_SNAPSHOTS_TABLE', 'collector_health_snapshots'),
  requestTimeoutMs: envInt('CLICKHOUSE_REQUEST_TIMEOUT_MS', 30000),
  logSql: envBool('CLICKHOUSE_LOG_SQL', process.env.NODE_ENV !== 'production'),
  dataTimezone: env('CLICKHOUSE_TIMEZONE', 'Europe/Moscow'),
  columns: {
    time: env('CH_COL_TIME', 'TimeReceived'),
    bytes: env('CH_COL_BYTES', 'Bytes'),
    packets: env('CH_COL_PACKETS', 'Packets'),
    srcIp: env('CH_COL_SRC_IP', 'SrcAddr'),
    dstIp: env('CH_COL_DST_IP', 'DstAddr'),
    srcPort: env('CH_COL_SRC_PORT', 'SrcPort'),
    dstPort: env('CH_COL_DST_PORT', 'DstPort'),
    proto: env('CH_COL_PROTO', 'Proto'),
    srcAsn: env('CH_COL_SRC_ASN', 'SrcAS'),
    dstAsn: env('CH_COL_DST_ASN', 'DstAS'),
  },
  flowColumns: {
    sourceId: envOpt('CH_COL_SOURCE_ID', 'source_id'),
    direction: envOpt('CH_COL_DIRECTION', 'direction'),
    etype: envOpt('CH_COL_ETYPE', 'etype'),
    srcLabel: envOpt('CH_COL_SRC_LABEL', 'src_label'),
    dstLabel: envOpt('CH_COL_DST_LABEL', 'dst_label'),
    srcEndpointScope: envOpt('CH_COL_SRC_ENDPOINT_SCOPE', 'src_endpoint_scope'),
    dstEndpointScope: envOpt('CH_COL_DST_ENDPOINT_SCOPE', 'dst_endpoint_scope'),
    srcEndpointSource: envOpt('CH_COL_SRC_ENDPOINT_SOURCE', 'src_endpoint_source'),
    dstEndpointSource: envOpt('CH_COL_DST_ENDPOINT_SOURCE', 'dst_endpoint_source'),
    srcNetworkName: envOpt('CH_COL_SRC_NETWORK_NAME', 'src_network_name'),
    dstNetworkName: envOpt('CH_COL_DST_NETWORK_NAME', 'dst_network_name'),
    srcEntity: envOpt('CH_COL_SRC_ENTITY', 'src_entity'),
    dstEntity: envOpt('CH_COL_DST_ENTITY', 'dst_entity'),
    srcVlan: envOpt('CH_COL_SRC_VLAN', 'src_vlan'),
    dstVlan: envOpt('CH_COL_DST_VLAN', 'dst_vlan'),
    vlanId: envOpt('CH_COL_VLAN_ID', 'vlan_id'),
    srcAttachmentKind: envOpt('CH_COL_SRC_ATTACHMENT_KIND', 'src_attachment_kind'),
    dstAttachmentKind: envOpt('CH_COL_DST_ATTACHMENT_KIND', 'dst_attachment_kind'),
    srcMac: envOpt('CH_COL_SRC_MAC', 'src_mac'),
    dstMac: envOpt('CH_COL_DST_MAC', 'dst_mac'),
    samplingRate: envOpt('CH_COL_SAMPLING_RATE', null),
    samplerAddress: envOpt('CH_COL_SAMPLER_ADDRESS', 'sampler_address'),
    inIf: envOpt('CH_COL_IN_IF', 'in_if'),
    outIf: envOpt('CH_COL_OUT_IF', 'out_if'),
    tcpFlags: envOpt('CH_COL_TCP_FLAGS', 'tcp_flags'),
    ipTtl: envOpt('CH_COL_IP_TTL', 'ip_ttl'),
  },
  /** MAC column storage: fixedstring (FixedString(6)) or uint64 (Akvorado SrcMAC/DstMAC). */
  macStorage: (() => {
    const v = String(env('CH_MAC_STORAGE', 'fixedstring')).toLowerCase();
    return v === 'uint64' ? 'uint64' : 'fixedstring';
  })(),
  healthColumns: {
    sourceId: envOpt('CH_COL_HEALTH_SOURCE_ID', 'source_id'),
    writerLag: envOpt('CH_COL_WRITER_LAG', 'writer_lag_sec'),
    spoolLag: envOpt('CH_COL_SPOOL_LAG', 'spool_lag_sec'),
    queueDrops: envOpt('CH_COL_QUEUE_DROPS', 'queue_drops'),
  },
};

let readClient = null;
let writeClient = null;
let lastPing = { ok: false, at: 0, error: null, version: null };

function createChClient(username, password, requestTimeoutMs = config.requestTimeoutMs, clickhouseSettings = undefined) {
  const settings = {
    // Keep long HTTP queries alive through idle LB/proxies.
    send_progress_in_http_headers: 1,
    http_headers_progress_interval_ms: 10000,
    ...(clickhouseSettings || {}),
  };
  return createClient({
    url: config.url,
    username,
    password,
    database: config.database,
    request_timeout: requestTimeoutMs,
    clickhouse_settings: settings,
  });
}

function getReadClient() {
  if (!readClient) {
    logVerbose(
      'ClickHouse',
      `read client init → ${config.url} / ${config.database} / ${config.readUsername}`,
    );
    readClient = createChClient(config.readUsername, config.readPassword);
  }
  return readClient;
}

function getWriteClient() {
  if (!writeClient) {
    logVerbose(
      'ClickHouse',
      `write client init → ${config.url} / ${config.database} / ${config.writeUsername}`,
    );
    writeClient = createChClient(config.writeUsername, config.writePassword);
  }
  return writeClient;
}

/** @deprecated Prefer getReadClient or getWriteClient */
function getClient() {
  return getReadClient();
}

function qIdent(name) {
  return `\`${String(name).replace(/`/g, '``')}\``;
}

function tableRef() {
  return `${qIdent(config.database)}.${qIdent(config.table)}`;
}

function flowsRawTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.flowsRawTable)}`;
}

function flowCol(key) {
  const name = config.flowColumns[key];
  return name ? qIdent(name) : null;
}

function dashboardTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dashboardTable)}`;
}

function dashboardHourTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dashboardHourTable)}`;
}

function dashboardDayTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dashboardDayTable)}`;
}

function sourcesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.sourcesTable)}`;
}

function flowSourcesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.flowSourcesTable)}`;
}

function collectorsViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.collectorsView)}`;
}

function asnRegistryEnrichedTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.asnRegistryEnrichedTable)}`;
}

function ipAsnPrefixesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.ipAsnPrefixesTable)}`;
}

function locationsViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.locationsView)}`;
}

function collectorsTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.collectorsTable)}`;
}

function snmpSettingsCurrentRef() {
  return `${qIdent(config.database)}.${qIdent(config.snmpSettingsCurrent)}`;
}

function snmpAgentsCurrentRef() {
  return `${qIdent(config.database)}.${qIdent(config.snmpAgentsCurrent)}`;
}

function snmpAgentsTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.snmpAgentsTable)}`;
}

function netInterfacesCurrentRef() {
  return `${qIdent(config.database)}.${qIdent(config.netInterfacesCurrent)}`;
}

function directionSettingsTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.directionSettingsTable)}`;
}

function directionSettingsViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.directionSettingsView)}`;
}

function interfaceRoleRulesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.interfaceRoleRulesTable)}`;
}

function interfaceRoleRulesViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.interfaceRoleRulesView)}`;
}

function interfaceRolesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.interfaceRolesTable)}`;
}

function interfaceRolesViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.interfaceRolesView)}`;
}

function interfaceRolesEffectiveTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.interfaceRolesEffectiveTable)}`;
}

function interfaceRolesEffectiveViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.interfaceRolesEffectiveView)}`;
}

function netInterfacesDictRef() {
  return String(config.netInterfacesDict)
    .split('.')
    .map(qIdent)
    .join('.');
}

function locationsTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.locationsTable)}`;
}

function collectorHealthViewRef() {
  if (!config.collectorHealthView) return null;
  return `${qIdent(config.database)}.${qIdent(config.collectorHealthView)}`;
}

function collectorHealthSnapshotsTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.collectorHealthSnapshotsTable)}`;
}

function healthCol(key) {
  const name = config.healthColumns[key];
  return name ? qIdent(name) : null;
}

function dnsLogTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dnsLogTable)}`;
}

function dnsAnswersTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dnsAnswersTable)}`;
}

function dnsActivity5mTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dnsActivity5mTable)}`;
}

function dnsDomains1hTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dnsDomains1hTable)}`;
}

function dnsClients1hTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dnsClients1hTable)}`;
}

function dnsServers1hTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dnsServers1hTable)}`;
}

function dnsResolversTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.dnsResolversTable)}`;
}

function dnsResolversViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.dnsResolversView)}`;
}

function protocolTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.protocolTable)}`;
}

function serviceTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.serviceTable)}`;
}

function unknownPortTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.unknownPortTable)}`;
}

function countryTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.countryTable)}`;
}

function talkerTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.talkerTable)}`;
}

function pairTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.pairTable)}`;
}

function talkerHourTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.talkerHourTable)}`;
}

function pairHourTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.pairHourTable)}`;
}

function l3PrefixesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.l3PrefixesTable)}`;
}

function l3PrefixesViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.l3PrefixesView)}`;
}

function clientsViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.clientsView)}`;
}

function clientPortsViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.clientPortsView)}`;
}

function flowExclusionsTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.flowExclusionsTable)}`;
}

function flowExclusionsViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.flowExclusionsView)}`;
}

function l2VlansTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.l2VlansTable)}`;
}

function l2VlansViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.l2VlansView)}`;
}

function vlanTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.vlanTable)}`;
}

function entitiesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.entitiesTable)}`;
}

function entitiesViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.entitiesView)}`;
}

function portServicesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.portServicesTable)}`;
}

function portServicesViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.portServicesView)}`;
}

function portServicesExpandedViewRef() {
  return `${qIdent(config.database)}.${qIdent(config.portServicesExpandedView)}`;
}

function asnNamesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.asnNamesTable)}`;
}

function usersTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.usersTable)}`;
}

function rolesTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.rolesTable)}`;
}

function rolePermissionsTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.rolePermissionsTable)}`;
}

function userPermissionsTableRef() {
  return `${qIdent(config.database)}.${qIdent(config.userPermissionsTable)}`;
}

function col(key) {
  return qIdent(config.columns[key]);
}

function colOpt(key) {
  const name = config.columns[key];
  return name ? qIdent(name) : null;
}

async function ping(force = false) {
  const now = Date.now();
  if (!force && now - lastPing.at < 5000) {
    logVerbose(
      'ClickHouse',
      `ping cache hit · age ${now - lastPing.at} ms · ok=${lastPing.ok}`,
    );
    return lastPing;
  }

  logVerbose('ClickHouse', force ? 'ping (forced)' : 'ping');

  try {
    const ch = getReadClient();
    const result = await ch.query({
      query: 'SELECT version() AS version',
      format: 'JSONEachRow',
    });
    const rows = await result.json();
    lastPing = {
      ok: true,
      at: now,
      error: null,
      version: rows[0]?.version ?? null,
    };
    logVerbose('ClickHouse', `ping OK · ${lastPing.version} · ${Date.now() - now} ms`);
  } catch (err) {
    const message = err?.message || String(err);
    lastPing = {
      ok: false,
      at: now,
      error: message,
      version: null,
    };
    logVerbose('ClickHouse', `ping FAIL · ${message} · ${Date.now() - now} ms`);
  }
  return lastPing;
}

function sqlLogName(options = {}) {
  if (options.name) return options.name;
  return options.label === 'chart' ? 'dashboard/traffic' : 'query';
}

async function query(sql, params = {}, options = {}) {
  const name = sqlLogName(options);
  const started = Date.now();

  if (config.logSql) logSqlStart(name, sql, params);

  let ephemeralClient = null;
  try {
    const timeoutMs = Number(options.requestTimeoutMs) || 0;
    const ch = options.useWrite
      ? getWriteClient()
      : (timeoutMs > 0 && timeoutMs !== config.requestTimeoutMs
        ? (ephemeralClient = createChClient(
          config.readUsername,
          config.readPassword,
          timeoutMs,
          options.clickhouse_settings,
        ))
        : getReadClient());
    const result = await ch.query({
      query: sql,
      query_params: params,
      format: 'JSONEachRow',
      clickhouse_settings: options.clickhouse_settings || undefined,
    });
    const rows = await result.json();
    const elapsedMs = Date.now() - started;
    logSqlDone(name, rows.length, elapsedMs, { logText: config.logSql });
    return { rows, elapsedMs };
  } catch (err) {
    const elapsedMs = Date.now() - started;
    logSqlError(name, err, elapsedMs);
    setFailedSql({
      name,
      sql,
      params,
      error: err?.message || String(err),
      elapsedMs,
      sqlInlined: inlineClickHouseParams(sql, params),
    });
    throw err;
  } finally {
    if (ephemeralClient) {
      ephemeralClient.close().catch(() => {});
    }
  }
}

async function executeCommand(sql, params = {}, options = {}) {
  const name = options.name || 'command';
  const started = Date.now();

  if (config.logSql) logSqlStart(name, sql, params);

  try {
    const ch = getWriteClient();
    await ch.command({ query: sql, query_params: params });
    const elapsedMs = Date.now() - started;
    logSqlDone(name, 0, elapsedMs, { logText: config.logSql });
    return { elapsedMs };
  } catch (err) {
    const elapsedMs = Date.now() - started;
    logSqlError(name, err, elapsedMs);
    setFailedSql({
      name,
      sql,
      params,
      error: err?.message || String(err),
      elapsedMs,
      sqlInlined: inlineClickHouseParams(sql, params),
    });
    throw err;
  }
}

async function insertRows(tableName, rows, options = {}) {
  const name = options.name || 'insert';
  const started = Date.now();
  const table = `${qIdent(config.database)}.${qIdent(tableName)}`;

  if (config.logSql) {
    logSqlStart(name, `INSERT INTO ${table} (${rows.length} row(s))`, {});
  }

  try {
    const ch = getWriteClient();
    await ch.insert({
      table: `${config.database}.${tableName}`,
      values: rows,
      format: 'JSONEachRow',
    });
    const elapsedMs = Date.now() - started;
    logSqlDone(name, rows.length, elapsedMs, { logText: config.logSql });
    return { rows: rows.length, elapsedMs };
  } catch (err) {
    const elapsedMs = Date.now() - started;
    logSqlError(name, err, elapsedMs);
    throw err;
  }
}

function getConfig() {
  return {
    url: config.url.replace(/\/\/([^:@/]+):([^@/]+)@/, '//$1:***@'),
    database: config.database,
    table: config.table,
    flowsRawTable: config.flowsRawTable,
    dashboardTable: config.dashboardTable,
    dashboardHourTable: config.dashboardHourTable,
    dashboardDayTable: config.dashboardDayTable,
    protocolTable: config.protocolTable,
    serviceTable: config.serviceTable,
    unknownPortTable: config.unknownPortTable,
    countryTable: config.countryTable,
    talkerTable: config.talkerTable,
    talkerHourTable: config.talkerHourTable,
    pairTable: config.pairTable,
    pairHourTable: config.pairHourTable,
    sourcesTable: config.sourcesTable,
    flowSourcesTable: config.flowSourcesTable,
    dnsLogTable: config.dnsLogTable,
    dnsAnswersTable: config.dnsAnswersTable,
    dnsActivity5mTable: config.dnsActivity5mTable,
    dnsDomains1hTable: config.dnsDomains1hTable,
    dnsClients1hTable: config.dnsClients1hTable,
    dnsServers1hTable: config.dnsServers1hTable,
    dnsResolversTable: config.dnsResolversTable,
    dnsResolversView: config.dnsResolversView,
    bmpRouteEventsTable: config.bmpRouteEventsTable,
    l3PrefixesTable: config.l3PrefixesTable,
    l3PrefixesView: config.l3PrefixesView,
    flowExclusionsTable: config.flowExclusionsTable,
    flowExclusionsView: config.flowExclusionsView,
    collectorsTable: config.collectorsTable,
    collectorsView: config.collectorsView,
    snmpSettingsCurrent: config.snmpSettingsCurrent,
    snmpSettingsTable: config.snmpSettingsTable,
    snmpAgentsCurrent: config.snmpAgentsCurrent,
    snmpAgentsTable: config.snmpAgentsTable,
    netInterfacesCurrent: config.netInterfacesCurrent,
    netInterfacesDict: config.netInterfacesDict,
    geoCountryDict: config.geoCountryDict,
    collectorHealthSnapshotsTable: config.collectorHealthSnapshotsTable,
    locationsTable: config.locationsTable,
    locationsView: config.locationsView,
    entitiesTable: config.entitiesTable,
    entitiesView: config.entitiesView,
    usersTable: config.usersTable,
    rolesTable: config.rolesTable,
    rolePermissionsTable: config.rolePermissionsTable,
    userPermissionsTable: config.userPermissionsTable,
    logSql: config.logSql,
    dataTimezone: config.dataTimezone,
    columns: { ...config.columns },
  };
}

function escapeSqlString(value) {
  return String(value || '').replace(/'/g, "''");
}

function parseDataDatetimeSql(paramName) {
  const tz = escapeSqlString(config.dataTimezone || 'UTC');
  return `parseDateTimeBestEffort({${paramName}:String}, '${tz}')`;
}

function formatDataDatetimeSql(expr) {
  const tz = escapeSqlString(config.dataTimezone || 'UTC');
  return `formatDateTime(${expr}, '%F %T', '${tz}')`;
}

/** Naive DateTime64(3) in CLICKHOUSE_TIMEZONE — same clock as now64() on the server. */
function formatDateTime64(date = new Date(), timeZone = config.dataTimezone || 'Europe/Moscow') {
  const d = date instanceof Date ? date : new Date(date);
  const instant = Number.isFinite(d.getTime()) ? d : new Date();
  try {
    const fmt = new Intl.DateTimeFormat('en-US', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
      fractionalSecondDigits: 3,
    });
    const parts = Object.fromEntries(fmt.formatToParts(instant).map((p) => [p.type, p.value]));
    const frac = String(parts.fractionalSecond ?? instant.getUTCMilliseconds()).padStart(3, '0').slice(0, 3);
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}.${frac}`;
  } catch {
    return instant.toISOString().replace('T', ' ').replace('Z', '');
  }
}

module.exports = {
  config,
  getClient,
  getReadClient,
  getWriteClient,
  ping,
  query,
  tableRef,
  flowsRawTableRef,
  flowCol,
  dashboardTableRef,
  dashboardHourTableRef,
  dashboardDayTableRef,
  protocolTableRef,
  serviceTableRef,
  unknownPortTableRef,
  countryTableRef,
  talkerTableRef,
  talkerHourTableRef,
  pairTableRef,
  pairHourTableRef,
  sourcesTableRef,
  flowSourcesTableRef,
  collectorsViewRef,
  asnNamesTableRef,
  ipAsnPrefixesTableRef,
  asnRegistryEnrichedTableRef,
  collectorsTableRef,
  snmpSettingsCurrentRef,
  snmpAgentsCurrentRef,
  snmpAgentsTableRef,
  netInterfacesCurrentRef,
  netInterfacesDictRef,
  directionSettingsTableRef,
  directionSettingsViewRef,
  interfaceRoleRulesTableRef,
  interfaceRoleRulesViewRef,
  interfaceRolesTableRef,
  interfaceRolesViewRef,
  interfaceRolesEffectiveTableRef,
  interfaceRolesEffectiveViewRef,
  locationsViewRef,
  locationsTableRef,
  collectorHealthViewRef,
  collectorHealthSnapshotsTableRef,
  healthCol,
  dnsLogTableRef,
  dnsAnswersTableRef,
  dnsActivity5mTableRef,
  dnsDomains1hTableRef,
  dnsClients1hTableRef,
  dnsServers1hTableRef,
  dnsResolversTableRef,
  dnsResolversViewRef,
  l3PrefixesTableRef,
  l3PrefixesViewRef,
  clientsViewRef,
  clientPortsViewRef,
  flowExclusionsTableRef,
  flowExclusionsViewRef,
  l2VlansTableRef,
  l2VlansViewRef,
  vlanTableRef,
  entitiesTableRef,
  entitiesViewRef,
  portServicesTableRef,
  portServicesViewRef,
  portServicesExpandedViewRef,
  usersTableRef,
  rolesTableRef,
  rolePermissionsTableRef,
  userPermissionsTableRef,
  insertRows,
  executeCommand,
  col,
  colOpt,
  getConfig,
  escapeSqlString,
  parseDataDatetimeSql,
  formatDataDatetimeSql,
  formatDateTime64,
};
