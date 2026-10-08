'use strict';

const { executeCommand, query, config } = require('./clickhouse');

const DB = () => config.database || 'default';
const TABLE = 'traffic_client_anomaly_1m';
const NET_MINUTE_TABLE = 'traffic_client_net_1m';
const NET_HOUR_TABLE = 'traffic_client_net_1h';
const PROTOS = ['all', 'tcp', 'udp'];

function tableRef() {
  return `${DB()}.${TABLE}`;
}

function netMinuteTableRef() {
  return `${DB()}.${NET_MINUTE_TABLE}`;
}

function netHourTableRef() {
  return `${DB()}.${NET_HOUR_TABLE}`;
}

// Минуты сетей /24 клиентов на портах нужны только для медианы последнего часа
// и разбора свежих инцидентов, поэтому живут двое суток. Норму за две недели
// держат часовые сводки: на PiterIX это ~27 тыс. строк в час против ~8 тыс.
// в минуту, и запрос нормы не упирается в память.
const NET_MINUTE_CREATE_SQL = `
CREATE TABLE IF NOT EXISTS ${DB()}.${NET_MINUTE_TABLE}
(
  minute DateTime('UTC'),
  client_id String,
  net String,
  bytes UInt64 DEFAULT 0,
  packets UInt64 DEFAULT 0,
  udp_bytes UInt64 DEFAULT 0,
  tcp_bytes UInt64 DEFAULT 0
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, client_id, net)
TTL minute + toIntervalDay(2)
SETTINGS ttl_only_drop_parts = 1
`;

const NET_HOUR_CREATE_SQL = `
CREATE TABLE IF NOT EXISTS ${DB()}.${NET_HOUR_TABLE}
(
  hour DateTime('UTC'),
  client_id String,
  net String,
  minutes UInt16 DEFAULT 0,
  bps_max Float64 DEFAULT 0,
  bps_p95 Float64 DEFAULT 0,
  pps_max Float64 DEFAULT 0,
  pps_p95 Float64 DEFAULT 0
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (client_id, net, hour)
TTL hour + toIntervalDay(16)
`;

const CREATE_SQL = `
CREATE TABLE IF NOT EXISTS ${DB()}.${TABLE}
(
  minute DateTime('UTC'),
  scope LowCardinality(String),
  scope_id String,
  proto LowCardinality(String),
  bytes UInt64 DEFAULT 0,
  packets UInt64 DEFAULT 0,
  bps Float64 DEFAULT 0,
  pps Float64 DEFAULT 0,
  growth_bps Nullable(Float64),
  growth_pps Nullable(Float64),
  avg_packet_bytes Float64 DEFAULT 0,
  cv_percent Nullable(Float64),
  syn_attempts UInt64 DEFAULT 0,
  syn_answered UInt64 DEFAULT 0,
  syn_in_flows UInt64 DEFAULT 0,
  syn_half_open UInt64 DEFAULT 0,
  syn_half_open_reply UInt64 DEFAULT 0,
  answer_pct Nullable(Float64),
  half_open_pct Nullable(Float64),
  half_open_reply_pct Nullable(Float64),
  port_entropy Nullable(Float64),
  port_entropy_out Nullable(Float64),
  ports_per_ip Nullable(Float64),
  ports_per_ip_out Nullable(Float64),
  amp_bytes UInt64 DEFAULT 0,
  amp_packets UInt64 DEFAULT 0,
  amp_srcs UInt32 DEFAULT 0,
  amp_top_share Float64 DEFAULT 0,
  growth_amp Nullable(Float64),
  foreign_bytes UInt64 DEFAULT 0,
  foreign_srcs UInt32 DEFAULT 0,
  top_countries String DEFAULT '',
  growth_foreign_bps Nullable(Float64),
  growth_foreign_share Nullable(Float64),
  syn_only_bytes UInt64 DEFAULT 0,
  syn_only_packets UInt64 DEFAULT 0,
  syn_only_rows UInt64 DEFAULT 0,
  syn_only_targets UInt64 DEFAULT 0,
  growth_syn Nullable(Float64),
  ack_only_bytes UInt64 DEFAULT 0,
  ack_only_packets UInt64 DEFAULT 0,
  ack_only_rows UInt64 DEFAULT 0,
  rst_bytes UInt64 DEFAULT 0,
  rst_packets UInt64 DEFAULT 0,
  rst_rows UInt64 DEFAULT 0,
  established_bytes UInt64 DEFAULT 0,
  established_packets UInt64 DEFAULT 0,
  established_rows UInt64 DEFAULT 0,
  data_bytes UInt64 DEFAULT 0,
  data_packets UInt64 DEFAULT 0,
  data_rows UInt64 DEFAULT 0,
  sampling_rate UInt64 DEFAULT 1,
  net_top String DEFAULT '',
  net_bps Float64 DEFAULT 0,
  net_pps Float64 DEFAULT 0,
  net_usual_bps Float64 DEFAULT 0,
  net_usual_pps Float64 DEFAULT 0,
  net_growth_bps Nullable(Float64),
  net_growth_pps Nullable(Float64),
  net_udp_bps Float64 DEFAULT 0,
  net_tcp_bps Float64 DEFAULT 0,
  net_list String DEFAULT ''
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (scope, scope_id, proto, minute)
TTL minute + toIntervalDay(16)
`;

const ADD_COLUMNS = [
  { name: 'port_entropy', type: 'Nullable(Float64)' },
  { name: 'port_entropy_out', type: 'Nullable(Float64)' },
  { name: 'ports_per_ip', type: 'Nullable(Float64)' },
  { name: 'ports_per_ip_out', type: 'Nullable(Float64)' },
  { name: 'amp_bytes', type: 'UInt64 DEFAULT 0' },
  { name: 'amp_packets', type: 'UInt64 DEFAULT 0' },
  { name: 'amp_srcs', type: 'UInt32 DEFAULT 0' },
  { name: 'amp_top_share', type: 'Float64 DEFAULT 0' },
  { name: 'growth_amp', type: 'Nullable(Float64)' },
  { name: 'foreign_bytes', type: 'UInt64 DEFAULT 0' },
  { name: 'foreign_srcs', type: 'UInt32 DEFAULT 0' },
  { name: 'top_countries', type: 'String DEFAULT \'\'' },
  { name: 'growth_foreign_bps', type: 'Nullable(Float64)' },
  { name: 'growth_foreign_share', type: 'Nullable(Float64)' },
  { name: 'syn_only_bytes', type: 'UInt64 DEFAULT 0' },
  { name: 'syn_only_packets', type: 'UInt64 DEFAULT 0' },
  { name: 'syn_only_rows', type: 'UInt64 DEFAULT 0' },
  { name: 'syn_only_targets', type: 'UInt64 DEFAULT 0' },
  { name: 'growth_syn', type: 'Nullable(Float64)' },
  { name: 'ack_only_bytes', type: 'UInt64 DEFAULT 0' },
  { name: 'ack_only_packets', type: 'UInt64 DEFAULT 0' },
  { name: 'ack_only_rows', type: 'UInt64 DEFAULT 0' },
  { name: 'rst_bytes', type: 'UInt64 DEFAULT 0' },
  { name: 'rst_packets', type: 'UInt64 DEFAULT 0' },
  { name: 'rst_rows', type: 'UInt64 DEFAULT 0' },
  { name: 'established_bytes', type: 'UInt64 DEFAULT 0' },
  { name: 'established_packets', type: 'UInt64 DEFAULT 0' },
  { name: 'established_rows', type: 'UInt64 DEFAULT 0' },
  { name: 'data_bytes', type: 'UInt64 DEFAULT 0' },
  { name: 'data_packets', type: 'UInt64 DEFAULT 0' },
  { name: 'data_rows', type: 'UInt64 DEFAULT 0' },
  { name: 'sampling_rate', type: 'UInt64 DEFAULT 1' },
  { name: 'net_top', type: 'String DEFAULT \'\'' },
  { name: 'net_bps', type: 'Float64 DEFAULT 0' },
  { name: 'net_pps', type: 'Float64 DEFAULT 0' },
  { name: 'net_usual_bps', type: 'Float64 DEFAULT 0' },
  { name: 'net_usual_pps', type: 'Float64 DEFAULT 0' },
  { name: 'net_growth_bps', type: 'Nullable(Float64)' },
  { name: 'net_growth_pps', type: 'Nullable(Float64)' },
  { name: 'net_udp_bps', type: 'Float64 DEFAULT 0' },
  { name: 'net_tcp_bps', type: 'Float64 DEFAULT 0' },
  { name: 'net_list', type: 'String DEFAULT \'\'' },
];

let ensurePromise = null;

async function ensureDetectionTables() {
  if (!ensurePromise) {
    ensurePromise = (async () => {
      const { rows: tables } = await query(`
        SELECT name
        FROM system.tables
        WHERE database = {db:String} AND name IN {names:Array(String)}
      `, { db: DB(), names: [NET_MINUTE_TABLE, NET_HOUR_TABLE] }, { name: 'detection/net-tables' });
      const present = new Set(tables.map((r) => String(r.name)));
      if (!present.has(NET_MINUTE_TABLE)) {
        await executeCommand(NET_MINUTE_CREATE_SQL, {}, { name: 'detection/create-net-minute' });
      }
      if (!present.has(NET_HOUR_TABLE)) {
        await executeCommand(NET_HOUR_CREATE_SQL, {}, { name: 'detection/create-net-hour' });
      }
      const { rows: cols } = await query(`
        SELECT name
        FROM system.columns
        WHERE database = {db:String} AND table = {table:String}
      `, { db: DB(), table: TABLE }, { name: 'detection/anomaly-cols' });
      const names = new Set(cols.map((r) => String(r.name)));
      if (!names.size) {
        await executeCommand(CREATE_SQL, {}, { name: 'detection/create-anomaly' });
        return;
      }
      const hasProtoKey = names.has('proto');
      const hasCore = names.has('scope')
        && names.has('growth_bps')
        && names.has('answer_pct')
        && names.has('syn_half_open_reply');
      if (!hasProtoKey || !hasCore) {
        await executeCommand(`DROP TABLE IF EXISTS ${DB()}.${TABLE}`, {}, { name: 'detection/drop-anomaly' });
        await executeCommand(CREATE_SQL, {}, { name: 'detection/create-anomaly' });
        return;
      }
      for (const column of ADD_COLUMNS) {
        if (names.has(column.name)) continue;
        await executeCommand(
          `ALTER TABLE ${DB()}.${TABLE} ADD COLUMN IF NOT EXISTS ${column.name} ${column.type}`,
          {},
          { name: `detection/add-${column.name.replace(/_/g, '-')}` },
        );
      }
    })().catch((err) => {
      ensurePromise = null;
      throw err;
    });
  }
  return ensurePromise;
}

module.exports = {
  TABLE,
  tableRef,
  NET_MINUTE_TABLE,
  NET_HOUR_TABLE,
  netMinuteTableRef,
  netHourTableRef,
  ensureDetectionTables,
  PROTOS,
};
