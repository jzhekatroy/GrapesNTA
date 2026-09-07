'use strict';

const { executeCommand, query, config } = require('./clickhouse');

const DB = () => config.database || 'default';
const TABLE = 'traffic_client_anomaly_1m';
const PROTOS = ['all', 'tcp', 'udp'];

function tableRef() {
  return `${DB()}.${TABLE}`;
}

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
  growth_amp Nullable(Float64),
  foreign_bytes UInt64 DEFAULT 0,
  foreign_srcs UInt32 DEFAULT 0,
  top_countries String DEFAULT '',
  growth_foreign_bps Nullable(Float64),
  growth_foreign_share Nullable(Float64)
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
  { name: 'growth_amp', type: 'Nullable(Float64)' },
  { name: 'foreign_bytes', type: 'UInt64 DEFAULT 0' },
  { name: 'foreign_srcs', type: 'UInt32 DEFAULT 0' },
  { name: 'top_countries', type: 'String DEFAULT \'\'' },
  { name: 'growth_foreign_bps', type: 'Nullable(Float64)' },
  { name: 'growth_foreign_share', type: 'Nullable(Float64)' },
];

let ensurePromise = null;

async function ensureDetectionTables() {
  if (!ensurePromise) {
    ensurePromise = (async () => {
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
  ensureDetectionTables,
  PROTOS,
};
