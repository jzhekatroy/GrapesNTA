'use strict';

const { executeCommand, query, config } = require('./clickhouse');

const DB = () => config.database || 'default';
const TABLE = 'traffic_client_anomaly_1m';

function tableRef() {
  return `${DB()}.${TABLE}`;
}

const CREATE_SQL = `
CREATE TABLE IF NOT EXISTS ${DB()}.${TABLE}
(
  minute DateTime('UTC'),
  scope LowCardinality(String),
  scope_id String,
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
  udp_port_entropy Nullable(Float64),
  udp_port_entropy_out Nullable(Float64),
  udp_ports_per_ip Nullable(Float64),
  udp_ports_per_ip_out Nullable(Float64)
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (scope, scope_id, minute)
TTL minute + toIntervalDay(16)
`;

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
      for (const column of [
        'udp_port_entropy',
        'udp_port_entropy_out',
        'udp_ports_per_ip',
        'udp_ports_per_ip_out',
      ]) {
        if (names.has(column)) continue;
        await executeCommand(
          `ALTER TABLE ${DB()}.${TABLE} ADD COLUMN IF NOT EXISTS ${column} Nullable(Float64)`,
          {},
          { name: `detection/add-${column.replace(/_/g, '-')}` },
        );
      }
      const matches = names.has('scope')
        && names.has('growth_bps')
        && names.has('answer_pct')
        && names.has('syn_half_open_reply');
      if (!matches) {
        await executeCommand(`DROP TABLE IF EXISTS ${DB()}.${TABLE}`, {}, { name: 'detection/drop-anomaly' });
        await executeCommand(CREATE_SQL, {}, { name: 'detection/create-anomaly' });
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
};
