'use strict';

const { query, config } = require('./clickhouse');

// Привязку наблюдения к клиенту кабинета пишет UI. Таблицу тоже создаёт UI:
// пока его не выложили, таблицы нет, а значит нет и клиентских наблюдений.
const OBSERVATION_CLIENTS_TABLE = process.env.OBSERVATION_CLIENTS_TABLE || 'app_observation_clients';

async function observationClientsTableExists() {
  const { rows } = await query(`
    SELECT count() AS n
    FROM system.tables
    WHERE database = {db:String} AND name = {table:String}
  `, { db: config.database, table: OBSERVATION_CLIENTS_TABLE }, { name: 'observations/clients-table-exists' });
  return Number(rows[0]?.n) > 0;
}

/** observation_id → client_id для живых привязок. */
async function loadObservationClients() {
  if (!(await observationClientsTableExists())) return new Map();
  const { rows } = await query(`
    SELECT
      observation_id,
      argMax(client_id, updated_at) AS client_id,
      argMax(deleted, updated_at) AS deleted
    FROM ${config.database}.${OBSERVATION_CLIENTS_TABLE}
    GROUP BY observation_id
  `, {}, { name: 'observations/clients' });
  return observationClientsFromRows(rows);
}

function observationClientsFromRows(rows) {
  const out = new Map();
  for (const row of rows || []) {
    const observationId = String(row.observation_id ?? '').trim();
    const clientId = String(row.client_id ?? '').trim();
    if (!observationId || !clientId || Number(row.deleted) === 1) continue;
    out.set(observationId, clientId);
  }
  return out;
}

module.exports = {
  OBSERVATION_CLIENTS_TABLE,
  loadObservationClients,
  observationClientsFromRows,
};
