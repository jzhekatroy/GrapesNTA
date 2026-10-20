'use strict';

const { query, config, insertRows, executeCommand } = require('./clickhouse');

// Привязку наблюдения к клиенту кабинета пишет UI. Таблицу тоже создаёт UI:
// пока его не выложили, таблицы нет, а значит нет и клиентских наблюдений.
const OBSERVATION_CLIENTS_TABLE = process.env.OBSERVATION_CLIENTS_TABLE || 'app_observation_clients';

function tableRef() {
  return `${config.database}.${OBSERVATION_CLIENTS_TABLE}`;
}

function clickhouseDateTime(date = new Date()) {
  return date.toISOString().replace('T', ' ').replace('Z', '');
}

async function ensureObservationClientsTable() {
  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${tableRef()}
      (
        observation_id String,
        client_id String,
        deleted UInt8 DEFAULT 0,
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = MergeTree
      ORDER BY observation_id
    `,
    {},
    { name: 'observations/create-clients-table' },
  );
}

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
    FROM ${tableRef()}
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

/** Inverse map: client_id → observation_id[] */
async function loadObservationIdsByClient() {
  const clients = await loadObservationClients();
  const byClient = new Map();
  for (const [observationId, clientId] of clients) {
    if (!byClient.has(clientId)) byClient.set(clientId, []);
    byClient.get(clientId).push(observationId);
  }
  return byClient;
}

async function upsertObservationClient(observationId, clientId) {
  const observation_id = String(observationId || '').trim();
  const client_id = String(clientId || '').trim();
  if (!observation_id || !client_id) {
    const err = new Error('observation_id и client_id обязательны');
    err.statusCode = 400;
    throw err;
  }
  await ensureObservationClientsTable();
  await insertRows(OBSERVATION_CLIENTS_TABLE, [{
    observation_id,
    client_id,
    deleted: 0,
    updated_at: clickhouseDateTime(),
  }], { name: 'observations/client-link' });
}

async function softDeleteObservationClient(observationId) {
  const observation_id = String(observationId || '').trim();
  if (!observation_id) return;
  const clients = await loadObservationClients();
  const client_id = clients.get(observation_id) || '';
  if (!client_id) return;
  await ensureObservationClientsTable();
  await insertRows(OBSERVATION_CLIENTS_TABLE, [{
    observation_id,
    client_id,
    deleted: 1,
    updated_at: clickhouseDateTime(),
  }], { name: 'observations/client-unlink' });
}

module.exports = {
  OBSERVATION_CLIENTS_TABLE,
  ensureObservationClientsTable,
  observationClientsTableExists,
  loadObservationClients,
  loadObservationIdsByClient,
  observationClientsFromRows,
  upsertObservationClient,
  softDeleteObservationClient,
};
