'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { config, query, insertRows, executeCommand } = require('./clickhouse');

const API_CLIENTS_TABLE = 'app_api_clients';
const BCRYPT_ROUNDS = 12;

function apiClientsTableRef() {
  return `${config.database}.${API_CLIENTS_TABLE}`;
}

function clickhouseDateTime(date = new Date()) {
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

function generateClientId() {
  return `nta-${crypto.randomBytes(12).toString('hex')}`;
}

function generateClientSecret() {
  return crypto.randomBytes(24).toString('hex');
}

async function ensureApiClientsTable() {
  await executeCommand(
    `
      CREATE TABLE IF NOT EXISTS ${apiClientsTableRef()}
      (
        client_id String,
        client_name String,
        secret_hash String,
        is_active UInt8 DEFAULT 1,
        created_at DateTime64(3) DEFAULT now64(3),
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = ReplacingMergeTree(updated_at)
      ORDER BY client_id
    `,
    {},
    { name: 'api-clients/create-table' },
  );
}

function mapRow(row = {}) {
  return {
    clientId: String(row.client_id ?? ''),
    clientName: String(row.client_name ?? ''),
    secretHash: String(row.secret_hash ?? ''),
    active: Number(row.is_active) === 1,
    createdAt: row.created_at ?? null,
    updatedAt: row.updated_at ?? null,
  };
}

// ReplacingMergeTree до схлопывания хранит несколько версий строки, поэтому
// читаем самую свежую по updated_at — тот же приём, что в app_erp_sync_settings.
async function getActiveClientById(clientId) {
  const id = String(clientId ?? '').trim();
  if (!id) return null;
  const { rows } = await query(
    `
      SELECT client_id, client_name, secret_hash, is_active, created_at, updated_at
      FROM ${apiClientsTableRef()}
      WHERE client_id = {clientId:String}
      ORDER BY updated_at DESC
      LIMIT 1
    `,
    { clientId: id },
    { name: 'api-clients/get-by-id' },
  );
  const client = rows[0] ? mapRow(rows[0]) : null;
  if (!client || !client.active) return null;
  return client;
}

async function verifyApiClient(clientId, clientSecret) {
  const client = await getActiveClientById(clientId);
  if (!client?.secretHash) return null;
  const ok = await bcrypt.compare(String(clientSecret ?? ''), client.secretHash);
  return ok ? client : null;
}

async function createApiClient({ name } = {}) {
  const clientName = String(name ?? '').trim();
  if (!clientName) {
    const err = new Error('Укажите название API-клиента');
    err.statusCode = 400;
    throw err;
  }
  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const secretHash = await bcrypt.hash(clientSecret, BCRYPT_ROUNDS);
  const now = clickhouseDateTime();
  await insertRows(API_CLIENTS_TABLE, [{
    client_id: clientId,
    client_name: clientName,
    secret_hash: secretHash,
    is_active: 1,
    created_at: now,
    updated_at: now,
  }], { name: 'api-clients/create' });
  // Секрет показывается один раз: в ClickHouse лежит только bcrypt-хэш.
  return { clientId, clientName, clientSecret };
}

async function deactivateApiClient(clientId) {
  const existing = await getActiveClientById(clientId);
  if (!existing) {
    const err = new Error('API-клиент не найден');
    err.statusCode = 404;
    throw err;
  }
  await insertRows(API_CLIENTS_TABLE, [{
    client_id: existing.clientId,
    client_name: existing.clientName,
    secret_hash: existing.secretHash,
    is_active: 0,
    created_at: existing.createdAt,
    updated_at: clickhouseDateTime(),
  }], { name: 'api-clients/deactivate' });
  return { clientId: existing.clientId, active: false };
}

async function listApiClients() {
  const { rows } = await query(
    `
      SELECT client_id, client_name, is_active, created_at, updated_at
      FROM ${apiClientsTableRef()}
      ORDER BY updated_at DESC
    `,
    {},
    { name: 'api-clients/list' },
  );
  const seen = new Set();
  const clients = [];
  for (const row of rows) {
    const { secretHash, ...client } = mapRow(row);
    if (seen.has(client.clientId)) continue;
    seen.add(client.clientId);
    clients.push(client);
  }
  return clients;
}

module.exports = {
  API_CLIENTS_TABLE,
  apiClientsTableRef,
  generateClientId,
  generateClientSecret,
  ensureApiClientsTable,
  getActiveClientById,
  verifyApiClient,
  createApiClient,
  deactivateApiClient,
  listApiClients,
};
