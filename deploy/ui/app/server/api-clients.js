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

// Границы для ручной регистрации кредов из UI (раздел «API интеграция ERP»).
const CLIENT_NAME_MAX = 120;
const CLIENT_ID_MIN = 12;
const CLIENT_ID_MAX = 64;
const CLIENT_SECRET_MIN = 12;
const CLIENT_SECRET_MAX = 512;
const MANUAL_CLIENT_ID_RE = /^[A-Za-z0-9._:-]+$/;

// Чистая валидация ручной пары client_id+секрет: проверяется без БД, поэтому
// покрыта юнит-тестами. Секрет сравнивается побайтово (bcrypt), поэтому не
// обрезается — ERP должен присылать ровно ту строку, что ввели в UI.
function validateManualRegistration({ name, clientId, clientSecret } = {}) {
  const clientName = String(name ?? '').trim();
  const id = String(clientId ?? '').trim();
  const secret = String(clientSecret ?? '');
  if (!clientName) return { error: 'Укажите название API-клиента' };
  if (clientName.length > CLIENT_NAME_MAX) {
    return { error: `Название длиннее ${CLIENT_NAME_MAX} символов` };
  }
  if (!id) return { error: 'Укажите client_id' };
  if (id.length < CLIENT_ID_MIN || id.length > CLIENT_ID_MAX) {
    return { error: `client_id должен быть от ${CLIENT_ID_MIN} до ${CLIENT_ID_MAX} символов` };
  }
  if (!MANUAL_CLIENT_ID_RE.test(id)) {
    return { error: 'client_id: допустимы латинские буквы, цифры и символы . _ : -' };
  }
  if (secret.length < CLIENT_SECRET_MIN || secret.length > CLIENT_SECRET_MAX) {
    return { error: `Секрет должен быть от ${CLIENT_SECRET_MIN} до ${CLIENT_SECRET_MAX} символов` };
  }
  return { value: { clientName, clientId: id, clientSecret: secret } };
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
async function getClientById(clientId) {
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
  return rows[0] ? mapRow(rows[0]) : null;
}

async function getActiveClientById(clientId) {
  const client = await getClientById(clientId);
  return client && client.active ? client : null;
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

// Идемпотентно: повторное отключение и отключение отсутствующего — не ошибка
// только отсутствие записи (404), чтобы кнопка-тумблер в UI не падала.
async function deactivateApiClient(clientId) {
  const existing = await getClientById(clientId);
  if (!existing) {
    const err = new Error('API-клиент не найден');
    err.statusCode = 404;
    throw err;
  }
  if (!existing.active) return { clientId: existing.clientId, active: false };
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

// Включение отключённого подключения с теми же кредами. Побочно это и откат
// пересоздания: старый client_id можно вернуть в строй, если новый не подошёл.
async function activateApiClient(clientId) {
  const existing = await getClientById(clientId);
  if (!existing) {
    const err = new Error('API-клиент не найден');
    err.statusCode = 404;
    throw err;
  }
  if (existing.active) return { clientId: existing.clientId, active: true };
  await insertRows(API_CLIENTS_TABLE, [{
    client_id: existing.clientId,
    client_name: existing.clientName,
    secret_hash: existing.secretHash,
    is_active: 1,
    created_at: existing.createdAt,
    updated_at: clickhouseDateTime(),
  }], { name: 'api-clients/activate' });
  return { clientId: existing.clientId, active: true };
}

// Пересоздание как в CLI: новый client_id + новый секрет под тем же именем.
// Старый client_id отключается, запись остаётся в таблице (история для журнала).
// Отзыв токенов старого client_id делает вызывающий слой (роутер), у него токен-стор.
async function recreateApiClient(clientId) {
  const existing = await getActiveClientById(clientId);
  if (!existing) {
    const err = new Error('API-клиент не найден или уже отключён');
    err.statusCode = 404;
    throw err;
  }
  const newClientId = generateClientId();
  const clientSecret = generateClientSecret();
  const secretHash = await bcrypt.hash(clientSecret, BCRYPT_ROUNDS);
  const now = clickhouseDateTime();
  // Сначала новый клиент, потом деактивация старого: если вторая запись не
  // пройдёт, останутся два активных (ERP продолжит работать) вместо нуля.
  await insertRows(API_CLIENTS_TABLE, [{
    client_id: newClientId,
    client_name: existing.clientName,
    secret_hash: secretHash,
    is_active: 1,
    created_at: now,
    updated_at: now,
  }], { name: 'api-clients/recreate' });
  await insertRows(API_CLIENTS_TABLE, [{
    client_id: existing.clientId,
    client_name: existing.clientName,
    secret_hash: existing.secretHash,
    is_active: 0,
    created_at: existing.createdAt,
    updated_at: now,
  }], { name: 'api-clients/recreate-deactivate' });
  // Секрет показывается один раз: в ClickHouse лежит только bcrypt-хэш.
  return {
    previousClientId: existing.clientId,
    clientId: newClientId,
    clientName: existing.clientName,
    clientSecret,
  };
}

// Ручная регистрация своих кредов из UI: админ сам задаёт client_id и секрет.
// Секрет не возвращаем — он и так у админа, в базе только хэш.
async function registerApiClient({ name, clientId, clientSecret } = {}) {
  const check = validateManualRegistration({ name, clientId, clientSecret });
  if (check.error) {
    const err = new Error(check.error);
    err.statusCode = 400;
    throw err;
  }
  const { clientName, clientId: id, clientSecret: secret } = check.value;
  // client_id — ключ ReplacingMergeTree: совпадение с любой версией (даже
  // отключённой) породило бы новую версию чужой записи, поэтому занятость
  // проверяем по всем строкам, а не только по активным.
  const { rows } = await query(
    `SELECT count() AS count FROM ${apiClientsTableRef()} WHERE client_id = {clientId:String}`,
    { clientId: id },
    { name: 'api-clients/register-exists' },
  );
  if (Number(rows[0]?.count) > 0) {
    const err = new Error('Такой client_id уже занят');
    err.statusCode = 409;
    throw err;
  }
  const secretHash = await bcrypt.hash(secret, BCRYPT_ROUNDS);
  const now = clickhouseDateTime();
  await insertRows(API_CLIENTS_TABLE, [{
    client_id: id,
    client_name: clientName,
    secret_hash: secretHash,
    is_active: 1,
    created_at: now,
    updated_at: now,
  }], { name: 'api-clients/register' });
  return { clientId: id, clientName, active: true, manual: true };
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
  validateManualRegistration,
  ensureApiClientsTable,
  getClientById,
  getActiveClientById,
  verifyApiClient,
  createApiClient,
  recreateApiClient,
  registerApiClient,
  activateApiClient,
  deactivateApiClient,
  listApiClients,
};
