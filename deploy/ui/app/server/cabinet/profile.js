'use strict';

const {
  getUserById,
  updateOwnProfile,
  changeUserPassword,
} = require('../users');
const { fetchLatestClient, clientSource } = require('./client-admin');

function httpError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  throw err;
}

function mapProfileUser(user) {
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName,
    roleId: user.roleId,
    forcePasswordChange: !!user.forcePasswordChange,
    updatedAt: user.updatedAt,
  };
}

function mapProfileCompany(row) {
  if (!row) return null;
  const clientId = String(row.client_id ?? row.clientId ?? '');
  return {
    clientId,
    displayName: String(row.display_name ?? row.displayName ?? clientId),
    bindMode: String(row.bind_mode ?? row.bindMode ?? ''),
    source: clientSource(clientId),
    enabled: Number(row.enabled) === 1,
  };
}

async function getCabinetProfile(user, cabinet) {
  const clientId = String(cabinet?.clientId || user?.clientId || '').trim();
  if (!clientId) httpError('Кабинет недоступен: клиент не привязан к учётной записи', 403);

  const freshUser = await getUserById(user.id);
  if (!freshUser) httpError('Пользователь не найден', 404);

  const clientRow = await fetchLatestClient(clientId);
  if (!clientRow) httpError('Клиент не найден', 404);

  return {
    data: mapProfileUser(freshUser),
    company: mapProfileCompany(clientRow),
  };
}

async function patchCabinetProfile(userId, body = {}) {
  if (body?.username !== undefined) {
    httpError('Логин нельзя изменить', 400);
  }
  const result = await updateOwnProfile(userId, body);
  return { data: mapProfileUser(result.data) };
}

async function changeCabinetProfilePassword(userId, password) {
  const result = await changeUserPassword(userId, password, { clearForce: true });
  return { data: mapProfileUser(result.data) };
}

module.exports = {
  getCabinetProfile,
  patchCabinetProfile,
  changeCabinetProfilePassword,
};
