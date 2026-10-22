'use strict';

const { loadRole } = require('./rbac/permissions');
const { loadDetectionEvents } = require('./detection-telegram');

async function resolveAttackAlertEnabled(user) {
  const roleId = user?.roleId;
  if (!roleId) return false;
  const role = await loadRole(roleId);
  return !!role?.attackAlert;
}

async function loadAttackAlertsPayload(user) {
  const enabled = await resolveAttackAlertEnabled(user);
  if (!enabled) {
    return { enabled: false, attacks: [] };
  }
  const attacks = await loadDetectionEvents({ status: 'active' });
  return { enabled: true, attacks };
}

module.exports = {
  resolveAttackAlertEnabled,
  loadAttackAlertsPayload,
};
