'use strict';

/**
 * Пересчёт net_interface_roles_effective после смены портов клиента.
 * Коллектор читает этот снимок, а не живой JOIN с биллингом.
 */
async function refreshEffectiveRolesAfterClientPorts() {
  const { materializeEffectiveRoles } = require('./net-interface-roles');
  await materializeEffectiveRoles();
}

module.exports = {
  refreshEffectiveRolesAfterClientPorts,
};
