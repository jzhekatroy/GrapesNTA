'use strict';

const { canAccess, canWrite } = require('../rbac/permissions');
const { CLIENTS_RESOURCE } = require('./constants');

const OBSERVATIONS_RESOURCE = 'observations';

async function canStaffMutateClientObservations(user) {
  return (await canWrite(user, CLIENTS_RESOURCE))
    || (await canWrite(user, OBSERVATIONS_RESOURCE));
}

async function canStaffViewClientObservations(user) {
  if (!(await canAccess(user, CLIENTS_RESOURCE))) return false;
  return (await canStaffMutateClientObservations(user))
    || (await canAccess(user, OBSERVATIONS_RESOURCE));
}

module.exports = {
  canStaffMutateClientObservations,
  canStaffViewClientObservations,
};
