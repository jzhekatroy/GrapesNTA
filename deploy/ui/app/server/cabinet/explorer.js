const {
  explorerSchema,
  explorerQuery,
  explorerFlows,
  explorerExportCsv,
} = require('../explorer');

const CABINET_EXPLORER_OPTIONS = { cabinet: true };

function cabinetExplorerOptions(clientId) {
  return { cabinetClientId: String(clientId || '').trim() };
}

function sanitizeCabinetExplorerBody(body = {}) {
  const next = { ...(body || {}) };
  delete next.clientId;
  delete next.client_id;
  delete next.collectorId;
  delete next.collectorFilter;
  delete next.sourceId;
  delete next.source_id;
  return next;
}

function cabinetExplorerSchema() {
  return explorerSchema(CABINET_EXPLORER_OPTIONS);
}

async function cabinetExplorerQuery(clientId, body = {}) {
  return explorerQuery(sanitizeCabinetExplorerBody(body), cabinetExplorerOptions(clientId));
}

async function cabinetExplorerFlows(clientId, body = {}) {
  return explorerFlows(sanitizeCabinetExplorerBody(body), cabinetExplorerOptions(clientId));
}

async function cabinetExplorerExportCsv(clientId, body = {}) {
  return explorerExportCsv(sanitizeCabinetExplorerBody(body), cabinetExplorerOptions(clientId));
}

module.exports = {
  sanitizeCabinetExplorerBody,
  cabinetExplorerSchema,
  cabinetExplorerQuery,
  cabinetExplorerFlows,
  cabinetExplorerExportCsv,
};
