const {
  explorerSchema,
  explorerQuery,
  explorerFlows,
  explorerExportCsv,
} = require('../explorer');

const CABINET_EXPLORER_OPTIONS = { cabinet: true };

function cabinetExplorerOptions(clientId, runtime = {}) {
  return {
    cabinetClientId: String(clientId || '').trim(),
    ...(runtime.ix ? { ix: true } : {}),
  };
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

function cabinetExplorerSchema(runtime = {}) {
  return explorerSchema({ ...CABINET_EXPLORER_OPTIONS, ...(runtime.ix ? { ix: true } : {}) });
}

async function cabinetExplorerQuery(clientId, body = {}, runtime = {}) {
  return explorerQuery(sanitizeCabinetExplorerBody(body), cabinetExplorerOptions(clientId, runtime));
}

async function cabinetExplorerFlows(clientId, body = {}, runtime = {}) {
  return explorerFlows(sanitizeCabinetExplorerBody(body), cabinetExplorerOptions(clientId, runtime));
}

async function cabinetExplorerExportCsv(clientId, body = {}, runtime = {}) {
  return explorerExportCsv(sanitizeCabinetExplorerBody(body), cabinetExplorerOptions(clientId, runtime));
}

module.exports = {
  sanitizeCabinetExplorerBody,
  cabinetExplorerSchema,
  cabinetExplorerQuery,
  cabinetExplorerFlows,
  cabinetExplorerExportCsv,
};
