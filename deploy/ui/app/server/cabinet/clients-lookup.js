const { query } = require('../clickhouse');

async function getEnabledClient(clientId) {
  const id = String(clientId ?? '').trim();
  if (!id) return null;
  const { rows } = await query(
    `
      SELECT
        client_id,
        display_name,
        comment,
        bind_mode
      FROM default.net_clients_enabled
      WHERE client_id = {clientId:String}
      LIMIT 1
    `,
    { clientId: id },
    { name: 'cabinet/get-enabled-client' },
  );
  if (!rows[0]) return null;
  return {
    clientId: String(rows[0].client_id),
    displayName: String(rows[0].display_name || rows[0].client_id),
    comment: String(rows[0].comment || ''),
    bindMode: String(rows[0].bind_mode || ''),
  };
}

/**
 * Fill in the readable client name the cabinet header shows. A client session
 * carries only the id, so the name comes from the catalog; if the row is gone
 * the id is better than an empty header.
 */
async function fillClientDisplayName(cabinet) {
  if (!cabinet || cabinet.mode !== 'client' || !cabinet.clientId || cabinet.clientDisplayName) {
    return cabinet;
  }
  const client = await getEnabledClient(cabinet.clientId).catch(() => null);
  return { ...cabinet, clientDisplayName: client ? client.displayName : cabinet.clientId };
}

module.exports = {
  getEnabledClient,
  fillClientDisplayName,
};
