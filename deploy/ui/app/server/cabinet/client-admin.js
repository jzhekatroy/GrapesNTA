const { parseCidr } = require('../l3-prefixes');
const {
  config,
  query,
  insertRows,
  l3PrefixesViewRef,
  netInterfacesCurrentRef,
} = require('../clickhouse');
const { asStringArray } = require('../client-search');

const CLIENTS_TABLE = 'net_clients';
const CLIENT_PREFIXES_TABLE = 'net_client_prefixes';
const CLIENT_PORTS_TABLE = 'net_client_ports';
const BIND_MODES = new Set(['prefixes', 'ports']);

function clickhouseDateTime(date = new Date()) {
  // net_clients.updated_at is DateTime (seconds); fractional part breaks JSONEachRow inserts.
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

function httpError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function mapClientRow(row) {
  // ClickHouse may qualify joined columns as c.client_id instead of client_id.
  const clientId = String(row?.client_id ?? row?.clientId ?? row?.['c.client_id'] ?? '');
  return {
    clientId,
    displayName: String(row.display_name ?? row.displayName ?? row?.['c.display_name'] ?? ''),
    comment: String(row.comment ?? row?.['c.comment'] ?? ''),
    bindMode: String(row.bind_mode ?? row.bindMode ?? row?.['c.bind_mode'] ?? ''),
    enabled: Number(row.enabled ?? row?.['c.enabled']) === 1,
    prefixCount: Number(row.prefix_count ?? row.prefixCount) || 0,
    portCount: Number(row.port_count ?? row.portCount) || 0,
    userCount: Number(row.user_count ?? row.userCount) || 0,
    updatedAt: row.updated_at ?? row.updatedAt ?? row?.['c.updated_at'] ?? null,
    bindingPreview: asStringArray(row.binding_preview ?? row.bindingPreview),
    bindingPrefixes: asStringArray(row.binding_prefixes ?? row.bindingPrefixes),
    bindingSearch: String(row.binding_search ?? row.bindingSearch ?? ''),
  };
}

function mapPrefixRow(row) {
  return {
    prefix: String(row.prefix ?? ''),
    family: Number(row.family) || 0,
    enabled: Number(row.enabled) === 1,
  };
}

function mapPortRow(row) {
  return {
    switchIp: String(row.switch_ip ?? ''),
    ifIndex: Number(row.if_index) || 0,
    comment: String(row.comment ?? ''),
    enabled: Number(row.enabled) === 1,
  };
}

function latestClientsCte() {
  return `
    latest_clients AS (
      SELECT
        client_id,
        display_name,
        comment,
        bind_mode,
        enabled,
        updated_at,
        row_number() OVER (
          PARTITION BY client_id
          ORDER BY updated_at DESC
        ) AS rn
      FROM default.${CLIENTS_TABLE}
    )
  `;
}

function latestPrefixesCte() {
  return `
    latest_prefixes AS (
      SELECT
        client_id,
        prefix,
        family,
        enabled,
        updated_at,
        row_number() OVER (
          PARTITION BY family, prefix
          ORDER BY updated_at DESC
        ) AS rn
      FROM default.${CLIENT_PREFIXES_TABLE}
    )
  `;
}

function latestPortsCte() {
  return `
    latest_ports AS (
      SELECT
        client_id,
        switch_ip,
        if_index,
        comment,
        enabled,
        updated_at,
        row_number() OVER (
          PARTITION BY switch_ip, if_index
          ORDER BY updated_at DESC
        ) AS rn
      FROM default.${CLIENT_PORTS_TABLE}
    )
  `;
}

async function fetchLatestClient(clientId, { useWrite = false } = {}) {
  const id = String(clientId ?? '').trim();
  if (!id) return null;
  const { rows } = await query(
    `
      WITH ${latestClientsCte()}
      SELECT
        client_id,
        display_name,
        comment,
        bind_mode,
        enabled,
        updated_at
      FROM latest_clients
      WHERE rn = 1 AND client_id = {clientId:String}
      LIMIT 1
    `,
    { clientId: id },
    { name: 'cabinet/client-latest', useWrite },
  );
  return rows[0] || null;
}

async function fetchEnabledL3Prefixes(prefixSet) {
  if (!prefixSet.size) return new Map();
  const prefixes = [...prefixSet];
  const { rows } = await query(
    `
      SELECT prefix, family
      FROM ${l3PrefixesViewRef()}
      WHERE prefix IN {prefixes:Array(String)}
    `,
    { prefixes },
    { name: 'cabinet/client-l3-prefixes-check' },
  );
  return new Map(rows.map((r) => [`${Number(r.family)}:${String(r.prefix)}`, true]));
}

async function fetchPrefixOwner(prefix, family, { exceptClientId } = {}) {
  const params = { prefix, family };
  let except = '';
  if (exceptClientId) {
    params.exceptClientId = String(exceptClientId);
    except = 'AND p.client_id != {exceptClientId:String}';
  }
  const { rows } = await query(
    `
      WITH
        ${latestPrefixesCte()},
        ${latestClientsCte()}
      SELECT
        p.client_id,
        c.display_name
      FROM latest_prefixes AS p
      LEFT JOIN latest_clients AS c
        ON c.client_id = p.client_id AND c.rn = 1
      WHERE p.rn = 1
        AND p.enabled = 1
        AND p.prefix = {prefix:String}
        AND p.family = {family:UInt8}
        ${except}
      LIMIT 1
    `,
    params,
    { name: 'cabinet/client-prefix-owner' },
  );
  if (!rows[0]) return null;
  return {
    clientId: String(rows[0].client_id),
    displayName: String(rows[0].display_name || rows[0].client_id),
  };
}

async function fetchPortOwner(switchIp, ifIndex, { exceptClientId } = {}) {
  const params = { switchIp: String(switchIp), ifIndex: Number(ifIndex) || 0 };
  let except = '';
  if (exceptClientId) {
    params.exceptClientId = String(exceptClientId);
    except = 'AND p.client_id != {exceptClientId:String}';
  }
  const { rows } = await query(
    `
      WITH
        ${latestPortsCte()},
        ${latestClientsCte()}
      SELECT
        p.client_id,
        c.display_name
      FROM latest_ports AS p
      LEFT JOIN latest_clients AS c
        ON c.client_id = p.client_id AND c.rn = 1
      WHERE p.rn = 1
        AND p.enabled = 1
        AND p.switch_ip = {switchIp:String}
        AND p.if_index = {ifIndex:UInt32}
        ${except}
      LIMIT 1
    `,
    params,
    { name: 'cabinet/client-port-owner' },
  );
  if (!rows[0]) return null;
  return {
    clientId: String(rows[0].client_id),
    displayName: String(rows[0].display_name || rows[0].client_id),
  };
}

async function countEnabledPrefixes(clientId) {
  const { rows } = await query(
    `
      WITH ${latestPrefixesCte()}
      SELECT count() AS count
      FROM latest_prefixes
      WHERE rn = 1 AND client_id = {clientId:String} AND enabled = 1
    `,
    { clientId: String(clientId) },
    { name: 'cabinet/client-prefix-count' },
  );
  return Number(rows[0]?.count) || 0;
}

async function countEnabledPorts(clientId) {
  const { rows } = await query(
    `
      WITH ${latestPortsCte()}
      SELECT count() AS count
      FROM latest_ports
      WHERE rn = 1 AND client_id = {clientId:String} AND enabled = 1
    `,
    { clientId: String(clientId) },
    { name: 'cabinet/client-port-count' },
  );
  return Number(rows[0]?.count) || 0;
}

async function listClients() {
  const usersTable = `${config.database}.${config.usersTable}`;
  const { rows, elapsedMs } = await query(
    `
      WITH
        ${latestClientsCte()},
        ${latestPrefixesCte()},
        ${latestPortsCte()},
        prefix_counts AS (
          SELECT client_id, count() AS prefix_count
          FROM latest_prefixes
          WHERE rn = 1 AND enabled = 1
          GROUP BY client_id
        ),
        port_counts AS (
          SELECT client_id, count() AS port_count
          FROM latest_ports
          WHERE rn = 1 AND enabled = 1
          GROUP BY client_id
        ),
        prefix_preview AS (
          SELECT
            client_id,
            arraySlice(arraySort(groupArray(prefix)), 1, 3) AS items,
            groupArray(prefix) AS prefixes,
            arrayStringConcat(groupArray(prefix), ' ') AS hay
          FROM latest_prefixes
          WHERE rn = 1 AND enabled = 1
          GROUP BY client_id
        ),
        port_preview AS (
          SELECT
            p.client_id AS client_id,
            arraySlice(arraySort(groupArray(
              concat(
                p.switch_ip,
                ' · ',
                if(ni.if_name != '', ni.if_name, concat('ifIndex ', toString(p.if_index)))
              )
            )), 1, 3) AS items,
            arrayStringConcat(groupArray(
              concat(
                p.switch_ip, ' ',
                toString(p.if_index), ' ',
                p.comment, ' ',
                ifNull(ni.if_name, ''), ' ',
                ifNull(ni.if_alias, ''), ' ',
                ifNull(ni.if_descr, '')
              )
            ), ' ') AS hay
          FROM latest_ports AS p
          LEFT JOIN ${netInterfacesCurrentRef()} AS ni
            ON ni.switch_ip = p.switch_ip AND ni.if_index = p.if_index
          WHERE p.rn = 1 AND p.enabled = 1
          GROUP BY p.client_id
        ),
        user_counts AS (
          SELECT
            client_id,
            count() AS user_count
          FROM (
            SELECT
              client_id,
              is_active,
              row_number() OVER (PARTITION BY id ORDER BY updated_at DESC) AS rn
            FROM ${usersTable}
          )
          WHERE rn = 1 AND client_id != '' AND is_active = 1
          GROUP BY client_id
        )
      SELECT
        c.client_id AS client_id,
        c.display_name AS display_name,
        c.comment AS comment,
        c.bind_mode AS bind_mode,
        c.enabled AS enabled,
        c.updated_at AS updated_at,
        coalesce(pc.prefix_count, 0) AS prefix_count,
        coalesce(pt.port_count, 0) AS port_count,
        coalesce(uc.user_count, 0) AS user_count,
        if(c.bind_mode = 'ports', coalesce(pp.items, []), coalesce(px.items, [])) AS binding_preview,
        coalesce(px.prefixes, []) AS binding_prefixes,
        if(c.bind_mode = 'ports', coalesce(pp.hay, ''), coalesce(px.hay, '')) AS binding_search
      FROM latest_clients AS c
      LEFT JOIN prefix_counts AS pc ON pc.client_id = c.client_id
      LEFT JOIN port_counts AS pt ON pt.client_id = c.client_id
      LEFT JOIN prefix_preview AS px ON px.client_id = c.client_id
      LEFT JOIN port_preview AS pp ON pp.client_id = c.client_id
      LEFT JOIN user_counts AS uc ON uc.client_id = c.client_id
      WHERE c.rn = 1
      ORDER BY c.display_name, c.client_id
    `,
    {},
    { name: 'cabinet/clients-list' },
  );
  return { data: rows.map(mapClientRow), meta: { elapsedMs, rows: rows.length } };
}

async function getClientAdmin(clientId, { useWrite = false } = {}) {
  const row = await fetchLatestClient(clientId, { useWrite });
  if (!row) return null;
  const [prefixCount, portCount, list] = await Promise.all([
    countEnabledPrefixes(clientId),
    countEnabledPorts(clientId),
    listClients(),
  ]);
  const userCount = (list.data.find((c) => c.clientId === String(clientId)) || {}).userCount || 0;
  return mapClientRow({
    ...row,
    prefix_count: prefixCount,
    port_count: portCount,
    user_count: userCount,
  });
}

function normalizeBindMode(value) {
  const mode = String(value ?? '').trim();
  if (!BIND_MODES.has(mode)) {
    throw httpError('bindMode должен быть prefixes или ports');
  }
  return mode;
}

function normalizeClientId(value, { required = true } = {}) {
  const id = String(value ?? '').trim();
  if (!id) {
    if (required) throw httpError('Укажите clientId');
    return '';
  }
  if (!/^client:[a-z0-9][a-z0-9._-]*$/i.test(id)) {
    throw httpError('clientId должен начинаться с client: и содержать только безопасные символы');
  }
  return id;
}

async function createClient(body = {}) {
  const clientId = normalizeClientId(body.clientId ?? body.client_id);
  const displayName = String(body.displayName ?? body.display_name ?? '').trim();
  if (!displayName) throw httpError('Укажите название клиента');
  const bindMode = normalizeBindMode(body.bindMode ?? body.bind_mode);
  const comment = String(body.comment ?? '').trim();

  const existing = await fetchLatestClient(clientId);
  if (existing) throw httpError('Клиент с таким идентификатором уже существует', 409);

  const now = clickhouseDateTime();
  const record = {
    client_id: clientId,
    display_name: displayName,
    comment,
    bind_mode: bindMode,
    enabled: 1,
    updated_at: now,
  };
  const { elapsedMs } = await insertRows(CLIENTS_TABLE, [record], { name: 'cabinet/client-create' });
  const admin = await getClientAdmin(clientId, { useWrite: true });
  return {
    data: admin || mapClientRow({
      client_id: clientId,
      display_name: displayName,
      comment,
      bind_mode: bindMode,
      enabled: 1,
      updated_at: now,
      prefix_count: 0,
      port_count: 0,
      user_count: 0,
    }),
    meta: { elapsedMs },
  };
}

async function updateClient(clientId, body = {}) {
  const existing = await fetchLatestClient(clientId);
  if (!existing) throw httpError('Клиент не найден', 404);

  if (body.clientId !== undefined || body.client_id !== undefined) {
    const nextId = String(body.clientId ?? body.client_id ?? '').trim();
    if (nextId && nextId !== String(existing.client_id)) {
      throw httpError('clientId нельзя изменить после создания');
    }
  }

  const displayName = String(body.displayName ?? body.display_name ?? existing.display_name ?? '').trim();
  if (!displayName) throw httpError('Укажите название клиента');

  let bindMode = String(existing.bind_mode ?? '');
  if (body.bindMode !== undefined || body.bind_mode !== undefined) {
    bindMode = normalizeBindMode(body.bindMode ?? body.bind_mode);
    const prefixCount = await countEnabledPrefixes(clientId);
    const portCount = await countEnabledPorts(clientId);
    if (bindMode === 'prefixes' && portCount > 0) {
      throw httpError('Сначала удалите все порты клиента, чтобы переключить способ привязки на сети');
    }
    if (bindMode === 'ports' && prefixCount > 0) {
      throw httpError('Сначала удалите все сети клиента, чтобы переключить способ привязки на порты');
    }
  }

  let enabled = Number(existing.enabled) === 1 ? 1 : 0;
  if (body.enabled !== undefined) {
    enabled = body.enabled === true || body.enabled === 1 || body.enabled === '1' ? 1 : 0;
  }

  const record = {
    client_id: String(existing.client_id),
    display_name: displayName,
    comment: String(body.comment ?? existing.comment ?? '').trim(),
    bind_mode: bindMode,
    enabled,
    updated_at: clickhouseDateTime(),
  };
  const { elapsedMs } = await insertRows(CLIENTS_TABLE, [record], { name: 'cabinet/client-update' });
  return { data: await getClientAdmin(clientId, { useWrite: true }), meta: { elapsedMs } };
}

async function listClientPrefixes(clientId) {
  const client = await fetchLatestClient(clientId);
  if (!client) throw httpError('Клиент не найден', 404);
  const { rows, elapsedMs } = await query(
    `
      WITH ${latestPrefixesCte()}
      SELECT prefix, family, enabled
      FROM latest_prefixes
      WHERE rn = 1 AND client_id = {clientId:String}
      ORDER BY family, prefix
    `,
    { clientId: String(clientId) },
    { name: 'cabinet/client-prefixes-list' },
  );
  return {
    data: rows.map(mapPrefixRow).filter((r) => r.enabled),
    meta: { elapsedMs, rows: rows.length, clientId: String(clientId) },
  };
}

async function listClientPorts(clientId) {
  const client = await fetchLatestClient(clientId);
  if (!client) throw httpError('Клиент не найден', 404);
  const { rows, elapsedMs } = await query(
    `
      WITH ${latestPortsCte()}
      SELECT switch_ip, if_index, comment, enabled
      FROM latest_ports
      WHERE rn = 1 AND client_id = {clientId:String}
      ORDER BY switch_ip, if_index
    `,
    { clientId: String(clientId) },
    { name: 'cabinet/client-ports-list' },
  );
  return {
    data: rows.map(mapPortRow).filter((r) => r.enabled),
    meta: { elapsedMs, rows: rows.length, clientId: String(clientId) },
  };
}

async function syncClientPrefixes(clientId, body = {}) {
  const client = await fetchLatestClient(clientId);
  if (!client) throw httpError('Клиент не найден', 404);
  if (String(client.bind_mode) !== 'prefixes') {
    throw httpError('У клиента выбран способ привязки по портам');
  }

  const items = Array.isArray(body.items) ? body.items : [];
  const desired = new Map();
  for (const item of items) {
    const parsed = parseCidr(item?.prefix);
    if (!parsed.ok) throw httpError(parsed.error);
    const key = `${parsed.family}:${parsed.prefix}`;
    if (desired.has(key)) continue;
    desired.set(key, { prefix: parsed.prefix, family: parsed.family });
  }

  const enabledL3 = await fetchEnabledL3Prefixes(new Set([...desired.values()].map((v) => v.prefix)));
  for (const item of desired.values()) {
    if (!enabledL3.has(`${item.family}:${item.prefix}`)) {
      throw httpError(`Сеть ${item.prefix} отсутствует в справочнике «Собственные сети»`);
    }
    const owner = await fetchPrefixOwner(item.prefix, item.family, { exceptClientId: clientId });
    if (owner) {
      throw httpError(`Сеть ${item.prefix} закреплена за клиентом ${owner.displayName}`, 409);
    }
  }

  const { rows: currentRows } = await query(
    `
      WITH ${latestPrefixesCte()}
      SELECT prefix, family, enabled
      FROM latest_prefixes
      WHERE rn = 1 AND client_id = {clientId:String}
    `,
    { clientId: String(clientId) },
    { name: 'cabinet/client-prefixes-current' },
  );

  const now = clickhouseDateTime();
  const inserts = [];
  const currentEnabled = new Map();
  for (const row of currentRows) {
    const key = `${Number(row.family)}:${String(row.prefix)}`;
    currentEnabled.set(key, row);
  }

  for (const [key, item] of desired.entries()) {
    if (!currentEnabled.has(key) || Number(currentEnabled.get(key).enabled) !== 1) {
      inserts.push({
        client_id: String(clientId),
        prefix: item.prefix,
        family: item.family,
        enabled: 1,
        updated_at: now,
      });
    }
  }

  for (const [key, row] of currentEnabled.entries()) {
    if (!desired.has(key) && Number(row.enabled) === 1) {
      inserts.push({
        client_id: String(clientId),
        prefix: String(row.prefix),
        family: Number(row.family),
        enabled: 0,
        updated_at: now,
      });
    }
  }

  if (inserts.length) {
    await insertRows(CLIENT_PREFIXES_TABLE, inserts, { name: 'cabinet/client-prefixes-sync' });
  }

  return listClientPrefixes(clientId);
}

async function syncClientPorts(clientId, body = {}) {
  const client = await fetchLatestClient(clientId);
  if (!client) throw httpError('Клиент не найден', 404);
  if (String(client.bind_mode) !== 'ports') {
    throw httpError('У клиента выбран способ привязки по сетям');
  }

  const items = Array.isArray(body.items) ? body.items : [];
  const desired = new Map();
  for (const item of items) {
    const switchIp = String(item?.switchIp ?? item?.switch_ip ?? '').trim();
    const ifIndex = Number(item?.ifIndex ?? item?.if_index);
    if (!switchIp) throw httpError('Укажите switchIp для каждого порта');
    if (!Number.isInteger(ifIndex) || ifIndex <= 0) throw httpError('Укажите корректный ifIndex для каждого порта');
    const key = `${switchIp}:${ifIndex}`;
    if (desired.has(key)) continue;
    desired.set(key, {
      switchIp,
      ifIndex,
      comment: String(item?.comment ?? '').trim(),
    });
  }

  for (const item of desired.values()) {
    const owner = await fetchPortOwner(item.switchIp, item.ifIndex, { exceptClientId: clientId });
    if (owner) {
      throw httpError(
        `Порт ${item.switchIp} ifIndex ${item.ifIndex} закреплён за клиентом ${owner.displayName}`,
        409,
      );
    }
  }

  const { rows: currentRows } = await query(
    `
      WITH ${latestPortsCte()}
      SELECT switch_ip, if_index, comment, enabled
      FROM latest_ports
      WHERE rn = 1 AND client_id = {clientId:String}
    `,
    { clientId: String(clientId) },
    { name: 'cabinet/client-ports-current' },
  );

  const now = clickhouseDateTime();
  const inserts = [];
  const currentEnabled = new Map();
  for (const row of currentRows) {
    const key = `${String(row.switch_ip)}:${Number(row.if_index)}`;
    currentEnabled.set(key, row);
  }

  for (const [key, item] of desired.entries()) {
    const prev = currentEnabled.get(key);
    if (!prev || Number(prev.enabled) !== 1 || String(prev.comment || '') !== item.comment) {
      inserts.push({
        client_id: String(clientId),
        switch_ip: item.switchIp,
        if_index: item.ifIndex,
        comment: item.comment,
        enabled: 1,
        updated_at: now,
      });
    }
  }

  for (const [key, row] of currentEnabled.entries()) {
    if (!desired.has(key) && Number(row.enabled) === 1) {
      inserts.push({
        client_id: String(clientId),
        switch_ip: String(row.switch_ip),
        if_index: Number(row.if_index),
        comment: String(row.comment || ''),
        enabled: 0,
        updated_at: now,
      });
    }
  }

  if (inserts.length) {
    await insertRows(CLIENT_PORTS_TABLE, inserts, { name: 'cabinet/client-ports-sync' });
  }

  return listClientPorts(clientId);
}

async function listPrefixOptions({ q = '', limit = 50 } = {}) {
  const search = String(q ?? '').trim();
  const max = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const params = { limit: max };
  let filter = '';
  if (search) {
    params.q = `%${search}%`;
    filter = 'AND p.prefix ILIKE {q:String}';
  }
  const { rows, elapsedMs } = await query(
    `
      WITH
        ${latestPrefixesCte()},
        ${latestClientsCte()}
      SELECT
        p.prefix AS prefix,
        p.family AS family,
        cp.client_id AS owner_client_id,
        c.display_name AS owner_display_name
      FROM ${l3PrefixesViewRef()} AS p
      LEFT JOIN latest_prefixes AS cp
        ON cp.rn = 1 AND cp.enabled = 1 AND cp.prefix = p.prefix AND cp.family = p.family
      LEFT JOIN latest_clients AS c
        ON c.rn = 1 AND c.client_id = cp.client_id
      WHERE 1 = 1
        ${filter}
      ORDER BY p.prefix
      LIMIT {limit:UInt32}
    `,
    params,
    { name: 'cabinet/client-prefix-options' },
  );
  return {
    data: rows.map((r) => ({
      prefix: String(r.prefix),
      family: Number(r.family) || 0,
      ownerClientId: String(r.owner_client_id || ''),
      ownerDisplayName: String(r.owner_display_name || ''),
      available: !String(r.owner_client_id || ''),
    })),
    meta: { elapsedMs, rows: rows.length },
  };
}

async function listPortOptions({ q = '', limit = 50 } = {}) {
  const search = String(q ?? '').trim();
  const max = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const params = { limit: max };
  let filter = '';
  if (search) {
    params.q = `%${search}%`;
    filter = `AND (
      ni.switch_ip ILIKE {q:String}
      OR ni.if_name ILIKE {q:String}
      OR ni.if_alias ILIKE {q:String}
      OR ni.if_descr ILIKE {q:String}
    )`;
  }
  const { rows, elapsedMs } = await query(
    `
      WITH
        ${latestPortsCte()},
        ${latestClientsCte()}
      SELECT
        ni.switch_ip,
        ni.if_index,
        ni.if_name,
        ni.if_alias,
        ni.if_descr,
        cp.client_id AS owner_client_id,
        c.display_name AS owner_display_name
      FROM ${config.netInterfacesCurrent} AS ni
      LEFT JOIN latest_ports AS cp
        ON cp.rn = 1
        AND cp.enabled = 1
        AND cp.switch_ip = ni.switch_ip
        AND cp.if_index = ni.if_index
      LEFT JOIN latest_clients AS c
        ON c.rn = 1 AND c.client_id = cp.client_id
      WHERE 1 = 1
        ${filter}
      ORDER BY ni.switch_ip, ni.if_index
      LIMIT {limit:UInt32}
    `,
    params,
    { name: 'cabinet/client-port-options' },
  );
  return {
    data: rows.map((r) => ({
      switchIp: String(r.switch_ip),
      ifIndex: Number(r.if_index) || 0,
      ifName: String(r.if_name || ''),
      ifAlias: String(r.if_alias || ''),
      ifDescr: String(r.if_descr || ''),
      ownerClientId: String(r.owner_client_id || ''),
      ownerDisplayName: String(r.owner_display_name || ''),
      available: !String(r.owner_client_id || ''),
    })),
    meta: { elapsedMs, rows: rows.length },
  };
}

module.exports = {
  listClients,
  getClientAdmin,
  createClient,
  updateClient,
  listClientPrefixes,
  listClientPorts,
  syncClientPrefixes,
  syncClientPorts,
  listPrefixOptions,
  listPortOptions,
  fetchPrefixOwner,
  fetchPortOwner,
  mapClientRow,
  normalizeBindMode,
  normalizeClientId,
};
