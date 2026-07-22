'use strict';

const { config, query } = require('./clickhouse');
const { lookupAsnDisplayNames } = require('./explorer');

const BMP_PEERS_TABLE = 'bmp_peers';
const BMP_EVENTS_TABLE = config.bmpRouteEventsTable || 'bmp_route_events';
const BGP_ROUTES_TABLE = 'bgp_prefix_origin_current';

const RANGE_INTERVALS = {
  '15m': 'INTERVAL 15 MINUTE',
  '1h': 'INTERVAL 1 HOUR',
  '6h': 'INTERVAL 6 HOUR',
  '24h': 'INTERVAL 24 HOUR',
};

const STALE_SEC = Math.max(60, Number(process.env.BMP_STALE_SEC) || 900);
const MAX_EVENTS = Math.min(Math.max(Number(process.env.BMP_MAX_EVENTS) || 200, 20), 500);
const MAX_ROUTES = Math.min(Math.max(Number(process.env.BMP_MAX_ROUTES) || 100, 20), 500);
const MAX_FLAP = Math.min(Math.max(Number(process.env.BMP_MAX_FLAP) || 50, 10), 200);
const FLAP_MIN_EVENTS = Math.max(4, Number(process.env.BMP_FLAP_MIN_EVENTS) || 6);

const SQL_IPV4 = (col) => `toString(toIPv4(reinterpretAsUInt32(reverse(substring(${col}, 1, 4)))))`;
const SQL_IPV6 = (col) => `toString(toIPv6(${col}))`;
/**
 * BMP peer/router/next-hop FixedString(16) is usually IPv4-mapped IPv6 (::ffff:a.b.c.d).
 * Strip the mapped prefix for display; leave real IPv6 as-is.
 */
const SQL_IP_FS16 = (col) => `multiIf(
  startsWith(${SQL_IPV6(col)}, '::ffff:'),
  replaceOne(${SQL_IPV6(col)}, '::ffff:', ''),
  ${SQL_IPV6(col)} = '::',
  '0.0.0.0',
  ${SQL_IPV6(col)}
)`;
const SQL_IP_V4_OR_V6 = (col, isV6Expr) => `multiIf(
  ${isV6Expr} = 1,
  ${SQL_IPV6(col)},
  ${SQL_IP_FS16(col)}
)`;
const SQL_PREFIX = (col, lenCol, familyExpr) => `multiIf(
  ${familyExpr} = 6,
  concat(${SQL_IPV6(col)}, '/', toString(${lenCol})),
  concat(${SQL_IPV4(col)}, '/', toString(${lenCol}))
)`;

function tableRef(name) {
  return `${config.database}.${name}`;
}

function parseRange(range = '1h') {
  const key = String(range || '1h').trim();
  const interval = RANGE_INTERVALS[key];
  if (!interval) {
    const err = new Error(`Недопустимый range: ${key}`);
    err.statusCode = 400;
    throw err;
  }
  return { key, interval, staleSec: STALE_SEC };
}

function parseLimit(raw, fallback, max) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.floor(n), max);
}

function parseOffset(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function parseUInt(raw) {
  if (raw == null || raw === '') return null;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.floor(n);
}

function asnLabel(asn, nameMap) {
  const n = Number(asn) || 0;
  if (!n) return '—';
  const name = nameMap?.get(n);
  return name ? `${name} (AS${n})` : `AS${n}`;
}

async function enrichAsnFields(rows, fields = ['peer_asn', 'origin_asn']) {
  const asns = new Set();
  for (const row of rows) {
    for (const f of fields) {
      const v = Number(row[f]);
      if (v > 0) asns.add(v);
    }
  }
  const nameMap = await lookupAsnDisplayNames([...asns]);
  return rows.map((row) => {
    const out = { ...row };
    for (const f of fields) {
      const v = Number(row[f]);
      if (v > 0) out[`${f}_label`] = asnLabel(v, nameMap);
    }
    return out;
  });
}

async function getBmpSummary() {
  const { rows } = await query(`
    SELECT
      (SELECT uniqExact(router_addr) FROM ${tableRef(BMP_EVENTS_TABLE)} WHERE ts >= now() - INTERVAL 15 MINUTE) AS routers_active_15m,
      (SELECT countIf(event_type = 'announce') FROM ${tableRef(BMP_EVENTS_TABLE)} WHERE ts >= now() - INTERVAL 1 HOUR) AS announces_1h,
      (SELECT countIf(event_type = 'withdraw') FROM ${tableRef(BMP_EVENTS_TABLE)} WHERE ts >= now() - INTERVAL 1 HOUR) AS withdraws_1h,
      (SELECT countIf(event_type = 'announce') FROM ${tableRef(BMP_EVENTS_TABLE)} WHERE ts >= now() - INTERVAL 15 MINUTE) AS announces_15m,
      (SELECT countIf(event_type = 'withdraw') FROM ${tableRef(BMP_EVENTS_TABLE)} WHERE ts >= now() - INTERVAL 15 MINUTE) AS withdraws_15m,
      (SELECT toString(max(ts)) FROM ${tableRef(BMP_EVENTS_TABLE)}) AS last_route_event_at,
      (SELECT toString(max(ts)) FROM ${tableRef(BMP_PEERS_TABLE)}) AS last_peer_event_at,
      (SELECT count() FROM ${tableRef(BGP_ROUTES_TABLE)}) AS routes_current,
      (SELECT toString(max(snapshot_ts)) FROM ${tableRef(BGP_ROUTES_TABLE)}) AS routes_snapshot_at
  `, {}, { name: 'bmp/summary' });

  const peerStats = await query(`
    WITH latest AS (
      SELECT
        *,
        row_number() OVER (PARTITION BY router_addr, peer_addr ORDER BY ts DESC) AS rn
      FROM ${tableRef(BMP_PEERS_TABLE)}
    )
    SELECT
      countIf(state = 'up') AS peers_up,
      countIf(state = 'down') AS peers_down
    FROM latest
    WHERE rn = 1
  `, {}, { name: 'bmp/summary-peers' });

  const row = rows[0] || {};
  const peers = peerStats.rows[0] || {};
  const lastRoute = row.last_route_event_at ? Date.parse(String(row.last_route_event_at).replace(' ', 'T') + 'Z') : null;
  const lastPeer = row.last_peer_event_at ? Date.parse(String(row.last_peer_event_at).replace(' ', 'T') + 'Z') : null;
  const now = Date.now();
  const routeAgeSec = lastRoute ? Math.floor((now - lastRoute) / 1000) : null;
  const peerAgeSec = lastPeer ? Math.floor((now - lastPeer) / 1000) : null;

  return {
    routersActive15m: Number(row.routers_active_15m) || 0,
    peersUp: Number(peers.peers_up) || 0,
    peersDown: Number(peers.peers_down) || 0,
    announces1h: Number(row.announces_1h) || 0,
    withdraws1h: Number(row.withdraws_1h) || 0,
    announces15m: Number(row.announces_15m) || 0,
    withdraws15m: Number(row.withdraws_15m) || 0,
    eventsPerMin15m: Math.round(((Number(row.announces_15m) || 0) + (Number(row.withdraws_15m) || 0)) / 15),
    routesCurrent: Number(row.routes_current) || 0,
    routesSnapshotAt: row.routes_snapshot_at || null,
    lastRouteEventAt: row.last_route_event_at || null,
    lastPeerEventAt: row.last_peer_event_at || null,
    routeEventAgeSec: routeAgeSec,
    peerEventAgeSec: peerAgeSec,
    staleAfterSec: STALE_SEC,
    healthy: routeAgeSec != null && routeAgeSec <= STALE_SEC,
  };
}

async function getBmpPeers(filters = {}) {
  const router = filters.router ? String(filters.router).trim() : '';
  const state = filters.state ? String(filters.state).trim().toLowerCase() : '';
  const peerAsn = parseUInt(filters.peer_asn);

  const where = ['rn = 1'];
  const params = {};
  if (router) {
    where.push(`(${SQL_IPV4('router_addr')} = {router:String} OR ${SQL_IPV6('router_addr')} = {router:String})`);
    params.router = router;
  }
  if (state === 'up' || state === 'down') {
    where.push('state = {state:String}');
    params.state = state;
  }
  if (peerAsn != null) {
    where.push('peer_asn = {peerAsn:UInt32}');
    params.peerAsn = peerAsn;
  }

  const { rows } = await query(`
    WITH latest AS (
      SELECT
        *,
        row_number() OVER (PARTITION BY router_addr, peer_addr ORDER BY ts DESC) AS rn
      FROM ${tableRef(BMP_PEERS_TABLE)}
    )
    SELECT
      toString(ts) AS ts,
      ${SQL_IP_V4_OR_V6('router_addr', 'is_ipv6')} AS router_addr,
      ${SQL_IP_V4_OR_V6('peer_addr', 'is_ipv6')} AS peer_addr,
      peer_asn,
      peer_type,
      is_ipv6,
      state,
      reason,
      local_asn,
      ${SQL_IP_V4_OR_V6('local_addr', 'is_ipv6')} AS local_addr,
      hold_time,
      negotiated_hold_time,
      bgp_id
    FROM latest
    WHERE ${where.join(' AND ')}
    ORDER BY state ASC, ts DESC
    LIMIT 500
  `, params, { name: 'bmp/peers' });

  const enriched = await enrichAsnFields(rows, ['peer_asn']);
  return { peers: enriched, staleAfterSec: STALE_SEC };
}

async function getBmpRouters() {
  const { rows } = await query(`
    WITH peer_latest AS (
      SELECT
        router_addr,
        peer_addr,
        state,
        ts,
        row_number() OVER (PARTITION BY router_addr, peer_addr ORDER BY ts DESC) AS rn
      FROM ${tableRef(BMP_PEERS_TABLE)}
    ),
    peer_agg AS (
      SELECT
        router_addr,
        countIf(state = 'up') AS peers_up,
        countIf(state = 'down') AS peers_down,
        max(ts) AS last_peer_ts
      FROM peer_latest
      WHERE rn = 1
      GROUP BY router_addr
    ),
    route_agg AS (
      SELECT
        router_addr,
        max(ts) AS last_route_ts,
        countIf(ts >= now() - INTERVAL 1 HOUR) AS events_1h
      FROM ${tableRef(BMP_EVENTS_TABLE)}
      GROUP BY router_addr
    )
    SELECT
      ${SQL_IP_FS16('coalesce(peer_agg.router_addr, route_agg.router_addr)')} AS router_addr,
      coalesce(peer_agg.peers_up, 0) AS peers_up,
      coalesce(peer_agg.peers_down, 0) AS peers_down,
      toString(peer_agg.last_peer_ts) AS last_peer_event_at,
      toString(route_agg.last_route_ts) AS last_route_event_at,
      coalesce(route_agg.events_1h, 0) AS events_1h
    FROM peer_agg
    FULL OUTER JOIN route_agg USING (router_addr)
    ORDER BY last_route_event_at DESC NULLS LAST
  `, {}, { name: 'bmp/routers' });

  const now = Date.now();
  const routers = rows.map((r) => {
    const lastRoute = r.last_route_event_at ? Date.parse(String(r.last_route_event_at).replace(' ', 'T') + 'Z') : null;
    const lastPeer = r.last_peer_event_at ? Date.parse(String(r.last_peer_event_at).replace(' ', 'T') + 'Z') : null;
    const routeAgeSec = lastRoute ? Math.floor((now - lastRoute) / 1000) : null;
    const peerAgeSec = lastPeer ? Math.floor((now - lastPeer) / 1000) : null;
    const stale = routeAgeSec == null || routeAgeSec > STALE_SEC;
    return {
      router_addr: r.router_addr,
      peers_up: Number(r.peers_up) || 0,
      peers_down: Number(r.peers_down) || 0,
      last_peer_event_at: r.last_peer_event_at || null,
      last_route_event_at: r.last_route_event_at || null,
      route_event_age_sec: routeAgeSec,
      peer_event_age_sec: peerAgeSec,
      events_1h: Number(r.events_1h) || 0,
      stale,
    };
  });

  return { routers, staleAfterSec: STALE_SEC };
}

function parseAsnFromQuery(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  const m = s.match(/^AS\s*(\d+)$/i) || s.match(/^(\d+)$/);
  if (!m) return null;
  return parseUInt(m[1]);
}

function looksLikePrefixQuery(raw) {
  const s = String(raw || '').trim();
  if (!s) return false;
  if (s.includes('/') || s.includes(':')) return true;
  return /^\d{1,3}(\.\d{1,3}){0,3}\.?$/.test(s);
}

function buildRoutesWhere(filters = {}) {
  const where = [];
  const params = {};
  const q = filters.q != null ? String(filters.q).trim() : '';
  const prefix = filters.prefix ? String(filters.prefix).trim() : '';
  const originAsn = parseUInt(filters.origin_asn);
  const peerAsn = parseUInt(filters.peer_asn);
  const family = parseUInt(filters.family);
  const asnNames = `${config.database}.${config.asnNamesTable || 'asn_names'}`;

  if (q) {
    const asnFromQ = parseAsnFromQuery(q);
    const parts = [];
    if (asnFromQ != null) {
      parts.push('(origin_asn = {qAsn:UInt32} OR peer_asn = {qAsn:UInt32})');
      params.qAsn = asnFromQ;
    } else if (looksLikePrefixQuery(q)) {
      parts.push('prefix LIKE {qPrefix:String}');
      params.qPrefix = `${q}%`;
    } else {
      parts.push(`(
        origin_asn IN (SELECT asn FROM ${asnNames} WHERE positionCaseInsensitiveUTF8(name, {qName:String}) > 0)
        OR peer_asn IN (SELECT asn FROM ${asnNames} WHERE positionCaseInsensitiveUTF8(name, {qName:String}) > 0)
      )`);
      params.qName = q;
    }
    where.push(`(${parts.join(' OR ')})`);
  }

  if (prefix) {
    where.push('prefix LIKE {prefix:String}');
    params.prefix = `${prefix}%`;
  }
  if (originAsn != null) {
    where.push('origin_asn = {originAsn:UInt32}');
    params.originAsn = originAsn;
  }
  if (peerAsn != null) {
    where.push('peer_asn = {peerAsn:UInt32}');
    params.peerAsn = peerAsn;
  }
  if (family === 4 || family === 6) {
    where.push('family = {family:UInt8}');
    params.family = family;
  }
  return { where, params };
}

async function getBmpRoutes(filters = {}) {
  const limit = parseLimit(filters.limit, 50, MAX_ROUTES);
  const offset = parseOffset(filters.offset);
  const { where, params } = buildRoutesWhere(filters);
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const [{ rows }, countRes] = await Promise.all([
    query(`
      SELECT
        prefix,
        family,
        origin_asn,
        peer_asn,
        active_paths,
        toString(last_ts) AS last_ts,
        source,
        toString(snapshot_ts) AS snapshot_ts
      FROM ${tableRef(BGP_ROUTES_TABLE)}
      ${whereSql}
      ORDER BY last_ts DESC
      LIMIT {limit:UInt32}
      OFFSET {offset:UInt32}
    `, { ...params, limit, offset }, { name: 'bmp/routes' }),
    query(`
      SELECT count() AS c
      FROM ${tableRef(BGP_ROUTES_TABLE)}
      ${whereSql}
    `, params, { name: 'bmp/routes-count' }),
  ]);

  const enriched = await enrichAsnFields(rows, ['origin_asn', 'peer_asn']);
  const total = Number(countRes.rows[0]?.c) || 0;
  return {
    routes: enriched,
    limit,
    offset,
    total,
    hasMore: offset + enriched.length < total,
    source: BGP_ROUTES_TABLE,
    note: 'Активные префиксы из периодического снимка BMP (bgp-origin-refresh).',
  };
}

function buildEventsWhere(filters = {}, range) {
  const where = [`ts >= now() - ${range.interval}`];
  const params = {};
  const router = filters.router ? String(filters.router).trim() : '';
  const peer = filters.peer ? String(filters.peer).trim() : '';
  const prefix = filters.prefix ? String(filters.prefix).trim() : '';
  const eventType = filters.event_type ? String(filters.event_type).trim().toLowerCase() : '';
  const originAsn = parseUInt(filters.origin_asn);
  const peerAsn = parseUInt(filters.peer_asn);
  const family = parseUInt(filters.family);

  if (router) {
    where.push(`(${SQL_IPV4('router_addr')} = {router:String} OR ${SQL_IPV6('router_addr')} = {router:String})`);
    params.router = router;
  }
  if (peer) {
    where.push(`(${SQL_IPV4('peer_addr')} = {peer:String} OR ${SQL_IPV6('peer_addr')} = {peer:String})`);
    params.peer = peer;
  }
  if (prefix) {
    // Qualify columns: CH may resolve bare `prefix` to a SELECT alias of the same name.
    where.push(`${SQL_PREFIX('prefix', 'prefix_len', 'family')} LIKE {prefixLike:String}`);
    params.prefixLike = `${prefix}%`;
  }
  if (eventType === 'announce' || eventType === 'withdraw') {
    where.push('event_type = {eventType:String}');
    params.eventType = eventType;
  }
  if (originAsn != null) {
    where.push('origin_asn = {originAsn:UInt32}');
    params.originAsn = originAsn;
  }
  if (peerAsn != null) {
    where.push('peer_asn = {peerAsn:UInt32}');
    params.peerAsn = peerAsn;
  }
  if (family === 4 || family === 6) {
    where.push('family = {family:UInt8}');
    params.family = family;
  }
  return { where, params };
}

async function getBmpEvents(filters = {}) {
  const range = parseRange(filters.range || '1h');
  const limit = parseLimit(filters.limit, 100, MAX_EVENTS);
  const offset = parseOffset(filters.offset);
  const { where, params } = buildEventsWhere(filters, range);

  // Alias must not be `prefix` — ClickHouse can substitute it into WHERE and break SQL_PREFIX.
  const { rows } = await query(`
    SELECT
      toString(ts) AS event_ts,
      ${SQL_IP_FS16('router_addr')} AS router_addr,
      ${SQL_IP_FS16('peer_addr')} AS peer_addr,
      peer_asn,
      event_type,
      family,
      ${SQL_PREFIX('prefix', 'prefix_len', 'family')} AS prefix_str,
      ${SQL_IP_FS16('next_hop')} AS next_hop,
      origin_asn,
      as_path,
      med,
      local_pref
    FROM ${tableRef(BMP_EVENTS_TABLE)}
    WHERE ${where.join(' AND ')}
    ORDER BY ts DESC
    LIMIT {limit:UInt32}
    OFFSET {offset:UInt32}
  `, { ...params, limit, offset }, { name: 'bmp/events' });

  const enriched = await enrichAsnFields(rows, ['peer_asn', 'origin_asn']);
  return {
    events: enriched.map((r) => ({
      ...r,
      prefix: r.prefix_str,
      ts: r.event_ts || r.ts,
    })),
    range: range.key,
    limit,
    offset,
  };
}

async function getBmpCounts(filters = {}) {
  const range = parseRange(filters.range || '1h');
  const { where, params } = buildEventsWhere({}, range);

  const { rows: totals } = await query(`
    SELECT
      countIf(event_type = 'announce') AS announces,
      countIf(event_type = 'withdraw') AS withdraws,
      countIf(family = 4) AS ipv4_events,
      countIf(family = 6) AS ipv6_events,
      countIf(event_type = 'announce' AND family = 4) AS announces_v4,
      countIf(event_type = 'announce' AND family = 6) AS announces_v6,
      countIf(event_type = 'withdraw' AND family = 4) AS withdraws_v4,
      countIf(event_type = 'withdraw' AND family = 6) AS withdraws_v6
    FROM ${tableRef(BMP_EVENTS_TABLE)}
    WHERE ${where.join(' AND ')}
  `, params, { name: 'bmp/counts' });

  const { rows: byRouter } = await query(`
    SELECT
      ${SQL_IP_FS16('router_addr')} AS router_addr,
      countIf(event_type = 'announce') AS announces,
      countIf(event_type = 'withdraw') AS withdraws
    FROM ${tableRef(BMP_EVENTS_TABLE)}
    WHERE ${where.join(' AND ')}
    GROUP BY router_addr
    ORDER BY announces + withdraws DESC
    LIMIT 20
  `, params, { name: 'bmp/counts-router' });

  const { rows: byPeerAsn } = await query(`
    SELECT
      peer_asn,
      countIf(event_type = 'announce') AS announces,
      countIf(event_type = 'withdraw') AS withdraws
    FROM ${tableRef(BMP_EVENTS_TABLE)}
    WHERE ${where.join(' AND ')}
    GROUP BY peer_asn
    ORDER BY announces + withdraws DESC
    LIMIT 20
  `, params, { name: 'bmp/counts-peer-asn' });

  const enrichedPeers = await enrichAsnFields(byPeerAsn, ['peer_asn']);
  return {
    range: range.key,
    totals: totals[0] || {},
    byRouter,
    byPeerAsn: enrichedPeers,
  };
}

async function getBmpChurn(filters = {}) {
  const range = parseRange(filters.range || '1h');
  const { where, params } = buildEventsWhere({}, range);
  const allowSeries = range.key === '15m' || range.key === '1h' || range.key === '6h' || range.key === '24h';

  let series = [];
  if (allowSeries) {
    const bucket = range.key === '24h' ? 'toStartOfFiveMinute(ts)' : 'toStartOfMinute(ts)';
    const { rows } = await query(`
      SELECT
        toString(${bucket}) AS minute,
        countIf(event_type = 'announce') AS announces,
        countIf(event_type = 'withdraw') AS withdraws
      FROM ${tableRef(BMP_EVENTS_TABLE)}
      WHERE ${where.join(' AND ')}
      GROUP BY minute
      ORDER BY minute
    `, params, { name: 'bmp/churn-series' });
    series = rows;
  }

  const { rows: topPrefixes } = await query(`
    SELECT
      ${SQL_PREFIX('prefix', 'prefix_len', 'family')} AS prefix,
      count() AS events,
      countIf(event_type = 'announce') AS announces,
      countIf(event_type = 'withdraw') AS withdraws
    FROM ${tableRef(BMP_EVENTS_TABLE)}
    WHERE ${where.join(' AND ')}
    GROUP BY prefix, prefix_len, family
    ORDER BY events DESC
    LIMIT 25
  `, params, { name: 'bmp/churn-prefixes' });

  return {
    range: range.key,
    series,
    topPrefixes,
    seriesNote: allowSeries ? null : 'Timeseries доступен для окон ≤24h',
  };
}

async function getBmpFlap(filters = {}) {
  const range = parseRange(filters.range || '1h');
  const limit = parseLimit(filters.limit, 50, MAX_FLAP);
  const { where, params } = buildEventsWhere({}, range);

  const { rows: flapRows } = await query(`
    SELECT
      ${SQL_PREFIX('prefix', 'prefix_len', 'family')} AS prefix,
      countIf(event_type = 'announce') AS announces,
      countIf(event_type = 'withdraw') AS withdraws,
      count() AS event_count,
      toString(min(ts)) AS first_ts,
      toString(max(ts)) AS last_ts
    FROM ${tableRef(BMP_EVENTS_TABLE)}
    WHERE ${where.join(' AND ')}
    GROUP BY prefix, prefix_len, family
    HAVING announces >= {minAnn:UInt32}
      AND withdraws >= {minWd:UInt32}
      AND event_count >= {minEvents:UInt32}
    ORDER BY event_count DESC, withdraws DESC
    LIMIT {limit:UInt32}
  `, {
    ...params,
    minAnn: Math.max(2, Math.floor(FLAP_MIN_EVENTS / 2)),
    minWd: Math.max(2, Math.floor(FLAP_MIN_EVENTS / 2)),
    minEvents: FLAP_MIN_EVENTS,
    limit,
  }, { name: 'bmp/flap' });

  const { rows: multiRouter } = await query(`
    SELECT
      ${SQL_PREFIX('prefix', 'prefix_len', 'family')} AS prefix,
      uniqExact(router_addr) AS router_count,
      uniqExact(peer_addr) AS peer_count,
      count() AS events
    FROM ${tableRef(BMP_EVENTS_TABLE)}
    WHERE ${where.join(' AND ')}
    GROUP BY prefix, prefix_len, family
    HAVING router_count > 1 OR peer_count > 1
    ORDER BY events DESC
    LIMIT {limit:UInt32}
  `, { ...params, limit }, { name: 'bmp/flap-multi' });

  return {
    range: range.key,
    flapCandidates: flapRows.map((r) => ({
      ...r,
      toggle_count: Math.min(Number(r.announces) || 0, Number(r.withdraws) || 0),
    })),
    multiSourcePrefixes: multiRouter,
    minToggles: FLAP_MIN_EVENTS,
  };
}

module.exports = {
  getBmpSummary,
  getBmpPeers,
  getBmpRouters,
  getBmpRoutes,
  getBmpEvents,
  getBmpCounts,
  getBmpChurn,
  getBmpFlap,
  STALE_SEC,
};
