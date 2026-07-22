const {
  query,
  col,
  flowCol,
  flowsRawTableRef,
  dnsLogTableRef,
  collectorsViewRef,
  locationsViewRef,
} = require('./clickhouse');
const { listFlowSources } = require('./net-flow-sources');

function mapLiveRow(r) {
  return {
    sourceId: String(r.source_id ?? ''),
    rows5m: Number(r.rows_5m) || 0,
    lastSeen: r.last_seen ?? null,
    ageSec: Number(r.age_sec) || 0,
    flowsPerMin: Number(r.flows_per_min) || 0,
    bytesPerSec: Number(r.bytes_per_sec) || 0,
    pktsPerSec: Number(r.pkts_per_sec) || 0,
    sourceKind: String(r.source_kind ?? 'flow'),
  };
}

async function fetchLiveFlows() {
  const timeCol = col('time');
  const bytesCol = col('bytes');
  const packetsCol = col('packets');
  const sourceIdCol = flowCol('sourceId');
  const map = new Map();

  if (sourceIdCol) {
    const flowsRaw = flowsRawTableRef();
    const { rows } = await query(
      `
        SELECT
          ${sourceIdCol} AS source_id,
          count() AS rows_5m,
          max(${timeCol}) AS last_seen,
          dateDiff('second', max(${timeCol}), now()) AS age_sec,
          round(count() / 5, 0) AS flows_per_min,
          round(sum(${bytesCol}) / 300, 0) AS bytes_per_sec,
          round(sum(${packetsCol}) / 300, 0) AS pkts_per_sec,
          'flow' AS source_kind
        FROM ${flowsRaw}
        WHERE ${sourceIdCol} != ''
          AND ${timeCol} >= now() - INTERVAL 5 MINUTE
        GROUP BY source_id
      `,
      {},
      { name: 'collectors/live-flows' },
    );
    for (const r of rows) {
      map.set(String(r.source_id), mapLiveRow(r));
    }
  }

  const dnsLog = dnsLogTableRef();
  try {
    const { rows: dnsRows } = await query(
      `
        SELECT
          source_id,
          count() AS rows_5m,
          max(ts) AS last_seen,
          dateDiff('second', max(ts), now()) AS age_sec,
          round(count() / 5, 0) AS flows_per_min,
          toUInt64(0) AS bytes_per_sec,
          toUInt64(0) AS pkts_per_sec,
          'dns' AS source_kind
        FROM ${dnsLog}
        WHERE source_id != ''
          AND ts >= now() - INTERVAL 5 MINUTE
        GROUP BY source_id
      `,
      {},
      { name: 'collectors/live-dns' },
    );
    for (const r of dnsRows) {
      const id = String(r.source_id);
      const existing = map.get(id);
      const next = mapLiveRow(r);
      if (!existing || next.ageSec < existing.ageSec) {
        map.set(id, next);
      } else if (existing) {
        map.set(id, {
          ...existing,
          rows5m: existing.rows5m + next.rows5m,
          flowsPerMin: existing.flowsPerMin + next.flowsPerMin,
        });
      }
    }
  } catch {
    // dns_log may be unavailable
  }

  return map;
}

function computeCollectorState(sourceIds, liveMap) {
  if (!sourceIds.length) return 'empty';
  const hasLive = sourceIds.some((id) => liveMap.has(id));
  return hasLive ? 'online' : 'offline';
}

function buildOverview(collectors, catalogSources, liveMap) {
  const sourcesByCollector = new Map();
  for (const src of catalogSources) {
    const cid = src.currentCollectorId || '';
    if (!sourcesByCollector.has(cid)) sourcesByCollector.set(cid, []);
    sourcesByCollector.get(cid).push(src);
  }

  const collectorRows = collectors.map((c) => {
    const bound = sourcesByCollector.get(c.collectorId) || [];
    const sourceIds = bound.map((s) => s.sourceId);
    const state = computeCollectorState(sourceIds, liveMap);

    let flowsPerMin = 0;
    let bytesPerSec = 0;
    let maxAgeSec = 0;
    let lastSeen = null;

    const sources = bound.map((src) => {
      const live = liveMap.get(src.sourceId);
      if (live) {
        flowsPerMin += live.flowsPerMin;
        bytesPerSec += live.bytesPerSec;
        maxAgeSec = Math.max(maxAgeSec, live.ageSec);
        if (!lastSeen || new Date(live.lastSeen) > new Date(lastSeen)) {
          lastSeen = live.lastSeen;
        }
      }
      return {
        sourceId: src.sourceId,
        sourceName: src.sourceName || src.sourceId,
        sourceType: src.sourceType,
        catalogState: src.state,
        isLive: Boolean(live),
        flowsPerMin: live?.flowsPerMin ?? 0,
        bytesPerSec: live?.bytesPerSec ?? 0,
        ageSec: live?.ageSec ?? null,
        lastSeen: live?.lastSeen ?? null,
      };
    });

    const liveCount = sources.filter((s) => s.isLive).length;

    return {
      collectorId: c.collectorId,
      displayName: c.displayName,
      hostname: c.hostname,
      locationId: c.locationId,
      locationName: c.locationName,
      state,
      flowsPerMin,
      bytesPerSec,
      lastSeen,
      maxAgeSec,
      sourceCount: sources.length,
      liveSourceCount: liveCount,
      sources,
    };
  });

  const byLocation = new Map();
  for (const colRow of collectorRows) {
    const locKey = colRow.locationId || colRow.locationName || '__unknown__';
    if (!byLocation.has(locKey)) {
      byLocation.set(locKey, {
        locationId: colRow.locationId,
        locationName: colRow.locationName || 'Без локации',
        collectors: [],
      });
    }
    byLocation.get(locKey).collectors.push(colRow);
  }

  const locations = [...byLocation.values()].sort((a, b) => (
    a.locationName.localeCompare(b.locationName, 'ru')
  ));

  return { locations, collectors: collectorRows };
}

function buildDiscovered(catalogSources, liveMap) {
  const catalogIds = new Set(catalogSources.map((s) => s.sourceId));
  const discovered = [];

  for (const [sourceId, live] of liveMap) {
    if (!catalogIds.has(sourceId)) {
      discovered.push({
        sourceId,
        sourceType: live.sourceKind === 'dns' ? 'dns' : '',
        state: 'unknown_source',
        lastSeen: live.lastSeen,
        ageSec: live.ageSec,
        flowsPerMin: live.flowsPerMin,
        bytesPerSec: live.bytesPerSec,
        currentCollectorId: '',
        currentCollectorName: '',
      });
    }
  }

  for (const src of catalogSources) {
    const live = liveMap.get(src.sourceId);
    if (src.state === 'broken_collector_link') {
      discovered.push({
        sourceId: src.sourceId,
        sourceType: src.sourceType,
        state: 'broken_collector_link',
        lastSeen: live?.lastSeen ?? null,
        ageSec: live?.ageSec ?? null,
        flowsPerMin: live?.flowsPerMin ?? 0,
        bytesPerSec: live?.bytesPerSec ?? 0,
        currentCollectorId: src.currentCollectorId,
        currentCollectorName: src.currentCollectorName,
      });
    } else if (src.state === 'unassigned' && live) {
      discovered.push({
        sourceId: src.sourceId,
        sourceType: src.sourceType,
        state: 'unassigned_online',
        lastSeen: live.lastSeen,
        ageSec: live.ageSec,
        flowsPerMin: live.flowsPerMin,
        bytesPerSec: live.bytesPerSec,
        currentCollectorId: '',
        currentCollectorName: '',
      });
    }
  }

  discovered.sort((a, b) => a.state.localeCompare(b.state) || a.sourceId.localeCompare(b.sourceId));
  return discovered;
}

async function loadCatalogAndCollectors() {
  const collectorsView = collectorsViewRef();
  const locationsView = locationsViewRef();

  const [collectorsRes, catalogRes] = await Promise.all([
    query(
      `
        SELECT
          c.collector_id,
          c.display_name,
          c.hostname,
          c.location_id,
          l.display_name AS location_name
        FROM ${collectorsView} AS c
        LEFT JOIN ${locationsView} AS l ON c.location_id = l.location_id
        ORDER BY location_name, c.display_name
      `,
      {},
      { name: 'collectors/overview-collectors' },
    ),
    query(listFlowSources().sql, listFlowSources().params, { name: 'collectors/overview-sources' }),
  ]);

  const collectors = collectorsRes.rows.map((r) => ({
    collectorId: String(r.collector_id ?? ''),
    displayName: String(r.display_name ?? ''),
    hostname: String(r.hostname ?? ''),
    locationId: String(r.location_id ?? ''),
    locationName: String(r.location_name ?? ''),
  }));

  const catalogSources = listFlowSources().map(catalogRes.rows);
  return { collectors, catalogSources };
}

async function fetchCollectorOverview() {
  const started = Date.now();
  const liveMap = await fetchLiveFlows();
  const { collectors, catalogSources } = await loadCatalogAndCollectors();
  const overview = buildOverview(collectors, catalogSources, liveMap);
  return {
    data: overview,
    meta: {
      elapsedMs: Date.now() - started,
      windowMinutes: 5,
      liveSourceCount: liveMap.size,
      collectorCount: collectors.length,
    },
  };
}

async function fetchDiscoveredSources() {
  const started = Date.now();
  const liveMap = await fetchLiveFlows();
  const { catalogSources } = await loadCatalogAndCollectors();
  const data = buildDiscovered(catalogSources, liveMap);
  return {
    data,
    meta: {
      elapsedMs: Date.now() - started,
      rows: data.length,
      windowMinutes: 5,
    },
  };
}

module.exports = {
  fetchLiveFlows,
  fetchCollectorOverview,
  fetchDiscoveredSources,
  buildOverview,
  computeCollectorState,
};
