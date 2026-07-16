#!/usr/bin/env node
'use strict';

/**
 * Catch-up worker for observation_rollups_5m (5-minute buckets, like dashboard).
 * Usage:
 *   node server/observations-rollup.js once
 *   node server/observations-rollup.js loop
 *
 * Writes:
 *   - total 5m rows (dim0='', dim1='')
 *   - top-N groupBy series (dim0/dim1) for live charts — worker hits flows_raw,
 *     live UI reads only rollup.
 *
 * Starts from observation createdAt (no historical backfill before start).
 * Each shot advances at most MAX_SHOT_MINUTES forward from the cursor.
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { query, insertRows, executeCommand } = require('./clickhouse');
const {
  ensureObservationsStore,
  listMaterializeJobs,
  patchMaterializeStatus,
  MIN_INTERVAL_SEC,
  MIN_REFRESH_SEC,
  ROLLUP_TABLE,
  ROLLUP_BUCKET_SEC,
} = require('./observations');
const {
  explorerTimeseries,
  explorerGroupedTimeseries,
} = require('./explorer');

const CONCURRENCY = Math.max(1, Number(process.env.OBSERVATION_ROLLUP_CONCURRENCY) || 1);
const MAX_SHOT_MINUTES = Math.max(15, Number(process.env.OBSERVATION_ROLLUP_SHOT_MINUTES) || 60);
/** Don't backfill older than this — live charts only need recent lookbacks. */
const MAX_CATCHUP_BEHIND_MS = Math.max(
  1,
  Number(process.env.OBSERVATION_ROLLUP_MAX_BEHIND_HOURS) || 24,
) * 3600 * 1000; // default 24h — enough for lookbacks, skips multi-day backfill
const BUCKET_MS = ROLLUP_BUCKET_SEC * 1000;
const GRANULARITY = '5m';
const REWIND_EVERY_MS = Math.max(
  60_000,
  Number(process.env.OBSERVATION_ROLLUP_REWIND_SEC) || 600,
) * 1000;

let ensureTablePromise = null;
let lastRewindAtMs = 0;

async function ensureTable() {
  if (!ensureTablePromise) {
    ensureTablePromise = executeCommand(`
    CREATE TABLE IF NOT EXISTS default.${ROLLUP_TABLE}
    (
      observation_id String,
      minute DateTime,
      dim0 LowCardinality(String) DEFAULT '',
      dim1 LowCardinality(String) DEFAULT '',
      bytes UInt64,
      packets UInt64,
      flows UInt64
    )
    ENGINE = SummingMergeTree
    PARTITION BY toYYYYMM(minute)
    ORDER BY (observation_id, minute, dim0, dim1)
    TTL minute + INTERVAL 14 DAY
    SETTINGS index_granularity = 8192
  `, {}, { name: 'observations/ensure-rollup-table' }).catch((err) => {
      ensureTablePromise = null;
      throw err;
    });
  }
  return ensureTablePromise;
}

/** Align down to closed 5-minute bucket start (UTC wall via Date). */
function floorToBucket(d) {
  const x = new Date(d);
  x.setSeconds(0, 0);
  const m = x.getMinutes();
  x.setMinutes(m - (m % 5));
  return x;
}

function earliestLiveFrom(safeTo) {
  return floorToBucket(new Date(safeTo.getTime() - MAX_CATCHUP_BEHIND_MS));
}

function resolveCatchupFrom(job, safeTo) {
  const earliest = earliestLiveFrom(safeTo);
  let from;
  if (job.cursorMinute) {
    // cursor is exclusive end of last successful window
    from = floorToBucket(job.cursorMinute);
  } else if (job.startedAt) {
    from = floorToBucket(job.startedAt);
  } else {
    from = earliest;
  }
  // Skip ancient history: charts show lookback windows (≤7d), not full life of observation.
  if (from < earliest) from = earliest;
  return from;
}

async function catchupGrouped(job, window, seriesLimit) {
  const groupBy = Array.isArray(job.groupBy) ? job.groupBy.filter(Boolean).slice(0, 2) : [];
  if (!groupBy.length) return { groupedPoints: 0, values: [] };

  const groupedBundle = await explorerGroupedTimeseries({
    ...window,
    metric: 'bps',
    groupBy,
    limit: seriesLimit,
    offset: 0,
    granularity: GRANULARITY,
  });
  const { rows: groupedRaw } = await query(groupedBundle.sql, groupedBundle.params, {
    name: `observations/rollup-grouped-${job.id}`,
  });
  const { flowRows, seriesByRow } = await groupedBundle.map(groupedRaw);
  if (!flowRows.length) return { groupedPoints: 0, values: [] };

  const values = [];
  for (const row of flowRows) {
    const dim0 = String(row.rawValues?.[0] ?? row.values?.[0] ?? '');
    const dim1 = groupBy.length > 1
      ? String(row.rawValues?.[1] ?? row.values?.[1] ?? '')
      : '';
    if (!dim0 && !dim1) continue;
    for (const pt of seriesByRow[row.id] || []) {
      values.push({
        observation_id: job.id,
        minute: pt.bucket,
        dim0,
        dim1,
        bytes: Number(pt.bytes) || 0,
        packets: Number(pt.packets) || 0,
        flows: Number(pt.flows) || 0,
      });
    }
  }
  return { groupedPoints: values.length, values };
}

async function catchupOne(job) {
  const intervalSec = Math.max(MIN_REFRESH_SEC, Number(job.intervalSec) || MIN_REFRESH_SEC);

  // Exclusive end of latest closed 5m bucket, minus one more bucket for late flows.
  // e.g. now 12:07 → floor 12:05 → safeTo 12:00 (materialize through […, 12:00)).
  let safeTo = floorToBucket(new Date());
  safeTo = new Date(safeTo.getTime() - BUCKET_MS);

  let from = resolveCatchupFrom(job, safeTo);
  if (from >= safeTo) {
    // Fully caught up — throttle next CH pass by live.refreshSec (≥5m).
    if (job.lastCatchupAt) {
      const ageSec = (Date.now() - new Date(job.lastCatchupAt).getTime()) / 1000;
      if (Number.isFinite(ageSec) && ageSec < intervalSec) {
        return { id: job.id, skipped: true, reason: 'interval' };
      }
    }
    await patchMaterializeStatus(job.id, {
      status: 'ok',
      lagSeconds: 0,
      lastCatchupAt: new Date().toISOString(),
      cursorMinute: job.cursorMinute || safeTo.toISOString(),
    });
    return { id: job.id, skipped: true };
  }

  let to = safeTo;
  const maxSpanMs = MAX_SHOT_MINUTES * 60 * 1000;
  if (to - from > maxSpanMs) {
    to = floorToBucket(new Date(from.getTime() + maxSpanMs));
    if (to <= from) to = new Date(from.getTime() + BUCKET_MS);
    if (to > safeTo) to = safeTo;
  }

  await patchMaterializeStatus(job.id, { status: 'running' });
  try {
    const window = {
      range: 'custom',
      from: from.toISOString(),
      to: to.toISOString(),
      filters: job.filters,
      granularity: GRANULARITY,
    };

    const totalBundle = await explorerTimeseries(window);
    const { rows: totalRaw } = await query(totalBundle.sql, totalBundle.params, {
      name: `observations/rollup-total-${job.id}`,
    });
    const totalPoints = await totalBundle.map(totalRaw);

    const values = totalPoints.map((p) => ({
      observation_id: job.id,
      minute: p.bucket,
      dim0: '',
      dim1: '',
      bytes: Number(p.bytes) || 0,
      packets: Number(p.packets) || 0,
      flows: Number(p.flows) || 0,
    }));

    const seriesLimit = Math.min(Math.max(Number(job.seriesLimit) || 20, 8), 50);
    const grouped = await catchupGrouped(job, window, seriesLimit);
    values.push(...grouped.values);

    if (values.length) {
      await insertRows(ROLLUP_TABLE, values, { name: `observations/rollup-insert-${job.id}` });
    }

    const lagSeconds = Math.max(0, Math.floor((Date.now() - to.getTime()) / 1000));
    await patchMaterializeStatus(job.id, {
      status: lagSeconds > intervalSec * 3 ? 'lagging' : 'ok',
      lagSeconds,
      lastCatchupAt: new Date().toISOString(),
      cursorMinute: to.toISOString(),
      lastError: null,
    });
    return {
      id: job.id,
      points: totalPoints.length,
      groupedPoints: grouped.groupedPoints,
      from,
      to,
      bucketSec: ROLLUP_BUCKET_SEC,
    };
  } catch (err) {
    await patchMaterializeStatus(job.id, {
      status: 'error',
      lastError: err.message,
      lastCatchupAt: new Date().toISOString(),
    });
    throw err;
  }
}

async function recoverStuckRunning() {
  const jobs = (await listMaterializeJobs()).filter((j) => j.status === 'running');
  for (const job of jobs) {
    await patchMaterializeStatus(job.id, {
      status: 'queued',
      lastError: 'воркер перезапущен — продолжаем с cursor/start',
    });
  }
  return jobs.length;
}

function chUtcToIso(value) {
  const s = String(value || '').trim();
  if (!s) return null;
  if (s.includes('T')) return s.endsWith('Z') ? s : `${s}Z`;
  return `${s.replace(' ', 'T')}.000Z`;
}

async function rewindCursorsIfAhead({ force = false } = {}) {
  const now = Date.now();
  if (!force && lastRewindAtMs && now - lastRewindAtMs < REWIND_EVERY_MS) {
    return { skipped: true };
  }
  lastRewindAtMs = now;
  const jobs = await listMaterializeJobs();
  for (const job of jobs) {
    if (!job.cursorMinute) continue;
    const { rows } = await query(
      `SELECT toTimeZone(max(minute), 'UTC') AS max_utc
       FROM default.${ROLLUP_TABLE}
       WHERE observation_id = {id:String}`,
      { id: job.id },
      { name: `observations/rollup-max-${job.id}` },
    );
    const maxIso = chUtcToIso(rows[0]?.max_utc);
    if (!maxIso) continue;
    // max(minute) is bucket start; exclusive cursor should be max + 5m
    const exclusiveEnd = new Date(new Date(maxIso).getTime() + BUCKET_MS);
    if (new Date(job.cursorMinute) > exclusiveEnd) {
      await patchMaterializeStatus(job.id, {
        cursorMinute: exclusiveEnd.toISOString(),
        status: 'queued',
        lastError: null,
      });
    }
  }
  return { skipped: false };
}

async function runOnce() {
  await ensureObservationsStore();
  await ensureTable();
  // Force rewind on cold start; later ticks throttle to REWIND_EVERY_MS.
  await rewindCursorsIfAhead({ force: !lastRewindAtMs });
  const jobs = (await listMaterializeJobs())
    .filter((j) => (
      j.status === 'queued'
      || j.status === 'lagging'
      || j.status === 'ok'
      || j.status === 'error'
      || j.status === 'running'
      || j.status === 'idle'
    ))
    .sort((a, b) => {
      const rank = (s) => ({ queued: 0, error: 1, lagging: 2, running: 3, idle: 4, ok: 5 }[s] ?? 9);
      const dr = rank(a.status) - rank(b.status);
      if (dr !== 0) return dr;
      return String(a.cursorMinute || '').localeCompare(String(b.cursorMinute || ''));
    });

  const results = [];
  const limit = Math.max(1, CONCURRENCY);
  for (let i = 0; i < jobs.length; i += limit) {
    const batch = jobs.slice(i, i + limit);
    for (const job of batch) {
      try {
        results.push(await catchupOne(job));
      } catch (err) {
        results.push({ id: job.id, error: err.message });
      }
    }
  }
  return results;
}

module.exports = {
  runOnce,
  recoverStuckRunning,
  ensureTable,
};

async function main() {
  const mode = process.argv[2] || 'once';
  const recovered = recoverStuckRunning();
  if (recovered) {
    console.log(new Date().toISOString(), 'recovered stuck running jobs:', recovered);
  }
  if (mode === 'loop') {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const started = Date.now();
      try {
        const results = await runOnce();
        console.log(new Date().toISOString(), 'rollup', JSON.stringify(results));
      } catch (err) {
        console.error(new Date().toISOString(), 'rollup fatal', err.message);
      }
      const sleepMs = Math.max(5000, MIN_INTERVAL_SEC * 1000 - (Date.now() - started));
      await new Promise((r) => setTimeout(r, sleepMs));
    }
  } else {
    const results = await runOnce();
    console.log(JSON.stringify(results, null, 2));
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
