#!/usr/bin/env node
'use strict';

/**
 * Catch-up worker for observation_rollups_5m (5-minute buckets, like dashboard).
 * Usage:
 *   node server/observations-rollup.js once
 *   node server/observations-rollup.js loop
 *   node server/observations-rollup.js rebuild <observationId> [fromIso]
 *
 * Writes:
 *   - total 5m rows (dim0='', dim1='')
 *   - top-N groupBy series (dim0/dim1) for live charts — worker hits flows_raw,
 *     live UI reads only rollup.
 *
 * Starts from observation createdAt (no historical backfill before start).
 * Each shot advances at most MAX_SHOT_MINUTES forward from the cursor.
 * Inserts are idempotent: the target window is deleted (mutations_sync=1) before insert.
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

/** Align down to closed 5-minute bucket start (UTC epoch, not process local TZ). */
function floorToBucket(d) {
  const ms = d instanceof Date ? d.getTime() : new Date(d).getTime();
  if (!Number.isFinite(ms)) return new Date(NaN);
  return new Date(Math.floor(ms / BUCKET_MS) * BUCKET_MS);
}

function toChUtc(d) {
  return (d instanceof Date ? d : new Date(d)).toISOString();
}

/**
 * Remove existing rollup rows for [from, to) so SummingMergeTree cannot double-count
 * on overlapping catch-up / rebuild. Waits for the mutation to finish.
 */
async function deleteRollupWindow(observationId, from, to) {
  if (!(from instanceof Date) || !(to instanceof Date) || !(from < to)) return;
  await executeCommand(`
    ALTER TABLE default.${ROLLUP_TABLE}
    DELETE WHERE observation_id = {id:String}
      AND minute >= parseDateTimeBestEffort({from:String}, 'UTC')
      AND minute < parseDateTimeBestEffort({to:String}, 'UTC')
    SETTINGS mutations_sync = 1
  `, {
    id: observationId,
    from: toChUtc(from),
    to: toChUtc(to),
  }, { name: `observations/rollup-delete-${observationId}` });
}

function earliestLiveFrom(safeTo) {
  return floorToBucket(new Date(safeTo.getTime() - MAX_CATCHUP_BEHIND_MS));
}

function jobStartedBucket(job) {
  if (job?.startedAt) {
    const started = floorToBucket(job.startedAt);
    if (started instanceof Date && Number.isFinite(started.getTime())) return started;
  }
  return null;
}

/**
 * Live catch-up starts at observation createdAt (startedAt).
 * Never backfill before creation — a new observation must not show multi-hour lag.
 * cursorMinute is the exclusive end of the last successful window.
 */
function resolveCatchupFrom(job, safeTo) {
  const earliest = earliestLiveFrom(safeTo);
  const started = jobStartedBucket(job);
  let from;
  if (job.cursorMinute) {
    from = floorToBucket(job.cursorMinute);
  } else if (started) {
    from = started;
  } else {
    from = earliest;
  }
  // Never before observation creation (fixes epoch/stale cursors → 19h "lag").
  if (started && from < started) from = started;
  // Hard cap for very old observations (charts only need recent lookbacks).
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

    // Always clear the window first — SummingMergeTree sums duplicates on re-insert.
    await deleteRollupWindow(job.id, from, to);
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

/**
 * Backfill-only: rematerialize a single observation strictly inside [from, to)
 * WITHOUT moving the live cursor and WITHOUT the MAX_CATCHUP_BEHIND_MS 24h cap.
 * The live loop keeps owning cursorMinute/status — we only rewrite the closed
 * historical window the operator asked for. Chunked by MAX_SHOT_MINUTES so a
 * multi-hour gap doesn't hit flows_raw in one shot.
 */
async function materializeWindow(job, fromIn, toIn) {
  let from = floorToBucket(fromIn);
  const to = floorToBucket(toIn);
  if (!(from instanceof Date) || !Number.isFinite(from.getTime())
      || !(to instanceof Date) || !Number.isFinite(to.getTime())) {
    return { id: job.id, points: 0, skipped: true, reason: 'bad_range' };
  }
  const started = jobStartedBucket(job);
  if (started && from < started) from = started;
  if (!(from < to)) {
    return { id: job.id, points: 0, skipped: true, reason: 'before_created' };
  }

  const maxSpanMs = MAX_SHOT_MINUTES * 60 * 1000;
  const seriesLimit = Math.min(Math.max(Number(job.seriesLimit) || 20, 8), 50);
  let totalPointsAll = 0;
  let groupedPointsAll = 0;
  let cursor = from;

  while (cursor < to) {
    let chunkTo = new Date(Math.min(cursor.getTime() + maxSpanMs, to.getTime()));
    if (chunkTo <= cursor) chunkTo = new Date(cursor.getTime() + BUCKET_MS);
    if (chunkTo > to) chunkTo = to;

    const window = {
      range: 'custom',
      from: cursor.toISOString(),
      to: chunkTo.toISOString(),
      filters: job.filters,
      granularity: GRANULARITY,
    };

    const totalBundle = await explorerTimeseries(window);
    const { rows: totalRaw } = await query(totalBundle.sql, totalBundle.params, {
      name: `observations/backfill-total-${job.id}`,
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

    const grouped = await catchupGrouped(job, window, seriesLimit);
    values.push(...grouped.values);

    // Idempotent rewrite: clear the chunk window then re-insert.
    await deleteRollupWindow(job.id, cursor, chunkTo);
    if (values.length) {
      await insertRows(ROLLUP_TABLE, values, { name: `observations/backfill-insert-${job.id}` });
    }

    totalPointsAll += totalPoints.length;
    groupedPointsAll += grouped.groupedPoints;
    cursor = chunkTo;
  }

  return {
    id: job.id,
    name: job.name,
    points: totalPointsAll,
    groupedPoints: groupedPointsAll,
    from: from.toISOString(),
    to: to.toISOString(),
  };
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

async function rebuildObservation(observationId, fromIso) {
  await ensureObservationsStore();
  await ensureTable();
  const jobs = await listMaterializeJobs();
  const job = jobs.find((j) => j.id === observationId);
  if (!job) {
    throw new Error(`Нет live-материализации для ${observationId}`);
  }

  let safeTo = floorToBucket(new Date());
  safeTo = new Date(safeTo.getTime() - BUCKET_MS);

  const started = jobStartedBucket(job) || earliestLiveFrom(safeTo);
  let from = fromIso
    ? floorToBucket(new Date(fromIso))
    : started;
  if (!(from instanceof Date) || !Number.isFinite(from.getTime())) {
    throw new Error(`Некорректный from: ${fromIso}`);
  }
  if (from < started) from = started;
  if (from < earliestLiveFrom(safeTo)) from = earliestLiveFrom(safeTo);
  if (from >= safeTo) {
    throw new Error('Нечего пересчитывать: from >= safeTo');
  }

  console.log(new Date().toISOString(), 'rebuild delete+cursor', {
    id: observationId,
    from: toChUtc(from),
    to: toChUtc(safeTo),
  });
  await deleteRollupWindow(observationId, from, safeTo);
  await patchMaterializeStatus(observationId, {
    status: 'queued',
    cursorMinute: from.toISOString(),
    lastError: null,
  });

  const shots = [];
  for (let i = 0; i < 200; i += 1) {
    const result = await catchupOne({
      ...job,
      ...(await listMaterializeJobs()).find((j) => j.id === observationId),
    });
    shots.push(result);
    console.log(new Date().toISOString(), 'rebuild shot', JSON.stringify(result));
    if (result?.skipped || result?.error) break;
    if (result?.to && new Date(result.to) >= safeTo) break;
  }
  return shots;
}

module.exports = {
  runOnce,
  recoverStuckRunning,
  ensureTable,
  deleteRollupWindow,
  rebuildObservation,
  materializeWindow,
  floorToBucket,
};

async function main() {
  const mode = process.argv[2] || 'once';
  if (mode === 'rebuild') {
    const id = process.argv[3];
    const fromIso = process.argv[4] || null;
    if (!id) {
      console.error('Usage: node server/observations-rollup.js rebuild <observationId> [fromIso]');
      process.exit(1);
    }
    const shots = await rebuildObservation(id, fromIso);
    console.log(JSON.stringify(shots, null, 2));
    return;
  }

  const recovered = await recoverStuckRunning();
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
