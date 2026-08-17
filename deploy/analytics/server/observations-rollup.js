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
 * Live catch-up starts at observation createdAt; optional history backfill runs
 * at lower priority after live is caught up.
 * Each shot advances at most MAX_SHOT_MINUTES forward from the cursor.
 * Inserts are idempotent: the target window is deleted (mutations_sync=1) before insert.
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const {
  query, insertRows, executeCommand, config, escapeSqlString,
} = require('./clickhouse');
const {
  ensureObservationsStore,
  listMaterializeJobs,
  patchMaterializeStatus,
  MIN_INTERVAL_SEC,
  MIN_REFRESH_SEC,
  ROLLUP_TABLE,
  ROLLUP_BUCKET_SEC,
  ROLLUP_DIM_COUNT,
  STUCK_SEC,
  MAX_FAIL_COUNT,
} = require('./observations');
const {
  loadObservationById,
  upsertObservation,
} = require('./observations-store');
const {
  explorerTimeseries,
  explorerGroupedTimeseries,
  explorerDimensions,
} = require('./explorer');

const CONCURRENCY = Math.max(1, Number(process.env.OBSERVATION_ROLLUP_CONCURRENCY) || 1);
const MAX_SHOT_MINUTES = Math.max(15, Number(process.env.OBSERVATION_ROLLUP_SHOT_MINUTES) || 15);
/** Cap how far live catch-up may lag behind wall clock. */
const MAX_CATCHUP_BEHIND_MS = Math.max(
  1,
  Number(process.env.OBSERVATION_ROLLUP_MAX_BEHIND_HOURS) || 24,
) * 3600 * 1000;
const BUCKET_MS = ROLLUP_BUCKET_SEC * 1000;
const GRANULARITY = '5m';
const REWIND_EVERY_MS = Math.max(
  60_000,
  Number(process.env.OBSERVATION_ROLLUP_REWIND_SEC) || 600,
) * 1000;
/**
 * Запас «на опоздавшие флоу» в бакетах перед закрытым бакетом. Коллектор пишет
 * в ClickHouse сразу (time_inserted_ns == time_received_ns), и закрытый бакет
 * больше не меняется, поэтому по умолчанию запаса нет: каждый лишний бакет —
 * это ровно +5 минут отставания графика от реального времени.
 */
const SAFETY_BUCKETS = readBucketCount(process.env.OBSERVATION_ROLLUP_SAFETY_BUCKETS, 0);
/**
 * Сколько уже записанных бакетов пересчитывать вместе с новым окном. Это замена
 * SAFETY_BUCKETS: опоздавшие флоу попадают в rollup при следующем шоте, а не за
 * счёт постоянного отставания. Пересчёт безопасен — окно удаляется перед вставкой.
 */
const RECHECK_BUCKETS = readBucketCount(process.env.OBSERVATION_ROLLUP_RECHECK_BUCKETS, 1);

function readBucketCount(raw, fallback) {
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.floor(n);
}

function backoffMinutes(failCount) {
  const steps = [1, 5, 15, 60];
  return steps[Math.min(steps.length - 1, Math.max(0, failCount - 1))];
}

function emptyRollupDims() {
  return Object.fromEntries(
    Array.from({ length: ROLLUP_DIM_COUNT }, (_, i) => [`dim${i}`, '']),
  );
}

let ensureTablePromise = null;
let lastRewindAtMs = 0;

const ROLLUP_DIM_COLUMNS = Array.from({ length: ROLLUP_DIM_COUNT }, (_, i) => `dim${i}`);

/**
 * Explorer печатает время бакета в dataTimezone, и в rollup оно приезжает строкой
 * без зоны. Колонка обязана быть в той же зоне, иначе ClickHouse прочитает строку
 * в зоне сервера и сдвинет момент времени на её смещение.
 */
function rollupMinuteType() {
  return `DateTime('${escapeSqlString(config.dataTimezone || 'UTC')}')`;
}

function rollupTableDdl(table) {
  const dimDefs = ROLLUP_DIM_COLUMNS
    .map((c) => `      ${c} LowCardinality(String) DEFAULT '',`)
    .join('\n');
  return `
    CREATE TABLE IF NOT EXISTS default.${table}
    (
      observation_id String,
      minute ${rollupMinuteType()},
${dimDefs}
      bytes UInt64,
      packets UInt64,
      flows UInt64
    )
    ENGINE = SummingMergeTree
    PARTITION BY toYYYYMM(minute)
    ORDER BY (observation_id, minute, ${ROLLUP_DIM_COLUMNS.join(', ')})
    TTL minute + INTERVAL 14 DAY
    SETTINGS index_granularity = 8192
  `;
}

/**
 * Таблицы, созданные до разреза из четырёх измерений, знают только dim0/dim1.
 * Новые колонки обязаны войти в ключ сортировки, иначе SummingMergeTree схлопнет
 * строки, различающиеся только dim2/dim3, и суммы поедут. ALTER MODIFY ORDER BY
 * умеет добавлять в ключ только колонки, созданные тем же запросом, поэтому
 * переливаем данные в новую таблицу и подменяем её атомарно.
 */
async function migrateRollupDims() {
  const { rows: tables } = await query(`
    SELECT sorting_key
    FROM system.tables
    WHERE database = 'default' AND name = {table:String}
  `, { table: ROLLUP_TABLE }, { name: 'observations/rollup-sorting-key' });
  const sortingKey = String(tables[0]?.sorting_key || '');
  if (!sortingKey || sortingKey.includes(ROLLUP_DIM_COLUMNS[ROLLUP_DIM_COUNT - 1])) return;

  const { rows: cols } = await query(`
    SELECT name
    FROM system.columns
    WHERE database = 'default' AND table = {table:String}
  `, { table: ROLLUP_TABLE }, { name: 'observations/rollup-columns' });
  const present = new Set(cols.map((r) => String(r.name)));
  const dimSelect = ROLLUP_DIM_COLUMNS
    .map((c) => (present.has(c) ? c : `'' AS ${c}`))
    .join(', ');

  const staging = `${ROLLUP_TABLE}_migrating`;
  await executeCommand(`DROP TABLE IF EXISTS default.${staging} SYNC`, {}, { name: 'observations/rollup-drop-staging' });
  await executeCommand(rollupTableDdl(staging), {}, { name: 'observations/rollup-create-staging' });
  await executeCommand(`
    INSERT INTO default.${staging}
    SELECT observation_id, minute, ${dimSelect}, bytes, packets, flows
    FROM default.${ROLLUP_TABLE}
  `, {}, { name: 'observations/rollup-copy-staging' });
  await executeCommand(
    `EXCHANGE TABLES default.${ROLLUP_TABLE} AND default.${staging}`,
    {},
    { name: 'observations/rollup-exchange' },
  );
  await executeCommand(`DROP TABLE IF EXISTS default.${staging} SYNC`, {}, { name: 'observations/rollup-drop-old' });
}

/**
 * Таблицы, созданные до привязки времени к зоне, объявляли minute как DateTime без
 * зоны, и ClickHouse печатал их в зоне сервера, а UI читал как dataTimezone.
 * Смена типа затрагивает только метаданные: хранится epoch, поэтому уже записанные
 * моменты времени остаются прежними и начинают печататься в нужной зоне.
 */
async function migrateRollupMinuteTz() {
  const wanted = rollupMinuteType();
  const { rows } = await query(`
    SELECT type
    FROM system.columns
    WHERE database = 'default' AND table = {table:String} AND name = 'minute'
  `, { table: ROLLUP_TABLE }, { name: 'observations/rollup-minute-type' });
  const current = String(rows[0]?.type || '');
  if (!current || current === wanted) return;
  await executeCommand(
    `ALTER TABLE default.${ROLLUP_TABLE} MODIFY COLUMN minute ${wanted}`,
    {},
    { name: 'observations/rollup-minute-tz' },
  );
}

async function ensureTable() {
  if (!ensureTablePromise) {
    ensureTablePromise = executeCommand(
      rollupTableDdl(ROLLUP_TABLE),
      {},
      { name: 'observations/ensure-rollup-table' },
    )
      .then(() => migrateRollupDims())
      .then(() => migrateRollupMinuteTz())
      .catch((err) => {
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

/**
 * Exclusive end of the newest window we may materialize: the bucket that just
 * closed, minus SAFETY_BUCKETS (0 by default).
 * e.g. now 12:07 → 12:05 → materialize through […, 12:05).
 */
function computeSafeTo(now = new Date()) {
  const closed = floorToBucket(now);
  if (!SAFETY_BUCKETS) return closed;
  return new Date(closed.getTime() - SAFETY_BUCKETS * BUCKET_MS);
}

function toChUtc(d) {
  return (d instanceof Date ? d : new Date(d)).toISOString();
}

/**
 * Remove existing rollup rows for [from, to) so SummingMergeTree cannot double-count
 * on overlapping catch-up / rebuild. Waits for the mutation to finish.
 */
async function deleteRollupWindow(observationId, from, to) {
  if (!(from instanceof Date) || !(to instanceof Date) || !(from < to)) return { elapsedMs: 0 };
  const started = Date.now();
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
  return { elapsedMs: Date.now() - started };
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

/**
 * Расширяет окно назад на RECHECK_BUCKETS уже записанных бакетов. Вызывается
 * только когда есть новый бакет, поэтому частота шотов не растёт — растёт лишь
 * ширина окна, а последний бакет перезаписывается с учётом опоздавших флоу.
 */
function widenForRecheck(job, from) {
  if (!RECHECK_BUCKETS || !job.cursorMinute) return from;
  const started = jobStartedBucket(job);
  let widened = new Date(from.getTime() - RECHECK_BUCKETS * BUCKET_MS);
  if (started && widened < started) widened = started;
  return widened < from ? widened : from;
}

/**
 * Explorer молча выбрасывает неизвестные измерения из groupBy. Для rollup это
 * опаснее ошибки: dim0 заполнился бы вторым измерением, а UI подписал бы его
 * первым. Поэтому проверяем разрез до запроса.
 */
function assertKnownGroupBy(groupBy) {
  const known = new Set(Object.keys(explorerDimensions()));
  const unknown = groupBy.filter((g) => !known.has(g));
  if (unknown.length) {
    throw new Error(`Неизвестное измерение разреза: ${unknown.join(', ')}`);
  }
}

async function catchupGrouped(job, window, seriesLimit) {
  const groupBy = Array.isArray(job.groupBy)
    ? job.groupBy.filter(Boolean).slice(0, ROLLUP_DIM_COUNT)
    : [];
  if (!groupBy.length) return { groupedPoints: 0, values: [] };
  assertKnownGroupBy(groupBy);

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
    const dims = emptyRollupDims();
    for (let i = 0; i < groupBy.length; i += 1) {
      dims[`dim${i}`] = String(row.rawValues?.[i] ?? row.values?.[i] ?? '');
    }
    // Строка со всеми пустыми значениями неотличима от итоговой — пропускаем.
    if (!Object.values(dims).some(Boolean)) continue;
    for (const pt of seriesByRow[row.id] || []) {
      values.push({
        observation_id: job.id,
        minute: pt.bucket,
        ...dims,
        bytes: Number(pt.bytes) || 0,
        packets: Number(pt.packets) || 0,
        flows: Number(pt.flows) || 0,
      });
    }
  }
  return { groupedPoints: values.length, values };
}

async function honorCancel(job) {
  if (!job.cancelRequested) return false;
  const item = await loadObservationById(job.id);
  if (!item) return true;
  item.materialize = {
    ...(item.materialize || {}),
    status: 'idle',
    enabled: false,
    cancelRequested: false,
    runningStartedAt: null,
    lastError: 'отменено пользователем',
  };
  item.live = { ...(item.live || {}), enabled: false };
  item.updatedAt = new Date().toISOString();
  await upsertObservation(item);
  return true;
}

async function applyFail(job, message) {
  const failCount = (Number(job.failCount) || 0) + 1;
  const waitMin = backoffMinutes(failCount);
  const nextAttemptAt = new Date(Date.now() + waitMin * 60 * 1000).toISOString();
  if (failCount >= MAX_FAIL_COUNT) {
    const item = await loadObservationById(job.id);
    if (item) {
      item.materialize = {
        ...(item.materialize || {}),
        enabled: false,
        status: 'error',
        failCount,
        nextAttemptAt: null,
        runningStartedAt: null,
        lastError: `остановлено после ${MAX_FAIL_COUNT} ошибок: ${message}`,
        cancelRequested: false,
      };
      item.live = { ...(item.live || {}), enabled: false };
      item.updatedAt = new Date().toISOString();
      await upsertObservation(item);
    }
    return { id: job.id, error: message, stopped: true, failCount };
  }
  await patchMaterializeStatus(job.id, {
    status: 'error',
    lastError: message,
    failCount,
    nextAttemptAt,
    runningStartedAt: null,
    lastCatchupAt: new Date().toISOString(),
  });
  return { id: job.id, error: message, failCount, nextAttemptAt };
}

function isTotalRollupRow(row) {
  return ROLLUP_DIM_COLUMNS.every((c) => !row[c]);
}

async function materializeWindow(job, from, to) {
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
    ...emptyRollupDims(),
    bytes: Number(p.bytes) || 0,
    packets: Number(p.packets) || 0,
    flows: Number(p.flows) || 0,
  }));

  const seriesLimit = Math.min(Math.max(Number(job.seriesLimit) || 20, 8), 50);
  const grouped = await catchupGrouped(job, window, seriesLimit);
  values.push(...grouped.values);

  const insertedTotalBytes = values
    .filter(isTotalRollupRow)
    .reduce((acc, row) => acc + (Number(row.bytes) || 0), 0);
  const sampleMinute = values[0]?.minute;
  const { elapsedMs: deleteMs } = await deleteRollupWindow(job.id, from, to);
  let insertMs = 0;
  if (values.length) {
    const insertStarted = Date.now();
    await insertRows(ROLLUP_TABLE, values, { name: `observations/rollup-insert-${job.id}` });
    insertMs = Date.now() - insertStarted;
  }

  let storedTotalBytes = null;
  let storedRatio = null;
  try {
    const { rows } = await query(`
      SELECT sum(bytes) AS bytes
      FROM default.${ROLLUP_TABLE}
      WHERE observation_id = {id:String}
        AND minute >= parseDateTimeBestEffort({from:String}, 'UTC')
        AND minute < parseDateTimeBestEffort({to:String}, 'UTC')
        AND dim0 = '' AND dim1 = '' AND dim2 = '' AND dim3 = ''
    `, {
      id: job.id,
      from: toChUtc(from),
      to: toChUtc(to),
    }, { name: `observations/rollup-verify-${job.id}` });
    storedTotalBytes = Number(rows[0]?.bytes) || 0;
    storedRatio = insertedTotalBytes > 0 ? storedTotalBytes / insertedTotalBytes : null;
  } catch (err) {
    console.warn(new Date().toISOString(), 'observation rollup verify failed', job.id, err.message);
  }

  const shotLog = {
    id: job.id,
    pid: process.pid,
    from: from.toISOString(),
    to: to.toISOString(),
    deleteMs,
    insertMs,
    insertRows: values.length,
    totalBuckets: totalPoints.length,
    groupedPoints: grouped.groupedPoints,
    insertedTotalBytes,
    storedTotalBytes,
    storedRatio,
    sampleMinute,
    sampleMinuteType: sampleMinute == null ? null : typeof sampleMinute,
  };
  if (storedRatio != null && storedRatio > 1.05) {
    console.error(new Date().toISOString(), 'observation rollup DOUBLE', JSON.stringify(shotLog));
  } else {
    console.log(new Date().toISOString(), 'observation rollup shot', JSON.stringify(shotLog));
  }
  return { totalPoints, groupedPoints: grouped.groupedPoints, storedRatio };
}

async function catchupBackfill(job, liveStart) {
  if (job.backfillDone || !job.backfillFrom) {
    return { id: job.id, skipped: true, reason: 'backfill_done' };
  }
  let from = floorToBucket(job.backfillCursor || job.backfillFrom);
  const end = floorToBucket(liveStart);
  if (!(from instanceof Date) || !Number.isFinite(from.getTime()) || from >= end) {
    await patchMaterializeStatus(job.id, {
      backfillDone: true,
      backfillCursor: end.toISOString(),
    });
    return { id: job.id, skipped: true, reason: 'backfill_done' };
  }
  let to = floorToBucket(new Date(from.getTime() + MAX_SHOT_MINUTES * 60 * 1000));
  if (to <= from) to = new Date(from.getTime() + BUCKET_MS);
  if (to > end) to = end;

  await patchMaterializeStatus(job.id, {
    status: 'running',
    runningStartedAt: new Date().toISOString(),
  });
  if (await honorCancel(job)) return { id: job.id, cancelled: true };

  try {
    const { totalPoints, groupedPoints } = await materializeWindow(job, from, to);
    const done = to >= end;
    await patchMaterializeStatus(job.id, {
      status: 'ok',
      lagSeconds: 0,
      backfillCursor: to.toISOString(),
      backfillDone: done,
      runningStartedAt: null,
      failCount: 0,
      nextAttemptAt: null,
      lastError: null,
      lastCatchupAt: new Date().toISOString(),
    });
    return {
      id: job.id,
      phase: 'backfill',
      points: totalPoints.length,
      groupedPoints,
      from,
      to,
      backfillDone: done,
    };
  } catch (err) {
    await applyFail(job, err.message);
    throw err;
  }
}

function isFreshRunning(job) {
  if (job.status !== 'running') return false;
  const startedMs = Date.parse(job.runningStartedAt || '');
  if (!Number.isFinite(startedMs)) return false;
  return (Date.now() - startedMs) <= STUCK_SEC * 1000;
}

async function catchupOne(job) {
  const intervalSec = Math.max(MIN_REFRESH_SEC, Number(job.intervalSec) || MIN_REFRESH_SEC);

  if (isFreshRunning(job)) {
    return { id: job.id, skipped: true, reason: 'already_running', pid: process.pid };
  }

  if (await honorCancel(job)) return { id: job.id, cancelled: true };

  if (job.nextAttemptAt) {
    const nextMs = Date.parse(job.nextAttemptAt);
    if (Number.isFinite(nextMs) && nextMs > Date.now()) {
      return { id: job.id, skipped: true, reason: 'backoff' };
    }
  }

  const safeTo = computeSafeTo();

  let from = resolveCatchupFrom(job, safeTo);
  if (from >= safeTo) {
    // Live caught up — optionally fill history at lower priority.
    if (!job.backfillDone && job.backfillFrom) {
      const liveStart = jobStartedBucket(job) || floorToBucket(job.startedAt || new Date());
      return catchupBackfill(job, liveStart);
    }
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
      dataThrough: new Date(safeTo.getTime() - BUCKET_MS).toISOString(),
      runningStartedAt: null,
    });
    return { id: job.id, skipped: true };
  }

  from = widenForRecheck(job, from);

  let to = safeTo;
  const maxSpanMs = MAX_SHOT_MINUTES * 60 * 1000;
  if (to - from > maxSpanMs) {
    to = floorToBucket(new Date(from.getTime() + maxSpanMs));
    if (to <= from) to = new Date(from.getTime() + BUCKET_MS);
    if (to > safeTo) to = safeTo;
  }

  await patchMaterializeStatus(job.id, {
    status: 'running',
    runningStartedAt: new Date().toISOString(),
  });
  if (await honorCancel(job)) return { id: job.id, cancelled: true };

  try {
    const { totalPoints, groupedPoints } = await materializeWindow(job, from, to);
    const lagSeconds = Math.max(0, Math.floor((Date.now() - to.getTime()) / 1000));
    await patchMaterializeStatus(job.id, {
      status: lagSeconds > intervalSec * 3 ? 'lagging' : 'ok',
      lagSeconds,
      lastCatchupAt: new Date().toISOString(),
      cursorMinute: to.toISOString(),
      dataThrough: new Date(to.getTime() - BUCKET_MS).toISOString(),
      lastError: null,
      failCount: 0,
      nextAttemptAt: null,
      runningStartedAt: null,
    });
    return {
      id: job.id,
      phase: 'live',
      points: totalPoints.length,
      groupedPoints,
      from,
      to,
      bucketSec: ROLLUP_BUCKET_SEC,
    };
  } catch (err) {
    await applyFail(job, err.message);
    throw err;
  }
}

async function recoverStuckRunning({ onStart = false } = {}) {
  const jobs = await listMaterializeJobs();
  let recovered = 0;
  for (const job of jobs) {
    if (job.status !== 'running') continue;
    const startedMs = Date.parse(job.runningStartedAt || '');
    const stuckByAge = Number.isFinite(startedMs)
      && (Date.now() - startedMs) > STUCK_SEC * 1000;
    // Periodic ticks only clear shots that exceeded STUCK_SEC.
    // Clearing a fresh `running` here starts a second INSERT into SummingMergeTree.
    if (!onStart && !stuckByAge) continue;
    await patchMaterializeStatus(job.id, {
      status: stuckByAge ? 'error' : 'queued',
      lastError: stuckByAge
        ? `превышено время выполнения (${STUCK_SEC}с)`
        : 'воркер перезапущен — продолжаем с cursor/start',
      runningStartedAt: null,
    });
    recovered += 1;
  }
  return recovered;
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
      `SELECT toUnixTimestamp(max(minute)) AS max_unix
       FROM default.${ROLLUP_TABLE}
       WHERE observation_id = {id:String}`,
      { id: job.id },
      { name: `observations/rollup-max-${job.id}` },
    );
    const maxUnix = Number(rows[0]?.max_unix);
    if (!Number.isFinite(maxUnix) || maxUnix <= 0) continue;
    // max(minute) is bucket start; exclusive cursor should be max + 5m
    const exclusiveEnd = new Date(maxUnix * 1000 + BUCKET_MS);
    if (new Date(job.cursorMinute) > exclusiveEnd) {
      console.warn(new Date().toISOString(), 'observation rollup rewind', JSON.stringify({
        id: job.id,
        cursorMinute: job.cursorMinute,
        maxUnix,
        exclusiveEnd: exclusiveEnd.toISOString(),
      }));
      await patchMaterializeStatus(job.id, {
        cursorMinute: exclusiveEnd.toISOString(),
        status: 'queued',
        lastError: null,
      });
    }
  }
  return { skipped: false };
}

function needsLiveCatchup(job, safeTo) {
  try {
    const from = resolveCatchupFrom(job, safeTo);
    return from < safeTo;
  } catch {
    return true;
  }
}

async function runOnce() {
  await ensureObservationsStore();
  await ensureTable();
  // Force rewind on cold start; later ticks throttle to REWIND_EVERY_MS.
  await rewindCursorsIfAhead({ force: !lastRewindAtMs });

  const safeTo = computeSafeTo();

  const jobs = (await listMaterializeJobs())
    .filter((j) => (
      j.status === 'queued'
      || j.status === 'lagging'
      || j.status === 'ok'
      || j.status === 'error'
      || j.status === 'idle'
    ))
    .sort((a, b) => {
      // Live catch-up before history backfill.
      const aLive = needsLiveCatchup(a, safeTo) ? 0 : 1;
      const bLive = needsLiveCatchup(b, safeTo) ? 0 : 1;
      if (aLive !== bLive) return aLive - bLive;
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

  const safeTo = computeSafeTo();

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

/** Delete+insert one [from, to) window. Does not move the live cursor. */
async function rematerializeRange(observationId, fromIso, toIso) {
  await ensureObservationsStore();
  await ensureTable();
  const jobs = await listMaterializeJobs();
  const job = jobs.find((j) => j.id === observationId);
  if (!job) {
    throw new Error(`Нет live-материализации для ${observationId}`);
  }
  const from = floorToBucket(new Date(fromIso));
  const to = floorToBucket(new Date(toIso));
  if (!(from instanceof Date) || !Number.isFinite(from.getTime()) || !(from < to)) {
    throw new Error(`Некорректное окно: ${fromIso} … ${toIso}`);
  }
  const { totalPoints, groupedPoints, storedRatio } = await materializeWindow(job, from, to);
  return {
    id: observationId,
    from: from.toISOString(),
    to: to.toISOString(),
    points: totalPoints.length,
    groupedPoints,
    storedRatio,
  };
}

module.exports = {
  runOnce,
  recoverStuckRunning,
  ensureTable,
  deleteRollupWindow,
  rebuildObservation,
  rematerializeRange,
  floorToBucket,
  computeSafeTo,
  widenForRecheck,
  SAFETY_BUCKETS,
  RECHECK_BUCKETS,
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
  if (mode === 'shot') {
    const id = process.argv[3];
    const fromIso = process.argv[4];
    const toIso = process.argv[5];
    if (!id || !fromIso || !toIso) {
      console.error('Usage: node server/observations-rollup.js shot <observationId> <fromIso> <toIso>');
      process.exit(1);
    }
    const out = await rematerializeRange(id, fromIso, toIso);
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  const recovered = await recoverStuckRunning({ onStart: true });
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
