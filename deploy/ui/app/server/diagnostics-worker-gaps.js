'use strict';

/**
 * Gap scan + backfill enqueue for grapes-worker traffic/observation rollups.
 * UI has no Docker access — requests go into a ClickHouse queue table that the
 * worker drains each minute.
 *
 * Gap detection is clamped to the actual data range present in the scan window
 * (first..last existing bucket per table), so leading emptiness (before first
 * ingest) and trailing lag are never reported as gaps — only interior holes.
 */

const { query, executeCommand, config } = require('./clickhouse');
const { loadAllObservations } = require('./observations-store');
const { ROLLUP_TABLE } = require('./observations');

const QUEUE_TABLE = 'traffic_rollup_backfill_queue';

/** 1m tables used for gap detection (bucket column = minute). */
const SCAN_1M_JOBS = [
  { job: 'traffic_dashboard_1m', table: 'traffic_dashboard_1m' },
  { job: 'traffic_protocol_1m', table: 'traffic_protocol_1m' },
  { job: 'traffic_direction_1m', table: 'traffic_direction_1m' },
  { job: 'traffic_role_1m', table: 'traffic_role_1m' },
  { job: 'traffic_vlan_1m', table: 'traffic_vlan_1m' },
  { job: 'traffic_country_1m', table: 'traffic_country_1m' },
  { job: 'traffic_service_1m', table: 'traffic_service_1m' },
  { job: 'traffic_unknown_port_1m', table: 'traffic_unknown_port_1m' },
  { job: 'traffic_asn_1m', table: 'traffic_asn_1m' },
  { job: 'traffic_asn_pair_1m', table: 'traffic_asn_pair_1m' },
];

const DEFAULT_BACKFILL_JOBS = [
  'traffic_dashboard_1m',
  'traffic_protocol_1m',
  'traffic_direction_1m',
  'traffic_role_1m',
  'traffic_entity_1m',
  'traffic_vlan_1m',
  'traffic_country_1m',
  'traffic_service_1m',
  'traffic_unknown_port_1m',
  'traffic_asn_1m',
  'traffic_asn_pair_1m',
  'traffic_dashboard_1h',
  'traffic_asn_1h',
  'traffic_asn_pair_1h',
  'traffic_dashboard_1d',
];

const MAX_SCAN_DAYS = 31;
const MAX_BACKFILL_WINDOW_MS = 7 * 24 * 3600 * 1000;
const MAX_QUEUE_WINDOWS = 30;
/** Observation rollups are 5m buckets; pad gap start so a partial bucket
 *  immediately before the detected hole is rewritten (underfill after CH outage). */
const OBS_BUCKET_MS = 5 * 60 * 1000;
/** Traffic 1m: pad one closed minute before the hole for the same reason. */
const TRAFFIC_BUCKET_MS = 60 * 1000;

function clampDays(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return 3;
  return Math.min(MAX_SCAN_DAYS, Math.max(1, Math.floor(n)));
}

function toChUtc(d) {
  const dt = d instanceof Date ? d : new Date(d);
  const pad = (n) => String(n).padStart(2, '0');
  return `${dt.getUTCFullYear()}-${pad(dt.getUTCMonth() + 1)}-${pad(dt.getUTCDate())} `
    + `${pad(dt.getUTCHours())}:${pad(dt.getUTCMinutes())}:${pad(dt.getUTCSeconds())}`;
}

function toIsoLoose(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date) return value.toISOString();
  const s = String(value).trim();
  if (!s) return null;
  if (s.includes('T')) return s.endsWith('Z') ? s : `${s}Z`;
  return `${s.replace(' ', 'T')}Z`;
}

/** Merge sorted missing bucket ISO strings into ranges (step in ms). */
function mergeMinutes(missingIso, stepMs) {
  const out = [];
  if (!missingIso.length) return out;
  let start = missingIso[0];
  let prev = missingIso[0];
  for (let i = 1; i < missingIso.length; i += 1) {
    const prevMs = Date.parse(prev);
    const curMs = Date.parse(missingIso[i]);
    if (Number.isFinite(prevMs) && Number.isFinite(curMs) && curMs - prevMs === stepMs) {
      prev = missingIso[i];
      continue;
    }
    out.push({ from: start, toExclusive: new Date(Date.parse(prev) + stepMs).toISOString() });
    start = missingIso[i];
    prev = missingIso[i];
  }
  out.push({ from: start, toExclusive: new Date(Date.parse(prev) + stepMs).toISOString() });
  return out;
}

/**
 * Expand a backfill window's start by one bucket before the detected hole.
 * Interior holes often leave the preceding closed bucket underfilled (partial
 * insert during CH outage); gap-scan only sees missing minutes, not underfill.
 */
function padBackfillWindow(window, includeObservations) {
  const fromMs = Date.parse(toIsoLoose(window.from));
  const toMs = Date.parse(toIsoLoose(window.to));
  if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || !(fromMs < toMs)) {
    return window;
  }
  const padMs = includeObservations ? OBS_BUCKET_MS : TRAFFIC_BUCKET_MS;
  // Floor to the pad unit, then step one bucket earlier.
  const floored = Math.floor(fromMs / padMs) * padMs;
  const paddedFrom = new Date(floored - padMs);
  const fromIso = paddedFrom.toISOString();
  const toIso = new Date(toMs).toISOString();
  return {
    ...window,
    from: fromIso,
    to: toIso,
    minutes: Math.round((toMs - paddedFrom.getTime()) / 60000),
  };
}

/** Union a list of {from,toExclusive} across jobs, merging with a tolerance (ms). */
function unionWindows(ranges, tolMs) {
  const norm = ranges
    .map((r) => ({ a: Date.parse(r.from), b: Date.parse(r.toExclusive) }))
    .filter((r) => Number.isFinite(r.a) && Number.isFinite(r.b) && r.b > r.a)
    .sort((x, y) => x.a - y.a);
  const merged = [];
  for (const cur of norm) {
    const last = merged[merged.length - 1];
    if (last && cur.a - last.b <= tolMs) {
      if (cur.b > last.b) last.b = cur.b;
    } else {
      merged.push({ ...cur });
    }
  }
  return merged.map((m) => ({
    from: new Date(m.a).toISOString(),
    to: new Date(m.b).toISOString(),
    minutes: Math.round((m.b - m.a) / 60000),
  }));
}

async function ensureQueueTable() {
  await executeCommand(`
    CREATE TABLE IF NOT EXISTS ${config.database}.${QUEUE_TABLE}
    (
      request_id String,
      created_at DateTime64(3, 'UTC') DEFAULT now64(3),
      from_minute DateTime('UTC'),
      to_minute DateTime('UTC'),
      jobs Array(String) DEFAULT [],
      include_observations UInt8 DEFAULT 1,
      status LowCardinality(String) DEFAULT 'pending',
      error String DEFAULT '',
      progress_job String DEFAULT '',
      progress_minute DateTime('UTC') DEFAULT toDateTime(0, 'UTC'),
      updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY request_id
    TTL toDateTime(created_at) + toIntervalDay(30)
    SETTINGS index_granularity = 8192
  `, {}, { name: 'diagnostics/ensure-backfill-queue' });
}

async function scanJobGaps(table, t0Ch, t1Ch) {
  // Clamp to [first..last present bucket] within the window, then anti-join.
  // NOT IN is used deliberately: on DateTime('UTC') the LEFT JOIN ... IS NULL
  // anti-join has falsely reported zero gaps on nta after a CH outage.
  const { rows } = await query(`
    WITH
      toDateTime({t0:String}, 'UTC') AS w0,
      toDateTime({t1:String}, 'UTC') AS w1,
      (SELECT min(minute) FROM ${config.database}.${table} WHERE minute >= w0 AND minute <= w1) AS dmin,
      (SELECT max(minute) FROM ${config.database}.${table} WHERE minute >= w0 AND minute <= w1) AS dmax
    SELECT ts AS missing
    FROM (
      SELECT assumeNotNull(dmin) + INTERVAL number MINUTE AS ts
      FROM numbers(toUInt64(ifNull(if(dmax >= dmin AND dmin > toDateTime('2000-01-01', 'UTC'),
                      dateDiff('minute', dmin, dmax) + 1, 0), 0)))
    )
    WHERE ts NOT IN (
      SELECT minute FROM ${config.database}.${table} WHERE minute >= dmin AND minute <= dmax
    )
    ORDER BY missing
  `, { t0: t0Ch, t1: t1Ch }, { name: `diagnostics/gaps-${table}` });

  const missing = (rows || [])
    .map((r) => toIsoLoose(r.missing))
    .filter(Boolean)
    .map((iso) => iso.replace(/\.\d{3}Z$/, 'Z'));
  const ranges = mergeMinutes(missing, 60_000);
  return {
    missingCount: missing.length,
    ranges: ranges.slice(0, 60),
  };
}

async function scanObservationGaps(t0Ch, t1Ch) {
  const all = await loadAllObservations();
  const candidates = all.filter((o) => o && !o.deleted && o.materialize?.enabled);
  const out = [];
  for (const o of candidates) {
    const { rows } = await query(`
      WITH
        toStartOfFiveMinutes(toDateTime({t0:String}, 'UTC')) AS w0,
        toStartOfFiveMinutes(toDateTime({t1:String}, 'UTC')) AS w1,
        (SELECT toStartOfFiveMinutes(min(minute)) FROM ${config.database}.${ROLLUP_TABLE}
          WHERE observation_id = {id:String} AND dim0 = '' AND dim1 = ''
            AND minute >= w0 AND minute <= w1) AS dmin,
        (SELECT toStartOfFiveMinutes(max(minute)) FROM ${config.database}.${ROLLUP_TABLE}
          WHERE observation_id = {id:String} AND dim0 = '' AND dim1 = ''
            AND minute >= w0 AND minute <= w1) AS dmax
      SELECT ts AS missing
      FROM (
        SELECT assumeNotNull(dmin) + INTERVAL (number * 5) MINUTE AS ts
        FROM numbers(toUInt64(ifNull(if(dmax >= dmin AND dmin > toDateTime('2000-01-01', 'UTC'),
                        intDiv(dateDiff('minute', dmin, dmax), 5) + 1, 0), 0)))
      )
      WHERE ts NOT IN (
        SELECT minute FROM ${config.database}.${ROLLUP_TABLE}
        WHERE observation_id = {id:String} AND dim0 = '' AND dim1 = ''
          AND minute >= dmin AND minute <= dmax
      )
      ORDER BY missing
    `, { t0: t0Ch, t1: t1Ch, id: o.id }, { name: `diagnostics/obs-gaps-${o.id}` });

    const missing = (rows || [])
      .map((r) => toIsoLoose(r.missing))
      .filter(Boolean)
      .map((iso) => iso.replace(/\.\d{3}Z$/, 'Z'));
    const ranges = mergeMinutes(missing, 300_000);
    out.push({
      kind: 'observation',
      id: o.id,
      name: o.name || o.id,
      missingCount: missing.length,
      ranges: ranges.slice(0, 60),
    });
  }
  return out;
}

/**
 * Resolve scan window from options.
 * opts: { days } OR { from, to } (ISO / datetime-local strings, treated as UTC).
 * Returns { fromIso, toIso, t0Ch, t1Ch, days }.
 */
function resolveWindow(opts = {}) {
  const now = Date.now();
  if (opts.from && opts.to) {
    const a = new Date(toIsoLoose(opts.from));
    const b = new Date(toIsoLoose(opts.to));
    if (!Number.isFinite(a.getTime()) || !Number.isFinite(b.getTime()) || !(a < b)) {
      const err = new Error('Некорректный диапазон from/to');
      err.status = 400;
      throw err;
    }
    return {
      fromIso: a.toISOString(),
      toIso: b.toISOString(),
      t0Ch: toChUtc(a),
      t1Ch: toChUtc(b),
      days: null,
    };
  }
  const days = clampDays(opts.days);
  const t1 = new Date(now - 2 * 60_000);
  const t0 = new Date(now - days * 24 * 3600 * 1000);
  return {
    fromIso: t0.toISOString(),
    toIso: t1.toISOString(),
    t0Ch: toChUtc(t0),
    t1Ch: toChUtc(t1),
    days,
  };
}

async function scanGaps(opts = {}) {
  const win = resolveWindow(opts);
  const traffic = [];
  for (const spec of SCAN_1M_JOBS) {
    try {
      const gap = await scanJobGaps(spec.table, win.t0Ch, win.t1Ch);
      traffic.push({ kind: 'traffic', job: spec.job, table: spec.table, ...gap });
    } catch (err) {
      traffic.push({
        kind: 'traffic', job: spec.job, table: spec.table,
        missingCount: null, error: err.message, ranges: [],
      });
    }
  }

  let observations = [];
  let observationsError = null;
  try {
    observations = await scanObservationGaps(win.t0Ch, win.t1Ch);
  } catch (err) {
    observationsError = err.message;
  }

  const trafficWithGaps = traffic.filter((t) => (t.missingCount || 0) > 0);
  const obsWithGaps = observations.filter((o) => (o.missingCount || 0) > 0);

  // Union of every gap range (traffic 1m + observation 5m) → windows to backfill.
  // Merge with a 5-minute tolerance so tiny adjacent holes coalesce.
  const allRanges = [
    ...trafficWithGaps.flatMap((t) => t.ranges || []),
    ...obsWithGaps.flatMap((o) => o.ranges || []),
  ];
  // Do not pad here — enqueueBackfill pads once so the UI preview stays honest
  // about the detected hole while the rewrite quietly includes the prior bucket.
  let gapWindows = unionWindows(allRanges, 5 * 60_000).slice(0, MAX_QUEUE_WINDOWS);
  const totalGapMinutes = gapWindows.reduce((s, w) => s + w.minutes, 0);

  let earliest = null;
  let latest = null;
  for (const w of gapWindows) {
    if (!earliest || Date.parse(w.from) < Date.parse(earliest)) earliest = w.from;
    if (!latest || Date.parse(w.to) > Date.parse(latest)) latest = w.to;
  }

  return {
    window: { from: win.fromIso, to: win.toIso, days: win.days },
    scannedAt: new Date().toISOString(),
    traffic,
    observations,
    observationsError,
    gapWindows,
    summary: {
      hasGaps: gapWindows.length > 0,
      windowCount: gapWindows.length,
      totalGapMinutes,
      trafficJobsWithGaps: trafficWithGaps.length,
      observationJobsWithGaps: obsWithGaps.length,
      earliest,
      latest,
    },
  };
}

async function listBackfillQueue(limit = 12) {
  await ensureQueueTable();
  const { rows } = await query(`
    SELECT
      request_id AS requestId,
      created_at AS createdAt,
      from_minute AS fromMinute,
      to_minute AS toMinute,
      jobs,
      include_observations AS includeObservations,
      status,
      error,
      progress_job AS progressJob,
      progress_minute AS progressMinute,
      updated_at AS updatedAt
    FROM ${config.database}.${QUEUE_TABLE} FINAL
    ORDER BY created_at DESC
    LIMIT {lim:UInt32}
  `, { lim: Math.min(50, Math.max(1, Number(limit) || 12)) }, { name: 'diagnostics/backfill-queue' });

  return (rows || []).map((r) => {
    const fromMs = Date.parse(toIsoLoose(r.fromMinute));
    const toMs = Date.parse(toIsoLoose(r.toMinute));
    const progIso = toIsoLoose(r.progressMinute);
    const progMs = progIso ? Date.parse(progIso) : NaN;
    const jobs = Array.isArray(r.jobs) ? r.jobs.map(String) : [];
    const includeObs = Boolean(Number(r.includeObservations));
    // Backfill walks jobs in order; each job restarts at from_minute. Percent must
    // include job index — otherwise the bar snaps back near 0% on every new job.
    const steps = Math.max(1, jobs.length + (includeObs ? 1 : 0));
    const progressJob = String(r.progressJob || '');
    let jobIdx = progressJob ? jobs.indexOf(progressJob) : -1;
    if (jobIdx < 0 && progressJob) jobIdx = 0;
    if (jobIdx < 0 && String(r.status) === 'running') jobIdx = 0;

    let percent = null;
    if (String(r.status) === 'done') {
      percent = 100;
    } else if (Number.isFinite(fromMs) && Number.isFinite(toMs) && toMs > fromMs) {
      let within = 0;
      if (Number.isFinite(progMs) && progMs >= fromMs) {
        within = Math.max(0, Math.min(1, (progMs - fromMs) / (toMs - fromMs)));
      }
      const completedJobs = Math.max(0, jobIdx);
      percent = Math.max(
        0,
        Math.min(99, Math.round(((completedJobs + within) / steps) * 100)),
      );
      if (String(r.status) === 'pending' && !progressJob) percent = 0;
    }
    return {
      requestId: String(r.requestId || ''),
      createdAt: toIsoLoose(r.createdAt),
      fromMinute: toIsoLoose(r.fromMinute),
      toMinute: toIsoLoose(r.toMinute),
      jobs,
      includeObservations: includeObs,
      status: String(r.status || ''),
      error: String(r.error || '') || null,
      progressJob: progressJob || null,
      progressMinute: progIso && progIso !== '1970-01-01T00:00:00Z' ? progIso : null,
      updatedAt: toIsoLoose(r.updatedAt),
      percent,
    };
  });
}

async function insertQueueRow({ requestId, fromDt, toDt, jobList, includeObservations }) {
  await executeCommand(`
    INSERT INTO ${config.database}.${QUEUE_TABLE}
      (request_id, created_at, from_minute, to_minute, jobs, include_observations,
       status, error, progress_job, progress_minute, updated_at)
    VALUES (
      {id:String},
      now64(3),
      toDateTime({from:String}, 'UTC'),
      toDateTime({to:String}, 'UTC'),
      {jobs:Array(String)},
      {inc:UInt8},
      'pending',
      '',
      '',
      toDateTime(0, 'UTC'),
      now64(3)
    )
  `, {
    id: requestId,
    from: toChUtc(fromDt),
    to: toChUtc(toDt),
    jobs: jobList,
    inc: includeObservations ? 1 : 0,
  }, { name: 'diagnostics/enqueue-backfill' });
}

/**
 * Enqueue backfill.
 * Accepts either:
 *   { ranges: [{from,to}, ...] }  — enqueue one queue row per gap window (only gaps), OR
 *   { from, to }                  — single explicit window.
 */
async function enqueueBackfill({ ranges = null, from = null, to = null,
  includeObservations = true, jobs = null } = {}) {
  await ensureQueueTable();

  let windows = [];
  if (Array.isArray(ranges) && ranges.length) {
    windows = ranges;
  } else if (from && to) {
    windows = [{ from, to }];
  } else {
    const err = new Error('Не передан диапазон пересчёта');
    err.status = 400;
    throw err;
  }

  const normalized = [];
  for (const w of windows) {
    const padded = padBackfillWindow(w, includeObservations);
    const a = new Date(toIsoLoose(padded.from));
    const b = new Date(toIsoLoose(padded.to));
    if (!Number.isFinite(a.getTime()) || !Number.isFinite(b.getTime()) || !(a < b)) {
      const err = new Error('Некорректное окно пересчёта');
      err.status = 400;
      throw err;
    }
    if (b.getTime() - a.getTime() > MAX_BACKFILL_WINDOW_MS) {
      const err = new Error('Окно пересчёта не больше 7 дней');
      err.status = 400;
      throw err;
    }
    normalized.push({ a, b });
  }
  if (normalized.length > MAX_QUEUE_WINDOWS) {
    const err = new Error(`Слишком много окон (${normalized.length}), максимум ${MAX_QUEUE_WINDOWS}`);
    err.status = 400;
    throw err;
  }

  const active = await listBackfillQueue(5);
  if (active.some((r) => r.status === 'pending' || r.status === 'running')) {
    const err = new Error('Уже есть активный запрос в очереди — дождитесь завершения или отмените его');
    err.status = 409;
    throw err;
  }

  const jobList = Array.isArray(jobs) && jobs.length ? jobs.map(String) : DEFAULT_BACKFILL_JOBS;
  const stamp = Date.now();
  const created = [];
  let idx = 0;
  for (const { a, b } of normalized) {
    const requestId = `bf-${stamp}-${idx}-${Math.random().toString(36).slice(2, 6)}`;
    idx += 1;
    // eslint-disable-next-line no-await-in-loop
    await insertQueueRow({ requestId, fromDt: a, toDt: b, jobList, includeObservations });
    created.push({ requestId, from: a.toISOString(), to: b.toISOString() });
  }

  return {
    enqueued: created.length,
    windows: created,
    jobs: jobList,
    includeObservations: Boolean(includeObservations),
    totalMinutes: normalized.reduce((s, w) => s + Math.round((w.b - w.a) / 60000), 0),
  };
}

/** Mark all pending/running requests as cancelled so the worker stops draining. */
async function cancelBackfill() {
  await ensureQueueTable();
  const active = await listBackfillQueue(50);
  const targets = active.filter((r) => r.status === 'pending' || r.status === 'running');
  for (const r of targets) {
    // eslint-disable-next-line no-await-in-loop
    await executeCommand(`
      INSERT INTO ${config.database}.${QUEUE_TABLE}
        (request_id, created_at, from_minute, to_minute, jobs, include_observations,
         status, error, progress_job, progress_minute, updated_at)
      VALUES (
        {id:String},
        toDateTime64({created:String}, 3, 'UTC'),
        toDateTime({from:String}, 'UTC'),
        toDateTime({to:String}, 'UTC'),
        {jobs:Array(String)},
        {inc:UInt8},
        'cancelled',
        'отменено оператором',
        {pjob:String},
        toDateTime({pmin:String}, 'UTC'),
        now64(3)
      )
    `, {
      id: r.requestId,
      created: toChUtc(new Date(r.createdAt || Date.now())),
      from: toChUtc(new Date(r.fromMinute)),
      to: toChUtc(new Date(r.toMinute)),
      jobs: r.jobs,
      inc: r.includeObservations ? 1 : 0,
      pjob: r.progressJob || '',
      pmin: r.progressMinute ? toChUtc(new Date(r.progressMinute)) : '1970-01-01 00:00:00',
    }, { name: 'diagnostics/cancel-backfill' });
  }
  return { cancelled: targets.length };
}

module.exports = {
  scanGaps,
  enqueueBackfill,
  listBackfillQueue,
  cancelBackfill,
  DEFAULT_BACKFILL_JOBS,
  SCAN_1M_JOBS,
};
