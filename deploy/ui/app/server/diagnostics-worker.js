'use strict';

/**
 * Operational diagnostics for grapes-worker (observations loop + traffic rollups).
 * Does not talk to Docker — status comes from CH heartbeat / traffic_rollup_state.
 */

const { getMergedDiagnosticsPayload } = require('./analytics-diagnostics');
const { query, config } = require('./clickhouse');
const { loadAllObservations } = require('./observations-store');
const {
  classifyScope,
  ROLLUP_TABLE,
  MAX_MATERIALIZE,
  MIN_REFRESH_SEC,
} = require('./observations');

const TRAFFIC_STATE_TABLE = 'traffic_rollup_state';
const DASHBOARD_JOB = 'traffic_dashboard_1m';
/** Soft lag (seconds) after which a 1m traffic job is flagged. Includes ~5m safety lag. */
const TRAFFIC_1M_LAG_WARN_SEC = 12 * 60;
/** How long since last successful run before we treat a job as stuck (not bucket age). */
const TRAFFIC_1M_STALE_UPDATE_SEC = 15 * 60;
const TRAFFIC_1H_STALE_UPDATE_SEC = 2 * 3600;
const TRAFFIC_1D_STALE_UPDATE_SEC = 30 * 3600;
/**
 * Jobs grapes-worker actually runs (deploy/worker cron / traffic-rollups).
 * Everything else in traffic_rollup_state is legacy noise (IP talker/pair,
 * old experiments). Client cabinet jobs are part of the same timer.
 */
const ACTIVE_TRAFFIC_JOBS = [
  'traffic_dashboard_1m',
  'traffic_protocol_1m',
  'traffic_direction_1m',
  'traffic_role_1m',
  'traffic_entity_1m',
  'traffic_client_1m',
  'traffic_vlan_1m',
  'traffic_country_1m',
  'traffic_service_1m',
  'traffic_unknown_port_1m',
  'traffic_dashboard_1h',
  'traffic_client_1h',
  'traffic_client_country_1h',
  'traffic_client_service_1h',
  'dns_client_domain_1h',
  'traffic_dashboard_1d',
  'traffic_client_1d',
  'traffic_client_country_1d',
  'traffic_client_service_1d',
  'traffic_asn_1m',
  'traffic_asn_1h',
  'traffic_asn_pair_1m',
  'traffic_asn_pair_1h',
];
const ACTIVE_TRAFFIC_JOB_SET = new Set(ACTIVE_TRAFFIC_JOBS);
const OBS_QUEUED_STUCK_SEC = 10 * 60;
const OBS_CURSOR_STUCK_SEC = 15 * 60;

function ageSecFrom(isoOrDate, now = Date.now()) {
  if (isoOrDate == null || isoOrDate === '') return null;
  const t = isoOrDate instanceof Date ? isoOrDate.getTime() : Date.parse(String(isoOrDate));
  if (!Number.isFinite(t)) return null;
  return Math.max(0, Math.floor((now - t) / 1000));
}

function toIsoLoose(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date) return value.toISOString();
  const s = String(value).trim();
  if (!s) return null;
  if (s.includes('T')) return s.endsWith('Z') ? s : `${s}Z`;
  return `${s.replace(' ', 'T')}Z`;
}

function problem(level, code, message, meta = {}) {
  return { level, code, message, ...meta };
}

function trafficStaleUpdateSec(jobName) {
  if (jobName.endsWith('_1d')) return TRAFFIC_1D_STALE_UPDATE_SEC;
  if (jobName.endsWith('_1h')) return TRAFFIC_1H_STALE_UPDATE_SEC;
  return TRAFFIC_1M_STALE_UPDATE_SEC;
}

function trafficBucketLagWarnSec(jobName) {
  if (jobName.endsWith('_1d')) return 40 * 3600; // yesterday bucket is normal until next day run
  if (jobName.endsWith('_1h')) return 2 * 3600;
  return TRAFFIC_1M_LAG_WARN_SEC;
}

async function loadTrafficRollupState() {
  try {
    const { rows } = await query(`
      SELECT
        job,
        last_bucket,
        status,
        last_error,
        rows_written,
        duration_ms,
        updated_at
      FROM ${config.database}.${TRAFFIC_STATE_TABLE} FINAL
      WHERE job IN {jobs:Array(String)}
    `, { jobs: ACTIVE_TRAFFIC_JOBS }, { name: 'diagnostics/traffic-rollup-state' });
    const now = Date.now();
    const mapped = rows
      .filter((r) => ACTIVE_TRAFFIC_JOB_SET.has(String(r.job || '')))
      .map((r) => {
        const jobName = String(r.job || '');
        const lastBucket = toIsoLoose(r.last_bucket);
        const updatedAt = toIsoLoose(r.updated_at);
        const bucketLagSec = ageSecFrom(lastBucket, now);
        const updateAgeSec = ageSecFrom(updatedAt, now);
        const status = String(r.status || '');
        const lagWarnSec = trafficBucketLagWarnSec(jobName);
        const updateWarnSec = trafficStaleUpdateSec(jobName);
        const failed = status === 'failed' || status === 'error';
        // Prefer "did the job run recently?" over raw bucket age (1d/1h buckets lag by design).
        const staleRun = updateAgeSec != null && updateAgeSec > updateWarnSec;
        const staleBucket = jobName.endsWith('_1m')
          && bucketLagSec != null
          && bucketLagSec > lagWarnSec;
        const stale = !failed && (staleRun || staleBucket);
        return {
          job: jobName,
          lastBucket,
          status,
          lastError: String(r.last_error || '') || null,
          rowsWritten: Number(r.rows_written) || 0,
          durationMs: r.duration_ms != null ? Number(r.duration_ms) : null,
          updatedAt,
          bucketLagSec,
          updateAgeSec,
          stale,
          lagWarnSec,
        };
      });

    const order = new Map(ACTIVE_TRAFFIC_JOBS.map((j, i) => [j, i]));
    mapped.sort((a, b) => {
      const ra = a.status === 'failed' || a.status === 'error' || a.stale ? 0 : 1;
      const rb = b.status === 'failed' || b.status === 'error' || b.stale ? 0 : 1;
      if (ra !== rb) return ra - rb;
      return (order.get(a.job) ?? 999) - (order.get(b.job) ?? 999);
    });
    return mapped;
  } catch (err) {
    return { error: err.message, rows: [] };
  }
}

async function loadObservationRollupMax(ids) {
  if (!ids.length) return { byId: {}, error: null };
  try {
    const { rows } = await query(`
      SELECT
        observation_id,
        toTimeZone(max(minute), 'UTC') AS max_minute,
        count() AS row_count
      FROM ${config.database}.${ROLLUP_TABLE}
      WHERE observation_id IN {ids:Array(String)}
      GROUP BY observation_id
    `, { ids }, { name: 'diagnostics/obs-rollup-stats' });
    const byId = Object.fromEntries(
      rows.filter((r) => r.observation_id).map((r) => [String(r.observation_id), r]),
    );
    return { byId, error: null };
  } catch (err) {
    return { byId: {}, error: err.message };
  }
}

function tickResultByObsId(lastTick) {
  const map = {};
  const list = Array.isArray(lastTick?.rollup) ? lastTick.rollup : [];
  for (const entry of list) {
    if (!entry || entry.id == null) continue;
    map[String(entry.id)] = entry;
  }
  return map;
}

function buildObservationJobs(all, rollupById, lastTick) {
  const now = Date.now();
  const tickById = tickResultByObsId(lastTick);
  // Live всегда включён, поэтому в диагностике интересны те, кому нужна подготовка данных.
  const candidates = all.filter((o) => (
    o.materialize?.enabled || classifyScope(o.filters, o.widgets).materializeRequired
  ));

  return candidates.map((o) => {
    const scope = classifyScope(o.filters, o.widgets);
    const mat = o.materialize || {};
    const live = o.live || {};
    const materializeEnabled = Boolean(mat.enabled);
    const workerWillPick = materializeEnabled && scope.materializeRequired;

    let skipReason = null;
    if (scope.materializeRequired && !materializeEnabled) {
      skipReason = 'подготовка данных выключена — воркер не возьмёт job';
    } else if (materializeEnabled && !scope.materializeRequired) {
      skipReason = 'scope native (нет фильтров/группировок) — materialize не нужен, воркер пропускает';
    } else if (!workerWillPick) {
      skipReason = 'воркер не выбирает этот job';
    }

    const st = rollupById[o.id];
    const maxMinute = st?.max_minute ? toIsoLoose(st.max_minute) : null;
    const cursorMinute = mat.cursorMinute ? toIsoLoose(mat.cursorMinute) : null;
    const cursorAgeSec = ageSecFrom(cursorMinute, now);
    const lastCatchupAt = mat.lastCatchupAt ? toIsoLoose(mat.lastCatchupAt) : null;
    const lastCatchupAgeSec = ageSecFrom(lastCatchupAt, now);
    const status = String(mat.status || (materializeEnabled ? 'queued' : 'idle'));
    const lastError = mat.lastError ? String(mat.lastError) : null;
    const tick = tickById[o.id] || null;

    return {
      id: o.id,
      name: o.name,
      createdAt: o.createdAt,
      updatedAt: o.updatedAt,
      liveEnabled: true,
      materializeEnabled,
      workerWillPick,
      skipReason,
      scope: {
        tier: scope.tier,
        materializeRequired: scope.materializeRequired,
        reason: scope.reason || null,
        fields: scope.fields || [],
      },
      materialize: {
        status,
        intervalSec: Number(mat.intervalSec) || Number(live.refreshSec) || MIN_REFRESH_SEC,
        cursorMinute,
        cursorAgeSec,
        lagSeconds: mat.lagSeconds != null ? Number(mat.lagSeconds) : null,
        lastCatchupAt,
        lastCatchupAgeSec,
        lastError,
      },
      rollup: {
        table: ROLLUP_TABLE,
        maxMinute,
        rowCount: st?.row_count != null ? Number(st.row_count) : null,
      },
      lastTickResult: tick,
    };
  }).sort((a, b) => {
    const rank = (j) => {
      if (j.materialize.lastError || j.materialize.status === 'error') return 0;
      if (j.skipReason) return 1;
      if (j.workerWillPick && (j.materialize.status === 'queued' || j.materialize.status === 'lagging')) return 2;
      if (j.workerWillPick) return 3;
      return 4;
    };
    return rank(a) - rank(b) || String(a.name).localeCompare(String(b.name));
  });
}

function buildProblems({ worker, jobs, trafficRows, trafficError }) {
  const problems = [];

  if (!worker?.alive) {
    problems.push(problem(
      'critical',
      'worker_offline',
      `grapes-worker (analytics loop) не отвечает: ${worker?.statusReason || worker?.status || 'offline'}`,
      { heartbeatAgeSec: worker?.heartbeatAgeSec ?? null },
    ));
  }
  if (worker?.lastError) {
    problems.push(problem('critical', 'worker_tick_error', `Ошибка последнего tick: ${worker.lastError}`));
  }

  for (const j of jobs) {
    if (j.scope.materializeRequired && !j.materializeEnabled) {
      problems.push(problem(
        'warning',
        'obs_live_without_materialize',
        `«${j.name}»: подготовка данных выключена — график и топ будут пустыми`,
        { observationId: j.id },
      ));
    }
    if (j.workerWillPick && j.materialize.status === 'error') {
      problems.push(problem(
        'critical',
        'obs_materialize_error',
        `«${j.name}»: materialize status=error${j.materialize.lastError ? ` — ${j.materialize.lastError}` : ''}`,
        { observationId: j.id },
      ));
    }
    if (j.workerWillPick && j.materialize.status === 'queued'
      && (j.materialize.cursorAgeSec == null || j.materialize.cursorAgeSec > OBS_QUEUED_STUCK_SEC)
      && (j.materialize.lastCatchupAgeSec == null || j.materialize.lastCatchupAgeSec > OBS_QUEUED_STUCK_SEC)) {
      problems.push(problem(
        'warning',
        'obs_queued_stuck',
        `«${j.name}»: status=queued, catch-up давно не было — воркер не продвигает cursor`,
        { observationId: j.id, status: j.materialize.status },
      ));
    }
    if (j.workerWillPick && j.materialize.status === 'lagging') {
      problems.push(problem(
        'warning',
        'obs_lagging',
        `«${j.name}»: lagging (lag=${j.materialize.lagSeconds ?? '—'}s)`,
        { observationId: j.id },
      ));
    }
    if (j.workerWillPick && j.materialize.status === 'ok'
      && j.materialize.cursorAgeSec != null && j.materialize.cursorAgeSec > OBS_CURSOR_STUCK_SEC) {
      problems.push(problem(
        'warning',
        'obs_cursor_stale',
        `«${j.name}»: cursor старше ${Math.round(j.materialize.cursorAgeSec / 60)} мин при status=ok`,
        { observationId: j.id },
      ));
    }
    if (j.workerWillPick && !j.rollup.maxMinute && j.materialize.status !== 'queued') {
      problems.push(problem(
        'warning',
        'obs_no_rollup_rows',
        `«${j.name}»: в ${ROLLUP_TABLE} нет строк (воркер ещё не записал или падает)`,
        { observationId: j.id },
      ));
    }
    if (j.lastTickResult?.error) {
      problems.push(problem(
        'critical',
        'obs_last_tick_error',
        `«${j.name}»: ошибка в последнем tick — ${j.lastTickResult.error}`,
        { observationId: j.id },
      ));
    }
  }

  if (trafficError) {
    problems.push(problem('warning', 'traffic_state_read_failed', `Не удалось прочитать ${TRAFFIC_STATE_TABLE}: ${trafficError}`));
  }

  for (const r of trafficRows) {
    if (r.status === 'failed' || r.status === 'error') {
      problems.push(problem(
        'critical',
        'traffic_job_failed',
        `Traffic rollup «${r.job}»: status=${r.status}${r.lastError ? ` — ${r.lastError}` : ''}`,
        { job: r.job },
      ));
    } else if (r.stale) {
      // Prefer the metric that actually crossed the threshold — updateAgeSec can be
      // ~3m (talkers cron */5) while last_bucket lag is what made the job stale.
      const updateWarnSec = trafficStaleUpdateSec(r.job);
      const staleRun = r.updateAgeSec != null && r.updateAgeSec > updateWarnSec;
      const ageSec = staleRun
        ? r.updateAgeSec
        : (r.bucketLagSec ?? r.updateAgeSec ?? 0);
      const ageMin = Math.round(ageSec / 60);
      const msg = staleRun
        ? `Traffic «${r.job}»: давно не обновлялся (~${ageMin} мин)`
        : `Traffic «${r.job}»: last_bucket отстаёт (~${ageMin} мин)`;
      problems.push(problem(
        'warning',
        'traffic_job_stale',
        msg,
        { job: r.job, updateAgeSec: r.updateAgeSec, bucketLagSec: r.bucketLagSec },
      ));
    }
  }

  const activeMat = jobs.filter((j) => j.workerWillPick).length;
  if (MAX_MATERIALIZE > 0 && activeMat > MAX_MATERIALIZE) {
    problems.push(problem(
      'warning',
      'obs_quota',
      `Активных materialize jobs: ${activeMat} (лимит ${MAX_MATERIALIZE})`,
    ));
  }

  return problems;
}

async function getWorkerDiagnostics() {
  const diag = await getMergedDiagnosticsPayload();
  const all = await loadAllObservations();
  const liveOrMatIds = all.map((o) => o.id);

  const [{ byId: rollupById, error: rollupStatsError }, traffic] = await Promise.all([
    loadObservationRollupMax(liveOrMatIds),
    loadTrafficRollupState(),
  ]);

  const trafficRows = Array.isArray(traffic) ? traffic : (traffic.rows || []);
  const trafficError = Array.isArray(traffic) ? null : (traffic.error || null);

  const allJobs = buildObservationJobs(all, rollupById, diag.lastTick);
  // Only actionable rows: worker picks them, or the observation needs data it does not get.
  const jobs = allJobs.filter((j) => j.workerWillPick || j.skipReason);
  const problems = buildProblems({
    worker: diag.worker,
    jobs: allJobs,
    trafficRows,
    trafficError,
  });

  const dashboard = trafficRows.find((r) => r.job === DASHBOARD_JOB) || null;
  const recentQueries = (Array.isArray(diag.queries) ? diag.queries : []).slice(0, 30);
  const queries = recentQueries
    .filter((q) => q && (q.error || Number(q.elapsedMs) >= 500))
    .slice(0, 20);

  return {
    service: 'grapes-worker',
    serviceLabel: 'grapes-worker',
    description: 'Observations analytics loop + traffic/ASN/client rollups (Docker).',
    updatedAt: new Date().toISOString(),
    problems,
    summary: {
      workerAlive: Boolean(diag.worker?.alive),
      problemCount: problems.length,
      criticalCount: problems.filter((p) => p.level === 'critical').length,
      observationJobs: jobs.length,
      workerWillPick: jobs.filter((j) => j.workerWillPick).length,
      trafficJobs: trafficRows.length,
      trafficFailed: trafficRows.filter((r) => r.status === 'failed' || r.status === 'error').length,
      trafficStale: trafficRows.filter((r) => r.stale).length,
      dashboardLagSec: dashboard?.bucketLagSec ?? null,
      dashboardStatus: dashboard?.status ?? null,
    },
    worker: {
      ...diag.worker,
      containerHint: 'grapes-worker',
    },
    lastTick: diag.lastTick || null,
    recentQueries,
    queries,
    storePath: diag.storePath || null,
    observations: {
      jobs,
      rollupTable: ROLLUP_TABLE,
      rollupStatsError,
      maxMaterialize: MAX_MATERIALIZE,
    },
    trafficRollups: {
      rows: trafficRows,
      error: trafficError,
      stateTable: TRAFFIC_STATE_TABLE,
      activeJobs: ACTIVE_TRAFFIC_JOBS,
    },
  };
}

module.exports = {
  getWorkerDiagnostics,
};
