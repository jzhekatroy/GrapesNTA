'use strict';

/**
 * Diagnostics for snmp-iface-sync (runs inside grapes-enrichment).
 * Job heartbeat from enrichment_job_status + live agent/interface counts.
 */

const { query, executeCommand, config } = require('./clickhouse');

const STATUS_TABLE = 'enrichment_job_status';
const JOB_ID = 'snmp-iface-sync';
const INTERVAL_SEC = 60;

let ensurePromise = null;

function ageSecFrom(isoOrDate, now = Date.now()) {
  if (isoOrDate == null || isoOrDate === '') return null;
  const t = isoOrDate instanceof Date ? isoOrDate.getTime() : Date.parse(String(isoOrDate));
  if (!Number.isFinite(t)) return null;
  return Math.max(0, Math.floor((now - t) / 1000));
}

// The poller stores "never happened" as the epoch, which would render as 1970.
function epochToNull(value) {
  const text = value == null ? '' : String(value);
  return !text || text.startsWith('1970-01-01') ? null : value;
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

async function ensureStatusTable() {
  if (!ensurePromise) {
    ensurePromise = executeCommand(`
      CREATE TABLE IF NOT EXISTS ${config.database}.${STATUS_TABLE}
      (
        job LowCardinality(String),
        status LowCardinality(String) DEFAULT 'idle',
        started_at Nullable(DateTime64(3)),
        finished_at Nullable(DateTime64(3)),
        duration_ms Nullable(UInt32),
        exit_code Nullable(Int32),
        message String DEFAULT '',
        log_tail String DEFAULT '',
        metrics_json String DEFAULT '{}',
        host String DEFAULT '',
        updated_at DateTime64(3) DEFAULT now64(3)
      )
      ENGINE = ReplacingMergeTree(updated_at)
      ORDER BY job
    `, {}, { name: 'diagnostics/ensure-snmp-status' }).catch((err) => {
      ensurePromise = null;
      throw err;
    });
  }
  return ensurePromise;
}

async function loadJobStatus() {
  await ensureStatusTable();
  try {
    const { rows } = await query(`
      SELECT
        job, status, started_at, finished_at, duration_ms, exit_code,
        message, log_tail, metrics_json, host, updated_at
      FROM ${config.database}.${STATUS_TABLE} FINAL
      WHERE job = {job:String}
      LIMIT 1
    `, { job: JOB_ID }, { name: 'diagnostics/snmp-status' });
    return { row: rows[0] || null, error: null };
  } catch (err) {
    return { row: null, error: err.message };
  }
}

async function loadAgentStats() {
  try {
    const { rows } = await query(`
      SELECT
        count() AS total,
        countIf(snmp_enabled = 1) AS enabled,
        countIf(snmp_enabled = 0) AS disabled,
        countIf(snmp_enabled = 1 AND last_poll_status = 'ok') AS ok,
        countIf(snmp_enabled = 1 AND last_poll_status = 'queued') AS queued,
        countIf(snmp_enabled = 1 AND last_poll_status = 'never') AS never,
        countIf(snmp_enabled = 1 AND last_poll_status = 'timeout') AS timeout,
        countIf(snmp_enabled = 1 AND last_poll_status = 'auth_error') AS auth_error,
        countIf(snmp_enabled = 1 AND last_poll_status IN ('error', 'config_error')) AS error,
        max(last_poll_at) AS last_poll_at,
        max(last_ok_at) AS last_ok_at,
        -- Enabled agents that have never answered at all.
        countIf(snmp_enabled = 1 AND last_ok_at = toDateTime(0, 'UTC')) AS never_ok
      FROM ${config.database}.net_snmp_agents_current
    `, {}, { name: 'diagnostics/snmp-agents' });
    const r = rows[0] || {};
    return {
      total: Number(r.total) || 0,
      enabled: Number(r.enabled) || 0,
      disabled: Number(r.disabled) || 0,
      ok: Number(r.ok) || 0,
      queued: Number(r.queued) || 0,
      never: Number(r.never) || 0,
      timeout: Number(r.timeout) || 0,
      authError: Number(r.auth_error) || 0,
      error: Number(r.error) || 0,
      lastPollAt: toIsoLoose(r.last_poll_at),
      lastOkAt: epochToNull(toIsoLoose(r.last_ok_at)),
      neverOk: Number(r.never_ok) || 0,
      errorMessage: null,
    };
  } catch (err) {
    return {
      total: 0, enabled: 0, disabled: 0, ok: 0, queued: 0, never: 0,
      timeout: 0, authError: 0, error: 0, lastPollAt: null, lastOkAt: null,
      neverOk: 0, errorMessage: err.message,
    };
  }
}

async function loadSettingsSummary() {
  try {
    const { rows } = await query(`
      SELECT
        enabled,
        port,
        timeout_ms,
        retries,
        refresh_interval_sec,
        length(community) AS community_len,
        updated_at
      FROM ${config.database}.net_snmp_settings_current
      WHERE settings_id = 'global'
      LIMIT 1
    `, {}, { name: 'diagnostics/snmp-settings' });
    const r = rows[0];
    if (!r) {
      return { present: false, errorMessage: 'нет строки global в net_snmp_settings_current' };
    }
    return {
      present: true,
      enabled: Number(r.enabled) === 1,
      port: Number(r.port) || 161,
      timeoutMs: Number(r.timeout_ms) || 0,
      retries: Number(r.retries) || 0,
      refreshIntervalSec: Number(r.refresh_interval_sec) || 0,
      hasCommunity: Number(r.community_len) > 0,
      updatedAt: toIsoLoose(r.updated_at),
      errorMessage: null,
    };
  } catch (err) {
    return { present: false, errorMessage: err.message };
  }
}

async function loadInterfaceCount() {
  try {
    const { rows } = await query(`
      SELECT count() AS c, max(updated_at) AS mx
      FROM ${config.database}.net_interfaces
    `, {}, { name: 'diagnostics/snmp-interfaces' });
    const r = rows[0] || {};
    return {
      count: Number(r.c) || 0,
      maxTs: toIsoLoose(r.mx),
      ageSec: ageSecFrom(toIsoLoose(r.mx)),
      errorMessage: null,
    };
  } catch (err) {
    return { count: null, maxTs: null, ageSec: null, errorMessage: err.message };
  }
}

function buildProblems({ job, agents, settings, interfaces }) {
  const problems = [];

  if (settings.errorMessage) {
    problems.push(problem('critical', 'snmp_settings_missing', `Настройки SNMP: ${settings.errorMessage}`));
  } else if (!settings.present) {
    problems.push(problem('critical', 'snmp_settings_missing', 'Нет global-настроек SNMP (schema/seed не применены)'));
  } else {
    if (!settings.enabled) {
      problems.push(problem('warning', 'snmp_disabled', 'Глобальный SNMP polling выключен'));
    }
    if (!settings.hasCommunity) {
      problems.push(problem('warning', 'snmp_no_community', 'Community не задан — опрос свитчей невозможен'));
    }
  }

  if (agents.errorMessage) {
    problems.push(problem('critical', 'snmp_agents_read_failed', `Не удалось прочитать агентов: ${agents.errorMessage}`));
  }

  if (job.error) {
    problems.push(problem('critical', 'snmp_status_read_failed', `Не удалось прочитать ${STATUS_TABLE}: ${job.error}`));
  } else if (!job.row) {
    problems.push(problem(
      'warning',
      'snmp_never_ran',
      'snmp-iface-sync ещё не писал статус (контейнер grapes-enrichment не запущен или джоба не стартовала)',
    ));
  } else {
    const status = String(job.row.status || '');
    const exitCode = job.row.exit_code != null ? Number(job.row.exit_code) : null;
    if (status === 'error' || (exitCode != null && exitCode !== 0 && status !== 'skipped')) {
      problems.push(problem(
        'critical',
        'snmp_job_error',
        `snmp-iface-sync: ошибка (exit=${exitCode ?? '?'}) — ${job.row.message || 'см. лог'}`,
      ));
    }
    if (status === 'running' && job.row.started_at) {
      const runAge = ageSecFrom(toIsoLoose(job.row.started_at));
      if (runAge != null && runAge > 15 * 60) {
        problems.push(problem(
          'warning',
          'snmp_job_stuck',
          `snmp-iface-sync: status=running уже ${Math.round(runAge / 60)} мин`,
        ));
      }
    }
    const finishAge = ageSecFrom(toIsoLoose(job.row.finished_at || job.row.updated_at));
    if (status !== 'running' && finishAge != null && finishAge > INTERVAL_SEC * 3 + 120) {
      problems.push(problem(
        'warning',
        'snmp_stale',
        `snmp-iface-sync: последний прогон ${Math.round(finishAge / 60)} мин назад`,
      ));
    }
  }

  if (agents.enabled > 0) {
    if (agents.timeout > 0 && agents.ok === 0 && interfaces.count === 0) {
      problems.push(problem(
        'critical',
        'snmp_all_timeout',
        `Все опросы падают в timeout (${agents.timeout} агентов), интерфейсов 0. `
          + 'Скорее всего с хоста nta нет маршрута/ACL до mgmt-сети свитчей (UDP/161). '
          + '«Опросить всех» ставит в очередь — поллер работает, но ответа от железа нет.',
      ));
    } else if (agents.timeout > 0 && agents.ok === 0) {
      const okAge = ageSecFrom(agents.lastOkAt);
      problems.push(problem(
        'critical',
        'snmp_all_timeout_cached',
        `Ни один свитч не отвечает (${agents.timeout} агентов в timeout). `
          + (okAge != null
            ? `Последний успешный опрос — ${Math.round(okAge / 3600)} ч назад, `
              + 'в UI показан устаревший каталог портов. '
            : 'Успешных опросов не было вообще. ')
          + 'Проверьте маршрут/ACL до mgmt-сети свитчей (UDP/161).',
      ));
    } else if (agents.timeout > 0 && agents.timeout >= agents.ok) {
      problems.push(problem(
        'warning',
        'snmp_many_timeouts',
        `Timeout у ${agents.timeout} из ${agents.enabled} включённых агентов (ok=${agents.ok})`,
      ));
    }
    if (agents.authError > 0) {
      problems.push(problem(
        'warning',
        'snmp_auth_errors',
        `auth_error у ${agents.authError} агентов — проверьте community`,
      ));
    }
    if (agents.queued > 0) {
      problems.push(problem(
        'warning',
        'snmp_queue_pending',
        `В очереди на опрос: ${agents.queued} (поллер берёт до 25 за цикл ~1 мин)`,
      ));
    }
  }

  if (interfaces.errorMessage) {
    problems.push(problem('warning', 'snmp_interfaces_read_failed', interfaces.errorMessage));
  }

  return problems;
}

async function getSnmpDiagnostics() {
  const [job, agents, settings, interfaces] = await Promise.all([
    loadJobStatus(),
    loadAgentStats(),
    loadSettingsSummary(),
    loadInterfaceCount(),
  ]);

  const row = job.row;
  const status = row ? String(row.status || 'idle') : 'idle';
  const problems = buildProblems({ job, agents, settings, interfaces });

  return {
    service: 'snmp-iface-sync',
    serviceLabel: 'SNMP (snmp-iface-sync)',
    description: 'Джоба внутри grapes-enrichment: discovery sFlow exporters + SNMP v2c poll → net_snmp_agents / net_interfaces.',
    updatedAt: new Date().toISOString(),
    problems,
    summary: {
      problemCount: problems.length,
      criticalCount: problems.filter((p) => p.level === 'critical').length,
      agentsEnabled: agents.enabled,
      agentsOk: agents.ok,
      agentsTimeout: agents.timeout,
      agentsQueued: agents.queued,
      interfaces: interfaces.count,
    },
    job: {
      id: JOB_ID,
      label: 'snmp-iface-sync',
      intervalSec: INTERVAL_SEC,
      status,
      startedAt: row ? toIsoLoose(row.started_at) : null,
      finishedAt: row ? toIsoLoose(row.finished_at) : null,
      updatedAt: row ? toIsoLoose(row.updated_at) : null,
      durationMs: row?.duration_ms != null ? Number(row.duration_ms) : null,
      exitCode: row?.exit_code != null ? Number(row.exit_code) : null,
      message: row ? String(row.message || '') : '',
      logTail: row ? String(row.log_tail || '') : '',
      host: row ? String(row.host || '') : null,
      neverRan: !row,
      finishAgeSec: ageSecFrom(toIsoLoose(row?.finished_at || row?.updated_at)),
    },
    settings,
    agents,
    interfaces,
    statusTable: STATUS_TABLE,
  };
}

module.exports = {
  getSnmpDiagnostics,
};
