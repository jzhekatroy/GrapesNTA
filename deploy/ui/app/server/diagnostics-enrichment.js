'use strict';

/**
 * Diagnostics for grapes-enrichment jobs (geo/RIR, bgp-origin, asn-names, iptoasn).
 * Status comes from enrichment_job_status + live table counts.
 */

const { query, executeCommand, config } = require('./clickhouse');

const STATUS_TABLE = 'enrichment_job_status';
const JOBS = [
  {
    id: 'bgp-origin',
    label: 'bgp-origin',
    intervalSec: 300,
    tables: ['bgp_prefix_origin_current'],
  },
  {
    id: 'geoloaderd',
    label: 'geoloaderd (FTP/RIR)',
    intervalSec: 86400,
    tables: ['geo_prefix_country', 'asn_registry'],
  },
  {
    id: 'asn-names',
    label: 'asn-names',
    intervalSec: 604800,
    tables: ['asn_names'],
  },
  {
    id: 'iptoasn',
    label: 'iptoasn (IP→ASN fallback)',
    intervalSec: 86400,
    tables: ['ip_asn_prefixes_current'],
  },
  // snmp-iface-sync has its own Diagnostics tab (see diagnostics-snmp.js).
];

let ensurePromise = null;

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
    `, {}, { name: 'diagnostics/ensure-enrichment-status' }).catch((err) => {
      ensurePromise = null;
      throw err;
    });
  }
  return ensurePromise;
}

async function loadJobStatusRows() {
  await ensureStatusTable();
  try {
    const { rows } = await query(`
      SELECT
        job,
        status,
        started_at,
        finished_at,
        duration_ms,
        exit_code,
        message,
        log_tail,
        metrics_json,
        host,
        updated_at
      FROM ${config.database}.${STATUS_TABLE} FINAL
      WHERE job IN {jobs:Array(String)}
    `, { jobs: JOBS.map((j) => j.id) }, { name: 'diagnostics/enrichment-status' });
    return rows;
  } catch (err) {
    return { error: err.message, rows: [] };
  }
}

async function loadTableMetrics() {
  const specs = [
    { table: 'geo_prefix_country', timeCol: 'snapshot_ts' },
    { table: 'asn_registry', timeCol: 'snapshot_ts' },
    { table: 'bgp_prefix_origin_current', timeCol: 'snapshot_ts' },
    { table: 'asn_names', timeCol: 'updated_at' },
    { table: 'ip_asn_prefixes_current', timeCol: 'snapshot_ts' },
  ];
  const out = {};
  await Promise.all(specs.map(async (s) => {
    try {
      const { rows } = await query(`
        SELECT
          count() AS c,
          max(${s.timeCol}) AS mx
        FROM ${config.database}.${s.table}
      `, {}, { name: `diagnostics/enrichment-table-${s.table}` });
      const r = rows[0] || {};
      out[s.table] = {
        count: Number(r.c) || 0,
        maxTs: toIsoLoose(r.mx),
        ageSec: ageSecFrom(toIsoLoose(r.mx)),
        error: null,
      };
    } catch (err) {
      out[s.table] = { count: null, maxTs: null, ageSec: null, error: err.message };
    }
  }));
  return out;
}

function parseMetrics(jsonStr) {
  try {
    const v = JSON.parse(String(jsonStr || '{}'));
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}

function buildJobs(statusRows, tables, now = Date.now()) {
  const byId = {};
  const list = Array.isArray(statusRows) ? statusRows : [];
  for (const r of list) {
    byId[String(r.job)] = r;
  }

  return JOBS.map((meta) => {
    const r = byId[meta.id];
    const status = r ? String(r.status || 'idle') : 'idle';
    const finishedAt = r ? toIsoLoose(r.finished_at) : null;
    const startedAt = r ? toIsoLoose(r.started_at) : null;
    const updatedAt = r ? toIsoLoose(r.updated_at) : null;
    const finishAgeSec = ageSecFrom(finishedAt || updatedAt, now);
    const staleAfter = meta.intervalSec * 2 + 600;
    const tableStats = meta.tables.map((t) => ({ table: t, ...(tables[t] || {}) }));
    const emptyTables = tableStats.filter((t) => t.count === 0);
    return {
      id: meta.id,
      label: meta.label,
      intervalSec: meta.intervalSec,
      optional: meta.optional === true,
      status,
      startedAt,
      finishedAt,
      updatedAt,
      durationMs: r?.duration_ms != null ? Number(r.duration_ms) : null,
      exitCode: r?.exit_code != null ? Number(r.exit_code) : null,
      message: r ? String(r.message || '') : '',
      logTail: r ? String(r.log_tail || '') : '',
      metrics: r ? parseMetrics(r.metrics_json) : {},
      host: r ? String(r.host || '') : null,
      finishAgeSec,
      stale: status !== 'running' && finishAgeSec != null && finishAgeSec > staleAfter,
      neverRan: !r,
      tables: tableStats,
      emptyTables: emptyTables.map((t) => t.table),
    };
  });
}

function buildProblems(jobs) {
  const problems = [];
  for (const j of jobs) {
    if (j.status === 'error' || (j.exitCode != null && j.exitCode !== 0 && j.status !== 'skipped')) {
      problems.push(problem(
        'critical',
        'enrichment_job_error',
        `${j.label}: ошибка (exit=${j.exitCode ?? '?'}) — ${j.message || 'см. лог'}`,
        { job: j.id },
      ));
    }
    if (j.status === 'running' && j.startedAt) {
      const runAge = ageSecFrom(j.startedAt);
      const maxRun = j.id === 'geoloaderd' ? 3 * 3600
        : (j.id === 'asn-names' ? 2 * 3600
          : (j.id === 'iptoasn' ? 3600 : 30 * 60));
      if (runAge != null && runAge > maxRun) {
        problems.push(problem(
          'warning',
          'enrichment_job_stuck',
          `${j.label}: status=running уже ${Math.round(runAge / 60)} мин`,
          { job: j.id },
        ));
      }
    }
    if (j.neverRan && !j.optional) {
      problems.push(problem(
        'warning',
        'enrichment_never_ran',
        `${j.label}: ещё не было записей в enrichment_job_status`,
        { job: j.id },
      ));
    } else if (j.stale && j.id === 'bgp-origin') {
      problems.push(problem(
        'warning',
        'enrichment_stale',
        `${j.label}: последний успешный прогон давно (${Math.round((j.finishAgeSec || 0) / 60)} мин)`,
        { job: j.id },
      ));
    }
    if (j.emptyTables.length && j.status !== 'running' && !j.optional) {
      problems.push(problem(
        'warning',
        'enrichment_empty_table',
        `${j.label}: пустые таблицы — ${j.emptyTables.join(', ')}`,
        { job: j.id },
      ));
    }
  }
  return problems;
}

async function getEnrichmentDiagnostics() {
  const [statusRaw, tables] = await Promise.all([
    loadJobStatusRows(),
    loadTableMetrics(),
  ]);
  const statusError = Array.isArray(statusRaw) ? null : statusRaw.error;
  const statusRows = Array.isArray(statusRaw) ? statusRaw : (statusRaw.rows || []);
  const jobs = buildJobs(statusRows, tables);
  const problems = buildProblems(jobs);
  if (statusError) {
    problems.unshift(problem('critical', 'enrichment_status_read_failed', `Не удалось прочитать ${STATUS_TABLE}: ${statusError}`));
  }

  return {
    service: 'grapes-enrichment',
    serviceLabel: 'grapes-enrichment',
    description: 'geo/RIR FTP, bgp-origin rebuild, asn-names (Team Cymru), iptoasn (IP→ASN fallback). SNMP — отдельная вкладка.',
    updatedAt: new Date().toISOString(),
    problems,
    summary: {
      problemCount: problems.length,
      criticalCount: problems.filter((p) => p.level === 'critical').length,
      running: jobs.filter((j) => j.status === 'running').length,
      errors: jobs.filter((j) => j.status === 'error').length,
      ok: jobs.filter((j) => j.status === 'ok').length,
    },
    jobs,
    tables,
    statusTable: STATUS_TABLE,
    statusError,
  };
}

module.exports = {
  getEnrichmentDiagnostics,
  JOBS,
};
