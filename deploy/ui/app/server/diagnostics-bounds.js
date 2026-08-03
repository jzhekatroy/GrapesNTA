'use strict';

/**
 * Diagnostics for bounds-service (CI bounds config.yaml for monitoring).
 */

const {
  boundsServiceUrl,
  boundsServiceToken,
  boundsServiceFetch,
  parseBoundsConfig,
} = require('./monitoring-bounds-config');
const { listParameterIds, getParameter } = require('./monitoring-intervals');

function env(name, fallback = '') {
  return process.env[name] ?? fallback;
}

function problem(level, code, message, meta = {}) {
  return { level, code, message, ...meta };
}

async function probeHealth() {
  const base = boundsServiceUrl();
  if (!base) {
    return { ok: false, latencyMs: null, error: 'Не настроен BOUNDS_SERVICE_URL' };
  }

  const started = Date.now();
  try {
    const response = await fetch(`${base}/health`, { headers: { Accept: 'application/json' } });
    const latencyMs = Date.now() - started;
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      return { ok: false, latencyMs, error: `HTTP ${response.status}` };
    }
    return { ok: true, latencyMs, error: null };
  } catch (err) {
    return {
      ok: false,
      latencyMs: Date.now() - started,
      error: `bounds-service недоступен (${err.message})`,
    };
  }
}

async function probeConfig() {
  const started = Date.now();
  try {
    const apiData = await boundsServiceFetch('/config/bounds');
    return {
      ok: true,
      latencyMs: Date.now() - started,
      mode: apiData.mode || env('BOUNDS_MODE', 'local'),
      configPath: apiData.configPath || env('BOUNDS_CONFIG_PATH', ''),
      host: env('BOUNDS_SSH_HOST', '') || null,
      apiData,
      error: null,
      status: null,
    };
  } catch (err) {
    return {
      ok: false,
      latencyMs: Date.now() - started,
      mode: null,
      configPath: null,
      host: env('BOUNDS_SSH_HOST', '') || null,
      apiData: null,
      error: err.message,
      status: err.status || null,
    };
  }
}

function buildParameters(apiData) {
  if (!apiData) return [];
  const boundsByParameter = parseBoundsConfig(apiData);
  return listParameterIds().map((id) => {
    const param = getParameter(id);
    const bounds = boundsByParameter[id] || {};
    return {
      id,
      label: param.label,
      section: param.boundsConfigKey,
      boundsRequiresCiMinimum: param.boundsRequiresCiMinimum !== false,
      ciLow: Number.isFinite(bounds.ciLow) ? bounds.ciLow : null,
      ciHigh: Number.isFinite(bounds.ciHigh) ? bounds.ciHigh : null,
      ciMinimum: Number.isFinite(bounds.ciMinimum) ? bounds.ciMinimum : null,
    };
  });
}

function buildProblems({ urlConfigured, health, config, parameters }) {
  const problems = [];

  if (!urlConfigured) {
    problems.push(problem(
      'critical',
      'bounds_url_missing',
      'Не настроен BOUNDS_SERVICE_URL для bounds-service',
    ));
    return problems;
  }

  if (!health.ok) {
    problems.push(problem(
      'critical',
      'bounds_unreachable',
      health.error || 'bounds-service не отвечает на /health',
    ));
  }

  if (!config.ok) {
    if (config.status === 401) {
      problems.push(problem(
        'critical',
        'bounds_auth_failed',
        config.error || 'Не удалось авторизоваться в bounds-service',
      ));
    } else {
      problems.push(problem(
        'critical',
        'bounds_config_unreadable',
        config.error || 'Не удалось прочитать config.yaml',
      ));
    }
  }

  if (config.ok && config.mode === 'ssh' && !config.host) {
    problems.push(problem(
      'warning',
      'bounds_ssh_host_missing',
      'Режим SSH, но BOUNDS_SSH_HOST не задан в grapes-nta',
    ));
  }

  for (const p of parameters) {
    const missingMinimum = p.boundsRequiresCiMinimum && p.ciMinimum == null;
    if (p.ciLow == null || p.ciHigh == null || missingMinimum) {
      problems.push(problem(
        'warning',
        'bounds_value_missing',
        `В config.yaml не найдены границы для ${p.label} (${p.id})`,
        { parameterId: p.id },
      ));
    }
  }

  return problems;
}

async function getBoundsDiagnostics() {
  const serviceUrl = boundsServiceUrl();
  const urlConfigured = Boolean(serviceUrl);
  const tokenConfigured = Boolean(boundsServiceToken());

  const emptyConfig = {
    ok: false,
    latencyMs: null,
    mode: null,
    configPath: null,
    host: env('BOUNDS_SSH_HOST', '') || null,
    apiData: null,
    error: 'URL не настроен',
    status: null,
  };

  const [health, config] = await Promise.all([
    probeHealth(),
    urlConfigured ? probeConfig() : Promise.resolve(emptyConfig),
  ]);

  const parameters = buildParameters(config.apiData);
  const problems = buildProblems({ urlConfigured, health, config, parameters });

  return {
    service: 'bounds-service',
    serviceLabel: 'Сервис управления границами',
    description: 'Хранение CI-границ для мониторинга ШПД в config.yaml (local или SSH).',
    updatedAt: new Date().toISOString(),
    problems,
    summary: {
      problemCount: problems.length,
      criticalCount: problems.filter((p) => p.level === 'critical').length,
      alive: health.ok,
      configOk: config.ok,
      mode: config.mode || env('BOUNDS_MODE', 'local'),
    },
    connection: {
      urlConfigured,
      serviceUrl: serviceUrl || null,
      tokenConfigured,
    },
    health,
    config: {
      ok: config.ok,
      latencyMs: config.latencyMs,
      mode: config.mode,
      configPath: config.configPath,
      host: config.host,
      loadedAt: config.ok ? new Date().toISOString() : null,
      error: config.error,
    },
    parameters,
  };
}

module.exports = {
  getBoundsDiagnostics,
};
