const CACHE_TTL_MS = 5 * 60 * 1000;
let cache = { loadedAt: 0, config: null };

function env(name, fallback = '') {
  return process.env[name] ?? fallback;
}

function boundsServiceUrl() {
  return String(env('BOUNDS_SERVICE_URL', '')).replace(/\/$/, '');
}

function boundsServiceToken() {
  return env('BOUNDS_SERVICE_TOKEN', '');
}

function mapHttpError(status, message) {
  if (status === 503 && /Не настроен/.test(message)) return message;
  if (status === 404) return message || 'config.yaml не найден';
  if (status === 400) return message || 'Некорректный запрос';
  if (status === 401) return 'Не удалось авторизоваться в bounds-service';
  return message || 'Не удалось загрузить config.yaml';
}

async function boundsServiceFetch(path, { method = 'GET', body } = {}) {
  const base = boundsServiceUrl();
  if (!base) {
    throw new Error('Не настроен BOUNDS_SERVICE_URL для bounds-service');
  }

  const headers = { Accept: 'application/json' };
  const token = boundsServiceToken();
  if (token) headers['X-Bounds-Token'] = token;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  let response;
  try {
    response = await fetch(`${base}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (err) {
    throw new Error(`bounds-service недоступен (${err.message})`);
  }

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = mapHttpError(response.status, payload.error || response.statusText);
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return payload;
}

function parseBoundsConfig(apiData) {
  const intervals = apiData?.intervals || {};
  const countryRu = apiData?.intervals_country_ru || {};
  const countryForeign = apiData?.intervals_country_F || {};

  return {
    broadband_total: {
      ciLow: Number(intervals.ci_low),
      ciHigh: Number(intervals.ci_high),
      ciMinimum: Number(intervals.ci_minimum),
      source: 'intervals',
    },
    broadband_in_ru: {
      ciLow: Number(countryRu.ci_low),
      ciHigh: Number(countryRu.ci_high),
      ciMinimum: Number(countryRu.ci_minimum),
      source: 'intervals_country_ru',
    },
    broadband_in_foreign: {
      ciLow: Number(countryForeign.ci_low),
      ciHigh: Number(countryForeign.ci_high),
      ciMinimum: Number(countryForeign.ci_minimum),
      source: 'intervals_country_F',
    },
  };
}

async function loadBoundsConfig({ force = false } = {}) {
  const now = Date.now();
  if (!force && cache.config && now - cache.loadedAt < CACHE_TTL_MS) {
    return cache.config;
  }

  const apiData = await boundsServiceFetch('/config/bounds');
  const boundsByParameter = parseBoundsConfig(apiData);

  cache = {
    loadedAt: now,
    config: {
      mode: apiData.mode || env('BOUNDS_MODE', 'local'),
      configPath: apiData.configPath || env('BOUNDS_CONFIG_PATH', ''),
      host: env('BOUNDS_SSH_HOST', ''),
      loadedAt: new Date(now).toISOString(),
      boundsByParameter,
    },
    error: null,
  };

  return cache.config;
}

function invalidateBoundsCache() {
  cache = { loadedAt: 0, config: null, error: null };
}

async function getMonitoringBounds(parameterId) {
  const { getParameter } = require('./monitoring-intervals');
  const param = getParameter(parameterId);
  if (!param) throw new Error(`Неизвестный показатель: ${parameterId}`);

  const configData = await loadBoundsConfig();
  const bounds = configData.boundsByParameter[param.id];
  if (!bounds
    || !Number.isFinite(bounds.ciLow)
    || !Number.isFinite(bounds.ciHigh)
    || !Number.isFinite(bounds.ciMinimum)) {
    throw new Error(`В config.yaml не найдены границы для показателя ${param.id}`);
  }

  return {
    parameter: param.id,
    label: param.label,
    unit: param.unit,
    featureName: param.featureName,
    configKey: param.boundsConfigKey,
    ciLow: bounds.ciLow,
    ciHigh: bounds.ciHigh,
    ciMinimum: bounds.ciMinimum,
    source: bounds.source,
    mode: configData.mode,
    host: configData.host || null,
    configPath: configData.configPath,
    loadedAt: configData.loadedAt,
  };
}

async function saveMonitoringBounds(parameterId, { ciLow, ciHigh, ciMinimum }) {
  const { getParameter } = require('./monitoring-intervals');
  const param = getParameter(parameterId);
  if (!param) throw new Error(`Неизвестный показатель: ${parameterId}`);

  const low = Number(ciLow);
  const high = Number(ciHigh);
  const minimum = Number(ciMinimum);
  if (!Number.isFinite(low) || !Number.isFinite(high) || !Number.isFinite(minimum)) {
    throw new Error('Границы должны быть числами');
  }

  await boundsServiceFetch('/config/bounds', {
    method: 'PUT',
    body: {
      section: param.boundsConfigKey,
      ci_low: low,
      ci_high: high,
      ci_minimum: minimum,
    },
  });

  invalidateBoundsCache();
  return getMonitoringBounds(parameterId);
}

module.exports = {
  boundsServiceUrl,
  boundsServiceToken,
  boundsServiceFetch,
  parseBoundsConfig,
  loadBoundsConfig,
  invalidateBoundsCache,
  getMonitoringBounds,
  saveMonitoringBounds,
};
