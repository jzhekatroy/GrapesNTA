'use strict';

(function explorerQueryDslModule() {
  const EXPLORER_DEFAULT_METRIC_KEYS = ['bps', 'volume', 'pps', 'fps', 'flows', 'uniq_src'];
  const EXPLORER_DEFAULT_FETCH_LIMIT = 25;
  const EXPLORER_MAX_FETCH_LIMIT = 10000;

  function metricKeysFromSchema(schema) {
    const fromKeys = Array.isArray(schema?.metricKeys) ? schema.metricKeys : [];
    if (fromKeys.length) return fromKeys.map((k) => String(k).trim()).filter(Boolean);
    const fromMetrics = Array.isArray(schema?.metrics)
      ? schema.metrics.map((m) => String(m?.id ?? '').trim()).filter(Boolean)
      : [];
    if (fromMetrics.length) return fromMetrics;
    return [...EXPLORER_DEFAULT_METRIC_KEYS];
  }

  function maxFetchFromSchema(schema) {
    const n = Number(schema?.maxLimit);
    return Number.isFinite(n) && n > 0 ? n : EXPLORER_MAX_FETCH_LIMIT;
  }

  function resolveExplorerFetchLimit(queryLimit, maxLimit = EXPLORER_MAX_FETCH_LIMIT) {
    const cap = Number(maxLimit);
    const max = Number.isFinite(cap) && cap > 0 ? cap : EXPLORER_MAX_FETCH_LIMIT;
    const n = Math.floor(Number(queryLimit));
    if (!Number.isFinite(n) || n <= 0) return EXPLORER_DEFAULT_FETCH_LIMIT;
    return Math.min(Math.max(n, 1), max);
  }

  function isExplorerMetricDslLine(line) {
    return /^metric\s+\S/i.test(String(line || '').trim());
  }

  function isExplorerLimitDslLine(line) {
    return /^limit\s+\S/i.test(String(line || '').trim());
  }

  function parseExplorerMetricDslLine(line, schema) {
    const trimmed = String(line || '').trim();
    const match = trimmed.match(/^metric\s+(\S+)\s*$/i);
    if (!match) {
      throw new Error('ожидается строка metric <id>');
    }
    const raw = match[1].trim();
    const keys = metricKeysFromSchema(schema);
    const keySet = new Set(keys.map((k) => k.toLowerCase()));
    const lower = raw.toLowerCase();
    if (!keySet.has(lower)) {
      throw new Error(`неизвестная метрика: ${raw}`);
    }
    const canonical = keys.find((k) => k.toLowerCase() === lower) || raw;
    return canonical;
  }

  function parseExplorerLimitDslLine(line, schema) {
    const trimmed = String(line || '').trim();
    const match = trimmed.match(/^limit\s+(\S+)\s*$/i);
    if (!match) {
      throw new Error('ожидается строка limit <n>');
    }
    const raw = match[1].trim();
    if (!/^\d+$/.test(raw)) {
      throw new Error(`неверный лимит: ${raw}`);
    }
    const parsed = Math.floor(Number(raw));
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error(`неверный лимит: ${raw}`);
    }
    const max = maxFetchFromSchema(schema);
    if (parsed > max) {
      throw new Error(`лимит не может превышать ${max}`);
    }
    return resolveExplorerFetchLimit(parsed, max);
  }

  function buildExplorerQueryDslSuggestions({ line, leading, schema }) {
    const trimmed = String(line || '').trim();
    const lower = trimmed.toLowerCase();
    const lineSuggestion = (label, insert, hint) => ({ label, hint, insert: `${leading}${insert}`, mode: 'line' });
    const suggestions = [];

    if (!trimmed || lower.startsWith('metric')) {
      const keys = metricKeysFromSchema(schema);
      const metrics = Array.isArray(schema?.metrics) ? schema.metrics : [];
      const labelById = Object.fromEntries(metrics.map((m) => [m.id, m.label]));
      keys.forEach((id) => {
        const label = labelById[id] || id;
        suggestions.push(lineSuggestion(`metric ${id}`, `metric ${id}`, label));
      });
      if (!trimmed) {
        suggestions.push(lineSuggestion('metric', 'metric bps', 'Метрика запроса'));
      }
    }

    if (!trimmed || lower.startsWith('limit')) {
      [25, 50, 100].forEach((n) => {
        suggestions.push(lineSuggestion(`limit ${n}`, `limit ${n}`, 'Лимит выборки'));
      });
      if (!trimmed) {
        suggestions.push(lineSuggestion('limit', 'limit 25', 'Лимит выборки API'));
      }
    }

    const needle = trimmed.toLowerCase();
    return suggestions.filter((item) => (
      String(item.label || '').toLowerCase().includes(needle)
      || String(item.hint || '').toLowerCase().includes(needle)
    ));
  }

  const api = {
    EXPLORER_DEFAULT_METRIC_KEYS,
    metricKeysFromSchema,
    maxFetchFromSchema,
    resolveExplorerFetchLimit,
    isExplorerMetricDslLine,
    isExplorerLimitDslLine,
    parseExplorerMetricDslLine,
    parseExplorerLimitDslLine,
    buildExplorerQueryDslSuggestions,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (typeof window !== 'undefined') {
    window.ExplorerQueryDsl = api;
  }
}());
