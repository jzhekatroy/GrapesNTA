'use strict';

const EXPLORER_THRESHOLD_OPS = [
  { id: 'gt', label: 'больше' },
  { id: 'gte', label: 'больше или равно' },
  { id: 'lt', label: 'меньше' },
  { id: 'lte', label: 'меньше или равно' },
  { id: 'between', label: 'между' },
  { id: 'outside', label: 'вне диапазона' },
];

const EXPLORER_THRESHOLD_PEAK_WINDOWS = [
  { id: '1m', label: 'за 1 мин' },
  { id: '5m', label: 'за 5 мин' },
  { id: '1h', label: 'за 1 час' },
];

const EXPLORER_THRESHOLD_DEFAULT_METRICS = [
  { id: 'bps', label: 'Средняя бит/с', peakSupported: true, defaultUnit: 'mbps' },
  { id: 'volume', label: 'Объём', peakSupported: true, defaultUnit: 'gb' },
  { id: 'pps', label: 'Пакеты/с', peakSupported: true, defaultUnit: 'pps' },
  { id: 'fps', label: 'Потоки/с', peakSupported: true, defaultUnit: 'fps' },
  { id: 'flows', label: 'Всего потоков', peakSupported: true, defaultUnit: 'count' },
  { id: 'uniq_src', label: 'Уникальных source IP', peakSupported: false, defaultUnit: 'count' },
  { id: 'avg_packet_size', label: 'Средний размер пакета', peakSupported: false, defaultUnit: 'b' },
  { id: 'avg_flow_size', label: 'Средний размер потока', peakSupported: false, defaultUnit: 'b' },
  { id: 'pct', label: 'Доля от общего', peakSupported: false, defaultUnit: 'pct' },
];

const UNIT_MULTIPLIERS = {
  bps: { bps: 1, kbps: 1000, mbps: 1e6, gbps: 1e9 },
  volume: { b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3, tb: 1024 ** 4 },
  pps: { pps: 1, kpps: 1000, mpps: 1e6 },
  fps: { fps: 1 },
  flows: { count: 1, k: 1000, m: 1e6 },
  uniq_src: { count: 1 },
  avg_packet_size: { b: 1 },
  avg_flow_size: { b: 1 },
  pct: { pct: 1 },
};

const UNIT_LABELS = {
  bps: { bps: 'бит/с', kbps: 'Кбит/с', mbps: 'Мбит/с', gbps: 'Гбит/с' },
  volume: { b: 'Б', kb: 'КБ', mb: 'МБ', gb: 'ГБ', tb: 'ТБ' },
  pps: { pps: 'пакет/с', kpps: 'тыс./с', mpps: 'млн/с' },
  fps: { fps: 'поток/с' },
  flows: { count: 'шт.', k: 'тыс.', m: 'млн' },
  uniq_src: { count: 'шт.' },
  avg_packet_size: { b: 'байт' },
  avg_flow_size: { b: 'байт' },
  pct: { pct: '%' },
};

function thresholdMetricsFromSchema(schema) {
  if (Array.isArray(schema?.thresholdMetrics) && schema.thresholdMetrics.length) {
    return schema.thresholdMetrics;
  }
  return EXPLORER_THRESHOLD_DEFAULT_METRICS;
}

function thresholdUnitsForMetric(metric) {
  return Object.keys(UNIT_MULTIPLIERS[metric] || { count: 1 });
}

function defaultThresholdUnit(metric, schemaMetrics) {
  const meta = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics })
    .find((m) => m.id === metric);
  return meta?.defaultUnit || 'count';
}

function parseThresholdUiNumber(value) {
  const s = String(value ?? '').trim().replace(',', '.');
  if (!s) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function uiToBaseThresholdValue(value, unit, metric) {
  const n = parseThresholdUiNumber(value);
  if (n == null) return null;
  const mult = (UNIT_MULTIPLIERS[metric] || {})[unit] || 1;
  if (metric === 'pct') return n;
  return n * mult;
}

function baseToUiThresholdValue(baseValue, unit, metric) {
  const n = Number(baseValue);
  if (!Number.isFinite(n)) return '';
  const mult = (UNIT_MULTIPLIERS[metric] || {})[unit] || 1;
  if (metric === 'pct') return String(n);
  const v = n / mult;
  const digits = v < 10 ? 2 : v < 100 ? 1 : 0;
  return String(Number(v.toFixed(digits)));
}

function normalizeExplorerThresholdDraft(row, schemaMetrics) {
  if (!row || typeof row !== 'object') return null;
  const metric = String(row.metric || 'bps').trim();
  const unit = String(row.unit || defaultThresholdUnit(metric, schemaMetrics)).trim();
  const valueBase = uiToBaseThresholdValue(row.value, unit, metric);
  if (valueBase == null) return null;
  let value2Base = null;
  const op = String(row.op || 'gt').trim();
  if (op === 'between' || op === 'outside') {
    value2Base = uiToBaseThresholdValue(row.value2, unit, metric);
    if (value2Base == null) return null;
  }
  let aggregate = String(row.aggregate || 'avg').trim();
  const meta = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics }).find((m) => m.id === metric);
  if (aggregate === 'peak' && !meta?.peakSupported) aggregate = 'avg';
  const payload = {
    metric,
    aggregate,
    op,
    value: valueBase,
    value2: value2Base,
    unit,
  };
  if (aggregate === 'peak') {
    payload.peakWindow = row.peakWindow || '5m';
  }
  return payload;
}

function validateExplorerThresholdDrafts(rows, schemaMetrics) {
  const validThresholds = [];
  const inactiveIds = new Set();
  (rows || []).forEach((row) => {
    const norm = normalizeExplorerThresholdDraft(row, schemaMetrics);
    if (norm) validThresholds.push(norm);
    else if (String(row.value ?? '').trim()) inactiveIds.add(row.id);
  });
  return { validThresholds, inactiveIds };
}

function cloneExplorerThresholds(rows) {
  return (rows || []).map((r, i) => ({
    id: r.id ?? `thr-${i}-${Date.now()}`,
    metric: r.metric || 'bps',
    aggregate: r.aggregate || 'avg',
    peakWindow: r.peakWindow || '5m',
    op: r.op || 'gt',
    value: r.value ?? '',
    value2: r.value2 ?? '',
    unit: r.unit || defaultThresholdUnit(r.metric),
  }));
}

function thresholdDraftFromApi(t, schemaMetrics) {
  const unit = t.unit || defaultThresholdUnit(t.metric, schemaMetrics);
  return {
    id: `thr-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    metric: t.metric,
    aggregate: t.aggregate || 'avg',
    peakWindow: t.peakWindow || '5m',
    op: t.op || 'gt',
    value: baseToUiThresholdValue(t.value, unit, t.metric),
    value2: t.value2 != null ? baseToUiThresholdValue(t.value2, unit, t.metric) : '',
    unit,
  };
}

function formatThresholdChipLabel(t, schemaMetrics) {
  const meta = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics }).find((m) => m.id === t.metric);
  const unit = t.unit || defaultThresholdUnit(t.metric, schemaMetrics);
  const unitLabel = (UNIT_LABELS[t.metric] || {})[unit] || unit;
  const opMeta = EXPLORER_THRESHOLD_OPS.find((o) => o.id === t.op);
  const opLabel = opMeta?.label || t.op;
  const val = baseToUiThresholdValue(t.value, unit, t.metric);
  const val2 = t.value2 != null ? baseToUiThresholdValue(t.value2, unit, t.metric) : null;
  const aggPrefix = t.aggregate === 'peak'
    ? `пик ${t.peakWindow === '1h' ? '1 час' : t.peakWindow === '1m' ? '1 мин' : '5 мин'}`
    : null;
  const metricLabel = meta?.label || t.metric;
  if (t.op === 'between' || t.op === 'outside') {
    return `${aggPrefix ? `${aggPrefix} ` : ''}${metricLabel} ${opLabel} ${val}–${val2} ${unitLabel}`.trim();
  }
  return `${aggPrefix ? `${aggPrefix} ` : ''}${metricLabel} ${opLabel} ${val} ${unitLabel}`.trim();
}

const EXPLORER_THRESHOLD_DSL_OP_TO_ID = {
  '>': 'gt',
  '>=': 'gte',
  '<': 'lt',
  '<=': 'lte',
  between: 'between',
  outside: 'outside',
};

const EXPLORER_THRESHOLD_DSL_OP_FROM_ID = {
  gt: '>',
  gte: '>=',
  lt: '<',
  lte: '<=',
  between: 'between',
  outside: 'outside',
};

function thresholdMetricIds(schemaMetrics) {
  return thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics })
    .map((m) => m.id)
    .sort((a, b) => b.length - a.length);
}

function splitThresholdDslValueUnit(text, metric, schemaMetrics) {
  const units = thresholdUnitsForMetric(metric);
  const defaultUnit = defaultThresholdUnit(metric, schemaMetrics);
  const parts = String(text || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) {
    const maybeUnit = parts[parts.length - 1].toLowerCase();
    if (units.includes(maybeUnit)) {
      return { value: parts.slice(0, -1).join(' '), unit: maybeUnit };
    }
    throw new Error(`неизвестная единица «${maybeUnit}» для метрики ${metric}`);
  }
  return { value: String(text || '').trim(), unit: defaultUnit };
}

function parseExplorerThresholdDslLine(line, schemaMetrics) {
  const trimmed = String(line || '').trim();
  if (!/^threshold\s+/i.test(trimmed)) return null;

  let rest = trimmed.replace(/^threshold\s+/i, '').trim();
  const aggMatch = rest.match(/^(avg|peak)\s+/i);
  if (!aggMatch) throw new Error('ожидается avg или peak после threshold');
  const aggregate = aggMatch[1].toLowerCase();
  rest = rest.slice(aggMatch[0].length).trim();

  const metricIds = thresholdMetricIds(schemaMetrics);
  let metric = null;
  for (const id of metricIds) {
    const re = new RegExp(`^${id.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}(?:\\s+|$)`, 'i');
    if (re.test(rest)) {
      metric = id;
      rest = rest.slice(id.length).trim();
      break;
    }
  }
  if (!metric) {
    const token = rest.split(/\s+/)[0] || '';
    throw new Error(`неизвестная метрика порога: ${token || '(пусто)'}`);
  }

  const meta = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics }).find((m) => m.id === metric);
  let peakWindow = '5m';
  if (aggregate === 'peak') {
    if (!meta?.peakSupported) {
      throw new Error(`метрика ${metric} не поддерживает peak-пороги`);
    }
    const winMatch = rest.match(/^(1m|5m|1h)\s+/i);
    if (winMatch) {
      peakWindow = winMatch[1].toLowerCase();
      rest = rest.slice(winMatch[0].length).trim();
    }
  }

  const opMatch = rest.match(/^(>=|<=|>|<|between|outside)\s+/i);
  if (!opMatch) throw new Error('ожидается оператор порога (>, >=, <, <=, between, outside)');
  const opSym = opMatch[1].toLowerCase();
  const op = EXPLORER_THRESHOLD_DSL_OP_TO_ID[opSym];
  if (!op) throw new Error(`неизвестный оператор порога: ${opSym}`);
  rest = rest.slice(opMatch[0].length).trim();

  let value;
  let value2 = '';
  let unit;
  if (op === 'between' || op === 'outside') {
    const rangeMatch = rest.match(/^(.+?)\s+and\s+(.+)$/i);
    if (!rangeMatch) throw new Error('для between/outside ожидается формат: VALUE and VALUE [UNIT]');
    const left = splitThresholdDslValueUnit(rangeMatch[1], metric, schemaMetrics);
    const rightText = rangeMatch[2].trim();
    const rightParts = rightText.split(/\s+/).filter(Boolean);
    const units = thresholdUnitsForMetric(metric);
    if (rightParts.length >= 2 && units.includes(rightParts[rightParts.length - 1].toLowerCase())) {
      value = left.value;
      value2 = rightParts.slice(0, -1).join(' ');
      unit = rightParts[rightParts.length - 1].toLowerCase();
    } else {
      value = left.value;
      value2 = rightText;
      unit = left.unit;
    }
  } else {
    const parsed = splitThresholdDslValueUnit(rest, metric, schemaMetrics);
    value = parsed.value;
    unit = parsed.unit;
  }

  if (parseThresholdUiNumber(value) == null) {
    throw new Error(`некорректное значение порога: ${value}`);
  }
  if ((op === 'between' || op === 'outside') && parseThresholdUiNumber(value2) == null) {
    throw new Error(`некорректное второе значение порога: ${value2}`);
  }

  const draft = {
    metric,
    aggregate,
    peakWindow,
    op,
    value,
    value2,
    unit,
  };
  if (normalizeExplorerThresholdDraft(draft, schemaMetrics) == null) {
    throw new Error('не удалось нормализовать порог (проверьте значения и единицы)');
  }
  return draft;
}

function serializeExplorerThresholdDraftToDsl(draft, schemaMetrics) {
  if (!draft || !String(draft.metric || '').trim()) return null;
  const metric = String(draft.metric).trim();
  const aggregate = String(draft.aggregate || 'avg').trim();
  const op = EXPLORER_THRESHOLD_DSL_OP_FROM_ID[draft.op] || draft.op;
  const unit = draft.unit || defaultThresholdUnit(metric, schemaMetrics);
  const peakPart = aggregate === 'peak' ? ` ${draft.peakWindow || '5m'}` : '';
  const unitSuffix = metric === 'pct' ? ' pct' : ` ${unit}`;

  if (draft.op === 'between' || draft.op === 'outside') {
    return `threshold ${aggregate} ${metric}${peakPart} ${op} ${draft.value} and ${draft.value2}${unitSuffix}`.trim();
  }
  if (metric === 'pct') {
    return `threshold ${aggregate} ${metric}${peakPart} ${op} ${draft.value}${unitSuffix}`.trim();
  }
  return `threshold ${aggregate} ${metric}${peakPart} ${op} ${draft.value} ${unit}`.trim();
}

function serializeExplorerThresholdsToDsl(thresholds, schemaMetrics) {
  return (thresholds || [])
    .map((row) => serializeExplorerThresholdDraftToDsl(row, schemaMetrics))
    .filter(Boolean);
}

const THRESHOLD_DSL_OPS = ['>=', '<=', '>', '<', 'between', 'outside'];

function thresholdDslValuePresets(metric, schemaMetrics) {
  const defaultUnit = defaultThresholdUnit(metric, schemaMetrics);
  switch (metric) {
    case 'bps':
      return [{ value: '100', unit: 'mbps' }, { value: '1', unit: 'gbps' }, { value: '10', unit: 'mbps' }];
    case 'volume':
      return [{ value: '1', unit: 'gb' }, { value: '10', unit: 'gb' }, { value: '100', unit: 'mb' }];
    case 'pps':
      return [{ value: '1000', unit: 'pps' }, { value: '1', unit: 'mpps' }, { value: '100', unit: 'kpps' }];
    case 'fps':
      return [{ value: '100', unit: 'fps' }, { value: '1000', unit: 'fps' }];
    case 'flows':
      return [{ value: '100', unit: 'count' }, { value: '1000', unit: 'count' }, { value: '1', unit: 'k' }];
    case 'uniq_src':
      return [{ value: '10', unit: 'count' }, { value: '100', unit: 'count' }];
    case 'avg_packet_size':
    case 'avg_flow_size':
      return [{ value: '512', unit: 'b' }, { value: '1500', unit: 'b' }];
    case 'pct':
      return [{ value: '5', unit: 'pct' }, { value: '10', unit: 'pct' }, { value: '25', unit: 'pct' }];
    default:
      return [{ value: '100', unit: defaultUnit }];
  }
}

function formatThresholdDslInsert({
  aggregate, metric, peakWindow, op, value, value2, unit,
}) {
  const peakPart = aggregate === 'peak' ? ` ${peakWindow || '5m'}` : '';
  if (op === 'between' || op === 'outside') {
    const unitSuffix = metric === 'pct' ? ' pct' : ` ${unit}`;
    return `threshold ${aggregate} ${metric}${peakPart} ${op} ${value} and ${value2}${unitSuffix}`;
  }
  if (metric === 'pct') {
    return `threshold ${aggregate} ${metric}${peakPart} ${op} ${value} pct`;
  }
  return `threshold ${aggregate} ${metric}${peakPart} ${op} ${value} ${unit}`;
}

function thresholdDslRangePresets(metric, schemaMetrics) {
  const unit = defaultThresholdUnit(metric, schemaMetrics);
  switch (metric) {
    case 'volume':
      return [{ value: '1', value2: '10', unit: 'gb' }, { value: '100', value2: '1000', unit: 'mb' }];
    case 'pct':
      return [{ value: '5', value2: '25', unit: 'pct' }, { value: '10', value2: '50', unit: 'pct' }];
    case 'bps':
      return [{ value: '100', value2: '1000', unit: 'mbps' }];
    default:
      return [{ value: '1', value2: '10', unit }];
  }
}

function analyzeExplorerThresholdDslPartial(line, schemaMetrics) {
  const trimmed = String(line || '').trim();
  if (!/^threshold(\s|$)/i.test(trimmed)) return null;

  let rest = trimmed.replace(/^threshold\s*/i, '').trim();
  if (!rest) return { stage: 'aggregate' };

  const aggMatch = rest.match(/^(avg|peak)(?:\s+|$)/i);
  if (!aggMatch) {
    return { stage: 'aggregate', partial: rest.split(/\s+/)[0] || '' };
  }
  const aggregate = aggMatch[1].toLowerCase();
  rest = rest.slice(aggMatch[0].length).trim();

  const metrics = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics });
  const metricIds = thresholdMetricIds(schemaMetrics);
  let metric = null;
  for (const id of metricIds) {
    const lowerRest = rest.toLowerCase();
    const lowerId = id.toLowerCase();
    if (lowerRest === lowerId || lowerRest.startsWith(`${lowerId} `)) {
      metric = id;
      rest = rest.slice(id.length).trim();
      break;
    }
  }
  if (!metric) {
    const metricPartial = rest.split(/\s+/)[0] || '';
    const metricCandidates = metricIds.filter((id) => (
      !metricPartial || id.toLowerCase().startsWith(metricPartial.toLowerCase())
    ));
    return { stage: 'metric', aggregate, metricPartial, metricCandidates };
  }

  const meta = metrics.find((m) => m.id === metric);
  let peakWindow = null;
  if (aggregate === 'peak' && meta?.peakSupported) {
    const winMatch = rest.match(/^(1m|5m|1h)(?:\s+|$)/i);
    if (winMatch) {
      peakWindow = winMatch[1].toLowerCase();
      rest = rest.slice(winMatch[0].length).trim();
    } else {
      const token = rest.split(/\s+/)[0] || '';
      const windowMatches = THRESHOLD_DSL_OPS.includes(token)
        ? []
        : THRESHOLD_PEAK_WINDOWS.filter((w) => (
          !token || w.toLowerCase().startsWith(token.toLowerCase())
        ));
      const opMatches = THRESHOLD_DSL_OPS.filter((op) => (
        !token || op.toLowerCase().startsWith(token.toLowerCase())
        || token.toLowerCase().startsWith(op.toLowerCase())
      ));
      if (token && windowMatches.length && !opMatches.some((op) => op === token || rest.startsWith(op))) {
        const exactWindow = windowMatches.find((w) => w.toLowerCase() === token.toLowerCase());
        if (!exactWindow || !rest.startsWith(`${exactWindow} `)) {
          return { stage: 'peakWindow', aggregate, metric, meta, peakWindowPartial: token };
        }
      }
      peakWindow = '5m';
    }
  }

  let op = null;
  for (const sym of THRESHOLD_DSL_OPS) {
    const lowerRest = rest.toLowerCase();
    if (lowerRest === sym || lowerRest.startsWith(`${sym} `)) {
      op = sym;
      rest = rest.slice(sym.length).trim();
      break;
    }
  }
  if (!op) {
    return {
      stage: 'operator',
      aggregate,
      metric,
      meta,
      peakWindow,
      opPartial: rest.split(/\s+/)[0] || '',
    };
  }

  const units = thresholdUnitsForMetric(metric);
  const defaultUnit = defaultThresholdUnit(metric, schemaMetrics);

  if (op === 'between' || op === 'outside') {
    if (!rest) {
      return {
        stage: 'rangeValue',
        aggregate,
        metric,
        meta,
        peakWindow,
        op,
        defaultUnit,
        units,
      };
    }
    const andSplit = rest.match(/^(.+?)\s+and\s+(.*)$/i);
    if (!andSplit) {
      return {
        stage: 'rangeValue',
        aggregate,
        metric,
        meta,
        peakWindow,
        op,
        valuePartial: rest,
        defaultUnit,
        units,
      };
    }
    const value1 = andSplit[1].trim();
    const tail = andSplit[2].trim();
    const tailParts = tail.split(/\s+/).filter(Boolean);
    const lastTok = tailParts[tailParts.length - 1] || '';
    if (tailParts.length >= 2 && units.includes(lastTok.toLowerCase())) {
      return { stage: 'complete', aggregate, metric, meta, peakWindow, op };
    }
    if (tailParts.length >= 2) {
      const unitMatches = units.filter((u) => u.startsWith(lastTok.toLowerCase()));
      if (unitMatches.length) {
        return {
          stage: 'rangeUnit',
          aggregate,
          metric,
          meta,
          peakWindow,
          op,
          value1,
          value2: tailParts.slice(0, -1).join(' '),
          unitPartial: lastTok,
          defaultUnit,
          units: unitMatches,
        };
      }
    }
    return {
      stage: 'rangeValue2',
      aggregate,
      metric,
      meta,
      peakWindow,
      op,
      value1,
      value2Partial: tail,
      defaultUnit,
      units,
    };
  }

  if (!rest) {
    return {
      stage: 'value',
      aggregate,
      metric,
      meta,
      peakWindow,
      op,
      defaultUnit,
      units,
    };
  }

  const parts = rest.split(/\s+/).filter(Boolean);
  const lastTok = parts[parts.length - 1] || '';
  if (parts.length >= 2 && units.includes(lastTok.toLowerCase())) {
    return { stage: 'complete', aggregate, metric, meta, peakWindow, op };
  }
  if (parts.length >= 2) {
    const unitMatches = units.filter((u) => u.startsWith(lastTok.toLowerCase()));
    if (unitMatches.length) {
      return {
        stage: 'unit',
        aggregate,
        metric,
        meta,
        peakWindow,
        op,
        value: parts.slice(0, -1).join(' '),
        unitPartial: lastTok,
        defaultUnit,
        units: unitMatches,
      };
    }
  }

  return {
    stage: 'value',
    aggregate,
    metric,
    meta,
    peakWindow,
    op,
    valuePartial: rest,
    defaultUnit,
    units,
  };
}

function buildExplorerThresholdDslSuggestions(line, leading, schemaMetrics) {
  const ctx = analyzeExplorerThresholdDslPartial(line, schemaMetrics);
  if (!ctx) return [];

  const suggestions = [];
  const push = (label, insert, hint) => {
    suggestions.push({ label, hint, insert: `${leading}${insert}`, mode: 'line' });
  };
  const ctxBase = () => ({
    aggregate: ctx.aggregate,
    metric: ctx.metric,
    peakWindow: ctx.peakWindow,
    op: ctx.op,
  });

  switch (ctx.stage) {
    case 'aggregate':
      ['avg', 'peak'].forEach((mode) => {
        if (ctx.partial && !mode.startsWith(ctx.partial.toLowerCase())) return;
        const sample = mode === 'peak' ? 'threshold peak bps 5m > 1 gbps' : 'threshold avg bps > 100 mbps';
        push(mode, sample, mode === 'peak' ? 'Пиковый порог' : 'Средний порог');
      });
      if (!suggestions.length) {
        push('threshold avg', 'threshold avg bps > 100 mbps', 'Средний порог');
        push('threshold peak', 'threshold peak bps 5m > 1 gbps', 'Пиковый порог');
      }
      break;

    case 'metric':
      (ctx.metricCandidates || []).forEach((id) => {
        const meta = thresholdMetricsFromSchema({ thresholdMetrics: schemaMetrics }).find((m) => m.id === id);
        const sample = ctx.aggregate === 'peak' && meta?.peakSupported
          ? `threshold ${ctx.aggregate} ${id} 5m > 1 ${meta?.defaultUnit || 'mbps'}`
          : `threshold ${ctx.aggregate} ${id} > 100 ${meta?.defaultUnit || 'mbps'}`;
        push(id, sample, meta?.label || id);
      });
      break;

    case 'peakWindow':
      EXPLORER_THRESHOLD_PEAK_WINDOWS.forEach(({ id, label }) => {
        if (ctx.peakWindowPartial && !id.startsWith(ctx.peakWindowPartial.toLowerCase())) return;
        push(id, `threshold ${ctx.aggregate} ${ctx.metric} ${id} > `, label || id);
      });
      break;

    case 'operator':
      THRESHOLD_DSL_OPS.forEach((opSym) => {
        if (ctx.opPartial && !opSym.startsWith(ctx.opPartial.toLowerCase())
          && !ctx.opPartial.toLowerCase().startsWith(opSym)) return;
        const peakPart = ctx.aggregate === 'peak' ? ` ${ctx.peakWindow || '5m'}` : '';
        push(opSym, `threshold ${ctx.aggregate} ${ctx.metric}${peakPart} ${opSym} `, 'Оператор порога');
      });
      break;

    case 'value': {
      const partial = String(ctx.valuePartial || '').trim().toLowerCase();
      thresholdDslValuePresets(ctx.metric, schemaMetrics).forEach(({ value, unit }) => {
        const label = ctx.metric === 'pct' ? `${value} pct` : `${value} ${unit}`;
        if (partial && !value.startsWith(partial) && !label.toLowerCase().includes(partial)) return;
        push(label, formatThresholdDslInsert({ ...ctxBase(), value, value2: '', unit }), 'Значение порога');
      });
      if (partial && /^[\d.,]+$/.test(partial)) {
        const rawValue = String(ctx.valuePartial).trim();
        const unit = ctx.defaultUnit;
        const label = ctx.metric === 'pct' ? `${rawValue} pct` : `${rawValue} ${unit}`;
        push(label, formatThresholdDslInsert({ ...ctxBase(), value: rawValue, value2: '', unit }), 'Текущее значение');
      }
      break;
    }

    case 'unit':
      ctx.units.forEach((unit) => {
        push(unit, formatThresholdDslInsert({ ...ctxBase(), value: ctx.value, value2: '', unit }), 'Единица');
      });
      break;

    case 'rangeValue':
      thresholdDslRangePresets(ctx.metric, schemaMetrics).forEach(({ value, value2, unit }) => {
        const label = ctx.metric === 'pct' ? `${value} and ${value2} pct` : `${value} and ${value2} ${unit}`;
        if (ctx.valuePartial) {
          const partial = ctx.valuePartial.toLowerCase();
          if (!label.toLowerCase().includes(partial) && !partial.startsWith(String(value))) return;
        }
        push(label, formatThresholdDslInsert({ ...ctxBase(), value, value2, unit }), 'Диапазон');
      });
      break;

    case 'rangeValue2': {
      const partial = String(ctx.value2Partial || '').trim().toLowerCase();
      thresholdDslValuePresets(ctx.metric, schemaMetrics).forEach(({ value, unit }) => {
        if (partial && !value.startsWith(partial)) return;
        const label = ctx.metric === 'pct' ? `${ctx.value1} and ${value} pct` : `${ctx.value1} and ${value} ${unit}`;
        push(label, formatThresholdDslInsert({ ...ctxBase(), value: ctx.value1, value2: value, unit }), 'Второе значение');
      });
      if (partial && /^[\d.,]+$/.test(partial)) {
        const rawValue = String(ctx.value2Partial).trim();
        const unit = ctx.defaultUnit;
        const label = ctx.metric === 'pct'
          ? `${ctx.value1} and ${rawValue} pct`
          : `${ctx.value1} and ${rawValue} ${unit}`;
        push(label, formatThresholdDslInsert({
          ...ctxBase(), value: ctx.value1, value2: rawValue, unit,
        }), 'Текущее значение');
      }
      break;
    }

    case 'rangeUnit':
      ctx.units.forEach((unit) => {
        const label = ctx.metric === 'pct'
          ? `${ctx.value1} and ${ctx.value2} pct`
          : `${ctx.value1} and ${ctx.value2} ${unit}`;
        push(label, formatThresholdDslInsert({
          ...ctxBase(), value: ctx.value1, value2: ctx.value2, unit,
        }), 'Единица');
      });
      break;

    case 'complete':
    default:
      break;
  }

  const seen = new Set();
  return suggestions.filter((item) => {
    const key = `${item.label}|${item.insert}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 12);
}

function shouldShowThresholdPeakWarning({ thresholds, groupBy, timeRange, customPeriod }) {
  const peak = (thresholds || []).some((t) => t.aggregate === 'peak');
  if (!peak) return false;
  const groups = groupBy || [];
  const ipHeavy = groups.includes('src_ip') || groups.includes('dst_ip')
    || (groups.includes('src_ip') && groups.includes('dst_ip'));
  if (!ipHeavy) return false;
  let windowSec = 3600;
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    windowSec = (new Date(customPeriod.to) - new Date(customPeriod.from)) / 1000;
  } else {
    const map = { '30m': 1800, '1h': 3600, '3h': 10800, '6h': 21600, '12h': 43200, '24h': 86400, '2d': 172800, '7d': 604800, '14d': 1209600 };
    windowSec = map[timeRange] || 3600;
  }
  return windowSec > 86400;
}

const ExplorerThresholdsExport = {
  EXPLORER_THRESHOLD_OPS,
  EXPLORER_THRESHOLD_PEAK_WINDOWS,
  EXPLORER_THRESHOLD_DEFAULT_METRICS,
  EXPLORER_THRESHOLD_DSL_OP_TO_ID,
  EXPLORER_THRESHOLD_DSL_OP_FROM_ID,
  thresholdMetricsFromSchema,
  thresholdMetricIds,
  thresholdUnitsForMetric,
  defaultThresholdUnit,
  parseThresholdUiNumber,
  uiToBaseThresholdValue,
  baseToUiThresholdValue,
  normalizeExplorerThresholdDraft,
  validateExplorerThresholdDrafts,
  cloneExplorerThresholds,
  thresholdDraftFromApi,
  formatThresholdChipLabel,
  parseExplorerThresholdDslLine,
  serializeExplorerThresholdDraftToDsl,
  serializeExplorerThresholdsToDsl,
  analyzeExplorerThresholdDslPartial,
  buildExplorerThresholdDslSuggestions,
  shouldShowThresholdPeakWarning,
  UNIT_LABELS,
};

if (typeof window !== 'undefined') {
  window.ExplorerThresholds = ExplorerThresholdsExport;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ExplorerThresholdsExport;
}
