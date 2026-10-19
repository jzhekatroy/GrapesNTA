/* Подписи для разметки портов оборудования (§2.11 ТЗ). */

const IR_CONNECTIVITY_LABELS = {
  '': 'Не задан',
  customer: 'Клиент',
  transit: 'Транзит',
  pni: 'PNI',
  ppni: 'PPNI',
  ix: 'IX',
  core: 'Ядро',
  cgnat: 'CGNAT',
  mgmt: 'Управление',
};

const IR_DIRECTION_LABELS = {
  in: 'Входящий',
  out: 'Исходящий',
  internal: 'Внутренний',
  transit: 'Транзит',
  unknown: 'Не определено',
};

const IR_DIRECTION_MODE_LABELS = {
  prefixes: 'По сетям',
  ports: 'По портам оборудования',
};

const IR_ONE_SIDED_LABELS = {
  strict: 'Не определять',
  infer: 'Определять по известной',
};

const IR_MATCH_FIELD_LABELS = {
  descr: 'Описание',
  alias: 'Alias',
  name: 'Имя порта',
};

function irLabelT(key, params) {
  if (typeof GrapesI18n !== 'undefined' && GrapesI18n.t) {
    return GrapesI18n.t(key, params);
  }
  return key;
}

function irBoundaryLabel(value) {
  const id = String(value || 'unknown');
  const key = `interfaceRolesPage.boundary.${id}`;
  if (typeof GrapesI18n !== 'undefined' && GrapesI18n.has(key)) {
    return irLabelT(key);
  }
  const fallback = { unknown: 'Не размечено', internal: 'Наша сторона', external: 'Внешняя' };
  return fallback[id] || fallback.unknown;
}

function irSourceLabel(value) {
  const id = String(value || 'default');
  const key = `interfaceRolesPage.source.${id}`;
  if (typeof GrapesI18n !== 'undefined' && GrapesI18n.has(key)) {
    return irLabelT(key);
  }
  const fallback = {
    manual: 'Вручную',
    client: 'Из биллинга',
    rule: 'Правило',
    default: 'По умолчанию',
  };
  return fallback[id] || String(value || '');
}

function irSwitchStatusLabel(status) {
  const id = String(status || '');
  const key = `interfaceRolesPage.switchStatus.${id}`;
  if (typeof GrapesI18n !== 'undefined' && GrapesI18n.has(key)) {
    return irLabelT(key);
  }
  const fallback = { not_started: 'Не начато', partial: 'Частично', done: 'Готово' };
  return fallback[id] || status;
}

function irConnectivityLabel(value) {
  const key = String(value ?? '');
  if (key in IR_CONNECTIVITY_LABELS) return IR_CONNECTIVITY_LABELS[key];
  return key || IR_CONNECTIVITY_LABELS[''];
}

function irDirectionLabel(value) {
  return IR_DIRECTION_LABELS[String(value || 'unknown')] || String(value || 'unknown');
}

function irBoundaryBadgeTone(boundary) {
  if (boundary === 'internal') return 'success';
  if (boundary === 'external') return 'info';
  return 'neutral';
}

function irSuggestedBoundaryLabel(value) {
  if (value === 'external') return 'похоже на внешний';
  if (value === 'internal') return 'похоже на нашу сторону';
  return '';
}

/** @deprecated use irBoundaryLabel; kept for callers reading raw maps */
const IR_BOUNDARY_LABELS = {
  unknown: 'Не размечено',
  internal: 'Наша сторона',
  external: 'Внешняя',
};

const IR_SOURCE_LABELS = {
  manual: 'Вручную',
  client: 'Из биллинга',
  rule: 'Правило',
  default: 'По умолчанию',
};

const IR_SWITCH_STATUS_LABELS = {
  not_started: 'Не начато',
  partial: 'Частично',
  done: 'Готово',
};

Object.assign(window, {
  IR_BOUNDARY_LABELS,
  IR_CONNECTIVITY_LABELS,
  IR_SOURCE_LABELS,
  IR_DIRECTION_LABELS,
  IR_DIRECTION_MODE_LABELS,
  IR_ONE_SIDED_LABELS,
  IR_MATCH_FIELD_LABELS,
  IR_SWITCH_STATUS_LABELS,
  irBoundaryLabel,
  irConnectivityLabel,
  irSourceLabel,
  irSwitchStatusLabel,
  irDirectionLabel,
  irBoundaryBadgeTone,
  irSuggestedBoundaryLabel,
});
