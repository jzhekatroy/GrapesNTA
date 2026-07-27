const net = require('net');
const {
  config,
  query,
  insertRows,
  executeCommand,
  netInterfacesCurrentRef,
  directionSettingsViewRef,
  interfaceRoleRulesViewRef,
  interfaceRolesViewRef,
  interfaceRolesEffectiveTableRef,
  interfaceRolesEffectiveViewRef,
} = require('./clickhouse');

/**
 * Сторона сети. Единственное, из чего выводится направление трафика:
 * internal — наша сторона, external — всё остальное.
 */
const BOUNDARY_VALUES = ['unknown', 'internal', 'external'];

const BOUNDARY_LABELS = {
  unknown: 'Не задана',
  internal: 'Наша сторона',
  external: 'Внешняя',
};

/** Тип стыка — описательное поле, на направление не влияет. */
const CONNECTIVITY_VALUES = [
  '', 'customer', 'transit', 'pni', 'ppni', 'ix', 'core', 'cgnat', 'mgmt',
];

const CONNECTIVITY_LABELS = {
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

const MATCH_FIELDS = ['descr', 'alias', 'name'];

const MATCH_FIELD_COLUMNS = {
  descr: 'if_descr',
  alias: 'if_alias',
  name: 'if_name',
};

/** Что делать, когда сторона второго порта неизвестна. */
const ONE_SIDED_POLICIES = ['strict', 'infer'];

const DIRECTION_MODES = ['prefixes', 'ports'];

const DEFAULT_SETTINGS = {
  directionMode: 'prefixes',
  defaultBoundary: 'unknown',
  oneSided: 'strict',
};

const MAX_PATTERN_LENGTH = 500;

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function chStringLiteral(value) {
  return `'${String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

function normalizeBoundary(value, fallback = 'unknown') {
  const boundary = String(value ?? '').trim().toLowerCase();
  return BOUNDARY_VALUES.includes(boundary) ? boundary : fallback;
}

function normalizeConnectivity(value) {
  const conn = String(value ?? '').trim().toLowerCase();
  return CONNECTIVITY_VALUES.includes(conn) ? conn : '';
}

function normalizeMatchField(value) {
  const field = String(value ?? '').trim().toLowerCase();
  return MATCH_FIELDS.includes(field) ? field : 'descr';
}

function newRuleId() {
  return `ifrule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/* ------------------------------------------------------------------ */
/* Настройки инсталляции                                               */
/* ------------------------------------------------------------------ */

function mapSettingsRow(r = {}) {
  const mode = String(r.direction_mode ?? '').trim().toLowerCase();
  const policy = String(r.one_sided ?? '').trim().toLowerCase();
  return {
    directionMode: DIRECTION_MODES.includes(mode) ? mode : DEFAULT_SETTINGS.directionMode,
    defaultBoundary: normalizeBoundary(r.default_boundary, DEFAULT_SETTINGS.defaultBoundary),
    oneSided: ONE_SIDED_POLICIES.includes(policy) ? policy : DEFAULT_SETTINGS.oneSided,
    updatedBy: String(r.updated_by ?? ''),
    updatedAt: r.updated_at ?? null,
  };
}

async function fetchDirectionSettings() {
  try {
    const { rows } = await query(
      `
        SELECT direction_mode, default_boundary, one_sided, updated_by, updated_at
        FROM ${directionSettingsViewRef()}
        WHERE settings_id = 'global'
        LIMIT 1
      `,
      {},
      { name: 'refs/direction-settings' },
    );
    return mapSettingsRow(rows[0] || {});
  } catch {
    return { ...DEFAULT_SETTINGS, updatedBy: '', updatedAt: null };
  }
}

async function getDirectionSettings() {
  const settings = await fetchDirectionSettings();
  return {
    ...settings,
    options: {
      directionModes: DIRECTION_MODES,
      boundaries: BOUNDARY_VALUES,
      boundaryLabels: BOUNDARY_LABELS,
      connectivity: CONNECTIVITY_VALUES,
      connectivityLabels: CONNECTIVITY_LABELS,
      oneSidedPolicies: ONE_SIDED_POLICIES,
    },
  };
}

async function saveDirectionSettings(body = {}, { updatedBy = '' } = {}) {
  const current = await fetchDirectionSettings();
  const mode = String(body?.directionMode ?? body?.direction_mode ?? current.directionMode)
    .trim().toLowerCase();
  if (!DIRECTION_MODES.includes(mode)) throw apiError('Неизвестный режим определения направления');

  const policy = String(body?.oneSided ?? body?.one_sided ?? current.oneSided)
    .trim().toLowerCase();
  if (!ONE_SIDED_POLICIES.includes(policy)) throw apiError('Неизвестная политика для неизвестной стороны');

  const record = {
    settings_id: 'global',
    direction_mode: mode,
    default_boundary: normalizeBoundary(
      body?.defaultBoundary ?? body?.default_boundary ?? current.defaultBoundary,
      current.defaultBoundary,
    ),
    one_sided: policy,
    updated_by: String(updatedBy || '').slice(0, 128),
  };
  const { elapsedMs } = await insertRows(config.directionSettingsTable, [record], {
    name: 'refs/direction-settings-save',
  });
  const materialized = await materializeEffectiveRoles();
  return { elapsedMs, materialized };
}

/* ------------------------------------------------------------------ */
/* Правила                                                             */
/* ------------------------------------------------------------------ */

function mapRuleRow(r) {
  return {
    ruleId: String(r.rule_id ?? ''),
    priority: Number(r.priority) || 0,
    matchField: normalizeMatchField(r.match_field),
    pattern: String(r.pattern ?? ''),
    caseSensitive: Number(r.case_sensitive) === 1,
    minSpeedMbps: Number(r.min_speed_mbps) || 0,
    maxSpeedMbps: Number(r.max_speed_mbps) || 0,
    boundary: normalizeBoundary(r.boundary, ''),
    connectivity: normalizeConnectivity(r.connectivity),
    comment: String(r.comment ?? ''),
    enabled: Number(r.enabled) === 1,
    updatedAt: r.updated_at ?? null,
  };
}

function sortRules(rules) {
  return [...rules].sort((a, b) => (a.priority - b.priority) || a.ruleId.localeCompare(b.ruleId));
}

async function fetchActiveRules() {
  const { rows } = await query(
    `
      SELECT rule_id, priority, match_field, pattern, case_sensitive,
             min_speed_mbps, max_speed_mbps, boundary, connectivity,
             comment, enabled, updated_at
      FROM ${interfaceRoleRulesViewRef()}
      WHERE enabled = 1
    `,
    {},
    { name: 'refs/interface-role-rules-active' },
  );
  return sortRules(rows.map(mapRuleRow));
}

/** Скорость порта в Мбит/с: ifHighSpeed, иначе пересчёт из ifSpeed. */
function speedMbpsExpr(ifAlias) {
  return `if(${ifAlias}.if_high_speed_mbps > 0,
    ${ifAlias}.if_high_speed_mbps,
    toUInt32(${ifAlias}.if_speed_bps / 1000000))`;
}

/** Условие срабатывания правила: текстовый шаблон И диапазон скорости. */
function ruleMatchSql(rule, ifAlias) {
  const conditions = [];
  if (rule.pattern) {
    const column = MATCH_FIELD_COLUMNS[rule.matchField] || MATCH_FIELD_COLUMNS.descr;
    const pattern = rule.caseSensitive ? rule.pattern : `(?i)${rule.pattern}`;
    conditions.push(`match(${ifAlias}.${column}, ${chStringLiteral(pattern)})`);
  }
  if (rule.minSpeedMbps > 0) {
    conditions.push(`${speedMbpsExpr(ifAlias)} >= ${rule.minSpeedMbps}`);
  }
  if (rule.maxSpeedMbps > 0) {
    conditions.push(`${speedMbpsExpr(ifAlias)} <= ${rule.maxSpeedMbps}`);
  }
  return conditions.length ? conditions.join(' AND ') : '0';
}

/**
 * Значение поля от первого сработавшего правила.
 * Правила, не задающие это поле, пропускаются — так одно правило может
 * назначать сторону, а другое тип стыка.
 */
function ruleValueSql(rules, ifAlias, field, { returnRuleId = false } = {}) {
  const applicable = rules.filter((rule) => String(rule[field] ?? '') !== '');
  if (!applicable.length) return `''`;
  const branches = applicable.map((rule) => {
    const value = returnRuleId ? rule.ruleId : rule[field];
    return `${ruleMatchSql(rule, ifAlias)}, ${chStringLiteral(value)}`;
  });
  return `multiIf(${branches.join(', ')}, '')`;
}

/**
 * Итоговые выражения: ручной override важнее правил, затем значение
 * по умолчанию из настроек.
 */
function effectiveSqlParts(rules, settings, { ifAlias = 'i', overrideAlias = 'o' } = {}) {
  const ruleBoundary = ruleValueSql(rules, ifAlias, 'boundary');
  const ruleBoundaryId = ruleValueSql(rules, ifAlias, 'boundary', { returnRuleId: true });
  const ruleConnectivity = ruleValueSql(rules, ifAlias, 'connectivity');
  const ruleConnectivityId = ruleValueSql(rules, ifAlias, 'connectivity', { returnRuleId: true });
  const manualBoundary = `${overrideAlias}.boundary`;
  const manualConnectivity = `${overrideAlias}.connectivity`;
  const fallback = chStringLiteral(settings.defaultBoundary);

  return {
    boundary: `multiIf(${manualBoundary} != '', ${manualBoundary},
      ${ruleBoundary} != '', ${ruleBoundary},
      ${fallback})`,
    boundarySource: `multiIf(${manualBoundary} != '', 'manual',
      ${ruleBoundary} != '', 'rule',
      'default')`,
    boundaryRuleId: `if(${manualBoundary} != '', '', ${ruleBoundaryId})`,
    connectivity: `if(${manualConnectivity} != '', ${manualConnectivity}, ${ruleConnectivity})`,
    connectivitySource: `multiIf(${manualConnectivity} != '', 'manual',
      ${ruleConnectivity} != '', 'rule',
      'default')`,
    connectivityRuleId: `if(${manualConnectivity} != '', '', ${ruleConnectivityId})`,
  };
}

/**
 * Направление из сторон входного и выходного портов.
 * oneSided = 'infer' позволяет классифицировать по одной известной стороне —
 * это нужно, когда sFlow отдаёт out_if в формате «несколько интерфейсов».
 */
function portDirectionSql(inBoundaryExpr, outBoundaryExpr, { oneSided = 'strict' } = {}) {
  const pairBranches = [
    `${inBoundaryExpr} = 'external' AND ${outBoundaryExpr} = 'internal', 'in'`,
    `${inBoundaryExpr} = 'internal' AND ${outBoundaryExpr} = 'external', 'out'`,
    `${inBoundaryExpr} = 'internal' AND ${outBoundaryExpr} = 'internal', 'internal'`,
    `${inBoundaryExpr} = 'external' AND ${outBoundaryExpr} = 'external', 'transit'`,
  ];
  const inferBranches = oneSided === 'infer' ? [
    `${inBoundaryExpr} = 'external', 'in'`,
    `${inBoundaryExpr} = 'internal', 'out'`,
    `${outBoundaryExpr} = 'external', 'out'`,
    `${outBoundaryExpr} = 'internal', 'in'`,
  ] : [];
  return `multiIf(${[...pairBranches, ...inferBranches].join(', ')}, 'unknown')`;
}

function listInterfaceRoleRules() {
  return {
    sql: `
      SELECT rule_id, priority, match_field, pattern, case_sensitive,
             min_speed_mbps, max_speed_mbps, boundary, connectivity,
             comment, enabled, updated_at
      FROM ${interfaceRoleRulesViewRef()}
      ORDER BY priority, rule_id
    `,
    params: {},
    map(rows) {
      return rows.map(mapRuleRow);
    },
  };
}

async function fetchRuleById(ruleId) {
  const { rows } = await query(
    `
      SELECT rule_id, priority, match_field, pattern, case_sensitive,
             min_speed_mbps, max_speed_mbps, boundary, connectivity,
             comment, enabled, updated_at
      FROM ${interfaceRoleRulesViewRef()}
      WHERE rule_id = {rule_id:String}
      LIMIT 1
    `,
    { rule_id: ruleId },
    { name: 'refs/interface-role-rule-one' },
  );
  return rows[0] ? mapRuleRow(rows[0]) : null;
}

/** RE2 в ClickHouse строже JS, поэтому шаблон проверяет сам движок. */
async function assertValidPattern(pattern) {
  try {
    await query(
      `SELECT match('', {pattern:String}) AS ok`,
      { pattern },
      { name: 'refs/interface-role-rule-validate' },
    );
  } catch (err) {
    throw apiError(`Некорректное регулярное выражение: ${err.message}`);
  }
}

function parseSpeedMbps(value, label) {
  if (value === undefined || value === null || value === '') return 0;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 100000000) {
    throw apiError(`${label}: ожидается целое число Мбит/с`);
  }
  return n;
}

async function buildRuleRecord(body) {
  const pattern = String(body?.pattern ?? '').trim();
  if (pattern.length > MAX_PATTERN_LENGTH) {
    throw apiError(`Шаблон длиннее ${MAX_PATTERN_LENGTH} символов`);
  }
  if (pattern) await assertValidPattern(pattern);

  const minSpeedMbps = parseSpeedMbps(body?.minSpeedMbps ?? body?.min_speed_mbps, 'Минимальная скорость');
  const maxSpeedMbps = parseSpeedMbps(body?.maxSpeedMbps ?? body?.max_speed_mbps, 'Максимальная скорость');
  if (!pattern && !minSpeedMbps && !maxSpeedMbps) {
    throw apiError('Укажите шаблон или диапазон скорости — иначе правило ничего не выбирает');
  }
  if (minSpeedMbps && maxSpeedMbps && minSpeedMbps > maxSpeedMbps) {
    throw apiError('Минимальная скорость больше максимальной');
  }

  const boundary = normalizeBoundary(body?.boundary, '');
  const connectivity = normalizeConnectivity(body?.connectivity);
  if ((boundary === '' || boundary === 'unknown') && !connectivity) {
    throw apiError('Правило должно задавать сторону сети или тип стыка');
  }

  const priority = Number(body?.priority);
  return {
    rule_id: String(body?.ruleId ?? body?.rule_id ?? '').trim() || newRuleId(),
    priority: Number.isInteger(priority) && priority >= 0 && priority <= 100000 ? priority : 100,
    match_field: normalizeMatchField(body?.matchField ?? body?.match_field),
    pattern,
    case_sensitive: body?.caseSensitive === true || body?.case_sensitive === 1 ? 1 : 0,
    min_speed_mbps: minSpeedMbps,
    max_speed_mbps: maxSpeedMbps,
    boundary: boundary === 'unknown' ? '' : boundary,
    connectivity,
    comment: String(body?.comment ?? '').trim(),
    enabled: body?.enabled === false || body?.enabled === 0 ? 0 : 1,
    deleted: 0,
  };
}

async function saveInterfaceRoleRule(body = {}) {
  const record = await buildRuleRecord(body);
  const { elapsedMs } = await insertRows(config.interfaceRoleRulesTable, [record], {
    name: 'refs/interface-role-rule-save',
  });
  const materialized = await materializeEffectiveRoles();
  return { elapsedMs, ruleId: record.rule_id, materialized };
}

async function deleteInterfaceRoleRule(body = {}) {
  const ruleId = String(body?.ruleId ?? body?.rule_id ?? '').trim();
  if (!ruleId) throw apiError('Не указано правило');
  const existing = await fetchRuleById(ruleId);
  if (!existing) throw apiError('Правило не найдено', 404);

  const { elapsedMs } = await insertRows(config.interfaceRoleRulesTable, [{
    rule_id: existing.ruleId,
    priority: existing.priority,
    match_field: existing.matchField,
    pattern: existing.pattern,
    case_sensitive: existing.caseSensitive ? 1 : 0,
    min_speed_mbps: existing.minSpeedMbps,
    max_speed_mbps: existing.maxSpeedMbps,
    boundary: existing.boundary,
    connectivity: existing.connectivity,
    comment: existing.comment,
    enabled: 0,
    deleted: 1,
  }], { name: 'refs/interface-role-rule-delete' });

  const materialized = await materializeEffectiveRoles();
  return { elapsedMs, ruleId, materialized };
}

/** Какие порты попадут под правило — предпросмотр до сохранения. */
async function previewInterfaceRoleRule(body = {}) {
  const pattern = String(body?.pattern ?? '').trim();
  if (pattern) await assertValidPattern(pattern);

  const rule = {
    matchField: normalizeMatchField(body?.matchField ?? body?.match_field),
    pattern,
    caseSensitive: body?.caseSensitive === true || body?.case_sensitive === 1,
    minSpeedMbps: parseSpeedMbps(body?.minSpeedMbps ?? body?.min_speed_mbps, 'Минимальная скорость'),
    maxSpeedMbps: parseSpeedMbps(body?.maxSpeedMbps ?? body?.max_speed_mbps, 'Максимальная скорость'),
  };
  if (!rule.pattern && !rule.minSpeedMbps && !rule.maxSpeedMbps) {
    throw apiError('Укажите шаблон или диапазон скорости');
  }
  const limit = Math.min(Math.max(Number(body?.limit) || 50, 1), 500);

  return {
    sql: `
      SELECT
        i.switch_ip AS switch_ip,
        i.if_index AS if_index,
        i.if_name AS if_name,
        i.if_alias AS if_alias,
        i.if_descr AS if_descr,
        ${speedMbpsExpr('i')} AS speed_mbps,
        count() OVER () AS total_matched
      FROM ${netInterfacesCurrentRef()} AS i
      WHERE ${ruleMatchSql(rule, 'i')}
      ORDER BY i.switch_ip, i.if_index
      LIMIT {limit:UInt32}
    `,
    params: { limit },
    map(rows) {
      return {
        total: rows.length ? Number(rows[0].total_matched) || rows.length : 0,
        interfaces: rows.map((r) => ({
          switchIp: String(r.switch_ip ?? ''),
          ifIndex: Number(r.if_index) || 0,
          ifName: String(r.if_name ?? ''),
          ifAlias: String(r.if_alias ?? ''),
          ifDescr: String(r.if_descr ?? ''),
          speedMbps: Number(r.speed_mbps) || 0,
        })),
      };
    },
  };
}

/* ------------------------------------------------------------------ */
/* Порты и ручная разметка                                             */
/* ------------------------------------------------------------------ */

/** Порты коммутатора: ручная разметка, правила и итоговые значения. */
async function listInterfaceRoles(switchIp) {
  const ip = String(switchIp || '').trim();
  if (!net.isIP(ip)) throw apiError('Некорректный IP коммутатора');
  const [rules, settings] = await Promise.all([fetchActiveRules(), fetchDirectionSettings()]);
  const parts = effectiveSqlParts(rules, settings);

  return {
    sql: `
      SELECT
        i.if_index AS if_index,
        i.if_name AS if_name,
        i.if_alias AS if_alias,
        i.if_descr AS if_descr,
        ${speedMbpsExpr('i')} AS speed_mbps,
        i.updated_at AS updated_at,
        o.boundary AS manual_boundary,
        o.connectivity AS manual_connectivity,
        o.comment AS manual_comment,
        ${parts.boundary} AS boundary,
        ${parts.boundarySource} AS boundary_source,
        ${parts.boundaryRuleId} AS boundary_rule_id,
        ${parts.connectivity} AS connectivity,
        ${parts.connectivitySource} AS connectivity_source,
        ${parts.connectivityRuleId} AS connectivity_rule_id
      FROM ${netInterfacesCurrentRef()} AS i
      LEFT JOIN ${interfaceRolesViewRef()} AS o
        ON o.switch_ip = i.switch_ip AND o.if_index = i.if_index
      WHERE i.switch_ip = {switch_ip:String}
      ORDER BY i.if_index
    `,
    params: { switch_ip: ip },
    map(rows) {
      return rows.map((r) => ({
        ifIndex: Number(r.if_index) || 0,
        ifName: String(r.if_name ?? ''),
        ifAlias: String(r.if_alias ?? ''),
        ifDescr: String(r.if_descr ?? ''),
        speedMbps: Number(r.speed_mbps) || 0,
        boundary: normalizeBoundary(r.boundary),
        boundarySource: String(r.boundary_source ?? 'default'),
        boundaryRuleId: String(r.boundary_rule_id ?? ''),
        connectivity: normalizeConnectivity(r.connectivity),
        connectivitySource: String(r.connectivity_source ?? 'default'),
        connectivityRuleId: String(r.connectivity_rule_id ?? ''),
        manualBoundary: normalizeBoundary(r.manual_boundary, ''),
        manualConnectivity: normalizeConnectivity(r.manual_connectivity),
        manualComment: String(r.manual_comment ?? ''),
        updatedAt: r.updated_at ?? null,
      }));
    },
  };
}

function parseInterfaceKey(entry) {
  const switchIp = String(entry?.switchIp ?? entry?.switch_ip ?? '').trim();
  if (!net.isIP(switchIp)) throw apiError('Некорректный IP коммутатора');
  const ifIndex = Number(entry?.ifIndex ?? entry?.if_index);
  if (!Number.isInteger(ifIndex) || ifIndex <= 0 || ifIndex > 4294967295) {
    throw apiError('Некорректный ifIndex');
  }
  return { switchIp, ifIndex };
}

/** Ручная разметка одного или нескольких портов; перекрывает правила. */
async function saveInterfaceRole(body = {}, { updatedBy = '' } = {}) {
  const entries = Array.isArray(body?.interfaces) && body.interfaces.length
    ? body.interfaces
    : [body];
  const author = String(updatedBy || '').slice(0, 128);

  const records = entries.map((entry) => {
    const { switchIp, ifIndex } = parseInterfaceKey(entry);
    const boundary = normalizeBoundary(entry?.boundary ?? body?.boundary, '');
    const connectivity = normalizeConnectivity(entry?.connectivity ?? body?.connectivity);
    if ((boundary === '' || boundary === 'unknown') && !connectivity) {
      throw apiError('Укажите сторону сети или тип стыка');
    }
    return {
      switch_ip: switchIp,
      if_index: ifIndex,
      boundary: boundary === 'unknown' ? '' : boundary,
      connectivity,
      comment: String(entry?.comment ?? body?.comment ?? '').trim(),
      updated_by: author,
      deleted: 0,
    };
  });

  const { elapsedMs } = await insertRows(config.interfaceRolesTable, records, {
    name: 'refs/interface-role-save',
  });
  const materialized = await materializeEffectiveRoles();
  return { elapsedMs, interfaces: records.length, materialized };
}

/** Снять ручную разметку — порт возвращается под управление правил. */
async function deleteInterfaceRole(body = {}, { updatedBy = '' } = {}) {
  const entries = Array.isArray(body?.interfaces) && body.interfaces.length
    ? body.interfaces
    : [body];
  const author = String(updatedBy || '').slice(0, 128);

  const records = entries.map((entry) => {
    const { switchIp, ifIndex } = parseInterfaceKey(entry);
    return {
      switch_ip: switchIp,
      if_index: ifIndex,
      boundary: '',
      connectivity: '',
      comment: '',
      updated_by: author,
      deleted: 1,
    };
  });

  const { elapsedMs } = await insertRows(config.interfaceRolesTable, records, {
    name: 'refs/interface-role-delete',
  });
  const materialized = await materializeEffectiveRoles();
  return { elapsedMs, interfaces: records.length, materialized };
}

/**
 * Пересчёт плоской таблицы разметки.
 * Её читают отчёты и (на следующем этапе) коллектор — чтобы не тянуть
 * правила и regex в горячий путь обработки потоков.
 */
async function materializeEffectiveRoles() {
  const [rules, settings] = await Promise.all([fetchActiveRules(), fetchDirectionSettings()]);
  const parts = effectiveSqlParts(rules, settings);
  const { elapsedMs } = await executeCommand(
    `
      INSERT INTO ${interfaceRolesEffectiveTableRef()}
        (switch_ip, if_index, boundary, boundary_source, boundary_rule_id,
         connectivity, connectivity_source, connectivity_rule_id, updated_at)
      SELECT
        i.switch_ip AS switch_ip,
        i.if_index AS if_index,
        ${parts.boundary} AS boundary,
        ${parts.boundarySource} AS boundary_source,
        ${parts.boundaryRuleId} AS boundary_rule_id,
        ${parts.connectivity} AS connectivity,
        ${parts.connectivitySource} AS connectivity_source,
        ${parts.connectivityRuleId} AS connectivity_rule_id,
        now() AS updated_at
      FROM ${netInterfacesCurrentRef()} AS i
      LEFT JOIN ${interfaceRolesViewRef()} AS o
        ON o.switch_ip = i.switch_ip AND o.if_index = i.if_index
    `,
    {},
    { name: 'refs/interface-roles-materialize' },
  );
  return { elapsedMs, rules: rules.length, defaultBoundary: settings.defaultBoundary };
}

/** Сводка разметки: сколько портов по сторонам и откуда значение. */
function getInterfaceRoleSummary() {
  return {
    sql: `
      SELECT
        boundary,
        boundary_source,
        connectivity,
        count() AS interfaces,
        uniqExact(switch_ip) AS switches
      FROM ${interfaceRolesEffectiveViewRef()}
      GROUP BY boundary, boundary_source, connectivity
    `,
    params: {},
    map(rows) {
      const byBoundary = new Map();
      const byConnectivity = new Map();
      let total = 0;
      let classified = 0;
      let manual = 0;

      for (const r of rows) {
        const boundary = normalizeBoundary(r.boundary);
        const connectivity = normalizeConnectivity(r.connectivity);
        const interfaces = Number(r.interfaces) || 0;
        total += interfaces;
        if (boundary !== 'unknown') classified += interfaces;
        if (String(r.boundary_source) === 'manual') manual += interfaces;

        const b = byBoundary.get(boundary)
          || { boundary, label: BOUNDARY_LABELS[boundary], interfaces: 0 };
        b.interfaces += interfaces;
        byBoundary.set(boundary, b);

        const c = byConnectivity.get(connectivity)
          || { connectivity, label: CONNECTIVITY_LABELS[connectivity], interfaces: 0 };
        c.interfaces += interfaces;
        byConnectivity.set(connectivity, c);
      }

      return {
        total,
        classified,
        manual,
        classifiedPercent: total ? Math.round((classified * 10000) / total) / 100 : 0,
        boundaries: [...byBoundary.values()].sort((a, b) => b.interfaces - a.interfaces),
        connectivity: [...byConnectivity.values()].sort((a, b) => b.interfaces - a.interfaces),
      };
    },
  };
}

module.exports = {
  BOUNDARY_VALUES,
  BOUNDARY_LABELS,
  CONNECTIVITY_VALUES,
  CONNECTIVITY_LABELS,
  MATCH_FIELDS,
  ONE_SIDED_POLICIES,
  DIRECTION_MODES,
  DEFAULT_SETTINGS,
  fetchDirectionSettings,
  getDirectionSettings,
  saveDirectionSettings,
  portDirectionSql,
  listInterfaceRoleRules,
  saveInterfaceRoleRule,
  deleteInterfaceRoleRule,
  previewInterfaceRoleRule,
  listInterfaceRoles,
  saveInterfaceRole,
  deleteInterfaceRole,
  materializeEffectiveRoles,
  getInterfaceRoleSummary,
};
