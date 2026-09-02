'use strict';

const { query, executeCommand, insertRows, config } = require('./clickhouse');
const { tableRef, ensureDetectionTables } = require('./detection-schema');
const { formatCh, parseUtc } = require('./detection-core');
const {
  KINDS,
  KIND_LABEL,
  classifyFromMetrics,
  refineClassification,
  isAttackKind,
  formatSwitchPort,
  formatVictim,
  formatSourceNets,
  formatL4Sources,
  actionFor,
  volumeStillHigh,
} = require('./detection-classify');
const { loadHourEnvelope, investigateIncident, emptyInvestigate } = require('./detection-investigate');

const SETTINGS_TABLE = 'app_detection_telegram';
const SETTINGS_VIEW = 'app_detection_telegram_current';
const EVENTS_TABLE = 'app_detection_events';
const SETTINGS_ID = 'global';
const DEFAULT_GROWTH_THRESHOLD = 1.6;
const DEFAULT_ALERT_SCOPE = 'all';
const DEFAULT_STREAK = 3;
const DEFAULT_NORMALIZE_STREAK = 3;
const DEFAULT_TELEGRAM_API_URL = 'https://api.telegram.org';
const MAX_STREAK = 60;
const ALERT_SCOPES = new Set(['all', 'client', 'net']);
const ALERT_SCOPE_LABEL = { all: 'всё', client: 'абоненты', net: 'сети' };
const PROTO_LABEL = { all: 'общее', tcp: 'TCP', udp: 'UDP' };
const SNAPSHOT_FIELDS = [
  'bps', 'pps', 'growth_bps', 'growth_pps', 'bytes', 'packets',
  'avg_packet_bytes', 'cv_percent',
  'syn_attempts', 'syn_answered', 'syn_in_flows', 'syn_half_open', 'syn_half_open_reply',
  'answer_pct', 'half_open_pct', 'half_open_reply_pct',
  'port_entropy', 'port_entropy_out', 'ports_per_ip', 'ports_per_ip_out',
];
const SNAPSHOT_CAMEL = {
  growth_bps: 'growthBps',
  growth_pps: 'growthPps',
  avg_packet_bytes: 'avgPacketBytes',
  cv_percent: 'cvPercent',
  syn_attempts: 'synAttempts',
  syn_answered: 'synAnswered',
  syn_in_flows: 'synInFlows',
  syn_half_open: 'synHalfOpen',
  syn_half_open_reply: 'synHalfOpenReply',
  answer_pct: 'answerPct',
  half_open_pct: 'halfOpenPct',
  half_open_reply_pct: 'halfOpenReplyPct',
  port_entropy: 'portEntropy',
  port_entropy_out: 'portEntropyOut',
  ports_per_ip: 'portsPerIp',
  ports_per_ip_out: 'portsPerIpOut',
};

const DEFAULT_SETTINGS = {
  bot_token: '',
  chat_id: '',
  growth_threshold: DEFAULT_GROWTH_THRESHOLD,
  alert_scope: DEFAULT_ALERT_SCOPE,
  streak: DEFAULT_STREAK,
  normalize_streak: DEFAULT_NORMALIZE_STREAK,
  api_url: DEFAULT_TELEGRAM_API_URL,
  enabled: 0,
};

let ensurePromise = null;

function apiError(message, statusCode = 400) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function boolInt(value, fallback) {
  if (value === undefined) return fallback;
  return value === true || value === 1 || value === '1' ? 1 : 0;
}

function settingsTableRef() {
  return `${config.database}.${SETTINGS_TABLE}`;
}

function settingsViewRef() {
  return `${config.database}.${SETTINGS_VIEW}`;
}

function normalizeAlertScope(value, fallback = DEFAULT_ALERT_SCOPE) {
  const v = String(value || '').trim().toLowerCase();
  return ALERT_SCOPES.has(v) ? v : fallback;
}

function normalizeStreak(value, fallback = DEFAULT_STREAK) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(MAX_STREAK, Math.round(n));
}

function normalizeTelegramApiUrl(value, fallback = DEFAULT_TELEGRAM_API_URL) {
  const raw = String(value ?? '').trim();
  if (!raw) return fallback;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw apiError('API Telegram: укажите http(s) URL, например https://tba.pinspb.ru');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw apiError('API Telegram: только http или https');
  }
  parsed.hash = '';
  parsed.search = '';
  parsed.pathname = parsed.pathname.replace(/\/+$/, '').replace(/\/bot$/i, '');
  return parsed.toString().replace(/\/+$/, '');
}

function telegramMethodUrl(apiUrl, botToken, method) {
  const base = normalizeTelegramApiUrl(apiUrl);
  return `${base}/bot${encodeURIComponent(botToken)}/${method}`;
}

function matchesAlertScope(row, alertScope) {
  const scope = normalizeAlertScope(alertScope);
  if (scope === 'all') return true;
  return String(row?.scope || '') === scope;
}

function mapSettings(row = {}) {
  return {
    enabled: Number(row.enabled) === 1,
    chatId: String(row.chat_id ?? ''),
    tokenSet: Boolean(String(row.bot_token ?? '')),
    growthThreshold: Number(row.growth_threshold) || DEFAULT_GROWTH_THRESHOLD,
    alertScope: normalizeAlertScope(row.alert_scope),
    streak: normalizeStreak(row.streak),
    normalizeStreak: normalizeStreak(row.normalize_streak, DEFAULT_NORMALIZE_STREAK),
    apiUrl: (() => {
      try {
        return normalizeTelegramApiUrl(row.api_url);
      } catch {
        return DEFAULT_TELEGRAM_API_URL;
      }
    })(),
    updatedAt: row.updated_at ?? null,
  };
}

function finiteGrowth(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function isAboveGrowthThreshold(row, threshold) {
  const gBps = finiteGrowth(row?.growth_bps ?? row?.growthBps);
  const gPps = finiteGrowth(row?.growth_pps ?? row?.growthPps);
  const t = Number(threshold) || DEFAULT_GROWTH_THRESHOLD;
  return (gBps != null && gBps >= t) || (gPps != null && gPps >= t);
}

function shouldSendAlert(historyNewestFirst, threshold, streak = DEFAULT_STREAK, enabledAtMs) {
  const need = normalizeStreak(streak);
  const history = Array.isArray(historyNewestFirst) ? historyNewestFirst : [];
  if (!history.length || !isAboveGrowthThreshold(history[0], threshold)) return false;
  if (history.length < need) return false;
  const window = history.slice(0, need);
  if (!window.every((row) => isAboveGrowthThreshold(row, threshold))) return false;
  const before = history[need];
  if (!before) return true;
  if (!isAboveGrowthThreshold(before, threshold)) return true;
  if (enabledAtMs) {
    const beforeTs = parseUtc(before.minute);
    if (Number.isFinite(beforeTs) && beforeTs < enabledAtMs) return true;
  }
  return false;
}

function shouldSendNormalize(historyNewestFirst, threshold, streak = DEFAULT_NORMALIZE_STREAK, options = {}) {
  const need = normalizeStreak(streak, DEFAULT_NORMALIZE_STREAK);
  const history = Array.isArray(historyNewestFirst) ? historyNewestFirst : [];
  if (!history.length || isAboveGrowthThreshold(history[0], threshold)) return false;
  if (history.length < need) return false;
  if (!history.slice(0, need).every((row) => !isAboveGrowthThreshold(row, threshold))) return false;
  if (volumeStillHigh(history[0]?.bps, options.alertBps, options.hourP95)) return false;
  return true;
}

function objectKey(scope, scopeId) {
  return `${scope}|${scopeId}`;
}

function eventsTableRef() {
  return `${config.database}.${EVENTS_TABLE}`;
}

function snapshotProto(row) {
  if (!row) return null;
  const out = {};
  for (const field of SNAPSHOT_FIELDS) {
    const camel = SNAPSHOT_CAMEL[field];
    const value = row[field] ?? (camel ? row[camel] : undefined);
    out[field] = value == null || value === '' ? null : value;
  }
  return out;
}

function snapshotByProto(group, fallbackRow) {
  const byProto = group?.byProto || {};
  return {
    all: snapshotProto(byProto.all || fallbackRow),
    tcp: snapshotProto(byProto.tcp),
    udp: snapshotProto(byProto.udp),
  };
}

function parseSnapshot(raw) {
  if (!raw) return {};
  if (typeof raw === 'object') return raw;
  try {
    return JSON.parse(String(raw));
  } catch {
    return {};
  }
}

function mapSnapshotToUi(snapshot) {
  const byProto = {};
  for (const proto of ['all', 'tcp', 'udp']) {
    const row = snapshot?.[proto];
    if (!row) continue;
    const mapped = { proto };
    for (const field of SNAPSHOT_FIELDS) {
      const camel = SNAPSHOT_CAMEL[field] || field;
      const value = row[field];
      mapped[camel] = value == null ? null : Number(value);
    }
    byProto[proto] = mapped;
  }
  return byProto;
}

function uiByProtoToSnapshot(byProto) {
  const out = {};
  for (const proto of ['all', 'tcp', 'udp']) {
    const ui = byProto?.[proto];
    if (!ui) {
      out[proto] = null;
      continue;
    }
    const snake = {};
    for (const field of SNAPSHOT_FIELDS) {
      const camel = SNAPSHOT_CAMEL[field] || field;
      snake[field] = ui[camel] ?? ui[field] ?? null;
    }
    out[proto] = snake;
  }
  return out;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function formatRateMsg(value, units) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return '—';
  let v = n;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  const digits = v < 10 ? 2 : v < 100 ? 1 : 0;
  return `${v.toFixed(digits)} ${units[i]}`;
}

function formatBpsMsg(value) {
  return formatRateMsg(value, ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с', 'Тбит/с']);
}

function formatPpsMsg(value) {
  return formatRateMsg(value, ['п/с', 'тыс. п/с', 'млн п/с', 'млрд п/с']);
}

function formatGrowthMsg(value) {
  const n = finiteGrowth(value);
  return n == null ? 'пусто' : `×${n.toFixed(2)}`;
}

function formatPctMsg(value) {
  const n = finiteGrowth(value);
  return n == null ? '—' : `${n.toFixed(1)}%`;
}

function formatNumMsg(value, digits = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  return n.toLocaleString('ru-RU', { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

function formatMinuteMsk(minute) {
  const ts = parseUtc(minute);
  if (!Number.isFinite(ts)) return String(minute || '—');
  return `${new Date(ts).toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })} МСК`;
}

function formatProtoBlock(proto, row) {
  if (!row) return `${PROTO_LABEL[proto] || proto}\n  нет данных`;
  const lines = [
    `${PROTO_LABEL[proto] || proto}`,
    `  bps: ${formatBpsMsg(row.bps)}`,
    `  pps: ${formatPpsMsg(row.pps)}`,
    `  рост bps: ${formatGrowthMsg(row.growth_bps)}`,
    `  рост pps: ${formatGrowthMsg(row.growth_pps)}`,
  ];
  if (proto === 'udp') {
    lines.push('  попытки / ответ / полуоткрытые / не зашли: —');
  } else {
    lines.push(`  попытки: ${formatNumMsg(row.syn_attempts, 0)}`);
    lines.push(`  ответ: ${formatPctMsg(row.answer_pct)}`);
    lines.push(`  полуоткрытые: ${formatPctMsg(row.half_open_pct)}`);
    lines.push(`  не зашли: ${formatPctMsg(row.half_open_reply_pct)}`);
  }
  lines.push(`  энтропия портов вх.: ${formatNumMsg(row.port_entropy, 2)}`);
  lines.push(`  энтропия портов исх.: ${formatNumMsg(row.port_entropy_out, 2)}`);
  lines.push(`  макс. портов/IP вх.: ${formatNumMsg(row.ports_per_ip, 0)}`);
  lines.push(`  макс. портов/IP исх.: ${formatNumMsg(row.ports_per_ip_out, 0)}`);
  lines.push(`  средний пакет: ${formatNumMsg(row.avg_packet_bytes, 0)} Б`);
  lines.push(`  CV: ${row.cv_percent == null ? '—' : `${formatNumMsg(row.cv_percent, 1)}%`}`);
  return lines.join('\n');
}

function formatAlertMessage({
  name,
  scope,
  scopeId,
  minute,
  threshold,
  streak = DEFAULT_STREAK,
  alertScope = DEFAULT_ALERT_SCOPE,
  byProto,
  verdict,
  investigate,
}) {
  const kind = scope === 'net' ? 'сеть /24' : 'абонент';
  const verdictKind = verdict?.kind || '';
  const title = isAttackKind(verdictKind)
    ? `🔴 ДЕТЕКЦИЯ · ${KIND_LABEL[verdictKind] || verdictKind}`
    : verdictKind === KINDS.benign_peak
      ? `🟡 ПИК НАГРУЗКИ · ${KIND_LABEL[verdictKind]}`
      : '🔴 Детекция: рост выше порога';
  const hour = verdict?.hourRatio != null
    ? `×${Number(verdict.hourRatio).toFixed(2)} к норме часа`
    : formatGrowthMsg(byProto?.all?.growth_bps);
  const header = [
    title,
    '',
    `Объект: ${name || scopeId}`,
    `Тип объекта: ${kind}`,
    `ID: ${scopeId}`,
    `Минута: ${formatMinuteMsk(minute)}`,
    `Объём: ${formatBpsMsg(byProto?.all?.bps)} · рост ${hour}`,
    verdict?.reason ? `Почему: ${verdict.reason}` : '',
    `Куда: ${formatVictim(investigate?.victim)}`,
    `Откуда сети: ${formatSourceNets(investigate?.source24)}`,
    `Коммутатор вход: ${formatSwitchPort(investigate?.switchIn)}`,
    `Коммутатор выход: ${formatSwitchPort(investigate?.switchOut)}`,
    `L4 откуда: ${formatL4Sources(investigate?.l4src)}`,
    `Что делать: ${actionFor(verdict, investigate)}`,
    `Порог: ×${Number(threshold).toFixed(2)} (bps или pps)`,
    `Стабильно: ${normalizeStreak(streak)} знач. подряд`,
    `Объекты: ${ALERT_SCOPE_LABEL[normalizeAlertScope(alertScope)] || 'всё'}`,
    '',
  ].filter((line, idx, arr) => line !== '' || arr[idx - 1] !== '');
  const body = ['all', 'tcp', 'udp'].map((proto) => formatProtoBlock(proto, byProto?.[proto]));
  return [...header, ...body].join('\n');
}

function formatNormalizeMessage({
  name,
  scope,
  scopeId,
  minute,
  alertMinute,
  threshold,
  streak = DEFAULT_NORMALIZE_STREAK,
  byProto,
}) {
  const kind = scope === 'net' ? 'сеть /24' : 'абонент';
  const header = [
    '🟢 Детекция: нормализация',
    '',
    `Объект: ${name || scopeId}`,
    `Тип: ${kind}`,
    `ID: ${scopeId}`,
    `Алерт: ${formatMinuteMsk(alertMinute)}`,
    `Нормализация: ${formatMinuteMsk(minute)}`,
    `Порог: ×${Number(threshold).toFixed(2)} (bps или pps)`,
    `Ниже нормы: ${normalizeStreak(streak, DEFAULT_NORMALIZE_STREAK)} знач. подряд`,
    '',
  ];
  const body = ['all', 'tcp', 'udp'].map((proto) => formatProtoBlock(proto, byProto[proto]));
  return [...header, ...body].join('\n');
}

function pickAlertCandidates(allRows, previousByKey, threshold, options = {}) {
  const streak = normalizeStreak(options.streak);
  const enabledAtMs = options.enabledAtMs;
  const alertScope = normalizeAlertScope(options.alertScope);
  const activeKeys = options.activeKeys instanceof Set ? options.activeKeys : new Set();
  const out = [];
  for (const row of allRows) {
    if (String(row.proto || '') !== 'all') continue;
    if (!matchesAlertScope(row, alertScope)) continue;
    const key = objectKey(row.scope, row.scope_id);
    if (activeKeys.has(key)) continue;
    const prev = previousByKey.get(key) || [];
    const history = [row, ...prev];
    if (shouldSendAlert(history, threshold, streak, enabledAtMs)) out.push({ row, key });
  }
  return out;
}

function pickNormalizeCandidates(allRows, previousByKey, threshold, options = {}) {
  const streak = normalizeStreak(options.streak, DEFAULT_NORMALIZE_STREAK);
  const activeByKey = options.activeByKey instanceof Map ? options.activeByKey : new Map();
  const out = [];
  for (const row of allRows) {
    if (String(row.proto || '') !== 'all') continue;
    const key = objectKey(row.scope, row.scope_id);
    const active = activeByKey.get(key);
    if (!active) continue;
    const prev = previousByKey.get(key) || [];
    const history = [row, ...prev];
    const alertBps = active.alertByProto?.all?.bps ?? active.alertBps;
    const hourP95 = active.verdict?.hourP95;
    if (shouldSendNormalize(history, threshold, streak, { alertBps, hourP95 })) {
      out.push({ row, key, active });
    }
  }
  return out;
}

function groupRowsByObject(rows) {
  const map = new Map();
  for (const row of rows) {
    const key = objectKey(row.scope, row.scope_id);
    const cur = map.get(key) || { scope: row.scope, scope_id: row.scope_id, byProto: {} };
    cur.byProto[row.proto] = row;
    map.set(key, cur);
  }
  return map;
}

async function ensureDetectionTelegramTables() {
  if (!ensurePromise) {
    ensurePromise = (async () => {
      await executeCommand(`
        CREATE TABLE IF NOT EXISTS ${settingsTableRef()}
        (
          settings_id String DEFAULT 'global',
          bot_token String DEFAULT '',
          chat_id String DEFAULT '',
          growth_threshold Float64 DEFAULT ${DEFAULT_GROWTH_THRESHOLD},
          alert_scope String DEFAULT '${DEFAULT_ALERT_SCOPE}',
          streak UInt16 DEFAULT ${DEFAULT_STREAK},
          normalize_streak UInt16 DEFAULT ${DEFAULT_NORMALIZE_STREAK},
          api_url String DEFAULT '${DEFAULT_TELEGRAM_API_URL}',
          enabled UInt8 DEFAULT 0,
          updated_at DateTime('UTC') DEFAULT now()
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY settings_id
        SETTINGS index_granularity = 8192
      `, {}, { name: 'detection/telegram-ensure-table' });

      await executeCommand(`
        ALTER TABLE ${settingsTableRef()}
          ADD COLUMN IF NOT EXISTS alert_scope String DEFAULT '${DEFAULT_ALERT_SCOPE}',
          ADD COLUMN IF NOT EXISTS streak UInt16 DEFAULT ${DEFAULT_STREAK},
          ADD COLUMN IF NOT EXISTS normalize_streak UInt16 DEFAULT ${DEFAULT_NORMALIZE_STREAK},
          ADD COLUMN IF NOT EXISTS api_url String DEFAULT '${DEFAULT_TELEGRAM_API_URL}'
      `, {}, { name: 'detection/telegram-ensure-columns' });

      await executeCommand(`
        CREATE TABLE IF NOT EXISTS ${eventsTableRef()}
        (
          event_id String,
          scope LowCardinality(String),
          scope_id String,
          name String DEFAULT '',
          status LowCardinality(String),
          alert_minute DateTime('UTC'),
          normalize_minute Nullable(DateTime('UTC')),
          alert_json String DEFAULT '',
          normalize_json String DEFAULT '',
          threshold Float64 DEFAULT ${DEFAULT_GROWTH_THRESHOLD},
          updated_at DateTime('UTC') DEFAULT now()
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (scope, scope_id, event_id)
        TTL alert_minute + toIntervalDay(90)
        SETTINGS index_granularity = 8192
      `, {}, { name: 'detection/events-ensure-table' });

      await executeCommand(`
        CREATE OR REPLACE VIEW ${settingsViewRef()}
        (
          settings_id String,
          bot_token String,
          chat_id String,
          growth_threshold Float64,
          alert_scope String,
          streak UInt16,
          normalize_streak UInt16,
          api_url String,
          enabled UInt8,
          updated_at DateTime('UTC')
        )
        AS SELECT
          settings_id,
          bot_token,
          chat_id,
          growth_threshold,
          alert_scope,
          streak,
          normalize_streak,
          api_url,
          enabled,
          updated_at_latest AS updated_at
        FROM
        (
          SELECT
            settings_id,
            argMax(bot_token, updated_at) AS bot_token,
            argMax(chat_id, updated_at) AS chat_id,
            argMax(growth_threshold, updated_at) AS growth_threshold,
            argMax(alert_scope, updated_at) AS alert_scope,
            argMax(streak, updated_at) AS streak,
            argMax(normalize_streak, updated_at) AS normalize_streak,
            argMax(api_url, updated_at) AS api_url,
            argMax(enabled, updated_at) AS enabled,
            max(updated_at) AS updated_at_latest
          FROM ${settingsTableRef()}
          GROUP BY settings_id
        )
      `, {}, { name: 'detection/telegram-ensure-view' });
    })().catch((err) => {
      ensurePromise = null;
      throw err;
    });
  }
  return ensurePromise;
}

async function getCurrentSettingsRaw() {
  await ensureDetectionTelegramTables();
  const { rows } = await query(`
    SELECT bot_token, chat_id, growth_threshold, alert_scope, streak, normalize_streak, api_url, enabled, updated_at
    FROM ${settingsViewRef()}
    WHERE settings_id = {id:String}
    LIMIT 1
  `, { id: SETTINGS_ID }, { name: 'detection/telegram-settings-current' });
  return rows[0] || null;
}

async function getDetectionTelegramSettings() {
  return mapSettings(await getCurrentSettingsRaw() || DEFAULT_SETTINGS);
}

async function saveDetectionTelegramSettings(payload = {}) {
  const existing = await getCurrentSettingsRaw();
  const base = existing || DEFAULT_SETTINGS;
  const replacement = String(payload.botToken ?? payload.bot_token ?? '').trim();
  const botToken = replacement || String(base.bot_token ?? '');
  const enabled = boolInt(payload.enabled, Number(base.enabled) === 1 ? 1 : 0);
  const chatId = String(payload.chatId ?? payload.chat_id ?? base.chat_id ?? '').trim();
  const thresholdRaw = payload.growthThreshold ?? payload.growth_threshold ?? base.growth_threshold;
  const growthThreshold = Number(thresholdRaw);
  if (!Number.isFinite(growthThreshold) || growthThreshold <= 0 || growthThreshold > 1000) {
    throw apiError('Порог роста: число от 0.01 до 1000');
  }
  const alertScopeRaw = payload.alertScope ?? payload.alert_scope ?? base.alert_scope;
  if (alertScopeRaw != null && String(alertScopeRaw).trim() !== '' && !ALERT_SCOPES.has(String(alertScopeRaw).trim().toLowerCase())) {
    throw apiError('Объекты: выберите всё, абоненты или сети');
  }
  const alertScope = normalizeAlertScope(alertScopeRaw);
  const streakRaw = payload.streak ?? base.streak;
  const streakNum = Number(streakRaw);
  if (!Number.isFinite(streakNum) || streakNum < 1 || streakNum > MAX_STREAK) {
    throw apiError(`Подряд выше порога: целое от 1 до ${MAX_STREAK}`);
  }
  const streak = normalizeStreak(streakNum);
  const normalizeRaw = payload.normalizeStreak ?? payload.normalize_streak ?? base.normalize_streak;
  const normalizeNum = Number(normalizeRaw);
  if (!Number.isFinite(normalizeNum) || normalizeNum < 1 || normalizeNum > MAX_STREAK) {
    throw apiError(`Подряд ниже порога: целое от 1 до ${MAX_STREAK}`);
  }
  const normalizeStreakValue = normalizeStreak(normalizeNum, DEFAULT_NORMALIZE_STREAK);
  const apiUrl = normalizeTelegramApiUrl(payload.apiUrl ?? payload.api_url ?? base.api_url);
  if (enabled && (!botToken || !chatId)) {
    throw apiError('Укажите токен бота и id группы перед включением Telegram');
  }

  await insertRows(SETTINGS_TABLE, [{
    settings_id: SETTINGS_ID,
    bot_token: botToken,
    chat_id: chatId,
    growth_threshold: growthThreshold,
    alert_scope: alertScope,
    streak,
    normalize_streak: normalizeStreakValue,
    api_url: apiUrl,
    enabled,
  }], { name: 'detection/telegram-settings-save' });

  return getDetectionTelegramSettings();
}

async function loadTelegramConfig() {
  const raw = await getCurrentSettingsRaw();
  if (!raw || Number(raw.enabled) !== 1) {
    throw apiError('Telegram отключён или не настроен', 503);
  }
  const botToken = String(raw.bot_token ?? '').trim();
  const chatId = String(raw.chat_id ?? '').trim();
  if (!botToken || !chatId) {
    throw apiError('Telegram: не заданы токен или группа', 503);
  }
  return {
    botToken,
    chatId,
    apiUrl: (() => {
      try {
        return normalizeTelegramApiUrl(raw.api_url);
      } catch {
        return DEFAULT_TELEGRAM_API_URL;
      }
    })(),
    growthThreshold: Number(raw.growth_threshold) || DEFAULT_GROWTH_THRESHOLD,
    alertScope: normalizeAlertScope(raw.alert_scope),
    streak: normalizeStreak(raw.streak),
    normalizeStreak: normalizeStreak(raw.normalize_streak, DEFAULT_NORMALIZE_STREAK),
    enabledAtMs: parseUtc(raw.updated_at),
  };
}

async function sendTelegramMessage(text, cfg) {
  const configRow = cfg || await loadTelegramConfig();
  const apiUrl = configRow.apiUrl || DEFAULT_TELEGRAM_API_URL;
  const url = telegramMethodUrl(apiUrl, configRow.botToken, 'sendMessage');
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: configRow.chatId,
        text: String(text || ''),
        disable_web_page_preview: true,
      }),
    });
  } catch (err) {
    const cause = err.cause?.code || err.cause?.message || err.message;
    let host = apiUrl;
    try { host = new URL(apiUrl).host; } catch { /* keep */ }
    throw apiError(`Telegram: нет сети до ${host} (${cause})`, 502);
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.ok === false) {
    const detail = body.description || body.error || `HTTP ${res.status}`;
    throw apiError(`Telegram: ${detail}`, 502);
  }
  return body;
}

async function sendTestTelegramMessage() {
  return sendTelegramMessage('Grapes NTA: проверка Telegram. Оповещения детекции настроены.');
}

async function loadPreviousAllRows(minute, keys, limit = DEFAULT_STREAK) {
  if (!keys.length) return new Map();
  await ensureDetectionTables();
  const take = normalizeStreak(limit);
  const keySet = new Set(keys.map((k) => objectKey(k.scope, k.scopeId)));
  const { rows } = await query(`
    SELECT scope, scope_id, minute, growth_bps, growth_pps, bps
    FROM (
      SELECT
        scope,
        scope_id,
        minute,
        growth_bps,
        growth_pps,
        bps,
        row_number() OVER (PARTITION BY scope, scope_id ORDER BY minute DESC) AS rn
      FROM ${tableRef()} FINAL
      WHERE proto = 'all'
        AND minute < ${utcDateTime('before')}
    )
    WHERE rn <= {take:UInt16}
    ORDER BY minute DESC
  `, { before: formatCh(parseUtc(minute)), take }, { name: 'detection/telegram-prev-rows' });

  const map = new Map();
  for (const r of rows) {
    const key = objectKey(r.scope, r.scope_id);
    if (!keySet.has(key)) continue;
    const list = map.get(key) || [];
    list.push(r);
    map.set(key, list);
  }
  return map;
}

function utcDateTime(param) {
  return `toDateTime({${param}:String}, 'UTC')`;
}

function mapEventRow(row) {
  const alertSnapshot = parseSnapshot(row.alert_json);
  const normalizeSnapshot = parseSnapshot(row.normalize_json);
  return {
    id: String(row.event_id),
    scope: String(row.scope || ''),
    scopeId: String(row.scope_id || ''),
    name: String(row.name || row.scope_id || ''),
    status: String(row.status || ''),
    alertMinute: row.alert_minute || null,
    normalizeMinute: row.normalize_minute || null,
    threshold: Number(row.threshold) || DEFAULT_GROWTH_THRESHOLD,
    alertByProto: mapSnapshotToUi(alertSnapshot),
    normalizeByProto: mapSnapshotToUi(normalizeSnapshot),
    verdict: alertSnapshot.verdict || null,
    investigate: alertSnapshot.investigate || null,
  };
}

async function loadActiveEventsByKey() {
  await ensureDetectionTelegramTables();
  const { rows } = await query(`
    SELECT event_id, scope, scope_id, name, status, alert_minute, normalize_minute, alert_json, normalize_json, threshold
    FROM (
      SELECT
        event_id,
        argMax(scope, updated_at) AS scope,
        argMax(scope_id, updated_at) AS scope_id,
        argMax(name, updated_at) AS name,
        argMax(status, updated_at) AS status,
        argMax(alert_minute, updated_at) AS alert_minute,
        argMax(normalize_minute, updated_at) AS normalize_minute,
        argMax(alert_json, updated_at) AS alert_json,
        argMax(normalize_json, updated_at) AS normalize_json,
        argMax(threshold, updated_at) AS threshold
      FROM ${eventsTableRef()}
      GROUP BY event_id
    )
    WHERE status = 'active'
  `, {}, { name: 'detection/events-active' });
  const map = new Map();
  for (const row of rows) {
    map.set(objectKey(row.scope, row.scope_id), mapEventRow(row));
  }
  return map;
}

async function insertDetectionEvent(row) {
  await insertRows(EVENTS_TABLE, [row], { name: 'detection/events-insert' });
}

function parseEventBound(value, label) {
  if (value == null || value === '') return null;
  const ts = parseUtc(value);
  if (!Number.isFinite(ts)) throw apiError(`${label}: неверная дата/время`);
  return formatCh(ts);
}

async function loadDetectionEvents({ status = 'active', limit = 200, from, to } = {}) {
  await ensureDetectionTelegramTables();
  const wanted = String(status) === 'normalized' || String(status) === 'history'
    ? 'history'
    : 'active';
  const take = Math.min(10000, Math.max(1, Number(limit) || 200));
  const fromCh = parseEventBound(from, 'Начало периода');
  const toCh = parseEventBound(to, 'Конец периода');
  if (fromCh && toCh && parseUtc(fromCh) >= parseUtc(toCh)) {
    throw apiError('Начало периода должно быть раньше конца');
  }
  const timeCol = wanted === 'history'
    ? 'if(status = \'peak\', alert_minute, normalize_minute)'
    : 'alert_minute';
  const timeClauses = [];
  const params = { take };
  if (fromCh) {
    timeClauses.push(`${timeCol} >= ${utcDateTime('from')}`);
    params.from = fromCh;
  }
  if (toCh) {
    timeClauses.push(`${timeCol} < ${utcDateTime('to')}`);
    params.to = toCh;
  }
  const timeSql = timeClauses.length ? `AND ${timeClauses.join(' AND ')}` : '';
  const statusSql = wanted === 'history'
    ? `status IN ('normalized', 'peak')`
    : `status = 'active'`;
  const { rows } = await query(`
    SELECT event_id, scope, scope_id, name, status, alert_minute, normalize_minute, alert_json, normalize_json, threshold
    FROM (
      SELECT
        event_id,
        argMax(scope, updated_at) AS scope,
        argMax(scope_id, updated_at) AS scope_id,
        argMax(name, updated_at) AS name,
        argMax(status, updated_at) AS status,
        argMax(alert_minute, updated_at) AS alert_minute,
        argMax(normalize_minute, updated_at) AS normalize_minute,
        argMax(alert_json, updated_at) AS alert_json,
        argMax(normalize_json, updated_at) AS normalize_json,
        argMax(threshold, updated_at) AS threshold
      FROM ${eventsTableRef()}
      GROUP BY event_id
    )
    WHERE ${statusSql}
      ${timeSql}
    ORDER BY if(status = 'active', alert_minute, if(status = 'peak', alert_minute, normalize_minute)) DESC
    LIMIT {take:UInt16}
  `, params, { name: 'detection/events-list' });
  return rows.map(mapEventRow);
}

function csvEscape(value) {
  const s = String(value ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function csvCell(value) {
  if (value == null || value === '') return '';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return csvEscape(value);
}

function buildDetectionEventsCsv(events) {
  const metricHeaders = [
    'bps', 'pps', 'growth_bps', 'growth_pps',
    'syn_attempts', 'answer_pct', 'half_open_pct', 'half_open_reply_pct',
    'port_entropy', 'port_entropy_out', 'ports_per_ip', 'ports_per_ip_out',
    'avg_packet_bytes', 'cv_percent',
  ];
  const headers = [
    'event_id', 'scope', 'scope_id', 'name', 'status', 'phase', 'phase_minute',
    'proto', 'threshold', ...metricHeaders,
  ];
  const lines = [headers.join(',')];
  for (const event of events) {
    const phases = [
      { id: 'alert', minute: event.alertMinute, byProto: event.alertByProto },
      { id: 'normalize', minute: event.normalizeMinute, byProto: event.normalizeByProto },
    ];
    for (const phase of phases) {
      if (phase.id === 'normalize' && event.status !== 'normalized') continue;
      for (const proto of ['all', 'tcp', 'udp']) {
        const row = phase.byProto?.[proto] || {};
        const cells = [
          event.id,
          event.scope,
          event.scopeId,
          event.name,
          event.status,
          phase.id,
          phase.minute || '',
          proto,
          event.threshold,
          ...metricHeaders.map((field) => {
            const camel = SNAPSHOT_CAMEL[field] || field;
            return row[camel] ?? row[field] ?? '';
          }),
        ];
        lines.push(cells.map(csvCell).join(','));
      }
    }
  }
  return `\uFEFF${lines.join('\n')}`;
}

async function exportDetectionEventsCsv(options = {}) {
  const events = await loadDetectionEvents({
    status: options.status || 'normalized',
    from: options.from,
    to: options.to,
    limit: options.limit || 10000,
  });
  return {
    csv: buildDetectionEventsCsv(events),
    count: events.length,
  };
}

async function maybeSendTelegram(text, cfg) {
  if (!cfg) return { sent: false, skipped: 'disabled' };
  try {
    await sendTelegramMessage(text, cfg);
    return { sent: true };
  } catch (err) {
    return { sent: false, error: err.message };
  }
}

async function processDetectionAlerts({ minute, rows, nameByKey }) {
  await ensureDetectionTelegramTables();
  const raw = await getCurrentSettingsRaw();
  const settings = mapSettings(raw || DEFAULT_SETTINGS);
  let tgCfg = null;
  try {
    tgCfg = await loadTelegramConfig();
  } catch (err) {
    if (Number(err.statusCode) !== 503) throw err;
  }

  const allRows = rows.filter((r) => String(r.proto) === 'all' && matchesAlertScope(r, settings.alertScope));
  const grouped = groupRowsByObject(rows);
  const activeByKey = await loadActiveEventsByKey();
  const above = allRows.filter((r) => isAboveGrowthThreshold(r, settings.growthThreshold));
  const watchKeys = [];
  const seen = new Set();
  for (const row of [...above, ...allRows.filter((r) => activeByKey.has(objectKey(r.scope, r.scope_id)))]) {
    const key = objectKey(row.scope, row.scope_id);
    if (seen.has(key)) continue;
    seen.add(key);
    watchKeys.push({ scope: row.scope, scopeId: row.scope_id });
  }

  const take = Math.max(settings.streak, settings.normalizeStreak);
  const previousByKey = await loadPreviousAllRows(minute, watchKeys, take);
  const alertCandidates = pickAlertCandidates(allRows, previousByKey, settings.growthThreshold, {
    streak: settings.streak,
    enabledAtMs: settings.enabled && settings.updatedAt ? parseUtc(settings.updatedAt) : tgCfg?.enabledAtMs,
    alertScope: settings.alertScope,
    activeKeys: new Set(activeByKey.keys()),
  });
  const normalizeCandidates = pickNormalizeCandidates(allRows, previousByKey, settings.growthThreshold, {
    streak: settings.normalizeStreak,
    activeByKey,
  });

  if (!alertCandidates.length && !normalizeCandidates.length) {
    return {
      skipped: above.length ? 'waiting_streak' : (activeByKey.size ? 'waiting_normalize' : 'none_above'),
      sent: 0,
      above: above.length,
      active: activeByKey.size,
      streak: settings.streak,
      normalizeStreak: settings.normalizeStreak,
    };
  }

  let sent = 0;
  let opened = 0;
  let closed = 0;
  const errors = [];

  for (const { row, key } of alertCandidates) {
    const group = grouped.get(key);
    const name = nameByKey?.get(key) || row.scope_id;
    const byProto = group?.byProto || { all: row };
    let hour = { p95: null, p999: null };
    let investigate = emptyInvestigate();
    try {
      hour = await loadHourEnvelope({ scope: row.scope, scopeId: row.scope_id, minute });
    } catch (err) {
      errors.push({ key, message: `hour: ${err.message}` });
    }
    let verdict = classifyFromMetrics(byProto, hour);
    if (verdict.needsInvestigate) {
      try {
        investigate = await investigateIncident({ scope: row.scope, scopeId: row.scope_id, minute });
        verdict = refineClassification(verdict, investigate);
      } catch (err) {
        errors.push({ key, message: `investigate: ${err.message}` });
      }
    }
    const snapshot = {
      ...snapshotByProto(group, row),
      verdict,
      investigate,
    };
    const attack = isAttackKind(verdict.kind);
    const eventId = `${key}|${minute}`;
    await insertDetectionEvent({
      event_id: eventId,
      scope: row.scope,
      scope_id: row.scope_id,
      name,
      status: attack ? 'active' : 'peak',
      alert_minute: minute,
      normalize_minute: attack ? null : minute,
      alert_json: JSON.stringify(snapshot),
      normalize_json: '',
      threshold: settings.growthThreshold,
    });
    opened += 1;
    if (!attack) continue;
    const text = formatAlertMessage({
      name,
      scope: row.scope,
      scopeId: row.scope_id,
      minute,
      threshold: settings.growthThreshold,
      streak: settings.streak,
      alertScope: settings.alertScope,
      byProto,
      verdict,
      investigate,
    });
    const tg = await maybeSendTelegram(text, tgCfg);
    if (tg.sent) sent += 1;
    if (tg.error) errors.push({ key, message: tg.error });
  }

  for (const { row, key, active } of normalizeCandidates) {
    const group = grouped.get(key);
    const name = nameByKey?.get(key) || active.name || row.scope_id;
    const snapshot = snapshotByProto(group, row);
    await insertDetectionEvent({
      event_id: active.id,
      scope: active.scope,
      scope_id: active.scopeId,
      name,
      status: 'normalized',
      alert_minute: active.alertMinute,
      normalize_minute: minute,
      alert_json: JSON.stringify(uiByProtoToSnapshot(active.alertByProto)),
      normalize_json: JSON.stringify(snapshot),
      threshold: active.threshold || settings.growthThreshold,
    });
    closed += 1;
    const text = formatNormalizeMessage({
      name,
      scope: active.scope,
      scopeId: active.scopeId,
      minute,
      alertMinute: active.alertMinute,
      threshold: active.threshold || settings.growthThreshold,
      streak: settings.normalizeStreak,
      byProto: group?.byProto || { all: row },
    });
    const tg = await maybeSendTelegram(text, tgCfg);
    if (tg.sent) sent += 1;
    if (tg.error) errors.push({ key, message: tg.error });
  }

  return {
    sent,
    opened,
    closed,
    alerts: alertCandidates.length,
    normalized: normalizeCandidates.length,
    telegram: tgCfg ? 'on' : 'disabled',
    errors: errors.length ? errors : undefined,
  };
}

module.exports = {
  DEFAULT_GROWTH_THRESHOLD,
  DEFAULT_ALERT_SCOPE,
  DEFAULT_STREAK,
  DEFAULT_NORMALIZE_STREAK,
  DEFAULT_TELEGRAM_API_URL,
  normalizeTelegramApiUrl,
  telegramMethodUrl,
  SETTINGS_TABLE,
  SETTINGS_VIEW,
  EVENTS_TABLE,
  ensureDetectionTelegramTables,
  getDetectionTelegramSettings,
  saveDetectionTelegramSettings,
  sendTestTelegramMessage,
  sendTelegramMessage,
  isAboveGrowthThreshold,
  shouldSendAlert,
  shouldSendNormalize,
  matchesAlertScope,
  pickAlertCandidates,
  pickNormalizeCandidates,
  formatAlertMessage,
  formatNormalizeMessage,
  snapshotByProto,
  loadDetectionEvents,
  exportDetectionEventsCsv,
  buildDetectionEventsCsv,
  processDetectionAlerts,
};
