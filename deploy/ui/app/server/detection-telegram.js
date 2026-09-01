'use strict';

const { query, executeCommand, insertRows, config } = require('./clickhouse');
const { tableRef, ensureDetectionTables } = require('./detection-schema');
const { formatCh, parseUtc } = require('./detection-core');

const SETTINGS_TABLE = 'app_detection_telegram';
const SETTINGS_VIEW = 'app_detection_telegram_current';
const SETTINGS_ID = 'global';
const DEFAULT_GROWTH_THRESHOLD = 1.6;
const DEFAULT_ALERT_SCOPE = 'all';
const DEFAULT_STREAK = 3;
const MAX_STREAK = 60;
const ALERT_SCOPES = new Set(['all', 'client', 'net']);
const ALERT_SCOPE_LABEL = { all: 'всё', client: 'абоненты', net: 'сети' };
const PROTO_LABEL = { all: 'общее', tcp: 'TCP', udp: 'UDP' };

const DEFAULT_SETTINGS = {
  bot_token: '',
  chat_id: '',
  growth_threshold: DEFAULT_GROWTH_THRESHOLD,
  alert_scope: DEFAULT_ALERT_SCOPE,
  streak: DEFAULT_STREAK,
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

function objectKey(scope, scopeId) {
  return `${scope}|${scopeId}`;
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
}) {
  const kind = scope === 'net' ? 'сеть /24' : 'абонент';
  const header = [
    'Детекция: рост выше порога',
    '',
    `Объект: ${name || scopeId}`,
    `Тип: ${kind}`,
    `ID: ${scopeId}`,
    `Минута: ${formatMinuteMsk(minute)}`,
    `Порог: ×${Number(threshold).toFixed(2)} (bps или pps)`,
    `Стабильно: ${normalizeStreak(streak)} знач. подряд`,
    `Объекты: ${ALERT_SCOPE_LABEL[normalizeAlertScope(alertScope)] || 'всё'}`,
    '',
  ];
  const body = ['all', 'tcp', 'udp'].map((proto) => formatProtoBlock(proto, byProto[proto]));
  return [...header, ...body].join('\n');
}

function pickAlertCandidates(allRows, previousByKey, threshold, options = {}) {
  const streak = normalizeStreak(options.streak);
  const enabledAtMs = options.enabledAtMs;
  const alertScope = normalizeAlertScope(options.alertScope);
  const out = [];
  for (const row of allRows) {
    if (String(row.proto || '') !== 'all') continue;
    if (!matchesAlertScope(row, alertScope)) continue;
    const key = objectKey(row.scope, row.scope_id);
    const prev = previousByKey.get(key) || [];
    const history = [row, ...prev];
    if (shouldSendAlert(history, threshold, streak, enabledAtMs)) out.push({ row, key });
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
          ADD COLUMN IF NOT EXISTS streak UInt16 DEFAULT ${DEFAULT_STREAK}
      `, {}, { name: 'detection/telegram-ensure-columns' });

      await executeCommand(`
        CREATE OR REPLACE VIEW ${settingsViewRef()}
        (
          settings_id String,
          bot_token String,
          chat_id String,
          growth_threshold Float64,
          alert_scope String,
          streak UInt16,
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
    SELECT bot_token, chat_id, growth_threshold, alert_scope, streak, enabled, updated_at
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
    growthThreshold: Number(raw.growth_threshold) || DEFAULT_GROWTH_THRESHOLD,
    alertScope: normalizeAlertScope(raw.alert_scope),
    streak: normalizeStreak(raw.streak),
    enabledAtMs: parseUtc(raw.updated_at),
  };
}

async function sendTelegramMessage(text, cfg) {
  const configRow = cfg || await loadTelegramConfig();
  const url = `https://api.telegram.org/bot${encodeURIComponent(configRow.botToken)}/sendMessage`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: configRow.chatId,
      text: String(text || ''),
      disable_web_page_preview: true,
    }),
  });
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
    SELECT scope, scope_id, minute, growth_bps, growth_pps
    FROM (
      SELECT
        scope,
        scope_id,
        minute,
        growth_bps,
        growth_pps,
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

async function processDetectionAlerts({ minute, rows, nameByKey }) {
  let cfg;
  try {
    cfg = await loadTelegramConfig();
  } catch (err) {
    if (Number(err.statusCode) === 503) return { skipped: 'disabled', sent: 0 };
    throw err;
  }

  const allRows = rows.filter((r) => String(r.proto) === 'all' && matchesAlertScope(r, cfg.alertScope));
  const above = allRows.filter((r) => isAboveGrowthThreshold(r, cfg.growthThreshold));
  if (!above.length) return { skipped: 'none_above', sent: 0 };

  const keys = above.map((r) => ({ scope: r.scope, scopeId: r.scope_id }));
  const previousByKey = await loadPreviousAllRows(minute, keys, cfg.streak);
  const candidates = pickAlertCandidates(allRows, previousByKey, cfg.growthThreshold, {
    streak: cfg.streak,
    enabledAtMs: cfg.enabledAtMs,
    alertScope: cfg.alertScope,
  });
  if (!candidates.length) return { skipped: 'waiting_streak', sent: 0, above: above.length, streak: cfg.streak };

  const grouped = groupRowsByObject(rows);
  let sent = 0;
  const errors = [];

  for (const { row, key } of candidates) {
    const group = grouped.get(key);
    const name = nameByKey?.get(key) || row.scope_id;
    const text = formatAlertMessage({
      name,
      scope: row.scope,
      scopeId: row.scope_id,
      minute,
      threshold: cfg.growthThreshold,
      streak: cfg.streak,
      alertScope: cfg.alertScope,
      byProto: group?.byProto || { all: row },
    });
    try {
      await sendTelegramMessage(text, cfg);
      sent += 1;
    } catch (err) {
      errors.push({ key, message: err.message });
    }
  }

  return {
    sent,
    candidates: candidates.length,
    errors: errors.length ? errors : undefined,
  };
}

module.exports = {
  DEFAULT_GROWTH_THRESHOLD,
  DEFAULT_ALERT_SCOPE,
  DEFAULT_STREAK,
  SETTINGS_TABLE,
  SETTINGS_VIEW,
  ensureDetectionTelegramTables,
  getDetectionTelegramSettings,
  saveDetectionTelegramSettings,
  sendTestTelegramMessage,
  sendTelegramMessage,
  isAboveGrowthThreshold,
  shouldSendAlert,
  matchesAlertScope,
  pickAlertCandidates,
  formatAlertMessage,
  processDetectionAlerts,
};
