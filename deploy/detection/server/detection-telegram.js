'use strict';

const { query, executeCommand, insertRows, config } = require('./clickhouse');
const { tableRef, ensureDetectionTables } = require('./detection-schema');
const { formatCh, parseUtc } = require('./detection-core');
const {
  KINDS,
  KIND_LABEL,
  HOUR_RATIO_PEAK,
  ENTROPY_FOCUSED,
  classifyFromMetrics,
  refineClassification,
  isAttackKind,
  isLegitimatePeak,
  formatSwitchPort,
  formatVictim,
  formatSourceNets,
  formatL4Sources,
  isUsableVictim,
  actionFor,
  volumeStillHigh,
} = require('./detection-classify');
const { loadHourEnvelope, loadClientBinding, formatClientMarkup, investigateIncident, emptyInvestigate } = require('./detection-investigate');
const { loadThresholdMap, resolveGrowthThreshold, hasGrowthOverride } = require('./detection-thresholds');
const {
  SIGNALS,
  SIGNAL_LABEL,
  AMP_PKT_MIN,
  isAmplificationHit,
  ampMetrics,
  foreignMetrics,
  evaluateForeignGeo,
  formatTopCountries,
  amplifierPortsFromL4,
  amplifierLabel,
  AMPLIFIER_PORT_LABEL,
  objectSignalKey,
} = require('./detection-signals');

const SETTINGS_TABLE = 'app_detection_telegram';
const SETTINGS_VIEW = 'app_detection_telegram_current';
const EVENTS_TABLE = 'app_detection_events';
const SETTINGS_ID = 'global';
const DEFAULT_GROWTH_THRESHOLD = 1.6;
const DEFAULT_ALERT_SCOPE = 'all';
const DEFAULT_ALERT_KIND = 'all';
const DEFAULT_STREAK = 3;
const DEFAULT_NORMALIZE_STREAK = 3;
const DEFAULT_TELEGRAM_API_URL = 'https://api.telegram.org';
const MAX_STREAK = 60;
const ALERT_SCOPES = new Set(['all', 'client', 'net']);
const ALERT_SCOPE_LABEL = { all: 'всё', client: 'абоненты', net: 'сети' };
const ALERT_KINDS = new Set(['all', 'attack', 'peak']);
const PROTO_LABEL = { all: 'общее', tcp: 'TCP', udp: 'UDP' };
const SNAPSHOT_FIELDS = [
  'bps', 'pps', 'growth_bps', 'growth_pps', 'bytes', 'packets',
  'avg_packet_bytes', 'cv_percent',
  'syn_attempts', 'syn_answered', 'syn_in_flows', 'syn_half_open', 'syn_half_open_reply',
  'answer_pct', 'half_open_pct', 'half_open_reply_pct',
  'port_entropy', 'port_entropy_out', 'ports_per_ip', 'ports_per_ip_out',
  'amp_bytes', 'amp_packets', 'amp_srcs', 'growth_amp',
  'foreign_bytes', 'foreign_srcs', 'top_countries',
  'growth_foreign_bps', 'growth_foreign_share',
];
// Список стран — строка вида RU:0.60,UZ:0.12; числовое приведение убило бы её.
const SNAPSHOT_STRING_FIELDS = new Set(['top_countries']);
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
  amp_bytes: 'ampBytes',
  amp_packets: 'ampPackets',
  amp_srcs: 'ampSrcs',
  growth_amp: 'growthAmp',
  foreign_bytes: 'foreignBytes',
  foreign_srcs: 'foreignSrcs',
  top_countries: 'topCountries',
  growth_foreign_bps: 'growthForeignBps',
  growth_foreign_share: 'growthForeignShare',
};

const DEFAULT_SETTINGS = {
  bot_token: '',
  chat_id: '',
  growth_threshold: DEFAULT_GROWTH_THRESHOLD,
  alert_scope: DEFAULT_ALERT_SCOPE,
  alert_kind: DEFAULT_ALERT_KIND,
  streak: DEFAULT_STREAK,
  normalize_streak: DEFAULT_NORMALIZE_STREAK,
  api_url: DEFAULT_TELEGRAM_API_URL,
  proxy_url: '',
  enabled: 0,
  amp_enabled: 1,
  geo_enabled: 1,
  amp_streak: 1,
  geo_streak: 1,
  amp_normalize_streak: DEFAULT_NORMALIZE_STREAK,
  geo_normalize_streak: DEFAULT_NORMALIZE_STREAK,
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

function normalizeAlertKind(value, fallback = DEFAULT_ALERT_KIND) {
  const v = String(value || '').trim().toLowerCase();
  return ALERT_KINDS.has(v) ? v : fallback;
}

// Рассылка: атаки / всплески / всё. В историю пишем независимо от этого.
function matchesAlertKind(isAttack, alertKind) {
  const kind = normalizeAlertKind(alertKind);
  if (kind === 'attack') return !!isAttack;
  if (kind === 'peak') return !isAttack;
  return true;
}

function historyStatusSql(alertKind) {
  const kind = normalizeAlertKind(alertKind);
  if (kind === 'attack') return `status = 'normalized'`;
  if (kind === 'peak') return `status = 'peak'`;
  return `status IN ('normalized', 'peak')`;
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

const TELEGRAM_PROXY_PROTOCOLS = new Set(['socks5', 'socks5h', 'http', 'https']);

function normalizeTelegramProxyUrl(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `socks5://${raw}`;
  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw apiError('Прокси: укажите socks5://user:pass@host:port');
  }
  const proto = parsed.protocol.replace(/:$/, '').toLowerCase();
  if (!TELEGRAM_PROXY_PROTOCOLS.has(proto)) {
    throw apiError('Прокси: только socks5, socks5h, http или https');
  }
  if (!parsed.hostname || !parsed.port) {
    throw apiError('Прокси: нужен хост и порт');
  }
  parsed.hash = '';
  parsed.search = '';
  parsed.pathname = '';
  return parsed.toString().replace(/\/+$/, '');
}

function redactTelegramProxyUrl(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(normalizeTelegramProxyUrl(raw));
    if (parsed.password) parsed.password = '';
    return parsed.toString().replace(/\/+$/, '');
  } catch {
    return '';
  }
}

function resolveTelegramProxyUrl(incoming, existing) {
  if (incoming === undefined || incoming === null) return String(existing ?? '').trim();
  const raw = String(incoming).trim();
  const current = String(existing ?? '').trim();
  if (!raw) return '';
  const redacted = redactTelegramProxyUrl(current);
  if (current && (raw === current || raw === redacted)) return current;
  return normalizeTelegramProxyUrl(raw);
}

function telegramFetchViaSocks(url, init, parsed) {
  const http = require('node:http');
  const https = require('node:https');
  const { SocksProxyAgent } = require('socks-proxy-agent');
  // socks5h, never socks5: with plain socks5 the agent resolves the Bot API
  // name locally, and the only reason for the proxy is that this host cannot.
  const socksUrl = new URL(parsed.toString());
  socksUrl.protocol = 'socks5h:';
  const agent = new SocksProxyAgent(socksUrl, { timeout: 45_000 });
  const target = new URL(url);
  const lib = target.protocol === 'http:' ? http : https;
  const body = init.body == null ? null : String(init.body);
  const headers = { ...(init.headers || {}) };
  if (body != null && headers['Content-Length'] == null && headers['content-length'] == null) {
    headers['Content-Length'] = String(Buffer.byteLength(body));
  }
  return new Promise((resolve, reject) => {
    const req = lib.request(target, {
      method: init.method || 'GET',
      headers,
      agent,
      timeout: 45_000,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          json: async () => {
            if (!buf.length) return {};
            return JSON.parse(buf.toString('utf8'));
          },
        });
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (body != null) req.write(body);
    req.end();
  });
}

async function telegramFetch(url, init, proxyUrl) {
  const { fetch, ProxyAgent } = require('undici');
  if (!proxyUrl) return fetch(url, init);
  const parsed = new URL(proxyUrl);
  const proto = parsed.protocol.replace(/:$/, '').toLowerCase();
  if (proto === 'http' || proto === 'https') {
    return fetch(url, { ...init, dispatcher: new ProxyAgent(proxyUrl) });
  }
  return telegramFetchViaSocks(url, init, parsed);
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
    alertKind: normalizeAlertKind(row.alert_kind),
    streak: normalizeStreak(row.streak),
    normalizeStreak: normalizeStreak(row.normalize_streak, DEFAULT_NORMALIZE_STREAK),
    apiUrl: (() => {
      try {
        return normalizeTelegramApiUrl(row.api_url);
      } catch {
        return DEFAULT_TELEGRAM_API_URL;
      }
    })(),
    proxyUrl: redactTelegramProxyUrl(row.proxy_url),
    proxySet: Boolean(String(row.proxy_url ?? '').trim()),
    updatedAt: row.updated_at ?? null,
    ampEnabled: Number(row.amp_enabled ?? 1) === 1,
    geoEnabled: Number(row.geo_enabled ?? 1) === 1,
    ampStreak: normalizeStreak(row.amp_streak, 1),
    geoStreak: normalizeStreak(row.geo_streak, 1),
    ampNormalizeStreak: normalizeStreak(row.amp_normalize_streak, DEFAULT_NORMALIZE_STREAK),
    geoNormalizeStreak: normalizeStreak(row.geo_normalize_streak, DEFAULT_NORMALIZE_STREAK),
  };
}

function signalSettings(settings = {}, signal = SIGNALS.volume) {
  if (signal === SIGNALS.amplification) {
    return {
      enabled: settings.ampEnabled !== false,
      streak: normalizeStreak(settings.ampStreak, 1),
      normalizeStreak: normalizeStreak(settings.ampNormalizeStreak, DEFAULT_NORMALIZE_STREAK),
    };
  }
  if (signal === SIGNALS.foreign_geo) {
    return {
      enabled: settings.geoEnabled !== false,
      streak: normalizeStreak(settings.geoStreak, 1),
      normalizeStreak: normalizeStreak(settings.geoNormalizeStreak, DEFAULT_NORMALIZE_STREAK),
    };
  }
  return {
    enabled: true,
    streak: normalizeStreak(settings.streak, DEFAULT_STREAK),
    normalizeStreak: normalizeStreak(settings.normalizeStreak, DEFAULT_NORMALIZE_STREAK),
  };
}

// В строках proto='all' колонки amp_* приходят из ClickHouse нулями, а не null,
// поэтому считать признак по самой строке минуты нельзя — нужна строка UDP той же
// минуты: доля отражателей меряется к UDP, а не ко всему трафику.
function ampRowFor(row, group) {
  if (String(row?.proto || '') === 'udp') return row;
  return row?.udpRow || group?.byProto?.udp || null;
}

function isSignalHot(signal, row, group, threshold) {
  if (signal === SIGNALS.amplification) {
    const udp = ampRowFor(row, group);
    return udp ? isAmplificationHit(udp) : false;
  }
  if (signal === SIGNALS.foreign_geo) {
    if (String(row?.scope || group?.scope || '') !== 'client') return false;
    // Замер 07.09 за 9 часов: все 150 горячих гео-минут пришлись на падающий
    // трафик (рост максимум ×0.88) — доля заграницы растёт просто потому, что
    // внутренний трафик к ночи проседает быстрее. Поэтому географию считаем
    // только на растущем объёме. Амплификацию так гейтить нельзя: у 95558
    // 3.7 Гбит/с с портов усилителей шли при росте объёма ×0.59.
    if (!isAboveGrowthThreshold(row, threshold)) return false;
    return evaluateForeignGeo(row).hit;
  }
  return isAboveGrowthThreshold(row, threshold);
}

function shouldSendSignal(historyNewestFirst, isHotFn, streak = DEFAULT_STREAK, enabledAtMs) {
  const need = normalizeStreak(streak);
  const history = Array.isArray(historyNewestFirst) ? historyNewestFirst : [];
  if (!history.length || !isHotFn(history[0])) return false;
  if (history.length < need) return false;
  if (!history.slice(0, need).every((row) => isHotFn(row))) return false;
  const before = history[need];
  if (!before) return true;
  if (!isHotFn(before)) return true;
  if (enabledAtMs) {
    const beforeTs = parseUtc(before.minute);
    if (Number.isFinite(beforeTs) && beforeTs < enabledAtMs) return true;
  }
  return false;
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

function objectKey(scope, scopeId, signal) {
  if (signal) return objectSignalKey(scope, scopeId, signal);
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
      if (value == null) {
        mapped[camel] = null;
      } else {
        mapped[camel] = SNAPSHOT_STRING_FIELDS.has(field) ? String(value) : Number(value);
      }
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

// A ClickHouse exception carries the whole failing expression; pasted whole it
// buried the rest of the alert. The event row keeps the full text.
function shortErrorMsg(value, limit = 120) {
  const raw = String(value ?? '').replace(/\s+/g, ' ').trim();
  const head = raw.split(/\swhile\s+executing\s/i)[0] || raw;
  return head.length > limit ? `${head.slice(0, limit - 1)}…` : head;
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

// Какие метрики строки вышли за рамки. Пороги те же, что у классификатора,
// иначе пометка в сообщении расходилась бы с вердиктом.
function outOfRangeFields(proto, row, { verdict, threshold } = {}) {
  const flags = new Set();
  if (!row) return flags;
  const t = Number(threshold) > 0 ? Number(threshold) : DEFAULT_GROWTH_THRESHOLD;
  const growthBps = finiteGrowth(row.growth_bps);
  const growthPps = finiteGrowth(row.growth_pps);
  if (growthBps != null && growthBps >= t) flags.add('growth_bps');
  if (growthPps != null && growthPps >= t) flags.add('growth_pps');
  const ratio = Number(verdict?.hourRatio);
  if (proto === 'all' && Number.isFinite(ratio) && ratio >= HOUR_RATIO_PEAK) flags.add('bps');
  const entropy = Number(row.port_entropy);
  if (Number.isFinite(entropy) && entropy < ENTROPY_FOCUSED) flags.add('port_entropy');
  const attempts = Number(row.syn_attempts);
  const answer = Number(row.answer_pct);
  if (attempts >= 200 && Number.isFinite(answer) && answer < 15) {
    flags.add('syn_attempts');
    flags.add('answer_pct');
  }
  if (Number(row.avg_packet_bytes) >= AMP_PKT_MIN) flags.add('avg_packet_bytes');
  if (proto === 'udp' && isAmplificationHit(row)) flags.add('amp');
  if (proto === 'all' && evaluateForeignGeo(row).hit) flags.add('foreign');
  return flags;
}

function formatProtoBlock(proto, row, flags = new Set()) {
  const title = `<b>${escapeHtml(PROTO_LABEL[proto] || proto)}</b>`;
  if (!row) return `${title}\n  нет данных`;
  // Вышедшее за рамки помечаем на месте, чтобы не искать его глазами в списке.
  const at = (field, text) => `${flags.has(field) ? '‼' : ' '} ${text}`;
  const lines = [
    title,
    at('bps', `bps: ${formatBpsMsg(row.bps)}`),
    at('pps', `pps: ${formatPpsMsg(row.pps)}`),
    at('growth_bps', `рост bps: ${formatGrowthMsg(row.growth_bps)}`),
    at('growth_pps', `рост pps: ${formatGrowthMsg(row.growth_pps)}`),
  ];
  if (proto === 'udp') {
    lines.push('  попытки / ответ / полуоткрытые / не зашли: —');
  } else {
    lines.push(at('syn_attempts', `попытки: ${formatNumMsg(row.syn_attempts, 0)}`));
    lines.push(at('answer_pct', `ответ: ${formatPctMsg(row.answer_pct)}`));
    lines.push(at('half_open_pct', `полуоткрытые: ${formatPctMsg(row.half_open_pct)}`));
    lines.push(at('half_open_reply_pct', `не зашли: ${formatPctMsg(row.half_open_reply_pct)}`));
  }
  lines.push(at('port_entropy', `энтропия портов вх.: ${formatNumMsg(row.port_entropy, 2)}`));
  lines.push(at('port_entropy_out', `энтропия портов исх.: ${formatNumMsg(row.port_entropy_out, 2)}`));
  lines.push(at('ports_per_ip', `макс. портов/IP вх.: ${formatNumMsg(row.ports_per_ip, 0)}`));
  lines.push(at('ports_per_ip_out', `макс. портов/IP исх.: ${formatNumMsg(row.ports_per_ip_out, 0)}`));
  lines.push(at('avg_packet_bytes', `средний пакет: ${formatNumMsg(row.avg_packet_bytes, 0)} Б`));
  lines.push(at('cv_percent', `CV: ${row.cv_percent == null ? '—' : `${formatNumMsg(row.cv_percent, 1)}%`}`));
  // Строки ниже есть не у каждой минуты: без трафика с портов усилителей и без
  // зарубежных источников это были бы нули в каждом сообщении.
  const amp = proto === 'udp' ? ampMetrics(row) : null;
  if (amp && amp.bytes > 0) {
    lines.push(at('amp', `с портов усилителей: ${formatBpsMsg(amp.bps)}`
      + ` · доля ${amp.share == null ? '—' : `${(amp.share * 100).toFixed(0)}%`}`
      + ` · ${formatNumMsg(amp.srcs, 0)} источников`
      + ` · пакет ${formatNumMsg(amp.avgPkt, 0)} Б`));
  }
  const geo = proto === 'all' ? foreignMetrics(row) : null;
  if (geo && geo.bytes > 0) {
    lines.push(at('foreign', `заграница: ${formatBpsMsg(geo.bps)}`
      + ` · доля ${geo.share == null ? '—' : `${(geo.share * 100).toFixed(0)}%`}`
      + ` · ${formatNumMsg(geo.srcs, 0)} источников`
      + ` · рост доли ${formatGrowthMsg(row.growth_foreign_share ?? row.growthForeignShare)}`));
    const countries = formatTopCountries(geo.top);
    if (countries) lines.push(`  страны: ${escapeHtml(countries)}`);
  }
  return lines.join('\n');
}

function isAlertAttack(verdict, signals = []) {
  const list = Array.isArray(signals) ? signals : [];
  if (isAttackKind(verdict?.kind)) return true;
  if (list.includes(SIGNALS.amplification)) return true;
  if (list.includes(SIGNALS.foreign_geo) && !isLegitimatePeak(verdict)) return true;
  return false;
}

function formatAlertHeadline(verdict, signals = []) {
  const verdictKind = verdict?.kind || '';
  const head = (emoji, text) => `${emoji} <b>${escapeHtml(text)}</b>`;
  if (verdictKind === KINDS.amplification) {
    const ports = amplifierPortsFromL4(verdict?.l4src);
    const extra = amplifierLabel(ports);
    return head('🔴', `АТАКА · ${KIND_LABEL.amplification}${extra ? ` ${extra}` : ''}`);
  }
  if (isAttackKind(verdictKind)) {
    return head('🔴', `АТАКА · ${KIND_LABEL[verdictKind] || verdictKind}`);
  }
  if (signals.includes(SIGNALS.foreign_geo) && verdictKind === KINDS.benign_peak && !isLegitimatePeak(verdict)) {
    return head('🔴', `АТАКА · ${SIGNAL_LABEL.foreign_geo}`);
  }
  if (verdictKind === KINDS.benign_peak) {
    if (isLegitimatePeak(verdict)) {
      return head('🟡', 'ПИК НАГРУЗКИ · легитимная загрузка');
    }
    return head('🟡', 'ПИК НАГРУЗКИ · похоже на легитимный всплеск');
  }
  return head('🔴', 'Детекция: рост выше порога');
}

function formatVolumeLine(all, verdict, hourUsual) {
  const hour = verdict?.hourRatio != null
    ? `к норме часа ×${Number(verdict.hourRatio).toFixed(2)}`
    : `рост ${formatGrowthMsg(all.growth_bps)}`;
  const usual = hourUsual > 0 ? ` (обычно ${formatBpsMsg(hourUsual)})` : '';
  const ratio = Number(verdict?.hourRatio);
  let mark = '';
  if (Number.isFinite(ratio)) {
    if (ratio >= 1.8) mark = '‼';
    else if (ratio >= HOUR_RATIO_PEAK) mark = '⚠';
  } else {
    const growth = Number(all.growth_bps);
    if (growth >= 1.8) mark = '‼';
    else if (growth >= DEFAULT_GROWTH_THRESHOLD) mark = '⚠';
  }
  const prefix = mark ? `${mark} ` : '';
  return `${prefix}Объём: <b>${escapeHtml(formatBpsMsg(all.bps))}</b> · ${escapeHtml(hour)}${escapeHtml(usual)}`;
}

function ampPortCameFrom(ports) {
  if (!ports.length) return 'С портов усилителей пришло';
  const bits = ports.map((port) => {
    const name = AMPLIFIER_PORT_LABEL[port];
    return name ? `порта ${port} (${name})` : `порта ${port}`;
  });
  return bits.length === 1 ? `С ${bits[0]} пришло` : `С ${bits.join(' и ')} пришло`;
}

function ruAddresses(count) {
  const n = Number(count);
  if (!Number.isFinite(n) || n < 0) return '';
  const k = n % 100;
  const d = n % 10;
  if (k >= 11 && k <= 14) return `${formatNumMsg(n, 0)} адресов`;
  if (d === 1) return `${formatNumMsg(n, 0)} адрес`;
  if (d >= 2 && d <= 4) return `${formatNumMsg(n, 0)} адреса`;
  return `${formatNumMsg(n, 0)} адресов`;
}

function formatAmpDestLines(investigate, ports) {
  const rows = (Array.isArray(investigate?.ampDest24) ? investigate.ampDest24 : [])
    .filter((row) => row?.net24)
    .slice(0, 5);
  if (!rows.length) return ['Куда: по сети клиента, не один сервер'];
  const tag = ports.length ? ports.join(' и ') : 'усилители';
  const lines = [`Куда (UDP/${escapeHtml(tag)}):`];
  for (const row of rows) {
    const parts = [];
    if (row.share != null) parts.push(`${(Number(row.share) * 100).toFixed(0)}%`);
    if (row.ips != null) parts.push(ruAddresses(row.ips));
    const bps = row.bps != null ? row.bps : (row.gbit != null ? Number(row.gbit) * 1e9 : null);
    if (bps != null && bps > 0) parts.push(formatBpsMsg(bps));
    lines.push(escapeHtml(`   ${row.net24} — ${parts.join(' · ')}`));
  }
  return lines;
}

function formatAmpHighlight({ amp, udp, all, hourUsual, verdict, investigate }) {
  const ports = amplifierPortsFromL4(investigate?.l4src);
  const lines = [
    `🔴 ${escapeHtml(ampPortCameFrom(ports))} <b>${escapeHtml(formatBpsMsg(amp.bps))}</b>`,
  ];
  const who = amp.srcs > 0
    ? (ports.length === 1 && ports[0] === 53
      ? `${formatNumMsg(amp.srcs, 0)} чужих резолверов`
      : `${formatNumMsg(amp.srcs, 0)} чужих источников`)
    : '';
  const pkt = amp.avgPkt > 0 ? `ответы по ~${formatNumMsg(amp.avgPkt, 0)} байт` : '';
  const details = [who, pkt].filter(Boolean);
  if (details.length) lines.push(`   ${escapeHtml(details.join(' · '))}`);
  const shares = [];
  if (amp.share != null) shares.push(`${(amp.share * 100).toFixed(0)}% его UDP`);
  if (Number(all.bps) > 0) {
    shares.push(`${((amp.bps / Number(all.bps)) * 100).toFixed(0)}% всего трафика клиента`);
  }
  if (shares.length) lines.push(escapeHtml(`   это ${shares.join(' и ')}`));
  lines.push(...formatAmpDestLines(investigate, ports));
  const ratio = Number(verdict?.hourRatio);
  if (hourUsual > 0 && Number(all.bps) > 0) {
    const shown = Number.isFinite(ratio) ? ratio : Number(all.bps) / hourUsual;
    if (shown < HOUR_RATIO_PEAK) {
      lines.push(escapeHtml(
        `Объём клиента сейчас ${formatBpsMsg(all.bps)}, обычно ${formatBpsMsg(hourUsual)} — ниже нормы.`,
      ));
      lines.push('По общему графику эту атаку не видно.');
    }
  }
  return lines;
}

function formatVictimHighlight(investigate, verdict) {
  if (investigate?.error) {
    return [`Куда: — (разбор не удался: ${escapeHtml(shortErrorMsg(investigate.error))})`];
  }
  const victim = investigate?.victim;
  if (!victim?.ip) return [];
  const share = Number(victim.share);
  if (verdict?.kind === KINDS.amplification && !isUsableVictim(victim)) {
    if (Number.isFinite(share) && share < 0.15) {
      return [`   в один адрес не бьёт (топ IP ${(share * 100).toFixed(1)}%)`];
    }
    return [];
  }
  if (!isUsableVictim(victim) && Number.isFinite(share) && share < 0.15) return [];
  const text = formatVictim(victim);
  if (text === '—') return [];
  if (share >= 0.8) return [`‼ Цель: <b>${escapeHtml(text)}</b>`];
  return [`Куда: ${escapeHtml(text)}`];
}

function formatAlertHighlights({ byProto, verdict, investigate, hourUsual }) {
  const all = byProto?.all || {};
  const udp = byProto?.udp || {};
  const tcp = byProto?.tcp || {};
  const amp = ampMetrics(udp);
  const geo = evaluateForeignGeo(all);
  const showAmp = verdict?.kind === KINDS.amplification || (amp.bps >= 50e6 && amp.share != null);
  const lines = [];
  if (showAmp && amp.bps > 0) {
    lines.push(...formatAmpHighlight({ amp, udp, all, hourUsual, verdict, investigate }));
  } else {
    lines.push(formatVolumeLine(all, verdict, hourUsual));
    const split = [
      Number(tcp.bps) > 0 ? `TCP ${formatBpsMsg(tcp.bps)}` : '',
      Number(udp.bps) > 0 ? `UDP ${formatBpsMsg(udp.bps)}` : '',
    ].filter(Boolean);
    if (split.length) lines.push(`   ${escapeHtml(split.join(' · '))}`);
    lines.push(...formatVictimHighlight(investigate, verdict));
  }
  if (geo.hit) {
    const growth = geo.shareGrowth != null ? ` — ×${geo.shareGrowth.toFixed(1)} к норме часа` : '';
    const usualShare = geo.shareNorm != null ? ` (обычно ${(geo.shareNorm * 100).toFixed(0)}%)` : '';
    lines.push(`‼ Заграница <b>${(geo.share * 100).toFixed(0)}%</b>${escapeHtml(growth)}${escapeHtml(usualShare)}`);
    const countries = formatTopCountries(geo.top);
    if (countries) lines.push(`   ${escapeHtml(countries)}`);
  }
  if (!showAmp) {
    const pkt = Number(udp.avg_packet_bytes ?? udp.avgPacketBytes ?? all.avg_packet_bytes ?? all.avgPacketBytes);
    if (pkt >= AMP_PKT_MIN) lines.push(`⚠ Пакеты <b>${Math.round(pkt)} Б</b> — крупные, близко к MTU`);
  }
  return { lines, ampShown: showAmp };
}

function formatAlertMessage({
  name,
  scope,
  scopeId,
  minute,
  threshold,
  thresholdIsCustom = false,
  streak = DEFAULT_STREAK,
  alertScope = DEFAULT_ALERT_SCOPE,
  byProto,
  verdict,
  investigate,
  binding,
  signals,
}) {
  const signalList = Array.isArray(signals) && signals.length ? signals : [SIGNALS.volume];
  const title = formatAlertHeadline({ ...verdict, l4src: investigate?.l4src }, signalList);
  // Префикс сети уже стоит в шапке, поэтому разметка нужна только абонентам.
  const markup = scope === 'client' ? formatClientMarkup(binding) : '';
  const markupLine = markup
    ? (binding?.bindMode === 'ports' ? `Порт: ${markup}` : `IP: ${markup}`)
    : '';
  const { lines: highlights, ampShown } = formatAlertHighlights({
    byProto,
    verdict,
    investigate,
    hourUsual: Number(verdict?.hourCeiling || verdict?.hourP95 || 0),
  });
  const l4 = formatL4Sources(investigate?.l4src);
  const switchIn = formatSwitchPort(investigate?.switchIn);
  const switchOut = formatSwitchPort(investigate?.switchOut);
  const sourceNets = formatSourceNets(investigate?.source24);
  // У пика нет строк с маркерами, поэтому причина — единственное объяснение;
  // у атаки она дословно повторяет то, что уже разложено по строкам выше.
  const reasonLine = verdict?.kind === KINDS.benign_peak && verdict?.reason
    ? `Почему: ${verdict.reason}`
    : '';
  const object = scope === 'net'
    ? `Сеть /24: <b>${escapeHtml(name && name !== scopeId ? `${name} (${scopeId})` : scopeId)}</b>`
    : `Клиент: <b>${escapeHtml(name || scopeId)}</b> (${escapeHtml(scopeId)})`;
  const blocks = [
    [
      title,
      object,
      `Минута: ${escapeHtml(formatMinuteMsk(minute))}`,
    ],
    [...highlights, reasonLine],
    [`<b>Что делать:</b> ${escapeHtml(actionFor(verdict, investigate))}`],
    [
      sourceNets !== '—' ? `Откуда сети: ${escapeHtml(sourceNets)}` : '',
      // Порты усилителей уже названы в шапке amp.
      !ampShown && l4 !== '—' ? `L4 откуда: ${escapeHtml(l4)}` : '',
      switchIn !== '—' ? `Коммутатор вход: ${escapeHtml(switchIn)}` : '',
      switchOut !== '—' ? `Коммутатор выход: ${escapeHtml(switchOut)}` : '',
      markupLine ? escapeHtml(markupLine) : '',
      escapeHtml(`Порог ×${Number(threshold).toFixed(2)}${thresholdIsCustom ? ' (индивидуальный)' : ''}`
        + ` · стабильно ${normalizeStreak(streak)} знач.`
        + ` · рассылка: ${ALERT_SCOPE_LABEL[normalizeAlertScope(alertScope)] || 'всё'}`),
    ],
    ['<b>Метрики за минуту</b>'],
    ...['all', 'tcp', 'udp'].map((proto) => [formatProtoBlock(
      proto,
      byProto?.[proto],
      outOfRangeFields(proto, byProto?.[proto], { verdict, threshold }),
    )]),
  ];
  return blocks
    .map((block) => block.filter(Boolean).join('\n'))
    .filter(Boolean)
    .join('\n\n');
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
  const blocks = [
    [
      '🟢 <b>НОРМА · трафик вернулся к обычному</b>',
      scope === 'net'
        ? `Сеть /24: <b>${escapeHtml(name && name !== scopeId ? `${name} (${scopeId})` : scopeId)}</b>`
        : `Клиент: <b>${escapeHtml(name || scopeId)}</b> (${escapeHtml(scopeId)})`,
      `Алерт был: ${escapeHtml(formatMinuteMsk(alertMinute))}`,
      `Нормализация: ${escapeHtml(formatMinuteMsk(minute))}`,
    ],
    [
      escapeHtml(`Порог ×${Number(threshold).toFixed(2)}`
        + ` · ниже нормы ${normalizeStreak(streak, DEFAULT_NORMALIZE_STREAK)} знач. подряд`),
    ],
    ['<b>Метрики за минуту</b>'],
    ...['all', 'tcp', 'udp'].map((proto) => [formatProtoBlock(proto, byProto?.[proto])]),
  ];
  return blocks
    .map((block) => block.filter(Boolean).join('\n'))
    .filter(Boolean)
    .join('\n\n');
}

function pickAlertCandidates(allRows, previousByKey, threshold, options = {}) {
  const settings = options.settings || {};
  const enabledAtMs = options.enabledAtMs;
  const alertScope = normalizeAlertScope(options.alertScope);
  const activeKeys = options.activeKeys instanceof Set ? options.activeKeys : new Set();
  const grouped = options.grouped instanceof Map ? options.grouped : new Map();
  const out = [];
  for (const row of allRows) {
    if (String(row.proto || '') !== 'all') continue;
    if (!matchesAlertScope(row, alertScope)) continue;
    const objectId = objectKey(row.scope, row.scope_id);
    const group = grouped.get(objectId) || { byProto: { all: row } };
    const prev = previousByKey.get(objectId) || [];
    const t = resolveGrowthThreshold(row.scope, row.scope_id, threshold, options.thresholdByKey);
    for (const signal of [SIGNALS.volume, SIGNALS.amplification, SIGNALS.foreign_geo]) {
      const cfg = signalSettings(settings, signal);
      if (!cfg.enabled) continue;
      if (signal === SIGNALS.foreign_geo && String(row.scope) !== 'client') continue;
      const signalKey = objectSignalKey(row.scope, row.scope_id, signal);
      if (activeKeys.has(signalKey) || (signal === SIGNALS.volume && activeKeys.has(objectId))) continue;
      const history = [row, ...prev];
      const hot = (item) => isSignalHot(signal, item, group, t);
      const ready = signal === SIGNALS.volume
        ? shouldSendAlert(history, t, options.streak ?? cfg.streak, enabledAtMs)
        : shouldSendSignal(history, hot, cfg.streak, enabledAtMs);
      if (!ready) continue;
      out.push({
        row,
        key: signal === SIGNALS.volume ? objectId : signalKey,
        objectKey: objectId,
        signalKey,
        signal,
        threshold: t,
        thresholdIsCustom: hasGrowthOverride(row.scope, row.scope_id, options.thresholdByKey),
        streak: signal === SIGNALS.volume ? (options.streak ?? cfg.streak) : cfg.streak,
      });
    }
  }
  return out;
}

function pickNormalizeCandidates(allRows, previousByKey, threshold, options = {}) {
  const settings = options.settings || {};
  const activeByKey = options.activeByKey instanceof Map ? options.activeByKey : new Map();
  const grouped = options.grouped instanceof Map ? options.grouped : new Map();
  const seen = new Set();
  const out = [];
  for (const row of allRows) {
    if (String(row.proto || '') !== 'all') continue;
    const objectId = objectKey(row.scope, row.scope_id);
    const group = grouped.get(objectId) || { byProto: { all: row } };
    const prev = previousByKey.get(objectId) || [];
    const history = [row, ...prev];
    for (const signal of [SIGNALS.volume, SIGNALS.amplification, SIGNALS.foreign_geo]) {
      const signalKey = objectSignalKey(row.scope, row.scope_id, signal);
      const active = activeByKey.get(signalKey) || (signal === SIGNALS.volume ? activeByKey.get(objectId) : null);
      if (!active) continue;
      const dedupe = active.id || signalKey;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      const activeSignal = active.signal || SIGNALS.volume;
      if (activeSignal !== signal && !(signal === SIGNALS.volume && !active.signal)) continue;
      const cfg = signalSettings(settings, activeSignal);
      const t = Number(active.threshold) || resolveGrowthThreshold(row.scope, row.scope_id, threshold, options.thresholdByKey);
      const ready = activeSignal === SIGNALS.volume
        ? shouldSendNormalize(history, t, options.streak ?? cfg.normalizeStreak, {
          alertBps: active.alertByProto?.all?.bps ?? active.alertBps,
          hourP95: active.verdict?.hourP95,
        })
        : shouldSendSignal(history, (item) => !isSignalHot(activeSignal, item, group, t), cfg.normalizeStreak);
      if (!ready) continue;
      out.push({ row, key: objectId, signalKey, signal: activeSignal, active });
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
          alert_kind String DEFAULT '${DEFAULT_ALERT_KIND}',
          streak UInt16 DEFAULT ${DEFAULT_STREAK},
          normalize_streak UInt16 DEFAULT ${DEFAULT_NORMALIZE_STREAK},
          api_url String DEFAULT '${DEFAULT_TELEGRAM_API_URL}',
          proxy_url String DEFAULT '',
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
          ADD COLUMN IF NOT EXISTS alert_kind String DEFAULT '${DEFAULT_ALERT_KIND}',
          ADD COLUMN IF NOT EXISTS streak UInt16 DEFAULT ${DEFAULT_STREAK},
          ADD COLUMN IF NOT EXISTS normalize_streak UInt16 DEFAULT ${DEFAULT_NORMALIZE_STREAK},
          ADD COLUMN IF NOT EXISTS api_url String DEFAULT '${DEFAULT_TELEGRAM_API_URL}',
          ADD COLUMN IF NOT EXISTS proxy_url String DEFAULT '',
          ADD COLUMN IF NOT EXISTS amp_enabled UInt8 DEFAULT 1,
          ADD COLUMN IF NOT EXISTS geo_enabled UInt8 DEFAULT 1,
          ADD COLUMN IF NOT EXISTS amp_streak UInt16 DEFAULT 1,
          ADD COLUMN IF NOT EXISTS geo_streak UInt16 DEFAULT 1,
          ADD COLUMN IF NOT EXISTS amp_normalize_streak UInt16 DEFAULT ${DEFAULT_NORMALIZE_STREAK},
          ADD COLUMN IF NOT EXISTS geo_normalize_streak UInt16 DEFAULT ${DEFAULT_NORMALIZE_STREAK}
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
          signal LowCardinality(String) DEFAULT 'volume',
          updated_at DateTime('UTC') DEFAULT now()
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (scope, scope_id, event_id)
        TTL alert_minute + toIntervalDay(90)
        SETTINGS index_granularity = 8192
      `, {}, { name: 'detection/events-ensure-table' });

      await executeCommand(`
        ALTER TABLE ${eventsTableRef()}
          ADD COLUMN IF NOT EXISTS signal LowCardinality(String) DEFAULT 'volume'
      `, {}, { name: 'detection/events-ensure-signal' });

      await executeCommand(`
        CREATE OR REPLACE VIEW ${settingsViewRef()}
        (
          settings_id String,
          bot_token String,
          chat_id String,
          growth_threshold Float64,
          alert_scope String,
          alert_kind String,
          streak UInt16,
          normalize_streak UInt16,
          api_url String,
          proxy_url String,
          enabled UInt8,
          amp_enabled UInt8,
          geo_enabled UInt8,
          amp_streak UInt16,
          geo_streak UInt16,
          amp_normalize_streak UInt16,
          geo_normalize_streak UInt16,
          updated_at DateTime('UTC')
        )
        AS SELECT
          settings_id,
          bot_token,
          chat_id,
          growth_threshold,
          alert_scope,
          alert_kind,
          streak,
          normalize_streak,
          api_url,
          proxy_url,
          enabled,
          amp_enabled,
          geo_enabled,
          amp_streak,
          geo_streak,
          amp_normalize_streak,
          geo_normalize_streak,
          updated_at_latest AS updated_at
        FROM
        (
          SELECT
            settings_id,
            argMax(bot_token, updated_at) AS bot_token,
            argMax(chat_id, updated_at) AS chat_id,
            argMax(growth_threshold, updated_at) AS growth_threshold,
            argMax(alert_scope, updated_at) AS alert_scope,
            argMax(alert_kind, updated_at) AS alert_kind,
            argMax(streak, updated_at) AS streak,
            argMax(normalize_streak, updated_at) AS normalize_streak,
            argMax(api_url, updated_at) AS api_url,
            argMax(proxy_url, updated_at) AS proxy_url,
            argMax(enabled, updated_at) AS enabled,
            argMax(amp_enabled, updated_at) AS amp_enabled,
            argMax(geo_enabled, updated_at) AS geo_enabled,
            argMax(amp_streak, updated_at) AS amp_streak,
            argMax(geo_streak, updated_at) AS geo_streak,
            argMax(amp_normalize_streak, updated_at) AS amp_normalize_streak,
            argMax(geo_normalize_streak, updated_at) AS geo_normalize_streak,
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
    SELECT bot_token, chat_id, growth_threshold, alert_scope, alert_kind, streak, normalize_streak, api_url, proxy_url, enabled,
           amp_enabled, geo_enabled, amp_streak, geo_streak, amp_normalize_streak, geo_normalize_streak, updated_at
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
    throw apiError('Рассылка по: выберите всё, абоненты или сети');
  }
  const alertScope = normalizeAlertScope(alertScopeRaw);
  const alertKindRaw = payload.alertKind ?? payload.alert_kind ?? base.alert_kind;
  if (alertKindRaw != null && String(alertKindRaw).trim() !== '' && !ALERT_KINDS.has(String(alertKindRaw).trim().toLowerCase())) {
    throw apiError('Отправлять: выберите всё, атаки или всплески');
  }
  const alertKind = normalizeAlertKind(alertKindRaw);
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
  const proxyUrl = resolveTelegramProxyUrl(payload.proxyUrl ?? payload.proxy_url, base.proxy_url);
  const ampEnabled = boolInt(payload.ampEnabled ?? payload.amp_enabled, Number(base.amp_enabled ?? 1) === 1 ? 1 : 0);
  const geoEnabled = boolInt(payload.geoEnabled ?? payload.geo_enabled, Number(base.geo_enabled ?? 1) === 1 ? 1 : 0);
  const ampStreak = normalizeStreak(payload.ampStreak ?? payload.amp_streak ?? base.amp_streak, 1);
  const geoStreak = normalizeStreak(payload.geoStreak ?? payload.geo_streak ?? base.geo_streak, 1);
  const ampNormalizeStreak = normalizeStreak(
    payload.ampNormalizeStreak ?? payload.amp_normalize_streak ?? base.amp_normalize_streak,
    DEFAULT_NORMALIZE_STREAK,
  );
  const geoNormalizeStreak = normalizeStreak(
    payload.geoNormalizeStreak ?? payload.geo_normalize_streak ?? base.geo_normalize_streak,
    DEFAULT_NORMALIZE_STREAK,
  );
  if (enabled && (!botToken || !chatId)) {
    throw apiError('Укажите токен бота и id группы перед включением Telegram');
  }

  await insertRows(SETTINGS_TABLE, [{
    settings_id: SETTINGS_ID,
    bot_token: botToken,
    chat_id: chatId,
    growth_threshold: growthThreshold,
    alert_scope: alertScope,
    alert_kind: alertKind,
    streak,
    normalize_streak: normalizeStreakValue,
    api_url: apiUrl,
    proxy_url: proxyUrl,
    enabled,
    amp_enabled: ampEnabled,
    geo_enabled: geoEnabled,
    amp_streak: ampStreak,
    geo_streak: geoStreak,
    amp_normalize_streak: ampNormalizeStreak,
    geo_normalize_streak: geoNormalizeStreak,
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
    proxyUrl: String(raw.proxy_url ?? '').trim(),
    growthThreshold: Number(raw.growth_threshold) || DEFAULT_GROWTH_THRESHOLD,
    alertScope: normalizeAlertScope(raw.alert_scope),
    alertKind: normalizeAlertKind(raw.alert_kind),
    streak: normalizeStreak(raw.streak),
    normalizeStreak: normalizeStreak(raw.normalize_streak, DEFAULT_NORMALIZE_STREAK),
    enabledAtMs: parseUtc(raw.updated_at),
  };
}

async function sendTelegramMessage(text, cfg) {
  const configRow = cfg || await loadTelegramConfig();
  const apiUrl = configRow.apiUrl || DEFAULT_TELEGRAM_API_URL;
  const proxyUrl = String(configRow.proxyUrl ?? '').trim();
  const url = telegramMethodUrl(apiUrl, configRow.botToken, 'sendMessage');
  let res;
  try {
    res = await telegramFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: configRow.chatId,
        text: String(text || ''),
        // Жирный текст в сообщениях детекции; всё подставляемое экранируется
        // в формировщиках, иначе Telegram отклонит разметку.
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
    }, proxyUrl);
  } catch (err) {
    const cause = err.cause?.code || err.cause?.message || err.message;
    let host = apiUrl;
    try { host = new URL(apiUrl).host; } catch { /* keep */ }
    const via = proxyUrl ? ` через ${redactTelegramProxyUrl(proxyUrl) || 'прокси'}` : '';
    throw apiError(`Telegram: нет сети до ${host}${via} (${cause})`, 502);
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.ok === false) {
    const detail = body.description || body.error || `HTTP ${res.status}`;
    throw apiError(`Telegram: ${detail}`, 502);
  }
  return body;
}

async function sendTestTelegramMessage() {
  const text = formatAlertMessage({
    name: 'ООО "Митигатор Клауд"',
    scope: 'client',
    scopeId: '101443',
    minute: '2026-09-06 16:27:00',
    threshold: 1.6,
    streak: 1,
    alertScope: 'all',
    signals: [SIGNALS.amplification, SIGNALS.foreign_geo],
    byProto: {
      all: {
        bps: 2.925e9, growth_bps: 3.56, avg_packet_bytes: 1127,
        foreign_bytes: 7.4e9, foreign_srcs: 45, top_countries: 'RU:0.60,UZ:0.12,SA:0.09,KZ:0.06,US:0.04',
        growth_foreign_share: 3.7, growth_foreign_bps: 10,
        bytes: 2.925e9 * 60 / 8,
      },
      tcp: { bps: 0.15e9 },
      udp: {
        bps: 2.741e9, amp_bytes: 3.683e9, amp_packets: 4065536, amp_srcs: 40,
        avg_packet_bytes: 1216, bytes: 2.741e9 * 60 / 8,
      },
    },
    verdict: {
      kind: KINDS.amplification,
      reason: 'амплификация в один сервер · топ IP 99.8% · отражатели 18%',
      hourRatio: 12.44,
      hourCeiling: 0.235e9,
    },
    investigate: {
      victim: { ip: '185.x.x.x', port: 443, protoLabel: 'UDP', share: 0.998 },
      source24: [{ net24: '5.188.0.0/24', share: 0.12, asn: 8193, ips: 7 }],
      switchIn: { switchIp: '172.18.19.165', ifName: 'port-channel2', share: 1 },
      switchOut: null,
      l4src: [
        { port: 53, proto: 17, share: 0.33 },
        { port: 123, proto: 17, share: 0.13 },
      ],
      ampDest24: [{ net24: '185.0.0.0/24', ips: 1, share: 0.998, bps: 2.74e9 }],
    },
  });
  return sendTelegramMessage(
    `Grapes NTA: тестовый алерт в новом формате.\n\n${text}`,
  );
}

async function loadPreviousAllRows(minute, keys, limit = DEFAULT_STREAK) {
  if (!keys.length) return new Map();
  await ensureDetectionTables();
  const take = normalizeStreak(limit);
  const keySet = new Set(keys.map((k) => objectKey(k.scope, k.scopeId)));
  const { rows } = await query(`
    SELECT scope, scope_id, proto, minute, growth_bps, growth_pps, bps, bytes,
           amp_bytes, amp_packets, amp_srcs, growth_amp,
           foreign_bytes, foreign_srcs, top_countries, growth_foreign_bps, growth_foreign_share
    FROM (
      SELECT
        scope,
        scope_id,
        proto,
        minute,
        growth_bps,
        growth_pps,
        bps,
        bytes,
        amp_bytes,
        amp_packets,
        amp_srcs,
        growth_amp,
        foreign_bytes,
        foreign_srcs,
        top_countries,
        growth_foreign_bps,
        growth_foreign_share,
        row_number() OVER (PARTITION BY scope, scope_id, proto ORDER BY minute DESC) AS rn
      FROM ${tableRef()} FINAL
      WHERE proto IN ('all', 'udp')
        AND minute < ${utcDateTime('before')}
    )
    WHERE rn <= {take:UInt16}
    ORDER BY minute DESC
  `, { before: formatCh(parseUtc(minute)), take }, { name: 'detection/telegram-prev-rows' });

  const merged = new Map();
  for (const r of rows) {
    const key = objectKey(r.scope, r.scope_id);
    if (!keySet.has(key)) continue;
    const stamp = String(r.minute);
    const byMinute = merged.get(key) || new Map();
    const cur = byMinute.get(stamp) || { minute: r.minute, scope: r.scope, scope_id: r.scope_id };
    if (String(r.proto) === 'udp') {
      // Держим строку UDP отдельным полем: Object.assign строки 'all' затирал бы
      // amp_* нулями, а cur.bytes всё равно остался бы общим — доля отражателей
      // считалась бы к сумме протоколов вместо UDP.
      cur.udpRow = r;
    } else {
      Object.assign(cur, r);
    }
    byMinute.set(stamp, cur);
    merged.set(key, byMinute);
  }
  const map = new Map();
  for (const [key, byMinute] of merged) {
    map.set(key, [...byMinute.values()].sort((a, b) => String(b.minute).localeCompare(String(a.minute))));
  }
  return map;
}

function utcDateTime(param) {
  return `toDateTime({${param}:String}, 'UTC')`;
}

function byProtoFromSnapshot(snapshot) {
  const byProto = {};
  for (const proto of ['all', 'tcp', 'udp']) {
    if (snapshot?.[proto]) byProto[proto] = snapshot[proto];
  }
  return byProto;
}

function storedOrFormattedAlertText(row, alertSnapshot) {
  const stored = String(alertSnapshot.telegramText || '').trim();
  if (stored) return stored;
  if (!alertSnapshot?.all && !alertSnapshot?.verdict) return '';
  return formatAlertMessage({
    name: String(row.name || row.scope_id || ''),
    scope: String(row.scope || ''),
    scopeId: String(row.scope_id || ''),
    minute: row.alert_minute,
    threshold: Number(row.threshold) || DEFAULT_GROWTH_THRESHOLD,
    byProto: byProtoFromSnapshot(alertSnapshot),
    verdict: alertSnapshot.verdict,
    investigate: alertSnapshot.investigate,
    binding: alertSnapshot.binding,
  });
}

function storedOrFormattedNormalizeText(row, normalizeSnapshot) {
  const stored = String(normalizeSnapshot.telegramText || '').trim();
  if (stored) return stored;
  if (!normalizeSnapshot?.all) return '';
  return formatNormalizeMessage({
    name: String(row.name || row.scope_id || ''),
    scope: String(row.scope || ''),
    scopeId: String(row.scope_id || ''),
    minute: row.normalize_minute,
    alertMinute: row.alert_minute,
    threshold: Number(row.threshold) || DEFAULT_GROWTH_THRESHOLD,
    byProto: byProtoFromSnapshot(normalizeSnapshot),
  });
}

function mapEventRow(row) {
  const alertSnapshot = parseSnapshot(row.alert_json);
  const normalizeSnapshot = parseSnapshot(row.normalize_json);
  return {
    id: String(row.event_id),
    scope: String(row.scope || ''),
    scopeId: String(row.scope_id || ''),
    signal: String(row.signal || SIGNALS.volume),
    name: String(row.name || row.scope_id || ''),
    status: String(row.status || ''),
    alertMinute: row.alert_minute || null,
    normalizeMinute: row.normalize_minute || null,
    threshold: Number(row.threshold) || DEFAULT_GROWTH_THRESHOLD,
    alertByProto: mapSnapshotToUi(alertSnapshot),
    normalizeByProto: mapSnapshotToUi(normalizeSnapshot),
    verdict: alertSnapshot.verdict || null,
    investigate: alertSnapshot.investigate || null,
    alertText: storedOrFormattedAlertText(row, alertSnapshot),
    normalizeText: storedOrFormattedNormalizeText(row, normalizeSnapshot),
  };
}

function persistAlertSnapshot(metrics, extras = {}) {
  return {
    ...metrics,
    verdict: extras.verdict || null,
    investigate: extras.investigate || null,
    binding: extras.binding || null,
    telegramText: String(extras.telegramText || ''),
  };
}

function persistActiveAlertSnapshot(active) {
  return persistAlertSnapshot(uiByProtoToSnapshot(active?.alertByProto), {
    verdict: active?.verdict,
    investigate: active?.investigate,
    telegramText: active?.alertText,
  });
}

async function loadActiveEventsByKey() {
  await ensureDetectionTelegramTables();
  const { rows } = await query(`
    SELECT event_id, scope, scope_id, name, status, signal, alert_minute, normalize_minute, alert_json, normalize_json, threshold
    FROM (
      SELECT
        event_id,
        argMax(scope, updated_at) AS scope,
        argMax(scope_id, updated_at) AS scope_id,
        argMax(name, updated_at) AS name,
        argMax(status, updated_at) AS status,
        argMax(signal, updated_at) AS signal,
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
    const event = mapEventRow(row);
    const signal = event.signal || SIGNALS.volume;
    map.set(objectSignalKey(event.scope, event.scopeId, signal), event);
    if (signal === SIGNALS.volume) map.set(objectKey(event.scope, event.scopeId), event);
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

async function loadDetectionEvents({ status = 'active', limit = 200, from, to, kind } = {}) {
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
    ? historyStatusSql(kind)
    : `status = 'active'`;
  const { rows } = await query(`
    SELECT event_id, scope, scope_id, name, status, signal, alert_minute, normalize_minute, alert_json, normalize_json, threshold
    FROM (
      SELECT
        event_id,
        argMax(scope, updated_at) AS scope,
        argMax(scope_id, updated_at) AS scope_id,
        argMax(name, updated_at) AS name,
        argMax(status, updated_at) AS status,
        argMax(signal, updated_at) AS signal,
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
    'event_id', 'scope', 'scope_id', 'signal', 'name', 'status', 'phase', 'phase_minute',
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
          event.signal || SIGNALS.volume,
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
    kind: options.kind,
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
  const thresholdByKey = await loadThresholdMap();
  const above = allRows.filter((r) => {
    const objectId = objectKey(r.scope, r.scope_id);
    const group = grouped.get(objectId);
    const t = resolveGrowthThreshold(r.scope, r.scope_id, settings.growthThreshold, thresholdByKey);
    return isSignalHot(SIGNALS.volume, r, group, t)
      || isSignalHot(SIGNALS.amplification, r, group, t)
      || isSignalHot(SIGNALS.foreign_geo, r, group, t);
  });
  const watchKeys = [];
  const seen = new Set();
  for (const row of allRows) {
    const key = objectKey(row.scope, row.scope_id);
    if (seen.has(key)) continue;
    const hasActive = [SIGNALS.volume, SIGNALS.amplification, SIGNALS.foreign_geo]
      .some((signal) => activeByKey.has(objectSignalKey(row.scope, row.scope_id, signal))
        || (signal === SIGNALS.volume && activeByKey.has(key)));
    if (!above.includes(row) && !hasActive) continue;
    seen.add(key);
    watchKeys.push({ scope: row.scope, scopeId: row.scope_id });
  }

  const take = Math.max(
    settings.streak,
    settings.normalizeStreak,
    settings.ampStreak,
    settings.geoStreak,
    settings.ampNormalizeStreak,
    settings.geoNormalizeStreak,
  );
  const previousByKey = await loadPreviousAllRows(minute, watchKeys, take);
  const pickOpts = {
    settings,
    grouped,
    enabledAtMs: settings.enabled && settings.updatedAt ? parseUtc(settings.updatedAt) : tgCfg?.enabledAtMs,
    alertScope: settings.alertScope,
    activeKeys: new Set(activeByKey.keys()),
    thresholdByKey,
    streak: settings.streak,
  };
  const alertCandidates = pickAlertCandidates(allRows, previousByKey, settings.growthThreshold, pickOpts);
  const normalizeCandidates = pickNormalizeCandidates(allRows, previousByKey, settings.growthThreshold, {
    settings,
    grouped,
    activeByKey,
    thresholdByKey,
    streak: settings.normalizeStreak,
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

  const alertGroups = new Map();
  for (const candidate of alertCandidates) {
    const groupKey = `${candidate.objectKey || candidate.key}|${minute}`;
    const list = alertGroups.get(groupKey) || [];
    list.push(candidate);
    alertGroups.set(groupKey, list);
  }

  for (const candidates of alertGroups.values()) {
    const { row, threshold: objectThreshold, thresholdIsCustom } = candidates[0];
    const objectId = objectKey(row.scope, row.scope_id);
    const group = grouped.get(objectId);
    const name = nameByKey?.get(objectId) || row.scope_id;
    const byProto = group?.byProto || { all: row };
    const signals = candidates.map((c) => c.signal || SIGNALS.volume);
    let hour = { p95: null, p999: null };
    let investigate = emptyInvestigate();
    let binding = null;
    if (row.scope === 'client') {
      try {
        binding = await loadClientBinding(row.scope_id);
      } catch (err) {
        errors.push({ key: objectId, message: `binding: ${err.message}` });
      }
    }
    try {
      hour = await loadHourEnvelope({ scope: row.scope, scopeId: row.scope_id, minute });
    } catch (err) {
      errors.push({ key: objectId, message: `hour: ${err.message}` });
    }
    let verdict = classifyFromMetrics(byProto, hour);
    if (verdict.needsInvestigate || signals.includes(SIGNALS.amplification) || signals.includes(SIGNALS.foreign_geo)) {
      try {
        investigate = await investigateIncident({ scope: row.scope, scopeId: row.scope_id, minute });
        verdict = refineClassification(verdict, investigate);
      } catch (err) {
        errors.push({ key: objectId, message: `investigate: ${err.message}` });
        investigate = { ...emptyInvestigate(), error: err.message };
      }
    }
    const attack = isAlertAttack(verdict, signals);
    const text = formatAlertMessage({
      name,
      scope: row.scope,
      scopeId: row.scope_id,
      minute,
      threshold: objectThreshold,
      thresholdIsCustom,
      streak: candidates[0].streak || settings.streak,
      alertScope: settings.alertScope,
      byProto,
      verdict,
      investigate,
      binding,
      signals,
    });
    const snapshot = persistAlertSnapshot(snapshotByProto(group, row), {
      verdict,
      investigate,
      binding,
      telegramText: text,
    });
    for (const candidate of candidates) {
      const signal = candidate.signal || SIGNALS.volume;
      const eventId = signal === SIGNALS.volume
        ? `${objectId}|${minute}`
        : `${objectId}|${signal}|${minute}`;
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
        threshold: objectThreshold,
        signal,
      });
      opened += 1;
    }
    const tg = await maybeSendTelegram(text, matchesAlertKind(attack, settings.alertKind) ? tgCfg : null);
    if (tg.sent) sent += 1;
    if (tg.error) errors.push({ key: objectId, message: tg.error });
  }

  for (const { row, key, active } of normalizeCandidates) {
    const group = grouped.get(key);
    const name = nameByKey?.get(key) || active.name || row.scope_id;
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
    const snapshot = {
      ...snapshotByProto(group, row),
      telegramText: text,
    };
    await insertDetectionEvent({
      event_id: active.id,
      scope: active.scope,
      scope_id: active.scopeId,
      name,
      status: 'normalized',
      alert_minute: active.alertMinute,
      normalize_minute: minute,
      alert_json: JSON.stringify(persistActiveAlertSnapshot(active)),
      normalize_json: JSON.stringify(snapshot),
      threshold: active.threshold || settings.growthThreshold,
      signal: active.signal || SIGNALS.volume,
    });
    closed += 1;
    const tg = await maybeSendTelegram(text, matchesAlertKind(true, settings.alertKind) ? tgCfg : null);
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

async function loadDetectionEventRaw(eventId) {
  await ensureDetectionTelegramTables();
  const { rows } = await query(`
    SELECT event_id, scope, scope_id, name, status, signal, alert_minute, normalize_minute, alert_json, normalize_json, threshold
    FROM (
      SELECT
        event_id,
        argMax(scope, updated_at) AS scope,
        argMax(scope_id, updated_at) AS scope_id,
        argMax(name, updated_at) AS name,
        argMax(status, updated_at) AS status,
        argMax(signal, updated_at) AS signal,
        argMax(alert_minute, updated_at) AS alert_minute,
        argMax(normalize_minute, updated_at) AS normalize_minute,
        argMax(alert_json, updated_at) AS alert_json,
        argMax(normalize_json, updated_at) AS normalize_json,
        argMax(threshold, updated_at) AS threshold
      FROM ${eventsTableRef()}
      WHERE event_id = {id:String}
      GROUP BY event_id
    )
  `, { id: String(eventId) }, { name: 'detection/events-one' });
  return rows[0] || null;
}

// Re-run the minute breakdown for a stored alert and write a replacement row.
// Metrics stay as they were; only verdict / investigate / telegramText change.
async function rebuildDetectionEventAlert({ scope, scopeId, minute, sendTelegram = false } = {}) {
  const minuteCh = formatCh(parseUtc(minute));
  if (!Number.isFinite(parseUtc(minuteCh))) {
    throw apiError('минута: неверная дата/время');
  }
  const key = objectKey(scope, scopeId);
  const eventId = `${key}|${minuteCh}`;
  const row = await loadDetectionEventRaw(eventId);
  if (!row) throw apiError(`событие ${eventId} не найдено`, 404);
  const snapshot = parseSnapshot(row.alert_json);
  const byProto = byProtoFromSnapshot(snapshot);
  if (!byProto.all) throw apiError(`у ${eventId} нет снимка метрик`);
  const settings = await getDetectionTelegramSettings();
  let hour = { p95: null, p999: null };
  let investigate = emptyInvestigate();
  let binding = snapshot.binding || null;
  if (row.scope === 'client') {
    try {
      binding = await loadClientBinding(row.scope_id);
    } catch {
      binding = snapshot.binding || null;
    }
  }
  try {
    hour = await loadHourEnvelope({ scope: row.scope, scopeId: row.scope_id, minute: minuteCh });
  } catch { /* keep empty envelope */ }
  let verdict = classifyFromMetrics(byProto, hour);
  if (verdict.needsInvestigate) {
    try {
      investigate = await investigateIncident({ scope: row.scope, scopeId: row.scope_id, minute: minuteCh });
      verdict = refineClassification(verdict, investigate);
    } catch (err) {
      investigate = { ...emptyInvestigate(), error: err.message };
    }
  }
  const text = formatAlertMessage({
    name: row.name || row.scope_id,
    scope: row.scope,
    scopeId: row.scope_id,
    minute: minuteCh,
    threshold: Number(row.threshold) || settings.growthThreshold,
    streak: settings.streak,
    alertScope: settings.alertScope,
    byProto,
    verdict,
    investigate,
    binding,
  });
  const next = persistAlertSnapshot(snapshot, { verdict, investigate, binding, telegramText: text });
  await insertDetectionEvent({
    event_id: row.event_id,
    scope: row.scope,
    scope_id: row.scope_id,
    name: row.name,
    status: row.status,
    alert_minute: row.alert_minute,
    normalize_minute: row.normalize_minute,
    alert_json: JSON.stringify(next),
    normalize_json: row.normalize_json || '',
    threshold: Number(row.threshold) || settings.growthThreshold,
    signal: row.signal || SIGNALS.volume,
  });
  let telegram = { sent: false, skipped: 'not_requested' };
  if (sendTelegram) telegram = await maybeSendTelegram(text, null);
  return {
    eventId,
    victim: investigate.victim,
    switchIn: investigate.switchIn,
    switchOut: investigate.switchOut,
    error: investigate.error || null,
    telegram,
    text,
  };
}

module.exports = {
  DEFAULT_GROWTH_THRESHOLD,
  DEFAULT_ALERT_SCOPE,
  DEFAULT_ALERT_KIND,
  DEFAULT_STREAK,
  DEFAULT_NORMALIZE_STREAK,
  DEFAULT_TELEGRAM_API_URL,
  shortErrorMsg,
  normalizeTelegramApiUrl,
  normalizeTelegramProxyUrl,
  redactTelegramProxyUrl,
  resolveTelegramProxyUrl,
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
  matchesAlertKind,
  isAlertAttack,
  historyStatusSql,
  normalizeAlertKind,
  pickAlertCandidates,
  pickNormalizeCandidates,
  shouldSendSignal,
  SIGNALS,
  formatAlertMessage,
  formatNormalizeMessage,
  snapshotByProto,
  mapEventRow,
  loadDetectionEvents,
  exportDetectionEventsCsv,
  buildDetectionEventsCsv,
  processDetectionAlerts,
  rebuildDetectionEventAlert,
};

if (require.main === module) {
  require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
  const [mode, scope, scopeId, minute] = process.argv.slice(2);
  if (mode !== 'rebuild' || !scope || !scopeId || !minute) {
    console.error("Usage: node server/detection-telegram.js rebuild <client|net> <id> '<YYYY-MM-DD HH:MM:SS>'");
    process.exit(2);
  }
  rebuildDetectionEventAlert({ scope, scopeId, minute }).then((out) => {
    process.stdout.write(`${out.text}\n`);
    console.error(JSON.stringify({
      eventId: out.eventId,
      victim: out.victim,
      switchIn: out.switchIn,
      switchOut: out.switchOut,
      error: out.error,
    }, null, 2));
  }).catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}
