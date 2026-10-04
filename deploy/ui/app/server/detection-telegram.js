'use strict';

const { query, executeCommand, insertRows, config } = require('./clickhouse');
const { tableRef, ensureDetectionTables } = require('./detection-schema');
const { formatCh, parseUtc, MINUTE } = require('./detection-core');
const {
  KINDS,
  HOUR_RATIO_PEAK,
  classifyFromMetrics,
  refineClassification,
  isTargetFocus,
  isAttackKind,
  isLegitimatePeak,
  downloadPeakLabel,
  formatSwitchPort,
  formatAsnLabel,
  isUsableVictim,
  volumeStillHigh,
} = require('./detection-classify');
const { loadHourEnvelope, loadClientBinding, loadProviderBinding, formatClientMarkup, investigateIncident, attachTargetFocus, emptyInvestigate, loadExcessAsnTop } = require('./detection-investigate');
const { loadThresholdMap, resolveGrowthThreshold, hasGrowthOverride } = require('./detection-thresholds');
const {
  SIGNALS,
  SIGNAL_ORDER,
  isAmplificationHit,
  ampStillGoing,
  ampMetrics,
  evaluateForeignGeo,
  formatTopCountries,
  amplifierPortsFromL4,
  amplifierLabel,
  objectSignalKey,
  isSynFloodHit,
  synFloodStillGoing,
  tcpClassMetrics,
  NET_STREAK,
  NET_NORMALIZE_STREAK,
  netSpikeMetrics,
  isNetSpikeHit,
  isNetSpikeStrong,
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
const DEFAULT_VOLUME_WINDOW = 6;
const DEFAULT_VOLUME_QUIET = 10;
const DEFAULT_TELEGRAM_API_URL = 'https://api.telegram.org';
const DEFAULT_MIN_CLIENT_SHARE_PCT = 10;
const TELEGRAM_SKIP_BELOW_SHARE = 'below_client_share';
const MAX_STREAK = 60;
const PREV_ROWS_GAP_MINUTES = 15;
const ALERT_SCOPES = new Set(['all', 'client', 'net']);
const ALERT_KINDS = new Set(['all', 'attack', 'peak']);
const SNAPSHOT_FIELDS = [
  'bps', 'pps', 'growth_bps', 'growth_pps', 'bytes', 'packets',
  'avg_packet_bytes', 'cv_percent',
  'syn_attempts', 'syn_answered', 'syn_in_flows', 'syn_half_open', 'syn_half_open_reply',
  'answer_pct', 'half_open_pct', 'half_open_reply_pct',
  'port_entropy', 'port_entropy_out', 'ports_per_ip', 'ports_per_ip_out',
  'amp_bytes', 'amp_packets', 'amp_srcs', 'growth_amp', 'growth_syn',
  'foreign_bytes', 'foreign_srcs', 'top_countries',
  'growth_foreign_bps', 'growth_foreign_share',
  'syn_only_bytes', 'syn_only_packets', 'syn_only_rows', 'syn_only_targets',
  'ack_only_bytes', 'ack_only_packets', 'ack_only_rows',
  'rst_bytes', 'rst_packets', 'rst_rows',
  'established_bytes', 'established_packets', 'established_rows',
  'data_bytes', 'data_packets', 'data_rows',
  'sampling_rate',
  'net_top', 'net_bps', 'net_pps', 'net_usual_bps', 'net_usual_pps',
  'net_growth_bps', 'net_growth_pps', 'net_udp_bps', 'net_tcp_bps', 'net_list',
];
// Список стран — строка вида RU:0.60,UZ:0.12; числовое приведение убило бы её.
const SNAPSHOT_STRING_FIELDS = new Set(['top_countries', 'net_top', 'net_list']);
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
  growth_syn: 'growthSyn',
  foreign_bytes: 'foreignBytes',
  foreign_srcs: 'foreignSrcs',
  top_countries: 'topCountries',
  growth_foreign_bps: 'growthForeignBps',
  growth_foreign_share: 'growthForeignShare',
  syn_only_bytes: 'synOnlyBytes',
  syn_only_packets: 'synOnlyPackets',
  syn_only_rows: 'synOnlyRows',
  syn_only_targets: 'synOnlyTargets',
  ack_only_bytes: 'ackOnlyBytes',
  ack_only_packets: 'ackOnlyPackets',
  ack_only_rows: 'ackOnlyRows',
  rst_bytes: 'rstBytes',
  rst_packets: 'rstPackets',
  rst_rows: 'rstRows',
  established_bytes: 'establishedBytes',
  established_packets: 'establishedPackets',
  established_rows: 'establishedRows',
  data_bytes: 'dataBytes',
  data_packets: 'dataPackets',
  data_rows: 'dataRows',
  sampling_rate: 'samplingRate',
  net_top: 'netTop',
  net_bps: 'netBps',
  net_pps: 'netPps',
  net_usual_bps: 'netUsualBps',
  net_usual_pps: 'netUsualPps',
  net_growth_bps: 'netGrowthBps',
  net_growth_pps: 'netGrowthPps',
  net_udp_bps: 'netUdpBps',
  net_tcp_bps: 'netTcpBps',
  net_list: 'netList',
};

const DEFAULT_AMP_HOUR_RATIO = 2;
const DEFAULT_AMP_MIN_MBIT = 20;
const DEFAULT_SYN_HOUR_RATIO = 10;
const DEFAULT_SYN_MIN_KPPS = 200;
const DEFAULT_SYN_PKT_MAX = 100;
const VECTOR_NOTIFY_GAP_MINUTES = 10;
const PEAK_GROWTH_RATIO = 2;

const DEFAULT_SETTINGS = {
  bot_token: '',
  chat_id: '',
  growth_threshold: DEFAULT_GROWTH_THRESHOLD,
  alert_scope: DEFAULT_ALERT_SCOPE,
  alert_kind: DEFAULT_ALERT_KIND,
  streak: DEFAULT_STREAK,
  normalize_streak: DEFAULT_NORMALIZE_STREAK,
  volume_hot_window: DEFAULT_VOLUME_WINDOW,
  volume_quiet_streak: DEFAULT_VOLUME_QUIET,
  api_url: DEFAULT_TELEGRAM_API_URL,
  proxy_url: '',
  enabled: 0,
  amp_enabled: 1,
  geo_enabled: 1,
  amp_streak: 1,
  geo_streak: 1,
  amp_normalize_streak: DEFAULT_NORMALIZE_STREAK,
  geo_normalize_streak: DEFAULT_NORMALIZE_STREAK,
  volume_min_share_pct: DEFAULT_MIN_CLIENT_SHARE_PCT,
  amp_min_share_pct: DEFAULT_MIN_CLIENT_SHARE_PCT,
  geo_min_share_pct: DEFAULT_MIN_CLIENT_SHARE_PCT,
  syn_min_share_pct: DEFAULT_MIN_CLIENT_SHARE_PCT,
  amp_hour_ratio: DEFAULT_AMP_HOUR_RATIO,
  amp_min_mbit: DEFAULT_AMP_MIN_MBIT,
  syn_enabled: 1,
  syn_hour_ratio: DEFAULT_SYN_HOUR_RATIO,
  syn_min_kpps: DEFAULT_SYN_MIN_KPPS,
  syn_pkt_max: DEFAULT_SYN_PKT_MAX,
  vector_notify: 1,
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

function normalizeAmpHourRatio(value, fallback = DEFAULT_AMP_HOUR_RATIO) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(100, Math.round(n * 10) / 10);
}

function normalizeAmpMinMbit(value, fallback = DEFAULT_AMP_MIN_MBIT) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(100000, Math.round(n * 10) / 10);
}

function normalizeSynHourRatio(value, fallback = DEFAULT_SYN_HOUR_RATIO) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(1000, Math.round(n * 10) / 10);
}

function normalizeSynMinKpps(value, fallback = DEFAULT_SYN_MIN_KPPS) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(100000, Math.round(n));
}

function normalizeSynPktMax(value, fallback = DEFAULT_SYN_PKT_MAX) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 40) return fallback;
  return Math.min(1500, Math.round(n));
}

function normalizeMinSharePct(value, fallback = DEFAULT_MIN_CLIENT_SHARE_PCT) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.min(100, Math.round(n * 10) / 10);
}

function parseMinSharePct(value, label) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 100) {
    throw apiError(`${label}: число от 0 до 100`);
  }
  return normalizeMinSharePct(n, 0);
}

function minSharePctForSignal(settings = {}, signal = SIGNALS.volume) {
  if (signal === SIGNALS.amplification) return normalizeMinSharePct(settings.ampMinSharePct ?? settings.amp_min_share_pct);
  if (signal === SIGNALS.foreign_geo) return normalizeMinSharePct(settings.geoMinSharePct ?? settings.geo_min_share_pct);
  if (signal === SIGNALS.syn_flood) return normalizeMinSharePct(settings.synMinSharePct ?? settings.syn_min_share_pct);
  return normalizeMinSharePct(settings.volumeMinSharePct ?? settings.volume_min_share_pct);
}

// Доля паразитного среза от всего трафика клиента. null — замера нет, алерт
// не глушим: лучше лишнее сообщение, чем пропущенная атака.
function parasiticClientShare(signal, { byProto } = {}) {
  const all = byProto?.all || {};
  const allBps = Number(all.bps) || 0;
  if (signal === SIGNALS.amplification) {
    const udp = ampRowFor({ proto: 'all', udpRow: byProto?.udp }, { byProto });
    const amp = ampMetrics(udp || {});
    if (!(amp.bps > 0) || !(allBps > 0)) return null;
    return amp.bps / allBps;
  }
  if (signal === SIGNALS.foreign_geo) {
    const geo = evaluateForeignGeo(all);
    if (geo.share != null) return geo.share;
    if (geo.bps > 0 && allBps > 0) return geo.bps / allBps;
    return null;
  }
  if (signal === SIGNALS.syn_flood) {
    const tcp = byProto?.tcp || {};
    const pick = tcpClassMetrics(tcp, 'syn_only').pps > tcpClassMetrics(all, 'syn_only').pps ? tcp : all;
    const syn = tcpClassMetrics(pick, 'syn_only');
    if (syn.bps > 0 && allBps > 0) return syn.bps / allBps;
    const allPps = Number(all.pps) || 0;
    if (syn.pps > 0 && allPps > 0) return syn.pps / allPps;
    return null;
  }
  const growth = finiteGrowth(all.growth_bps ?? all.growthBps);
  if (growth > 1) return Math.min(1, Math.max(0, 1 - 1 / growth));
  return null;
}

function shouldSkipTelegramForShare(signals, ctx, settings = {}) {
  const list = Array.isArray(signals) && signals.length ? signals : [SIGNALS.volume];
  return list.every((signal) => {
    // Отражение, SYN и сеть /24 режутся кратностью к своей норме, не долей от
    // всего клиента: у сети внутри крупного клиента доля по определению мала.
    if (signal === SIGNALS.amplification || signal === SIGNALS.syn_flood || signal === SIGNALS.net_spike) {
      return false;
    }
    const minPct = minSharePctForSignal(settings, signal);
    if (!(minPct > 0)) return false;
    const share = parasiticClientShare(signal, ctx);
    if (share == null) return false;
    return (share * 100) < minPct;
  });
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
  const rowScope = String(row?.scope || '');
  // Провайдер — та же сеть, только целиком: «Рассылка по сетям» его не отсекает.
  if (scope === 'net' && rowScope === 'provider') return true;
  return rowScope === scope;
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
    volumeWindow: normalizeStreak(row.volume_hot_window, DEFAULT_VOLUME_WINDOW),
    volumeQuiet: normalizeStreak(row.volume_quiet_streak, DEFAULT_VOLUME_QUIET),
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
    volumeMinSharePct: normalizeMinSharePct(row.volume_min_share_pct ?? row.volumeMinSharePct),
    ampMinSharePct: normalizeMinSharePct(row.amp_min_share_pct ?? row.ampMinSharePct),
    geoMinSharePct: normalizeMinSharePct(row.geo_min_share_pct ?? row.geoMinSharePct),
    synMinSharePct: normalizeMinSharePct(row.syn_min_share_pct ?? row.synMinSharePct),
    ampHourRatio: normalizeAmpHourRatio(row.amp_hour_ratio ?? row.ampHourRatio),
    ampMinMbit: normalizeAmpMinMbit(row.amp_min_mbit ?? row.ampMinMbit),
    synEnabled: Number(row.syn_enabled ?? 1) === 1,
    synHourRatio: normalizeSynHourRatio(row.syn_hour_ratio ?? row.synHourRatio),
    synMinKpps: normalizeSynMinKpps(row.syn_min_kpps ?? row.synMinKpps),
    synPktMax: normalizeSynPktMax(row.syn_pkt_max ?? row.synPktMax),
    vectorNotify: Number(row.vector_notify ?? row.vectorNotify ?? 1) === 1,
  };
}

function ampOptions(settings = {}) {
  return {
    bpsMin: normalizeAmpMinMbit(settings.ampMinMbit) * 1e6,
    hourRatio: normalizeAmpHourRatio(settings.ampHourRatio),
  };
}

function synOptions(settings = {}) {
  return {
    ppsMin: normalizeSynMinKpps(settings.synMinKpps) * 1e3,
    hourRatio: normalizeSynHourRatio(settings.synHourRatio),
    pktMax: normalizeSynPktMax(settings.synPktMax),
  };
}

function isSynHot(row, settings = {}) {
  const syn = synOptions(settings);
  return isSynFloodHit(row || {}, syn) || isSynFloodHit(row?.tcpRow || {}, syn);
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
  if (signal === SIGNALS.syn_flood) {
    return {
      enabled: settings.synEnabled !== false,
      streak: 1,
      normalizeStreak: normalizeStreak(settings.normalizeStreak, DEFAULT_NORMALIZE_STREAK),
    };
  }
  if (signal === SIGNALS.net_spike) {
    return {
      enabled: process.env.DETECTION_NET_SPIKE !== '0',
      streak: NET_STREAK,
      normalizeStreak: NET_NORMALIZE_STREAK,
    };
  }
  const streak = normalizeStreak(settings.streak, DEFAULT_STREAK);
  const window = settings.volumeWindow != null || settings.volume_hot_window != null
    ? normalizeStreak(settings.volumeWindow ?? settings.volume_hot_window, DEFAULT_VOLUME_WINDOW)
    : streak;
  const quiet = settings.volumeQuiet != null || settings.volume_quiet_streak != null
    ? normalizeStreak(settings.volumeQuiet ?? settings.volume_quiet_streak, DEFAULT_VOLUME_QUIET)
    : normalizeStreak(settings.normalizeStreak, DEFAULT_NORMALIZE_STREAK);
  return {
    enabled: true,
    streak,
    window: Math.max(streak, window),
    normalizeStreak: quiet,
  };
}

// В строках proto='all' колонки amp_* приходят из ClickHouse нулями, а не null,
// поэтому считать признак по самой строке минуты нельзя — нужна строка UDP той же
// минуты: доля отражателей меряется к UDP, а не ко всему трафику.
function ampRowFor(row, group) {
  if (String(row?.proto || '') === 'udp') return row;
  return row?.udpRow || group?.byProto?.udp || null;
}

function isSignalHot(signal, row, group, threshold, settings = {}) {
  if (signal === SIGNALS.amplification) {
    const udp = ampRowFor(row, group);
    return udp ? isAmplificationHit(udp, ampOptions(settings)) : false;
  }
  if (signal === SIGNALS.syn_flood) {
    // Только поля самой минуты. group.tcp — текущий тик: если подставить его
    // в историю, вчерашние строки без syn_only выглядят горячими, серия
    // «уже идёт» и алерт не открывается (waiting_streak на nta 14.09).
    return isSynHot(row, settings);
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
  if (signal === SIGNALS.net_spike) {
    const scope = String(row?.scope || group?.scope || '');
    return (scope === 'client' || scope === 'provider') && isNetSpikeHit(row);
  }
  return isAboveGrowthThreshold(row, threshold);
}

// Сеть /24 открывается серией из двух минут, а рост ×20 — сразу: так короткий
// удар не уходит без события. Повтор того же удара режет activeKeys.
function shouldSendNetSpike(historyNewestFirst, isHotFn, streak, enabledAtMs) {
  const history = Array.isArray(historyNewestFirst) ? historyNewestFirst : [];
  if (shouldSendSignal(history, isHotFn, streak, enabledAtMs)) return true;
  if (!isNetSpikeStrong(history[0])) return false;
  return !history[1] || !isHotFn(history[1]);
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

// growth_bps — это «факт / норма». Лишнее — всё, что выше нормы:
// 15.4 Гбит/с при росте ×8.58 значит норма 1.8 и лишних 13.6.
function trafficAboveBaseline(bps, growth) {
  const total = Number(bps);
  const ratio = finiteGrowth(growth);
  if (!(total > 0) || !(ratio > 0)) return { baselineBps: null, excessBps: null };
  const baselineBps = total / ratio;
  return { baselineBps, excessBps: Math.max(0, total - baselineBps) };
}

function isAboveGrowthThreshold(row, threshold) {
  const gBps = finiteGrowth(row?.growth_bps ?? row?.growthBps);
  const gPps = finiteGrowth(row?.growth_pps ?? row?.growthPps);
  const t = Number(threshold) || DEFAULT_GROWTH_THRESHOLD;
  return (gBps != null && gBps >= t) || (gPps != null && gPps >= t);
}

function rowsInWindow(historyNewestFirst, windowSize) {
  const history = Array.isArray(historyNewestFirst) ? historyNewestFirst : [];
  const win = normalizeStreak(windowSize);
  if (!history.length) return [];
  const newest = parseUtc(history[0]?.minute);
  if (!Number.isFinite(newest)) return history.slice(0, win);
  const from = newest - (win - 1) * MINUTE;
  const out = [];
  for (const row of history) {
    const ts = parseUtc(row?.minute);
    if (!Number.isFinite(ts) || ts < from) break;
    out.push(row);
  }
  return out;
}

function windowQualifies(historyNewestFirst, threshold, need, windowSize) {
  const history = Array.isArray(historyNewestFirst) ? historyNewestFirst : [];
  if (!history.length || !isAboveGrowthThreshold(history[0], threshold)) return false;
  const rows = rowsInWindow(history, windowSize);
  let hot = 0;
  for (const row of rows) {
    if (isAboveGrowthThreshold(row, threshold)) hot += 1;
  }
  if (hot >= need) return true;
  return sparseWindowQualifies(rows, hot, need);
}

// Под атакой воркер не успевает и пишет минуту из нескольких (ШПД 04.10 15:41
// и 15:46 UTC), три строки в окне не набираются. Пропуск — не тишина: если все
// записанные минуты окна горячие и тянутся на серию, серия есть.
function sparseWindowQualifies(rows, hot, need) {
  if (rows.length < 2 || hot < rows.length) return false;
  const newest = parseUtc(rows[0]?.minute);
  const oldest = parseUtc(rows.at(-1)?.minute);
  if (!Number.isFinite(newest) || !Number.isFinite(oldest)) return false;
  return newest - oldest >= (need - 1) * MINUTE;
}

function shouldSendAlert(historyNewestFirst, threshold, streak = DEFAULT_STREAK, enabledAtMs, windowSize) {
  const need = normalizeStreak(streak);
  const win = normalizeStreak(windowSize, need);
  const history = Array.isArray(historyNewestFirst) ? historyNewestFirst : [];
  if (win <= need) {
    if (!history.length || !isAboveGrowthThreshold(history[0], threshold)) return false;
    if (history.length < need) return false;
    const slice = history.slice(0, need);
    if (!slice.every((row) => isAboveGrowthThreshold(row, threshold))) return false;
    const before = history[need];
    if (!before) return true;
    if (!isAboveGrowthThreshold(before, threshold)) return true;
    if (enabledAtMs) {
      const beforeTs = parseUtc(before.minute);
      if (Number.isFinite(beforeTs) && beforeTs < enabledAtMs) return true;
    }
    return false;
  }
  if (!windowQualifies(history, threshold, need, win)) return false;
  // Фронт сравниваем с прошлой горячей минутой: тихая минута между импульсами
  // не должна открывать атаку заново.
  const prevHot = history.findIndex((row, i) => i > 0 && isAboveGrowthThreshold(row, threshold));
  if (prevHot < 0) return true;
  const prev = history.slice(prevHot);
  const newestTs = parseUtc(history[0]?.minute);
  const prevTs = parseUtc(prev[0]?.minute);
  if (Number.isFinite(newestTs) && Number.isFinite(prevTs) && newestTs - prevTs > win * MINUTE) return true;
  if (!windowQualifies(prev, threshold, need, win)) return true;
  if (enabledAtMs) {
    const oldest = rowsInWindow(prev, win).at(-1);
    const oldestTs = parseUtc(oldest?.minute);
    if (Number.isFinite(oldestTs) && oldestTs < enabledAtMs) return true;
  }
  return false;
}

// Серия из нескольких минут открывается на последней, а атака часто уже
// схлынула. Вердикт и цель берём по минуте с самым большим ростом bps.
function heaviestHotMinute(historyNewestFirst, threshold, streak = DEFAULT_STREAK, windowSize) {
  const need = normalizeStreak(streak);
  const win = normalizeStreak(windowSize, need);
  const history = win > need
    ? rowsInWindow(historyNewestFirst, win)
    : (Array.isArray(historyNewestFirst) ? historyNewestFirst : []).slice(0, need);
  let best = null;
  let bestGrowth = null;
  for (const row of history) {
    if (!isAboveGrowthThreshold(row, threshold)) continue;
    const growth = finiteGrowth(row?.growth_bps ?? row?.growthBps);
    const better = !best
      || (growth != null && (bestGrowth == null || growth > bestGrowth))
      || (growth === bestGrowth && Number(row?.bps) > Number(best?.bps));
    if (better) {
      best = row;
      bestGrowth = growth;
    }
  }
  return best;
}

function sameMinute(left, right) {
  const a = parseUtc(left);
  const b = parseUtc(right);
  return Number.isFinite(a) && a === b;
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

// Нормализация сигнала: N тихих минут подряд. Без rising edge — иначе SYN,
// который кончился до выкладки или пока воркер стоял, висит навсегда:
// все минуты в окне уже тихие, фронта нет. 72966 так висел 1.7 суток.
function shouldNormalizeQuiet(historyNewestFirst, isQuietFn, streak = DEFAULT_NORMALIZE_STREAK) {
  const need = normalizeStreak(streak, DEFAULT_NORMALIZE_STREAK);
  const history = Array.isArray(historyNewestFirst) ? historyNewestFirst : [];
  if (!history.length || !isQuietFn(history[0])) return false;
  if (history.length < need) return false;
  return history.slice(0, need).every((row) => isQuietFn(row));
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

function mskParts(minute) {
  const ts = parseUtc(minute);
  if (!Number.isFinite(ts)) return null;
  const parts = new Intl.DateTimeFormat('ru-RU', {
    timeZone: 'Europe/Moscow',
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date(ts));
  const get = (type) => parts.find((p) => p.type === type)?.value || '';
  return { date: `${get('day')}.${get('month')}`, time: `${get('hour')}:${get('minute')}` };
}

function formatAlertTime(minute) {
  const p = mskParts(minute);
  return p ? `${p.date} ${p.time} МСК` : String(minute || '—');
}

function formatClockMsk(minute) {
  const p = mskParts(minute);
  return p ? p.time : '—';
}

function isAlertAttack(verdict, signals = []) {
  const list = Array.isArray(signals) ? signals : [];
  if (isAttackKind(verdict?.kind)) return true;
  if (list.includes(SIGNALS.amplification)) return true;
  if (list.includes(SIGNALS.syn_flood) && !isLegitimatePeak(verdict)) return true;
  if (list.includes(SIGNALS.foreign_geo) && !isLegitimatePeak(verdict)) return true;
  if (list.includes(SIGNALS.net_spike) && !isLegitimatePeak(verdict)) return true;
  return false;
}

function ruRazWord(n) {
  if (!Number.isInteger(n)) return 'раза';
  const k = n % 100;
  const d = n % 10;
  if (k >= 11 && k <= 14) return 'раз';
  if (d === 1) return 'раз';
  if (d >= 2 && d <= 4) return 'раза';
  return 'раз';
}

// «в 62 раза», «в 21 раз», «в 2,4 раза»: до десяти — с десятыми, иначе ×2.38
// и ×2.0 читались бы одинаково.
function formatTimes(ratio) {
  const n = Number(ratio);
  if (!Number.isFinite(n) || n <= 0) return '';
  const rounded = n >= 10 ? Math.round(n) : Math.round(n * 10) / 10;
  if (Number.isInteger(rounded)) return `${rounded} ${ruRazWord(rounded)}`;
  return `${String(rounded).replace('.', ',')} раза`;
}

function biggerThanUsual(ratio, suffix = '') {
  return `<b>В ${escapeHtml(formatTimes(ratio))} больше обычного${escapeHtml(suffix)}:</b>`;
}

function formatSharePct(share) {
  const n = Number(share) * 100;
  if (!Number.isFinite(n)) return '';
  // 177 Мбит/с внутри 40 Гбит/с — это 0.4%, а округление до целого печатало «0%»
  // и выглядело как «доли нет вовсе».
  if (n > 0 && n < 0.1) return '<0.1%';
  return n < 1 ? `${n.toFixed(1)}%` : `${n.toFixed(0)}%`;
}

// В списке из пяти строк доли около 2% нельзя схлопывать в одно «2%».
function formatFineShare(share) {
  const n = Number(share) * 100;
  if (!Number.isFinite(n) || n <= 0) return '';
  if (n < 0.1) return '<0,1%';
  if (n < 10) return `${n.toFixed(1).replace('.', ',')}%`;
  return `${Math.round(n)}%`;
}

// Биллинг отдаёт полное имя и короткое в скобках: «Общество с ограниченной
// ответственностью "Сторм Нетворкс" [ООО "Сторм Нетворкс" ]». В шапку берём
// короткое — полное занимает всю строку превью в Telegram.
function shortClientName(name) {
  const raw = String(name ?? '').trim();
  const match = raw.match(/\[([^\]]+)\]\s*$/);
  const short = match ? match[1].trim() : '';
  return short && short.length < raw.length ? short : raw;
}

function protoLabel(victim, tcp, udp, all) {
  const fromVictim = String(victim?.protoLabel || '').toUpperCase();
  if (fromVictim === 'TCP' || fromVictim === 'UDP') return fromVictim;
  if (Number(victim?.proto) === 17) return 'UDP';
  if (Number(victim?.proto) === 6) return 'TCP';
  const allBps = Number(all?.bps) || 0;
  const udpBps = Number(udp?.bps) || 0;
  const tcpBps = Number(tcp?.bps) || 0;
  if (allBps > 0 && udpBps / allBps >= 0.6) return 'UDP';
  if (allBps > 0 && tcpBps / allBps >= 0.6) return 'TCP';
  if (udpBps > tcpBps && udpBps > 0) return 'UDP';
  if (tcpBps > 0) return 'TCP';
  return '';
}

function formatAlertPort(port) {
  const n = Number(port);
  return Number.isFinite(n) && n !== 0 ? String(n) : '';
}

function formatHostPort(ip, port) {
  const host = String(ip || '');
  const p = formatAlertPort(port);
  if (!p) return host;
  return host.includes(':') ? `[${host}]:${p}` : `${host}:${p}`;
}

function formatServiceOn(investigate) {
  const label = downloadPeakLabel(investigate);
  const [proto, port] = String(label || '').split('/');
  if (port && port !== '?' && port !== '0') return `${proto} на ${port}`;
  return proto || '';
}

function topSource(investigate) {
  const row = Array.isArray(investigate?.source24) ? investigate.source24[0] : null;
  return row?.net24 ? row : null;
}

function victimShapeFor(victim, investigate) {
  const shape = investigate?.victimShape;
  return shape?.ip && shape.ip === victim?.ip ? shape : null;
}

function victimDisplayPort(victim, investigate) {
  const shape = victimShapeFor(victim, investigate);
  const count = Number(shape ? shape.dstPorts : investigate?.destPort?.count);
  if (Number.isFinite(count) && count > 1) return null;
  return formatAlertPort(victim?.port) || null;
}

function ruCount(count, [one, few, many]) {
  const n = Number(count);
  if (!Number.isFinite(n) || n < 0) return '';
  const k = n % 100;
  const d = n % 10;
  const word = (k >= 11 && k <= 14) ? many : (d === 1 ? one : (d >= 2 && d <= 4 ? few : many));
  return `${formatNumMsg(n, 0)} ${word}`;
}

function ruAddresses(count) {
  return ruCount(count, ['адрес', 'адреса', 'адресов']);
}

function ruSources(count) {
  return ruCount(count, ['источник', 'источника', 'источников']);
}

function ruPorts(count) {
  return ruCount(count, ['порт', 'порта', 'портов']);
}

function ruNets24(count) {
  return `${ruCount(count, ["сеть", "сети", "сетей"])} /24`;
}

function ruSessions(count) {
  return ruCount(count, ['сеанс', 'сеанса', 'сеансов']);
}

// Кто бьёт. Адресов в ковровой атаке тысячи, поэтому именуем сети /24, а сами
// адреса даём только числом — списком IP шапку не прочитать.
const SOURCE_NET_MIN_SHARE = 0.02;

function formatAttackSourceLines(investigate, shape = null) {
  const nets = (Array.isArray(investigate?.source24) ? investigate.source24 : [])
    .filter((row) => row?.net24 && Number(row.share) >= SOURCE_NET_MIN_SHARE)
    .slice(0, 3);
  const totals = investigate?.sources || {};
  const scale = [];
  if (shape) {
    if (Number(shape.srcs) > 0) scale.push(ruAddresses(shape.srcs));
    if (Number(shape.sessions) > 0) scale.push(ruSessions(shape.sessions));
    if (Number(shape.sessions) > 3) scale.push(`3 крупнейших — ${formatSharePct(shape.topShare)}`);
  } else {
    if (Number(totals.ipCount) > 0) scale.push(ruAddresses(totals.ipCount));
    if (Number(totals.net24Count) > 1) scale.push(ruNets24(totals.net24Count));
  }
  if (!nets.length && !scale.length) return [];
  const lines = [escapeHtml(`Источники: ${scale.length ? scale.join(' · ') : 'сети ниже'}`)];
  for (const row of nets) {
    const bits = [formatSharePct(row.share)];
    if (row.ips != null) bits.push(ruAddresses(row.ips));
    const asn = formatAsnLabel(row.asn, row.asnName || row.asName).trim();
    if (asn) bits.push(asn);
    lines.push(escapeHtml(`   ${row.net24} — ${bits.filter(Boolean).join(' · ')}`));
  }
  return lines;
}

function formatSourceOperatorLines(investigate) {
  const asns = (Array.isArray(investigate?.sources?.asns) ? investigate.sources.asns : [])
    .filter((row) => Number(row?.asn) > 0 && Number(row.share) > 0)
    .slice(0, 5);
  const countries = (Array.isArray(investigate?.sources?.countries) ? investigate.sources.countries : [])
    .filter((row) => row?.cc && Number(row.share) > 0)
    .slice(0, 5);
  const lines = [];
  if (asns.length) {
    const text = asns.map((row) => {
      const name = formatAsnLabel(row.asn, row.asnName || row.asName).trim();
      return `${name} — ${formatSharePct(row.share)}`;
    }).join(' · ');
    lines.push(escapeHtml(`Откуда операторы: ${text}`));
  }
  if (countries.length) {
    const text = countries.map((row) => `${row.cc} ${formatSharePct(row.share)}`).join(' · ');
    lines.push(escapeHtml(`Страны источников: ${text}`));
  }
  return lines;
}

function packetClass(bytes) {
  const n = Number(bytes) || 0;
  if (!(n > 0)) return '';
  if (n < 200) return 'small';
  if (n < 800) return 'mid';
  return 'large';
}

const PKT_CLASS_EDGES = { small: [0, 200], mid: [200, 800], large: [800, Infinity] };
const PKT_CLASS_MARGIN = 0.12;

// Класс пакета меняется, только когда размер ушёл от границы с запасом:
// 889 и 744 Б одного флуда не должны перекидывать «от 800» ↔ «200–800».
function packetClassMoved(prev, next) {
  if (!prev?.pkt || !next?.pkt || prev.pkt === next.pkt) return false;
  const bytes = Number(next.pktBytes);
  const edges = PKT_CLASS_EDGES[prev.pkt];
  if (!(bytes > 0) || !edges) return true;
  const [low, high] = edges;
  return bytes < low * (1 - PKT_CLASS_MARGIN) || bytes > high * (1 + PKT_CLASS_MARGIN);
}

function protoGrowth(row) {
  if (!(Number(row?.bps) > 0)) return null;
  return finiteGrowth(row?.growth_bps ?? row?.growthBps);
}

// Протокол атаки — тот, что вырос. Доля во всём трафике клиента врёт, когда
// у клиента свой большой фон: 81050 живёт на 12–15 Гбит/с TCP, и UDP-флуд
// в 95.129.234.0/24 читался то «UDP», то «смешанным» от силы импульса.
// Норма UDP за час атаки уже поднята прошлыми импульсами, поэтому слабый
// импульс растёт лишь в 1.4×: сравниваем рост протоколов между собой.
const PROTO_GROWTH_MIN = 1.2;
const PROTO_GROWTH_LEAD = 1.3;

function attackProtoRow(byProto) {
  const udp = byProto?.udp;
  const tcp = byProto?.tcp;
  const udpGrowth = protoGrowth(udp);
  const tcpGrowth = protoGrowth(tcp);
  if (udpGrowth == null || tcpGrowth == null) return null;
  if (udpGrowth >= PROTO_GROWTH_MIN && udpGrowth >= tcpGrowth * PROTO_GROWTH_LEAD) return { proto: 'udp', row: udp };
  if (tcpGrowth >= PROTO_GROWTH_MIN && tcpGrowth >= udpGrowth * PROTO_GROWTH_LEAD) return { proto: 'tcp', row: tcp };
  return null;
}

function portSignature(investigate) {
  const dest = investigate?.destPort;
  const top = Array.isArray(dest?.top) ? dest.top[0] : null;
  const count = Number(dest?.count) || 0;
  const share = Number(top?.share) || 0;
  if (count > 8 || (count > 1 && share > 0 && share < 0.2)) return 'scatter';
  if (top && share >= 0.5 && Number(top.port) > 0) return `port:${Number(top.port)}`;
  return '';
}

// Между «явно один» и «явно размазано» оставлен зазор с пустым значением: пустое
// поле со сменой не сравнивается, поэтому доля, гуляющая у границы, не шлёт
// «вектор сменился» каждые 10 минут.
function dominantSignature(rows, keyOf, { focus = 0.5, spread = 0.25 } = {}) {
  const list = Array.isArray(rows) ? rows.filter((row) => keyOf(row)) : [];
  if (!list.length) return '';
  const share = Number(list[0].share) || 0;
  if (share >= focus) return String(keyOf(list[0]));
  if (share < spread) return 'spread';
  return '';
}

function prefixSignature(investigate) {
  return dominantSignature(investigate?.dest24, (row) => row?.net24);
}

function asnSignature(investigate) {
  return dominantSignature(
    investigate?.sources?.asns,
    (row) => (Number(row?.asn) > 0 ? row.asn : ''),
    { focus: 0.4, spread: 0.2 },
  );
}

function vectorSnapshot({ byProto, investigate, verdict } = {}) {
  const all = byProto?.all || {};
  const bps = Number(all.bps) || 0;
  const udp = Number(byProto?.udp?.bps) || 0;
  const tcp = Number(byProto?.tcp?.bps) || 0;
  const grown = attackProtoRow(byProto);
  let proto = 'mix';
  if (grown) proto = grown.proto;
  else if (bps > 0 && udp / bps >= 0.6) proto = 'udp';
  else if (bps > 0 && tcp / bps >= 0.6) proto = 'tcp';
  const pktRow = grown?.row || all;
  const pktBytes = Number(pktRow.avg_packet_bytes ?? pktRow.avgPacketBytes) || 0;
  const asns = asnSignature(investigate);
  const topAsn = investigate?.sources?.asns?.[0];
  return {
    proto,
    pkt: packetClass(pktBytes),
    pktBytes: Math.round(pktBytes),
    ports: portSignature(investigate),
    prefixes: prefixSignature(investigate),
    asns,
    asnName: asns && asns !== 'spread' ? String(topAsn?.asnName || '') : '',
    kind: String(verdict?.kind || ''),
  };
}

function vectorDiffLines(prev, next) {
  if (!prev || !next) return [];
  const differ = (key) => prev[key] && next[key] && prev[key] !== next[key];
  const lines = [];
  const before = vectorLabel(prev);
  if (before && before !== vectorLabel(next)) lines.push(`Было: ${before}`);
  const asnText = (v) => (v.asns === 'spread'
    ? 'разбросаны по многим операторам'
    : `в основном AS${v.asns}${v.asnName ? ` ${v.asnName}` : ''}`);
  if (differ('asns')) lines.push(`Источники: были ${asnText(prev)} → теперь ${asnText(next)}`);
  const netText = (v) => (v.prefixes === 'spread' ? 'по многим /24' : `в основном ${v.prefixes}`);
  if (differ('prefixes')) lines.push(`Цель: была ${netText(prev)} → теперь ${netText(next)}`);
  return lines;
}

function vectorChanged(prev, next) {
  if (!prev || !next) return false;
  const differ = (key) => prev[key] && next[key] && prev[key] !== next[key];
  if (differ('kind') && next.kind !== 'benign_peak' && prev.kind !== 'benign_peak') return true;
  return Boolean(differ('proto') || packetClassMoved(prev, next) || differ('ports') || differ('prefixes') || differ('asns'));
}

function vectorLabel(vector) {
  if (!vector) return '';
  const proto = vector.proto === 'udp' ? 'UDP' : vector.proto === 'tcp' ? 'TCP' : vector.proto === 'mix' ? 'смешанный' : '';
  const pkt = vector.pkt === 'small'
    ? 'пакет до 200 Б'
    : vector.pkt === 'mid'
      ? 'пакет 200–800 Б'
      : vector.pkt === 'large'
        ? 'пакет от 800 Б'
        : '';
  const ports = vector.ports === 'scatter'
    ? 'порты случайные'
    : String(vector.ports || '').startsWith('port:')
      ? `порт ${String(vector.ports).slice(5)}`
      : '';
  return [proto, pkt, ports].filter(Boolean).join(', ');
}

function signalRate(signal, row, group) {
  if (signal === SIGNALS.syn_flood) {
    const packets = Number(row?.syn_only_packets ?? row?.synOnlyPackets) || 0;
    return { bps: 0, pps: packets / 60, unit: 'pps' };
  }
  if (signal === SIGNALS.amplification) {
    const udp = ampRowFor(row, group) || {};
    const bytes = Number(udp.amp_bytes ?? udp.ampBytes) || 0;
    return { bps: bytes * 8 / 60, pps: 0, unit: 'amp' };
  }
  return {
    bps: Number(row?.bps) || 0,
    pps: Number(row?.pps) || 0,
    unit: 'bps',
  };
}

function bumpPeak(peak, rate, minute) {
  const prev = peak || { bps: 0, pps: 0, minute: '' };
  const next = { bps: Number(prev.bps) || 0, pps: Number(prev.pps) || 0, minute: prev.minute || '' };
  const better = rate.unit === 'pps'
    ? rate.pps > next.pps
    : rate.unit === 'amp'
      ? rate.bps > next.bps
      : rate.bps > next.bps;
  if (!better) return next;
  return { bps: rate.bps, pps: rate.pps, minute };
}

function rateDoubled(track, rate) {
  if (!track) return false;
  if (rate.unit === 'pps') {
    return Number(track.lastReportPps) > 0 && rate.pps >= Number(track.lastReportPps) * PEAK_GROWTH_RATIO;
  }
  return Number(track.lastReportBps) > 0 && rate.bps >= Number(track.lastReportBps) * PEAK_GROWTH_RATIO;
}

function notifyGapOpen(lastMinute, minute) {
  const prev = parseUtc(lastMinute);
  const now = parseUtc(minute);
  if (!Number.isFinite(prev) || !Number.isFinite(now)) return true;
  return now - prev >= VECTOR_NOTIFY_GAP_MINUTES * MINUTE;
}

function ampSrcPortRows(investigate) {
  return (Array.isArray(investigate?.ampSrcPort?.top) ? investigate.ampSrcPort.top : [])
    .filter((row) => row && Number.isFinite(Number(row.port)))
    .slice(0, 5);
}

function ampPortsFor(investigate) {
  const rows = ampSrcPortRows(investigate);
  return rows.length ? rows.map((row) => Number(row.port)) : amplifierPortsFromL4(investigate?.l4src);
}

function formatFocusLines(investigate) {
  const list = Array.isArray(investigate?.focuses) && investigate.focuses.length
    ? investigate.focuses
    : (investigate?.focus ? [investigate.focus] : []);
  return list.filter((focus) => isTargetFocus(focus)).map((focus) => {
    const growth = focus.fresh || !(Number(focus.growth) > 0)
      ? 'раньше почти не было'
      : `×${Number(focus.growth).toFixed(1)} к своему часу`;
    return escapeHtml(
      `Цель ${focus.protoLabel}: ${formatHostPort(focus.ip, focus.port)} — ${formatBpsMsg(focus.bps)}`
      + ` · пакет ${formatNumMsg(focus.avgPkt, 0)} Б`
      + ` · ${ruSources(focus.srcs)}`
      + ` · ${growth}`
      + ` · ${formatSharePct(focus.share)} ${focus.protoLabel}`,
    );
  });
}

function formatNetGrowth(growth) {
  const g = Number(growth);
  if (!Number.isFinite(g)) return '';
  return `×${g >= 10 ? Math.round(g) : g.toFixed(1)}`;
}

function formatSynRate(pps) {
  if (!(Number(pps) > 0)) return '0 SYN/с';
  return formatPpsMsg(pps).replace(/п\/с$/, 'SYN/с');
}

// Минутка считает голый SYN с сэмплированием и без адресов, разбор — точно, но
// только по верхушке: п/с и размер пакета берём из минутки, адреса и цели — из разбора.
function synDetail(byProto, investigate) {
  const all = byProto?.all || {};
  const tcp = byProto?.tcp || {};
  const row = tcpClassMetrics(tcp, 'syn_only').pps > tcpClassMetrics(all, 'syn_only').pps ? tcp : all;
  const fromRow = tcpClassMetrics(row, 'syn_only');
  const detail = investigate?.syn;
  return {
    pps: fromRow.pps > 0 ? fromRow.pps : Number(detail?.pps) || 0,
    avgPkt: fromRow.avgPkt > 0 ? fromRow.avgPkt : Number(detail?.avgPkt) || 0,
    growth: finiteGrowth(row.growth_syn ?? row.growthSyn ?? all.growth_syn ?? all.growthSyn),
    srcIps: Number(detail?.srcIps) || 0,
    srcNets: Number(detail?.srcNets) || 0,
    srcAsns: Number(detail?.srcAsns) || 0,
    dstIps: Number(detail?.dstIps) || 0,
    dest: (Array.isArray(detail?.dest) ? detail.dest : []).filter((d) => d?.ip),
  };
}

function netProtoLabel(net) {
  if (!(net.bps > 0)) return '';
  if (net.tcpShare != null && net.tcpShare >= 0.6) return 'TCP';
  if (net.udpBps / net.bps >= 0.6) return 'UDP';
  return '';
}

function withProtoPrefix(proto, text) {
  return proto ? `${proto}-${text}` : `${text.charAt(0).toUpperCase()}${text.slice(1)}`;
}

// Вид алерта решает, какие строки показать: заголовок, размер и цель
// считаются по одному и тому же виду, иначе шапка спорит с телом.
function alertMode(verdict, signals, attack) {
  const kind = verdict?.kind || '';
  if (kind === KINDS.amplification) return 'amp';
  if (kind === KINDS.syn_flood) return 'syn';
  if (attack && signals.includes(SIGNALS.net_spike)) return 'net';
  if (kind === KINDS.volumetric) return 'volumetric';
  if (kind === KINDS.carpet) return 'carpet';
  if (attack && signals.includes(SIGNALS.amplification)) return 'amp';
  if (attack && signals.includes(SIGNALS.syn_flood)) return 'syn';
  if (attack && signals.includes(SIGNALS.foreign_geo)) return 'geo';
  if (kind === KINDS.benign_peak) return 'peak';
  return attack ? 'generic' : 'unknown';
}

function alertTitle(mode, { byProto, investigate, verdict }) {
  const all = byProto?.all || {};
  const proto = protoLabel(investigate?.victim, byProto?.tcp || {}, byProto?.udp || {}, all);
  if (mode === 'amp') {
    const fromAmp = (Array.isArray(verdict?.ampSrcPort?.top) ? verdict.ampSrcPort.top : [])
      .map((row) => ({ port: row.port, proto: 17 }));
    const ports = fromAmp.length ? amplifierPortsFromL4(fromAmp) : ampPortsFor(investigate);
    // Все отражатели перечислены в строке «Отражатели»; в заголовке — два главных.
    const label = amplifierLabel(ports.slice(0, 2));
    return `Амплификация${label ? ` ${label}` : ''}${ports.length > 2 ? ' и др.' : ''}`;
  }
  if (mode === 'syn') return 'SYN-флуд';
  if (mode === 'net') return withProtoPrefix(netProtoLabel(netSpikeMetrics(all)), 'флуд в сеть /24');
  if (mode === 'volumetric') return withProtoPrefix(proto, 'флуд в один сервер');
  if (mode === 'carpet') return withProtoPrefix(proto, 'флуд по сети');
  if (mode === 'geo') return 'Всплеск трафика из-за рубежа';
  if (mode === 'peak') return 'Пик трафика, не атака';
  return 'Рост трафика выше порога';
}

function providerLabel(scopeId, name) {
  const raw = String(name || scopeId || '').trim().replace(/^isp:/i, '');
  return raw || String(scopeId || '').replace(/^isp:/i, '');
}

function formatAlertWho(scope, scopeId, name) {
  const shortName = shortClientName(name);
  const named = shortName && shortName !== scopeId ? shortName : '';
  if (scope === 'net') {
    return `сеть <b>${escapeHtml(scopeId)}</b>${named ? ` · ${escapeHtml(named)}` : ''}`;
  }
  if (scope === 'provider') {
    return `провайдер <b>${escapeHtml(providerLabel(scopeId, named || name))}</b>`;
  }
  return `${named ? `<b>${escapeHtml(named)}</b> · ` : ''}ID <b>${escapeHtml(scopeId)}</b>`;
}

// Меньше ×1.05 — шум замера, «в 1,0 раза больше» читать незачем.
const VOLUME_RATIO_SHOWN = 1.05;

function hourUsualOf(verdict) {
  return Number(verdict?.hourCeiling || verdict?.hourP95 || 0);
}

function volumeRatio(all, verdict) {
  const bps = Number(all?.bps);
  const ratio = Number(verdict?.hourRatio);
  if (Number.isFinite(ratio) && ratio > 0) return ratio;
  const usual = hourUsualOf(verdict);
  return bps > 0 && usual > 0 ? bps / usual : null;
}

function formatVolumeSize(all, verdict) {
  const bps = Number(all?.bps) || 0;
  const pps = Number(all?.pps) || 0;
  const usual = hourUsualOf(verdict);
  const ratio = volumeRatio(all, verdict);
  const usualText = usual > 0 ? `, обычно ${escapeHtml(formatBpsMsg(usual))}` : '';
  if (ratio != null && ratio >= VOLUME_RATIO_SHOWN) {
    return `${biggerThanUsual(ratio)} ${escapeHtml(formatBpsMsg(bps))}${usualText}`;
  }
  // Алерт мог открыться по пакетам при прежних байтах: без этой строки
  // «объём как обычно» спорит с красной шапкой.
  const growthPps = finiteGrowth(all?.growth_pps ?? all?.growthPps);
  if (growthPps != null && growthPps >= HOUR_RATIO_PEAK && pps > 0) {
    return `${biggerThanUsual(growthPps, ' по пакетам')} ${escapeHtml(formatPpsMsg(pps))}, обычно до ~${escapeHtml(formatPpsMsg(pps / growthPps))}`;
  }
  if (ratio != null) {
    const level = ratio < 1 ? 'ниже обычного' : 'на уровне обычного';
    return `Объём <b>${escapeHtml(formatBpsMsg(bps))}</b> — ${level}${usual > 0 ? ` (${escapeHtml(formatBpsMsg(usual))})` : ''}`;
  }
  // Нормы часа нет — сравниваем с 14-дневным p999, это потолок, а не среднее.
  const growthBps = finiteGrowth(all?.growth_bps ?? all?.growthBps);
  if (growthBps != null && growthBps >= HOUR_RATIO_PEAK && bps > 0) {
    return `${biggerThanUsual(growthBps)} ${escapeHtml(formatBpsMsg(bps))}, обычно до ~${escapeHtml(formatBpsMsg(bps / growthBps))}`;
  }
  return `Объём <b>${escapeHtml(formatBpsMsg(bps))}</b>`;
}

function formatSizeLine(mode, { byProto, verdict, syn }) {
  const all = byProto?.all || {};
  const udp = byProto?.udp || {};
  if (mode === 'syn' && syn.pps > 0) {
    if (syn.growth != null && syn.growth >= HOUR_RATIO_PEAK) {
      return `${biggerThanUsual(syn.growth)} ${escapeHtml(formatSynRate(syn.pps))}, обычно ~${escapeHtml(formatSynRate(syn.pps / syn.growth))}`;
    }
    return `Голый SYN: <b>${escapeHtml(formatSynRate(syn.pps))}</b>`;
  }
  if (mode === 'net') {
    const net = netSpikeMetrics(all);
    if (net.net) {
      const byPps = net.growthPps != null && (net.growthBps == null || net.growthPps > net.growthBps);
      const now = byPps ? formatPpsMsg(net.pps) : formatBpsMsg(net.bps);
      const usual = byPps ? net.usualPps : net.usualBps;
      const where = ` в ${net.net}`;
      if (usual > 0 && net.growth != null) {
        const usualText = byPps ? formatPpsMsg(usual) : formatBpsMsg(usual);
        return `${biggerThanUsual(net.growth)} ${escapeHtml(`${now}${where}`)}, обычно ${escapeHtml(usualText)}`;
      }
      return `<b>${escapeHtml(now)}</b>${escapeHtml(where)}, раньше почти не было`;
    }
  }
  if (mode === 'amp') {
    const amp = ampMetrics(udp);
    if (amp.bps > 0) {
      const growth = finiteGrowth(udp.growth_amp ?? udp.growthAmp ?? all.growth_amp);
      if (growth != null && growth >= HOUR_RATIO_PEAK) {
        return `${biggerThanUsual(growth)} ${escapeHtml(formatBpsMsg(amp.bps))} ответов усилителей, обычно ~${escapeHtml(formatBpsMsg(amp.bps / growth))}`;
      }
      const share = amp.share != null ? ` — ${formatSharePct(amp.share)} UDP клиента` : '';
      return `Ответы усилителей: <b>${escapeHtml(formatBpsMsg(amp.bps))}</b>${escapeHtml(share)}`;
    }
  }
  if (mode === 'geo') {
    const geo = evaluateForeignGeo(all);
    if (geo.share != null) {
      const now = `${formatSharePct(geo.share)} трафика${geo.bps > 0 ? ` (${formatBpsMsg(geo.bps)})` : ''}`;
      if (geo.shareGrowth != null && geo.shareNorm != null && geo.shareGrowth >= HOUR_RATIO_PEAK) {
        return `<b>Доля из-за рубежа в ${escapeHtml(formatTimes(geo.shareGrowth))} больше обычного:</b> ${escapeHtml(now)}, обычно ${escapeHtml(formatSharePct(geo.shareNorm))}`;
      }
      return `Из-за рубежа: <b>${escapeHtml(now)}</b>`;
    }
  }
  return formatVolumeSize(all, verdict);
}

function formatVictimTarget(investigate, { proto, of }) {
  const victim = investigate?.victim;
  if (!isUsableVictim(victim)) return [];
  const port = victimDisplayPort(victim, investigate);
  const shape = victimShapeFor(victim, investigate);
  const bits = [];
  if (victim.share != null) bits.push(`${formatSharePct(victim.share)} трафика ${of}`);
  if (shape && Number(shape.dstPorts) > 1) bits.push(`на ${ruPorts(shape.dstPorts)}`);
  return [
    `Цель: <b>${escapeHtml(formatHostPort(victim.ip, port))}</b>${proto ? ` (${escapeHtml(proto)})` : ''}`
      + (bits.length ? ` — ${escapeHtml(bits.join(' · '))}` : ''),
  ];
}

function formatSynTarget(syn, investigate, verdict, byProto) {
  const lines = [];
  const top = syn.dest[0];
  if (top && Number(top.share) >= 0.5) {
    lines.push(`Цель: <b>${escapeHtml(formatHostPort(top.ip, top.port))}</b> — ${escapeHtml(formatSharePct(top.share))} атаки`);
  } else if (top) {
    const many = syn.dstIps > 1 ? `${ruAddresses(syn.dstIps)}, ` : '';
    lines.push(escapeHtml(`Цели: ${many}больше всего ${formatHostPort(top.ip, top.port)} — ${formatSharePct(top.share)}`));
  } else if (isUsableVictim(investigate?.victim)) {
    lines.push(`Цель: <b>${escapeHtml(investigate.victim.ip)}</b>`);
  } else {
    lines.push('Цель: сеть клиента');
  }
  const src = [];
  if (syn.srcIps > 0) src.push(ruAddresses(syn.srcIps));
  if (syn.srcNets > 1) src.push(ruNets24(syn.srcNets));
  if (syn.srcAsns > 1) src.push(`${formatNumMsg(syn.srcAsns, 0)} AS`);
  if (src.length) lines.push(escapeHtml(`Источники: ${src.join(' · ')}`));
  const answer = finiteGrowth(byProto?.tcp?.answer_pct ?? byProto?.all?.answer_pct ?? verdict?.answerPct);
  if (answer != null) {
    const pct = answer > 0 && answer < 1 ? answer.toFixed(1).replace('.', ',') : answer.toFixed(0);
    lines.push(escapeHtml(`Сервер ответил на ${pct}% запросов`));
  }
  return lines;
}

function ampSourcePortRows(investigate) {
  const rows = ampSrcPortRows(investigate);
  if (rows.length) return rows.slice(0, 5);
  return amplifierPortsFromL4(investigate?.l4src).slice(0, 5).map((port) => ({ port }));
}

function formatAmpTarget(investigate, byProto) {
  const lines = [];
  const amp = ampMetrics(byProto?.udp || {});
  const ips = (Array.isArray(investigate?.ampDestIp) ? investigate.ampDestIp : [])
    .filter((row) => row?.ip)
    .slice(0, 5);
  const nets = (Array.isArray(investigate?.ampDest24) ? investigate.ampDest24 : [])
    .filter((row) => row?.net24 && Number(row.share) >= SOURCE_NET_MIN_SHARE);
  const destPorts = (Array.isArray(investigate?.ampDestPort?.top) ? investigate.ampDestPort.top : [])
    .filter((row) => Number(row?.port) > 0)
    .slice(0, 5);
  const srcIps = (Array.isArray(investigate?.ampSrcIp) ? investigate.ampSrcIp : [])
    .filter((row) => row?.ip)
    .slice(0, 5);
  const srcPorts = ampSourcePortRows(investigate);

  if (nets.length || ips.length) {
    const where = nets.slice(0, 3).map((row) => {
      const share = Number(row.share);
      const pct = share > 0 && share < 0.995 ? ` ${formatFineShare(share)}` : '';
      return `${row.net24}${pct}`;
    });
    const destCount = nets.reduce((sum, row) => sum + (Number(row.ips) || 0), 0);
    const head = [
      destCount > 0 ? ruAddresses(destCount) : '',
      where.length ? `в ${where.join(' · ')}` : '',
    ].filter(Boolean).join(' ');
    lines.push(escapeHtml(`Куда: ${head || 'сеть клиента'}`));
    for (const row of ips) lines.push(escapeHtml(`   ${row.ip} — ${formatFineShare(row.share)}`));
  }

  const destPortCount = Number(investigate?.ampDestPort?.count) || destPorts.length;
  if (destPortCount > 0) {
    lines.push(escapeHtml(`Порты назначения: ${destPortCount}`));
    for (const row of destPorts) lines.push(escapeHtml(`   ${row.port} — ${formatFineShare(row.share)}`));
  }

  const srcBits = [];
  if (amp.srcs > 0) srcBits.push(ruCount(amp.srcs, ['отражатель', 'отражателя', 'отражателей']));
  if (amp.avgPkt > 0) srcBits.push(`ответы по ~${formatNumMsg(amp.avgPkt, 0)} Б`);
  if (srcBits.length || srcIps.length || srcPorts.length) {
    lines.push(escapeHtml(`Откуда: ${srcBits.join(' · ') || 'отражатели'}`));
    for (const row of srcIps) {
      const port = Number(row.port) > 0 ? ` · порт ${row.port}` : '';
      lines.push(escapeHtml(`   ${row.ip} — ${formatFineShare(row.share)}${port}`));
    }
    for (const row of srcPorts) {
      const share = formatFineShare(row.share);
      lines.push(escapeHtml(`   порт ${row.port}${share ? ` — ${share}` : ''}`));
    }
  }
  return lines;
}

function formatPeakReason(investigate, verdict, byProto) {
  if (isLegitimatePeak(verdict)) {
    const src = topSource(investigate);
    const service = formatServiceOn(investigate);
    const bits = [];
    if (src) {
      const asn = formatAsnLabel(src.asn, src.asnName || src.asName).trim();
      bits.push(`с ${src.net24}${asn ? ` (${asn})` : ''}`);
    }
    if (service) bits.push(service);
    if (src?.share != null) bits.push(`${formatSharePct(src.share)} трафика`);
    return [escapeHtml(`Почему не атака: похоже на загрузку${bits.length ? ` — ${bits.join(' · ')}` : ''}`)];
  }
  const lines = [];
  if (verdict?.reason) lines.push(escapeHtml(`Почему не атака: ${verdict.reason}`));
  lines.push(...formatVictimTarget(investigate, { proto: protoLabel(investigate?.victim, byProto?.tcp, byProto?.udp, byProto?.all), of: 'клиента' }));
  return lines;
}

function formatNetExtra(byProto, verdict, scope) {
  const all = byProto?.all || {};
  const lines = [];
  const net = netSpikeMetrics(all);
  const more = net.list.filter((item) => item.net !== net.net);
  if (more.length) {
    lines.push(escapeHtml(`Ещё сети: ${more
      .map((item) => `${item.net} — ${formatBpsMsg(item.bps)} ${formatNetGrowth(item.growth)}`.trim())
      .join('; ')}`));
  }
  const bps = Number(all.bps) || 0;
  const ratio = volumeRatio(all, verdict);
  if (bps > 0 && ratio != null) {
    const note = ratio < HOUR_RATIO_PEAK
      ? 'на общем объёме удар почти не заметен'
      : `в ${formatTimes(ratio)} больше обычного`;
    const who = scope === 'provider' ? 'Весь провайдер' : 'Весь клиент';
    lines.push(escapeHtml(`${who}: ${formatBpsMsg(bps)} — ${note}`));
  }
  return lines;
}

function formatCutLine({ byProto, investigate, binding, scope, scopeId, mode, verdict }) {
  if (mode === 'amp' || mode === 'syn' || mode === 'geo') return '';
  if (scope !== 'provider' && mode !== 'carpet') return '';
  if (mode === 'peak' && isLegitimatePeak(verdict)) return '';
  const all = byProto?.all || {};
  const udp = byProto?.udp || {};
  const bps = Number(all.bps) || 0;
  const udpShare = bps > 0 ? Number(udp.bps || 0) / bps : 0;
  if (udpShare < 0.6) return '';
  const pkt = Math.round(Number(all.avg_packet_bytes ?? all.avgPacketBytes) || 0);
  const portCount = Number(investigate?.destPort?.count) || 0;
  const topPort = investigate?.destPort?.top?.[0];
  const topShare = Number(topPort?.share) || 0;
  const scattered = portCount > 8 || (portCount > 1 && topShare < 0.2);
  const prefixes = (Array.isArray(binding?.prefixes) ? binding.prefixes : [])
    .map((prefix) => String(prefix || '').trim())
    .filter(Boolean)
    .slice(0, 6);
  let where = 'на сеть клиента';
  if (prefixes.length) where = `на ${prefixes.join(', ')}`;
  else if (scope === 'provider') where = 'на сети провайдера';
  else if (scope === 'net' && scopeId) where = `на ${scopeId}`;
  const size = pkt > 0 ? `, пакет около ${pkt} Б` : '';
  let ports = '';
  if (scattered) ports = '. Порты случайные, по порту не резать';
  else if (topPort && Number(topPort.port) > 0 && topShare >= 0.5) ports = `, порт ${topPort.port}`;
  return `Резать: входящий UDP${size}, ${where}${ports}`;
}

function formatTargetLines(mode, ctx) {
  const { byProto, verdict, investigate, syn, scope } = ctx;
  if (investigate?.error && mode !== 'syn') {
    return [`Цель: не удалось разобрать (${escapeHtml(shortErrorMsg(investigate.error))})`];
  }
  const all = byProto?.all || {};
  const proto = protoLabel(investigate?.victim, byProto?.tcp || {}, byProto?.udp || {}, all);
  if (mode === 'syn') return formatSynTarget(syn, investigate, verdict, byProto);
  if (mode === 'amp') return formatAmpTarget(investigate, byProto);
  if (mode === 'peak') return formatPeakReason(investigate, verdict, byProto);
  const lines = [];
  if (mode === 'carpet') {
    const totals = investigate?.sources || {};
    const scale = [];
    if (Number(totals.dstIpCount) > 0) scale.push(ruAddresses(totals.dstIpCount));
    if (Number(totals.dstNetCount) > 1) scale.push(ruNets24(totals.dstNetCount));
    const of = scope === 'provider' ? 'сети провайдера' : 'сеть клиента';
    lines.push(escapeHtml(`Цель: ${of}, не один сервер${scale.length ? ` — ${scale.join(' · ')}` : ''}`));
    for (const row of (Array.isArray(investigate?.dest24) ? investigate.dest24 : []).filter((r) => r?.net24).slice(0, 3)) {
      lines.push(escapeHtml(`   ${row.net24} — ${formatSharePct(row.share)}`));
    }
  } else {
    lines.push(...formatVictimTarget(investigate, { proto, of: mode === 'net' ? 'сети' : 'клиента' }));
  }
  if (mode === 'geo') {
    const countries = formatTopCountries(evaluateForeignGeo(all).top);
    if (countries) lines.push(escapeHtml(`Страны: ${countries}`));
  }
  const victim = investigate?.victim;
  const shape = mode !== 'carpet' && isUsableVictim(victim) ? victimShapeFor(victim, investigate) : null;
  lines.push(...formatAttackSourceLines(investigate, shape));
  lines.push(...formatSourceOperatorLines(investigate));
  if (mode === 'net') lines.push(...formatNetExtra(byProto, verdict, scope));
  if (mode === 'volumetric' || mode === 'generic') lines.push(...formatFocusLines(investigate));
  const cut = formatCutLine({ ...ctx, mode });
  if (cut) lines.push(escapeHtml(cut));
  return lines;
}

function formatMetricsLines(mode, { byProto, verdict, investigate, binding, scope, signals, syn }) {
  const all = byProto?.all || {};
  const tcp = byProto?.tcp || {};
  const udp = byProto?.udp || {};
  const lines = ['Метрики минуты'];
  const bps = Number(all.bps) || 0;
  const pps = Number(all.pps) || 0;
  const usual = hourUsualOf(verdict);
  const growthPps = finiteGrowth(all.growth_pps ?? all.growthPps);
  const total = [
    `${formatBpsMsg(bps)}${usual > 0 ? ` (обычно ${formatBpsMsg(usual)})` : ''}`,
    pps > 0
      ? `${formatPpsMsg(pps)}${growthPps != null && growthPps >= HOUR_RATIO_PEAK ? ` (×${growthPps.toFixed(1).replace('.', ',')})` : ''}`
      : '',
  ].filter(Boolean);
  const trafficWho = scope === 'net' ? '' : scope === 'provider' ? ' провайдера' : ' клиента';
  lines.push(escapeHtml(`Весь трафик${trafficWho}: ${total.join(' · ')}`));
  const split = [];
  if (bps > 0 && Number(tcp.bps) > 0) split.push(`TCP ${formatSharePct(Number(tcp.bps) / bps)}`);
  if (bps > 0 && Number(udp.bps) > 0) split.push(`UDP ${formatSharePct(Number(udp.bps) / bps)}`);
  if (Number(all.avg_packet_bytes) > 0) split.push(`средний пакет ${formatNumMsg(all.avg_packet_bytes, 0)} Б`);
  if (split.length) lines.push(escapeHtml(split.join(' · ')));
  const shape = [];
  const entropy = finiteGrowth(all.port_entropy ?? all.portEntropy);
  if (entropy != null) shape.push(`Энтропия портов ${entropy.toFixed(2).replace('.', ',')} бит`);
  const cv = finiteGrowth(all.cv_percent ?? all.cvPercent);
  if (cv != null && cv > 0) shape.push(`CV пакета ${cv.toFixed(0)}%`);
  if (shape.length) lines.push(escapeHtml(shape.join(' · ')));
  if (mode === 'syn' && syn.pps > 0) {
    const bits = [];
    if (syn.avgPkt > 0) bits.push(`пакет ${formatNumMsg(syn.avgPkt, 0)} Б`);
    const halfOpen = finiteGrowth(tcp.half_open_pct ?? all.half_open_pct);
    if (halfOpen != null) bits.push(`полуоткрытых ${halfOpen.toFixed(0)}%`);
    if (bits.length) lines.push(escapeHtml(`SYN: ${bits.join(' · ')}`));
  }
  const amp = ampMetrics(udp);
  if (mode !== 'amp' && amp.bytes > 0 && signals.includes(SIGNALS.amplification)) {
    lines.push(escapeHtml(`С портов усилителей: ${formatBpsMsg(amp.bps)}${amp.share != null ? ` · ${formatSharePct(amp.share)} UDP` : ''}`));
  }
  if (mode !== 'geo' && signals.includes(SIGNALS.foreign_geo)) {
    const geo = evaluateForeignGeo(all);
    if (geo.share != null) {
      const countries = formatTopCountries(geo.top);
      lines.push(escapeHtml(`Из-за рубежа: ${formatSharePct(geo.share)}${countries ? ` · ${countries}` : ''}`));
    }
  }
  const switchIn = formatSwitchPort(investigate?.switchIn);
  const switchOut = formatSwitchPort(investigate?.switchOut);
  const sw = [
    switchIn !== '—' ? `Вход: ${switchIn}` : '',
    switchOut !== '—' ? `выход: ${switchOut}` : '',
  ].filter(Boolean);
  if (sw.length) lines.push(escapeHtml(sw.join(' · ')));
  // Префикс сети уже стоит в шапке, поэтому разметка нужна только абонентам.
  const markup = scope === 'client' || scope === 'provider' ? formatClientMarkup(binding) : '';
  if (markup) {
    const label = scope === 'provider'
      ? 'Сети'
      : `${binding?.bindMode === 'ports' ? 'Порт' : 'IP'} клиента`;
    lines.push(escapeHtml(`${label}: ${markup}`));
  }
  return lines;
}

function formatAlertMessage({
  name,
  scope,
  scopeId,
  minute,
  startMinute = null,
  byProto,
  verdict,
  investigate,
  binding,
  signals,
  repeat = null,
}) {
  const signalList = Array.isArray(signals) && signals.length ? signals : [SIGNALS.volume];
  const attack = isAlertAttack(verdict, signalList);
  const mode = alertMode(verdict, signalList, attack);
  const ctx = {
    byProto,
    verdict,
    investigate,
    binding,
    scope,
    scopeId,
    signals: signalList,
    syn: synDetail(byProto, investigate),
  };
  const title = alertTitle(mode, {
    byProto,
    investigate,
    verdict: { ...verdict, ampSrcPort: investigate?.ampSrcPort },
  });
  const blocks = [
    [
      `${attack ? '🔴' : '🟡'} <b>${escapeHtml(title)}</b> · ${formatAlertWho(scope, scopeId, name)}`,
      `Начало: <b>${escapeHtml(formatAlertTime(startMinute || minute))}</b>`,
      repeat ? formatRepeatHtml(repeat, scope, minute) : '',
      formatSizeLine(mode, ctx),
    ],
    formatTargetLines(mode, ctx),
    formatMetricsLines(mode, ctx),
  ];
  return blocks
    .map((block) => block.filter(Boolean).join('\n'))
    .filter(Boolean)
    .join('\n\n');
}

function formatDuration(minutes) {
  const m = Math.max(1, Math.round(minutes));
  if (m < 60) return `${m} мин`;
  const h = Math.floor(m / 60);
  const rest = m % 60;
  return rest ? `${h} ч ${rest} мин` : `${h} ч`;
}

function attackTargetText(mode, byProto, investigate) {
  if (mode === 'syn') {
    const top = synDetail(byProto, investigate).dest[0];
    if (top && Number(top.share) >= 0.5) return formatHostPort(top.ip, top.port);
  }
  if (mode === 'amp') {
    const ip = (Array.isArray(investigate?.ampDestIp) ? investigate.ampDestIp : [])[0];
    if (ip?.ip && Number(ip.share) >= 0.5) return ip.ip;
  }
  if (mode === 'net') {
    const net = netSpikeMetrics(byProto?.all || {});
    if (net.net) return net.net;
  }
  const victim = investigate?.victim;
  if (mode !== 'carpet' && isUsableVictim(victim)) {
    return formatHostPort(victim.ip, victimDisplayPort(victim, investigate));
  }
  return '';
}

// «В начале» и «сейчас» меряем одним и тем же: у SYN-флуда после атаки байты
// клиента не падают, падает голый SYN — его и показываем, даже нулём.
function headlineRate(mode, byProto, investigate) {
  if (mode === 'syn') return formatSynRate(synDetail(byProto, investigate).pps);
  if (mode === 'amp') return `${formatBpsMsg(ampMetrics(byProto?.udp || {}).bps)} ответов усилителей`;
  const bps = Number(byProto?.all?.bps);
  return bps > 0 ? formatBpsMsg(bps) : '';
}

// Нормализация приходит после streak спокойных минут: конец атаки — первая из них.
function formatRateNow(rate) {
  if (!rate) return '';
  if (rate.unit === 'pps') return rate.pps > 0 ? formatPpsMsg(rate.pps) : '';
  const bits = [];
  if (rate.bps > 0) bits.push(formatBpsMsg(rate.bps));
  if (rate.unit !== 'amp' && rate.pps > 0) bits.push(formatPpsMsg(rate.pps));
  return bits.join(', ');
}

function formatVectorChangeMessage({
  name,
  scope,
  scopeId,
  byProto,
  verdict,
  investigate,
  binding,
  signals,
  rate,
  previous,
}) {
  const signalList = Array.isArray(signals) && signals.length ? signals : [SIGNALS.volume];
  const mode = alertMode(verdict, signalList, true);
  const current = vectorSnapshot({ byProto, investigate, verdict });
  const label = vectorLabel(current);
  const diff = vectorDiffLines(previous, current);
  const now = formatRateNow(rate);
  const cut = formatCutLine({ byProto, investigate, binding, scope, scopeId, mode, verdict });
  // Источники считаются по байтам всего среза: для SYN и отражения это чужой
  // живой трафик клиента, а не атакующие.
  const sources = mode === 'syn' || mode === 'amp'
    ? []
    : [...formatSourceOperatorLines(investigate), ...formatAttackSourceLines(investigate)];
  return [
    `🟠 <b>Вектор сменился</b> · ${formatAlertWho(scope, scopeId, name)}`,
    label ? escapeHtml(label) : '',
    ...diff.map((line) => escapeHtml(line)),
    now ? escapeHtml(`Сейчас ${now}`) : '',
    cut ? escapeHtml(cut) : '',
    ...sources,
  ].filter(Boolean).join('\n');
}

function formatPeakGrewMessage({ name, scope, scopeId, rate }) {
  const now = formatRateNow(rate);
  return [
    `🟠 <b>Атака растёт</b> · ${formatAlertWho(scope, scopeId, name)}`,
    escapeHtml(`Растёт: ${now || '—'}`),
  ].join('\n');
}

function formatNormalizeMessage({
  name,
  scope,
  scopeId,
  minute,
  alertMinute,
  startMinute = null,
  streak = DEFAULT_NORMALIZE_STREAK,
  byProto,
  alertByProto = null,
  verdict = null,
  investigate = null,
  signals = null,
  track = null,
}) {
  const signalList = Array.isArray(signals) && signals.length ? signals : [SIGNALS.volume];
  const from = startMinute || alertMinute;
  const fromTs = parseUtc(from);
  const nowTs = parseUtc(minute);
  const quiet = normalizeStreak(streak, DEFAULT_NORMALIZE_STREAK);
  const endTs = Number.isFinite(fromTs) && Number.isFinite(nowTs)
    ? Math.max(fromTs + MINUTE, nowTs - (quiet - 1) * MINUTE)
    : NaN;
  const lines = [`🟢 <b>Атака закончилась</b> · ${formatAlertWho(scope, scopeId, name)}`];
  const opened = alertByProto?.all ? alertByProto : null;
  if (verdict || opened) {
    const mode = alertMode(verdict, signalList, true);
    const title = alertTitle(mode, {
      byProto: opened || byProto,
      investigate,
      verdict: { ...verdict, ampSrcPort: investigate?.ampSrcPort },
    });
    const target = attackTargetText(mode, opened || byProto, investigate);
    lines.push(escapeHtml(`${title}${target ? ` на ${target}` : ''}`));
    if (Number.isFinite(endTs)) {
      lines.push(`Длилась <b>${escapeHtml(formatDuration((endTs - fromTs) / MINUTE))}</b>: `
        + `${escapeHtml(formatClockMsk(from))}–${escapeHtml(formatClockMsk(endTs))} МСК`);
    }
    const before = opened ? headlineRate(mode, opened, investigate) : '';
    const now = headlineRate(mode, byProto, null);
    const rates = [before ? `в начале ${before}` : '', now ? `сейчас ${now}` : ''].filter(Boolean).join(' · ');
    if (rates) lines.push(escapeHtml(`${rates.charAt(0).toUpperCase()}${rates.slice(1)}`));
    const peakBits = [];
    if (Number(track?.peak?.bps) > 0) peakBits.push(formatBpsMsg(track.peak.bps));
    if (Number(track?.peak?.pps) > 0) peakBits.push(formatPpsMsg(track.peak.pps));
    if (peakBits.length) {
      const when = track.peak.minute ? ` в ${formatClockMsk(track.peak.minute)} МСК` : '';
      lines.push(escapeHtml(`Пик: ${peakBits.join(', ')}${when}`));
    }
    const vectors = (Array.isArray(track?.vectors) ? track.vectors : []).filter(Boolean);
    if (vectors.length) lines.push(escapeHtml(`Векторы: ${vectors.join(' → ')}`));
  } else {
    if (Number.isFinite(endTs)) {
      lines.push(`Началась ${escapeHtml(formatAlertTime(from))}, закончилась ${escapeHtml(formatClockMsk(endTs))} МСК`);
    }
    const bps = Number(byProto?.all?.bps);
    if (bps > 0) lines.push(escapeHtml(`Сейчас ${formatBpsMsg(bps)}`));
  }
  return lines.filter(Boolean).join('\n');
}

// Начало атаки — первая горячая минута цепочки. Для объёма пауза внутри окна
// цепочку не рвёт: импульс 1 через 1 иначе сбрасывал бы начало на последний всплеск.
function alertStartMinute(history, hot, windowMinutes) {
  const allow = Math.max(1, Number(windowMinutes) || 1);
  let start = null;
  let prevHotTs = null;
  for (const item of history) {
    const ts = parseUtc(item?.minute);
    if (!Number.isFinite(ts)) break;
    if (!hot(item)) {
      if (allow <= 1) break;
      continue;
    }
    if (prevHotTs != null && prevHotTs - ts > allow * MINUTE) break;
    start = item.minute;
    prevHotTs = ts;
  }
  return start;
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
    for (const signal of SIGNAL_ORDER) {
      const cfg = signalSettings(settings, signal);
      if (!cfg.enabled) continue;
      if (signal === SIGNALS.foreign_geo && String(row.scope) !== 'client') continue;
      const signalKey = objectSignalKey(row.scope, row.scope_id, signal);
      if (activeKeys.has(signalKey) || (signal === SIGNALS.volume && activeKeys.has(objectId))) continue;
      const history = [row, ...prev];
      const hot = (item) => isSignalHot(signal, item, group, t, settings);
      // SYN: дубли режет activeKeys, а не «минута до тоже горячая». Иначе флуд,
      // который шёл до выкладки, навсегда остаётся без события — rising edge
      // уже потерян, активной записи нет.
      const volumeWindow = signal === SIGNALS.volume && cfg.window > cfg.streak ? cfg.window : 1;
      let ready;
      if (signal === SIGNALS.volume) {
        ready = shouldSendAlert(history, t, options.streak ?? cfg.streak, enabledAtMs, cfg.window);
      } else if (signal === SIGNALS.syn_flood) {
        ready = hot(row);
      } else if (signal === SIGNALS.net_spike) {
        ready = shouldSendNetSpike(history, hot, cfg.streak, enabledAtMs);
      } else {
        ready = shouldSendSignal(history, hot, cfg.streak, enabledAtMs);
      }
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
        window: signal === SIGNALS.volume ? cfg.window : null,
        startMinute: alertStartMinute(history, hot, volumeWindow) || row.minute,
      });
    }
  }
  return out;
}

// Чужая география — признак той же аномалии, что всплеск или атака. Отдельное
// событие на неё дало бы вторую запись и вторую телеграмму о нормализации, поэтому
// его не заводим, если по объекту другое событие открывается сейчас или уже открыто.
// Рост объёма и удар в одну /24 — одна объёмная атака на объект: второе
// событие по ней дежурному не нужно (71747, 04.10 09:50 и 09:54 МСК).
function volumetricTwinActive(scope, scopeId, signal, activeByKey) {
  if (signal === SIGNALS.volume) {
    return activeByKey.has(objectSignalKey(scope, scopeId, SIGNALS.net_spike));
  }
  if (signal === SIGNALS.net_spike) {
    return activeByKey.has(objectSignalKey(scope, scopeId, SIGNALS.volume))
      || activeByKey.has(objectKey(scope, scopeId));
  }
  return false;
}

function dropDuplicateGeo(candidates, activeByKey = new Map()) {
  const hasOther = candidates.some((c) => (c.signal || SIGNALS.volume) !== SIGNALS.foreign_geo);
  const hasNetSpike = candidates.some((c) => c.signal === SIGNALS.net_spike);
  return candidates.filter((c) => {
    const signal = c.signal || SIGNALS.volume;
    if (signal === SIGNALS.volume || signal === SIGNALS.net_spike) {
      if (signal === SIGNALS.volume && hasNetSpike) return false;
      return !volumetricTwinActive(c.row?.scope, c.row?.scope_id, signal, activeByKey);
    }
    if (c.signal !== SIGNALS.foreign_geo) return true;
    if (hasOther) return false;
    const { scope, scope_id: scopeId } = c.row;
    return !SIGNAL_ORDER.some((signal) => signal !== SIGNALS.foreign_geo
      && (activeByKey.has(objectSignalKey(scope, scopeId, signal))
        || (signal === SIGNALS.volume && activeByKey.has(objectKey(scope, scopeId)))));
  });
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
    for (const signal of SIGNAL_ORDER) {
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
      const quiet = (item) => {
        if (activeSignal === SIGNALS.amplification) {
          const udp = ampRowFor(item, group);
          if (!udp) return true;
          const amp = ampOptions(settings);
          return !isAmplificationHit(udp, amp) && !ampStillGoing(udp, amp);
        }
        if (activeSignal === SIGNALS.syn_flood) {
          return !isSynHot(item, settings) && !synFloodStillGoing(item, synOptions(settings));
        }
        return !isSignalHot(activeSignal, item, group, t, settings);
      };
      let ready;
      if (activeSignal === SIGNALS.volume) {
        ready = shouldSendNormalize(history, t, cfg.normalizeStreak, {
          alertBps: active.alertByProto?.all?.bps ?? active.alertBps,
          hourP95: active.verdict?.hourP95,
        });
      } else if (activeSignal === SIGNALS.syn_flood || activeSignal === SIGNALS.net_spike) {
        ready = shouldNormalizeQuiet(history, quiet, cfg.normalizeStreak);
      } else {
        ready = shouldSendSignal(history, quiet, cfg.normalizeStreak);
      }
      if (!ready) continue;
      out.push({ row, key: objectId, signalKey, signal: activeSignal, active });
    }
  }
  return out;
}

// Объект ниже MIN_BPS не пишется в минутную таблицу, и pickNormalizeCandidates
// его не видит: на зеркале 73 события 08.09 висели три недели у тихих абонентов.
// Отсутствие строки в обработанном тике — тихая минута. Счёт в памяти, а не по
// дырам в таблице: простой воркера тишиной не считается.
const silentTicksByEvent = new Map();
const SILENT_TELEGRAM_MAX_AGE_MS = 24 * 60 * MINUTE;

function pickSilentNormalizeCandidates(activeByKey, presentKeys, minute, options = {}) {
  const settings = options.settings || {};
  const ticks = options.ticks instanceof Map ? options.ticks : silentTicksByEvent;
  const skipIds = options.skipIds instanceof Set ? options.skipIds : new Set();
  const seen = new Set();
  const out = [];
  for (const active of activeByKey.values()) {
    const id = active?.id;
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const objectId = objectKey(active.scope, active.scopeId);
    if (presentKeys.has(objectId)) {
      ticks.delete(id);
      continue;
    }
    const count = (ticks.get(id) || 0) + 1;
    ticks.set(id, count);
    if (skipIds.has(id)) continue;
    const cfg = signalSettings(settings, active.signal || SIGNALS.volume);
    if (count < cfg.normalizeStreak) continue;
    ticks.delete(id);
    const alertTs = parseUtc(active.alertMinute);
    const nowTs = parseUtc(minute);
    out.push({
      row: {
        scope: active.scope, scope_id: active.scopeId, proto: 'all', minute,
        bps: 0, pps: 0, bytes: 0, packets: 0, growth_bps: 0, growth_pps: 0,
      },
      key: objectId,
      signalKey: objectSignalKey(active.scope, active.scopeId, active.signal || SIGNALS.volume),
      signal: active.signal || SIGNALS.volume,
      active,
      silent: true,
      telegram: Number.isFinite(alertTs) && Number.isFinite(nowTs)
        && nowTs - alertTs <= SILENT_TELEGRAM_MAX_AGE_MS,
    });
  }
  for (const id of ticks.keys()) {
    if (!seen.has(id)) ticks.delete(id);
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
          ADD COLUMN IF NOT EXISTS geo_normalize_streak UInt16 DEFAULT ${DEFAULT_NORMALIZE_STREAK},
          ADD COLUMN IF NOT EXISTS volume_min_share_pct Float64 DEFAULT ${DEFAULT_MIN_CLIENT_SHARE_PCT},
          ADD COLUMN IF NOT EXISTS amp_min_share_pct Float64 DEFAULT ${DEFAULT_MIN_CLIENT_SHARE_PCT},
          ADD COLUMN IF NOT EXISTS geo_min_share_pct Float64 DEFAULT ${DEFAULT_MIN_CLIENT_SHARE_PCT},
          ADD COLUMN IF NOT EXISTS syn_min_share_pct Float64 DEFAULT ${DEFAULT_MIN_CLIENT_SHARE_PCT},
          ADD COLUMN IF NOT EXISTS amp_hour_ratio Float64 DEFAULT ${DEFAULT_AMP_HOUR_RATIO},
          ADD COLUMN IF NOT EXISTS amp_min_mbit Float64 DEFAULT ${DEFAULT_AMP_MIN_MBIT},
          ADD COLUMN IF NOT EXISTS syn_enabled UInt8 DEFAULT 1,
          ADD COLUMN IF NOT EXISTS syn_hour_ratio Float64 DEFAULT ${DEFAULT_SYN_HOUR_RATIO},
          ADD COLUMN IF NOT EXISTS syn_min_kpps Float64 DEFAULT ${DEFAULT_SYN_MIN_KPPS},
          ADD COLUMN IF NOT EXISTS syn_pkt_max Float64 DEFAULT ${DEFAULT_SYN_PKT_MAX},
          ADD COLUMN IF NOT EXISTS volume_hot_window UInt16 DEFAULT ${DEFAULT_VOLUME_WINDOW},
          ADD COLUMN IF NOT EXISTS volume_quiet_streak UInt16 DEFAULT ${DEFAULT_VOLUME_QUIET},
          ADD COLUMN IF NOT EXISTS vector_notify UInt8 DEFAULT 1
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
          volume_min_share_pct Float64,
          amp_min_share_pct Float64,
          geo_min_share_pct Float64,
          syn_min_share_pct Float64,
          amp_hour_ratio Float64,
          amp_min_mbit Float64,
          syn_enabled UInt8,
          syn_hour_ratio Float64,
          syn_min_kpps Float64,
          syn_pkt_max Float64,
          volume_hot_window UInt16,
          volume_quiet_streak UInt16,
          vector_notify UInt8,
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
          volume_min_share_pct,
          amp_min_share_pct,
          geo_min_share_pct,
          syn_min_share_pct,
          amp_hour_ratio,
          amp_min_mbit,
          syn_enabled,
          syn_hour_ratio,
          syn_min_kpps,
          syn_pkt_max,
          volume_hot_window,
          volume_quiet_streak,
          vector_notify,
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
            argMax(volume_min_share_pct, updated_at) AS volume_min_share_pct,
            argMax(amp_min_share_pct, updated_at) AS amp_min_share_pct,
            argMax(geo_min_share_pct, updated_at) AS geo_min_share_pct,
            argMax(syn_min_share_pct, updated_at) AS syn_min_share_pct,
            argMax(amp_hour_ratio, updated_at) AS amp_hour_ratio,
            argMax(amp_min_mbit, updated_at) AS amp_min_mbit,
            argMax(syn_enabled, updated_at) AS syn_enabled,
            argMax(syn_hour_ratio, updated_at) AS syn_hour_ratio,
            argMax(syn_min_kpps, updated_at) AS syn_min_kpps,
            argMax(syn_pkt_max, updated_at) AS syn_pkt_max,
            argMax(volume_hot_window, updated_at) AS volume_hot_window,
            argMax(volume_quiet_streak, updated_at) AS volume_quiet_streak,
            argMax(vector_notify, updated_at) AS vector_notify,
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
           amp_enabled, geo_enabled, amp_streak, geo_streak, amp_normalize_streak, geo_normalize_streak,
           volume_min_share_pct, amp_min_share_pct, geo_min_share_pct, syn_min_share_pct,
           amp_hour_ratio, amp_min_mbit,
           syn_enabled, syn_hour_ratio, syn_min_kpps, syn_pkt_max,
           volume_hot_window, volume_quiet_streak, vector_notify, updated_at
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
  const volumeMinSharePct = parseMinSharePct(
    payload.volumeMinSharePct ?? payload.volume_min_share_pct,
    'Рост объёма, мин. доля',
  ) ?? normalizeMinSharePct(base.volume_min_share_pct);
  const ampMinSharePct = parseMinSharePct(
    payload.ampMinSharePct ?? payload.amp_min_share_pct,
    'Амплификация, мин. доля',
  ) ?? normalizeMinSharePct(base.amp_min_share_pct);
  const geoMinSharePct = parseMinSharePct(
    payload.geoMinSharePct ?? payload.geo_min_share_pct,
    'Заграница, мин. доля',
  ) ?? normalizeMinSharePct(base.geo_min_share_pct);
  const synMinSharePct = parseMinSharePct(
    payload.synMinSharePct ?? payload.syn_min_share_pct,
    'SYN-флуд, мин. доля',
  ) ?? normalizeMinSharePct(base.syn_min_share_pct);
  const ampHourRatio = normalizeAmpHourRatio(
    payload.ampHourRatio ?? payload.amp_hour_ratio ?? base.amp_hour_ratio,
  );
  const ampMinMbit = normalizeAmpMinMbit(
    payload.ampMinMbit ?? payload.amp_min_mbit ?? base.amp_min_mbit,
  );
  const synEnabled = boolInt(payload.synEnabled ?? payload.syn_enabled, Number(base.syn_enabled ?? 1) === 1 ? 1 : 0);
  const synHourRatio = normalizeSynHourRatio(
    payload.synHourRatio ?? payload.syn_hour_ratio ?? base.syn_hour_ratio,
  );
  const synMinKpps = normalizeSynMinKpps(
    payload.synMinKpps ?? payload.syn_min_kpps ?? base.syn_min_kpps,
  );
  const synPktMax = normalizeSynPktMax(
    payload.synPktMax ?? payload.syn_pkt_max ?? base.syn_pkt_max,
  );
  const volumeWindowRaw = Number(payload.volumeWindow ?? payload.volume_hot_window ?? base.volume_hot_window ?? DEFAULT_VOLUME_WINDOW);
  if (!Number.isFinite(volumeWindowRaw) || volumeWindowRaw < 1 || volumeWindowRaw > MAX_STREAK) {
    throw apiError(`Окно объёма: целое от 1 до ${MAX_STREAK}`);
  }
  const volumeWindow = Math.max(streak, normalizeStreak(volumeWindowRaw, DEFAULT_VOLUME_WINDOW));
  const volumeQuietRaw = Number(payload.volumeQuiet ?? payload.volume_quiet_streak ?? base.volume_quiet_streak ?? DEFAULT_VOLUME_QUIET);
  if (!Number.isFinite(volumeQuietRaw) || volumeQuietRaw < 1 || volumeQuietRaw > MAX_STREAK) {
    throw apiError(`Тихих минут для закрытия объёма: целое от 1 до ${MAX_STREAK}`);
  }
  const volumeQuiet = normalizeStreak(volumeQuietRaw, DEFAULT_VOLUME_QUIET);
  const vectorNotify = boolInt(
    payload.vectorNotify ?? payload.vector_notify,
    Number(base.vector_notify ?? 1) === 1 ? 1 : 0,
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
    volume_min_share_pct: volumeMinSharePct,
    amp_min_share_pct: ampMinSharePct,
    geo_min_share_pct: geoMinSharePct,
    syn_min_share_pct: synMinSharePct,
    amp_hour_ratio: ampHourRatio,
    amp_min_mbit: ampMinMbit,
    syn_enabled: synEnabled,
    syn_hour_ratio: synHourRatio,
    syn_min_kpps: synMinKpps,
    syn_pkt_max: synPktMax,
    volume_hot_window: volumeWindow,
    volume_quiet_streak: volumeQuiet,
    vector_notify: vectorNotify,
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
      ampDestIp: [{ ip: '185.0.0.10', share: 0.998, bps: 2.74e9 }],
    },
  });
  return sendTelegramMessage(
    `Grapes NTA: тестовый алерт в новом формате.\n\n${text}`,
  );
}

function previousRowsLookbackMinutes(take) {
  return normalizeStreak(take) + 1 + PREV_ROWS_GAP_MINUTES;
}

function previousRowsScopeFilter(keys) {
  const byScope = new Map();
  for (const key of keys || []) {
    const scope = String(key.scope || '').trim();
    const scopeId = String(key.scopeId ?? key.scope_id ?? '').trim();
    if (!scope || !scopeId) continue;
    const ids = byScope.get(scope) || [];
    ids.push(scopeId);
    byScope.set(scope, ids);
  }
  const params = {};
  const parts = [];
  let i = 0;
  for (const [scope, ids] of byScope) {
    const scopeParam = `scope_${i}`;
    const idsParam = `ids_${i}`;
    parts.push(`(scope = {${scopeParam}:String} AND scope_id IN {${idsParam}:Array(String)})`);
    params[scopeParam] = scope;
    params[idsParam] = [...new Set(ids)];
    i += 1;
  }
  return {
    sql: parts.length ? `(${parts.join(' OR ')})` : '0',
    params,
  };
}

async function loadPreviousAllRows(minute, keys, limit = DEFAULT_STREAK) {
  if (!keys.length) return new Map();
  await ensureDetectionTables();
  const take = normalizeStreak(limit);
  const beforeTs = parseUtc(minute);
  if (!Number.isFinite(beforeTs)) return new Map();
  const fromTs = beforeTs - previousRowsLookbackMinutes(take) * MINUTE;
  const keySet = new Set(keys.map((k) => objectKey(k.scope, k.scopeId)));
  const scopeFilter = previousRowsScopeFilter(keys);
  if (scopeFilter.sql === '0') return new Map();
  const { rows } = await query(`
    SELECT scope, scope_id, proto, minute, growth_bps, growth_pps, bps, bytes,
           amp_bytes, amp_packets, amp_srcs, growth_amp,
           foreign_bytes, foreign_srcs, top_countries, growth_foreign_bps, growth_foreign_share,
           syn_only_bytes, syn_only_packets, syn_only_rows, syn_only_targets, answer_pct, growth_syn, sampling_rate,
           net_top, net_bps, net_pps, net_usual_bps, net_growth_bps, net_growth_pps
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
        syn_only_bytes,
        syn_only_packets,
        syn_only_rows,
        syn_only_targets,
        answer_pct,
        growth_syn,
        sampling_rate,
        net_top,
        net_bps,
        net_pps,
        net_usual_bps,
        net_growth_bps,
        net_growth_pps,
        row_number() OVER (PARTITION BY scope, scope_id, proto ORDER BY minute DESC) AS rn
      FROM ${tableRef()} FINAL
      WHERE proto IN ('all', 'udp')
        AND minute >= ${utcDateTime('from')}
        AND minute < ${utcDateTime('before')}
        AND ${scopeFilter.sql}
    )
    WHERE rn <= {take:UInt16}
    ORDER BY minute DESC
  `, {
    from: formatCh(fromTs),
    before: formatCh(beforeTs),
    take,
    ...scopeFilter.params,
  }, { name: 'detection/telegram-prev-rows' });

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

async function loadMinuteByProto(scope, scopeId, minute) {
  const minuteCh = formatCh(parseUtc(minute));
  if (!minuteCh) return null;
  const { rows } = await query(`
    SELECT *
    FROM ${tableRef()} FINAL
    WHERE scope = {scope:String}
      AND scope_id = {scopeId:String}
      AND minute = ${utcDateTime('m')}
  `, {
    scope: String(scope),
    scopeId: String(scopeId),
    m: minuteCh,
  }, { name: 'detection/minute-by-proto' });
  const byProto = {};
  for (const row of rows) byProto[String(row.proto)] = row;
  return byProto.all ? byProto : null;
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
    startMinute: alertSnapshot.startMinute || null,
    byProto: byProtoFromSnapshot(alertSnapshot),
    verdict: alertSnapshot.verdict,
    investigate: alertSnapshot.investigate,
    binding: alertSnapshot.binding,
    signals: [String(row.signal || SIGNALS.volume)],
  });
}

function storedOrFormattedNormalizeText(row, normalizeSnapshot, alertSnapshot = {}) {
  const stored = String(normalizeSnapshot.telegramText || '').trim();
  if (stored) return stored;
  if (!normalizeSnapshot?.all) return '';
  return formatNormalizeMessage({
    name: String(row.name || row.scope_id || ''),
    scope: String(row.scope || ''),
    scopeId: String(row.scope_id || ''),
    minute: row.normalize_minute,
    alertMinute: row.alert_minute,
    startMinute: alertSnapshot.startMinute || null,
    byProto: byProtoFromSnapshot(normalizeSnapshot),
    alertByProto: byProtoFromSnapshot(alertSnapshot),
    verdict: alertSnapshot.verdict || null,
    investigate: alertSnapshot.investigate || null,
    signals: [String(row.signal || SIGNALS.volume)],
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
    startMinute: alertSnapshot.startMinute || null,
    normalizeMinute: row.normalize_minute || null,
    threshold: Number(row.threshold) || DEFAULT_GROWTH_THRESHOLD,
    alertByProto: mapSnapshotToUi(alertSnapshot),
    normalizeByProto: mapSnapshotToUi(normalizeSnapshot),
    verdict: alertSnapshot.verdict || null,
    investigate: alertSnapshot.investigate || null,
    alertText: storedOrFormattedAlertText(row, alertSnapshot),
    normalizeText: storedOrFormattedNormalizeText(row, normalizeSnapshot, alertSnapshot),
    telegramSkip: String(alertSnapshot.telegramSkip || ''),
    track: alertSnapshot.track || null,
    binding: alertSnapshot.binding || null,
    focusMinute: alertSnapshot.focusMinute || '',
  };
}

function persistAlertSnapshot(metrics, extras = {}) {
  return {
    ...metrics,
    verdict: extras.verdict || null,
    investigate: extras.investigate || null,
    binding: extras.binding || null,
    telegramText: String(extras.telegramText || ''),
    telegramSkip: String(extras.telegramSkip || ''),
    focusMinute: String(extras.focusMinute || ''),
    startMinute: String(extras.startMinute || ''),
    track: Object.prototype.hasOwnProperty.call(extras, 'track') ? (extras.track || null) : (metrics?.track || null),
  };
}

function persistActiveAlertSnapshot(active) {
  return persistAlertSnapshot(uiByProtoToSnapshot(active?.alertByProto), {
    verdict: active?.verdict,
    investigate: active?.investigate,
    telegramText: active?.alertText,
    binding: active?.binding,
    telegramSkip: active?.telegramSkip,
    focusMinute: active?.focusMinute,
    startMinute: active?.startMinute,
    track: active?.track || null,
  });
}

function earliestStartMinute(candidates, minute) {
  let best = minute;
  for (const c of candidates) {
    if (c?.startMinute && parseUtc(c.startMinute) < parseUtc(best)) best = c.startMinute;
  }
  return formatCh(parseUtc(best));
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

const REPEAT_WINDOW_MS = 24 * 3600 * 1000;

// Атаки объекта за сутки до minute: одна запись на минуту открытия, сколько бы
// сигналов её ни открыли. Снимок разбираем здесь: JSON-функции на сервере падают
// по памяти на больших alert_json.
async function loadRecentAttacks({ scope, scopeId, minute }) {
  const to = formatCh(parseUtc(minute));
  const from = formatCh(parseUtc(minute) - REPEAT_WINDOW_MS);
  const { rows } = await query(`
    SELECT ev_minute, ev_status, ev_json
    FROM (
      SELECT
        event_id,
        argMax(status, updated_at) AS ev_status,
        argMax(alert_minute, updated_at) AS ev_minute,
        argMax(alert_json, updated_at) AS ev_json
      FROM ${eventsTableRef()}
      WHERE scope = {scope:String}
        AND scope_id = {scopeId:String}
        AND alert_minute >= ${utcDateTime('from')}
        AND alert_minute < ${utcDateTime('to')}
      GROUP BY event_id
    )
    WHERE ev_status IN ('active', 'normalized')
    ORDER BY ev_minute
  `, { scope: String(scope), scopeId: String(scopeId), from, to }, { name: 'detection/events-recent-attacks' });
  const byMinute = new Map();
  for (const r of rows) {
    const key = formatCh(parseUtc(r.ev_minute));
    let victimIp = '';
    try {
      victimIp = String(JSON.parse(r.ev_json || '{}')?.investigate?.victim?.ip || '');
    } catch {
      victimIp = '';
    }
    const prev = byMinute.get(key);
    if (!prev || (!prev.victimIp && victimIp)) byMinute.set(key, { minute: key, victimIp });
  }
  return [...byMinute.values()];
}

// Номер атаки за сутки: по тому же адресу, если он уже был целью, иначе по объекту.
function summarizeRepeat(prior, victimIp = '') {
  const list = Array.isArray(prior) ? prior.filter((p) => p?.minute) : [];
  if (!list.length) return null;
  const sameIp = victimIp ? list.filter((p) => p.victimIp === victimIp) : [];
  const pool = sameIp.length ? sameIp : list;
  return {
    nth: pool.length + 1,
    target: sameIp.length ? victimIp : '',
    lastMinute: pool[pool.length - 1].minute,
  };
}

function formatRepeatLine(repeat, scope, minute) {
  if (!repeat) return '';
  const target = repeat.target || (scope === 'net' ? 'эту сеть' : 'этого клиента');
  const last = new Date(parseUtc(repeat.lastMinute));
  const now = new Date(parseUtc(minute));
  const day = (d) => d.toLocaleDateString('ru-RU', { timeZone: 'Europe/Moscow' });
  const time = last.toLocaleTimeString('ru-RU', { timeZone: 'Europe/Moscow', hour: '2-digit', minute: '2-digit' });
  const when = day(last) === day(now)
    ? time
    : `${last.toLocaleDateString('ru-RU', { timeZone: 'Europe/Moscow', day: '2-digit', month: '2-digit' })} ${time}`;
  return `Повтор: ${repeat.nth}-я атака за сутки на ${target}, прошлая в ${when} МСК`;
}

function formatRepeatHtml(repeat, scope, minute) {
  const text = escapeHtml(formatRepeatLine(repeat, scope, minute));
  return text.replace(/^Повтор: (\d+-я атака за сутки)/, "Повтор: <b>$1</b>");
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
  const events = rows.map(mapEventRow);
  if (wanted === 'active') await attachLiveState(events);
  return events;
}

const LIVE_ONGOING_GAP_MINUTES = 3;
const LIVE_LOOKBACK_MS = 24 * 60 * MINUTE;

// Состояние открытого события по минутам детектора после срабатывания: в карточке
// без него видно только минуту алерта, и не понять, идёт атака или затихла
// (ШПД 04.10: импульсы по 55 Гбит/с раз в 2–3 минуты, события висели часами).
function liveEventState(rowsAsc, { alertMinute, threshold, signal, normalizeStreak: need, nowTs = Date.now() } = {}) {
  const alertTs = parseUtc(alertMinute);
  const rows = (rowsAsc || []).filter((r) => {
    const ts = parseUtc(r.minute);
    return Number.isFinite(ts) && (!Number.isFinite(alertTs) || ts >= alertTs);
  });
  if (!rows.length) return null;
  const t = Number(threshold) || DEFAULT_GROWTH_THRESHOLD;
  const hot = (r) => isAboveGrowthThreshold(r, t);
  let peak = null;
  let lastHot = null;
  let hotMinutes = 0;
  for (const r of rows) {
    if (!peak || Number(r.bps) > Number(peak.bps)) peak = r;
    if (hot(r)) {
      hotMinutes += 1;
      lastHot = r;
    }
  }
  let quietStreak = 0;
  for (let i = rows.length - 1; i >= 0 && !hot(rows[i]); i -= 1) quietStreak += 1;
  const last = rows[rows.length - 1];
  const lastTs = parseUtc(last.minute);
  const lastHotTs = lastHot ? parseUtc(lastHot.minute) : null;
  const sinceHotMin = lastHotTs != null ? Math.round((lastTs - lastHotTs) / MINUTE) : null;
  const volumeLike = !signal || signal === SIGNALS.volume || signal === SIGNALS.net_spike;
  let state = null;
  if (volumeLike) {
    state = sinceHotMin != null && sinceHotMin <= LIVE_ONGOING_GAP_MINUTES ? 'ongoing' : 'fading';
  }
  const nowSplit = trafficAboveBaseline(last.bps, last.growth_bps);
  const hotSplit = lastHot ? trafficAboveBaseline(lastHot.bps, lastHot.growth_bps) : { baselineBps: null, excessBps: null };
  return {
    state,
    lastMinute: last.minute,
    lastBps: Number(last.bps) || 0,
    lastGrowth: finiteGrowth(last.growth_bps),
    lastBaselineBps: nowSplit.baselineBps,
    lastExcessBps: nowSplit.excessBps,
    lastHotMinute: lastHot ? lastHot.minute : null,
    lastHotBps: lastHot ? Number(lastHot.bps) || 0 : null,
    lastHotBaselineBps: hotSplit.baselineBps,
    lastHotExcessBps: hotSplit.excessBps,
    sinceHotMin,
    peakBps: Number(peak.bps) || 0,
    peakMinute: peak.minute,
    hotMinutes,
    quietStreak,
    normalizeStreak: need || null,
    lagMin: Number.isFinite(lastTs) ? Math.max(0, Math.round((nowTs - lastTs) / MINUTE)) : null,
  };
}

async function attachLiveState(events) {
  if (!events.length) return;
  try {
    const nowTs = Date.now();
    const alertTimes = events.map((e) => parseUtc(e.alertMinute)).filter(Number.isFinite);
    if (!alertTimes.length) return;
    const fromTs = Math.max(Math.min(...alertTimes), nowTs - LIVE_LOOKBACK_MS);
    const scopeFilter = previousRowsScopeFilter(events.map((e) => ({ scope: e.scope, scopeId: e.scopeId })));
    if (scopeFilter.sql === '0') return;
    const { rows } = await query(`
      SELECT scope, scope_id, toString(minute) AS m, bps, growth_bps, growth_pps
      FROM ${tableRef()}
      WHERE proto = 'all'
        AND minute >= ${utcDateTime('from')}
        AND ${scopeFilter.sql}
      ORDER BY minute
    `, { from: formatCh(fromTs), ...scopeFilter.params }, { name: 'detection/events-live' });
    const byKey = new Map();
    for (const r of rows) {
      const key = objectKey(r.scope, r.scope_id);
      const list = byKey.get(key) || [];
      list.push({ minute: r.m, bps: r.bps, growth_bps: r.growth_bps, growth_pps: r.growth_pps });
      byKey.set(key, list);
    }
    const settings = await getDetectionTelegramSettings();
    for (const event of events) {
      event.live = liveEventState(byKey.get(objectKey(event.scope, event.scopeId)), {
        alertMinute: event.alertMinute,
        threshold: event.threshold,
        signal: event.signal,
        normalizeStreak: signalSettings(settings, event.signal).normalizeStreak,
        nowTs,
      });
    }
  } catch (err) {
    console.warn(new Date().toISOString(), 'detection events live state skipped', err.message);
  }
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

function netSpikeByProto(net) {
  const bytes = net.bps * 60 / 8;
  const packets = net.pps * 60;
  return {
    all: {
      proto: 'all',
      bps: net.bps,
      pps: net.pps,
      bytes,
      packets,
      avg_packet_bytes: packets > 0 ? bytes / packets : 0,
    },
    tcp: { proto: 'tcp', bps: net.tcpBps },
    udp: { proto: 'udp', bps: net.udpBps },
  };
}

// Отражение и SYN уже доказаны по клиенту целиком, их вердикт не трогаем.
// Иначе форму и цель ищем в самой /24: по клиенту целиком удар не виден.
function isNetFocus(net, verdict) {
  return Boolean(net?.net)
    && verdict?.kind !== KINDS.amplification
    && verdict?.kind !== KINDS.syn_flood;
}

function netSpikeVerdict(net, hour = {}) {
  return classifyFromMetrics(netSpikeByProto(net), {
    ...hour,
    p95: net.usualBps,
    p999: net.usualBps,
    recentMedian: null,
  });
}

// Строки про объём клиента и пару «к 14д / к часу» считают по клиенту, поэтому
// его норму возвращаем; кратность сети уже стоит в строке «Сеть /24».
function withClientVolume(verdict, clientVerdict = {}) {
  return {
    ...verdict,
    hourP95: clientVerdict.hourP95 ?? null,
    hourP999: clientVerdict.hourP999 ?? null,
    hourCeiling: clientVerdict.hourCeiling ?? null,
    hourRatio: clientVerdict.hourRatio ?? null,
    netHourRatio: verdict?.hourRatio ?? null,
  };
}

function openTrack(signal, row, group, byProto, investigate, verdict, minute) {
  const rate = signalRate(signal, row, group);
  const vector = vectorSnapshot({ byProto, investigate, verdict });
  return {
    vector,
    toldVector: vector,
    vectors: [vectorLabel(vector)].filter(Boolean),
    peak: { bps: rate.bps, pps: rate.pps, minute },
    lastReportBps: rate.bps,
    lastReportPps: rate.pps,
    lastNotifyMinute: minute,
    lastLookMinute: minute,
    pendingVector: false,
  };
}

async function saveActiveTrack(event, track) {
  await insertDetectionEvent({
    event_id: event.id,
    scope: event.scope,
    scope_id: event.scopeId,
    name: event.name,
    status: 'active',
    alert_minute: event.alertMinute,
    normalize_minute: null,
    alert_json: JSON.stringify(persistActiveAlertSnapshot({ ...event, track })),
    normalize_json: '',
    threshold: event.threshold,
    signal: event.signal || SIGNALS.volume,
  });
}

function rememberVector(track, nextVector) {
  const label = vectorLabel(nextVector);
  const vectors = Array.isArray(track.vectors) ? track.vectors.slice() : [];
  if (label && !vectors.includes(label)) vectors.push(label);
  return { ...track, vector: nextVector, vectors };
}

// Пока атака открыта: пик для сообщения о закрытии, рост вдвое и смена вектора.
// Полный разбор минуты — только если протокол или размер пакета уже другие,
// прошло 10 минут, или пора отправить отложенную смену.
async function followOpenAttacks({
  minute, rows, grouped, activeByKey, nameByKey, settings, tgCfg, skipIds, thresholdByKey,
}) {
  const seen = new Set();
  let sent = 0;
  let updated = 0;
  const errors = [];
  const present = grouped instanceof Map ? grouped : groupRowsByObject(rows || []);
  for (const event of activeByKey.values()) {
    if (!event?.id || seen.has(event.id)) continue;
    seen.add(event.id);
    if (skipIds?.has(event.id)) continue;
    if (event.status && event.status !== 'active') continue;
    const key = objectKey(event.scope, event.scopeId);
    const group = present.get(key);
    const row = group?.byProto?.all;
    if (!row) continue;
    const signal = event.signal || SIGNALS.volume;
    const rate = signalRate(signal, row, group);
    // Минута между импульсами — это фон провайдера, а не новый вектор.
    const threshold = resolveGrowthThreshold(event.scope, event.scopeId, settings.growthThreshold, thresholdByKey);
    const hotNow = isSignalHot(signal, row, group, threshold, settings)
      || (signal === SIGNALS.syn_flood && synFloodStillGoing(row, synOptions(settings)));
    // Открытие не ушло в Telegram из-за малой доли — продолжения тоже не шлём.
    const tgFollow = String(event.telegramSkip || '') !== TELEGRAM_SKIP_BELOW_SHARE
      && matchesAlertKind(true, settings.alertKind) ? tgCfg : null;
    let track = event.track;
    if (!track) {
      let investigate = event.investigate || null;
      if (settings.vectorNotify) {
        try {
          investigate = await investigateIncident({ scope: event.scope, scopeId: event.scopeId, minute });
          investigate = await attachTargetFocus(investigate, { scope: event.scope, scopeId: event.scopeId, minute });
        } catch (err) {
          errors.push({ key, message: `track-prime: ${err.message}` });
          investigate = event.investigate || null;
        }
      }
      try {
        await saveActiveTrack(event, openTrack(signal, row, group, group.byProto, investigate, event.verdict, minute));
        updated += 1;
      } catch (err) {
        errors.push({ key, message: `track-save: ${err.message}` });
      }
      continue;
    }
    const peakBefore = `${track.peak?.bps || 0}|${track.peak?.pps || 0}|${track.peak?.minute || ''}`;
    const vectorsBefore = (track.vectors || []).join('|');
    const lookBefore = track.lastLookMinute || '';
    track = {
      ...track,
      peak: bumpPeak(track.peak, rate, minute),
      vectors: Array.isArray(track.vectors) ? track.vectors.slice() : [],
      vector: { ...(track.vector || {}) },
    };
    const cheap = vectorSnapshot({ byProto: group.byProto });
    const cheapChanged = hotNow && Boolean(
      (track.vector?.proto && cheap.proto && track.vector.proto !== cheap.proto)
      || packetClassMoved(track.vector, cheap),
    );
    const lookDue = notifyGapOpen(track.lastLookMinute || track.lastNotifyMinute, minute);
    const gapOk = notifyGapOpen(track.lastNotifyMinute, minute);
    let investigated = null;
    const wantInvestigate = hotNow && settings.vectorNotify && (
      cheapChanged || lookDue || (track.pendingVector && gapOk)
    );
    if (wantInvestigate) {
      try {
        investigated = await investigateIncident({ scope: event.scope, scopeId: event.scopeId, minute });
        investigated = await attachTargetFocus(investigated, { scope: event.scope, scopeId: event.scopeId, minute });
        const nextVector = vectorSnapshot({ byProto: group.byProto, investigate: investigated, verdict: event.verdict });
        if (vectorChanged(track.vector, nextVector)) {
          track = { ...rememberVector(track, nextVector), pendingVector: true };
        }
        track.lastLookMinute = minute;
      } catch (err) {
        errors.push({ key, message: `track-vector: ${err.message}` });
      }
    } else if (!settings.vectorNotify && cheapChanged) {
      track = rememberVector(track, { ...track.vector, proto: cheap.proto, pkt: cheap.pkt, pktBytes: cheap.pktBytes });
      track.pendingVector = false;
    }
    let notified = false;
    const toldVector = event.track?.vector;
    const currentVector = investigated
      ? vectorSnapshot({ byProto: group.byProto, investigate: investigated, verdict: event.verdict })
      : null;
    if (investigated && track.pendingVector && !vectorChanged(toldVector, currentVector)) {
      track = { ...track, pendingVector: false, vector: currentVector };
    }
    if (settings.vectorNotify && track.pendingVector && gapOk && investigated) {
      let binding = null;
      if (event.scope === 'client' || event.scope === 'provider') {
        try {
          binding = event.scope === 'provider'
            ? await loadProviderBinding(event.scopeId)
            : await loadClientBinding(event.scopeId);
        } catch (err) {
          errors.push({ key, message: `track-binding: ${err.message}` });
        }
      }
      const text = formatVectorChangeMessage({
        name: nameByKey?.get(key) || event.name,
        scope: event.scope,
        scopeId: event.scopeId,
        byProto: group.byProto,
        verdict: event.verdict,
        investigate: investigated,
        binding,
        signals: [signal],
        rate,
        previous: track.toldVector || toldVector,
      });
      const tg = await maybeSendTelegram(text, tgFollow);
      if (tg.sent) sent += 1;
      if (tg.error) errors.push({ key, message: tg.error });
      track = {
        ...track,
        toldVector: currentVector,
        pendingVector: false,
        lastReportBps: rate.bps,
        lastReportPps: rate.pps,
        lastNotifyMinute: minute,
      };
      notified = true;
    } else if (gapOk && rateDoubled(track, rate)) {
      const text = formatPeakGrewMessage({
        name: nameByKey?.get(key) || event.name,
        scope: event.scope,
        scopeId: event.scopeId,
        rate,
      });
      const tg = await maybeSendTelegram(text, tgFollow);
      if (tg.sent) sent += 1;
      if (tg.error) errors.push({ key, message: tg.error });
      track = {
        ...track,
        lastReportBps: rate.bps,
        lastReportPps: rate.pps,
        lastNotifyMinute: minute,
      };
      notified = true;
    }
    const peakAfter = `${track.peak?.bps || 0}|${track.peak?.pps || 0}|${track.peak?.minute || ''}`;
    const vectorsAfter = (track.vectors || []).join('|');
    const dirty = notified
      || peakAfter !== peakBefore
      || vectorsAfter !== vectorsBefore
      || (track.lastLookMinute || '') !== lookBefore
      || Boolean(track.pendingVector) !== Boolean(event.track?.pendingVector);
    if (!dirty) continue;
    try {
      await saveActiveTrack(event, track);
      updated += 1;
    } catch (err) {
      errors.push({ key, message: `track-save: ${err.message}` });
    }
  }
  return { sent, updated, errors };
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
    return SIGNAL_ORDER.some((signal) => isSignalHot(signal, r, group, t, settings));
  });
  const watchKeys = [];
  const seen = new Set();
  for (const row of allRows) {
    const key = objectKey(row.scope, row.scope_id);
    if (seen.has(key)) continue;
    const hasActive = SIGNAL_ORDER
      .some((signal) => activeByKey.has(objectSignalKey(row.scope, row.scope_id, signal))
        || (signal === SIGNALS.volume && activeByKey.has(key)));
    if (!above.includes(row) && !hasActive) continue;
    seen.add(key);
    watchKeys.push({ scope: row.scope, scopeId: row.scope_id });
  }

  const volumeCfg = signalSettings(settings, SIGNALS.volume);
  const take = Math.max(
    settings.streak,
    settings.normalizeStreak,
    volumeCfg.window + 1,
    volumeCfg.normalizeStreak,
    settings.ampStreak,
    settings.geoStreak,
    settings.ampNormalizeStreak,
    settings.geoNormalizeStreak,
    NET_NORMALIZE_STREAK,
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
  const presentKeys = new Set(rows
    .filter((r) => String(r.proto) === 'all')
    .map((r) => objectKey(r.scope, r.scope_id)));
  if (presentKeys.size) {
    normalizeCandidates.push(...pickSilentNormalizeCandidates(activeByKey, presentKeys, minute, {
      settings,
      skipIds: new Set(normalizeCandidates.map((c) => c.active?.id).filter(Boolean)),
    }));
  }

  let sent = 0;
  let opened = 0;
  let closed = 0;
  const errors = [];
  const touchedIds = new Set();

  const alertGroups = new Map();
  for (const candidate of alertCandidates) {
    const groupKey = `${candidate.objectKey || candidate.key}|${minute}`;
    const list = alertGroups.get(groupKey) || [];
    list.push(candidate);
    alertGroups.set(groupKey, list);
  }

  for (const candidates of alertGroups.values()) {
    const eventCandidates = dropDuplicateGeo(candidates, activeByKey);
    if (!eventCandidates.length) continue;
    const { row, threshold: objectThreshold } = candidates[0];
    const objectId = objectKey(row.scope, row.scope_id);
    const group = grouped.get(objectId);
    const name = nameByKey?.get(objectId) || row.scope_id;
    const signals = candidates.map((c) => c.signal || SIGNALS.volume);
    let byProto = group?.byProto || { all: row };
    let focusMinute = minute;
    if (signals.length && signals.every((signal) => signal === SIGNALS.volume)) {
      const history = [row, ...(previousByKey.get(objectId) || [])];
      const heavy = heaviestHotMinute(
        history,
        objectThreshold,
        candidates[0].streak || settings.streak,
        candidates[0].window || volumeCfg.window,
      );
      if (heavy && !sameMinute(heavy.minute, minute)) {
        try {
          const loaded = await loadMinuteByProto(row.scope, row.scope_id, heavy.minute);
          if (loaded) {
            byProto = loaded;
            focusMinute = formatCh(parseUtc(heavy.minute));
          }
        } catch (err) {
          errors.push({ key: objectId, message: `heavy-minute: ${err.message}` });
        }
      }
    }
    let hour = { p95: null, p999: null };
    let investigate = emptyInvestigate();
    let binding = null;
    if (row.scope === 'client' || row.scope === 'provider') {
      try {
        binding = row.scope === 'provider'
          ? await loadProviderBinding(row.scope_id)
          : await loadClientBinding(row.scope_id);
      } catch (err) {
        errors.push({ key: objectId, message: `binding: ${err.message}` });
      }
    }
    try {
      hour = await loadHourEnvelope({ scope: row.scope, scopeId: row.scope_id, minute: focusMinute });
    } catch (err) {
      errors.push({ key: objectId, message: `hour: ${err.message}` });
    }
    hour = {
      ...hour,
      ampMinBps: ampOptions(settings).bpsMin,
      ampHourRatio: ampOptions(settings).hourRatio,
      syn: synOptions(settings),
    };
    let verdict = classifyFromMetrics(byProto, hour);
    const clientVerdict = verdict;
    const net = signals.includes(SIGNALS.net_spike) ? netSpikeMetrics(byProto.all || row) : null;
    const netFocus = isNetFocus(net, verdict);
    if (netFocus) verdict = netSpikeVerdict(net, hour);
    const target = netFocus
      ? { scope: 'net', scopeId: net.net, clientId: String(row.scope_id), parentScope: row.scope }
      : { scope: row.scope, scopeId: row.scope_id };
    if (verdict.needsInvestigate || verdict.kind === KINDS.benign_peak || netFocus
      || signals.includes(SIGNALS.amplification)
      || signals.includes(SIGNALS.syn_flood) || signals.includes(SIGNALS.foreign_geo)) {
      try {
        investigate = await investigateIncident({ ...target, minute: focusMinute });
        investigate = await attachTargetFocus(investigate, { ...target, minute: focusMinute });
        if (verdict.kind === KINDS.benign_peak && (target.scope === 'provider' || target.scope === 'client')) {
          try {
            const junk = await loadExcessAsnTop({ ...target, minute: focusMinute });
            investigate = {
              ...investigate,
              junk: {
                share: junk.share,
                junkBps: junk.junkBps,
                topSrcShare: junk.topSrcShare,
                hotSrcs: junk.hotSrcs,
              },
            };
          } catch (err) {
            errors.push({ key: objectId, message: `junk: ${err.message}` });
          }
        }
        verdict = refineClassification(verdict, investigate, { scope: target.scope });
      } catch (err) {
        errors.push({ key: objectId, message: `investigate: ${err.message}` });
        investigate = { ...emptyInvestigate(), error: err.message };
      }
    }
    if (netFocus) verdict = withClientVolume(verdict, clientVerdict);
    const attack = isAlertAttack(verdict, signals);
    let repeat = null;
    if (attack) {
      try {
        const prior = await loadRecentAttacks({ scope: row.scope, scopeId: row.scope_id, minute });
        repeat = summarizeRepeat(prior, String(investigate?.victim?.ip || ''));
      } catch (err) {
        errors.push({ key: objectId, message: `repeat: ${err.message}` });
      }
    }
    const startMinute = earliestStartMinute(eventCandidates, minute);
    const text = formatAlertMessage({
      name,
      scope: row.scope,
      scopeId: row.scope_id,
      repeat,
      minute: focusMinute,
      startMinute,
      byProto,
      verdict,
      investigate,
      binding,
      signals,
    });
    const skipShare = shouldSkipTelegramForShare(signals, { byProto, verdict, investigate }, settings);
    const snapshot = persistAlertSnapshot(snapshotByProto({ byProto }, byProto.all || row), {
      verdict,
      investigate,
      binding,
      telegramText: text,
      telegramSkip: skipShare ? TELEGRAM_SKIP_BELOW_SHARE : '',
      focusMinute: focusMinute !== minute ? focusMinute : '',
      startMinute,
    });
    for (const candidate of eventCandidates) {
      const signal = candidate.signal || SIGNALS.volume;
      const eventId = signal === SIGNALS.volume
        ? `${objectId}|${minute}`
        : `${objectId}|${signal}|${minute}`;
      const stored = attack
        ? { ...snapshot, track: openTrack(signal, byProto.all || row, group, byProto, investigate, verdict, focusMinute) }
        : snapshot;
      await insertDetectionEvent({
        event_id: eventId,
        scope: row.scope,
        scope_id: row.scope_id,
        name,
        status: attack ? 'active' : 'peak',
        alert_minute: minute,
        normalize_minute: attack ? null : minute,
        alert_json: JSON.stringify(stored),
        normalize_json: '',
        threshold: objectThreshold,
        signal,
      });
      touchedIds.add(eventId);
      opened += 1;
    }
    const tg = await maybeSendTelegram(
      text,
      (!skipShare && matchesAlertKind(attack, settings.alertKind)) ? tgCfg : null,
    );
    if (tg.sent) sent += 1;
    if (tg.error) errors.push({ key: objectId, message: tg.error });
  }

  for (const { row, key, active, silent, telegram } of normalizeCandidates) {
    const group = grouped.get(key);
    const name = nameByKey?.get(key) || active.name || row.scope_id;
    const text = formatNormalizeMessage({
      name,
      scope: active.scope,
      scopeId: active.scopeId,
      minute,
      alertMinute: active.alertMinute,
      startMinute: active.startMinute,
      streak: signalSettings(settings, active.signal || SIGNALS.volume).normalizeStreak,
      byProto: group?.byProto || { all: row },
      alertByProto: byProtoFromSnapshot(uiByProtoToSnapshot(active.alertByProto)),
      verdict: active.verdict,
      investigate: active.investigate,
      signals: [active.signal || SIGNALS.volume],
      track: active.track,
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
    touchedIds.add(active.id);
    closed += 1;
    const skipShare = String(active.telegramSkip || '') === TELEGRAM_SKIP_BELOW_SHARE;
    const skipStale = silent && !telegram;
    const tg = await maybeSendTelegram(
      text,
      (!skipShare && !skipStale && matchesAlertKind(true, settings.alertKind)) ? tgCfg : null,
    );
    if (tg.sent) sent += 1;
    if (tg.error) errors.push({ key, message: tg.error });
  }

  let follow = { sent: 0, updated: 0, errors: [] };
  try {
    follow = await followOpenAttacks({
      minute,
      rows,
      grouped,
      activeByKey,
      nameByKey,
      settings,
      tgCfg,
      skipIds: touchedIds,
      thresholdByKey,
    });
  } catch (err) {
    errors.push({ key: 'follow', message: err.message });
  }
  sent += follow.sent || 0;
  if (follow.errors?.length) errors.push(...follow.errors);

  if (!opened && !closed && !follow.updated && !follow.sent) {
    return {
      skipped: above.length ? 'waiting_streak' : (activeByKey.size ? 'waiting_normalize' : 'none_above'),
      sent: 0,
      above: above.length,
      active: activeByKey.size,
      streak: settings.streak,
      normalizeStreak: settings.normalizeStreak,
      updates: 0,
    };
  }

  return {
    sent,
    opened,
    closed,
    updates: follow.updated || 0,
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
  const minuteForFacts = snapshot.focusMinute || minuteCh;
  let hour = { p95: null, p999: null };
  let investigate = emptyInvestigate();
  let binding = snapshot.binding || null;
  if (row.scope === 'client' || row.scope === 'provider') {
    try {
      binding = row.scope === 'provider'
        ? await loadProviderBinding(row.scope_id)
        : await loadClientBinding(row.scope_id);
    } catch {
      binding = snapshot.binding || null;
    }
  }
  try {
    hour = await loadHourEnvelope({ scope: row.scope, scopeId: row.scope_id, minute: minuteForFacts });
  } catch { /* keep empty envelope */ }
  hour = {
    ...hour,
    ampMinBps: ampOptions(settings).bpsMin,
    ampHourRatio: ampOptions(settings).hourRatio,
    syn: synOptions(settings),
  };
  let verdict = classifyFromMetrics(byProto, hour);
  if (verdict.needsInvestigate || verdict.kind === KINDS.benign_peak) {
    try {
      investigate = await investigateIncident({ scope: row.scope, scopeId: row.scope_id, minute: minuteForFacts });
      investigate = await attachTargetFocus(investigate, {
        scope: row.scope,
        scopeId: row.scope_id,
        minute: minuteForFacts,
      });
      if (verdict.kind === KINDS.benign_peak && (row.scope === 'provider' || row.scope === 'client')) {
        const junk = await loadExcessAsnTop({
          scope: row.scope,
          scopeId: row.scope_id,
          minute: minuteForFacts,
        });
        investigate = {
          ...investigate,
          junk: {
            share: junk.share,
            junkBps: junk.junkBps,
            topSrcShare: junk.topSrcShare,
            hotSrcs: junk.hotSrcs,
          },
        };
      }
      verdict = refineClassification(verdict, investigate, { scope: row.scope });
    } catch (err) {
      investigate = { ...emptyInvestigate(), error: err.message };
    }
  }
  const text = formatAlertMessage({
    name: row.name || row.scope_id,
    scope: row.scope,
    scopeId: row.scope_id,
    minute: minuteForFacts,
    startMinute: snapshot.startMinute || null,
    byProto,
    verdict,
    investigate,
    binding,
    signals: [row.signal || SIGNALS.volume],
  });
  const next = persistAlertSnapshot(snapshot, {
    verdict,
    investigate,
    binding,
    telegramText: text,
    focusMinute: snapshot.focusMinute || '',
    startMinute: snapshot.startMinute || '',
  });
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
  PREV_ROWS_GAP_MINUTES,
  previousRowsLookbackMinutes,
  liveEventState,
  previousRowsScopeFilter,
  DEFAULT_TELEGRAM_API_URL,
  DEFAULT_MIN_CLIENT_SHARE_PCT,
  TELEGRAM_SKIP_BELOW_SHARE,
  normalizeMinSharePct,
  parasiticClientShare,
  shouldSkipTelegramForShare,
  minSharePctForSignal,
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
  heaviestHotMinute,
  shouldSendNormalize,
  shouldNormalizeQuiet,
  matchesAlertScope,
  matchesAlertKind,
  isAlertAttack,
  historyStatusSql,
  normalizeAlertKind,
  pickAlertCandidates,
  pickNormalizeCandidates,
  pickSilentNormalizeCandidates,
  shouldSendSignal,
  shouldSendNetSpike,
  isNetFocus,
  netSpikeVerdict,
  withClientVolume,
  dropDuplicateGeo,
  loadRecentAttacks,
  summarizeRepeat,
  formatRepeatLine,
  SIGNALS,
  formatAlertMessage,
  formatCutLine,
  formatVectorChangeMessage,
  formatPeakGrewMessage,
  formatSourceOperatorLines,
  vectorSnapshot,
  vectorChanged,
  vectorLabel,
  rateDoubled,
  bumpPeak,
  mapSettings,
  alertStartMinute,
  signalSettings,
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
