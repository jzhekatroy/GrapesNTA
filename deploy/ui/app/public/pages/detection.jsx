const { useState, useEffect, useCallback, useMemo } = React;

const PROTOS = ['all', 'tcp', 'udp'];
const PROTO_ORDER = { all: 0, tcp: 1, udp: 2 };
const PROTO_LABEL = { all: 'общее', tcp: 'TCP', udp: 'UDP' };
const PROTO_TONE = { all: 'neutral', tcp: 'info', udp: 'warning' };
const KIND_LABEL = {
  volumetric: 'атака в сервер',
  carpet: 'атака по сети',
  syn_flood: 'SYN-флуд',
  amplification: 'амплификация',
  benign_peak: 'обычный пик',
};
const SIGNAL_LABEL = {
  volume: 'объём',
  amplification: 'амплификация',
  foreign_geo: 'заграница',
  net_spike: 'сеть /24',
};
const PAGE_TABS = [
  { id: 'table', label: 'Таблица' },
  { id: 'active', label: 'Активные' },
  { id: 'history', label: 'История' },
  { id: 'thresholds', label: 'Пороги' },
  { id: 'telegram', label: 'Telegram' },
];
const TELEGRAM_DEFAULTS = {
  enabled: false,
  chatId: '',
  growthThreshold: 1.6,
  alertScope: 'all',
  alertKind: 'all',
  streak: 3,
  normalizeStreak: 3,
  volumeWindow: 6,
  volumeQuiet: 10,
  apiUrl: 'https://api.telegram.org',
  proxyUrl: '',
  proxySet: false,
  tokenSet: false,
  volumeMinSharePct: 10,
  ampMinSharePct: 10,
  synMinSharePct: 10,
  geoMinSharePct: 10,
  ampHourRatio: 2,
  ampMinMbit: 20,
  synEnabled: true,
  synHourRatio: 10,
  synMinKpps: 200,
  synPktMax: 100,
  vectorNotify: true,
};
const TELEGRAM_VECTORS = [
  { id: 'volume', label: 'Рост объёма', shareKey: 'volumeMinSharePct' },
  { id: 'amplification', label: 'Амплификация', shareKey: 'ampMinSharePct' },
  { id: 'syn_flood', label: 'SYN-флуд', shareKey: 'synMinSharePct' },
  { id: 'foreign_geo', label: 'Заграница', shareKey: 'geoMinSharePct' },
];
const CHART_PERIODS = [
  { id: '1h', hours: 1, label: '1ч', title: '1 час' },
  { id: '6h', hours: 6, label: '6ч', title: '6 часов' },
  { id: '24h', hours: 24, label: '24ч', title: '24 часа' },
  { id: '7d', hours: 168, label: '7д', title: '7 дней' },
];
const HANDSHAKE_METRICS = new Set(['synAttempts', 'answerPct', 'halfOpenPct', 'halfOpenReplyPct']);
const METRIC_TITLES = {
  bps: 'bps',
  pps: 'pps',
  growthBps: 'Рост bps',
  growthPps: 'Рост pps',
  synAttempts: 'Попытки',
  answerPct: 'Ответ',
  halfOpenPct: 'Полуоткрытые',
  halfOpenReplyPct: 'Не зашли',
  portEntropy: 'Энтропия портов вх.',
  portEntropyOut: 'Энтропия портов исх.',
  portsPerIp: 'Макс. портов/IP вх.',
  portsPerIpOut: 'Макс. портов/IP исх.',
  avgPacketBytes: 'Средний пакет',
  cvPercent: 'CV',
};

function formatWhen(value) {
  if (!value) return '—';
  const raw = String(value);
  const iso = raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return raw;
  return `${date.toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })} МСК`;
}

function utcCh(ms) {
  return new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
}

function displayLocalToMs(value) {
  if (!value || typeof displayDatetimeLocalToData !== 'function' || typeof parseChartBucketMs !== 'function') return null;
  return parseChartBucketMs(String(displayDatetimeLocalToData(value)).replace('T', ' '));
}

function displayLocalToUtcCh(value) {
  const ms = displayLocalToMs(value);
  return ms == null ? null : utcCh(ms);
}

function defaultHistoryRangeLocal() {
  const toMs = Date.now();
  const fromMs = toMs - 7 * 24 * 3600 * 1000;
  if (typeof msToDatetimeLocalValue === 'function' && typeof getDisplayTimezone === 'function') {
    const tz = getDisplayTimezone();
    return {
      from: msToDatetimeLocalValue(fromMs, tz),
      to: msToDatetimeLocalValue(toMs, tz),
    };
  }
  const pad = (n) => String(n).padStart(2, '0');
  const fmt = (ms) => {
    const d = new Date(ms);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  return { from: fmt(fromMs), to: fmt(toMs) };
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function chartWindow(periodId, customRange) {
  if (customRange?.from && customRange?.to) {
    const fromMs = displayLocalToMs(customRange.from);
    const toMs = displayLocalToMs(customRange.to);
    if (fromMs != null && toMs != null && toMs > fromMs) return { fromMs, toMs, hours: null };
  }
  const hours = CHART_PERIODS.find((p) => p.id === periodId)?.hours || 6;
  const toMs = Date.now();
  return { fromMs: toMs - hours * 3600 * 1000, toMs, hours };
}

function chartPeriodLabel(periodId, customRange) {
  if (customRange?.from && customRange?.to && typeof formatCustomPeriodLabel === 'function') {
    return formatCustomPeriodLabel(customRange);
  }
  return CHART_PERIODS.find((p) => p.id === periodId)?.title || '6 часов';
}

function formatNum(value, digits = 2) {
  if (value == null || !Number.isFinite(Number(value))) return '—';
  return Number(value).toLocaleString('ru-RU', { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

function formatGrowth(value) {
  if (value == null || !Number.isFinite(Number(value))) return 'пусто';
  return `×${Number(value).toFixed(2)}`;
}

function formatPct(value) {
  if (value == null || !Number.isFinite(Number(value))) return 'пусто';
  return `${Number(value).toFixed(1)}%`;
}

function formatEntropy(value) {
  if (value == null || !Number.isFinite(Number(value))) return 'пусто';
  return Number(value).toFixed(2);
}

function formatPorts(value) {
  if (value == null || !Number.isFinite(Number(value))) return 'пусто';
  return Number(value).toLocaleString('ru-RU', { maximumFractionDigits: 0 });
}

function formatRate(value, units) {
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

function formatBps(value) {
  return formatRate(value, ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с', 'Тбит/с']);
}

function formatPps(value) {
  return formatRate(value, ['п/с', 'тыс. п/с', 'млн п/с', 'млрд п/с']);
}

function eventAttackBps(event) {
  const n = Number(event?.alertByProto?.all?.bps);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function eventHourUsual(event) {
  const v = event?.verdict || {};
  const n = Number(v.hourCeiling ?? v.hourP95);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function eventHourRatio(event) {
  const r = Number(event?.verdict?.hourRatio);
  if (Number.isFinite(r) && r > 0) return r;
  const bps = eventAttackBps(event);
  const usual = eventHourUsual(event);
  if (bps != null && usual) return bps / usual;
  return null;
}

function formatHourShare(ratio) {
  if (ratio == null || !Number.isFinite(ratio) || ratio <= 0) return '—';
  const pct = ratio * 100;
  const digits = pct >= 10 ? 0 : 1;
  return `${pct.toLocaleString('ru-RU', { minimumFractionDigits: digits, maximumFractionDigits: digits })}%`;
}

function formatMskTime(value) {
  if (!value) return '—';
  const raw = String(value);
  const date = new Date(raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`);
  if (Number.isNaN(date.getTime())) return raw;
  return date.toLocaleTimeString('ru-RU', { timeZone: 'Europe/Moscow', hour: '2-digit', minute: '2-digit' });
}

function liveStateView(live) {
  if (!live) return { tone: 'neutral', label: 'нет данных', headline: null, lines: [], title: '' };
  const excess = live.lastHotExcessBps;
  const headline = excess != null
    ? `${formatBps(excess)} лишнего`
    : (live.lastHotBps != null ? formatBps(live.lastHotBps) : null);
  const lines = [];
  if (live.lastHotBaselineBps != null) {
    lines.push(`всего ${formatBps(live.lastHotBps)}, норма ${formatBps(live.lastHotBaselineBps)}`);
  }
  const title = [
    live.lastHotMinute ? `удар ${formatMskTime(live.lastHotMinute)}` : null,
    live.peakBps ? `пик ${formatBps(live.peakBps)} в ${formatMskTime(live.peakMinute)}` : null,
    live.normalizeStreak ? `тихих минут ${live.quietStreak} из ${live.normalizeStreak}` : null,
    live.lagMin != null ? `данные на ${formatMskTime(live.lastMinute)}` : null,
  ].filter(Boolean).join('\n');
  if (live.state === 'ongoing') return { tone: 'critical', label: 'атака', headline, lines, title };
  if (live.state === 'fading') {
    return {
      tone: 'warning',
      label: 'затихает',
      headline: excess != null ? `было ${formatBps(excess)} лишнего` : headline,
      lines,
      title,
    };
  }
  return { tone: 'neutral', label: '—', headline: null, lines: [], title };
}

function isPeakEvent(event) {
  return event?.verdict?.kind === 'benign_peak' || event?.status === 'peak';
}

function attackLoadTitle(event) {
  const bps = eventAttackBps(event);
  const ratio = eventHourRatio(event);
  const usual = eventHourUsual(event);
  return [
    bps != null ? `атака ${formatBps(bps)}` : null,
    ratio != null ? `×${ratio.toFixed(2)} к норме часа` : null,
    usual != null ? `норма ${formatBps(usual)}` : null,
  ].filter(Boolean).join(' · ');
}

function AttackLoadBanner({ event }) {
  if (!event) return null;
  const bps = eventAttackBps(event);
  const ratio = eventHourRatio(event);
  const usual = eventHourUsual(event);
  if (bps == null && ratio == null) return null;
  const peak = isPeakEvent(event);
  return (
    <div className={`detection-attack-banner${peak ? ' detection-attack-banner--peak' : ''}`}>
      <div className="detection-attack-banner__item">
        <div className="detection-attack-banner__label">Объём атаки</div>
        <div className="detection-attack-banner__value">{bps == null ? '—' : formatBps(bps)}</div>
      </div>
      <div className="detection-attack-banner__item">
        <div className="detection-attack-banner__label">От нормы часа</div>
        <div className="detection-attack-banner__value">{ratio == null ? '—' : formatHourShare(ratio)}</div>
      </div>
      {usual != null && (
        <div className="detection-attack-banner__item">
          <div className="detection-attack-banner__label">Норма часа</div>
          <div className="detection-attack-banner__value detection-attack-banner__value--muted">{formatBps(usual)}</div>
        </div>
      )}
    </div>
  );
}

function objectKind(row) {
  return String(row?.scope || '').toLowerCase() === 'net' ? 'net' : 'client';
}

function protoOf(row) {
  return PROTO_ORDER[row?.proto] != null ? row.proto : 'all';
}

function matchesSearch(row, needle) {
  if (!needle) return true;
  const kindLabel = objectKind(row) === 'net' ? 'сеть net /24' : 'абонент клиент';
  const protoLabel = PROTO_LABEL[protoOf(row)] || '';
  return `${row.name || ''} ${row.scopeId || ''} ${kindLabel} ${protoLabel}`.toLowerCase().includes(needle);
}

function isBlankMetric(formatted) {
  return formatted === '—' || formatted === 'пусто';
}

function metricText(row, metric, formatted) {
  if (!row) return '—';
  if (row.proto === 'udp' && HANDSHAKE_METRICS.has(metric)) return '—';
  return formatted(row);
}

function sortMetric(group, key, protoFilter) {
  const proto = protoFilter === 'any' ? 'all' : protoFilter;
  const row = group?.byProto?.[proto] || group?.byProto?.all;
  const value = row?.[key];
  if (value == null || !Number.isFinite(Number(value))) return null;
  return Number(value);
}

function patchTelegram(prev, patch) {
  return { ...TELEGRAM_DEFAULTS, ...prev, ...patch };
}

function notifyHeadline(row) {
  const text = String(row?.alertText || row?.normalizeText || '').trim();
  if (!text) return '';
  return text.split('\n').find((line) => line.trim()) || '';
}

function formatAsnShare(share) {
  const pct = Number(share) * 100;
  if (!Number.isFinite(pct) || pct <= 0) return '';
  const digits = pct >= 10 ? 0 : 1;
  return `${pct.toLocaleString('ru-RU', { maximumFractionDigits: digits })}%`;
}

function JunkRows({ rows, labelOf }) {
  if (!rows?.length) return null;
  return rows.map((row) => (
    <div key={labelOf(row)} style={{ display: 'flex', gap: 8, fontSize: 13 }}>
      <span style={{ flex: 1 }}>{labelOf(row)}</span>
      <span>{formatBps(row.bps)}</span>
      <span style={{ width: 48, textAlign: 'right', color: 'var(--fg-muted)' }}>{formatAsnShare(row.share)}</span>
    </div>
  ));
}

function EventAsnTop({ event }) {
  const minute = event?.live?.lastHotMinute || event?.alertMinute || '';
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!event?.scope || !event?.scopeId || !minute) {
      setData(null);
      return undefined;
    }
    let cancelled = false;
    setBusy(true);
    setError('');
    setData(null);
    ApiClient.loadDetectionEventAsn({ scope: event.scope, scopeId: event.scopeId, minute })
      .then((row) => { if (!cancelled) setData(row); })
      .catch((err) => { if (!cancelled) setError(err.message || 'Не удалось посчитать мусорный UDP'); })
      .finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [event?.id, event?.scope, event?.scopeId, minute]);
  const share = data ? formatAsnShare(data.share) : '';
  return (
    <div style={{ margin: '8px 0 14px' }}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>
        {busy ? 'Считаю мусорный UDP…' : 'Мусорный UDP'}
      </div>
      {error ? <div style={{ color: 'var(--st-critical)' }}>{error}</div> : null}
      {data ? (
        <div style={{ fontSize: 13, marginBottom: 8 }}>
          {share || '0%'} входящего
          {' · '}
          {formatBps(data.junkBps)} из {formatBps(data.inboundBps)}
          {' · '}
          {formatMskTime(data.minute)}
          {data.asnCount ? ` · ${data.asnCount} ASN` : ''}
        </div>
      ) : null}
      {data?.asns?.length ? <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 4 }}>Откуда</div> : null}
      <JunkRows rows={data?.asns} labelOf={(row) => `AS${row.asn}${row.asnName ? ` ${row.asnName}` : ''}`} />
      {data?.networks?.length ? <div style={{ fontSize: 12, color: 'var(--fg-muted)', margin: '8px 0 4px' }}>Куда</div> : null}
      <JunkRows
        rows={data?.networks}
        labelOf={(row) => `${row.prefix}${row.ips ? ` · ${row.ips} адр.` : ''}`}
      />
    </div>
  );
}

function EventNotifyModal({ event, onClose }) {
  const peak = isPeakEvent(event);
  return (
    <Modal
      open={!!event}
      onClose={onClose}
      size="lg"
      title="Текст оповещения"
      subtitle={event ? `${event.name || event.scopeId}${peak ? ' · обычный пик' : ''}` : ''}
      footer={<Button kind="ghost" onClick={onClose}>Закрыть</Button>}
    >
      <AttackLoadBanner event={event} />
      {event ? <EventAsnTop event={event} /> : null}
      {event?.alertText ? (
        <pre className="detection-notify-text">{event.alertText}</pre>
      ) : (
        <div className="detection-notify-box__empty">Текста срабатывания нет</div>
      )}
      {event?.normalizeText ? (
        <>
          <div className="detection-notify-box__head">Нормализация</div>
          <pre className="detection-notify-text">{event.normalizeText}</pre>
        </>
      ) : null}
    </Modal>
  );
}

function EventMark({ kind }) {
  const tone = kind === 'ok' ? 'ok' : kind === 'peak' ? 'peak' : 'alert';
  const title = tone === 'ok' ? 'Нормализация' : tone === 'peak' ? 'Пик' : 'Алерт';
  return (
    <span
      className={`detection-event-mark detection-event-mark--${tone}`}
      title={title}
    />
  );
}

function formatVictimCell(inv) {
  const v = inv?.victim;
  if (!v?.ip) return '—';
  const proto = v.protoLabel ? `${v.protoLabel} ` : '';
  const port = v.port != null ? `:${v.port}` : '';
  const pct = v.share != null ? ` (${(Number(v.share) * 100).toFixed(1)}%)` : '';
  return `${proto}${v.ip}${port}${pct}`;
}

function formatSwitchCell(inv) {
  const port = inv?.switchIn;
  if (!port || (!port.ifName && !port.ifAlias && !port.switchIp)) return '—';
  const name = port.ifName || (port.ifIndex ? `ifIndex ${port.ifIndex}` : '');
  const alias = port.ifAlias ? ` (${port.ifAlias})` : '';
  return `${port.switchIp || ''} ${name}${alias}`.trim();
}

function formatSource24Cell(inv) {
  const row = inv?.source24?.[0];
  if (!row?.net24) return '—';
  const pct = row.share != null ? ` ${(Number(row.share) * 100).toFixed(1)}%` : '';
  return `${row.net24}${pct}`;
}

function EventMetricStack({ phases, metric, formatted }) {
  const lines = [];
  for (const phase of phases) {
    for (const proto of PROTOS) {
      const row = phase.byProto?.[proto];
      lines.push({
        key: `${phase.id}-${proto}`,
        text: metricText(row, metric, formatted),
      });
    }
  }
  return (
    <div className="detection-stack" style={{ '--detection-stack-rows': lines.length }}>
      {lines.map((line) => (
        <div key={line.key} className="detection-stack__line">{line.text}</div>
      ))}
    </div>
  );
}

function eventPhases(event, withNormalize) {
  const phases = [{ id: 'alert', kind: 'alert', byProto: event.alertByProto || {} }];
  if (withNormalize) phases.push({ id: 'ok', kind: 'ok', byProto: event.normalizeByProto || {} });
  return phases;
}

function MetricStack({ group, metric, formatted, onOpen, protos }) {
  const list = protos?.length ? protos : PROTOS;
  return (
    <div className="detection-stack" style={{ '--detection-stack-rows': list.length }}>
      {list.map((proto) => {
        const row = group.byProto[proto];
        const text = metricText(row, metric, formatted);
        const clickable = row && !isBlankMetric(text);
        return (
          <div key={proto} className="detection-stack__line">
            {clickable ? (
              <button
                type="button"
                className="link-btn"
                onClick={(e) => {
                  e.stopPropagation();
                  onOpen(row, metric);
                }}
              >
                {text}
              </button>
            ) : text}
          </div>
        );
      })}
    </div>
  );
}

function chartFormatValue(metric, value) {
  if (value == null || !Number.isFinite(Number(value))) return '—';
  if (metric === 'bps') return formatBps(value);
  if (metric === 'pps') return formatPps(value);
  if (metric === 'growthBps' || metric === 'growthPps') return formatGrowth(value);
  if (metric === 'answerPct' || metric === 'halfOpenPct' || metric === 'halfOpenReplyPct' || metric === 'cvPercent') {
    return formatPct(value);
  }
  if (metric === 'portEntropy' || metric === 'portEntropyOut') return formatEntropy(value);
  if (metric === 'portsPerIp' || metric === 'portsPerIpOut') return formatPorts(value);
  if (metric === 'avgPacketBytes') return `${formatNum(value, 0)} Б`;
  return formatNum(value, 0);
}

function ThresholdCell({ globalThreshold, override, disabled, onSave }) {
  const inherited = override == null;
  const [draft, setDraft] = useState(inherited ? '' : String(override));
  useEffect(() => {
    setDraft(override == null ? '' : String(override));
  }, [override]);
  const commit = () => {
    const raw = String(draft || '').trim().replace(',', '.');
    if (raw === '') {
      if (!inherited) onSave(null);
      return;
    }
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0 || n > 1000) {
      setDraft(inherited ? '' : String(override));
      return;
    }
    if (inherited || n !== Number(override)) onSave(n);
  };
  const shown = Number(inherited ? globalThreshold : override);
  return (
    <input
      className="input"
      style={{
        width: 78,
        padding: '4px 6px',
        fontWeight: inherited ? 400 : 600,
        color: inherited ? 'var(--fg-secondary)' : 'var(--st-info-fg, inherit)',
      }}
      title={inherited
        ? `Общий порог ×${Number(globalThreshold).toFixed(2)}. Задайте свой, чтобы перекрыть.`
        : `Индивидуальный ×${Number(override).toFixed(2)}. Пустое поле вернёт общий ×${Number(globalThreshold).toFixed(2)}.`}
      placeholder={`×${Number(shown).toFixed(2)}`}
      value={draft}
      disabled={disabled}
      onClick={(e) => e.stopPropagation()}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === 'Enter') e.currentTarget.blur();
        if (e.key === 'Escape') {
          setDraft(inherited ? '' : String(override));
          e.currentTarget.blur();
        }
      }}
    />
  );
}

function PageDetection() {
  const [data, setData] = useState({ minute: null, items: [] });
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [kind, setKind] = useState('all');
  const [protoFilter, setProtoFilter] = useState('any');
  const [chart, setChart] = useState(null);
  const [chartData, setChartData] = useState(null);
  const [chartError, setChartError] = useState('');
  const [chartPeriod, setChartPeriod] = useState('6h');
  const [chartCustom, setChartCustom] = useState(null);
  const [chartZoomStack, setChartZoomStack] = useState([]);
  const [telegram, setTelegram] = useState(null);
  const [telegramError, setTelegramError] = useState('');
  const [telegramForbidden, setTelegramForbidden] = useState(false);
  const [telegramBusy, setTelegramBusy] = useState(false);
  const [botToken, setBotToken] = useState('');
  const [pageTab, setPageTab] = useState('table');
  const [events, setEvents] = useState([]);
  const [eventsError, setEventsError] = useState('');
  const [eventsBusy, setEventsBusy] = useState(false);
  const [historyRange, setHistoryRange] = useState(() => defaultHistoryRangeLocal());
  const [historyKind, setHistoryKind] = useState('all');
  const [eventsExporting, setEventsExporting] = useState(false);
  const [messageEvent, setMessageEvent] = useState(null);
  const [thresholdByKey, setThresholdByKey] = useState({});
  const [thresholdBusyKey, setThresholdBusyKey] = useState('');
  const [thresholdGlobal, setThresholdGlobal] = useState(1.6);

  const reload = useCallback(() => {
    setError('');
    return ApiClient.loadDetectionLatest()
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const historyBounds = useCallback(() => {
    const from = displayLocalToUtcCh(historyRange.from);
    const to = displayLocalToUtcCh(historyRange.to);
    return { from, to };
  }, [historyRange.from, historyRange.to]);

  const reloadEvents = useCallback((status) => {
    setEventsBusy(true);
    setEventsError('');
    const opts = { status, limit: status === 'normalized' ? 1000 : 200 };
    if (status === 'normalized') {
      const { from, to } = historyBounds();
      if (from) opts.from = from;
      if (to) opts.to = to;
      if (historyKind && historyKind !== 'all') opts.kind = historyKind;
    }
    return ApiClient.loadDetectionEvents(opts)
      .then(setEvents)
      .catch((e) => setEventsError(e.message))
      .finally(() => setEventsBusy(false));
  }, [historyBounds, historyKind]);

  useEffect(() => {
    if (pageTab === 'active') reloadEvents('active');
    if (pageTab === 'history') reloadEvents('normalized');
  }, [pageTab, reloadEvents]);

  const exportHistory = async () => {
    setEventsExporting(true);
    setEventsError('');
    try {
      const { from, to } = historyBounds();
      if (!from || !to) throw new Error('Укажите начало и конец периода');
      if (displayLocalToMs(historyRange.from) >= displayLocalToMs(historyRange.to)) {
        throw new Error('Начало периода должно быть раньше конца');
      }
      const { blob, count } = await ApiClient.exportDetectionEventsCsv({
        status: 'normalized',
        from,
        to,
        limit: 10000,
        kind: historyKind,
      });
      if (!count) {
        pushToast?.({ kind: 'warning', title: 'Нечего выгружать', desc: 'За выбранный период записей нет.' });
        return;
      }
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      downloadBlob(`detection-history-${stamp}.csv`, blob);
      pushToast?.({ kind: 'success', title: 'CSV выгружен', desc: `${count} событий.` });
    } catch (e) {
      setEventsError(e.message);
      pushToast?.({ kind: 'error', title: 'Ошибка выгрузки', desc: e.message });
    } finally {
      setEventsExporting(false);
    }
  };

  useEffect(() => {
    ApiClient.loadDetectionThresholds()
      .then((res) => {
        const next = {};
        for (const row of res.items) {
          next[`${row.scope}|${row.scopeId}`] = Number(row.growthThreshold);
        }
        setThresholdByKey(next);
        setThresholdGlobal(res.global);
      })
      .catch(() => { /* колонка покажет дефолтный порог */ });
  }, []);

  const saveObjectThreshold = async (row, value) => {
    const key = `${row.scope}|${row.scopeId}`;
    setThresholdBusyKey(key);
    try {
      const saved = await ApiClient.saveDetectionThreshold({
        scope: row.scope,
        scopeId: row.scopeId,
        growthThreshold: value,
      });
      setThresholdByKey((prev) => {
        const next = { ...prev };
        if (saved?.growthThreshold == null) delete next[key];
        else next[key] = Number(saved.growthThreshold);
        return next;
      });
      pushToast?.({
        kind: 'success',
        title: saved?.growthThreshold == null ? 'Порог сброшен на общий' : `Порог ×${Number(saved.growthThreshold).toFixed(2)}`,
        desc: row.name || row.scopeId,
      });
    } catch (e) {
      pushToast?.({ kind: 'error', title: 'Порог не сохранён', desc: e.message });
    } finally {
      setThresholdBusyKey('');
    }
  };

  useEffect(() => {
    ApiClient.loadDetectionTelegramSettings()
      .then((data) => {
        setTelegram(data);
        setTelegramForbidden(false);
        setTelegramError('');
        setBotToken('');
      })
      .catch((e) => {
        if (e.status === 403) setTelegramForbidden(true);
        setTelegramError(e.message);
      });
  }, []);

  useEffect(() => {
    if (!chart) {
      setChartData(null);
      setChartError('');
      return undefined;
    }
    let cancelled = false;
    setChartData(null);
    setChartError('');
    const window = chartWindow(chartPeriod, chartCustom);
    ApiClient.loadDetectionHistory({
      scope: chart.scope,
      scopeId: chart.scopeId,
      proto: chart.proto,
      metric: chart.metric,
      hours: window.hours,
      from: window.hours ? undefined : utcCh(window.fromMs),
      to: window.hours ? undefined : utcCh(window.toMs),
    })
      .then((body) => { if (!cancelled) setChartData(body); })
      .catch((e) => { if (!cancelled) setChartError(e.message); });
    return () => { cancelled = true; };
  }, [chart, chartPeriod, chartCustom]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const groups = new Map();
    for (const item of data.items || []) {
      if (kind !== 'all' && objectKind(item) !== kind) continue;
      const proto = protoOf(item);
      const id = `${objectKind(item)}:${item.scopeId}`;
      const cur = groups.get(id) || {
        id,
        scope: item.scope,
        scopeId: item.scopeId,
        name: item.name,
        byProto: { all: null, tcp: null, udp: null },
      };
      cur.byProto[proto] = { ...item, proto };
      if (item.name) cur.name = item.name;
      groups.set(id, cur);
    }
    return [...groups.values()]
      .filter((g) => !needle || [g, ...PROTOS.map((p) => g.byProto[p])].some((r) => r && matchesSearch(r, needle)))
      .map((g) => ({
        ...g,
        bps: Number((protoFilter === 'any' ? g.byProto.all : g.byProto[protoFilter])?.bps || 0),
      }));
  }, [data.items, q, kind, protoFilter]);

  const visibleProtos = protoFilter === 'any' ? PROTOS : [protoFilter];

  const openChart = useCallback((row, metric) => {
    setChart({
      scope: row.scope,
      scopeId: row.scopeId,
      proto: protoOf(row),
      name: row.name,
      metric,
      title: METRIC_TITLES[metric] || metric,
    });
  }, []);

  const chartBounds = useMemo(
    () => chartWindow(chartPeriod, chartCustom),
    [chartPeriod, chartCustom],
  );

  const chartPoints = useMemo(() => {
    if (!chartData?.points?.length) return [];
    return chartData.points.map((p) => ({
      bucket: p.bucket || p.t,
      bucketMs: p.bucketMs,
      bps: p.v == null ? null : Number(p.v),
    }));
  }, [chartData]);

  const pickChartPeriod = useCallback((id) => {
    setChartPeriod(id);
    setChartCustom(null);
    setChartZoomStack([]);
  }, []);

  const onChartRangeSelect = useCallback((range) => {
    if (!range?.from || !range?.to) return;
    if (typeof validateCustomPeriod === 'function' && validateCustomPeriod(range)) return;
    setChartZoomStack((stack) => [...stack, chartCustom]);
    setChartCustom({ from: range.from, to: range.to });
  }, [chartCustom]);

  const resetChartZoom = useCallback(() => {
    if (!chartZoomStack.length) {
      setChartCustom(null);
      return;
    }
    setChartCustom(chartZoomStack[chartZoomStack.length - 1]);
    setChartZoomStack((stack) => stack.slice(0, -1));
  }, [chartZoomStack]);

  const metric = (key, formatted) => (g) => (
    <MetricStack group={g} metric={key} formatted={formatted} onOpen={openChart} protos={visibleProtos} />
  );
  const byMetric = (key) => (g) => sortMetric(g, key, protoFilter);

  const saveTelegram = async () => {
    setTelegramBusy(true);
    setTelegramError('');
    try {
      const payload = {
        enabled: telegram?.enabled,
        chatId: telegram?.chatId || '',
        growthThreshold: telegram?.growthThreshold ?? 1.6,
        alertScope: telegram?.alertScope || 'all',
        alertKind: telegram?.alertKind || 'all',
        streak: telegram?.streak ?? 3,
        normalizeStreak: telegram?.normalizeStreak ?? 3,
        volumeWindow: telegram?.volumeWindow ?? 6,
        volumeQuiet: telegram?.volumeQuiet ?? 10,
        apiUrl: telegram?.apiUrl || 'https://api.telegram.org',
        proxyUrl: telegram?.proxyUrl || '',
        ampEnabled: telegram?.ampEnabled !== false,
        geoEnabled: telegram?.geoEnabled !== false,
        ampStreak: telegram?.ampStreak ?? 1,
        geoStreak: telegram?.geoStreak ?? 1,
        volumeMinSharePct: telegram?.volumeMinSharePct ?? 10,
        ampMinSharePct: telegram?.ampMinSharePct ?? 10,
        synMinSharePct: telegram?.synMinSharePct ?? 10,
        geoMinSharePct: telegram?.geoMinSharePct ?? 10,
        ampHourRatio: telegram?.ampHourRatio ?? 2,
        ampMinMbit: telegram?.ampMinMbit ?? 20,
        synEnabled: telegram?.synEnabled !== false,
        synHourRatio: telegram?.synHourRatio ?? 10,
        synMinKpps: telegram?.synMinKpps ?? 200,
        synPktMax: telegram?.synPktMax ?? 100,
        vectorNotify: telegram?.vectorNotify !== false,
      };
      if (botToken.trim()) payload.botToken = botToken.trim();
      const data = await ApiClient.saveDetectionTelegramSettings(payload);
      setTelegram(data);
      setBotToken('');
      pushToast?.({ kind: 'success', title: pageTab === 'thresholds' ? 'Пороги сохранены' : 'Telegram сохранён' });
    } catch (e) {
      setTelegramError(e.message);
    } finally {
      setTelegramBusy(false);
    }
  };

  const eventMetric = (key, formatted) => (event) => {
    const withNormalize = pageTab === 'history';
    return <EventMetricStack phases={eventPhases(event, withNormalize)} metric={key} formatted={formatted} />;
  };

  const testTelegram = async () => {
    setTelegramBusy(true);
    setTelegramError('');
    try {
      await ApiClient.testDetectionTelegramSettings();
      pushToast?.({ kind: 'success', title: 'Тестовое сообщение отправлено' });
    } catch (e) {
      setTelegramError(e.message);
    } finally {
      setTelegramBusy(false);
    }
  };

  // Общий порог правится на вкладке «Пороги» — берём его значение сразу,
  // не дожидаясь перезагрузки списка исключений.
  const globalThreshold = Number(telegram?.growthThreshold ?? thresholdGlobal) || 1.6;

  return (
    <div className="col" style={{ gap: 14 }}>
      {error && (
        <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)' }}>
          {error}
        </div>
      )}

      <div className="seg" role="tablist" aria-label="Разделы детекции">
        {PAGE_TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={pageTab === tab.id}
            className={pageTab === tab.id ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => setPageTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {pageTab === 'telegram' && (
      <Card
        title="Telegram"
        subtitle="Куда слать сообщения. Порог, окно и число горячих минут — на вкладке «Пороги»: это обнаружение, а не отправка. Ниже доли паразитного трафика событие пишется в историю и в Telegram не уходит. Если api.telegram.org с nta не открывается — укажите SOCKS5 прокси. API URL меняйте только если есть своё зеркало Bot API."
      >
        <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
          {telegramForbidden ? (
            <div style={{ color: 'var(--fg-secondary)' }}>
              Настройки Telegram доступны только администратору.
            </div>
          ) : !telegram && !telegramError ? (
            <div style={{ color: 'var(--fg-muted)' }}>Загрузка настроек…</div>
          ) : (
            <>
              {telegramError && (
                <div style={{ color: 'var(--st-critical)' }}>{telegramError}</div>
              )}
              <label className="row" style={{ gap: 8, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={!!telegram?.enabled}
                  onChange={(e) => setTelegram(patchTelegram(telegram, { enabled: e.target.checked }))}
                />
                Включить оповещения
              </label>
              <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
                <label className="col" style={{ gap: 4, minWidth: 260, flex: 1 }}>
                  <span>Токен бота {telegram?.tokenSet ? '(задан)' : ''}</span>
                  <input
                    className="input"
                    type="password"
                    placeholder={telegram?.tokenSet ? 'оставьте пустым, чтобы не менять' : ''}
                    value={botToken}
                    onChange={(e) => setBotToken(e.target.value)}
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 280, flex: 1 }}>
                  <span>API Telegram</span>
                  <input
                    className="input"
                    value={telegram?.apiUrl || 'https://api.telegram.org'}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { apiUrl: e.target.value }))}
                    placeholder="https://tba.pinspb.ru"
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 320, flex: 1 }}>
                  <span>Прокси {telegram?.proxySet ? '(задан)' : ''}</span>
                  <input
                    className="input"
                    value={telegram?.proxyUrl || ''}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { proxyUrl: e.target.value }))}
                    placeholder="socks5://user:pass@host:port"
                    autoComplete="off"
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 180 }}>
                  <span>ID группы</span>
                  <input
                    className="input"
                    value={telegram?.chatId || ''}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { chatId: e.target.value }))}
                    placeholder="-100…"
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 160 }}>
                  <span>Рассылка по</span>
                  <select
                    className="input"
                    value={telegram?.alertScope || 'all'}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { alertScope: e.target.value }))}
                  >
                    <option value="all">Всё</option>
                    <option value="client">Абоненты</option>
                    <option value="net">Сети</option>
                  </select>
                </label>
                <label className="col" style={{ gap: 4, minWidth: 180 }}>
                  <span>Отправлять</span>
                  <select
                    className="input"
                    value={telegram?.alertKind || 'all'}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { alertKind: e.target.value }))}
                  >
                    <option value="all">Всё</option>
                    <option value="attack">Атаки</option>
                    <option value="peak">Всплески</option>
                  </select>
                </label>
              </div>
              <label className="row" style={{ gap: 8, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={telegram?.vectorNotify !== false}
                  onChange={(e) => setTelegram(patchTelegram(telegram, { vectorNotify: e.target.checked }))}
                />
                <span>Оповещать о смене вектора атаки</span>
              </label>
              <div style={{ color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
                Пока атака открыта — сообщение, если меняются протокол, размер пакета, порты, префиксы или операторы источников. Не чаще раза в 10 минут. Рост скорости вдвое приходит и с выключенной галочкой.
              </div>
              <div className="table-wrap table-wrap--telegram-vectors">
                <table className="table table--telegram-vectors">
                  <thead>
                    <tr>
                      <th>Вектор</th>
                      <th className="num">Мин. доля клиента, %</th>
                    </tr>
                  </thead>
                  <tbody>
                    {TELEGRAM_VECTORS.map((vector) => {
                      const share = telegram?.[vector.shareKey] ?? 10;
                      return (
                        <tr key={vector.id}>
                          <td>{vector.label}</td>
                          <td className="num">
                            {vector.id === 'amplification' || vector.id === 'syn_flood' ? (
                              <span style={{ color: 'var(--fg-muted)' }}>не используется</span>
                            ) : (
                              <input
                                className="input"
                                type="number"
                                min="0"
                                max="100"
                                step="1"
                                value={share}
                                onChange={(e) => setTelegram(patchTelegram(telegram, {
                                  [vector.shareKey]: e.target.value === '' ? '' : Number(e.target.value),
                                }))}
                                title="Ниже доли — только история, в Telegram нет. 0 — слать всегда."
                              />
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <div style={{ color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
                Если паразитный трафик ниже доли от всего трафика клиента — событие пишется в историю, в Telegram не уходит. 0 — слать всегда.
              </div>
              <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                <Button size="sm" disabled={telegramBusy} onClick={saveTelegram}>Сохранить</Button>
                <Button
                  size="sm"
                  disabled={telegramBusy || !(telegram?.tokenSet || botToken.trim())}
                  onClick={testTelegram}
                >
                  Тестовое сообщение
                </Button>
              </div>
            </>
          )}
        </div>
      </Card>
      )}

      {pageTab === 'thresholds' && (
      <Card
        title="Рост объёма"
        subtitle="Событие открывается, когда за окно набралось нужное число горячих минут. Горячая минута — рост не ниже общего порога, минуты не обязаны идти подряд. Закрывается после тихих минут подряд. Это обнаружение: в Telegram уходит отдельно, по вкладке «Telegram»."
      >
        <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
          {telegramForbidden ? (
            <div style={{ color: 'var(--fg-secondary)' }}>
              Настройки порогов доступны только администратору.
            </div>
          ) : !telegram && !telegramError ? (
            <div style={{ color: 'var(--fg-muted)' }}>Загрузка настроек…</div>
          ) : (
            <>
              {telegramError && (
                <div style={{ color: 'var(--st-critical)' }}>{telegramError}</div>
              )}
              <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
                <label className="col" style={{ gap: 4, minWidth: 140 }}>
                  <span>Порог общий</span>
                  <input
                    className="input"
                    type="number"
                    step="0.1"
                    min="0.1"
                    value={telegram?.growthThreshold ?? 1.6}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { growthThreshold: Number(e.target.value) }))}
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 160 }}>
                  <span>Горячих минут</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="60"
                    step="1"
                    value={telegram?.streak ?? 3}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { streak: Number(e.target.value) }))}
                    title="Сколько горячих минут нужно набрать в окне, чтобы открыть событие."
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 140 }}>
                  <span>Окно, мин</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="60"
                    step="1"
                    value={telegram?.volumeWindow ?? 6}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { volumeWindow: Number(e.target.value) }))}
                    title="За сколько минут считать горячие. Например, 3 горячие за 10 минут."
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 200 }}>
                  <span>Тихих минут до закрытия</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="60"
                    step="1"
                    value={telegram?.volumeQuiet ?? 10}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { volumeQuiet: Number(e.target.value) }))}
                    title="Событие по объёму закрывается после стольких тихих минут подряд."
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 220 }}>
                  <span>Минут ниже порога</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="60"
                    step="1"
                    value={telegram?.normalizeStreak ?? 3}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { normalizeStreak: Number(e.target.value) }))}
                    title="Закрытие отражения, SYN и заграницы. Объём закрывается полем «Тихих минут до закрытия»."
                  />
                </label>
              </div>
              <div style={{ color: 'var(--fg-muted)' }}>
                Импульсная атака не теряется: горячие минуты считаются внутри окна, а не строго подряд. «Минут ниже порога» закрывает отражение, SYN и заграницу.
              </div>
              <div className="row" style={{ gap: 8 }}>
                <Button size="sm" disabled={telegramBusy} onClick={saveTelegram}>Сохранить</Button>
              </div>
            </>
          )}
        </div>
      </Card>
      )}

      {pageTab === 'thresholds' && (
      <Card
        title="Отражение"
        subtitle="Срабатывает, когда трафик с портов усилителей не ниже минимума и не меньше заданной кратности к обычному уровню этого клиента в тот же час (будни и выходные отдельно). Доля от всего трафика клиента не используется."
      >
        <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
          {telegramForbidden ? (
            <div style={{ color: 'var(--fg-secondary)' }}>
              Настройки порогов доступны только администратору.
            </div>
          ) : !telegram && !telegramError ? (
            <div style={{ color: 'var(--fg-muted)' }}>Загрузка настроек…</div>
          ) : (
            <>
              {telegramError && (
                <div style={{ color: 'var(--st-critical)' }}>{telegramError}</div>
              )}
              <label className="row" style={{ gap: 8, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={telegram?.ampEnabled !== false}
                  onChange={(e) => setTelegram(patchTelegram(telegram, { ampEnabled: e.target.checked }))}
                />
                Следить за отражением
              </label>
              <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
                <label className="col" style={{ gap: 4, minWidth: 180 }}>
                  <span>Кратность к норме часа</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="100"
                    step="0.1"
                    value={telegram?.ampHourRatio ?? 2}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { ampHourRatio: Number(e.target.value) }))}
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 180 }}>
                  <span>Минимум, Мбит/с</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="100000"
                    step="1"
                    value={telegram?.ampMinMbit ?? 20}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { ampMinMbit: Number(e.target.value) }))}
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 160 }}>
                  <span>Минут подряд</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="60"
                    step="1"
                    value={telegram?.ampStreak ?? 1}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { ampStreak: Number(e.target.value) }))}
                  />
                </label>
              </div>
              <div style={{ color: 'var(--fg-muted)' }}>
                Если за этот час ещё нет нормы, решает только минимум. Порты усилителей: DNS 53, NTP 123, SSDP 1900 и остальные из списка детекции.
              </div>
              <div className="row" style={{ gap: 8 }}>
                <Button size="sm" disabled={telegramBusy} onClick={saveTelegram}>Сохранить</Button>
              </div>
            </>
          )}
        </div>
      </Card>
      )}

      {pageTab === 'thresholds' && !telegramForbidden && telegram && (
      <Card
        title="SYN-флуд"
        subtitle="Считаются пакеты голого SYN (без ACK) к клиенту. Срабатывает, когда их не меньше минимума и не меньше заданной кратности к обычному уровню этого клиента в тот же час (будни и выходные отдельно). Доля от TCP и от всего трафика клиента не используется."
      >
        <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
          <label className="row" style={{ gap: 8, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={telegram?.synEnabled !== false}
              onChange={(e) => setTelegram(patchTelegram(telegram, { synEnabled: e.target.checked }))}
            />
            Следить за SYN-флудом
          </label>
          <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
            <label className="col" style={{ gap: 4, minWidth: 180 }}>
              <span>Кратность к норме часа</span>
              <input
                className="input"
                type="number"
                min="1"
                max="1000"
                step="0.5"
                value={telegram?.synHourRatio ?? 10}
                onChange={(e) => setTelegram(patchTelegram(telegram, { synHourRatio: Number(e.target.value) }))}
              />
            </label>
            <label className="col" style={{ gap: 4, minWidth: 180 }}>
              <span>Минимум, тыс. п/с</span>
              <input
                className="input"
                type="number"
                min="1"
                max="100000"
                step="10"
                value={telegram?.synMinKpps ?? 200}
                onChange={(e) => setTelegram(patchTelegram(telegram, { synMinKpps: Number(e.target.value) }))}
              />
            </label>
            <label className="col" style={{ gap: 4, minWidth: 180 }}>
              <span>Средний пакет до, байт</span>
              <input
                className="input"
                type="number"
                min="40"
                max="1500"
                step="1"
                value={telegram?.synPktMax ?? 100}
                onChange={(e) => setTelegram(patchTelegram(telegram, { synPktMax: Number(e.target.value) }))}
              />
            </label>
          </div>
          <div style={{ color: 'var(--fg-muted)' }}>
            Если за этот час ещё нет нормы, решает только минимум. Событие открывается с первой горячей минуты; закрытие — по полю «Минут ниже порога» в блоке «Рост объёма».
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Button size="sm" disabled={telegramBusy} onClick={saveTelegram}>Сохранить</Button>
          </div>
        </div>
      </Card>
      )}

      {pageTab === 'thresholds' && !telegramForbidden && telegram && (
      <Card
        title="Заграница"
        subtitle="Срабатывает у абонента, когда растёт доля трафика из-за рубежа и объём выше общего порога. Доля, ниже которой сообщение не уходит в Telegram, задаётся на вкладке «Telegram»."
      >
        <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
          <label className="row" style={{ gap: 8, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={telegram?.geoEnabled !== false}
              onChange={(e) => setTelegram(patchTelegram(telegram, { geoEnabled: e.target.checked }))}
            />
            Следить за заграницей
          </label>
          <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
            <label className="col" style={{ gap: 4, minWidth: 160 }}>
              <span>Минут подряд</span>
              <input
                className="input"
                type="number"
                min="1"
                max="60"
                step="1"
                value={telegram?.geoStreak ?? 1}
                onChange={(e) => setTelegram(patchTelegram(telegram, { geoStreak: Number(e.target.value) }))}
              />
            </label>
          </div>
          <div style={{ color: 'var(--fg-muted)' }}>
            Закрытие — по полю «Минут ниже порога» в блоке «Рост объёма».
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Button size="sm" disabled={telegramBusy} onClick={saveTelegram}>Сохранить</Button>
          </div>
        </div>
      </Card>
      )}

      {chart && (
        <Card
          title={`${chart.title} · ${chart.name}`}
          subtitle={`${PROTO_LABEL[chart.proto] || chart.proto} · ${chartPeriodLabel(chartPeriod, chartCustom)} · выделите диапазон на графике`}
          tools={(
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              {(chartCustom || chartZoomStack.length > 0) && (
                <button
                  type="button"
                  className="time-pill time-pill--reset"
                  title="Вернуть предыдущий период"
                  onClick={resetChartZoom}
                >
                  <Icon name="zoom" size={14} />
                  <span>Сброс</span>
                </button>
              )}
              <div className="seg" role="group" aria-label="Период графика">
                {CHART_PERIODS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    className={!chartCustom && chartPeriod === p.id ? 'seg__item seg__item--active' : 'seg__item'}
                    onClick={() => pickChartPeriod(p.id)}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              <Button size="sm" onClick={() => setChart(null)}>Закрыть</Button>
            </div>
          )}
        >
          {chartError && (
            <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)' }}>
              {chartError}
            </div>
          )}
          {!chartError && !chartData && (
            <div style={{ color: 'var(--fg-muted)', padding: '8px 0' }}>Загрузка графика…</div>
          )}
          {!chartError && chartData && chartPoints.length < 2 && (
            <div style={{ color: 'var(--fg-muted)', padding: '8px 0' }}>
              Мало точек для графика. История появится, когда воркер запишет несколько минут.
            </div>
          )}
          {!chartError && chartPoints.length >= 2 && (
            <TimeSeriesSparkChart
              points={chartPoints}
              height={240}
              valueKey="bps"
              formatValue={(v) => chartFormatValue(chart.metric, v)}
              axisFormatter={chart.metric === 'bps' ? fmtBitsAxis : fmtCompact}
              onRangeSelect={onChartRangeSelect}
              bucketSeconds={60}
              displayTimezone={typeof getDisplayTimezone === 'function' ? getDisplayTimezone() : undefined}
              periodStartMs={chartBounds.fromMs}
              periodEndMs={chartBounds.toMs}
              skipLeadingGaps
              skipTrailingGaps
              fillGaps={false}
              yAxisUnit={chartData.units || ''}
            />
          )}
        </Card>
      )}

      {(pageTab === 'active' || pageTab === 'history') && (
        <Card
          title={pageTab === 'active' ? 'Активные события' : 'История'}
          subtitle={pageTab === 'active'
            ? 'Алерт уже ушёл, нормализации ещё нет. Срез метрик — момент срабатывания, все протоколы.'
            : 'В историю пишется всё. Фильтр — атаки, всплески или все. Клик по строке открывает текст.'}
          tools={(
            <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              {pageTab === 'history' && (
                <>
                  <div className="seg" role="group" aria-label="Тип в истории">
                    <button
                      type="button"
                      className={historyKind === 'all' ? 'seg__item seg__item--active' : 'seg__item'}
                      onClick={() => setHistoryKind('all')}
                    >
                      Все
                    </button>
                    <button
                      type="button"
                      className={historyKind === 'attack' ? 'seg__item seg__item--active' : 'seg__item'}
                      onClick={() => setHistoryKind('attack')}
                    >
                      Атаки
                    </button>
                    <button
                      type="button"
                      className={historyKind === 'peak' ? 'seg__item seg__item--active' : 'seg__item'}
                      onClick={() => setHistoryKind('peak')}
                    >
                      Всплески
                    </button>
                  </div>
                  <label className="row" style={{ gap: 6, alignItems: 'center', font: 'var(--pv-text-body-3)' }}>
                    <span style={{ color: 'var(--fg-secondary)' }}>с</span>
                    <input
                      className="input"
                      type="datetime-local"
                      value={historyRange.from || ''}
                      onChange={(e) => setHistoryRange((r) => ({ ...r, from: e.target.value }))}
                    />
                  </label>
                  <label className="row" style={{ gap: 6, alignItems: 'center', font: 'var(--pv-text-body-3)' }}>
                    <span style={{ color: 'var(--fg-secondary)' }}>по</span>
                    <input
                      className="input"
                      type="datetime-local"
                      value={historyRange.to || ''}
                      onChange={(e) => setHistoryRange((r) => ({ ...r, to: e.target.value }))}
                    />
                  </label>
                  <Button
                    size="sm"
                    disabled={eventsBusy || eventsExporting}
                    onClick={() => reloadEvents('normalized')}
                  >
                    Показать
                  </Button>
                  <Button
                    size="sm"
                    kind="ghost"
                    icon="export"
                    disabled={eventsBusy || eventsExporting}
                    onClick={exportHistory}
                  >
                    {eventsExporting ? 'Выгрузка…' : 'CSV'}
                  </Button>
                </>
              )}
              {pageTab === 'active' && (
                <Button
                  size="sm"
                  disabled={eventsBusy}
                  onClick={() => reloadEvents('active')}
                >
                  Обновить
                </Button>
              )}
            </div>
          )}
        >
          {eventsError && (
            <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', marginBottom: 10 }}>
              {eventsError}
            </div>
          )}
          <DataTable
            key={pageTab}
            rows={events}
            rowKey="id"
            pageSize={50}
            onRowClick={(r) => setMessageEvent(r)}
            getRowClassName={(r) => (r.id === messageEvent?.id ? 'is-selected' : '')}
            emptyTitle={eventsBusy ? 'Загрузка…' : 'Нет событий'}
            emptyDesc={pageTab === 'active'
              ? 'Пока нет объектов, которые держатся выше порога после алерта.'
              : 'История появится после первой атаки или пика.'}
            initialSort={{ key: 'alertMinute', dir: 'desc' }}
            columns={[
              {
                key: 'name',
                title: 'Объект',
                width: 260,
                sortAccessor: (r) => r.name || r.scopeId || '',
                render: (r) => (
                  <span>
                    <Badge tone={r.scope === 'client' ? 'neutral' : 'info'}>
                      {r.scope === 'client' ? 'абонент' : r.scope === 'provider' ? 'провайдер' : 'сеть /24'}
                    </Badge>
                    {' '}
                    {r.name || r.scopeId}
                  </span>
                ),
              },
              ...(pageTab === 'active' ? [{
                key: 'live',
                title: 'Сейчас',
                width: 260,
                sortAccessor: (r) => r.live?.lastHotExcessBps || 0,
                render: (r) => {
                  const view = liveStateView(r.live);
                  return (
                    <div title={view.title}>
                      <Badge tone={view.tone}>{view.label}</Badge>
                      {view.headline && (
                        <div style={{ fontWeight: 600 }}>{view.headline}</div>
                      )}
                      {view.lines.map((line) => (
                        <div key={line} style={{ fontSize: 12, color: 'var(--fg-muted)' }}>{line}</div>
                      ))}
                    </div>
                  );
                },
              }] : []),
              {
                key: 'attackVol',
                title: 'Объём атаки',
                width: 140,
                sortAccessor: (r) => eventAttackBps(r) ?? -1,
                render: (r) => {
                  const bps = eventAttackBps(r);
                  return (
                    <span className="detection-attack-vol" title={attackLoadTitle(r)}>
                      {bps == null ? '—' : formatBps(bps)}
                    </span>
                  );
                },
              },
              {
                key: 'attackShare',
                title: 'От нормы',
                width: 110,
                sortAccessor: (r) => eventHourRatio(r) ?? -1,
                render: (r) => {
                  const ratio = eventHourRatio(r);
                  const peak = isPeakEvent(r);
                  return (
                    <span
                      className={`detection-attack-share${peak ? ' detection-attack-share--peak' : ''}`}
                      title={attackLoadTitle(r)}
                    >
                      {ratio == null ? '—' : formatHourShare(ratio)}
                    </span>
                  );
                },
              },
              {
                key: 'kind',
                title: 'Тип',
                width: 150,
                sortAccessor: (r) => r.verdict?.kind || r.status || '',
                render: (r) => {
                  const kind = r.verdict?.kind;
                  const peak = kind === 'benign_peak' || r.status === 'peak';
                  return (
                    <Badge tone={peak ? 'warning' : kind ? 'critical' : 'neutral'}>
                      {KIND_LABEL[kind] || (peak ? 'обычный пик' : '—')}
                    </Badge>
                  );
                },
              },
              {
                key: 'signal',
                title: 'Признак',
                width: 140,
                sortAccessor: (r) => r.signal || 'volume',
                render: (r) => SIGNAL_LABEL[r.signal] || SIGNAL_LABEL.volume,
              },
              {
                key: 'notify',
                title: 'Сообщение Telegram',
                width: 280,
                sortable: false,
                render: (r) => {
                  const line = notifyHeadline(r);
                  return line
                    ? <span className="detection-notify-line">{line}</span>
                    : <span style={{ color: 'var(--fg-muted)' }}>нет текста</span>;
                },
              },
              {
                key: 'victim',
                title: 'Куда',
                width: 220,
                sortable: false,
                render: (r) => (
                  <span title={r.verdict?.reason || ''}>{formatVictimCell(r.investigate)}</span>
                ),
              },
              {
                key: 'source24',
                title: 'Откуда /24',
                width: 170,
                sortable: false,
                render: (r) => formatSource24Cell(r.investigate),
              },
              {
                key: 'switchIn',
                title: 'Коммутатор вход',
                width: 220,
                sortable: false,
                render: (r) => formatSwitchCell(r.investigate),
              },
              {
                key: 'phase',
                title: '',
                width: 150,
                sortable: false,
                render: (r) => {
                  const phases = eventPhases(r, pageTab === 'history');
                  return (
                    <div className="detection-stack" style={{ '--detection-stack-rows': phases.length * PROTOS.length }}>
                      {phases.flatMap((phase) => PROTOS.map((proto) => (
                        <div key={`${phase.id}-${proto}`} className="detection-stack__line">
                          <EventMark kind={phase.kind} />
                          <span style={{ marginLeft: 6 }}>{PROTO_LABEL[proto]}</span>
                        </div>
                      )))}
                    </div>
                  );
                },
              },
              {
                key: 'alertMinute',
                title: 'Срабатывание',
                width: 180,
                sortAccessor: (r) => r.alertMinute || '',
                render: (r) => formatWhen(r.alertMinute),
              },
              {
                key: 'normalizeMinute',
                title: 'Нормализация',
                width: 180,
                sortAccessor: (r) => r.normalizeMinute || '',
                render: (r) => (pageTab === 'history' && r.status !== 'peak' ? formatWhen(r.normalizeMinute) : '—'),
              },
              { key: 'bps', title: 'bps', num: true, width: 120, sortable: false, render: eventMetric('bps', (row) => formatBps(row.bps)) },
              { key: 'pps', title: 'pps', num: true, width: 120, sortable: false, render: eventMetric('pps', (row) => formatPps(row.pps)) },
              { key: 'growthBps', title: 'Рост bps', num: true, width: 110, sortable: false, render: eventMetric('growthBps', (row) => formatGrowth(row.growthBps)) },
              { key: 'growthPps', title: 'Рост pps', num: true, width: 110, sortable: false, render: eventMetric('growthPps', (row) => formatGrowth(row.growthPps)) },
              { key: 'synAttempts', title: 'Попытки', num: true, width: 110, sortable: false, render: eventMetric('synAttempts', (row) => formatNum(row.synAttempts, 0)) },
              { key: 'answerPct', title: 'Ответ', num: true, width: 100, sortable: false, render: eventMetric('answerPct', (row) => formatPct(row.answerPct)) },
              { key: 'halfOpenPct', title: 'Полуоткрытые', num: true, width: 130, sortable: false, render: eventMetric('halfOpenPct', (row) => formatPct(row.halfOpenPct)) },
              { key: 'halfOpenReplyPct', title: 'Не зашли', num: true, width: 110, sortable: false, render: eventMetric('halfOpenReplyPct', (row) => formatPct(row.halfOpenReplyPct)) },
              { key: 'portEntropy', title: 'Энтропия портов вх.', num: true, width: 165, sortable: false, render: eventMetric('portEntropy', (row) => formatEntropy(row.portEntropy)) },
              { key: 'portEntropyOut', title: 'Энтропия портов исх.', num: true, width: 170, sortable: false, render: eventMetric('portEntropyOut', (row) => formatEntropy(row.portEntropyOut)) },
              { key: 'portsPerIp', title: 'Макс. портов/IP вх.', num: true, width: 165, sortable: false, render: eventMetric('portsPerIp', (row) => formatPorts(row.portsPerIp)) },
              { key: 'portsPerIpOut', title: 'Макс. портов/IP исх.', num: true, width: 170, sortable: false, render: eventMetric('portsPerIpOut', (row) => formatPorts(row.portsPerIpOut)) },
              { key: 'avgPacketBytes', title: 'Средний пакет', num: true, width: 130, sortable: false, render: eventMetric('avgPacketBytes', (row) => `${formatNum(row.avgPacketBytes, 0)} Б`) },
              { key: 'cvPercent', title: 'CV', num: true, width: 90, sortable: false, render: eventMetric('cvPercent', (row) => (row.cvPercent == null ? '—' : `${formatNum(row.cvPercent, 1)}%`)) },
            ]}
          />
        </Card>
      )}

      <EventNotifyModal event={messageEvent} onClose={() => setMessageEvent(null)} />

      {pageTab === 'table' && (
      <Card
        title="Детекция"
        subtitle={data.minute
          ? `Минута ${formatWhen(data.minute)} · ${rows.length} объектов · порог общий ×${globalThreshold.toFixed(2)}, в колонке можно задать свой`
          : 'Минута ещё не посчитана'}
        tools={(
          <div className="row" style={{ gap: 8, alignItems: 'center' }}>
            <div className="seg">
              <button
                type="button"
                className={kind === 'all' ? 'seg__item seg__item--active' : 'seg__item'}
                onClick={() => setKind('all')}
              >
                Все
              </button>
              <button
                type="button"
                className={kind === 'client' ? 'seg__item seg__item--active' : 'seg__item'}
                onClick={() => setKind('client')}
              >
                Абонент
              </button>
              <button
                type="button"
                className={kind === 'net' ? 'seg__item seg__item--active' : 'seg__item'}
                onClick={() => setKind('net')}
              >
                Сеть
              </button>
            </div>
            <div className="seg" role="group" aria-label="Протокол">
              <button
                type="button"
                className={protoFilter === 'any' ? 'seg__item seg__item--active' : 'seg__item'}
                onClick={() => setProtoFilter('any')}
              >
                Все
              </button>
              {PROTOS.map((proto) => (
                <button
                  key={proto}
                  type="button"
                  className={protoFilter === proto ? 'seg__item seg__item--active' : 'seg__item'}
                  onClick={() => setProtoFilter(proto)}
                >
                  {PROTO_LABEL[proto]}
                </button>
              ))}
            </div>
            <Button size="sm" onClick={reload}>Обновить</Button>
          </div>
        )}
      >
        <DataTable
          key={`${data.minute || 'empty'}:${kind}:${protoFilter}`}
          rows={rows}
          rowKey="id"
          pageSize={50}
          emptyTitle="Нет данных"
          emptyDesc="Воркер ещё не записал минуту. Запустите npm run detection."
          initialSort={{ key: 'bps', dir: 'desc' }}
          toolbar={{
            search: q,
            onSearch: setQ,
            searchPlaceholder: 'имя, сеть, /24, id, TCP, UDP…',
          }}
          columns={[
            {
              key: 'name',
              title: 'Объект',
              width: 280,
              sortAccessor: (r) => r.name || r.scopeId || '',
              render: (r) => (
                <span>
                  <Badge tone={r.scope === 'client' ? 'neutral' : 'info'}>
                    {r.scope === 'client' ? 'абонент' : r.scope === 'provider' ? 'провайдер' : 'сеть /24'}
                  </Badge>
                  {' '}
                  {r.name}
                </span>
              ),
            },
            {
              key: 'threshold',
              title: 'Порог',
              width: 96,
              num: true,
              sortAccessor: (r) => Number(thresholdByKey[`${r.scope}|${r.scopeId}`] ?? globalThreshold),
              render: (r) => (
                <ThresholdCell
                  globalThreshold={globalThreshold}
                  override={thresholdByKey[`${r.scope}|${r.scopeId}`]}
                  disabled={telegramForbidden || thresholdBusyKey === `${r.scope}|${r.scopeId}`}
                  onSave={(value) => saveObjectThreshold(r, value)}
                />
              ),
            },
            {
              key: 'proto',
              title: '',
              width: 84,
              sortable: false,
              render: () => (
                <div className="detection-stack" style={{ '--detection-stack-rows': visibleProtos.length }}>
                  {visibleProtos.map((proto) => (
                    <div key={proto} className="detection-stack__line">
                      <Badge tone={PROTO_TONE[proto]}>{PROTO_LABEL[proto]}</Badge>
                    </div>
                  ))}
                </div>
              ),
            },
            {
              key: 'bps',
              title: 'bps',
              num: true,
              width: 120,
              sortAccessor: byMetric('bps'),
              render: metric('bps', (r) => formatBps(r.bps)),
            },
            { key: 'pps', title: 'pps', num: true, width: 120, sortAccessor: byMetric('pps'), render: metric('pps', (r) => formatPps(r.pps)) },
            { key: 'growthBps', title: 'Рост bps', num: true, width: 110, sortAccessor: byMetric('growthBps'), render: metric('growthBps', (r) => formatGrowth(r.growthBps)) },
            { key: 'growthPps', title: 'Рост pps', num: true, width: 110, sortAccessor: byMetric('growthPps'), render: metric('growthPps', (r) => formatGrowth(r.growthPps)) },
            {
              key: 'synAttempts',
              title: 'Попытки',
              num: true,
              width: 110,
              sortAccessor: byMetric('synAttempts'),
              render: metric('synAttempts', (r) => formatNum(r.synAttempts, 0)),
            },
            {
              key: 'answerPct',
              title: 'Ответ',
              num: true,
              width: 100,
              sortAccessor: byMetric('answerPct'),
              render: metric('answerPct', (r) => formatPct(r.answerPct)),
            },
            {
              key: 'halfOpenPct',
              title: 'Полуоткрытые',
              num: true,
              width: 130,
              sortAccessor: byMetric('halfOpenPct'),
              render: metric('halfOpenPct', (r) => formatPct(r.halfOpenPct)),
            },
            {
              key: 'halfOpenReplyPct',
              title: 'Не зашли',
              num: true,
              width: 110,
              sortAccessor: byMetric('halfOpenReplyPct'),
              render: metric('halfOpenReplyPct', (r) => formatPct(r.halfOpenReplyPct)),
            },
            {
              key: 'portEntropy',
              title: 'Энтропия портов вх.',
              num: true,
              width: 165,
              sortAccessor: byMetric('portEntropy'),
              render: metric('portEntropy', (r) => formatEntropy(r.portEntropy)),
            },
            {
              key: 'portEntropyOut',
              title: 'Энтропия портов исх.',
              num: true,
              width: 170,
              sortAccessor: byMetric('portEntropyOut'),
              render: metric('portEntropyOut', (r) => formatEntropy(r.portEntropyOut)),
            },
            {
              key: 'portsPerIp',
              title: 'Макс. портов/IP вх.',
              num: true,
              width: 165,
              sortAccessor: byMetric('portsPerIp'),
              render: metric('portsPerIp', (r) => formatPorts(r.portsPerIp)),
            },
            {
              key: 'portsPerIpOut',
              title: 'Макс. портов/IP исх.',
              num: true,
              width: 170,
              sortAccessor: byMetric('portsPerIpOut'),
              render: metric('portsPerIpOut', (r) => formatPorts(r.portsPerIpOut)),
            },
            {
              key: 'avgPacketBytes',
              title: 'Средний пакет',
              num: true,
              width: 130,
              sortAccessor: byMetric('avgPacketBytes'),
              render: metric('avgPacketBytes', (r) => `${formatNum(r.avgPacketBytes, 0)} Б`),
            },
            {
              key: 'cvPercent',
              title: 'CV',
              num: true,
              width: 90,
              sortAccessor: byMetric('cvPercent'),
              render: metric('cvPercent', (r) => (r.cvPercent == null ? '—' : `${formatNum(r.cvPercent, 1)}%`)),
            },
          ]}
        />
      </Card>
      )}
    </div>
  );
}

window.PageDetection = PageDetection;
