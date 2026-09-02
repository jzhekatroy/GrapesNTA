const { useState, useEffect, useCallback, useMemo } = React;

const PROTOS = ['all', 'tcp', 'udp'];
const PROTO_ORDER = { all: 0, tcp: 1, udp: 2 };
const PROTO_LABEL = { all: 'общее', tcp: 'TCP', udp: 'UDP' };
const PROTO_TONE = { all: 'neutral', tcp: 'info', udp: 'warning' };
const KIND_LABEL = {
  volumetric: 'атака в сервер',
  carpet: 'атака по сети',
  syn_flood: 'SYN-флуд',
  benign_peak: 'обычный пик',
};
const PAGE_TABS = [
  { id: 'table', label: 'Таблица' },
  { id: 'active', label: 'Активные' },
  { id: 'history', label: 'История' },
  { id: 'telegram', label: 'Telegram' },
];
const TELEGRAM_DEFAULTS = {
  enabled: false,
  chatId: '',
  growthThreshold: 1.6,
  alertScope: 'all',
  streak: 3,
  normalizeStreak: 3,
  apiUrl: 'https://api.telegram.org',
  tokenSet: false,
};
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
  const [eventsExporting, setEventsExporting] = useState(false);

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
    }
    return ApiClient.loadDetectionEvents(opts)
      .then(setEvents)
      .catch((e) => setEventsError(e.message))
      .finally(() => setEventsBusy(false));
  }, [historyBounds]);

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
        streak: telegram?.streak ?? 3,
        normalizeStreak: telegram?.normalizeStreak ?? 3,
        apiUrl: telegram?.apiUrl || 'https://api.telegram.org',
      };
      if (botToken.trim()) payload.botToken = botToken.trim();
      const data = await ApiClient.saveDetectionTelegramSettings(payload);
      setTelegram(data);
      setBotToken('');
      pushToast?.({ kind: 'success', title: 'Telegram сохранён' });
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
        subtitle="Алерт — X значений подряд выше порога (строка «общее»). Нормализация — Y значений подряд ниже. Повторный алерт — только после нормализации. Если nta не достучится до api.telegram.org — укажите локальный Bot API, например https://tba.pinspb.ru."
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
                <label className="col" style={{ gap: 4, minWidth: 180 }}>
                  <span>ID группы</span>
                  <input
                    className="input"
                    value={telegram?.chatId || ''}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { chatId: e.target.value }))}
                    placeholder="-100…"
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 120 }}>
                  <span>Порог роста</span>
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
                  <span>Объекты</span>
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
                <label className="col" style={{ gap: 4, minWidth: 160 }}>
                  <span>Подряд выше порога</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="60"
                    step="1"
                    value={telegram?.streak ?? 3}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { streak: Number(e.target.value) }))}
                  />
                </label>
                <label className="col" style={{ gap: 4, minWidth: 180 }}>
                  <span>Подряд ниже порога</span>
                  <input
                    className="input"
                    type="number"
                    min="1"
                    max="60"
                    step="1"
                    value={telegram?.normalizeStreak ?? 3}
                    onChange={(e) => setTelegram(patchTelegram(telegram, { normalizeStreak: Number(e.target.value) }))}
                  />
                </label>
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
            : 'Закрытые атаки и обычные пики. Фильтр по времени. В CSV — срез алерта и нормализации по всем протоколам.'}
          tools={(
            <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              {pageTab === 'history' && (
                <>
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
                      {r.scope === 'client' ? 'абонент' : 'сеть /24'}
                    </Badge>
                    {' '}
                    {r.name || r.scopeId}
                  </span>
                ),
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

      {pageTab === 'table' && (
      <Card
        title="Детекция"
        subtitle={data.minute
          ? `Минута ${formatWhen(data.minute)} · ${rows.length} объектов`
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
                    {r.scope === 'client' ? 'абонент' : 'сеть /24'}
                  </Badge>
                  {' '}
                  {r.name}
                </span>
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
