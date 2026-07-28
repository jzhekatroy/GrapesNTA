/* Custom SVG charts: AreaChart (time-series), Sparkline, Donut, BarList,
   HorizontalBars, Sankey (basic), WorldHeat (placeholder).
   All hand-rolled, no deps. */

function fluidChartStyle(height, width = 800) {
  return {
    '--chart-min-h': `${height}px`,
    '--chart-aspect': `${width} / ${height}`,
  };
}

/* ============== AreaChart ============== */
function AreaChart({ data, height = 240, color = 'var(--accent)', units = 'Гбит/с', hideAxis }) {
  // data: [{ t, v, v2? }] — v2 optional for stacked or secondary
  const w = 800, padL = 50, padR = 12, padT = 16, padB = 26;
  const h = height;
  const max = Math.max(...data.map((d) => Math.max(d.v, d.v2 || 0))) * 1.18 || 1;
  const x = (i) => padL + (i / (data.length - 1)) * (w - padL - padR);
  const y = (v) => padT + (1 - v / max) * (h - padT - padB);

  const linePts = data.map((d, i) => `${x(i)},${y(d.v)}`).join(' ');
  const areaPath = `M ${x(0)},${y(0)} L ${data.map((d, i) => `${x(i)},${y(d.v)}`).join(' L ')} L ${x(data.length - 1)},${y(0)} Z`;

  const yTicks = 4;
  const yVals = Array.from({length: yTicks + 1}, (_, i) => (max / yTicks) * i);

  const tEvery = Math.max(1, Math.floor(data.length / 6));

  const id = useMemo(() => 'g' + Math.random().toString(36).slice(2, 8), []);

  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{width: '100%', height: h, display: 'block'}}>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#7E92F8" stopOpacity="0.55" />
          <stop offset="100%" stopColor="#6972F0" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {!hideAxis && yVals.map((v, i) => (
        <g key={i}>
          <line x1={padL} x2={w - padR} y1={y(v)} y2={y(v)} stroke="var(--chart-grid)" />
          <text x={padL - 8} y={y(v) + 4} textAnchor="end" fontSize="10" fill="var(--fg-muted)" fontFamily="Mulish">
            {fmtCompact(v)}
          </text>
        </g>
      ))}
      <defs>
        <linearGradient id={`stroke${id}`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#7E92F8" />
          <stop offset="100%" stopColor="#6972F0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#${id})`} />
      <polyline points={linePts} fill="none" stroke={`url(#stroke${id})`} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      {!hideAxis && data.map((d, i) => i % tEvery === 0 && (
        <text key={i} x={x(i)} y={h - 6} textAnchor="middle" fontSize="10" fill="var(--fg-muted)" fontFamily="Mulish">{d.t}</text>
      ))}
    </svg>
  );
}

function chartPpsField(key) {
  return `${key}_pps`;
}

function getPointPps(pt, key) {
  const v = pt[chartPpsField(key)];
  if (v != null && v !== '') return Number(v) || 0;
  if (key === 'total' && pt.pps != null) return Number(pt.pps) || 0;
  return 0;
}

function chartSeriesNumber(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function chartSeriesValues(points, lines, getValue = (pt, key) => pt[key]) {
  if (!lines.length) return [];
  return points.flatMap((pt) => lines
    .map((ln) => chartSeriesNumber(getValue(pt, ln.key)))
    .filter((v) => v != null));
}

function buildChartPolylineSegments(points, xAt, yAt, getValue) {
  const segments = [];
  let current = [];
  points.forEach((pt, i) => {
    const value = getValue(pt);
    if (value == null) {
      if (current.length) {
        segments.push(current);
        current = [];
      }
      return;
    }
    current.push(`${xAt(i)},${yAt(value)}`);
  });
  if (current.length) segments.push(current);
  return segments;
}

function chartSeriesPps(pt, key) {
  const v = pt[chartPpsField(key)];
  if (v != null && v !== '') return chartSeriesNumber(v);
  if (key === 'total' && pt.pps != null) return chartSeriesNumber(pt.pps);
  return null;
}

function collectChartValueKeys(lines, extraKeys = []) {
  const keys = new Set(extraKeys);
  for (const ln of lines || []) {
    if (ln?.key) {
      keys.add(ln.key);
      keys.add(chartPpsField(ln.key));
    }
  }
  return [...keys];
}

function makeChartGapPlaceholder(bucketMs, valueKeys) {
  const bucket = msToBucketString(bucketMs);
  const pt = { bucket, bucketMs, t: null, _gap: true };
  for (const key of valueKeys) pt[key] = null;
  return pt;
}

function fillChartTimeGaps(points, { bucketSeconds, startMs, endMs, valueKeys = [], skipLeadingGaps = false } = {}) {
  if (!Array.isArray(points) || !points.length || !bucketSeconds) return points || [];

  const step = bucketSeconds * 1000;
  const sorted = [...points]
    .map((pt) => ({ pt, ms: resolvePointEpochMs(pt) }))
    .filter(({ ms }) => ms != null)
    .sort((a, b) => a.ms - b.ms);

  if (!sorted.length) return points;

  const anchorMs = sorted[0].ms;
  const byMs = new Map();
  for (const { pt, ms } of sorted) {
    const snapped = anchorMs + Math.round((ms - anchorMs) / step) * step;
    if (!byMs.has(snapped)) byMs.set(snapped, pt);
  }

  if (startMs != null && endMs != null && endMs > startMs) {
    const result = [];
    let ms;
    if (skipLeadingGaps && anchorMs > startMs) {
      // Rollup starts after window open — no leading gap placeholders.
      ms = anchorMs;
    } else {
      const delta = Math.ceil((startMs - anchorMs) / step);
      ms = anchorMs + delta * step;
    }
    while (ms <= endMs) {
      result.push(byMs.get(ms) || makeChartGapPlaceholder(ms, valueKeys));
      ms += step;
    }
    return result.length ? result : points;
  }

  const result = [];
  for (let i = 0; i < sorted.length; i += 1) {
    const { pt, ms } = sorted[i];
    result.push(pt);
    if (i >= sorted.length - 1) continue;
    const nextMs = sorted[i + 1].ms;
    let fillMs = ms + step;
    while (fillMs < nextMs) {
      result.push(makeChartGapPlaceholder(fillMs, valueKeys));
      fillMs += step;
    }
  }
  return result;
}

function buildChartTimeScale(data, padL, padR, w) {
  const n = data.length;
  const plotW = w - padL - padR;
  const startMs = resolvePointEpochMs(data[0]);
  const endMs = resolvePointEpochMs(data[n - 1]);
  const span = startMs != null && endMs != null ? endMs - startMs : 0;

  const xAtIndex = (i) => {
    if (n <= 1) return padL + plotW / 2;
    if (span <= 0) return padL + (i / (n - 1)) * plotW;
    const ms = resolvePointEpochMs(data[i]);
    if (ms == null) return padL;
    return padL + ((ms - startMs) / span) * plotW;
  };

  const indexFromClientX = (clientX, wrapRef) => {
    const el = wrapRef?.current;
    if (!el || !data.length) return null;
    const rect = el.getBoundingClientRect();
    if (!rect.width) return null;
    const vx = ((clientX - rect.left) / rect.width) * w;
    if (vx < padL || vx > w - padR) return null;
    if (n <= 1) return 0;
    if (span <= 0) {
      return Math.max(0, Math.min(n - 1, Math.round(((vx - padL) / plotW) * (n - 1))));
    }
    const targetMs = startMs + ((vx - padL) / plotW) * span;
    let bestIdx = 0;
    let bestDist = Infinity;
    for (let i = 0; i < n; i += 1) {
      const ms = resolvePointEpochMs(data[i]);
      if (ms == null) continue;
      const dist = Math.abs(ms - targetMs);
      if (dist < bestDist) {
        bestDist = dist;
        bestIdx = i;
      }
    }
    return bestIdx;
  };

  const selectionBandPct = (startIdx, endIdx) => {
    const lo = Math.min(startIdx, endIdx);
    const hi = Math.max(startIdx, endIdx);
    const xLo = xAtIndex(lo);
    const xHi = xAtIndex(hi);
    return {
      left: ((xLo - padL) / plotW) * 100,
      width: Math.max(((xHi - xLo) / plotW) * 100, 0),
    };
  };

  return { xAtIndex, indexFromClientX, selectionBandPct, startMs, endMs, n, plotW };
}

function buildChartAreaPathSegments(points, xAt, yAt, yZero, getValue) {
  const segments = [];
  let current = [];
  points.forEach((pt, i) => {
    const value = getValue(pt);
    if (value == null) {
      if (current.length) {
        segments.push(current);
        current = [];
      }
      return;
    }
    current.push({ i, value });
  });
  if (current.length) segments.push(current);

  return segments.map((seg) => {
    const first = seg[0];
    const last = seg[seg.length - 1];
    const top = seg.map(({ i, value }) => `${xAt(i)},${yAt(value)}`).join(' L ');
    return `M ${xAt(first.i)},${yZero} L ${top} L ${xAt(last.i)},${yZero} Z`;
  });
}

const CHART_TIP_LINE_ORDER = ['total', 'incoming', 'outgoing', 'transit', 'internal', 'unclassified'];

function sortLinesForTip(lines) {
  const rank = Object.fromEntries(CHART_TIP_LINE_ORDER.map((k, i) => [k, i]));
  return [...lines].sort((a, b) => (rank[a.key] ?? 99) - (rank[b.key] ?? 99));
}

function updateChartHoverIndex(clientX, indexFromClientX, setHoverIdx) {
  const idx = indexFromClientX(clientX);
  if (idx != null) setHoverIdx(idx);
}

function clearChartHoverIndex(setHoverIdx, blocked) {
  if (!blocked) setHoverIdx(null);
}

const CHART_PERIOD_MINUTES = {
  '15m': 15,
  '30m': 30,
  '1h': 60,
  '3h': 180,
  '6h': 360,
  '12h': 720,
  '24h': 1440,
  '2d': 2880,
  '7d': 10080,
  '14d': 20160,
  '30d': 43200,
};

const DATA_TIMEZONE = 'Europe/Moscow';
const TIMEZONE_STORAGE_KEY = 'grapes-display-timezone';

let dataTimezone = (typeof window !== 'undefined' && window.__GRAPES_RUNTIME__?.dataTimezone)
  || DATA_TIMEZONE;

function getDataTimezone() {
  return dataTimezone || DATA_TIMEZONE;
}

function setDataTimezone(timeZone) {
  if (timeZone) dataTimezone = String(timeZone);
}

function detectBrowserTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || DATA_TIMEZONE;
  } catch {
    return DATA_TIMEZONE;
  }
}

function loadTimezonePreference() {
  try {
    const raw = localStorage.getItem(TIMEZONE_STORAGE_KEY);
    if (!raw) return { mode: 'auto', timezone: detectBrowserTimezone() };
    const parsed = JSON.parse(raw);
    if (parsed?.mode === 'manual' && parsed?.timezone) {
      return { mode: 'manual', timezone: String(parsed.timezone) };
    }
    return { mode: 'auto', timezone: detectBrowserTimezone() };
  } catch {
    return { mode: 'auto', timezone: detectBrowserTimezone() };
  }
}

function saveTimezonePreference(pref) {
  displayTimezonePref = pref;
  try {
    localStorage.setItem(TIMEZONE_STORAGE_KEY, JSON.stringify(pref));
  } catch {
    /* ignore quota errors */
  }
}

function resolveDisplayTimezone(pref = displayTimezonePref) {
  if (pref?.mode === 'manual' && pref?.timezone) return pref.timezone;
  return detectBrowserTimezone();
}

function getDisplayTimezone() {
  return resolveDisplayTimezone(displayTimezonePref);
}

function setDisplayTimezonePreference(pref) {
  saveTimezonePreference(pref);
}

let displayTimezonePref = loadTimezonePreference();

function formatTimezoneShortLabel(timeZone = getDisplayTimezone()) {
  try {
    const parts = new Intl.DateTimeFormat('ru-RU', {
      timeZone,
      timeZoneName: 'shortOffset',
    }).formatToParts(new Date());
    const name = parts.find((p) => p.type === 'timeZoneName')?.value;
    if (name) return name.replace('GMT', 'UTC');
  } catch {
    /* ignore invalid timezone */
  }
  return String(timeZone || DATA_TIMEZONE);
}

function formatTimezoneLongLabel(timeZone = getDisplayTimezone()) {
  try {
    const parts = new Intl.DateTimeFormat('ru-RU', {
      timeZone,
      timeZoneName: 'longGeneric',
    }).formatToParts(new Date());
    const name = parts.find((p) => p.type === 'timeZoneName')?.value;
    if (name) return `${name} · ${formatTimezoneShortLabel(timeZone)}`;
  } catch {
    /* ignore invalid timezone */
  }
  return timeZone;
}

function intlPartsMs(ms, timeZone = getDataTimezone()) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).formatToParts(new Date(ms));
}

function pickIntlPart(parts, type) {
  return parts.find((p) => p.type === type)?.value ?? '00';
}

function msToBucketString(ms, timeZone = getDataTimezone()) {
  const parts = intlPartsMs(ms, timeZone);
  return `${pickIntlPart(parts, 'year')}-${pickIntlPart(parts, 'month')}-${pickIntlPart(parts, 'day')} `
    + `${pickIntlPart(parts, 'hour')}:${pickIntlPart(parts, 'minute')}:${pickIntlPart(parts, 'second')}`;
}

function msToDatetimeLocalValue(ms, timeZone = getDataTimezone()) {
  const parts = intlPartsMs(ms, timeZone);
  return `${pickIntlPart(parts, 'year')}-${pickIntlPart(parts, 'month')}-${pickIntlPart(parts, 'day')}T`
    + `${pickIntlPart(parts, 'hour')}:${pickIntlPart(parts, 'minute')}`;
}

function normalizeBucketString(bucket) {
  if (bucket == null || bucket === '') return '';
  const s = String(bucket).trim();
  if (s.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(s)) {
    const ms = new Date(s).getTime();
    return Number.isFinite(ms) ? msToBucketString(ms) : '';
  }
  const m = s.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(?::(\d{2}))?/);
  if (m) return `${m[1]} ${m[2]}:${m[3] || '00'}`;
  return s.slice(0, 19).replace('T', ' ');
}

function parseBucketWallParts(bucket) {
  const normalized = normalizeBucketString(bucket);
  const m = normalized.match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return null;
  return {
    y: Number(m[1]),
    mo: Number(m[2]),
    d: Number(m[3]),
    h: Number(m[4]),
    mi: Number(m[5]),
    s: Number(m[6]) || 0,
  };
}

function wallPartsToMs(parts, timeZone = getDataTimezone()) {
  if (!parts) return null;
  const pad = (n) => String(n).padStart(2, '0');
  const target = `${parts.y}-${pad(parts.mo)}-${pad(parts.d)} ${pad(parts.h)}:${pad(parts.mi)}:${pad(parts.s)}`;
  const anchor = Date.UTC(parts.y, parts.mo - 1, parts.d, parts.h, parts.mi, parts.s);
  let lo = anchor - 36 * 3600000;
  let hi = anchor + 36 * 3600000;
  for (let i = 0; i < 48; i += 1) {
    const mid = Math.floor((lo + hi) / 2);
    const got = msToBucketString(mid, timeZone);
    if (got === target) return mid;
    if (got < target) lo = mid + 1;
    else hi = mid - 1;
  }
  return anchor;
}

function bucketWallToMs(bucket, dataTimeZone = getDataTimezone()) {
  return wallPartsToMs(parseBucketWallParts(bucket), dataTimeZone);
}

function resolvePointEpochMs(point) {
  if (point?.bucketMs != null && Number.isFinite(Number(point.bucketMs))) {
    return Number(point.bucketMs);
  }
  const bucket = point?.bucket || point?._raw?.bucket;
  if (bucket) return bucketWallToMs(bucket, getDataTimezone());
  return null;
}

function formatMsLabel(ms, longRange, displayTimeZone = getDisplayTimezone()) {
  if (ms == null || !Number.isFinite(Number(ms))) return '—';
  const parts = intlPartsMs(Number(ms), displayTimeZone);
  const day = pickIntlPart(parts, 'day');
  const month = pickIntlPart(parts, 'month');
  const hour = pickIntlPart(parts, 'hour');
  const minute = pickIntlPart(parts, 'minute');
  if (longRange) return `${day}.${month} ${hour}:${minute}`;
  return `${hour}:${minute}`;
}

function formatPointTimeLabel(point, longRange, displayTimeZone = getDisplayTimezone()) {
  const ms = resolvePointEpochMs(point);
  if (ms == null) return '—';
  return formatMsLabel(ms, longRange, displayTimeZone);
}

function formatBucketLabel(bucket, longRange, displayTimeZone = getDisplayTimezone(), bucketMs = null) {
  const ms = bucketMs != null && Number.isFinite(Number(bucketMs))
    ? Number(bucketMs)
    : resolvePointEpochMs({ bucket, bucketMs });
  if (ms == null) return '—';
  return formatMsLabel(ms, longRange, displayTimeZone);
}

function formatTipPointTime(point, displayTimeZone = getDisplayTimezone()) {
  const ms = resolvePointEpochMs(point);
  if (ms == null) return point?.t || '—';
  const parts = intlPartsMs(Number(ms), displayTimeZone);
  const day = pickIntlPart(parts, 'day');
  const month = pickIntlPart(parts, 'month');
  const year = pickIntlPart(parts, 'year');
  const hour = pickIntlPart(parts, 'hour');
  const minute = pickIntlPart(parts, 'minute');
  return `${day}.${month}.${year} ${hour}:${minute}`;
}

function formatTipBucketDuration(bucketSeconds) {
  if (!bucketSeconds || bucketSeconds <= 0) return null;
  if (bucketSeconds === 60) return '1 мин';
  if (bucketSeconds === 300) return '5 мин';
  if (bucketSeconds === 3600) return '1 ч';
  if (bucketSeconds % 3600 === 0) return `${bucketSeconds / 3600} ч`;
  if (bucketSeconds % 60 === 0) return `${bucketSeconds / 60} мин`;
  return `${bucketSeconds} с`;
}

function dataDatetimeLocalToDisplay(value, displayTimeZone = getDisplayTimezone(), dataTimeZone = getDataTimezone()) {
  if (!value) return '';
  const ms = wallPartsToMs(parseBucketWallParts(String(value).replace('T', ' ')), dataTimeZone);
  if (ms == null) return String(value);
  return msToDatetimeLocalValue(ms, displayTimeZone);
}

function displayDatetimeLocalToData(value, displayTimeZone = getDisplayTimezone(), dataTimeZone = getDataTimezone()) {
  if (!value) return '';
  const ms = wallPartsToMs(parseBucketWallParts(String(value).replace('T', ' ')), displayTimeZone);
  if (ms == null) return String(value);
  return msToDatetimeLocalValue(ms, dataTimeZone);
}

function bucketToDatetimeLocalInput(bucket, addSeconds = 0) {
  const parts = parseBucketWallParts(bucket);
  if (!parts) return '';
  let { y, mo, d, h, mi, s } = parts;
  s += addSeconds;
  while (s >= 60) { s -= 60; mi += 1; }
  while (mi >= 60) { mi -= 60; h += 1; }
  while (h >= 24) { h -= 24; d += 1; }
  const pad = (n) => String(n).padStart(2, '0');
  return `${y}-${pad(mo)}-${pad(d)}T${pad(h)}:${pad(mi)}`;
}

function parseChartBucketMs(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  return bucketWallToMs(value, getDataTimezone());
}

function customPeriodSpanMs(customPeriod) {
  if (!customPeriod?.from || !customPeriod?.to) return null;
  const displayTz = getDisplayTimezone();
  const fromMs = wallPartsToMs(parseBucketWallParts(String(customPeriod.from).replace('T', ' ')), displayTz);
  const toMs = wallPartsToMs(parseBucketWallParts(String(customPeriod.to).replace('T', ' ')), displayTz);
  if (fromMs == null || toMs == null) return null;
  return toMs - fromMs;
}

function isLongChartRange(timeRange, customPeriod) {
  if (timeRange === 'custom') {
    const span = customPeriodSpanMs(customPeriod);
    return span != null && span > 24 * 60 * 60 * 1000;
  }
  return (CHART_PERIOD_MINUTES[timeRange] || 0) > 1440;
}

function formatChartPointTimeLabel(ms, longRange, displayTimeZone = getDisplayTimezone()) {
  if (ms == null || !Number.isFinite(Number(ms))) return '—';
  return formatMsLabel(Number(ms), longRange, displayTimeZone);
}

function chartPointToDatetimeLocal(date, timeZone = getDataTimezone()) {
  const ms = date instanceof Date ? date.getTime() : new Date(date).getTime();
  if (!Number.isFinite(ms)) return '';
  return msToDatetimeLocalValue(ms, timeZone);
}

function computeChartPeriodBounds(timeRange, customPeriod) {
  const now = Date.now();
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    const displayTz = getDisplayTimezone();
    const startMs = wallPartsToMs(parseBucketWallParts(String(customPeriod.from).replace('T', ' ')), displayTz);
    const endMs = wallPartsToMs(parseBucketWallParts(String(customPeriod.to).replace('T', ' ')), displayTz);
    if (startMs != null && endMs != null && endMs > startMs) {
      return { startMs, endMs };
    }
  }
  const minutes = CHART_PERIOD_MINUTES[timeRange] || 1440;
  return { startMs: now - minutes * 60 * 1000, endMs: now };
}

function resolvePointTimeMs(points, index) {
  const pt = points[index];
  if (pt?.bucketMs != null && Number.isFinite(Number(pt.bucketMs))) {
    return Number(pt.bucketMs);
  }
  const direct = parseChartBucketMs(pt?.bucket || pt?._raw?.bucket);
  if (direct != null) return direct;
  if (!points.length) return null;
  const firstMs = Number(points[0]?.bucketMs) || parseChartBucketMs(points[0]?.bucket || points[0]?._raw?.bucket);
  const lastMs = Number(points[points.length - 1]?.bucketMs)
    || parseChartBucketMs(points[points.length - 1]?.bucket || points[points.length - 1]?._raw?.bucket);
  if (firstMs != null && lastMs != null && points.length > 1) {
    return firstMs + (index / (points.length - 1)) * (lastMs - firstMs);
  }
  if (firstMs != null && points.length === 1) return firstMs;
  return null;
}

function parsePointChartLabel(label) {
  const s = String(label || '').trim();
  let m = s.match(/^(\d{2}):(\d{2})$/);
  if (m) return { h: Number(m[1]), mi: Number(m[2]), longRange: false };
  m = s.match(/^(\d{2})\.(\d{2})\s+(\d{2}):(\d{2})$/);
  if (m) return { d: Number(m[1]), mo: Number(m[2]), h: Number(m[3]), mi: Number(m[4]), longRange: true };
  return null;
}

function pointSelectionDatetimeLocal(point, displayTimeZone = getDisplayTimezone()) {
  const ms = resolvePointEpochMs(point);
  if (ms == null) return '';
  const parsed = parsePointChartLabel(point?.t);
  if (!parsed) return msToDatetimeLocalValue(ms, displayTimeZone);
  const parts = intlPartsMs(ms, displayTimeZone);
  const y = pickIntlPart(parts, 'year');
  const mo = parsed.longRange ? String(parsed.mo).padStart(2, '0') : pickIntlPart(parts, 'month');
  const d = parsed.longRange ? String(parsed.d).padStart(2, '0') : pickIntlPart(parts, 'day');
  const h = String(parsed.h).padStart(2, '0');
  const mi = String(parsed.mi).padStart(2, '0');
  return `${y}-${mo}-${d}T${h}:${mi}`;
}

function addWallSecondsToDatetimeLocal(dateTimeLocal, seconds, displayTimeZone = getDisplayTimezone()) {
  if (!dateTimeLocal) return '';
  const ms = wallPartsToMs(parseBucketWallParts(String(dateTimeLocal).replace('T', ' ')), displayTimeZone);
  if (ms == null) return '';
  return msToDatetimeLocalValue(ms + seconds * 1000, displayTimeZone);
}

function chartRangeFromPointSelection(points, startIdx, endIdx, bucketSeconds = 300, displayTimeZone = getDisplayTimezone()) {
  if (!Array.isArray(points) || !points.length) return null;
  const lo = Math.max(0, Math.min(startIdx, endIdx));
  const hi = Math.min(points.length - 1, Math.max(startIdx, endIdx));
  const tz = displayTimeZone || getDisplayTimezone();
  const startMs = resolvePointEpochMs(points[lo]);
  const endMs = resolvePointEpochMs(points[hi]);
  if (startMs == null || endMs == null) return null;
  const from = pointSelectionDatetimeLocal(points[lo], tz);
  const to = addWallSecondsToDatetimeLocal(pointSelectionDatetimeLocal(points[hi], tz), bucketSeconds, tz);
  if (!from || !to || from >= to) return null;
  return { from, to };
}

function chartTipClassName({ rich = false, translucent = false, opaque = false, toggle = false, extra = '' } = {}) {
  return [
    'dual-chart__tip',
    rich && 'dual-chart__tip--rich',
    translucent && 'dual-chart__tip--translucent',
    opaque && 'dual-chart__tip--opaque',
    toggle && 'dual-chart__tip--toggle',
    extra,
  ].filter(Boolean).join(' ');
}

function ChartHoverTip({
  style,
  rich = false,
  extra = '',
  translucentToggle = false,
  children,
}) {
  const [translucent, setTranslucent] = useState(false);
  const isTranslucent = translucentToggle && translucent;
  const surfaceStyle = translucentToggle
    ? (isTranslucent
      ? {
          backgroundColor: 'var(--chart-tip-translucent-bg)',
          borderColor: 'var(--chart-tip-translucent-border)',
          backdropFilter: 'none',
          WebkitBackdropFilter: 'none',
        }
      : {
          backgroundColor: 'var(--bg-surface-3)',
          borderColor: 'var(--bd-strong)',
          backdropFilter: 'none',
          WebkitBackdropFilter: 'none',
        })
    : null;
  return (
    <div
      className={chartTipClassName({
        rich,
        extra,
        translucent: isTranslucent,
        opaque: translucentToggle && !translucent,
        toggle: translucentToggle,
      })}
      style={surfaceStyle ? { ...style, ...surfaceStyle } : style}
      onClick={translucentToggle ? (e) => { e.stopPropagation(); setTranslucent((v) => !v); } : undefined}
      onMouseDown={translucentToggle ? (e) => e.stopPropagation() : undefined}
    >
      {children}
      {translucentToggle && (
        <div className="dual-chart__tip-hint">
          {isTranslucent ? 'Клик — отключить прозрачность' : 'Клик — включить прозрачность'}
        </div>
      )}
    </div>
  );
}

/* Traffic chart: bandwidth (bw) or packets/s (pps) by direction */
function DualChart({
  points = [],
  lines = [],
  ppsLines,
  height = 280,
  mode = 'bw',
  onRangeSelect,
  bucketSeconds = 300,
  displayTimezone,
  periodStartMs,
  periodEndMs,
  skipLeadingGaps = false,
  valueFormatter = fmtBits,
  axisFormatter = fmtCompact,
  ppsFormatter = fmtNum,
  tipUnitLabel,
  tipBucketLabel,
  tipTimeFormatter,
  tipTranslucent = false,
  yAxisLabel,
  yAxisUnit,
}) {
  const wrapRef = useRef(null);
  const dragRef = useRef(null);
  const [hoverIdx, setHoverIdx] = useState(null);
  const [selection, setSelection] = useState(null);

  const isPps = mode === 'pps';
  const activeLines = isPps ? [] : lines;
  const ppsSeries = ppsLines != null ? ppsLines : lines;
  const activePpsLines = isPps ? ppsSeries : [];
  const valueKeys = useMemo(
    () => collectChartValueKeys(lines, ['pps']),
    [lines.map((ln) => ln.key).join(',')],
  );
  const data = useMemo(
    () => fillChartTimeGaps(points, {
      bucketSeconds,
      startMs: periodStartMs,
      endMs: periodEndMs,
      valueKeys,
      skipLeadingGaps,
    }),
    [points, bucketSeconds, periodStartMs, periodEndMs, valueKeys.join(','), skipLeadingGaps],
  );

  const w = 800;
  const yAxisTitlePad = yAxisLabel || yAxisUnit ? 28 : 0;
  const padL = 68 + yAxisTitlePad;
  const padR = 12;
  const padT = 20;
  const padB = 28;
  const h = height;
  const bwValues = chartSeriesValues(data, activeLines);
  const ppsValues = activePpsLines.length
    ? data.flatMap((pt) => activePpsLines
      .map((ln) => chartSeriesPps(pt, ln.key))
      .filter((v) => v != null))
    : [];
  const max1 = bwValues.length ? Math.max(...bwValues) * 1.15 || 1 : 1;
  const max2 = ppsValues.length ? Math.max(...ppsValues) * 1.15 || 1 : 1;
  const n = Math.max(data.length, 1);
  const timeScale = data.length > 1 ? buildChartTimeScale(data, padL, padR, w) : null;
  const x = timeScale ? (i) => timeScale.xAtIndex(i) : () => padL;
  const y1 = (v) => padT + (1 - v / max1) * (h - padT - padB);
  const y2 = (v) => padT + (1 - v / max2) * (h - padT - padB);
  const yScale = isPps ? y2 : y1;
  const maxScale = isPps ? max2 : max1;
  const tEvery = Math.max(1, Math.floor(n / 8));
  const yTicks = 4;
  const selectable = typeof onRangeSelect === 'function' && data.length > 1;
  const tz = displayTimezone || getDisplayTimezone();
  const startMs = timeScale?.startMs ?? (data.length ? resolvePointEpochMs(data[0]) : null);
  const endMs = timeScale?.endMs ?? (data.length ? resolvePointEpochMs(data[data.length - 1]) : null);
  const longRange = startMs != null && endMs != null && (endMs - startMs) > 24 * 3600000;

  const indexFromClientX = (clientX) => {
    if (timeScale) return timeScale.indexFromClientX(clientX, wrapRef);
    const el = wrapRef.current;
    if (!el || !data.length) return null;
    const rect = el.getBoundingClientRect();
    if (!rect.width) return null;
    const vx = ((clientX - rect.left) / rect.width) * w;
    if (vx < padL || vx > w - padR) return null;
    return 0;
  };

  const hoverPoint = !selection && hoverIdx != null ? data[hoverIdx] : null;
  const tipPct = hoverIdx != null && n > 0 ? (x(hoverIdx) / w) * 100 : 50;
  const tipAlign = tipPct > 72 ? 'end' : tipPct < 20 ? 'start' : 'center';
  const tipStyle = {
    left: `${tipPct}%`,
    transform: tipAlign === 'end' ? 'translateX(calc(-100% - 8px))' : tipAlign === 'start' ? 'translateX(8px)' : 'translateX(-50%)',
  };

  const onChartMouseMove = (e) => {
    if (dragRef.current) {
      const idx = indexFromClientX(e.clientX);
      if (idx == null) return;
      dragRef.current.currentIdx = idx;
      setSelection({ start: dragRef.current.startIdx, end: idx });
      return;
    }
    updateChartHoverIndex(e.clientX, indexFromClientX, setHoverIdx);
  };

  const finishDrag = () => {
    const drag = dragRef.current;
    dragRef.current = null;
    if (!drag || !selectable) {
      setSelection(null);
      return;
    }
    const endIdx = drag.currentIdx ?? drag.startIdx;
    setSelection(null);
    const movedPx = Math.abs(drag.lastX - drag.startX);
    if (movedPx < 4) return;
    const range = chartRangeFromPointSelection(data, drag.startIdx, endIdx, bucketSeconds, tz);
    if (range) onRangeSelect(range);
  };

  const onChartMouseDown = (e) => {
    if (!selectable || e.button !== 0) return;
    const idx = indexFromClientX(e.clientX);
    if (idx == null) return;
    e.preventDefault();
    dragRef.current = {
      startIdx: idx,
      currentIdx: idx,
      startX: e.clientX,
      lastX: e.clientX,
    };
    setSelection({ start: idx, end: idx });
    setHoverIdx(null);

    const onMove = (ev) => {
      if (!dragRef.current) return;
      dragRef.current.lastX = ev.clientX;
      const nextIdx = indexFromClientX(ev.clientX);
      if (nextIdx == null) return;
      dragRef.current.currentIdx = nextIdx;
      setSelection({ start: dragRef.current.startIdx, end: nextIdx });
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      finishDrag();
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  const onChartMouseLeave = () => {
    clearChartHoverIndex(setHoverIdx, dragRef.current);
  };

  const selectionBand = selection && timeScale
    ? timeScale.selectionBandPct(selection.start, selection.end)
    : null;
  const chartPadLeftPct = (padL / w) * 100;
  const chartPadRightPct = (padR / w) * 100;
  const chartPlotWidthPct = 100 - chartPadLeftPct - chartPadRightPct;
  const tipTimeLabel = hoverPoint
    ? (tipTimeFormatter
      ? tipTimeFormatter(hoverPoint)
      : (resolvePointEpochMs(hoverPoint) != null
        ? formatTipPointTime(hoverPoint, tz)
        : formatPointTimeLabel(hoverPoint, longRange, tz)))
    : '';
  const tipBucket = tipBucketLabel ?? (tipUnitLabel ? formatTipBucketDuration(bucketSeconds) : null);
  const tipMeta = hoverPoint && (tipBucket || tipUnitLabel)
    ? [tipBucket ? `интервал ${tipBucket}` : null, tipUnitLabel || null].filter(Boolean).join(' · ')
    : null;

  return (
    <div
      ref={wrapRef}
      className={`dual-chart dual-chart--fluid${selectable ? ' dual-chart--selectable' : ''}${selection ? ' dual-chart--dragging' : ''}`}
      style={{
        ...fluidChartStyle(height),
        ...(yAxisLabel || yAxisUnit ? {
          '--dual-chart-y-title-w': `${(yAxisTitlePad / w) * 100}%`,
          '--dual-chart-pad-t': `${(padT / h) * 100}%`,
          '--dual-chart-pad-b': `${(padB / h) * 100}%`,
        } : {}),
      }}
      onMouseMove={onChartMouseMove}
      onMouseLeave={onChartMouseLeave}
      onMouseDown={onChartMouseDown}
    >
      {(yAxisLabel || yAxisUnit) && (
        <div className="dual-chart__y-axis-title" aria-hidden="true">
          <div className="dual-chart__y-axis-title-inner">
            {[yAxisLabel, yAxisUnit].filter(Boolean).join('\n')}
          </div>
        </div>
      )}
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" overflow="visible" className="dual-chart__svg">
        {Array.from({length: yTicks + 1}, (_, i) => {
          const vLeft = (maxScale / yTicks) * i;
          const yy = yScale(vLeft);
          return (
            <g key={i}>
              <line x1={padL} x2={w - padR} y1={yy} y2={yy} stroke="rgba(255,255,255,0.05)" />
              <text x={padL - 8} y={yy + 4} textAnchor="end" fontSize="10" fill="var(--fg-muted)" fontFamily="Mulish">{axisFormatter(vLeft)}</text>
            </g>
          );
        })}
        {activeLines.map((ln) => {
          const segments = buildChartPolylineSegments(
            data,
            x,
            y1,
            (pt) => chartSeriesNumber(pt[ln.key]),
          );
          const isTotal = ln.key === 'total';
          return segments.map((pts, segmentIdx) => (
            <polyline
              key={`${ln.key}-${segmentIdx}`}
              points={pts.join(' ')}
              fill="none"
              stroke={ln.color}
              strokeWidth={isTotal ? 2.5 : 1.75}
              strokeLinejoin="round"
              strokeLinecap="round"
              opacity={isTotal ? 1 : 0.9}
            />
          ));
        })}
        {activePpsLines.map((ln) => {
          const segments = buildChartPolylineSegments(
            data,
            x,
            y2,
            (pt) => chartSeriesPps(pt, ln.key),
          );
          const isTotal = ln.key === 'total';
          return segments.map((pts, segmentIdx) => (
            <polyline
              key={`pps-${ln.key}-${segmentIdx}`}
              points={pts.join(' ')}
              fill="none"
              stroke={ln.color}
              strokeWidth={isTotal ? 2.5 : 2}
              strokeLinejoin="round"
              strokeLinecap="round"
              opacity={isTotal ? 1 : 0.9}
            />
          ));
        })}
        {hoverPoint && (
          <g pointerEvents="none">
            <line
              x1={x(hoverIdx)}
              x2={x(hoverIdx)}
              y1={padT}
              y2={h - padB}
              stroke="rgba(255,255,255,0.28)"
              strokeWidth="1"
              strokeDasharray="4 3"
            />
            {activeLines.map((ln) => {
              const v = chartSeriesNumber(hoverPoint[ln.key]);
              if (v == null) return null;
              return (
              <circle
                key={ln.key}
                cx={x(hoverIdx)}
                cy={y1(v)}
                r={4}
                fill={ln.color}
                stroke="#14131F"
                strokeWidth="1.5"
              />
              );
            })}
            {activePpsLines.map((ln) => {
              const v = chartSeriesPps(hoverPoint, ln.key);
              if (v == null) return null;
              return (
              <circle
                key={`pps-${ln.key}`}
                cx={x(hoverIdx)}
                cy={y2(v)}
                r={4}
                fill={ln.color}
                stroke="#14131F"
                strokeWidth="1.5"
              />
              );
            })}
          </g>
        )}
        {data.map((pt, i) => i % tEvery === 0 && (
          <text key={i} x={x(i)} y={h - 6} textAnchor="middle" fontSize="10" fill="var(--fg-muted)" fontFamily="Mulish">
            {resolvePointEpochMs(pt) != null ? formatPointTimeLabel(pt, longRange, tz) : pt.t}
          </text>
        ))}
      </svg>
      {selectionBand && (
        <div
          className="dual-chart__selection"
          style={{
            left: `calc(${chartPadLeftPct}% + ${(selectionBand.left / 100) * chartPlotWidthPct}%)`,
            width: `${Math.max((selectionBand.width / 100) * chartPlotWidthPct, 0.4)}%`,
          }}
        />
      )}
      {hoverPoint && (
        <ChartHoverTip
          style={tipStyle}
          rich={!!tipMeta}
          translucentToggle={tipTranslucent}
        >
          <div className="dual-chart__tip-time">{tipTimeLabel}</div>
          {tipMeta && <div className="dual-chart__tip-meta">{tipMeta}</div>}
          {sortLinesForTip(activeLines).map((ln) => (
            <div key={ln.key} className="dual-chart__tip-row">
              <span className="dual-chart__tip-swatch" style={{ background: ln.color }} />
              <span className="dual-chart__tip-label">{ln.label}</span>
              <span className="dual-chart__tip-val mono">
                {valueFormatter(chartSeriesNumber(hoverPoint[ln.key]))}
              </span>
            </div>
          ))}
          {sortLinesForTip(activePpsLines).map((ln) => (
            <div key={`pps-${ln.key}`} className="dual-chart__tip-row">
              <span className="dual-chart__tip-swatch" style={{ background: ln.color }} />
              <span className="dual-chart__tip-label">{ln.label}, п/с</span>
              <span className="dual-chart__tip-val mono">{ppsFormatter(chartSeriesPps(hoverPoint, ln.key))}</span>
            </div>
          ))}
        </ChartHoverTip>
      )}
    </div>
  );
}

/* Compact multi-line chart for protocol/service trends on dashboard. */
function CategoryTrendChart({
  points = [],
  lines = [],
  height = 190,
  bucketSeconds = 300,
  displayTimezone,
  onRangeSelect,
  periodStartMs,
  periodEndMs,
  tipTranslucent = false,
}) {
  const wrapRef = useRef(null);
  const dragRef = useRef(null);
  const [hoverIdx, setHoverIdx] = useState(null);
  const [selection, setSelection] = useState(null);
  const [hidden, setHidden] = useState(() => new Set());

  const visibleLines = lines.filter((ln) => !hidden.has(ln.key));
  const valueKeys = useMemo(
    () => collectChartValueKeys(lines),
    [lines.map((ln) => ln.key).join(',')],
  );
  const chartPoints = useMemo(
    () => fillChartTimeGaps(points, {
      bucketSeconds,
      startMs: periodStartMs,
      endMs: periodEndMs,
      valueKeys,
    }),
    [points, bucketSeconds, periodStartMs, periodEndMs, valueKeys.join(',')],
  );
  const w = 800;
  const padL = 48;
  const padR = 8;
  const padT = 16;
  const padB = 24;
  const h = height;
  const values = visibleLines.length
    ? chartPoints.flatMap((pt) => visibleLines
      .map((ln) => chartSeriesNumber(pt[ln.key]))
      .filter((v) => v != null))
    : [];
  const max = values.length ? Math.max(...values) * 1.15 || 1 : 1;
  const n = Math.max(chartPoints.length, 1);
  const timeScale = chartPoints.length > 1 ? buildChartTimeScale(chartPoints, padL, padR, w) : null;
  const x = timeScale ? (i) => timeScale.xAtIndex(i) : () => padL;
  const y = (v) => padT + (1 - v / max) * (h - padT - padB);
  const tEvery = Math.max(1, Math.floor(n / 6));
  const yTicks = 3;
  const tz = displayTimezone || getDisplayTimezone();
  const selectable = typeof onRangeSelect === 'function' && chartPoints.length > 1;
  const startMs = timeScale?.startMs ?? (chartPoints.length ? resolvePointEpochMs(chartPoints[0]) : null);
  const endMs = timeScale?.endMs ?? (chartPoints.length ? resolvePointEpochMs(chartPoints[chartPoints.length - 1]) : null);
  const longRange = startMs != null && endMs != null && (endMs - startMs) > 24 * 3600000;

  const indexFromClientX = (clientX) => {
    if (timeScale) return timeScale.indexFromClientX(clientX, wrapRef);
    return null;
  };

  const hoverPoint = !selection && hoverIdx != null ? chartPoints[hoverIdx] : null;
  const tipPct = hoverIdx != null && n > 0 ? (x(hoverIdx) / w) * 100 : 50;
  const tipAlign = tipPct > 72 ? 'end' : tipPct < 20 ? 'start' : 'center';
  const tipStyle = {
    left: `${tipPct}%`,
    transform: tipAlign === 'end' ? 'translateX(calc(-100% - 8px))' : tipAlign === 'start' ? 'translateX(8px)' : 'translateX(-50%)',
  };

  const onChartMouseMove = (e) => {
    if (dragRef.current) {
      const idx = indexFromClientX(e.clientX);
      if (idx == null) return;
      dragRef.current.currentIdx = idx;
      setSelection({ start: dragRef.current.startIdx, end: idx });
      return;
    }
    updateChartHoverIndex(e.clientX, indexFromClientX, setHoverIdx);
  };

  const finishDrag = () => {
    const drag = dragRef.current;
    dragRef.current = null;
    if (!drag || !selectable) {
      setSelection(null);
      return;
    }
    const endIdx = drag.currentIdx ?? drag.startIdx;
    setSelection(null);
    const movedPx = Math.abs(drag.lastX - drag.startX);
    if (movedPx < 4) return;
    const range = chartRangeFromPointSelection(chartPoints, drag.startIdx, endIdx, bucketSeconds, tz);
    if (range) onRangeSelect(range);
  };

  const onChartMouseDown = (e) => {
    if (!selectable || e.button !== 0) return;
    const idx = indexFromClientX(e.clientX);
    if (idx == null) return;
    e.preventDefault();
    dragRef.current = {
      startIdx: idx,
      currentIdx: idx,
      startX: e.clientX,
      lastX: e.clientX,
    };
    setSelection({ start: idx, end: idx });
    setHoverIdx(null);

    const onMove = (ev) => {
      if (!dragRef.current) return;
      dragRef.current.lastX = ev.clientX;
      const nextIdx = indexFromClientX(ev.clientX);
      if (nextIdx == null) return;
      dragRef.current.currentIdx = nextIdx;
      setSelection({ start: dragRef.current.startIdx, end: nextIdx });
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      finishDrag();
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  const onChartMouseLeave = () => {
    clearChartHoverIndex(setHoverIdx, dragRef.current);
  };

  const selectionBand = selection && timeScale
    ? timeScale.selectionBandPct(selection.start, selection.end)
    : null;
  const chartPadLeftPct = (padL / w) * 100;
  const chartPadRightPct = (padR / w) * 100;
  const chartPlotWidthPct = 100 - chartPadLeftPct - chartPadRightPct;

  const toggleLine = (key) => {
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  useEffect(() => {
    setHidden(new Set());
  }, [lines.map((ln) => ln.key).join(',')]);

  if (!points.length || !lines.length) {
    return <div className="category-trend__empty">Нет данных за выбранный период</div>;
  }

  return (
    <div className="category-trend">
      <div
        ref={wrapRef}
        className={`category-trend__chart dual-chart dual-chart--fluid${selectable ? ' dual-chart--selectable' : ''}${selection ? ' dual-chart--dragging' : ''}`}
        style={fluidChartStyle(height)}
        onMouseMove={onChartMouseMove}
        onMouseLeave={onChartMouseLeave}
        onMouseDown={onChartMouseDown}
      >
        <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="dual-chart__svg">
          {Array.from({ length: yTicks + 1 }, (_, i) => {
            const vLeft = (max / yTicks) * i;
            const yy = y(vLeft);
            return (
              <g key={i}>
                <line x1={padL} x2={w - padR} y1={yy} y2={yy} stroke="rgba(255,255,255,0.05)" />
                <text x={padL - 6} y={yy + 4} textAnchor="end" fontSize="9" fill="var(--fg-muted)" fontFamily="Mulish">{fmtCompact(vLeft)}</text>
              </g>
            );
          })}
          {visibleLines.map((ln) => {
            const segments = buildChartPolylineSegments(
              chartPoints,
              x,
              y,
              (pt) => chartSeriesNumber(pt[ln.key]),
            );
            return segments.map((pts, segmentIdx) => (
              <polyline
                key={`${ln.key}-${segmentIdx}`}
                points={pts.join(' ')}
                fill="none"
                stroke={ln.color}
                strokeWidth="1.75"
                strokeLinejoin="round"
                strokeLinecap="round"
              />
            ));
          })}
          {hoverPoint && (
            <g pointerEvents="none">
              <line
                x1={x(hoverIdx)}
                x2={x(hoverIdx)}
                y1={padT}
                y2={h - padB}
                stroke="rgba(255,255,255,0.28)"
                strokeWidth="1"
                strokeDasharray="4 3"
              />
              {visibleLines.map((ln) => {
                const v = chartSeriesNumber(hoverPoint[ln.key]);
                if (v == null) return null;
                return (
                <circle
                  key={ln.key}
                  cx={x(hoverIdx)}
                  cy={y(v)}
                  r="3.5"
                  fill={ln.color}
                  stroke="#14131F"
                  strokeWidth="1.5"
                />
                );
              })}
            </g>
          )}
          {chartPoints.map((pt, i) => i % tEvery === 0 && (
            <text key={i} x={x(i)} y={h - 4} textAnchor="middle" fontSize="9" fill="var(--fg-muted)" fontFamily="Mulish">
              {resolvePointEpochMs(pt) != null ? formatPointTimeLabel(pt, longRange, tz) : pt.t}
            </text>
          ))}
        </svg>
        {selectionBand && (
          <div
            className="dual-chart__selection"
            style={{
              left: `calc(${chartPadLeftPct}% + ${(selectionBand.left / 100) * chartPlotWidthPct}%)`,
              width: `${Math.max((selectionBand.width / 100) * chartPlotWidthPct, 0.4)}%`,
            }}
          />
        )}
        {hoverPoint && (
          <ChartHoverTip
            style={tipStyle}
            extra="category-trend__tip"
            translucentToggle={tipTranslucent}
          >
            <div className="dual-chart__tip-time">
              {resolvePointEpochMs(hoverPoint) != null
                ? formatTipPointTime(hoverPoint, tz)
                : formatPointTimeLabel(hoverPoint, longRange, tz)}
            </div>
            {sortLinesForTip(visibleLines).map((ln) => (
              <div key={ln.key} className="dual-chart__tip-row">
                <span className="dual-chart__tip-swatch" style={{ background: ln.color }} />
                <span className="dual-chart__tip-label">{ln.label}</span>
                <span className="dual-chart__tip-val mono">{fmtBits(chartSeriesNumber(hoverPoint[ln.key]))}</span>
              </div>
            ))}
          </ChartHoverTip>
        )}
      </div>
      <div className="category-trend__legend">
        {lines.map((ln) => {
          const off = hidden.has(ln.key);
          return (
            <button
              key={ln.key}
              type="button"
              className={`chart-legend__item category-trend__legend-item${off ? ' is-off' : ''}`}
              aria-pressed={!off}
              title={off ? 'Показать на графике' : 'Скрыть с графика'}
              onClick={() => toggleLine(ln.key)}
            >
              <span
                className="chart-legend__swatch"
                style={{ width: 10, height: 2, background: ln.color, opacity: off ? 0.35 : 1 }}
              />
              {ln.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* Interactive single-series time chart (Explorer dynamics). */
function TimeSeriesSparkChart({
  points = [],
  height = 180,
  color = '#7E92F8',
  displayTimezone,
  valueLabel = 'Средняя бит/с',
  valueKey = 'bps',
  formatValue,
  axisFormatter = fmtCompact,
  className = '',
  onRangeSelect,
  bucketSeconds = 300,
  periodStartMs,
  periodEndMs,
  skipLeadingGaps = false,
  tipTranslucent = false,
}) {
  const wrapRef = useRef(null);
  const dragRef = useRef(null);
  const [hoverIdx, setHoverIdx] = useState(null);
  const [selection, setSelection] = useState(null);
  const gradId = useMemo(() => `ts${Math.random().toString(36).slice(2, 8)}`, []);
  const fmtValue = formatValue || fmtBits;

  const data = useMemo(() => {
    const densified = fillChartTimeGaps(points || [], {
      bucketSeconds,
      startMs: periodStartMs,
      endMs: periodEndMs,
      valueKeys: [valueKey, 'bps', 'v'],
      skipLeadingGaps,
    });
    return densified.map((pt) => ({
      ...pt,
      v: chartSeriesNumber(pt[valueKey] ?? pt.bps),
    }));
  }, [points, bucketSeconds, periodStartMs, periodEndMs, valueKey, skipLeadingGaps]);
  if (!data.length) return null;

  const w = 800;
  const padL = 72;
  const padR = 12;
  const padT = 16;
  const padB = 32;
  const h = height;
  const valueList = data.map((d) => d.v).filter((v) => v != null);
  const max = valueList.length ? Math.max(...valueList) * 1.12 || 1 : 1;
  const n = data.length;
  const timeScale = data.length > 1 ? buildChartTimeScale(data, padL, padR, w) : null;
  const x = timeScale ? (i) => timeScale.xAtIndex(i) : () => padL;
  const y = (v) => padT + (1 - v / max) * (h - padT - padB);
  const yZero = y(0);
  const yTicks = 4;
  const tEvery = Math.max(1, Math.floor(n / 8));
  const tz = displayTimezone || getDisplayTimezone();
  const startMs = timeScale?.startMs ?? resolvePointEpochMs(data[0]);
  const endMs = timeScale?.endMs ?? resolvePointEpochMs(data[n - 1]);
  const longRange = startMs != null && endMs != null && (endMs - startMs) > 24 * 3600000;
  const selectable = typeof onRangeSelect === 'function' && data.length > 1;

  const indexFromClientX = (clientX) => {
    if (timeScale) return timeScale.indexFromClientX(clientX, wrapRef);
    return null;
  };

  const onChartMouseMove = (e) => {
    if (dragRef.current) {
      const idx = indexFromClientX(e.clientX);
      if (idx == null) return;
      dragRef.current.currentIdx = idx;
      setSelection({ start: dragRef.current.startIdx, end: idx });
      return;
    }
    updateChartHoverIndex(e.clientX, indexFromClientX, setHoverIdx);
  };

  const finishDrag = () => {
    const drag = dragRef.current;
    dragRef.current = null;
    if (!drag || !selectable) {
      setSelection(null);
      return;
    }
    const endIdx = drag.currentIdx ?? drag.startIdx;
    setSelection(null);
    const movedPx = Math.abs(drag.lastX - drag.startX);
    if (movedPx < 4) return;
    const range = chartRangeFromPointSelection(data, drag.startIdx, endIdx, bucketSeconds, tz);
    if (range) onRangeSelect(range);
  };

  const onChartMouseDown = (e) => {
    if (!selectable || e.button !== 0) return;
    const idx = indexFromClientX(e.clientX);
    if (idx == null) return;
    e.preventDefault();
    dragRef.current = {
      startIdx: idx,
      currentIdx: idx,
      startX: e.clientX,
      lastX: e.clientX,
    };
    setSelection({ start: idx, end: idx });
    setHoverIdx(null);

    const onMove = (ev) => {
      if (!dragRef.current) return;
      dragRef.current.lastX = ev.clientX;
      const nextIdx = indexFromClientX(ev.clientX);
      if (nextIdx == null) return;
      dragRef.current.currentIdx = nextIdx;
      setSelection({ start: dragRef.current.startIdx, end: nextIdx });
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      finishDrag();
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  const onChartMouseLeave = () => {
    clearChartHoverIndex(setHoverIdx, dragRef.current);
  };

  const selectionBand = selection && timeScale
    ? timeScale.selectionBandPct(selection.start, selection.end)
    : null;
  const chartPadLeftPct = (padL / w) * 100;
  const chartPadRightPct = (padR / w) * 100;
  const chartPlotWidthPct = 100 - chartPadLeftPct - chartPadRightPct;

  const hoverPoint = !selection && hoverIdx != null ? data[hoverIdx] : null;
  const tipPct = hoverIdx != null && n > 0 ? (x(hoverIdx) / w) * 100 : 50;
  const tipAlign = tipPct > 72 ? 'end' : tipPct < 20 ? 'start' : 'center';
  const tipStyle = {
    left: `${tipPct}%`,
    transform: tipAlign === 'end' ? 'translateX(calc(-100% - 8px))' : tipAlign === 'start' ? 'translateX(8px)' : 'translateX(-50%)',
  };

  const lineSegments = buildChartPolylineSegments(data, x, y, (pt) => pt.v);
  const areaSegments = buildChartAreaPathSegments(data, x, y, yZero, (pt) => pt.v);

  return (
    <div
      ref={wrapRef}
      className={`dual-chart dual-chart--fluid${selectable ? ' dual-chart--selectable' : ''}${selection ? ' dual-chart--dragging' : ''}${className ? ` ${className}` : ''}`}
      style={fluidChartStyle(height)}
      onMouseMove={onChartMouseMove}
      onMouseLeave={onChartMouseLeave}
      onMouseDown={onChartMouseDown}
    >
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" overflow="visible" className="dual-chart__svg">
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.45" />
            <stop offset="100%" stopColor={color} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {Array.from({ length: yTicks + 1 }, (_, i) => {
          const v = (max / yTicks) * i;
          const yy = y(v);
          return (
            <g key={i}>
              <line x1={padL} x2={w - padR} y1={yy} y2={yy} stroke="var(--chart-grid, rgba(255,255,255,0.05))" />
              <text x={padL - 10} y={yy + 4} textAnchor="end" fontSize="10" fill="var(--fg-muted)" fontFamily="Mulish">
                {axisFormatter(v)}
              </text>
            </g>
          );
        })}
        {areaSegments.map((pathD, idx) => (
          <path key={`area-${idx}`} d={pathD} fill={`url(#${gradId})`} />
        ))}
        {lineSegments.map((pts, segmentIdx) => (
          <polyline
            key={`line-${segmentIdx}`}
            points={pts.join(' ')}
            fill="none"
            stroke={color}
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ))}
        {hoverPoint && (
          <g pointerEvents="none">
            <line
              x1={x(hoverIdx)}
              x2={x(hoverIdx)}
              y1={padT}
              y2={h - padB}
              stroke="rgba(255,255,255,0.28)"
              strokeWidth="1"
              strokeDasharray="4 3"
            />
            {hoverPoint.v != null && (
            <circle
              cx={x(hoverIdx)}
              cy={y(hoverPoint.v)}
              r={4}
              fill={color}
              stroke="#14131F"
              strokeWidth="1.5"
            />
            )}
          </g>
        )}
        {data.map((pt, i) => i % tEvery === 0 && (
          <text key={i} x={x(i)} y={h - 6} textAnchor="middle" fontSize="10" fill="var(--fg-muted)" fontFamily="Mulish">
            {formatPointTimeLabel(pt, longRange, tz)}
          </text>
        ))}
      </svg>
      {selectionBand && (
        <div
          className="dual-chart__selection"
          style={{
            left: `calc(${chartPadLeftPct}% + ${(selectionBand.left / 100) * chartPlotWidthPct}%)`,
            width: `${Math.max((selectionBand.width / 100) * chartPlotWidthPct, 0.4)}%`,
          }}
        />
      )}
      {hoverPoint && (
        <ChartHoverTip style={tipStyle} translucentToggle={tipTranslucent}>
          <div className="dual-chart__tip-time">{formatPointTimeLabel(hoverPoint, longRange, tz)}</div>
          <div className="dual-chart__tip-row">
            <span className="dual-chart__tip-swatch" style={{ background: color }} />
            <span className="dual-chart__tip-label">{valueLabel}</span>
            <span className="dual-chart__tip-val mono">{fmtValue(hoverPoint.v)}</span>
          </div>
          {hoverPoint.bytes != null && (
            <div className="dual-chart__tip-row">
              <span className="dual-chart__tip-swatch" style={{ background: 'transparent' }} />
              <span className="dual-chart__tip-label">Объём</span>
              <span className="dual-chart__tip-val mono">{fmtBytes(hoverPoint.bytes)}</span>
            </div>
          )}
        </ChartHoverTip>
      )}
    </div>
  );
}

/* ============== Sparkline ============== */
function Sparkline({ data, width = 100, height = 32, color = '#7E92F8', filled }) {
  const max = Math.max(...data), min = Math.min(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - 2 - ((v - min) / range) * (height - 4);
    return `${x},${y}`;
  }).join(' ');
  const id = useMemo(() => 'sp' + Math.random().toString(36).slice(2, 8), []);
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{display: 'block'}}>
      {filled && (
        <>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.4" />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          <polygon points={`0,${height} ${pts} ${width},${height}`} fill={`url(#${id})`} />
        </>
      )}
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const DONUT_MIN_PERCENT = 0.01;

function donutSegmentPercent(d) {
  return Number(d?.value ?? d?.percent) || 0;
}

/** Видимый в легенде % (2 знака): скрываем всё, что округляется до 0.00. */
function isVisibleDonutSegment(d) {
  const pct = donutSegmentPercent(d);
  if (isDonutOtherSegment(d)) return pct > 0;
  return pct >= DONUT_MIN_PERCENT;
}

/** Сегменты donut: ≥ 0.01 % (0.03 % остаётся, 0.00 % в списке нет). */
function filterNonZeroDonutSegments(data) {
  return (data || []).filter(isVisibleDonutSegment);
}

function isDonutOtherSegment(d) {
  const code = String(d?.serviceCode || d?.protocol || d?.label || '').toLowerCase();
  return code === 'other';
}

function donutSegmentKey(d) {
  return d?.serviceCode || d?.protocol || d?.label || '';
}

/** Ненулевые сегменты; Other всегда в конце списка. */
function filterNonZeroDonutWithOtherLast(data) {
  const visible = filterNonZeroDonutSegments(data);
  const main = visible.filter((d) => !isDonutOtherSegment(d));
  const other = visible.filter(isDonutOtherSegment);
  return [...main, ...other];
}

const DONUT_LEGEND_COLLAPSED = 6;

function sortDonutLegendRows(rows) {
  const main = (rows || []).filter((d) => !isDonutOtherSegment(d));
  const other = (rows || []).filter(isDonutOtherSegment);
  main.sort((a, b) => donutSegmentPercent(b) - donutSegmentPercent(a));
  return [...main, ...other];
}

function collapseDonutLegendRows(rows, limit = DONUT_LEGEND_COLLAPSED) {
  const sorted = sortDonutLegendRows(rows);
  const main = sorted.filter((d) => !isDonutOtherSegment(d));
  const other = sorted.filter(isDonutOtherSegment);
  if (other.length) return [...main.slice(0, limit - 1), ...other];
  return main.slice(0, limit);
}

function donutLegendCanExpand(data, legendLimit = DONUT_LEGEND_COLLAPSED) {
  const all = sortDonutLegendRows(data || []);
  const collapsed = collapseDonutLegendRows(filterNonZeroDonutSegments(data), legendLimit);
  return all.length > collapsed.length;
}

function donutCenterTraffic(items) {
  const totalGb = items.reduce((s, p) => s + (p.trafficGb || 0), 0);
  if (totalGb >= 1000) {
    const tb = totalGb / 1000;
    return {
      label: tb >= 100 ? String(Math.round(tb)) : tb >= 10 ? tb.toFixed(0) : tb.toFixed(1),
      sub: 'ТБ',
    };
  }
  if (totalGb >= 1) return { label: totalGb.toFixed(1), sub: 'ГБ' };
  if (totalGb > 0) return { label: totalGb.toFixed(2), sub: 'ГБ' };
  return { label: '0', sub: 'ГБ' };
}

function donutCenterTrafficGb(items) {
  return donutCenterTraffic(items).label;
}

/* ============== Donut ============== */
function Donut({ data, size = 180, thickness = 26, centerLabel, centerSub, layout, legendLimit = DONUT_LEGEND_COLLAPSED, onOtherClick }) {
  // data: [{ label, value, color }]
  const [legendExpanded, setLegendExpanded] = useState(false);
  const [hoverKey, setHoverKey] = useState(null);
  const segments = filterNonZeroDonutSegments(data);
  const allLegendRows = sortDonutLegendRows(data);
  const visibleLegendRows = sortDonutLegendRows(segments);
  const collapsedLegendRows = collapseDonutLegendRows(visibleLegendRows, legendLimit);
  const legendRows = legendExpanded ? allLegendRows : collapsedLegendRows;
  const canExpandLegend = donutLegendCanExpand(data, legendLimit);
  const compact = layout === 'compact';
  const donutSize = compact ? (size === 180 ? 128 : size) : size;
  const donutThickness = compact ? (thickness === 26 ? 18 : thickness) : thickness;
  const total = segments.reduce((s, d) => s + donutSegmentPercent(d), 0) || 1;
  const r = (donutSize - donutThickness) / 2;
  const cx = donutSize / 2, cy = donutSize / 2;
  let acc = 0;
  const segs = segments.map((d) => {
    const v = donutSegmentPercent(d);
    const start = (acc / total) * 2 * Math.PI - Math.PI / 2;
    acc += v;
    const end = (acc / total) * 2 * Math.PI - Math.PI / 2;
    const large = end - start > Math.PI ? 1 : 0;
    const x1 = cx + r * Math.cos(start), y1 = cy + r * Math.sin(start);
    const x2 = cx + r * Math.cos(end), y2 = cy + r * Math.sin(end);
    return { d, path: `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`, key: donutSegmentKey(d) };
  });
  const hitStroke = donutThickness + 14;
  const centerFont = compact ? '800 20px/1 var(--pv-font-sans)' : '800 26px/1 var(--pv-font-sans)';

  const clearHoverUnlessMovingWithin = (e) => {
    const next = e.relatedTarget;
    if (next instanceof Node && e.currentTarget.contains(next)) return;
    setHoverKey(null);
  };

  return (
    <div
      className={compact ? 'donut donut--compact' : 'donut'}
      onMouseLeave={clearHoverUnlessMovingWithin}
    >
      <div className="donut__chart">
        <svg viewBox={`0 0 ${donutSize} ${donutSize}`} className="donut__svg">
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--track)" strokeWidth={donutThickness} />
          {segs.map((s) => {
            const active = hoverKey == null || hoverKey === s.key;
            const highlighted = hoverKey === s.key;
            return (
              <path
                key={`vis-${s.key}`}
                className="donut__segment"
                d={s.path}
                fill="none"
                stroke={s.d.color}
                strokeWidth={highlighted ? donutThickness + 3 : donutThickness}
                strokeLinecap="butt"
                style={{ opacity: active ? 1 : 0.28 }}
                pointerEvents="none"
              />
            );
          })}
          {segs.map((s) => (
            <path
              key={`hit-${s.key}`}
              className="donut__segment-hit"
              d={s.path}
              fill="none"
              stroke="transparent"
              strokeWidth={hitStroke}
              strokeLinecap="butt"
              onMouseEnter={() => setHoverKey(s.key)}
            />
          ))}
        </svg>
        <div
          className="donut__center"
          style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', pointerEvents: 'none' }}
        >
          <div style={{ textAlign: 'center' }}>
            <div style={{ font: centerFont, letterSpacing: '-0.015em' }}>{centerLabel}</div>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 4 }}>{centerSub}</div>
          </div>
        </div>
      </div>
      <div className={`donut__legend${legendExpanded ? ' donut__legend--expanded' : ''}`}>
        {legendRows.map((d, i) => {
          const pct = donutSegmentPercent(d);
          const isZero = !isVisibleDonutSegment(d);
          const key = donutSegmentKey(d);
          const highlighted = hoverKey === key;
          const dimmed = hoverKey != null && hoverKey !== key;
          return (
            <div
              key={`${key}-${i}`}
              className={[
                'donut__legend-row',
                isZero && 'donut__legend-row--zero',
                highlighted && 'donut__legend-row--active',
                dimmed && 'donut__legend-row--dim',
              ].filter(Boolean).join(' ')}
              onMouseEnter={() => setHoverKey(key)}
            >
              <span className="donut__legend-swatch" style={{ background: d.color }} aria-hidden="true" />
              <span className="donut__legend-label">
                {isDonutOtherSegment(d) && onOtherClick ? (
                  <button type="button" className="donut__legend-link" onClick={onOtherClick}>
                    {d.label}
                  </button>
                ) : (
                  d.label
                )}
              </span>
              <span className="donut__legend-pct mono">{pct.toFixed(2)}%</span>
            </div>
          );
        })}
        {canExpandLegend && (
          <button
            type="button"
            className="donut__legend-toggle"
            aria-expanded={legendExpanded}
            title={legendExpanded ? 'Свернуть список' : 'Показать весь список'}
            onClick={() => setLegendExpanded((v) => !v)}
          >
            <Icon name={legendExpanded ? 'arrowU' : 'arrowD'} size={14} />
          </button>
        )}
      </div>
    </div>
  );
}

/* ============== Horizontal bar list ============== */
function BarList({ items, valueFormatter = (v) => fmtBytes(v) + '/с' }) {
  const max = Math.max(...items.map((i) => i.value)) || 1;
  return (
    <div style={{display: 'flex', flexDirection: 'column', gap: 10}}>
      {items.map((it, i) => {
        const pct = (it.value / max) * 100;
        return (
          <div key={i}>
            <div style={{display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4}}>
              {it.flag && <span style={{fontSize: 14, lineHeight: 1}}>{it.flag}</span>}
              <span style={{flex: 1, font: 'var(--pv-text-body-2)', color: 'var(--fg-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{it.label}</span>
              {it.sub && <span style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>{it.sub}</span>}
              <span className="mono" style={{font: 'var(--pv-text-body-2-bold)', minWidth: 80, textAlign: 'right'}}>{valueFormatter(it.value)}</span>
            </div>
            <div style={{height: 6, background: 'var(--track)', borderRadius: 999, overflow: 'hidden'}}>
              <div style={{
                width: `${pct}%`,
                height: '100%',
                background: it.color || 'linear-gradient(90deg, #7E92F8, #6972F0)',
                borderRadius: 999,
              }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ============== Mini world heatmap (stylised) ============== */
// Renders a soft dotted world silhouette with country markers.
function WorldHeat({ markers }) {
  // Use a simple equirectangular dot-grid background and place markers in [-180..180, -85..85]
  const w = 720, h = 360;
  const project = (lat, lon) => {
    const x = ((lon + 180) / 360) * w;
    const y = ((85 - lat) / 170) * h;
    return [x, y];
  };
  const dotCols = 90, dotRows = 36;
  const dots = [];
  for (let r = 0; r < dotRows; r++) {
    for (let c = 0; c < dotCols; c++) {
      const lon = -180 + (c / dotCols) * 360;
      const lat = 85 - (r / dotRows) * 170;
      if (!inLand(lat, lon)) continue;
      dots.push([(c / dotCols) * w + w / dotCols / 2, (r / dotRows) * h + h / dotRows / 2]);
    }
  }
  const max = Math.max(...markers.map(m => m.value)) || 1;
  return (
    <div style={{position: 'relative', width: '100%', aspectRatio: `${w}/${h}`}}>
      <svg viewBox={`0 0 ${w} ${h}`} style={{position: 'absolute', inset: 0, width: '100%', height: '100%'}}>
        {dots.map((p, i) => <circle key={i} cx={p[0]} cy={p[1]} r="1.6" fill="rgba(161,164,196,0.18)" />)}
        {markers.map((m, i) => {
          const [x, y] = project(m.lat, m.lon);
          const intensity = m.value / max;
          const radius = 6 + intensity * 18;
          return (
            <g key={i}>
              <circle cx={x} cy={y} r={radius} fill="rgba(115,129,244,0.22)" />
              <circle cx={x} cy={y} r={radius * 0.55} fill="rgba(126,146,248,0.55)" />
              <circle cx={x} cy={y} r="3" fill="#fff" />
              {m.label && (
                <text x={x} y={y - radius - 6} textAnchor="middle" fontSize="10" fill="#fff" fontFamily="Mulish" fontWeight="700">
                  {m.label}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// Crude "is-land" mask using lon/lat boxes; good enough for a stylised look.
function inLand(lat, lon) {
  const boxes = [
    [-170, -55, 60, -10],   // Americas wide
    [-15, 35, 60, 70],      // Europe
    [-20, -38, 55, 35],     // Africa
    [25, 0, 145, 75],       // Asia
    [110, -45, 160, -10],   // Australia
    [-60, -75, -30, -55],   // Antarctic peninsula stub (light)
  ];
  return boxes.some(([lo1, la1, lo2, la2]) => lon >= lo1 && lon <= lo2 && lat >= la1 && lat <= la2);
}

/* ============== Country choropleth (GeoJSON) ============== */
let worldGeoJsonCache = null;
let worldGeoJsonPromise = null;

function loadWorldGeoJson() {
  if (worldGeoJsonCache) return Promise.resolve(worldGeoJsonCache);
  if (worldGeoJsonPromise) return worldGeoJsonPromise;
  worldGeoJsonPromise = fetch('/data/world-countries.json', { cache: 'force-cache' })
    .then((res) => {
      if (!res.ok) throw new Error(`GeoJSON HTTP ${res.status}`);
      return res.json();
    })
    .then((data) => {
      worldGeoJsonCache = data;
      return data;
    });
  return worldGeoJsonPromise;
}

function geoFeatureCode(props) {
  const iso = props?.ISO_A2;
  if (iso && iso !== '-99') return iso;
  const eh = props?.ISO_A2_EH;
  if (eh && eh !== '-99') return eh;
  return null;
}

function projectLonLat(lon, lat, w, h) {
  const x = ((lon + 180) / 360) * w;
  const y = ((90 - lat) / 180) * h;
  return [x, y];
}

function ringToPath(ring, w, h) {
  if (!ring?.length) return '';
  let d = '';
  for (let i = 0; i < ring.length; i++) {
    const [x, y] = projectLonLat(ring[i][0], ring[i][1], w, h);
    d += `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`;
  }
  return `${d}Z`;
}

function polygonToPath(coords, w, h) {
  return (coords || []).map((ring) => ringToPath(ring, w, h)).join('');
}

function geometryToPath(geom, w, h) {
  if (!geom) return '';
  if (geom.type === 'Polygon') return polygonToPath(geom.coordinates, w, h);
  if (geom.type === 'MultiPolygon') {
    return geom.coordinates.map((poly) => polygonToPath(poly, w, h)).join('');
  }
  return '';
}

const COUNTRY_TIER_DEFS = [
  { min: 25, label: '≥25%', varName: '--country-map-tier-5', fallback: 'rgba(63, 74, 180, 0.96)' },
  { min: 5, label: '5–25%', varName: '--country-map-tier-4', fallback: 'rgba(82, 98, 210, 0.88)' },
  { min: 1, label: '1–5%', varName: '--country-map-tier-3', fallback: 'rgba(105, 122, 235, 0.72)' },
  { min: 0.2, label: '0.2–1%', varName: '--country-map-tier-2', fallback: 'rgba(126, 146, 248, 0.52)' },
  { min: 0, label: '<0.2%', varName: '--country-map-tier-1', fallback: 'rgba(160, 175, 255, 0.30)' },
];

function cssMapVar(name, fallback) {
  if (typeof document === 'undefined') return fallback;
  const val = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return val || fallback;
}

function isLightMapTheme() {
  if (typeof document === 'undefined') return false;
  return document.documentElement.getAttribute('data-theme') === 'light';
}

function countrySharePercent(row) {
  return row ? Number(row.sharePercent) || 0 : 0;
}

function countryTrafficGb(row) {
  return row ? Number(row.trafficGb) || 0 : 0;
}

function countryTotalTrafficGb(rows) {
  return (rows || []).reduce((sum, row) => sum + countryTrafficGb(row), 0);
}

function countryMapMetricValue(row, colorMetric) {
  return colorMetric === 'volume' ? countryTrafficGb(row) : countrySharePercent(row);
}

function formatCountryGbLabel(gb) {
  return fmtVolumeSize(Number(gb) || 0);
}

function countryVolumeTierLabel(minGb, maxGb) {
  if (maxGb != null && minGb <= 0) return `<${formatCountryGbLabel(maxGb)}`;
  if (maxGb == null) return `≥${formatCountryGbLabel(minGb)}`;
  return `${formatCountryGbLabel(minGb)}–${formatCountryGbLabel(maxGb)}`;
}

function getCountryMapTierDefs(colorMetric, totalGb) {
  if (colorMetric !== 'volume') return COUNTRY_TIER_DEFS;

  const total = totalGb || 0;
  const volumeBounds = [
    { min: total * 0.25, max: null },
    { min: total * 0.05, max: total * 0.25 },
    { min: total * 0.01, max: total * 0.05 },
    { min: total * 0.002, max: total * 0.01 },
    { min: 0, max: total * 0.002 },
  ];

  return volumeBounds.map((bound, index) => ({
    min: bound.min,
    label: countryVolumeTierLabel(bound.min, bound.max),
    varName: COUNTRY_TIER_DEFS[index].varName,
    fallback: COUNTRY_TIER_DEFS[index].fallback,
  }));
}

function getCountryMapPalette(colorMetric = 'share', totalGb = 0) {
  return {
    empty: cssMapVar('--country-map-empty', 'rgba(161, 164, 196, 0.12)'),
    unknownHatch: isLightMapTheme() ? 'url(#country-unknown-hatch-light)' : 'url(#country-unknown-hatch)',
    tiers: getCountryMapTierDefs(colorMetric, totalGb).map((tier) => ({
      min: tier.min,
      label: tier.label,
      fill: cssMapVar(tier.varName, tier.fallback),
    })),
  };
}

function countryMapFill(row, palette, colorMetric = 'share') {
  const p = palette || getCountryMapPalette(colorMetric);
  if (!row) return p.empty;
  const code = String(row.countryCode || '').trim();
  if (code === '??') return p.unknownHatch;

  const value = countryMapMetricValue(row, colorMetric);
  if (value <= 0) return p.empty;

  for (const tier of p.tiers) {
    if (value >= tier.min) return tier.fill;
  }
  return p.tiers[p.tiers.length - 1].fill;
}

function countryFlagEmoji(code) {
  if (!code || code === '??' || code.length !== 2) return '🏳';
  const up = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(up)) return '🏳';
  return String.fromCodePoint(
    ...[...up].map((c) => 0x1F1E6 - 65 + c.charCodeAt(0)),
  );
}

function countryDisplayName(code, nameByCode) {
  if (code === '??') return 'Неизвестно';
  return nameByCode?.[code] || code || '—';
}

const COUNTRY_MAP_W = 720;
const COUNTRY_MAP_H = 360;
const COUNTRY_ZOOM_MIN = 1;
const COUNTRY_ZOOM_MAX = 8;

function clampCountryZoom(k) {
  return Math.max(COUNTRY_ZOOM_MIN, Math.min(COUNTRY_ZOOM_MAX, k));
}

function normalizeCountryView(view) {
  const k = clampCountryZoom(view?.k ?? 1);
  if (k <= 1) return { k: 1, x: 0, y: 0 };
  return { k, x: view?.x ?? 0, y: view?.y ?? 0 };
}

function countryViewAtPoint(view, mx, my, factor) {
  const k2 = clampCountryZoom(view.k * factor);
  if (k2 === view.k) return view;
  if (k2 <= 1) return { k: 1, x: 0, y: 0 };
  return {
    k: k2,
    x: view.x + mx * (view.k - k2),
    y: view.y + my * (view.k - k2),
  };
}

function countryMapTooltipContent(hover) {
  if (!hover?.row) return null;
  return (
    <>
      <div className="country-choropleth__tooltip-title">
        {countryFlagEmoji(hover.code)} {hover.name}
      </div>
      <div className="country-choropleth__tooltip-row">
        <span>Объём</span>
        <span className="mono">{fmtVolumeSize(hover.row.trafficGb)}</span>
      </div>
      <div className="country-choropleth__tooltip-row">
        <span>Доля</span>
        <span className="mono">{hover.row.sharePercent.toFixed(2)}%</span>
      </div>
      <div className="country-choropleth__tooltip-row">
        <span>Средняя скорость</span>
        <span className="mono">{hover.row.avgGbps.toFixed(3)} Gbps</span>
      </div>
      <div className="country-choropleth__tooltip-row">
        <span>Пакеты</span>
        <span className="mono">{fmtNum(hover.row.packetCount)}</span>
      </div>
      <div className="country-choropleth__tooltip-row">
        <span>Потоки</span>
        <span className="mono">{fmtNum(hover.row.flowCount)}</span>
      </div>
    </>
  );
}

function CountryMapTooltip({ hover }) {
  if (!hover?.row) return null;
  return ReactDOM.createPortal(
    <div
      className="country-choropleth__tooltip"
      style={{ left: hover.clientX, top: hover.clientY }}
    >
      {countryMapTooltipContent(hover)}
    </div>,
    document.body,
  );
}

function CountryChoropleth({
  rows = [],
  colorMetric = 'share',
  loading = false,
  failed = false,
  large = false,
  showExpand = false,
  onExpand,
}) {
  const w = COUNTRY_MAP_W;
  const h = COUNTRY_MAP_H;
  const [geo, setGeo] = useState(worldGeoJsonCache);
  const [geoError, setGeoError] = useState(null);
  const [hover, setHover] = useState(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const mapWrapRef = useRef(null);
  const svgRef = useRef(null);
  const dragRef = useRef(null);
  const interactive = large;
  const totalGb = useMemo(() => countryTotalTrafficGb(rows), [rows]);
  const [themeTick, setThemeTick] = useState(0);

  useEffect(() => {
    const syncPalette = () => setThemeTick((tick) => tick + 1);
    const obs = new MutationObserver(syncPalette);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => obs.disconnect();
  }, []);

  const mapPalette = useMemo(
    () => getCountryMapPalette(colorMetric, totalGb),
    [colorMetric, totalGb, themeTick],
  );

  useEffect(() => {
    let cancelled = false;
    if (worldGeoJsonCache) {
      setGeo(worldGeoJsonCache);
      return undefined;
    }
    loadWorldGeoJson()
      .then((data) => { if (!cancelled) setGeo(data); })
      .catch((err) => { if (!cancelled) setGeoError(err.message); });
    return () => { cancelled = true; };
  }, []);

  const dataByCode = useMemo(() => {
    const map = {};
    for (const row of rows) {
      const code = String(row.countryCode || '').trim();
      if (code) map[code] = row;
    }
    return map;
  }, [rows]);

  const unknownRow = dataByCode['??'] || null;

  const shapes = useMemo(() => {
    if (!geo?.features?.length) return [];
    const nameByCode = {};
    const list = [];
    for (const feature of geo.features) {
      const code = geoFeatureCode(feature.properties);
      if (!code) continue;
      nameByCode[code] = feature.properties?.NAME_RU || feature.properties?.NAME || code;
      const row = dataByCode[code];
      list.push({
        code,
        name: nameByCode[code],
        d: geometryToPath(feature.geometry, w, h),
        fill: countryMapFill(row, mapPalette, colorMetric),
        row,
      });
    }
    list.nameByCode = nameByCode;
    return list;
  }, [geo, dataByCode, mapPalette, colorMetric]);

  const mapPointFromClient = useCallback((clientX, clientY) => {
    const svg = svgRef.current;
    if (!svg) return { x: w / 2, y: h / 2 };
    const rect = svg.getBoundingClientRect();
    return {
      x: ((clientX - rect.left) / rect.width) * w,
      y: ((clientY - rect.top) / rect.height) * h,
    };
  }, [w, h]);

  const zoomByFactor = useCallback((factor, clientX, clientY) => {
    const anchor = mapPointFromClient(clientX, clientY);
    setView((prev) => countryViewAtPoint(normalizeCountryView(prev), anchor.x, anchor.y, factor));
  }, [mapPointFromClient]);

  const resetView = useCallback(() => {
    setView({ k: 1, x: 0, y: 0 });
  }, []);

  useEffect(() => {
    if (!interactive) return undefined;
    const wrap = mapWrapRef.current;
    if (!wrap) return undefined;

    const onWheel = (e) => {
      e.preventDefault();
      const factor = e.deltaY > 0 ? 0.88 : 1.12;
      zoomByFactor(factor, e.clientX, e.clientY);
    };

    wrap.addEventListener('wheel', onWheel, { passive: false });
    return () => wrap.removeEventListener('wheel', onWheel);
  }, [interactive, zoomByFactor]);

  useEffect(() => {
    if (!interactive || !dragging) return undefined;

    const onMove = (e) => {
      const drag = dragRef.current;
      const svg = svgRef.current;
      if (!drag || !svg) return;
      const rect = svg.getBoundingClientRect();
      const scaleX = rect.width > 0 ? w / rect.width : 1;
      const scaleY = rect.height > 0 ? h / rect.height : 1;
      const dx = (e.clientX - drag.startX) * scaleX;
      const dy = (e.clientY - drag.startY) * scaleY;
      setView({
        k: drag.k,
        x: drag.x + dx,
        y: drag.y + dy,
      });
    };

    const onUp = () => {
      dragRef.current = null;
      setDragging(false);
    };

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [interactive, dragging, w, h]);

  const startDrag = (e) => {
    if (!interactive) return;
    if (e.button !== 0) return;
    const current = normalizeCountryView(view);
    if (current.k <= 1) return;
    dragRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      x: current.x,
      y: current.y,
      k: current.k,
    };
    setDragging(true);
    setHover(null);
  };

  const zoomControl = (factor) => {
    const wrap = mapWrapRef.current;
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    zoomByFactor(factor, rect.left + rect.width / 2, rect.top + rect.height / 2);
  };

  const normalizedView = interactive ? normalizeCountryView(view) : { k: 1, x: 0, y: 0 };
  const canPan = interactive && normalizedView.k > 1;

  if (loading || (!geo && !geoError)) {
    return <div className="country-choropleth__state">Загрузка карты…</div>;
  }
  if (failed) {
    return <div className="country-choropleth__state">Не удалось загрузить</div>;
  }
  if (geoError) {
    return <div className="country-choropleth__state">Не удалось загрузить карту</div>;
  }
  if (!loading && rows.length === 0) {
    return <div className="country-choropleth__state">Нет данных за период</div>;
  }

  return (
    <div className={`country-choropleth${large ? ' country-choropleth--large' : ''}`}>
      <div
        ref={mapWrapRef}
        className={`country-choropleth__map-wrap${dragging ? ' is-dragging' : ''}${canPan ? ' is-zoomed' : ''}`}
        onMouseDown={interactive ? startDrag : undefined}
      >
        {(showExpand || interactive) && (
        <div className="country-choropleth__zoom-controls">
          {showExpand && onExpand && (
            <button
              type="button"
              className="country-choropleth__zoom-btn"
              title="Открыть крупно"
              aria-label="Открыть крупно"
              onMouseDown={(e) => e.stopPropagation()}
              onClick={onExpand}
            >
              <Icon name="expand" size={14} />
            </button>
          )}
          {interactive && (
            <>
          <button
            type="button"
            className="country-choropleth__zoom-btn"
            title="Приблизить"
            aria-label="Приблизить"
            onMouseDown={(e) => e.stopPropagation()}
            onClick={() => zoomControl(1.25)}
          >
            +
          </button>
          <button
            type="button"
            className="country-choropleth__zoom-btn"
            title="Отдалить"
            aria-label="Отдалить"
            onMouseDown={(e) => e.stopPropagation()}
            onClick={() => zoomControl(0.8)}
          >
            −
          </button>
          <button
            type="button"
            className="country-choropleth__zoom-btn"
            title="Сбросить масштаб"
            aria-label="Сбросить масштаб"
            disabled={!canPan}
            onMouseDown={(e) => e.stopPropagation()}
            onClick={resetView}
          >
            <Icon name="zoom" size={14} />
          </button>
            </>
          )}
        </div>
        )}
        <svg
          ref={svgRef}
          viewBox={`0 0 ${w} ${h}`}
          className="country-choropleth__svg"
          role="img"
          aria-label="Тепловая карта стран"
        >
          <defs>
            <pattern
              id="country-unknown-hatch"
              patternUnits="userSpaceOnUse"
              width="8"
              height="8"
              patternTransform="rotate(45)"
            >
              <rect width="8" height="8" fill="rgba(161,164,196,0.14)" />
              <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(127,127,157,0.55)" strokeWidth="3" />
            </pattern>
            <pattern
              id="country-unknown-hatch-light"
              patternUnits="userSpaceOnUse"
              width="8"
              height="8"
              patternTransform="rotate(45)"
            >
              <rect width="8" height="8" fill="#EDE4DA" />
              <line x1="0" y1="0" x2="0" y2="8" stroke="rgba(100, 72, 40, 0.45)" strokeWidth="3" />
            </pattern>
          </defs>
          <g transform={interactive ? `translate(${normalizedView.x}, ${normalizedView.y}) scale(${normalizedView.k})` : undefined}>
            {shapes.map((s) => (
              <path
                key={s.code}
                d={s.d}
                fill={s.fill}
                className="country-choropleth__country"
                onMouseEnter={(e) => {
                  if (!s.row || (interactive && dragging)) return;
                  setHover({
                    code: s.code,
                    name: s.name,
                    row: s.row,
                    clientX: e.clientX,
                    clientY: e.clientY,
                  });
                }}
                onMouseMove={(e) => {
                  if (!s.row || (interactive && dragging)) return;
                  setHover((prev) => prev?.code === s.code ? {
                    ...prev,
                    clientX: e.clientX,
                    clientY: e.clientY,
                  } : prev);
                }}
                onMouseLeave={() => setHover(null)}
              />
            ))}
          </g>
        </svg>
      </div>
      <CountryMapTooltip hover={hover} />
      <div className="country-choropleth__legend row">
        {mapPalette.tiers.map((tier) => (
          <span key={tier.label} className="country-choropleth__legend-tier">
            <span
              className="country-choropleth__legend-swatch"
              style={{ background: tier.fill }}
            />
            {tier.label}
          </span>
        ))}
        <span className="country-choropleth__legend-tier">
          <span className="country-choropleth__legend-swatch country-choropleth__legend-swatch--unknown" />
          Неизвестно
          {unknownRow && (
            <span className="country-choropleth__legend-unknown-meta mono">
              · {unknownRow.sharePercent.toFixed(2)}% · {fmtVolumeSize(unknownRow.trafficGb)}
            </span>
          )}
        </span>
      </div>
    </div>
  );
}

function countryRankListSort(a, b, colorMetric) {
  const metricDiff = colorMetric === 'volume'
    ? b.trafficGb - a.trafficGb
    : b.sharePercent - a.sharePercent;
  if (metricDiff !== 0) return metricDiff;
  return a.label.localeCompare(b.label, 'ru');
}

function countryRankListBuild(rows, geoFeatures, colorMetric = 'share') {
  const dataByCode = {};
  for (const row of rows) {
    const code = String(row.countryCode || '').trim();
    if (code) dataByCode[code] = row;
  }

  const items = [];
  for (const feature of geoFeatures) {
    const code = geoFeatureCode(feature.properties);
    if (!code) continue;
    const row = dataByCode[code];
    const sharePercent = row ? Number(row.sharePercent) || 0 : 0;
    items.push({
      code,
      label: feature.properties?.NAME_RU || feature.properties?.NAME || code,
      flag: countryFlagEmoji(code),
      sharePercent,
      trafficGb: row ? Number(row.trafficGb) || 0 : 0,
    });
  }

  if (dataByCode['??']) {
    const row = dataByCode['??'];
    items.push({
      code: '??',
      label: 'Неизвестно',
      flag: countryFlagEmoji('??'),
      sharePercent: Number(row.sharePercent) || 0,
      trafficGb: Number(row.trafficGb) || 0,
    });
  }

  items.sort((a, b) => countryRankListSort(a, b, colorMetric));

  return items;
}

const COUNTRY_RANK_COLLAPSED = 5;

function CountryRankList({ rows = [], listKey = '', colorMetric = 'share' }) {
  const [expanded, setExpanded] = useState(false);
  const [geo, setGeo] = useState(worldGeoJsonCache);

  useEffect(() => {
    setExpanded(false);
  }, [listKey]);

  useEffect(() => {
    let cancelled = false;
    if (worldGeoJsonCache) {
      setGeo(worldGeoJsonCache);
      return undefined;
    }
    loadWorldGeoJson()
      .then((data) => { if (!cancelled) setGeo(data); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const allItems = useMemo(() => {
    if (geo?.features?.length) {
      return countryRankListBuild(rows, geo.features, colorMetric);
    }
    return rows
      .filter((r) => r.countryCode !== '??')
      .slice()
      .map((r) => ({
        code: r.countryCode,
        label: countryDisplayName(r.countryCode),
        flag: countryFlagEmoji(r.countryCode),
        sharePercent: Number(r.sharePercent) || 0,
        trafficGb: Number(r.trafficGb) || 0,
      }))
      .sort((a, b) => countryRankListSort(a, b, colorMetric));
  }, [rows, geo, colorMetric]);

  if (!allItems.length) return null;

  const visible = expanded ? allItems : allItems.slice(0, COUNTRY_RANK_COLLAPSED);
  const hiddenCount = Math.max(0, allItems.length - COUNTRY_RANK_COLLAPSED);
  const canExpand = hiddenCount > 0;
  const maxMetric = colorMetric === 'volume'
    ? (allItems[0]?.trafficGb || 1)
    : (allItems[0]?.sharePercent || 1);

  return (
    <div className={`country-rank-list${expanded ? ' country-rank-list--expanded' : ''}`}>
      <div className="country-rank-list__items">
        {visible.map((it) => {
          const metricValue = colorMetric === 'volume' ? it.trafficGb : it.sharePercent;
          const pctBar = maxMetric > 0 ? (metricValue / maxMetric) * 100 : 0;
          const isZero = metricValue === 0;
          const metricLabel = colorMetric === 'volume'
            ? fmtVolumeSize(it.trafficGb)
            : `${it.sharePercent.toFixed(2)}%`;
          return (
            <div
              key={it.code}
              className={`country-rank-list__row${isZero ? ' country-rank-list__row--zero' : ''}`}
            >
              <div className="country-rank-list__head">
                <span className="country-rank-list__flag">{it.flag}</span>
                <span className="country-rank-list__label">{it.label}</span>
                <span className="country-rank-list__pct mono">{metricLabel}</span>
              </div>
              <div className="country-rank-list__track">
                <div
                  className="country-rank-list__fill"
                  style={{ width: `${pctBar}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
      {canExpand && (
        <button
          type="button"
          className="country-rank-list__toggle"
          aria-expanded={expanded}
          onClick={() => setExpanded((v) => !v)}
        >
          <Icon name={expanded ? 'chevU' : 'chevD'} size={14} />
          <span>{expanded ? 'Свернуть' : `Ещё ${hiddenCount} ${hiddenCount === 1 ? 'страна' : hiddenCount < 5 ? 'страны' : 'стран'}`}</span>
        </button>
      )}
    </div>
  );
}

function countryBarListItems(rows, colorMetric, nameByCode) {
  return rows
    .filter((r) => r.countryCode !== '??')
    .slice()
    .sort((a, b) => b.trafficGb - a.trafficGb)
    .slice(0, 5)
    .map((r) => {
      const code = r.countryCode;
      return {
        label: countryDisplayName(code, nameByCode),
        flag: countryFlagEmoji(code),
        value: colorMetric === 'volume' ? r.trafficGb : r.sharePercent,
        raw: r,
      };
    });
}

Object.assign(window, {
  loadWorldGeoJson,
  countryFlagEmoji,
  countryDisplayName,
  countryBarListItems,
  CountryRankList,
});

/* ============== Sankey (simple, 2 columns) ============== */
function sankeyTruncateLabel(label, maxLen = 28) {
  const text = String(label ?? '');
  return text.length > maxLen ? `${text.slice(0, maxLen - 1)}…` : text;
}

function Sankey({
  left,
  right,
  links,
  height = 240,
  maxHeight = 720,
  minBarHeight = 6,
}) {
  // left/right: [{ id, label, color }]; links: [{ from, to, value }]
  const w = 600;
  const colW = 12;
  const totalL = {};
  const totalR = {};
  links.forEach((l) => {
    totalL[l.from] = (totalL[l.from] || 0) + l.value;
    totalR[l.to] = (totalR[l.to] || 0) + l.value;
  });
  const sumL = Object.values(totalL).reduce((a, b) => a + b, 0) || 1;
  const sumR = Object.values(totalR).reduce((a, b) => a + b, 0) || 1;
  const leftSorted = [...left].sort((a, b) => (totalL[b.id] || 0) - (totalL[a.id] || 0));
  const rightSorted = [...right].sort((a, b) => (totalR[b.id] || 0) - (totalR[a.id] || 0));
  const maxNodes = Math.max(leftSorted.length, rightSorted.length, 1);
  const gap = maxNodes > 40 ? 1 : maxNodes > 20 ? 2 : maxNodes > 10 ? 4 : 6;
  const minBar = minBarHeight;
  const drawableH = Math.max(height, maxNodes * minBar + Math.max(0, maxNodes - 1) * gap);
  const h = drawableH;
  const flowAreaL = Math.max(h - gap * Math.max(leftSorted.length - 1, 0), 1);
  const flowAreaR = Math.max(h - gap * Math.max(rightSorted.length - 1, 0), 1);
  let yL = 0;
  let yR = 0;
  const leftPos = {};
  leftSorted.forEach((n) => {
    const ny = (totalL[n.id] || 0) / sumL * flowAreaL;
    leftPos[n.id] = { y: yL, h: ny, node: n };
    yL += ny + gap;
  });
  const rightPos = {};
  rightSorted.forEach((n) => {
    const ny = (totalR[n.id] || 0) / sumR * flowAreaR;
    rightPos[n.id] = { y: yR, h: ny, node: n };
    yR += ny + gap;
  });
  const lCur = {};
  const rCur = {};
  leftSorted.forEach((n) => { lCur[n.id] = leftPos[n.id].y; });
  rightSorted.forEach((n) => { rCur[n.id] = rightPos[n.id].y; });
  const labelFor = (node, barH) => (barH >= 12 ? sankeyTruncateLabel(node.label) : '');

  return (
    <div
      className="explorer-sankey"
      style={{
        maxHeight: `min(70vh, ${maxHeight}px)`,
        overflowY: 'auto',
        overflowX: 'hidden',
        paddingRight: 2,
      }}
    >
      <svg viewBox={`0 0 ${w} ${h}`} style={{ width: '100%', height: h, display: 'block', minHeight: h }}>
        {leftSorted.map((n) => (
          <g key={n.id}>
            <rect x={0} y={leftPos[n.id].y} width={colW} height={leftPos[n.id].h} fill={n.color} rx="2">
              <title>{n.label}</title>
            </rect>
            {labelFor(n, leftPos[n.id].h) && (
              <text x={colW + 6} y={leftPos[n.id].y + leftPos[n.id].h / 2 + 4} fontSize="11" fill="var(--fg-primary)" fontFamily="Mulish" fontWeight="600">
                {labelFor(n, leftPos[n.id].h)}
              </text>
            )}
          </g>
        ))}
        {rightSorted.map((n) => (
          <g key={n.id}>
            <rect x={w - colW} y={rightPos[n.id].y} width={colW} height={rightPos[n.id].h} fill={n.color} rx="2">
              <title>{n.label}</title>
            </rect>
            {labelFor(n, rightPos[n.id].h) && (
              <text x={w - colW - 6} y={rightPos[n.id].y + rightPos[n.id].h / 2 + 4} textAnchor="end" fontSize="11" fill="var(--fg-primary)" fontFamily="Mulish" fontWeight="600">
                {labelFor(n, rightPos[n.id].h)}
              </text>
            )}
          </g>
        ))}
        {links.map((l, i) => {
          const lp = leftPos[l.from];
          const rp = rightPos[l.to];
          if (!lp || !rp) return null;
          const lh = (l.value / sumL) * flowAreaL;
          const rh = (l.value / sumR) * flowAreaR;
          const y0 = lCur[l.from];
          lCur[l.from] += lh;
          const y1 = rCur[l.to];
          rCur[l.to] += rh;
          const x0 = colW;
          const x1 = w - colW;
          const mid = (x0 + x1) / 2;
          const path = `M ${x0} ${y0} C ${mid} ${y0}, ${mid} ${y1}, ${x1} ${y1} L ${x1} ${y1 + rh} C ${mid} ${y1 + rh}, ${mid} ${y0 + lh}, ${x0} ${y0 + lh} Z`;
          return <path key={i} d={path} fill={lp.node.color} opacity="0.32" />;
        })}
      </svg>
    </div>
  );
}

/* ============== Format helpers ============== */
function fmtBytes(b) {
  if (b == null) return '—';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'];
  let i = 0; let v = b;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}
function fmtBits(bps) {
  if (bps == null) return '—';
  const units = ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с', 'Тбит/с', 'Пбит/с'];
  let i = 0;
  let v = Math.abs(Number(bps)) || 0;
  const sign = Number(bps) < 0 ? '-' : '';
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${sign}${v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)} ${units[i]}`;
}
/** Compact Y-axis labels so "0.57 Тбит/с" fits in the left pad. */
function fmtBitsAxis(bps) {
  if (bps == null) return '';
  const units = ['', 'K', 'M', 'G', 'T', 'P'];
  let i = 0;
  let v = Math.abs(Number(bps)) || 0;
  const sign = Number(bps) < 0 ? '-' : '';
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  if (i === 0) return `${sign}${Math.round(v)}`;
  const num = v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : v.toFixed(0);
  return `${sign}${num}${units[i]}`;
}
function fmtNum(n) {
  if (n == null) return '—';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + ' млрд';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' млн';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + ' тыс';
  return String(Math.round(n));
}
function fmtGbps(bps) {
  if (bps == null || bps === 0) return '0 Gbps';
  const g = bps / 1e9;
  if (g >= 1000) {
    const t = g / 1000;
    return `${t >= 100 ? Math.round(t) : t >= 10 ? t.toFixed(0) : t.toFixed(1)} Tbps`;
  }
  return `${g >= 100 ? Math.round(g) : g >= 10 ? g.toFixed(0) : g.toFixed(1)} Gbps`;
}
function fmtMpps(pps) {
  if (pps == null || pps === 0) return '0 Mpps';
  const m = pps / 1e6;
  return `${m >= 100 ? Math.round(m) : m >= 10 ? m.toFixed(0) : m.toFixed(1)} Mpps`;
}
function fmtGbTotal(bytes) {
  if (bytes == null || bytes === 0) return '0 Gb';
  const bits = bytes * 8;
  if (bits >= 1e15) return `${(bits / 1e15).toFixed(bits >= 10e15 ? 0 : 1)} Pb`;
  if (bits >= 1e12) return `${(bits / 1e12).toFixed(bits >= 10e12 ? 0 : 1)} Tb`;
  if (bits >= 1e9) return `${(bits / 1e9).toFixed(bits >= 10e9 ? 0 : 1)} Gb`;
  return `${(bits / 1e6).toFixed(1)} Mb`;
}
function fmtVolumeSize(gb = 0, tb = 0) {
  const totalTb = tb >= 1 ? tb : gb / 1000;
  if (totalTb >= 1000) {
    const pb = totalTb / 1000;
    return `${pb >= 100 ? Math.round(pb) : pb >= 10 ? pb.toFixed(0) : pb.toFixed(1)} Pb`;
  }
  if (totalTb >= 1) {
    return `${totalTb >= 100 ? Math.round(totalTb) : totalTb >= 10 ? totalTb.toFixed(0) : totalTb.toFixed(1)} Tb`;
  }
  if (gb >= 1) return `${gb >= 100 ? Math.round(gb) : gb >= 10 ? gb.toFixed(0) : gb.toFixed(1)} Gb`;
  if (gb > 0) return `${(gb * 1000).toFixed(1)} Mb`;
  return '0 Gb';
}
function fmtMpTotal(packets) {
  if (packets == null || packets === 0) return '0 Mp';
  if (packets >= 1e12) return `${(packets / 1e12).toFixed(packets >= 10e12 ? 0 : 1)} Tp`;
  if (packets >= 1e9) return `${(packets / 1e9).toFixed(packets >= 10e9 ? 0 : 1)} Bp`;
  const mp = packets / 1e6;
  return `${mp >= 100 ? Math.round(mp) : mp >= 10 ? mp.toFixed(0) : mp.toFixed(1)} Mp`;
}
function fmtCompact(n) {
  if (n == null) return '';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(Math.round(n));
}
function fmtTime(d) {
  const date = typeof d === 'string' || typeof d === 'number' ? new Date(d) : d;
  return date.toLocaleString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}
function fmtAgo(d) {
  const date = typeof d === 'string' || typeof d === 'number' ? new Date(d) : d;
  const s = (Date.now() - date.getTime()) / 1000;
  if (s < 60) return `${Math.floor(s)} с назад`;
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
  if (s < 86400) return `${Math.floor(s / 3600)} ч назад`;
  return `${Math.floor(s / 86400)} дн назад`;
}

Object.assign(window, {
  AreaChart, DualChart, CategoryTrendChart, TimeSeriesSparkChart, Sparkline, Donut, filterNonZeroDonutSegments, filterNonZeroDonutWithOtherLast, donutCenterTraffic, donutCenterTrafficGb, BarList, WorldHeat, CountryChoropleth, CountryRankList, Sankey,
  computeChartPeriodBounds, chartRangeFromPointSelection, parseChartBucketMs,
  fillChartTimeGaps, buildChartTimeScale,
  formatChartPointTimeLabel, formatPointTimeLabel, formatBucketLabel, formatTipPointTime, formatTipBucketDuration, normalizeBucketString, isLongChartRange,
  msToDatetimeLocalValue, msToBucketString, bucketToDatetimeLocalInput, resolvePointEpochMs,
  getDataTimezone, setDataTimezone, DATA_TIMEZONE, detectBrowserTimezone, loadTimezonePreference, saveTimezonePreference,
  resolveDisplayTimezone, getDisplayTimezone, setDisplayTimezonePreference,
  formatTimezoneShortLabel, formatTimezoneLongLabel,
  dataDatetimeLocalToDisplay, displayDatetimeLocalToData,
  fmtBytes, fmtBits, fmtBitsAxis, fmtNum, fmtGbps, fmtMpps, fmtGbTotal, fmtVolumeSize, fmtMpTotal, fmtCompact, fmtTime, fmtAgo,
});
