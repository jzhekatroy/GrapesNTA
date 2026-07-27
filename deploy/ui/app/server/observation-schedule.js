'use strict';

const DEFAULT_TIMEZONE = 'Europe/Moscow';
const DEFAULT_TIME = '08:00';
const RU_MONTHS = [
  'января', 'февраля', 'марта', 'апреля', 'мая', 'июня',
  'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря',
];

function isValidTimeZone(timeZone) {
  try {
    Intl.DateTimeFormat('en-US', { timeZone }).format(new Date());
    return true;
  } catch {
    return false;
  }
}

function parseTime(value, fallback = DEFAULT_TIME) {
  const s = String(value ?? fallback).trim();
  const m = /^(\d{1,2}):(\d{2})$/.exec(s);
  if (!m) return fallback.split(':').map(Number);
  const hour = Number(m[1]);
  const minute = Number(m[2]);
  if (!Number.isInteger(hour) || !Number.isInteger(minute) || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    return fallback.split(':').map(Number);
  }
  return [hour, minute];
}

function formatTime(hour, minute) {
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function boundedInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return fallback;
  return n;
}

function buildSchedule(raw = {}, prev = {}) {
  const kind = ['daily', 'weekly', 'monthly'].includes(raw.kind)
    ? raw.kind
    : (['daily', 'weekly', 'monthly'].includes(prev.kind) ? prev.kind : 'daily');

  const [hour, minute] = parseTime(raw.time ?? prev.time);
  const time = formatTime(hour, minute);

  const timezoneRaw = String(raw.timezone ?? prev.timezone ?? DEFAULT_TIMEZONE).trim();
  const timezone = isValidTimeZone(timezoneRaw) ? timezoneRaw : DEFAULT_TIMEZONE;

  return {
    kind,
    time,
    weekday: kind === 'weekly'
      ? boundedInt(raw.weekday ?? prev.weekday, 1, 1, 7)
      : boundedInt(prev.weekday, 1, 1, 7),
    day: kind === 'monthly'
      ? boundedInt(raw.day ?? prev.day, 1, 1, 28)
      : boundedInt(prev.day, 1, 1, 28),
    timezone,
  };
}

function normalizeSchedule(raw = {}, existing = {}) {
  const prevSchedule = existing?.schedule
    || existing?.report?.schedule
    || {};
  const incoming = raw.schedule && typeof raw.schedule === 'object' ? raw.schedule : null;

  if (incoming?.kind) {
    return buildSchedule(incoming, prevSchedule);
  }

  const hasPrev = Boolean(prevSchedule.kind);
  const cronProvided = raw.cron !== undefined && raw.cron !== null && String(raw.cron).trim() !== '';
  const cron = String(raw.cron ?? existing?.cron ?? existing?.report?.cron ?? '').trim();

  if (hasPrev && !cronProvided && !incoming) {
    return buildSchedule(prevSchedule, prevSchedule);
  }

  return buildSchedule({
    kind: 'daily',
    time: DEFAULT_TIME,
    timezone: raw.timezone ?? existing?.timezone ?? existing?.report?.timezone ?? prevSchedule.timezone,
  }, prevSchedule);
}

function getZonedParts(date, timeZone) {
  const d = date instanceof Date ? date : new Date(date);
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = Object.fromEntries(fmt.formatToParts(d).map((p) => [p.type, p.value]));
  return {
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    second: Number(parts.second),
  };
}

function getZonedYmdHm(date, timeZone) {
  const z = getZonedParts(date, timeZone);
  return {
    year: z.year,
    month: z.month,
    day: z.day,
    hour: z.hour,
    minute: z.minute,
  };
}

function zonedLocalToUtcIso(year, month, day, hour, minute, timeZone) {
  // Guess as if the local wall time were UTC, then correct by the observed offset.
  let utcMs = Date.UTC(year, month - 1, day, hour, minute, 0);
  for (let i = 0; i < 4; i += 1) {
    const z = getZonedParts(new Date(utcMs), timeZone);
    const asUtc = Date.UTC(z.year, z.month - 1, z.day, z.hour, z.minute, z.second || 0);
    const target = Date.UTC(year, month - 1, day, hour, minute, 0);
    const delta = target - asUtc;
    utcMs += delta;
    if (delta === 0) break;
  }
  const check = getZonedParts(new Date(utcMs), timeZone);
  if (
    check.year !== year
    || check.month !== month
    || check.day !== day
    || check.hour !== hour
    || check.minute !== minute
  ) {
    throw new Error(`Cannot resolve local time ${year}-${month}-${day} ${hour}:${minute} in ${timeZone}`);
  }
  // Snap to exact minute start (drop residual seconds from offset math).
  utcMs -= (check.second || 0) * 1000;
  return new Date(utcMs).toISOString();
}

function previousLocalDay(year, month, day, timeZone) {
  const startMs = Date.parse(zonedLocalToUtcIso(year, month, day, 0, 0, timeZone));
  return getZonedYmdHm(new Date(startMs - 1), timeZone);
}

function localWeekday(year, month, day, timeZone) {
  const iso = zonedLocalToUtcIso(year, month, day, 12, 0, timeZone);
  const wd = new Intl.DateTimeFormat('en-US', { timeZone, weekday: 'short' }).format(new Date(iso));
  const map = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
  return map[wd] || 1;
}

function formatPeriodLabelYmd(year, month, day, timeZone) {
  const monthName = RU_MONTHS[month - 1] || String(month);
  return `${day} ${monthName} ${year}, 00:00–24:00 (${timeZone})`;
}

function reportWindowForPeriod(period, schedule, now = new Date()) {
  const tz = schedule?.timezone || DEFAULT_TIMEZONE;
  const p = period === 'last_24h' ? 'last_24h' : 'yesterday';

  if (p === 'last_24h') {
    const to = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
    const from = new Date(Date.parse(to) - 86400 * 1000).toISOString();
    return {
      from,
      to,
      period: p,
      range: 'custom',
      label: `Последние 24 часа (${tz})`,
    };
  }

  const z = getZonedYmdHm(now, tz);
  const y = previousLocalDay(z.year, z.month, z.day, tz);
  const from = zonedLocalToUtcIso(y.year, y.month, y.day, 0, 0, tz);
  const to = zonedLocalToUtcIso(z.year, z.month, z.day, 0, 0, tz);
  return {
    from,
    to,
    period: 'yesterday',
    range: 'custom',
    label: formatPeriodLabelYmd(y.year, y.month, y.day, tz),
  };
}

function lastScheduledSlot(schedule, now = new Date()) {
  const tz = schedule?.timezone || DEFAULT_TIMEZONE;
  const [hour, minute] = parseTime(schedule?.time);
  const nowDate = now instanceof Date ? now : new Date(now);

  if (schedule?.kind === 'weekly') {
    let ymd = getZonedYmdHm(nowDate, tz);
    for (let i = 0; i < 400; i += 1) {
      if (localWeekday(ymd.year, ymd.month, ymd.day, tz) === schedule.weekday) {
        const slot = new Date(zonedLocalToUtcIso(ymd.year, ymd.month, ymd.day, hour, minute, tz));
        if (slot.getTime() <= nowDate.getTime()) return slot;
      }
      ymd = previousLocalDay(ymd.year, ymd.month, ymd.day, tz);
    }
    return null;
  }

  if (schedule?.kind === 'monthly') {
    const z = getZonedYmdHm(nowDate, tz);
    let y = z.year;
    let m = z.month;
    for (let i = 0; i < 36; i += 1) {
      const slot = new Date(zonedLocalToUtcIso(y, m, schedule.day, hour, minute, tz));
      if (slot.getTime() <= nowDate.getTime()) return slot;
      m -= 1;
      if (m < 1) {
        m = 12;
        y -= 1;
      }
    }
    return null;
  }

  const z = getZonedYmdHm(nowDate, tz);
  const todaySlot = new Date(zonedLocalToUtcIso(z.year, z.month, z.day, hour, minute, tz));
  if (todaySlot.getTime() <= nowDate.getTime()) return todaySlot;
  const prev = previousLocalDay(z.year, z.month, z.day, tz);
  return new Date(zonedLocalToUtcIso(prev.year, prev.month, prev.day, hour, minute, tz));
}

function isScheduleDue(schedule, lastSuccessIso, now = new Date(), { graceHours = 6 } = {}) {
  const slot = lastScheduledSlot(schedule, now);
  if (!slot) return false;

  const nowMs = (now instanceof Date ? now : new Date(now)).getTime();
  const slotMs = slot.getTime();
  const graceMs = graceHours * 3600 * 1000;
  if (nowMs - slotMs > graceMs) return false;

  if (!lastSuccessIso) return true;
  const lastMs = Date.parse(String(lastSuccessIso));
  if (!Number.isFinite(lastMs)) return true;
  return lastMs < slotMs;
}

module.exports = {
  normalizeSchedule,
  getZonedYmdHm,
  zonedLocalToUtcIso,
  reportWindowForPeriod,
  lastScheduledSlot,
  isScheduleDue,
  DEFAULT_TIMEZONE,
};
