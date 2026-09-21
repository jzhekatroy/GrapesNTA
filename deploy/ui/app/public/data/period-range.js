'use strict';

/**
 * Границы своего периода для фильтра времени.
 *
 * Запросы трафика фильтруют полуинтервалом `time >= ts_from AND time < ts_to`,
 * и верхняя граница дополнительно округляется вниз до минуты. Поэтому конец
 * периода хранится как первая НЕвключённая минута: сутки 19.09 — это
 * [19.09 00:00, 20.09 00:00), а не «до 23:59», при котором последняя минута
 * суток молча выпадала из выборки.
 *
 * Пользователю полночь следующего дня показывается как 24:00 предыдущего:
 * иначе выбор одного дня выглядел бы в календаре как два.
 */
(function () {
  const DATETIME_LOCAL_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/;
  const END_OF_DAY_HOUR = 24;

  function parseParts(value) {
    const m = String(value || '').match(DATETIME_LOCAL_RE);
    if (!m) return null;
    return {
      y: Number(m[1]), mo: Number(m[2]), d: Number(m[3]), h: Number(m[4]), mi: Number(m[5]),
    };
  }

  function formatParts(parts) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${parts.y}-${pad(parts.mo)}-${pad(parts.d)}T${pad(parts.h)}:${pad(parts.mi)}`;
  }

  function dayKey(parts) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${parts.y}-${pad(parts.mo)}-${pad(parts.d)}`;
  }

  function compareDays(a, b) {
    if (a.y !== b.y) return a.y - b.y;
    if (a.mo !== b.mo) return a.mo - b.mo;
    return a.d - b.d;
  }

  function addDays(parts, deltaDays) {
    const dt = new Date(Date.UTC(parts.y, parts.mo - 1, parts.d + deltaDays));
    return { y: dt.getUTCFullYear(), mo: dt.getUTCMonth() + 1, d: dt.getUTCDate() };
  }

  function isMidnight(parts) {
    return parts.h === 0 && parts.mi === 0;
  }

  /** Хранимый конец периода -> как его показать человеку: полночь становится 24:00 прошлых суток. */
  function endDisplayParts(value) {
    const parts = parseParts(value);
    if (!parts) return null;
    if (!isMidnight(parts)) return parts;
    return { ...addDays(parts, -1), h: END_OF_DAY_HOUR, mi: 0 };
  }

  /** Обратное преобразование: 24:00 суток -> полночь следующих. */
  function endStoredValue(display) {
    if (!display) return '';
    if (display.h < END_OF_DAY_HOUR) return formatParts(display);
    return formatParts({ ...addDays(display, 1), h: 0, mi: 0 });
  }

  function startOfDay(dayParts) {
    return { ...dayParts, h: 0, mi: 0 };
  }

  function wholeDayPeriod(dayParts) {
    return {
      from: formatParts(startOfDay(dayParts)),
      to: endStoredValue({ ...dayParts, h: END_OF_DAY_HOUR, mi: 0 }),
    };
  }

  /**
   * Период по двум кликам в календаре. Дни могут прийти в обратном порядке —
   * тянуть диапазон справа налево так же естественно, как слева направо.
   */
  function buildRangePeriod(startDay, endDay, fromTime, toTime) {
    let start = startDay;
    let end = endDay;
    if (compareDays(end, start) < 0) {
      start = endDay;
      end = startDay;
    }
    return {
      from: formatParts({ ...start, h: fromTime.h, mi: fromTime.mi }),
      to: endStoredValue({ ...end, h: toTime.h, mi: toTime.mi }),
    };
  }

  function orderDays(a, b) {
    return compareDays(a, b) <= 0 ? { start: a, end: b } : { start: b, end: a };
  }

  /** Состояние клетки календаря: попадает ли день в диапазон и где его края. */
  function dayRangeState(day, startDay, endDay) {
    if (!day || !startDay || !endDay) {
      return { inRange: false, isStart: false, isEnd: false, isMiddle: false };
    }
    const { start, end } = orderDays(startDay, endDay);
    const key = dayKey(day);
    const startKey = dayKey(start);
    const endKey = dayKey(end);
    const inRange = key >= startKey && key <= endKey;
    const isStart = key === startKey;
    const isEnd = key === endKey;
    return { inRange, isStart, isEnd, isMiddle: inRange && !isStart && !isEnd };
  }

  function formatHm(parts) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${pad(parts.h)}:${pad(parts.mi)}`;
  }

  function formatPeriodLabel(period) {
    const from = parseParts(period?.from);
    const to = endDisplayParts(period?.to);
    if (!from || !to) return 'Свой период';
    const pad = (n) => String(n).padStart(2, '0');
    const fromDay = `${pad(from.d)}.${pad(from.mo)}`;
    const toDay = `${pad(to.d)}.${pad(to.mo)}`;
    if (dayKey(from) === dayKey(to)) {
      return `${fromDay} ${formatHm(from)}–${formatHm(to)}`;
    }
    return `${fromDay} ${formatHm(from)} — ${toDay} ${formatHm(to)}`;
  }

  /** Целые прошедшие сутки для пресета «Вчера». */
  function yesterdayPeriod(todayParts) {
    return wholeDayPeriod(addDays(todayParts, -1));
  }

  function isWholeDayPeriod(period) {
    const from = parseParts(period?.from);
    const to = endDisplayParts(period?.to);
    if (!from || !to) return false;
    return isMidnight(from) && to.h === END_OF_DAY_HOUR && to.mi === 0 && dayKey(from) === dayKey(to);
  }

  /**
   * Приводит введённое в поле времени к допустимому числу. Пустую строку
   * отдаёт как null: поле должно уметь побыть пустым, пока его перенабирают,
   * иначе первый ноль невозможно стереть.
   */
  function clampTimePart(value, max) {
    const raw = String(value ?? '').trim();
    if (!raw) return null;
    const n = Number(raw);
    if (!Number.isFinite(n)) return null;
    return Math.min(max, Math.max(0, Math.floor(n)));
  }

  const api = {
    END_OF_DAY_HOUR,
    parseParts,
    formatParts,
    dayKey,
    compareDays,
    addDays,
    startOfDay,
    endDisplayParts,
    endStoredValue,
    wholeDayPeriod,
    buildRangePeriod,
    orderDays,
    dayRangeState,
    formatPeriodLabel,
    yesterdayPeriod,
    isWholeDayPeriod,
    clampTimePart,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (typeof window !== 'undefined') {
    window.PeriodRange = api;
  }
}());
