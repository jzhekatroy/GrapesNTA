/* Язык интерфейса: ru/en. Переводов строк пока нет, модуль только выбирает и запоминает код. */
(function (global) {
  const LOCALES = [
    { id: 'ru', label: 'Русский', short: 'RU' },
    { id: 'en', label: 'English', short: 'EN' },
  ];
  const SUPPORTED = new Set(LOCALES.map((item) => item.id));
  const PENDING_KEY = 'grapes-locale-pending';

  function normalizeLocale(value) {
    const locale = String(value ?? '').trim().toLowerCase();
    return SUPPORTED.has(locale) ? locale : '';
  }

  function detectBrowserLocale() {
    const tags = [];
    if (Array.isArray(global.navigator?.languages)) tags.push(...global.navigator.languages);
    if (global.navigator?.language) tags.push(global.navigator.language);
    for (const tag of tags) {
      const primary = String(tag || '').trim().toLowerCase().split('-')[0];
      if (SUPPORTED.has(primary)) return primary;
    }
    return 'ru';
  }

  function readPendingLocale() {
    try {
      return normalizeLocale(global.sessionStorage?.getItem(PENDING_KEY));
    } catch (err) {
      return '';
    }
  }

  function writePendingLocale(locale) {
    const normalized = normalizeLocale(locale);
    if (!normalized) return;
    try {
      global.sessionStorage.setItem(PENDING_KEY, normalized);
    } catch (err) {
      /* приватный режим может запретить sessionStorage */
    }
  }

  function clearPendingLocale() {
    try {
      global.sessionStorage.removeItem(PENDING_KEY);
    } catch (err) {
      /* ignore */
    }
  }

  function resolveDisplayLocale({ accountLocale, pending } = {}) {
    return normalizeLocale(accountLocale)
      || normalizeLocale(pending)
      || detectBrowserLocale();
  }

  global.GrapesLocale = {
    LOCALES,
    normalizeLocale,
    detectBrowserLocale,
    readPendingLocale,
    writePendingLocale,
    clearPendingLocale,
    resolveDisplayLocale,
  };
})(window);
