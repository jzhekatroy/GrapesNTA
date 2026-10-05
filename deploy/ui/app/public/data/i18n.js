(function (global) {
  const PAGE_SECTION_KEY = {
    dashboard: 'overview',
    observations: 'overview',
    dns: 'overview',
    explorer: 'traffic',
    'dns-explorer': 'traffic',
    top: 'traffic',
    collectors: 'data',
    snmp: 'data',
    bmp: 'data',
    'traffic-classification': 'netmodel',
    cidr: 'netmodel',
    'dns-resolvers': 'netmodel',
    'interface-roles': 'netmodel',
    'port-services': 'netmodel',
    users: 'admin',
    audit: 'admin',
    clients: 'admin',
    smtp: 'admin',
    ttl: 'admin',
  };

  const NAV_SECTION_IDS = {
    overview: 'overview',
    traffic: 'traffic',
    settings: 'settings',
    data: 'data',
    netmodel: 'netmodel',
    admin: 'admin',
  };

  const TZ_PRESET_LABEL_KEY = {
    auto: 'tz.auto',
    'Europe/Moscow': 'tz.moscow',
    'Europe/Kaliningrad': 'tz.kaliningrad',
    'Europe/Samara': 'tz.samara',
    'Asia/Yekaterinburg': 'tz.yekaterinburg',
    'Asia/Omsk': 'tz.omsk',
    'Asia/Krasnoyarsk': 'tz.krasnoyarsk',
    'Asia/Irkutsk': 'tz.irkutsk',
    'Asia/Yakutsk': 'tz.yakutsk',
    'Asia/Vladivostok': 'tz.vladivostok',
    UTC: 'tz.utc',
  };

  const BUILTIN_ROLE_IDS = new Set(['Administrator', 'Operator', 'ReadOnly', 'Client']);

  let locale = 'ru';
  let revision = 0;
  const listeners = new Set();

  function messagesFor(loc) {
    const bag = global.GrapesI18nMessages || {};
    return bag[loc] || {};
  }

  function normalizeLocale(value) {
    const loc = String(value || '').trim().toLowerCase();
    return loc === 'en' ? 'en' : 'ru';
  }

  function setLocale(next) {
    const normalized = normalizeLocale(next);
    if (normalized === locale) return;
    locale = normalized;
    revision += 1;
    listeners.forEach((fn) => {
      try { fn(locale, revision); } catch (err) { /* ignore */ }
    });
  }

  function getLocale() {
    return locale;
  }

  function intlLocale() {
    return locale === 'en' ? 'en' : 'ru-RU';
  }

  function subscribe(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  }

  function has(key) {
    const ru = messagesFor('ru');
    const en = messagesFor('en');
    return key in ru || key in en;
  }

  function raw(key, loc) {
    const table = messagesFor(loc);
    if (Object.prototype.hasOwnProperty.call(table, key)) return table[key];
    if (loc !== 'ru') return messagesFor('ru')[key];
    return undefined;
  }

  function t(key, params) {
    const template = raw(key, locale) ?? raw(key, 'ru') ?? key;
    if (!params) return template;
    return String(template).replace(/\{(\w+)\}/g, (_, name) => (
      params[name] !== undefined && params[name] !== null ? String(params[name]) : `{${name}}`
    ));
  }

  function navItemLabel(pageId) {
    const key = `nav.item.${pageId}`;
    return has(key) ? t(key) : null;
  }

  function navSectionLabel(sectionId) {
    const mapped = NAV_SECTION_IDS[sectionId];
    if (!mapped) return null;
    return t(`nav.section.${mapped}`);
  }

  function localizedPageMeta(pageId, registryEntry) {
    const item = navItemLabel(pageId);
    const sectionKey = PAGE_SECTION_KEY[pageId];
    if (item && sectionKey) {
      return {
        title: item,
        section: t(`nav.section.${sectionKey}`),
      };
    }
    if (registryEntry) return registryEntry;
    return { title: pageId, section: '' };
  }

  function localizedRoleDisplay(roleId, displayName) {
    if (roleId && BUILTIN_ROLE_IDS.has(roleId)) {
      const key = `role.${roleId}`;
      if (has(key)) return t(key);
    }
    return displayName || t('user.fallbackName');
  }

  function timezonePresetLabel(presetId) {
    const key = TZ_PRESET_LABEL_KEY[presetId];
    return key ? t(key) : presetId;
  }

  global.GrapesI18n = {
    PAGE_SECTION_KEY,
    NAV_SECTION_IDS,
    TZ_PRESET_LABEL_KEY,
    BUILTIN_ROLE_IDS,
    setLocale,
    getLocale,
    intlLocale,
    subscribe,
    has,
    t,
    navItemLabel,
    navSectionLabel,
    localizedPageMeta,
    localizedRoleDisplay,
    timezonePresetLabel,
  };
})(window);
