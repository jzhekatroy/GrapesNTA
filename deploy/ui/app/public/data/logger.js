/* Логи и метрики загрузки виджетов dashboard (LOG_VERBOSE → /runtime-config.js) */

const DashboardLog = (() => {
  let suppressed = false;

  // Клиентский кабинет не показывает время загрузки даже при LOG_VERBOSE.
  function setSuppressed(value) {
    suppressed = !!value;
  }

  function isVerbose() {
    return !suppressed && window.__GRAPES_RUNTIME__?.verbose === true;
  }

  function tag(widget) {
    return `[Grapes · dashboard · ${widget}]`;
  }

  function formatParts(extra = {}) {
    const parts = [];
    if (extra.loadMs != null) parts.push(`${extra.loadMs} ms`);
    if (extra.serverMs != null) parts.push(`SQL ${extra.serverMs} ms`);
    if (extra.rows != null) parts.push(`${extra.rows} row(s)`);
    if (extra.source) parts.push(extra.source);
    if (extra.error) parts.push(`ERROR ${extra.error}`);
    return parts.join(' · ');
  }

  function fetchStart(name) {
    const started = performance.now();
    if (isVerbose()) console.log(`${tag(name)} fetch…`);
    return (extra = {}) => {
      const loadMs = Math.round(performance.now() - started);
      if (isVerbose()) console.log(`${tag(name)} fetch · ${formatParts({ ...extra, loadMs })}`);
      return { loadMs, ...extra };
    };
  }

  function widgetStart(widget) {
    const started = performance.now();
    if (isVerbose()) console.log(`${tag(`widget · ${widget}`)} загрузка…`);
    return (extra = {}) => {
      const loadMs = Math.round(performance.now() - started);
      if (isVerbose()) console.log(`${tag(`widget · ${widget}`)} готово · ${formatParts({ ...extra, loadMs })}`);
      return { loadMs, ...extra };
    };
  }

  function batchStart(label) {
    const started = performance.now();
    if (isVerbose()) console.log(`${tag(label)} batch · старт`);
    return (extra = {}) => {
      const loadMs = Math.round(performance.now() - started);
      if (isVerbose()) console.log(`${tag(label)} batch · готово · ${formatParts({ ...extra, loadMs })}`);
      return { loadMs, ...extra };
    };
  }

  return { fetchStart, widgetStart, batchStart, isVerbose, setSuppressed };
})();

Object.assign(window, { DashboardLog });
