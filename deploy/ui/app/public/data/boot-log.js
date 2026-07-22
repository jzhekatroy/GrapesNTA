/* Диагностика экрана загрузки (LOG_VERBOSE на сервере → /runtime-config.js) */

const BootLog = (() => {
  const t0 = performance.now();
  let stepIndex = 0;
  let mounted = false;
  let failed = false;
  let lastLabel = 'инициализация';
  let heartbeatTimer = null;
  let stallTimer = null;
  let easterEggShown = false;

  function isVerbose() {
    return window.__GRAPES_RUNTIME__?.verbose === true;
  }

  function elapsed() {
    return Math.round(performance.now() - t0);
  }

  function tag() {
    return `[Grapes · boot · ${elapsed()} ms]`;
  }

  function maybeLogEasterEgg() {
    if (!isVerbose() || easterEggShown) return;
    easterEggShown = true;
    console.log('https://www.youtube.com/watch?v=0jOC-RClgr4');
  }

  function ui() {
    return {
      boot: document.getElementById('boot'),
      status: document.getElementById('boot-status'),
      elapsed: document.getElementById('boot-elapsed'),
      log: document.getElementById('boot-log'),
    };
  }

  function appendLogLine(entry) {
    if (!isVerbose()) return;
    const { log } = ui();
    if (!log) return;
    const line = document.createElement('div');
    line.className = `boot__log-line${entry.level === 'error' ? ' is-error' : ''}`;
    line.textContent = `${entry.ms} ms · ${entry.label}`;
    log.appendChild(line);
    while (log.childElementCount > 12) log.firstElementChild?.remove();
    log.scrollTop = log.scrollHeight;
  }

  function refreshElapsed() {
    if (!isVerbose()) return;
    const { elapsed: el } = ui();
    if (el) el.textContent = `${elapsed()} ms`;
  }

  function step(label, { level = 'info', silent = false } = {}) {
    if (mounted || failed) return;
    if (!silent) lastLabel = label;

    if (!isVerbose() && level !== 'error') return;

    stepIndex += 1;
    const entry = { i: stepIndex, ms: elapsed(), label, level };
    if (!silent) console.log(tag(), label);

    const { boot, status } = ui();
    if (!silent && status) status.textContent = label;
    if (!silent) appendLogLine(entry);
    if (boot && level === 'error') boot.classList.add('is-error');

    refreshElapsed();
  }

  function fail(label, detail) {
    if (mounted) return;
    failed = true;
    const msg = detail ? `${label} · ${detail}` : label;
    lastLabel = msg;
    console.error(tag(), msg, detail || '');
    stopTimers();

    const { boot, status } = ui();
    if (boot) boot.classList.add('is-error');
    if (status) status.textContent = msg;
    appendLogLine({ ms: elapsed(), label: msg, level: 'error' });
  }

  function done() {
    if (mounted || failed) return;
    mounted = true;
    if (isVerbose()) step('React смонтирован · скрываем экран загрузки');
    stopTimers();
    requestAnimationFrame(() => document.getElementById('boot')?.remove());
  }

  function stopTimers() {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    if (stallTimer) clearInterval(stallTimer);
    heartbeatTimer = null;
    stallTimer = null;
  }

  function watchMount() {
    const poll = () => {
      if (document.getElementById('root')?.firstChild) {
        done();
        return;
      }
      if (elapsed() > 120000) {
        fail('таймаут 120 с', `React не смонтировался · последний шаг: ${lastLabel}`);
        return;
      }
      setTimeout(poll, 50);
    };
    poll();
  }

  function wireScript(el) {
    if (el.dataset.bootWired) return;
    el.dataset.bootWired = '1';

    const label = el.dataset.bootLabel || el.getAttribute('src')?.split('/').pop() || 'script';
    const kind = el.type === 'text/babel' ? 'JSX/Babel' : 'script';

    el.addEventListener('load', () => {
      step(`загружен · ${kind} · ${label}`);
    });
    el.addEventListener('error', () => {
      fail(`ошибка загрузки · ${label}`);
    });
  }

  function wireScripts() {
    document.querySelectorAll('script[src]').forEach(wireScript);
  }

  function startTimers() {
    heartbeatTimer = setInterval(refreshElapsed, 100);
    stallTimer = setInterval(() => {
      if (mounted || failed) return;
      refreshElapsed();
      appendLogLine({ ms: elapsed(), label: `ожидание · ${lastLabel}`, level: 'info' });
    }, 5000);
  }

  function onWindowError(event) {
    const msg = event.message || 'неизвестная ошибка';
    const where = event.filename ? `${event.filename}:${event.lineno || 0}` : '';
    fail(`ошибка JavaScript · ${msg}`, where);
  }

  function onRejection(event) {
    const reason = event.reason;
    const msg = reason?.message || String(reason || 'unhandled rejection');
    fail(`ошибка promise · ${msg}`);
  }

  function init() {
    const { boot } = ui();
    if (isVerbose() && boot) boot.classList.add('is-verbose');

    wireScripts();
    new MutationObserver(wireScripts).observe(document.documentElement, { childList: true, subtree: true });

    window.addEventListener('error', onWindowError);
    window.addEventListener('unhandledrejection', onRejection);

    if (isVerbose()) {
      step('старт загрузки страницы');
      maybeLogEasterEgg();
      document.addEventListener('DOMContentLoaded', () => step('DOMContentLoaded'));
      startTimers();
    } else {
      lastLabel = 'загрузка';
    }

    watchMount();
  }

  return { step, fail, done, watchMount, wireScripts, init, elapsed, isVerbose };
})();

BootLog.init();
Object.assign(window, { BootLog });
