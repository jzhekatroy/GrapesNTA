function envBool(name, fallback = false) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

const verbose = envBool('LOG_VERBOSE', process.env.NODE_ENV !== 'production');

let easterEggShown = false;

function maybeLogEasterEgg() {
  if (!verbose || easterEggShown) return;
  easterEggShown = true;
  console.log('https://www.youtube.com/watch?v=0jOC-RClgr4');
}

function tag(level) {
  return `[Grapes · ${level}]`;
}

function summarizeBody(body) {
  if (!body || typeof body !== 'object') return body;
  const out = Array.isArray(body) ? [...body] : { ...body };
  for (const key of Object.keys(out)) {
    if (/password|password_hash|community/i.test(key)) {
      out[key] = '***';
    } else if (out[key] && typeof out[key] === 'object') {
      out[key] = summarizeBody(out[key]);
    }
  }
  if (typeof out.sql === 'string') {
    const sql = out.sql.trim();
    out.sql = sql.length > 120 ? `${sql.slice(0, 120)}… (${sql.length} chars)` : sql;
  }
  return out;
}

function logVerbose(level, ...args) {
  if (!verbose) return;
  console.log(tag(level), ...args);
  maybeLogEasterEgg();
}

function logApiIncoming(req) {
  if (!verbose) return;

  const query = req.query && Object.keys(req.query).length > 0 ? req.query : null;
  console.log(`\n${tag('API')} → ${req.method} ${req.originalUrl || req.url}`);

  if (query) {
    console.log(tag('API · query'), JSON.stringify(query, null, 2));
  }

  if (req.method === 'POST' && req.body && Object.keys(req.body).length > 0) {
    console.log(tag('API · body'), JSON.stringify(summarizeBody(req.body), null, 2));
  }
}

function formatApiMeta(meta) {
  if (!meta || typeof meta !== 'object') return '';

  const { elapsedMs: sqlMs, rows, ...rest } = meta;
  const parts = [];
  if (sqlMs != null) parts.push(`SQL ${sqlMs} ms`);
  if (rows != null) parts.push(`${rows} row(s)`);

  const restKeys = Object.keys(rest);
  if (restKeys.length) parts.push(JSON.stringify(rest));

  return parts.length ? ` · ${parts.join(' · ')}` : '';
}

function logApiDone(route, statusCode, elapsedMs, meta) {
  if (!verbose) return;

  console.log(
    `${tag('API')} ← ${route} · HTTP ${statusCode} · ${elapsedMs} ms${formatApiMeta(meta)}\n`,
  );
}

function logSqlStart(name, sql, params) {
  const hasParams = params && Object.keys(params).length > 0;
  console.log(`\n${tag(`SQL · ${name}`)}`);
  console.log(sql.trim());
  if (hasParams) console.log(tag(`SQL · ${name} · params`), JSON.stringify(params, null, 2));
}

function logSqlDone(name, rows, sqlMs, { logText = false } = {}) {
  const line = `${tag(`SQL · ${name}`)} OK · ${rows} row(s) · ${sqlMs} ms`;
  if (logText) console.log(`${line}\n`);
  else logVerbose(`SQL · ${name}`, `OK · ${rows} row(s) · ${sqlMs} ms`);
}

function logSqlError(name, err, sqlMs) {
  const msg = err?.message || String(err);
  console.error(`${tag(`SQL · ${name}`)} ERROR · ${sqlMs} ms · ${msg}\n`);
}

function logApiError(route, err, elapsedMs) {
  const msg = err?.message || String(err);
  console.error(`${tag('API')} ✗ ${route} · ${elapsedMs} ms · ${msg}\n`);
}

function getLogConfig() {
  return { verbose };
}

module.exports = {
  logVerbose,
  logApiIncoming,
  logApiDone,
  logApiError,
  logSqlStart,
  logSqlDone,
  logSqlError,
  getLogConfig,
};
