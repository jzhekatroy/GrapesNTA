'use strict';

const { AsyncLocalStorage } = require('async_hooks');

const storage = new AsyncLocalStorage();

function getRequestContext() {
  return storage.getStore() || null;
}

function runWithRequestContext(store, fn) {
  return storage.run(store, fn);
}

function setFailedSql(details) {
  const ctx = getRequestContext();
  if (!ctx) return;
  ctx.failedSql = {
    name: details?.name || null,
    sql: details?.sql || '',
    params: details?.params && typeof details.params === 'object' ? details.params : {},
    error: details?.error || '',
    elapsedMs: details?.elapsedMs ?? null,
    sqlInlined: details?.sqlInlined || '',
  };
}

module.exports = {
  getRequestContext,
  runWithRequestContext,
  setFailedSql,
};
