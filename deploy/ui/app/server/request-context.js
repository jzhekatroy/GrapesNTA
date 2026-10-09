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

function enableAuditQueryCapture() {
  const ctx = getRequestContext();
  if (!ctx) return;
  ctx.captureAuditQueries = true;
  if (!Array.isArray(ctx.auditQueries)) ctx.auditQueries = [];
}

function pushAuditQuery(entry) {
  const ctx = getRequestContext();
  if (!ctx?.captureAuditQueries) return;
  if (!Array.isArray(ctx.auditQueries)) ctx.auditQueries = [];
  ctx.auditQueries.push({
    name: entry?.name || '',
    elapsedMs: entry?.elapsedMs ?? null,
    sql: entry?.sql || '',
    error: entry?.error || null,
  });
}

function getAuditQueries() {
  const ctx = getRequestContext();
  return Array.isArray(ctx?.auditQueries) ? ctx.auditQueries : [];
}

module.exports = {
  getRequestContext,
  runWithRequestContext,
  setFailedSql,
  enableAuditQueryCapture,
  pushAuditQuery,
  getAuditQueries,
};
