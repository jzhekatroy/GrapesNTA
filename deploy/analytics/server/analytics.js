#!/usr/bin/env node
'use strict';

/**
 * Grapes analytics worker — observations rollup + scheduled reports.
 * Run in Docker near ClickHouse (not inside UI process).
 *
 *   node server/analytics.js
 *   node server/analytics.js once   # single tick (rollup + due reports)
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

process.env.GRAPES_ANALYTICS_WORKER = '1';

const {
  markWorkerStart,
  markHeartbeat,
  recordTick,
} = require('./analytics-diagnostics');
const { runOnce: runRollupOnce, recoverStuckRunning } = require('./observations-rollup');
const {
  ensureObservationsStore,
  runDueObservationReports,
  MIN_INTERVAL_SEC,
} = require('./observations');
const { ensureSmtpSettingsTables } = require('./smtp-settings');

const REPORT_CHECK_SEC = Math.max(
  60,
  Number(process.env.ANALYTICS_REPORT_CHECK_SEC) || 60,
);

let lastReportCheckMs = 0;

async function runReportsIfDue(force = false) {
  const now = Date.now();
  if (!force && now - lastReportCheckMs < REPORT_CHECK_SEC * 1000) {
    return { skipped: true };
  }
  lastReportCheckMs = now;
  const results = await runDueObservationReports();
  return { results };
}

async function tick() {
  const started = Date.now();
  markHeartbeat();
  await ensureObservationsStore();
  await ensureSmtpSettingsTables().catch((err) => {
    console.warn(new Date().toISOString(), 'smtp ensure failed', err.message);
  });
  const recovered = await recoverStuckRunning();
  if (recovered) {
    console.log(new Date().toISOString(), 'analytics recovered stuck jobs:', recovered);
  }
  let rollup = [];
  let reports = { skipped: true };
  let tickError = null;
  try {
    rollup = await runRollupOnce();
    reports = await runReportsIfDue();
  } catch (err) {
    tickError = err.message;
    throw err;
  } finally {
    recordTick({
      rollup,
      reports,
      elapsedMs: Date.now() - started,
      error: tickError,
    });
  }
  return { rollup, reports };
}

async function loop() {
  markWorkerStart('loop');
  console.log(new Date().toISOString(), 'analytics started', {
    rollupIntervalSec: MIN_INTERVAL_SEC,
    reportCheckSec: REPORT_CHECK_SEC,
  });
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const started = Date.now();
    try {
      const out = await tick();
      console.log(new Date().toISOString(), 'analytics tick', JSON.stringify(out));
    } catch (err) {
      console.error(new Date().toISOString(), 'analytics tick fatal', err.message);
    }
    const sleepMs = Math.max(5000, MIN_INTERVAL_SEC * 1000 - (Date.now() - started));
    await new Promise((r) => setTimeout(r, sleepMs));
  }
}

async function main() {
  const mode = process.argv[2] || 'loop';
  if (mode === 'once') {
    markWorkerStart('once');
    const out = await tick();
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  if (mode === 'loop') {
    await loop();
    return;
  }
  console.error('usage: node server/analytics.js [loop|once]');
  process.exit(2);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { tick, loop };
