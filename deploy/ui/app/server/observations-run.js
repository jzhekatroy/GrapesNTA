#!/usr/bin/env node
'use strict';

/**
 * Report snapshot runner.
 * Usage:
 *   node server/observations-run.js due
 *   node server/observations-run.js list
 *   node server/observations-run.js once <observationId>
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const {
  ensureObservationsStore,
  runDueObservationReports,
  runObservationReport,
  listReportJobs,
} = require('./observations');

async function findOwnerId(observationId) {
  const jobs = await listReportJobs();
  const job = jobs.find((j) => j.id === observationId);
  if (job) return job.ownerId;
  // Fallback: report may be disabled — still allow once via full list path in runObservationReport.
  return null;
}

async function main() {
  await ensureObservationsStore();
  const mode = process.argv[2] || 'due';
  if (mode === 'list') {
    console.log(JSON.stringify({ jobs: await listReportJobs() }, null, 2));
    return;
  }
  if (mode === 'once') {
    const id = process.argv[3];
    if (!id) {
      console.error('usage: node server/observations-run.js once <observationId>');
      process.exit(2);
    }
    let ownerId = await findOwnerId(id);
    if (!ownerId) {
      const { loadObservationById } = require('./observations-store');
      const obs = await loadObservationById(id);
      ownerId = obs?.ownerId || null;
    }
    if (!ownerId) {
      console.error('observation not found');
      process.exit(1);
    }
    const run = await runObservationReport(id, ownerId);
    console.log(JSON.stringify({ ok: true, run }, null, 2));
    return;
  }

  const results = await runDueObservationReports();
  console.log(JSON.stringify({ ok: true, results }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
