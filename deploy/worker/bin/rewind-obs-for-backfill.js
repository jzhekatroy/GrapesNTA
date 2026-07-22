#!/usr/bin/env node
'use strict';

/**
 * Rewind materialize cursors for all enabled observation jobs so the worker
 * catch-up loop re-fills [from, to). Deletes existing rollup rows in that window
 * (idempotent SummingMergeTree rewrite on catch-up).
 *
 * Usage: node rewind-obs-for-backfill.js <fromIso> <toIso>
 */

const path = require('path');

// Worker image layout: /app/bin + /app/analytics/server
process.chdir(path.join(__dirname, '..', 'analytics'));

const {
  listMaterializeJobs,
  patchMaterializeStatus,
  ensureObservationsStore,
} = require('./server/observations');
const {
  deleteRollupWindow,
  floorToBucket,
  ensureTable,
} = require('./server/observations-rollup');

async function main() {
  const fromIso = process.argv[2];
  const toIso = process.argv[3];
  if (!fromIso || !toIso) {
    console.error('Usage: node rewind-obs-for-backfill.js <fromIso> <toIso>');
    process.exit(2);
  }

  let from = floorToBucket(new Date(fromIso));
  let to = floorToBucket(new Date(toIso));
  if (!(from < to)) {
    console.error('from must be before to');
    process.exit(2);
  }

  await ensureObservationsStore();
  await ensureTable();
  const jobs = await listMaterializeJobs();
  const results = [];

  for (const job of jobs) {
    if (!job?.id) continue;
    const started = job.startedAt ? floorToBucket(job.startedAt) : null;
    let jobFrom = from;
    if (started && jobFrom < started) jobFrom = started;
    if (!(jobFrom < to)) {
      results.push({ id: job.id, skipped: true, reason: 'before_created' });
      continue;
    }
    await deleteRollupWindow(job.id, jobFrom, to);
    await patchMaterializeStatus(job.id, {
      status: 'queued',
      cursorMinute: jobFrom.toISOString(),
      lastError: null,
    });
    results.push({
      id: job.id,
      name: job.name,
      from: jobFrom.toISOString(),
      to: to.toISOString(),
    });
  }

  console.log(JSON.stringify({ rewound: results.length, results }, null, 2));
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
