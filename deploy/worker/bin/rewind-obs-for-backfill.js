#!/usr/bin/env node
'use strict';

/**
 * Backfill observations STRICTLY inside [from, to).
 *
 * Unlike the old behaviour (rewind cursorMinute → live loop re-materializes
 * forward to now, capped at 24h), this rewrites only the requested window and
 * never touches the live cursor/status. That means:
 *   - no 24h catch-up storm on flows_raw,
 *   - other observations' live materialization is not disturbed,
 *   - the operator-selected gap is filled idempotently (delete window + insert).
 *
 * Usage: node rewind-obs-for-backfill.js <fromIso> <toIso>
 */

const path = require('path');

// Worker image layout: /app/bin (this file) + /app/analytics/server (modules).
// require() resolves relative to this file's dir, not cwd, so point at analytics
// explicitly. chdir too so any relative dotenv/data paths in modules still work.
const ANALYTICS_DIR = path.join(__dirname, '..', 'analytics');
process.chdir(ANALYTICS_DIR);

const {
  listMaterializeJobs,
  ensureObservationsStore,
} = require(path.join(ANALYTICS_DIR, 'server', 'observations'));
const {
  materializeWindow,
  floorToBucket,
  ensureTable,
} = require(path.join(ANALYTICS_DIR, 'server', 'observations-rollup'));

async function main() {
  const fromIso = process.argv[2];
  const toIso = process.argv[3];
  if (!fromIso || !toIso) {
    console.error('Usage: node rewind-obs-for-backfill.js <fromIso> <toIso>');
    process.exit(2);
  }

  const from = floorToBucket(new Date(fromIso));
  const to = floorToBucket(new Date(toIso));
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
    try {
      const res = await materializeWindow(job, from, to);
      results.push(res);
    } catch (err) {
      results.push({ id: job.id, error: err && err.message ? err.message : String(err) });
    }
  }

  const filled = results.filter((r) => !r.skipped && !r.error).length;
  console.log(JSON.stringify({
    window: { from: from.toISOString(), to: to.toISOString() },
    jobs: results.length,
    filled,
    results,
  }, null, 2));
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
