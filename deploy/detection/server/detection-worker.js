#!/usr/bin/env node
'use strict';

/**
 * Считает минутные показатели по абонентам и /24.
 *
 *   node server/detection-worker.js loop
 *   node server/detection-worker.js once
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

process.env.GRAPES_DETECTION_WORKER = '1';

const { tick } = require('./detection-engine');

const TICK_SEC = Math.max(15, Number(process.env.DETECTION_TICK_SEC) || 20);

async function loop() {
  console.log(new Date().toISOString(), 'detection started', { tickSec: TICK_SEC });
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const started = Date.now();
    try {
      const out = await tick();
      console.log(new Date().toISOString(), 'detection tick', JSON.stringify(out));
    } catch (err) {
      console.error(new Date().toISOString(), 'detection tick fatal', err.message);
    }
    const sleepMs = Math.max(5000, TICK_SEC * 1000 - (Date.now() - started));
    await new Promise((r) => setTimeout(r, sleepMs));
  }
}

async function main() {
  const mode = process.argv[2] || 'loop';
  if (mode === 'once') {
    const out = await tick();
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  if (mode === 'loop') {
    await loop();
    return;
  }
  console.error('usage: node server/detection-worker.js [loop|once]');
  process.exit(2);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { tick, loop };
