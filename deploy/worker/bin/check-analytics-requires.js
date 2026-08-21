#!/usr/bin/env node
'use strict';

/**
 * Fail if a vendored analytics module require()s a same-dir sibling that
 * was not copied into the worker snapshot. That is how grapes-worker
 * crash-looped on ./explorer-cabinet-client.
 */

const fs = require('fs');
const path = require('path');

const REQUIRE_RE = /require\(\s*['"]\.\/([^'"]+)['"]\s*\)/g;

function resolveDir() {
  if (process.argv[2]) return path.resolve(process.argv[2]);
  const here = __dirname;
  const guesses = [
    path.join(here, '../analytics/server'),
    path.join(here, '../../analytics/server'),
  ];
  for (const dir of guesses) {
    if (fs.existsSync(path.join(dir, 'analytics.js'))) return dir;
  }
  throw new Error('analytics server dir not found');
}

function siblingName(spec) {
  const trimmed = String(spec || '').replace(/\.js$/i, '');
  if (!trimmed || trimmed.includes('/') || trimmed.startsWith('.')) return null;
  return `${trimmed}.js`;
}

const dir = resolveDir();
const files = fs.readdirSync(dir).filter((name) => name.endsWith('.js') && !name.endsWith('.test.js'));
const missing = [];

for (const file of files) {
  const text = fs.readFileSync(path.join(dir, file), 'utf8');
  REQUIRE_RE.lastIndex = 0;
  let match;
  while ((match = REQUIRE_RE.exec(text))) {
    const name = siblingName(match[1]);
    if (!name) continue;
    if (!fs.existsSync(path.join(dir, name))) {
      missing.push(`${file} -> ${name}`);
    }
  }
}

if (missing.length) {
  console.error('missing analytics sibling modules:');
  for (const line of missing) console.error(`  ${line}`);
  process.exit(1);
}

console.log(`analytics requires ok (${files.length} files, ${dir})`);
