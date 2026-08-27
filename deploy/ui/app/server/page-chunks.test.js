'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const MANIFEST_PATH = path.join(__dirname, '..', 'public', 'data', 'page-chunks.manifest.js');

function loadManifest() {
  const src = fs.readFileSync(MANIFEST_PATH, 'utf8');
  const match = src.match(/const PAGE_CHUNKS_MANIFEST = (\{[\s\S]*?\n\});/);
  assert.ok(match, 'PAGE_CHUNKS_MANIFEST не распарсился');
  // eslint-disable-next-line no-eval
  return eval(`(${match[1]})`);
}

test('каждый lazy-чанк объявляет exports.default', () => {
  const manifest = loadManifest();
  const missing = Object.entries(manifest.chunks || {})
    .filter(([, spec]) => !spec?.exports?.default)
    .map(([id]) => id);
  assert.deepEqual(missing, [], 'чанк без exports.default даёт «Компонент не найден»');
});

test('observations экспортирует PageObservations', () => {
  const manifest = loadManifest();
  assert.equal(manifest.chunks.observations.exports.default, 'PageObservations');
});
