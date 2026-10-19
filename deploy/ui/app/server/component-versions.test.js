'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  parseComponentVersions,
  readComponentVersions,
  componentVersionsPayload,
} = require('./component-versions');
const { getResourceForPath } = require('./rbac/api-map');

const FILE = [
  'schema\tschema-v1.0.2\t2026-10-13T15:00:00+03:00\t2026-10-15T08:22:00Z',
  'worker\tworker-v1.0.3\t2026-10-13T16:10:00+03:00\t2026-10-15T08:23:00Z',
  'detection\tdetection-v1.0.3+ab12cd34\t2026-10-13T16:40:00+03:00\t2026-10-15T08:25:00Z',
  'enrichment\tenrichment-unknown\t\t2026-10-15T08:24:00Z',
  '',
].join('\n');

test('parseComponentVersions читает строки deploy.sh и чистит пустые версии', () => {
  const rows = parseComponentVersions(FILE);
  assert.deepEqual(rows.worker, {
    version: 'worker-v1.0.3',
    versionDate: '2026-10-13T13:10:00.000Z',
    deployedAt: '2026-10-15T08:23:00.000Z',
  });
  assert.equal(rows.detection.version, 'detection-v1.0.3+ab12cd34');
  assert.equal(rows.enrichment.version, null);
  assert.equal(rows.enrichment.versionDate, null);
});

test('readComponentVersions без файла отдаёт пусто', () => {
  const missing = path.join(os.tmpdir(), `grapes-versions-missing-${process.pid}.tsv`);
  assert.deepEqual(readComponentVersions(missing), {});
});

test('readComponentVersions читает файл', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grapes-versions-'));
  const file = path.join(dir, 'component-versions.tsv');
  fs.writeFileSync(file, FILE, 'utf8');
  assert.equal(readComponentVersions(file).schema.version, 'schema-v1.0.2');
});

test('версия интерфейса — из процесса, выкладка — из файла; невыложенных нет', () => {
  const recorded = parseComponentVersions(
    `ui\tui-v1.0.23\t2026-10-12T10:00:00Z\t2026-10-14T09:00:00Z\n${FILE}`,
  );
  const payload = componentVersionsPayload({
    recorded,
    buildInfo: {
      version: 'ui-v1.0.24',
      versionDate: '2026-10-13T13:35:21Z',
      commit: 'ab12cd34',
      buildDate: '2026-10-15T08:23:10Z',
    },
    now: new Date('2026-10-19T07:20:00Z'),
  });
  assert.equal(payload.generatedAt, '2026-10-19T07:20:00.000Z');
  assert.deepEqual(payload.components.map((c) => c.id), ['ui', 'detection', 'worker', 'enrichment', 'schema']);
  const ui = payload.components[0];
  assert.equal(ui.version, 'ui-v1.0.24');
  assert.equal(ui.versionDate, '2026-10-13T13:35:21.000Z');
  assert.equal(ui.deployedAt, '2026-10-14T09:00:00.000Z');
  assert.equal(ui.commit, 'ab12cd34');
});

test('интерфейс есть всегда, остальные — только если выкладывались', () => {
  const payload = componentVersionsPayload({ recorded: {}, buildInfo: {} });
  assert.deepEqual(payload.components.map((c) => c.id), ['ui']);
  assert.equal(payload.components[0].version, null);
});

test('эндпоинт версий закрыт правом «Диагностика»', () => {
  assert.equal(getResourceForPath('/api/diagnostics/versions'), 'diagnostics');
});
