'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const {
  parseComponentVersion,
  buildVersionsCopyLine,
} = require(path.join(__dirname, '..', 'public', 'pages', 'versions-format.js'));

test('parseComponentVersion strips prefix and dirty suffix', () => {
  assert.deepEqual(parseComponentVersion('ui-v1.0.24'), {
    display: 'v1.0.24',
    dirty: false,
    commitHash: '',
  });
  assert.deepEqual(parseComponentVersion('detection-v1.0.3+ab12cd34'), {
    display: 'v1.0.3',
    dirty: true,
    commitHash: 'ab12cd34',
  });
  assert.deepEqual(parseComponentVersion('v1.0.3+abc'), {
    display: 'v1.0.3',
    dirty: true,
    commitHash: 'abc',
  });
});

test('buildVersionsCopyLine formats day.month from versionDate', () => {
  const line = buildVersionsCopyLine([
    {
      id: 'ui',
      version: 'ui-v1.0.24',
      versionDate: '2026-10-13T13:35:21.000Z',
    },
    {
      id: 'worker',
      version: 'worker-v1.0.3',
      versionDate: '2026-10-14T08:31:01.000Z',
    },
    {
      id: 'schema',
      version: 'schema-v1.0.2',
      versionDate: '2026-10-15T08:24:00.000Z',
    },
    { id: 'empty', version: null },
  ], 'UTC');
  assert.match(line, /^ui v1\.0\.24 \(13\.10\)/);
  assert.match(line, /worker v1\.0\.3 \(14\.10\)/);
  assert.match(line, /schema v1\.0\.2 \(15\.10\)/);
  assert.equal(line.split(' · ').length, 3);
});
