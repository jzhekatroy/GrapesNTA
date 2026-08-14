'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  getBuildInfo,
  parseSourceTxt,
  formatBuildInfoLogLine,
  resetBuildInfoCacheForTests,
} = require('./build-info');

function tempRepo(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `grapes-build-info-${name}-`));
  fs.mkdirSync(path.join(dir, 'server'), { recursive: true });
  return dir;
}

function writeSourceTxt(repoRoot, content) {
  fs.writeFileSync(path.join(repoRoot, 'SOURCE.txt'), content, 'utf8');
}

function writeBuildInfoJson(repoRoot, buildDate) {
  fs.writeFileSync(
    path.join(repoRoot, 'server', 'build-info.json'),
    JSON.stringify({ buildDate }),
    'utf8',
  );
}

test.beforeEach(() => {
  resetBuildInfoCacheForTests();
});

test('parseSourceTxt reads synced_commit only', () => {
  assert.deepEqual(parseSourceTxt('synced_commit=abc123\nsynced_at=2026-01-01\n'), {
    commit: 'abc123',
  });
});

test('SOURCE.txt + build-info.json', () => {
  const repoRoot = tempRepo('both');
  writeSourceTxt(repoRoot, 'synced_commit=prodhash\n');
  writeBuildInfoJson(repoRoot, '2026-08-13T19:00:00.000Z');

  assert.deepEqual(getBuildInfo({ repoRoot }), {
    buildDate: '2026-08-13T19:00:00.000Z',
    commit: 'prodhash',
  });
});

test('SOURCE.txt without build-info.json', () => {
  const repoRoot = tempRepo('source-only');
  writeSourceTxt(repoRoot, 'synced_commit=prodhash\n');

  assert.deepEqual(getBuildInfo({ repoRoot }), {
    commit: 'prodhash',
  });
});

test('build-info.json without SOURCE.txt', () => {
  const repoRoot = tempRepo('json-only');
  writeBuildInfoJson(repoRoot, '2026-08-13T19:00:00.000Z');

  assert.deepEqual(getBuildInfo({ repoRoot }), {
    buildDate: '2026-08-13T19:00:00.000Z',
  });
});

test('env BUILD_DATE + GIT_COMMIT', () => {
  const repoRoot = tempRepo('env');

  assert.deepEqual(getBuildInfo({
    repoRoot,
    env: {
      BUILD_DATE: '2026-08-13T20:00:00.000Z',
      GIT_COMMIT: 'envhash',
    },
  }), {
    buildDate: '2026-08-13T20:00:00.000Z',
    commit: 'envhash',
  });
});

test('BUILD_DATE env overrides build-info.json', () => {
  const repoRoot = tempRepo('env-override');
  writeBuildInfoJson(repoRoot, '2026-08-13T19:00:00.000Z');

  assert.deepEqual(getBuildInfo({
    repoRoot,
    env: { BUILD_DATE: '2026-08-13T21:00:00.000Z' },
  }), {
    buildDate: '2026-08-13T21:00:00.000Z',
  });
});

test('build-info.json overrides invalid BUILD_DATE env', () => {
  const repoRoot = tempRepo('file-over-env');
  writeBuildInfoJson(repoRoot, '2026-08-13T19:00:00.000Z');

  assert.deepEqual(getBuildInfo({
    repoRoot,
    env: { BUILD_DATE: 'unknown' },
  }), {
    buildDate: '2026-08-13T19:00:00.000Z',
  });
});

test('SOURCE commit overrides GIT_COMMIT env', () => {
  const repoRoot = tempRepo('source-over-env');
  writeSourceTxt(repoRoot, 'synced_commit=sourcehash\n');

  assert.deepEqual(getBuildInfo({
    repoRoot,
    env: { GIT_COMMIT: 'envhash' },
  }), {
    commit: 'sourcehash',
  });
});

test('nothing configured', () => {
  const repoRoot = tempRepo('empty');
  assert.deepEqual(getBuildInfo({ repoRoot }), {});
});

test('invalid build date values are ignored', () => {
  const repoRoot = tempRepo('invalid-date');
  writeBuildInfoJson(repoRoot, 'not-a-date');

  assert.deepEqual(getBuildInfo({ repoRoot }), {});
  assert.deepEqual(getBuildInfo({
    repoRoot,
    env: { BUILD_DATE: 'unknown' },
  }), {});
});

test('formatBuildInfoLogLine', () => {
  assert.equal(formatBuildInfoLogLine({}), null);
  assert.equal(
    formatBuildInfoLogLine({ buildDate: '2026-08-13T19:00:00.000Z' }),
    'Build info: built 2026-08-13T19:00:00.000Z',
  );
  assert.equal(
    formatBuildInfoLogLine({ commit: 'abc1234' }),
    'Build info: commit abc1234',
  );
  assert.equal(
    formatBuildInfoLogLine({
      buildDate: '2026-08-13T19:00:00.000Z',
      commit: 'abc1234',
    }),
    'Build info: built 2026-08-13T19:00:00.000Z, commit abc1234',
  );
});
