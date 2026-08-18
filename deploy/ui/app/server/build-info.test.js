'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  getBuildInfo,
  parseSourceTxt,
  shortCommit,
  formatBuildInfoLogLine,
  resetBuildInfoCacheForTests,
} = require('./build-info');

function tempRepo(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `grapes-build-info-${name}-`));
  fs.mkdirSync(path.join(dir, 'server', 'data'), { recursive: true });
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
    commit: 'sourceha',
  });
});

test('SOURCE_TXT_PATH env overrides default path', () => {
  const repoRoot = tempRepo('source-env-path');
  const customPath = path.join(repoRoot, 'deploy', 'SOURCE.txt');
  fs.mkdirSync(path.dirname(customPath), { recursive: true });
  fs.writeFileSync(customPath, 'synced_commit=customhash\n', 'utf8');

  assert.deepEqual(getBuildInfo({
    repoRoot,
    env: { SOURCE_TXT_PATH: customPath },
  }), {
    commit: 'customha',
  });
});

test('parseSourceTxt keeps full synced_commit hash', () => {
  const hash = 'ba3a7dc1e6f1b68e1b6e7bac2c4fb32dad15960c';
  assert.deepEqual(parseSourceTxt(`synced_commit=${hash}\n`), { commit: hash });
});

test('getBuildInfo shortens synced_commit to 8 chars', () => {
  const repoRoot = tempRepo('long-hash');
  writeSourceTxt(repoRoot, 'synced_commit=ba3a7dc1e6f1b68e1b6e7bac2c4fb32dad15960c\n');

  assert.deepEqual(getBuildInfo({ repoRoot }), {
    commit: 'ba3a7dc1',
  });
});

test('shortCommit', () => {
  assert.equal(shortCommit('ba3a7dc1e6f1b68e1b6e7bac2c4fb32dad15960c'), 'ba3a7dc1');
  assert.equal(shortCommit('abc'), 'abc');
  assert.equal(shortCommit(''), undefined);
});

test('missing SOURCE.txt returns buildDate only without error', () => {
  const repoRoot = tempRepo('no-source');
  writeBuildInfoJson(repoRoot, '2026-08-13T19:00:00.000Z');

  assert.deepEqual(getBuildInfo({ repoRoot }), {
    buildDate: '2026-08-13T19:00:00.000Z',
  });
});

test('SOURCE.txt directory is ignored', () => {
  const repoRoot = tempRepo('source-dir');
  writeBuildInfoJson(repoRoot, '2026-08-13T19:00:00.000Z');
  fs.mkdirSync(path.join(repoRoot, 'SOURCE.txt'), { recursive: true });

  assert.deepEqual(getBuildInfo({ repoRoot }), {
    buildDate: '2026-08-13T19:00:00.000Z',
  });
});

test('SOURCE.txt without synced_commit shows buildDate only', () => {
  const repoRoot = tempRepo('source-empty');
  writeBuildInfoJson(repoRoot, '2026-08-13T19:00:00.000Z');
  writeSourceTxt(repoRoot, 'synced_at=2026-01-01\n');

  assert.deepEqual(getBuildInfo({ repoRoot }), {
    buildDate: '2026-08-13T19:00:00.000Z',
  });
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
