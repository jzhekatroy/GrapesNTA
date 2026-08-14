'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const DEFAULT_REPO_ROOT = path.join(__dirname, '..');
const DEFAULT_BUILD_INFO_PATH = path.join(__dirname, 'build-info.json');
const SOURCE_FILE = 'SOURCE.txt';
const GIT_TIMEOUT_MS = 2000;

let cached = null;

function trimValue(raw) {
  const v = String(raw || '').trim();
  return v || undefined;
}

function parseSourceTxt(content) {
  const out = {};
  for (const line of String(content || '').split(/\r?\n/)) {
    const syncedCommit = line.match(/^synced_commit=(.+)$/);
    if (syncedCommit) {
      out.commit = trimValue(syncedCommit[1]);
      continue;
    }
  }
  return out;
}

function readSourceTxt(repoRoot) {
  const filePath = path.join(repoRoot, SOURCE_FILE);
  try {
    return parseSourceTxt(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

function readBuildInfoJson(repoRoot) {
  const filePath = repoRoot
    ? path.join(repoRoot, 'server', 'build-info.json')
    : DEFAULT_BUILD_INFO_PATH;
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const buildDate = trimValue(parsed?.buildDate);
    return buildDate ? { buildDate } : {};
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

function normalizeBuildDate(raw) {
  const v = trimValue(raw);
  if (!v || v === 'unknown') return undefined;
  const ms = Date.parse(v);
  if (!Number.isFinite(ms)) return undefined;
  return new Date(ms).toISOString();
}

function gitShortHead(repoRoot) {
  const gitDir = path.join(repoRoot, '.git');
  try {
    if (!fs.existsSync(gitDir)) return undefined;
  } catch {
    return undefined;
  }

  const result = spawnSync('git', ['-C', repoRoot, 'rev-parse', '--short', 'HEAD'], {
    encoding: 'utf8',
    timeout: GIT_TIMEOUT_MS,
  });
  if (result.status !== 0) return undefined;
  return trimValue(result.stdout);
}

function resolveCommit(repoRoot, env = process.env) {
  const fromSource = readSourceTxt(repoRoot).commit;
  if (fromSource) return fromSource;

  const fromGit = gitShortHead(repoRoot);
  if (fromGit) return fromGit;

  return trimValue(env.GIT_COMMIT);
}

function resolveBuildDate(repoRoot, env = process.env) {
  const fromEnv = normalizeBuildDate(env.BUILD_DATE);
  if (fromEnv) return fromEnv;

  return normalizeBuildDate(readBuildInfoJson(repoRoot).buildDate);
}

function getBuildInfo(opts = {}) {
  if (cached && !opts.repoRoot && !opts.env) return cached;

  const repoRoot = opts.repoRoot || DEFAULT_REPO_ROOT;
  const env = opts.env || process.env;
  const data = {};

  const buildDate = resolveBuildDate(repoRoot, env);
  if (buildDate) data.buildDate = buildDate;

  const commit = resolveCommit(repoRoot, env);
  if (commit) data.commit = commit;

  if (!opts.repoRoot && !opts.env) cached = data;
  return data;
}

function resetBuildInfoCacheForTests() {
  cached = null;
}

function formatBuildInfoLogLine(info) {
  if (!info?.buildDate && !info?.commit) return null;
  const parts = [];
  if (info.buildDate) parts.push(`built ${info.buildDate}`);
  if (info.commit) parts.push(`commit ${info.commit}`);
  return `Build info: ${parts.join(', ')}`;
}

module.exports = {
  getBuildInfo,
  parseSourceTxt,
  formatBuildInfoLogLine,
  resetBuildInfoCacheForTests,
};
