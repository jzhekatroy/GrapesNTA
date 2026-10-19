'use strict';

const fs = require('fs');
const path = require('path');

// Пишет deploy.sh: строка на компонент — имя, версия, дата версии, время выкладки.
const DEFAULT_FILE = path.join(__dirname, 'data', 'component-versions.tsv');

const COMPONENTS = [
  { id: 'ui', title: 'Интерфейс' },
  { id: 'detection', title: 'Детекция' },
  { id: 'worker', title: 'Worker' },
  { id: 'enrichment', title: 'Обогащение' },
  { id: 'schema', title: 'Схема ClickHouse' },
];

function cleanVersion(raw) {
  const v = String(raw || '').trim();
  if (!v || v === 'unknown' || v.endsWith('-unknown')) return null;
  return v;
}

function isoOrNull(raw) {
  const v = String(raw || '').trim();
  if (!v) return null;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function parseComponentVersions(text) {
  const out = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const [name, version, versionDate, deployedAt] = line.split('\t');
    const id = String(name || '').trim();
    if (!id) continue;
    out[id] = {
      version: cleanVersion(version),
      versionDate: isoOrNull(versionDate),
      deployedAt: isoOrNull(deployedAt),
    };
  }
  return out;
}

function readComponentVersions(file = process.env.COMPONENT_VERSIONS_FILE || DEFAULT_FILE) {
  try {
    return parseComponentVersions(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

/**
 * Версия интерфейса берётся из самого процесса: файл мог остаться от прошлой
 * выкладки, а запущенный контейнер свою версию знает точно. Компоненты, которых
 * нет в файле, на площадке не выкладывались — их не показываем.
 */
function componentVersionsPayload({ recorded = {}, buildInfo = {}, now = new Date() } = {}) {
  const components = [];
  for (const { id, title } of COMPONENTS) {
    const row = recorded[id];
    if (id === 'ui') {
      components.push({
        id,
        title,
        version: cleanVersion(buildInfo.version) || row?.version || null,
        versionDate: isoOrNull(buildInfo.versionDate) || row?.versionDate || null,
        deployedAt: row?.deployedAt || null,
        commit: buildInfo.commit || null,
        buildDate: isoOrNull(buildInfo.buildDate),
      });
      continue;
    }
    if (!row) continue;
    components.push({ id, title, ...row });
  }
  return { generatedAt: new Date(now).toISOString(), components };
}

module.exports = {
  COMPONENTS,
  parseComponentVersions,
  readComponentVersions,
  componentVersionsPayload,
};
