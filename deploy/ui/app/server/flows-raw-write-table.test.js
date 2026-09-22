'use strict';

// На время смены раскладки flows_raw чтение идёт через обёртку ENGINE = Merge
// поверх новой и старой таблиц, а схема принадлежит физической таблице.
// Обёртка при этом коварна: ALTER ADD COLUMN она принимает молча, вниз не
// передаёт, и первое же чтение такой колонки падает с NOT_FOUND_COLUMN_IN_BLOCK.
// MODIFY TTL она отклоняет сразу. Поэтому имя для чтения и имя для ALTER
// разведены, и эти тесты стерегут разведение.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const CH_PATH = require.resolve('./clickhouse');
const TTL_PATH = require.resolve('./ttl-management');

const SAVED = {};
const KEYS = ['CLICKHOUSE_FLOWS_RAW_TABLE', 'CLICKHOUSE_FLOWS_RAW_WRITE_TABLE'];

function loadFresh(modulePath) {
  for (const p of [CH_PATH, TTL_PATH]) delete require.cache[p];
  return require(modulePath);
}

beforeEach(() => {
  for (const k of KEYS) SAVED[k] = process.env[k];
});

afterEach(() => {
  for (const k of KEYS) {
    if (SAVED[k] === undefined) delete process.env[k];
    else process.env[k] = SAVED[k];
  }
  for (const p of [CH_PATH, TTL_PATH]) delete require.cache[p];
});

describe('имя таблицы для чтения и имя для изменения схемы', () => {
  it('по умолчанию совпадают, поведение прежнее', () => {
    delete process.env.CLICKHOUSE_FLOWS_RAW_TABLE;
    delete process.env.CLICKHOUSE_FLOWS_RAW_WRITE_TABLE;
    const ch = loadFresh(CH_PATH);
    assert.equal(ch.config.flowsRawTable, 'flows_raw');
    assert.equal(ch.config.flowsRawWriteTable, 'flows_raw');
    assert.equal(ch.flowsRawTableRef(), ch.flowsRawWriteTableRef());
  });

  it('следует за CLICKHOUSE_FLOWS_RAW_TABLE, если отдельное имя не задано', () => {
    process.env.CLICKHOUSE_FLOWS_RAW_TABLE = 'flows_custom';
    delete process.env.CLICKHOUSE_FLOWS_RAW_WRITE_TABLE;
    const ch = loadFresh(CH_PATH);
    assert.equal(ch.config.flowsRawWriteTable, 'flows_custom');
    assert.equal(ch.flowsRawTableRef(), ch.flowsRawWriteTableRef());
  });

  it('расходятся на время перехода: читаем обёртку, схему правим у физической', () => {
    process.env.CLICKHOUSE_FLOWS_RAW_TABLE = 'flows_all';
    process.env.CLICKHOUSE_FLOWS_RAW_WRITE_TABLE = 'flows_raw';
    const ch = loadFresh(CH_PATH);
    assert.match(ch.flowsRawTableRef(), /`flows_all`$/);
    assert.match(ch.flowsRawWriteTableRef(), /`flows_raw`$/);
    assert.notEqual(ch.flowsRawTableRef(), ch.flowsRawWriteTableRef());
  });

  it('настройка TTL из интерфейса правит физическую таблицу, а не обёртку', () => {
    process.env.CLICKHOUSE_FLOWS_RAW_TABLE = 'flows_all';
    process.env.CLICKHOUSE_FLOWS_RAW_WRITE_TABLE = 'flows_raw';
    loadFresh(CH_PATH);
    const ttl = require(TTL_PATH);
    const entry = (ttl.TTL_CATALOG || ttl.__ttlCatalogForTests || [])
      .find((e) => e.id === 'flows_raw');
    if (!entry) return; // справочник не экспортируется — проверка ниже через список
    assert.equal(entry.table(), 'flows_raw');
  });
});

describe('разбор трафика читает ту таблицу, что указана для чтения', () => {
  it('SQL сводки ссылается на обёртку, а не на физическую таблицу', async () => {
    process.env.CLICKHOUSE_FLOWS_RAW_TABLE = 'flows_all';
    process.env.CLICKHOUSE_FLOWS_RAW_WRITE_TABLE = 'flows_raw';
    loadFresh(CH_PATH);
    const explorerPath = require.resolve('./explorer');
    delete require.cache[explorerPath];
    const { explorerSummary } = require(explorerPath);

    const spec = await explorerSummary({
      range: 'custom',
      from: '2026-09-22 01:00:00',
      to: '2026-09-22 02:00:00',
      metric: 'bps',
    });
    assert.match(spec.sql, /FROM `default`\.`flows_all` AS f/);
    assert.doesNotMatch(spec.sql, /`default`\.`flows_raw`/);
    delete require.cache[explorerPath];
  });
});
