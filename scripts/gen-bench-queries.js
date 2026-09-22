#!/usr/bin/env node
'use strict';

/**
 * Готовит набор реальных запросов разбора трафика для замера раскладки flows_raw.
 *
 * SQL берётся не из головы, а у самого интерфейса: explorerSummary и компания
 * возвращают {sql, params} без обращения к базе, поэтому замер гоняет ровно то,
 * что уходит в ClickHouse при работе пользователя.
 *
 * Использование:
 *   node scripts/gen-bench-queries.js <from> <to> <файл-вывода> [таблица]
 *
 * Вывод пишется в файл, а не в stdout: модули интерфейса логируют в stdout
 * и перемешались бы с JSON.
 *
 * Время задаётся в том же виде, что приходит из интерфейса: 'YYYY-MM-DD HH:MM:SS'.
 */

const fs = require('fs');
const path = require('path');

// В контейнере интерфейса код лежит в /app/server, в репозитории — глубже.
const SERVER_DIR = process.env.BENCH_SERVER_DIR
  || path.join(__dirname, '..', 'deploy', 'ui', 'app', 'server');

const from = process.argv[2];
const to = process.argv[3];
const outFile = process.argv[4];
const table = process.argv[5] || '';

if (!from || !to || !outFile) {
  console.error('нужно: node scripts/gen-bench-queries.js "<from>" "<to>" <файл-вывода> [таблица]');
  process.exit(2);
}

// Имя таблицы читается модулем на этапе загрузки, поэтому ставим до require.
if (table) process.env.CLICKHOUSE_FLOWS_RAW_TABLE = table;
// Колонки времени на стенде названы так же, как в боевой схеме.
process.env.CH_COL_TIME = process.env.CH_COL_TIME || 'time_received_ns';

const {
  explorerSummary,
  explorerFlows,
  explorerTimeseries,
} = require(path.join(SERVER_DIR, 'explorer'));

const WINDOW = { range: 'custom', from, to, metric: 'bps', limit: 25 };

// Порт, по которому фильтруем в «тяжёлых» вариантах. Подставляется вызывающим
// скриптом: это самый нагруженный порт на стенде.
const IF_ALIAS = process.env.BENCH_IF_ALIAS || '';

const CASES = [
  {
    id: 'summary_plain',
    label: 'Сводка за окно, без фильтров',
    build: () => explorerSummary({ ...WINDOW }),
  },
  {
    id: 'top_asn_plain',
    label: 'Топ ASN, без фильтров',
    build: () => explorerFlows({ ...WINDOW, groupBy: ['src_asn'] }),
  },
  {
    id: 'top_ip_plain',
    label: 'Топ IP-источников, без фильтров',
    build: () => explorerFlows({ ...WINDOW, groupBy: ['src_ip'] }),
  },
  {
    id: 'top_port_pair',
    label: 'Топ пар портов по описанию',
    build: () => explorerFlows({ ...WINDOW, groupBy: ['in_if_alias', 'out_if_alias'] }),
  },
  {
    id: 'timeseries_plain',
    label: 'График по времени, без фильтров',
    build: () => explorerTimeseries({ ...WINDOW }),
  },
  {
    id: 'top_client',
    label: 'Топ клиентов кабинета',
    build: () => explorerFlows({ ...WINDOW, groupBy: ['cabinet_client'] }),
  },
  {
    id: 'top_asn_pair',
    label: 'Топ пар ASN',
    build: () => explorerFlows({ ...WINDOW, groupBy: ['src_asn', 'dst_asn'] }),
  },
  {
    id: 'top_switch_port',
    label: 'Топ коммутатор + входной порт',
    build: () => explorerFlows({ ...WINDOW, groupBy: ['switch_ip', 'in_if_name'] }),
  },
  {
    id: 'top_proto',
    label: 'Разрез по протоколам',
    build: () => explorerFlows({ ...WINDOW, groupBy: ['proto'] }),
  },
];

// Варианты с фильтром по описанию порта: именно они были самыми медленными.
if (IF_ALIAS) {
  const f = [{ field: 'in_if_alias', op: '=', value: IF_ALIAS }];
  CASES.push(
    {
      id: 'summary_if_filter',
      label: 'Сводка с фильтром по описанию порта',
      build: () => explorerSummary({ ...WINDOW, filters: f }),
    },
    {
      id: 'top_asn_if_filter',
      label: 'Топ ASN с фильтром по описанию порта',
      build: () => explorerFlows({ ...WINDOW, groupBy: ['src_asn'], filters: f }),
    },
    {
      id: 'top_ip_if_filter',
      label: 'Топ IP-источников с фильтром по описанию порта',
      build: () => explorerFlows({ ...WINDOW, groupBy: ['src_ip'], filters: f }),
    },
    {
      id: 'timeseries_if_filter',
      label: 'График по времени с фильтром по описанию порта',
      build: () => explorerTimeseries({ ...WINDOW, filters: f }),
    },
  );
}

(async () => {
  const out = [];
  for (const c of CASES) {
    try {
      const spec = await c.build();
      if (!spec || !spec.sql) {
        console.error(`пропущен ${c.id}: спецификация без sql`);
        continue;
      }
      out.push({ id: c.id, label: c.label, sql: spec.sql, params: spec.params || {} });
    } catch (err) {
      console.error(`пропущен ${c.id}: ${err && err.message ? err.message : err}`);
    }
  }
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.error(`записано запросов: ${out.length} → ${outFile}`);
  process.exit(0);
})();
