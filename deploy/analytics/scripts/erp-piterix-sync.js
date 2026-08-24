#!/usr/bin/env node
'use strict';

require('dotenv').config();
const fs = require('fs');
const { createClient } = require('@clickhouse/client');
const { createClientAdapter, runSync } = require('../server/erp-piterix-run');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return fallback;
  const v = process.argv[i + 1];
  if (v == null || v.startsWith('--')) return true;
  return v;
}

async function main() {
  const limit = Number(arg('limit', '50'));
  const full = process.argv.includes('--full');
  const fromJson = arg('from-json', '');
  const url = process.env.ERP_SYNC_CH_URL || process.env.CLICKHOUSE_URL;
  const user = process.env.ERP_SYNC_CH_USER || process.env.CLICKHOUSE_WRITE_USER || process.env.CLICKHOUSE_USER;
  const password = process.env.ERP_SYNC_CH_PASSWORD || process.env.CLICKHOUSE_WRITE_PASSWORD || process.env.CLICKHOUSE_PASSWORD;
  if (!url) throw new Error('Нужен ERP_SYNC_CH_URL или CLICKHOUSE_URL');

  let clients = null;
  if (fromJson && fromJson !== true) {
    const dump = JSON.parse(fs.readFileSync(fromJson, 'utf8'));
    clients = dump.data || dump;
  }

  const ch = createClient({
    url,
    username: user,
    password,
    database: 'default',
    clickhouse_settings: { wait_end_of_query: 1, max_execution_time: 120 },
  });
  try {
    const summary = await runSync(createClientAdapter(ch), {
      clients,
      full,
      limit,
      trigger: process.env.ERP_SYNC_TRIGGER || 'cli',
      actor: process.env.ERP_SYNC_ACTOR || 'cli',
    });
    console.log(JSON.stringify(summary, null, 2));
  } finally {
    await ch.close();
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
