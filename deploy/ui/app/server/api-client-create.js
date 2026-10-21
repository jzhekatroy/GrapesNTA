#!/usr/bin/env node
'use strict';

// Выдача кредов внешнему API-клиенту (ERP). Запуск из deploy/ui/app:
//   node server/api-client-create.js --name "PiterIX ERP"
// На сервере: docker exec grapes-nta node server/api-client-create.js --name "..."
// Живёт в server/, а не scripts/, потому что Dockerfile копирует только
// server/ и public/ (см. detection-worker.js — тот же паттерн запуска).

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const { createApiClient, ensureApiClientsTable } = require('./api-clients');

function parseArgv(argv) {
  const args = { name: '' };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--name' || arg === '-n') {
      args.name = String(argv[i + 1] ?? '').trim();
      i += 1;
    } else if (arg.startsWith('--name=')) {
      args.name = arg.slice('--name='.length).trim();
    } else if (arg === '--help' || arg === '-h') {
      args.help = true;
    }
  }
  return args;
}

function printHelp() {
  console.log('Выдача client_id/client_secret для внешнего Bearer-API.');
  console.log('Использование: node server/api-client-create.js --name "PiterIX ERP"');
}

async function main() {
  const args = parseArgv(process.argv);
  if (args.help) {
    printHelp();
    process.exit(0);
  }
  if (!args.name) {
    printHelp();
    process.exit(1);
  }

  await ensureApiClientsTable();
  const created = await createApiClient({ name: args.name });

  console.log('API-клиент создан:');
  console.log(`  client_id:     ${created.clientId}`);
  console.log(`  client_name:   ${created.clientName}`);
  console.log(`  client_secret: ${created.clientSecret}`);
  console.log('');
  console.log('Секрет показан единственный раз — сохраните его сейчас.');
  console.log('В ClickHouse лежит только bcrypt-хэш; при утере секрета');
  console.log('перевыпустите клиента этой же командой.');
  process.exit(0);
}

main().catch((err) => {
  console.error(`Ошибка: ${err.message}`);
  process.exit(1);
});
