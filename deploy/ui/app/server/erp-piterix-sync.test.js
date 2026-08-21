const test = require('node:test');
const assert = require('node:assert/strict');
const { isActive, uniquePorts, classifyClients, REASON } = require('./erp-piterix-sync');

test('isActive требует int_status=1 и отсутствие блока', () => {
  assert.equal(isActive({ int_status: 1, block: { is_blocked: false } }), true);
  assert.equal(isActive({ int_status: 0, block: { is_blocked: false } }), false);
  assert.equal(isActive({ int_status: 1, block: { is_blocked: true } }), false);
});

test('uniquePorts берёт только host+ifIndex', () => {
  const ports = uniquePorts({
    ips: [
      { switch: { host: '172.18.19.1', port: 10, inven_number: 'КМ1' } },
      { switch: { host: '172.18.19.1', port: 10 } },
      { switch: null },
      { ip: '1.1.1.1' },
    ],
  });
  assert.equal(ports.length, 1);
  assert.equal(ports[0].key, '172.18.19.1:10');
});

test('classifyClients оставляет только активных с уникальным портом в каталоге', () => {
  const agents = new Map([['172.18.19.1', { display_name: 'sw1' }]]);
  const ifaces = new Set(['172.18.19.1:10']);
  const ifaceRows = new Map([['172.18.19.1:10', { if_name: 'Eth1', if_alias: 'foo' }]]);
  const { labelable, skipped, activeCount } = classifyClients([
    {
      basic_account: 1,
      name: 'A',
      int_status: 1,
      block: { is_blocked: false },
      ips: [{ switch: { host: '172.18.19.1', port: 10 } }],
    },
    {
      basic_account: 2,
      name: 'B',
      int_status: 0,
      block: { is_blocked: false },
      ips: [{ switch: { host: '172.18.19.1', port: 10 } }],
    },
    {
      basic_account: 3,
      name: 'C',
      int_status: 1,
      block: { is_blocked: false },
      ips: [{ switch: { host: '172.18.19.9', port: 10 } }],
    },
  ], { agents, ifaces, ifaceRows });

  assert.equal(activeCount, 2);
  assert.equal(labelable.length, 1);
  assert.equal(labelable[0].clientId, '1');
  assert.equal(labelable[0].comment, 'erp:piter_ix');
  assert.equal(skipped.some((s) => s.reason === REASON.inactive), true);
  assert.equal(skipped.some((s) => s.reason === REASON.switch_unknown), true);
});

test('enabledCategoryIds берёт только включённые', () => {
  const { enabledCategoryIds } = require('./erp-piterix-settings');
  assert.deepEqual(
    enabledCategoryIds({ categories: { piter_ix: true, dc: false, bb: true } }),
    ['piter_ix', 'bb'],
  );
});

test('clientsToDisable снимает только пропавших из ERP', () => {
  const { clientsToDisable } = require('./erp-piterix-sync');
  assert.deepEqual(clientsToDisable(['1', '2', '3'], ['2', '3']), ['1']);
});

test('portsToDisable снимает старый порт и порты отключённого ЛС', () => {
  const { portsToDisable } = require('./erp-piterix-sync');
  const dropped = portsToDisable(
    [
      { client_id: '1', switch_ip: '172.18.19.1', if_index: 10, comment: 'old' },
      { client_id: '1', switch_ip: '172.18.19.1', if_index: 11, comment: 'keep' },
      { client_id: '9', switch_ip: '172.18.19.2', if_index: 1, comment: 'gone' },
    ],
    [{ client_id: '1', switch_ip: '172.18.19.1', if_index: 11 }],
    ['9'],
  );
  assert.equal(dropped.length, 2);
  assert.deepEqual(dropped.map((p) => `${p.client_id}:${p.if_index}`).sort(), ['1:10', '9:1']);
});
