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
  const { enabledCategoryIds, mapSettings, resolveErpConfig } = require('./erp-piterix-settings');
  assert.deepEqual(
    enabledCategoryIds({ categories: { piter_ix: true, dc: false, bb: true } }),
    ['piter_ix', 'bb'],
  );
  const pub = mapSettings({});
  assert.equal(pub.apiHost, 'erp.bth.su');
  assert.equal(pub.apiBase, 'https://erp.bth.su');
  assert.equal(pub.tokenSet, true);
  assert.equal(pub.apiToken, undefined);
  const cfg = resolveErpConfig(mapSettings({}, { includeToken: true }));
  assert.equal(cfg.host, 'erp.bth.su');
  assert.equal(cfg.pageLimit, 20);
  assert.ok(cfg.token);
});

test('Host заголовок только если URL — IP, как на PiterIX', () => {
  const { erpRequestHeaders } = require('./erp-piterix-run');
  const cfg = { token: 't', host: 'erp.bth.su' };
  const byName = erpRequestHeaders(cfg, 'https://erp.bth.su/api/v1/clients/by-category/bb?limit=20');
  assert.equal(byName.Host, undefined);
  assert.equal(byName.Accept, 'application/json');
  const byIp = erpRequestHeaders(cfg, 'https://195.2.241.23:8443/api/v1/clients/by-category/piter_ix?limit=20');
  assert.equal(byIp.Host, 'erp.bth.su');
});

test('uniquePrefixes берёт текущий IP из ERP, историю не трогает', () => {
  const { uniquePrefixes } = require('./erp-piterix-sync');
  const prefixes = uniquePrefixes({
    ips: [{ ip: '188.143.132.189', cidr: null, switch: { host: '10.72.31.15', port: 3 } }],
    ip_history: [{ ip: '1.2.3.4', cidr: null }],
  });
  assert.equal(prefixes.length, 1);
  assert.equal(prefixes[0].prefix, '188.143.132.189/32');
  assert.equal(prefixes[0].family, 4);
});

test('classifyClients в режиме IP размечает по адресу без SNMP', () => {
  const { classifyClients } = require('./erp-piterix-sync');
  const { labelable, skipped } = classifyClients([
    {
      basic_account: 104,
      name: 'Калинин',
      int_status: 1,
      block: { is_blocked: false },
      ips: [{ ip: '188.143.132.189', cidr: null }],
    },
    {
      basic_account: 113,
      name: 'Екимова',
      int_status: 1,
      block: { is_blocked: false },
      ips: [{ ip: '188.143.134.119', cidr: null }],
    },
  ], {}, { bindMode: 'prefixes', sourceTag: 'erp:bb' });
  assert.equal(labelable.length, 2);
  assert.equal(labelable[0].prefixes[0].prefix, '188.143.132.189/32');
  assert.equal(labelable[0].comment, 'erp:bb');
  assert.equal(skipped.length, 0);
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
