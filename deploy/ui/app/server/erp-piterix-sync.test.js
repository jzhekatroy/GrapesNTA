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

test('отчёт кладёт несколько MAC клиента в одну ячейку', () => {
  const { buildReportRows, reportToCsv } = require('./erp-piterix-report');
  const active = {
    int_status: 1,
    block: { is_blocked: false },
    name: 'Клиент',
  };
  const client = {
    ...active,
    basic_account: 10,
    ips: [
      { ip: '188.143.1.1', mac: 'AA:BB:CC:DD:EE:01', switch: { host: '172.18.19.28', port: 10 } },
      { ip: '188.143.1.2', mac: 'aa:bb:cc:dd:ee:01', switch: { host: '172.18.19.28', port: 10 } },
      { ip: '188.143.1.3', mac: 'AA-BB-CC-DD-EE-02', switch: { host: '172.18.19.28', port: 11 } },
      { ip: '188.143.1.4', mac: null },
      { ip: '188.143.1.5', mac: '11:22:33:44:55:66' },
    ],
    ip_history: [{ ip: '9.9.9.9', mac: '00:11:22:33:44:55' }],
  };
  const catalog = {
    agents: new Map([['172.18.19.28', { display_name: 'sw' }]]),
    ifaces: new Set(['172.18.19.28:10', '172.18.19.28:11']),
    ifaceRows: new Map(),
  };
  const expected = '11:22:33:44:55:66; aa:bb:cc:dd:ee:01; aa:bb:cc:dd:ee:02';
  const portRows = buildReportRows({ clients: [client], catalog, bindMode: 'ports' });
  assert.equal(portRows.length, 2);
  assert.equal(portRows[0].macs, expected);
  assert.equal(portRows[1].macs, expected);
  const prefixRows = buildReportRows({ clients: [client], bindMode: 'prefixes', l3: null });
  assert.ok(prefixRows.length > 1);
  assert.ok(prefixRows.every((row) => row.macs === expected));
  const header = reportToCsv(portRows).split('\n')[0];
  assert.match(header, /MAC/);
  assert.match(reportToCsv(portRows), /11:22:33:44:55:66; aa:bb:cc:dd:ee:01; aa:bb:cc:dd:ee:02/);
});

test('clientsToDisable снимает только пропавших из ERP', () => {
  const { clientsToDisable } = require('./erp-piterix-sync');
  assert.deepEqual(clientsToDisable(['1', '2', '3'], ['2', '3']), ['1']);
});

test('ЛС без порта отмечает, что у того же клиента другой ЛС уже размечен', () => {
  const { buildReportRows } = require('./erp-piterix-report');
  const catalog = {
    agents: new Map([['172.18.19.28', { display_name: 'sw' }]]),
    ifaces: new Set(['172.18.19.28:10']),
    ifaceRows: new Map([['172.18.19.28:10', { if_name: 'Eth1', if_alias: '', if_speed_bps: 1e9 }]]),
  };
  const active = {
    int_status: 1,
    block: { is_blocked: false },
    name: 'ООО РЕКОНН',
  };
  const rows = buildReportRows({
    clients: [
      { ...active, basic_account: 106306, ips: [{ switch: { host: '172.18.19.28', port: 10 } }] },
      { ...active, basic_account: 106307, ips: [{ ip: '10.0.0.1' }] },
      {
        ...active,
        name: 'Другой клиент',
        basic_account: 1,
        ips: [{ ip: '10.0.0.2' }],
      },
    ],
    catalog,
    bindMode: 'ports',
  });
  const byAccount = Object.fromEntries(rows.map((row) => [row.account, row.reason]));
  assert.equal(byAccount['106306'], '');
  assert.equal(byAccount['106307'], REASON.no_port_sibling);
  assert.equal(byAccount['1'], REASON.no_port);
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

test('включённый piter_ix без сохранённых групп означает обе галки', () => {
  const { mapSettings } = require('./erp-piterix-settings');
  const fresh = mapSettings({});
  assert.deepEqual(fresh.piterIxGroups, { 710: true, 726: true });
  const off = mapSettings({ cat_piter_ix: 0 });
  assert.deepEqual(off.piterIxGroups, { 710: false, 726: false });
  const onlyIx = mapSettings({ cat_piter_ix: 1, piter_ix_g710: 1, piter_ix_g726: 0 });
  assert.deepEqual(onlyIx.piterIxGroups, { 710: true, 726: false });
});

test('обе группы piter_ix не отбрасывают клиентов без номера группы', () => {
  const { filterClientsByPiterIxGroups } = require('./erp-piterix-sync');
  const clients = [{ basic_account: 1 }, { basic_account: 2, billing_group_id: 710 }];
  assert.equal(filterClientsByPiterIxGroups(clients, ['710', '726']).length, 2);
});

test('одна группа piter_ix берёт только клиентов с этим номером', () => {
  const { filterClientsByPiterIxGroups } = require('./erp-piterix-sync');
  const clients = [
    { basic_account: 1, billing_group_id: 710 },
    { basic_account: 2, billing_group: { id: 726 } },
    { basic_account: 3, group_id: '710' },
  ];
  const kept = filterClientsByPiterIxGroups(clients, ['710']);
  assert.deepEqual(kept.map((c) => c.basic_account), [1, 3]);
});

test('одна группа без номера в ответе ERP останавливает прогон', () => {
  const { filterClientsByPiterIxGroups } = require('./erp-piterix-sync');
  assert.throws(
    () => filterClientsByPiterIxGroups([{ basic_account: 1 }], ['726']),
    /не присылает группу биллинга/,
  );
});

test('IX MAC берётся только с принятого порта и не пишется, если ЛС несколько', () => {
  const { collectIxPortMacs, clientsWithoutPortMac, classifyObservedPortMacs } = require('./erp-piterix-sync');
  const clients = [
    {
      basic_account: '1',
      int_status: 1,
      block: { is_blocked: false },
      ips: [
        { mac: 'AA:BB:CC:DD:EE:01', switch: { host: '172.18.19.1', port: 10 } },
        { mac: 'AA:BB:CC:DD:EE:09' },
      ],
    },
    {
      basic_account: '2',
      int_status: 1,
      block: { is_blocked: false },
      ips: [{ mac: 'aa-bb-cc-dd-ee-01', switch: { host: '172.18.19.1', port: 10 } }],
    },
    {
      basic_account: '3',
      int_status: 1,
      block: { is_blocked: false },
      ips: [{ mac: '001122334455', switch: { host: '172.18.19.1', port: 11 } }],
    },
  ];
  const accepted = new Set(['1|172.18.19.1|10', '2|172.18.19.1|10', '3|172.18.19.1|11']);
  const planned = collectIxPortMacs(clients, accepted);
  assert.equal(planned.bindings.length, 1);
  assert.equal(planned.bindings[0].client_id, '3');
  assert.equal(planned.bindings[0].mac, '001122334455');
  assert.equal(planned.ambiguous.length, 1);
  assert.deepEqual(planned.ambiguous[0].accounts, ['1', '2']);

  const missing = clientsWithoutPortMac([
    { clientId: '1', displayName: 'A', ports: [{ switchIp: '172.18.19.1', ifIndex: 10 }] },
    { clientId: '3', displayName: 'C', ports: [{ switchIp: '172.18.19.1', ifIndex: 11 }] },
  ], planned.bindings);
  assert.deepEqual(missing.map((row) => row.clientId), ['1']);

  const owners = new Map([['172.18.19.1|11', '3']]);
  const bindings = [
    ...planned.bindings,
    { client_id: '8', switch_ip: '172.18.19.1', if_index: 20, mac: 'aabbccddee08' },
  ];
  const seen = classifyObservedPortMacs([
    { switch_ip: '172.18.19.1', if_index: 11, mac: '00:11:22:33:44:55', bytes: 2e6 },
    { switch_ip: '172.18.19.1', if_index: 11, mac: 'aabbccddee08', bytes: 3e6 },
    { switch_ip: '172.18.19.1', if_index: 11, mac: 'ffffffffffff', bytes: 4e6 },
    { switch_ip: '172.18.19.9', if_index: 1, mac: 'ffffffffffff', bytes: 9e6 },
  ], bindings, owners);
  assert.equal(seen.foreign.length, 1);
  assert.equal(seen.foreign[0].owner, '3');
  assert.deepEqual(seen.foreign[0].accounts, ['8']);
  assert.equal(seen.unlisted.length, 1);
  assert.equal(seen.unlisted[0].mac, 'ffffffffffff');
});

test('MAC, перешедший на порту к другому ЛС, не отключается поверх новой привязки', () => {
  const { portMacsToDisable } = require('./erp-piterix-sync');
  const dropped = portMacsToDisable(
    [
      { client_id: '1', switch_ip: '172.18.19.1', if_index: 10, mac: 'aabbccddee01' },
      { client_id: '1', switch_ip: '172.18.19.1', if_index: 10, mac: 'aabbccddee02' },
    ],
    [{ client_id: '2', switch_ip: '172.18.19.1', if_index: 10, mac: 'aabbccddee01', enabled: 1 }],
  );
  assert.deepEqual(dropped.map((row) => row.mac), ['aabbccddee02']);
});

test('отчёт IX пишет ошибку про пустой MAC только при включённой галке', () => {
  const { buildReportRows } = require('./erp-piterix-report');
  const ix = {
    macOnPort: false,
    noMac: [{ clientId: '19', displayName: 'Без MAC', ports: [{ switchIp: '172.18.19.1', ifIndex: 8 }] }],
    ambiguous: [{ accounts: ['1', '2'], switchIp: '172.18.19.1', ifIndex: 10, mac: 'aabbccddee01' }],
    foreign: [{ owner: '3', switchIp: '172.18.19.1', ifIndex: 11, mac: 'aabbccddee01', accounts: ['1'], bytes: 10 }],
    unlisted: [{ owner: '3', switchIp: '172.18.19.1', ifIndex: 11, mac: 'ffffffffffff', bytes: 10 }],
    note: '',
  };
  const off = buildReportRows({ clients: [], ix, bindMode: 'ports' });
  assert.equal(off.some((row) => row.section === 'IX: MAC на нескольких ЛС'), true);
  assert.equal(off.some((row) => row.section === 'IX: нет MAC'), false);
  assert.equal(off.some((row) => row.section === 'IX: чужой MAC'), false);
  const on = buildReportRows({ clients: [], ix: { ...ix, macOnPort: true, note: 'учёт IX включён, но ни один VLAN не отмечен как IX' }, bindMode: 'ports' });
  assert.equal(on.filter((row) => row.section === 'IX: нет MAC').length, 1);
  assert.equal(on.some((row) => row.section === 'IX: чужой MAC'), true);
  assert.equal(on.some((row) => row.section === 'IX: MAC нет в ERP'), true);
  assert.equal(on.some((row) => row.section === 'IX' && /VLAN/.test(row.reason)), true);
  assert.equal(on.find((row) => row.section === 'IX: нет MAC').macs, '');
  assert.match(on.find((row) => row.section === 'IX: чужой MAC').macs, /aa:bb:cc:dd:ee:01/);
});
