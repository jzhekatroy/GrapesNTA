'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
  parseArgs,
  attackRange,
  rollupParticipants,
  formatReports,
  formatReportsCsv,
  formatAttackList,
} = require('./attack-asn');

describe('grapes-attack-asn', () => {
  it('читает флаги', () => {
    const args = parseArgs(['node', 'attack-asn.js', '--csv', '--attack', 'client:1|2026-10-23 12:00:00', '--limit', '15']);
    assert.equal(args.csv, true);
    assert.equal(args.attackId, 'client:1|2026-10-23 12:00:00');
    assert.equal(args.limit, 15);
    assert.throws(() => parseArgs(['node', 'attack-asn.js', '--nope']), /Неизвестный аргумент/);
  });

  it('окно идёт от начала атаки до сейчас, у закрытой — до минуты завершения', () => {
    const now = Date.parse('2026-10-23T13:00:00Z');
    const active = attackRange({
      status: 'active',
      startMinute: '2026-10-23 12:00:00',
      alertMinute: '2026-10-23 12:05:00',
    }, now);
    assert.equal(active.from, '2026-10-23 12:00:00');
    assert.equal(active.to, '2026-10-23 13:00:00');
    assert.equal(active.closed, false);

    const closed = attackRange({
      status: 'normalized',
      startMinute: '2026-10-23 12:00:00',
      normalizeMinute: '2026-10-23 12:40:00',
    }, Date.parse('2026-10-23T15:00:00Z'));
    assert.equal(closed.to, '2026-10-23 12:41:00');
    assert.equal(closed.closed, true);

    const fromAlert = attackRange({
      status: 'active',
      alertMinute: '2026-10-23 12:05:00',
    }, now);
    assert.equal(fromAlert.from, '2026-10-23 12:05:00');
    assert.equal(attackRange({ status: 'active' }, now), null);
  });

  it('сортирует AS и /24 по убыванию и считает долю и накопленную долю', () => {
    const rolled = rollupParticipants([
      { asn: 10, asnName: 'Small', prefix: '2.0.0.0/24', bytes: 25 },
      { asn: 20, asnName: 'Big', prefix: '1.0.0.0/24', bytes: 50 },
      { asn: 20, asnName: 'Big', prefix: '1.0.1.0/24', bytes: 25 },
    ]);
    assert.equal(rolled.totalBytes, 100);
    assert.deepEqual(rolled.asns.map((row) => row.asn), [20, 10]);
    assert.equal(rolled.asns[0].prefixCount, 2);
    assert.equal(rolled.asns[0].share, 0.75);
    assert.equal(rolled.asns[0].cumulative, 0.75);
    assert.equal(rolled.asns[1].cumulative, 1);
    assert.deepEqual(rolled.prefixes.map((row) => row.prefix), ['1.0.0.0/24', '1.0.1.0/24', '2.0.0.0/24']);
    assert.equal(rolled.prefixes[1].share, 0.25);
  });

  it('печатает AS и сети /24, а CSV экранирует имя с запятой', () => {
    const report = {
      event: {
        id: 'client:1|2026-10-23 12:00:00',
        name: 'Ромашка, ООО',
        status: 'active',
        scope: 'client',
        scopeId: '1',
      },
      range: { from: '2026-10-23 09:00:00', to: '2026-10-23 10:00:00', closed: false },
      limit: 20000,
      truncated: false,
      ...rollupParticipants([
        { asn: 12389, asnName: 'Rostelecom', prefix: '1.2.3.0/24', bytes: 1500 * 1024 * 1024 },
        { asn: 8359, asnName: 'MTS', prefix: '5.6.7.0/24', bytes: 500 * 1024 * 1024 },
      ]),
    };
    const text = formatReports([report]);
    assert.match(text, /ASN/);
    assert.match(text, /Сети \/24/);
    assert.match(text, /AS12389/);
    assert.match(text, /1\.2\.3\.0\/24/);
    assert.match(text, /75\.0%/);
    assert.ok(text.indexOf('AS12389') < text.indexOf('AS8359'));
    assert.ok(text.indexOf('1.2.3.0/24') < text.indexOf('5.6.7.0/24'));

    const csv = formatReportsCsv([report]);
    assert.match(csv, /^section,attack_id,/);
    assert.match(csv, /asn,client:1\|2026-10-23 12:00:00,"Ромашка, ООО",active,client,1,12389,Rostelecom,,1572864000,75.00,75.00,1,0/);
    assert.match(csv, /prefix,.*1\.2\.3\.0\/24,1572864000,75\.00,,,0/);
    assert.equal(formatAttackList([]), 'Активных атак нет.\n');
  });

  it('запрос группирует мусорный UDP по AS и /24', () => {
    const src = fs.readFileSync(path.join(__dirname, 'detection-investigate.js'), 'utf8');
    const body = src.slice(src.indexOf('async function loadAttackPrefixes'), src.indexOf('\nmodule.exports'));
    assert.match(body, /excessUdpSql\(\)/);
    assert.match(body, /GROUP BY asn, prefix/);
    assert.match(body, /prefix != '' AND asn != 0/);
    assert.match(body, /ORDER BY bytes DESC/);
  });
});
