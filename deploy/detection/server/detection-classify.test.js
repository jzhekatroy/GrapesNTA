'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  KINDS,
  classifyFromMetrics,
  refineClassification,
  isAttackKind,
  actionFor,
  volumeStillHigh,
  formatVictim,
  formatSwitchPort,
  hourCeiling,
} = require('./detection-classify');

describe('detection-classify', () => {
  it('Hostland: узкая энтропия UDP + рост часа → volumetric, после доли 99% остаётся атака', () => {
    const byProto = {
      all: { bps: 5.84e9, port_entropy: 0.95, syn_attempts: 74, answer_pct: 24 },
      tcp: { bps: 1.54e9, port_entropy: 1.49 },
      udp: { bps: 4.29e9, port_entropy: 0.29 },
    };
    const first = classifyFromMetrics(byProto, { p95: 0.84e9, p999: 3.71e9 });
    assert.equal(first.kind, KINDS.volumetric);
    assert.equal(first.needsInvestigate, true);
    const refined = refineClassification(first, { victim: { share: 0.994 } });
    assert.equal(refined.kind, KINDS.volumetric);
    assert.equal(isAttackKind(refined.kind), true);
  });

  it('Belcloud: объём ×30 и UDP → carpet, топ IP 0.2% подтверждает', () => {
    const byProto = {
      all: { bps: 5.91e9, port_entropy: 10.05 },
      tcp: { bps: 7.9e5, port_entropy: 0 },
      udp: { bps: 5.90e9, port_entropy: 10.05 },
    };
    const first = classifyFromMetrics(byProto, { p95: 0.07e9, p999: 0.19e9 });
    assert.equal(first.kind, KINDS.carpet);
    const refined = refineClassification(first, { victim: { share: 0.002 } });
    assert.equal(refined.kind, KINDS.carpet);
  });

  it('Электрон-Телеком: объём внутри часа и высокая энтропия → пик, без разбора', () => {
    const byProto = {
      all: { bps: 25.6e9, port_entropy: 10.46 },
      tcp: { bps: 23.7e9, port_entropy: 10.39 },
      udp: { bps: 1.89e9, port_entropy: 6.61 },
    };
    const first = classifyFromMetrics(byProto, { p95: 23e9, p999: 26.7e9 });
    assert.equal(first.kind, KINDS.benign_peak);
    assert.equal(first.needsInvestigate, false);
    assert.equal(isAttackKind(first.kind), false);
  });

  it('Митигатор Клауд: p999 задран началом той же атаки, потолок от p95 её возвращает', () => {
    const byProto = {
      all: { bps: 2.925e9, port_entropy: 2.07, syn_attempts: 0 },
      tcp: { bps: 0.15e9, port_entropy: 5.1 },
      udp: { bps: 2.741e9, port_entropy: 1.94 },
    };
    // p999 = 2.585 это минута 16:26 того же всплеска, попавшая в baseline;
    // после карантина остаются p95 0.2 и p999 0.226, медиана часа 0.147.
    const hour = { p95: 0.2e9, p999: 0.226e9, recentMedian: 0.147e9 };
    const first = classifyFromMetrics(byProto, hour);
    assert.equal(Math.round(first.hourRatio * 100) / 100, 12.44);
    assert.equal(first.kind, KINDS.carpet);
    assert.equal(first.needsInvestigate, true);
    const refined = refineClassification(first, { victim: { share: 0.998 } });
    assert.equal(refined.kind, KINDS.volumetric);
  });

  it('АТС Смольного: плавный утренний рост остаётся пиком, потолок не мешает', () => {
    const byProto = {
      all: { bps: 2.93e9, port_entropy: 8.53, syn_attempts: 4, answer_pct: 0 },
      tcp: { bps: 2.862e9, port_entropy: 8.49 },
      udp: { bps: 0.033e9, port_entropy: 3.17 },
    };
    // После карантина история даёт всего 1.273 Гбит/с — неделю назад клиент
    // возил вдвое меньше. Норму держит медиана последнего часа.
    const hour = { p95: 1.132e9, p999: 1.273e9, recentMedian: 1.813e9 };
    const first = classifyFromMetrics(byProto, hour);
    assert.equal(Math.round(first.hourRatio * 100) / 100, 1.01);
    assert.equal(first.kind, KINDS.benign_peak);
    assert.equal(first.needsInvestigate, false);
  });

  it('норма собирается из истории и последнего часа, что больше', () => {
    // Потолок p95 срезает задранный p999.
    assert.equal(hourCeiling({ p95: 1e9, p999: 8e9 }), 4e9);
    // Ровный клиент: история выше локальной медианы, берём её.
    assert.equal(hourCeiling({ p95: 40e9, p999: 48e9, recentMedian: 20e9 }), 48e9);
    // Растущий клиент: локальный уровень выше истории.
    assert.equal(hourCeiling({ p95: 1e9, p999: 1.2e9, recentMedian: 2e9 }), 3.2e9);
    assert.equal(hourCeiling({ p999: 8e9 }), 8e9);
    assert.equal(hourCeiling({ recentMedian: 2e9 }), 3.2e9);
    assert.equal(hourCeiling({}), null);
  });

  it('refine: нет концентрации и объём свой → пик', () => {
    const first = classifyFromMetrics(
      { all: { bps: 6.9e9, port_entropy: 10.1 }, tcp: { bps: 6e9 }, udp: { bps: 0.9e9 } },
      { p999: 8e9 },
    );
    const refined = refineClassification(first, { victim: { share: 0.062 } });
    assert.equal(refined.kind, KINDS.benign_peak);
  });

  it('объём не сел — нормализацию держим', () => {
    assert.equal(volumeStillHigh(9.4e9, 6.9e9, 3e9), true);
    assert.equal(volumeStillHigh(0.64e9, 5.8e9, 0.84e9), false);
  });

  it('Митигатор Клауд с amp-метриками → амплификация в один сервер', () => {
    const byProto = {
      all: { bps: 2.925e9, port_entropy: 2.07, syn_attempts: 0, bytes: 2.925e9 * 60 / 8 },
      tcp: { bps: 0.15e9 },
      udp: {
        bps: 2.741e9,
        bytes: 2.741e9 * 60 / 8,
        amp_bytes: 3.683e9,
        amp_packets: 4_065_536,
        amp_srcs: 40,
      },
    };
    const hour = { p95: 0.2e9, p999: 0.226e9, recentMedian: 0.147e9 };
    const first = classifyFromMetrics(byProto, hour);
    assert.equal(first.kind, KINDS.amplification);
    assert.equal(first.needsInvestigate, true);
    const refined = refineClassification(first, { victim: { share: 0.998 } });
    assert.equal(refined.kind, KINDS.amplification);
    assert.match(refined.reason, /амплификация в один сервер/);
    assert.equal(isAttackKind(refined.kind), true);
  });

  it('81050: амплификация при росте объёма всего ×1.25', () => {
    const byProto = {
      all: { bps: 18.762e9, port_entropy: 6.53, growth_bps: 1.25 },
      tcp: { bps: 12.781e9 },
      udp: {
        bps: 5.066e9,
        bytes: 5.066e9 * 60 / 8,
        amp_bytes: 12.12 * 1024 ** 3,
        amp_packets: Math.round(12.12 * 1024 ** 3 / 1505),
        amp_srcs: 119,
      },
    };
    const first = classifyFromMetrics(byProto, { p95: 15e9, p999: 16e9, recentMedian: 14e9 });
    assert.equal(first.kind, KINDS.amplification);
  });

  it('71762: UDP 1% и нет amp → обычный пик, не амплификация', () => {
    const first = classifyFromMetrics({
      all: { bps: 8e9, port_entropy: 8.2 },
      tcp: { bps: 7.92e9 },
      udp: { bps: 0.08e9, bytes: 0.08e9 * 60 / 8, amp_bytes: 0, amp_packets: 0, amp_srcs: 0 },
    }, { p95: 6e9, p999: 7e9, recentMedian: 5e9 });
    assert.notEqual(first.kind, KINDS.amplification);
    assert.equal(first.kind, KINDS.benign_peak);
  });

  it('только география: вид инцидента по остальным метрикам, разбор нужен', () => {
    const first = classifyFromMetrics({
      all: {
        bps: 6.9e9, port_entropy: 10.1, bytes: 6.9e9 * 60 / 8,
        foreign_bytes: 14e9, growth_foreign_share: 3.7, growth_foreign_bps: 10,
      },
      tcp: { bps: 6e9 },
      udp: { bps: 0.9e9, bytes: 0.9e9 * 60 / 8, amp_bytes: 0, amp_packets: 0, amp_srcs: 0 },
    }, { p95: 8e9, p999: 8.5e9, recentMedian: 7e9 });
    assert.equal(first.foreignHit, true);
    assert.equal(first.kind, KINDS.benign_peak);
    assert.equal(first.needsInvestigate, true);
  });

  it('85932: HTTPS с одного IP Mail.ru на эфемерный порт → пик загрузки', () => {
    const first = classifyFromMetrics({
      all: {
        bps: 923.6e6, port_entropy: 0.13, syn_attempts: 2003, answer_pct: 33.3,
        avg_packet_bytes: 1507,
      },
      tcp: { bps: 923e6, port_entropy: 0.1, avg_packet_bytes: 1510 },
      udp: { bps: 0.6e6 },
    }, { p95: 60.7e6, p999: 60.7e6 });
    assert.equal(first.kind, KINDS.benign_peak);
    const refined = refineClassification(first, {
      victim: { ip: '94.26.164.176', port: 53495, protoLabel: 'TCP', share: 0.994 },
      source24: [{ net24: '95.163.51.0/24', asn: 47764, share: 0.994, ips: 1 }],
      l4src: [{ port: 443, proto: 6, share: 1 }],
    });
    assert.equal(refined.kind, KINDS.benign_peak);
    assert.match(refined.reason, /пик загрузки/);
    assert.equal(isAttackKind(refined.kind), false);
    assert.equal(actionFor(refined, { victim: { ip: '94.26.164.176', port: 53495 } }), 'пик загрузки, фильтр не нужен');
  });

  it('Hostland: UDP на 443 с многих IP не становится загрузкой', () => {
    const first = classifyFromMetrics({
      all: { bps: 5.84e9, port_entropy: 0.95, syn_attempts: 74, answer_pct: 24, avg_packet_bytes: 400 },
      tcp: { bps: 1.54e9 },
      udp: { bps: 4.29e9, port_entropy: 0.29 },
    }, { p95: 0.84e9, p999: 3.71e9 });
    const refined = refineClassification(first, {
      victim: { ip: '185.26.122.4', port: 443, protoLabel: 'UDP', share: 0.994 },
      source24: [{ net24: '125.224.150.0/24', share: 0.01, asn: 3462, ips: 4 }],
      l4src: [{ port: 80, proto: 17, share: 0.14 }],
    });
    assert.equal(refined.kind, KINDS.volumetric);
  });

  it('рост к часу без UDP-формы — пик, не ковёр', () => {
    const first = classifyFromMetrics({
      all: { bps: 37.8e6, port_entropy: 4.96, syn_attempts: 62, answer_pct: 64.5, avg_packet_bytes: 1505 },
      tcp: { bps: 0.175e6, avg_packet_bytes: 925 },
      udp: { bps: 0 },
    }, { p95: 0.27e6, p999: 0.27e6, recentMedian: 0.27e6 });
    assert.equal(first.kind, KINDS.benign_peak);
    assert.equal(isAttackKind(first.kind), false);
  });

  it('109749: HTTPS с нескольких CDN, TCP в сэмпле почти ноль → пик загрузки', () => {
    const first = classifyFromMetrics({
      all: { bps: 37.8e6, port_entropy: 4.96, syn_attempts: 62, answer_pct: 64.5, avg_packet_bytes: 1505 },
      tcp: { bps: 0.175e6, avg_packet_bytes: 925 },
      udp: { bps: 0 },
    }, { p95: 0.27e6, p999: 0.27e6 });
    const refined = refineClassification(first, {
      victim: { ip: '188.143.148.57', port: 36556, protoLabel: 'TCP', share: 0.142 },
      source24: [{ net24: '150.241.243.0/24', asn: 214647, share: 0.615, ips: 1 }],
      l4src: [{ port: 443, proto: 6, share: 1 }],
    });
    assert.equal(refined.kind, KINDS.benign_peak);
    assert.match(refined.reason, /пик загрузки/);
  });

  it('70807: HTTP с AWS в один IP, доля TCP 55% → пик загрузки, не volumetric', () => {
    const first = classifyFromMetrics({
      all: { bps: 202e6, port_entropy: 0.18, syn_attempts: 87, answer_pct: 80.5, avg_packet_bytes: 1494 },
      tcp: { bps: 112e6, avg_packet_bytes: 1494 },
      udp: { bps: 666 },
    }, { p95: 50e6, p999: 50e6 });
    const refined = refineClassification(first, {
      victim: { ip: '188.143.152.77', port: 49986, protoLabel: 'TCP', share: 0.98 },
      source24: [{ net24: '108.157.214.0/24', asn: 16509, share: 0.98, ips: 1 }],
      l4src: [{ port: 80, proto: 6, share: 0.98 }],
    });
    assert.equal(refined.kind, KINDS.benign_peak);
    assert.equal(isAttackKind(refined.kind), false);
    assert.equal(actionFor(refined, { victim: { ip: '188.143.152.77', port: 49986 } }), 'пик загрузки, фильтр не нужен');
  });

  it('76998: QUIC UDP/443 с Akamai на эфемерный порт → пик загрузки', () => {
    const first = classifyFromMetrics({
      all: { bps: 23.8e6, port_entropy: 0.77, syn_attempts: 37, answer_pct: 21.6, avg_packet_bytes: 1479 },
      tcp: { bps: 12.2e3, avg_packet_bytes: 171 },
      udp: { bps: 20.1e6, port_entropy: 0.71, avg_packet_bytes: 1487 },
    }, { p95: 6.4e6, p999: 6.4e6 });
    const refined = refineClassification(first, {
      victim: { ip: '188.143.150.72', port: 49534, protoLabel: 'UDP', share: 0.872 },
      source24: [{ net24: '184.51.252.0/24', asn: 20940, share: 0.975, ips: 2 }],
      l4src: [{ port: 443, proto: 17, share: 1 }],
    });
    assert.equal(refined.kind, KINDS.benign_peak);
    assert.match(refined.reason, /пик загрузки · узкий источник · UDP\/443/);
    assert.equal(isAttackKind(refined.kind), false);
    assert.equal(actionFor(refined, { victim: { ip: '188.143.150.72', port: 49534, protoLabel: 'UDP' } }), 'пик загрузки, фильтр не нужен');
  });

  it('QUIC-флуд с многих IP на эфемерный порт остаётся атакой', () => {
    const first = classifyFromMetrics({
      all: { bps: 200e6, port_entropy: 0.2, avg_packet_bytes: 1480 },
      tcp: { bps: 1e6 },
      udp: { bps: 199e6, port_entropy: 0.1 },
    }, { p95: 10e6, p999: 10e6 });
    const refined = refineClassification(first, {
      victim: { ip: '188.143.150.72', port: 49534, protoLabel: 'UDP', share: 0.99 },
      source24: [{ net24: '184.51.252.0/24', share: 0.05, ips: 20 }],
      l4src: [{ port: 443, proto: 17, share: 1 }],
    });
    assert.equal(refined.kind, KINDS.volumetric);
    assert.equal(isAttackKind(refined.kind), true);
  });

  it('20944: OpenVPN UDP/1194 с одного IP → пик загрузки', () => {
    const first = classifyFromMetrics({
      all: { bps: 27.2e6, port_entropy: 0.01, syn_attempts: 21, answer_pct: 23.8, avg_packet_bytes: 1439 },
      tcp: { bps: 3.2e3, avg_packet_bytes: 329 },
      udp: { bps: 35.4e6, port_entropy: 0 },
    }, { p95: 903, p999: 903 });
    const refined = refineClassification(first, {
      victim: { ip: '188.143.164.169', port: 55893, protoLabel: 'UDP', share: 1 },
      source24: [{ net24: '62.231.7.0/24', asn: 3216, share: 1, ips: 1 }],
      l4src: [{ port: 1194, proto: 17, share: 1 }],
    });
    assert.equal(refined.kind, KINDS.benign_peak);
    assert.match(refined.reason, /пик загрузки · узкий источник · UDP\/1194/);
    assert.equal(isAttackKind(refined.kind), false);
    assert.equal(actionFor(refined, { victim: { ip: '188.143.164.169', port: 55893, protoLabel: 'UDP' } }), 'пик загрузки, фильтр не нужен');
  });

  it('5855: один UDP-пир на любом порту → пик, не volumetric', () => {
    const first = classifyFromMetrics({
      all: { bps: 146e6, port_entropy: 3.74, syn_attempts: 240, answer_pct: 81.7, avg_packet_bytes: 1241 },
      tcp: { bps: 18.8e6 },
      udp: { bps: 111e6, port_entropy: 3.56 },
    }, { p95: 53.3e6, p999: 53.3e6 });
    const refined = refineClassification(first, {
      victim: { ip: '188.143.137.136', port: 42571, protoLabel: 'UDP', share: 0.841 },
      source24: [{ net24: '130.49.187.0/24', asn: 215540, share: 0.848, ips: 1 }],
      l4src: [{ port: 50264, proto: 17, share: 0.84 }],
    });
    assert.equal(refined.kind, KINDS.benign_peak);
    assert.match(refined.reason, /узкий источник · UDP\/50264/);
    assert.equal(isAttackKind(refined.kind), false);
  });

  it('56128: торрент, много пиров, топ /24 27% → остаётся атака', () => {
    const first = classifyFromMetrics({
      all: { bps: 71.1e6, port_entropy: 0.16, syn_attempts: 165, answer_pct: 37, avg_packet_bytes: 1197 },
      tcp: { bps: 207e3 },
      udp: { bps: 87.4e6, port_entropy: 0.01 },
    }, { p95: 17.1e6, p999: 17.1e6 });
    const refined = refineClassification(first, {
      victim: { ip: '188.143.160.61', port: 15574, protoLabel: 'UDP', share: 0.998 },
      source24: [{ net24: '77.45.229.0/24', asn: 12389, share: 0.273, ips: 1 }],
      l4src: [{ port: 10550, proto: 17, share: 0.27 }],
    });
    assert.equal(refined.kind, KINDS.volumetric);
    assert.equal(isAttackKind(refined.kind), true);
  });

  it('UDP/1194 с многих IP не становится VPN-пиком', () => {
    const first = classifyFromMetrics({
      all: { bps: 80e6, port_entropy: 0.01, avg_packet_bytes: 1400 },
      tcp: { bps: 1e3 },
      udp: { bps: 80e6, port_entropy: 0 },
    }, { p95: 1e6, p999: 1e6 });
    const refined = refineClassification(first, {
      victim: { ip: '188.143.164.169', port: 55893, protoLabel: 'UDP', share: 1 },
      source24: [{ net24: '62.231.7.0/24', share: 0.12, ips: 40 }],
      l4src: [{ port: 1194, proto: 17, share: 1 }],
    });
    assert.equal(refined.kind, KINDS.volumetric);
    assert.equal(isAttackKind(refined.kind), true);
  });

  it('81050: веерная amp без цели — резать на сеть клиента, не на GRE :0', () => {
    assert.equal(actionFor({ kind: KINDS.amplification }, {
      victim: { ip: '185.129.101.255', port: 0, proto: 47, protoLabel: '47', share: 0.057 },
      l4src: [
        { port: 443, proto: 6, share: 0.43 },
        { port: 53, proto: 17, share: 0.03 },
      ],
    }), 'резать входящий UDP/53 на сеть клиента');
  });

  it('81953: amp в одну /24 — резать на неё, не на сеть клиента', () => {
    assert.equal(actionFor({ kind: KINDS.amplification }, {
      victim: { ip: '31.171.101.14', port: 0, proto: 17, protoLabel: 'UDP', share: 0.017 },
      l4src: [{ port: 53, proto: 17, share: 0.04 }],
      ampDest24: [
        { net24: '31.171.101.0/24', share: 0.99, ips: 10 },
        { net24: '91.218.160.0/24', share: 0.01, ips: 1 },
      ],
    }), 'резать входящий UDP/53 на 31.171.101.0/24');
  });

  it('один источник и 4.6 Мбит/с amp — не амплификация', () => {
    const byProto = {
      all: { bps: 5e6 },
      udp: { bps: 5e6, bytes: 5e6 * 60 / 8, amp_bytes: 34e6, amp_packets: 34000, amp_srcs: 1 },
    };
    const first = classifyFromMetrics(byProto, { p95: 4e6, p999: 5e6 });
    assert.notEqual(first.kind, KINDS.amplification);
  });

  it('форматирует жертву и порт коммутатора, иначе прочерк', () => {
    assert.equal(formatVictim(null), '—');
    assert.match(formatVictim({
      ip: '185.26.122.4', net24: '185.26.122.0/24', port: 443, protoLabel: 'UDP', share: 0.994,
    }), /185\.26\.122\.4:443/);
    assert.equal(formatSwitchPort(null), '—');
    assert.match(formatSwitchPort({
      switchIp: '172.18.19.165', ifName: 'port-channel2', ifAlias: 'imaqliq.9236', share: 1,
    }), /port-channel2/);
  });
});
