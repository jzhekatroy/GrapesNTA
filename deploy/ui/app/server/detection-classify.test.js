'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  KINDS,
  classifyFromMetrics,
  refineClassification,
  isAttackKind,
  volumeStillHigh,
  formatVictim,
  formatSwitchPort,
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
