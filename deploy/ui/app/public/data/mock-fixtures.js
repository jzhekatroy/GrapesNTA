/* Deterministic mock data fixtures. */

const seededRand = (() => {
  let s = 1234567;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 0xFFFFFFFF; };
})();

/** Статистика трафика по направлениям: max / avg / volume (bps + pps). */
const TRAFFIC_DIRECTION_STATS = {
  max: {
    total:        { bps: 30e9, pps: 10e6 },
    incoming:     { bps: 10e9, pps: 3e6 },
    outgoing:     { bps: 5e9,  pps: 2e6 },
    transit:      { bps: 6e9,  pps: 2e6 },
    internal:     { bps: 9e9,  pps: 3e6 },
    unclassified: { bps: 0,    pps: 0 },
  },
  avg: {
    total:        { bps: 18.4e9, pps: 6.2e6 },
    incoming:     { bps: 6.8e9,  pps: 2.1e6 },
    outgoing:     { bps: 3.2e9,  pps: 1.4e6 },
    transit:      { bps: 3.9e9,  pps: 1.3e6 },
    internal:     { bps: 5.1e9,  pps: 1.8e6 },
    unclassified: { bps: 0.2e9,  pps: 0.05e6 },
  },
  volume: {
    total:        { gb: 712, tb: 0.712, packets: 207e9 },
    incoming:     { gb: 377, tb: 0.377, packets: 89e9 },
    outgoing:     { gb: 184, tb: 0.184, packets: 80e9 },
    transit:      { gb: 88,  tb: 0.088, packets: 25e9 },
    internal:     { gb: 62,  tb: 0.062, packets: 14e9 },
    unclassified: { gb: 0.1, tb: 0,     packets: 0.05e9 },
  },
};

function seriesTraffic(points = 60, peak = 14e9, ppsPeak = 9e6) {
  const arr = [];
  for (let i = 0; i < points; i++) {
    const t = new Date(Date.now() - (points - i - 1) * 5 * 60 * 1000);
    const wave = 0.5 + 0.4 * Math.sin(i / 4) + 0.2 * Math.sin(i / 9) + (seededRand() - 0.5) * 0.15;
    arr.push({
      t: t.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
      v: Math.max(0.5e9, wave * peak),
      v2: Math.max(2e5, wave * ppsPeak + (seededRand() - 0.5) * 3e5),
    });
  }
  return arr;
}

const RANGE_MINUTES = {
  '30m': 30,
  '1h': 60,
  '3h': 180,
  '6h': 360,
  '12h': 720,
  '24h': 1440,
  '2d': 2880,
  '7d': 10080,
  '14d': 20160,
  '30d': 43200,
  '60d': 86400,
  '90d': 129600,
};

const CHART_MOCK_LINES = [
  { key: 'incoming', label: 'Входящий', color: '#51D16D', share: 0.37 },
  { key: 'outgoing', label: 'Исходящий', color: '#6972F0', share: 0.17 },
  { key: 'transit', label: 'Транзит', color: '#F0B400', share: 0.21 },
  { key: 'internal', label: 'Внутренний', color: '#A4ADFF', share: 0.28 },
  { key: 'unclassified', label: 'Неклассифицировано', color: '#7F7F9D', share: 0.01 },
  { key: 'total', label: 'Всего', color: '#7E92F8', share: 1 },
];

const CHART_MOCK_DRAW_ORDER = ['incoming', 'outgoing', 'transit', 'internal', 'unclassified', 'total'];

function mockChartLines(directions) {
  if (directions == null) {
    return CHART_MOCK_DRAW_ORDER
      .map((key) => CHART_MOCK_LINES.find((ln) => ln.key === key))
      .filter(Boolean)
      .map(({ key, label, color }) => ({ key, label, color }));
  }
  return CHART_MOCK_DRAW_ORDER
    .map((key) => CHART_MOCK_LINES.find((ln) => ln.key === key))
    .filter((ln) => ln && directions[ln.key])
    .map(({ key, label, color }) => ({ key, label, color }));
}

const MOCK_TIMEZONE = 'Europe/Moscow';

function mockMoscowBucket(date) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: MOCK_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).formatToParts(date);
  const pick = (type) => parts.find((p) => p.type === type)?.value ?? '00';
  return `${pick('year')}-${pick('month')}-${pick('day')} ${pick('hour')}:${pick('minute')}:${pick('second')}`;
}

function mockMoscowBucketLabel(date, longRange) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: MOCK_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(date);
  const pick = (type) => parts.find((p) => p.type === type)?.value ?? '00';
  if (longRange) return `${pick('day')}.${pick('month')} ${pick('hour')}:${pick('minute')}`;
  return `${pick('hour')}:${pick('minute')}`;
}

function seriesTrafficForRange(timeRange = '1h', customPeriod, directions, peak = 14e9, ppsPeak = 9e6) {
  let minutes = RANGE_MINUTES[timeRange] || 60;
  if (timeRange === 'custom' && customPeriod?.from && customPeriod?.to) {
    const span = new Date(customPeriod.to) - new Date(customPeriod.from);
    if (Number.isFinite(span) && span > 0) minutes = Math.round(span / 60000);
  }
  const pointCount = Math.max(1, Math.ceil(minutes / 5));
  const longRange = minutes > 1440;
  const lines = mockChartLines(directions);
  const lineMeta = CHART_MOCK_LINES.filter((ln) => lines.some((l) => l.key === ln.key));
  const points = [];

  for (let i = 0; i < pointCount; i++) {
    const t = new Date(Date.now() - (pointCount - i - 1) * 5 * 60 * 1000);
    const wave = 0.5 + 0.4 * Math.sin(i / 4) + 0.2 * Math.sin(i / 9) + (seededRand() - 0.5) * 0.15;
    const base = Math.max(0.5e9, wave * peak);
    const ppsBase = Math.max(2e5, wave * ppsPeak + (seededRand() - 0.5) * 3e5);
    const pt = {
      bucket: mockMoscowBucket(t),
      bucketMs: t.getTime(),
      t: mockMoscowBucketLabel(t, longRange),
    };
    for (const ln of lineMeta) {
      pt[ln.key] = Math.max(0, base * ln.share * (0.92 + seededRand() * 0.16));
      pt[`${ln.key}_pps`] = Math.max(0, ppsBase * ln.share * (0.92 + seededRand() * 0.16));
    }
    points.push(pt);
  }

  return { points, lines };
}

const PROTOCOLS = [
  { label: 'TCP',  protocol: 'TCP',  value: 58.40, color: PROTOCOL_CHART_COLORS[0], trafficGb: 412.5 },
  { label: 'UDP',  protocol: 'UDP',  value: 26.20, color: PROTOCOL_CHART_COLORS[1], trafficGb: 185.2 },
  { label: 'QUIC', protocol: 'QUIC', value: 8.10,  color: PROTOCOL_CHART_COLORS[2], trafficGb: 57.3 },
  { label: 'ICMP', protocol: 'ICMP', value: 3.30,  color: PROTOCOL_CHART_COLORS[3], trafficGb: 23.4 },
  { label: 'GRE',  protocol: 'GRE',  value: 2.10,  color: PROTOCOL_CHART_COLORS[4], trafficGb: 14.8 },
  { label: 'SCTP', protocol: 'SCTP', value: 0.03,  color: PROTOCOL_CHART_COLORS[13], trafficGb: 0.2 },
  { label: 'ESP',  protocol: 'ESP',  value: 0.004, color: PROTOCOL_CHART_COLORS[14], trafficGb: 0.03 },
  { label: 'AH',   protocol: 'AH',   value: 0,     color: PROTOCOL_CHART_COLORS[15], trafficGb: 0 },
  { label: 'Other',protocol: 'Other',value: 1.90,  color: PROTOCOL_CHART_COLORS[19], trafficGb: 13.4 },
];

const OTHER_PORTS_TOP = [
  { transport: 'TCP', port: 8443, portSide: 'dst', percent: 18.2, avgGbps: 1.24, trafficGb: 4.5, packets: 820000, flows: 12040 },
  { transport: 'UDP', port: 53, portSide: 'dst', percent: 12.5, avgGbps: 0.86, trafficGb: 3.1, packets: 410000, flows: 8920 },
  { transport: 'TCP', port: 8080, portSide: 'src', percent: 9.4, avgGbps: 0.64, trafficGb: 2.3, packets: 290000, flows: 5100 },
  { transport: 'TCP', port: 443, portSide: 'dst', percent: 7.1, avgGbps: 0.48, trafficGb: 1.7, packets: 210000, flows: 4200 },
  { transport: 'UDP', port: 123, portSide: 'src', percent: 4.2, avgGbps: 0.29, trafficGb: 1.0, packets: 98000, flows: 2100 },
  { transport: 'TCP', port: 22, portSide: 'dst', percent: 3.8, avgGbps: 0.26, trafficGb: 0.9, packets: 76000, flows: 1800 },
  { transport: 'TCP', port: 3306, portSide: 'dst', percent: 3.1, avgGbps: 0.21, trafficGb: 0.75, packets: 62000, flows: 1500 },
  { transport: 'UDP', port: 161, portSide: 'src', percent: 2.4, avgGbps: 0.16, trafficGb: 0.58, packets: 48000, flows: 1200 },
  { transport: 'TCP', port: 25, portSide: 'dst', percent: 1.9, avgGbps: 0.13, trafficGb: 0.46, packets: 39000, flows: 980 },
  { transport: 'TCP', port: 143, portSide: 'dst', percent: 1.5, avgGbps: 0.1, trafficGb: 0.36, packets: 31000, flows: 820 },
  { transport: 'TCP', port: 110, portSide: 'dst', percent: 1.2, avgGbps: 0.08, trafficGb: 0.29, packets: 25000, flows: 640 },
  { transport: 'UDP', port: 514, portSide: 'src', percent: 0.9, avgGbps: 0.06, trafficGb: 0.22, packets: 19000, flows: 510 },
];

const SERVICES = [
  { label: 'HTTPS', value: 42.10, color: PROTOCOL_CHART_COLORS[5], trafficGb: 298.1, serviceCode: 'https' },
  { label: 'HTTP',  value: 12.40, color: PROTOCOL_CHART_COLORS[6], trafficGb: 87.8, serviceCode: 'http' },
  { label: 'DNS',   value: 8.20,  color: PROTOCOL_CHART_COLORS[7], trafficGb: 58.1, serviceCode: 'dns' },
  { label: 'SSH',   value: 4.50,  color: PROTOCOL_CHART_COLORS[8], trafficGb: 31.9, serviceCode: 'ssh' },
  { label: 'SMTP',  value: 2.10,  color: PROTOCOL_CHART_COLORS[10], trafficGb: 14.8, serviceCode: 'smtp' },
  { label: 'NTP',   value: 0.03,  color: PROTOCOL_CHART_COLORS[9], trafficGb: 0.21, serviceCode: 'ntp' },
  { label: 'Redis', value: 0.004, color: PROTOCOL_CHART_COLORS[11], trafficGb: 0.03, serviceCode: 'redis' },
  { label: 'LDAP',  value: 0,     color: PROTOCOL_CHART_COLORS[12], trafficGb: 0, serviceCode: 'ldap' },
  { label: 'Other', value: 31.15, color: PROTOCOL_CHART_COLORS[19], trafficGb: 220.4, serviceCode: 'other' },
];

const COUNTRIES_TOP = [
  { label: 'Россия',          flag: '🇷🇺', value: 12.3e9, lat: 60, lon: 90, code: 'RU' },
  { label: 'Германия',        flag: '🇩🇪', value: 3.1e9,  lat: 51, lon: 10, code: 'DE' },
  { label: 'США',             flag: '🇺🇸', value: 2.8e9,  lat: 39, lon: -98, code: 'US' },
  { label: 'Нидерланды',      flag: '🇳🇱', value: 1.6e9,  lat: 52, lon: 5,  code: 'NL' },
  { label: 'Великобритания',  flag: '🇬🇧', value: 1.1e9,  lat: 54, lon: -2, code: 'GB' },
  { label: 'Казахстан',       flag: '🇰🇿', value: 0.74e9, lat: 48, lon: 67, code: 'KZ' },
  { label: 'Китай',           flag: '🇨🇳', value: 0.62e9, lat: 36, lon: 104,code: 'CN' },
];

const RECENT_FLOWS = [
  { ts: '14:38:22.451', src: '10.41.12.84:5432',   dst: '34.91.220.10:443', proto: 'TCP',  bytes: 2.4e6, pkts: 1820, dur: '00:00:42', asn: 'AS15169' },
  { ts: '14:38:22.418', src: '192.168.10.4:54231', dst: '52.84.150.39:443', proto: 'TCP',  bytes: 188e3, pkts: 312,  dur: '00:00:09', asn: 'AS16509' },
  { ts: '14:38:22.392', src: '10.0.5.21:443',      dst: '85.142.30.18:51221', proto: 'TCP', bytes: 41e3, pkts: 38, dur: '00:00:02', asn: 'AS8359' },
  { ts: '14:38:22.355', src: '10.0.5.21:7531',     dst: '8.8.8.8:53',       proto: 'UDP',  bytes: 412,   pkts: 4,    dur: '00:00:00', asn: 'AS15169' },
  { ts: '14:38:22.301', src: '172.16.4.10:443',    dst: '188.114.97.3:443', proto: 'QUIC', bytes: 6.1e6, pkts: 4220, dur: '00:01:14', asn: 'AS13335' },
  { ts: '14:38:22.288', src: '10.41.12.84:22',     dst: '203.0.113.55:51811',proto: 'TCP', bytes: 18e3,  pkts: 12,   dur: '00:00:01', asn: '—' },
];

const COLLECTORS = [
  { id: 'c1', name: 'msk-collector-01', ip: '10.0.10.11', port: 9995, proto: 'NetFlow v9', status: 'healthy', version: '2.14.3', ingest: 412300, cpu: 38, mem: 54, disk: 41, last: Date.now() - 4000, region: 'Москва' },
  { id: 'c2', name: 'msk-collector-02', ip: '10.0.10.12', port: 4739, proto: 'IPFIX',      status: 'healthy', version: '2.14.3', ingest: 380120, cpu: 44, mem: 61, disk: 38, last: Date.now() - 7000, region: 'Москва' },
  { id: 'c3', name: 'spb-collector-01', ip: '10.1.10.11', port: 6343, proto: 'sFlow v5',   status: 'warning', version: '2.13.7', ingest: 196880, cpu: 71, mem: 82, disk: 64, last: Date.now() - 26000, region: 'Санкт-Петербург' },
  { id: 'c4', name: 'spb-collector-02', ip: '10.1.10.12', port: 9995, proto: 'NetFlow v9', status: 'healthy', version: '2.14.2', ingest: 142005, cpu: 31, mem: 48, disk: 33, last: Date.now() - 5000, region: 'Санкт-Петербург' },
  { id: 'c5', name: 'nsk-collector-01', ip: '10.2.10.11', port: 4739, proto: 'IPFIX',      status: 'critical', version: '2.14.3', ingest: 0,      cpu: 0,  mem: 0,  disk: 88, last: Date.now() - 6 * 60 * 1000, region: 'Новосибирск' },
  { id: 'c6', name: 'ekt-collector-01', ip: '10.3.10.11', port: 9995, proto: 'NetFlow v9', status: 'healthy', version: '2.14.3', ingest: 88420,  cpu: 22, mem: 39, disk: 28, last: Date.now() - 3000, region: 'Екатеринбург' },
  { id: 'c7', name: 'kzn-collector-01', ip: '10.4.10.11', port: 6343, proto: 'sFlow v5',   status: 'healthy', version: '2.14.1', ingest: 64280,  cpu: 29, mem: 47, disk: 31, last: Date.now() - 8000, region: 'Казань' },
  { id: 'c8', name: 'ros-collector-01', ip: '10.5.10.11', port: 9995, proto: 'NetFlow v9', status: 'warning', version: '2.13.9', ingest: 38110,  cpu: 58, mem: 76, disk: 71, last: Date.now() - 18000, region: 'Ростов-на-Дону' },
];


const ROUTERS = [
  { id: 'r1', name: 'bb-msk-01',  ip: '10.0.0.1',  model: 'Juniper MX204',       snmp: 'healthy', flow: 'healthy', flows24: 412e6, ifaces: 24, last: Date.now() - 3000, location: 'Москва, M9' },
  { id: 'r2', name: 'bb-msk-02',  ip: '10.0.0.2',  model: 'Juniper MX204',       snmp: 'healthy', flow: 'healthy', flows24: 388e6, ifaces: 24, last: Date.now() - 4000, location: 'Москва, M9' },
  { id: 'r3', name: 'edge-msk-01',ip: '10.0.1.1',  model: 'Cisco ASR 9006',      snmp: 'healthy', flow: 'warning', flows24: 198e6, ifaces: 12, last: Date.now() - 14000, location: 'Москва, дц1' },
  { id: 'r4', name: 'edge-spb-01',ip: '10.1.1.1',  model: 'Cisco ASR 9006',      snmp: 'healthy', flow: 'healthy', flows24: 142e6, ifaces: 16, last: Date.now() - 5000, location: 'Санкт-Петербург' },
  { id: 'r5', name: 'edge-spb-02',ip: '10.1.1.2',  model: 'Huawei NE40E-X8A',    snmp: 'warning', flow: 'healthy', flows24: 132e6, ifaces: 16, last: Date.now() - 22000, location: 'Санкт-Петербург' },
  { id: 'r6', name: 'edge-nsk-01',ip: '10.2.1.1',  model: 'Juniper MX204',       snmp: 'critical', flow: 'critical', flows24: 0, ifaces: 12, last: Date.now() - 6 * 60 * 1000, location: 'Новосибирск' },
  { id: 'r7', name: 'edge-ekt-01',ip: '10.3.1.1',  model: 'Cisco NCS 5500',      snmp: 'healthy', flow: 'healthy', flows24: 88e6,  ifaces: 14, last: Date.now() - 3000, location: 'Екатеринбург' },
  { id: 'r8', name: 'edge-kzn-01',ip: '10.4.1.1',  model: 'Juniper ACX7100',     snmp: 'healthy', flow: 'healthy', flows24: 64e6,  ifaces: 10, last: Date.now() - 7000, location: 'Казань' },
  { id: 'r9', name: 'core-msk-01',ip: '10.0.2.1',  model: 'Arista 7280R3',       snmp: 'healthy', flow: 'healthy', flows24: 510e6, ifaces: 32, last: Date.now() - 2000, location: 'Москва, ядро' },
  { id: 'r10',name: 'core-msk-02',ip: '10.0.2.2',  model: 'Arista 7280R3',       snmp: 'healthy', flow: 'healthy', flows24: 498e6, ifaces: 32, last: Date.now() - 3000, location: 'Москва, ядро' },
];

const CIDR_TREE = [
  { id: 'n1', prefix: '10.0.0.0/8',     desc: 'Внутренняя сеть компании', tags: ['internal','corp'], owner: 'IT-инфраструктура', assigned: 'NOC', updated: '2026-04-18', depth: 0, children: ['n2','n3','n6'] },
  { id: 'n2', prefix: '10.0.0.0/16',    desc: 'Москва, дата-центр M9',     tags: ['msk','dc'],       owner: 'Сетевой отдел',     assigned: 'А. Соколов', updated: '2026-05-02', depth: 1, parent: 'n1', children: ['n4','n5'] },
  { id: 'n4', prefix: '10.0.10.0/24',   desc: 'Серверы коллекторов',       tags: ['collectors'],     owner: 'NOC',                assigned: 'А. Соколов', updated: '2026-05-10', depth: 2, parent: 'n2' },
  { id: 'n5', prefix: '10.0.12.0/24',   desc: 'Балансировщики L4',         tags: ['lb','prod'],      owner: 'Платформа',          assigned: 'М. Иванова', updated: '2026-04-29', depth: 2, parent: 'n2' },
  { id: 'n3', prefix: '10.1.0.0/16',    desc: 'Санкт-Петербург, ДЦ',       tags: ['spb','dc'],       owner: 'Сетевой отдел',     assigned: 'Д. Петров', updated: '2026-05-01', depth: 1, parent: 'n1' },
  { id: 'n6', prefix: '10.2.0.0/16',    desc: 'Новосибирск, ДЦ',           tags: ['nsk','dc'],       owner: 'Сетевой отдел',     assigned: 'Д. Петров', updated: '2026-04-21', depth: 1, parent: 'n1' },
  { id: 'n7', prefix: '172.16.0.0/12',  desc: 'VPN-туннели партнёров',      tags: ['vpn','partners'],owner: 'Безопасность',      assigned: 'К. Орлова', updated: '2026-03-30', depth: 0, children: ['n8'] },
  { id: 'n8', prefix: '172.16.4.0/22',  desc: 'Партнёр: NetEdge LLC',       tags: ['vpn','partner-netedge'], owner: 'Безопасность', assigned: 'К. Орлова', updated: '2026-04-12', depth: 1, parent: 'n7' },
  { id: 'n9', prefix: '192.168.0.0/16', desc: 'Тест-стенд и dev',           tags: ['dev','staging'], owner: 'R&D',               assigned: 'А. Никитин', updated: '2026-04-30', depth: 0 },
  { id: 'n10',prefix: '203.0.113.0/24', desc: 'Публичный pool — клиенты',   tags: ['public','customer'], owner: 'Биллинг',       assigned: 'Г. Воронин', updated: '2026-05-12', depth: 0 },
];

const USERS = [
  { id: 'u1', name: 'Александр Соколов', email: 'a.sokolov@grapes.net',     role: 'Администратор', dept: 'NOC',          last: '2 мин назад',  status: 'Active',  avatar: 'А' },
  { id: 'u2', name: 'Мария Иванова',     email: 'm.ivanova@grapes.net',     role: 'NOC-инженер',   dept: 'NOC',          last: '11 мин назад', status: 'Active',  avatar: 'М' },
  { id: 'u3', name: 'Дмитрий Петров',    email: 'd.petrov@grapes.net',      role: 'Аналитик',      dept: 'Безопасность', last: '34 мин назад', status: 'Active',  avatar: 'Д' },
  { id: 'u4', name: 'Ксения Орлова',     email: 'k.orlova@grapes.net',      role: 'NOC-инженер',   dept: 'NOC',          last: '1 ч назад',    status: 'Active',  avatar: 'К' },
  { id: 'u5', name: 'Глеб Воронин',      email: 'g.voronin@grapes.net',     role: 'Только чтение', dept: 'Биллинг',      last: '4 ч назад',    status: 'Active',  avatar: 'Г' },
  { id: 'u6', name: 'Артём Никитин',     email: 'a.nikitin@grapes.net',     role: 'Аналитик',      dept: 'R&D',          last: 'вчера',        status: 'Active',  avatar: 'А' },
  { id: 'u7', name: 'Юлия Серова',       email: 'y.serova@partner.io',      role: 'Только чтение', dept: 'Партнёр',      last: '—',            status: 'Invited', avatar: 'Ю' },
  { id: 'u8', name: 'Михаил Кравцов',    email: 'm.kravtsov@grapes.net',    role: 'NOC-инженер',   dept: 'NOC',          last: '17 дн назад',  status: 'Blocked', avatar: 'М' },
];

const PERMISSION_MATRIX = [
  { id: 'dashboard',  label: 'Обзор' },
  { id: 'explorer',   label: 'Explorer Flows' },
  { id: 'top',        label: 'Топ ASN' },
  { id: 'collectors', label: 'Коллекторы' },
  { id: 'snmp',       label: 'SNMP' },
  { id: 'routers',    label: 'Роутеры и экспортёры' },
  { id: 'cidr',       label: 'Собственные сети (CIDR)' },
  { id: 'flow-exclusions', label: 'Исключения из статистики' },
  { id: 'users',      label: 'Пользователи и права' },
];

const ROLE_DEFAULTS = {
  'Администратор':  () => 'admin',
  'NOC-инженер':    (m) => m.id === 'users' ? 'view' : 'write',
  'Аналитик':       (m) => ['dashboard','explorer','top','cidr'].includes(m.id) ? 'write' : ['routers','collectors'].includes(m.id) ? 'view' : 'none',
  'Только чтение':  (m) => m.id === 'users' ? 'none' : 'view',
};

Object.assign(window, {
  seriesTraffic, seriesTrafficForRange, TRAFFIC_DIRECTION_STATS, PROTOCOLS, SERVICES, OTHER_PORTS_TOP, COUNTRIES_TOP, RECENT_FLOWS,
  COLLECTORS, ROUTERS, CIDR_TREE, USERS, PERMISSION_MATRIX, ROLE_DEFAULTS,
});
