/* Другие справочники: Приложения, Репутационные списки, BGP-сообщества, Кастомные измерения */

const APPLICATIONS = [
  { id: 'a1', name: 'HTTPS / TLS', category: 'Web',         ports: '443, 8443', proto: 'TCP', method: 'Порт + DPI', flows24: 412e6, status: 'enabled', icon: 'key' },
  { id: 'a2', name: 'HTTP',        category: 'Web',         ports: '80, 8080',  proto: 'TCP', method: 'Порт + DPI', flows24: 88e6,  status: 'enabled', icon: 'globe' },
  { id: 'a3', name: 'QUIC / HTTP3',category: 'Web',         ports: '443',       proto: 'UDP', method: 'DPI',        flows24: 142e6, status: 'enabled', icon: 'flow' },
  { id: 'a4', name: 'DNS',         category: 'Инфраструктура',ports: '53',      proto: 'UDP/TCP', method: 'Порт',   flows24: 720e6, status: 'enabled', icon: 'network' },
  { id: 'a5', name: 'SSH',         category: 'Управление',  ports: '22',        proto: 'TCP', method: 'Порт',       flows24: 1.2e6, status: 'enabled', icon: 'shield' },
  { id: 'a6', name: 'BGP',         category: 'Маршрутизация',ports: '179',      proto: 'TCP', method: 'Порт',       flows24: 4.8e6, status: 'enabled', icon: 'router' },
  { id: 'a7', name: 'NTP',         category: 'Инфраструктура',ports: '123',     proto: 'UDP', method: 'Порт',       flows24: 6.4e6, status: 'enabled', icon: 'clock' },
  { id: 'a8', name: 'SMTP / SMTPS',category: 'Почта',       ports: '25, 587, 465',proto: 'TCP',method: 'Порт',      flows24: 880e3, status: 'enabled', icon: 'upload' },
  { id: 'a9', name: 'ClickHouse',  category: 'Базы данных', ports: '8123, 9000',proto: 'TCP', method: 'Порт',       flows24: 22e6,  status: 'enabled', icon: 'db' },
  { id: 'a10',name: 'Kafka',       category: 'Базы данных', ports: '9092',      proto: 'TCP', method: 'Порт + DPI', flows24: 14e6,  status: 'enabled', icon: 'flow' },
  { id: 'a11',name: 'WireGuard',   category: 'VPN',         ports: '51820',     proto: 'UDP', method: 'Порт + DPI', flows24: 3.6e6, status: 'enabled', icon: 'shield' },
  { id: 'a12',name: 'IPsec',       category: 'VPN',         ports: '500, 4500', proto: 'UDP', method: 'Протокол',   flows24: 1.8e6, status: 'enabled', icon: 'shield' },
  { id: 'a13',name: 'BitTorrent',  category: 'P2P',         ports: '6881-6889', proto: 'TCP/UDP', method: 'DPI',    flows24: 240e3, status: 'disabled',icon: 'download' },
  { id: 'a14',name: 'Steam / Valve',category: 'Игры',       ports: '27015-27050',proto: 'UDP', method: 'DPI',       flows24: 188e3, status: 'enabled', icon: 'play' },
  { id: 'a15',name: 'Microsoft Teams',category: 'Видео',    ports: '3478-3481', proto: 'UDP', method: 'DPI',        flows24: 412e3, status: 'enabled', icon: 'users' },
];

const REPUTATION_FEEDS = [
  { id: 'f1', name: 'Spamhaus DROP',         vendor: 'Spamhaus',  category: 'Спам / источники атак', entries: 1832,  format: 'CIDR',  schedule: 'Каждый час',   last: '12 мин назад', status: 'healthy', autoBlock: true,  matched24: 4280 },
  { id: 'f2', name: 'Spamhaus EDROP',        vendor: 'Spamhaus',  category: 'Спам / источники атак', entries: 412,   format: 'CIDR',  schedule: 'Каждый час',   last: '12 мин назад', status: 'healthy', autoBlock: true,  matched24: 188 },
  { id: 'f3', name: 'Emerging Threats',      vendor: 'Proofpoint',category: 'Вредоносное ПО',        entries: 28140, format: 'IP',    schedule: 'Каждые 6 ч',   last: '2 ч назад',   status: 'healthy', autoBlock: false, matched24: 920 },
  { id: 'f4', name: 'AbuseIPDB · 90+',       vendor: 'AbuseIPDB', category: 'Сканеры / brute-force', entries: 412800,format: 'IP',    schedule: 'Каждые 30 мин',last: '8 мин назад', status: 'healthy', autoBlock: false, matched24: 14200 },
  { id: 'f5', name: 'FireHOL Level 1',       vendor: 'FireHOL',   category: 'Bogons / Malware C2',   entries: 5840,  format: 'CIDR',  schedule: 'Каждый час',   last: '18 мин назад', status: 'healthy', autoBlock: true,  matched24: 740 },
  { id: 'f6', name: 'Tor exit nodes',        vendor: 'Tor Project',category: 'Анонимизация',         entries: 1980,  format: 'IP',    schedule: 'Каждые 15 мин',last: '4 мин назад', status: 'healthy', autoBlock: false, matched24: 312 },
  { id: 'f7', name: 'GeoIP-блок · санкции',  vendor: 'Internal',  category: 'Геополитика',           entries: 92,    format: 'ASN',   schedule: 'Каждый день',  last: '14 ч назад',  status: 'warning', autoBlock: false, matched24: 0 },
  { id: 'f8', name: 'Внутренний blacklist',  vendor: 'NOC',       category: 'Внутренние правила',    entries: 41,    format: 'IP/CIDR',schedule: 'Вручную',     last: '3 дн назад',  status: 'idle',    autoBlock: true,  matched24: 28 },
  { id: 'f9', name: 'Crowdstrike feeds',     vendor: 'CrowdStrike',category: 'APT / C2',             entries: 18420, format: 'IP',    schedule: 'Каждые 15 мин',last: '6 мин назад', status: 'critical',autoBlock: true,  matched24: 0 },
];

const BGP_COMMUNITIES = [
  { id: 'c1', value: '31133:100',  desc: 'MegaFon · prefer-customer',   action: 'PREFER',   source: 'AS31133 MegaFon',   matches24: 412e3 },
  { id: 'c2', value: '31133:200',  desc: 'MegaFon · do not advertise to peers', action: 'NO_EXPORT', source: 'AS31133 MegaFon', matches24: 18e3 },
  { id: 'c3', value: '8359:1',     desc: 'MTS · prepend ×1',             action: 'PREPEND',  source: 'AS8359 MTS',        matches24: 84e3 },
  { id: 'c4', value: '8359:3',     desc: 'MTS · prepend ×3',             action: 'PREPEND',  source: 'AS8359 MTS',        matches24: 12e3 },
  { id: 'c5', value: '12389:666',  desc: 'Rostelecom · blackhole',       action: 'BLACKHOLE', source: 'AS12389 Rostelecom', matches24: 412, severity: 'critical' },
  { id: 'c6', value: '13335:60',   desc: 'Cloudflare · scrubbed',         action: 'TAG',     source: 'AS13335 Cloudflare', matches24: 240e3 },
  { id: 'c7', value: 'large:65000:1:100', desc: 'Internal · gold tier',  action: 'PREFER',   source: 'Internal',          matches24: 188e3 },
  { id: 'c8', value: 'large:65000:1:200', desc: 'Internal · do not export', action: 'NO_EXPORT', source: 'Internal',     matches24: 22e3 },
  { id: 'c9', value: '65535:0',    desc: 'NO_EXPORT (стандарт)',          action: 'NO_EXPORT', source: 'RFC 1997',         matches24: 14e3 },
  { id: 'c10',value: '65535:666',  desc: 'BLACKHOLE (стандарт)',          action: 'BLACKHOLE', source: 'RFC 7999',         matches24: 0,    severity: 'critical' },
];

const CUSTOM_DIMS = [
  { id: 'd1', name: 'environment',   type: 'string', source: 'Тег CIDR',         examples: ['prod','staging','dev'], coverage: 86, status: 'active' },
  { id: 'd2', name: 'business_unit', type: 'string', source: 'CMDB API',          examples: ['platform','noc','billing'], coverage: 72, status: 'active' },
  { id: 'd3', name: 'is_internal',   type: 'boolean',source: 'CIDR-выражение',    examples: ['true','false'], coverage: 100, status: 'active' },
  { id: 'd4', name: 'tier',          type: 'string', source: 'Lookup по ASN',     examples: ['gold','silver','bronze'], coverage: 64, status: 'active' },
  { id: 'd5', name: 'app_owner',     type: 'string', source: 'Lookup по dst_port',examples: ['team-alpha','team-bravo'], coverage: 41, status: 'partial' },
  { id: 'd6', name: 'is_paid_peering',type: 'boolean',source: 'BGP-сообщество',   examples: ['true','false'], coverage: 28, status: 'partial' },
];

function PageOtherRefs({ onNavigate }) {
  const [tab, setTab] = useState('applications');

  const TABS = [
    { id: 'applications', label: 'Приложения',          icon: 'layers',  count: APPLICATIONS.length },
    { id: 'feeds',        label: 'Репутационные списки', icon: 'shield',  count: REPUTATION_FEEDS.length },
    { id: 'bgp',          label: 'BGP-сообщества',       icon: 'router',  count: BGP_COMMUNITIES.length },
    { id: 'custom',       label: 'Кастомные измерения',  icon: 'tag',     count: CUSTOM_DIMS.length },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Другие справочники</h1>
          <p>Сигнатуры приложений, репутационные списки, BGP-сообщества и пользовательские измерения для обогащения потоков.</p>
        </div>
        <div className="row" style={{gap: 8}}>
          <Button kind="ghost" icon="refresh">Синхронизировать всё</Button>
          <Button kind="primary" icon="plus">Добавить</Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="row" style={{gap: 4, borderBottom: '1px solid var(--bd-soft)', marginBottom: 20}}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              all: 'unset', cursor: 'pointer',
              padding: '12px 18px',
              font: 'var(--pv-text-body-2-bold)',
              color: tab === t.id ? 'var(--fg-primary)' : 'var(--fg-secondary)',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1,
              display: 'inline-flex', alignItems: 'center', gap: 8,
            }}
          >
            <Icon name={t.icon} size={14} />
            {t.label}
            <span className="badge badge--neutral" style={{padding: '0 6px'}}>{t.count}</span>
          </button>
        ))}
      </div>

      {tab === 'applications' && <AppTab onNavigate={onNavigate} />}
      {tab === 'feeds'        && <FeedsTab />}
      {tab === 'bgp'          && <BGPTab />}
      {tab === 'custom'       && <CustomDimsTab />}
    </div>
  );
}

/* ================ Приложения ================ */
function AppTab({ onNavigate }) {
  const [search, setSearch] = useState('');
  const [cat, setCat] = useState('all');

  const cats = useMemo(() => ['all', ...new Set(APPLICATIONS.map(a => a.category))], []);
  const filtered = useMemo(() => APPLICATIONS.filter(a => {
    if (cat !== 'all' && a.category !== cat) return false;
    if (search) { const s = search.toLowerCase(); return a.name.toLowerCase().includes(s) || a.ports.includes(s); }
    return true;
  }), [search, cat]);

  const cols = [
    { key: 'name', title: 'Приложение', width: 240, render: (a) => (
      <div className="row" style={{gap: 10}}>
        <div style={{width: 32, height: 32, borderRadius: 8, background: 'var(--surf-2)', color: 'var(--fg-secondary)', display: 'grid', placeItems: 'center'}}>
          <Icon name={a.icon} size={16} />
        </div>
        <div>
          <div style={{font: 'var(--pv-text-body-2-bold)', color: 'var(--fg-primary)'}}>{a.name}</div>
          <div className="row" style={{gap: 4, marginTop: 2}}><span className="tag">{a.category}</span></div>
        </div>
      </div>
    )},
    { key: 'ports', title: 'Порты', width: 160, render: (a) => <span className="mono">{a.ports}</span> },
    { key: 'proto', title: 'Протокол', width: 110, render: (a) => <Badge tone="neutral">{a.proto}</Badge> },
    { key: 'method',title: 'Метод детекции', width: 150 },
    { key: 'flows24', title: 'Потоков / 24 ч', width: 150, num: true, align: 'right', render: (a) => <span className="mono" style={{font: 'var(--pv-text-body-2-bold)'}}>{fmtNum(a.flows24)}</span> },
    { key: 'status', title: 'Статус', width: 110, render: (a) => <Badge tone={a.status === 'enabled' ? 'success' : 'neutral'} dot>{a.status === 'enabled' ? 'Включено' : 'Отключено'}</Badge> },
  ];

  return (
    <DataTable
      rows={filtered}
      columns={cols}
      rowKey="id"
      pageSize={12}
      onRowClick={() => onNavigate('explorer')}
      toolbar={{
        search,
        onSearch: setSearch,
        left: (
          <select className="input" style={{maxWidth: 220}} value={cat} onChange={(e) => setCat(e.target.value)}>
            {cats.map(c => <option key={c} value={c}>{c === 'all' ? 'Все категории' : c}</option>)}
          </select>
        ),
      }}
      rowActions={(a) => (
        <div className="row" style={{gap: 4, justifyContent: 'flex-end'}}>
          <button className="icon-btn tt" data-tt="Открыть в Explorer" onClick={(e) => { e.stopPropagation(); onNavigate('explorer'); }}><Icon name="explorer" size={14} /></button>
          <button className="icon-btn tt" data-tt="Редактировать"><Icon name="edit" size={14} /></button>
          <button className="icon-btn"><Icon name="more" size={16} /></button>
        </div>
      )}
    />
  );
}

/* ================ Репутационные списки ================ */
function FeedsTab() {
  const [search, setSearch] = useState('');
  const filtered = useMemo(() => REPUTATION_FEEDS.filter(f => !search || f.name.toLowerCase().includes(search.toLowerCase()) || f.vendor.toLowerCase().includes(search.toLowerCase())), [search]);

  const cols = [
    { key: 'name', title: 'Список', width: 260, render: (f) => (
      <div>
        <div style={{font: 'var(--pv-text-body-2-bold)', color: 'var(--fg-primary)'}}>{f.name}</div>
        <div className="row" style={{gap: 6, marginTop: 2}}>
          <span className="tag">{f.vendor}</span>
          <span className="tag">{f.category}</span>
        </div>
      </div>
    )},
    { key: 'entries', title: 'Записей', width: 110, num: true, align: 'right', render: (f) => <span className="mono" style={{font: 'var(--pv-text-body-2-bold)'}}>{fmtNum(f.entries)}</span> },
    { key: 'format', title: 'Формат', width: 100, render: (f) => <Badge tone="neutral">{f.format}</Badge> },
    { key: 'schedule', title: 'Расписание', width: 140 },
    { key: 'last', title: 'Последняя синхр.', width: 150, render: (f) => (
      <span style={{font: 'var(--pv-text-body-3)', color: f.status === 'critical' ? 'var(--st-critical)' : 'var(--fg-secondary)'}}>{f.last}</span>
    )},
    { key: 'matched24', title: 'Совпадений / 24 ч', width: 160, num: true, align: 'right', render: (f) => (
      f.matched24 > 0
        ? <span className="mono" style={{font: 'var(--pv-text-body-2-bold)', color: f.matched24 > 1000 ? 'var(--st-warning)' : 'var(--fg-primary)'}}>{fmtNum(f.matched24)}</span>
        : <span style={{color: 'var(--fg-muted)'}}>—</span>
    )},
    { key: 'autoBlock', title: 'Авто-блок', width: 110, sortable: false, render: (f) => (
      <Badge tone={f.autoBlock ? 'critical' : 'neutral'} dot>{f.autoBlock ? 'Да' : 'Нет'}</Badge>
    )},
    { key: 'status', title: 'Статус', width: 130, render: (f) => <StatusIndicator status={f.status} /> },
  ];

  return (
    <div>
      <div className="grid grid--4col grid--mb">
        <SumCard label="Активных списков" value={REPUTATION_FEEDS.filter(f => f.status === 'healthy').length} icon="shield" tone="success" />
        <SumCard label="Всего записей" value={fmtNum(REPUTATION_FEEDS.reduce((s, f) => s + f.entries, 0))} icon="layers" />
        <SumCard label="Совпадений / 24 ч" value={fmtNum(REPUTATION_FEEDS.reduce((s, f) => s + f.matched24, 0))} icon="alert" tone="warning" />
        <SumCard label="Проблемных" value={REPUTATION_FEEDS.filter(f => f.status === 'critical' || f.status === 'warning').length} icon="x" tone="critical" />
      </div>
      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        pageSize={12}
        toolbar={{
          search, onSearch: setSearch,
          left: <Button kind="ghost" size="sm" icon="filter">Фильтры</Button>,
        }}
        rowActions={(f) => (
          <div className="row" style={{gap: 4, justifyContent: 'flex-end'}}>
            <button className="icon-btn tt" data-tt="Синхронизировать" onClick={() => pushToast({ kind: 'success', title: `${f.name}: синхронизация запущена` })}>
              <Icon name="refresh" size={14} />
            </button>
            <button className="icon-btn tt" data-tt="Редактировать"><Icon name="edit" size={14} /></button>
            <button className="icon-btn"><Icon name="more" size={16} /></button>
          </div>
        )}
      />
    </div>
  );
}

/* ================ BGP-сообщества ================ */
function BGPTab() {
  const [search, setSearch] = useState('');
  const filtered = useMemo(() => BGP_COMMUNITIES.filter(c => !search || c.value.includes(search) || c.desc.toLowerCase().includes(search.toLowerCase())), [search]);

  const actionTone = (a) => ({
    PREFER:    'success',
    PREPEND:   'info',
    NO_EXPORT: 'warning',
    BLACKHOLE: 'critical',
    TAG:       'neutral',
  }[a] || 'neutral');

  const cols = [
    { key: 'value', title: 'Значение', width: 180, render: (c) => (
      <span className="mono" style={{font: 'var(--pv-text-body-2-bold)', color: c.severity === 'critical' ? 'var(--st-critical)' : 'var(--fg-primary)'}}>
        {c.value}
      </span>
    )},
    { key: 'desc', title: 'Описание', render: (c) => c.desc },
    { key: 'action', title: 'Действие', width: 140, render: (c) => <Badge tone={actionTone(c.action)} dot>{c.action}</Badge> },
    { key: 'source', title: 'Источник', width: 200 },
    { key: 'matches24', title: 'Совпадений / 24 ч', width: 160, num: true, align: 'right', render: (c) => (
      c.matches24 > 0 ? <span className="mono">{fmtNum(c.matches24)}</span> : <span style={{color: 'var(--fg-muted)'}}>—</span>
    )},
  ];

  return (
    <DataTable
      rows={filtered}
      columns={cols}
      rowKey="id"
      pageSize={12}
      toolbar={{
        search, onSearch: setSearch,
        left: (
          <div className="seg">
            <button className="is-active">Все действия</button>
            <button>PREFER</button>
            <button>PREPEND</button>
            <button>NO_EXPORT</button>
            <button>BLACKHOLE</button>
          </div>
        ),
      }}
      rowActions={(c) => (
        <div className="row" style={{gap: 4, justifyContent: 'flex-end'}}>
          <button className="icon-btn tt" data-tt="Открыть в Explorer"><Icon name="explorer" size={14} /></button>
          <button className="icon-btn"><Icon name="more" size={16} /></button>
        </div>
      )}
    />
  );
}

/* ================ Кастомные измерения ================ */
function CustomDimsTab() {
  return (
    <div className="grid grid--auto-fill">
      {CUSTOM_DIMS.map(d => (
        <Card key={d.id}>
          <div className="row" style={{justifyContent: 'space-between', marginBottom: 10}}>
            <div className="row" style={{gap: 8}}>
              <div style={{width: 32, height: 32, borderRadius: 8, background: 'rgba(115,129,244,0.12)', color: '#A4ADFF', display: 'grid', placeItems: 'center'}}>
                <Icon name={d.type === 'boolean' ? 'check' : 'tag'} size={16} />
              </div>
              <div>
                <div className="mono" style={{font: 'var(--pv-text-h4)'}}>{d.name}</div>
                <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 2}}>{d.type}</div>
              </div>
            </div>
            <Badge tone={d.status === 'active' ? 'success' : 'warning'} dot>
              {d.status === 'active' ? 'Активно' : 'Частично'}
            </Badge>
          </div>
          <div style={{font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6}}>Источник</div>
          <div style={{font: 'var(--pv-text-body-2)', marginBottom: 12}}>{d.source}</div>
          <div style={{font: 'var(--pv-text-body-3-bold)', color: 'var(--fg-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6}}>Примеры значений</div>
          <div className="row" style={{gap: 4, flexWrap: 'wrap', marginBottom: 14}}>
            {d.examples.map(v => <Tag key={v}>{v}</Tag>)}
          </div>
          <div>
            <div className="row" style={{justifyContent: 'space-between', marginBottom: 4}}>
              <span style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>Покрытие потоков</span>
              <span className="mono" style={{font: 'var(--pv-text-body-3-bold)'}}>{d.coverage}%</span>
            </div>
            <MiniBar value={d.coverage} warn={50} crit={20} label=" " />
          </div>
          <div className="divider" style={{margin: '14px 0 12px'}} />
          <div className="row" style={{justifyContent: 'flex-end', gap: 4}}>
            <Button size="sm" kind="ghost" icon="play">Тест</Button>
            <Button size="sm" kind="ghost" icon="edit">Изменить</Button>
          </div>
        </Card>
      ))}

      {/* Add new */}
      <Card style={{
        border: '1.5px dashed var(--bd-default)',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        gap: 10, minHeight: 320, background: 'transparent',
        cursor: 'pointer',
      }}>
        <div style={{width: 48, height: 48, borderRadius: 14, background: 'rgba(115,129,244,0.12)', color: '#A4ADFF', display: 'grid', placeItems: 'center'}}>
          <Icon name="plus" size={24} />
        </div>
        <div style={{font: 'var(--pv-text-h4)'}}>Создать измерение</div>
        <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', textAlign: 'center', maxWidth: 280}}>
          Lookup по полю, BGP-сообществу или CIDR-тегу. Появится в Explorer как новая dimension.
        </div>
      </Card>
    </div>
  );
}

Object.assign(window, { PageOtherRefs });
