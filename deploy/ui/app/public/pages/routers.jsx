/* Роутеры и экспортёры */

function PageRouters() {
  const [rows] = useState(ROUTERS);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [editing, setEditing] = useState(null);

  const filtered = useMemo(() => rows.filter((r) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return r.name.toLowerCase().includes(s) || r.ip.includes(s) || r.model.toLowerCase().includes(s) || r.location.toLowerCase().includes(s);
  }), [rows, search]);

  const cols = [
    { key: 'name', title: 'Имя роутера', width: 180, render: (r) => (
      <div>
        <div style={{font: 'var(--pv-text-body-2-bold)'}}>{r.name}</div>
        <div className="row" style={{gap: 6, marginTop: 2}}>
          <span className="tag" style={{fontSize: 10}}>{r.location}</span>
        </div>
      </div>
    )},
    { key: 'ip', title: 'IP', width: 130, render: (r) => <span className="mono">{r.ip}</span> },
    { key: 'model', title: 'Модель', width: 200, render: (r) => (
      <div className="row" style={{gap: 8}}>
        <Icon name="router" size={14} style={{color: 'var(--fg-secondary)'}} />
        <span>{r.model}</span>
      </div>
    )},
    { key: 'snmp', title: 'SNMP', width: 130, render: (r) => <StatusIndicator status={r.snmp} label={r.snmp === 'healthy' ? 'Опрашивается' : r.snmp === 'warning' ? 'Задержки' : 'Нет ответа'} /> },
    { key: 'flow', title: 'Flow export', width: 140, render: (r) => <StatusIndicator status={r.flow} label={r.flow === 'healthy' ? 'Активен' : r.flow === 'warning' ? 'Нестабилен' : 'Не получаем'} /> },
    { key: 'flows24', title: 'Потоков / 24 ч', width: 150, num: true, align: 'right', sortAccessor: (r) => r.flows24, render: (r) => (
      <span className="mono" style={{font: 'var(--pv-text-body-2-bold)'}}>{fmtNum(r.flows24)}</span>
    )},
    { key: 'ifaces', title: 'Интерфейсы', width: 110, num: true, align: 'right', render: (r) => (
      <span className="mono">{r.ifaces}</span>
    )},
    { key: 'last', title: 'Последний раз', width: 140, sortAccessor: (r) => r.last, render: (r) => {
      const stale = Date.now() - r.last > 60 * 1000;
      return <span style={{font: 'var(--pv-text-body-3)', color: stale ? 'var(--st-warning)' : 'var(--fg-secondary)'}}>{fmtAgo(r.last)}</span>;
    }},
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Роутеры и экспортёры</h1>
          <p>Источники потоков NetFlow / sFlow / IPFIX. SNMP-опрос обновляет инвентарь каждые 5 минут.</p>
        </div>
        <div className="row" style={{gap: 8}}>
          <Button kind="ghost" icon="upload">Импорт</Button>
          <Button kind="ghost" icon="refresh">Опросить</Button>
          <Button kind="primary" icon="plus" onClick={() => setEditing({ isNew: true, name: '', ip: '', model: 'Juniper MX204', location: 'Москва' })}>Добавить роутер</Button>
        </div>
      </div>

      <div className="grid grid--4col grid--mb">
        <SumCard label="Всего роутеров" value={rows.length} icon="router" />
        <SumCard label="Экспортируют поток" value={rows.filter(r => r.flow === 'healthy').length} icon="check" tone="success" />
        <SumCard label="С предупреждениями" value={rows.filter(r => r.flow === 'warning' || r.snmp === 'warning').length} icon="alert" tone="warning" />
        <SumCard label="Не отвечают" value={rows.filter(r => r.flow === 'critical' || r.snmp === 'critical').length} icon="x" tone="critical" />
      </div>

      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        selectable
        selected={selected}
        onSelectChange={setSelected}
        pageSize={10}
        onRowClick={(r) => setEditing(r)}
        toolbar={{
          search,
          onSearch: setSearch,
          left: selected.size > 0 ? (
            <div className="row" style={{gap: 8}}>
              <span style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)'}}>Выбрано: <b style={{color: '#fff'}}>{selected.size}</b></span>
              <Button size="sm" kind="ghost" icon="refresh">Опросить</Button>
              <Button size="sm" kind="ghost" icon="export">Экспорт</Button>
              <Button size="sm" kind="danger" icon="trash">Удалить</Button>
            </div>
          ) : (
            <Button kind="ghost" size="sm" icon="filter">Фильтры</Button>
          ),
        }}
        rowActions={(r) => (
          <div className="row" style={{gap: 4, justifyContent: 'flex-end'}}>
            <button className="icon-btn tt" data-tt="Тест" onClick={(e) => { e.stopPropagation(); pushToast({ kind: r.snmp === 'critical' ? 'error' : 'success', title: `${r.name}: ${r.snmp === 'critical' ? 'нет ответа SNMP' : 'опрос успешен'}`, desc: r.snmp === 'critical' ? 'Проверьте community и доступность.' : `Получено ${r.ifaces} интерфейсов.` }); }}>
              <Icon name="play" size={14} />
            </button>
            <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setEditing(r); }}><Icon name="edit" size={15} /></button>
            <button className="icon-btn"><Icon name="more" size={16} /></button>
          </div>
        )}
      />

      <RouterEditModal router={editing} onClose={() => setEditing(null)} />
    </div>
  );
}

function RouterEditModal({ router, onClose }) {
  const [tab, setTab] = useState('general');
  if (!router) return null;
  const tabs = [
    { id: 'general',    label: 'Общие',         icon: 'info' },
    { id: 'snmp',       label: 'SNMP',          icon: 'network' },
    { id: 'flow',       label: 'Flow export',   icon: 'flow' },
    { id: 'interfaces', label: 'Интерфейсы',    icon: 'link' },
  ];
  return (
    <Modal
      open
      onClose={onClose}
      title={router.isNew ? 'Добавить роутер' : router.name}
      subtitle={router.isNew ? 'Новый источник потоков' : `${router.ip} · ${router.model}`}
      size="xl"
      footer={
        <>
          <Button kind="ghost" onClick={onClose}>Отмена</Button>
          {!router.isNew && <Button kind="ghost" icon="play">Тест SNMP</Button>}
          <Button kind="primary" icon="save" onClick={() => { pushToast({ kind: 'success', title: 'Сохранено', desc: `Настройки роутера ${router.name || 'нового источника'} применены.` }); onClose(); }}>Сохранить</Button>
        </>
      }
    >
      <div className="row" style={{gap: 4, borderBottom: '1px solid var(--bd-soft)', marginBottom: 4}}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              all: 'unset', cursor: 'pointer',
              padding: '12px 16px',
              font: 'var(--pv-text-body-2-bold)',
              color: tab === t.id ? '#fff' : 'var(--fg-secondary)',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1,
              display: 'inline-flex', alignItems: 'center', gap: 8,
            }}>
            <Icon name={t.icon} size={14} />
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'general' && (
        <div className="grid grid--2col">
          <div className="field"><label>Имя</label><input className="input" defaultValue={router.name} /></div>
          <div className="field"><label>Локация</label><input className="input" defaultValue={router.location} /></div>
          <div className="field"><label>IP-адрес</label><input className="input mono" defaultValue={router.ip} /></div>
          <div className="field"><label>Модель</label><input className="input" defaultValue={router.model} /></div>
          <div className="field" style={{gridColumn: '1 / -1'}}>
            <label>Теги</label>
            <div className="row" style={{flexWrap: 'wrap', gap: 6}}>
              <Tag>edge</Tag><Tag>prod</Tag><Tag>msk</Tag>
              <Button kind="ghost" size="xs" icon="plus">Добавить тег</Button>
            </div>
          </div>
          <div className="field" style={{gridColumn: '1 / -1'}}>
            <label>Описание</label>
            <textarea className="input" rows="3" style={{height: 'auto', paddingTop: 10}} defaultValue="Магистральный роутер ядра, обрабатывает 100G-аплинки." />
          </div>
        </div>
      )}

      {tab === 'snmp' && (
        <div className="grid grid--2col">
          <div className="field"><label>Версия</label>
            <div className="seg"><button>v1</button><button>v2c</button><button className="is-active">v3</button></div>
          </div>
          <div className="field"><label>Порт</label><input className="input mono" defaultValue={161} /></div>
          <div className="field"><label>Имя пользователя</label><input className="input mono" defaultValue="grapes_snmp_user" /></div>
          <div className="field"><label>Уровень безопасности</label>
            <select className="input"><option>authPriv</option><option>authNoPriv</option><option>noAuthNoPriv</option></select>
          </div>
          <div className="field"><label>Auth protocol</label><select className="input"><option>SHA-256</option><option>SHA-1</option><option>MD5</option></select></div>
          <div className="field"><label>Privacy protocol</label><select className="input"><option>AES-256</option><option>AES-128</option><option>DES</option></select></div>
          <div className="field" style={{gridColumn: '1 / -1'}}>
            <label>Период опроса</label>
            <div className="seg" style={{width: 'fit-content'}}>
              <button>1 мин</button><button className="is-active">5 мин</button><button>15 мин</button><button>1 ч</button>
            </div>
          </div>
        </div>
      )}

      {tab === 'flow' && (
        <div className="grid grid--2col">
          <div className="field"><label>Протокол</label>
            <div className="seg"><button className="is-active">NetFlow v9</button><button>IPFIX</button><button>sFlow v5</button></div>
          </div>
          <div className="field"><label>Sampling rate</label><input className="input mono" defaultValue="1:1000" /></div>
          <div className="field"><label>Целевой коллектор</label>
            <select className="input"><option>msk-collector-01 (10.0.10.11:9995)</option><option>msk-collector-02 (10.0.10.12:4739)</option></select>
          </div>
          <div className="field"><label>Активный таймаут</label><input className="input mono" defaultValue="60 c" /></div>
          <div className="field" style={{gridColumn: '1 / -1'}}>
            <label>Шаблоны</label>
            <div className="row" style={{flexWrap: 'wrap', gap: 6}}>
              {['IPv4 base','IPv6 base','MAC','MPLS labels','BGP-next-hop','TCP flags'].map(t => <Tag key={t}>{t}</Tag>)}
            </div>
          </div>
          <Card pad="sm" style={{gridColumn: '1 / -1', background: 'var(--st-info-bg)', borderColor: 'rgba(115,129,244,0.3)'}}>
            <div className="row" style={{gap: 10, alignItems: 'flex-start'}}>
              <Icon name="info" size={16} style={{color: '#A4ADFF', marginTop: 2}} />
              <div>
                <div style={{font: 'var(--pv-text-body-2-bold)', color: '#fff'}}>Подсказка</div>
                <div style={{font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginTop: 2}}>
                  Используйте sampling 1:1000 на интерфейсах ≥10G. Для аналитики DDoS снизьте до 1:100.
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {tab === 'interfaces' && (
        <div className="table-wrap" style={{margin: 0}}>
          <table className="table">
            <thead>
              <tr>
                <th style={{width: 24}}><Checkbox /></th>
                <th>Индекс</th><th>Имя</th><th>Описание</th><th>Скорость</th><th>Статус</th>
              </tr>
            </thead>
            <tbody>
              {[
                { i: 1, n: 'xe-0/0/0', d: 'Uplink Megafon', s: 10e9, st: 'healthy' },
                { i: 2, n: 'xe-0/0/1', d: 'Uplink Rostelecom', s: 10e9, st: 'healthy' },
                { i: 3, n: 'xe-0/0/2', d: 'IX peering', s: 10e9, st: 'warning' },
                { i: 4, n: 'et-0/0/4', d: 'Core link → core-msk-01', s: 100e9, st: 'healthy' },
                { i: 5, n: 'ge-1/0/0', d: 'Mgmt', s: 1e9, st: 'idle' },
              ].map((r) => (
                <tr key={r.i}>
                  <td><Checkbox defaultChecked={r.st === 'healthy'} /></td>
                  <td className="mono num">{r.i}</td>
                  <td className="mono">{r.n}</td>
                  <td>{r.d}</td>
                  <td className="num">{fmtBits(r.s)}</td>
                  <td><StatusIndicator status={r.st} label={r.st === 'healthy' ? 'UP' : r.st === 'warning' ? 'Flapping' : 'DOWN'} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}

Object.assign(window, { PageRouters });
