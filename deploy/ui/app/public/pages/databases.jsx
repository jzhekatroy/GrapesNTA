/* Внешние базы данных */

function PageDatabases() {
  const [rows] = useState(DATABASES);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [showAdd, setShowAdd] = useState(false);

  const filtered = useMemo(() => rows.filter((r) => {
    if (typeFilter !== 'all' && r.type !== typeFilter) return false;
    if (search) {
      const s = search.toLowerCase();
      return r.name.toLowerCase().includes(s) || r.host.toLowerCase().includes(s);
    }
    return true;
  }), [rows, search, typeFilter]);

  const typeBg = (t) => ({
    ClickHouse: '#FECC1B',
    PostgreSQL: '#336791',
    Redis: '#DC382C',
    Kafka: '#231F20',
  }[t] || '#666');

  const cols = [
    { key: 'name', title: 'Подключение', width: 220, render: (r) => (
      <div className="row" style={{gap: 10}}>
        <div style={{width: 32, height: 32, borderRadius: 8, background: typeBg(r.type) + '20', color: typeBg(r.type), display: 'grid', placeItems: 'center', flexShrink: 0}}>
          <Icon name={r.type === 'Kafka' ? 'flow' : r.type === 'Redis' ? 'layers' : 'db'} size={16} />
        </div>
        <div>
          <div style={{font: 'var(--pv-text-body-2-bold)', color: '#fff'}}>{r.name}</div>
          <div className="row" style={{gap: 6, marginTop: 2}}>
            <span className="tag">{r.role}</span>
          </div>
        </div>
      </div>
    )},
    { key: 'type', title: 'Тип', width: 130, render: (r) => <Badge tone="neutral">{r.type}</Badge> },
    { key: 'host', title: 'Хост', width: 220, render: (r) => <span className="mono" style={{font: 'var(--pv-text-body-2)'}}>{r.host}</span> },
    { key: 'status', title: 'Состояние', width: 130, render: (r) => <StatusIndicator status={r.status} /> },
    { key: 'version', title: 'Версия', width: 100, render: (r) => <span className="mono" style={{color: 'var(--fg-secondary)'}}>{r.version}</span> },
    { key: 'retention', title: 'Хранение', width: 130 },
    { key: 'size', title: 'Объём', width: 130, num: true, align: 'right', sortAccessor: (r) => r.size, render: (r) => (
      <span className="mono" style={{font: 'var(--pv-text-body-2-bold)'}}>{fmtBytes(r.size)}</span>
    )},
    { key: 'sync', title: 'Последняя синхр.', width: 150, sortAccessor: (r) => r.sync, render: (r) => {
      const stale = Date.now() - r.sync > 60 * 1000;
      return <span style={{font: 'var(--pv-text-body-3)', color: stale ? 'var(--st-warning)' : 'var(--fg-secondary)'}}>{fmtAgo(r.sync)}</span>;
    }},
    { key: 'load', title: 'Нагрузка', width: 130, sortable: false, render: (r) => {
      const data = Array.from({length: 18}, (_, i) => 30 + Math.sin(i / 2 + r.id.charCodeAt(0)) * 20 + Math.random() * 10);
      return <Sparkline data={data} width={110} height={28} color="#A4ADFF" filled />;
    }},
  ];

  const types = ['all','ClickHouse','PostgreSQL','Redis','Kafka'];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Внешние базы данных</h1>
          <p>Хранилища потоков, метаданных и кэша. Подключения проверяются каждые 30 секунд.</p>
        </div>
        <div className="row" style={{gap: 8}}>
          <Button kind="ghost" icon="export">Экспорт</Button>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)}>Добавить подключение</Button>
        </div>
      </div>

      <div className="grid grid--4col grid--mb">
        <SumCard label="Всего подключений" value={rows.length} icon="db" />
        <SumCard label="Здоровых" value={rows.filter(r => r.status === 'healthy').length} icon="check" tone="success" />
        <SumCard label="Объём данных" value={fmtBytes(rows.reduce((s, r) => s + r.size, 0))} icon="hdd" />
        <SumCard label="С ошибками" value={rows.filter(r => r.status === 'critical').length} icon="alert" tone="critical" />
      </div>

      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        pageSize={10}
        toolbar={{
          search,
          onSearch: setSearch,
          left: (
            <div className="seg">
              {types.map((t) => (
                <button key={t} className={typeFilter === t ? 'is-active' : ''} onClick={() => setTypeFilter(t)}>
                  {t === 'all' ? 'Все типы' : t}
                </button>
              ))}
            </div>
          ),
        }}
        rowActions={(r) => (
          <div className="row" style={{gap: 4, justifyContent: 'flex-end'}}>
            <button className="icon-btn tt" data-tt="Тест соединения" onClick={() => pushToast({ kind: r.status === 'critical' ? 'error' : 'success', title: r.status === 'critical' ? `${r.name}: соединение не установлено` : `${r.name}: соединение успешно`, desc: r.status === 'critical' ? 'Проверьте хост и порт.' : 'Время отклика 23 мс.' })}>
              <Icon name="play" size={14} />
            </button>
            <button className="icon-btn tt" data-tt="Редактировать"><Icon name="edit" size={15} /></button>
            <button className="icon-btn"><Icon name="more" size={16} /></button>
          </div>
        )}
      />

      <Modal
        open={showAdd}
        onClose={() => setShowAdd(false)}
        title="Добавить подключение"
        subtitle="Подключите внешнее хранилище данных"
        size="lg"
        footer={
          <>
            <Button kind="ghost" onClick={() => setShowAdd(false)}>Отмена</Button>
            <Button kind="ghost" icon="play" onClick={() => pushToast({ kind: 'success', title: 'Соединение успешно', desc: 'Хост отвечает, версия 24.3.5' })}>Тест соединения</Button>
            <Button kind="primary" onClick={() => { setShowAdd(false); pushToast({ kind: 'success', title: 'Подключение добавлено', desc: 'Готово к работе.' }); }}>Добавить</Button>
          </>
        }
      >
        <div className="grid grid--2col">
          <div className="field" style={{gridColumn: '1 / -1'}}>
            <label>Тип хранилища</label>
            <div className="grid grid--4col grid--gap-xs">
              {['ClickHouse','PostgreSQL','Redis','Kafka'].map((t) => (
                <label key={t} style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
                  padding: 14, border: '1px solid var(--bd-default)', borderRadius: 10,
                  cursor: 'pointer', position: 'relative',
                }}>
                  <input type="radio" name="dbtype" defaultChecked={t === 'ClickHouse'} style={{position: 'absolute', top: 8, right: 8}} />
                  <div style={{width: 32, height: 32, borderRadius: 8, background: typeBg(t) + '25', color: typeBg(t), display: 'grid', placeItems: 'center'}}>
                    <Icon name={t === 'Kafka' ? 'flow' : t === 'Redis' ? 'layers' : 'db'} size={18} />
                  </div>
                  <span style={{font: 'var(--pv-text-body-2-bold)'}}>{t}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="field">
            <label>Имя подключения</label>
            <input className="input" placeholder="clickhouse-edge" />
          </div>
          <div className="field">
            <label>Роль</label>
            <select className="input" defaultValue="Основная">
              <option>Основная</option><option>Реплика</option><option>Архив</option><option>Кэш</option><option>Очередь</option>
            </select>
          </div>
          <div className="field" style={{gridColumn: '1 / span 2'}}>
            <label>Хост</label>
            <input className="input mono" placeholder="ch04.dc-msk1:9000" />
          </div>
          <div className="field">
            <label>Пользователь</label>
            <input className="input mono" placeholder="grapes_writer" />
          </div>
          <div className="field">
            <label>Пароль</label>
            <input className="input" type="password" placeholder="••••••••••" />
          </div>
          <div className="field" style={{gridColumn: '1 / -1'}}>
            <label>Политика хранения</label>
            <div className="seg" style={{width: 'fit-content'}}>
              {['7 дн','30 дн','90 дн','180 дн','365 дн','Бессрочно'].map(p => (
                <button key={p} className={p === '90 дн' ? 'is-active' : ''}>{p}</button>
              ))}
            </div>
          </div>
        </div>
      </Modal>
    </div>
  );
}

Object.assign(window, { PageDatabases });
