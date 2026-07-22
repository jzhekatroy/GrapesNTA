/* Placeholder page for not-yet-built modules (Explorer, Топ-говорящие). */

function PageComingSoon({ pageId, onNavigate }) {
  const map = {
    explorer: {
      title: 'Explorer Flows',
      desc: 'Визуальный конструктор запросов с drill-down, Sankey-диаграммами и графиками. Сейчас в разработке.',
      icon: 'explorer',
      preview: 'explorer',
    },
    top: {
      title: 'Топ-говорящие',
      desc: 'Расширенный анализ топ-N по любым измерениям с группировкой и сравнением периодов.',
      icon: 'top',
      preview: 'top',
    },
    other: {
      title: 'Другие справочники',
      desc: 'Приложения, репутационные списки, тенанты и ASN.',
      icon: 'refs',
      preview: 'refs',
    },
  };
  const m = map[pageId] || map.explorer;
  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{m.title}</h1>
          <p>{m.desc}</p>
        </div>
        <div className="row" style={{gap: 8}}>
          <Button kind="ghost" onClick={() => onNavigate('dashboard')}>К обзору</Button>
        </div>
      </div>

      <Card>
        <div style={{display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, padding: '48px 24px', textAlign: 'center'}}>
          <div style={{
            width: 88, height: 88,
            borderRadius: 22,
            background: 'linear-gradient(180deg, rgba(126,146,248,0.18), rgba(105,114,240,0.06))',
            border: '1px solid rgba(126,146,248,0.25)',
            display: 'grid', placeItems: 'center',
            color: '#A4ADFF',
          }}>
            <Icon name={m.icon} size={40} stroke={1.6} />
          </div>
          <div>
            <div style={{font: 'var(--pv-text-display-2)', letterSpacing: '-0.01em'}}>Скоро</div>
            <div style={{font: 'var(--pv-text-body-1)', color: 'var(--fg-secondary)', marginTop: 6, maxWidth: 520}}>
              Этот раздел будет следующим в порядке генерации. Каркас приложения, Обзор,
              инфраструктура и справочники уже готовы и связаны между собой.
            </div>
          </div>
          <div className="row" style={{gap: 8, marginTop: 8}}>
            <Button kind="primary" icon="dashboard" onClick={() => onNavigate('dashboard')}>Открыть Обзор</Button>
            <Button kind="ghost" icon="collectors" onClick={() => onNavigate('collectors')}>К коллекторам</Button>
          </div>
        </div>
      </Card>
    </div>
  );
}

Object.assign(window, { PageComingSoon });
