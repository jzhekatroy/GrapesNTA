/* Placeholder page for not-yet-built modules (Explorer, Топ-говорящие). */

function comingSoonT(key, params) {
  return GrapesI18n.t(key, params);
}

function PageComingSoon({ pageId, onNavigate }) {
  const map = {
    explorer: {
      titleKey: 'comingSoon.explorer.title',
      descKey: 'comingSoon.explorer.desc',
      icon: 'explorer',
      preview: 'explorer',
    },
    top: {
      titleKey: 'comingSoon.top.title',
      descKey: 'comingSoon.top.desc',
      icon: 'top',
      preview: 'top',
    },
  };
  const m = map[pageId] || map.explorer;
  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{comingSoonT(m.titleKey)}</h1>
          <p>{comingSoonT(m.descKey)}</p>
        </div>
        <div className="row" style={{gap: 8}}>
          <Button kind="ghost" onClick={() => onNavigate('dashboard')}>{comingSoonT('comingSoon.toOverview')}</Button>
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
            <div style={{font: 'var(--pv-text-display-2)', letterSpacing: '-0.01em'}}>{comingSoonT('comingSoon.headline')}</div>
            <div style={{font: 'var(--pv-text-body-1)', color: 'var(--fg-secondary)', marginTop: 6, maxWidth: 520}}>
              {comingSoonT('comingSoon.body')}
            </div>
          </div>
          <div className="row" style={{gap: 8, marginTop: 8}}>
            <Button kind="primary" icon="dashboard" onClick={() => onNavigate('dashboard')}>{comingSoonT('comingSoon.openDashboard')}</Button>
            <Button kind="ghost" icon="collectors" onClick={() => onNavigate('collectors')}>{comingSoonT('comingSoon.openCollectors')}</Button>
          </div>
        </div>
      </Card>
    </div>
  );
}

Object.assign(window, { PageComingSoon });
