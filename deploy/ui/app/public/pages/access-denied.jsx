/* Страница отказа в доступе */

function t(key, params) {
  return GrapesI18n.t(key, params);
}

function accessDeniedPageTitle(pageId) {
  const navLabel = GrapesI18n.navItemLabel(pageId);
  if (navLabel) return navLabel;
  const registry = PAGE_TITLES?.[pageId];
  const meta = GrapesI18n.localizedPageMeta(pageId, registry);
  if (meta?.title) return meta.title;
  if (pageId) return pageId;
  return t('accessDenied.fallbackPage');
}

function PageAccessDenied({ pageId, onNavigate }) {
  const sectionTitle = accessDeniedPageTitle(pageId);
  return (
    <div className="main__container">
      <Card pad="lg" style={{ maxWidth: 560, margin: '48px auto' }}>
        <Empty
          icon="key"
          title={t('accessDenied.title')}
          desc={t('accessDenied.desc')}
          action={
            <Button kind="primary" onClick={() => onNavigate('dashboard')}>
              {t('accessDenied.toOverview')}
            </Button>
          }
        />
        <div style={{ marginTop: 16, textAlign: 'center', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {t('accessDenied.requestedSection', { title: sectionTitle })}
        </div>
      </Card>
    </div>
  );
}

Object.assign(window, { PageAccessDenied });
