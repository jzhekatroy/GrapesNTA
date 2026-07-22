/* Страница отказа в доступе */

function PageAccessDenied({ pageId, onNavigate }) {
  const title = PAGE_TITLES?.[pageId]?.title || pageId || 'страница';
  return (
    <div className="main__container">
      <Card pad="lg" style={{ maxWidth: 560, margin: '48px auto' }}>
        <Empty
          icon="key"
          title="Доступ запрещён"
          desc="У вас нет прав для доступа к данной странице."
          action={
            <Button kind="primary" onClick={() => onNavigate('dashboard')}>
              К обзору
            </Button>
          }
        />
        <div style={{ marginTop: 16, textAlign: 'center', color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          Запрошенный раздел: {title}
        </div>
      </Card>
    </div>
  );
}

Object.assign(window, { PageAccessDenied });
