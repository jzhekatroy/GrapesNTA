/* Версии компонентов — Администрирование (право diagnostics). */

function versionsT(key, params) {
  return GrapesI18n.t(key, params);
}

function versionsComponentLabel(componentId, fallbackTitle) {
  const key = `versionsPage.component.${componentId}`;
  if (GrapesI18n.has(key)) return versionsT(key);
  return fallbackTitle || componentId;
}

function PageVersions({ displayTimezone }) {
  const [payload, setPayload] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await ApiClient.loadComponentVersions();
      setPayload(data);
    } catch (err) {
      setPayload(null);
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const components = payload?.components || [];
  const uiRow = components.find((c) => c.id === 'ui');

  const copySummary = async () => {
    const text = VersionsFormat.buildVersionsCopyLine(components, displayTimezone);
    if (!text) return;
    try {
      await copyTextToClipboard(text);
      pushToast?.({ kind: 'success', title: versionsT('versionsPage.toast.copied') });
    } catch (err) {
      pushToast?.({
        kind: 'error',
        title: versionsT('versionsPage.toast.copyFailed'),
        desc: err.message || '',
      });
    }
  };

  const cols = [
    {
      key: 'component',
      title: versionsT('versionsPage.col.component'),
      width: 220,
      sortable: false,
      render: (r) => (
        <div className="col" style={{ gap: 2 }}>
          <span style={{ font: 'var(--pv-text-body-3-bold)' }}>{versionsComponentLabel(r.id, r.title)}</span>
          <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>{r.id}</span>
        </div>
      ),
    },
    {
      key: 'version',
      title: versionsT('versionsPage.col.version'),
      width: 200,
      sortable: false,
      render: (r) => {
        const raw = r.version;
        if (raw == null || String(raw).trim() === '') {
          return (
            <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <span>—</span>
              <Badge tone="neutral">{versionsT('versionsPage.badge.noData')}</Badge>
            </div>
          );
        }
        const { display, dirty, commitHash } = VersionsFormat.parseComponentVersion(raw);
        return (
          <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="mono">{display || '—'}</span>
            {dirty && (
              <span title={versionsT('versionsPage.badge.notFromTagHint', { hash: commitHash })}>
                <Badge tone="warning">{versionsT('versionsPage.badge.notFromTag')}</Badge>
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'versionDate',
      title: versionsT('versionsPage.col.versionDate'),
      width: 180,
      sortable: false,
      render: (r) => (
        <span>{r.versionDate ? formatUserDateTime(r.versionDate, displayTimezone) : '—'}</span>
      ),
    },
    {
      key: 'deployedAt',
      title: versionsT('versionsPage.col.deployedAt'),
      width: 180,
      sortable: false,
      render: (r) => (
        <span>{r.deployedAt ? formatUserDateTime(r.deployedAt, displayTimezone) : '—'}</span>
      ),
    },
  ];

  const generatedSubtitle = payload?.generatedAt
    ? versionsT('versionsPage.generatedAt', {
      time: formatUserDateTime(payload.generatedAt, displayTimezone),
    })
    : '';

  const buildFooter = uiRow && (uiRow.buildDate || uiRow.commit) ? (
    <div
      style={{
        marginTop: 8,
        font: 'var(--pv-text-body-3)',
        color: 'var(--fg-muted)',
        textAlign: 'right',
      }}
    >
      {uiRow.buildDate && (
        <>
          {versionsT('versionsPage.buildFooter', {
            buildDate: formatUserDateTime(uiRow.buildDate, displayTimezone),
          })}
        </>
      )}
      {uiRow.buildDate && uiRow.commit && ' · '}
      {uiRow.commit && <span className="mono">{uiRow.commit}</span>}
    </div>
  ) : null;

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>{versionsT('versionsPage.title')}</h1>
          {generatedSubtitle && (
            <p style={{ color: 'var(--fg-muted)', margin: 0 }}>{generatedSubtitle}</p>
          )}
        </div>
        <div className="row page-head__actions" style={{ gap: 8 }}>
          <Button kind="ghost" icon="copy" onClick={copySummary} disabled={loading || !components.length}>
            {versionsT('versionsPage.copy')}
          </Button>
          <Button kind="ghost" icon="refresh" onClick={load} disabled={loading}>
            {versionsT('chrome.refresh')}
          </Button>
        </div>
      </div>

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>
            {versionsT('versionsPage.loading')}
          </div>
        </Card>
      ) : error ? (
        <Card pad="sm">
          <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{error}</div>
        </Card>
      ) : (
        <>
          <DataTable
            rows={components}
            columns={cols}
            rowKey="id"
            pageSize={Math.max(components.length, 1)}
          />
          {buildFooter}
        </>
      )}
    </div>
  );
}

Object.assign(window, { PageVersions });
