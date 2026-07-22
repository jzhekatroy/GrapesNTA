/* Коллекторы — локации, коллекторы и привязка экспортёров потоков */

const SAVE_SUCCESS_TITLE = 'Настройки сохранены';
const SAVE_SUCCESS_DESC = 'Изменения будут автоматически применены в течение 60 секунд.';
const COLLECTORS_TAB_KEY = 'grapes-collectors-tab';

const SOURCE_STATE_LABELS = {
  assigned: 'Привязан',
  unassigned: 'Без коллектора',
  broken_collector_link: 'Коллектор не найден',
};

const SOURCE_STATE_TONE = {
  assigned: 'healthy',
  unassigned: 'warning',
  broken_collector_link: 'critical',
};

const DISCOVERED_STATE_LABELS = {
  unknown_source: 'Новый экспортёр',
  broken_collector_link: 'Коллектор не найден',
  unassigned_online: 'Работает без коллектора',
};

const DISCOVERED_STATE_TONE = {
  unknown_source: 'warning',
  broken_collector_link: 'critical',
  unassigned_online: 'warning',
};

const CATALOG_COLLECTOR_STATE_LABELS = {
  online: 'Работает',
  offline: 'Нет данных',
  empty: 'Без экспортёров',
};

const CATALOG_COLLECTOR_STATE_TONE = {
  online: 'healthy',
  offline: 'critical',
  empty: 'idle',
};

function flowExporterHint() {
  return 'Экспортёр потоков — source_id / observation domain, откуда приходят NetFlow, sFlow или DNS-записи.';
}

function collectorStatusHint(row) {
  if (row.state === 'online') {
    return `${row.liveSourceCount || 0}/${row.sourceCount || 0} активных за последние 5 минут`;
  }
  if (row.state === 'offline') {
    return 'Экспортёры привязаны, но live-данных за 5 минут нет';
  }
  return 'Привяжите хотя бы один экспортёр потоков';
}

function CollectorCatalogStateBadge({ state }) {
  return (
    <StatusIndicator
      status={CATALOG_COLLECTOR_STATE_TONE[state] || 'idle'}
      label={CATALOG_COLLECTOR_STATE_LABELS[state] || 'Неизвестно'}
    />
  );
}

function buildLiveSourceMap(overview, discoveredRows = []) {
  const live = new Map();
  for (const collector of overview?.collectors || []) {
    for (const src of collector.sources || []) {
      live.set(src.sourceId, {
        isLive: Boolean(src.isLive),
        flowsPerMin: Number(src.flowsPerMin) || 0,
        bytesPerSec: Number(src.bytesPerSec) || 0,
        ageSec: src.ageSec,
      });
    }
  }
  for (const row of discoveredRows || []) {
    if (row.ageSec != null || Number(row.flowsPerMin) > 0) {
      live.set(row.sourceId, {
        isLive: true,
        flowsPerMin: Number(row.flowsPerMin) || 0,
        bytesPerSec: Number(row.bytesPerSec) || 0,
        ageSec: row.ageSec,
      });
    }
  }
  return live;
}

function SourceLiveBadge({ isLive }) {
  return (
    <StatusIndicator
      status={isLive ? 'healthy' : 'idle'}
      label={isLive ? 'Работает' : 'Нет данных'}
    />
  );
}

const COMPLETENESS_LABELS = {
  ok: 'Учтено',
  warning: 'Есть риск',
  critical: 'Потери',
  unknown: 'Нет метрик',
};

const COMPLETENESS_TONES = {
  ok: 'healthy',
  warning: 'warning',
  critical: 'critical',
  unknown: 'idle',
};

const COMPLETENESS_REASON_LABELS = {
  insufficient_snapshots: 'Мало snapshots',
  xdp_map_full: 'XDP map_full',
  insert_errors: 'Ошибки INSERT',
  queue_drops: 'Сброс очереди CH',
  udp_drops: 'Сброс UDP',
  low_completeness: 'Низкая полнота',
};

function fmtPct(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return `${Number(value).toFixed(2)}%`;
}

function CompletenessBadge({ status }) {
  const id = status || 'unknown';
  return (
    <StatusIndicator
      status={COMPLETENESS_TONES[id] || 'idle'}
      label={COMPLETENESS_LABELS[id] || id}
    />
  );
}

function SourceBindingBadge({ state }) {
  if (state === 'assigned') return <StatusIndicator status="healthy" label="Привязан" />;
  if (state === 'broken_collector_link') return <StatusIndicator status="critical" label="Коллектор не найден" />;
  return <StatusIndicator status="warning" label="Не привязан" />;
}

function fmtCatalogUpdatedAt(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function PageCollectors() {
  const [tab, setTab] = useState(() => {
    const pending = sessionStorage.getItem(COLLECTORS_TAB_KEY);
    if (pending) {
      sessionStorage.removeItem(COLLECTORS_TAB_KEY);
      if (['locations', 'collectors', 'sources', 'unassigned'].includes(pending)) return pending;
    }
    return 'collectors';
  });
  const [refreshKey, setRefreshKey] = useState(0);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Коллекторы</h1>
          <p>Справочник локаций, коллекторов и экспортёров потоков.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload}>Обновить</Button>
        </div>
      </div>

      <div className="seg" style={{ width: 'fit-content', marginBottom: 16 }}>
        <button className={tab === 'locations' ? 'is-active' : ''} onClick={() => setTab('locations')}>Локации</button>
        <button className={tab === 'collectors' ? 'is-active' : ''} onClick={() => setTab('collectors')}>Коллекторы</button>
        <button className={tab === 'sources' ? 'is-active' : ''} onClick={() => setTab('sources')}>Экспортёры</button>
        <button className={tab === 'unassigned' ? 'is-active' : ''} onClick={() => setTab('unassigned')}>Непривязанные</button>
      </div>

      {tab === 'locations' && (
        <LocationsTab refreshKey={refreshKey} onReload={reload} />
      )}
      {tab === 'collectors' && (
        <CollectorsTab refreshKey={refreshKey} onReload={reload} />
      )}
      {tab === 'sources' && (
        <SourcesTab refreshKey={refreshKey} onReload={reload} />
      )}
      {tab === 'unassigned' && (
        <UnassignedTab refreshKey={refreshKey} onReload={reload} />
      )}
    </div>
  );
}

function LocationsTab({ refreshKey, onReload }) {
  const canWrite = AuthAccess.canWritePage('collectors');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const res = await ApiClient.loadLocations();
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
      } else {
        setRows((res.rows || []).map((r) => ({ ...r, id: r.locationId })));
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => (
      (r.displayName || '').toLowerCase().includes(s)
      || (r.locationId || '').toLowerCase().includes(s)
      || (r.city || '').toLowerCase().includes(s)
      || (r.country || '').toLowerCase().includes(s)
      || (r.comment || '').toLowerCase().includes(s)
    ));
  }, [rows, search]);

  const handleDisable = async (row) => {
    if (!window.confirm(`Отключить локацию «${row.displayName}»?`)) return;
    try {
      await ApiClient.saveLocation({
        locationId: row.locationId,
        displayName: row.displayName,
        city: row.city,
        country: row.country,
        comment: row.comment,
        enabled: 0,
      });
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось отключить', desc: err.message });
    }
  };

  const cols = [
    {
      key: 'displayName',
      title: 'Название',
      width: 220,
      sortAccessor: (r) => r.displayName,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName || '—'}</span>
      ),
    },
    {
      key: 'locationId',
      title: 'ID локации',
      width: 140,
      sortAccessor: (r) => r.locationId,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.locationId}</span>
      ),
    },
    {
      key: 'city',
      title: 'Город',
      width: 120,
      render: (r) => <span style={{ color: 'var(--fg-secondary)' }}>{r.city || '—'}</span>,
    },
    {
      key: 'country',
      title: 'Страна',
      width: 80,
      render: (r) => <span className="tag">{r.country || '—'}</span>,
    },
    {
      key: 'comment',
      title: 'Комментарий',
      width: 200,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.comment || '—'}
        </span>
      ),
    },
    {
      key: 'updatedAt',
      title: 'Изменено',
      width: 150,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {fmtCatalogUpdatedAt(r.updatedAt)}
        </span>
      ),
    },
  ];

  if (loading) {
    return (
      <Card pad="sm">
        <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
      </Card>
    );
  }

  if (loadError) {
    return (
      <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={onReload}>Повторить</Button>} />
    );
  }

  return (
    <>
      <div className="row" style={{ justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!canWrite}>Добавить локацию</Button>
      </div>
      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        selectable
        selected={selected}
        onSelectChange={setSelected}
        pageSize={15}
        onRowClick={canWrite ? (r) => setEditing({ ...r, isNew: false }) : undefined}
        emptyTitle="Нет активных локаций"
        emptyDesc="Добавьте локацию перед созданием коллекторов."
        toolbar={{ search, onSearch: setSearch }}
        rowActions={canWrite ? (r) => (
          <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
            <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: false }); }}>
              <Icon name="edit" size={15} />
            </button>
            <button className="icon-btn tt" data-tt="Отключить" onClick={(e) => { e.stopPropagation(); handleDisable(r); }}>
              <Icon name="trash" size={15} />
            </button>
          </div>
        ) : null}
      />
      <LocationFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd}
        onClose={() => { setShowAdd(false); setEditing(null); }}
        onSaved={() => {
          setShowAdd(false);
          setEditing(null);
          onReload();
          pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
        }}
      />
    </>
  );
}

function CollectorsTab({ refreshKey, onReload }) {
  const canWrite = AuthAccess.canWritePage('collectors');
  const [rows, setRows] = useState([]);
  const [locations, setLocations] = useState([]);
  const [flowSources, setFlowSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [deleting, setDeleting] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const [colRes, locRes, srcRes] = await Promise.all([
        ApiClient.loadCollectorsAdmin(),
        ApiClient.loadLocations(),
        ApiClient.loadFlowSources(),
      ]);
      if (cancelled) return;
      if (colRes.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
        setLocations([]);
        setFlowSources([]);
        setLoading(false);
        return;
      }

      const sourcesByCollector = new Map();
      (srcRes.rows || []).forEach((s) => {
        const cid = s.currentCollectorId || '';
        if (!sourcesByCollector.has(cid)) sourcesByCollector.set(cid, []);
        sourcesByCollector.get(cid).push(s);
      });
      setRows((colRes.rows || []).map((r) => ({
        ...r,
        state: 'empty',
        sourceCount: 0,
        liveSourceCount: 0,
        id: r.collectorId,
        boundSources: sourcesByCollector.get(r.collectorId) || [],
      })));
      setLocations(locRes.source === 'clickhouse' ? (locRes.rows || []) : []);
      setFlowSources(srcRes.source === 'clickhouse' ? (srcRes.rows || []) : []);
      setLoading(false);

      const overviewRes = await ApiClient.loadCollectorOverview();
      if (cancelled || overviewRes.source === 'error') return;
      const statusByCollector = new Map(
        ((overviewRes.data?.collectors) || []).map((c) => [c.collectorId, c]),
      );
      setRows((colRes.rows || []).map((r) => ({
        ...r,
        ...(statusByCollector.get(r.collectorId) || { state: 'empty', sourceCount: 0, liveSourceCount: 0 }),
        id: r.collectorId,
        boundSources: sourcesByCollector.get(r.collectorId) || [],
      })));
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => (
      (r.displayName || '').toLowerCase().includes(s)
      || (r.collectorId || '').toLowerCase().includes(s)
      || (r.locationName || '').toLowerCase().includes(s)
      || (r.locationId || '').toLowerCase().includes(s)
      || (r.hostname || '').toLowerCase().includes(s)
      || (r.comment || '').toLowerCase().includes(s)
      || (r.boundSources || []).some((src) => (src.sourceId || '').toLowerCase().includes(s))
    ));
  }, [rows, search]);

  const handleDisable = async (row) => {
    const bound = row.boundSources || [];
    if (bound.length > 0) {
      setDeleting(row);
      return;
    }
    if (!window.confirm(`Отключить коллектор «${row.displayName}»?`)) return;
    try {
      await ApiClient.saveCollector({
        collectorId: row.collectorId,
        locationId: row.locationId,
        displayName: row.displayName,
        hostname: row.hostname,
        comment: row.comment,
        enabled: 0,
      });
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось отключить', desc: err.message });
    }
  };

  const cols = useMemo(() => [
    {
      key: 'displayName',
      title: 'Название',
      width: 220,
      sortAccessor: (r) => r.displayName,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName || '—'}</span>
      ),
    },
    {
      key: 'collectorId',
      title: 'ID коллектора',
      width: 140,
      sortAccessor: (r) => r.collectorId,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.collectorId}</span>
      ),
    },
    {
      key: 'locationName',
      title: 'Локация',
      width: 200,
      sortAccessor: (r) => r.locationName,
      render: (r) => (
        <div>
          <div style={{ font: 'var(--pv-text-body-2)' }}>{r.locationName || '—'}</div>
          {r.locationId && <span className="tag" style={{ marginTop: 2 }}>{r.locationId}</span>}
        </div>
      ),
    },
    {
      key: 'hostname',
      title: 'Имя хоста',
      width: 160,
      render: (r) => (
        <span className="mono" style={{ color: 'var(--fg-secondary)' }}>{r.hostname || '—'}</span>
      ),
    },
    {
      key: 'state',
      title: 'Состояние',
      width: 170,
      render: (r) => (
        <div>
          <CollectorCatalogStateBadge state={r.state} />
          <div style={{ marginTop: 3, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {collectorStatusHint(r)}
          </div>
        </div>
      ),
    },
    {
      key: 'boundSources',
      title: 'Экспортёры потоков',
      width: 220,
      render: (r) => {
        const list = r.boundSources || [];
        if (!list.length) return <span style={{ color: 'var(--fg-secondary)' }}>Не привязаны</span>;
        return (
          <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
            {list.slice(0, 4).map((s) => (
              <span key={s.sourceId} className="tag mono">{s.sourceId}</span>
            ))}
            {list.length > 4 && <span className="tag">+{list.length - 4}</span>}
          </div>
        );
      },
    },
    {
      key: 'comment',
      title: 'Комментарий',
      width: 200,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.comment || '—'}
        </span>
      ),
    },
    {
      key: 'updatedAt',
      title: 'Изменено',
      width: 150,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {fmtCatalogUpdatedAt(r.updatedAt)}
        </span>
      ),
    },
  ], []);

  if (loading) {
    return (
      <Card pad="sm">
        <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
      </Card>
    );
  }

  if (loadError) {
    return (
      <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={onReload}>Повторить</Button>} />
    );
  }

  return (
    <>
      <div className="row" style={{ justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={locations.length === 0 || !canWrite}>
          Добавить коллектор
        </Button>
      </div>
      {locations.length === 0 && (
        <Card pad="sm" style={{ marginBottom: 12 }}>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            Сначала добавьте хотя бы одну локацию на вкладке «Локации».
          </div>
        </Card>
      )}
      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        selectable
        selected={selected}
        onSelectChange={setSelected}
        pageSize={15}
        onRowClick={canWrite ? (r) => setEditing({ ...r, isNew: false }) : undefined}
        emptyTitle="Нет активных коллекторов"
        emptyDesc="Добавьте коллектор и привяжите его к локации. Экспортёры можно привязать сразу в форме."
        toolbar={{ search, onSearch: setSearch }}
        rowActions={canWrite ? (r) => (
          <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
            <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: false }); }}>
              <Icon name="edit" size={15} />
            </button>
            <button
              className="icon-btn tt"
              data-tt={(r.boundSources || []).length ? 'Удалить (с отвязкой экспортёров)' : 'Отключить'}
              onClick={(e) => { e.stopPropagation(); handleDisable(r); }}
            >
              <Icon name="trash" size={15} />
            </button>
          </div>
        ) : null}
      />
      <CollectorFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd}
        locations={locations}
        flowSources={flowSources}
        onClose={() => { setShowAdd(false); setEditing(null); }}
        onSaved={() => {
          setShowAdd(false);
          setEditing(null);
          onReload();
          pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
        }}
      />
      <DeleteCollectorModal
        open={!!deleting}
        row={deleting}
        onClose={() => setDeleting(null)}
        onDeleted={() => {
          setDeleting(null);
          onReload();
          pushToast({ kind: 'success', title: 'Коллектор удалён', desc: SAVE_SUCCESS_DESC });
        }}
      />
    </>
  );
}

function LocationFormModal({ open, row, isNew, onClose, onSaved }) {
  const [locationId, setLocationId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [city, setCity] = useState('');
  const [country, setCountry] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    setFormError('');
    if (isNew) {
      setLocationId('');
      setDisplayName('');
      setCity('');
      setCountry('');
      setComment('');
    } else {
      setLocationId(row?.locationId || '');
      setDisplayName(row?.displayName || '');
      setCity(row?.city || '');
      setCountry(row?.country || '');
      setComment(row?.comment || '');
    }
  }, [open, isNew, row]);

  const handleSave = async () => {
    const name = displayName.trim();
    const id = locationId.trim().toLowerCase();
    if (isNew && !id) {
      setFormError('Укажите location_id');
      return;
    }
    if (!name) {
      setFormError('Укажите название локации');
      return;
    }

    setSaving(true);
    setFormError('');
    try {
      await ApiClient.saveLocation({
        locationId: isNew ? id : row.locationId,
        displayName: name,
        city: city.trim(),
        country: country.trim(),
        comment: comment.trim(),
        enabled: 1,
      });
      onSaved();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? 'Добавить локацию' : 'Редактировать локацию'}
      subtitle={isNew ? 'Новая запись каталога' : row?.locationId}
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
          <Button kind="primary" icon="save" onClick={handleSave} disabled={saving}>
            {saving ? 'Сохранение…' : 'Сохранить'}
          </Button>
        </>
      }
    >
      {formError && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
          {formError}
        </div>
      )}
      <div className="grid grid--2col">
        {isNew ? (
          <div className="field">
            <label>ID локации</label>
            <input
              className="input mono"
              placeholder="msk-m9"
              value={locationId}
              onChange={(e) => setLocationId(e.target.value)}
            />
            <div className="hint">Строчные латинские буквы, цифры и дефис. Не изменяется после создания.</div>
          </div>
        ) : (
          <div className="field">
            <label>ID локации</label>
            <input className="input mono" value={row?.locationId || ''} readOnly disabled />
          </div>
        )}
        <div className="field">
          <label>Название</label>
          <input
            className="input"
            placeholder="Москва, ММТС-9"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </div>
        <div className="field">
          <label>Город</label>
          <input className="input" placeholder="Москва" value={city} onChange={(e) => setCity(e.target.value)} />
        </div>
        <div className="field">
          <label>Страна</label>
          <input className="input mono" placeholder="RU" value={country} onChange={(e) => setCountry(e.target.value)} />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Комментарий</label>
          <textarea
            className="input"
            rows={3}
            placeholder="Необязательно"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </div>
      </div>
    </Modal>
  );
}

function DeleteCollectorModal({ open, row, onClose, onDeleted }) {
  const [confirmName, setConfirmName] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const boundSources = row?.boundSources || [];
  const expectedName = row?.displayName || '';
  const nameMatches = confirmName.trim() === expectedName.trim();

  useEffect(() => {
    if (!open) return;
    setConfirmName('');
    setFormError('');
  }, [open, row]);

  const handleDelete = async () => {
    if (!row?.collectorId || !nameMatches) return;
    setSaving(true);
    setFormError('');
    try {
      await ApiClient.deleteCollector({
        collectorId: row.collectorId,
        confirmName: confirmName.trim(),
      });
      onDeleted();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  if (!open || !row) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Удалить коллектор"
      subtitle={row.collectorId}
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
          <Button kind="primary" icon="trash" onClick={handleDelete} disabled={saving || !nameMatches}>
            {saving ? 'Удаление…' : 'Удалить коллектор'}
          </Button>
        </>
      }
    >
      {formError && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
          {formError}
        </div>
      )}
      <div style={{ marginBottom: 16, padding: '12px 14px', borderRadius: 8, background: 'var(--st-warning-bg)', color: 'var(--st-warning)', font: 'var(--pv-text-body-3)' }}>
        Коллектор будет отключён. Привязанные экспортёры ({boundSources.length}) станут без коллектора и потребуют новой привязки.
      </div>
      {boundSources.length > 0 && (
        <div className="row" style={{ gap: 4, flexWrap: 'wrap', marginBottom: 16 }}>
          {boundSources.map((s) => (
            <span key={s.sourceId} className="tag mono">{s.sourceId}</span>
          ))}
        </div>
      )}
      <div className="field">
        <label>
          Введите название коллектора для подтверждения:
          {' '}
          <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{expectedName}</span>
        </label>
        <input
          className="input"
          placeholder={expectedName}
          value={confirmName}
          onChange={(e) => setConfirmName(e.target.value)}
          autoComplete="off"
        />
        <div className="hint">Удаление возможно только при точном совпадении названия.</div>
      </div>
    </Modal>
  );
}

function CollectorSourceCheckbox({ sourceId, hint, checked, onToggle }) {
  return (
    <label className="row" style={{ gap: 8, padding: '4px 0', cursor: 'pointer' }}>
      <input type="checkbox" checked={checked} onChange={onToggle} />
      <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{sourceId}</span>
      <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>{hint}</span>
    </label>
  );
}

function CollectorFormModal({ open, row, isNew, locations, flowSources, onClose, onSaved, prefill }) {
  const [collectorId, setCollectorId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [locationId, setLocationId] = useState('');
  const [hostname, setHostname] = useState('');
  const [comment, setComment] = useState('');
  const [sourceIds, setSourceIds] = useState(() => new Set());
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    setFormError('');
    if (prefill) {
      setCollectorId(prefill.collectorId || '');
      setDisplayName(prefill.displayName || '');
      setLocationId(prefill.locationId || locations[0]?.locationId || '');
      setHostname(prefill.hostname || '');
      setComment(prefill.comment || '');
      setSourceIds(new Set(prefill.sourceIds || []));
    } else if (isNew) {
      setCollectorId('');
      setDisplayName('');
      setLocationId(locations[0]?.locationId || '');
      setHostname('');
      setComment('');
      setSourceIds(new Set());
    } else {
      setCollectorId(row?.collectorId || '');
      setDisplayName(row?.displayName || '');
      setLocationId(row?.locationId || '');
      setHostname(row?.hostname || '');
      setComment(row?.comment || '');
      const bound = (row?.boundSources || []).map((s) => s.sourceId);
      setSourceIds(new Set(bound));
    }
  }, [open, isNew, row, locations, prefill]);

  const toggleSource = useCallback((id) => {
    setSourceIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleSave = useCallback(async () => {
    const name = displayName.trim();
    const id = collectorId.trim().toLowerCase();
    if (isNew && !id) {
      setFormError('Укажите collector_id');
      return;
    }
    if (!name) {
      setFormError('Укажите название коллектора');
      return;
    }
    if (!locationId) {
      setFormError('Выберите локацию');
      return;
    }

    setSaving(true);
    setFormError('');
    try {
      const body = await ApiClient.saveCollector({
        collectorId: isNew ? id : row.collectorId,
        locationId,
        displayName: name,
        hostname: hostname.trim(),
        comment: comment.trim(),
        enabled: 1,
        sourceIds: [...sourceIds],
      });
      if (body.meta?.bindErrors?.length) {
        pushToast({
          kind: 'warning',
          title: 'Коллектор сохранён с предупреждениями',
          desc: body.meta.bindErrors.map((e) => `${e.sourceId}: ${e.error}`).join('; '),
        });
      }
      onSaved();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  }, [collectorId, comment, displayName, hostname, isNew, locationId, onSaved, row, sourceIds]);

  const selectableSources = useMemo(() => (
    (flowSources || []).slice().sort((a, b) => a.sourceId.localeCompare(b.sourceId))
  ), [flowSources]);

  const targetCollectorId = isNew ? collectorId : row?.collectorId;
  const sourceCheckboxRows = useMemo(() => selectableSources.map((src) => {
    let hint = SOURCE_STATE_LABELS[src.state] || src.state;
    if (src.currentCollectorId && src.currentCollectorId !== targetCollectorId) {
      hint = `→ ${src.currentCollectorName || src.currentCollectorId}`;
    }
    return { sourceId: src.sourceId, hint };
  }), [selectableSources, targetCollectorId]);

  const modalFooter = useMemo(() => (
    <>
      <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
      <Button kind="primary" icon="save" onClick={handleSave} disabled={saving}>
        {saving ? 'Сохранение…' : 'Сохранить'}
      </Button>
    </>
  ), [handleSave, onClose, saving]);

  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? 'Добавить коллектор' : 'Редактировать коллектор'}
      subtitle={isNew ? 'Новая запись каталога' : row?.collectorId}
      footer={modalFooter}
    >
      {formError && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
          {formError}
        </div>
      )}
      <div className="grid grid--2col">
        {isNew ? (
          <div className="field">
            <label>ID коллектора</label>
            <input
              className="input mono"
              placeholder="col-msk-1"
              value={collectorId}
              onChange={(e) => setCollectorId(e.target.value)}
              readOnly={Boolean(prefill?.collectorId)}
              disabled={Boolean(prefill?.collectorId)}
            />
            <div className="hint">Строчные латинские буквы, цифры и дефис. Не изменяется после создания.</div>
          </div>
        ) : (
          <div className="field">
            <label>ID коллектора</label>
            <input className="input mono" value={row?.collectorId || ''} readOnly disabled />
          </div>
        )}
        <div className="field">
          <label>Название</label>
          <input
            className="input"
            placeholder="XDP mirror M9 #1"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </div>
        <div className="field">
          <label>Локация</label>
          <select className="input" value={locationId} onChange={(e) => setLocationId(e.target.value)}>
            {locations.map((loc) => (
              <option key={loc.locationId} value={loc.locationId}>
                {loc.displayName} ({loc.locationId})
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Имя хоста</label>
          <input
            className="input mono"
            placeholder="col01.example"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
          />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Комментарий</label>
          <textarea
            className="input"
            rows={3}
            placeholder="Необязательно"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Экспортёры потоков</label>
          <div className="card" style={{ maxHeight: 180, overflow: 'auto', padding: 8 }}>
            {!selectableSources.length ? (
              <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>Нет экспортёров в каталоге</div>
            ) : sourceCheckboxRows.map((src) => (
              <CollectorSourceCheckbox
                key={src.sourceId}
                sourceId={src.sourceId}
                hint={src.hint}
                checked={sourceIds.has(src.sourceId)}
                onToggle={() => toggleSource(src.sourceId)}
              />
            ))}
          </div>
          <div className="hint">{flowExporterHint()} Выбранные экспортёры будут привязаны к этому коллектору автоматически.</div>
        </div>
      </div>
    </Modal>
  );
}

function SourceStateBadge({ state }) {
  return (
    <StatusIndicator
      status={SOURCE_STATE_TONE[state] || 'idle'}
      label={SOURCE_STATE_LABELS[state] || state}
    />
  );
}

function CompletenessKvItem({ label, value }) {
  return (
    <div className="talker-detail-item">
      <dt>{label}</dt>
      <dd>{value ?? '—'}</dd>
    </div>
  );
}

function CompletenessDetailsModal({ open, source, meta, onClose }) {
  if (!open || !source) return null;

  const c = source.completeness;
  const windowLabel = meta
    ? `${meta.windowMinutes || 5} мин, лаг ${meta.lagMinutes || 2} мин`
    : '5 мин, лаг 2 мин';
  const reasons = (c?.reasons || []).map((r) => COMPLETENESS_REASON_LABELS[r] || r);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Полнота учёта"
      subtitle={`${source.sourceId} · окно ${windowLabel}`}
      footer={<Button kind="ghost" onClick={onClose}>Закрыть</Button>}
    >
      {!c ? (
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          Нет health snapshots для этого экспортёра. Проверьте, что коллектор пишет в таблицу
          {' '}
          <span className="mono">collector_health_snapshots</span>
          {' '}
          и что
          {' '}
          <span className="mono">source_id</span>
          {' '}
          совпадает.
        </div>
      ) : (
        <dl className="talker-detail-grid">
          <CompletenessKvItem label="Статус" value={<CompletenessBadge status={c.status} />} />
          {reasons.length > 0 && (
            <CompletenessKvItem label="Причины" value={reasons.join(', ')} />
          )}
          <CompletenessKvItem label="Окно" value={`${fmtCatalogUpdatedAt(c.windowFrom)} — ${fmtCatalogUpdatedAt(c.windowTo)}`} />
          <CompletenessKvItem label="Snapshots" value={fmtNum(c.snapshotCount)} />
          <CompletenessKvItem label="XDP пакеты" value={fmtNum(c.xdpPackets)} />
          <CompletenessKvItem label="В CH пакеты" value={fmtNum(c.chPackets)} />
          <CompletenessKvItem label="Полнота пакетов" value={fmtPct(c.packetsPct)} />
          <CompletenessKvItem label="XDP байты" value={fmtBytes(c.xdpBytes)} />
          <CompletenessKvItem label="В CH байты" value={fmtBytes(c.chBytes)} />
          <CompletenessKvItem label="Полнота байт" value={fmtPct(c.bytesPct)} />
          <CompletenessKvItem label="map_full Δ" value={fmtNum(c.mapFullDelta)} />
          <CompletenessKvItem label="insert_errs Δ" value={fmtNum(c.insertErrsDelta)} />
          <CompletenessKvItem label="queue_drops Δ" value={fmtNum(c.queueDropsDelta)} />
          <CompletenessKvItem label="udp_drops Δ" value={fmtNum(c.udpDropsDelta)} />
          <CompletenessKvItem label="records_acked Δ" value={`${fmtNum(c.recordsAckedDelta)} (техн.)`} />
          <CompletenessKvItem label="Коллектор" value={c.collectorId || '—'} />
          <CompletenessKvItem label="Демон" value={c.daemon || '—'} />
          <CompletenessKvItem label="Последний snapshot" value={fmtCatalogUpdatedAt(c.lastSnapshotAt)} />
          <CompletenessKvItem label="Статус демона" value={c.lastDaemonStatus || '—'} />
        </dl>
      )}
    </Modal>
  );
}

function BindSourceModal({ open, source, collectorOptions, onClose, onSaved }) {
  const [collectorId, setCollectorId] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    setFormError('');
    setCollectorId(source?.currentCollectorId || collectorOptions[0]?.value || '');
  }, [open, source, collectorOptions]);

  const handleSave = async () => {
    if (!source?.sourceId) return;
    setSaving(true);
    setFormError('');
    try {
      await ApiClient.bindFlowSource({ sourceId: source.sourceId, collectorId });
      onSaved();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  if (!open || !source) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Привязать к коллектору"
      subtitle={source.sourceId}
      footer={
        <>
          <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
          <Button kind="primary" icon="link" onClick={handleSave} disabled={saving || !collectorId}>
            {saving ? 'Сохранение…' : 'Привязать'}
          </Button>
        </>
      }
    >
      {formError && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
          {formError}
        </div>
      )}
      <div className="field">
          <label>Коллектор</label>
        <select className="input" value={collectorId} onChange={(e) => setCollectorId(e.target.value)}>
          <option value="">— отвязать —</option>
          {collectorOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>
      <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
        Текущее состояние экспортёра: <SourceStateBadge state={source.state} />
        {source.currentCollectorName && (
          <span style={{ marginLeft: 8 }}>→ {source.currentCollectorName}</span>
        )}
      </div>
    </Modal>
  );
}

function SourcesTab({ refreshKey, onReload }) {
  return <FlowSourcesTab refreshKey={refreshKey} onReload={onReload} />;
}

function FlowSourcesTab({ refreshKey, onReload }) {
  const canWrite = AuthAccess.canWritePage('collectors');
  const [rows, setRows] = useState([]);
  const [collectorOptions, setCollectorOptions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [binding, setBinding] = useState(null);
  const [completenessBySource, setCompletenessBySource] = useState(new Map());
  const [completenessMeta, setCompletenessMeta] = useState(null);
  const [details, setDetails] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const [srcRes, optRes, overviewRes, discRes, completenessRes] = await Promise.all([
        ApiClient.loadFlowSources(),
        ApiClient.loadCollectorOptions(),
        ApiClient.loadCollectorOverview(),
        ApiClient.loadDiscoveredSources(),
        ApiClient.loadCollectorCompleteness(),
      ]);
      if (cancelled) return;
      if (srcRes.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
      } else {
        const liveBySource = buildLiveSourceMap(overviewRes.data, discRes.rows || []);
        const completenessMap = new Map(
          (completenessRes.rows || []).map((row) => [row.sourceId, row]),
        );
        setCompletenessBySource(completenessMap);
        setCompletenessMeta(completenessRes.meta || null);
        setRows((srcRes.rows || []).map((r) => {
          const live = liveBySource.get(r.sourceId);
          return {
            ...r,
            id: r.sourceId,
            isLive: Boolean(live?.isLive),
            flowsPerMin: live?.flowsPerMin ?? 0,
            bytesPerSec: live?.bytesPerSec ?? 0,
            ageSec: live?.ageSec ?? null,
            completeness: completenessMap.get(r.sourceId) || null,
          };
        }));
      }
      setCollectorOptions(optRes.source === 'clickhouse' ? (optRes.rows || []) : []);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const handleUnbind = async (row) => {
    if (!window.confirm(`Отвязать экспортёр «${row.sourceId}» от коллектора?`)) return;
    try {
      await ApiClient.bindFlowSource({ sourceId: row.sourceId, collectorId: '' });
      pushToast({ kind: 'success', title: 'Экспортёр отвязан', desc: SAVE_SUCCESS_DESC });
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось отвязать', desc: err.message });
    }
  };

  const handleDelete = async (row) => {
    if (!window.confirm(`Удалить экспортёр «${row.sourceId}» из каталога? Live-данные могут снова показать его как непривязанный.`)) return;
    try {
      await ApiClient.deleteFlowSource({ sourceId: row.sourceId });
      pushToast({ kind: 'success', title: 'Экспортёр удалён', desc: SAVE_SUCCESS_DESC });
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить', desc: err.message });
    }
  };

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => (
      (r.sourceId || '').toLowerCase().includes(s)
      || (r.sourceName || '').toLowerCase().includes(s)
      || (r.sourceType || '').toLowerCase().includes(s)
      || (r.currentCollectorName || '').toLowerCase().includes(s)
    ));
  }, [rows, search]);

  const cols = [
    {
      key: 'sourceId',
      title: 'ID экспортёра',
      width: 160,
      sortAccessor: (r) => r.sourceId,
      render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.sourceId}</span>,
    },
    {
      key: 'sourceName',
      title: 'Название',
      width: 180,
      render: (r) => r.sourceName || '—',
    },
    {
      key: 'sourceType',
      title: 'Тип',
      width: 100,
      render: (r) => <Badge tone="neutral">{r.sourceType || '—'}</Badge>,
    },
    {
      key: 'isLive',
      title: 'Работает',
      width: 140,
      render: (r) => (
        <div>
          <SourceLiveBadge isLive={r.isLive} />
          {r.isLive && (
            <div style={{ marginTop: 3, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
              {fmtNum(r.flowsPerMin)} потоков/мин
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'completeness',
      title: 'Полнота',
      width: 150,
      render: (r) => {
        const c = r.completeness || completenessBySource.get(r.sourceId);
        return (
          <button
            type="button"
            style={{ all: 'unset', textAlign: 'left', cursor: 'pointer' }}
            onClick={(e) => {
              e.stopPropagation();
              setDetails({ ...r, completeness: c || null });
            }}
            title="Показать детали полноты учёта"
          >
            <CompletenessBadge status={c?.status} />
            {c && c.status !== 'unknown' && (
              <div style={{ marginTop: 3, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
                {fmtPct(c.bytesPct)} байт
              </div>
            )}
          </button>
        );
      },
    },
    {
      key: 'state',
      title: 'Привязка',
      width: 160,
      render: (r) => <SourceBindingBadge state={r.state} />,
    },
    {
      key: 'currentCollectorName',
      title: 'Коллектор',
      width: 200,
      render: (r) => (
        <div>
          <div>{r.currentCollectorName || (r.currentCollectorId ? r.currentCollectorId : '—')}</div>
          {r.currentLocationName && (
            <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{r.currentLocationName}</span>
          )}
        </div>
      ),
    },
  ];

  if (loading) {
    return (
      <Card pad="sm">
        <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
      </Card>
    );
  }

  if (loadError) {
    return (
      <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={onReload}>Повторить</Button>} />
    );
  }

  return (
    <>
      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        pageSize={15}
        emptyTitle="Нет экспортёров потоков в каталоге"
        emptyDesc={`${flowExporterHint()} Новые экспортёры появятся на вкладке «Непривязанные», когда от них придут live-данные.`}
        toolbar={{ search, onSearch: setSearch }}
        rowActions={canWrite ? (r) => (
          <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
            <Button size="sm" kind="ghost" icon="link" onClick={(e) => { e.stopPropagation(); setBinding(r); }}>
              Привязать
            </Button>
            {r.currentCollectorId && (
              <Button size="sm" kind="ghost" onClick={(e) => { e.stopPropagation(); handleUnbind(r); }}>
                Отвязать
              </Button>
            )}
            <Button size="sm" kind="ghost" icon="trash" onClick={(e) => { e.stopPropagation(); handleDelete(r); }}>
              Удалить
            </Button>
          </div>
        ) : null}
      />
      <BindSourceModal
        open={!!binding}
        source={binding}
        collectorOptions={collectorOptions}
        onClose={() => setBinding(null)}
        onSaved={() => {
          setBinding(null);
          onReload();
          pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
        }}
      />
      <CompletenessDetailsModal
        open={!!details}
        source={details}
        meta={completenessMeta}
        onClose={() => setDetails(null)}
      />
    </>
  );
}

function UnassignedTab({ refreshKey, onReload }) {
  const canWrite = AuthAccess.canWritePage('collectors');
  const [rows, setRows] = useState([]);
  const [emptyCollectors, setEmptyCollectors] = useState([]);
  const [locations, setLocations] = useState([]);
  const [flowSources, setFlowSources] = useState([]);
  const [collectorOptions, setCollectorOptions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [binding, setBinding] = useState(null);
  const [createFrom, setCreateFrom] = useState(null);
  const [registering, setRegistering] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const [discRes, locRes, srcRes, optRes, overviewRes] = await Promise.all([
        ApiClient.loadDiscoveredSources(),
        ApiClient.loadLocations(),
        ApiClient.loadFlowSources(),
        ApiClient.loadCollectorOptions(),
        ApiClient.loadCollectorOverview(),
      ]);
      if (cancelled) return;
      if (discRes.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
        setEmptyCollectors([]);
      } else {
        setRows((discRes.rows || []).map((r) => ({ ...r, id: r.sourceId })));
        setEmptyCollectors(((overviewRes.data?.collectors) || [])
          .filter((c) => Number(c.sourceCount) === 0)
          .map((c) => ({ ...c, id: c.collectorId })));
      }
      setLocations(locRes.source === 'clickhouse' ? (locRes.rows || []) : []);
      setFlowSources(srcRes.source === 'clickhouse' ? (srcRes.rows || []) : []);
      setCollectorOptions(optRes.source === 'clickhouse' ? (optRes.rows || []) : []);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => (
      (r.sourceId || '').toLowerCase().includes(s)
      || (r.currentCollectorName || '').toLowerCase().includes(s)
    ));
  }, [rows, search]);

  const filteredEmptyCollectors = useMemo(() => {
    if (!search) return emptyCollectors;
    const s = search.toLowerCase();
    return emptyCollectors.filter((r) => (
      (r.collectorId || '').toLowerCase().includes(s)
      || (r.displayName || '').toLowerCase().includes(s)
      || (r.locationName || '').toLowerCase().includes(s)
    ));
  }, [emptyCollectors, search]);

  const handleRegister = async (row) => {
    setRegistering(row.sourceId);
    try {
      await ApiClient.registerFlowSource({
        sourceId: row.sourceId,
        sourceType: row.sourceType || 'manual',
        displayName: row.sourceId,
      });
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
      onReload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось зарегистрировать', desc: err.message });
    } finally {
      setRegistering(null);
    }
  };

  const collectorCols = [
    {
      key: 'displayName',
      title: 'Коллектор',
      width: 220,
      render: (r) => (
        <div>
          <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName || r.collectorId}</div>
          <div className="mono" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{r.collectorId}</div>
        </div>
      ),
    },
    {
      key: 'locationName',
      title: 'Локация',
      width: 180,
      render: (r) => r.locationName || '—',
    },
    {
      key: 'state',
      title: 'Состояние',
      width: 170,
      render: (r) => (
        <div>
          <CollectorCatalogStateBadge state={r.state} />
          <div style={{ marginTop: 3, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {collectorStatusHint(r)}
          </div>
        </div>
      ),
    },
  ];

  const cols = [
    {
      key: 'sourceId',
      title: 'ID экспортёра',
      width: 160,
      render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.sourceId}</span>,
    },
    {
      key: 'state',
      title: 'Причина',
      width: 180,
      render: (r) => (
        <StatusIndicator
          status={DISCOVERED_STATE_TONE[r.state] || 'idle'}
          label={DISCOVERED_STATE_LABELS[r.state] || r.state}
        />
      ),
    },
    {
      key: 'flowsPerMin',
      title: 'Потоков/мин',
      width: 100,
      render: (r) => <span className="mono num">{fmtNum(r.flowsPerMin)}</span>,
    },
    {
      key: 'ageSec',
      title: 'Давность',
      width: 100,
      render: (r) => (r.ageSec != null ? `${r.ageSec} с` : '—'),
    },
    {
      key: 'currentCollectorName',
      title: 'Коллектор',
      width: 180,
      render: (r) => r.currentCollectorName || r.currentCollectorId || '—',
    },
  ];

  if (loading) {
    return (
      <Card pad="sm">
        <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
      </Card>
    );
  }

  if (loadError) {
    return (
      <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={onReload}>Повторить</Button>} />
    );
  }

  return (
    <>
      <Card pad="sm" style={{ marginBottom: 12 }}>
        <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 4 }}>Что сюда попадает</div>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          Коллекторы без экспортёров и live-экспортёры, которые ещё не привязаны к рабочему коллектору.
        </div>
      </Card>
      <DataTable
        rows={filteredEmptyCollectors}
        columns={collectorCols}
        rowKey="id"
        pageSize={8}
        emptyTitle="Нет коллекторов без экспортёров"
        emptyDesc="У всех активных коллекторов есть привязанные экспортёры."
        toolbar={{ search, onSearch: setSearch }}
      />
      <div style={{ height: 16 }} />
      <DataTable
        rows={filtered}
        columns={cols}
        rowKey="id"
        pageSize={15}
        emptyTitle="Нет непривязанных экспортёров"
        emptyDesc="Все live-экспортёры есть в каталоге и привязаны к рабочим коллекторам."
        toolbar={{ search, onSearch: setSearch }}
        rowActions={canWrite ? (r) => (
          <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
            {r.state === 'unknown_source' && (
              <Button
                size="sm"
                kind="ghost"
                disabled={registering === r.sourceId}
                onClick={(e) => { e.stopPropagation(); handleRegister(r); }}
              >
                Зарегистрировать
              </Button>
            )}
            {(r.state === 'broken_collector_link' || r.state === 'unassigned_online') && (
              <>
                <Button size="sm" kind="ghost" icon="link" onClick={(e) => { e.stopPropagation(); setBinding(r); }}>
                  Привязать
                </Button>
                <Button size="sm" kind="ghost" icon="plus" onClick={(e) => { e.stopPropagation(); setCreateFrom(r); }}>
                  Создать коллектор
                </Button>
              </>
            )}
          </div>
        ) : null}
      />
      <BindSourceModal
        open={!!binding}
        source={binding ? {
          sourceId: binding.sourceId,
          state: binding.state === 'broken_collector_link' ? 'broken_collector_link' : 'unassigned',
          currentCollectorId: binding.currentCollectorId,
          currentCollectorName: binding.currentCollectorName,
        } : null}
        collectorOptions={collectorOptions}
        onClose={() => setBinding(null)}
        onSaved={() => {
          setBinding(null);
          onReload();
          pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
        }}
      />
      <CollectorFormModal
        open={!!createFrom}
        isNew
        row={null}
        locations={locations}
        flowSources={flowSources}
        prefill={createFrom ? {
          collectorId: `col-${createFrom.sourceId}`.slice(0, 64),
          displayName: createFrom.sourceId,
          sourceIds: [createFrom.sourceId],
        } : null}
        onClose={() => setCreateFrom(null)}
        onSaved={() => {
          setCreateFrom(null);
          onReload();
          pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
        }}
      />
    </>
  );
}

function SumCard({ label, value, icon, tone, hint }) {
  const bgTone = tone === 'success' ? 'var(--st-success-bg)' : tone === 'warning' ? 'var(--st-warning-bg)' : tone === 'critical' ? 'var(--st-critical-bg)' : 'var(--surf-2)';
  const fg = tone === 'success' ? 'var(--st-success)' : tone === 'warning' ? 'var(--st-warning)' : tone === 'critical' ? 'var(--st-critical)' : 'var(--fg-secondary)';
  return (
    <Card>
      <div className="row" style={{ alignItems: 'center', gap: 14 }}>
        <div style={{ width: 44, height: 44, borderRadius: 12, background: bgTone, color: fg, display: 'grid', placeItems: 'center' }}>
          <Icon name={icon} size={20} stroke={2.2} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="sum-card__label">{label}</div>
          <div className="sum-card__value">{value}</div>
          {hint && <div className="sum-card__hint">{hint}</div>}
        </div>
      </div>
    </Card>
  );
}

Object.assign(window, { PageCollectors, SumCard });
