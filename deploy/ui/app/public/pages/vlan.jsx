/* VLAN — анализ трафика по VLAN + справочник имён (net_l2_vlans) */

const VLAN_ATTACHMENT_TYPES = [
  { value: 'unknown', label: 'Не задано' },
  { value: 'customer', label: 'Клиент' },
  { value: 'uplink', label: 'Аплинк' },
  { value: 'core', label: 'Ядро' },
  { value: 'peering', label: 'Пиринг' },
  { value: 'ix', label: 'IX' },
  { value: 'internal', label: 'Внутренний' },
  { value: 'transit', label: 'Транзит' },
  { value: 'management', label: 'Управление' },
];
const VLAN_ATTACHMENT_LABELS = Object.fromEntries(VLAN_ATTACHMENT_TYPES.map((t) => [t.value, t.label]));

const VLAN_BOUNDARY_TYPES = [
  { value: 'unknown', label: 'Не задано' },
  { value: 'internal', label: 'Внутренний' },
  { value: 'external', label: 'Внешний' },
];
const VLAN_BOUNDARY_LABELS = Object.fromEntries(VLAN_BOUNDARY_TYPES.map((t) => [t.value, t.label]));

const VLAN_SAVE_TITLE = 'Сохранено';
const VLAN_SAVE_DESC = 'Изменения справочника применятся в течение 60 секунд.';

function PageVlan({ timeRange = '24h', customPeriod, directions, collectorFilter } = {}) {
  const canWrite = AuthAccess.canWritePage('vlan');
  const [tab, setTab] = useState('traffic');
  const [trafficRows, setTrafficRows] = useState([]);
  const [namedRows, setNamedRows] = useState([]);
  const [seenRows, setSeenRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [entities, setEntities] = useState([]);
  const [refreshKey, setRefreshKey] = useState(0);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);
  const directionsKey = JSON.stringify(directions || {});
  const collectorFilterKey = (collectorFilter || []).join('|');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const [topR, namedR, seenR] = await Promise.all([
        ApiClient.loadVlanTop({ timeRange, customPeriod, directions, collectorFilter, limit: 200 }),
        ApiClient.loadRefVlans(),
        ApiClient.loadRefVlansSeen({ hours: 24, limit: 200 }),
      ]);
      if (cancelled) return;
      if (!topR.ok && namedR.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setTrafficRows([]);
        setNamedRows([]);
      } else {
        setTrafficRows(Array.isArray(topR.data) ? topR.data : []);
        setNamedRows(namedR.source === 'error' ? [] : (namedR.rows || []));
      }
      setSeenRows(seenR.source === 'error' ? [] : (seenR.rows || []));
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [timeRange, customPeriod?.from, customPeriod?.to, directionsKey, collectorFilterKey, refreshKey]);

  useEffect(() => {
    let cancelled = false;
    ApiClient.loadNetEntities().then((res) => {
      if (cancelled) return;
      setEntities(res.source === 'error' ? [] : (res.rows || []));
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  // Merge traffic-based rows with named-only VLANs (named but no recent traffic).
  const merged = useMemo(() => {
    const byId = new Map();
    for (const r of trafficRows) {
      byId.set(r.vlanId, { ...r, named: false });
    }
    for (const n of namedRows) {
      const existing = byId.get(n.vlanId);
      if (existing) {
        byId.set(n.vlanId, {
          ...existing,
          named: true,
          displayName: n.displayName,
          attachmentType: n.attachmentType || existing.attachmentType,
          boundary: n.boundary || existing.boundary,
          entityId: n.entityId || existing.entityId,
          comment: n.comment,
        });
      } else {
        byId.set(n.vlanId, {
          vlanId: n.vlanId,
          displayName: n.displayName,
          attachmentType: n.attachmentType || 'unknown',
          boundary: n.boundary || 'unknown',
          entityId: n.entityId || '',
          comment: n.comment,
          bytes: 0, avgBps: 0, packets: 0, flows: 0, pct: 0,
          named: true,
        });
      }
    }
    return [...byId.values()].map((r) => ({ ...r, id: r.vlanId }));
  }, [trafficRows, namedRows]);

  const filtered = useMemo(() => {
    if (!search) return merged;
    const s = search.toLowerCase();
    return merged.filter((r) => (
      String(r.vlanId).includes(s)
      || (r.displayName || '').toLowerCase().includes(s)
      || (VLAN_ATTACHMENT_LABELS[r.attachmentType] || '').toLowerCase().includes(s)
    ));
  }, [merged, search]);

  const entityNameById = useMemo(() => {
    const m = {};
    for (const e of entities) m[e.entityId] = e.displayName;
    return m;
  }, [entities]);

  const handleDelete = async (row) => {
    if (!window.confirm(`Удалить имя VLAN ${row.vlanId}${row.displayName ? ` («${row.displayName}»)` : ''}?`)) return;
    try {
      await ApiClient.deleteRefVlan({ vlanId: row.vlanId });
      pushToast({ kind: 'success', title: VLAN_SAVE_TITLE, desc: VLAN_SAVE_DESC });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить', desc: err.message });
    }
  };

  const trafficCols = [
    {
      key: 'vlanId',
      title: 'VLAN',
      width: 90,
      sortAccessor: (r) => r.vlanId,
      render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.vlanId}</span>,
    },
    {
      key: 'displayName',
      title: 'Название',
      width: 200,
      sortAccessor: (r) => r.displayName || '',
      render: (r) => (
        r.displayName
          ? <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName}</span>
          : <span style={{ color: 'var(--fg-tertiary)' }}>без имени</span>
      ),
    },
    {
      key: 'pct',
      title: 'Доля',
      width: 80,
      sortAccessor: (r) => r.pct,
      render: (r) => <span className="num mono">{(Number(r.pct) || 0).toFixed(2)}%</span>,
    },
    {
      key: 'bytes',
      title: 'Объём',
      width: 110,
      sortAccessor: (r) => r.bytes,
      render: (r) => <span className="num mono">{fmtBytes(r.bytes)}</span>,
    },
    {
      key: 'avgBps',
      title: 'Средняя бит/с',
      width: 120,
      sortAccessor: (r) => r.avgBps,
      render: (r) => <span className="num mono">{fmtBits(r.avgBps)}</span>,
    },
    {
      key: 'flows',
      title: 'Потоки',
      width: 100,
      sortAccessor: (r) => r.flows,
      render: (r) => <span className="num mono">{fmtNum(r.flows)}</span>,
    },
  ];

  const catalogRows = useMemo(() => {
    const byId = new Map();
    for (const n of namedRows) {
      byId.set(n.vlanId, { ...n, id: n.vlanId, named: true });
    }
    for (const s of seenRows) {
      if (!byId.has(s.vlanId)) {
        byId.set(s.vlanId, {
          vlanId: s.vlanId,
          displayName: '',
          attachmentType: 'unknown',
          boundary: 'unknown',
          entityId: '',
          comment: '',
          bytes: s.bytes,
          named: false,
          id: s.vlanId,
        });
      }
    }
    return [...byId.values()];
  }, [namedRows, seenRows]);

  const filteredCatalog = useMemo(() => {
    if (!search) return catalogRows;
    const s = search.toLowerCase();
    return catalogRows.filter((r) => (
      String(r.vlanId).includes(s)
      || (r.displayName || '').toLowerCase().includes(s)
      || (VLAN_ATTACHMENT_LABELS[r.attachmentType] || '').toLowerCase().includes(s)
    ));
  }, [catalogRows, search]);

  const catalogCols = [
    {
      key: 'vlanId',
      title: 'VLAN',
      width: 90,
      sortAccessor: (r) => r.vlanId,
      render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.vlanId}</span>,
    },
    {
      key: 'displayName',
      title: 'Название',
      width: 200,
      sortAccessor: (r) => r.displayName || '',
      render: (r) => (
        r.displayName
          ? <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName}</span>
          : <span style={{ color: 'var(--fg-tertiary)' }}>без имени</span>
      ),
    },
    {
      key: 'attachmentType',
      title: 'Тип',
      width: 120,
      render: (r) => <span className="tag">{VLAN_ATTACHMENT_LABELS[r.attachmentType] || r.attachmentType || '—'}</span>,
    },
    {
      key: 'entityId',
      title: 'Владелец',
      width: 160,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.entityId ? (entityNameById[r.entityId] || r.entityId) : '—'}
        </span>
      ),
    },
    {
      key: 'boundary',
      title: 'Граница',
      width: 120,
      render: (r) => <span className="tag">{VLAN_BOUNDARY_LABELS[r.boundary] || r.boundary || '—'}</span>,
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>VLAN</h1>
          <p>Трафик по VLAN и справочник имён. Период, направления и коллекторы берутся из фильтров в шапке.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
          {tab === 'catalog' && (
            <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!canWrite}>Назвать VLAN</Button>
          )}
        </div>
      </div>

      <div className="row" style={{ gap: 8, marginBottom: 16 }}>
        <Button kind={tab === 'traffic' ? 'primary' : 'ghost'} onClick={() => setTab('traffic')}>Трафик</Button>
        <Button kind={tab === 'catalog' ? 'primary' : 'ghost'} onClick={() => setTab('catalog')}>Каталог</Button>
      </div>

      {tab === 'catalog' && seenRows.length > 0 && (
        <Card pad="sm" style={{ marginBottom: 12 }}>
          <div style={{ font: 'var(--pv-text-body-2-bold)', marginBottom: 6 }}>
            Замечены в трафике без имени (24 ч): {seenRows.length}
          </div>
          <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
            {seenRows.slice(0, 20).map((s) => (
              <button
                key={s.vlanId}
                className="tag"
                style={{ cursor: canWrite ? 'pointer' : 'default' }}
                disabled={!canWrite}
                onClick={() => canWrite && setEditing({ vlanId: s.vlanId, isNew: true })}
              >
                VLAN {s.vlanId} · {fmtBytes(s.bytes)}
              </button>
            ))}
          </div>
        </Card>
      )}

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : loadError ? (
        <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={reload}>Повторить</Button>} />
      ) : tab === 'traffic' ? (
        <DataTable
          rows={filtered}
          columns={trafficCols}
          rowKey="id"
          pageSize={20}
          initialSort={{ key: 'bytes', dir: 'desc' }}
          emptyTitle="Нет данных по VLAN"
          emptyDesc="За выбранный период VLAN-трафик не найден."
          toolbar={{ search, onSearch: setSearch }}
        />
      ) : (
        <DataTable
          rows={filteredCatalog}
          columns={catalogCols}
          rowKey="id"
          pageSize={20}
          initialSort={{ key: 'vlanId', dir: 'asc' }}
          onRowClick={canWrite ? (r) => setEditing({ ...r, isNew: !r.named }) : undefined}
          emptyTitle="Каталог пуст"
          emptyDesc="Добавьте имя VLAN или дождитесь появления VLAN в трафике."
          toolbar={{ search, onSearch: setSearch }}
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setEditing({ ...r, isNew: !r.named }); }}>
                <Icon name="edit" size={15} />
              </button>
              {r.named && (
                <button className="icon-btn tt" data-tt="Удалить имя" onClick={(e) => { e.stopPropagation(); handleDelete(r); }}>
                  <Icon name="trash" size={15} />
                </button>
              )}
            </div>
          ) : null}
        />
      )}

      <VlanFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd || (editing && editing.isNew)}
        entities={entities}
        onClose={() => { setShowAdd(false); setEditing(null); }}
        onSaved={() => {
          setShowAdd(false);
          setEditing(null);
          reload();
          pushToast({ kind: 'success', title: VLAN_SAVE_TITLE, desc: VLAN_SAVE_DESC });
        }}
      />
    </div>
  );
}

function VlanFormModal({ open, row, isNew, entities, onClose, onSaved }) {
  const [vlanId, setVlanId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [attachmentType, setAttachmentType] = useState('unknown');
  const [boundary, setBoundary] = useState('unknown');
  const [entityId, setEntityId] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    setFormError('');
    setVlanId(row?.vlanId != null ? String(row.vlanId) : '');
    setDisplayName(row?.displayName || '');
    setAttachmentType(row?.attachmentType || 'unknown');
    setBoundary(row?.boundary || 'unknown');
    setEntityId(row?.entityId || '');
    setComment(row?.comment || '');
  }, [open, row]);

  const handleSave = async () => {
    const idNum = Number(vlanId);
    if (!Number.isInteger(idNum) || idNum < 1 || idNum > 4094) {
      setFormError('VLAN ID должен быть числом от 1 до 4094');
      return;
    }
    if (!displayName.trim()) {
      setFormError('Укажите название VLAN');
      return;
    }
    setSaving(true);
    setFormError('');
    try {
      await ApiClient.saveRefVlan({
        vlanId: idNum,
        displayName: displayName.trim(),
        attachmentType,
        boundary,
        entityId: entityId || '',
        comment,
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
      title={isNew ? 'Назвать VLAN' : `Редактировать VLAN ${row?.vlanId}`}
      subtitle={isNew ? 'Новая запись справочника' : undefined}
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
        <div className="field">
          <label>VLAN ID</label>
          <input
            className="input mono"
            type="number"
            min="1"
            max="4094"
            placeholder="445"
            value={vlanId}
            onChange={(e) => setVlanId(e.target.value)}
            disabled={!isNew}
            readOnly={!isNew}
          />
        </div>
        <div className="field">
          <label>Название</label>
          <input
            className="input"
            placeholder="Клиент А, Uplink M9…"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </div>
        <div className="field">
          <label>Тип подключения</label>
          <select className="input" value={attachmentType} onChange={(e) => setAttachmentType(e.target.value)}>
            {VLAN_ATTACHMENT_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>
        <div className="field">
          <label>Граница</label>
          <select className="input" value={boundary} onChange={(e) => setBoundary(e.target.value)}>
            {VLAN_BOUNDARY_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Владелец (необязательно)</label>
          <select className="input" value={entityId} onChange={(e) => setEntityId(e.target.value)}>
            <option value="">— не задан —</option>
            {(entities || []).map((e) => <option key={e.entityId} value={e.entityId}>{e.displayName}</option>)}
          </select>
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Комментарий</label>
          <input
            className="input"
            placeholder="Необязательно"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </div>
      </div>
    </Modal>
  );
}

Object.assign(window, { PageVlan, VLAN_ATTACHMENT_TYPES, VLAN_BOUNDARY_TYPES });
