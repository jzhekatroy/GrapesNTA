/* VLAN — справочник имён (net_l2_vlans) + VLAN, увиденные в трафике. */

const VLAN_SAVE_TITLE = 'Сохранено';
const VLAN_SAVE_DESC = 'Изменения справочника применятся в течение 60 секунд.';
const VLAN_SEEN_HOURS = 24 * 7;
const VLAN_SEEN_LIMIT = 1000;

function PageVlan({ embedded = false, refreshKey: parentRefreshKey = 0, onReload } = {}) {
  const canWrite = AuthAccess.canWritePage('vlan');
  const [namedRows, setNamedRows] = useState([]);
  const [seenRows, setSeenRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [localRefreshKey, setLocalRefreshKey] = useState(0);

  const refreshKey = onReload ? parentRefreshKey : localRefreshKey;
  const reload = useCallback(() => {
    if (onReload) onReload();
    else setLocalRefreshKey((k) => k + 1);
  }, [onReload]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const [namedR, seenR] = await Promise.all([
        ApiClient.loadRefVlans(),
        ApiClient.loadRefVlansSeen({ hours: VLAN_SEEN_HOURS, limit: VLAN_SEEN_LIMIT }),
      ]);
      if (cancelled) return;
      if (namedR.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setNamedRows([]);
        setSeenRows([]);
      } else {
        setNamedRows((namedR.rows || []).map((r) => ({ ...r, id: r.vlanId })));
        // seen API уже отдаёт только безымянные; ошибку seen не валим всю страницу
        setSeenRows(
          seenR.source === 'error'
            ? []
            : (seenR.rows || []).map((r) => ({ ...r, id: r.vlanId })),
        );
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filterRows = useCallback((rows) => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => (
      String(r.vlanId).includes(s)
      || (r.displayName || '').toLowerCase().includes(s)
      || (r.comment || '').toLowerCase().includes(s)
    ));
  }, [search]);

  const filteredNamed = useMemo(() => filterRows(namedRows), [namedRows, filterRows]);
  const filteredSeen = useMemo(() => filterRows(seenRows), [seenRows, filterRows]);

  const handleDelete = async (row) => {
    if (!window.confirm(`Удалить имя VLAN ${row.vlanId}${row.displayName ? ` («${row.displayName}»)` : ''}? VLAN останется в списке обнаруженных, если есть в трафике.`)) return;
    try {
      await ApiClient.deleteRefVlan({ vlanId: row.vlanId });
      pushToast({ kind: 'success', title: VLAN_SAVE_TITLE, desc: VLAN_SAVE_DESC });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить', desc: err.message });
    }
  };

  const openNameSeen = (row) => {
    setShowAdd(false);
    setEditing({
      vlanId: row.vlanId,
      displayName: '',
      comment: '',
      isNew: true,
      fromSeen: true,
    });
  };

  const namedCols = [
    {
      key: 'vlanId',
      title: 'VLAN',
      width: 100,
      sortAccessor: (r) => r.vlanId,
      render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.vlanId}</span>,
    },
    {
      key: 'displayName',
      title: 'Название',
      width: 280,
      sortAccessor: (r) => r.displayName || '',
      render: (r) => (
        r.displayName
          ? <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.displayName}</span>
          : <span style={{ color: 'var(--fg-muted)' }}>без имени</span>
      ),
    },
    {
      key: 'status',
      title: 'Статус',
      width: 120,
      sortAccessor: () => 1,
      render: () => <Badge tone="success" dot>Размечен</Badge>,
    },
    {
      key: 'comment',
      title: 'Комментарий',
      width: 280,
      sortAccessor: (r) => r.comment || '',
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.comment || '—'}
        </span>
      ),
    },
  ];

  const seenCols = [
    {
      key: 'vlanId',
      title: 'VLAN',
      width: 100,
      sortAccessor: (r) => r.vlanId,
      render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.vlanId}</span>,
    },
    {
      key: 'status',
      title: 'Статус',
      width: 140,
      sortAccessor: () => 0,
      render: () => <Badge tone="warning" dot>Не размечен</Badge>,
    },
    {
      key: 'bytes',
      title: 'Объём (7д)',
      width: 140,
      sortAccessor: (r) => r.bytes || 0,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-3)' }}>
          {typeof fmtBytes === 'function' ? fmtBytes(r.bytes || 0) : String(r.bytes || 0)}
        </span>
      ),
    },
    {
      key: 'flows',
      title: 'Потоки',
      width: 120,
      sortAccessor: (r) => r.flows || 0,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {typeof fmtNum === 'function' ? fmtNum(r.flows || 0) : String(r.flows || 0)}
        </span>
      ),
    },
  ];

  const toolbar = { search, onSearch: setSearch };

  const body = (
    <>
      {!embedded && (
        <div className="page-head">
          <div>
            <h1>VLAN</h1>
            <p>
              Сверху — размеченные имена для отчётов. Ниже — VLAN, увиденные в трафике за 7 дней без имени.
            </p>
          </div>
          <div className="row" style={{ gap: 8 }}>
            <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
            <Button kind="primary" icon="plus" onClick={() => { setEditing(null); setShowAdd(true); }} disabled={!canWrite}>
              Добавить VLAN
            </Button>
          </div>
        </div>
      )}

      {embedded && (
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, gap: 8 }}>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            Размеченные сверху, затем обнаруженные в трафике за 7 дней.
          </div>
          <Button kind="primary" icon="plus" onClick={() => { setEditing(null); setShowAdd(true); }} disabled={!canWrite}>
            Добавить VLAN
          </Button>
        </div>
      )}

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : loadError ? (
        <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={reload}>Повторить</Button>} />
      ) : (
        <div className="col" style={{ gap: 20 }}>
          <div>
            <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 10 }}>
              <h2 style={{ margin: 0, font: 'var(--pv-text-h4)' }}>Размеченные</h2>
              <span style={{ color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
                {filteredNamed.length}
                {search && filteredNamed.length !== namedRows.length ? ` из ${namedRows.length}` : ''}
              </span>
            </div>
            <DataTable
              rows={filteredNamed}
              columns={namedCols}
              rowKey="id"
              pageSize={50}
              initialSort={{ key: 'vlanId', dir: 'asc' }}
              onRowClick={canWrite ? (r) => { setShowAdd(false); setEditing({ ...r, isNew: false }); } : undefined}
              emptyTitle="Нет размеченных VLAN"
              emptyDesc="Назовите VLAN из списка обнаруженных ниже или добавьте вручную."
              toolbar={toolbar}
              rowActions={canWrite ? (r) => (
                <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
                  <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setShowAdd(false); setEditing({ ...r, isNew: false }); }}>
                    <Icon name="edit" size={15} />
                  </button>
                  <button className="icon-btn tt" data-tt="Удалить имя" onClick={(e) => { e.stopPropagation(); handleDelete(r); }}>
                    <Icon name="trash" size={15} />
                  </button>
                </div>
              ) : null}
            />
          </div>

          <div>
            <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 10 }}>
              <h2 style={{ margin: 0, font: 'var(--pv-text-h4)' }}>Обнаруженные в трафике</h2>
              <span style={{ color: 'var(--fg-muted)', font: 'var(--pv-text-body-3)' }}>
                без имени · {filteredSeen.length}
                {search && filteredSeen.length !== seenRows.length ? ` из ${seenRows.length}` : ''}
              </span>
            </div>
            <DataTable
              rows={filteredSeen}
              columns={seenCols}
              rowKey="id"
              pageSize={50}
              initialSort={{ key: 'bytes', dir: 'desc' }}
              onRowClick={canWrite ? openNameSeen : undefined}
              emptyTitle="Нет неразмеченных VLAN"
              emptyDesc="За последние 7 дней в трафике нет VLAN без имени в справочнике."
              toolbar={null}
              rowActions={canWrite ? (r) => (
                <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
                  <Button size="sm" kind="primary" onClick={(e) => { e.stopPropagation(); openNameSeen(r); }}>
                    Назвать
                  </Button>
                </div>
              ) : null}
            />
          </div>
        </div>
      )}

      <VlanFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd || !!editing?.isNew || !!editing?.fromSeen}
        onClose={() => { setShowAdd(false); setEditing(null); }}
        onSaved={() => {
          setShowAdd(false);
          setEditing(null);
          reload();
          pushToast({ kind: 'success', title: VLAN_SAVE_TITLE, desc: VLAN_SAVE_DESC });
        }}
      />
    </>
  );

  if (embedded) return body;
  return <div className="main__container">{body}</div>;
}

function VlanFormModal({ open, row, isNew, onClose, onSaved }) {
  const [vlanId, setVlanId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const fromSeen = !!row?.fromSeen;
  const vlanIdLocked = !isNew || fromSeen;

  useEffect(() => {
    if (!open) return;
    setFormError('');
    setVlanId(row?.vlanId != null ? String(row.vlanId) : '');
    setDisplayName(row?.displayName || '');
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
        attachmentType: row?.attachmentType || 'unknown',
        boundary: row?.boundary || 'unknown',
        entityId: row?.entityId || '',
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

  const title = fromSeen
    ? `Назвать VLAN ${row?.vlanId}`
    : (isNew ? 'Добавить VLAN' : `Редактировать VLAN ${row?.vlanId}`);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
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
            disabled={vlanIdLocked}
            readOnly={vlanIdLocked}
          />
        </div>
        <div className="field">
          <label>Название</label>
          <input
            className="input"
            placeholder="Клиент А, Uplink M9…"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            autoFocus
          />
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

Object.assign(window, { PageVlan });
