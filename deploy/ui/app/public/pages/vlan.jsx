/* VLAN — справочник имён (net_l2_vlans), раздел «Модель сети». */

const VLAN_SAVE_TITLE = 'Сохранено';
const VLAN_SAVE_DESC = 'Изменения справочника применятся в течение 60 секунд.';

function PageVlan() {
  const canWrite = AuthAccess.canWritePage('vlan');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const namedR = await ApiClient.loadRefVlans();
      if (cancelled) return;
      if (namedR.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
      } else {
        setRows((namedR.rows || []).map((r) => ({ ...r, id: r.vlanId })));
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!search) return rows;
    const s = search.toLowerCase();
    return rows.filter((r) => (
      String(r.vlanId).includes(s)
      || (r.displayName || '').toLowerCase().includes(s)
      || (r.comment || '').toLowerCase().includes(s)
    ));
  }, [rows, search]);

  const handleDelete = async (row) => {
    if (!window.confirm(`Удалить VLAN ${row.vlanId}${row.displayName ? ` («${row.displayName}»)` : ''}?`)) return;
    try {
      await ApiClient.deleteRefVlan({ vlanId: row.vlanId });
      pushToast({ kind: 'success', title: VLAN_SAVE_TITLE, desc: VLAN_SAVE_DESC });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось удалить', desc: err.message });
    }
  };

  const cols = [
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
          : <span style={{ color: 'var(--fg-tertiary)' }}>без имени</span>
      ),
    },
    {
      key: 'comment',
      title: 'Комментарий',
      width: 320,
      sortAccessor: (r) => r.comment || '',
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.comment || '—'}
        </span>
      ),
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>VLAN</h1>
          <p>Справочник VLAN: имена для отчётов и разбора трафика.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!canWrite}>Добавить VLAN</Button>
        </div>
      </div>

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : loadError ? (
        <Empty icon="db" title="Не удалось загрузить" desc={loadError} action={<Button kind="primary" icon="refresh" onClick={reload}>Повторить</Button>} />
      ) : (
        <DataTable
          rows={filtered}
          columns={cols}
          rowKey="id"
          pageSize={50}
          initialSort={{ key: 'vlanId', dir: 'asc' }}
          onRowClick={canWrite ? (r) => setEditing(r) : undefined}
          emptyTitle="Каталог пуст"
          emptyDesc="Добавьте VLAN — укажите ID и название."
          toolbar={{ search, onSearch: setSearch }}
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              <button className="icon-btn tt" data-tt="Редактировать" onClick={(e) => { e.stopPropagation(); setEditing(r); }}>
                <Icon name="edit" size={15} />
              </button>
              <button className="icon-btn tt" data-tt="Удалить" onClick={(e) => { e.stopPropagation(); handleDelete(r); }}>
                <Icon name="trash" size={15} />
              </button>
            </div>
          ) : null}
        />
      )}

      <VlanFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd}
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

function VlanFormModal({ open, row, isNew, onClose, onSaved }) {
  const [vlanId, setVlanId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

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
      // Поля type/boundary/owner в UI убраны — при правке сохраняем прежние значения из записи.
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

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? 'Добавить VLAN' : `Редактировать VLAN ${row?.vlanId}`}
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
