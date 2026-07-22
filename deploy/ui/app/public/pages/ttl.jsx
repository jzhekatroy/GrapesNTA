/* Управление TTL — сроки хранения таблиц ClickHouse */

const HEAVY_WARNING = 'MODIFY TTL на больших таблицах запускает мутацию и может упереться в память сервера. Меняйте по одной таблице, желательно вне пиковой нагрузки.';

function PageTTL() {
  const canWrite = AuthAccess.canWritePage('ttl');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await ApiClient.loadTtl();
      setRows((data || []).map((r) => ({ ...r, id: r.id })));
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const cols = [
    {
      key: 'label',
      title: 'Данные',
      width: 220,
      render: (r) => (
        <div>
          <div style={{ font: 'var(--pv-text-body-2-bold)', color: '#fff' }}>{r.label}</div>
          {r.heavy && (
            <div style={{ marginTop: 4 }}>
              <Badge tone="warning">Тяжёлая</Badge>
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'table',
      title: 'Таблица',
      width: 200,
      render: (r) => <span className="mono" style={{ font: 'var(--pv-text-body-2)' }}>{r.table}</span>,
    },
    {
      key: 'ttlDays',
      title: 'TTL (дн)',
      width: 100,
      num: true,
      align: 'right',
      sortAccessor: (r) => r.ttlDays,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.ttlDays ?? '—'}</span>
      ),
    },
    {
      key: 'totalBytes',
      title: 'Объём',
      width: 120,
      num: true,
      align: 'right',
      sortAccessor: (r) => r.totalBytes,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-2)' }}>{fmtBytes(r.totalBytes)}</span>
      ),
    },
    {
      key: 'ttlExpression',
      title: 'Выражение TTL',
      width: 280,
      sortable: false,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {r.ttlExpression || '—'}
        </span>
      ),
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Управление TTL</h1>
          <p>Сроки хранения таблиц ClickHouse. Изменения применяются через ALTER TABLE … MODIFY TTL.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={loadAll} disabled={loading}>Обновить</Button>
        </div>
      </div>

      <Card pad="sm" style={{ marginBottom: 16, borderColor: 'var(--st-warning)40' }}>
        <div className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
          <Icon name="alert" size={18} style={{ color: 'var(--st-warning)', flexShrink: 0, marginTop: 2 }} />
          <div style={{ font: 'var(--pv-text-body-2)', color: 'var(--fg-secondary)' }}>
            {HEAVY_WARNING}
          </div>
        </div>
      </Card>

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : error ? (
        <Empty icon="db" title="Не удалось загрузить" desc={error} action={<Button kind="primary" icon="refresh" onClick={loadAll}>Повторить</Button>} />
      ) : (
        <DataTable
          rows={rows}
          columns={cols}
          rowKey="id"
          pageSize={15}
          emptyTitle="Нет таблиц"
          emptyDesc="Каталог TTL пуст или ClickHouse недоступен."
          rowActions={canWrite ? (r) => (
            <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
              <Button size="sm" kind="ghost" icon="edit" onClick={(e) => { e.stopPropagation(); setEditing(r); }}>
                Изменить
              </Button>
            </div>
          ) : null}
        />
      )}

      <TtlEditModal
        open={!!editing}
        row={editing}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null);
          loadAll();
          pushToast({ kind: 'success', title: 'TTL обновлён', desc: 'Изменение отправлено в ClickHouse.' });
        }}
      />
    </div>
  );
}

function TtlEditModal({ open, row, onClose, onSaved }) {
  const [days, setDays] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!open || !row) return;
    setDays(String(row.ttlDays ?? ''));
    setError('');
    setSaving(false);
  }, [open, row]);

  const handleSave = async () => {
    if (!row) return;
    const value = Number(days);
    if (!Number.isInteger(value) || value < 1) {
      setError('Укажите целое число дней (не меньше 1)');
      return;
    }
    setSaving(true);
    setError('');
    try {
      await ApiClient.updateTtl(row.id, value);
      onSaved();
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
      setSaving(false);
    }
  };

  if (!row) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Изменить TTL"
      subtitle={`${row.label} · ${row.table}`}
      footer={(
        <div className="row" style={{ gap: 8, justifyContent: 'flex-end', width: '100%' }}>
          <Button kind="ghost" onClick={onClose} disabled={saving}>Отмена</Button>
          <Button kind="primary" onClick={handleSave} disabled={saving}>
            {saving ? 'Применение…' : `Применить к ${row.table}`}
          </Button>
        </div>
      )}
    >
      <div style={{ display: 'grid', gap: 16 }}>
        <div>
          <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', marginBottom: 6 }}>Текущий срок</div>
          <div className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{row.ttlDays} дн</div>
        </div>

        <label style={{ display: 'grid', gap: 6 }}>
          <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>Новый срок (дней)</span>
          <input
            className="input"
            type="number"
            min="1"
            max="3650"
            value={days}
            onChange={(e) => setDays(e.target.value)}
            disabled={saving}
          />
        </label>

        {row.heavy && (
          <Card pad="sm" style={{ borderColor: 'var(--st-warning)40' }}>
            <div className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
              <Icon name="alert" size={16} style={{ color: 'var(--st-warning)', flexShrink: 0, marginTop: 2 }} />
              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{HEAVY_WARNING}</div>
            </div>
          </Card>
        )}

        {error && (
          <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{error}</div>
        )}
      </div>
    </Modal>
  );
}

Object.assign(window, { PageTTL });
