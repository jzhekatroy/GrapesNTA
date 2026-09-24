/* Управление TTL — сроки хранения таблиц ClickHouse */

const HEAVY_WARNING = 'MODIFY TTL на больших таблицах запускает мутацию и может упереться в память сервера. Меняйте по одной таблице, желательно вне пиковой нагрузки.';

function diskBarTone(usedPct) {
  const pct = Number(usedPct);
  if (!Number.isFinite(pct)) return 'ok';
  if (pct >= 90) return 'crit';
  if (pct >= 65) return 'warn';
  return 'ok';
}

function TtlDiskBar({ disk }) {
  if (!disk || !(Number(disk.totalBytes) > 0)) return null;

  const usedPct = Math.min(100, Math.max(0, Number(disk.usedPct) || 0));
  const tone = diskBarTone(usedPct);
  const totalLabel = fmtBytes(disk.totalBytes);
  const freeLabel = fmtBytes(disk.freeBytes);
  const label = `${totalLabel} / ${freeLabel}`;

  return (
    <div className="ttl-disk">
      <div className="ttl-disk__caption">Занятость диска</div>
      <div
        className={`ttl-disk-bar ttl-disk-bar--${tone}`}
        role="progressbar"
        aria-label="Занятость диска ClickHouse"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(usedPct)}
        aria-valuetext={label}
        title={`Занято ${usedPct.toFixed(1)}% · всего ${totalLabel} · свободно ${freeLabel}`}
      >
        <div className="ttl-disk-bar__crit-zone" aria-hidden="true" />
        <div className="ttl-disk-bar__fill" style={{ width: `${usedPct}%` }} />
        <div className="ttl-disk-bar__crit-edge ttl-disk-bar__crit-edge--start" aria-hidden="true" />
        <div className="ttl-disk-bar__crit-edge ttl-disk-bar__crit-edge--end" aria-hidden="true" />
        <div className="ttl-disk-bar__label mono">{label}</div>
      </div>
    </div>
  );
}

const FLOW_MODES = [
  ['off', 'Выключено'],
  ['dry_run', 'Проверка без изменений'],
  ['on', 'Включено'],
];

const FLOW_STATUS = {
  dry_run: 'проверка',
  running: 'идёт',
  done: 'готово',
  failed: 'ошибка',
  skipped: 'пропущено',
  waiting: 'ждёт',
};

function flowFieldStyle() {
  return { display: 'grid', gap: 6 };
}

function flowLabelStyle() {
  return { font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' };
}

function FlowStoragePanel({ canWrite, onReady }) {
  const [data, setData] = useState(null);
  const [form, setForm] = useState(null);
  const [totalDays, setTotalDays] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const body = await ApiClient.loadFlowStorage();
      setData(body);
      setForm(body.settings);
      if (onReady) onReady();
      setTotalDays(body.flows?.ttlDays == null ? '' : String(body.flows.ttlDays));
      setError('');
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    if (!form) return;
    const days = Number(totalDays);
    if (!Number.isInteger(days) || days < 1) {
      setError('Укажите, сколько суток хранить всего');
      return;
    }
    setSaving(true);
    setError('');
    try {
      if (days !== data?.flows?.ttlDays) {
        await ApiClient.updateTtl('flows_raw', days);
      }
      if (data?.schemaReady) {
        await ApiClient.saveFlowStorage({
          ...form,
          xdpThresholdBytes: Math.round(Number(form.xdpThresholdBytes) / 1000) * 1000,
        });
      }
      await load();
      pushToast({ kind: 'success', title: 'Хранение потоков сохранено' });
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
    } finally {
      setSaving(false);
    }
  };

  const forecast = data?.forecast;
  const forecastText = !forecast ? '' : (
    forecast.thinnedBytes == null
      ? 'Сколько займут прореженные сутки — не замерено для этой частоты и порога.'
      : `Точные сутки ${fmtBytes(forecast.exactBytes)}, прореженные ${fmtBytes(forecast.thinnedBytes)}. `
        + `За ${forecast.exactDays + forecast.warmDays} сут. выйдет около ${fmtBytes(forecast.totalBytes)}. `
        + (forecast.fits == null ? '' : (forecast.fits ? 'Места хватит.' : 'На выбранный срок места не хватит.'))
  );

  return (
    <Card pad="sm" style={{ marginBottom: 16 }}>
      <div style={{ display: 'grid', gap: 14 }}>
        <div>
          <div style={{ font: 'var(--pv-text-body-2-bold)', color: 'var(--fg-primary)' }}>Хранение потоков</div>
          <div style={{ marginTop: 4, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
            Свежие сутки хранятся точно. Более старые сутки xdpflowd прореживаются ночью: мелкие потоки
            оставляются выборочно, суммы трафика сохраняются. NetFlow и sFlow не прореживаются и лежат точно весь срок.
          </div>
        </div>

        {!data ? (
          <div style={{ color: 'var(--fg-secondary)' }}>{error || 'Загрузка…'}</div>
        ) : (
          <>
            {!data.schemaReady && (
              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--st-warning)' }}>
                Таблицы настроек ещё не созданы. После выкладки схемы здесь появятся режим и журнал.
              </div>
            )}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
              <label style={flowFieldStyle()}>
                <span style={flowLabelStyle()}>Режим</span>
                <select className="input" value={form.mode} disabled={!canWrite || saving || !data.schemaReady}
                  onChange={(e) => setForm({ ...form, mode: e.target.value })}>
                  {FLOW_MODES.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
                </select>
              </label>
              <label style={flowFieldStyle()}>
                <span style={flowLabelStyle()}>Точно, суток</span>
                <input className="input" type="number" min="1" max="3650" value={form.hotDays}
                  disabled={!canWrite || saving || !data.schemaReady}
                  onChange={(e) => setForm({ ...form, hotDays: Number(e.target.value) })} />
              </label>
              <label style={flowFieldStyle()}>
                <span style={flowLabelStyle()}>Всего, суток</span>
                <input className="input" type="number" min="1" max="3650" value={totalDays}
                  disabled={!canWrite || saving}
                  onChange={(e) => setTotalDays(e.target.value)} />
              </label>
              <label style={flowFieldStyle()}>
                <span style={flowLabelStyle()}>Запуск</span>
                <input className="input" type="time" value={form.runAt} disabled={!canWrite || saving || !data.schemaReady}
                  onChange={(e) => setForm({ ...form, runAt: e.target.value })} />
              </label>
              <label style={flowFieldStyle()}>
                <span style={flowLabelStyle()}>xdpflowd, частота</span>
                <select className="input" value={form.xdpRate} disabled={!canWrite || saving || !data.schemaReady}
                  onChange={(e) => setForm({ ...form, xdpRate: Number(e.target.value) })}>
                  {(data.rates || []).map((rate) => <option key={rate} value={rate}>1:{rate}</option>)}
                </select>
              </label>
              <label style={flowFieldStyle()}>
                <span style={flowLabelStyle()}>xdpflowd, порог, КБ</span>
                <input className="input" type="number" min="1" value={Math.round(Number(form.xdpThresholdBytes) / 1000)}
                  disabled={!canWrite || saving || !data.schemaReady}
                  onChange={(e) => setForm({ ...form, xdpThresholdBytes: Number(e.target.value) * 1000 })} />
              </label>
            </div>
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              Тёплых суток: {forecast ? forecast.warmDays : '—'}. {forecast?.note || ''}
              {forecastText ? ` ${forecastText}` : ''}
            </div>
            {Array.isArray(data.log) && data.log.length > 0 && (
              <div style={{ display: 'grid', gap: 6 }}>
                {data.log.map((row) => (
                  <div key={row.day} className="row" style={{ gap: 12, font: 'var(--pv-text-body-3)' }}>
                    <span className="mono">{row.day}</span>
                    <span>{FLOW_STATUS[row.status] || row.status}</span>
                    <span className="mono">{fmtBytes(row.bytesBefore)} → {row.bytesAfter ? fmtBytes(row.bytesAfter) : '—'}</span>
                    {row.message ? <span style={{ color: 'var(--fg-secondary)' }}>{row.message}</span> : null}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
        {error && data && (
          <div style={{ color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>{error}</div>
        )}
        {canWrite && data && (
          <div>
            <Button kind="primary" onClick={save} disabled={saving}>{saving ? 'Сохранение…' : 'Сохранить'}</Button>
          </div>
        )}
      </div>
    </Card>
  );
}

function PageTTL() {
  const canWrite = AuthAccess.canWritePage('ttl');
  const [rows, setRows] = useState([]);
  const [disk, setDisk] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState(null);
  const [flowPanelOk, setFlowPanelOk] = useState(false);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await ApiClient.loadTtl();
      const data = Array.isArray(result) ? result : (result?.data || []);
      setRows((data || []).map((r) => ({ ...r, id: r.id })));
      setDisk(Array.isArray(result) ? null : (result?.disk || null));
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
      setRows([]);
      setDisk(null);
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
          <div style={{ font: 'var(--pv-text-body-2-bold)', color: 'var(--fg-primary)' }}>{r.label}</div>
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
          <h1>Сроки хранения</h1>
          <TtlDiskBar disk={disk} />
          <p>Сроки хранения таблиц ClickHouse. Изменения применяются через ALTER TABLE … MODIFY TTL.</p>
        </div>
        <div className="row page-head__actions" style={{ gap: 8 }}>
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

      <FlowStoragePanel canWrite={canWrite} onReady={() => setFlowPanelOk(true)} />

      {loading ? (
        <Card pad="sm">
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div>
        </Card>
      ) : error ? (
        <Empty icon="db" title="Не удалось загрузить" desc={error} action={<Button kind="primary" icon="refresh" onClick={loadAll}>Повторить</Button>} />
      ) : (
        <DataTable
          rows={flowPanelOk ? rows.filter((r) => r.id !== 'flows_raw') : rows}
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
