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
  { id: 'off', label: 'Выключено', hint: 'Все сутки хранятся без сжатия.' },
  { id: 'on', label: 'Включено', hint: 'Ночью старые сутки сжимаются.' },
];

const FLOW_FIELD = { display: 'grid', gap: 6, alignContent: 'start' };
const FLOW_LABEL = { font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' };
const FLOW_HINT = { font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' };

function onlyDigits(value) {
  return String(value ?? '').replace(/\D+/g, '').slice(0, 6);
}

function FlowStat({ label, value, tone }) {
  return (
    <div className="row" style={{ justifyContent: 'space-between', gap: 12, font: 'var(--pv-text-body-3)' }}>
      <span style={{ color: 'var(--fg-secondary)' }}>{label}</span>
      <span className="mono" style={{ color: tone || 'var(--fg-primary)', textAlign: 'right' }}>{value}</span>
    </div>
  );
}

const FLOW_DAY = {
  done: 'Сжаты',
  running: 'Сжимаются',
  failed: 'Ошибка',
  waiting: 'Ожидание',
  skipped: 'Пропущены',
  full: 'Целиком',
  pending: 'Ещё нет',
};

function flowDayComment(row) {
  if (row.state === 'failed') return row.error || '';
  if (row.state === 'done' && row.bytesBefore) return `было ${fmtBytes(row.bytesBefore)}`;
  return row.note || '';
}

function FlowDays({ days }) {
  const rows = Array.isArray(days) ? days : [];
  return (
    <Card pad="sm">
      <div style={{ display: 'grid', gap: 10 }}>
        <div style={FLOW_LABEL}>Сутки на диске</div>
        {rows.length === 0 ? (
          <div style={FLOW_HINT}>Суток сырых потоков нет.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
            <thead>
              <tr style={{ color: 'var(--fg-muted)', textAlign: 'left' }}>
                <th style={{ padding: '4px 8px 4px 0', fontWeight: 'normal' }}>Сутки</th>
                <th style={{ padding: '4px 8px', fontWeight: 'normal', textAlign: 'right' }}>Объём</th>
                <th style={{ padding: '4px 8px', fontWeight: 'normal' }}>Сжатие</th>
                <th style={{ padding: '4px 0 4px 8px', fontWeight: 'normal' }}>Комментарий</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const failed = row.state === 'failed';
                const comment = flowDayComment(row);
                return (
                  <tr key={row.day} style={{ borderTop: '1px solid var(--bd-soft)' }}>
                    <td className="mono" style={{ padding: '6px 8px 6px 0' }}>{row.day}</td>
                    <td className="mono" style={{ padding: '6px 8px', textAlign: 'right' }}>{fmtBytes(row.bytes)}</td>
                    <td style={{ padding: '6px 8px', color: failed ? 'var(--st-critical)' : 'var(--fg-primary)' }}>
                      {FLOW_DAY[row.state] || row.state}
                    </td>
                    <td style={{ padding: '6px 0 6px 8px', color: failed ? 'var(--st-critical)' : 'var(--fg-secondary)' }}>
                      {comment}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </Card>
  );
}

function FlowStoragePanel({ canWrite }) {
  const [data, setData] = useState(null);
  const [form, setForm] = useState(null);
  const [totalDays, setTotalDays] = useState('');
  const [hotDays, setHotDays] = useState('');
  const [thresholdKb, setThresholdKb] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const body = await ApiClient.loadFlowStorage();
      setData(body);
      setForm(body.settings);
      setHotDays(String(body.settings?.hotDays ?? ''));
      setThresholdKb(String(Math.round(Number(body.settings?.xdpThresholdBytes || 0) / 1000)));
      setTotalDays(body.flows?.ttlDays == null ? '' : String(body.flows.ttlDays));
      setError('');
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    if (!form) return;
    const total = Number(totalDays);
    const hot = Number(hotDays);
    const kb = Number(thresholdKb);
    if (!Number.isInteger(total) || total < 1) {
      setError('Укажите срок хранения в сутках');
      return;
    }
    if (!Number.isInteger(hot) || hot < 1 || hot >= total) {
      setError('Срок без сжатия должен быть от 1 суток и меньше общего срока');
      return;
    }
    if (!Number.isInteger(kb) || kb < 1) {
      setError('Укажите размер мелкого потока в КБ, не меньше 1');
      return;
    }
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(String(form.runAt || ''))) {
      setError('Время запуска — в формате ЧЧ:ММ');
      return;
    }
    setSaving(true);
    setError('');
    try {
      if (total !== data?.flows?.ttlDays) {
        await ApiClient.updateTtl('flows_raw', total);
      }
      if (data?.schemaReady) {
        await ApiClient.saveFlowStorage({
          ...form,
          hotDays: hot,
          xdpThresholdBytes: kb * 1000,
        });
      }
      await load();
      pushToast({ kind: 'success', title: 'Настройки хранения сохранены' });
    } catch (err) {
      setError(err.message || ApiClient.LOAD_FAILED);
    } finally {
      setSaving(false);
    }
  };

  const disabled = !canWrite || saving || !data?.schemaReady;
  const forecast = data?.forecast;
  const mode = FLOW_MODES.find((m) => m.id === form?.mode) || FLOW_MODES[0];
  const fitsTone = forecast?.fits === false ? 'var(--st-critical)' : (forecast?.fits ? 'var(--st-success)' : undefined);

  return (
    <>
    <Card pad="sm" style={{ marginBottom: 16 }}>
      <div style={{ display: 'grid', gap: 16 }}>
        <div style={{ ...FLOW_HINT, maxWidth: 820 }}>
          Свежие сутки хранятся полностью. В старых сутках мелкие потоки xdpflowd сохраняются выборочно,
          с пересчётом объёма, поэтому итоги трафика не меняются. NetFlow и sFlow не сжимаются.
        </div>

        {!data ? (
          <div style={{ color: error ? 'var(--st-critical)' : 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            {error || 'Загрузка…'}
          </div>
        ) : (
          <>
            {!data.schemaReady && (
              <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--st-warning)' }}>
                Таблицы настроек не созданы: выложите схему базы, затем настройки станут доступны.
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 24 }}>
              <div style={{ display: 'grid', gap: 14, alignContent: 'start' }}>
                <label style={FLOW_FIELD}>
                  <span style={FLOW_LABEL}>Сжатие старых суток</span>
                  <select className="input" value={form.mode} disabled={disabled}
                    onChange={(e) => setForm({ ...form, mode: e.target.value })}>
                    {FLOW_MODES.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
                  </select>
                  <span style={FLOW_HINT}>{mode.hint}</span>
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <label style={FLOW_FIELD}>
                    <span style={FLOW_LABEL}>Срок хранения, сутки</span>
                    <input className="input mono" type="text" inputMode="numeric" value={totalDays}
                      disabled={!canWrite || saving}
                      onChange={(e) => setTotalDays(onlyDigits(e.target.value))} />
                  </label>
                  <label style={FLOW_FIELD}>
                    <span style={FLOW_LABEL}>Из них без сжатия, сутки</span>
                    <input className="input mono" type="text" inputMode="numeric" value={hotDays}
                      disabled={disabled}
                      onChange={(e) => setHotDays(onlyDigits(e.target.value))} />
                  </label>
                </div>
                <span style={{ ...FLOW_HINT, marginTop: -8 }}>Текущие сутки всегда хранятся без сжатия.</span>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <label style={FLOW_FIELD}>
                    <span style={FLOW_LABEL}>Мелкий поток — меньше, КБ</span>
                    <input className="input mono" type="text" inputMode="numeric" value={thresholdKb}
                      disabled={disabled}
                      onChange={(e) => setThresholdKb(onlyDigits(e.target.value))} />
                  </label>
                  <label style={FLOW_FIELD}>
                    <span style={FLOW_LABEL}>Из мелких сохранять</span>
                    <select className="input" value={form.xdpRate} disabled={disabled}
                      onChange={(e) => setForm({ ...form, xdpRate: Number(e.target.value) })}>
                      {(data.rates || []).map((rate) => <option key={rate} value={rate}>1 из {rate}</option>)}
                    </select>
                  </label>
                </div>

                <label style={{ ...FLOW_FIELD, maxWidth: 160 }}>
                  <span style={FLOW_LABEL}>Ночной запуск</span>
                  <input className="input mono" type="text" inputMode="numeric" placeholder="ЧЧ:ММ" maxLength={5}
                    value={form.runAt} disabled={disabled}
                    onChange={(e) => setForm({ ...form, runAt: e.target.value.replace(/[^\d:]/g, '').slice(0, 5) })} />
                </label>
              </div>

              <div style={{ display: 'grid', gap: 10, alignContent: 'start' }}>
                <div style={FLOW_LABEL}>Прогноз по текущим настройкам</div>
                {forecast ? (
                  <>
                    <FlowStat label="Сутки без сжатия" value={fmtBytes(forecast.exactBytes)} />
                    <FlowStat
                      label="Сжатые сутки"
                      value={forecast.thinnedBytes == null ? 'нет замера' : `≈ ${fmtBytes(forecast.thinnedBytes)}`}
                    />
                    <FlowStat
                      label={`Всего за ${forecast.exactDays + forecast.warmDays} сут.`}
                      value={forecast.totalBytes == null ? '—' : `≈ ${fmtBytes(forecast.totalBytes)}`}
                    />
                    <FlowStat
                      label="Доступно на диске"
                      value={forecast.roomBytes == null ? '—' : fmtBytes(forecast.roomBytes)}
                    />
                    <FlowStat
                      label="Итог"
                      tone={fitsTone}
                      value={forecast.fits == null ? '—' : (forecast.fits ? 'места хватает' : 'места не хватает')}
                    />
                    <div style={{ ...FLOW_HINT, marginTop: 4 }}>
                      Точность: {forecast.measured ? forecast.note : 'для этих параметров не измерялась'}.
                    </div>
                  </>
                ) : (
                  <div style={FLOW_HINT}>Нет данных для прогноза.</div>
                )}
              </div>
            </div>
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
    {data && <FlowDays days={data.days} />}
    </>
  );
}

function PageTTL() {
  const canWrite = AuthAccess.canWritePage('ttl');
  const [tab, setTab] = useState('tables');
  const [rows, setRows] = useState([]);
  const [disk, setDisk] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState(null);
  const [flowRevision, setFlowRevision] = useState(0);

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
          <h1>Хранение данных</h1>
          <TtlDiskBar disk={disk} />
        </div>
        <div className="row page-head__actions" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={() => { loadAll(); setFlowRevision((n) => n + 1); }} disabled={loading}>Обновить</Button>
        </div>
      </div>

      <div className="seg" role="tablist" aria-label="Разделы хранения" style={{ marginBottom: 16 }}>
        <button type="button" role="tab" aria-selected={tab === 'tables'} className={tab === 'tables' ? 'is-active' : ''} onClick={() => setTab('tables')}>
          Сроки таблиц
        </button>
        <button type="button" role="tab" aria-selected={tab === 'flows'} className={tab === 'flows' ? 'is-active' : ''} onClick={() => setTab('flows')}>
          Хранение сырых потоков
        </button>
      </div>

      {tab === 'flows' ? <FlowStoragePanel key={flowRevision} canWrite={canWrite} /> : (
      <>
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
          rows={rows.filter((r) => r.id !== 'flows_raw')}
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
      </>
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
