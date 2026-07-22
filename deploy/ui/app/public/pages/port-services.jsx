/* Сервисы / порты — справочник port_services (ClickHouse) */

const TRANSPORTS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'sctp', label: 'SCTP' },
  { value: 'icmp', label: 'ICMP' },
  { value: 'icmpv6', label: 'ICMPv6' },
];

const PORT_MODES = [
  { value: 'single', label: 'Один порт' },
  { value: 'range', label: 'Диапазон' },
];

const COMMON_CATEGORIES = ['web', 'dns', 'voip', 'database', 'mail', 'vpn', 'management', 'p2p', 'games', 'video'];

const SAVE_SUCCESS_TITLE = 'Настройки сохранены';
const SAVE_SUCCESS_DESC = 'Изменения будут автоматически применены в течение 60 секунд.';

const SERVICE_CODE_RE = /^[a-z0-9_]+$/;

function portServiceRowKey(row) {
  return `${row.transport}:${row.portFrom}:${row.portTo}`;
}

function fmtPortServiceUpdatedAt(value) {
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

function inferPortMode(row) {
  if (!row) return 'single';
  return row.portFrom === row.portTo ? 'single' : 'range';
}

const CATEGORY_NEW = '__new__';

function CategoryCombobox({ value, onChange, options }) {
  const items = useMemo(
    () => [...new Set((options || []).map((c) => String(c).trim()).filter(Boolean))].sort(),
    [options],
  );

  const trimmed = String(value ?? '').trim();
  const [mode, setMode] = useState(() => (
    trimmed && !items.includes(trimmed) ? 'custom' : 'pick'
  ));

  if (mode === 'custom') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <input
          className="input"
          placeholder="Новая категория"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoFocus
        />
        {items.length > 0 && (
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            style={{ alignSelf: 'flex-start', padding: '4px 8px' }}
            onClick={() => {
              setMode('pick');
              onChange(items[0] || '');
            }}
          >
            Выбрать из списка
          </button>
        )}
      </div>
    );
  }

  const selectValue = items.includes(String(value ?? '').trim()) ? value : '';

  return (
    <select
      className="input"
      value={selectValue}
      onChange={(e) => {
        const next = e.target.value;
        if (next === CATEGORY_NEW) {
          setMode('custom');
          onChange('');
          return;
        }
        onChange(next);
      }}
    >
      <option value="" disabled>Выберите категорию</option>
      {items.map((c) => (
        <option key={c} value={c}>{c}</option>
      ))}
      <option value={CATEGORY_NEW}>+ Новая категория…</option>
    </select>
  );
}

function PagePortServices() {
  const canWrite = AuthAccess.canWritePage('port-services');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [transportFilter, setTransportFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [editing, setEditing] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [showSeedDefaults, setShowSeedDefaults] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError(null);
      const res = await ApiClient.loadPortServices({
        search: search.trim() || undefined,
        transport: transportFilter || undefined,
        category: categoryFilter || undefined,
      });
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setRows([]);
      } else {
        setRows((res.rows || []).map((r) => ({ ...r, id: portServiceRowKey(r) })));
      }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey, search, transportFilter, categoryFilter]);

  const categoryOptions = useMemo(() => {
    const fromRows = rows.map((r) => r.category).filter(Boolean);
    return [...new Set([...COMMON_CATEGORIES, ...fromRows])].sort();
  }, [rows]);

  const handleDisable = async (row) => {
    const label = `${row.transport}/${row.portLabel}`;
    if (!window.confirm(`Отключить правило «${label} → ${row.serviceName}»?`)) return;
    try {
      await ApiClient.disablePortService({
        transport: row.transport,
        portFrom: row.portFrom,
        portTo: row.portTo,
      });
      pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
      reload();
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось отключить', desc: err.message });
    }
  };

  const cols = [
    {
      key: 'transport',
      title: 'Транспорт',
      width: 90,
      sortAccessor: (r) => r.transport,
      render: (r) => <span className="tag">{r.transport}</span>,
    },
    {
      key: 'portLabel',
      title: 'Порт / диапазон',
      width: 120,
      sortAccessor: (r) => r.portFrom,
      render: (r) => (
        <span className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.portLabel}</span>
      ),
    },
    {
      key: 'serviceCode',
      title: 'Код сервиса',
      width: 120,
      sortAccessor: (r) => r.serviceCode,
      render: (r) => <span className="mono">{r.serviceCode}</span>,
    },
    {
      key: 'serviceName',
      title: 'Название',
      width: 160,
      sortAccessor: (r) => r.serviceName,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-2-bold)' }}>{r.serviceName || '—'}</span>
      ),
    },
    {
      key: 'category',
      title: 'Категория',
      width: 100,
      sortAccessor: (r) => r.category,
      render: (r) => <span className="tag">{r.category || '—'}</span>,
    },
    {
      key: 'description',
      title: 'Описание',
      width: 200,
      render: (r) => (
        <span style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          {r.description || '—'}
        </span>
      ),
    },
    {
      key: 'updatedAt',
      title: 'Обновлено',
      width: 150,
      sortAccessor: (r) => r.updatedAt,
      render: (r) => (
        <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          {fmtPortServiceUpdatedAt(r.updatedAt)}
        </span>
      ),
    },
  ];

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Сервисы / порты</h1>
          <p>Соответствия портов и диапазонов сервисам для классификации трафика в отчётах.</p>
        </div>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <Button kind="ghost" icon="refresh" onClick={reload} disabled={loading}>Обновить</Button>
          <Button
            kind="ghost"
            onClick={() => setShowSeedDefaults(true)}
            disabled={!!loadError || !canWrite}
          >
            Добавить стандартные
          </Button>
          <Button kind="primary" icon="plus" onClick={() => setShowAdd(true)} disabled={!!loadError || !canWrite}>Добавить сервис</Button>
        </div>
      </div>

      <div className="row" style={{ gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <div className="field" style={{ margin: 0, minWidth: 140 }}>
          <label style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>Транспорт</label>
          <select
            className="input"
            value={transportFilter}
            onChange={(e) => setTransportFilter(e.target.value)}
          >
            <option value="">Все</option>
            {TRANSPORTS.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </div>
        <div className="field" style={{ margin: 0, minWidth: 140 }}>
          <label style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>Категория</label>
          <select
            className="input"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
          >
            <option value="">Все</option>
            {categoryOptions.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
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
          rows={rows}
          columns={cols}
          rowKey="id"
          selectable
          selected={selected}
          onSelectChange={setSelected}
          pageSize={15}
          onRowClick={canWrite ? (r) => setEditing({ ...r, isNew: false }) : undefined}
          emptyTitle="Нет активных правил"
          emptyDesc="Добавьте соответствие порта сервису или уточните фильтры."
          toolbar={{
            search,
            onSearch: setSearch,
            searchPlaceholder: 'Порт, код, название, категория…',
          }}
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
      )}

      <PortServiceFormModal
        open={showAdd || !!editing}
        row={editing}
        isNew={showAdd || (editing && editing.isNew)}
        categoryOptions={categoryOptions}
        onClose={() => { setShowAdd(false); setEditing(null); }}
        onSaved={() => {
          setShowAdd(false);
          setEditing(null);
          reload();
          pushToast({ kind: 'success', title: SAVE_SUCCESS_TITLE, desc: SAVE_SUCCESS_DESC });
        }}
      />

      <SeedDefaultsModal
        open={showSeedDefaults}
        onClose={() => setShowSeedDefaults(false)}
        onDone={() => {
          setShowSeedDefaults(false);
          reload();
        }}
      />
    </div>
  );
}

function SeedDefaultsModal({ open, onClose, onDone }) {
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setPreview(null);
    setError('');
    setLoading(true);
    (async () => {
      try {
        const data = await ApiClient.previewPortServiceDefaults();
        if (!cancelled) setPreview(data);
      } catch (err) {
        if (!cancelled) setError(err.message || 'Не удалось загрузить превью');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [open]);

  const counts = preview?.counts || {};
  const toAdd = preview?.toAdd || [];
  const canApply = !loading && !error && toAdd.length > 0;

  const handleApply = async () => {
    if (!canApply || applying) return;
    setApplying(true);
    setError('');
    try {
      const body = await ApiClient.seedPortServiceDefaults();
      const meta = body.meta || body;
      pushToast({
        kind: 'success',
        title: meta.inserted > 0 ? `Добавлено: ${meta.inserted}` : 'Нечего добавлять',
        desc: meta.message || SAVE_SUCCESS_DESC,
      });
      onDone();
    } catch (err) {
      setError(err.message || 'Не удалось добавить стандартные сервисы');
    } finally {
      setApplying(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={applying ? () => {} : onClose}
      title="Стандартные сервисы"
      subtitle="Добавятся только отсутствующие соответствия. Ваши правила не перезаписываются."
      size="lg"
      footer={(
        <div className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
          <Button kind="ghost" onClick={onClose} disabled={applying}>Отмена</Button>
          <Button kind="primary" onClick={handleApply} disabled={!canApply || applying}>
            {applying ? 'Добавление…' : `Добавить${toAdd.length ? ` (${toAdd.length})` : ''}`}
          </Button>
        </div>
      )}
    >
      {loading ? (
        <div style={{ padding: 16, color: 'var(--fg-secondary)' }}>Сверяем со справочником…</div>
      ) : error ? (
        <div style={{ color: 'var(--danger, #c44)' }}>{error}</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ font: 'var(--pv-text-body-2)', color: 'var(--fg-secondary)' }}>
            В наборе {preview?.totalDefaults ?? 0} стандартных правил
            (HTTP/HTTPS, DNS, SSH, mail, БД и др.).
          </div>
          <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
            <span className="tag">Будет добавлено: {counts.toAdd ?? 0}</span>
            <span className="tag">Уже есть: {counts.skippedExisting ?? 0}</span>
            {(counts.skippedDisabled ?? 0) > 0 && (
              <span className="tag">Пропущено (отключены вами): {counts.skippedDisabled}</span>
            )}
            {(counts.skippedOverlap ?? 0) > 0 && (
              <span className="tag">Пропущено (пересечение): {counts.skippedOverlap}</span>
            )}
          </div>
          {toAdd.length === 0 ? (
            <div style={{ padding: '8px 0', color: 'var(--fg-secondary)' }}>
              Нечего добавлять — все стандартные ключи уже учтены или конфликтуют с вашими правилами.
            </div>
          ) : (
            <div style={{ maxHeight: 280, overflow: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
                <thead>
                  <tr style={{ textAlign: 'left', color: 'var(--fg-secondary)' }}>
                    <th style={{ padding: '8px 10px' }}>Транспорт</th>
                    <th style={{ padding: '8px 10px' }}>Порт</th>
                    <th style={{ padding: '8px 10px' }}>Сервис</th>
                    <th style={{ padding: '8px 10px' }}>Категория</th>
                  </tr>
                </thead>
                <tbody>
                  {toAdd.map((r) => (
                    <tr key={`${r.transport}:${r.portFrom}:${r.portTo}`}>
                      <td style={{ padding: '6px 10px' }}>{r.transport}</td>
                      <td style={{ padding: '6px 10px' }} className="mono">{r.portLabel}</td>
                      <td style={{ padding: '6px 10px' }}>{r.serviceName}</td>
                      <td style={{ padding: '6px 10px' }}>{r.category}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {(counts.skippedDisabled > 0 || counts.skippedOverlap > 0) && (
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
              Отключённые вами правила и пересечения с активными диапазонами не восстанавливаются и не меняются.
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

function PortServiceFormModal({ open, row, isNew, categoryOptions, onClose, onSaved }) {
  const [transport, setTransport] = useState('tcp');
  const [portMode, setPortMode] = useState('single');
  const [port, setPort] = useState('');
  const [portFrom, setPortFrom] = useState('');
  const [portTo, setPortTo] = useState('');
  const [serviceCode, setServiceCode] = useState('');
  const [serviceName, setServiceName] = useState('');
  const [category, setCategory] = useState('web');
  const [description, setDescription] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  useEffect(() => {
    if (!open) return;
    setFormError('');
    if (isNew) {
      setTransport('tcp');
      setPortMode('single');
      setPort('');
      setPortFrom('');
      setPortTo('');
      setServiceCode('');
      setServiceName('');
      setCategory('web');
      setDescription('');
    } else {
      setTransport(row?.transport || 'tcp');
      const mode = inferPortMode(row);
      setPortMode(mode);
      if (mode === 'single') {
        setPort(String(row?.portFrom ?? ''));
        setPortFrom('');
        setPortTo('');
      } else {
        setPort('');
        setPortFrom(String(row?.portFrom ?? ''));
        setPortTo(String(row?.portTo ?? ''));
      }
      setServiceCode(row?.serviceCode || '');
      setServiceName(row?.serviceName || '');
      setCategory(row?.category || 'web');
      setDescription(row?.description || '');
    }
  }, [open, isNew, row]);

  const validateClient = () => {
    if (!TRANSPORTS.some((t) => t.value === transport)) {
      return 'Выберите транспортный протокол';
    }
    if (portMode === 'single') {
      if (String(port).trim() === '') return 'Укажите порт';
      const p = Number(port);
      if (!Number.isInteger(p) || p < 0 || p > 65535) {
        return 'Укажите порт в диапазоне 0–65535';
      }
    } else {
      if (String(portFrom).trim() === '' || String(portTo).trim() === '') {
        return 'Укажите начало и конец диапазона';
      }
      const from = Number(portFrom);
      const to = Number(portTo);
      if (!Number.isInteger(from) || from < 0 || from > 65535) {
        return 'Укажите начало диапазона в пределах 0–65535';
      }
      if (!Number.isInteger(to) || to < 0 || to > 65535) {
        return 'Укажите конец диапазона в пределах 0–65535';
      }
      if (from > to) return 'Начало диапазона не может быть больше конца';
    }
    const code = serviceCode.trim().toLowerCase();
    if (!code) return 'Укажите код сервиса';
    if (!SERVICE_CODE_RE.test(code)) {
      return 'Код сервиса: только латиница нижнего регистра, цифры и _';
    }
    if (!serviceName.trim()) return 'Укажите название сервиса';
    if (!category.trim()) return 'Укажите категорию';
    return '';
  };

  const handleSave = async () => {
    const errMsg = validateClient();
    if (errMsg) {
      setFormError(errMsg);
      return;
    }

    const payload = {
      transport,
      portMode,
      serviceCode: serviceCode.trim().toLowerCase(),
      serviceName: serviceName.trim(),
      category: category.trim(),
      description: description.trim(),
    };

    if (portMode === 'single') {
      const p = Number(port);
      payload.port = p;
      payload.portFrom = p;
      payload.portTo = p;
    } else {
      payload.portFrom = Number(portFrom);
      payload.portTo = Number(portTo);
    }

    if (!isNew && row) {
      payload.originalTransport = row.transport;
      payload.originalPortFrom = row.portFrom;
      payload.originalPortTo = row.portTo;
    }

    setSaving(true);
    setFormError('');
    try {
      await ApiClient.savePortService(payload);
      onSaved();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  const keyLabel = !isNew && row
    ? `${row.transport}/${row.portLabel}`
    : null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? 'Добавить сервис' : 'Редактировать сервис'}
      subtitle={isNew ? 'Новое правило port → service' : keyLabel}
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
      <div className="grid grid--2col grid--gap-sm">
        <div className="field">
          <label>Транспорт</label>
          <select className="input" value={transport} onChange={(e) => setTransport(e.target.value)}>
            {TRANSPORTS.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Режим порта</label>
          <select
            className="input"
            value={portMode}
            onChange={(e) => {
              const next = e.target.value;
              setPortMode(next);
              if (next === 'range') {
                if (!String(portFrom).trim() && !String(portTo).trim() && String(port).trim()) {
                  setPortFrom(port);
                  setPortTo(port);
                }
              }
            }}
          >
            {PORT_MODES.map((m) => (
              <option key={m.value} value={m.value}>{m.label}</option>
            ))}
          </select>
        </div>
        {portMode === 'single' ? (
          <div className="field" style={{ gridColumn: '1 / -1' }}>
            <label>Порт</label>
            <input
              className="input mono"
              type="number"
              min={0}
              max={65535}
              placeholder="443"
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
          </div>
        ) : (
          <>
            <div className="field">
              <label>Порт от</label>
              <input
                className="input mono"
                type="number"
                min={0}
                max={65535}
                placeholder="8000"
                value={portFrom}
                onChange={(e) => setPortFrom(e.target.value)}
              />
            </div>
            <div className="field">
              <label>Порт до</label>
              <input
                className="input mono"
                type="number"
                min={0}
                max={65535}
                placeholder="8999"
                value={portTo}
                onChange={(e) => setPortTo(e.target.value)}
              />
            </div>
          </>
        )}
        <div className="field">
          <label>Код сервиса</label>
          <input
            className="input mono"
            placeholder="https"
            value={serviceCode}
            onChange={(e) => setServiceCode(e.target.value.toLowerCase())}
          />
        </div>
        <div className="field">
          <label>Название</label>
          <input
            className="input"
            placeholder="HTTPS"
            value={serviceName}
            onChange={(e) => setServiceName(e.target.value)}
          />
        </div>
        <div className="field">
          <label>Категория</label>
          <CategoryCombobox
            key={open ? (isNew ? 'new' : `${row?.transport}-${row?.portFrom}-${row?.portTo}`) : 'closed'}
            value={category}
            onChange={setCategory}
            options={categoryOptions}
          />
        </div>
        <div className="field" style={{ gridColumn: '1 / -1' }}>
          <label>Описание</label>
          <input
            className="input"
            placeholder="Необязательно"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
      </div>
    </Modal>
  );
}

Object.assign(window, { PagePortServices, TRANSPORTS, PORT_MODES });
