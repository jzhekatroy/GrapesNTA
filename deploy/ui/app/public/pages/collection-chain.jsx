/* Цепочка сбора — диагностика потерь по звеньям pipeline */

const { useState, useEffect, useCallback, useMemo } = React;

const WINDOW_OPTIONS = [
  { id: '15m', label: '15 мин' },
  { id: '1h', label: '1 ч' },
  { id: '24h', label: '24 ч' },
];

const STAGE_SEVERITY_CLASS = {
  ok: 'pipeline-stage--ok',
  warning: 'pipeline-stage--warning',
  critical: 'pipeline-stage--critical',
  info: 'pipeline-stage--info',
};

const STAGE_CHART_LABELS = {
  interface: 'Интерфейс',
  collector: 'XDP',
  receiver: 'Приёмник',
  spool: 'Спул',
  clickhouse: 'ClickHouse',
  netflow: 'NetFlow',
  socket: 'Сокет',
};

const PIPELINE_THRESHOLD_STAGES = [
  {
    id: 'interface',
    label: 'Интерфейс',
    description: 'Сбросы на NIC (phy_rx_discards) относительно принятых пакетов.',
    warnKey: 'interfaceWarnPct',
    critKey: 'interfaceCritPct',
    defaultWarn: 0.01,
    defaultCrit: 0.1,
  },
  {
    id: 'collector',
    label: 'Коллектор (XDP)',
    description: 'Потери в BPF: xdp_map_full и xdp_parse_errors.',
    warnKey: 'collectorWarnPct',
    critKey: 'collectorCritPct',
    defaultWarn: 0.01,
    defaultCrit: 0.1,
  },
  {
    id: 'receiver',
    label: 'Коллектор (приёмник)',
    description: 'UDP-очередь и ошибки разбора NetFlow/sFlow (flowcollectord).',
    warnKey: 'receiverWarnPct',
    critKey: 'receiverCritPct',
    defaultWarn: 0.01,
    defaultCrit: 0.1,
  },
  {
    id: 'socket',
    label: 'Сокет получателя NetFlow',
    description: 'Дропы UDP-сокета nfcapd на этом же хосте (nf_socket_drops).',
    warnKey: 'socketWarnPct',
    critKey: 'socketCritPct',
    defaultWarn: 0.1,
    defaultCrit: 1.0,
  },
];

const PIPELINE_FIXED_THRESHOLDS = [
  {
    label: 'Спул',
    description: 'Любое ненулевое spool_corruption_frames сразу считается аварией.',
  },
  {
    label: 'ClickHouse',
    description: 'Любая ошибка INSERT (insert_errs) или сброс очереди writer — авария.',
  },
  {
    label: 'NetFlow-экспорт',
    description: 'Любая ошибка отправки (nf_send_errs) — авария.',
  },
];

function readCollectionChainHash() {
  const { pageId, params } = parseAppHash();
  if (pageId !== 'collection-chain') return { sourceId: '', window: '1h' };
  return {
    sourceId: params.get('source') || '',
    window: params.get('window') || '1h',
  };
}

function writeCollectionChainHash(sourceId, window) {
  const q = new URLSearchParams();
  if (sourceId) q.set('source', sourceId);
  if (window && window !== '1h') q.set('window', window);
  const qs = q.toString();
  location.hash = qs ? `#collection-chain?${qs}` : '#collection-chain';
}

function fmtLossPct(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  const n = Number(value);
  if (n === 0) return '0%';
  if (n < 0.01) return '<0.01%';
  if (n < 1) return `${n.toFixed(3)}%`;
  return `${n.toFixed(2)}%`;
}

function fmtPassPct(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return `${Number(value).toFixed(2)}%`;
}

function PipelineStageArrow({ passPct, label, note }) {
  const title = note
    ? `${label || 'Доля «Прошло»'}: ${fmtPassPct(passPct)}. ${note}`
    : `${label || 'Доля «Прошло» на этом звене'} от «Прошло» на предыдущем (минус потери): ${fmtPassPct(passPct)}`;
  return (
    <div className="pipeline-arrow" title={title}>
      <div className="pipeline-arrow__line" />
      <div className="pipeline-arrow__label">
        <div className="pipeline-arrow__pct">{fmtPassPct(passPct)}</div>
        {label && <div className="pipeline-arrow__hint">{label}</div>}
        {note && <div className="pipeline-arrow__note">{note}</div>}
      </div>
      <div className="pipeline-arrow__head">▼</div>
    </div>
  );
}

function PipelineStageBlock({ stage, onNavigate }) {
  const cls = STAGE_SEVERITY_CLASS[stage.severity] || STAGE_SEVERITY_CLASS.ok;
  return (
    <div className={`pipeline-stage ${cls}${stage.isRootCause ? ' pipeline-stage--root-cause' : ''}`}>
      {stage.isRootCause && (
        <div className="pipeline-stage__root-label">Потери начинаются здесь</div>
      )}
      <div className="pipeline-stage__head">
        <div>
          <div className="pipeline-stage__title">{stage.label}</div>
          {stage.sourceLabel && (
            <div className="pipeline-stage__source">{stage.sourceLabel}</div>
          )}
        </div>
        {stage.isEstimate && (
          <Badge tone="warning">оценка</Badge>
        )}
        {stage.isExclusion && (
          <Badge tone="neutral">отброшено правилами</Badge>
        )}
      </div>
      <div className="pipeline-stage__metrics">
        {!stage.isExclusion && stage.id !== 'socket' && (
          <div className="pipeline-stage__metric">
            <span className="pipeline-stage__metric-label">Прошло</span>
            <span className="pipeline-stage__metric-value mono">{fmtNum(stage.passed)}</span>
          </div>
        )}
        {stage.lost > 0 || stage.id === 'socket' ? (
          <div className="pipeline-stage__metric">
            <span className="pipeline-stage__metric-label">Потеряно</span>
            <span className="pipeline-stage__metric-value mono">{fmtNum(stage.lost)}</span>
            {!stage.isExclusion && (
              <span className="pipeline-stage__metric-pct" title="Потери от предыдущего звена">
                {fmtLossPct(stage.lossPct)}
                <span className="pipeline-stage__metric-pct-hint"> от пред. звена</span>
              </span>
            )}
          </div>
        ) : !stage.isExclusion && (
          <div className="pipeline-stage__metric">
            <span className="pipeline-stage__metric-label">Потери</span>
            <span className="pipeline-stage__metric-value">нет</span>
          </div>
        )}
        {stage.isExclusion && (
          <div className="pipeline-stage__metric">
            <span className="pipeline-stage__metric-label">Объём</span>
            <span className="pipeline-stage__metric-value mono">{fmtNum(stage.passed)}</span>
          </div>
        )}
      </div>
      {stage.isExclusion && typeof onNavigate === 'function' && (
        <div className="pipeline-stage__footer">
          <Button kind="ghost" size="sm" onClick={() => onNavigate('flow-exclusions')}>
            Исключения из статистики
          </Button>
        </div>
      )}
    </div>
  );
}

function PipelineFunnel({ stages, onNavigate }) {
  if (!stages?.length) {
    return (
      <div className="pipeline-funnel pipeline-funnel--empty">
        Нет данных для построения цепочки за выбранное окно.
      </div>
    );
  }

  return (
    <div className="pipeline-funnel">
      {stages.map((stage, idx) => (
        <React.Fragment key={stage.id}>
          {idx > 0 && (
            <PipelineStageArrow
              passPct={stage.passPct}
              label={stage.passPctLabel}
              note={stage.passPctNote}
            />
          )}
          <PipelineStageBlock stage={stage} onNavigate={onNavigate} />
        </React.Fragment>
      ))}
    </div>
  );
}

function PipelineHistoryChart({ history, windowKey, loading }) {
  const stageIds = useMemo(() => {
    const ids = new Set();
    for (const bucket of history?.buckets || []) {
      for (const key of Object.keys(bucket.stages || {})) ids.add(key);
    }
    return [...ids];
  }, [history]);

  const lines = useMemo(() => stageIds.map((id, i) => ({
    key: id,
    label: STAGE_CHART_LABELS[id] || id,
    color: (typeof PROTOCOL_CHART_COLORS !== 'undefined'
      ? PROTOCOL_CHART_COLORS[i % PROTOCOL_CHART_COLORS.length]
      : `hsl(${(i * 47) % 360}, 65%, 55%)`),
  })), [stageIds]);

  const chartPoints = useMemo(() => {
    const buckets = history?.buckets || [];
    const longRange = windowKey === '24h';
    return buckets.map((b) => {
      const d = new Date(b.ts);
      const t = longRange
        ? d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
        : d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
      const pt = { t, ts: b.ts };
      for (const ln of lines) {
        pt[ln.key] = b.stages?.[ln.key] ?? 0;
      }
      return pt;
    });
  }, [history, lines, windowKey]);

  const bucketSeconds = history?.bucketSeconds || 60;

  if (loading) {
    return <div style={{ padding: 24, color: 'var(--fg-secondary)', textAlign: 'center' }}>Загрузка…</div>;
  }

  if (chartPoints.length < 2 || typeof DualChart !== 'function') {
    return (
      <div style={{ padding: 24, color: 'var(--fg-secondary)', textAlign: 'center' }}>
        Недостаточно точек для графика
      </div>
    );
  }

  return (
    <>
      <DualChart
        points={chartPoints}
        lines={lines}
        height={260}
        mode="bw"
        bucketSeconds={bucketSeconds}
        tipUnitLabel="%"
        valueFormatter={(v) => fmtLossPct(v)}
        axisFormatter={(v) => `${Number(v).toFixed(2)}%`}
        yAxisLabel="Потери"
        yAxisUnit="%"
      />
      <div className="row pipeline-history-legend">
        {lines.map((ln) => (
          <span key={ln.key}><span style={{ color: ln.color }}>●</span> {ln.label}</span>
        ))}
      </div>
    </>
  );
}

function PipelineThresholdField({ label, hint, value, onChange, disabled, inputId }) {
  return (
    <div className="field pipeline-thresholds__field">
      <label htmlFor={inputId}>{label}</label>
      {hint && <div className="hint pipeline-thresholds__field-hint">{hint}</div>}
      <div className="pipeline-thresholds__input-wrap">
        <input
          id={inputId}
          className="input"
          type="number"
          step="0.001"
          min="0"
          max="100"
          disabled={disabled}
          value={value}
          onChange={onChange}
        />
        <span className="pipeline-thresholds__unit">%</span>
      </div>
    </div>
  );
}

function PipelineThresholdsPanel({ canWrite, thresholds, onSaved }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (thresholds) setForm({ ...thresholds });
  }, [thresholds]);

  if (!form) return null;

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      await ApiClient.savePipelineThresholds(form);
      pushToast({ kind: 'success', title: 'Пороги сохранены' });
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card title="Пороги потерь" pad="sm" style={{ marginTop: 16 }}>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: open ? 12 : 0 }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          Когда подсвечивать звено жёлтым или красным. Сравнивается доля потерь от предыдущего звена в воронке.
        </div>
        <Button kind="ghost" size="sm" onClick={() => setOpen((v) => !v)}>
          {open ? 'Свернуть' : 'Изменить'}
        </Button>
      </div>
      {open && (
        <>
          {error && <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>}
          <div className="pipeline-thresholds">
            {PIPELINE_THRESHOLD_STAGES.map((stage) => (
              <div key={stage.id} className="pipeline-thresholds__stage">
                <div className="pipeline-thresholds__stage-head">
                  <div className="pipeline-thresholds__stage-title">{stage.label}</div>
                  <div className="pipeline-thresholds__stage-desc">{stage.description}</div>
                </div>
                <div className="pipeline-thresholds__stage-fields">
                  <PipelineThresholdField
                    inputId={`pipeline-threshold-${stage.id}-warn`}
                    label="Предупреждение (жёлтый)"
                    hint={`По умолчанию ${stage.defaultWarn}%`}
                    disabled={!canWrite}
                    value={form[stage.warnKey]}
                    onChange={(e) => setForm((f) => ({ ...f, [stage.warnKey]: e.target.value }))}
                  />
                  <PipelineThresholdField
                    inputId={`pipeline-threshold-${stage.id}-crit`}
                    label="Авария (красный)"
                    hint={`По умолчанию ${stage.defaultCrit}%`}
                    disabled={!canWrite}
                    value={form[stage.critKey]}
                    onChange={(e) => setForm((f) => ({ ...f, [stage.critKey]: e.target.value }))}
                  />
                </div>
              </div>
            ))}

            <div className="pipeline-thresholds__fixed">
              <div className="pipeline-thresholds__fixed-title">Фиксированные правила</div>
              <div className="pipeline-thresholds__fixed-desc">
                Для этих звеньев пороги не настраиваются — любое срабатывание сразу авария:
              </div>
              <ul className="pipeline-thresholds__fixed-list">
                {PIPELINE_FIXED_THRESHOLDS.map((item) => (
                  <li key={item.label}>
                    <span className="pipeline-thresholds__fixed-label">{item.label}</span>
                    {' — '}
                    {item.description}
                  </li>
                ))}
              </ul>
            </div>
          </div>
          {!canWrite && (
            <div className="hint" style={{ marginTop: 12 }}>
              Для изменения порогов нужны права записи на странице «Цепочка сбора».
            </div>
          )}
          {canWrite && (
            <div className="row" style={{ marginTop: 12, justifyContent: 'flex-end' }}>
              <Button kind="primary" onClick={save} disabled={saving}>
                {saving ? 'Сохранение…' : 'Сохранить пороги'}
              </Button>
            </div>
          )}
        </>
      )}
    </Card>
  );
}

function CollectorSourceList({ tree, selectedSourceId, onSelect }) {
  const [collapsed, setCollapsed] = useState({});

  const toggleLoc = (key) => {
    setCollapsed((s) => ({ ...s, [key]: !s[key] }));
  };

  if (!tree?.length) {
    return (
      <div style={{ padding: 12, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
        Нет коллекторов в каталоге
      </div>
    );
  }

  return (
    <div className="collection-chain-list">
      {tree.map((loc) => {
        const locKey = loc.locationId || loc.locationName;
        const isCollapsed = collapsed[locKey];
        return (
          <div key={locKey} className="collection-chain-list__loc">
            <button
              type="button"
              className="collection-chain-list__loc-head"
              onClick={() => toggleLoc(locKey)}
            >
              <span>{isCollapsed ? '▸' : '▾'}</span>
              <span>{loc.locationName}</span>
            </button>
            {!isCollapsed && (loc.collectors || []).map((col) => (
              <div key={col.collectorId} className="collection-chain-list__collector">
                <div className="collection-chain-list__collector-name">{col.displayName}</div>
                {(col.sources || []).map((src) => (
                  <button
                    key={src.sourceId}
                    type="button"
                    className={`collection-chain-list__source${selectedSourceId === src.sourceId ? ' is-active' : ''}`}
                    onClick={() => onSelect(src.sourceId)}
                  >
                    <span className="mono">{src.sourceId}</span>
                    {src.isLive && <span className="collection-chain-list__live" title="Есть live-данные" />}
                  </button>
                ))}
                {!col.sources?.length && (
                  <div className="collection-chain-list__empty">нет экспортёров</div>
                )}
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

function PageCollectionChain({ onNavigate }) {
  const initial = readCollectionChainHash();
  const [windowKey, setWindowKey] = useState(initial.window);
  const [sourceId, setSourceId] = useState(initial.sourceId);
  const [tree, setTree] = useState([]);
  const [pipeline, setPipeline] = useState(null);
  const [history, setHistory] = useState(null);
  const [thresholds, setThresholds] = useState(null);
  const [loadingTree, setLoadingTree] = useState(true);
  const [loadingPipeline, setLoadingPipeline] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [loadError, setLoadError] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const canWrite = AuthAccess.canWritePage('collection-chain');

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoadingTree(true);
      const res = await ApiClient.loadCollectorOverview();
      if (cancelled) return;
      if (res.source === 'error') {
        setLoadError(ApiClient.LOAD_FAILED);
        setTree([]);
      } else {
        setTree(res.data?.locations || []);
        if (!sourceId) {
          const first = (res.data?.locations || [])
            .flatMap((l) => l.collectors || [])
            .flatMap((c) => c.sources || [])[0];
          if (first?.sourceId) setSourceId(first.sourceId);
        }
      }
      setLoadingTree(false);
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  useEffect(() => {
    if (!sourceId) return;
    writeCollectionChainHash(sourceId, windowKey);
  }, [sourceId, windowKey]);

  useEffect(() => {
    let cancelled = false;
    if (!sourceId) return undefined;

    (async () => {
      setLoadingPipeline(true);
      setLoadError(null);
      const [pipeRes, histRes, thrRes] = await Promise.all([
        ApiClient.loadCollectorPipeline(sourceId, windowKey),
        ApiClient.loadCollectorPipelineHistory(sourceId, windowKey),
        ApiClient.loadPipelineThresholds(),
      ]);
      if (cancelled) return;
      if (pipeRes.source === 'error') {
        setLoadError(pipeRes.error || ApiClient.LOAD_FAILED);
        setPipeline(null);
      } else {
        setPipeline(pipeRes.data);
      }
      if (histRes.source !== 'error') setHistory(histRes.data);
      else setHistory(null);
      if (thrRes.source !== 'error') setThresholds(thrRes.data);
      setLoadingPipeline(false);
      setLoadingHistory(false);
    })();

    return () => { cancelled = true; };
  }, [sourceId, windowKey, refreshKey]);

  const handleSelectSource = (id) => {
    setSourceId(id);
  };

  const meta = pipeline?.meta;

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Цепочка сбора</h1>
          <p>Диагностика потерь по звеньям pipeline: где именно теряются пакеты.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload}>Обновить</Button>
        </div>
      </div>

      <div className="collection-chain-layout">
        <Card title="Экспортёры" pad="sm" className="collection-chain-layout__sidebar">
          {loadingTree ? (
            <div style={{ padding: 12, color: 'var(--fg-secondary)' }}>Загрузка…</div>
          ) : (
            <CollectorSourceList
              tree={tree}
              selectedSourceId={sourceId}
              onSelect={handleSelectSource}
            />
          )}
        </Card>

        <div className="collection-chain-layout__main">
          <Card pad="sm" style={{ marginBottom: 16 }}>
            <div className="row" style={{ gap: 12, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ font: 'var(--pv-text-body-2-bold)' }}>
                  {sourceId ? <span className="mono">{sourceId}</span> : 'Выберите экспортёр'}
                </div>
                {meta && (
                  <div style={{ marginTop: 4, font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
                    {meta.collectorId && <>Коллектор: <span className="mono">{meta.collectorId}</span> · </>}
                    {meta.daemon && <>Демон: <span className="mono">{meta.daemon}</span> · </>}
                    {meta.iface && <>IF: <span className="mono">{meta.iface}</span> · </>}
                    Статус: {meta.status || '—'}
                  </div>
                )}
              </div>
              <div className="seg">
                {WINDOW_OPTIONS.map((o) => (
                  <button
                    key={o.id}
                    type="button"
                    className={windowKey === o.id ? 'is-active' : ''}
                    onClick={() => setWindowKey(o.id)}
                  >
                    {o.label}
                  </button>
                ))}
              </div>
            </div>
          </Card>

          {loadError && (
            <div className="form-error" style={{ marginBottom: 16 }}>{loadError}</div>
          )}

          {loadingPipeline && !pipeline ? (
            <Card pad="sm"><div style={{ padding: 24, textAlign: 'center', color: 'var(--fg-secondary)' }}>Загрузка…</div></Card>
          ) : (
            <>
              {pipeline?.insufficientData && (
                <Card pad="sm" style={{ marginBottom: 16 }}>
                  <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
                    Мало snapshots за окно (нужно ≥2). Проверьте, что коллектор пишет в
                    {' '}
                    <span className="mono">collector_health_snapshots</span>
                    .
                  </div>
                </Card>
              )}

              <Card title="Воронка" pad="sm" style={{ marginBottom: 16 }}>
                <PipelineFunnel stages={pipeline?.stages || []} onNavigate={onNavigate} />
              </Card>

              <Card title="История потерь" pad="sm" style={{ marginBottom: 16 }}>
                <PipelineHistoryChart
                  history={history}
                  windowKey={windowKey}
                  loading={loadingHistory}
                />
              </Card>

              <PipelineThresholdsPanel
                canWrite={canWrite}
                thresholds={thresholds}
                onSaved={reload}
              />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { PageCollectionChain });
