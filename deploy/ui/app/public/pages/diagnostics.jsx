/* Диагностика контейнеров / периодических jobs: grapes-worker, grapes-enrichment, SNMP. */

const { useState, useEffect, useCallback } = React;

const DIAG_REFRESH_MS = 15000;
const FAILED_REQUESTS_PAGE_SIZES = [25, 50, 100];
const FAILED_REQUESTS_DEFAULT_LIMIT = 25;

function fmtDiagTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('ru-RU');
  } catch {
    return String(iso);
  }
}

function fmtAge(sec) {
  if (sec == null || !Number.isFinite(Number(sec))) return '—';
  const n = Number(sec);
  if (n < 60) return `${n} с`;
  if (n < 3600) return `${Math.floor(n / 60)} мин`;
  const h = Math.floor(n / 3600);
  const m = Math.floor((n % 3600) / 60);
  return m ? `${h} ч ${m} мин` : `${h} ч`;
}

function fmtBuildDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString('ru-RU', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return String(iso);
  }
}

function workerStatusMeta(worker) {
  if (!worker) return { label: 'неизвестно', color: 'var(--fg-muted)', tone: 'idle' };
  if (worker.alive) return { label: 'работает', color: 'var(--st-success)', tone: 'healthy' };
  if (worker.status === 'stale') return { label: 'нет heartbeat', color: 'var(--st-warning)', tone: 'warning' };
  return { label: 'остановлен', color: 'var(--st-critical)', tone: 'critical' };
}

function matStatusTone(status) {
  const s = String(status || '');
  if (s === 'ok') return 'healthy';
  if (s === 'running') return 'healthy';
  if (s === 'queued' || s === 'lagging' || s === 'idle') return 'warning';
  if (s === 'error') return 'critical';
  return 'idle';
}

function jobStatusTone(status) {
  const s = String(status || '');
  if (s === 'ok') return 'healthy';
  if (s === 'running') return 'healthy';
  if (s === 'skipped' || s === 'idle') return 'warning';
  if (s === 'error') return 'critical';
  return 'idle';
}

function ProblemsBanner({ problems, okText }) {
  if (!problems?.length) {
    return (
      <div style={{
        padding: 12,
        borderRadius: 8,
        background: 'var(--st-success-bg)',
        color: 'var(--fg-primary)',
        font: 'var(--pv-text-body-3)',
      }}>
        {okText || 'Критических проблем не видно.'}
      </div>
    );
  }
  return (
    <div className="col" style={{ gap: 8 }}>
      {problems.map((p) => {
        const bg = p.level === 'critical'
          ? 'var(--st-critical-bg)'
          : 'var(--st-warning-bg)';
        const color = p.level === 'critical' ? 'var(--st-critical)' : 'var(--fg-primary)';
        return (
          <div
            key={`${p.code}-${p.observationId || p.job || p.message}`}
            style={{ padding: 12, borderRadius: 8, background: bg, color, font: 'var(--pv-text-body-3)' }}
          >
            <span className="mono" style={{ opacity: 0.75, marginRight: 8 }}>{p.level}</span>
            {p.message}
          </div>
        );
      })}
    </div>
  );
}

const GAP_PRESETS = [
  { label: 'Сутки', days: 1 },
  { label: '3 дня', days: 3 },
  { label: 'Неделя', days: 7 },
  { label: '2 недели', days: 14 },
];

function fmtMinutes(total) {
  const n = Math.max(0, Math.round(Number(total) || 0));
  if (n < 60) return `${n} мин`;
  const h = Math.floor(n / 60);
  const m = n % 60;
  if (h < 24) return m ? `${h} ч ${m} мин` : `${h} ч`;
  const d = Math.floor(h / 24);
  const hr = h % 24;
  return hr ? `${d} д ${hr} ч` : `${d} д`;
}

function toLocalInputUTC(iso) {
  // datetime-local value in UTC (we treat inputs as UTC)
  if (!iso) return '';
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`
    + `T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

function queueStatusTone(status) {
  const s = String(status || '');
  if (s === 'done') return 'healthy';
  if (s === 'running') return 'healthy';
  if (s === 'pending') return 'warning';
  if (s === 'error') return 'critical';
  if (s === 'cancelled') return 'idle';
  return 'idle';
}

function queueStatusLabel(status) {
  const s = String(status || '');
  return ({
    pending: 'в очереди',
    running: 'идёт пересчёт',
    done: 'готово',
    error: 'ошибка',
    cancelled: 'отменено',
  })[s] || s;
}

function GapsPanel() {
  const [mode, setMode] = useState('preset'); // 'preset' | 'custom'
  const [days, setDays] = useState(3);
  const [fromInput, setFromInput] = useState('');
  const [toInput, setToInput] = useState('');
  const [scan, setScan] = useState(null);
  const [selectedIdx, setSelectedIdx] = useState(() => new Set());
  const [includeObs, setIncludeObs] = useState(true);
  const [queue, setQueue] = useState([]);
  const [busy, setBusy] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');

  const refreshQueue = useCallback(() => {
    return ApiClient.loadWorkerBackfillQueue()
      .then((rows) => setQueue(Array.isArray(rows) ? rows : (rows?.data || [])))
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshQueue();
  }, [refreshQueue]);

  const active = queue.some((r) => r.status === 'pending' || r.status === 'running');

  useEffect(() => {
    if (!active) return undefined;
    const t = setInterval(() => { refreshQueue(); }, 5000);
    return () => clearInterval(t);
  }, [active, refreshQueue]);

  const runScan = useCallback(async (opts) => {
    setBusy(true);
    setErr('');
    setMsg('');
    try {
      const data = await ApiClient.scanWorkerGaps(opts);
      setScan(data);
      setShowDetails(false);
      await refreshQueue();
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }, [refreshQueue]);

  const onPreset = (d) => {
    setMode('preset');
    setDays(d);
    runScan({ days: d });
  };

  const onScanCustom = () => {
    if (!fromInput || !toInput) {
      setErr('Укажите начало и конец диапазона');
      return;
    }
    // Treat datetime-local as UTC.
    runScan({ from: `${fromInput}:00Z`, to: `${toInput}:00Z` });
  };

  const gapWindows = scan?.gapWindows || [];
  const hasGaps = !!scan?.summary?.hasGaps;

  useEffect(() => {
    const gw = scan?.gapWindows || [];
    setSelectedIdx(new Set(gw.map((_, i) => i)));
  }, [scan]);

  const toggleIdx = (i) => setSelectedIdx((prev) => {
    const next = new Set(prev);
    if (next.has(i)) next.delete(i); else next.add(i);
    return next;
  });
  const allSelected = gapWindows.length > 0 && selectedIdx.size === gapWindows.length;
  const toggleAll = () => setSelectedIdx(
    allSelected ? new Set() : new Set(gapWindows.map((_, i) => i)),
  );
  const selectedWindows = gapWindows.filter((_, i) => selectedIdx.has(i));
  const selectedMinutes = selectedWindows.reduce((s, w) => s + (w.minutes || 0), 0);

  const enqueue = async (windows, label) => {
    if (!windows.length) return;
    setBusy(true);
    setErr('');
    setMsg('');
    try {
      const body = await ApiClient.enqueueWorkerBackfill({
        ranges: windows.map((w) => ({ from: w.from, to: w.to })),
        includeObservations: includeObs,
      });
      setMsg(`${label}: окон ${body.enqueued ?? windows.length} · ${fmtMinutes(body.totalMinutes)}`);
      await refreshQueue();
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  };

  const onBackfill = async () => {
    if (!selectedWindows.length) {
      setErr('Отметьте хотя бы одну дыру для пересчёта');
      return;
    }
    const ok = window.confirm(
      `Пересчитать выбранные дыры?\n\n`
      + `Окон: ${selectedWindows.length} из ${gapWindows.length}\n`
      + `Суммарно: ${fmtMinutes(selectedMinutes)}\n\n`
      + 'Worker берёт задачи из очереди по одной и перезаписывает бакеты (delete+insert) —\n'
      + 'данные обновляются по мере прохождения, старые значения не задваиваются.',
    );
    if (!ok) return;
    await enqueue(selectedWindows, 'Поставлено в очередь');
  };

  const onBackfillCustomRange = async () => {
    if (!fromInput || !toInput) {
      setErr('Укажите начало и конец диапазона');
      return;
    }
    const from = `${fromInput}:00Z`;
    const to = `${toInput}:00Z`;
    const mins = Math.round((Date.parse(to) - Date.parse(from)) / 60000);
    if (!(mins > 0)) {
      setErr('Конец диапазона должен быть позже начала');
      return;
    }
    const ok = window.confirm(
      `Пересчитать весь указанный диапазон (не только дыры)?\n\n`
      + `${fmtDiagTime(from)} → ${fmtDiagTime(to)}\n`
      + `${fmtMinutes(mins)}\n\n`
      + 'Все бакеты в диапазоне будут перезаписаны (delete+insert), без задвоения.',
    );
    if (!ok) return;
    await enqueue([{ from, to, minutes: mins }], 'Диапазон в очереди');
  };

  const onCancel = async () => {
    if (!window.confirm('Отменить текущий пересчёт? Уже записанные бакеты останутся, остальное не будет досчитано.')) return;
    setBusy(true);
    setErr('');
    try {
      const body = await ApiClient.cancelWorkerBackfill();
      setMsg(`Отменено запросов: ${body.cancelled ?? 0}`);
      await refreshQueue();
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  };

  const trafficGaps = (scan?.traffic || []).filter((t) => (t.missingCount || 0) > 0 || t.error);
  const obsGaps = (scan?.observations || []).filter((o) => (o.missingCount || 0) > 0);
  const recent = queue.slice(0, 6);

  return (
    <Card title="Дыры в агрегатах">
      <div className="col" style={{ gap: 12, font: 'var(--pv-text-body-3)' }}>
        <div style={{ color: 'var(--fg-secondary)' }}>
          Скан ищет пропущенные минутные бакеты <span className="mono">traffic_*_1m</span> и 5-мин
          бакеты наблюдений <em>внутри</em> периода с данными (края без данных не считаются дырой).
          «Пересчитать» ставит в очередь только найденные окна — worker забирает их перед live-rollup.
        </div>

        {/* Диапазон проверки */}
        <div className="row" style={{ gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {GAP_PRESETS.map((p) => (
            <button
              key={p.days}
              type="button"
              className={`btn${mode === 'preset' && days === p.days ? ' btn--primary' : ''}`}
              onClick={() => onPreset(p.days)}
              disabled={busy}
            >
              {p.label}
            </button>
          ))}
          <button
            type="button"
            className={`btn${mode === 'custom' ? ' btn--primary' : ''}`}
            onClick={() => setMode(mode === 'custom' ? 'preset' : 'custom')}
            disabled={busy}
          >
            Свой диапазон
          </button>
        </div>

        {mode === 'custom' && (
          <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <label className="col" style={{ gap: 2 }}>
              <span style={{ color: 'var(--fg-muted)' }}>с (UTC)</span>
              <input
                type="datetime-local"
                className="input"
                value={fromInput}
                disabled={busy}
                onChange={(e) => setFromInput(e.target.value)}
              />
            </label>
            <label className="col" style={{ gap: 2 }}>
              <span style={{ color: 'var(--fg-muted)' }}>по (UTC)</span>
              <input
                type="datetime-local"
                className="input"
                value={toInput}
                disabled={busy}
                onChange={(e) => setToInput(e.target.value)}
              />
            </label>
            <button type="button" className="btn" onClick={onScanCustom} disabled={busy}>
              {busy ? '…' : 'Просканировать'}
            </button>
            <button
              type="button"
              className="btn"
              onClick={onBackfillCustomRange}
              disabled={busy || active}
              title="Перезаписать весь указанный диапазон целиком (не только дыры)"
            >
              Пересчитать весь диапазон
            </button>
          </div>
        )}

        {err && <div style={{ color: 'var(--st-critical)' }}>{err}</div>}
        {msg && <div style={{ color: 'var(--st-success)' }}>{msg}</div>}

        {/* Результат скана */}
        {scan && (
          <div className="col" style={{ gap: 8 }}>
            <div style={{ color: 'var(--fg-muted)' }}>
              Проверено: <span className="mono">{fmtDiagTime(scan.window?.from)}</span>
              {' → '}<span className="mono">{fmtDiagTime(scan.window?.to)}</span>
              {' · скан '}<span className="mono">{fmtDiagTime(scan.scannedAt)}</span>
            </div>

            {!hasGaps && (
              <div style={{
                padding: 10, borderRadius: 8,
                background: 'var(--st-success-bg)', color: 'var(--fg-primary)',
              }}>
                Дыр за выбранный период не найдено.
              </div>
            )}

            {hasGaps && (
              <div className="col" style={{ gap: 8 }}>
                <div style={{
                  padding: 10, borderRadius: 8,
                  background: 'var(--st-warning-bg)', color: 'var(--fg-primary)',
                }}>
                  Найдено окон дыр: <b>{scan.summary.windowCount}</b>
                  {' · суммарно '}<b>{fmtMinutes(scan.summary.totalGapMinutes)}</b>
                  {' · traffic jobs '}<span className="mono">{scan.summary.trafficJobsWithGaps}</span>
                  {', наблюдений '}<span className="mono">{scan.summary.observationJobsWithGaps}</span>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr>
                        <th style={{ textAlign: 'center', padding: 6, color: 'var(--fg-muted)', width: 34 }}>
                          <input
                            type="checkbox"
                            checked={allSelected}
                            onChange={toggleAll}
                            disabled={busy}
                            title="Выбрать все / снять все"
                          />
                        </th>
                        <th style={{ textAlign: 'left', padding: 6, color: 'var(--fg-muted)' }}>#</th>
                        <th style={{ textAlign: 'left', padding: 6, color: 'var(--fg-muted)' }}>окно дыры (UTC → локальное)</th>
                        <th style={{ textAlign: 'right', padding: 6, color: 'var(--fg-muted)' }}>длительность</th>
                      </tr>
                    </thead>
                    <tbody>
                      {gapWindows.map((w, i) => (
                        <tr key={`${w.from}-${i}`}>
                          <td style={{ padding: 6, textAlign: 'center' }}>
                            <input
                              type="checkbox"
                              checked={selectedIdx.has(i)}
                              onChange={() => toggleIdx(i)}
                              disabled={busy}
                            />
                          </td>
                          <td style={{ padding: 6 }} className="mono">{i + 1}</td>
                          <td style={{ padding: 6 }}>
                            {fmtDiagTime(w.from)} <span style={{ color: 'var(--fg-muted)' }}>→</span> {fmtDiagTime(w.to)}
                          </td>
                          <td style={{ padding: 6, textAlign: 'right' }} className="mono">{fmtMinutes(w.minutes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  <button
                    type="button"
                    className="btn btn--primary"
                    onClick={onBackfill}
                    disabled={busy || active || selectedWindows.length === 0}
                    title={active ? 'Дождитесь завершения текущего пересчёта' : 'Пересчитать отмеченные дыры'}
                  >
                    Пересчитать выбранные ({selectedWindows.length}{selectedWindows.length ? ` · ${fmtMinutes(selectedMinutes)}` : ''})
                  </button>
                  <label className="row" style={{ gap: 6, alignItems: 'center' }}
                    title="Пересчёт наблюдений тяжелее — перематывает курсоры и досчитывает до 24 ч назад">
                    <input
                      type="checkbox"
                      checked={includeObs}
                      onChange={(e) => setIncludeObs(e.target.checked)}
                      disabled={busy}
                    />
                    <span>включая наблюдения</span>
                  </label>
                  {(trafficGaps.length > 0 || obsGaps.length > 0) && (
                    <button type="button" className="btn" onClick={() => setShowDetails((v) => !v)}>
                      {showDetails ? 'Скрыть детали' : 'Детали по jobs'}
                    </button>
                  )}
                </div>

                {showDetails && (trafficGaps.length > 0 || obsGaps.length > 0) && (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr>
                          <th style={{ textAlign: 'left', padding: 6, color: 'var(--fg-muted)' }}>job / наблюдение</th>
                          <th style={{ textAlign: 'right', padding: 6, color: 'var(--fg-muted)' }}>дыр</th>
                          <th style={{ textAlign: 'left', padding: 6, color: 'var(--fg-muted)' }}>диапазоны (до 3)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {trafficGaps.map((t) => (
                          <tr key={t.job}>
                            <td style={{ padding: 6 }} className="mono">{t.job}</td>
                            <td style={{ padding: 6, textAlign: 'right' }} className="mono">
                              {t.error ? 'err' : t.missingCount}
                            </td>
                            <td style={{ padding: 6, color: 'var(--fg-secondary)' }}>
                              {t.error || (t.ranges || []).slice(0, 3).map((r) => (
                                `${fmtDiagTime(r.from)}→${fmtDiagTime(r.toExclusive)}`
                              )).join('; ') || '—'}
                            </td>
                          </tr>
                        ))}
                        {obsGaps.map((o) => (
                          <tr key={o.id}>
                            <td style={{ padding: 6 }}>
                              obs · {o.name}
                              <div className="mono" style={{ color: 'var(--fg-muted)' }}>{o.id}</div>
                            </td>
                            <td style={{ padding: 6, textAlign: 'right' }} className="mono">{o.missingCount}</td>
                            <td style={{ padding: 6, color: 'var(--fg-secondary)' }}>
                              {(o.ranges || []).slice(0, 3).map((r) => (
                                `${fmtDiagTime(r.from)}→${fmtDiagTime(r.toExclusive)}`
                              )).join('; ') || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Очередь / прогресс пересчёта */}
        {recent.length > 0 && (
          <div className="col" style={{ gap: 8 }}>
            <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: 'var(--fg-muted)' }}>
                Пересчёт{active ? ' — идёт (обновление данных на лету)' : ''}
              </span>
              {active && (
                <button type="button" className="btn" onClick={onCancel} disabled={busy}>
                  Отменить
                </button>
              )}
            </div>
            {recent.map((r) => {
              const pct = Number.isFinite(Number(r.percent)) ? Number(r.percent) : null;
              const isActive = r.status === 'pending' || r.status === 'running';
              return (
                <div key={r.requestId} className="col" style={{
                  gap: 4, padding: 8, borderRadius: 8, background: 'var(--surf-2)',
                }}>
                  <div className="row" style={{ gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                    <StatusIndicator status={queueStatusTone(r.status)} label={queueStatusLabel(r.status)} />
                    <span>{fmtDiagTime(r.fromMinute)} → {fmtDiagTime(r.toMinute)}</span>
                    {pct != null && <span className="mono" style={{ color: 'var(--fg-secondary)' }}>{pct}%</span>}
                    {r.progressJob && r.status === 'running' && (
                      <span style={{ color: 'var(--fg-secondary)' }}>
                        сейчас: <span className="mono">{r.progressJob}</span> @ {fmtDiagTime(r.progressMinute)}
                      </span>
                    )}
                  </div>
                  {pct != null && (r.status === 'running' || r.status === 'done') && (
                    <div style={{
                      height: 6, borderRadius: 4, overflow: 'hidden',
                      background: 'rgba(127,127,127,.25)',
                    }}>
                      <div style={{
                        width: `${pct}%`, height: '100%',
                        background: r.status === 'done' ? 'var(--st-success)' : 'var(--accent, #3b82f6)',
                        transition: 'width .4s ease',
                      }} />
                    </div>
                  )}
                  {r.error && <span style={{ color: r.status === 'cancelled' ? 'var(--fg-muted)' : 'var(--st-critical)' }}>{r.error}</span>}
                  {isActive && (
                    <span className="mono" style={{ color: 'var(--fg-muted)', fontSize: 11 }}>{r.requestId}</span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Card>
  );
}

function WorkerPanel({ data, loading, onReload }) {
  const [expandedId, setExpandedId] = useState(null);
  const worker = data?.worker;
  const status = workerStatusMeta(worker);
  const jobs = data?.observations?.jobs || [];
  const traffic = data?.trafficRollups?.rows || [];
  const summary = data?.summary || {};

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', maxWidth: 720 }}>
          Контейнер <span className="mono">grapes-worker</span>: analytics loop (наблюдения) + traffic/ASN rollups.
          Статус из ClickHouse heartbeat и таблиц состояния — без доступа к Docker daemon.
        </div>
        <button type="button" className="btn" onClick={onReload} disabled={loading}>
          {loading && !data ? 'загрузка…' : 'Обновить'}
        </button>
      </div>

      <ProblemsBanner
        problems={data?.problems}
        okText="Критических проблем не видно. Worker отвечает, jobs без явных ошибок."
      />

      <div className="grid grid--auto-fit-md grid--gap-sm" style={{ font: 'var(--pv-text-body-3)' }}>
        <Card title="Сводка">
          <div className="col" style={{ gap: 6 }}>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--fg-muted)' }}>Worker</span>
              <StatusIndicator status={status.tone} label={status.label} />
            </div>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--fg-muted)' }}>Проблемы</span>
              <span className="mono">
                {summary.criticalCount || 0} crit / {summary.problemCount || 0} всего
              </span>
            </div>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--fg-muted)' }}>Obs jobs (воркер берёт)</span>
              <span className="mono">{summary.workerWillPick ?? 0} / {summary.observationJobs ?? 0}</span>
            </div>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--fg-muted)' }}>Dashboard 1m lag</span>
              <span className="mono">{fmtAge(summary.dashboardLagSec)}</span>
            </div>
          </div>
        </Card>

        <Card title="Процесс analytics">
          <div className="grid grid--auto-fit-md grid--gap-sm" style={{ font: 'var(--pv-text-body-3)' }}>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Статус</div>
              <div style={{ font: 'var(--pv-text-body-2-bold)', color: status.color }}>{status.label}</div>
              {worker?.statusReason && (
                <div style={{ color: 'var(--fg-secondary)', marginTop: 2 }}>{worker.statusReason}</div>
              )}
            </div>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Источник</div>
              <div className="mono">
                {worker?.source === 'clickhouse' ? 'ClickHouse' : worker?.source === 'file' ? 'локальный файл' : (worker?.source || '—')}
              </div>
            </div>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Host / PID</div>
              <div className="mono">{worker?.host || '—'} · {worker?.pid ?? '—'}</div>
            </div>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Heartbeat</div>
              <div>{fmtDiagTime(worker?.lastHeartbeatAt)}</div>
              <div style={{ color: 'var(--fg-secondary)' }}>{fmtAge(worker?.heartbeatAgeSec)} назад</div>
            </div>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Последний tick</div>
              <div>{fmtDiagTime(worker?.lastTickAt)}</div>
              <div style={{ color: 'var(--fg-secondary)' }}>
                {worker?.lastTickMs != null ? `${worker.lastTickMs} мс` : '—'}
              </div>
            </div>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Запущен</div>
              <div>{fmtDiagTime(worker?.startedAt)}</div>
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <div style={{ color: 'var(--fg-muted)' }}>Ошибка tick</div>
              <div style={{ color: worker?.lastError ? 'var(--st-critical)' : 'inherit' }}>{worker?.lastError || '—'}</div>
            </div>
          </div>
          {data?.lastTick && (worker?.lastError || data.lastTick.error
            || (Array.isArray(data.lastTick.rollup)
              && data.lastTick.rollup.some((x) => x && !x.skipped && (x.error || x.points != null)))) && (
            <pre style={{
              marginTop: 12,
              padding: 10,
              borderRadius: 8,
              background: 'var(--surf-2)',
              font: 'var(--pv-text-body-3)',
              overflow: 'auto',
              maxHeight: 220,
            }}>
              {JSON.stringify(data.lastTick, null, 2)}
            </pre>
          )}
        </Card>
      </div>

      <Card title="Наблюдения — materialize / почему не берёт воркер">
        <div style={{ marginBottom: 8, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          Показаны наблюдения с включённым live или materialize. Колонка «воркер» —
          реально ли job попадает в loop (`materialize.enabled` + нужны фильтры/groupBy).
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', padding: 6 }}>Наблюдение</th>
                <th style={{ textAlign: 'left', padding: 6 }}>воркер</th>
                <th style={{ textAlign: 'left', padding: 6 }}>status</th>
                <th style={{ textAlign: 'left', padding: 6 }}>cursor / catch-up</th>
                <th style={{ textAlign: 'right', padding: 6 }}>lag</th>
                <th style={{ textAlign: 'left', padding: 6 }}>max minute CH</th>
                <th style={{ textAlign: 'left', padding: 6 }}>причина / ошибка</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => {
                const reason = j.materialize?.lastError
                  || j.skipReason
                  || j.scope?.reason
                  || (j.lastTickResult?.error ? String(j.lastTickResult.error) : null)
                  || '—';
                const bad = Boolean(j.materialize?.lastError || (j.liveEnabled && j.skipReason) || j.materialize?.status === 'error');
                return (
                  <tr key={j.id} style={{ background: bad ? 'var(--st-critical-bg)' : 'transparent' }}>
                    <td style={{ padding: 6 }}>
                      <div style={{ font: 'var(--pv-text-body-2-bold)' }}>{j.name}</div>
                      <div className="mono" style={{ color: 'var(--fg-muted)', fontSize: 11 }}>{j.id}</div>
                      <div style={{ color: 'var(--fg-secondary)' }}>
                        live={j.liveEnabled ? 'on' : 'off'} · mat={j.materializeEnabled ? 'on' : 'off'}
                      </div>
                    </td>
                    <td style={{ padding: 6 }}>
                      {j.workerWillPick
                        ? <StatusIndicator status="healthy" label="берёт" />
                        : <StatusIndicator status="warning" label="пропуск" />}
                    </td>
                    <td style={{ padding: 6 }}>
                      <StatusIndicator
                        status={matStatusTone(j.materialize?.status)}
                        label={j.materialize?.status || '—'}
                      />
                    </td>
                    <td style={{ padding: 6 }} className="mono">
                      <div>{fmtDiagTime(j.materialize?.cursorMinute)}</div>
                      <div style={{ color: 'var(--fg-secondary)' }}>
                        catch-up {fmtDiagTime(j.materialize?.lastCatchupAt)}
                        {j.materialize?.lastCatchupAgeSec != null
                          ? ` (${fmtAge(j.materialize.lastCatchupAgeSec)})`
                          : ''}
                      </div>
                    </td>
                    <td style={{ padding: 6, textAlign: 'right' }} className="mono">
                      {j.materialize?.lagSeconds ?? '—'}
                    </td>
                    <td style={{ padding: 6 }} className="mono">
                      {fmtDiagTime(j.rollup?.maxMinute)}
                      {j.rollup?.rowCount != null && (
                        <div style={{ color: 'var(--fg-secondary)' }}>{j.rollup.rowCount} rows</div>
                      )}
                    </td>
                    <td style={{
                      padding: 6,
                      color: bad ? 'var(--st-critical)' : 'var(--fg-secondary)',
                      maxWidth: 320,
                      wordBreak: 'break-word',
                    }}>
                      {reason}
                    </td>
                  </tr>
                );
              })}
              {!loading && !jobs.length && (
                <tr>
                  <td colSpan={7} style={{ padding: 8, color: 'var(--fg-secondary)' }}>
                    Нет наблюдений с live/materialize
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {data?.observations?.rollupStatsError && (
          <div style={{ marginTop: 8, color: 'var(--st-warning)', font: 'var(--pv-text-body-3)' }}>
            CH rollup stats: {data.observations.rollupStatsError}
          </div>
        )}
      </Card>

      <GapsPanel />

      <Card title="Traffic / ASN / client rollups (только активные jobs worker)">
        <div style={{ marginBottom: 8, color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
          Без legacy IP talker/pair. Включая клиентские витрины кабинета
          (<span className="mono">traffic_client_*</span>, <span className="mono">dns_client_domain_1h</span>).
          Для 1h/1d смотри «обновлён» — бакет вчерашнего дня днём нормален.
        </div>
        {data?.trafficRollups?.error && (
          <div style={{ marginBottom: 8, color: 'var(--st-critical)', font: 'var(--pv-text-body-3)' }}>
            {data.trafficRollups.error}
          </div>
        )}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', padding: 6 }}>job</th>
                <th style={{ textAlign: 'left', padding: 6 }}>status</th>
                <th style={{ textAlign: 'left', padding: 6 }}>last_bucket</th>
                <th style={{ textAlign: 'right', padding: 6 }}>возраст бакета</th>
                <th style={{ textAlign: 'right', padding: 6 }}>обновлён</th>
                <th style={{ textAlign: 'right', padding: 6 }}>duration</th>
                <th style={{ textAlign: 'left', padding: 6 }}>error</th>
              </tr>
            </thead>
            <tbody>
              {traffic.map((r) => (
                <tr key={r.job} style={{ background: r.stale || r.status === 'failed' ? 'var(--st-warning-bg)' : 'transparent' }}>
                  <td style={{ padding: 6 }} className="mono">{r.job}</td>
                  <td style={{ padding: 6 }}>
                    <StatusIndicator
                      status={r.status === 'ok' && !r.stale ? 'healthy' : (r.status === 'failed' ? 'critical' : 'warning')}
                      label={r.stale && r.status === 'ok' ? 'stale' : (r.status || '—')}
                    />
                  </td>
                  <td style={{ padding: 6 }} className="mono">{fmtDiagTime(r.lastBucket)}</td>
                  <td style={{ padding: 6, textAlign: 'right' }} className="mono">{fmtAge(r.bucketLagSec)}</td>
                  <td style={{ padding: 6, textAlign: 'right' }} className="mono">{fmtAge(r.updateAgeSec)}</td>
                  <td style={{ padding: 6, textAlign: 'right' }} className="mono">
                    {r.durationMs != null ? `${r.durationMs} мс` : '—'}
                  </td>
                  <td style={{ padding: 6, color: r.lastError ? 'var(--st-critical)' : 'var(--fg-secondary)' }}>
                    {r.lastError || '—'}
                  </td>
                </tr>
              ))}
              {!loading && !traffic.length && (
                <tr>
                  <td colSpan={7} style={{ padding: 8, color: 'var(--fg-secondary)' }}>
                    Нет активных traffic jobs
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Последние запросы">
        <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: 6 }}>время</th>
              <th style={{ textAlign: 'left', padding: 6 }}>имя</th>
              <th style={{ textAlign: 'right', padding: 6 }}>мс</th>
              <th style={{ textAlign: 'right', padding: 6 }}>строк</th>
              <th style={{ textAlign: 'left', padding: 6 }}>ошибка</th>
            </tr>
          </thead>
          <tbody>
            {(data?.recentQueries || data?.queries || []).map((q) => (
              <React.Fragment key={q.id}>
                <tr
                  onClick={() => setExpandedId((cur) => (cur === q.id ? null : q.id))}
                  style={{ cursor: 'pointer', background: expandedId === q.id ? 'var(--surf-2)' : 'transparent' }}
                >
                  <td style={{ padding: 6 }} className="mono">{fmtDiagTime(q.at)}</td>
                  <td style={{ padding: 6 }} className="mono">{q.name}</td>
                  <td style={{ padding: 6, textAlign: 'right' }} className="mono">{q.elapsedMs}</td>
                  <td style={{ padding: 6, textAlign: 'right' }} className="mono">{q.rows}</td>
                  <td style={{ padding: 6, color: q.error ? 'var(--st-critical)' : 'var(--fg-secondary)' }}>
                    {q.error || '—'}
                  </td>
                </tr>
                {expandedId === q.id && (
                  <tr>
                    <td colSpan={5} style={{ padding: '8px 6px 12px' }}>
                      <pre style={{
                        margin: 0,
                        padding: 10,
                        borderRadius: 8,
                        background: 'var(--surf-1)',
                        border: '1px solid var(--bd-soft)',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        font: 'var(--pv-text-body-3)',
                        maxHeight: 360,
                        overflow: 'auto',
                      }}>
                        {q.sql}
                        {'\n\n-- params\n'}
                        {JSON.stringify(q.params || {}, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
            {!loading && !(data?.recentQueries || data?.queries || []).length && (
              <tr>
                <td colSpan={5} style={{ padding: 8, color: 'var(--fg-secondary)' }}>
                  Запросов пока нет — воркер не писал диагностику
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function EnrichmentPanel({ data, loading, onReload }) {
  const [openLog, setOpenLog] = useState(null);
  const jobs = data?.jobs || [];
  const tables = data?.tables || {};
  const summary = data?.summary || {};

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', maxWidth: 720 }}>
          Контейнер <span className="mono">grapes-enrichment</span>: geoloaderd (FTP/RIR), bgp-origin, asn-names.
          Статус прогонов в <span className="mono">enrichment_job_status</span> + counts целевых таблиц.
        </div>
        <button type="button" className="btn" onClick={onReload} disabled={loading}>
          {loading && !data ? 'загрузка…' : 'Обновить'}
        </button>
      </div>

      <ProblemsBanner
        problems={data?.problems}
        okText="Критических проблем не видно. Enrichment jobs без ошибок."
      />

      <Card title="Сводка">
        <div className="row" style={{ gap: 24, flexWrap: 'wrap', font: 'var(--pv-text-body-3)' }}>
          <div>ok: <span className="mono">{summary.ok ?? 0}</span></div>
          <div>running: <span className="mono">{summary.running ?? 0}</span></div>
          <div>errors: <span className="mono">{summary.errors ?? 0}</span></div>
          <div>problems: <span className="mono">{summary.problemCount ?? 0}</span></div>
        </div>
      </Card>

      {jobs.map((j) => (
        <Card key={j.id} title={j.label}>
          <div className="grid grid--auto-fit-md grid--gap-sm" style={{ font: 'var(--pv-text-body-3)' }}>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Статус</div>
              <StatusIndicator status={jobStatusTone(j.status)} label={j.status || 'idle'} />
              {j.stale && <div style={{ color: 'var(--st-warning)', marginTop: 4 }}>давно не обновлялся</div>}
            </div>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Интервал</div>
              <div className="mono">{fmtAge(j.intervalSec)}</div>
            </div>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Последний прогон</div>
              <div>{fmtDiagTime(j.finishedAt || j.updatedAt)}</div>
              <div style={{ color: 'var(--fg-secondary)' }}>{fmtAge(j.finishAgeSec)} назад</div>
            </div>
            <div>
              <div style={{ color: 'var(--fg-muted)' }}>Длительность / exit</div>
              <div className="mono">
                {j.durationMs != null ? `${j.durationMs} мс` : '—'}
                {' · '}
                {j.exitCode != null ? j.exitCode : '—'}
              </div>
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <div style={{ color: 'var(--fg-muted)' }}>Сообщение</div>
              <div style={{ color: j.status === 'error' ? 'var(--st-critical)' : 'inherit' }}>{j.message || '—'}</div>
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <div style={{ color: 'var(--fg-muted)', marginBottom: 4 }}>Таблицы</div>
              <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
                {(j.tables || []).map((t) => (
                  <div key={t.table} className="mono">
                    {t.table}: {t.count == null ? '?' : t.count}
                    {t.ageSec != null ? ` · ${fmtAge(t.ageSec)}` : ''}
                    {t.error ? ` · err` : ''}
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div style={{ marginTop: 10 }}>
            <button
              type="button"
              className="btn"
              onClick={() => setOpenLog((cur) => (cur === j.id ? null : j.id))}
              disabled={!j.logTail}
            >
              {openLog === j.id ? 'Скрыть лог' : (j.logTail ? 'Показать лог' : 'Лога нет')}
            </button>
          </div>
          {openLog === j.id && j.logTail && (
            <pre style={{
              marginTop: 10,
              padding: 10,
              borderRadius: 8,
              background: 'var(--surf-2)',
              font: 'var(--pv-text-body-3)',
              overflow: 'auto',
              maxHeight: 360,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}>
              {j.logTail}
            </pre>
          )}
        </Card>
      ))}

      <Card title="Целевые таблицы (live)">
        <table style={{ width: '100%', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: 6 }}>таблица</th>
              <th style={{ textAlign: 'right', padding: 6 }}>count</th>
              <th style={{ textAlign: 'left', padding: 6 }}>max ts</th>
              <th style={{ textAlign: 'right', padding: 6 }}>возраст</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(tables).map(([name, t]) => (
              <tr key={name}>
                <td style={{ padding: 6 }} className="mono">{name}</td>
                <td style={{ padding: 6, textAlign: 'right' }} className="mono">
                  {t.count == null ? '—' : t.count}
                </td>
                <td style={{ padding: 6 }} className="mono">{fmtDiagTime(t.maxTs)}</td>
                <td style={{ padding: 6, textAlign: 'right' }} className="mono">{fmtAge(t.ageSec)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function SnmpPanel({ data, loading, onReload }) {
  const job = data?.job;
  const agents = data?.agents || {};
  const settings = data?.settings || {};
  const interfaces = data?.interfaces || {};
  const problems = data?.problems || [];
  const summary = data?.summary || {};
  const tone = jobStatusTone(job?.status);

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', maxWidth: 760 }}>
          Джоба <span className="mono">snmp-iface-sync</span> внутри <span className="mono">grapes-enrichment</span>:
          discovery sFlow exporters + SNMP v2c poll каталога интерфейсов.
          «Опросить всех» на странице SNMP только ставит агентов в очередь — этот поллер забирает их по таймеру (~1 мин, до 25 за цикл).
        </div>
        <Button kind="ghost" icon="refresh" onClick={onReload} disabled={loading}>
          {loading ? 'Обновление…' : 'Обновить'}
        </Button>
      </div>

      <ProblemsBanner
        problems={problems}
        okText="SNMP-поллер и опросы выглядят нормально."
      />

      <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
        {[
          ['job', job?.status || '—', tone],
          ['enabled', summary.agentsEnabled ?? '—', 'idle'],
          ['ok', summary.agentsOk ?? '—', 'healthy'],
          ['timeout', summary.agentsTimeout ?? '—', (summary.agentsTimeout || 0) > 0 ? 'critical' : 'idle'],
          ['queued', summary.agentsQueued ?? '—', (summary.agentsQueued || 0) > 0 ? 'warning' : 'idle'],
          ['interfaces', summary.interfaces ?? '—', (summary.interfaces || 0) > 0 ? 'healthy' : 'warning'],
        ].map(([k, v, t]) => (
          <div
            key={k}
            style={{
              minWidth: 110,
              padding: '10px 12px',
              borderRadius: 8,
              background: t === 'critical' ? 'var(--st-critical-bg)'
                : t === 'warning' ? 'var(--st-warning-bg)'
                  : t === 'healthy' ? 'var(--st-success-bg)' : 'var(--bg-secondary)',
            }}
          >
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{k}</div>
            <div className="mono" style={{ font: 'var(--pv-text-body-2-bold)' }}>{String(v)}</div>
          </div>
        ))}
      </div>

      <Card title="snmp-iface-sync">
        {!job ? (
          <div style={{ color: 'var(--fg-secondary)' }}>Нет данных</div>
        ) : (
          <div className="col" style={{ gap: 8, font: 'var(--pv-text-body-3)' }}>
            <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
              <span>status: <b className="mono">{job.status}</b></span>
              <span>exit: <span className="mono">{job.exitCode ?? '—'}</span></span>
              <span>duration: <span className="mono">{job.durationMs != null ? `${job.durationMs} ms` : '—'}</span></span>
              <span>возраст: <span className="mono">{fmtAge(job.finishAgeSec)}</span></span>
            </div>
            <div>finished: <span className="mono">{fmtDiagTime(job.finishedAt)}</span></div>
            <div>message: <span className="mono">{job.message || '—'}</span></div>
            {job.logTail ? (
              <pre style={{
                margin: 0,
                padding: 10,
                borderRadius: 8,
                background: 'var(--bg-secondary)',
                whiteSpace: 'pre-wrap',
                maxHeight: 220,
                overflow: 'auto',
                font: 'var(--pv-text-code)',
              }}
              >
                {job.logTail}
              </pre>
            ) : null}
          </div>
        )}
      </Card>

      <Card title="Настройки / агенты / интерфейсы">
        <div className="col" style={{ gap: 10, font: 'var(--pv-text-body-3)' }}>
          <div>
            settings: enabled=<span className="mono">{String(!!settings.enabled)}</span>
            {' · '}community=<span className="mono">{settings.hasCommunity ? 'задан' : 'пусто'}</span>
            {' · '}port=<span className="mono">{settings.port ?? '—'}</span>
            {' · '}timeout_ms=<span className="mono">{settings.timeoutMs ?? '—'}</span>
            {' · '}refresh=<span className="mono">{settings.refreshIntervalSec ?? '—'}s</span>
          </div>
          <div>
            agents: total=<span className="mono">{agents.total ?? 0}</span>
            {' · '}enabled=<span className="mono">{agents.enabled ?? 0}</span>
            {' · '}ok=<span className="mono">{agents.ok ?? 0}</span>
            {' · '}queued=<span className="mono">{agents.queued ?? 0}</span>
            {' · '}timeout=<span className="mono">{agents.timeout ?? 0}</span>
            {' · '}auth=<span className="mono">{agents.authError ?? 0}</span>
            {' · '}error=<span className="mono">{agents.error ?? 0}</span>
          </div>
          <div>
            interfaces: count=<span className="mono">{interfaces.count ?? '—'}</span>
            {' · '}max ts=<span className="mono">{fmtDiagTime(interfaces.maxTs)}</span>
            {' · '}возраст=<span className="mono">{fmtAge(interfaces.ageSec)}</span>
          </div>
        </div>
      </Card>
    </div>
  );
}

function AnalysisSnapshotsPanel({ data, loading, onReload }) {
  const oldest = data?.oldest || null;

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', maxWidth: 760 }}>
          Активные публичные ссылки на сохранённые результаты разбора трафика и DNS (SQLite, TTL 24 ч).
        </div>
        <Button kind="ghost" icon="refresh" onClick={onReload} disabled={loading}>
          {loading ? 'Обновление…' : 'Обновить'}
        </Button>
      </div>

      <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
        {[
          ['Всего ссылок', data?.total ?? '—'],
          ['Explorer', data?.explorer ?? '—'],
          ['DNS Explorer', data?.dnsExplorer ?? '—'],
        ].map(([label, value]) => (
          <div
            key={label}
            style={{
              minWidth: 140,
              padding: '12px 14px',
              borderRadius: 8,
              background: 'var(--bg-secondary)',
            }}
          >
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{label}</div>
            <div className="mono" style={{ font: 'var(--pv-text-header-3)', marginTop: 4 }}>{String(value)}</div>
          </div>
        ))}
      </div>

      <Card title="Самая старая активная ссылка">
        {oldest ? (
          <div className="col" style={{ gap: 8, font: 'var(--pv-text-body-3)' }}>
            <div>
              Создана: <span className="mono">{fmtDiagTime(oldest.createdAt)}</span>
            </div>
            <div>
              Истекает: <span className="mono">{fmtDiagTime(oldest.expiresAt)}</span>
            </div>
            <div>
              До истечения: <span className="mono">{fmtAge(oldest.expiresInSec)}</span>
            </div>
          </div>
        ) : (
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)' }}>
            Нет активных опубликованных ссылок.
          </div>
        )}
      </Card>

      {data?.checkedAt && (
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
          Проверено: <span className="mono">{fmtDiagTime(data.checkedAt)}</span>
        </div>
      )}
    </div>
  );
}

function fmtFailedRequestRoute(route) {
  const raw = String(route || '');
  const q = raw.indexOf('?');
  return q >= 0 ? raw.slice(0, q) : raw;
}

function fmtFailedRequestErrorShort(error) {
  if (!error) return '—';
  const firstLine = String(error).split(/\r?\n/).find((line) => line.trim()) || String(error);
  const text = firstLine.trim();
  if (text.length <= 96) return text;
  return `${text.slice(0, 96)}…`;
}

function fmtApiRequestText(item) {
  const lines = [`${item.method} ${item.route}`];
  if (item.query && Object.keys(item.query).length) {
    lines.push('', 'Query:', JSON.stringify(item.query, null, 2));
  }
  if (item.body && Object.keys(item.body).length) {
    lines.push('', 'Body:', JSON.stringify(item.body, null, 2));
  }
  return lines.join('\n');
}

function FailedRequestsPager({ offset, limit, total, onChange, loading }) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil((total || 0) / limit));
  const from = total ? offset + 1 : 0;
  const to = Math.min(offset + limit, total || 0);

  return (
    <div className="row" style={{ gap: 10, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
      <span style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
        {total ? `${from}–${to} из ${total}` : 'нет записей'}
      </span>
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <select
          className="input"
          value={limit}
          disabled={loading}
          onChange={(e) => onChange({ offset: 0, limit: Number(e.target.value) })}
          style={{ width: 90 }}
          title="Записей на странице"
        >
          {FAILED_REQUESTS_PAGE_SIZES.map((n) => (
            <option key={n} value={n}>{n}</option>
          ))}
        </select>
        <Button
          kind="ghost"
          size="sm"
          disabled={loading || page <= 1}
          onClick={() => onChange({ offset: Math.max(0, offset - limit), limit })}
        >
          Назад
        </Button>
        <span style={{ font: 'var(--pv-text-body-3)', minWidth: 70, textAlign: 'center' }}>
          {page} / {pages}
        </span>
        <Button
          kind="ghost"
          size="sm"
          disabled={loading || page >= pages}
          onClick={() => onChange({ offset: offset + limit, limit })}
        >
          Далее
        </Button>
      </div>
    </div>
  );
}

function FailedRequestsPanel({ data, loading, onReload, page, onPageChange }) {
  const [expandedId, setExpandedId] = React.useState(null);
  const items = data?.items || [];
  const total = data?.total ?? 0;
  const offset = page?.offset ?? 0;
  const limit = page?.limit ?? FAILED_REQUESTS_DEFAULT_LIMIT;
  const latest = offset === 0 ? (items[0] || null) : null;

  React.useEffect(() => {
    setExpandedId(null);
  }, [offset, limit]);

  async function handleCopy(label, text) {
    try {
      await copyTextToClipboard(text);
      pushToast({ kind: 'success', title: `${label} скопировано` });
    } catch (err) {
      pushToast({ kind: 'error', title: 'Не удалось скопировать', desc: err.message });
    }
  }

  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)', maxWidth: 760 }}>
          Ошибки API и ClickHouse (без 401/403). Хранение {data?.retentionDays ?? 3} дн. в SQLite.
        </div>
        <Button kind="ghost" icon="refresh" onClick={onReload} disabled={loading}>
          {loading ? 'Обновление…' : 'Обновить'}
        </Button>
      </div>

      <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
        {[
          ['Всего записей', total || '—'],
          ['На странице', items.length || '—'],
          ['Последняя ошибка', latest ? fmtDiagTime(latest.at) : (total ? 'см. стр. 1' : '—')],
        ].map(([label, value]) => (
          <div
            key={label}
            style={{
              minWidth: 140,
              padding: '12px 14px',
              borderRadius: 8,
              background: 'var(--bg-secondary)',
            }}
          >
            <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>{label}</div>
            <div className="mono" style={{ font: 'var(--pv-text-header-3)', marginTop: 4 }}>{String(value)}</div>
          </div>
        ))}
      </div>

      <FailedRequestsPager
        offset={offset}
        limit={limit}
        total={total}
        loading={loading}
        onChange={onPageChange}
      />

      <Card title="Упавшие запросы">
        <table style={{ width: '100%', tableLayout: 'fixed', borderCollapse: 'collapse', font: 'var(--pv-text-body-3)' }}>
          <colgroup>
            <col style={{ width: '12%' }} />
            <col style={{ width: '7%' }} />
            <col style={{ width: '24%' }} />
            <col style={{ width: '7%' }} />
            <col style={{ width: '7%' }} />
            <col style={{ width: '43%' }} />
          </colgroup>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', padding: 6 }}>время</th>
              <th style={{ textAlign: 'left', padding: 6 }}>метод</th>
              <th style={{ textAlign: 'left', padding: 6 }}>маршрут</th>
              <th style={{ textAlign: 'right', padding: 6 }}>HTTP</th>
              <th style={{ textAlign: 'right', padding: 6 }}>мс</th>
              <th style={{ textAlign: 'left', padding: 6 }}>ошибка</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <React.Fragment key={item.id}>
                <tr
                  onClick={() => setExpandedId((cur) => (cur === item.id ? null : item.id))}
                  style={{ cursor: 'pointer', background: expandedId === item.id ? 'var(--surf-2)' : 'transparent' }}
                >
                  <td style={{ padding: 6, whiteSpace: 'nowrap' }} className="mono">{fmtDiagTime(item.at)}</td>
                  <td style={{ padding: 6, whiteSpace: 'nowrap' }} className="mono">{item.method}</td>
                  <td style={{ padding: 6, overflow: 'hidden', minWidth: 0, maxWidth: 0 }}>
                    <OverflowText
                      value={fmtFailedRequestRoute(item.route)}
                      title={item.route}
                      className="mono"
                    />
                  </td>
                  <td style={{ padding: 6, textAlign: 'right', whiteSpace: 'nowrap' }} className="mono">{item.statusCode}</td>
                  <td style={{ padding: 6, textAlign: 'right', whiteSpace: 'nowrap' }} className="mono">{item.elapsedMs ?? '—'}</td>
                  <td style={{ padding: 6, color: 'var(--st-critical)', overflow: 'hidden' }}>
                    <OverflowText
                      value={fmtFailedRequestErrorShort(item.error)}
                      title={item.error || ''}
                    />
                  </td>
                </tr>
                {expandedId === item.id && (
                  <tr>
                    <td colSpan={6} style={{ padding: '8px 6px 12px' }}>
                      <div className="col" style={{ gap: 12 }}>
                        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                          <Button kind="ghost" onClick={() => handleCopy('API-запрос', fmtApiRequestText(item))}>
                            Копировать API
                          </Button>
                          {item.error && (
                            <Button kind="ghost" onClick={() => handleCopy('Ошибка', item.error)}>
                              Копировать ошибку
                            </Button>
                          )}
                          {item.sql?.inlined && (
                            <Button kind="ghost" onClick={() => handleCopy('SQL', item.sql.inlined)}>
                              Копировать SQL
                            </Button>
                          )}
                        </div>

                        <div>
                          <div style={{ font: 'var(--pv-text-body-3-bold)', marginBottom: 6 }}>Ошибка</div>
                          <pre style={{
                            margin: 0,
                            padding: 10,
                            borderRadius: 8,
                            background: 'var(--surf-1)',
                            border: '1px solid var(--bd-soft)',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                            font: 'var(--pv-text-body-3)',
                            maxHeight: 240,
                            overflow: 'auto',
                            color: 'var(--st-critical)',
                          }}>
                            {item.error || '—'}
                          </pre>
                        </div>

                        <div>
                          <div style={{ font: 'var(--pv-text-body-3-bold)', marginBottom: 6 }}>API</div>
                          <pre style={{
                            margin: 0,
                            padding: 10,
                            borderRadius: 8,
                            background: 'var(--surf-1)',
                            border: '1px solid var(--bd-soft)',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                            font: 'var(--pv-text-body-3)',
                            maxHeight: 240,
                            overflow: 'auto',
                          }}>
                            {fmtApiRequestText(item)}
                          </pre>
                        </div>

                        {item.sql && (
                          <div>
                            <div style={{ font: 'var(--pv-text-body-3-bold)', marginBottom: 6 }}>
                              SQL {item.sql.name ? `· ${item.sql.name}` : ''}
                            </div>
                            <pre style={{
                              margin: 0,
                              padding: 10,
                              borderRadius: 8,
                              background: 'var(--surf-1)',
                              border: '1px solid var(--bd-soft)',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                              font: 'var(--pv-text-body-3)',
                              maxHeight: 360,
                              overflow: 'auto',
                            }}>
                              {item.sql.inlined || item.sql.template}
                              {'\n\n-- template\n'}
                              {item.sql.template}
                              {'\n\n-- params\n'}
                              {JSON.stringify(item.sql.params || {}, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
            {!loading && !items.length && (
              <tr>
                <td colSpan={6} style={{ padding: 8, color: 'var(--fg-secondary)' }}>
                  Упавших запросов пока нет.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>

      <FailedRequestsPager
        offset={offset}
        limit={limit}
        total={total}
        loading={loading}
        onChange={onPageChange}
      />

      {data?.checkedAt && (
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-muted)' }}>
          Проверено: <span className="mono">{fmtDiagTime(data.checkedAt)}</span>
        </div>
      )}
    </div>
  );
}

function PageDiagnostics() {
  const [tab, setTab] = useState(() => sessionStorage.getItem('grapes-diagnostics-tab') || 'worker');
  const [workerData, setWorkerData] = useState(null);
  const [enrichData, setEnrichData] = useState(null);
  const [snmpData, setSnmpData] = useState(null);
  const [snapshotsData, setSnapshotsData] = useState(null);
  const [failuresData, setFailuresData] = useState(null);
  const [failuresPage, setFailuresPage] = useState({
    limit: FAILED_REQUESTS_DEFAULT_LIMIT,
    offset: 0,
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [buildInfo, setBuildInfo] = useState(null);

  useEffect(() => {
    let cancelled = false;
    ApiClient.loadBuildInfo()
      .then((data) => {
        if (cancelled) return;
        if (data?.buildDate || data?.commit) setBuildInfo(data);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const reload = useCallback((opts = { initial: false }) => {
    if (tab === 'erp' || tab === 'detection') {
      setLoading(false);
      setError('');
      return;
    }
    if (opts.initial) setLoading(true);
    const loader = tab === 'enrichment'
      ? ApiClient.loadEnrichmentDiagnostics()
      : tab === 'snmp'
        ? ApiClient.loadSnmpDiagnostics()
        : tab === 'snapshots'
          ? ApiClient.loadAnalysisSnapshotsDiagnostics()
          : tab === 'failures'
            ? ApiClient.loadFailedRequestsDiagnostics({
              limit: failuresPage.limit,
              offset: failuresPage.offset,
            })
            : ApiClient.loadWorkerDiagnostics();
    loader
      .then((body) => {
        if (tab === 'enrichment') setEnrichData(body);
        else if (tab === 'snmp') setSnmpData(body);
        else if (tab === 'snapshots') setSnapshotsData(body);
        else if (tab === 'failures') {
          if (body?.total && failuresPage.offset >= body.total && failuresPage.offset > 0) {
            setFailuresPage((prev) => ({ ...prev, offset: 0 }));
            return;
          }
          setFailuresData(body);
        } else setWorkerData(body);
        setError('');
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message);
        setLoading(false);
      });
  }, [tab, failuresPage.limit, failuresPage.offset]);

  useEffect(() => {
    reload({ initial: true });
    const t = setInterval(() => reload({ initial: false }), DIAG_REFRESH_MS);
    return () => clearInterval(t);
  }, [reload]);

  return (
    <div className="page col" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8 }}>
        <div>
          <h1 style={{ margin: 0, font: 'var(--pv-text-header-1)' }}>Диагностика</h1>
          <div style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-body-3)', marginTop: 4 }}>
            Статус периодических сервисов, журнал ошибок API, синхронизация ERP и ссылки на результаты анализа.
          </div>
        </div>
        <div className="seg">
          <button
            type="button"
            className={tab === 'worker' ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => setTab('worker')}
          >
            grapes-worker
          </button>
          <button
            type="button"
            className={tab === 'enrichment' ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => setTab('enrichment')}
          >
            grapes-enrichment
          </button>
          <button
            type="button"
            className={tab === 'snmp' ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => setTab('snmp')}
          >
            SNMP
          </button>
          <button
            type="button"
            className={tab === 'detection' ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => { sessionStorage.setItem('grapes-diagnostics-tab', 'detection'); setTab('detection'); }}
          >
            Детекция
          </button>
          <button
            type="button"
            className={tab === 'snapshots' ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => setTab('snapshots')}
          >
            Ссылки анализа
          </button>
          <button
            type="button"
            className={tab === 'failures' ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => setTab('failures')}
          >
            Ошибки запросов
          </button>
          <button
            type="button"
            className={tab === 'erp' ? 'seg__item seg__item--active' : 'seg__item'}
            onClick={() => { sessionStorage.setItem('grapes-diagnostics-tab', 'erp'); setTab('erp'); }}
          >
            ERP
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)' }}>
          {error}
        </div>
      )}

      {tab === 'worker' && (
        <WorkerPanel
          data={workerData}
          loading={loading}
          onReload={() => reload({ initial: false })}
        />
      )}
      {tab === 'enrichment' && (
        <EnrichmentPanel
          data={enrichData}
          loading={loading}
          onReload={() => reload({ initial: false })}
        />
      )}
      {tab === 'snmp' && (
        <SnmpPanel
          data={snmpData}
          loading={loading}
          onReload={() => reload({ initial: false })}
        />
      )}
      {tab === 'detection' && <PageDetection />}
      {tab === 'snapshots' && (
        <AnalysisSnapshotsPanel
          data={snapshotsData}
          loading={loading}
          onReload={() => reload({ initial: false })}
        />
      )}
      {tab === 'failures' && (
        <FailedRequestsPanel
          data={failuresData}
          loading={loading}
          page={failuresPage}
          onPageChange={setFailuresPage}
          onReload={() => reload({ initial: false })}
        />
      )}
      {tab === 'erp' && <PageErpPiterix />}

      {buildInfo && (buildInfo.buildDate || buildInfo.commit) && (
        <div
          style={{
            marginTop: 8,
            font: 'var(--pv-text-body-3)',
            color: 'var(--fg-muted)',
            textAlign: 'right',
          }}
        >
          {buildInfo.buildDate && (
            <>Сборка: {fmtBuildDate(buildInfo.buildDate)}</>
          )}
          {buildInfo.buildDate && buildInfo.commit && ' · '}
          {buildInfo.commit && (
            <span className="mono">{buildInfo.commit}</span>
          )}
        </div>
      )}
    </div>
  );
}

window.PageDiagnostics = PageDiagnostics;
