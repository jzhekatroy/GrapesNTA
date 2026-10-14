const { useState, useEffect, useCallback, useMemo, useRef } = React;

const REFRESH_MS = 30_000;
const PEAKS_STORAGE_KEY = 'grapes-monitoring-show-peaks';
const COMPONENT_ORDER = ['collectors', 'detection', 'worker', 'clickhouse', 'enrichment', 'snmp'];
const OK_TITLE = {
  collectors: 'Коллекторы',
  detection: 'детекция',
  worker: 'Worker',
  clickhouse: 'ClickHouse',
  enrichment: 'Обогащение',
  snmp: 'SNMP',
};

function formatBps(value) {
  return window.DetectionFormatBps?.(value) ?? String(value ?? '—');
}

function formatMskTime(value) {
  return window.DetectionFormatMskTime?.(value) ?? '—';
}

function formatMskTimeFull(value) {
  if (!value) return '—';
  const raw = String(value);
  const date = new Date(raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`);
  if (Number.isNaN(date.getTime())) return raw;
  return date.toLocaleString('ru-RU', {
    timeZone: 'Europe/Moscow',
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function isPeakRow(row) {
  return row?.verdict?.kind === 'benign_peak' || window.DetectionIsPeakEvent?.(row);
}

function attackMainBps(row) {
  const excess = row?.live?.lastHotExcessBps;
  if (excess != null && Number.isFinite(Number(excess))) return Number(excess);
  const alert = Number(row?.alertByProto?.all?.bps);
  if (Number.isFinite(alert) && alert > 0) return alert;
  return 0;
}

function stateRank(row) {
  const st = row?.live?.state;
  if (st === 'ongoing') return 0;
  if (st === 'fading') return 1;
  return 2;
}

function sortAttackRows(rows) {
  return [...rows].sort((a, b) => {
    const sr = stateRank(a) - stateRank(b);
    if (sr !== 0) return sr;
    return attackMainBps(b) - attackMainBps(a);
  });
}

function scopeLabel(scope) {
  return window.DetectionScopeShort?.[scope] || scope || '—';
}

function kindLabel(kind) {
  return window.DetectionKindLabel?.[kind] || kind || '—';
}

function liveStateLabel(row) {
  const st = row?.live?.state;
  if (st === 'ongoing') return { text: 'идёт', tone: 'critical' };
  if (st === 'fading') return { text: 'затихает', tone: 'warning' };
  return { text: 'нет данных', tone: 'neutral' };
}

function formatHourRatio(row) {
  const ratio = window.DetectionEventHourRatio?.(row);
  if (ratio == null || !Number.isFinite(ratio) || ratio <= 0) return null;
  return `×${ratio.toLocaleString('ru-RU', { minimumFractionDigits: 1, maximumFractionDigits: 1 })} к норме часа`;
}

function durationMinutesFrom(startMinute) {
  if (!startMinute) return null;
  const raw = String(startMinute);
  const start = new Date(raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`);
  if (Number.isNaN(start.getTime())) return null;
  const mins = Math.max(0, Math.round((Date.now() - start.getTime()) / 60_000));
  return mins;
}

function formatSinceDuration(since) {
  if (!since) return '';
  const start = new Date(since);
  if (Number.isNaN(start.getTime())) return '';
  const mins = Math.max(1, Math.round((Date.now() - start.getTime()) / 60_000));
  return `с ${formatMskTime(since)} (${mins} мин)`;
}

function readShowPeaks() {
  try {
    return localStorage.getItem(PEAKS_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function writeShowPeaks(on) {
  try {
    localStorage.setItem(PEAKS_STORAGE_KEY, on ? '1' : '0');
  } catch { /* ignore */ }
}

function canOpenProblemLink(perms, problem) {
  if (!problem?.link) return false;
  if (!perms) return true;
  const page = String(problem.link).replace(/^#/, '');
  if (page === 'diagnostics') return !!perms.diagnostics;
  if (page === 'snmp') return !!(perms.snmp || perms.collectors);
  if (page === 'collectors') return !!perms.collectors;
  return !!perms[page];
}

function navigateProblem(onNavigate, problem) {
  const tab = problem?.diagnosticsTab;
  if (tab) sessionStorage.setItem('grapes-diagnostics-tab', tab);
  const page = String(problem.link || '').replace(/^#/, '');
  if (page && onNavigate) onNavigate(page);
  else if (problem.link) location.hash = problem.link.replace(/^#/, '');
}

function useMonitoringPoll(fetchFn, enabled) {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [lastOkAt, setLastOkAt] = useState(null);
  const dataRef = useRef(data);
  dataRef.current = data;

  const tick = useCallback(async () => {
    try {
      const next = await fetchFn();
      setData(next);
      setError('');
      setLastOkAt(Date.now());
    } catch (err) {
      setError(err.message || 'Ошибка запроса');
    }
  }, [fetchFn]);

  useEffect(() => {
    if (!enabled) return undefined;
    tick();
    let timer = null;
    const schedule = () => {
      if (timer) clearInterval(timer);
      if (document.hidden) return;
      timer = setInterval(tick, REFRESH_MS);
    };
    schedule();
    const onVis = () => {
      if (document.hidden) {
        if (timer) clearInterval(timer);
        timer = null;
      } else {
        tick();
        schedule();
      }
    };
    document.addEventListener('visibilitychange', onVis);
    return () => {
      if (timer) clearInterval(timer);
      document.removeEventListener('visibilitychange', onVis);
    };
  }, [enabled, tick]);

  return { data, error, lastOkAt, refresh: tick };
}

function RefreshAge({ lastOkAt }) {
  const [, bump] = useState(0);
  useEffect(() => {
    const t = setInterval(() => bump((n) => n + 1), 5000);
    return () => clearInterval(t);
  }, []);
  if (!lastOkAt) return <span className="monitoring-refresh-age monitoring-refresh-age--warn">обновление…</span>;
  const sec = Math.max(0, Math.round((Date.now() - lastOkAt) / 1000));
  const stale = sec > 60;
  return (
    <span className={`monitoring-refresh-age${stale ? ' monitoring-refresh-age--warn' : ''}`}>
      обновлено {sec} с назад
    </span>
  );
}

function MonitoringHeader({
  attackCount,
  criticalCount,
  warningCount,
  problemsFailed,
  meta,
  lastOkAt,
}) {
  const detectionMinute = meta?.detectionMinute;
  const stale = !!meta?.detectionStale;
  const systemOk = !problemsFailed && criticalCount === 0 && warningCount === 0;

  return (
    <div className="monitoring-header">
      <h1 className="monitoring-header__title">Мониторинг</h1>
      <div className="monitoring-header__stats">
        <span className={attackCount > 0 ? 'monitoring-stat monitoring-stat--critical' : 'monitoring-stat monitoring-stat--muted'}>
          {attackCount > 0 ? `${attackCount} атак` : 'атак нет'}
        </span>
        {problemsFailed ? (
          <span className="monitoring-stat monitoring-stat--critical">? критичных · ? предупреждений</span>
        ) : systemOk ? (
          <span className="monitoring-stat monitoring-stat--ok">система в порядке</span>
        ) : (
          <>
            {criticalCount > 0 && (
              <span className="monitoring-stat monitoring-stat--critical">
                {criticalCount} {criticalCount === 1 ? 'критичная проблема' : 'критичных'}
              </span>
            )}
            {warningCount > 0 && (
              <span className="monitoring-stat monitoring-stat--warning">
                {warningCount} {warningCount === 1 ? 'предупреждение' : 'предупреждения'}
              </span>
            )}
          </>
        )}
      </div>
      <div className="monitoring-header__meta">
        {detectionMinute ? (
          <span className={stale ? 'monitoring-detection-meta monitoring-detection-meta--stale' : 'monitoring-detection-meta'}>
            данные детекции на {formatMskTime(detectionMinute)} МСК
          </span>
        ) : null}
        <RefreshAge lastOkAt={lastOkAt} />
      </div>
    </div>
  );
}

function AttackCard({ row, muted, onOpen }) {
  const state = liveStateLabel(row);
  const ratio = formatHourRatio(row);
  const excess = row?.live?.lastHotExcessBps;
  const alertBps = Number(row?.alertByProto?.all?.bps);
  let volumeLine = null;
  if (excess != null && Number.isFinite(Number(excess))) {
    volumeLine = state.text === 'затихает'
      ? `было ${formatBps(excess)} лишнего`
      : `${formatBps(excess)} лишнего`;
  } else if (Number.isFinite(alertBps) && alertBps > 0) {
    volumeLine = `${formatBps(alertBps)} в момент срабатывания`;
  }
  const peakLine = row?.live?.peakBps
    ? `пик ${formatBps(row.live.peakBps)} в ${formatMskTime(row.live.peakMinute)}`
    : null;
  const start = row?.startMinute || row?.alertMinute;
  const dur = durationMinutesFrom(start);
  const durLine = dur != null && state.text === 'идёт' ? `идёт ${dur} мин` : null;
  const quietLine = state.text === 'затихает' && row?.live?.normalizeStreak
    ? `тихо ${row.live.quietStreak ?? 0} из ${row.live.normalizeStreak} мин`
    : null;
  const victim = window.DetectionFormatVictimCell?.(row.investigate) || '—';
  const sw = window.DetectionFormatSwitchCell?.(row.investigate) || '—';

  return (
    <button
      type="button"
      className={`monitoring-attack-card${muted ? ' monitoring-attack-card--muted' : ''}`}
      onClick={() => onOpen(row.id)}
    >
      <div className="monitoring-attack-card__head">
        <span className={`monitoring-attack-card__state monitoring-attack-card__state--${state.tone}`}>
          {state.text}
        </span>
        <span className="monitoring-attack-card__object">
          {row.name || row.scopeId}
          {' · '}
          {scopeLabel(row.scope)}
          {' · '}
          {kindLabel(row.verdict?.kind)}
        </span>
      </div>
      {volumeLine && <div className="monitoring-attack-card__volume">{volumeLine}</div>}
      <div className="monitoring-attack-card__sub">
        {[ratio, durLine, peakLine, quietLine].filter(Boolean).join(' · ')}
      </div>
      <div className="monitoring-attack-card__foot">
        куда {victim} · вход {sw}
      </div>
    </button>
  );
}

function AttacksEmpty({ meta }) {
  if (meta?.detectionStale) {
    if (meta.detectionEmpty) {
      return (
        <div className="monitoring-empty monitoring-empty--warn">
          Атак не видно, но детекция за сутки не записала ни одной минуты — список может быть неполным
        </div>
      );
    }
    if (meta.detectionLagSec == null) {
      return (
        <div className="monitoring-empty monitoring-empty--warn">
          Атак не видно, но свежесть детекции неизвестна — список может быть неполным
        </div>
      );
    }
    const mins = Math.max(1, Math.round(Number(meta.detectionLagSec) / 60));
    return (
      <div className="monitoring-empty monitoring-empty--warn">
        {`Атак не видно, но детекция отстала на ${mins} мин — список может быть неполным`}
      </div>
    );
  }
  return (
    <div className="monitoring-empty">
      <div>Атак нет</div>
      {meta?.detectionMinute ? (
        <div className="monitoring-empty__hint">данные на {formatMskTime(meta.detectionMinute)} МСК</div>
      ) : null}
    </div>
  );
}

function ProblemsPanel({ components, problems, perms, onNavigate, failed }) {
  const [expanded, setExpanded] = useState({});
  const byComponent = useMemo(() => {
    const map = {};
    for (const p of problems || []) {
      const id = p.component || 'other';
      if (!map[id]) map[id] = [];
      map[id].push(p);
    }
    return map;
  }, [problems]);

  const okNames = useMemo(() => {
    const list = (components || [])
      .filter((c) => c.status === 'ok')
      .sort((a, b) => COMPONENT_ORDER.indexOf(a.id) - COMPONENT_ORDER.indexOf(b.id))
      .map((c) => OK_TITLE[c.id] || c.title || c.id);
    return list;
  }, [components]);

  if (failed) {
    return (
      <div className="monitoring-problems">
        <div className="monitoring-problems__title">Проблемы системы</div>
        <div className="monitoring-problems-fail">Не удалось проверить систему</div>
      </div>
    );
  }

  return (
    <div className="monitoring-problems">
      <div className="monitoring-problems__title">Проблемы системы</div>
      <div className="monitoring-problems__list">
        {COMPONENT_ORDER.map((compId) => {
          const comp = (components || []).find((c) => c.id === compId);
          const rows = byComponent[compId] || [];
          if (!rows.length) return null;
          const title = comp?.title || compId;
          const isOpen = expanded[compId];
          const visible = isOpen ? rows : rows.slice(0, 2);
          const hiddenCount = rows.length - visible.length;
          return (
            <div key={compId} className="monitoring-problems__group">
              <div className="monitoring-problems__group-title">{title}</div>
              {visible.map((p) => {
                const linkOk = canOpenProblemLink(perms, p);
                return (
                  <div key={p.id} className="monitoring-problem-row">
                    <span className={`monitoring-problem-row__dot monitoring-problem-row__dot--${p.level || 'warning'}`} />
                    <div className="monitoring-problem-row__body">
                      <div className="monitoring-problem-row__title">{p.title}</div>
                      <div className="monitoring-problem-row__msg">{p.message}</div>
                      {p.since ? (
                        <div className="monitoring-problem-row__since">{formatSinceDuration(p.since)}</div>
                      ) : null}
                    </div>
                    {linkOk ? (
                      <button
                        type="button"
                        className="monitoring-problem-row__link"
                        aria-label="Перейти"
                        onClick={() => navigateProblem(onNavigate, p)}
                      >
                        →
                      </button>
                    ) : null}
                  </div>
                );
              })}
              {rows.length >= 4 && !isOpen && hiddenCount > 0 ? (
                <button
                  type="button"
                  className="monitoring-problems__more"
                  onClick={() => setExpanded((e) => ({ ...e, [compId]: true }))}
                >
                  ещё {hiddenCount}
                </button>
              ) : null}
            </div>
          );
        })}
      </div>
      {okNames.length ? (
        <div className="monitoring-problems__ok">В порядке: {okNames.join(', ')}</div>
      ) : null}
    </div>
  );
}

function MonitoringListView({ onNavigate, effectivePermissions }) {
  const [showPeaks, setShowPeaks] = useState(readShowPeaks);
  const fetchAttacks = useCallback(() => ApiClient.loadMonitoringAttacks(), []);
  const fetchProblems = useCallback(() => ApiClient.loadMonitoringProblems(), []);
  const attacksPoll = useMonitoringPoll(fetchAttacks, true);
  const problemsPoll = useMonitoringPoll(fetchProblems, true);

  const lastOkAt = Math.max(attacksPoll.lastOkAt || 0, problemsPoll.lastOkAt || 0) || null;
  const meta = problemsPoll.data?.meta || null;
  const rawAttacks = attacksPoll.data?.attacks || [];
  const peaks = attacksPoll.data?.peaks || [];
  const peaksError = attacksPoll.data?.peaksError;

  const attacksOnly = useMemo(
    () => sortAttackRows(rawAttacks.filter((r) => !isPeakRow(r))),
    [rawAttacks],
  );
  const attackCount = attacksOnly.length;

  const peakRows = useMemo(() => {
    const ids = new Set(attacksOnly.map((r) => r.id));
    const fromAttacks = rawAttacks.filter((r) => isPeakRow(r));
    const merged = [...fromAttacks];
    for (const p of peaks) {
      if (!p?.id || ids.has(p.id)) continue;
      ids.add(p.id);
      merged.push(p);
    }
    return sortAttackRows(merged);
  }, [attacksOnly, rawAttacks, peaks]);

  const displayRows = useMemo(() => {
    if (!showPeaks) return attacksOnly;
    return [...attacksOnly, ...peakRows];
  }, [attacksOnly, peakRows, showPeaks]);

  const problems = problemsPoll.data?.problems || [];
  const criticalCount = problems.filter((p) => p.level === 'critical').length;
  const warningCount = problems.filter((p) => p.level === 'warning').length;
  const problemsFailed = !!problemsPoll.error && !problemsPoll.data;

  const openAttack = (id) => {
    location.hash = `monitoring?attack=${encodeURIComponent(id)}`;
  };

  const togglePeaks = (on) => {
    setShowPeaks(on);
    writeShowPeaks(on);
  };

  return (
    <div className="main__container monitoring-page">
      <MonitoringHeader
        attackCount={attackCount}
        criticalCount={criticalCount}
        warningCount={warningCount}
        problemsFailed={problemsFailed}
        meta={meta}
        lastOkAt={lastOkAt}
      />
      {problemsFailed ? (
        <div className="monitoring-banner monitoring-banner--critical">Не удалось проверить систему</div>
      ) : null}
      <div className="monitoring-grid">
        <section className="monitoring-attacks">
          <div className="monitoring-attacks__head">
            <span className="monitoring-attacks__title">Активные атаки</span>
            <label className="monitoring-peaks-toggle">
              <Checkbox checked={showPeaks} onChange={togglePeaks} />
              <span>Показать пики</span>
            </label>
          </div>
          {peaksError ? (
            <div className="monitoring-peaks-error">{peaksError}</div>
          ) : null}
          {attacksPoll.error && !attacksPoll.data ? (
            <div className="monitoring-banner monitoring-banner--warn">{attacksPoll.error}</div>
          ) : null}
          {!displayRows.length ? (
            <AttacksEmpty meta={meta} />
          ) : (
            <div className="monitoring-attack-list">
              {displayRows.map((row) => (
                <AttackCard
                  key={row.id}
                  row={row}
                  muted={showPeaks && isPeakRow(row)}
                  onOpen={openAttack}
                />
              ))}
            </div>
          )}
        </section>
        <ProblemsPanel
          components={problemsPoll.data?.components}
          problems={problems}
          perms={effectivePermissions}
          onNavigate={onNavigate}
          failed={problemsFailed}
        />
      </div>
    </div>
  );
}

function MonitoringVolumeBanner({ event }) {
  if (!event) return null;
  const excess = event?.live?.lastHotExcessBps;
  const peak = event?.live?.peakBps;
  const ratio = window.DetectionEventHourRatio?.(event);
  const usual = window.DetectionEventHourUsual?.(event);
  const fmtRatio = window.DetectionFormatHourShare?.(ratio);
  return (
    <div className="detection-attack-banner">
      <div className="detection-attack-banner__item">
        <div className="detection-attack-banner__label">Лишнее сейчас</div>
        <div className="detection-attack-banner__value">
          {excess != null ? formatBps(excess) : '—'}
        </div>
      </div>
      <div className="detection-attack-banner__item">
        <div className="detection-attack-banner__label">Пик</div>
        <div className="detection-attack-banner__value">
          {peak != null ? formatBps(peak) : '—'}
        </div>
      </div>
      <div className="detection-attack-banner__item">
        <div className="detection-attack-banner__label">От нормы часа</div>
        <div className="detection-attack-banner__value">{fmtRatio || '—'}</div>
      </div>
      {usual != null && (
        <div className="detection-attack-banner__item">
          <div className="detection-attack-banner__label">Норма часа</div>
          <div className="detection-attack-banner__value detection-attack-banner__value--muted">
            {formatBps(usual)}
          </div>
        </div>
      )}
    </div>
  );
}

function historyChartPoints(history) {
  return (history?.points || []).map((p) => {
    const baseline = Number(p.baselineBps);
    return {
      t: p.t,
      bucket: p.t,
      bucketMs: p.bucketMs != null ? Number(p.bucketMs) : parseChartBucketMs(p.t),
      bps: Number(p.bps) || 0,
      baselineBps: Number.isFinite(baseline) && baseline > 0 ? baseline : null,
    };
  });
}

function MonitoringAttackDetail({ attackId, onBack }) {
  const [event, setEvent] = useState(null);
  const [history, setHistory] = useState(null);
  const [error, setError] = useState('');
  const [flowspecOpen, setFlowspecOpen] = useState(false);
  const lastOkRef = useRef(null);
  const [, bump] = useState(0);

  const load = useCallback(async () => {
    try {
      const ev = await ApiClient.loadMonitoringAttack(attackId);
      setEvent(ev);
      setError('');
      lastOkRef.current = Date.now();
      const hist = await ApiClient.loadMonitoringAttackHistory(attackId);
      setHistory(hist);
    } catch (err) {
      setError(err.message || 'Не удалось загрузить атаку');
    }
  }, [attackId]);

  useEffect(() => {
    load();
    let timer = null;
    const schedule = () => {
      if (timer) clearInterval(timer);
      if (document.hidden) return;
      timer = setInterval(load, REFRESH_MS);
    };
    schedule();
    const onVis = () => {
      if (document.hidden) {
        if (timer) clearInterval(timer);
        timer = null;
      } else {
        load();
        schedule();
      }
    };
    document.addEventListener('visibilitychange', onVis);
    return () => {
      if (timer) clearInterval(timer);
      document.removeEventListener('visibilitychange', onVis);
    };
  }, [load]);

  useEffect(() => {
    const t = setInterval(() => bump((n) => n + 1), 5000);
    return () => clearInterval(t);
  }, []);

  const chartPoints = useMemo(() => historyChartPoints(history), [history]);
  const periodStartMs = parseChartBucketMs(history?.from);
  const periodEndMs = parseChartBucketMs(history?.to);
  const marks = history?.alertMinute
    ? [{ t: history.alertMinute, label: 'алерт' }]
    : [];

  const state = liveStateLabel(event || {});
  const finished = event && event.status !== 'active';
  const finishMinute = event?.status === 'normalized'
    ? event.normalizeMinute
    : event?.status === 'peak'
      ? event.alertMinute
      : null;

  const loadAsn = useCallback(
    () => ApiClient.loadMonitoringAttackAsn(attackId),
    [attackId],
  );
  const loadFlowspec = useCallback(
    () => ApiClient.loadMonitoringAttackFlowspec(attackId),
    [attackId],
  );
  const flowspecEligible = event && window.DetectionIpMarkupEligible?.(event);

  if (error && !event) {
    return (
      <div className="main__container monitoring-page">
        <Button kind="ghost" onClick={onBack}>← Мониторинг</Button>
        <div className="monitoring-banner monitoring-banner--critical">{error}</div>
      </div>
    );
  }

  return (
    <div className="main__container monitoring-page monitoring-page--detail">
      <div className="monitoring-detail__nav">
        <Button kind="ghost" onClick={onBack}>← Мониторинг</Button>
        {lastOkRef.current ? (
          <RefreshAge lastOkAt={lastOkRef.current} />
        ) : null}
      </div>
      {event ? (
        <>
          <div className="monitoring-detail__head">
            <h1>{event.name || event.scopeId}</h1>
            <div className="monitoring-detail__tags">
              <Badge tone="info">{scopeLabel(event.scope)}</Badge>
              <Badge tone="critical">{kindLabel(event.verdict?.kind)}</Badge>
              <Badge tone={state.tone === 'critical' ? 'critical' : state.tone === 'warning' ? 'warning' : 'neutral'}>
                {state.text}
              </Badge>
            </div>
            <div className="monitoring-detail__times">
              {event.startMinute ? `Началась ${formatMskTimeFull(event.startMinute)}` : null}
              {event.alertMinute ? ` · сработала ${formatMskTimeFull(event.alertMinute)}` : null}
            </div>
            {finished && finishMinute ? (
              <div className="monitoring-detail-finished">
                Атака завершена · {formatMskTimeFull(finishMinute)}
              </div>
            ) : null}
          </div>
          <MonitoringVolumeBanner event={event} />
          <Card title="Трафик и норма">
            {chartPoints.length ? (
              <CategoryTrendChart
                points={chartPoints}
                lines={[
                  { key: 'bps', label: 'Трафик', color: '#7E92F8' },
                  { key: 'baselineBps', label: 'Норма', color: 'var(--fg-muted)' },
                ]}
                height={220}
                bucketSeconds={60}
                periodStartMs={periodStartMs}
                periodEndMs={periodEndMs}
                skipTrailingGaps
                marks={marks}
              />
            ) : (
              <div className="monitoring-empty">Нет данных для графика</div>
            )}
          </Card>
          <Card title="Направление">
            <div className="monitoring-detail-inv">
              <div><span className="monitoring-detail-inv__label">Куда</span> {window.DetectionFormatVictimCell?.(event.investigate)}</div>
              <div><span className="monitoring-detail-inv__label">Откуда</span> {window.DetectionFormatSource24Cell?.(event.investigate)}</div>
              <div><span className="monitoring-detail-inv__label">Вход</span> {window.DetectionFormatSwitchCell?.(event.investigate)}</div>
            </div>
          </Card>
          <Card title="Мусорный UDP">
            <EventAsnTop
              event={event}
              loadAsn={loadAsn}
              missingMinuteMessage="Нет минуты среза"
            />
          </Card>
          {flowspecEligible ? (
            <div className="row" style={{ gap: 8 }}>
              <Button onClick={() => setFlowspecOpen(true)}>Отчёт для фильтра</Button>
            </div>
          ) : null}
          {event.alertText ? (
            <Card title="Текст срабатывания">
              <pre className="detection-notify-text">{event.alertText}</pre>
            </Card>
          ) : null}
          {event.normalizeText ? (
            <Card title="Нормализация">
              <pre className="detection-notify-text">{event.normalizeText}</pre>
            </Card>
          ) : null}
          <FlowspecReportModal
            event={flowspecOpen ? event : null}
            onClose={() => setFlowspecOpen(false)}
            loadFlowspec={loadFlowspec}
          />
        </>
      ) : (
        <div className="monitoring-empty">Загрузка…</div>
      )}
    </div>
  );
}

function PageMonitoring({ onNavigate, effectivePermissions }) {
  const [attackId, setAttackId] = useState(() => {
    const { pageId, params } = parseAppHash();
    if (pageId !== 'monitoring') return '';
    const raw = params.get('attack') || '';
    try {
      return raw ? decodeURIComponent(raw) : '';
    } catch {
      return raw;
    }
  });

  useEffect(() => {
    const onHash = () => {
      const { pageId, params } = parseAppHash();
      if (pageId !== 'monitoring') return;
      const raw = params.get('attack') || '';
      try {
        setAttackId(raw ? decodeURIComponent(raw) : '');
      } catch {
        setAttackId(raw);
      }
    };
    addEventListener('hashchange', onHash);
    return () => removeEventListener('hashchange', onHash);
  }, []);

  const onBack = () => {
    location.hash = 'monitoring';
  };

  if (attackId) {
    return <MonitoringAttackDetail attackId={attackId} onBack={onBack} />;
  }
  return (
    <MonitoringListView
      onNavigate={onNavigate}
      effectivePermissions={effectivePermissions}
    />
  );
}

window.PageMonitoring = PageMonitoring;
