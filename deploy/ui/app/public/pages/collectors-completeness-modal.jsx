/* global React, ApiClient, Button, Modal, TimeSeriesSparkChart, Icon, fmtNum */

const { useState, useEffect } = React;

const EXPORTER_STATUS_LABELS = {
  working: 'работает',
  no_data: 'нет данных',
  no_connection: 'нет связи',
};

const TONE_CLASS = {
  healthy: 'completeness-tone-green',
  warning: 'completeness-tone-yellow',
  critical: 'completeness-tone-red',
  idle: 'completeness-tone-unknown',
};

function fmtPct(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return `${Number(value).toFixed(2)}%`;
}

function fmtCompactCount(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} млн`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)} тыс`;
  return String(Math.round(n));
}

function fmtTs(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function FunnelLine({ line, onNavigate }) {
  if (!line) return null;

  if (line.kind === 'loss') {
    const toneClass = line.tone ? TONE_CLASS[line.tone] || '' : '';
    return (
      <div className={`completeness-funnel-line completeness-funnel-line--loss ${toneClass}`}>
        <span className="completeness-funnel-label">{line.label}</span>
        <span className="completeness-funnel-value mono">{fmtCompactCount(line.value)}</span>
        {(line.lossPctLabel || line.lossPct != null) && (
          <span className="completeness-funnel-pct mono">({line.lossPctLabel || fmtPct(line.lossPct)})</span>
        )}
      </div>
    );
  }

  if (line.kind === 'exclusion') {
    return (
      <div className="completeness-funnel-line completeness-funnel-line--exclusion">
        <span className="completeness-funnel-label">{line.label}</span>
        <span className="completeness-funnel-value mono">{fmtCompactCount(line.value)}</span>
        {line.note && <span className="completeness-funnel-note">{line.note}</span>}
        {onNavigate && (
          <button
            type="button"
            className="completeness-funnel-link"
            onClick={() => {
              sessionStorage.setItem('grapes-collectors-tab', 'exclusions');
              onNavigate('collectors');
            }}
          >
            Исключения потоков
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="completeness-funnel-line">
      <div className="completeness-funnel-line-main">
        <span className="completeness-funnel-label">{line.label}</span>
        {line.sourceLabel && (
          <span className="completeness-funnel-source">{line.sourceLabel}</span>
        )}
        <span className="completeness-funnel-value mono">{fmtCompactCount(line.value)}</span>
        {line.completenessPct != null && (
          <span className="completeness-funnel-pct mono completeness-tone-green">{fmtPct(line.completenessPct)}</span>
        )}
        {line.note && <span className="completeness-funnel-note">{line.note}</span>}
      </div>
    </div>
  );
}

function MetricCard({ title, rows }) {
  if (!rows || rows.length === 0) return null;
  return (
    <div className="completeness-metric-card">
      <div className="completeness-metric-card-title">{title}</div>
      <dl className="completeness-metric-card-grid">
        {rows.map((row) => (
          <div key={row.key} className="completeness-metric-row">
            <dt>{row.label}</dt>
            <dd className={row.tone ? TONE_CLASS[row.tone] : ''}>{row.display ?? fmtNum(row.value)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function buildSpoolRows(spool) {
  if (!spool) return [];
  return [
    { key: 'recordsAcked', label: 'записей подтверждено', value: spool.recordsAcked },
    { key: 'spoolCorruptionFrames', label: 'повреждено кадров', value: spool.spoolCorruptionFrames, tone: spool.spoolCorruptionFrames > 0 ? 'critical' : undefined },
    { key: 'lagSegments', label: 'отставание', display: `${fmtNum(spool.lagSegments)} сегментов` },
    { key: 'drainerProgressAgeSec', label: 'возраст прогресса', display: `${Number(spool.drainerProgressAgeSec || 0).toFixed(1)} с` },
    { key: 'insertErrs', label: 'ошибок вставки', value: spool.insertErrs, tone: spool.insertErrs > 0 ? 'critical' : undefined },
    { key: 'chQueueDrops', label: 'сбросов очереди', value: spool.chQueueDrops, tone: spool.chQueueDrops > 0 ? 'critical' : undefined },
  ];
}

function buildNetflowRows(netflow) {
  if (!netflow) return [];
  const rows = [
    { key: 'nfRecordsOut', label: 'отправлено записей', value: netflow.nfRecordsOut },
    { key: 'nfPacketsOut', label: 'датаграмм', value: netflow.nfPacketsOut },
    { key: 'nfSendErrs', label: 'ошибок отправки', value: netflow.nfSendErrs, tone: netflow.nfSendErrs > 0 ? 'critical' : undefined },
  ];
  if (netflow.nfSocketDrops != null) {
    rows.push({
      key: 'nfSocketDrops',
      label: 'дропов сокета получателя',
      value: netflow.nfSocketDrops,
      tone: netflow.nfSocketDropTone === 'critical' ? 'critical' : netflow.nfSocketDropTone === 'warning' ? 'warning' : undefined,
    });
  }
  if (netflow.nfDsts) {
    rows.push({ key: 'nfDsts', label: 'Получатели', display: netflow.nfDsts });
  }
  return rows;
}

function fmtBreakdownValue(row) {
  if (row.kind === 'result') return fmtPct(row.value);
  return fmtCompactCount(row.value);
}

function fmtBreakdownPct(row) {
  if (row.kind === 'result') return '—';
  if (row.pctOfBase == null) return '—';
  return fmtPct(Math.min(100, row.pctOfBase));
}

function LossBreakdownRow({ row }) {
  const toneClass = {
    base: '',
    accounted: 'completeness-loss-row--accounted',
    exclusion: 'completeness-loss-row--exclusion',
    sum: 'completeness-loss-row--sum',
    result: 'completeness-loss-row--result',
    loss: row.value > 0 ? 'completeness-loss-row--loss' : '',
    unconfirmed: row.value > 0 ? 'completeness-loss-row--unconfirmed' : '',
    critical: row.value > 0 ? 'completeness-loss-row--critical' : '',
    info: '',
  }[row.kind] || '';

  return (
    <tr className={toneClass}>
      <td className="completeness-loss-table__label">{row.label}</td>
      <td className="completeness-loss-table__value mono">{fmtBreakdownValue(row)}</td>
      <td className="completeness-loss-table__pct mono">{fmtBreakdownPct(row)}</td>
    </tr>
  );
}

function LossBreakdownPanel({ breakdown }) {
  const [open, setOpen] = useState(false);
  if (!breakdown?.sections?.length) return null;

  return (
    <div className="completeness-loss-breakdown">
      <button
        type="button"
        className="completeness-loss-breakdown__toggle"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <Icon name={open ? 'chevU' : 'chevD'} size={14} />
        <span>Статистика потерь</span>
      </button>
      {open && (
        <div className="completeness-loss-breakdown__body">
          {breakdown.sections.map((section) => (
            <div key={section.id} className="completeness-loss-breakdown__section">
              <div className="completeness-loss-breakdown__section-title">{section.title}</div>
              <table className="completeness-loss-table">
                <thead>
                  <tr>
                    <th>Показатель</th>
                    <th>За окно</th>
                    <th>%</th>
                  </tr>
                </thead>
                <tbody>
                  {section.rows.map((row) => (
                    <LossBreakdownRow key={row.key} row={row} />
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function fmtPctAxis(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return `${Math.round(Number(value))}%`;
}

function CompletenessHistoryChart({ history, loading }) {
  if (loading) {
    return <div className="completeness-history-loading">Загрузка истории…</div>;
  }
  const buckets = history?.buckets || [];
  if (!buckets.length) {
    return (
      <div className="completeness-history-empty">
        Нет данных за 24 ч (нужны snapshots с растущими счётчиками).
      </div>
    );
  }

  const points = buckets.map((p) => ({
    bucketMs: new Date(p.ts).getTime(),
    completenessPct: p.completenessPct,
  }));

  return (
    <TimeSeriesSparkChart
      points={points}
      height={220}
      valueKey="completenessPct"
      valueLabel="Полнота"
      formatValue={fmtPct}
      axisFormatter={fmtPctAxis}
      bucketSeconds={history?.bucketSeconds || 900}
      skipLeadingGaps
      className="completeness-history-chart"
    />
  );
}

function CollectorsCompletenessModal({ open, source, onClose, onNavigate }) {
  const [detail, setDetail] = useState(null);
  const [history, setHistory] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!open || !source?.sourceId) {
      setDetail(null);
      setHistory(null);
      setError(null);
      return undefined;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    (async () => {
      const [detailRes, historyRes] = await Promise.all([
        ApiClient.loadCompletenessDetail(source.sourceId),
        ApiClient.loadCompletenessHistory(source.sourceId),
      ]);
      if (cancelled) return;

      if (detailRes.source === 'error') {
        setError(detailRes.error || 'Не удалось загрузить детали');
        setDetail(null);
      } else {
        setDetail(detailRes.data);
      }

      if (historyRes.source === 'error') {
        setHistory(null);
      } else {
        setHistory(historyRes.data);
      }

      setLoading(false);
    })();

    return () => {
      cancelled = true;
    };
  }, [open, source?.sourceId]);

  if (!open || !source) return null;

  const c = source.completeness;
  const verdict = detail?.verdict;
  const funnel = detail?.packetFunnel || [];
  const spoolRows = buildSpoolRows(detail?.spool);
  const netflowRows = buildNetflowRows(detail?.netflow);
  const aggregation = detail?.aggregation;
  const lossBreakdown = detail?.lossBreakdown;

  const windowMinutes = detail?.windowMinutes || c?.windowMinutes || 30;
  const windowLabel = `${windowMinutes} мин`;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Подробнее: полнота сбора"
      subtitle={`${source.sourceId} · окно ${windowLabel}`}
      size="lg"
      footer={<Button kind="ghost" onClick={onClose}>Закрыть</Button>}
    >
      {loading && !detail && (
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>Загрузка…</div>
      )}

      {error && (
        <div className="form-error" style={{ marginBottom: 12 }}>{error}</div>
      )}

      {!loading && !detail && !error && !c && (
        <div style={{ font: 'var(--pv-text-body-3)', color: 'var(--fg-secondary)' }}>
          Нет health snapshots для этого экспортёра.
        </div>
      )}

      {(detail || c) && (
        <div className="completeness-modal-body">
          {verdict && (
            <section className="completeness-modal-section">
              <h3 className="completeness-modal-section-title">Вердикт</h3>
              <div className="completeness-verdict">
                <div className="completeness-verdict-headline">{verdict.headline}</div>
                {verdict.subline && verdict.subline.split('\n').map((line, idx) => (
                  <div key={idx} className="completeness-verdict-line">{line}</div>
                ))}
              </div>
            </section>
          )}

          {funnel.length > 0 && (
            <section className="completeness-modal-section">
              <h3 className="completeness-modal-section-title">Статистика (пакеты)</h3>
              <div className="completeness-funnel">
                {funnel.map((line) => (
                  <FunnelLine key={line.id} line={line} onNavigate={onNavigate} />
                ))}
              </div>
              {aggregation?.text && (
                <div className="completeness-aggregation">{aggregation.text}</div>
              )}
              <LossBreakdownPanel breakdown={lossBreakdown} />
            </section>
          )}

          {(spoolRows.length > 0 || netflowRows.length > 0) && (
            <section className="completeness-modal-section completeness-modal-cards">
              {spoolRows.length > 0 && (
                <MetricCard title="Кеш и запись" rows={spoolRows} />
              )}
              {netflowRows.length > 0 && (
                <MetricCard title="NetFlow-экспорт" rows={netflowRows} />
              )}
            </section>
          )}

          <section className="completeness-modal-section">
            <h3 className="completeness-modal-section-title">История полноты (24 ч)</h3>
            <CompletenessHistoryChart history={history} loading={loading} />
          </section>

          {c && (
            <section className="completeness-modal-section completeness-modal-meta">
              <div className="completeness-meta-grid">
                <span>Snapshots: {fmtNum(c.snapshotCount)}</span>
                <span>Статус: {EXPORTER_STATUS_LABELS[c.exporterStatus] || c.exporterStatus || '—'}</span>
                <span>Последний snapshot: {fmtTs(c.lastSnapshotAt)}</span>
              </div>
            </section>
          )}
        </div>
      )}
    </Modal>
  );
}

Object.assign(window, { CollectorsCompletenessModal });
