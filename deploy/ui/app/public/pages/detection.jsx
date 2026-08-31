const { useState, useEffect, useCallback, useMemo } = React;

function formatWhen(value) {
  if (!value) return '—';
  const raw = String(value);
  const iso = raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return raw;
  return `${date.toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })} МСК`;
}

function formatNum(value, digits = 2) {
  if (value == null || !Number.isFinite(Number(value))) return '—';
  return Number(value).toLocaleString('ru-RU', { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

function formatGrowth(value) {
  if (value == null || !Number.isFinite(Number(value))) return 'пусто';
  return `×${Number(value).toFixed(2)}`;
}

function formatPct(value) {
  if (value == null || !Number.isFinite(Number(value))) return 'пусто';
  return `${Number(value).toFixed(1)}%`;
}

function formatRate(value, units) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return '—';
  let v = n;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  const digits = v < 10 ? 2 : v < 100 ? 1 : 0;
  return `${v.toFixed(digits)} ${units[i]}`;
}

function formatBps(value) {
  return formatRate(value, ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с', 'Тбит/с']);
}

function formatPps(value) {
  return formatRate(value, ['п/с', 'тыс. п/с', 'млн п/с', 'млрд п/с']);
}

function objectKind(row) {
  return String(row?.scope || '').toLowerCase() === 'net' ? 'net' : 'client';
}

function matchesSearch(row, needle) {
  if (!needle) return true;
  const kindLabel = objectKind(row) === 'net' ? 'сеть net /24' : 'абонент клиент';
  return `${row.name || ''} ${row.scopeId || ''} ${kindLabel}`.toLowerCase().includes(needle);
}

function PageDetection() {
  const [data, setData] = useState({ minute: null, items: [] });
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [kind, setKind] = useState('all');

  const reload = useCallback(() => {
    setError('');
    return ApiClient.loadDetectionLatest()
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data.items || [])
      .filter((r) => kind === 'all' || objectKind(r) === kind)
      .filter((r) => matchesSearch(r, needle))
      .map((r) => ({ ...r, id: `${objectKind(r)}:${r.scopeId}` }));
  }, [data.items, q, kind]);

  return (
    <div className="col" style={{ gap: 14 }}>
      {error && (
        <div style={{ padding: 10, borderRadius: 8, background: 'var(--st-critical-bg)', color: 'var(--st-critical)' }}>
          {error}
        </div>
      )}

      <Card
        title="Детекция"
        subtitle={data.minute ? `Минута ${formatWhen(data.minute)} · ${rows.length} объектов` : 'Минута ещё не посчитана'}
        tools={(
          <div className="row" style={{ gap: 8, alignItems: 'center' }}>
            <div className="seg">
              <button
                type="button"
                className={kind === 'all' ? 'seg__item seg__item--active' : 'seg__item'}
                onClick={() => setKind('all')}
              >
                Все
              </button>
              <button
                type="button"
                className={kind === 'client' ? 'seg__item seg__item--active' : 'seg__item'}
                onClick={() => setKind('client')}
              >
                Абонент
              </button>
              <button
                type="button"
                className={kind === 'net' ? 'seg__item seg__item--active' : 'seg__item'}
                onClick={() => setKind('net')}
              >
                Сеть
              </button>
            </div>
            <Button size="sm" onClick={reload}>Обновить</Button>
          </div>
        )}
      >
        <DataTable
          key={`${data.minute || 'empty'}:${kind}`}
          rows={rows}
          rowKey="id"
          pageSize={50}
          emptyTitle="Нет данных"
          emptyDesc="Воркер ещё не записал минуту. Запустите npm run detection."
          toolbar={{
            search: q,
            onSearch: setQ,
            searchPlaceholder: 'имя, сеть, /24, id…',
          }}
          columns={[
            {
              key: 'name',
              title: 'Объект',
              width: 280,
              render: (r) => (
                <span>
                  <Badge tone={r.scope === 'client' ? 'neutral' : 'info'}>
                    {r.scope === 'client' ? 'абонент' : 'сеть /24'}
                  </Badge>
                  {' '}
                  {r.name}
                </span>
              ),
            },
            { key: 'bps', title: 'bps', num: true, width: 120, render: (r) => formatBps(r.bps) },
            { key: 'pps', title: 'pps', num: true, width: 120, render: (r) => formatPps(r.pps) },
            { key: 'growthBps', title: 'Рост bps', num: true, width: 110, render: (r) => formatGrowth(r.growthBps) },
            { key: 'growthPps', title: 'Рост pps', num: true, width: 110, render: (r) => formatGrowth(r.growthPps) },
            {
              key: 'synAttempts',
              title: 'Попытки',
              num: true,
              width: 110,
              render: (r) => formatNum(r.synAttempts, 0),
            },
            {
              key: 'answerPct',
              title: 'Ответ',
              num: true,
              width: 100,
              render: (r) => formatPct(r.answerPct),
            },
            {
              key: 'halfOpenPct',
              title: 'Полуоткрытые',
              num: true,
              width: 130,
              render: (r) => formatPct(r.halfOpenPct),
            },
            {
              key: 'halfOpenReplyPct',
              title: 'Не зашли',
              num: true,
              width: 110,
              render: (r) => formatPct(r.halfOpenReplyPct),
            },
            { key: 'avgPacketBytes', title: 'Средний пакет', num: true, width: 130, render: (r) => `${formatNum(r.avgPacketBytes, 0)} Б` },
            { key: 'cvPercent', title: 'CV', num: true, width: 90, render: (r) => (r.cvPercent == null ? '—' : `${formatNum(r.cvPercent, 1)}%`) },
          ]}
        />
      </Card>
    </div>
  );
}

window.PageDetection = PageDetection;
