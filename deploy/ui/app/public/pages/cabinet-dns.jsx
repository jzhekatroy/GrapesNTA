/* DNS-раздел личного кабинета клиента */

const CABINET_DNS_TOP_LIMIT = 50;
const CABINET_DNS_QUERY_LIMITS = [100, 250, 500, 1000];
const CABINET_DNS_DETAIL_MAX_DAYS = 30;
const CABINET_DNS_TOP_MAX_DAYS = 180;

function dnsRcodeLabel(rcode) {
  const n = Number(rcode);
  if (n === 0) return 'NOERROR';
  if (n === 3) return 'NXDOMAIN';
  if (n === 2) return 'SERVFAIL';
  return String(rcode ?? '—');
}

function PageCabinetDns({ timeRange, customPeriod, displayTimezone }) {
  const [domainsState, setDomainsState] = useState({ source: 'loading', data: [], meta: null, error: '' });
  const [queriesState, setQueriesState] = useState({ source: 'idle', data: [], meta: null, error: '' });
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [queryLimit, setQueryLimit] = useState(100);
  const [sourceId, setSourceId] = useState('');

  const periodLabel = timeRangeLabel(timeRange, customPeriod);
  const periodKey = `${timeRange}|${customPeriod?.from || ''}|${customPeriod?.to || ''}`;
  const sourceOptions = Array.isArray(domainsState.meta?.sources)
    ? domainsState.meta.sources
    : [];

  useEffect(() => {
    setSelectedDomain(null);
    setQueriesState({ source: 'idle', data: [], meta: null, error: '' });
  }, [periodKey, sourceId]);

  useEffect(() => {
    let cancelled = false;
    setDomainsState({ source: 'loading', data: [], meta: null, error: '' });
    ApiClient.loadCabinetDnsDomains({
      timeRange,
      customPeriod,
      sourceId: sourceId || undefined,
      limit: CABINET_DNS_TOP_LIMIT,
    })
      .then((result) => {
        if (cancelled) return;
        setDomainsState({
          source: result.source || 'error',
          data: Array.isArray(result.data) ? result.data : [],
          meta: result.meta || null,
          error: result.error || '',
          loadMs: result.loadMs ?? null,
          serverMs: result.serverMs ?? null,
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setDomainsState({
            source: 'error',
            data: [],
            meta: null,
            error: err.message || ApiClient.LOAD_FAILED,
          });
        }
      });
    return () => { cancelled = true; };
  }, [periodKey, sourceId]);

  useEffect(() => {
    if (!selectedDomain) return undefined;
    let cancelled = false;
    setQueriesState({ source: 'loading', data: [], meta: null, error: '' });
    ApiClient.loadCabinetDnsQueries({
      timeRange,
      customPeriod,
      domain: selectedDomain,
      limit: queryLimit,
    })
      .then((result) => {
        if (cancelled) return;
        setQueriesState({
          source: result.source || 'error',
          data: Array.isArray(result.data) ? result.data : [],
          meta: result.meta || null,
          error: result.error || '',
          loadMs: result.loadMs ?? null,
          serverMs: result.serverMs ?? null,
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setQueriesState({
            source: 'error',
            data: [],
            meta: null,
            error: err.message || ApiClient.LOAD_FAILED,
          });
        }
      });
    return () => { cancelled = true; };
  }, [periodKey, selectedDomain, queryLimit]);

  const openDomain = (row) => {
    if (row?.folded || row?.domain === 'other' || row?.domain === 'unknown') return;
    setSelectedDomain(row.domain);
  };

  const detailTitle = selectedDomain ? formatCabinetDomainLabel({ domain: selectedDomain }) : '';

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>DNS</h1>
          <p>
            {selectedDomain
              ? `Запросы по домену ${detailTitle}`
              : `Топ доменов по регистрируемому имени · ${periodLabel}`}
          </p>
        </div>
        {selectedDomain && (
          <Button kind="ghost" icon="arrowL" onClick={() => setSelectedDomain(null)}>
            К топу доменов
          </Button>
        )}
      </div>

      {!selectedDomain ? (
        <Card
          title="Топ доменов"
          subtitle={`Глубина витрины до ${CABINET_DNS_TOP_MAX_DAYS} суток · ${periodLabel}`}
          loadMs={domainsState.loadMs}
          serverMs={domainsState.serverMs}
          tools={sourceOptions.length > 1 ? (
            <select
              className="input input--sm"
              value={sourceId}
              onChange={(e) => setSourceId(e.target.value)}
              title="Точка наблюдения"
            >
              <option value="">Все источники</option>
              {sourceOptions.map((src) => (
                <option key={src.id || src.sourceId} value={src.id || src.sourceId}>
                  {src.label || src.name || src.sourceId || src.id}
                </option>
              ))}
            </select>
          ) : null}
        >
          <p style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-caption-1)', marginTop: 0 }}>
            В таблице — регистрируемые домены, а не каждое полное имя запроса.
          </p>
          {domainsState.source === 'loading' ? (
            <div className="skeleton" style={{ height: 240 }} />
          ) : domainsState.source === 'error' ? (
            <CabinetErrorState error={domainsState.error} />
          ) : !domainsState.data.length ? (
            <CabinetEmptyState titleHint={CABINET_DNS_EMPTY_HINT} />
          ) : (
            <DataTable
              rows={domainsState.data}
              rowKey="domain"
              dense
              pageSize={15}
              resizableColumns={false}
              columns={[
                {
                  key: 'domain',
                  title: 'Домен',
                  render: (row) => {
                    const label = formatCabinetDomainLabel(row);
                    const clickable = !row.folded && row.domain !== 'other' && row.domain !== 'unknown';
                    if (!clickable) {
                      return <span className="cabinet-dns-domain-label">{label}</span>;
                    }
                    return (
                      <button type="button" className="link-btn" onClick={() => openDomain(row)}>
                        {label}
                      </button>
                    );
                  },
                },
                { key: 'queries', title: 'Запросы', align: 'right', num: true, render: (r) => fmtNum(r.queries) },
                { key: 'responses', title: 'Ответы', align: 'right', num: true, render: (r) => fmtNum(r.responses) },
                { key: 'nxdomain', title: 'Не найдено', align: 'right', num: true, render: (r) => fmtNum(r.nxdomain) },
                { key: 'servfail', title: 'Сбои DNS', align: 'right', num: true, render: (r) => fmtNum(r.servfail) },
              ]}
            />
          )}
        </Card>
      ) : (
        <Card
          title={detailTitle}
          subtitle={`Сырой журнал до ${CABINET_DNS_DETAIL_MAX_DAYS} суток · ${periodLabel}`}
          loadMs={queriesState.loadMs}
          serverMs={queriesState.serverMs}
          tools={(
            <select
              className="input input--sm"
              value={String(queryLimit)}
              onChange={(e) => setQueryLimit(Number(e.target.value) || 100)}
              title="Число строк"
            >
              {CABINET_DNS_QUERY_LIMITS.map((n) => (
                <option key={n} value={n}>{n} строк</option>
              ))}
            </select>
          )}
        >
          <p style={{ color: 'var(--fg-secondary)', font: 'var(--pv-text-caption-1)', marginTop: 0 }}>
            Список читается из сырого журнала (до {CABINET_DNS_DETAIL_MAX_DAYS} суток), тогда как топ доменов
            {' '}строится по витрине (до {CABINET_DNS_TOP_MAX_DAYS} суток). Показаны последние {queryLimit} записей.
          </p>
          {queriesState.source === 'loading' ? (
            <div className="skeleton" style={{ height: 240 }} />
          ) : queriesState.source === 'error' ? (
            <CabinetErrorState error={queriesState.error} />
          ) : !queriesState.data.length ? (
            <CabinetEmptyState>За выбранный период запросов по этому домену нет.</CabinetEmptyState>
          ) : (
            <DataTable
              rows={queriesState.data}
              rowKey={(row, idx) => `${row.ts}-${row.queryName}-${idx}`}
              dense
              pageSize={20}
              resizableColumns={false}
              columns={[
                {
                  key: 'ts',
                  title: 'Время',
                  render: (row) => formatDataTimestamp(row.ts, displayTimezone || getDisplayTimezone()),
                },
                { key: 'clientIp', title: 'Клиент', mono: true },
                { key: 'serverIp', title: 'Сервер', mono: true },
                { key: 'queryName', title: 'Имя', render: (r) => r.queryName || '—' },
                { key: 'qtype', title: 'Тип' },
                {
                  key: 'rcode',
                  title: 'Код',
                  render: (r) => (
                    <Badge tone={Number(r.rcode) === 0 ? 'success' : Number(r.rcode) === 3 ? 'warning' : 'critical'}>
                      {dnsRcodeLabel(r.rcode)}
                    </Badge>
                  ),
                },
                {
                  key: 'isResponse',
                  title: 'Событие',
                  render: (r) => (
                    <Badge tone={r.isResponse ? 'success' : 'info'}>
                      {r.isResponse ? 'Ответ' : 'Запрос'}
                    </Badge>
                  ),
                },
                { key: 'transport', title: 'Транспорт' },
              ]}
            />
          )}
        </Card>
      )}
    </div>
  );
}

Object.assign(window, { PageCabinetDns });
