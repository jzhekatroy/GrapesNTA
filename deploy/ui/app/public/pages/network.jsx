/* Моя сеть — CIDR, владельцы L3 и VLAN в одной странице с вкладками. */

const NETWORK_TAB_KEY = 'grapes-network-tab';
const NETWORK_TABS = [
  { id: 'entities', label: 'Владельцы L3', perm: 'entities' },
  { id: 'cidr', label: 'CIDR', perm: 'cidr' },
  { id: 'vlan', label: 'VLAN', perm: 'vlan' },
];

function canAccessNetworkTab(effectivePermissions, perm) {
  if (!effectivePermissions) return true;
  return !!effectivePermissions[perm];
}

function PageNetwork({ effectivePermissions, initialTab }) {
  const available = useMemo(
    () => NETWORK_TABS.filter((t) => canAccessNetworkTab(effectivePermissions, t.perm)),
    [effectivePermissions],
  );

  const [tab, setTab] = useState(() => {
    const pending = sessionStorage.getItem(NETWORK_TAB_KEY);
    if (pending) sessionStorage.removeItem(NETWORK_TAB_KEY);
    const preferred = initialTab || pending;
    if (preferred && NETWORK_TABS.some((t) => t.id === preferred)) return preferred;
    return available[0]?.id || 'entities';
  });
  const [refreshKey, setRefreshKey] = useState(0);
  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    if (!available.length) return;
    if (!available.some((t) => t.id === tab)) setTab(available[0].id);
  }, [available, tab]);

  useEffect(() => {
    if (!initialTab) return;
    if (available.some((t) => t.id === initialTab)) setTab(initialTab);
  }, [initialTab, available]);

  if (!available.length) {
    return (
      <div className="main__container">
        <Empty
          icon="cidr"
          title="Нет доступа"
          desc="Нет прав ни на одну вкладку раздела «Моя сеть»."
        />
      </div>
    );
  }

  return (
    <div className="main__container">
      <div className="page-head">
        <div>
          <h1>Моя сеть</h1>
          <p>Владельцы L3, собственные сети (CIDR) и справочник VLAN.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Button kind="ghost" icon="refresh" onClick={reload}>Обновить</Button>
        </div>
      </div>

      <div className="seg" style={{ width: 'fit-content', marginBottom: 16 }}>
        {available.map((t) => (
          <button
            key={t.id}
            type="button"
            className={tab === t.id ? 'is-active' : ''}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'cidr' && (
        <PageCIDR embedded refreshKey={refreshKey} onReload={reload} />
      )}
      {tab === 'entities' && (
        <PageEntities embedded refreshKey={refreshKey} onReload={reload} />
      )}
      {tab === 'vlan' && (
        <PageVlan embedded refreshKey={refreshKey} onReload={reload} />
      )}
    </div>
  );
}

Object.assign(window, { PageNetwork, NETWORK_TAB_KEY });
