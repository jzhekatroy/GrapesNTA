/* Root app: routing + shell + global toast stack. */

const THEME_TRANSITION_MS = 350;

function App() {
  const [registryReady, setRegistryReady] = useState(false);
  const [validIds, setValidIds] = useState(new Set(['dashboard']));
  const [hiddenPageIds, setHiddenPageIds] = useState(new Set());
  const [pageTitles, setPageTitlesState] = useState({});
  const initialRaw = (location.hash || '#dashboard').slice(1);
  const initialQ = initialRaw.indexOf('?');
  const initialPageId = initialQ >= 0 ? initialRaw.slice(0, initialQ) : initialRaw;
  const [page, setPage] = useState(initialPageId === 'collector-status' ? 'collectors' : initialPageId);
  const [hashRoute, setHashRoute] = useState(() => location.hash || '');
  const [collapsed, setCollapsed] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('grapes-theme') || 'dark');
  const [timeRange, setTimeRange] = useState('24h');
  const [customPeriod, setCustomPeriod] = useState(defaultCustomPeriod);
  const [periodZoomStack, setPeriodZoomStack] = useState([]);
  const periodRef = useRef({ timeRange, customPeriod });
  const [directions, setDirections] = useState(defaultDirectionsEnabled);
  const [collectorFilter, setCollectorFilter] = useState([]);
  const [timezonePref, setTimezonePref] = useState(() => loadTimezonePreference());
  const displayTimezone = resolveDisplayTimezone(timezonePref);
  const [auth, setAuth] = useState({ loading: true, user: null });
  const [refreshKey, setRefreshKey] = useState(0);
  const [monitoringDeviationsTotal, setMonitoringDeviationsTotal] = useState(0);
  const [monitoringDeviationsError, setMonitoringDeviationsError] = useState('');
  const themeInitialized = useRef(false);

  useEffect(() => {
    let cancelled = false;
    AppPages.load()
      .then((pages) => {
        if (cancelled) return;
        const titles = AppPages.titlesMap(pages);
        const ids = AppPages.validIds(pages);
        const hidden = AppPages.hiddenIds(pages);
        if (typeof setPageTitles === 'function') setPageTitles(titles);
        setPageTitlesState(titles);
        setValidIds(ids);
        setHiddenPageIds(hidden);
        setRegistryReady(true);
        const { pageId, params } = parseAppHash();
        const hashId = AppPages.resolvePageId(pageId, ids);
        if (pageId === 'collector-status') {
          location.replace(`${location.pathname}${location.search}#collectors`);
        }
        setPage(hashId);
        setHashRoute(location.hash || '');
        if (hashId === 'top' && params.toString()) {
          const global = applyTopTalkersUrlGlobals(params);
          if (global.timeRange) setTimeRange(global.timeRange);
          if (global.customPeriod) setCustomPeriod(global.customPeriod);
          if (global.directions) setDirections(global.directions);
          if (global.collectorFilter !== undefined) setCollectorFilter(global.collectorFilter);
        }
        if (hashId === 'explorer' && params.toString()) {
          const global = applyExplorerUrlGlobals(params);
          if (global.timeRange) setTimeRange(global.timeRange);
          if (global.customPeriod) setCustomPeriod(global.customPeriod);
          if (global.directions) setDirections(global.directions);
          if (global.collectorFilter !== undefined) setCollectorFilter(global.collectorFilter);
        }
        if (hashId === 'dns-explorer' && params.toString()) {
          const global = applyDnsExplorerUrlGlobals(params);
          if (global.timeRange) setTimeRange(global.timeRange);
          if (global.customPeriod) setCustomPeriod(global.customPeriod);
          if (global.collectorFilter !== undefined) setCollectorFilter(global.collectorFilter);
        }
      })
      .catch(() => {
        if (!cancelled) setRegistryReady(true);
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    AuthAccess.setEffectiveWritePermissions(auth.user?.effectiveWritePermissions || null);
  }, [auth.user]);

  useEffect(() => {
    const root = document.documentElement;
    const applyTheme = () => {
      root.setAttribute('data-theme', theme);
      localStorage.setItem('grapes-theme', theme);
    };

    if (!themeInitialized.current) {
      themeInitialized.current = true;
      applyTheme();
      return;
    }

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      applyTheme();
      return;
    }

    root.classList.add('theme-transition');
    applyTheme();
    const timer = window.setTimeout(() => {
      root.classList.remove('theme-transition');
    }, THEME_TRANSITION_MS);

    return () => window.clearTimeout(timer);
  }, [theme]);

  useEffect(() => {
    if (window.__GRAPES_RUNTIME__?.dataTimezone) {
      setDataTimezone(window.__GRAPES_RUNTIME__.dataTimezone);
    }
  }, []);

  useEffect(() => {
    setDisplayTimezonePreference(timezonePref);
  }, [timezonePref]);

  useEffect(() => {
    periodRef.current = { timeRange, customPeriod };
  }, [timeRange, customPeriod]);

  useEffect(() => {
    if (!auth.user) return undefined;
    const perms = auth.user?.effectivePermissions;
    if (perms && !perms.monitoring) return undefined;

    let cancelled = false;
    const load = () => {
      ApiClient.loadMonitoringParameters().then((result) => {
        if (cancelled) return;
        if (result.source === 'error') {
          setMonitoringDeviationsTotal(0);
          setMonitoringDeviationsError(result.error || ApiClient.LOAD_FAILED);
          return;
        }
        setMonitoringDeviationsTotal(Number(result.meta?.totalDeviations24h) || 0);
        setMonitoringDeviationsError('');
      });
    };
    load();
    const timer = setInterval(load, 60_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [auth.user]);

  useEffect(() => {
    let cancelled = false;
    ApiClient.loadCurrentUser()
      .then((user) => {
        if (!cancelled) setAuth({ loading: false, user });
      })
      .catch(() => {
        if (!cancelled) setAuth({ loading: false, user: null });
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!registryReady) return;
    const onHash = () => {
      const { pageId, params } = parseAppHash();
      const resolved = AppPages.resolvePageId(pageId, validIds);
      if (pageId === 'collector-status') {
        location.replace(`${location.pathname}${location.search}#collectors`);
        return;
      }
      setPage(resolved);
      setHashRoute(location.hash || '');
      if (pageId === 'top' && params.toString()) {
        const global = applyTopTalkersUrlGlobals(params);
        if (global.timeRange) setTimeRange(global.timeRange);
        if (global.customPeriod) setCustomPeriod(global.customPeriod);
        if (global.directions) setDirections(global.directions);
        if (global.collectorFilter !== undefined) setCollectorFilter(global.collectorFilter);
      }
      if (pageId === 'explorer' && params.toString()) {
        const global = applyExplorerUrlGlobals(params);
        if (global.timeRange) setTimeRange(global.timeRange);
        if (global.customPeriod) setCustomPeriod(global.customPeriod);
        if (global.directions) setDirections(global.directions);
        if (global.collectorFilter !== undefined) setCollectorFilter(global.collectorFilter);
      }
      if (pageId === 'dns-explorer' && params.toString()) {
        const global = applyDnsExplorerUrlGlobals(params);
        if (global.timeRange) setTimeRange(global.timeRange);
        if (global.customPeriod) setCustomPeriod(global.customPeriod);
        if (global.collectorFilter !== undefined) setCollectorFilter(global.collectorFilter);
      }
    };
    addEventListener('hashchange', onHash);
    return () => removeEventListener('hashchange', onHash);
  }, [registryReady, validIds]);

  const navigate = useCallback((id) => {
    if (id === '__toggle') { setCollapsed(v => !v); return; }
    if (id === '__theme')  { setTheme(t => t === 'dark' ? 'light' : 'dark'); return; }
    if (!validIds.has(id)) return;
    setPage(id);
    location.hash = id;
  }, [validIds]);

  const handleLogin = (user) => setAuth({ loading: false, user });
  const handleLogout = async () => {
    try {
      await ApiClient.logout();
    } catch (err) {
      console.warn('[Auth] logout failed:', err.message);
    }
    setAuth({ loading: false, user: null });
  };
  const reloadCurrentUser = async () => {
    const user = await ApiClient.loadCurrentUser();
    setAuth({ loading: false, user });
  };
  const handleRefresh = useCallback(() => setRefreshKey((k) => k + 1), []);
  const toggleTheme = useCallback(() => setTheme(t => t === 'dark' ? 'light' : 'dark'), []);

  const handleTimeRangeChange = useCallback((next) => {
    setPeriodZoomStack([]);
    setTimeRange(next);
  }, []);

  const handleCustomPeriodChange = useCallback((next) => {
    setPeriodZoomStack([]);
    setCustomPeriod(next);
  }, []);

  const handleTimezonePrefChange = useCallback((next) => {
    setDisplayTimezonePreference(next);
    setTimezonePref(next);
  }, []);

  const applyChartRangeZoom = useCallback((range) => {
    if (!range?.from || !range?.to || validateCustomPeriod(range)) return;
    const prev = periodRef.current;
    setPeriodZoomStack((stack) => [...stack, prev]);
    setTimeRange('custom');
    setCustomPeriod({ from: range.from, to: range.to });
  }, []);

  const resetChartRangeZoom = useCallback(() => {
    setPeriodZoomStack((stack) => {
      if (!stack.length) return stack;
      const prev = stack[stack.length - 1];
      setTimeRange(prev.timeRange);
      setCustomPeriod(prev.customPeriod);
      return stack.slice(0, -1);
    });
  }, []);

  const canAccessPage = useCallback((pageId) => {
    const perms = auth.user?.effectivePermissions;
    if (!perms) return true;
    if (pageId === 'snmp') return !!(perms.snmp || perms.collectors);
    if (pageId === 'smtp') return !!perms.diagnostics;
    return !!perms[pageId];
  }, [auth.user]);

  if (auth.loading || !registryReady) {
    return <AuthFrame title="Grapes NTA" subtitle="Проверяем сессию..." theme={theme} onToggleTheme={toggleTheme} />;
  }

  if (!auth.user) {
    return <LoginScreen onLogin={handleLogin} theme={theme} onToggleTheme={toggleTheme} />;
  }

  if (auth.user.forcePasswordChange) {
    return <ForcePasswordChangeScreen user={auth.user} onDone={reloadCurrentUser} onLogout={handleLogout} theme={theme} onToggleTheme={toggleTheme} />;
  }

  let pageEl;
  if (!canAccessPage(page)) {
    pageEl = <PageAccessDenied pageId={page} onNavigate={navigate} />;
  } else {
    switch (page) {
      case 'dashboard':  pageEl = <PageDashboard key={`${refreshKey}-${displayTimezone}`} onNavigate={navigate} directions={directions} timeRange={timeRange} customPeriod={customPeriod} collectorFilter={collectorFilter} displayTimezone={displayTimezone} onChartRangeSelect={applyChartRangeZoom} />; break;
      case 'monitoring': pageEl = <PageMonitoring key={`${refreshKey}-${displayTimezone}`} displayTimezone={displayTimezone} />; break;
      case 'explorer':   pageEl = <PageExplorer key={`${refreshKey}-${displayTimezone}-${hashRoute}`} onNavigate={navigate} displayTimezone={displayTimezone} />; break;
      case 'dns-explorer': pageEl = <PageDnsExplorer key={`${refreshKey}-${displayTimezone}-${hashRoute}`} onNavigate={navigate} displayTimezone={displayTimezone} />; break;
      case 'observations': pageEl = <PageObservations key={refreshKey} onNavigate={navigate} />; break;
      case 'diagnostics': pageEl = <PageDiagnostics key={refreshKey} />; break;
      case 'top':        pageEl = <PageTop key={`${refreshKey}-${displayTimezone}`} onNavigate={navigate} timeRange={timeRange} customPeriod={customPeriod} directions={directions} collectorFilter={collectorFilter} displayTimezone={displayTimezone} />; break;
      case 'vlan':       pageEl = <PageVlan key={refreshKey} />; break;
      case 'smtp':       pageEl = <PageSmtp key={refreshKey} />; break;
      case 'dns':        pageEl = <PageDnsQueries key={`${refreshKey}-${displayTimezone}-${(collectorFilter || []).join(',')}`} onNavigate={navigate} timeRange={timeRange} customPeriod={customPeriod} collectorFilter={collectorFilter} displayTimezone={displayTimezone} onChartRangeSelect={applyChartRangeZoom} />; break;
      case 'collectors': pageEl = <PageCollectors key={refreshKey} onNavigate={navigate} />; break;
      case 'snmp': pageEl = (
        <PageSnmp
          key={`${refreshKey}-${displayTimezone}`}
          displayTimezone={displayTimezone}
          canOpenInterfaceRoles={canAccessPage('interface-roles')}
        />
      ); break;
      case 'bmp':        pageEl = <PageBmp key={refreshKey} />; break;
      case 'interface-roles': pageEl = <PageInterfaceRoles key={refreshKey} onNavigate={navigate} />; break;
      case 'routers':    pageEl = <PageRouters key={refreshKey} />; break;
      case 'entities':   pageEl = <PageEntities key={refreshKey} />; break;
      case 'cidr':       pageEl = <PageCIDR key={refreshKey} />; break;
      case 'dns-resolvers': pageEl = <PageDnsResolvers key={refreshKey} />; break;
      case 'port-services': pageEl = <PagePortServices key={refreshKey} />; break;
      case 'flow-exclusions': pageEl = <PageFlowExclusions key={refreshKey} />; break;
      case 'users':      pageEl = <PageUsers key={refreshKey} currentUser={auth.user} onAuthRefresh={reloadCurrentUser} />; break;
      case 'ttl':        pageEl = <PageTTL key={refreshKey} />; break;
      default:           pageEl = <PageComingSoon key={refreshKey} pageId={page} onNavigate={navigate} />;
    }
  }

  return (
    <div className="app" data-collapsed={collapsed} data-screen-label={`Grapes NTA · ${pageTitles[page]?.title || page}`}>
      <Sidebar
        current={page}
        onNavigate={navigate}
        collapsed={collapsed}
        effectivePermissions={auth.user?.effectivePermissions}
      />
      <Header
        current={page}
        onNavigate={navigate}
        onToggleSidebar={() => setCollapsed(v => !v)}
        currentUser={auth.user}
        onLogout={handleLogout}
        onRefresh={handleRefresh}
        theme={theme}
        onToggleTheme={() => navigate('__theme')}
        timeRange={timeRange}
        onTimeRangeChange={handleTimeRangeChange}
        customPeriod={customPeriod}
        onCustomPeriodChange={handleCustomPeriodChange}
        chartZoomDepth={periodZoomStack.length}
        onChartZoomReset={resetChartRangeZoom}
        directions={directions}
        onDirectionsChange={setDirections}
        collectorFilter={collectorFilter}
        onCollectorFilterChange={setCollectorFilter}
        pageTitles={pageTitles}
        hiddenPageIds={hiddenPageIds}
        displayTimezone={displayTimezone}
        timezonePref={timezonePref}
        onTimezonePrefChange={handleTimezonePrefChange}
        monitoringDeviationsTotal={monitoringDeviationsTotal}
        monitoringDeviationsError={monitoringDeviationsError}
      />
      <main className="main">
        {pageEl}
      </main>
      <ToastStack />
    </div>
  );
}

function AuthFrame({ title, subtitle, children, theme, onToggleTheme }) {
  return (
    <div className="auth-screen">
      <Card className="auth-card">
        {onToggleTheme && (
          <button
            type="button"
            className="auth-card__theme icon-btn tt"
            data-tt={theme === 'dark' ? 'Светлая тема' : 'Тёмная тема'}
            onClick={onToggleTheme}
          >
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={18} />
          </button>
        )}
        <div className="auth-brand">
          <div className="sidebar__logo"><GrapesGlyph size={20} /></div>
          <div>
            <div className="auth-title">{title}</div>
            {subtitle && <div className="auth-subtitle">{subtitle}</div>}
          </div>
        </div>
        {children}
      </Card>
      <ToastStack />
    </div>
  );
}

function LoginScreen({ onLogin, theme, onToggleTheme }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setSaving(true);
    try {
      const result = await ApiClient.login({ username, password });
      onLogin(result.user);
    } catch (err) {
      setError(err.message || 'Не удалось войти');
    } finally {
      setSaving(false);
    }
  };

  return (
    <AuthFrame title="Вход в Grapes NTA" subtitle="Используйте локальную учётную запись" theme={theme} onToggleTheme={onToggleTheme}>
      <form className="col" style={{gap: 14}} onSubmit={submit}>
        <div className="field">
          <label>Имя пользователя</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label>Пароль</label>
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        {error && <div className="form-error">{error}</div>}
        <Button kind="primary" type="submit" disabled={saving || !username || !password}>
          {saving ? 'Вход...' : 'Войти'}
        </Button>
      </form>
    </AuthFrame>
  );
}

function ForcePasswordChangeScreen({ user, onDone, onLogout, theme, onToggleTheme }) {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setSaving(true);
    try {
      await ApiClient.changeUserPassword(user.id, { password });
      pushToast({ kind: 'success', title: 'Пароль изменён' });
      await onDone();
    } catch (err) {
      setError(err.message || 'Не удалось изменить пароль');
    } finally {
      setSaving(false);
    }
  };

  return (
    <AuthFrame title="Смена пароля" subtitle={`Первый вход: ${user.username}`} theme={theme} onToggleTheme={onToggleTheme}>
      <form className="col" style={{gap: 14}} onSubmit={submit}>
        <div className="field">
          <label>Новый пароль</label>
          <div className="row" style={{gap: 8}}>
            <input
              className="input"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Минимум 12 символов"
              autoFocus
            />
            <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>
              {showPassword ? 'Скрыть' : 'Показать'}
            </Button>
          </div>
        </div>
        {error && <div className="form-error">{error}</div>}
        <div className="row" style={{justifyContent: 'space-between'}}>
          <Button kind="ghost" onClick={onLogout}>Выйти</Button>
          <Button kind="primary" type="submit" disabled={saving || password.length < 12}>
            {saving ? 'Сохранение...' : 'Сменить пароль'}
          </Button>
        </div>
      </form>
    </AuthFrame>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
