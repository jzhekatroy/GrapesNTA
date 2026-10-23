/* Root app: routing + shell + global toast stack. */

const THEME_TRANSITION_MS = 350;

function t(key, params) {
  return GrapesI18n.t(key, params);
}

const LOGIN_ERROR_I18N = {
  invalid_credentials: 'auth.login.invalidCredentials',
  client_disabled: 'auth.login.clientDisabled',
  account_disabled: 'auth.login.accountDisabled',
  client_unbound: 'auth.login.clientUnbound',
};

function loginErrorMessage(err) {
  const code = err?.body?.code;
  const key = code && LOGIN_ERROR_I18N[code];
  if (key) return t(key);
  const msg = String(err?.message || '');
  if (err?.status === 401 && msg.includes('Вход с паролем')) return t('auth.login.invalidCredentials');
  if (err?.status === 403 && msg.includes('приостановлен')) return t('auth.login.clientDisabled');
  if (msg === 'Учётная запись отключена') return t('auth.login.accountDisabled');
  if (msg.includes('не привязана к клиенту')) return t('auth.login.clientUnbound');
  return msg || t('auth.login.failed');
}

function LazyPage({ pageId, exportName, fallback, ...props }) {
  const [ready, setReady] = useState(() => PageChunks.isLoaded(pageId));
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    if (PageChunks.isLoaded(pageId)) {
      setReady(true);
      setError(null);
      return undefined;
    }
    setReady(false);
    setError(null);
    PageChunks.load(pageId)
      .then(() => {
        if (!cancelled) setReady(true);
      })
      .catch((e) => {
        if (!cancelled) setError(e);
      });
    return () => { cancelled = true; };
  }, [pageId]);

  if (error) {
    return (
      <div className="other-ports-table__state">
        {error.message || t('app.pageLoadFailed')}
      </div>
    );
  }
  if (!ready) {
    return fallback ?? <div className="other-ports-table__state">{t('app.pageLoading')}</div>;
  }
  const Comp = PageChunks.component(pageId, exportName);
  if (!Comp) {
    return <div className="other-ports-table__state">{t('app.pageComponentMissing')}</div>;
  }
  return <Comp {...props} />;
}

function canAccessPageForUser(user, pageId) {
  const perms = user?.effectivePermissions;
  if (pageId === 'cabinet-settings' && !isCabinetMode(user)) {
    return false;
  }
  if (isCabinetMode(user)) {
    if (user?.cabinet?.bindMode === 'ports' && pageId === 'dns') return false;
    return CABINET_PAGE_IDS.has(pageId);
  }
  if (!perms) return true;
  if (pageId === 'snmp') return !!(perms.snmp || perms.collectors);
  if (pageId === 'smtp') return !!perms.diagnostics;
  if (pageId === 'cidr' || pageId === 'vlan' || pageId === 'entities') {
    return !!(perms.cidr || perms.vlan || perms.entities);
  }
  return !!perms[pageId];
}

function resolveRoleLandingPage(user, canAccess) {
  const requested = user?.role?.startPage || 'dashboard';
  const target = AppPages.resolvePageId(requested, canAccess.validIds);
  if (canAccessPageForUser(user, target)) return target;
  if (canAccessPageForUser(user, 'dashboard')) return 'dashboard';
  return target;
}

function isEmptyAppHash() {
  const hash = location.hash || '';
  return hash === '' || hash === '#';
}

function App() {
  const applyStartPageAfterLoginRef = useRef(false);
  const [registryReady, setRegistryReady] = useState(false);
  const [validIds, setValidIds] = useState(new Set(['dashboard']));
  const [hiddenPageIds, setHiddenPageIds] = useState(new Set());
  const [pageTitles, setPageTitlesState] = useState({});
  const [page, setPage] = useState(() => {
    const raw = (location.hash || '#dashboard').slice(1);
    const q = raw.indexOf('?');
    const pageId = q >= 0 ? raw.slice(0, q) : raw;
    if (pageId === 'flow-exclusions') {
      sessionStorage.setItem('grapes-collectors-tab', 'exclusions');
      return 'collectors';
    }
    if (pageId === 'erp-piterix') {
      sessionStorage.setItem('grapes-diagnostics-tab', 'erp');
      return 'diagnostics';
    }
    if (pageId === 'collector-status') return 'collectors';
    return pageId;
  });
  const [hashRoute, setHashRoute] = useState(() => location.hash || '');
  const [collapsed, setCollapsed] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('grapes-theme') || 'dark');
  const [locale, setLocale] = useState(() => GrapesLocale.resolveDisplayLocale({
    pending: GrapesLocale.readPendingLocale(),
  }));
  GrapesI18n.setLocale(locale);
  const [timeRange, setTimeRange] = useState('24h');
  const [customPeriod, setCustomPeriod] = useState(defaultCustomPeriod);
  const [periodZoomStack, setPeriodZoomStack] = useState([]);
  const periodRef = useRef({ timeRange, customPeriod });
  const [directions, setDirections] = useState(defaultDirectionsEnabled);
  const [cabinetDirections, setCabinetDirections] = useState(defaultCabinetDirectionsEnabled);
  const [collectorFilter, setCollectorFilter] = useState([]);
  const [timezonePref, setTimezonePref] = useState(() => loadTimezonePreference());
  const displayTimezone = resolveDisplayTimezone(timezonePref);
  const [auth, setAuth] = useState({ loading: true, user: null });
  const authRef = useRef(auth);
  authRef.current = auth;
  const [refreshKey, setRefreshKey] = useState(0);
  const [latestBuildInfo, setLatestBuildInfo] = useState(null);
  const [observationComposeTick, setObservationComposeTick] = useState(0);
  const themeInitialized = useRef(false);
  const lastAuditPageRef = useRef({ pageId: '', at: 0 });

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
        if (pageId === 'collector-status' || pageId === 'flow-exclusions') {
          if (pageId === 'flow-exclusions') {
            sessionStorage.setItem('grapes-collectors-tab', 'exclusions');
          }
          location.replace(`${location.pathname}${location.search}#collectors`);
        }
        if (pageId === 'erp-piterix') {
          sessionStorage.setItem('grapes-diagnostics-tab', 'erp');
          location.replace(`${location.pathname}${location.search}#diagnostics`);
        }
        if (pageId === 'vlan' || pageId === 'entities') {
          sessionStorage.setItem('grapes-network-tab', pageId);
          location.replace(`${location.pathname}${location.search}#cidr`);
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
    AuthAccess.setEffectivePermissions(auth.user?.effectivePermissions || null);
    AuthAccess.setEffectiveWritePermissions(auth.user?.effectiveWritePermissions || null);
    AuthAccess.setGrantedActions(auth.user?.permissions || null);
  }, [auth.user]);

  useEffect(() => {
    document.documentElement.lang = locale || 'ru';
  }, [locale]);

  useEffect(() => {
    if (auth.loading) return undefined;
    const accountLocale = GrapesLocale.normalizeLocale(auth.user?.locale);
    if (accountLocale) {
      GrapesLocale.clearPendingLocale();
      setLocale(accountLocale);
      return undefined;
    }
    const pending = GrapesLocale.readPendingLocale();
    if (!auth.user) {
      setLocale(pending || GrapesLocale.detectBrowserLocale());
      return undefined;
    }
    if (!pending) {
      setLocale(GrapesLocale.detectBrowserLocale());
      return undefined;
    }
    let cancelled = false;
    ApiClient.updateLocale(pending)
      .then((user) => {
        if (cancelled) return;
        GrapesLocale.clearPendingLocale();
        setLocale(pending);
        setAuth((prev) => ({ ...prev, user }));
      })
      .catch((err) => {
        if (cancelled) return;
        setLocale(pending);
        pushToast({ kind: 'error', title: t('app.localeSaveFailed'), desc: err.message });
      });
    return () => { cancelled = true; };
  }, [auth.loading, auth.user?.id, auth.user?.locale]);

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
    if (!auth.user) {
      setLatestBuildInfo(null);
      return undefined;
    }

    let cancelled = false;
    let baseline = '';
    let notified = false;
    const versionKey = (info) => {
      if (info?.commit) return info.commit;
      if (info?.buildDate) return info.buildDate;
      return '';
    };
    const load = async () => {
      try {
        const info = await ApiClient.loadLatestBuildInfo();
        if (cancelled) return;
        setLatestBuildInfo(info || null);
        const key = versionKey(info);
        if (!key) return;
        if (!baseline) {
          baseline = key;
          return;
        }
        if (key !== baseline && !notified) {
          notified = true;
          pushToast({
            kind: 'info',
            title: t('app.newVersion.title'),
            desc: t('app.newVersion.desc'),
            duration: 0,
            actionLabel: t('app.newVersion.reload'),
            onAction: () => { ApiClient.hardReload(); },
          });
        }
      } catch {
        // A temporary polling failure must not interrupt the current session.
      }
    };

    load();
    const timer = setInterval(load, 60_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [auth.user?.id]);

  useEffect(() => {
    ApiClient.setSessionInvalidHandler((err) => {
      const user = authRef.current?.user;
      const wasCabinetClient = user?.cabinet?.mode === 'client';
      const toast = ApiClient.sessionInvalidToast(err, { wasCabinetClient });
      setAuth({ loading: false, user: null });
      setTimeout(() => pushToast(toast), 0);
    });
    return () => ApiClient.setSessionInvalidHandler(null);
  }, []);

  useEffect(() => {
    if (!auth.user || auth.loading || !isCabinetMode(auth.user)) return undefined;
    let cancelled = false;
    const tick = async () => {
      try {
        const user = await ApiClient.loadCurrentUser();
        if (!cancelled) setAuth((prev) => ({ ...prev, user }));
      } catch (err) {
        if (!cancelled && ApiClient.isSessionInvalidError(err)) {
          setAuth({ loading: false, user: null });
        }
      }
    };
    const timer = setInterval(tick, 10_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [auth.user?.id, auth.user?.cabinet?.mode]);

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
      if (pageId === 'collector-status' || pageId === 'flow-exclusions') {
        if (pageId === 'flow-exclusions') {
          sessionStorage.setItem('grapes-collectors-tab', 'exclusions');
        }
        location.replace(`${location.pathname}${location.search}#collectors`);
        return;
      }
      if (pageId === 'erp-piterix') {
        sessionStorage.setItem('grapes-diagnostics-tab', 'erp');
        location.replace(`${location.pathname}${location.search}#diagnostics`);
        return;
      }
      if (pageId === 'vlan' || pageId === 'entities') {
        sessionStorage.setItem('grapes-network-tab', pageId);
        location.replace(`${location.pathname}${location.search}#cidr`);
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

  useEffect(() => {
    const bumpComposeTick = () => setObservationComposeTick((tick) => tick + 1);
    window.addEventListener('grapes-observation-compose', bumpComposeTick);
    return () => window.removeEventListener('grapes-observation-compose', bumpComposeTick);
  }, []);

  useEffect(() => {
    if (page === 'explorer') return undefined;
    try {
      sessionStorage.removeItem('grapes-observation-compose');
    } catch {
      // ignore
    }
    try {
      window.dispatchEvent(new CustomEvent('grapes-observation-compose'));
    } catch {
      // ignore
    }
    return undefined;
  }, [page]);

  useEffect(() => {
    if (!auth.user || auth.loading) return undefined;
    const pageId = page;
    const now = Date.now();
    const prev = lastAuditPageRef.current;
    if (prev.pageId === pageId && now - prev.at < 2000) return undefined;
    lastAuditPageRef.current = { pageId, at: now };
    ApiClient.reportAuditPage(pageId);
    return undefined;
  }, [auth.user, auth.loading, page]);

  const navigate = useCallback((id) => {
    if (id === '__toggle') { setCollapsed(v => !v); return; }
    if (id === '__theme')  { setTheme(t => t === 'dark' ? 'light' : 'dark'); return; }
    let target = id;
    if (target === 'flow-exclusions') {
      sessionStorage.setItem('grapes-collectors-tab', 'exclusions');
      target = 'collectors';
    }
    if (target === 'erp-piterix') {
      sessionStorage.setItem('grapes-diagnostics-tab', 'erp');
      target = 'diagnostics';
    }
    if (target === 'vlan' || target === 'entities') {
      sessionStorage.setItem('grapes-network-tab', target);
      target = 'cidr';
    }
    if (!validIds.has(target)) return;
    setPage(target);
    location.hash = target;
  }, [validIds]);

  const handleLogin = (user) => {
    applyStartPageAfterLoginRef.current = true;
    setAuth({ loading: false, user });
  };
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
    return user;
  };
  const handleStopImpersonation = async () => {
    try {
      await ApiClient.stopImpersonation();
      await reloadCurrentUser();
      pushToast({ kind: 'success', title: t('cabinet.impersonation.left') });
      setPage('clients');
      location.hash = 'clients';
    } catch (err) {
      pushToast({ kind: 'error', title: t('cabinet.impersonation.leaveFailed'), desc: err.message });
    }
  };
  const handleRefresh = useCallback(() => setRefreshKey((k) => k + 1), []);
  const toggleTheme = useCallback(() => setTheme(t => t === 'dark' ? 'light' : 'dark'), []);
  const handleLocaleChange = useCallback(async (next) => {
    const normalized = GrapesLocale.normalizeLocale(next);
    if (!normalized || normalized === locale) return;
    const previous = locale;
    setLocale(normalized);
    if (!authRef.current.user) {
      GrapesLocale.writePendingLocale(normalized);
      return;
    }
    try {
      const user = await ApiClient.updateLocale(normalized);
      setAuth((prev) => ({ ...prev, user }));
    } catch (err) {
      setLocale(previous);
      pushToast({ kind: 'error', title: t('app.localeSaveFailed'), desc: err.message });
    }
  }, [locale]);

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

  const canAccessPage = useCallback(
    (pageId) => canAccessPageForUser(auth.user, pageId),
    [auth.user],
  );

  const cabinetMode = isCabinetMode(auth.user);
  DashboardLog.setSuppressed(cabinetMode);
  const cabinetReadOnly = !!auth.user?.cabinet?.readOnly;
  const canManageCabinetObservations = cabinetMode && (
    AuthAccess.canWritePage('clients') || AuthAccess.canWritePage('observations')
  );
  // Impersonation is read-only for the cabinet shell, but operators with clients/observations
  // write may still configure client observations (server guard allows the same).
  const cabinetObservationsReadOnly = cabinetReadOnly && !canManageCabinetObservations;
  const clientDisplayName = auth.user?.cabinet?.clientDisplayName || '';
  const cabinetBindMode = auth.user?.cabinet?.bindMode || '';

  useEffect(() => {
    if (!auth.user || !registryReady) return;
    const cabinetBlocked = isCabinetMode(auth.user) && (
      !CABINET_PAGE_IDS.has(page)
      || (cabinetBindMode === 'ports' && page === 'dns')
    );
    if (cabinetBlocked) {
      setPage('dashboard');
      location.hash = 'dashboard';
    }
  }, [auth.user, registryReady, page, cabinetBindMode]);

  useEffect(() => {
    if (!auth.user || !registryReady) return;
    const afterLogin = applyStartPageAfterLoginRef.current;
    const emptyHash = isEmptyAppHash();
    if (!afterLogin && !emptyHash) return;
    applyStartPageAfterLoginRef.current = false;
    const target = resolveRoleLandingPage(auth.user, { validIds });
    const currentHash = (location.hash || '').slice(1).split('?')[0];
    if (currentHash === target && page === target) return;
    setPage(target);
    location.hash = target;
  }, [auth.user, registryReady, validIds, page]);

  if (auth.loading || !registryReady) {
    return <AuthFrame title={t('auth.appTitle')} subtitle={t('auth.sessionChecking')} theme={theme} onToggleTheme={toggleTheme} locale={locale} onLocaleChange={handleLocaleChange} />;
  }

  if (!auth.user) {
    return <LoginScreen onLogin={handleLogin} theme={theme} onToggleTheme={toggleTheme} locale={locale} onLocaleChange={handleLocaleChange} />;
  }

  if (auth.user.forcePasswordChange) {
    return <ForcePasswordChangeScreen user={auth.user} onDone={reloadCurrentUser} onLogout={handleLogout} theme={theme} onToggleTheme={toggleTheme} locale={locale} onLocaleChange={handleLocaleChange} />;
  }

  let pageEl;
  if (!canAccessPage(page)) {
    pageEl = <PageAccessDenied pageId={page} onNavigate={navigate} />;
  } else {
    switch (page) {
      case 'monitoring':
        pageEl = (
          <LazyPage
            pageId="monitoring"
            key={`${refreshKey}-${hashRoute}`}
            onNavigate={navigate}
            effectivePermissions={auth.user?.effectivePermissions}
          />
        );
        break;
      case 'dashboard':
        pageEl = (
          <LazyPage
            pageId="dashboard"
            key={`${refreshKey}-${displayTimezone}`}
            onNavigate={navigate}
            directions={directions}
            cabinetDirections={cabinetDirections}
            timeRange={timeRange}
            customPeriod={customPeriod}
            collectorFilter={collectorFilter}
            displayTimezone={displayTimezone}
            onChartRangeSelect={applyChartRangeZoom}
            cabinetMode={cabinetMode}
            readOnly={cabinetReadOnly}
          />
        );
        break;
      case 'explorer':
        pageEl = (
          <LazyPage
            pageId="explorer"
            key={`${refreshKey}-${displayTimezone}-${hashRoute}-${observationComposeTick}-${locale}`}
            onNavigate={navigate}
            displayTimezone={displayTimezone}
            cabinetMode={cabinetMode}
            readOnly={cabinetObservationsReadOnly}
          />
        );
        break;
      case 'dns-explorer':
        pageEl = (
          <LazyPage
            pageId="dns-explorer"
            key={`${refreshKey}-${displayTimezone}-${hashRoute}`}
            onNavigate={navigate}
            displayTimezone={displayTimezone}
          />
        );
        break;
      case 'observations':
        pageEl = (
          <LazyPage
            pageId="observations"
            key={refreshKey}
            onNavigate={navigate}
            cabinetMode={cabinetMode}
            readOnly={cabinetObservationsReadOnly}
            displayTimezone={displayTimezone}
          />
        );
        break;
      case 'diagnostics':
        pageEl = <LazyPage pageId="diagnostics" key={refreshKey} />;
        break;
      case 'top':
        pageEl = (
          <LazyPage
            pageId="top"
            key={`${refreshKey}-${displayTimezone}`}
            onNavigate={navigate}
            timeRange={timeRange}
            customPeriod={customPeriod}
            directions={directions}
            collectorFilter={collectorFilter}
            displayTimezone={displayTimezone}
          />
        );
        break;
      case 'smtp':
        pageEl = <LazyPage pageId="smtp" key={refreshKey} />;
        break;
      case 'api-integration-erp':
        pageEl = (
          <LazyPage
            pageId="api-integration-erp"
            key={refreshKey}
            currentUser={auth.user}
          />
        );
        break;
      case 'versions':
        pageEl = <LazyPage pageId="versions" key={refreshKey} displayTimezone={displayTimezone} />;
        break;
      case 'dns':
        pageEl = cabinetMode
          ? (
            <LazyPage
              pageId="dashboard"
              exportName="PageCabinetDns"
              key={`${refreshKey}-${displayTimezone}`}
              onNavigate={navigate}
              timeRange={timeRange}
              customPeriod={customPeriod}
              displayTimezone={displayTimezone}
              readOnly={cabinetReadOnly}
            />
          )
          : (
            <LazyPage
              pageId="dns"
              key={`${refreshKey}-${displayTimezone}-${(collectorFilter || []).join(',')}`}
              onNavigate={navigate}
              timeRange={timeRange}
              customPeriod={customPeriod}
              collectorFilter={collectorFilter}
              displayTimezone={displayTimezone}
              onChartRangeSelect={applyChartRangeZoom}
            />
          );
        break;
      case 'collectors':
        pageEl = (
          <LazyPage
            pageId="collectors"
            key={refreshKey}
            onNavigate={navigate}
            effectivePermissions={auth.user?.effectivePermissions}
          />
        );
        break;
      case 'snmp':
        pageEl = (
          <LazyPage
            pageId="snmp"
            key={`${refreshKey}-${displayTimezone}`}
            displayTimezone={displayTimezone}
            canOpenInterfaceRoles={canAccessPage('interface-roles')}
          />
        );
        break;
      case 'bmp':
        pageEl = <LazyPage pageId="bmp" key={refreshKey} />;
        break;
      case 'interface-roles':
        pageEl = <LazyPage pageId="interface-roles" key={refreshKey} onNavigate={navigate} />;
        break;
      case 'traffic-classification':
        pageEl = <LazyPage pageId="traffic-classification" key={refreshKey} />;
        break;
      case 'routers':
        pageEl = <LazyPage pageId="routers" key={refreshKey} />;
        break;
      case 'cidr':
      case 'vlan':
      case 'entities':
        pageEl = (
          <LazyPage
            pageId="network"
            key={refreshKey}
            effectivePermissions={auth.user?.effectivePermissions}
            initialTab={page === 'cidr' ? undefined : page}
          />
        );
        break;
      case 'dns-resolvers':
        pageEl = <LazyPage pageId="dns-resolvers" key={refreshKey} />;
        break;
      case 'port-services':
        pageEl = <LazyPage pageId="port-services" key={refreshKey} />;
        break;
      case 'flow-exclusions':
        pageEl = (
          <LazyPage
            pageId="collectors"
            key={refreshKey}
            onNavigate={navigate}
            effectivePermissions={auth.user?.effectivePermissions}
          />
        );
        break;
      case 'users':
        pageEl = (
          <LazyPage
            pageId="users"
            key={`${refreshKey}-${displayTimezone}`}
            currentUser={auth.user}
            onAuthRefresh={reloadCurrentUser}
            onNavigate={navigate}
            displayTimezone={displayTimezone}
          />
        );
        break;
      case 'audit':
        pageEl = (
          <LazyPage
            pageId="audit"
            key={`${refreshKey}-${displayTimezone}`}
            currentUser={auth.user}
            displayTimezone={displayTimezone}
          />
        );
        break;
      case 'clients':
        pageEl = (
          <LazyPage
            pageId="clients"
            key={refreshKey}
            currentUser={auth.user}
            onAuthRefresh={reloadCurrentUser}
            onNavigate={navigate}
          />
        );
        break;
      case 'cabinet-settings':
        pageEl = (
          <LazyPage
            pageId="cabinet-settings"
            key={refreshKey}
            readOnly={cabinetReadOnly}
            onAuthRefresh={reloadCurrentUser}
          />
        );
        break;
      case 'ttl':
        pageEl = <LazyPage pageId="ttl" key={refreshKey} />;
        break;
      default:
        pageEl = <PageComingSoon key={refreshKey} pageId={page} onNavigate={navigate} />;
    }
  }

  return (
    <div className="app" data-collapsed={collapsed} data-cabinet={cabinetMode ? '1' : '0'} data-screen-label={`Grapes NTA · ${GrapesI18n.localizedPageMeta(page, pageTitles[page]).title || page}`}>
      {isImpersonating(auth.user) && (
        <ImpersonationBanner
          cabinet={auth.user.cabinet}
          onStop={handleStopImpersonation}
          onRefreshUser={reloadCurrentUser}
        />
      )}
      <Sidebar
        current={page}
        onNavigate={navigate}
        collapsed={collapsed}
        effectivePermissions={auth.user?.effectivePermissions}
        cabinetMode={cabinetMode}
        cabinetBindMode={cabinetBindMode}
        clientDisplayName={clientDisplayName}
        locale={locale}
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
        cabinetDirections={cabinetDirections}
        onCabinetDirectionsChange={setCabinetDirections}
        collectorFilter={collectorFilter}
        onCollectorFilterChange={setCollectorFilter}
        pageTitles={pageTitles}
        hiddenPageIds={hiddenPageIds}
        displayTimezone={displayTimezone}
        timezonePref={timezonePref}
        onTimezonePrefChange={handleTimezonePrefChange}
        locale={locale}
        onLocaleChange={handleLocaleChange}
        cabinetMode={cabinetMode}
        clientDisplayName={clientDisplayName}
        onStopImpersonation={handleStopImpersonation}
        buildInfo={latestBuildInfo}
      />
      <main className="main">
        {pageEl}
      </main>
      <AttackAlertHost user={auth.user} onNavigate={navigate} cabinetMode={cabinetMode} />
      <ToastStack />
    </div>
  );
}

function AuthFrame({ title, subtitle, children, theme, onToggleTheme, locale, onLocaleChange }) {
  return (
    <div className="auth-screen">
      <Card className="auth-card">
        {onLocaleChange && (
          <LanguageSelector locale={locale} onLocaleChange={onLocaleChange} variant="auth" />
        )}
        {onToggleTheme && (
          <button
            type="button"
            className="auth-card__theme icon-btn tt"
            data-tt={theme === 'dark' ? t('chrome.themeLight') : t('chrome.themeDark')}
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

async function offerBrowserPasswordSave(username, password) {
  // SPA login (fetch + preventDefault) often skips Chrome's heuristic "save password"
  // prompt. Credential Management API asks explicitly; localhost is a secure context.
  try {
    if (typeof PasswordCredential === 'undefined' || !navigator.credentials?.store) return;
    const id = String(username || '').trim();
    const secret = String(password || '');
    if (!id || !secret) return;
    await navigator.credentials.store(new PasswordCredential({ id, password: secret, name: id }));
  } catch (_) {
    // User dismissed, "Never" for this origin, or policy blocked — ignore.
  }
}

function LoginScreen({ onLogin, theme, onToggleTheme, locale, onLocaleChange }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [errorKind, setErrorKind] = useState('');
  const [saving, setSaving] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setErrorKind('');
    setSaving(true);
    try {
      const result = await ApiClient.login({ username, password });
      await offerBrowserPasswordSave(username, password);
      onLogin(result.user);
    } catch (err) {
      const suspended = err.status === 403
        && (err.body?.code === 'client_disabled'
          || String(err.message || '').toLowerCase().includes('приостановлен'));
      setErrorKind(suspended ? 'suspended' : 'default');
      setError(loginErrorMessage(err));
      if (suspended) setPassword('');
    } finally {
      setSaving(false);
    }
  };

  return (
    <AuthFrame title={t('auth.login.title')} subtitle={t('auth.login.subtitle')} theme={theme} onToggleTheme={onToggleTheme} locale={locale} onLocaleChange={onLocaleChange}>
      <form
        className="col"
        style={{gap: 14}}
        onSubmit={submit}
        autoComplete="on"
        method="post"
        action="/api/auth/login"
      >
        <div className="field">
          <label htmlFor="login-username">{t('auth.login.username')}</label>
          <input
            id="login-username"
            className="input"
            name="username"
            type="text"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
          />
        </div>
        <div className="field">
          <label htmlFor="login-password">{t('auth.login.password')}</label>
          <input
            id="login-password"
            className="input"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        {error && (
          <div
            className="form-error"
            style={errorKind === 'suspended'
              ? { font: 'var(--pv-text-body-1-bold)', lineHeight: 1.4 }
              : undefined}
          >
            {error}
          </div>
        )}
        <Button kind="primary" type="submit" disabled={saving || !username || !password}>
          {saving ? t('auth.login.submitting') : t('auth.login.submit')}
        </Button>
      </form>
    </AuthFrame>
  );
}

function ForcePasswordChangeScreen({ user, onDone, onLogout, theme, onToggleTheme, locale, onLocaleChange }) {
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
      pushToast({ kind: 'success', title: t('auth.passwordChange.toastSuccess') });
      await onDone();
    } catch (err) {
      setError(err.message || t('auth.passwordChange.failed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <AuthFrame title={t('auth.passwordChange.title')} subtitle={t('auth.passwordChange.subtitleFirstLogin', { username: user.username })} theme={theme} onToggleTheme={onToggleTheme} locale={locale} onLocaleChange={onLocaleChange}>
      <form className="col" style={{gap: 14}} onSubmit={submit} autoComplete="on" method="post">
        <div className="field">
          <label htmlFor="login-new-password">{t('auth.passwordChange.newPassword')}</label>
          <div className="row" style={{gap: 8}}>
            <input
              id="login-new-password"
              className="input"
              name="new-password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t('auth.passwordChange.minLengthPlaceholder')}
              autoFocus
            />
            <Button kind="ghost" onClick={() => setShowPassword((v) => !v)}>
              {showPassword ? t('auth.passwordChange.hide') : t('auth.passwordChange.show')}
            </Button>
          </div>
        </div>
        {error && <div className="form-error">{error}</div>}
        <div className="row" style={{justifyContent: 'space-between'}}>
          <Button kind="ghost" onClick={onLogout}>{t('chrome.logout')}</Button>
          <Button kind="primary" type="submit" disabled={saving || password.length < 12}>
            {saving ? t('auth.passwordChange.saving') : t('auth.passwordChange.submit')}
          </Button>
        </div>
      </form>
    </AuthFrame>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
