/* Реестр lazy-чанков страниц. Источник правды для PageChunks и scripts/build-frontend.js.
   Алиасы pageId синхронизировать с AppPages.resolvePageId (public/data/app-pages.js). */

const PAGE_CHUNKS_MANIFEST = {
  version: 1,
  aliases: {
    'flow-exclusions': 'collectors',
    'collector-status': 'collectors',
    vlan: 'network',
    entities: 'network',
    'erp-piterix': 'diagnostics',
  },
  chunks: {
    dashboard: {
      scripts: [
        '/components/talkers.jsx',
        '/components/overview.jsx',
        '/components/dashboard-layout.jsx',
        '/pages/cabinet-shared.jsx',
        '/pages/cabinet-dns.jsx',
        '/pages/dashboard.jsx',
      ],
      exports: {
        default: 'PageDashboard',
        PageCabinetDns: 'PageCabinetDns',
      },
    },
    explorer: {
      scripts: [
        '/data/explorer-thresholds.js',
        '/data/explorer-field-search.js',
        '/data/explorer-group-dsl.js',
        '/pages/explorer.jsx',
      ],
      exports: { default: 'PageExplorer' },
    },
    'dns-explorer': {
      scripts: ['/pages/dns-explorer.jsx'],
      exports: { default: 'PageDnsExplorer' },
    },
    dns: {
      scripts: ['/pages/dns-queries.jsx'],
      exports: { default: 'PageDnsQueries' },
    },
    top: {
      scripts: ['/components/talkers.jsx', '/pages/top-talkers.jsx'],
      exports: { default: 'PageTop' },
    },
    collectors: {
      scripts: [
        '/pages/collectors-completeness-modal.jsx',
        '/pages/flow-exclusions.jsx',
        '/pages/collectors.jsx',
      ],
      exports: { default: 'PageCollectors' },
    },
    network: {
      scripts: [
        '/pages/cidr.jsx',
        '/pages/vlan.jsx',
        '/pages/entities.jsx',
        '/pages/network.jsx',
      ],
      exports: { default: 'PageNetwork' },
    },
    diagnostics: {
      scripts: ['/pages/erp-piterix.jsx', '/pages/diagnostics.jsx'],
      exports: { default: 'PageDiagnostics' },
    },
    snmp: {
      scripts: ['/data/interface-role-labels.js', '/pages/snmp.jsx'],
      exports: { default: 'PageSnmp' },
    },
    'interface-roles': {
      scripts: ['/data/interface-role-labels.js', '/pages/interface-roles.jsx'],
      exports: { default: 'PageInterfaceRoles' },
    },
    observations: {
      scripts: ['/pages/observations.jsx'],
    },
    users: {
      scripts: ['/pages/users.jsx'],
      exports: { default: 'PageUsers' },
    },
    audit: {
      scripts: ['/pages/audit.jsx'],
      exports: { default: 'PageAudit' },
    },
    clients: {
      scripts: ['/pages/clients.jsx'],
      exports: { default: 'PageClients' },
    },
    bmp: {
      scripts: ['/pages/bmp.jsx'],
      exports: { default: 'PageBmp' },
    },
    'traffic-classification': {
      scripts: ['/data/interface-role-labels.js', '/pages/traffic-classification.jsx'],
      exports: { default: 'PageTrafficClassification' },
    },
    'dns-resolvers': {
      scripts: ['/pages/dns-resolvers.jsx'],
      exports: { default: 'PageDnsResolvers' },
    },
    'port-services': {
      scripts: ['/pages/port-services.jsx'],
      exports: { default: 'PagePortServices' },
    },
    smtp: {
      scripts: ['/pages/smtp.jsx'],
      exports: { default: 'PageSmtp' },
    },
    ttl: {
      scripts: ['/pages/ttl.jsx'],
      exports: { default: 'PageTTL' },
    },
    routers: {
      scripts: ['/pages/routers.jsx'],
      exports: { default: 'PageRouters' },
    },
  },
  core: {
    scripts: [
      '/data/protocol-colors.js',
      '/data/mock-fixtures.js',
      '/data/logger.js',
      '/data/api.js',
      '/data/auth-access.js',
      '/data/app-pages.js',
      '/data/page-chunks.manifest.js',
      '/data/page-chunks.js',
      '/components/icons.jsx',
      '/components/ui.jsx',
      '/components/charts.jsx',
      '/components/shell.jsx',
      '/pages/access-denied.jsx',
      '/pages/coming-soon.jsx',
      '/app.jsx',
    ],
  },
};

Object.assign(window, { PAGE_CHUNKS_MANIFEST });
