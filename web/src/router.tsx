import { createRootRoute, createRoute, createRouter, Outlet } from '@tanstack/react-router';
import { AppLayout } from './shell/AppLayout';
import { NotFoundPage } from './shell/NotFound';
import { LoginPage } from './pages/Login';
import { DashboardPage } from './pages/Dashboard';
import { BackupsPage } from './pages/Backups';
import { BackupWizardPage } from './pages/BackupWizard';
import { VaultsPage } from './pages/Vaults';
import { ApprovalsPage } from './pages/Approvals';
import { AuditPage } from './pages/Audit';
import { ActivityPage } from './pages/Activity';
import { SecurityPage } from './pages/Security';
import { KyvernoPolicyPage } from './pages/KyvernoPolicy';
import { NetpolNamespacePage } from './pages/NetpolNamespace';
import { SettingsAccessPage } from './pages/settings/Access';
import { SettingsNotificationsPage } from './pages/settings/Notifications';
import { DestinationsPage } from './pages/settings/Destinations';
import { RegistriesPage } from './pages/settings/Registries';
import { ClustersSettingsPage } from './pages/settings/Clusters';

const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : typeof v === 'number' ? String(v) : undefined);
/** Search params are always optional, so links never need to pass them. */
function opt<T extends Record<string, unknown>>(fn: (s: Record<string, unknown>) => T): (s: Record<string, unknown>) => Partial<T> {
  return fn;
}
function pick<T extends string>(v: unknown, allowed: readonly T[]): T | undefined {
  return allowed.includes(v as T) ? (v as T) : undefined;
}

const rootRoute = createRootRoute({ component: () => <Outlet />, notFoundComponent: NotFoundPage });

export const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  validateSearch: opt((s) => ({ error: str(s.error), return_to: str(s.return_to) })),
  component: LoginPage,
});

const appRoute = createRoute({ getParentRoute: () => rootRoute, id: 'app', component: AppLayout });

export const dashboardRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/',
  validateSearch: opt((s) => ({
    q: str(s.q),
    filter: pick(s.filter, ['eol', 'skew', 'offline'] as const),
    provider: str(s.provider),
    version: str(s.version),
    add: s.add === true || s.add === '1' || s.add === 1 ? true : undefined,
  })),
  component: DashboardPage,
});

export const BACKUP_TABS = ['candidates', 'jobs', 'runs'] as const;
export const backupsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/backups',
  validateSearch: opt((s) => ({ tab: pick(s.tab, BACKUP_TABS), cluster: str(s.cluster), self: s.self === true || s.self === 1 || s.self === '1' ? true : undefined })),
  component: BackupsPage,
});

export const backupWizardRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/backups/new',
  validateSearch: opt((s) => ({ target: str(s.target), job: str(s.job) })),
  component: BackupWizardPage,
});

export const vaultsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/vaults',
  validateSearch: opt((s) => ({ vault: str(s.vault), mount: str(s.mount), path: str(s.path), cluster: str(s.cluster) })),
  component: VaultsPage,
});

export const APPROVAL_VIEWS = ['waiting', 'mine', 'all'] as const;
export const approvalsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/approvals',
  validateSearch: opt((s) => ({ view: pick(s.view, APPROVAL_VIEWS), cr: str(s.cr) })),
  component: ApprovalsPage,
});

export const auditRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/audit',
  validateSearch: opt((s) => ({ cluster: str(s.cluster), run: str(s.run) })),
  component: AuditPage,
});

export const activityRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/activity',
  validateSearch: opt((s) => ({ q: str(s.q), group: str(s.group) })),
  component: ActivityPage,
});

export const SECURITY_TABS = ['images', 'kyverno', 'netpol', 'sensitive', 'secrets'] as const;
export const securityRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/security',
  validateSearch: opt((s) => ({ tab: pick(s.tab, SECURITY_TABS), digest: str(s.digest), cluster: str(s.cluster) })),
  component: SecurityPage,
});

export const kyvernoPolicyRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/security/kyverno',
  validateSearch: opt((s) => ({ cluster: str(s.cluster), kind: str(s.kind), namespace: str(s.namespace), name: str(s.name), from: str(s.from) })),
  component: KyvernoPolicyPage,
});

export const netpolNamespaceRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/security/netpol',
  validateSearch: opt((s) => ({ cluster: str(s.cluster), namespace: str(s.namespace), policy: str(s.policy), from: str(s.from) })),
  component: NetpolNamespacePage,
});

export const settingsRoute = createRoute({ getParentRoute: () => appRoute, path: '/settings', component: SettingsAccessPage });
export const notificationsRoute = createRoute({ getParentRoute: () => appRoute, path: '/settings/notifications', component: SettingsNotificationsPage });
export const destinationsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/settings/destinations',
  validateSearch: opt((s) => ({ id: str(s.id) })),
  component: DestinationsPage,
});
export const registriesRoute = createRoute({ getParentRoute: () => appRoute, path: '/settings/registries', component: RegistriesPage });
export const clustersSettingsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/settings/clusters',
  validateSearch: opt((s) => ({ cluster: str(s.cluster) })),
  component: ClustersSettingsPage,
});

export const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([
    dashboardRoute,
    backupsRoute,
    backupWizardRoute,
    vaultsRoute,
    approvalsRoute,
    auditRoute,
    activityRoute,
    securityRoute,
    kyvernoPolicyRoute,
    netpolNamespaceRoute,
    settingsRoute,
    notificationsRoute,
    destinationsRoute,
    registriesRoute,
    clustersSettingsRoute,
  ]),
]);

export const router = createRouter({ routeTree, defaultPreload: false, scrollRestoration: true });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
