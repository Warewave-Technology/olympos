import { useEffect, useState } from 'react';
import { Link, Outlet, useRouterState } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { ApiError, api, errorMessage, logout } from '../api/client';
import type { ChangeRequest, ItemList, RestoreRequest } from '../api/types';
import { MeProvider, useMeQuery } from '../auth/me';
import { can, primaryRole } from '../auth/permissions';
import { personName } from '../lib/format';
import logoUrl from '../assets/logo.svg';
import { IconMenu, IconClose } from '../ui/icons';
import { Badge, Spinner } from '../ui/kit';

const NAV = [
  { to: '/', label: 'Dashboard', exact: true },
  { to: '/backups', label: 'Backups' },
  { to: '/vaults', label: 'Vaults' },
  { to: '/approvals', label: 'Approvals', badge: true },
  { to: '/audit', label: 'Audit', also: '/activity' },
  { to: '/security', label: 'Security' },
  { to: '/monitoring', label: 'Monitoring' },
  { to: '/settings', label: 'Settings' },
] as const;

export function Brand({ size = 30 }: { size?: number }) {
  return (
    <Link to="/" className="brand" aria-label="Olympos home">
      <img src={logoUrl} alt="" width={size} height={size} />
      <span className="wordmark">olympos</span>
    </Link>
  );
}

export function AppLayout() {
  const meQ = useMeQuery();
  const [menuOpen, setMenuOpen] = useState(false);
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  useEffect(() => setMenuOpen(false), [pathname]);

  const me = meQ.data;
  const waitingQ = useQuery({
    queryKey: ['change-requests', { waiting_for_me: true, status: 'pending' }],
    queryFn: () => api.get<ItemList<ChangeRequest>>('/change-requests', { waiting_for_me: true, status: 'pending' }),
    enabled: !!me && can(me, 'vault_approve'),
    refetchInterval: 60_000,
    retry: false,
  });
  // Restore requests wait for a checker with operate on both clusters (docs/design/ui-restore.md).
  const waitingRestoresQ = useQuery({
    queryKey: ['restores', { waiting_for_me: true, status: 'pending' }],
    queryFn: () => api.get<ItemList<RestoreRequest>>('/restores', { waiting_for_me: true, status: 'pending' }),
    enabled: !!me && can(me, 'operate'),
    refetchInterval: 60_000,
    retry: false,
  });

  if (meQ.isPending) {
    return (
      <div className="fullpage">
        <div className="inline">
          <Spinner label="Loading Olympos" />
          <span className="muted">Loading Olympos…</span>
        </div>
      </div>
    );
  }
  if (meQ.isError || !me) {
    const err = meQ.error;
    const revoked = err instanceof ApiError && err.status === 403;
    return (
      <div className="fullpage">
        <div className="card pad-lg" style={{ maxWidth: 480 }} role="alert">
          <h1 className="section-title">{revoked ? 'Your access was revoked' : 'Olympos is not reachable'}</h1>
          <p className="muted" style={{ margin: 0 }}>
            {revoked
              ? 'You are signed in, but you no longer have an active grant. Ask an Olympos admin to grant you access again.'
              : `${errorMessage(err)} Check that the server is running, then retry.`}
          </p>
          <div className="end">
            {revoked ? (
              <button type="button" className="btn" onClick={() => void logout()}>
                Sign out
              </button>
            ) : (
              <button type="button" className="btn pri" onClick={() => void meQ.refetch()}>
                Retry
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  // The badge counts both kinds: vault changes and restores waiting for this user.
  const waiting = (waitingQ.data?.items.length ?? 0) + (waitingRestoresQ.data?.items.length ?? 0);
  return (
    <MeProvider me={me}>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <div className="shell">
        <header className="topbar">
          <Brand size={26} />
          <button
            type="button"
            className="btn icon"
            aria-label={menuOpen ? 'Close navigation' : 'Open navigation'}
            aria-expanded={menuOpen}
            aria-controls="sidebar"
            onClick={() => setMenuOpen((o) => !o)}
          >
            {menuOpen ? <IconClose /> : <IconMenu />}
          </button>
        </header>
        <nav id="sidebar" className={`sidebar${menuOpen ? ' open' : ''}`} aria-label="Main">
          <Brand />
          <div className="nav">
            {NAV.map((n) => (
              <Link
                key={n.to}
                to={n.to}
                activeOptions={{ exact: 'exact' in n ? n.exact : false }}
                activeProps={{ className: 'on', 'aria-current': 'page' }}
                className={'also' in n && pathname.startsWith(n.also) ? 'on' : undefined}
              >
                <span>{n.label}</span>
                {'badge' in n && waiting > 0 && (
                  <Badge tone="warn">
                    {waiting}
                    <span className="sr-only"> waiting for you</span>
                  </Badge>
                )}
              </Link>
            ))}
          </div>
          <div className="side-footer">
            <div className="who">{personName(me.principal)}</div>
            <div className="muted small">
              {primaryRole(me)} <span style={{ whiteSpace: 'nowrap' }}>· Entra ID{me.is_guest ? ' · guest' : ''}</span>
            </div>
            <button type="button" className="btn sm" onClick={() => void logout()}>
              Sign out
            </button>
          </div>
        </nav>
        <main id="main" className="main" tabIndex={-1}>
          <div className="page">
            <Outlet />
          </div>
        </main>
      </div>
    </MeProvider>
  );
}
