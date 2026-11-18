import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHead } from '../../ui/status';

const SECTIONS = [
  { to: '/settings', hash: undefined, label: 'Access', key: 'access' },
  { to: '/settings', hash: 'notifications', label: 'Notifications', key: 'notifications' },
  { to: '/settings/destinations', hash: undefined, label: 'Destinations', key: 'destinations' },
  { to: '/settings/registries', hash: undefined, label: 'Registries', key: 'registries' },
  { to: '/settings/clusters', hash: undefined, label: 'Clusters & agents', key: 'clusters' },
] as const;

export type SettingsSection = (typeof SECTIONS)[number]['key'];

export function SettingsLayout({ current, sub, actions, children }: { current: SettingsSection; sub: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <>
      <PageHead title="Settings" sub={sub} actions={actions} />
      <div className="row">
        <nav className="side card" aria-label="Settings sections">
          {SECTIONS.map((s) => (
            <Link key={s.key} to={s.to} hash={s.hash} className={current === s.key ? 'on' : undefined} aria-current={current === s.key ? 'page' : undefined} activeOptions={{ exact: true, includeHash: true }}>
              {s.label}
            </Link>
          ))}
        </nav>
        <div className="grow stack">{children}</div>
      </div>
    </>
  );
}
