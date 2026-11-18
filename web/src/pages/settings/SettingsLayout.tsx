import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { PageHead } from '../../ui/status';

const SECTIONS = [
  { to: '/settings', label: 'Access', key: 'access' },
  { to: '/settings/notifications', label: 'Notifications', key: 'notifications' },
  { to: '/settings/destinations', label: 'Destinations', key: 'destinations' },
  { to: '/settings/registries', label: 'Registries', key: 'registries' },
  { to: '/settings/clusters', label: 'Clusters & agents', key: 'clusters' },
] as const;

export type SettingsSection = (typeof SECTIONS)[number]['key'];

export function SettingsLayout({ current, sub, actions, children }: { current: SettingsSection; sub: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <>
      <PageHead title="Settings" sub={sub} actions={actions} />
      <div className="settings-grid">
        <nav className="side card" aria-label="Settings sections">
          {SECTIONS.map((s) => (
            <Link key={s.key} to={s.to} className={current === s.key ? 'on' : undefined} aria-current={current === s.key ? 'page' : undefined} activeOptions={{ exact: true }}>
              {s.label}
            </Link>
          ))}
        </nav>
        <div className="settings-content">{children}</div>
      </div>
    </>
  );
}
