// Monitoring (docs/design/monitoring-overview.html): a tab bar driven by MONITORING_TABS, the scenario detail
// (?scenario=) and the run dialog (?run=) over either.
import { Link, useNavigate } from '@tanstack/react-router';
import { useCan } from '../../auth/me';
import { monitoringRoute } from '../../router';
import { PageHead } from '../../ui/status';
import { RunDialog } from './RunDialog';
import { ScenarioDetail } from './ScenarioDetail';
import { MONITORING_TABS, monitoringTab } from './tabs';

export function MonitoringTabs({ active }: { active: string }) {
  return (
    <nav className="tabs" aria-label="Monitoring sections">
      {MONITORING_TABS.map((t) => (
        <Link key={t.id} to="/monitoring" search={{ tab: t.id === MONITORING_TABS[0].id ? undefined : t.id }} className={t.id === active ? 'on' : undefined} aria-current={t.id === active ? 'page' : undefined}>
          {t.label}
        </Link>
      ))}
    </nav>
  );
}

export function MonitoringPage() {
  const search = monitoringRoute.useSearch();
  const navigate = useNavigate({ from: '/monitoring' });
  const canEdit = useCan('synthetic_edit');
  const tab = monitoringTab(search.tab);
  const Tab = tab.component;
  return (
    <>
      {search.scenario ? (
        <ScenarioDetail id={search.scenario} />
      ) : (
        <>
          <PageHead
            title="Monitoring"
            sub="Synthetic scenarios run from inside every cluster, so you see what each cluster sees."
            actions={
              tab.id === 'synthetic' &&
              canEdit && (
                <Link to="/monitoring/editor" className="btn pri">
                  New scenario
                </Link>
              )
            }
          />
          <MonitoringTabs active={tab.id} />
          <Tab />
        </>
      )}
      {search.run && (
        <RunDialog
          id={search.run}
          onClose={() => void navigate({ search: (s) => ({ ...s, run: undefined }) })}
          onBack={(scenario) => void navigate({ search: (s) => ({ tab: s.tab, scenario, run: undefined }) })}
        />
      )}
    </>
  );
}
